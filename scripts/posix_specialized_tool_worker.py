#!/usr/bin/env python3
"""Closed, descriptor-only guest worker for specialized Plamen tools.

This program is an intentionally small execution primitive.  The native
provider opens and retains every authority object, starts this worker inside
an already network-denied guest, and authenticates/replays the returned bytes.
The worker never discovers ``PATH``, a home directory, proxy state, a network
interface, or a tool by name.  All filesystem references in a request are
symbolic references to an explicitly retained descriptor.

The terminal is exact canonical JSON without a trailing newline.  It is
observation data, not native authority: population-zero, network isolation,
mount recensus, and HMAC authentication remain native-provider duties.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
if os.name == "posix":
    import fcntl
    import resource
else:
    fcntl = None  # type: ignore[assignment]
    resource = None  # type: ignore[assignment]
from pathlib import PurePosixPath
import re
import selectors
import signal
import stat
import sys
import time
from typing import Any, NoReturn


REQUEST_SCHEMA = "plamen.posix-specialized-tool-worker-request.v1"
APPLE_REQUEST_SCHEMA = "plamen.posix-specialized-tool-worker-apple-request.v2"
TERMINAL_SCHEMA = "plamen.posix-specialized-tool-worker-terminal.v1"
APPLE_TERMINAL_SCHEMA = "plamen.posix-specialized-tool-worker-apple-terminal.v2"
REJECTION_SCHEMA = "plamen.posix-specialized-tool-worker-rejection.v1"
EMPTY_LIST_SHA256 = hashlib.sha256(b"[]").hexdigest()
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_DURATION_MS = 30 * 60 * 1000
MAX_MEMORY_BYTES = 8 * 1024 * 1024 * 1024
MAX_STDOUT_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_FILES = 65_536
MAX_OUTPUT_BYTES = 4 * 1024 * 1024 * 1024
MAX_OPEN_FDS = 64

_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
_ENV_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)
_JS_OPERATIONS = frozenset(
    {"PREPARE_TOOLCHAIN", "ONLINE_INSTALL", "CACHE_HANDOFF", "OFFLINE_REPLAY"}
)
_PROJECTION_OPERATION = "EVM_PROJECTION_COMMIT"
_METHOD_PAYLOAD_OPERATIONS = _JS_OPERATIONS | {
    "MANAGED_EVM_EXECUTE", _PROJECTION_OPERATION,
}
_OPERATIONS = _METHOD_PAYLOAD_OPERATIONS | {"SNAPSHOT_TOOL_EXECUTE"}
_ROLES = (
    "acquisition",
    "cache",
    "generation",
    "project",
    "scratch",
    "source",
    "state",
    "tool",
)
_REQUIRED_ROLES = {
    **{operation: frozenset(_ROLES) for operation in _JS_OPERATIONS},
    "MANAGED_EVM_EXECUTE": frozenset(_ROLES),
    "SNAPSHOT_TOOL_EXECUTE": frozenset(
        {"project", "scratch", "source", "state", "tool"}
    ),
    _PROJECTION_OPERATION: frozenset(
        {"project", "scratch", "source", "state", "tool"}
    ),
}
_APPLE_REQUIRED_ROLES = {
    **{
        operation: frozenset(
            {"acquisition", "scratch", "source", "state", "tool"}
        )
        for operation in _JS_OPERATIONS
    },
    "MANAGED_EVM_EXECUTE": frozenset(_ROLES),
    "SNAPSHOT_TOOL_EXECUTE": frozenset(
        {"project", "scratch", "source", "state", "tool"}
    ),
    _PROJECTION_OPERATION: frozenset(
        {"project", "scratch", "source", "state", "tool"}
    ),
}
_WRITABLE_ROLES = frozenset({"cache", "generation", "scratch", "state"})
_DENIED_ENV = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "NODE_OPTIONS",
        "PATH",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUBYOPT",
        "SHELLOPTS",
    }
)
_DENIED_ENV_PREFIXES = ("DYLD_", "LD_", "http_", "https_", "HTTP_", "HTTPS_")
_DESCRIPTOR_KEYS = frozenset({"access", "fd", "identity_sha256", "kind"})
_APPLE_DESCRIPTOR_KEYS = frozenset(
    {"access", "kind", "payload_bytes", "payload_entries", "payload_sha256"}
)
_REQUEST_KEYS = frozenset(
    {
        "argv",
        "cwd",
        "descriptors",
        "effects_binding_sha256",
        "environment",
        "limits",
        "network_mode",
        "operation",
        "request_id",
        "request_sha256",
        "schema",
        "worker_runtime_sha256",
    }
)
_APPLE_REQUEST_KEYS = _REQUEST_KEYS | frozenset(
    {"runtime_closure_sha256", "tool_anchor_id"}
)
_APPLE_MANAGED_REQUEST_KEYS = _APPLE_REQUEST_KEYS | frozenset(
    {
        "managed_provisioner_sha256", "managed_provisioner_size",
        "method_payload_ascii", "method_payload_sha256",
    }
)
_APPLE_JS_REQUEST_KEYS = _APPLE_REQUEST_KEYS | frozenset(
    {
        "js_offline_materializer_sha256", "js_offline_materializer_size",
        "method_payload_ascii", "method_payload_sha256",
    }
)
_APPLE_SLITHER_REQUEST_KEYS = _APPLE_REQUEST_KEYS | frozenset(
    {
        "slither_forge_sha256", "slither_forge_size",
        "slither_internal_environment_sha256",
        "slither_python_sha256", "slither_python_size",
        "slither_solc_sha256", "slither_solc_size",
    }
)
_APPLE_PROJECTION_REQUEST_KEYS = _APPLE_REQUEST_KEYS | frozenset(
    {
        "method_payload_ascii", "method_payload_sha256",
        "projection_solc_sha256", "projection_solc_size",
    }
)
_LIMIT_KEYS = frozenset(
    {
        "duration_ms",
        "memory_bytes",
        "open_fds",
        "output_bytes",
        "output_files",
        "stderr_bytes",
        "stdout_bytes",
    }
)

# These are guest image ABI, not request data.  Apple Container receives only
# directory bind mounts, so regular tool/source payloads occupy the one fixed
# leaf ``payload`` inside their role mount.  No caller-controlled pathname is
# accepted by attached-stdio mode.
APPLE_MOUNT_ROOT = "/plamen/retained"
APPLE_MOUNT_ROLE_PATHS = (
    ("acquisition", "/plamen/retained/acquisition"),
    ("cache", "/plamen/retained/cache"),
    ("generation", "/plamen/retained/generation"),
    ("project", "/plamen/retained/project"),
    ("scratch", "/plamen/retained/scratch"),
    ("source", "/plamen/retained/source"),
    ("state", "/plamen/retained/state"),
)
# Only anchors already authenticated by the immutable image contract appear
# here.  Guessing a conventional path for any other tool is forbidden.
APPLE_TOOL_ANCHORS = (
    ("forge", "/usr/local/lib/plamen/toolchains/foundry/bin/forge"),
    ("js-python", "/usr/local/lib/plamen/python/bin/python3.12"),
    (
        "managed-python",
        "/usr/local/lib/plamen/python/bin/python3.12",
    ),
    ("opengrep", "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep"),
    ("slither", "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither"),
    ("solc", "/usr/local/lib/plamen/toolchains/solc-amd64/solc"),
)
_APPLE_ANCHORS_BY_OPERATION = {
    **{operation: frozenset({"js-python"}) for operation in _JS_OPERATIONS},
    "MANAGED_EVM_EXECUTE": frozenset({"managed-python"}),
    "SNAPSHOT_TOOL_EXECUTE": frozenset(
        {"forge", "opengrep", "slither", "solc"}
    ),
    _PROJECTION_OPERATION: frozenset({"js-python"}),
}
APPLE_INTERNAL_FDS = (
    ("acquisition", 10),
    ("cache", 11),
    ("generation", 12),
    ("project", 13),
    ("scratch", 14),
    ("source", 15),
    ("state", 16),
    ("tool", 17),
)

# Slither delegates compilation to crytic-compile, which in turn executes the
# reviewed Forge/Solc image members.  Those dependencies are not request
# environment: the authenticated Apple worker ABI supplies this fixed closure
# only after the outer v2 request and image-member bindings have validated.
_SLITHER_INTERNAL_ENVIRONMENT = (
    ("FOUNDRY_CACHE_PATH", "@fd:state/foundry-cache"),
    ("FOUNDRY_OUT", "@fd:scratch/foundry-out"),
    ("HOME", "@fd:state/home"),
    (
        "PATH",
        "/usr/local/lib/plamen/toolchains/managed-evm/bin:"
        "/usr/local/lib/plamen/toolchains/foundry/bin:"
        "/usr/local/lib/plamen/toolchains/solc-amd64:/usr/bin:/bin",
    ),
    ("XDG_CACHE_HOME", "@fd:state/cache"),
)
_SLITHER_INTERNAL_ENVIRONMENT_TOKEN = object()
_APPLE_ATTACHED_REQUEST_TOKEN = object()


class SpecializedToolWorkerError(RuntimeError):
    """A stable, fail-closed rejection from the guest worker."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(detail or code)


def _fail(code: str, detail: str = "") -> NoReturn:
    raise SpecializedToolWorkerError(code, detail)


def canonical_bytes(value: Any) -> bytes:
    """Encode only the exact JSON data model as ASCII canonical JSON."""

    def plain(item: Any) -> Any:
        if type(item) is dict:
            result: dict[str, Any] = {}
            for key, child in item.items():
                if type(key) is not str or key in result:
                    _fail("NON_CANONICAL_JSON_MODEL")
                result[key] = plain(child)
            return result
        if type(item) in {list, tuple}:
            return [plain(child) for child in item]
        if item is None or type(item) in {str, int, bool}:
            return item
        _fail("NON_CANONICAL_JSON_MODEL")

    try:
        return json.dumps(
            plain(value), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SpecializedToolWorkerError("NON_CANONICAL_JSON_MODEL") from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


SLITHER_INTERNAL_ENVIRONMENT_SHA256 = _sha(
    canonical_bytes(_SLITHER_INTERNAL_ENVIRONMENT)
)


def _exact_object(value: Any, keys: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        _fail(code)
    return value


def _hex(value: Any, code: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(code)
    return value


def _bounded_int(value: Any, maximum: int, code: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _fail(code)
    return value


def _safe_relative(value: Any, code: str, *, dot: bool = False) -> str:
    if type(value) is not str or not value or "\x00" in value or "\\" in value:
        _fail(code)
    if dot and value == ".":
        return value
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        _fail(code)
    return value


def _descriptor_observation(role: str, row: dict[str, Any]) -> dict[str, Any]:
    fd = row["fd"]
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise SpecializedToolWorkerError("DESCRIPTOR_UNAVAILABLE", role) from exc
    expected_kind = row["kind"]
    if expected_kind == "REGULAR_FILE":
        if not stat.S_ISREG(info.st_mode):
            _fail("DESCRIPTOR_KIND_MISMATCH", role)
        digest = hashlib.sha256()
        offset = 0
        while offset < info.st_size:
            block = os.pread(fd, min(1024 * 1024, info.st_size - offset), offset)
            if not block:
                _fail("DESCRIPTOR_SHORT_READ", role)
            digest.update(block)
            offset += len(block)
        content_sha256: str | None = digest.hexdigest()
    elif expected_kind == "DIRECTORY":
        if not stat.S_ISDIR(info.st_mode):
            _fail("DESCRIPTOR_KIND_MISMATCH", role)
        content_sha256 = None
    else:
        _fail("DESCRIPTOR_KIND_INVALID", role)
    observed = {
        "access": row["access"],
        "content_sha256": content_sha256,
        "device": int(info.st_dev),
        "fd": fd,
        "gid": int(info.st_gid),
        "inode": int(info.st_ino),
        "kind": expected_kind,
        "link_count": int(info.st_nlink),
        "mode": stat.S_IMODE(info.st_mode),
        "role": role,
        "size": int(info.st_size),
        "uid": int(info.st_uid),
    }
    observed["identity_sha256"] = _sha(canonical_bytes(observed))
    return observed


def descriptor_identity(role: str, fd: int, kind: str, access: str) -> str:
    """Return the request identity for an already-open descriptor."""
    row = {"access": access, "fd": fd, "identity_sha256": "0" * 64, "kind": kind}
    return _descriptor_observation(role, row)["identity_sha256"]


def parse_request(
    raw: bytes, *, _apple_attached_token: object | None = None,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_REQUEST_BYTES or raw.endswith(b"\n"):
        _fail("REQUEST_BYTES_INVALID")
    try:
        request = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SpecializedToolWorkerError("REQUEST_JSON_INVALID") from exc
    _exact_object(request, _REQUEST_KEYS, "REQUEST_SCHEMA_INVALID")
    if raw != canonical_bytes(request):
        _fail("REQUEST_NOT_EXACT_CANONICAL_JSON")
    if request["schema"] != REQUEST_SCHEMA:
        _fail("REQUEST_SCHEMA_INVALID")
    stored_sha = _hex(request["request_sha256"], "REQUEST_DIGEST_INVALID")
    unsigned = dict(request)
    unsigned.pop("request_sha256")
    if stored_sha != _sha(canonical_bytes(unsigned)):
        _fail("REQUEST_DIGEST_INVALID")
    if type(request["request_id"]) is not str or _SAFE_ID.fullmatch(request["request_id"]) is None:
        _fail("REQUEST_ID_INVALID")
    operation = request["operation"]
    if operation not in _OPERATIONS:
        _fail("ONLINE_OR_UNSUPPORTED_OPERATION_DENIED")
    _hex(request["effects_binding_sha256"], "EFFECTS_BINDING_INVALID")
    _hex(request["worker_runtime_sha256"], "WORKER_RUNTIME_BINDING_INVALID")
    expected_network_mode = (
        "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST"
        if operation == "ONLINE_INSTALL" else "DENY_ALL"
    )
    if request["network_mode"] != expected_network_mode:
        _fail("NETWORK_MODE_NOT_DENY_ALL")

    limits = _exact_object(request["limits"], _LIMIT_KEYS, "LIMITS_INVALID")
    _bounded_int(limits["duration_ms"], MAX_DURATION_MS, "DURATION_LIMIT_INVALID")
    _bounded_int(limits["memory_bytes"], MAX_MEMORY_BYTES, "MEMORY_LIMIT_INVALID")
    _bounded_int(limits["stdout_bytes"], MAX_STDOUT_BYTES, "STDOUT_LIMIT_INVALID")
    _bounded_int(limits["stderr_bytes"], MAX_STDERR_BYTES, "STDERR_LIMIT_INVALID")
    _bounded_int(limits["output_files"], MAX_OUTPUT_FILES, "OUTPUT_FILE_LIMIT_INVALID")
    _bounded_int(limits["output_bytes"], MAX_OUTPUT_BYTES, "OUTPUT_BYTE_LIMIT_INVALID")
    _bounded_int(limits["open_fds"], MAX_OPEN_FDS, "FD_LIMIT_INVALID", minimum=8)

    descriptors = _exact_object(
        request["descriptors"], frozenset(_ROLES), "DESCRIPTOR_ROSTER_INVALID"
    )
    if _apple_attached_token is None:
        required = _REQUIRED_ROLES[operation]
    elif _apple_attached_token is _APPLE_ATTACHED_REQUEST_TOKEN:
        required = _APPLE_REQUIRED_ROLES[operation]
    else:
        _fail("APPLE_ATTACHED_AUTHORITY_INVALID")
    observations: dict[str, dict[str, Any]] = {}
    used_fds: set[int] = set()
    for role in _ROLES:
        row = descriptors[role]
        if row is None:
            if role in required:
                _fail("REQUIRED_DESCRIPTOR_ABSENT", role)
            continue
        _exact_object(row, _DESCRIPTOR_KEYS, "DESCRIPTOR_SCHEMA_INVALID")
        fd = _bounded_int(row["fd"], 1_048_575, "DESCRIPTOR_NUMBER_INVALID", minimum=3)
        if fd in used_fds:
            _fail("DESCRIPTOR_ALIAS_DENIED", role)
        used_fds.add(fd)
        if row["access"] not in {"READ_ONLY", "READ_WRITE"}:
            _fail("DESCRIPTOR_ACCESS_INVALID", role)
        if role in _WRITABLE_ROLES:
            if row["access"] != "READ_WRITE" or row["kind"] != "DIRECTORY":
                _fail("WRITABLE_DESCRIPTOR_INVALID", role)
        elif row["access"] != "READ_ONLY":
            _fail("READ_ONLY_DESCRIPTOR_INVALID", role)
        _hex(row["identity_sha256"], "DESCRIPTOR_IDENTITY_INVALID")
        observed = _descriptor_observation(role, row)
        if observed["identity_sha256"] != row["identity_sha256"]:
            _fail("DESCRIPTOR_IDENTITY_MISMATCH", role)
        observations[role] = observed

    cwd = _exact_object(request["cwd"], frozenset({"relative", "role"}), "CWD_INVALID")
    if cwd["role"] not in observations or observations[cwd["role"]]["kind"] != "DIRECTORY":
        _fail("CWD_DESCRIPTOR_INVALID")
    _safe_relative(cwd["relative"], "CWD_RELATIVE_INVALID", dot=True)
    argv = request["argv"]
    if type(argv) is not list or not argv or len(argv) > 1024 or argv[0] != "@fd:tool":
        _fail("ARGV_INVALID")
    for token in argv:
        if type(token) is not str or not token or "\x00" in token or "\n" in token:
            _fail("ARGV_INVALID")
        if token.startswith("@fd:"):
            _resolve_token(token, observations)
        elif token.startswith(("/", "~")) or "\\" in token or "://" in token:
            _fail("AMBIENT_PATH_OR_NETWORK_TOKEN_DENIED")

    environment = request["environment"]
    if type(environment) is not list or len(environment) > 128:
        _fail("ENVIRONMENT_INVALID")
    previous = ""
    for pair in environment:
        if type(pair) is not list or len(pair) != 2:
            _fail("ENVIRONMENT_INVALID")
        key, value = pair
        if type(key) is not str or _ENV_KEY.fullmatch(key) is None or key <= previous:
            _fail("ENVIRONMENT_NOT_CANONICAL")
        previous = key
        if key in _DENIED_ENV or key.startswith(_DENIED_ENV_PREFIXES):
            _fail("AMBIENT_OR_LOADER_ENVIRONMENT_DENIED", key)
        if type(value) is not str or "\x00" in value or "\n" in value:
            _fail("ENVIRONMENT_INVALID")
        if value.startswith("@fd:"):
            _resolve_token(value, observations)
        elif value.startswith(("/", "~")) or "\\" in value or "://" in value:
            _fail("AMBIENT_PATH_OR_NETWORK_ENVIRONMENT_DENIED", key)
    return request, observations


def _resolve_token(token: str, observations: dict[str, dict[str, Any]]) -> str:
    body = token.removeprefix("@fd:")
    role, separator, relative = body.partition("/")
    if role not in observations:
        _fail("FD_TOKEN_ROLE_INVALID", role)
    if separator:
        _safe_relative(relative, "FD_TOKEN_RELATIVE_INVALID")
    # The production providers launch a Linux guest and bind this exact procfs
    # descriptor projection.  Darwin's /dev/fd cannot exec a regular retained
    # file and therefore is deliberately not a weaker host-side fallback.
    return f"/proc/self/fd/{observations[role]['fd']}" + (f"/{relative}" if separator else "")


def _open_cwd(root_fd: int, relative: str) -> int:
    current = os.dup(root_fd)
    try:
        if relative != ".":
            for component in PurePosixPath(relative).parts:
                child = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=current,
                )
                os.close(current)
                current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _apply_limits(limits: dict[str, int]) -> None:
    cpu_seconds = max(1, (limits["duration_ms"] + 999) // 1000)
    pairs = (
        (resource.RLIMIT_AS, limits["memory_bytes"]),
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, cpu_seconds),
        (resource.RLIMIT_FSIZE, limits["output_bytes"]),
        (resource.RLIMIT_NOFILE, limits["open_fds"]),
    )
    for kind, ceiling in pairs:
        _soft, hard = resource.getrlimit(kind)
        # Darwin refuses to lower RLIMIT_AS below the Python worker's existing
        # virtual-address reservation.  The production guest is Linux and gets
        # the immutable hard ceiling; a Darwin contract test still gets the
        # requested soft ceiling while native custody remains the authoritative
        # outer memory bound.
        if sys.platform == "darwin" and kind == resource.RLIMIT_AS:
            # macOS charges the inherited Python VM reservation against this
            # limit and rejects any reviewed useful ceiling before exec.  The
            # Apple provider's Linux guest is the production boundary; direct
            # Darwin execution exists only for parser/exec contract tests.
            continue
        resource.setrlimit(kind, (ceiling, ceiling))
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))


def _close_unlisted_fds(allowed: set[int]) -> None:
    """Remove ambient inherited descriptors before executing the tool.

    This is descriptor-census hygiene, not filesystem authority discovery.
    Production is a Linux guest with procfs mounted by the native provider; a
    missing exact census surface is therefore a hard failure.
    """
    try:
        descriptors = [int(name, 10) for name in os.listdir("/proc/self/fd")]
    except (OSError, ValueError) as exc:
        raise SpecializedToolWorkerError("FD_CENSUS_UNAVAILABLE") from exc
    for descriptor in descriptors:
        if descriptor > 2 and descriptor not in allowed:
            try:
                os.close(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise


def _manifest_directory(fd: int, prefix: str, rows: list[dict[str, Any]], counters: list[int], limits: dict[str, int]) -> None:
    names = sorted(os.listdir(fd))
    for name in names:
        if type(name) is not str or name in {".", ".."} or "/" in name or "\x00" in name:
            _fail("OUTPUT_NAME_INVALID")
        relative = f"{prefix}/{name}" if prefix else name
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            _fail("OUTPUT_NODE_KIND_DENIED", relative)
        counters[0] += 1
        if counters[0] > limits["output_files"]:
            _fail("OUTPUT_FILE_LIMIT_EXCEEDED")
        if stat.S_ISREG(info.st_mode):
            counters[1] += int(info.st_size)
            if counters[1] > limits["output_bytes"]:
                _fail("OUTPUT_BYTE_LIMIT_EXCEEDED")
            child = os.open(name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            try:
                digest = hashlib.sha256()
                offset = 0
                while offset < info.st_size:
                    block = os.pread(child, min(1024 * 1024, info.st_size - offset), offset)
                    if not block:
                        _fail("OUTPUT_SHORT_READ", relative)
                    digest.update(block)
                    offset += len(block)
            finally:
                os.close(child)
            rows.append({"kind": "FILE", "mode": stat.S_IMODE(info.st_mode), "path": relative, "sha256": digest.hexdigest(), "size": int(info.st_size)})
        else:
            rows.append({"kind": "DIRECTORY", "mode": stat.S_IMODE(info.st_mode), "path": relative, "size": 0})
            child = os.open(name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0), dir_fd=fd)
            try:
                _manifest_directory(child, relative, rows, counters, limits)
            finally:
                os.close(child)


def _output_manifest(observations: dict[str, dict[str, Any]], limits: dict[str, int]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    counters = [0, 0]
    for role in sorted(_WRITABLE_ROLES & observations.keys()):
        role_rows: list[dict[str, Any]] = []
        _manifest_directory(observations[role]["fd"], "", role_rows, counters, limits)
        rows.append({"entries": role_rows, "role": role})
    return {"byte_count": counters[1], "file_count": counters[0], "sha256": _sha(canonical_bytes(rows))}


def _projection_payload(raw: str) -> dict[str, Any]:
    """Validate the caller-visible projection preimage before any mutation."""

    try:
        value = json.loads(raw.encode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SpecializedToolWorkerError("PROJECTION_PAYLOAD_INVALID") from exc
    keys = frozenset(
        {
            "dependency_materialization_receipt",
            "original_source_scope_sha256",
            "run_id",
            "schema",
        }
    )
    _exact_object(value, keys, "PROJECTION_PAYLOAD_INVALID")
    if canonical_bytes(value) != raw.encode("ascii"):
        _fail("PROJECTION_PAYLOAD_NOT_CANONICAL")
    if value.get("schema") != "plamen.evm-analysis-projection-native-request.v1":
        _fail("PROJECTION_PAYLOAD_SCHEMA_INVALID")
    if type(value.get("run_id")) is not str or _SAFE_ID.fullmatch(value["run_id"]) is None:
        _fail("PROJECTION_RUN_ID_INVALID")
    _hex(value.get("original_source_scope_sha256"), "PROJECTION_SOURCE_SCOPE_INVALID")
    receipt = value.get("dependency_materialization_receipt")
    if type(receipt) is not dict or receipt.get("schema") != (
        "plamen.js-dependency-materialization-receipt.v2"
    ):
        _fail("PROJECTION_DEPENDENCY_RECEIPT_INVALID")
    stored = receipt.get("receipt_sha256")
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    if _hex(stored, "PROJECTION_DEPENDENCY_RECEIPT_INVALID") != _sha(
        canonical_bytes(unsigned)
    ):
        _fail("PROJECTION_DEPENDENCY_RECEIPT_INVALID")
    lock = receipt.get("lock_selection_sha256")
    modules = receipt.get("modules_tree")
    if (
        _hex(lock, "PROJECTION_LOCK_SELECTION_INVALID") != lock
        or type(modules) is not dict
        or modules.get("algorithm") != "PLAMEN_CANONICAL_TREE_SHA256_V1"
        or _hex(modules.get("sha256"), "PROJECTION_MODULES_TREE_INVALID")
        != modules.get("sha256")
        or type(modules.get("entry_count")) is not int
        or type(modules.get("expanded_bytes")) is not int
    ):
        _fail("PROJECTION_DEPENDENCY_RECEIPT_INVALID")
    return value


def _projection_closure(fd: int) -> dict[str, Any]:
    """Render the EVM workspace closure denominator through a held fd."""

    stream = hashlib.sha256()
    counts = {"files": 0, "directories": 0, "bytes": 0}

    def add(row: dict[str, Any]) -> None:
        raw = canonical_bytes(row)
        stream.update(len(raw).to_bytes(8, "big"))
        stream.update(raw)

    def visit(directory_fd: int, parts: tuple[str, ...]) -> None:
        if len(parts) > 64:
            _fail("PROJECTION_DIRECTORY_DEPTH_EXCEEDED")
        for name in sorted(os.listdir(directory_fd)):
            if (
                type(name) is not str
                or name in {"", ".", ".."}
                or "/" in name
                or "\\" in name
                or "\x00" in name
            ):
                _fail("PROJECTION_NAME_INVALID")
            relative = "/".join((*parts, name))
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                _fail("PROJECTION_LINK_DENIED", relative)
            if stat.S_ISDIR(info.st_mode):
                counts["directories"] += 1
                if counts["directories"] > MAX_OUTPUT_FILES:
                    _fail("PROJECTION_DIRECTORY_LIMIT_EXCEEDED")
                add({"kind": "DIRECTORY", "mode": mode, "relative_path": relative})
                child = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=directory_fd,
                )
                try:
                    replay = os.fstat(child)
                    if (replay.st_dev, replay.st_ino) != (info.st_dev, info.st_ino):
                        _fail("PROJECTION_DIRECTORY_CHANGED", relative)
                    visit(child, (*parts, name))
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                counts["files"] += 1
                counts["bytes"] += int(info.st_size)
                if counts["files"] > MAX_OUTPUT_FILES or counts["bytes"] > MAX_OUTPUT_BYTES:
                    _fail("PROJECTION_OUTPUT_LIMIT_EXCEEDED")
                child = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                digest = hashlib.sha256()
                try:
                    offset = 0
                    while offset < info.st_size:
                        block = os.pread(child, min(1024 * 1024, info.st_size - offset), offset)
                        if not block:
                            _fail("PROJECTION_SHORT_READ", relative)
                        digest.update(block)
                        offset += len(block)
                    replay = os.fstat(child)
                    if (replay.st_dev, replay.st_ino, replay.st_size) != (
                        info.st_dev, info.st_ino, info.st_size
                    ):
                        _fail("PROJECTION_FILE_CHANGED", relative)
                finally:
                    os.close(child)
                add(
                    {
                        "kind": "FILE",
                        "mode": mode,
                        "relative_path": relative,
                        "sha256": digest.hexdigest(),
                        "size": int(info.st_size),
                    }
                )
            else:
                _fail("PROJECTION_SPECIAL_OR_HARDLINK_DENIED", relative)

    visit(fd, ())
    unsigned = {
        "byte_count": counts["bytes"],
        "directory_count": counts["directories"],
        "entry_stream_sha256": stream.hexdigest(),
        "file_count": counts["files"],
        "schema_version": "plamen.evm_dependency_content_closure.v1",
    }
    return {**unsigned, "closure_sha256": _sha(canonical_bytes(unsigned))}


def _copy_projection_tree(
    source_fd: int,
    destination_fd: int,
    *,
    reject_node_modules: bool,
) -> None:
    """Copy one immutable tree without resolving a host pathname."""

    for name in sorted(os.listdir(source_fd)):
        if (
            type(name) is not str
            or name in {"", ".", ".."}
            or "/" in name
            or "\\" in name
            or "\x00" in name
        ):
            _fail("PROJECTION_NAME_INVALID")
        if reject_node_modules and name == "node_modules":
            _fail("PROJECT_NODE_MODULES_PREEXISTING")
        info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            _fail("PROJECTION_LINK_DENIED", name)
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            os.mkdir(name, mode=mode, dir_fd=destination_fd)
            child_source = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0),
                dir_fd=source_fd,
            )
            child_destination = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0),
                dir_fd=destination_fd,
            )
            try:
                _copy_projection_tree(
                    child_source, child_destination, reject_node_modules=False
                )
            finally:
                os.close(child_destination)
                os.close(child_source)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            source = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_fd,
            )
            destination = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=destination_fd,
            )
            try:
                offset = 0
                while offset < info.st_size:
                    block = os.pread(source, min(1024 * 1024, info.st_size - offset), offset)
                    if not block:
                        _fail("PROJECTION_SHORT_READ", name)
                    written = 0
                    while written < len(block):
                        amount = os.write(destination, block[written:])
                        if amount <= 0:
                            _fail("PROJECTION_SHORT_WRITE", name)
                        written += amount
                    offset += len(block)
                os.fsync(destination)
            finally:
                os.close(destination)
                os.close(source)
        else:
            _fail("PROJECTION_SPECIAL_OR_HARDLINK_DENIED", name)


def _materialize_evm_projection(
    request: dict[str, Any], observations: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Create a fresh, out-of-tree project + dependency projection."""

    payload = _projection_payload(request["method_payload_ascii"])
    project_fd = observations["project"]["fd"]
    modules_fd = observations["source"]["fd"]
    scratch_fd = observations["scratch"]["fd"]
    state_fd = observations["state"]["fd"]
    receipt = payload["dependency_materialization_receipt"]
    if os.listdir(scratch_fd):
        _fail("PROJECTION_SCRATCH_NOT_EMPTY")
    if os.listdir(state_fd):
        _fail("PROJECTION_STATE_NOT_EMPTY")
    modules_manifest_rows: list[dict[str, Any]] = []
    modules_manifest_counts = [0, 0]
    _manifest_directory(
        modules_fd, "", modules_manifest_rows, modules_manifest_counts, request["limits"]
    )
    modules_tree = receipt["modules_tree"]
    if (
        _sha(canonical_bytes(modules_manifest_rows)) != modules_tree["sha256"]
        or modules_manifest_counts[0] != modules_tree["entry_count"]
        or modules_manifest_counts[1] != modules_tree["expanded_bytes"]
    ):
        _fail("PROJECTION_MODULES_RECEIPT_MISMATCH")
    os.mkdir("analysis-workspace", mode=0o700, dir_fd=scratch_fd)
    workspace_fd = os.open(
        "analysis-workspace",
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0),
        dir_fd=scratch_fd,
    )
    try:
        _copy_projection_tree(project_fd, workspace_fd, reject_node_modules=True)
        source_closure = _projection_closure(workspace_fd)
        os.mkdir("node_modules", mode=0o700, dir_fd=workspace_fd)
        projected_modules_fd = os.open(
            "node_modules",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0),
            dir_fd=workspace_fd,
        )
        try:
            _copy_projection_tree(
                modules_fd, projected_modules_fd, reject_node_modules=False
            )
            modules_closure = _projection_closure(projected_modules_fd)
        finally:
            os.close(projected_modules_fd)
        workspace_closure = _projection_closure(workspace_fd)
    finally:
        os.close(workspace_fd)
    observation = {
        "analysis_workspace": workspace_closure,
        "dependency_materialization_receipt_sha256": receipt["receipt_sha256"],
        "js_lock_selection_sha256": receipt["lock_selection_sha256"],
        "materialized_node_modules": modules_closure,
        "original_source_scope_sha256": payload["original_source_scope_sha256"],
        "schema": "plamen.evm-analysis-projection-worker-observation.v1",
        "source_copy": source_closure,
        "workspace_relative_path": "analysis-workspace",
    }
    lineage_id = f"projection-{request['request_sha256'][:32]}"
    source_snapshot = {
        "schema": "plamen.audit-source-snapshot-binding.v1",
        "snapshot_sha256": payload["original_source_scope_sha256"],
        "source_scope_sha256": payload["original_source_scope_sha256"],
    }
    private_projection = {
        "schema": "plamen.private-source-projection.v1",
        "lineage_id": lineage_id,
        "source_snapshot_sha256": payload["original_source_scope_sha256"],
        "descriptor_sha256": _sha(canonical_bytes({
            "closure_sha256": workspace_closure["closure_sha256"],
            "role": "apple-contained-analysis-workspace",
        })),
        "tree_sha256": workspace_closure["closure_sha256"],
        "read_only": True,
    }
    dependencies = {
        "schema": "plamen.evm-dependency-materialization-native.v1",
        "lineage_id": lineage_id,
        "build_system": "hardhat",
        "provider_receipt_schema": (
            "plamen.js-dependency-materialization-receipt.v2"
        ),
        "provider_receipt_sha256": receipt["receipt_sha256"],
        "closure_sha256": modules_closure["closure_sha256"],
        "complete": True,
    }
    compiler_provider_receipt = _sha(canonical_bytes({
        "domain": "PLAMEN-MANAGED-EVM-COMPILER-ADMISSION-V1",
        "runtime_closure_sha256": request["runtime_closure_sha256"],
        "solc_sha256": request["projection_solc_sha256"],
        "solc_size": request["projection_solc_size"],
    }))
    compiler = {
        "schema": "plamen.solc-materialization-native.v1",
        "lineage_id": lineage_id,
        "provider_receipt_schema": (
            "plamen.managed-evm-python-native-admission.v1"
        ),
        "provider_receipt_sha256": compiler_provider_receipt,
        "version": "0.8.26",
        "artifact_sha256": request["projection_solc_sha256"],
        "artifact_bytes": request["projection_solc_size"],
        "complete": True,
    }
    guest_mount = {
        "schema": "plamen.guest-read-only-mount.v1",
        "lineage_id": lineage_id,
        "mount_id": "project",
        "guest_path": "/workspace/project",
        "source_projection_sha256": workspace_closure["closure_sha256"],
        "read_only": True,
    }
    native_request = {
        "schema": "plamen.native-materialization-request.v1",
        "lineage_id": lineage_id,
        "build_system": "hardhat",
        "source_snapshot": source_snapshot,
        "private_source_projection": private_projection,
        "dependencies": dependencies,
        "compiler": compiler,
        "guest_mount": guest_mount,
    }
    native_request_sha256 = _sha(canonical_bytes(native_request))
    terminal_basis = {
        "native_request_sha256": native_request_sha256,
        "projection_worker_request_sha256": request["request_sha256"],
        "workspace_closure_sha256": workspace_closure["closure_sha256"],
    }
    lineage = {
        "schema": "plamen.evm-tool-materialization-lineage.v2",
        "lineage_id": lineage_id,
        "build_system": "hardhat",
        "source_snapshot": source_snapshot,
        "private_source_projection": private_projection,
        "dependencies": dependencies,
        "compiler": compiler,
        "guest_mount": guest_mount,
        "native_materialization_terminal": {
            "schema": "plamen.native-materialization-terminal.v1",
            "lineage_id": lineage_id,
            "request_sha256": native_request_sha256,
            "terminal_sha256": _sha(canonical_bytes(terminal_basis)),
            "complete": True,
        },
    }
    lineage_raw = canonical_bytes(lineage)
    observation["materialization_lineage_byte_count"] = len(lineage_raw)
    observation["materialization_lineage_sha256"] = _sha(lineage_raw)
    observation["native_materialization_request_sha256"] = (
        native_request_sha256
    )
    raw = canonical_bytes(observation)
    output = os.open(
        "projection-observation.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o400,
        dir_fd=state_fd,
    )
    try:
        _write_all(output, raw)
        os.fsync(output)
    finally:
        os.close(output)
    lineage_output = os.open(
        "materialization-lineage.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o400,
        dir_fd=state_fd,
    )
    try:
        _write_all(lineage_output, lineage_raw)
        os.fsync(lineage_output)
    finally:
        os.close(lineage_output)
    return observation


def _apple_payload_observation(fd: int, kind: str, limits: dict[str, int]) -> dict[str, Any]:
    info = os.fstat(fd)
    if kind in {"REGULAR_FILE", "IMAGE_MEMBER"}:
        if not stat.S_ISREG(info.st_mode):
            _fail("APPLE_MOUNT_PAYLOAD_KIND_MISMATCH")
        digest = hashlib.sha256()
        offset = 0
        while offset < info.st_size:
            block = os.pread(fd, min(1024 * 1024, info.st_size - offset), offset)
            if not block:
                _fail("APPLE_MOUNT_PAYLOAD_SHORT_READ")
            digest.update(block)
            offset += len(block)
        return {
            "payload_bytes": int(info.st_size),
            "payload_entries": 1,
            "payload_sha256": digest.hexdigest(),
        }
    if kind != "DIRECTORY" or not stat.S_ISDIR(info.st_mode):
        _fail("APPLE_MOUNT_PAYLOAD_KIND_MISMATCH")
    rows: list[dict[str, Any]] = []
    counters = [0, 0]
    _manifest_directory(fd, "", rows, counters, limits)
    return {
        "payload_bytes": counters[1],
        "payload_entries": counters[0],
        "payload_sha256": _sha(canonical_bytes(rows)),
    }


def _require_apple_mount_access(fd: int, access: str) -> None:
    try:
        readonly = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
    except OSError as exc:
        raise SpecializedToolWorkerError("FIXED_APPLE_MOUNT_ACCESS_UNOBSERVED") from exc
    if (access == "READ_ONLY") != readonly:
        _fail("FIXED_APPLE_MOUNT_ACCESS_MISMATCH")


def _parse_apple_attached_request(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_REQUEST_BYTES or raw.endswith(b"\n"):
        _fail("REQUEST_BYTES_INVALID")
    try:
        request = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SpecializedToolWorkerError("REQUEST_JSON_INVALID") from exc
    if type(request) is not dict:
        _fail("REQUEST_SCHEMA_INVALID")
    operation = request.get("operation")
    expected_keys = (
        _APPLE_MANAGED_REQUEST_KEYS
        if operation == "MANAGED_EVM_EXECUTE"
        else _APPLE_PROJECTION_REQUEST_KEYS
        if operation == _PROJECTION_OPERATION
        else _APPLE_JS_REQUEST_KEYS
        if operation in _JS_OPERATIONS
        else _APPLE_SLITHER_REQUEST_KEYS
        if operation == "SNAPSHOT_TOOL_EXECUTE"
        and request.get("tool_anchor_id") == "slither"
        else _APPLE_REQUEST_KEYS
    )
    _exact_object(request, expected_keys, "REQUEST_SCHEMA_INVALID")
    if raw != canonical_bytes(request) or request.get("schema") != APPLE_REQUEST_SCHEMA:
        _fail("REQUEST_NOT_EXACT_CANONICAL_JSON")
    stored = _hex(request.get("request_sha256"), "REQUEST_DIGEST_INVALID")
    unsigned = dict(request)
    unsigned.pop("request_sha256")
    if stored != _sha(canonical_bytes(unsigned)):
        _fail("REQUEST_DIGEST_INVALID")
    if type(request.get("request_id")) is not str or _SAFE_ID.fullmatch(request["request_id"]) is None:
        _fail("REQUEST_ID_INVALID")
    if operation not in _OPERATIONS:
        _fail("ONLINE_OR_UNSUPPORTED_OPERATION_DENIED")
    expected_network_mode = (
        "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST"
        if operation == "ONLINE_INSTALL" else "DENY_ALL"
    )
    if request.get("network_mode") != expected_network_mode:
        _fail("NETWORK_MODE_NOT_DENY_ALL")
    _hex(request.get("effects_binding_sha256"), "EFFECTS_BINDING_INVALID")
    _hex(request.get("worker_runtime_sha256"), "WORKER_RUNTIME_BINDING_INVALID")
    _hex(request.get("runtime_closure_sha256"), "RUNTIME_CLOSURE_BINDING_INVALID")
    anchor_id = request.get("tool_anchor_id")
    if type(anchor_id) is not str or anchor_id not in _APPLE_ANCHORS_BY_OPERATION[operation]:
        _fail("APPLE_TOOL_ANCHOR_UNAVAILABLE")
    if operation == "SNAPSHOT_TOOL_EXECUTE" and anchor_id == "slither":
        for dependency in ("forge", "python", "solc"):
            _hex(
                request.get(f"slither_{dependency}_sha256"),
                f"SLITHER_{dependency.upper()}_DIGEST_INVALID",
            )
            _bounded_int(
                request.get(f"slither_{dependency}_size"),
                MAX_OUTPUT_BYTES,
                f"SLITHER_{dependency.upper()}_SIZE_INVALID",
            )
        if _hex(
            request.get("slither_internal_environment_sha256"),
            "SLITHER_INTERNAL_ENVIRONMENT_DIGEST_INVALID",
        ) != SLITHER_INTERNAL_ENVIRONMENT_SHA256:
            _fail("SLITHER_INTERNAL_ENVIRONMENT_DIGEST_INVALID")
    if operation == _PROJECTION_OPERATION:
        _hex(
            request.get("projection_solc_sha256"),
            "PROJECTION_SOLC_DIGEST_INVALID",
        )
        _bounded_int(
            request.get("projection_solc_size"), MAX_OUTPUT_BYTES,
            "PROJECTION_SOLC_SIZE_INVALID",
        )
    if operation in _METHOD_PAYLOAD_OPERATIONS:
        payload = request.get("method_payload_ascii")
        if type(payload) is not str or not payload or len(payload) > MAX_REQUEST_BYTES:
            _fail("METHOD_PAYLOAD_INVALID")
        try:
            payload_bytes = payload.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SpecializedToolWorkerError("METHOD_PAYLOAD_INVALID") from exc
        if _hex(
            request.get("method_payload_sha256"),
            "METHOD_PAYLOAD_DIGEST_INVALID",
        ) != _sha(payload_bytes):
            _fail("METHOD_PAYLOAD_DIGEST_INVALID")
        if operation == "MANAGED_EVM_EXECUTE":
            _hex(
                request.get("managed_provisioner_sha256"),
                "MANAGED_PROVISIONER_DIGEST_INVALID",
            )
            _bounded_int(
                request.get("managed_provisioner_size"), MAX_REQUEST_BYTES,
                "MANAGED_PROVISIONER_SIZE_INVALID",
            )
        elif operation in _JS_OPERATIONS:
            _hex(
                request.get("js_offline_materializer_sha256"),
                "JS_MATERIALIZER_DIGEST_INVALID",
            )
            _bounded_int(
                request.get("js_offline_materializer_size"), MAX_REQUEST_BYTES,
                "JS_MATERIALIZER_SIZE_INVALID",
            )
        else:
            _projection_payload(payload)
    limits = _exact_object(request.get("limits"), _LIMIT_KEYS, "LIMITS_INVALID")
    _bounded_int(limits["duration_ms"], MAX_DURATION_MS, "DURATION_LIMIT_INVALID")
    _bounded_int(limits["memory_bytes"], MAX_MEMORY_BYTES, "MEMORY_LIMIT_INVALID")
    _bounded_int(limits["stdout_bytes"], MAX_STDOUT_BYTES, "STDOUT_LIMIT_INVALID")
    _bounded_int(limits["stderr_bytes"], MAX_STDERR_BYTES, "STDERR_LIMIT_INVALID")
    _bounded_int(limits["output_files"], MAX_OUTPUT_FILES, "OUTPUT_FILE_LIMIT_INVALID")
    _bounded_int(limits["output_bytes"], MAX_OUTPUT_BYTES, "OUTPUT_BYTE_LIMIT_INVALID")
    _bounded_int(limits["open_fds"], MAX_OPEN_FDS, "FD_LIMIT_INVALID", minimum=18)
    descriptors = _exact_object(
        request.get("descriptors"), frozenset(_ROLES), "DESCRIPTOR_ROSTER_INVALID"
    )
    required = _APPLE_REQUIRED_ROLES[operation]
    for role in _ROLES:
        row = descriptors[role]
        if row is None:
            if role in required:
                _fail("REQUIRED_DESCRIPTOR_ABSENT", role)
            continue
        _exact_object(row, _APPLE_DESCRIPTOR_KEYS, "APPLE_DESCRIPTOR_SCHEMA_INVALID")
        if row["access"] not in {"READ_ONLY", "READ_WRITE"}:
            _fail("DESCRIPTOR_ACCESS_INVALID", role)
        if role in _WRITABLE_ROLES:
            if row["access"] != "READ_WRITE" or row["kind"] != "DIRECTORY":
                _fail("WRITABLE_DESCRIPTOR_INVALID", role)
        elif row["access"] != "READ_ONLY":
            _fail("READ_ONLY_DESCRIPTOR_INVALID", role)
        if role == "tool" and row["kind"] != "IMAGE_MEMBER":
            _fail("APPLE_TOOL_PAYLOAD_NOT_REGULAR")
        if role != "tool" and row["kind"] == "IMAGE_MEMBER":
            _fail("IMAGE_MEMBER_ROLE_INVALID", role)
        if row["kind"] not in {"REGULAR_FILE", "DIRECTORY", "IMAGE_MEMBER"}:
            _fail("DESCRIPTOR_KIND_INVALID", role)
        _bounded_int(row["payload_entries"], MAX_OUTPUT_FILES, "APPLE_PAYLOAD_ENTRIES_INVALID", minimum=0)
        _bounded_int(row["payload_bytes"], MAX_OUTPUT_BYTES, "APPLE_PAYLOAD_BYTES_INVALID", minimum=0)
        _hex(row["payload_sha256"], "APPLE_PAYLOAD_DIGEST_INVALID")
    cwd = _exact_object(request.get("cwd"), frozenset({"relative", "role"}), "CWD_INVALID")
    if cwd.get("role") not in descriptors or descriptors[cwd["role"]] is None or descriptors[cwd["role"]]["kind"] != "DIRECTORY":
        _fail("CWD_DESCRIPTOR_INVALID")
    _safe_relative(cwd.get("relative"), "CWD_RELATIVE_INVALID", dot=True)
    if operation == _PROJECTION_OPERATION:
        if request.get("argv") != ["@fd:tool"]:
            _fail("AMBIENT_PATH_OR_NETWORK_TOKEN_DENIED")
        if request.get("environment") != []:
            _fail("AMBIENT_OR_LOADER_ENVIRONMENT_DENIED")
        if descriptors["source"]["kind"] != "DIRECTORY":
            _fail("DESCRIPTOR_KIND_MISMATCH", "source")
    # Exact argv/environment validation is replayed after fixed mounts become
    # internal retained descriptors.  No filesystem effect occurs before then.
    return request


def _initial_apple_fd_census() -> None:
    try:
        observed = {int(name, 10) for name in os.listdir("/proc/self/fd")}
    except (OSError, ValueError) as exc:
        raise SpecializedToolWorkerError("FD_CENSUS_UNAVAILABLE") from exc
    for descriptor in observed:
        if descriptor <= 2:
            continue
        try:
            os.fstat(descriptor)
        except OSError as exc:
            # procfs reports its transient enumeration descriptor, which is
            # already closed by the time listdir returns.
            if exc.errno == errno.EBADF:
                continue
            raise
        _fail("AMBIENT_DESCRIPTOR_PRESENT")


def _validate_apple_attached_stdio() -> None:
    identities: set[tuple[int, int]] = set()
    for descriptor in (0, 1, 2):
        if os.isatty(descriptor):
            _fail("ATTACHED_STDIO_TTY_DENIED")
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            raise SpecializedToolWorkerError("ATTACHED_STDIO_UNAVAILABLE") from exc
        if not (stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode)):
            _fail("ATTACHED_STDIO_KIND_INVALID")
        identity = (int(info.st_dev), int(info.st_ino))
        if identity in identities:
            _fail("ATTACHED_STDIO_ALIAS_DENIED")
        identities.add(identity)


def _open_fixed_apple_mounts(request: dict[str, Any]) -> list[int]:
    """Open fixed guest mount targets and remap them to ABI FDs 10..17."""
    path_by_role = dict(APPLE_MOUNT_ROLE_PATHS)
    anchor_by_id = dict(APPLE_TOOL_ANCHORS)
    target_by_role = dict(APPLE_INTERNAL_FDS)
    opened: dict[str, int] = {}
    duplicated: dict[str, int] = {}
    try:
        for role in _ROLES:
            row = request["descriptors"][role]
            if row is None:
                continue
            if role == "tool":
                path = anchor_by_id[request["tool_anchor_id"]]
            else:
                base = path_by_role[role]
                path = f"{base}/payload" if row["kind"] == "REGULAR_FILE" else base
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            if row["kind"] == "DIRECTORY":
                flags |= getattr(os, "O_DIRECTORY", 0)
            try:
                opened[role] = os.open(path, flags)
            except OSError as exc:
                raise SpecializedToolWorkerError("FIXED_APPLE_MOUNT_UNAVAILABLE", role) from exc
            _require_apple_mount_access(opened[role], row["access"])
            observation = _apple_payload_observation(opened[role], row["kind"], request["limits"])
            if any(observation[key] != row[key] for key in observation):
                _fail("FIXED_APPLE_MOUNT_PAYLOAD_MISMATCH", role)
        physical: set[tuple[int, int]] = set()
        for role, descriptor in opened.items():
            info = os.fstat(descriptor)
            identity = (int(info.st_dev), int(info.st_ino))
            if identity in physical:
                _fail("FIXED_APPLE_MOUNT_ALIAS_DENIED", role)
            physical.add(identity)
            duplicated[role] = fcntl.fcntl(
                descriptor, fcntl.F_DUPFD_CLOEXEC, 128
            )
        for descriptor in opened.values():
            os.close(descriptor)
        opened.clear()
        result: list[int] = []
        for role in _ROLES:
            if role not in duplicated:
                continue
            target = target_by_role[role]
            os.dup2(duplicated[role], target, inheritable=False)
            result.append(target)
        return result
    except BaseException:
        for descriptor in (*opened.values(), *duplicated.values()):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    finally:
        for descriptor in duplicated.values():
            try:
                os.close(descriptor)
            except OSError:
                pass


def execute_apple_attached_request(raw: bytes) -> bytes:
    """Execute an Apple attached-stdio request using only fixed guest mounts."""
    if fcntl is None or resource is None:
        raise SpecializedToolWorkerError("UNSUPPORTED_PLATFORM")
    request = _parse_apple_attached_request(raw)
    original_request_sha256 = request["request_sha256"]
    opened = _open_fixed_apple_mounts(request)
    target_by_role = dict(APPLE_INTERNAL_FDS)
    try:
        if request["operation"] == _PROJECTION_OPERATION:
            pre: dict[str, dict[str, Any]] = {}
            for role in _ROLES:
                row = request["descriptors"][role]
                if row is None:
                    continue
                descriptor_row = {
                    "access": row["access"],
                    "fd": target_by_role[role],
                    "identity_sha256": "0" * 64,
                    "kind": "REGULAR_FILE" if role == "tool" else row["kind"],
                }
                descriptor_row["identity_sha256"] = descriptor_identity(
                    role, descriptor_row["fd"], descriptor_row["kind"],
                    descriptor_row["access"],
                )
                pre[role] = _descriptor_observation(role, descriptor_row)
            started = time.monotonic_ns()
            projection = _materialize_evm_projection(request, pre)
            post: dict[str, dict[str, Any]] = {}
            for role, observation in sorted(pre.items()):
                replay_row = {
                    "access": observation["access"],
                    "fd": observation["fd"],
                    "identity_sha256": "0" * 64,
                    "kind": observation["kind"],
                }
                replay_row["identity_sha256"] = descriptor_identity(
                    role, replay_row["fd"], replay_row["kind"],
                    replay_row["access"],
                )
                post[role] = _descriptor_observation(role, replay_row)
            if any(
                pre[role]["identity_sha256"] != post[role]["identity_sha256"]
                for role in ("project", "source", "tool")
            ):
                _fail("READ_ONLY_DESCRIPTOR_CHANGED")
            empty = {
                "observed_bytes": 0,
                "retained_bytes": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
            terminal = {
                "descriptor_post": {
                    role: post[role]["identity_sha256"] for role in sorted(post)
                },
                "descriptor_pre": {
                    role: pre[role]["identity_sha256"] for role in sorted(pre)
                },
                "duration_ms": min(
                    MAX_DURATION_MS,
                    max(0, (time.monotonic_ns() - started) // 1_000_000),
                ),
                "effects_binding_sha256": request["effects_binding_sha256"],
                "host_authority_required": [
                    "HMAC_AUTHENTICATION", "MOUNT_RECENSUS",
                    "NETWORK_DENIAL", "POPULATION_ZERO",
                ],
                "network": {
                    "guest_observation": "NATIVE_PROVIDER_EVIDENCE_REQUIRED",
                    "mode": "DENY_ALL",
                    "observed_egress_sha256": EMPTY_LIST_SHA256,
                },
                "operation": request["operation"],
                "output_manifest": _output_manifest(post, request["limits"]),
                "peak_memory_bytes": 0,
                "process_group_kill_issued": False,
                "projection_observation_sha256": _sha(
                    canonical_bytes(projection)
                ),
                "request_id": request["request_id"],
                "request_sha256": request["request_sha256"],
                "returncode": 0,
                "schema": APPLE_TERMINAL_SCHEMA,
                "status": "COMPLETE",
                "stderr": empty,
                "stdout": empty,
                "worker_runtime_sha256": request["worker_runtime_sha256"],
                "apple_mount_payload_sha256": _sha(
                    canonical_bytes(request["descriptors"])
                ),
                "method_payload_sha256": request["method_payload_sha256"],
                "projection_solc_sha256": request["projection_solc_sha256"],
                "projection_solc_size": request["projection_solc_size"],
                "runtime_closure_sha256": request["runtime_closure_sha256"],
                "tool_anchor_id": request["tool_anchor_id"],
                "tool_image_member_sha256": request["descriptors"]["tool"][
                    "payload_sha256"
                ],
            }
            result = canonical_bytes(terminal)
            if len(result) > MAX_RESPONSE_BYTES:
                _fail("TERMINAL_BYTES_EXCEEDED")
            return result
        internal = dict(request)
        internal["schema"] = REQUEST_SCHEMA
        internal.pop("runtime_closure_sha256")
        internal.pop("tool_anchor_id")
        for key in (
            "managed_provisioner_sha256", "managed_provisioner_size",
            "js_offline_materializer_sha256", "js_offline_materializer_size",
            "method_payload_ascii", "method_payload_sha256",
            "slither_forge_sha256", "slither_forge_size",
            "slither_internal_environment_sha256",
            "slither_python_sha256", "slither_python_size",
            "slither_solc_sha256", "slither_solc_size",
        ):
            internal.pop(key, None)
        descriptors: dict[str, Any] = {}
        for role in _ROLES:
            apple_row = request["descriptors"][role]
            if apple_row is None:
                descriptors[role] = None
                continue
            fd = target_by_role[role]
            descriptors[role] = {
                "access": apple_row["access"],
                "fd": fd,
                "identity_sha256": descriptor_identity(
                    role, fd, apple_row["kind"], apple_row["access"]
                ),
                "kind": apple_row["kind"],
            }
        internal["descriptors"] = descriptors
        unsigned = dict(internal)
        unsigned.pop("request_sha256")
        internal["request_sha256"] = _sha(canonical_bytes(unsigned))
        terminal = json.loads(execute_request(
            canonical_bytes(internal),
            _apple_attached_token=_APPLE_ATTACHED_REQUEST_TOKEN,
            _internal_environment_token=(
                _SLITHER_INTERNAL_ENVIRONMENT_TOKEN
                if request["operation"] == "SNAPSHOT_TOOL_EXECUTE"
                and request["tool_anchor_id"] == "slither"
                else None
            ),
        ))
        terminal["request_sha256"] = original_request_sha256
        terminal["schema"] = APPLE_TERMINAL_SCHEMA
        terminal["apple_mount_payload_sha256"] = _sha(
            canonical_bytes(request["descriptors"])
        )
        terminal["runtime_closure_sha256"] = request["runtime_closure_sha256"]
        terminal["tool_anchor_id"] = request["tool_anchor_id"]
        terminal["tool_image_member_sha256"] = request["descriptors"]["tool"][
            "payload_sha256"
        ]
        if request["operation"] in _METHOD_PAYLOAD_OPERATIONS:
            terminal["method_payload_sha256"] = request[
                "method_payload_sha256"
            ]
        if request["operation"] == "MANAGED_EVM_EXECUTE":
            terminal["managed_provisioner_sha256"] = request[
                "managed_provisioner_sha256"
            ]
            terminal["managed_provisioner_size"] = request[
                "managed_provisioner_size"
            ]
        elif request["operation"] in _JS_OPERATIONS:
            terminal["js_offline_materializer_sha256"] = request[
                "js_offline_materializer_sha256"
            ]
            terminal["js_offline_materializer_size"] = request[
                "js_offline_materializer_size"
            ]
        elif (
            request["operation"] == "SNAPSHOT_TOOL_EXECUTE"
            and request["tool_anchor_id"] == "slither"
        ):
            for key in (
                "slither_forge_sha256", "slither_forge_size",
                "slither_internal_environment_sha256",
                "slither_python_sha256", "slither_python_size",
                "slither_solc_sha256", "slither_solc_size",
            ):
                terminal[key] = request[key]
        result = canonical_bytes(terminal)
        if len(result) > MAX_RESPONSE_BYTES:
            _fail("TERMINAL_BYTES_EXCEEDED")
        return result
    finally:
        for descriptor in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass


def execute_request(
    raw: bytes, *, _apple_attached_token: object | None = None,
    _internal_environment_token: object | None = None,
) -> bytes:
    """Validate and execute one request, returning canonical no-LF evidence."""
    if fcntl is None or resource is None:
        raise SpecializedToolWorkerError("UNSUPPORTED_PLATFORM")
    request, pre = parse_request(
        raw, _apple_attached_token=_apple_attached_token
    )
    limits = request["limits"]
    argv = [_resolve_token(token, pre) if token.startswith("@fd:") else token for token in request["argv"]]
    environment = {
        key: _resolve_token(value, pre) if value.startswith("@fd:") else value
        for key, value in request["environment"]
    }
    if _internal_environment_token is not None:
        if _internal_environment_token is not _SLITHER_INTERNAL_ENVIRONMENT_TOKEN:
            _fail("INTERNAL_ENVIRONMENT_AUTHORITY_INVALID")
        for key, value in _SLITHER_INTERNAL_ENVIRONMENT:
            if key in environment:
                _fail("INTERNAL_ENVIRONMENT_COLLISION", key)
            environment[key] = (
                _resolve_token(value, pre) if value.startswith("@fd:") else value
            )
    cwd = _open_cwd(pre[request["cwd"]["role"]]["fd"], request["cwd"]["relative"])
    stdin_read, stdin_write = os.pipe()
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    os.close(stdin_write)
    started = time.monotonic_ns()
    if os.name == "posix":
        pid = os.fork()
    else:
        raise SpecializedToolWorkerError("UNSUPPORTED_PLATFORM")
    if pid == 0:
        try:
            os.setsid()
            os.dup2(stdin_read, 0)
            os.dup2(stdout_write, 1)
            os.dup2(stderr_write, 2)
            os.fchdir(cwd)
            for observation in pre.values():
                os.set_inheritable(observation["fd"], True)
            _close_unlisted_fds({0, 1, 2, *(item["fd"] for item in pre.values())})
            _apply_limits(limits)
            os.execve(argv[0], argv, environment)
        except BaseException as exc:
            message = f"guest exec failed:{type(exc).__name__}:{getattr(exc, 'errno', 0) or 0}".encode("ascii", "replace")
            try:
                os.write(2, message[:4096])
            finally:
                os._exit(126)
    os.close(stdin_read)
    os.close(stdout_write)
    os.close(stderr_write)
    os.close(cwd)
    selector = selectors.DefaultSelector()
    selector.register(stdout_read, selectors.EVENT_READ, "stdout")
    selector.register(stderr_read, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    observed = {"stdout": 0, "stderr": 0}
    status = "RUNNING"
    returncode: int | None = None
    usage = None
    termination_deadline: int | None = None
    deadline = started + limits["duration_ms"] * 1_000_000
    try:
        while selector.get_map():
            now = time.monotonic_ns()
            if status == "RUNNING" and now >= deadline:
                status = "TIMED_OUT"
                termination_deadline = now + 1_000_000_000
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if termination_deadline is not None and now >= termination_deadline:
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fd)
                    os.close(key.fd)
                break
            events = selector.select(0.05)
            for key, _mask in events:
                try:
                    block = os.read(key.fd, 65536)
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    raise
                if not block:
                    selector.unregister(key.fd)
                    os.close(key.fd)
                    continue
                name = key.data
                observed[name] += len(block)
                digests[name].update(block)
                ceiling = limits[f"{name}_bytes"]
                room = max(0, ceiling - len(buffers[name]))
                buffers[name].extend(block[:room])
                if observed[name] > ceiling and status == "RUNNING":
                    status = "OUTPUT_LIMIT_EXCEEDED"
                    termination_deadline = time.monotonic_ns() + 1_000_000_000
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if returncode is None:
                waited, wait_status, usage_now = os.wait4(pid, os.WNOHANG)
                if waited == pid:
                    returncode = os.waitstatus_to_exitcode(wait_status)
                    usage = usage_now
                    if status == "RUNNING":
                        status = "COMPLETE" if returncode == 0 else "FAILED"
                    termination_deadline = time.monotonic_ns() + 1_000_000_000
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        if returncode is None:
            _waited, wait_status, usage = os.wait4(pid, 0)
            returncode = os.waitstatus_to_exitcode(wait_status)
            if status == "RUNNING":
                status = "COMPLETE" if returncode == 0 else "FAILED"
    finally:
        selector.close()
        for fd in (stdout_read, stderr_read):
            try:
                os.close(fd)
            except OSError:
                pass
    ended = time.monotonic_ns()
    post = {role: _descriptor_observation(role, request["descriptors"][role]) for role in sorted(pre)}
    stable_read_only = all(
        pre[role]["identity_sha256"] == post[role]["identity_sha256"]
        for role in pre if request["descriptors"][role]["access"] == "READ_ONLY"
    )
    try:
        output_manifest = _output_manifest(post, limits)
    except SpecializedToolWorkerError as exc:
        status = exc.code
        output_manifest = {"byte_count": 0, "file_count": 0, "sha256": "0" * 64}
    peak = 0 if usage is None else int(usage.ru_maxrss) * (1 if sys.platform == "darwin" else 1024)
    terminal = {
        "descriptor_post": {role: post[role]["identity_sha256"] for role in sorted(post)},
        "descriptor_pre": {role: pre[role]["identity_sha256"] for role in sorted(pre)},
        "duration_ms": min(MAX_DURATION_MS, max(0, (ended - started) // 1_000_000)),
        "effects_binding_sha256": request["effects_binding_sha256"],
        "host_authority_required": ["HMAC_AUTHENTICATION", "MOUNT_RECENSUS", "NETWORK_DENIAL", "POPULATION_ZERO"],
        "network": {"guest_observation": "NATIVE_PROVIDER_EVIDENCE_REQUIRED", "mode": "DENY_ALL", "observed_egress_sha256": EMPTY_LIST_SHA256},
        "operation": request["operation"],
        "output_manifest": output_manifest,
        "peak_memory_bytes": peak,
        "process_group_kill_issued": True,
        "request_id": request["request_id"],
        "request_sha256": request["request_sha256"],
        "returncode": returncode,
        "schema": TERMINAL_SCHEMA,
        "status": status if stable_read_only else "READ_ONLY_DESCRIPTOR_CHANGED",
        "stderr": {"observed_bytes": observed["stderr"], "retained_bytes": len(buffers["stderr"]), "sha256": digests["stderr"].hexdigest()},
        "stdout": {"observed_bytes": observed["stdout"], "retained_bytes": len(buffers["stdout"]), "sha256": digests["stdout"].hexdigest()},
        "worker_runtime_sha256": request["worker_runtime_sha256"],
    }
    result = canonical_bytes(terminal)
    if len(result) > MAX_RESPONSE_BYTES:
        _fail("TERMINAL_BYTES_EXCEEDED")
    return result


def _read_all(fd: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(fd, min(65536, maximum + 1 - total))
        if not block:
            return b"".join(chunks)
        chunks.append(block)
        total += len(block)
        if total > maximum:
            _fail("REQUEST_BYTES_INVALID")


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            _fail("RESPONSE_WRITE_FAILED")
        offset += written


def serve_once(request_fd: int, response_fd: int) -> int:
    """Serve one native-provided request/response descriptor pair."""
    if fcntl is None or resource is None:
        raise SpecializedToolWorkerError("UNSUPPORTED_PLATFORM")
    if type(request_fd) is not int or type(response_fd) is not int or request_fd < 3 or response_fd < 3 or request_fd == response_fd:
        _fail("CONTROL_DESCRIPTOR_INVALID")
    raw = b""
    try:
        raw = _read_all(request_fd, MAX_REQUEST_BYTES)
        response = execute_request(raw)
        code = 0
    except SpecializedToolWorkerError as exc:
        response = canonical_bytes({
            "code": exc.code,
            "request_bytes_sha256": _sha(raw),
            "schema": REJECTION_SCHEMA,
        })
        code = 2
    _write_all(response_fd, response)
    return code


def serve_apple_attached_stdio_v1() -> int:
    """Serve exactly one Apple Container attached stdin/stdout transaction."""
    if fcntl is None or resource is None:
        raise SpecializedToolWorkerError("UNSUPPORTED_PLATFORM")
    raw = b""
    try:
        _validate_apple_attached_stdio()
        _initial_apple_fd_census()
        raw = _read_all(0, MAX_REQUEST_BYTES)
        response = execute_apple_attached_request(raw)
        code = 0
    except SpecializedToolWorkerError as exc:
        response = canonical_bytes({
            "code": exc.code,
            "request_bytes_sha256": _sha(raw),
            "schema": REJECTION_SCHEMA,
        })
        code = 2
    _write_all(1, response)
    return code


def main(argv: list[str] | None = None) -> int:
    """Accept only symbolic control-FD arguments; never inspect ambient state."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--apple-attached-stdio-v1"]:
        return serve_apple_attached_stdio_v1()
    if len(args) != 4 or args[0] != "--request-fd" or args[2] != "--response-fd":
        return 64
    try:
        request_fd = int(args[1], 10)
        response_fd = int(args[3], 10)
    except ValueError:
        return 64
    return serve_once(request_fd, response_fd)


if __name__ == "__main__":
    raise SystemExit(main())
