"""Content-bound audit snapshots for safe deterministic resume.

The checkpoint says *where* execution stopped.  This module records *what* was
being audited and which methodology/tool implementation produced the evidence.
It deliberately has no dependency on the driver or checkpoint classes so the
snapshot can be built and tested before phase orchestration starts.
"""

from __future__ import annotations

import atexit
from dataclasses import dataclass
from contextlib import contextmanager, nullcontext
import csv
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import tomllib
from typing import Any, Callable, Iterable, Mapping
import uuid
from urllib.parse import urljoin, urlparse

from owned_process_runner import run_owned_process
from plamen_types import (
    ALL_AUDIT_SOURCE_SUFFIXES,
    L1_SOURCE_SUFFIXES,
    SOURCE_SUFFIXES_BY_ECOSYSTEM,
    normalize_scope_match_mode,
    validate_exact_scope_authority,
)
from production_source_scope import is_production_source_path
import toolchain_control_authority as _toolchain_controls

SNAPSHOT_SCHEMA = "plamen.audit-input-snapshot.v1"
RUNTIME_TOOL_IDENTITY_SCHEMA = "plamen.runtime-tool-identity.v2"
TOOLCHAIN_VERSION_LOCK_SCHEMA = "plamen.toolchain_version_lock.v1"
TOOLCHAIN_GOVERNANCE_SCHEMA = "plamen.toolchain_governance.v1"
NEW = "NEW"
MATCH = "MATCH"
MISMATCH = "MISMATCH"
LEGACY_UNBOUND = "LEGACY_UNBOUND"

_COMPONENTS = ("source_scope", "audit_config", "methodology", "toolchain")
_SOURCE_SUFFIXES = SOURCE_SUFFIXES_BY_ECOSYSTEM
_L1_SOURCE_SUFFIXES = L1_SOURCE_SUFFIXES
_ALL_SOURCE_SUFFIXES = ALL_AUDIT_SOURCE_SUFFIXES
_MANIFEST_NAMES = {
    ".gitmodules",
    "Anchor.toml",
    "Cargo.lock",
    "Cargo.toml",
    "Move.lock",
    "Move.toml",
    "Scarb.lock",
    "Scarb.toml",
    "daml.yaml",
    "foundry.toml",
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "hardhat.config.js",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
    "hardhat.config.ts",
    "bun.lockb",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "package.json",
    "pnpm-lock.yaml",
    "remappings.txt",
    "rust-toolchain",
    "rust-toolchain.toml",
    "soldeer.lock",
    "yarn.lock",
}
_MANIFEST_SKIP_DIRS = {
    ".git",
    ".scratchpad",
    ".plamen",
    "artifacts",
    "cache",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
}
_PROJECT_CONTEXT_SKIP_DIRS = _MANIFEST_SKIP_DIRS | {
    ".medusa-tests",
    "__pycache__",
    "build",
    "downloads",
    "generated",
    ".plamen-audit-inputs",
    "vendor",
}
_COMPILED_DEPENDENCY_SKIP_DIRS = frozenset(
    {".git", ".cache", "target", "out", "artifacts"}
)
_COMPILED_DEPENDENCY_SKIP_DIRS_CASEFOLD = frozenset(
    item.casefold() for item in _COMPILED_DEPENDENCY_SKIP_DIRS
)
_GENERATED_VERIFIER_DIRS = {
    ".plamen-poc",
    "cache-poc",
    "cache_poc",
    "cache_test",
    "out-poc",
    "out_poc",
    "out_test",
}
_GENERATED_AUDIT_NAME_RE = re.compile(
    r"(?:^|[_\-.])(?:poc|exploit|verify|audit[_-]?report|fuzz[_-]?corpus)"
    r"(?:[_\-.]|$)",
    re.IGNORECASE,
)


def _name_in_set(name: str, values: set[str]) -> bool:
    if os.name == "nt":
        return name.casefold() in {item.casefold() for item in values}
    return name in values


def _is_descendant_or_equal(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _resolved_path_identity(path: Path) -> str:
    """Return the platform-canonical identity used for resolved root sets."""

    return os.path.normcase(os.path.normpath(str(path.resolve())))


def _is_compiled_dependency_skip_dir(name: str) -> bool:
    """Mirror the compiled-dependency walk's exact directory filter."""

    if os.name == "nt":
        return name.casefold() in _COMPILED_DEPENDENCY_SKIP_DIRS_CASEFOLD
    return name in _COMPILED_DEPENDENCY_SKIP_DIRS


def _compiled_dependency_walk_reaches(
    ancestor: Path,
    descendant: Path,
) -> bool:
    """Prove that the ancestor dependency walk visits ``descendant``.

    Lexical ancestry is insufficient: the compiled dependency walker prunes
    generated/cache directory names.  An explicitly declared root below such
    a component remains a distinct authority because a walk beginning at that
    root can bind bytes which the outer walk deliberately never reaches.
    """

    resolved_ancestor = ancestor.resolve()
    resolved_descendant = descendant.resolve()
    if _resolved_path_identity(resolved_ancestor) == _resolved_path_identity(
        resolved_descendant
    ):
        return True
    try:
        relative = resolved_descendant.relative_to(resolved_ancestor)
    except ValueError:
        return False
    return not any(
        _is_compiled_dependency_skip_dir(part) for part in relative.parts
    )


def _directory_has_production_source(directory: Path) -> bool:
    """Return whether a conventional output root also contains real source.

    Directory names are only a weak convention.  A user-owned ``out_test``
    containing ``Bridge.sol`` remains an audited input, while compiler JSON and
    generated ``*.t.sol`` harnesses remain mutable evidence output.  The walk
    is bounded by the same fail-closed project inventory ceiling.
    """
    seen = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [
            name for name in dirnames
            if not _name_in_set(name, _PROJECT_CONTEXT_SKIP_DIRS)
            and not name.startswith(".")
        ]
        for name in filenames:
            seen += 1
            if seen > _MAX_EXTERNAL_INPUT_FILES:
                raise SnapshotInputError(
                    "conventional generated directory exceeds the bounded "
                    "file-count limit; declare a smaller immutable input root"
                )
            path = Path(dirpath) / name
            if path.suffix.lower() not in _ALL_SOURCE_SUFFIXES:
                continue
            if is_production_source_path(path, directory):
                return True
    return False


def _is_project_context_skip_dir(name: str, directory: Path | None = None) -> bool:
    """Classify exact conventional generated/build directories.

    Verifiers may select an isolated Foundry/Cargo output directory (for
    example ``out_test``) so concurrent PoC builds do not collide.  Such
    compiler outputs are mutable evidence products, not immutable audit
    inputs.  The allowlist is intentionally exact: names such as ``outbound``,
    ``target_protocol``, or ``cache_manager`` remain audited inputs.
    """
    # Every Plamen run directory is mutable evidence, including distinct clean
    # destinations such as ``.scratchpad-plamen-e2e-...``.  Binding one into
    # its own immutable project snapshot creates a self-referential snapshot
    # that drifts as soon as the checkpoint/log is written.
    if name.casefold().startswith(".scratchpad"):
        return True
    if _name_in_set(name, _PROJECT_CONTEXT_SKIP_DIRS):
        return True
    if not _name_in_set(name, _GENERATED_VERIFIER_DIRS):
        return False
    # A conventional verifier name is not proof of ownership.  When it holds
    # production source, retain the directory and filter generated siblings at
    # file level instead of hiding the source tree wholesale.
    return directory is None or not _directory_has_production_source(directory)
_METHODOLOGY_DIRS = (
    "agents",
    "architecture",
    "benchmarks",
    "commands",
    "methodology",
    "prompts",
    "rules",
    "skills",
    "plamen_l1",
    "codex-adapter/commands",
    "codex-adapter/skills",
    "verification_policy",
)
_TOOLCHAIN_DIRS = (
    ".github",
    "hooks",
    "scripts",
    "custom-mcp",
    "mcp-packages",
    "opengrep-rules",
)
_TOOLCHAIN_ROOT_FILES = (
    ".plamen-manifest.json",
    "VERSION",
    "plamen",
    "plamen.bat",
    "plamen.py",
    "plamen.sh",
    "pyproject.toml",
    "requirements-ci.lock",
    "requirements.txt",
    "requirements-dev.txt",
)
_TOOLCHAIN_VERSION_LOCK_PATH = (
    Path(__file__).resolve().parent.parent
    / "verification_policy"
    / "toolchain_version_lock.v1.json"
)
_TOOLCHAIN_GOVERNANCE_PATH = (
    Path(__file__).resolve().parent.parent
    / "verification_policy"
    / "toolchain_governance.v1.json"
)
_SCIP_PROTOBUF_GENERATED_PATH = (
    Path(__file__).resolve().parent.parent / "plamen_l1" / "scip_pb2.py"
)
_RUNTIME_CONFIG_KEYS = {
    "scratchpad",
    "fresh",
    "fresh_restart",
    "resume",
    "hibernate",
}
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_HEAD_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SCOPE_PATH_RE = re.compile(
    r"(?P<path>(?:(?:[A-Za-z]:)?[\\/])?"
    r"(?:[A-Za-z0-9_@.+*?\[\]-]+[\\/])*"
    r"[A-Za-z0-9_@.+*?\[\]-]+\.(?:sol|vy|rs|go|move|daml|proto))"
    r"(?::L?\d+(?:[-:]\d+)?)?",
    re.IGNORECASE,
)
_MAX_EXTERNAL_INPUT_FILES = 20_000
_MAX_EXTERNAL_INPUT_BYTES = 2 * 1024 * 1024 * 1024
_MAX_REMOTE_DOCUMENTS = 32
_MAX_REMOTE_DOCUMENT_BYTES = 64 * 1024 * 1024
_NAT64_TRANSITION_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
_MAX_SNAPSHOT_FILES = 100_000
_MAX_RUNTIME_ENTRY_MANIFEST_ITEMS = 128
_MAX_RUNTIME_ENTRY_IDENTITY_BYTES = 512
_MAX_STABLE_READ_RETRIES = 3
_ARCHIVE_ROOT_NAME = ".plamen-stale-snapshots"
_ARCHIVE_LOCK_NAME = ".plamen-snapshot-startup.lock"
_ARCHIVE_INTENT_NAME = ".plamen-snapshot-archive-intent.json"
_SCRATCHPAD_OWNER_NAME = ".plamen-scratchpad-owner.json"
_BACKEND_RUNTIME_CONTRACT_NAME = "backend_runtime_contract.json"
_BACKEND_RUNTIME_CONTRACT_SCHEMA = "plamen.backend-runtime-contract.v1"
_BACKEND_RUNTIME_MAX_FILE_BYTES = 1024 * 1024
_BACKEND_RUNTIME_CANDIDATES: dict[str, tuple[str, ...]] = {
    # Claude Code may create this scheduler lock after a Task call. Stable
    # project controls beside it (CLAUDE.md/settings.json) are deliberately not
    # listed and remain content-bound audit inputs.
    "claude": (".claude/scheduled_tasks.lock",),
}

_SEMANTIC_ENV_PREFIXES = (
    "PLAMEN_",
    "FOUNDRY_",
    "HARDHAT_",
    "CARGO_",
    "RUST",
    "GO",
    "APTOS_",
    "SUI_",
    "STELLAR_",
    "SOLANA_",
)
_OPERATIONAL_ENV_KEYS = {
    "PLAMEN_NO_HIBERNATE",
    "PLAMEN_LOG_LEVEL",
    "PLAMEN_PROGRESS_INTERVAL",
}
# Kept as a compatibility-visible empty mapping for older tests/importers.
# Runtime executable fingerprints deliberately never consult or populate it:
# path stat tuples are not a stable content protocol across snapshots.
_TOOL_FINGERPRINT_CACHE: dict[tuple[Any, ...], bytes] = {}
_PYTHON_PACKAGE_CACHE: dict[tuple[Any, ...], bytes] = {}
_TOOL_PROBE_DIAGNOSTICS: dict[str, str] = {}
_FILE_HASH_CACHE: dict[
    str, tuple[tuple[Any, ...], tuple[bytes, int]]
] = {}


class SnapshotInputError(RuntimeError):
    """The audited input universe could not be frozen without ambiguity."""


def _remote_document_policy(config: Mapping[str, Any]) -> tuple[bool, bool]:
    """Return explicit private-network and plaintext-HTTP opt-ins."""

    return (
        config.get("allow_private_document_urls") is True,
        config.get("allow_insecure_document_http") is True,
    )


def _validated_remote_document_target(
    url: str,
    *,
    allow_private: bool,
    allow_insecure_http: bool,
) -> tuple[tuple[str, ...], int]:
    """Validate a remote target and return the exact addresses safe to dial."""

    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise SnapshotInputError(
            f"remote documentation URL is malformed: {url}"
        ) from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise SnapshotInputError(
            f"remote documentation URL must use HTTP(S): {url}"
        )
    if scheme != "https" and not allow_insecure_http:
        raise SnapshotInputError(
            f"remote documentation URL must use HTTPS: {url}"
        )
    if parsed.username is not None or parsed.password is not None:
        raise SnapshotInputError(
            f"remote documentation URL must not contain credentials: {url}"
        )
    if parsed.fragment:
        raise SnapshotInputError(
            f"remote documentation URL must not contain a fragment: {url}"
        )
    hostname = parsed.hostname
    if not hostname:
        raise SnapshotInputError(
            f"remote documentation URL has no hostname: {url}"
        )
    hostname = hostname.rstrip(".")
    if not hostname:
        raise SnapshotInputError(
            f"remote documentation URL has no hostname: {url}"
        )
    effective_port = port or (443 if scheme == "https" else 80)
    if not 1 <= effective_port <= 65535:
        raise SnapshotInputError(
            f"remote documentation URL has an invalid port: {url}"
        )

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = (literal,)
    else:
        try:
            answers = socket.getaddrinfo(
                hostname,
                effective_port,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise SnapshotInputError(
                f"remote documentation hostname resolution failed: {url}"
            ) from exc
        resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for answer in answers:
            try:
                address = ipaddress.ip_address(str(answer[4][0]).split("%", 1)[0])
            except (IndexError, ValueError):
                continue
            if address not in resolved:
                resolved.append(address)
        if not resolved:
            raise SnapshotInputError(
                f"remote documentation hostname resolved to no IP address: {url}"
            )
        addresses = tuple(resolved)

    for address in addresses:
        if (
            not allow_private
            and isinstance(address, ipaddress.IPv6Address)
            and any(
                address in network
                for network in _NAT64_TRANSITION_NETWORKS
            )
        ):
            raise SnapshotInputError(
                "remote documentation hostname resolved to a private-capable "
                f"NAT64 transition address: {address}"
            )
        embedded_ipv4: list[ipaddress.IPv4Address] = []
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped is not None:
                embedded_ipv4.append(address.ipv4_mapped)
            if address.sixtofour is not None:
                embedded_ipv4.append(address.sixtofour)
            if address.teredo is not None:
                embedded_ipv4.extend(address.teredo)
        if (
            not allow_private
            and any(not embedded.is_global for embedded in embedded_ipv4)
        ):
            raise SnapshotInputError(
                "remote documentation hostname resolved through a private "
                f"or non-global transition address: {address}"
            )
        if address.is_unspecified or address.is_multicast:
            raise SnapshotInputError(
                "remote documentation hostname resolved to an unsafe "
                f"non-global address: {address}"
            )
        if not allow_private and not address.is_global:
            raise SnapshotInputError(
                "remote documentation hostname resolved to a private or "
                f"non-global address: {address}"
            )
    return tuple(str(address) for address in addresses), effective_port


def _request_remote_document_once(
    url: str,
    connect_addresses: tuple[str, ...],
    timeout_seconds: float,
) -> tuple[int, Mapping[str, str], bytes]:
    """Issue one GET to an already-validated, DNS-pinned target."""

    parsed = urlparse(url)
    hostname = str(parsed.hostname or "")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    target = parsed.path or "/"
    if parsed.params:
        target += f";{parsed.params}"
    if parsed.query:
        target += f"?{parsed.query}"
    last_error: Exception | None = None
    for address in connect_addresses:
        connection: http.client.HTTPConnection | None = None
        raw_socket: socket.socket | None = None
        try:
            raw_socket = socket.create_connection(
                (address, port),
                timeout=timeout_seconds,
            )
            if parsed.scheme.lower() == "https":
                raw_socket = ssl.create_default_context().wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                )
            connection = http.client.HTTPConnection(
                hostname,
                port,
                timeout=timeout_seconds,
            )
            connection.sock = raw_socket
            connection.request(
                "GET",
                target,
                headers={"User-Agent": "Plamen-Audit-Input-Freezer/1"},
            )
            response = connection.getresponse()
            try:
                payload = response.read(_MAX_REMOTE_DOCUMENT_BYTES + 1)
                headers = {
                    str(name): str(value)
                    for name, value in response.getheaders()
                }
                return int(response.status), headers, payload
            finally:
                response.close()
        except Exception as exc:
            last_error = exc
        finally:
            if connection is not None:
                connection.close()
            elif raw_socket is not None:
                raw_socket.close()
    assert last_error is not None
    raise last_error


def _remote_header(
    headers: Mapping[str, str],
    name: str,
) -> str:
    for key, value in headers.items():
        if str(key).casefold() == name.casefold():
            return str(value)
    return ""


def _fetch_remote_document(
    url: str,
    *,
    config: Mapping[str, Any],
    timeout_seconds: float,
) -> tuple[bytes, str, Mapping[str, str]]:
    """Fetch one document without permitting unchecked redirects or DNS drift."""

    allow_private, allow_insecure_http = _remote_document_policy(config)
    current = url
    for redirect_count in range(6):
        addresses, _port = _validated_remote_document_target(
            current,
            allow_private=allow_private,
            allow_insecure_http=allow_insecure_http,
        )
        try:
            status, headers, payload = _request_remote_document_once(
                current,
                addresses,
                timeout_seconds,
            )
        except SnapshotInputError:
            raise
        except Exception as exc:
            raise SnapshotInputError(
                f"remote documentation fetch failed: {current}"
            ) from exc
        if status in {301, 302, 303, 307, 308}:
            location = _remote_header(headers, "Location").strip()
            if not location:
                raise SnapshotInputError(
                    "remote documentation redirect omitted Location"
                )
            if redirect_count >= 5:
                raise SnapshotInputError(
                    "remote documentation exceeded redirect limit"
                )
            # The next loop validates and DNS-pins the redirect before dialing.
            current = urljoin(current, location)
            continue
        if status < 200 or status >= 300:
            raise SnapshotInputError(
                f"remote documentation returned HTTP {status}: {current}"
            )
        if len(payload) > _MAX_REMOTE_DOCUMENT_BYTES:
            raise SnapshotInputError(
                f"remote documentation exceeds byte limit: {current}"
            )
        return payload, current, headers
    raise SnapshotInputError("remote documentation exceeded redirect limit")


def materialize_remote_documents(
    config: dict[str, Any], *, timeout_seconds: float = 20.0
) -> Path | None:
    """Fetch configured URL documents once into a content-addressed bundle.

    Workers receive the immutable local bundle, never a mutable URL.  The
    manifest binds source/effective URLs, validators, media type, byte count,
    and content digest. A partial or failed fetch creates no valid bundle.
    Local docs paths are left unchanged.
    """
    raw = str(config.get("docs_path") or "").strip()
    if not raw:
        return None
    try:
        tokens = shlex.split(raw, posix=os.name != "nt")
    except ValueError as exc:
        raise SnapshotInputError("docs_path URL list is malformed") from exc
    remote = [token for token in tokens if urlparse(token).scheme.lower() in {"http", "https"}]
    if not remote:
        return None
    if len(remote) != len(tokens):
        raise SnapshotInputError("docs_path cannot mix local paths and remote URLs")
    if len(remote) > _MAX_REMOTE_DOCUMENTS:
        raise SnapshotInputError("too many remote documentation inputs")

    raw_root = str(config.get("project_root") or "").strip()
    project_root = Path(raw_root).resolve() if raw_root else Path()
    if not raw_root or not project_root.is_dir():
        raise SnapshotInputError("project_root is required before fetching documentation")

    records: list[dict[str, Any]] = []
    payloads: list[bytes] = []
    total = 0
    for index, url in enumerate(remote):
        try:
            payload, effective, headers = _fetch_remote_document(
                url,
                config=config,
                timeout_seconds=timeout_seconds,
            )
        except SnapshotInputError:
            raise
        except Exception as exc:
            raise SnapshotInputError(f"remote documentation fetch failed: {url}") from exc
        if len(payload) > _MAX_REMOTE_DOCUMENT_BYTES:
            raise SnapshotInputError(f"remote documentation exceeds byte limit: {url}")
        total += len(payload)
        if total > _MAX_EXTERNAL_INPUT_BYTES:
            raise SnapshotInputError("remote documentation bundle exceeds byte limit")
        digest = _sha256(payload)
        # The full digest lives in the manifest; short local names avoid the
        # legacy Windows MAX_PATH limit in deeply nested audit workspaces.
        name = f"{index:03d}.bin"
        payloads.append(payload)
        records.append(
            {
                "source_url": url,
                "effective_url": effective,
                "content_sha256": digest,
                "byte_count": len(payload),
                "content_type": _remote_header(headers, "Content-Type"),
                "etag": _remote_header(headers, "ETag"),
                "last_modified": _remote_header(headers, "Last-Modified"),
                "local_name": name,
            }
        )

    manifest = {
        "schema": "plamen.remote-document-bundle.v1",
        "documents": records,
    }
    bundle_digest = _sha256(_canonical_json(manifest))
    bundle_root = project_root / ".plamen-audit-inputs"
    destination = bundle_root / bundle_digest[:24]
    if not destination.exists():
        bundle_root.mkdir(parents=True, exist_ok=True)
        temporary = bundle_root / f".tmp-{uuid.uuid4().hex[:12]}"
        temporary.mkdir(parents=False, exist_ok=False)
        try:
            for record, payload in zip(records, payloads):
                (temporary / record["local_name"]).write_bytes(payload)
            _atomic_json(temporary / "manifest.json", manifest)
            try:
                os.replace(temporary, destination)
            except FileExistsError:
                shutil.rmtree(temporary)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)
            raise
    # Re-validate an existing/raced bundle before trusting it.
    for record in records:
        path = destination / record["local_name"]
        digest, _size = _hash_path(path)
        if digest.hex() != record["content_sha256"]:
            raise SnapshotInputError("remote documentation bundle failed integrity check")
    config["docs_source_urls"] = list(remote)
    config["docs_path"] = str(destination)
    return destination


def _typed_document_inputs(config: Mapping[str, Any]) -> tuple[str, ...] | None:
    raw = config.get("docs_inputs")
    if raw is None:
        return None
    if not isinstance(raw, (list, tuple)):
        raise SnapshotInputError("docs_inputs must be a JSON list of strings")
    values: list[str] = []
    for index, value in enumerate(raw):
        if not isinstance(value, str) or not value.strip():
            raise SnapshotInputError(
                f"docs_inputs[{index}] must be a nonempty string"
            )
        values.append(value.strip())
    if not values:
        raise SnapshotInputError("docs_inputs must not be empty when configured")
    if len(values) != len(set(values)):
        raise SnapshotInputError("docs_inputs contains duplicate entries")
    if len(values) > _MAX_EXTERNAL_INPUT_FILES:
        raise SnapshotInputError("docs_inputs exceeds the bounded input count")
    return tuple(values)


def _document_local_name(index: int, source: str) -> str:
    parsed = urlparse(source)
    leaf = Path(parsed.path if parsed.scheme else source).name
    suffix = Path(leaf).suffix.lower()
    if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
        suffix = ".bin"
    return f"{index:05d}{suffix}"


def _typed_docs_input_digest(inputs: tuple[str, ...]) -> str:
    return _sha256(
        _canonical_json(
            {
                "schema": "plamen.document-input-authority.v1",
                "inputs": list(inputs),
            }
        )
    )


def _assert_no_lexical_links(
    path: Path,
    *,
    label: str,
    _validated_paths: set[str] | None = None,
    _validated_root: Path | None = None,
) -> Path:
    """Reject symlink/junction/reparse traversal before resolving a local input."""

    absolute = path.expanduser().absolute()
    parts = absolute.parts
    if not parts:
        raise SnapshotInputError(f"{label} is empty")
    if _validated_root is not None:
        root = _validated_root.expanduser().absolute()
        try:
            relative = absolute.relative_to(root)
        except ValueError as exc:
            raise SnapshotInputError(
                f"{label} escapes its validated lexical root: {path}"
            ) from exc
        cursor = root
        components = relative.parts
    else:
        cursor = Path(absolute.anchor) if absolute.anchor else Path(parts[0])
        start = 1 if absolute.anchor else 0
        components = parts[start:]
    for component in components:
        cursor = cursor / component
        cache_key = os.path.normcase(os.path.abspath(str(cursor)))
        if _validated_paths is not None and cache_key in _validated_paths:
            continue
        try:
            row = cursor.lstat()
        except OSError as exc:
            raise SnapshotInputError(f"{label} is missing or unreadable: {path}") from exc
        if (
            stat.S_ISLNK(row.st_mode)
            or bool(
                getattr(row, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
        ):
            raise SnapshotInputError(
                f"{label} traverses a link, junction, or reparse point: {path}"
            )
        if _validated_paths is not None:
            _validated_paths.add(cache_key)
    return absolute


def _validate_typed_docs_bundle(
    *,
    config: dict[str, Any],
    inputs: tuple[str, ...],
    receipt_path: Path,
) -> Path:
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SnapshotInputError(
            "typed documentation resume receipt is missing or unreadable"
        ) from exc
    if not isinstance(receipt, dict) or receipt.get("schema") != (
        "plamen.document-input-receipt.v1"
    ):
        raise SnapshotInputError("typed documentation resume receipt schema is invalid")
    expected_input_digest = _typed_docs_input_digest(inputs)
    if receipt.get("input_digest") != expected_input_digest:
        raise SnapshotInputError(
            "typed documentation inputs differ from the bound resume receipt"
        )

    project_root = Path(str(config.get("project_root") or "")).resolve()
    bundle_root = (project_root / ".plamen-audit-inputs").resolve()
    raw_bundle = Path(str(receipt.get("bundle_path") or ""))
    bundle = _assert_no_lexical_links(
        raw_bundle,
        label="typed documentation bundle",
    ).resolve()
    try:
        bundle.relative_to(bundle_root)
    except ValueError as exc:
        raise SnapshotInputError(
            "typed documentation bundle escapes the project input root"
        ) from exc
    if not bundle.is_dir() or bundle.is_symlink() or _is_reparse_point(bundle):
        raise SnapshotInputError("typed documentation bundle is missing or unsafe")
    manifest_path = bundle / "manifest.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        raise SnapshotInputError(
            "typed documentation bundle manifest is unreadable"
        ) from exc
    if _sha256(manifest_bytes) != receipt.get("manifest_sha256"):
        raise SnapshotInputError("typed documentation bundle manifest drifted")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != "plamen.document-input-bundle.v1"
        or manifest.get("input_digest") != expected_input_digest
    ):
        raise SnapshotInputError("typed documentation bundle authority is invalid")

    records = manifest.get("documents")
    if not isinstance(records, list) or not records:
        raise SnapshotInputError("typed documentation bundle has no documents")
    local_names = [
        str(record.get("local_name") or "")
        for record in records
        if isinstance(record, dict)
    ]
    if len(local_names) != len(set(local_names)):
        raise SnapshotInputError(
            "typed documentation bundle has duplicate local names"
        )
    try:
        members = list(bundle.iterdir())
    except OSError as exc:
        raise SnapshotInputError(
            "typed documentation bundle roster is unreadable"
        ) from exc
    if any(
        member.is_dir() or member.is_symlink() or _is_reparse_point(member)
        for member in members
    ):
        raise SnapshotInputError(
            "typed documentation bundle roster contains an unsafe member"
        )
    actual_names = {member.name for member in members}
    expected_names = {"manifest.json", *local_names}
    if actual_names != expected_names:
        raise SnapshotInputError(
            "typed documentation bundle roster differs from its manifest"
        )
    for record in records:
        if not isinstance(record, dict):
            raise SnapshotInputError("typed documentation record is invalid")
        local_name = str(record.get("local_name") or "")
        if not re.fullmatch(r"\d{5}\.[a-z0-9]{1,10}", local_name):
            raise SnapshotInputError("typed documentation local name is invalid")
        payload_path = bundle / local_name
        try:
            payload = payload_path.read_bytes()
        except OSError as exc:
            raise SnapshotInputError(
                "typed documentation bundle payload is unreadable"
            ) from exc
        if _sha256(payload) != record.get("content_sha256"):
            raise SnapshotInputError("typed documentation bundle payload drifted")
        if record.get("source_kind") == "local":
            source_path = _assert_no_lexical_links(
                Path(str(record.get("source_path") or "")),
                label="local documentation source",
            )
            try:
                current = source_path.read_bytes()
            except OSError as exc:
                raise SnapshotInputError(
                    "local documentation changed or became unreadable after freeze"
                ) from exc
            if _sha256(current) != record.get("content_sha256"):
                raise SnapshotInputError(
                    "local documentation changed after the audit input freeze"
                )
    config["docs_path"] = str(bundle)
    config["_docs_materialized_bundle"] = str(bundle)
    return bundle


def materialize_document_inputs(
    config: dict[str, Any],
    *,
    receipt_path: Path | None = None,
    allow_remote_fetch: bool = True,
    timeout_seconds: float = 20.0,
) -> Path | None:
    """Materialize typed local/remote documentation into one immutable bundle.

    `docs_inputs` is the unambiguous authority.  Each list entry is one local
    file/directory or one HTTP(S) URL, so spaces and mixed source kinds carry no
    shell-token semantics.  Legacy `docs_path` remains supported when the typed
    field is absent.
    """

    inputs = _typed_document_inputs(config)
    if inputs is None:
        return materialize_remote_documents(
            config,
            timeout_seconds=timeout_seconds,
        )
    existing_docs_path = str(config.get("docs_path") or "").strip()
    materialized = str(config.get("_docs_materialized_bundle") or "").strip()
    if existing_docs_path and existing_docs_path != materialized:
        raise SnapshotInputError(
            "docs_inputs is authoritative; legacy docs_path must be empty"
        )

    if not allow_remote_fetch:
        if receipt_path is None:
            raise SnapshotInputError(
                "typed documentation resume requires a bound receipt path"
            )
        return _validate_typed_docs_bundle(
            config=config,
            inputs=inputs,
            receipt_path=Path(receipt_path),
        )

    raw_root = str(config.get("project_root") or "").strip()
    project_root = Path(raw_root).resolve() if raw_root else Path()
    if not raw_root or not project_root.is_dir():
        raise SnapshotInputError(
            "project_root is required before materializing documentation"
        )
    remote_count = sum(
        1
        for source in inputs
        if not re.match(r"^[A-Za-z]:[\\/]", source)
        and urlparse(source).scheme.lower() in {"http", "https"}
    )
    if remote_count > _MAX_REMOTE_DOCUMENTS:
        raise SnapshotInputError("too many remote documentation inputs")

    records: list[dict[str, Any]] = []
    payloads: list[bytes] = []
    total_bytes = 0
    total_files = 0
    for input_index, source in enumerate(inputs):
        parsed = urlparse(source)
        windows_absolute = bool(re.match(r"^[A-Za-z]:[\\/]", source))
        if not windows_absolute and parsed.scheme.lower() in {"http", "https"}:
            try:
                payload, effective, headers = _fetch_remote_document(
                    source,
                    config=config,
                    timeout_seconds=timeout_seconds,
                )
            except SnapshotInputError:
                raise
            except Exception as exc:
                raise SnapshotInputError(
                    f"remote documentation fetch failed: {source}"
                ) from exc
            if len(payload) > _MAX_REMOTE_DOCUMENT_BYTES:
                raise SnapshotInputError(
                    f"remote documentation exceeds byte limit: {source}"
                )
            local_name = _document_local_name(total_files, source)
            records.append(
                {
                    "source_kind": "remote",
                    "source_input": source,
                    "effective_source": effective,
                    "content_sha256": _sha256(payload),
                    "byte_count": len(payload),
                    "content_type": _remote_header(headers, "Content-Type"),
                    "etag": _remote_header(headers, "ETag"),
                    "last_modified": _remote_header(headers, "Last-Modified"),
                    "local_name": local_name,
                }
            )
            payloads.append(payload)
            total_files += 1
            total_bytes += len(payload)
        elif parsed.scheme and not windows_absolute:
            raise SnapshotInputError(
                f"unsupported documentation input scheme: {source}"
            )
        else:
            local = Path(source).expanduser()
            if not local.is_absolute():
                local = project_root / local
            lexical = _assert_no_lexical_links(
                local,
                label="local documentation input",
            )
            resolved = lexical.resolve()
            if not resolved.exists():
                raise SnapshotInputError(
                    f"local documentation input does not exist: {resolved}"
                )
            if resolved.is_symlink() or _is_reparse_point(resolved):
                raise SnapshotInputError(
                    f"local documentation input is a link/reparse point: {resolved}"
                )
            if resolved.is_dir():
                children: list[Path] = []
                for child in sorted(resolved.rglob("*")):
                    if child.is_symlink() or _is_reparse_point(child):
                        raise SnapshotInputError(
                            "local documentation directory contains a link, "
                            f"junction, or reparse point: {child}"
                        )
                    if (
                        child.is_file()
                        and not any(
                            part.startswith(".") or part in _MANIFEST_SKIP_DIRS
                            for part in child.relative_to(resolved).parts[:-1]
                        )
                    ):
                        children.append(child)
                if not children:
                    raise SnapshotInputError(
                        f"local documentation directory is empty: {resolved}"
                    )
            elif resolved.is_file():
                children = [resolved]
            else:
                raise SnapshotInputError(
                    f"local documentation input is not a regular file: {resolved}"
                )
            for child in children:
                try:
                    payload = child.read_bytes()
                except OSError as exc:
                    raise SnapshotInputError(
                        f"local documentation input is unreadable: {child}"
                    ) from exc
                local_name = _document_local_name(total_files, child.name)
                records.append(
                    {
                        "source_kind": "local",
                        "source_input": source,
                        "source_path": str(child.resolve()),
                        "source_relative": (
                            child.relative_to(resolved).as_posix()
                            if resolved.is_dir()
                            else child.name
                        ),
                        "content_sha256": _sha256(payload),
                        "byte_count": len(payload),
                        "content_type": "",
                        "local_name": local_name,
                        "input_index": input_index,
                    }
                )
                payloads.append(payload)
                total_files += 1
                total_bytes += len(payload)

        if (
            total_files > _MAX_EXTERNAL_INPUT_FILES
            or total_bytes > _MAX_EXTERNAL_INPUT_BYTES
        ):
            raise SnapshotInputError(
                "documentation inputs exceed bounded file/byte limits"
            )

    input_digest = _typed_docs_input_digest(inputs)
    manifest = {
        "schema": "plamen.document-input-bundle.v1",
        "input_digest": input_digest,
        "documents": records,
    }
    manifest_bytes = json.dumps(
        manifest,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    bundle_digest = _sha256(_canonical_json(manifest))
    bundle_root = project_root / ".plamen-audit-inputs"
    destination = bundle_root / bundle_digest[:24]
    if not destination.exists():
        bundle_root.mkdir(parents=True, exist_ok=True)
        temporary = bundle_root / f".tmp-{uuid.uuid4().hex[:12]}"
        temporary.mkdir(parents=False, exist_ok=False)
        try:
            for record, payload in zip(records, payloads):
                (temporary / record["local_name"]).write_bytes(payload)
            (temporary / "manifest.json").write_bytes(manifest_bytes)
            try:
                os.replace(temporary, destination)
            except FileExistsError:
                shutil.rmtree(temporary)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)
            raise

    receipt = {
        "schema": "plamen.document-input-receipt.v1",
        "input_digest": input_digest,
        "bundle_digest": bundle_digest,
        "bundle_path": str(destination.resolve()),
        "manifest_sha256": _sha256(manifest_bytes),
    }
    if receipt_path is not None:
        receipt_path = Path(receipt_path)
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_json(receipt_path, receipt)
    config["docs_path"] = str(destination.resolve())
    config["_docs_materialized_bundle"] = str(destination.resolve())
    # Validate both newly-created and raced/existing destinations before use.
    if receipt_path is not None:
        return _validate_typed_docs_bundle(
            config=config,
            inputs=inputs,
            receipt_path=receipt_path,
        )
    for record in records:
        payload = (destination / record["local_name"]).read_bytes()
        if _sha256(payload) != record["content_sha256"]:
            raise SnapshotInputError(
                "typed documentation bundle failed integrity validation"
            )
    return destination.resolve()


def _is_generated_verification_source(path: Path, project_root: Path) -> bool:
    """Exclude post-freeze PoC/test/harness files from production scope.

    ``recon_prepass._production_source_files`` already excludes conventional
    test directories and names.  Verification additionally creates common
    framework forms such as ``Vault.t.sol`` and ``poc_*.sol`` inside source
    roots; admitting those after the snapshot would make the audit mutate its
    own target.
    """
    try:
        relative = path.resolve().relative_to(project_root.resolve())
    except Exception:
        relative = path
    lowered_parts = tuple(part.lower() for part in relative.parts)
    if any(part in {"harness", "harnesses", ".plamen-poc"} for part in lowered_parts[:-1]):
        return True
    name = relative.name.lower()
    stem = relative.stem.lower()
    return (
        name.endswith((".t.sol", ".spec.sol"))
        or stem.startswith(("poc_", "poc-", "exploit_", "exploit-"))
        or stem.endswith(("_poc", "-poc", "_harness", "-harness"))
    )


@dataclass(frozen=True)
class SnapshotVerdict:
    state: str
    changed_components: tuple[str, ...] = ()
    runtime_entry_changes: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class ArchiveReceipt:
    archive_dir: Path
    moved_names: tuple[str, ...]
    preserved_names: tuple[str, ...]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _portable_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value.resolve())
    if isinstance(value, Mapping):
        return {
            str(k): _portable_value(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_portable_value(v) for v in value]
    if isinstance(value, set):
        return sorted((_portable_value(v) for v in value), key=repr)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def _semantic_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Remove process-local fields while retaining every audit-semantic input."""
    return {
        str(key): _portable_value(value)
        for key, value in sorted(config.items(), key=lambda item: str(item[0]))
        if not str(key).startswith("_") and str(key) not in _RUNTIME_CONFIG_KEYS
    }


EntryPayload = Path | bytes


def _file_change_token(path: Path, info: os.stat_result) -> int:
    """Return the OS change timestamp, distinct from user-settable mtime.

    POSIX exposes inode change time as ``st_ctime_ns``.  On Windows Python's
    ``st_ctime`` is the creation timestamp, so query ``FILE_BASIC_INFO`` for
    the kernel-maintained ChangeTime instead.  Falling back to creation time
    would make a same-size edit with restored mtime an unsafe cache hit.
    """

    if os.name != "nt":
        return int(getattr(info, "st_ctime_ns", 0))

    import ctypes
    from ctypes import wintypes

    class FILE_BASIC_INFO(ctypes.Structure):
        _fields_ = [
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_info = kernel32.GetFileInformationByHandleEx
    get_info.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    get_info.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        str(path),
        0x0080,  # FILE_READ_ATTRIBUTES
        0x00000001 | 0x00000002 | 0x00000004,  # share read/write/delete
        None,
        3,  # OPEN_EXISTING
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS (also valid for files)
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        raise SnapshotInputError(
            f"audited input change time is unreadable: {path} (winerror={error})"
        )
    try:
        basic = FILE_BASIC_INFO()
        if not get_info(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)):
            error = ctypes.get_last_error()
            raise SnapshotInputError(
                f"audited input change time is unreadable: {path} "
                f"(winerror={error})"
            )
        return int(basic.ChangeTime)
    finally:
        close_handle(handle)


def _file_identity(
    path: Path, info: os.stat_result, link_target: str | None
) -> tuple[Any, ...]:
    """Return a same-process cache key that changes on file replacement/edit.

    ``mtime`` alone is insufficient because callers can restore it.  The key
    also binds ctime, inode/device identity, size, mode, and the symlink target.
    A second stat is required before a cached digest is returned, preserving
    the existing walk/read mixed-time protection.
    """

    return (
        os.path.normcase(os.path.abspath(os.fspath(path))),
        getattr(info, "st_dev", 0),
        getattr(info, "st_ino", 0),
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        _file_change_token(path, info),
        link_target,
    )


def _filesystem_io_path(path: Path) -> Path:
    """Return an I/O spelling that preserves long local paths on Windows.

    ``os.walk`` can enumerate a child whose ordinary absolute spelling exceeds
    MAX_PATH even when a later ``stat``/``open`` of that same spelling fails
    with ``FileNotFoundError``.  The extended-length namespace addresses the
    already-resolved local object without weakening link or stability checks.
    """

    path = Path(path)
    if os.name != "nt":
        return path
    raw = os.path.abspath(os.fspath(path))
    if raw.startswith("\\\\?\\"):
        return Path(raw)
    # Keep the ordinary spelling whenever Win32 can address it.  Besides
    # remaining friendlier to diagnostics and test doubles, this preserves a
    # single cache identity for ordinary paths.  Reserve the extended namespace
    # for paths at genuine MAX_PATH risk.
    if len(raw) < 248:
        return path
    if raw.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + raw[2:])
    return Path("\\\\?\\" + raw)


def _hash_path_impl(
    path: Path,
    *,
    use_cache: bool,
) -> tuple[bytes, int]:
    """Stream-hash one stable regular file; never bless an unreadable state.

    A pre/post stat comparison prevents a walk-then-read mixed-time digest.  A
    changing file is retried a bounded number of times and then fails closed.
    Symlinks are content-bound together with their link target, while special
    files (devices, sockets, FIFOs) are rejected.
    """
    io_path = _filesystem_io_path(path)
    for _attempt in range(_MAX_STABLE_READ_RETRIES):
        try:
            link_target = os.readlink(io_path) if io_path.is_symlink() else None
            before = io_path.stat()
            if not stat.S_ISREG(before.st_mode):
                raise SnapshotInputError(f"audited input is not a regular file: {path}")
            identity = _file_identity(io_path, before, link_target)
            cache_key = str(identity[0])
            cached = _FILE_HASH_CACHE.get(cache_key) if use_cache else None
            if cached is not None and cached[0] == identity:
                after = io_path.stat()
                after_target = os.readlink(io_path) if io_path.is_symlink() else None
                if identity == _file_identity(io_path, after, after_target):
                    return cached[1]
                continue
            hasher = hashlib.sha256()
            byte_count = 0
            if link_target is not None:
                prefix = b"SYMLINK\0" + os.fsencode(link_target) + b"\0"
                hasher.update(prefix)
                byte_count += len(prefix)
            with io_path.open("rb") as stream:
                opened_before = os.fstat(stream.fileno())
                object_identity = lambda value: (
                    getattr(value, "st_dev", 0),
                    getattr(value, "st_ino", 0),
                    stat.S_IFMT(value.st_mode),
                )
                if object_identity(opened_before) != object_identity(before):
                    continue
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    byte_count += len(chunk)
                opened_after = os.fstat(stream.fileno())
                if object_identity(opened_after) != object_identity(before):
                    continue
            after = io_path.stat()
            after_target = os.readlink(io_path) if io_path.is_symlink() else None
            stable = identity == _file_identity(io_path, after, after_target)
            if stable:
                result = (hasher.digest(), byte_count)
                if use_cache:
                    _FILE_HASH_CACHE[cache_key] = (identity, result)
                return result
        except SnapshotInputError:
            raise
        except Exception as exc:
            raise SnapshotInputError(
                f"audited input is unreadable: {path} ({type(exc).__name__})"
            ) from exc
    raise SnapshotInputError(f"audited input changed while being frozen: {path}")


def _hash_path(path: Path) -> tuple[bytes, int]:
    """Hash a stable audited-input file with the bounded metadata cache."""

    return _hash_path_impl(path, use_cache=True)


def _hash_runtime_executable(path: Path) -> tuple[bytes, int]:
    """Hash executable bytes without trusting a prior metadata cache entry."""

    return _hash_path_impl(path, use_cache=False)


def _digest_entries(entries: Iterable[tuple[str, EntryPayload]]) -> dict[str, Any]:
    hasher = hashlib.sha256()
    path_hasher = hashlib.sha256()
    count = 0
    byte_count = 0
    prior_name: str | None = None
    for relative, payload in sorted(entries, key=lambda item: item[0]):
        if relative == prior_name:
            raise SnapshotInputError(f"duplicate audited-input identity: {relative}")
        prior_name = relative
        encoded_name = relative.replace("\\", "/").encode("utf-8")
        if isinstance(payload, Path):
            file_digest, payload_size = _hash_path(payload)
        else:
            file_digest = hashlib.sha256(payload).digest()
            payload_size = len(payload)
        hasher.update(len(encoded_name).to_bytes(8, "big"))
        hasher.update(encoded_name)
        hasher.update(payload_size.to_bytes(8, "big"))
        hasher.update(file_digest)
        path_hasher.update(len(encoded_name).to_bytes(8, "big"))
        path_hasher.update(encoded_name)
        count += 1
        if count > _MAX_SNAPSHOT_FILES:
            raise SnapshotInputError(
                "audit input inventory exceeds the bounded file-count limit"
            )
        byte_count += payload_size
    return {
        "digest": hasher.hexdigest(),
        "path_set_digest": path_hasher.hexdigest(),
        "file_count": count,
        "byte_count": byte_count,
    }


def _runtime_entry_manifest(
    entries: Iterable[tuple[str, EntryPayload]],
) -> dict[str, dict[str, Any]]:
    """Return bounded, non-secret identities for synthetic runtime inputs.

    Runtime entries are already part of the toolchain aggregate, but the
    aggregate alone cannot explain a mismatch.  Persist only each logical
    ``@runtime/*`` name plus its digest and size: this is enough to diagnose
    drift without copying version output, environment values, executable
    paths, or other potentially sensitive payload bytes into the checkpoint.
    """

    manifest: dict[str, dict[str, Any]] = {}
    for identity, payload in sorted(entries, key=lambda item: item[0]):
        if not identity.startswith("@runtime/"):
            continue
        encoded_identity = identity.encode("utf-8")
        if (
            not encoded_identity
            or len(encoded_identity) > _MAX_RUNTIME_ENTRY_IDENTITY_BYTES
            or "\x00" in identity
        ):
            raise SnapshotInputError("runtime entry identity is invalid")
        if identity in manifest:
            raise SnapshotInputError(
                f"duplicate runtime entry identity: {identity}"
            )
        if isinstance(payload, Path):
            raise SnapshotInputError(
                f"runtime entry payload must be synthetic bytes: {identity}"
            )
        manifest[identity] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "byte_count": len(payload),
        }
        if len(manifest) > _MAX_RUNTIME_ENTRY_MANIFEST_ITEMS:
            raise SnapshotInputError(
                "runtime entry manifest exceeds the bounded item-count limit"
            )
    return manifest


def _read_entry(path: Path) -> bytes:
    """Read a small control input; large source trees use streaming hashes."""
    try:
        if path.is_symlink():
            # Bind the link itself and its resolved content.  A symlink target
            # change must not pass as an unchanged audit input.
            target = os.readlink(path)
            return b"SYMLINK\0" + os.fsencode(target) + b"\0" + path.read_bytes()
        return path.read_bytes()
    except Exception as exc:
        raise SnapshotInputError(
            f"audited input is unreadable: {path} ({type(exc).__name__})"
        ) from exc


def _tree_entries(
    root: Path,
    directories: Iterable[str],
    *,
    include: Callable[[Path, str], bool] | None = None,
) -> list[tuple[str, EntryPayload]]:
    # Package-manager payloads are mutable generated runtimes, not reviewed
    # Plamen source.  Their source manifests/lockfiles remain in this tree,
    # while executable npm payloads are admitted through the independently
    # signed immutable-generation authority in plamen_mcp_runtime.py.  Walking
    # node_modules here duplicated that authority and made Windows startup hash
    # tens of thousands of files (often close to a gigabyte) before Recon.
    generated_directories = {
        "__pycache__",
        ".git",
        ".pytest_cache",
        "node_modules",
    }
    entries: list[tuple[str, EntryPayload]] = []
    for directory in directories:
        base = root / directory
        if not base.is_dir():
            continue
        if base.is_symlink() or (
            hasattr(base, "is_junction") and base.is_junction()
        ):
            raise SnapshotInputError(
                f"audited methodology/tool directory is a symlink or junction: {base}"
            )
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            directory_path = Path(dirpath)
            linked_directories = [
                directory_path / name
                for name in dirnames
                if (directory_path / name).is_symlink()
                or (
                    hasattr(directory_path / name, "is_junction")
                    and (directory_path / name).is_junction()
                )
            ]
            if linked_directories:
                raise SnapshotInputError(
                    "audited methodology/tool tree contains a directory "
                    f"symlink or junction: {linked_directories[0]}"
                )
            dirnames[:] = sorted(
                name for name in dirnames
                if name not in generated_directories
            )
            for name in sorted(filenames):
                path = directory_path / name
                if not path.is_file():
                    continue
                rel = path.relative_to(root).as_posix()
                if include is not None and not include(path, rel):
                    continue
                entries.append((rel, path))
    return entries


def _manifest_files(project_root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in _MANIFEST_SKIP_DIRS and not name.startswith(".")
        )
        for name in sorted(filenames):
            if name in _MANIFEST_NAMES:
                found.append(Path(dirpath) / name)
    return found


def _is_generated_audit_artifact(path: Path, project_root: Path) -> bool:
    try:
        relative = path.relative_to(project_root)
    except Exception:
        relative = path
    name = relative.name.lower()
    if name in {
        "audit_report.md",
        "audit-report.md",
        "medusa.json",
        _ARCHIVE_LOCK_NAME.lower(),
        _ARCHIVE_INTENT_NAME.lower(),
        "snapshot_rewind_receipt.json",
    }:
        return True
    if name.startswith("audit_report") and name.endswith(".md"):
        return True
    if name.endswith(("_rca.md", "-rca.md")):
        return True
    if name.endswith((".t.sol", ".spec.sol")):
        return True
    lowered_parts = {part.lower() for part in relative.parts[:-1]}
    if lowered_parts & {"test", "tests", "harness", "harnesses"}:
        if relative.stem.lower().startswith(("exploit", "poc", "verify")):
            return True
    return bool(_GENERATED_AUDIT_NAME_RE.search(relative.stem))


def _project_context_files(
    project_root: Path,
    *,
    excluded_runtime_paths: frozenset[str] = frozenset(),
    excluded_roots: tuple[Path, ...] = (),
) -> list[Path]:
    """Inventory every stable upstream file workers are allowed to consume.

    Build caches, dependency install trees, VCS internals, the scratchpad, and
    recognisable generated audit outputs are outside the read/freeze boundary.
    Pre-existing tests and documentation remain bound because they influence
    human/agent reasoning even when they are not production deployment units.
    """
    files: list[Path] = []
    excluded_root_identities = {
        os.path.normcase(os.path.abspath(str(Path(root).resolve())))
        for root in excluded_roots
    }
    source_bearing_generated_roots: set[Path] = set()
    for dirpath, dirnames, filenames in os.walk(project_root):
        retained_dirs: list[str] = []
        for name in sorted(dirnames):
            directory = Path(dirpath) / name
            directory_identity = os.path.normcase(
                os.path.abspath(str(directory.resolve()))
            )
            if directory_identity in excluded_root_identities:
                continue
            if _is_project_context_skip_dir(name, directory):
                continue
            if name.startswith(".scratchpad-stale-snapshot"):
                continue
            if name.startswith(".plamen-stale-snapshots"):
                continue
            retained_dirs.append(name)
            if _name_in_set(name, _GENERATED_VERIFIER_DIRS):
                source_bearing_generated_roots.add(directory.resolve())
        for name in retained_dirs:
            directory = Path(dirpath) / name
            if directory.is_symlink() or _is_reparse_point(directory):
                raise SnapshotInputError(
                    "audit input contains a directory symlink/junction; "
                    "freeze the linked dependency into an explicit immutable "
                    f"input bundle: {directory}"
                )
        dirnames[:] = retained_dirs
        for name in sorted(filenames):
            path = Path(dirpath) / name
            relative = path.relative_to(project_root).as_posix()
            runtime_key = (
                relative.casefold() if os.name == "nt" else relative
            )
            if runtime_key in excluded_runtime_paths:
                # An exact runtime exemption is not permission to hide a link,
                # directory, or unbounded payload at that identity.
                if (
                    path.is_symlink()
                    or _is_reparse_point(path)
                    or not path.is_file()
                ):
                    raise SnapshotInputError(
                        "owned backend runtime path is not a regular local file: "
                        f"{path}"
                    )
                if path.stat().st_size > _BACKEND_RUNTIME_MAX_FILE_BYTES:
                    raise SnapshotInputError(
                        "owned backend runtime file exceeds bounded size: "
                        f"{path}"
                    )
                continue
            generated_root = next(
                (
                    root for root in source_bearing_generated_roots
                    if _is_descendant_or_equal(path, root)
                ),
                None,
            )
            if generated_root is not None:
                # Bind user source and its build authority, but not mutable
                # compiler products adjacent to it.
                if not (
                    path.suffix.lower() in _ALL_SOURCE_SUFFIXES
                    and is_production_source_path(path, generated_root)
                ) and path.name not in _MANIFEST_NAMES:
                    continue
            if _is_generated_audit_artifact(path, project_root):
                continue
            files.append(path)
            if len(files) > _MAX_EXTERNAL_INPUT_FILES:
                raise SnapshotInputError(
                    "audit input tree exceeds the bounded file-count limit; "
                    "freeze a smaller explicit input bundle"
                )
    return files


def _project_identity(project_root: Path) -> str:
    lexical = str(project_root.resolve())
    if os.name == "nt":
        lexical = lexical.casefold()
    return _sha256(lexical.encode("utf-8"))


def _validated_backend_runtime_contract(
    config: Mapping[str, Any], project_root: Path
) -> dict[str, Any] | None:
    raw = config.get("_backend_runtime_contract")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SnapshotInputError("backend runtime contract is not an object")
    required = {
        "schema",
        "backend",
        "project_root_sha256",
        "isolation_mode",
        "ephemeral_paths",
        "preexisting_bound_inputs",
    }
    if set(raw) != required or raw.get("schema") != _BACKEND_RUNTIME_CONTRACT_SCHEMA:
        raise SnapshotInputError("backend runtime contract schema is invalid")
    backend = str(raw.get("backend") or "").strip().lower()
    configured = str(config.get("cli_backend") or "claude").strip().lower()
    if backend != configured:
        raise SnapshotInputError("backend runtime contract backend mismatch")
    if raw.get("project_root_sha256") != _project_identity(project_root):
        raise SnapshotInputError("backend runtime contract project mismatch")
    allowed = set(_BACKEND_RUNTIME_CANDIDATES.get(backend, ()))
    ephemeral = raw.get("ephemeral_paths")
    preexisting = raw.get("preexisting_bound_inputs")
    if not isinstance(ephemeral, list) or not isinstance(preexisting, list):
        raise SnapshotInputError("backend runtime contract path lists are invalid")
    if any(not isinstance(item, str) or item not in allowed for item in ephemeral):
        raise SnapshotInputError("backend runtime contract contains an unapproved path")
    if len(set(ephemeral)) != len(ephemeral):
        raise SnapshotInputError("backend runtime contract contains duplicate paths")
    expected_isolation_mode = (
        "EXACT_OWNED_PATH_FALLBACK" if ephemeral else "NO_EPHEMERAL_PATHS"
    )
    if raw.get("isolation_mode") != expected_isolation_mode:
        raise SnapshotInputError("backend runtime contract isolation mode is invalid")
    preexisting_paths: list[str] = []
    for item in preexisting:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "bytes", "sha256"}
            or item.get("path") not in allowed
            or type(item.get("bytes")) is not int
            or not isinstance(item.get("sha256"), str)
            or _HEX_64_RE.fullmatch(item["sha256"]) is None
        ):
            raise SnapshotInputError(
                "backend runtime contract preexisting-input row is invalid"
            )
        if item["bytes"] < 0 or item["bytes"] > _BACKEND_RUNTIME_MAX_FILE_BYTES:
            raise SnapshotInputError(
                "backend runtime contract preexisting-input size is invalid"
            )
        preexisting_paths.append(item["path"])
    if len(set(preexisting_paths)) != len(preexisting_paths):
        raise SnapshotInputError(
            "backend runtime contract contains duplicate preexisting paths"
        )
    if set(ephemeral) & set(preexisting_paths):
        raise SnapshotInputError("backend runtime path has conflicting ownership")
    if set(ephemeral) | set(preexisting_paths) != allowed:
        raise SnapshotInputError(
            "backend runtime contract does not classify every approved path"
        )
    return raw


def prepare_backend_runtime_contract(
    config: dict[str, Any], scratchpad: Path
) -> dict[str, Any]:
    """Create or reload the exact backend-runtime/source classification.

    Only a supported path that was absent when the contract was first created
    can become backend-owned ephemeral state. A pre-existing file keeps its
    source-input authority and is hash-bound. The receipt lives in the
    scratchpad and its canonical payload is also bound into ``source_scope``.
    """
    project_root = Path(str(config.get("project_root") or "")).resolve()
    scratchpad = Path(scratchpad).resolve()
    if not project_root.is_dir():
        raise SnapshotInputError("backend runtime contract project is missing")
    try:
        scratchpad.relative_to(project_root)
    except ValueError as exc:
        raise SnapshotInputError(
            "backend runtime contract scratchpad must be inside project_root"
        ) from exc
    scratchpad.mkdir(parents=True, exist_ok=True)
    receipt_path = scratchpad / _BACKEND_RUNTIME_CONTRACT_NAME
    backend = str(config.get("cli_backend") or "claude").strip().lower()

    if receipt_path.exists() or receipt_path.is_symlink():
        if (
            receipt_path.is_symlink()
            or _is_reparse_point(receipt_path)
            or not receipt_path.is_file()
        ):
            raise SnapshotInputError(
                "backend runtime contract receipt is not a regular local file"
            )
        try:
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SnapshotInputError(
                "backend runtime contract receipt is unreadable"
            ) from exc
        config["_backend_runtime_contract"] = payload
        validated = _validated_backend_runtime_contract(config, project_root)
        assert validated is not None
        return validated

    ephemeral: list[str] = []
    preexisting: list[dict[str, Any]] = []
    for relative in _BACKEND_RUNTIME_CANDIDATES.get(backend, ()):
        path = project_root / Path(relative)
        if not path.exists() and not path.is_symlink():
            ephemeral.append(relative)
            continue
        if (
            path.is_symlink()
            or _is_reparse_point(path)
            or not path.is_file()
        ):
            raise SnapshotInputError(
                f"backend runtime candidate is not a regular local file: {path}"
            )
        if path.stat().st_size > _BACKEND_RUNTIME_MAX_FILE_BYTES:
            raise SnapshotInputError(
                f"backend runtime candidate exceeds bounded size: {path}"
            )
        digest, size = _hash_path(path)
        preexisting.append(
            {"path": relative, "bytes": size, "sha256": digest.hex()}
        )

    payload: dict[str, Any] = {
        "schema": _BACKEND_RUNTIME_CONTRACT_SCHEMA,
        "backend": backend,
        "project_root_sha256": _project_identity(project_root),
        "isolation_mode": (
            "EXACT_OWNED_PATH_FALLBACK" if ephemeral else "NO_EPHEMERAL_PATHS"
        ),
        "ephemeral_paths": sorted(ephemeral),
        "preexisting_bound_inputs": sorted(
            preexisting, key=lambda item: item["path"]
        ),
    }
    config["_backend_runtime_contract"] = payload
    _validated_backend_runtime_contract(config, project_root)
    _atomic_json(receipt_path, payload)
    return payload


def _build_context_entries(
    config: Mapping[str, Any], project_root: Path
) -> list[tuple[str, EntryPayload]]:
    """Freeze the manifest-owning build context when it differs from scope.

    ``project_root`` is the audit scope, but build and PoC execution commonly
    run from a parent, descendant, or tightly discovered sibling directory.
    Freezing only the source subtree would then allow manifests, lockfiles, or
    dependency sources consumed by the compiler to change without invalidating
    prior evidence.  The driver supplies the mechanically resolved root through
    the private ``_resolved_build_root`` field before snapshot construction.

    Entry identities are relative or opaque; absolute host paths are never
    serialized.  The complete stable context is bound because anything a build
    worker may read can affect compilation or verification.  Existing bounded
    inventory limits remain the fail-closed guard for an unexpectedly broad
    root.
    """
    raw = str(config.get("_resolved_build_root") or "").strip()
    if not raw:
        return [("@build_root_relation", b"project_root")]
    build_root = Path(raw).expanduser().resolve()
    if not build_root.is_dir():
        raise SnapshotInputError(
            f"resolved build root is missing or not a directory: {build_root}"
        )

    raw_contexts = config.get("_resolved_build_context_roots")
    context_roots: list[Path] = [build_root]
    if isinstance(raw_contexts, (list, tuple)):
        for value in raw_contexts:
            candidate = Path(str(value)).expanduser().resolve()
            if candidate not in context_roots:
                context_roots.append(candidate)
    for candidate in context_roots:
        if not candidate.is_dir():
            raise SnapshotInputError(
                f"resolved build context root is missing or not a directory: {candidate}"
            )

    raw_dependencies = config.get("_resolved_compiled_dependency_roots")
    dependency_roots: list[Path] = []
    if isinstance(raw_dependencies, (list, tuple)):
        for value in raw_dependencies:
            candidate = Path(str(value)).expanduser().resolve()
            if candidate not in dependency_roots:
                dependency_roots.append(candidate)
    for candidate in dependency_roots:
        if not candidate.is_dir():
            raise SnapshotInputError(
                f"resolved compiled dependency root is missing: {candidate}"
            )

    # Treat compiled dependency roots as a set, not as an ordered list of
    # independent walks.  Package managers commonly declare both a complete
    # store (for example ``node_modules``) and remapping targets below it.  The
    # outer walk already binds every byte below reachable targets, so replaying
    # those descendants only inflates the immutable inventory and can push an
    # otherwise bounded repository over the snapshot ceiling. Descendants
    # behind the walk's explicit prune set remain independent content roots.
    #
    # ``normcase`` is required on Windows: differently-cased spellings of the
    # same root must not become separate authorities.  Sorting parents before
    # children also makes the result independent of discovery/declaration
    # order.  The resolved paths themselves are never serialized.
    def dependency_path_key(root: Path) -> str:
        return _resolved_path_identity(root)

    unique_dependency_roots: dict[str, Path] = {}
    for root in dependency_roots:
        unique_dependency_roots.setdefault(dependency_path_key(root), root)
    declared_dependency_roots = sorted(
        unique_dependency_roots.values(), key=dependency_path_key
    )
    compiled_content_roots: list[Path] = []
    for root in sorted(
        declared_dependency_roots,
        key=lambda item: (len(item.parts), dependency_path_key(item)),
    ):
        if any(
            _compiled_dependency_walk_reaches(prior, root)
            for prior in compiled_content_roots
        ):
            continue
        compiled_content_roots.append(root)

    # Preserve the mechanically declared topology without exposing absolute
    # host paths.  This distinguishes a single outer declaration from an outer
    # declaration plus explicit remapping roots, while reversed input order is
    # canonical and each file remains content-bound exactly once.
    dependency_declarations: list[dict[str, Any]] = []
    for root in declared_dependency_roots:
        content_index = next(
            index
            for index, content_root in enumerate(compiled_content_roots)
            if _compiled_dependency_walk_reaches(content_root, root)
        )
        content_root = compiled_content_roots[content_index]
        dependency_declarations.append(
            {
                "content_root": content_index,
                "content_relation": (
                    "."
                    if dependency_path_key(root) == dependency_path_key(content_root)
                    else root.relative_to(content_root).as_posix()
                ),
            }
        )

    def relation_to_project(root: Path) -> str:
        if root == project_root:
            return "project_root"
        try:
            return f"descendant:{root.relative_to(project_root).as_posix()}"
        except ValueError:
            try:
                return f"ancestor:{project_root.relative_to(root).as_posix()}"
            except ValueError:
                return "external"

    entries: list[tuple[str, EntryPayload]] = [
        ("@build_context_count", str(len(context_roots)).encode("ascii")),
    ]
    covered_roots: list[Path] = []
    for index, root in enumerate(context_roots):
        # A local dependency nested inside the primary workspace is already
        # content-bound by that workspace walk.  Keep the metadata count stable
        # but do not duplicate every file under a second identity.
        covered = next(
            (prior for prior in covered_roots if _is_descendant_or_equal(root, prior)),
            None,
        )
        label = "build_root" if index == 0 else f"build_context_{index}"
        entries.extend(
            [
                (f"@{label}_relation", relation_to_project(root).encode("utf-8")),
                (f"@{label}_git_head", _git_head(root).encode("ascii")),
                (f"@{label}_git_submodules", _git_submodule_state(root)),
            ]
        )
        if covered is not None:
            entries.append((f"@{label}_covered_by_prior", b"true"))
            continue
        covered_roots.append(root)
        prefix = "build_context" if index == 0 else f"build_context_external/{index}"
        for path in _project_context_files(root):
            if _is_descendant_or_equal(path, project_root):
                continue  # already frozen under context/
            # Preserve the lexical in-root identity.  Resolving first would turn
            # an in-tree file symlink into an external path and either crash or
            # expose a host path. `_hash_path` binds target string and content.
            relative = path.relative_to(root).as_posix()
            entries.append((f"{prefix}/{relative}", path))

    # Compiler-consumed dependency roots need a dedicated walk. The normal
    # project-context inventory intentionally skips node_modules/vendor.
    # Canonical outer roots below bind each declared compiler input exactly
    # once. Directory links are followed only when they resolve into one of the
    # mechanically declared roots, and the link target is bound.
    if dependency_declarations:
        entries.append(
            (
                "@compiled_dependency_declarations",
                json.dumps(
                    dependency_declarations,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
            )
        )
    allowed_link_roots = [
        project_root,
        build_root,
        *context_roots,
        *declared_dependency_roots,
    ]
    for index, dependency_root in enumerate(compiled_content_roots):
        prefix = f"compiled_dependency/{index}"
        visited_directories: set[Path] = set()
        for dirpath, dirnames, filenames in os.walk(dependency_root, followlinks=True):
            directory = Path(dirpath)
            resolved_directory = directory.resolve()
            if resolved_directory in visited_directories:
                dirnames[:] = []
                continue
            visited_directories.add(resolved_directory)
            retained: list[str] = []
            for name in sorted(dirnames):
                child = directory / name
                if _is_compiled_dependency_skip_dir(name):
                    continue
                if child.is_symlink() or _is_reparse_point(child):
                    target = child.resolve()
                    if not any(_is_descendant_or_equal(target, root) for root in allowed_link_roots):
                        raise SnapshotInputError(
                            "compiled dependency directory link escapes declared "
                            f"build inputs: {child}"
                        )
                    relative_link = child.relative_to(dependency_root).as_posix()
                    entries.append(
                        (f"{prefix}/@dirlink/{relative_link}", os.fsencode(os.readlink(child)))
                    )
                retained.append(name)
            dirnames[:] = retained
            for name in sorted(filenames):
                path = directory / name
                relative = path.relative_to(dependency_root).as_posix()
                entries.append((f"{prefix}/{relative}", path))

    raw_files = config.get("_resolved_build_context_files")
    if isinstance(raw_files, (list, tuple)):
        for index, value in enumerate(raw_files):
            path = Path(str(value)).expanduser().resolve()
            if not path.is_file():
                raise SnapshotInputError(f"resolved build context file is missing: {path}")
            opaque = _sha256(str(path).encode("utf-8"))
            entries.append((f"build_context_file/{index}/{opaque}/{path.name}", path))
    return entries


def _casefold_production_source_files(
    project_root: Path,
    suffixes: tuple[str, ...],
    *,
    dependency_roots: Iterable[Path] = (),
) -> list[Path]:
    """Use the canonical production predicate with case-insensitive suffixes."""
    wanted = {suffix.lower() for suffix in suffixes}
    frozen_dependency_roots = {Path(path).resolve() for path in dependency_roots}
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        retained: list[str] = []
        for name in dirnames:
            directory = Path(dirpath) / name
            if (
                not _is_project_context_skip_dir(name, directory)
                and not name.startswith(".")
                and directory.resolve() not in frozen_dependency_roots
            ):
                retained.append(name)
        dirnames[:] = retained
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in wanted:
                continue
            if is_production_source_path(path, project_root):
                out.append(path)
    return sorted(out)


def _snapshot_foundry_dependency_roots(
    config: Mapping[str, Any], project_root: Path
) -> tuple[Path, ...]:
    if str(config.get("language") or "").strip().lower() != "evm":
        return ()
    raw = str(config.get("_resolved_build_root") or "").strip()
    build_root = Path(raw).resolve() if raw else project_root.resolve()
    if not raw:
        for candidate in (project_root.resolve(), *project_root.resolve().parents):
            if (candidate / "foundry.toml").is_file():
                build_root = candidate
                break
    manifest = build_root / "foundry.toml"
    if not manifest.is_file():
        return ()
    try:
        with manifest.open("rb") as stream:
            data = tomllib.load(stream)
    except Exception as exc:
        raise SnapshotInputError(
            f"foundry.toml cannot be parsed for production-source scope: {exc}"
        ) from exc
    configured: list[str] = []
    profile = data.get("profile")
    if isinstance(profile, dict):
        for value in profile.values():
            if not isinstance(value, dict):
                continue
            libs = value.get("libs")
            if isinstance(libs, str):
                configured.append(libs)
            elif isinstance(libs, list):
                configured.extend(str(item) for item in libs if isinstance(item, str))
    libs = data.get("libs")
    if isinstance(libs, str):
        configured.append(libs)
    elif isinstance(libs, list):
        configured.extend(str(item) for item in libs if isinstance(item, str))
    if not configured:
        configured = ["lib"]
    return tuple(
        sorted(
            {(build_root / value).resolve() for value in configured},
            key=lambda path: str(path).casefold(),
        )
    )


def _scope_target_identity(path: Path) -> str:
    """Return the filesystem-appropriate identity for an already-resolved path.

    Windows path lookup is case-insensitive, so case variants must collapse to
    one target. POSIX filesystems are case-sensitive by default; folding there
    can silently discard one of two distinct in-scope source files.
    """
    value = str(path)
    return value.casefold() if os.name == "nt" else value


def _scope_file_targets(
    config: Mapping[str, Any], project_root: Path
) -> list[Path]:
    try:
        scope_match_mode = normalize_scope_match_mode(
            config.get("scope_match_mode", "legacy")
        )
    except ValueError as exc:
        raise SnapshotInputError(str(exc)) from exc
    raw_scope = str(config.get("scope_file") or "").strip()
    if not raw_scope:
        if scope_match_mode == "exact":
            raise SnapshotInputError(
                "exact scope matching requires a scope_file"
            )
        return []
    if re.match(r"^https?://", raw_scope, re.IGNORECASE):
        raise SnapshotInputError(
            "remote scope files must be fetched into an immutable local input bundle"
        )
    scope_path = Path(raw_scope).expanduser()
    if not scope_path.is_absolute():
        scope_path = project_root / scope_path
    try:
        text = scope_path.read_text(encoding="utf-8-sig")
    except Exception as exc:
        raise SnapshotInputError(f"scope_file is unreadable: {scope_path}") from exc

    if scope_match_mode == "exact":
        if bool(config.get("allow_external_scope_targets", False)):
            raise SnapshotInputError(
                "exact scope authority does not permit external targets"
            )
        try:
            rows = validate_exact_scope_authority(
                project_root,
                scope_path,
                pipeline=str(config.get("pipeline") or "sc"),
                ecosystem=str(config.get("language") or ""),
            )
        except ValueError as exc:
            raise SnapshotInputError(str(exc)) from exc
        return [
            (project_root / Path(row)).resolve()
            for row in rows
        ]

    allow_external = bool(config.get("allow_external_scope_targets", False))
    targets: dict[str, Path] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "<!--")):
            continue
        matches = list(_SCOPE_PATH_RE.finditer(stripped))
        for match in matches:
            token = match.group("path").strip(" `\t|-:")
            if not token:
                continue
            candidate = Path(token).expanduser()
            if not candidate.is_absolute():
                candidate = project_root / candidate
            # A scope line may be a glob. Expand deterministically from root.
            if any(char in token for char in "*?["):
                pattern = token.replace("\\", "/")
                expanded = sorted(project_root.glob(pattern))
            else:
                expanded = [candidate]
            if not expanded:
                raise SnapshotInputError(f"scope target did not match: {token}")
            for target in expanded:
                resolved = target.resolve()
                try:
                    resolved.relative_to(project_root)
                except ValueError:
                    if not allow_external:
                        raise SnapshotInputError(
                            f"scope target escapes project_root: {token}"
                        )
                if resolved.is_dir():
                    children = [
                        child for child in sorted(resolved.rglob("*"))
                        if child.is_file() and child.suffix.lower() in _ALL_SOURCE_SUFFIXES
                    ]
                    if not children:
                        raise SnapshotInputError(
                            f"scope directory has no auditable source: {token}"
                        )
                    for child in children:
                        resolved_child = child.resolve()
                        targets[_scope_target_identity(resolved_child)] = resolved_child
                elif resolved.is_file():
                    targets[_scope_target_identity(resolved)] = resolved
                else:
                    raise SnapshotInputError(f"scope target is missing: {token}")
    if text.strip() and not targets:
        raise SnapshotInputError(
            "scope_file contains no parseable auditable targets; use one path per row"
        )
    return [targets[key] for key in sorted(targets)]


def _git_head(project_root: Path) -> str:
    # Avoid spawning a capability-bearing process for an input that is
    # mechanically known not to be a Git worktree.
    if not (project_root / ".git").exists():
        return "UNAVAILABLE"
    try:
        result = run_owned_process(
            ["git", "-C", str(project_root), "rev-parse", "--verify", "HEAD"],
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        value = result.stdout.strip()
        if result.returncode == 0 and _GIT_HEAD_RE.fullmatch(value.lower()):
            return value.lower()
    except Exception:
        pass
    return "UNAVAILABLE"


def _git_submodule_state(project_root: Path) -> bytes:
    """Bind dependency checkout identity and dirty/uninitialized markers."""
    if not (project_root / ".git").exists():
        return b"UNAVAILABLE:NOT_A_GIT_WORKTREE"
    if not (project_root / ".gitmodules").is_file():
        return b"NO_SUBMODULES"
    try:
        result = run_owned_process(
            ["git", "-C", str(project_root), "submodule", "status", "--recursive"],
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.replace("\r\n", "\n").encode("utf-8", "replace")
        return f"UNAVAILABLE:rc={result.returncode}".encode("ascii", "replace")
    except Exception as exc:
        return f"UNAVAILABLE:{type(exc).__name__}".encode("ascii", "replace")


def _external_input_entries(
    config: Mapping[str, Any], project_root: Path
) -> list[tuple[str, EntryPayload]]:
    """Bind user-provided scope and documentation inputs, including externals."""
    entries: list[tuple[str, EntryPayload]] = []
    total_files = 0
    total_bytes = 0
    for key in ("scope_file", "docs_path"):
        raw = str(config.get(key) or "").strip()
        if not raw:
            continue
        if re.match(r"^https?://", raw, re.IGNORECASE):
            raise SnapshotInputError(
                f"remote {key} must be fetched into an immutable local input bundle"
            )
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = project_root / path
        resolved = path.resolve()
        if not resolved.exists():
            raise SnapshotInputError(f"configured {key} does not exist: {resolved}")
        opaque_root = _sha256(str(resolved).encode("utf-8"))
        if resolved.is_dir():
            found = False
            for child in sorted(resolved.rglob("*")):
                if not child.is_file() or any(
                    part.startswith(".") or part in _MANIFEST_SKIP_DIRS
                    for part in child.relative_to(resolved).parts[:-1]
                ):
                    continue
                found = True
                relative = child.relative_to(resolved).as_posix()
                entries.append((f"{key}/{opaque_root}/{relative}", child))
                total_files += 1
                try:
                    total_bytes += child.stat().st_size
                except OSError as exc:
                    raise SnapshotInputError(
                        f"configured {key} contains an unreadable input: {child}"
                    ) from exc
            if not found:
                raise SnapshotInputError(f"configured {key} directory is empty: {resolved}")
        else:
            if not resolved.is_file():
                raise SnapshotInputError(f"configured {key} is not a regular file: {resolved}")
            entries.append((f"{key}/{opaque_root}", resolved))
            total_files += 1
            total_bytes += resolved.stat().st_size
        if total_files > _MAX_EXTERNAL_INPUT_FILES or total_bytes > _MAX_EXTERNAL_INPUT_BYTES:
            raise SnapshotInputError(
                "external audit inputs exceed bounded file/byte limits; "
                "provide a smaller immutable bundle"
            )
    return entries


def _source_scope_inventory(
    config: Mapping[str, Any],
) -> tuple[
    Path,
    str,
    str,
    list[Path],
    list[Path],
    list[Path],
]:
    """Resolve the exact production/build/scope roster used by source_scope."""

    raw_root = str(config.get("project_root") or "").strip()
    if not raw_root:
        raise SnapshotInputError("project_root is required")
    project_root = Path(raw_root).resolve()
    if not project_root.is_dir():
        raise SnapshotInputError(f"project_root is missing or not a directory: {project_root}")
    language = str(config.get("language") or "").strip().lower()
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    if pipeline not in {"sc", "l1"}:
        raise SnapshotInputError(f"unsupported audit pipeline: {pipeline!r}")
    suffixes = _L1_SOURCE_SUFFIXES if pipeline == "l1" else _SOURCE_SUFFIXES.get(language)
    if suffixes is None:
        # Unknown language is not permission to hash no source.  Hash every
        # supported production suffix and let startup's language gate decide.
        suffixes = _ALL_SOURCE_SUFFIXES

    production_files: list[Path] = []
    dependency_roots = _snapshot_foundry_dependency_roots(config, project_root)
    for path in _casefold_production_source_files(
        project_root, tuple(suffixes), dependency_roots=dependency_roots
    ):
        if _is_generated_verification_source(path, project_root):
            continue
        production_files.append(path)

    build_source_files: list[Path] = []
    raw_build_sources = config.get("_resolved_build_source_files")
    if isinstance(raw_build_sources, (list, tuple)):
        for value in raw_build_sources:
            path = Path(str(value)).expanduser().resolve()
            if not path.is_file() or path.suffix.lower() not in set(suffixes):
                raise SnapshotInputError(
                    f"resolved build source is missing or has wrong suffix: {path}"
                )
            build_source_files.append(path)

    scope_targets = _scope_file_targets(config, project_root)
    if not production_files and not build_source_files and not scope_targets:
        raise SnapshotInputError(
            "no auditable production source or explicit scope target was found"
        )
    return (
        project_root,
        language,
        pipeline,
        production_files,
        build_source_files,
        scope_targets,
    )


def _source_component(config: Mapping[str, Any]) -> dict[str, Any]:
    (
        project_root,
        language,
        pipeline,
        production_files,
        build_source_files,
        scope_targets,
    ) = _source_scope_inventory(config)
    limitations: list[str] = []
    build_input_limitations = config.get("_snapshot_build_input_limitations")
    if isinstance(build_input_limitations, (list, tuple)):
        reason = "; ".join(
            re.sub(r"\s+", " ", str(item)).strip()
            for item in build_input_limitations
            if str(item).strip()
        )[:1200]
    else:
        reason = ""
    if reason:
        limitations.append(
            "BUILD_INPUT_PREPARATION_DEGRADED: dependency/build input "
            f"preparation cannot be complete ({reason}); source-only findings "
            "remain valid but build/AST/PoC completeness requires human review"
        )
    vyper_production = [
        path for path in production_files if path.suffix.lower() == ".vy"
    ]
    vyper_explicit = [
        path for path in scope_targets if path.suffix.lower() == ".vy"
    ]
    if vyper_production or vyper_explicit:
        limitations.append(
            "VYPER_END_TO_END_COVERAGE_UNPROVEN: inputs are content-bound, "
            "but compiler/AST/PoC/methodology parity with Solidity is not established"
        )
        production_non_vyper = [
            path for path in production_files if path.suffix.lower() != ".vy"
        ]
        if (
            vyper_explicit or not production_non_vyper
        ) and not bool(config.get("allow_incomplete_vyper_coverage", False)):
            raise SnapshotInputError(
                "Vyper is explicitly/solely in scope but no end-to-end Vyper "
                "audit lane is proven; set allow_incomplete_vyper_coverage "
                "only for a deliberately degraded human-review run"
            )

    # Bind the complete stable project context agents can consume, not merely
    # deployable source. This closes the committed/dirty README, schema, test,
    # and build-configuration asymmetry while excluding caches and generated
    # audit outputs.
    entries: list[tuple[str, EntryPayload]] = []
    context_paths: set[str] = set()
    runtime_contract = _validated_backend_runtime_contract(config, project_root)
    runtime_exclusions = frozenset(
        (
            item.casefold() if os.name == "nt" else item
        )
        for item in (
            runtime_contract.get("ephemeral_paths", [])
            if runtime_contract is not None
            else []
        )
    )
    if runtime_contract is not None:
        entries.append(
            ("@backend_runtime_contract", _canonical_json(runtime_contract))
        )
    configured_scratchpad = str(config.get("scratchpad") or "").strip()
    excluded_project_roots = (
        (Path(configured_scratchpad).expanduser().resolve(),)
        if configured_scratchpad
        else ()
    )
    for path in _project_context_files(
        project_root,
        excluded_runtime_paths=runtime_exclusions,
        excluded_roots=excluded_project_roots,
    ):
        relative = path.relative_to(project_root).as_posix()
        context_paths.add(str(path.resolve()).casefold())
        entries.append((f"context/{relative}", path))

    entries.extend(_build_context_entries(config, project_root))

    # Scope targets bypass default dependency/test exclusions. External targets
    # receive opaque identities so absolute host paths are not leaked.
    for target in scope_targets:
        resolved = target.resolve()
        if str(resolved).casefold() in context_paths:
            continue
        try:
            relative = resolved.relative_to(project_root).as_posix()
            label = f"explicit_scope/{relative}"
        except ValueError:
            label = f"explicit_scope/@outside/{_sha256(str(resolved).encode('utf-8'))}"
        entries.append((label, resolved))

    entries.extend(_external_input_entries(config, project_root))

    production_names = [
        path.resolve().relative_to(project_root).as_posix()
        for path in production_files
    ]
    production_names.extend(
        f"@build_context/{_sha256(str(path.resolve()).encode('utf-8'))}/{path.name}"
        for path in build_source_files
    )
    explicit_names = []
    for path in scope_targets:
        try:
            explicit_names.append(path.resolve().relative_to(project_root).as_posix())
        except ValueError:
            explicit_names.append(f"@outside/{_sha256(str(path.resolve()).encode('utf-8'))}")
    entries.append(("@production_paths", _canonical_json(sorted(production_names))))
    entries.append(("@explicit_scope_paths", _canonical_json(sorted(explicit_names))))

    # Commit identity is part of the frozen audit target even if a commit only
    # changes out-of-scope files.  The content digest still protects dirty and
    # non-git worktrees.
    git_head = _git_head(project_root)
    entries.append(("@git_head", git_head.encode("ascii")))
    entries.append(("@git_submodules", _git_submodule_state(project_root)))
    component = _digest_entries(entries)
    component.update(
        {
            "language": language,
            "pipeline": pipeline,
            "git_head": git_head,
            "coverage_limitations": limitations,
        }
    )
    return component


def _production_source_names(config: Mapping[str, Any]) -> list[str]:
    (
        project_root,
        _language,
        _pipeline,
        production_files,
        build_source_files,
        scope_targets,
    ) = _source_scope_inventory(config)
    names = [
        path.resolve().relative_to(project_root).as_posix()
        for path in production_files
    ]
    names.extend(
        f"@build_context/{_sha256(str(path.resolve()).encode('utf-8'))}/{path.name}"
        for path in build_source_files
    )
    for path in scope_targets:
        try:
            names.append(path.resolve().relative_to(project_root).as_posix())
        except ValueError:
            names.append(
                f"@outside/{_sha256(str(path.resolve()).encode('utf-8'))}"
            )
    return sorted(set(names))


_SOURCE_PATH_WINDOWS_RESERVED_STEMS = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        "clock$",
        "conin$",
        "conout$",
        *(f"com{ordinal}" for ordinal in range(1, 10)),
        *(f"lpt{ordinal}" for ordinal in range(1, 10)),
    }
)


def _canonical_production_source_name(value: object) -> str:
    """Validate one host-independent project-relative/synthetic source name."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise SnapshotInputError(
            "production source-path authority contains an empty/noncanonical path"
        )
    if (
        "\\" in value
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
        or "//" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or any(char in '<>:"|?*' for char in value)
    ):
        raise SnapshotInputError(
            f"production source-path authority path is not cross-OS relative: {value!r}"
        )
    parts = value.split("/")
    if (
        any(part in {"", ".", ".."} for part in parts)
        or any(part.rstrip(" .") != part for part in parts)
        or any(
            part.split(".", 1)[0].casefold()
            in _SOURCE_PATH_WINDOWS_RESERVED_STEMS
            for part in parts
        )
        or PurePosixPath(value).as_posix() != value
    ):
        raise SnapshotInputError(
            f"production source-path authority path is noncanonical: {value!r}"
        )
    return value


def validate_production_source_path_authority(
    value: object,
    *,
    expected_snapshot: Mapping[str, Any] | None = None,
    expected_config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the typed production-path roster without host-path leakage."""

    required = {
        "schema",
        "snapshot_digest",
        "source_scope_digest",
        "pipeline",
        "language",
        "source_paths",
        "source_path_count",
        "source_path_set_digest",
        "authority_digest",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise SnapshotInputError("production source-path authority schema is invalid")
    if value.get("schema") != "plamen.report_source_path_authority.v1":
        raise SnapshotInputError("production source-path authority version differs")
    paths = value.get("source_paths")
    if (
        not isinstance(paths, list)
        or not paths
        or any(not isinstance(path, str) or not path for path in paths)
        or paths != sorted(set(paths))
    ):
        raise SnapshotInputError("production source-path authority roster is invalid")
    canonical_paths = [
        _canonical_production_source_name(path) for path in paths
    ]
    for field in (
        "snapshot_digest",
        "source_scope_digest",
        "source_path_set_digest",
        "authority_digest",
    ):
        raw = value.get(field)
        if not isinstance(raw, str) or _HEX_64_RE.fullmatch(raw) is None:
            raise SnapshotInputError(
                f"production source-path authority {field} is invalid"
            )
    if (
        type(value.get("source_path_count")) is not int
        or value["source_path_count"] != len(paths)
        or value["source_path_set_digest"] != _sha256(_canonical_json(paths))
        or value.get("pipeline") not in {"sc", "l1"}
        or not isinstance(value.get("language"), str)
    ):
        raise SnapshotInputError("production source-path authority content differs")
    unsigned = dict(value)
    supplied = unsigned.pop("authority_digest")
    if supplied != _sha256(_canonical_json(unsigned)):
        raise SnapshotInputError("production source-path authority digest differs")
    if expected_snapshot is not None:
        if not _valid_snapshot(expected_snapshot):
            raise SnapshotInputError("bound audit snapshot is invalid")
        source = expected_snapshot["components"]["source_scope"]
        if (
            value["snapshot_digest"] != expected_snapshot["snapshot_digest"]
            or value["source_scope_digest"] != source["digest"]
            or value["pipeline"] != source["pipeline"]
            or value["language"] != source["language"]
        ):
            raise SnapshotInputError(
                "production source-path authority differs from bound snapshot"
            )
    if expected_config is not None:
        if expected_snapshot is None:
            raise SnapshotInputError(
                "production source-path config validation requires a bound snapshot"
            )
        current_source = _source_component(expected_config)
        bound_source = expected_snapshot["components"]["source_scope"]
        if current_source != bound_source:
            raise SnapshotInputError(
                "production source scope changed from bound config/snapshot"
            )
        recomputed_paths = _production_source_names(expected_config)
        if canonical_paths != recomputed_paths:
            raise SnapshotInputError(
                "production source-path roster differs from bound config"
            )
    return {
        "schema": value["schema"],
        "snapshot_digest": value["snapshot_digest"],
        "source_scope_digest": value["source_scope_digest"],
        "pipeline": value["pipeline"],
        "language": value["language"],
        "source_paths": canonical_paths,
        "source_path_count": len(paths),
        "source_path_set_digest": value["source_path_set_digest"],
        "authority_digest": value["authority_digest"],
    }


def build_production_source_path_authority(
    config: Mapping[str, Any],
    audit_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a path roster only when the complete source component still matches."""

    if not _valid_snapshot(audit_snapshot):
        raise SnapshotInputError("bound audit snapshot is invalid")
    current_source = _source_component(config)
    bound_source = audit_snapshot["components"]["source_scope"]
    if current_source != bound_source:
        raise SnapshotInputError(
            "audited source scope changed before report path authority"
        )
    paths = _production_source_names(config)
    payload: dict[str, Any] = {
        "schema": "plamen.report_source_path_authority.v1",
        "snapshot_digest": audit_snapshot["snapshot_digest"],
        "source_scope_digest": bound_source["digest"],
        "pipeline": bound_source["pipeline"],
        "language": bound_source["language"],
        "source_paths": paths,
        "source_path_count": len(paths),
        "source_path_set_digest": _sha256(_canonical_json(paths)),
        "authority_digest": "",
    }
    unsigned = dict(payload)
    unsigned.pop("authority_digest")
    payload["authority_digest"] = _sha256(_canonical_json(unsigned))
    return validate_production_source_path_authority(
        payload,
        expected_snapshot=audit_snapshot,
        expected_config=config,
    )


def canonical_production_source_path_authority_bytes(
    value: object,
    *,
    expected_snapshot: Mapping[str, Any] | None = None,
    expected_config: Mapping[str, Any] | None = None,
) -> bytes:
    normalized = validate_production_source_path_authority(
        value,
        expected_snapshot=expected_snapshot,
        expected_config=expected_config,
    )
    return _canonical_json(normalized) + b"\n"


def _config_component(config: Mapping[str, Any]) -> dict[str, Any]:
    semantic = _semantic_config(config)
    return {
        "digest": _sha256(_canonical_json(semantic)),
        "field_count": len(semantic),
    }


def build_methodology_snapshot_component(
    implementation_root: Path,
) -> dict[str, Any]:
    """Build the one canonical content identity for audit methodology.

    Deterministic runtime providers use this public helper to prove that a
    derived methodology projection came from the same implementation bytes as
    the startup audit snapshot.  Keeping the directory denominator and hashing
    algorithm here prevents a second, subtly different definition of
    "methodology" at a later phase boundary.
    """
    implementation_root = Path(implementation_root).resolve()
    if not implementation_root.is_dir():
        raise SnapshotInputError(
            "methodology implementation root is missing or not a directory: "
            f"{implementation_root}"
        )
    return _digest_entries(_tree_entries(implementation_root, _METHODOLOGY_DIRS))


def _methodology_component(implementation_root: Path) -> dict[str, Any]:
    return build_methodology_snapshot_component(implementation_root)


def _toolchain_component(
    implementation_root: Path,
    *,
    project_root: Path | None = None,
    config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    def _include(path: Path, rel: str) -> bool:
        lowered = rel.replace("\\", "/").lower()
        if any(part in {"__pycache__", ".pytest_cache", ".git"} for part in lowered.split("/")):
            return False
        return not path.name.startswith("test_") and path.suffix.lower() != ".pyc"

    entries = _tree_entries(implementation_root, _TOOLCHAIN_DIRS, include=_include)
    for name in _TOOLCHAIN_ROOT_FILES:
        path = implementation_root / name
        if path.is_file():
            entries.append((name, path))
    entries.extend(
        _runtime_tool_entries(project_root=project_root, config=config)
    )
    component = _digest_entries(entries)
    component["runtime_entries"] = _runtime_entry_manifest(entries)
    return component


def _command_version(command: tuple[str, ...]) -> bytes:
    try:
        result = run_owned_process(
            list(command),
            encoding="utf-8",
            errors="replace",
            timeout=3,
        )
        output = (result.stdout or result.stderr).strip()
        return f"rc={result.returncode}\n{output[:4096]}".encode("utf-8", "replace")
    except FileNotFoundError:
        return b"UNAVAILABLE"
    except subprocess.TimeoutExpired:
        return b"TIMEOUT"
    except Exception as exc:
        return f"ERROR:{type(exc).__name__}".encode("ascii", "replace")


def _semantic_probe_output(tool_id: str, raw: bytes) -> str:
    """Separate stable semantic state from bounded raw failure evidence."""

    text = raw.decode("utf-8", "replace").strip()
    upper = text.upper()
    if upper in {"UNAVAILABLE", "TIMEOUT"} or upper.startswith("ERROR:"):
        return text
    first, _separator, _rest = text.partition("\n")
    match = re.fullmatch(r"rc=(-?[0-9]+)", first.strip())
    if match is None:
        _TOOL_PROBE_DIAGNOSTICS[tool_id] = text[:4096]
        return "PROBE_FAILED:MALFORMED"
    return_code = int(match.group(1))
    if return_code == 0:
        return text
    _TOOL_PROBE_DIAGNOSTICS[tool_id] = text[:4096]
    return f"PROBE_FAILED:RC_{return_code}"


def _load_toolchain_identity_controls_legacy() -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    str,
    str,
]:
    """Load local reviewed identity controls without acquiring any tool."""
    try:
        lock_raw = _TOOLCHAIN_VERSION_LOCK_PATH.read_bytes()
        governance_raw = _TOOLCHAIN_GOVERNANCE_PATH.read_bytes()
        lock = json.loads(lock_raw)
        governance = json.loads(governance_raw)
    except Exception as exc:
        raise SnapshotInputError(
            "toolchain identity controls are unreadable"
        ) from exc
    identities = lock.get("identities") if isinstance(lock, dict) else None
    tools = governance.get("tools") if isinstance(governance, dict) else None
    reviewed_lock = (
        governance.get("reviewed_version_lock")
        if isinstance(governance, dict)
        else None
    )
    if (
        lock.get("schema_version") != TOOLCHAIN_VERSION_LOCK_SCHEMA
        or governance.get("schema_version") != TOOLCHAIN_GOVERNANCE_SCHEMA
        or not isinstance(identities, list)
        or not identities
        or not isinstance(tools, list)
        or not tools
        or not isinstance(reviewed_lock, dict)
        or reviewed_lock.get("path")
        != "verification_policy/toolchain_version_lock.v1.json"
        or reviewed_lock.get("schema_version")
        != TOOLCHAIN_VERSION_LOCK_SCHEMA
    ):
        raise SnapshotInputError(
            "toolchain identity version-lock schema/path is invalid"
        )
    reviewed_lock_digest = str(reviewed_lock.get("sha256") or "")
    observed_lock_digest = hashlib.sha256(lock_raw).hexdigest()
    runtime_statuses = reviewed_lock.get("runtime_statuses")
    if (
        re.fullmatch(r"[0-9a-f]{64}", reviewed_lock_digest) is None
        or reviewed_lock_digest != observed_lock_digest
        or not isinstance(runtime_statuses, list)
        or len(runtime_statuses) != len(set(runtime_statuses))
        or set(runtime_statuses)
        != {
            "MATCH",
            "MISMATCH",
            "UNAVAILABLE",
            "EXTERNAL_MANAGER",
            "DEBT",
            "UNREGISTERED",
            "REVOKED",
        }
    ):
        raise SnapshotInputError(
            "toolchain version-lock digest/statuses do not match governance"
        )
    locked: dict[str, dict[str, Any]] = {}
    for row in identities:
        if not isinstance(row, dict):
            raise SnapshotInputError(
                "toolchain version-lock identity is invalid"
            )
        identity_id = str(row.get("identity_id") or "")
        expected = str(row.get("expected_version") or "")
        identity_kind = str(row.get("identity_kind") or "")
        parser = str(row.get("version_output_parser") or "")
        package_name = str(row.get("package_name") or "")
        install_spec = str(row.get("install_spec") or "")
        probe = row.get("version_probe")
        if (
            not identity_id
            or identity_id in locked
            or re.fullmatch(r"\d+\.\d+\.\d+", expected) is None
            or identity_kind not in {"command", "python_distribution"}
            or parser
            not in {"SCIP_GO_EXACT_V1", "PYTHON_METADATA_EXACT"}
            or not package_name
            or not isinstance(probe, list)
            or not probe
            or not all(isinstance(item, str) and item for item in probe)
            or row.get("acquisition_scope") != "SETUP_ONLY"
            or row.get("deterministic_provider_authority_requires")
            != "MATCH"
        ):
            raise SnapshotInputError(
                "toolchain version-lock identity is invalid"
            )
        if identity_kind == "python_distribution":
            if (
                not str(row.get("python_module") or "")
                or parser != "PYTHON_METADATA_EXACT"
                or install_spec
                != f"{package_name}=={expected}"
                or probe
                != ["python-importlib-metadata", package_name]
            ):
                raise SnapshotInputError(
                    "toolchain version-lock Python module binding is invalid"
                )
            generated_version = str(
                row.get("generated_code_version") or ""
            )
            if generated_version:
                generated = _semantic_version_tuple(generated_version)
                runtime = _semantic_version_tuple(expected)
                if (
                    generated is None
                    or runtime is None
                    or generated[0] != runtime[0]
                    or generated > runtime
                    or (
                        identity_id == "protobuf"
                        and row.get("generated_module_path")
                        != "plamen_l1/scip_pb2.py"
                    )
                ):
                    raise SnapshotInputError(
                        "toolchain version-lock generated/runtime binding "
                        "is invalid"
                    )
            if identity_id == "protobuf" and not generated_version:
                raise SnapshotInputError(
                    "toolchain version-lock generated/runtime binding "
                    "is invalid"
                )
        if identity_kind == "command" and (
            parser != "SCIP_GO_EXACT_V1"
            or install_spec != f"{package_name}@v{expected}"
            or probe[0] != identity_id
        ):
            raise SnapshotInputError(
                "toolchain version-lock identity/install binding is invalid"
            )
        if identity_id == "scip-go":
            if (
                row.get("go_command_path")
                != "github.com/scip-code/scip-go/cmd/scip-go"
                or row.get("go_module_path")
                != "github.com/scip-code/scip-go"
                or package_name != row.get("go_command_path")
            ):
                raise SnapshotInputError(
                    "toolchain version-lock Go build binding is invalid"
                )
        locked[identity_id] = dict(row)
    governed: dict[str, dict[str, Any]] = {}
    lock_references: dict[str, list[str]] = {}
    for row in tools:
        if not isinstance(row, dict):
            raise SnapshotInputError(
                "toolchain governance identity is invalid"
            )
        tool_id = str(row.get("tool_id") or "")
        authority = row.get("runtime_authority")
        update = row.get("update_policy")
        revocation = row.get("revocation_policy")
        blocked_versions = (
            revocation.get("blocked_version_substrings")
            if isinstance(revocation, dict)
            else None
        )
        blocked_digests = (
            revocation.get("blocked_executable_sha256")
            if isinstance(revocation, dict)
            else None
        )
        if (
            not tool_id
            or tool_id in governed
            or not isinstance(authority, dict)
            or authority.get("identity_status")
            not in {
                "MATCH",
                "EXTERNAL_MANAGER",
                "DEBT",
                "UNREGISTERED",
            }
            or not isinstance(
                authority.get("deterministic_provider_authority"),
                bool,
            )
            or not isinstance(update, dict)
            or not str(update.get("state") or "")
            or not str(update.get("acquisition_scope") or "")
            or not isinstance(revocation, dict)
            or set(revocation)
            != {
                "blocked_version_substrings",
                "blocked_executable_sha256",
            }
            or not isinstance(blocked_versions, list)
            or not all(
                isinstance(value, str) and bool(value.strip())
                for value in blocked_versions
            )
            or not isinstance(blocked_digests, list)
            or not all(
                isinstance(value, str)
                and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                for value in blocked_digests
            )
        ):
            raise SnapshotInputError(
                "toolchain governance identity/revocation is invalid"
            )
        state = str(update["state"])
        acquisition_scope = str(update["acquisition_scope"])
        mismatch_effect = str(authority.get("mismatch_effect") or "")
        semantic_match = False
        if state == "EXACT_REVIEWED_RELEASE":
            semantic_match = (
                acquisition_scope == "SETUP_ONLY"
                and authority
                == {
                    "identity_status": "MATCH",
                    "deterministic_provider_authority": True,
                    "mismatch_effect": "FAIL_PROVIDER_SELECTION",
                }
                and bool(str(update.get("version_lock_identity") or ""))
            )
        elif state == "GOVERNED_DEBT":
            semantic_match = (
                acquisition_scope == "SETUP_ONLY"
                and update.get("unresolved_debt") is True
                and bool(str(update.get("reason") or "").strip())
                and authority
                == {
                    "identity_status": "DEBT",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": "CAPABILITY_DEBT_NO_CLEAN_AUTHORITY",
                }
            )
        elif state in {
            "EXTERNAL_TOOLCHAIN_MANAGER",
            "EXTERNAL_PLATFORM_MANAGER",
        }:
            semantic_match = (
                acquisition_scope == "EXTERNAL_OPERATOR_SETUP"
                and authority
                == {
                    "identity_status": "EXTERNAL_MANAGER",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": "SNAPSHOT_OBSERVED_IDENTITY_ONLY",
                }
            )
        elif state == "HUMAN_REVIEWED_DIGEST_REQUIRED":
            semantic_match = (
                acquisition_scope == "EXTERNAL_OPERATOR_SETUP"
                and authority
                == {
                    "identity_status": "DEBT",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": "FAIL_WITHOUT_REVIEWED_DIGEST",
                }
            )
        if not semantic_match or not mismatch_effect:
            raise SnapshotInputError(
                f"toolchain governance semantics are invalid: {tool_id}"
            )
        reference = str(update.get("version_lock_identity") or "")
        if reference:
            lock_references.setdefault(reference, []).append(tool_id)
        governed[tool_id] = dict(row)
    for identity_id, locked_row in locked.items():
        references = lock_references.get(identity_id, [])
        governed_row = governed.get(identity_id)
        if references != [identity_id] or governed_row is None:
            raise SnapshotInputError(
                "each version-lock identity must have exactly one matching "
                f"governance row: {identity_id}"
            )
        update = governed_row["update_policy"]
        authority = governed_row["runtime_authority"]
        if (
            update.get("state") != "EXACT_REVIEWED_RELEASE"
            or update.get("acquisition_scope")
            != locked_row["acquisition_scope"]
            or authority
            != {
                "identity_status": "MATCH",
                "deterministic_provider_authority": True,
                "mismatch_effect": "FAIL_PROVIDER_SELECTION",
            }
        ):
            raise SnapshotInputError(
                "version-lock and governance authority do not reconcile: "
                f"{identity_id}"
            )
    unknown_references = set(lock_references) - set(locked)
    if unknown_references:
        raise SnapshotInputError(
            "toolchain governance references an unknown version-lock identity"
        )
    return (
        locked,
        governed,
        hashlib.sha256(lock_raw).hexdigest(),
        hashlib.sha256(governance_raw).hexdigest(),
    )


def _load_toolchain_identity_controls() -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    str,
    str,
]:
    """Load the same single-read control pair used by setup and the ledger."""

    try:
        controls = _toolchain_controls.load_toolchain_controls(
            _TOOLCHAIN_GOVERNANCE_PATH,
            _TOOLCHAIN_VERSION_LOCK_PATH,
        )
    except _toolchain_controls.ToolchainControlError as exc:
        raise SnapshotInputError(str(exc)) from exc
    return (
        {
            identity_id: dict(row)
            for identity_id, row in controls.locked.items()
        },
        {
            tool_id: dict(row)
            for tool_id, row in controls.governed.items()
        },
        controls.lock_sha256,
        controls.governance_sha256,
    )


def _locked_version_output_matches(
    tool_id: str,
    observed: str,
    controls: tuple[
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
        str,
        str,
    ]
    | None = None,
) -> bool:
    """Match exactly one tool-owned version statement.

    A compatibility token, dependency version, or second plausible version
    line is never enough to mint MATCH.
    """

    locked, _governed, _lock_digest, _governance_digest = (
        controls if controls is not None else _load_toolchain_identity_controls()
    )
    row = locked.get(tool_id)
    if row is None:
        return False
    expected = str(row["expected_version"])
    parser = str(row["version_output_parser"])
    text = str(observed or "").strip()
    if parser == "PYTHON_METADATA_EXACT":
        return text == expected
    if parser != "SCIP_GO_EXACT_V1":
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or lines[0] != "rc=0" or len(lines) != 2:
        return False
    return (
        re.fullmatch(
            rf"(?i:(?:scip-go(?:\s+version)?\s+)?v?{re.escape(expected)})",
            lines[1],
        )
        is not None
    )


def _version_output_matches(expected: str, observed: str) -> bool:
    """Compatibility helper with an exact, whole-output denominator."""

    return str(observed or "").strip() == str(expected or "").strip()


def _observed_version_available(
    *,
    resolved_identity: str,
    version: str,
) -> bool:
    normalized = str(version or "").strip().upper()
    return (
        resolved_identity != "UNAVAILABLE"
        and bool(normalized)
        and normalized not in {"UNAVAILABLE", "TIMEOUT"}
        and not normalized.startswith("ERROR:")
        and not normalized.startswith("PROBE_FAILED:")
    )


def _runtime_identity_policy(
    tool_id: str,
    *,
    resolved_identity: str,
    version: str,
    identity_kind: str = "command",
    controls: tuple[
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
        str,
        str,
    ]
    | None = None,
) -> tuple[dict[str, Any], str, bool, str, str]:
    locked, governed, lock_digest, governance_digest = (
        controls
        if controls is not None
        else _load_toolchain_identity_controls()
    )
    locked_row = locked.get(tool_id)
    governed_row = governed.get(tool_id)
    available = _observed_version_available(
        resolved_identity=resolved_identity,
        version=version,
    )
    if locked_row is not None:
        expected: dict[str, Any] = {
            "policy": (
                str(governed_row["update_policy"]["state"])
                if governed_row is not None
                else "REVIEWED_VERSION_OBSERVED_CONTENT"
            ),
            "version": locked_row["expected_version"],
            "package": locked_row["package_name"],
            "install_spec": locked_row["install_spec"],
            "content_authority": locked_row["content_authority"],
        }
        if "generated_code_version" in locked_row:
            expected["generated_code_version"] = locked_row[
                "generated_code_version"
            ]
        if not available:
            status = "UNAVAILABLE"
        elif identity_kind != locked_row.get("identity_kind"):
            status = "MISMATCH"
        elif _locked_version_output_matches(tool_id, version, controls):
            status = "OBSERVED_NONAUTHORITATIVE"
        else:
            status = "MISMATCH"
        return (
            expected,
            status,
            False,
            lock_digest,
            governance_digest,
        )
    if governed_row is None:
        status = "UNREGISTERED"
    elif not available:
        status = "UNAVAILABLE"
    else:
        status = str(
            governed_row["runtime_authority"]["identity_status"]
        )
    expected = {
        "policy": (
            str(governed_row["update_policy"]["state"])
            if governed_row is not None
            else "UNREGISTERED_DEBT"
        ),
        "version": None,
    }
    return expected, status, False, lock_digest, governance_digest


def _path_is_within(path: Path, root: Path | None) -> bool:
    if root is None:
        return False
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False
    except OSError:
        return True


def _windows_hardlink_aliases(path: Path) -> tuple[Path, ...]:
    """Enumerate every Windows name for one file identity."""

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    first_name = kernel32.FindFirstFileNameW
    first_name.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
    ]
    first_name.restype = wintypes.HANDLE
    next_name = kernel32.FindNextFileNameW
    next_name.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
    ]
    next_name.restype = wintypes.BOOL
    close = kernel32.FindClose
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL

    size = wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(size.value)
    handle = first_name(str(path), 0, ctypes.byref(size), buffer)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(
            ctypes.get_last_error(),
            "FindFirstFileNameW failed",
        )
    aliases: list[Path] = []
    try:
        while True:
            relative = buffer.value.lstrip("\\/")
            aliases.append(
                (Path(path.anchor) / relative).resolve(strict=True)
            )
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if next_name(handle, ctypes.byref(size), buffer):
                continue
            error = ctypes.get_last_error()
            if error == 38:  # ERROR_HANDLE_EOF
                break
            raise OSError(error, "FindNextFileNameW failed")
    finally:
        close(handle)
    return tuple(aliases)


_RETAINED_HARDLINK_DENIAL_FDS: dict[tuple[int, int], int] = {}
_RETAINED_HARDLINK_APPROVALS: dict[
    tuple[int, int],
    tuple[int, tuple[str, ...], str],
] = {}
_RETAINED_HARDLINK_APPROVAL_TAGS: dict[tuple[int, int], bytes] = {}
_RETAINED_HARDLINK_APPROVAL_KEY = os.urandom(32)
_RETAINED_DESCRIPTOR_READ_LOCK = threading.RLock()
_PYTHON_DISTRIBUTION_CLOSURE_CACHE: dict[str, tuple[dict[str, Any], bytes]] = {}
_PYTHON_DISTRIBUTION_CLOSURE_CACHE_KEY = os.urandom(32)


def _retained_hardlink_approval_payload(
    identity: tuple[int, int],
    approval: tuple[int, tuple[str, ...], str],
) -> bytes:
    count, aliases, authority_root = approval
    return _canonical_json({
        "aliases": list(aliases),
        "authority_root": authority_root,
        "identity": list(identity),
        "link_count": count,
    })


def _seal_retained_hardlink_approval(
    identity: tuple[int, int],
    approval: tuple[int, tuple[str, ...], str],
) -> None:
    _RETAINED_HARDLINK_APPROVAL_TAGS[identity] = hmac.new(
        _RETAINED_HARDLINK_APPROVAL_KEY,
        _retained_hardlink_approval_payload(identity, approval),
        hashlib.sha256,
    ).digest()


def _retained_hardlink_approval_is_authentic(
    identity: tuple[int, int],
    approval: tuple[int, tuple[str, ...], str],
) -> bool:
    expected = _RETAINED_HARDLINK_APPROVAL_TAGS.get(identity)
    return expected is not None and hmac.compare_digest(
        expected,
        hmac.new(
            _RETAINED_HARDLINK_APPROVAL_KEY,
            _retained_hardlink_approval_payload(identity, approval),
            hashlib.sha256,
        ).digest(),
    )


def _clear_retained_hardlink_approval_tags() -> None:
    _RETAINED_HARDLINK_APPROVAL_TAGS.clear()


def _python_distribution_closure_cache_tag(payload: Mapping[str, Any]) -> bytes:
    return hmac.new(
        _PYTHON_DISTRIBUTION_CLOSURE_CACHE_KEY,
        _canonical_json(payload),
        hashlib.sha256,
    ).digest()


def _clear_python_distribution_closure_cache() -> None:
    _PYTHON_DISTRIBUTION_CLOSURE_CACHE.clear()


def _read_retained_regular_bytes(
    path: Path,
    identity: tuple[int, int],
    *,
    expected_size: int,
    expected_link_count: int,
    label: str,
    current_info: os.stat_result | None = None,
) -> bytes:
    """Read immutable provider bytes through the retained denial descriptor."""

    descriptor = _RETAINED_HARDLINK_DENIAL_FDS.get(identity)
    if descriptor is None:
        raise SnapshotInputError(f"{label} retained denial handle is missing")
    try:
        current = (
            current_info
            if current_info is not None
            else path.stat(follow_symlinks=False)
        )
        current_identity = (int(current.st_dev), int(current.st_ino))
        attrs = int(getattr(current, "st_file_attributes", 0))
        if (
            current_identity != identity
            or not stat.S_ISREG(current.st_mode)
            or bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            or int(current.st_nlink) != expected_link_count
            or int(current.st_size) != expected_size
        ):
            raise SnapshotInputError(f"{label} retained path identity drifted")
        with _RETAINED_DESCRIPTOR_READ_LOCK:
            held_before = os.fstat(descriptor)
            held_identity = (int(held_before.st_dev), int(held_before.st_ino))
            if (
                held_identity != identity
                or not stat.S_ISREG(held_before.st_mode)
                or int(held_before.st_size) != expected_size
                or int(held_before.st_nlink) != expected_link_count
            ):
                raise SnapshotInputError(
                    f"{label} retained denial identity drifted"
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = expected_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise SnapshotInputError(
                        f"{label} retained bytes were truncated"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise SnapshotInputError(f"{label} retained bytes grew")
            os.lseek(descriptor, 0, os.SEEK_SET)
            held_after = os.fstat(descriptor)
        if (
            (int(held_after.st_dev), int(held_after.st_ino)) != identity
            or int(held_after.st_size) != expected_size
            or int(held_after.st_nlink) != expected_link_count
        ):
            raise SnapshotInputError(f"{label} retained bytes drifted")
        return b"".join(chunks)
    except SnapshotInputError:
        raise
    except (OSError, ValueError) as exc:
        raise SnapshotInputError(f"{label} retained bytes are unreadable") from exc


def _windows_default_stream_primitives() -> tuple[Any, Any, Any, Any, Any]:
    """Capture the direct native stream-enumeration call surface once."""

    import ctypes
    from ctypes import wintypes

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", ctypes.c_longlong),
            ("cStreamName", wintypes.WCHAR * 296),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(WIN32_FIND_STREAM_DATA),
        wintypes.DWORD,
    ]
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(WIN32_FIND_STREAM_DATA),
    ]
    find_next.restype = wintypes.BOOL
    close = kernel32.FindClose
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    return ctypes, WIN32_FIND_STREAM_DATA, find_first, find_next, close


def _assert_windows_default_stream_only(
    path: Path,
    *,
    label: str,
    _primitives: tuple[Any, Any, Any, Any, Any] | None = None,
) -> None:
    """Require exactly the unnamed NTFS data stream for a retained file.

    A denial handle on ``::$DATA`` does not prevent a second named stream from
    being created on the same file.  The retained-distribution fast path must
    therefore enumerate streams on every replay rather than treating the
    default-stream descriptor as ADS authority.
    """

    if os.name != "nt":
        return
    try:
        primitives = _primitives or _windows_default_stream_primitives()
        ctypes, stream_data_type, find_first, find_next, close = primitives
        data = stream_data_type()
        handle = find_first(str(path.absolute()), 0, ctypes.byref(data), 0)
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            raise OSError(ctypes.get_last_error(), "FindFirstStreamW failed")
        names: list[str] = []
        try:
            names.append(str(data.cStreamName))
            while True:
                ctypes.set_last_error(0)
                if find_next(handle, ctypes.byref(data)):
                    names.append(str(data.cStreamName))
                    continue
                error = ctypes.get_last_error()
                if error == 38:  # ERROR_HANDLE_EOF
                    break
                raise OSError(error, "FindNextStreamW failed")
        finally:
            close(handle)
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise SnapshotInputError(f"{label} stream namespace is unreadable") from exc
    if names != ["::$DATA"]:
        raise SnapshotInputError(f"{label} has an alternate data stream")


def _retain_windows_hardlink_write_denial(
    path: Path,
) -> tuple[tuple[int, int], bool]:
    """Retain a native read handle that denies write/delete through all names."""

    if os.name != "nt":
        raise OSError("Windows denial handles are unavailable")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    row = path.stat(follow_symlinks=False)
    identity = (int(row.st_dev), int(row.st_ino))
    retained = _RETAINED_HARDLINK_DENIAL_FDS.get(identity)
    if retained is not None:
        held = os.fstat(retained)
        if (int(held.st_dev), int(held.st_ino)) != identity:
            raise OSError("retained hardlink denial identity drift")
        return identity, False

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ; deny write and delete
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(
            ctypes.get_last_error(),
            "provider hardlink write-denial handle unavailable",
        )
    try:
        descriptor = msvcrt.open_osfhandle(
            int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
    held = os.fstat(descriptor)
    if (int(held.st_dev), int(held.st_ino)) != identity:
        os.close(descriptor)
        raise OSError("provider hardlink changed during denial acquisition")
    _RETAINED_HARDLINK_DENIAL_FDS[identity] = descriptor
    return identity, True


def _release_retained_hardlink_denials() -> None:
    for descriptor in tuple(_RETAINED_HARDLINK_DENIAL_FDS.values()):
        try:
            os.close(descriptor)
        except OSError:
            pass
    _RETAINED_HARDLINK_DENIAL_FDS.clear()
    _RETAINED_HARDLINK_APPROVALS.clear()
    _clear_retained_hardlink_approval_tags()
    _clear_python_distribution_closure_cache()


atexit.register(_release_retained_hardlink_denials)


def _retained_hardlink_approval_replays(
    path: Path,
    label: str,
    *,
    row: os.stat_result,
    link_count: int,
    project_root: Path | None,
    retain_fully_enumerated_external_aliases: bool,
    retained_authority_root: Path | None,
) -> bool:
    """Rejoin a retained approval without re-enumerating its locked aliases."""

    identity = (int(row.st_dev), int(row.st_ino))
    approval = _RETAINED_HARDLINK_APPROVALS.get(identity)
    if approval is None:
        return False
    if not _retained_hardlink_approval_is_authentic(identity, approval):
        raise SnapshotInputError(
            f"{label} retained hardlink approval cache drifted"
        )
    if not retain_fully_enumerated_external_aliases:
        raise SnapshotInputError(
            f"{label} retained hardlink approval is not valid for this consumer"
        )
    descriptor = _RETAINED_HARDLINK_DENIAL_FDS.get(identity)
    if descriptor is None:
        raise SnapshotInputError(
            f"{label} retained hardlink denial handle is missing"
        )
    try:
        held = os.fstat(descriptor)
        current = row
        locked_count, locked_aliases, locked_authority_root = approval
        current_authority_root = os.path.normcase(os.path.abspath(str(
            retained_authority_root
            if retained_authority_root is not None
            else path.anchor
        )))
        current_path = os.path.normcase(os.path.abspath(str(path)))
        # ``commonpath`` raises when the managed runtime and audit target live
        # on different Windows volumes.  A cross-volume alias is necessarily
        # outside the target; reuse the canonical containment helper that also
        # preserves fail-closed behavior for unreadable same-volume paths.
        aliases_are_external = project_root is not None and all(
            not _path_is_within(Path(alias), project_root)
            for alias in locked_aliases
        )
        alias_identities_match = all(
            (
                int((alias_row := Path(alias).stat(
                    follow_symlinks=False
                )).st_dev),
                int(alias_row.st_ino),
            )
            == identity
            and stat.S_ISREG(alias_row.st_mode)
            and not bool(
                int(getattr(alias_row, "st_file_attributes", 0))
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
            for alias in locked_aliases
        )
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise SnapshotInputError(
            f"{label} retained hardlink approval drifted"
        ) from exc
    current_identity = (int(current.st_dev), int(current.st_ino))
    if (
        (int(held.st_dev), int(held.st_ino)) != identity
        or current_identity != identity
        or int(current.st_nlink) != locked_count
        or link_count != locked_count
        or len(locked_aliases) != locked_count
        or len(set(locked_aliases)) != locked_count
        or tuple(sorted(locked_aliases)) != locked_aliases
        or current_path not in locked_aliases
        or current_authority_root != locked_authority_root
        or not aliases_are_external
        or not alias_identities_match
    ):
        raise SnapshotInputError(
            f"{label} retained hardlink approval drifted"
        )
    return True


def _reject_unexpected_hardlinks(
    path: Path,
    label: str,
    *,
    project_root: Path | None = None,
    retain_fully_enumerated_external_aliases: bool = False,
    retained_authority_root: Path | None = None,
) -> None:
    """Reject aliases except a fully enumerated approved Win32 set.

    Git for Windows legitimately hardlinks its byte-identical command
    launchers within one protected installation directory.  Such aliases add
    no mutation authority beyond the containing directory itself.  Reviewed
    Python distributions may also be installed by a package manager into two
    external runtime roots using hardlinks.  That narrowly opted-in form is
    accepted only after a retained native handle denies writes and deletes
    through every name, then every name is re-enumerated, has the same native
    identity, and remains outside an existing audit target.  Provider replay
    rehashes the closure after use.  Incomplete enumeration and target-owned
    aliases always remain rejected.
    """

    try:
        row = path.stat(follow_symlinks=False)
        link_count = int(row.st_nlink)
    except OSError as exc:
        raise SnapshotInputError(
            f"{label} link identity cannot be inspected"
        ) from exc
    if os.name == "nt" and _retained_hardlink_approval_replays(
        path,
        label,
        row=row,
        link_count=link_count,
        project_root=project_root,
        retain_fully_enumerated_external_aliases=(
            retain_fully_enumerated_external_aliases
        ),
        retained_authority_root=retained_authority_root,
    ):
        return
    if link_count == 1:
        return
    if os.name == "nt":
        try:
            identity = (int(row.st_dev), int(row.st_ino))
            aliases = _windows_hardlink_aliases(path)
            canonical_parent = os.path.normcase(
                str(path.parent.resolve(strict=True))
            )
            canonical_aliases = {
                os.path.normcase(str(alias.resolve(strict=True)))
                for alias in aliases
            }
            identities_match = all(
                (
                    int(alias.stat().st_dev),
                    int(alias.stat().st_ino),
                )
                == identity
                for alias in aliases
            )
            aliases_are_external = all(
                not _path_is_within(alias, project_root)
                for alias in aliases
            )
            same_directory = all(
                os.path.normcase(
                    str(alias.parent.resolve(strict=True))
                )
                == canonical_parent
                for alias in aliases
            )
            common_valid = (
                len(aliases) == link_count
                and len(canonical_aliases) == link_count
                and identities_match
                and aliases_are_external
            )
            if common_valid and same_directory:
                return
            if (
                common_valid
                and retain_fully_enumerated_external_aliases
                and project_root is not None
            ):
                retained_identity, created = (
                    _retain_windows_hardlink_write_denial(path)
                )
                try:
                    fresh_row = path.stat(follow_symlinks=False)
                    fresh_count = int(fresh_row.st_nlink)
                    fresh_identity = (
                        int(fresh_row.st_dev),
                        int(fresh_row.st_ino),
                    )
                    fresh_aliases = _windows_hardlink_aliases(path)
                    fresh_names = {
                        os.path.normcase(
                            str(alias.resolve(strict=True))
                        )
                        for alias in fresh_aliases
                    }
                    if (
                        fresh_identity == retained_identity == identity
                        and fresh_count == link_count
                        and len(fresh_aliases) == link_count
                        and len(fresh_names) == link_count
                        and all(
                            (
                                int(alias.stat().st_dev),
                                int(alias.stat().st_ino),
                            )
                            == identity
                            and not _path_is_within(alias, project_root)
                            for alias in fresh_aliases
                        )
                    ):
                        authority_root_name = os.path.normcase(os.path.abspath(str(
                            retained_authority_root
                            if retained_authority_root is not None
                            else path.anchor
                        )))
                        approval = (
                            link_count,
                            tuple(sorted(fresh_names)),
                            authority_root_name,
                        )
                        _RETAINED_HARDLINK_APPROVALS[identity] = approval
                        _seal_retained_hardlink_approval(identity, approval)
                        return
                except BaseException:
                    if created:
                        descriptor = _RETAINED_HARDLINK_DENIAL_FDS.pop(
                            retained_identity,
                            None,
                        )
                        if descriptor is not None:
                            os.close(descriptor)
                    raise
                if created:
                    descriptor = _RETAINED_HARDLINK_DENIAL_FDS.pop(
                        retained_identity,
                        None,
                    )
                    if descriptor is not None:
                        os.close(descriptor)
        except (OSError, ValueError):
            pass
    if link_count != 1:
        raise SnapshotInputError(
            f"{label} has an unexpected hardlink alias"
        )


def _identity_revocation_issues(
    tool_id: str,
    *,
    version: str,
    digests: Iterable[str],
    controls: tuple[
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
        str,
        str,
    ],
) -> list[str]:
    governed = controls[1]
    row = governed.get(tool_id)
    if row is None:
        return ["tool has no governance row"]
    policy = row["revocation_policy"]
    issues: list[str] = []
    lowered_version = str(version or "").casefold()
    for token in policy["blocked_version_substrings"]:
        if str(token).casefold() in lowered_version:
            issues.append(f"version matches revoked token {token!r}")
    blocked = {
        str(value).casefold()
        for value in policy["blocked_executable_sha256"]
    }
    for digest in digests:
        normalized = str(digest or "").casefold()
        if normalized and normalized in blocked:
            issues.append(f"content digest is revoked: {normalized}")
    return issues


def _go_build_information(executable: Path) -> str:
    go = shutil.which("go")
    if not go:
        return "UNAVAILABLE"
    return _semantic_probe_output(
        "scip-go:go-build-information",
        _command_version(
            (str(Path(go).resolve()), "version", "-m", str(executable))
        ),
    )


def _scip_go_build_information_matches(
    observed: str,
    locked_row: Mapping[str, Any],
) -> bool:
    lines = [
        line.rstrip()
        for line in str(observed or "").splitlines()
        if line.strip()
    ]
    if not lines or lines[0] != "rc=0":
        return False
    path_rows = [
        line.strip().split("\t")
        for line in lines[1:]
        if line.strip().startswith("path\t")
    ]
    module_rows = [
        line.strip().split("\t")
        for line in lines[1:]
        if line.strip().startswith("mod\t")
    ]
    if len(path_rows) != 1 or len(module_rows) != 1:
        return False
    if len(path_rows[0]) != 2 or path_rows[0][1] != locked_row.get(
        "go_command_path"
    ):
        return False
    if len(module_rows[0]) < 3:
        return False
    return (
        module_rows[0][1] == locked_row.get("go_module_path")
        and module_rows[0][2]
        == f"v{locked_row.get('expected_version')}"
    )


def _runtime_tool_fingerprint(
    command: tuple[str, ...],
    *,
    project_root: Path | None = None,
    probe_version: bool = True,
    controls: tuple[
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
        str,
        str,
    ]
    | None = None,
) -> bytes:
    """Capture one command identity without a cross-snapshot cache.

    The version probe executes the exact resolved path whose bytes are hashed,
    and a second content read must match before the identity is returned.
    """

    executable = shutil.which(command[0])
    executable_path: Path | None = None
    if executable:
        try:
            executable_path = Path(executable).resolve(strict=True)
        except OSError as exc:
            raise SnapshotInputError(
                f"runtime tool cannot be inspected: {command[0]}"
            ) from exc
        if _path_is_within(executable_path, project_root):
            raise SnapshotInputError(
                f"runtime tool resolves inside audit target: {command[0]}"
            )
        _reject_unexpected_hardlinks(
            executable_path,
            f"runtime tool {command[0]}",
            project_root=project_root,
            # Windows package managers commonly expose one executable through
            # multiple hardlink names (for example a shared Python Scripts
            # directory and a managed runtime prefix).  Admit that layout only
            # through the existing strict path: enumerate every alias, prove
            # every name is outside the audit target, retain a native handle
            # that denies writes/deletes through the shared file identity, and
            # revalidate the complete alias set on replay.
            retain_fully_enumerated_external_aliases=(
                os.name == "nt" and project_root is not None
            ),
            retained_authority_root=Path(executable_path.anchor),
        )
    controls = (
        controls
        if controls is not None
        else _load_toolchain_identity_controls()
    )
    lock_digest = controls[2]
    governance_digest = controls[3]
    before_digest = ""
    before_size = 0
    if executable_path is not None:
        try:
            digest, before_size = _hash_runtime_executable(executable_path)
            before_digest = digest.hex()
        except SnapshotInputError as exc:
            raise SnapshotInputError(
                f"runtime tool cannot be content-bound: {command[0]}"
            ) from exc
        if probe_version:
            version_command = (
                str(executable_path),
                *tuple(command[1:]),
            )
            version = _semantic_probe_output(
                command[0],
                _command_version(version_command),
            )
        else:
            version = "NOT_PROBED_NONAUTHORITATIVE"
        after_digest, after_size = _hash_runtime_executable(executable_path)
        if (
            after_digest.hex() != before_digest
            or after_size != before_size
        ):
            raise SnapshotInputError(
                f"runtime tool changed during identity capture: {command[0]}"
            )
    else:
        version = "UNAVAILABLE"
    identity: dict[str, Any] = {
        "schema": RUNTIME_TOOL_IDENTITY_SCHEMA,
        "tool_id": command[0],
        "identity_kind": "command",
        "command": list(command),
        "resolved_executable": (
            str(executable_path) if executable_path is not None else "UNAVAILABLE"
        ),
        "version": version,
    }
    if executable_path is not None:
        identity.update(
            {
                "executable_sha256": before_digest,
                "executable_bytes": before_size,
            }
        )
    expected, status, authority, lock_digest, governance_digest = (
        _runtime_identity_policy(
            command[0],
            resolved_identity=str(identity["resolved_executable"]),
            version=version,
            identity_kind="command",
            controls=controls,
        )
    )
    if command[0] == "scip-go" and executable_path is not None:
        build_information = _go_build_information(executable_path)
        identity["go_build_information"] = build_information
        identity["go_build_information_sha256"] = hashlib.sha256(
            build_information.encode("utf-8")
        ).hexdigest()
        locked_row = controls[0].get("scip-go")
        if (
            locked_row is None
            or not _scip_go_build_information_matches(
                build_information, locked_row
            )
        ):
            status = "MISMATCH"
            authority = False
    revocation_issues = _identity_revocation_issues(
        command[0],
        version=version,
        digests=(before_digest,),
        controls=controls,
    )
    if revocation_issues:
        status = "REVOKED"
        authority = False
        identity["revocation_issues"] = revocation_issues
    observed = {
        "resolved_executable": identity["resolved_executable"],
        "version": version,
    }
    if "executable_sha256" in identity:
        observed["executable_sha256"] = identity["executable_sha256"]
        observed["executable_bytes"] = identity["executable_bytes"]
    identity.update({
        "expected_identity": expected,
        "observed_identity": observed,
        "identity_status": status,
        "deterministic_provider_authority": authority,
        "toolchain_version_lock_sha256": lock_digest,
        "toolchain_governance_sha256": governance_digest,
    })
    return _canonical_json(identity)


def _python_distribution_version(distribution: str) -> str:
    try:
        from importlib import metadata

        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return "UNAVAILABLE"
    except Exception as exc:
        return f"ERROR:{type(exc).__name__}"


def _protobuf_live_distribution_paths(
    install_root: Path,
    dist_info_name: str,
) -> set[str]:
    """Enumerate only protobuf-owned roots without following filesystem links."""

    base = Path(install_root)
    try:
        base_info = base.lstat()
    except OSError as exc:
        raise SnapshotInputError(
            "Python provider protobuf install root is unreadable"
        ) from exc
    if (
        not stat.S_ISDIR(base_info.st_mode)
        or base.is_symlink()
        or bool(
            int(getattr(base_info, "st_file_attributes", 0))
            & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        )
    ):
        raise SnapshotInputError(
            "Python provider protobuf install root is a symlink/reparse"
        )
    governed = (
        PurePosixPath("google/protobuf"),
        PurePosixPath("google/_upb"),
        PurePosixPath(dist_info_name),
    )
    observed: set[str] = set()
    casefolded: dict[str, str] = {}
    for relative_root in governed:
        directory = base.joinpath(*relative_root.parts)
        cursor = base
        for part in relative_root.parts:
            cursor = cursor / part
            try:
                info = cursor.lstat()
            except OSError as exc:
                raise SnapshotInputError(
                    "Python provider protobuf governed root is missing: "
                    f"{relative_root.as_posix()}"
                ) from exc
            if cursor.is_symlink() or bool(
                int(getattr(info, "st_file_attributes", 0))
                & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            ):
                raise SnapshotInputError(
                    "Python provider protobuf governed root is a symlink/reparse: "
                    f"{relative_root.as_posix()}"
                )
            if not stat.S_ISDIR(info.st_mode):
                raise SnapshotInputError(
                    "Python provider protobuf governed root is not a directory: "
                    f"{relative_root.as_posix()}"
                )
        pending = [directory]
        while pending:
            current = pending.pop()
            try:
                with os.scandir(current) as stream:
                    children = sorted(stream, key=lambda item: item.name)
            except OSError as exc:
                raise SnapshotInputError(
                    "Python provider protobuf governed root is unreadable: "
                    f"{relative_root.as_posix()}"
                ) from exc
            for child in children:
                path = Path(child.path)
                try:
                    info = path.lstat()
                except OSError as exc:
                    raise SnapshotInputError(
                        "Python provider protobuf live member is unreadable"
                    ) from exc
                relative = path.relative_to(base).as_posix()
                if path.is_symlink() or bool(
                    int(getattr(info, "st_file_attributes", 0))
                    & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                ):
                    raise SnapshotInputError(
                        "Python provider protobuf live member is a symlink/reparse: "
                        f"{relative}"
                    )
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise SnapshotInputError(
                        "Python provider protobuf live member is not regular: "
                        f"{relative}"
                    )
                if (
                    relative.endswith((".pyc", ".pyo"))
                    or "__pycache__" in PurePosixPath(relative).parts
                ):
                    continue
                folded = relative.casefold()
                prior = casefolded.get(folded)
                if prior is not None and prior != relative:
                    raise SnapshotInputError(
                        "Python provider protobuf live path has a case alias: "
                        f"{prior}, {relative}"
                    )
                casefolded[folded] = relative
                observed.add(relative)
    return observed


def _validate_protobuf_live_distribution_denominator(
    install_root: Path,
    record_relative: str,
    record_names: Iterable[str],
) -> None:
    """Require the live protobuf-owned disk set to equal its RECORD set."""

    record_path = PurePosixPath(record_relative)
    if len(record_path.parts) != 2 or record_path.name != "RECORD":
        raise SnapshotInputError(
            "Python provider protobuf RECORD root is invalid"
        )
    dist_info_name = record_path.parts[0]
    governed_prefixes = (
        "google/protobuf/",
        "google/_upb/",
        f"{dist_info_name}/",
    )
    expected = {
        name
        for name in record_names
        if not (
            name.endswith((".pyc", ".pyo"))
            or "__pycache__" in PurePosixPath(name).parts
        )
    }
    if any(
        not name.startswith(governed_prefixes)
        for name in expected
    ):
        raise SnapshotInputError(
            "Python provider protobuf RECORD escapes governed roots"
        )
    folded: dict[str, str] = {}
    for name in expected:
        prior = folded.get(name.casefold())
        if prior is not None and prior != name:
            raise SnapshotInputError(
                "Python provider protobuf RECORD contains a case alias"
            )
        folded[name.casefold()] = name
    observed = _protobuf_live_distribution_paths(
        Path(install_root), dist_info_name
    )
    if observed != expected:
        extra = sorted(observed - expected)
        missing = sorted(expected - observed)
        raise SnapshotInputError(
            "Python provider protobuf live denominator differs from RECORD; "
            f"unrecorded={extra[:8]}; missing={missing[:8]}"
        )


def _fold_python_distribution_entries(
    entries: Iterable[tuple[str, str, int]],
) -> tuple[str, str, int]:
    path_set = hashlib.sha256()
    content = hashlib.sha256()
    total = 0
    for relative_name, digest_hex, size in entries:
        encoded_name = relative_name.encode("utf-8")
        path_set.update(len(encoded_name).to_bytes(8, "big"))
        path_set.update(encoded_name)
        content.update(len(encoded_name).to_bytes(8, "big"))
        content.update(encoded_name)
        content.update(bytes.fromhex(digest_hex))
        content.update(size.to_bytes(8, "big"))
        total += size
    return content.hexdigest(), path_set.hexdigest(), total


def _replay_python_distribution_closure_cache(
    distribution: str,
    module_name: str,
    *,
    project_root: Path | None,
) -> dict[str, Any] | None:
    """Rehash a retained provider roster without repeating path discovery."""

    if (
        distribution.casefold() not in {"slither-analyzer", "protobuf"}
        or os.name != "nt"
    ):
        return None
    cache_name = distribution.casefold()
    cached = _PYTHON_DISTRIBUTION_CLOSURE_CACHE.get(cache_name)
    if cached is None:
        return None
    payload, expected_tag = cached
    if not hmac.compare_digest(
        expected_tag, _python_distribution_closure_cache_tag(payload)
    ):
        raise SnapshotInputError(
            f"Python provider retained closure cache drifted: {distribution}"
        )
    try:
        from importlib import util

        resolved_project_root = (
            project_root.resolve(strict=True)
            if project_root is not None
            else None
        )
        project_name = (
            os.path.normcase(os.path.abspath(str(resolved_project_root)))
            if resolved_project_root is not None
            else ""
        )
        if (
            payload.get("schema")
            != "plamen.retained-python-distribution-closure.v1"
            or payload.get("distribution") != distribution
            or payload.get("module_name") != module_name
        ):
            raise SnapshotInputError(
                f"Python provider retained closure scope drifted: {distribution}"
            )
        # The cache is a process-local acceleration, not global authority.
        # Test runners and long-lived callers may snapshot more than one audit
        # root in the same process.  A correctly authenticated entry for a
        # different root is a cache miss; the caller performs a fresh bounded
        # capture and replaces it.  Treating that ordinary scope transition as
        # tampering made the second independent audit fail deterministically.
        if payload.get("project_root") != project_name:
            return None
        authority_root = Path(str(payload["authority_root"]))
        _assert_no_lexical_links(
            authority_root,
            label=f"Python provider authority root {distribution}",
        )
        spec = util.find_spec(module_name)
        if spec is None or not spec.origin:
            raise SnapshotInputError(
                f"Python provider retained module is unavailable: {module_name}"
            )
        module_origin = os.path.normcase(os.path.abspath(spec.origin))
        if module_origin != payload.get("module_origin"):
            raise SnapshotInputError(
                f"Python provider retained module origin drifted: {module_name}"
            )
        rows = payload.get("rows")
        if not isinstance(rows, list) or not rows:
            raise SnapshotInputError(
                f"Python provider retained closure is empty: {distribution}"
            )
        cached_relative_names = [
            str(row.get("relative_name") or "")
            for row in rows
            if isinstance(row, Mapping)
        ]
        record_candidates = [
            name
            for name in cached_relative_names
            if name.replace("\\", "/").endswith(".dist-info/RECORD")
        ]
        if (
            len(cached_relative_names) != len(rows)
            or len(set(cached_relative_names)) != len(rows)
            or len(record_candidates) != 1
        ):
            raise SnapshotInputError(
                f"Python provider retained RECORD denominator drifted: "
                f"{distribution}"
            )
        record_relative = record_candidates[0]
        record_cache_rows = [
            row
            for row in rows
            if isinstance(row, Mapping)
            and str(row.get("relative_name") or "") == record_relative
        ]
        if len(record_cache_rows) != 1:
            raise SnapshotInputError(
                f"Python provider retained RECORD identity drifted: {distribution}"
            )
        record_path = Path(str(record_cache_rows[0]["path"]))
        install_root = record_path.parent.parent
        record_entries: list[tuple[str, str, int]] = []
        content_entries: list[tuple[str, str, int]] = []
        observed_identities: set[tuple[int, int]] = set()
        record_raw: bytes | None = None
        module_digest = ""
        stream_primitives = _windows_default_stream_primitives()
        for row in rows:
            if not isinstance(row, Mapping):
                raise SnapshotInputError(
                    f"Python provider retained closure row drifted: {distribution}"
                )
            relative_name = str(row["relative_name"])
            located = Path(str(row["path"]))
            identity = (int(row["device"]), int(row["file_id"]))
            expected_size = int(row["size"])
            expected_link_count = int(row["link_count"])
            relative_parts = PurePosixPath(relative_name).parts
            scripts_member = (
                len(relative_parts) == 4
                and relative_parts[:3] == ("..", "..", "Scripts")
                and relative_parts[-1].casefold().endswith(".exe")
            )
            if (
                not relative_name
                or relative_name.startswith("/")
                or (".." in relative_parts and not scripts_member)
            ):
                raise SnapshotInputError(
                    f"Python provider retained RECORD path drifted: "
                    f"{distribution}:{relative_name}"
                )
            expected_path = os.path.normcase(os.path.abspath(str(
                install_root / Path(relative_name)
            )))
            if os.path.normcase(os.path.abspath(str(located))) != expected_path:
                raise SnapshotInputError(
                    f"Python provider retained RECORD path was retargeted: "
                    f"{distribution}:{relative_name}"
                )
            if identity in observed_identities:
                raise SnapshotInputError(
                    f"Python provider retained closure aliases an identity: "
                    f"{distribution}:{relative_name}"
                )
            observed_identities.add(identity)
            try:
                located.relative_to(authority_root)
            except ValueError as exc:
                raise SnapshotInputError(
                    f"Python provider retained path escapes authority root: "
                    f"{distribution}:{relative_name}"
                ) from exc
            if resolved_project_root is not None and _path_is_within(
                located, resolved_project_root
            ):
                raise SnapshotInputError(
                    f"Python provider retained path entered audit target: "
                    f"{distribution}:{relative_name}"
                )
            live_info = located.stat(follow_symlinks=False)
            if int(live_info.st_nlink) != expected_link_count:
                raise SnapshotInputError(
                    f"Python provider retained link count drifted: "
                    f"{distribution}:{relative_name}"
                )
            _assert_windows_default_stream_only(
                located,
                label=(
                    "Python provider retained distribution file "
                    f"{distribution}:{relative_name}"
                ),
                _primitives=stream_primitives,
            )
            approval_replayed = _retained_hardlink_approval_replays(
                located,
                f"Python provider distribution file "
                f"{distribution}:{relative_name}",
                row=live_info,
                link_count=int(live_info.st_nlink),
                project_root=project_root,
                retain_fully_enumerated_external_aliases=True,
                retained_authority_root=authority_root,
            )
            if expected_link_count > 1 and not approval_replayed:
                raise SnapshotInputError(
                    f"Python provider retained hardlink approval is missing: "
                    f"{distribution}:{relative_name}"
                )
            raw = _read_retained_regular_bytes(
                located,
                identity,
                expected_size=expected_size,
                expected_link_count=expected_link_count,
                label=(
                    "Python provider retained distribution file "
                    f"{distribution}:{relative_name}"
                ),
                current_info=live_info,
            )
            digest_hex = hashlib.sha256(raw).hexdigest()
            record_entries.append((relative_name, digest_hex, len(raw)))
            if (
                not scripts_member
                and not relative_name.endswith((".pyc", ".pyo"))
                and "__pycache__" not in relative_parts
            ):
                content_entries.append((relative_name, digest_hex, len(raw)))
            if os.path.normcase(os.path.abspath(str(located))) == module_origin:
                module_digest = digest_hex
            if relative_name == record_relative:
                record_raw = raw
        if (
            len(observed_identities) != len(rows)
            or not module_digest
            or record_raw is None
            or hashlib.sha256(record_raw).hexdigest()
            != payload.get("record_sha256")
            or len(record_raw) != int(payload.get("record_bytes", -1))
        ):
            raise SnapshotInputError(
                f"Python provider retained RECORD closure drifted: {distribution}"
            )
        try:
            parsed_rows_raw = list(csv.reader(
                record_raw.decode("utf-8", "strict").splitlines()
            ))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise SnapshotInputError(
                f"Python provider retained RECORD is malformed: {distribution}"
            ) from exc
        if (
            not parsed_rows_raw
            or any(len(row) != 3 for row in parsed_rows_raw)
        ):
            raise SnapshotInputError(
                f"Python provider retained RECORD is malformed: {distribution}"
            )
        parsed_normalized_rows: list[dict[str, Any]] = []
        for name, digest_value, size_value in parsed_rows_raw:
            normalized = name.replace("\\", "/")
            if not normalized or normalized.startswith("/"):
                raise SnapshotInputError(
                    f"Python provider retained RECORD path is invalid: "
                    f"{distribution}"
                )
            if digest_value:
                if (
                    not digest_value.startswith("sha256=")
                    or not size_value.isdigit()
                ):
                    raise SnapshotInputError(
                        f"Python provider retained RECORD digest is invalid: "
                        f"{distribution}"
                    )
                normalized_size: int | None = int(size_value)
            elif (
                normalized != record_relative
                and "__pycache__" not in PurePosixPath(normalized).parts
                and not normalized.endswith((".pyc", ".pyo"))
            ):
                raise SnapshotInputError(
                    f"Python provider retained RECORD member is unauthenticated: "
                    f"{distribution}:{normalized}"
                )
            else:
                normalized_size = None
            parsed_normalized_rows.append({
                "path": normalized,
                "hash": digest_value,
                "bytes": normalized_size,
            })
        parsed_names = [str(row["path"]) for row in parsed_normalized_rows]
        if (
            len(parsed_names) != len(set(parsed_names))
            or len(parsed_names) != len(rows)
            or set(parsed_names) != set(cached_relative_names)
        ):
            raise SnapshotInputError(
                f"Python provider retained RECORD denominator changed: "
                f"{distribution}"
            )
        if distribution.casefold() == "protobuf":
            _validate_protobuf_live_distribution_denominator(
                install_root,
                record_relative,
                parsed_names,
            )
        parsed_by_name = {
            str(row["path"]): row for row in parsed_normalized_rows
        }
        import base64

        for relative_name, digest_hex, size in record_entries:
            parsed_row = parsed_by_name[relative_name]
            if parsed_row["hash"]:
                encoded = base64.urlsafe_b64encode(
                    bytes.fromhex(digest_hex)
                ).decode("ascii").rstrip("=")
                if (
                    parsed_row["hash"] != f"sha256={encoded}"
                    or int(parsed_row["bytes"]) != size
                ):
                    raise SnapshotInputError(
                        f"Python provider retained RECORD member drifted: "
                        f"{distribution}:{relative_name}"
                    )
        parsed_normalized_rows.sort(key=lambda row: str(row["path"]))
        parsed_normalized_digest = hashlib.sha256(
            _canonical_json(parsed_normalized_rows)
        ).hexdigest()
        # Terminally rejoin every namespace identity and retained descriptor.
        terminal_fold = hashlib.sha256()
        for row in rows:
            located = Path(str(row["path"]))
            identity = (int(row["device"]), int(row["file_id"]))
            descriptor = _RETAINED_HARDLINK_DENIAL_FDS.get(identity)
            if descriptor is None:
                raise SnapshotInputError(
                    f"Python provider retained denial handle disappeared: "
                    f"{distribution}:{row['relative_name']}"
                )
            live_info = located.stat(follow_symlinks=False)
            held_info = os.fstat(descriptor)
            live_identity = (int(live_info.st_dev), int(live_info.st_ino))
            held_identity = (int(held_info.st_dev), int(held_info.st_ino))
            if (
                live_identity != identity
                or held_identity != identity
                or int(live_info.st_nlink) != int(row["link_count"])
                or int(held_info.st_nlink) != int(row["link_count"])
                or int(live_info.st_size) != int(row["size"])
                or int(held_info.st_size) != int(row["size"])
            ):
                raise SnapshotInputError(
                    f"Python provider retained terminal identity drifted: "
                    f"{distribution}:{row['relative_name']}"
                )
            terminal_fold.update(_canonical_json({
                "device": identity[0],
                "file_id": identity[1],
                "link_count": int(row["link_count"]),
                "path": os.path.normcase(os.path.abspath(str(located))),
                "relative_name": str(row["relative_name"]),
                "size": int(row["size"]),
            }))
        if terminal_fold.hexdigest() != payload.get("physical_fold_sha256"):
            raise SnapshotInputError(
                f"Python provider retained physical fold drifted: {distribution}"
            )
    except SnapshotInputError:
        raise
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise SnapshotInputError(
            f"Python provider retained closure is unreadable: {distribution}"
        ) from exc

    content_digest, path_digest, total = _fold_python_distribution_entries(
        content_entries
    )
    record_digest, record_path_digest, record_total = (
        _fold_python_distribution_entries(record_entries)
    )
    return {
        "distribution_files_sha256": content_digest,
        "distribution_path_set_sha256": path_digest,
        "distribution_file_count": len(content_entries),
        "distribution_bytes": total,
        "record_member_files_sha256": record_digest,
        "record_member_path_set_sha256": record_path_digest,
        "record_member_file_count": len(record_entries),
        "record_member_native_identity_count": len(observed_identities),
        "record_member_bytes": record_total,
        "record_path": record_relative,
        "record_sha256": hashlib.sha256(record_raw).hexdigest(),
        "record_bytes": len(record_raw),
        "record_row_count": len(parsed_normalized_rows),
        "record_normalized_rows_sha256": parsed_normalized_digest,
        "module_origin": str(payload["module_origin_display"]),
        "module_sha256": module_digest,
    }


def _python_distribution_closure(
    distribution: str,
    module_name: str,
    *,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Bind every installed distribution file plus the loaded module origin."""

    retained = _replay_python_distribution_closure_cache(
        distribution,
        module_name,
        project_root=project_root,
    )
    if retained is not None:
        return retained

    try:
        from importlib import metadata, util

        distributions = [
            candidate
            for candidate in metadata.distributions()
            if str(candidate.metadata.get("Name") or "").casefold()
            == distribution.casefold()
        ]
        if len(distributions) != 1:
            raise SnapshotInputError(
                f"Python provider distribution is ambiguous: {distribution}"
            )
        dist = distributions[0]
        files = list(dist.files or ())
        spec = util.find_spec(module_name)
    except Exception as exc:
        raise SnapshotInputError(
            f"Python provider distribution is unreadable: {distribution}"
        ) from exc
    if not files or spec is None or not spec.origin:
        raise SnapshotInputError(
            f"Python provider closure is incomplete: {distribution}"
        )
    distribution_authority_root = (
        Path(dist.locate_file(".")).resolve(strict=True).parent.parent
    )
    lexical_validation_cache: set[str] = set()
    _assert_no_lexical_links(
        distribution_authority_root,
        label=f"Python provider authority root {distribution}",
        _validated_paths=lexical_validation_cache,
    )
    try:
        resolved_project_root = (
            project_root.resolve(strict=True)
            if project_root is not None
            else None
        )
    except OSError as exc:
        raise SnapshotInputError(
            "Python provider audit target root is unreadable"
        ) from exc

    def inside_project(candidate: Path) -> bool:
        if resolved_project_root is None:
            return False
        try:
            candidate.relative_to(resolved_project_root)
            return True
        except ValueError:
            return False

    module_origin = _assert_no_lexical_links(
        Path(spec.origin),
        label=f"Python provider module {module_name}",
        _validated_paths=lexical_validation_cache,
        _validated_root=distribution_authority_root,
    ).resolve(strict=True)
    if inside_project(module_origin):
        raise SnapshotInputError(
            f"Python provider module resolves inside audit target: {module_name}"
        )
    _reject_unexpected_hardlinks(
        module_origin,
        f"Python provider module {module_name}",
        project_root=project_root,
        retain_fully_enumerated_external_aliases=True,
        retained_authority_root=distribution_authority_root,
    )
    record_candidates = [
        relative
        for relative in files
        if str(relative).replace("\\", "/").endswith(".dist-info/RECORD")
    ]
    if len(record_candidates) != 1:
        raise SnapshotInputError(
            f"Python provider RECORD is ambiguous: {distribution}"
        )
    record_relative = str(record_candidates[0]).replace("\\", "/")
    try:
        located_record_path = Path(dist.locate_file(record_candidates[0]))
        record_path = _assert_no_lexical_links(
            located_record_path,
            label=f"Python provider RECORD {distribution}",
            _validated_paths=lexical_validation_cache,
            _validated_root=distribution_authority_root,
        ).resolve(strict=True)
        if inside_project(record_path):
            raise SnapshotInputError(
                f"Python provider RECORD resolves inside audit target: "
                f"{distribution}"
            )
        record_info = record_path.lstat()
        if (
            not stat.S_ISREG(record_info.st_mode)
            or record_path.is_symlink()
            or _is_reparse_point(record_path)
        ):
            raise SnapshotInputError(
                f"Python provider RECORD is not a regular physical file: "
                f"{distribution}"
            )
        _reject_unexpected_hardlinks(
            record_path,
            f"Python provider RECORD {distribution}",
            project_root=project_root,
            retain_fully_enumerated_external_aliases=True,
            retained_authority_root=distribution_authority_root,
        )
        if os.name == "nt":
            _retain_windows_hardlink_write_denial(record_path)
        record_raw = record_path.read_bytes()
        record_rows_raw = list(
            csv.reader(record_raw.decode("utf-8", "strict").splitlines())
        )
    except Exception as exc:
        raise SnapshotInputError(
            f"Python provider RECORD is unreadable: {distribution}"
        ) from exc
    if (
        not record_rows_raw
        or any(len(row) != 3 for row in record_rows_raw)
    ):
        raise SnapshotInputError(
            f"Python provider RECORD is malformed: {distribution}"
        )
    normalized_record_rows: list[dict[str, Any]] = []
    record_names: list[str] = []
    for name, digest_value, size_value in record_rows_raw:
        normalized = name.replace("\\", "/")
        if (
            not normalized
            or normalized.startswith("/")
            or (
                distribution.casefold() == "protobuf"
                and ".." in PurePosixPath(normalized).parts
            )
        ):
            raise SnapshotInputError(
                f"Python provider RECORD path is invalid: {distribution}"
            )
        if digest_value:
            if not digest_value.startswith("sha256=") or not size_value.isdigit():
                raise SnapshotInputError(
                    f"Python provider RECORD digest is invalid: {distribution}"
                )
            normalized_size: int | None = int(size_value)
        elif (
            normalized != record_relative
            and "__pycache__" not in PurePosixPath(normalized).parts
            and not normalized.endswith((".pyc", ".pyo"))
        ):
            raise SnapshotInputError(
                f"Python provider RECORD member is unauthenticated: {distribution}"
            )
        else:
            normalized_size = None
        normalized_record_rows.append(
            {"path": normalized, "hash": digest_value, "bytes": normalized_size}
        )
        record_names.append(normalized)
    if len(record_names) != len(set(record_names)):
        raise SnapshotInputError(
            f"Python provider RECORD contains duplicate paths: {distribution}"
        )
    normalized_record_rows.sort(key=lambda row: row["path"])
    metadata_names = {
        str(relative).replace("\\", "/") for relative in files
    }
    if metadata_names != set(record_names):
        raise SnapshotInputError(
            f"Python provider RECORD denominator is inconsistent: {distribution}"
        )
    if distribution.casefold() == "protobuf":
        _validate_protobuf_live_distribution_denominator(
            located_record_path.parent.parent,
            record_relative,
            record_names,
        )
    record_by_name = {
        str(row["path"]): row for row in normalized_record_rows
    }
    # RECORD is rooted at ``<install-root>/<dist-info>/RECORD``.  A reviewed
    # console-script row may use the wheel-standard ``../../Scripts/name.exe``
    # spelling, but it must still resolve beneath this one interpreter prefix.
    # No other parent traversal is admitted.
    install_root = record_path.parent.parent
    if install_root.parent.parent.resolve(strict=True) != distribution_authority_root:
        raise SnapshotInputError(
            f"Python provider authority root is inconsistent: {distribution}"
        )
    entries: list[tuple[str, str, int]] = []
    record_entries: list[tuple[str, str, int]] = []
    retained_cache_rows: list[dict[str, Any]] = []
    record_native_identities: set[tuple[int, int]] = set()
    module_digest = ""
    stream_primitives = (
        _windows_default_stream_primitives() if os.name == "nt" else None
    )
    for relative in sorted(
        files,
        key=lambda value: str(value).replace("\\", "/"),
    ):
        relative_name = str(relative).replace("\\", "/")
        relative_parts = PurePosixPath(relative_name).parts
        scripts_member = (
            distribution.casefold() == "slither-analyzer"
            and len(relative_parts) == 4
            and relative_parts[:3] == ("..", "..", "Scripts")
            and relative_parts[-1].casefold().endswith(".exe")
        )
        if (
            not relative_name
            or relative_name.startswith("/")
            or (".." in relative_parts and not scripts_member)
        ):
            raise SnapshotInputError(
                f"Python provider RECORD member path is outside its fixed "
                f"runtime namespace: {distribution}:{relative_name}"
            )
        try:
            located_candidate = Path(dist.locate_file(relative))
            located = _assert_no_lexical_links(
                located_candidate,
                label=(
                    "Python provider distribution file "
                    f"{distribution}:{relative_name}"
                ),
                _validated_paths=lexical_validation_cache,
                _validated_root=distribution_authority_root,
            ).resolve(strict=True)
        except OSError as exc:
            raise SnapshotInputError(
                f"Python provider distribution file is missing: "
                f"{distribution}:{relative_name}"
            ) from exc
        try:
            located.relative_to(distribution_authority_root)
        except ValueError as exc:
            raise SnapshotInputError(
                f"Python provider distribution file escapes its interpreter "
                f"prefix: {distribution}:{relative_name}"
            ) from exc
        if inside_project(located):
            raise SnapshotInputError(
                f"Python provider distribution resolves inside audit target: "
                f"{distribution}"
            )
        located_info = located.lstat()
        if (
            not stat.S_ISREG(located_info.st_mode)
            or located.is_symlink()
            or _is_reparse_point(located)
        ):
            raise SnapshotInputError(
                f"Python provider distribution member is not a regular "
                f"physical file: {distribution}:{relative_name}"
            )
        _reject_unexpected_hardlinks(
            located,
            f"Python provider distribution file "
            f"{distribution}:{relative_name}",
            project_root=project_root,
            retain_fully_enumerated_external_aliases=True,
            retained_authority_root=distribution_authority_root,
        )
        if os.name == "nt":
            retained_identity, _created = (
                _retain_windows_hardlink_write_denial(located)
            )
            reopened = located.stat(follow_symlinks=False)
            reopened_identity = (
                int(reopened.st_dev),
                int(reopened.st_ino),
            )
            if retained_identity != reopened_identity:
                raise SnapshotInputError(
                    f"Python provider distribution member changed after "
                    f"write-denial acquisition: {distribution}:{relative_name}"
                )
            _assert_windows_default_stream_only(
                located,
                label=(
                    "Python provider distribution file "
                    f"{distribution}:{relative_name}"
                ),
                _primitives=stream_primitives,
            )
            if retained_identity in record_native_identities:
                raise SnapshotInputError(
                    f"Python provider RECORD contains a physical identity "
                    f"alias: {distribution}:{relative_name}"
                )
            record_native_identities.add(retained_identity)
        digest, size = _hash_path(located)
        digest_hex = digest.hex()
        record_row = record_by_name[relative_name]
        if record_row["hash"]:
            import base64

            encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            if (
                record_row["hash"] != f"sha256={encoded}"
                or record_row["bytes"] != size
            ):
                raise SnapshotInputError(
                    f"Python provider RECORD member drifted: "
                    f"{distribution}:{relative_name}"
                )
        record_entries.append((relative_name, digest_hex, size))
        # Preserve the established reviewed-content denominator for generated
        # bytecode, whose RECORD rows deliberately carry no wheel hash, and for
        # console scripts outside site-packages.  Both categories are now still
        # part of the separately hashed and physically leased RECORD closure
        # below, so provider replay observes them without pretending they are
        # wheel-authenticated content.
        if (
            not scripts_member
            and not relative_name.endswith((".pyc", ".pyo"))
            and "__pycache__" not in relative_parts
        ):
            entries.append((relative_name, digest_hex, size))
            content_member = True
        else:
            content_member = False
        if located == module_origin:
            module_digest = digest_hex
        if (
            os.name == "nt"
            and distribution.casefold() in {"slither-analyzer", "protobuf"}
        ):
            native_identity = (int(located_info.st_dev), int(located_info.st_ino))
            retained_cache_rows.append({
                "content_member": content_member,
                "device": native_identity[0],
                "file_id": native_identity[1],
                "link_count": int(located_info.st_nlink),
                "module_member": located == module_origin,
                "path": os.path.normcase(os.path.abspath(str(located))),
                "record_hash": str(record_row["hash"] or ""),
                "record_member": located == record_path,
                "record_size": record_row["bytes"],
                "relative_name": relative_name,
                "size": size,
            })
    if (
        not entries
        or not module_digest
        or len(record_entries) != len(normalized_record_rows)
        or (
            os.name == "nt"
            and len(record_native_identities) != len(normalized_record_rows)
        )
    ):
        raise SnapshotInputError(
            f"Python provider full RECORD physical denominator is incomplete: "
            f"{distribution}"
        )
    path_set = hashlib.sha256()
    content = hashlib.sha256()
    total = 0
    for relative_name, digest_hex, size in entries:
        encoded_name = relative_name.encode("utf-8")
        path_set.update(len(encoded_name).to_bytes(8, "big"))
        path_set.update(encoded_name)
        content.update(len(encoded_name).to_bytes(8, "big"))
        content.update(encoded_name)
        content.update(bytes.fromhex(digest_hex))
        content.update(size.to_bytes(8, "big"))
        total += size
    record_path_set = hashlib.sha256()
    record_content = hashlib.sha256()
    record_total = 0
    for relative_name, digest_hex, size in record_entries:
        encoded_name = relative_name.encode("utf-8")
        record_path_set.update(len(encoded_name).to_bytes(8, "big"))
        record_path_set.update(encoded_name)
        record_content.update(len(encoded_name).to_bytes(8, "big"))
        record_content.update(encoded_name)
        record_content.update(bytes.fromhex(digest_hex))
        record_content.update(size.to_bytes(8, "big"))
        record_total += size
    result = {
        "distribution_files_sha256": content.hexdigest(),
        "distribution_path_set_sha256": path_set.hexdigest(),
        "distribution_file_count": len(entries),
        "distribution_bytes": total,
        "record_member_files_sha256": record_content.hexdigest(),
        "record_member_path_set_sha256": record_path_set.hexdigest(),
        "record_member_file_count": len(record_entries),
        "record_member_native_identity_count": len(record_native_identities),
        "record_member_bytes": record_total,
        "record_path": record_relative,
        "record_sha256": hashlib.sha256(record_raw).hexdigest(),
        "record_bytes": len(record_raw),
        "record_row_count": len(normalized_record_rows),
        "record_normalized_rows_sha256": hashlib.sha256(
            _canonical_json(normalized_record_rows)
        ).hexdigest(),
        "module_origin": str(module_origin),
        "module_sha256": module_digest,
    }
    if (
        os.name == "nt"
        and distribution.casefold() in {"slither-analyzer", "protobuf"}
    ):
        physical_fold = hashlib.sha256()
        for row in retained_cache_rows:
            physical_fold.update(_canonical_json({
                "device": int(row["device"]),
                "file_id": int(row["file_id"]),
                "link_count": int(row["link_count"]),
                "path": str(row["path"]),
                "relative_name": str(row["relative_name"]),
                "size": int(row["size"]),
            }))
        payload = {
            "authority_root": os.path.normcase(
                os.path.abspath(str(distribution_authority_root))
            ),
            "distribution": distribution,
            "module_name": module_name,
            "module_origin": os.path.normcase(
                os.path.abspath(str(module_origin))
            ),
            "module_origin_display": str(module_origin),
            "physical_fold_sha256": physical_fold.hexdigest(),
            "project_root": (
                os.path.normcase(os.path.abspath(str(resolved_project_root)))
                if resolved_project_root is not None
                else ""
            ),
            "record_bytes": len(record_raw),
            "record_normalized_rows_sha256": result[
                "record_normalized_rows_sha256"
            ],
            "record_path": record_relative,
            "record_row_count": len(normalized_record_rows),
            "record_sha256": hashlib.sha256(record_raw).hexdigest(),
            "rows": retained_cache_rows,
            "schema": "plamen.retained-python-distribution-closure.v1",
        }
        _PYTHON_DISTRIBUTION_CLOSURE_CACHE[distribution.casefold()] = (
            payload,
            _python_distribution_closure_cache_tag(payload),
        )
    return result


def _observed_protobuf_generated_version() -> str:
    try:
        text = _SCIP_PROTOBUF_GENERATED_PATH.read_text(
            encoding="utf-8", errors="strict"
        )
    except Exception:
        return "UNAVAILABLE"
    matches = re.findall(
        r"(?m)^# Protobuf Python Version: "
        r"([0-9]+\.[0-9]+\.[0-9]+)\s*$",
        text,
    )
    return matches[0] if len(matches) == 1 else "AMBIGUOUS"


def _semantic_version_tuple(value: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", str(value))
    return tuple(map(int, match.groups())) if match else None


def _protobuf_versions_compatible(
    *,
    observed_runtime: str,
    observed_generated: str,
    locked_row: Mapping[str, Any],
) -> bool:
    runtime = _semantic_version_tuple(observed_runtime)
    generated = _semantic_version_tuple(observed_generated)
    expected_runtime = _semantic_version_tuple(
        str(locked_row.get("expected_version") or "")
    )
    expected_generated = _semantic_version_tuple(
        str(locked_row.get("generated_code_version") or "")
    )
    return bool(
        runtime
        and generated
        and expected_runtime
        and expected_generated
        and runtime == expected_runtime
        and generated == expected_generated
        and generated[0] == runtime[0]
        and generated <= runtime
    )


def _reviewed_python_distribution_content_status(
    locked_row: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> tuple[str, bool, tuple[str, ...]]:
    """Evaluate typed installed content without trusting governance booleans."""

    authority = locked_row.get("content_authority")
    if (
        not isinstance(authority, Mapping)
        or authority.get("mode") != "REVIEWED_CONTENT_MATCH"
    ):
        return "OBSERVED_NONAUTHORITATIVE", False, ("reviewed-content-absent",)
    rows = authority.get("reviewed_content_sha256")
    if not isinstance(rows, list) or not rows:
        return "OBSERVED_NONAUTHORITATIVE", False, ("reviewed-content-empty",)
    expected: dict[str, str] = {}
    for row in rows:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"content_kind", "sha256"}
            or not isinstance(row.get("content_kind"), str)
            or not isinstance(row.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
            or row["content_kind"] in expected
        ):
            return "REVOKED", False, ("reviewed-content-malformed",)
        expected[row["content_kind"]] = row["sha256"]
    observed_fields = {
        "wheel": "wheel_sha256",
        "record": "record_sha256",
        "normalized_record_rows": "record_normalized_rows_sha256",
        "distribution_path_set": "distribution_path_set_sha256",
        "distribution_files": "distribution_files_sha256",
        "module": "module_sha256",
        "generated_module": "generated_module_sha256",
    }
    if set(expected) != set(observed_fields):
        return "REVOKED", False, ("reviewed-content-denominator",)
    required = {
        "wheel_filename",
        "wheel_python_tag",
        "wheel_abi_tag",
        "wheel_platform_tag",
        *observed_fields.values(),
    }
    issues: list[str] = []
    expected_wheel = (
        "protobuf-7.35.1-cp310-abi3-win_amd64.whl",
        "cp310",
        "abi3",
        "win_amd64",
    )
    observed_wheel = (
        observed.get("wheel_filename"),
        observed.get("wheel_python_tag"),
        observed.get("wheel_abi_tag"),
        observed.get("wheel_platform_tag"),
    )
    if all(observed.get(key) for key in (
        "wheel_filename",
        "wheel_python_tag",
        "wheel_abi_tag",
        "wheel_platform_tag",
    )) and observed_wheel != expected_wheel:
        issues.append("wheel-identity")
    for kind, field in observed_fields.items():
        if observed.get(field) and observed.get(field) != expected[kind]:
            issues.append(kind)
    if issues:
        return "REVOKED", False, tuple(issues)
    missing = sorted(key for key in required if not observed.get(key))
    if missing:
        return "OBSERVED_NONAUTHORITATIVE", False, tuple(
            f"missing:{key}" for key in missing
        )
    return "MATCH", True, ()


def _reviewed_wheel_observation(
    locked_row: Mapping[str, Any],
    *,
    project_root: Path | None,
) -> dict[str, Any]:
    authority = locked_row.get("content_authority")
    if not isinstance(authority, Mapping):
        return {}
    rows = authority.get("reviewed_content_sha256")
    if not isinstance(rows, list):
        return {}
    wheel_row = next(
        (
            row for row in rows
            if isinstance(row, Mapping) and row.get("content_kind") == "wheel"
        ),
        None,
    )
    if not isinstance(wheel_row, Mapping):
        return {}
    filename = "protobuf-7.35.1-cp310-abi3-win_amd64.whl"
    wheel_path = Path(sys.prefix) / "reviewed_wheels" / filename
    if not wheel_path.is_file():
        return {}
    try:
        resolved = wheel_path.resolve(strict=True)
        if _path_is_within(resolved, project_root):
            return {}
        _reject_unexpected_hardlinks(
            resolved,
            "reviewed protobuf wheel",
            project_root=project_root,
        )
        digest, _size = _hash_path(resolved)
    except (OSError, SnapshotInputError):
        return {}
    return {
        "wheel_filename": filename,
        "wheel_python_tag": "cp310",
        "wheel_abi_tag": "abi3",
        "wheel_platform_tag": "win_amd64",
        "wheel_sha256": digest.hex(),
    }


def _runtime_python_distribution_fingerprint(
    identity_id: str,
    *,
    project_root: Path | None = None,
) -> bytes:
    controls = _load_toolchain_identity_controls()
    locked_row = controls[0].get(identity_id)
    if (
        locked_row is None
        or locked_row.get("identity_kind") != "python_distribution"
    ):
        raise SnapshotInputError(
            f"Python distribution identity is not reviewed: {identity_id}"
        )
    distribution = str(locked_row["package_name"])
    module_name = str(locked_row["python_module"])
    version = _python_distribution_version(distribution)
    expected, status, authority, lock_digest, governance_digest = (
        _runtime_identity_policy(
            identity_id,
            resolved_identity=(
                distribution
                if version != "UNAVAILABLE"
                else "UNAVAILABLE"
            ),
            version=version,
            identity_kind="python_distribution",
            controls=controls,
        )
    )
    closure: dict[str, Any] = {}
    if _observed_version_available(
        resolved_identity=distribution,
        version=version,
    ):
        closure = _python_distribution_closure(
            distribution,
            module_name,
            project_root=project_root,
        )
    expected_distribution = {
        "distribution": distribution,
        "version": expected["version"],
    }
    expected_distribution["content_authority"] = expected.get(
        "content_authority"
    )
    if "generated_code_version" in expected:
        expected_distribution["generated_code_version"] = expected[
            "generated_code_version"
        ]
    generated_observed = ""
    if identity_id == "protobuf":
        generated_observed = _observed_protobuf_generated_version()
        if not _protobuf_versions_compatible(
            observed_runtime=version,
            observed_generated=generated_observed,
            locked_row=locked_row,
        ):
            status = "MISMATCH"
            authority = False
        try:
            generated_digest, generated_bytes = _hash_path(
                _SCIP_PROTOBUF_GENERATED_PATH
            )
            closure["generated_module_sha256"] = generated_digest.hex()
            closure["generated_module_bytes"] = generated_bytes
        except SnapshotInputError:
            status = "REVOKED"
            authority = False
        closure.update(
            _reviewed_wheel_observation(
                locked_row,
                project_root=project_root,
            )
        )
        if status not in {"MISMATCH", "REVOKED"}:
            status, authority, content_issues = (
                _reviewed_python_distribution_content_status(
                    locked_row,
                    closure,
                )
            )
            if content_issues:
                closure["content_authority_issues"] = list(content_issues)
    revocation_issues = _identity_revocation_issues(
        identity_id,
        version=version,
        digests=(
            str(closure.get("distribution_files_sha256") or ""),
            str(closure.get("module_sha256") or ""),
        ),
        controls=controls,
    )
    if revocation_issues:
        status = "REVOKED"
        authority = False
    identity = {
        "schema": RUNTIME_TOOL_IDENTITY_SCHEMA,
        "tool_id": identity_id,
        "identity_kind": "python_distribution",
        "command": ["python-importlib-metadata", distribution],
        "resolved_executable": sys.executable,
        "version": version,
        "expected_identity": expected_distribution,
        "observed_identity": {
            "distribution": distribution,
            "version": version,
        },
        "identity_status": status,
        "deterministic_provider_authority": authority,
        "toolchain_version_lock_sha256": lock_digest,
        "toolchain_governance_sha256": governance_digest,
        **closure,
    }
    if generated_observed:
        identity["generated_code_observed_version"] = generated_observed
    if revocation_issues:
        identity["revocation_issues"] = revocation_issues
    return _canonical_json(identity)


def _signed_provider_authority(identity: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(identity)
    payload.pop("authority_digest", None)
    payload["authority_digest"] = hashlib.sha256(
        _canonical_json(payload)
    ).hexdigest()
    return payload


def capture_command_provider_authority(
    tool_id: str,
    version_command: tuple[str, ...],
    *,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Capture a provider-ready command identity without raising into audit flow."""

    try:
        if not version_command or version_command[0] != tool_id:
            raise SnapshotInputError(
                "provider version command does not match its tool identity"
            )
        identity = json.loads(
            _runtime_tool_fingerprint(
                version_command,
                project_root=project_root,
            )
        )
        if not isinstance(identity, dict):
            raise SnapshotInputError("provider identity is not an object")
        result = dict(identity)
        result["authority_status"] = str(
            result.get("identity_status") or "INVALID"
        )
        result["reason"] = (
            ""
            if result.get("deterministic_provider_authority") is True
            else (
                "observed runtime identity lacks independently reviewed "
                "authentic content authority"
            )
        )
        return _signed_provider_authority(result)
    except SnapshotInputError as exc:
        message = str(exc)
        status = (
            "TARGET_RESOLUTION_REJECTED"
            if "inside audit target" in message or "hardlink" in message
            else "CONTROL_INVALID"
        )
        return _signed_provider_authority({
            "schema": RUNTIME_TOOL_IDENTITY_SCHEMA,
            "tool_id": tool_id,
            "identity_kind": "command",
            "authority_status": status,
            "deterministic_provider_authority": False,
            "reason": message,
        })


def capture_python_provider_authority(
    identity_id: str,
    *,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Capture a provider-ready Python distribution/module closure."""

    try:
        identity = json.loads(
            _runtime_python_distribution_fingerprint(
                identity_id,
                project_root=project_root,
            )
        )
        if not isinstance(identity, dict):
            raise SnapshotInputError("provider identity is not an object")
        result = dict(identity)
        result["authority_status"] = str(
            result.get("identity_status") or "INVALID"
        )
        result["reason"] = (
            ""
            if result.get("deterministic_provider_authority") is True
            else (
                "observed Python distribution/module closure lacks "
                "independently reviewed authentic content authority"
            )
        )
        return _signed_provider_authority(result)
    except SnapshotInputError as exc:
        message = str(exc)
        status = (
            "TARGET_RESOLUTION_REJECTED"
            if "inside audit target" in message or "hardlink" in message
            else "CONTROL_INVALID"
        )
        return _signed_provider_authority({
            "schema": RUNTIME_TOOL_IDENTITY_SCHEMA,
            "tool_id": identity_id,
            "identity_kind": "python_distribution",
            "authority_status": status,
            "deterministic_provider_authority": False,
            "reason": message,
        })


def provider_authority_replays(
    authority: Mapping[str, Any],
    *,
    project_root: Path | None = None,
) -> bool:
    """Re-capture and compare the full signed authority after provider use."""

    tool_id = str(authority.get("tool_id") or "")
    kind = str(authority.get("identity_kind") or "command")
    if kind == "python_distribution":
        replay = capture_python_provider_authority(
            tool_id, project_root=project_root
        )
    else:
        command = authority.get("command")
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(item, str) for item in command)
        ):
            return False
        replay = capture_command_provider_authority(
            tool_id,
            tuple(command),
            project_root=project_root,
        )
    return (
        authority.get("deterministic_provider_authority") is True
        and replay.get("deterministic_provider_authority") is True
        and replay.get("authority_digest") == authority.get("authority_digest")
    )


def _installed_python_packages() -> bytes:
    try:
        from importlib import metadata
        import sysconfig

        prefix = Path(sys.prefix).resolve(strict=True)
        managed_roots: dict[str, str] = {}
        configured_paths = sysconfig.get_paths()
        for key in ("purelib", "platlib"):
            raw = configured_paths.get(key)
            if not isinstance(raw, str) or not raw:
                raise SnapshotInputError(
                    f"managed Python {key} path is unavailable"
                )
            try:
                root = Path(raw).resolve(strict=True)
                root.relative_to(prefix)
            except (OSError, ValueError) as exc:
                raise SnapshotInputError(
                    f"managed Python {key} path escapes the interpreter prefix"
                ) from exc
            if not root.is_dir():
                raise SnapshotInputError(
                    f"managed Python {key} path is not a directory"
                )
            managed_roots[
                os.path.normcase(os.path.abspath(str(root)))
            ] = str(root)
        roots = tuple(managed_roots[key] for key in sorted(managed_roots))
        if not roots:
            raise SnapshotInputError(
                "managed Python package denominator is unavailable"
            )

        packages = sorted(
            {
                (
                    (dist.metadata.get("Name") or "UNKNOWN").lower(),
                    dist.version,
                )
                for dist in metadata.distributions(path=roots)
            }
        )
        # Do not cache this result across snapshots.  Package metadata can
        # change while an audit is running even though its site-packages root
        # directory metadata remains unchanged.  Re-reading the fixed managed
        # roots makes that drift observable without admitting temporary
        # process-global sys.path entries.
        return _canonical_json(packages)
    except Exception as exc:
        raise SnapshotInputError("installed Python package state is unreadable") from exc


RUNTIME_TOOL_COMMANDS: dict[str, tuple[str, ...]] = {
    "git": ("git", "--version"),
    "codex": ("codex", "--version"),
    "claude": ("claude", "--version"),
    "node": ("node", "--version"),
    "npm": ("npm", "--version"),
    "forge": ("forge", "--version"),
    "solc": ("solc", "--version"),
    "medusa": ("medusa", "--version"),
    "cargo": ("cargo", "--version"),
    "rustc": ("rustc", "--version"),
    "cargo-build-sbf": ("cargo-build-sbf", "--version"),
    "cargo-scout-audit": ("cargo-scout-audit", "--help"),
    "cargo-fuzz": ("cargo-fuzz", "--version"),
    "cargo-audit": ("cargo-audit", "--version"),
    "rust-analyzer": ("rust-analyzer", "--version"),
    "go": ("go", "version"),
    "scip-go": ("scip-go", "--version"),
    "govulncheck": ("govulncheck", "-version"),
    "solana": ("solana", "--version"),
    "anchor": ("anchor", "--version"),
    "trident": ("trident", "--version"),
    "aptos": ("aptos", "--version"),
    "sui": ("sui", "--version"),
    "stellar": ("stellar", "--version"),
    "daml": ("daml", "version"),
    "damlc": ("damlc", "version"),
    "opengrep": ("opengrep", "--version"),
    "semgrep": ("semgrep", "--version"),
    "docker": ("docker", "--version"),
    "ast-grep": ("ast-grep", "--version"),
}


def _fixed_runtime_tool_entries(
    *,
    project_root: Path | None = None,
) -> tuple[tuple[str, bytes], ...]:
    """Capture runtime/tool identity on every snapshot construction.

    Deliberately uncached: resume and phase-boundary revalidation must observe
    PATH or executable replacement in the same Python process.
    """
    entries: list[tuple[str, bytes]] = [
        (
            "@runtime/platform",
            f"{platform.system()}|{platform.release()}|{platform.machine()}".encode(),
        ),
        ("@runtime/python", sys.version.encode("utf-8", "replace")),
    ]
    controls = _load_toolchain_identity_controls()
    for name, command in RUNTIME_TOOL_COMMANDS.items():
        governed = controls[1].get(name)
        # Exact-release tools must prove their parsed version.  A governed
        # version revocation also requires a live probe.  DEBT/EXTERNAL tools
        # without version revocations are content-bound by resolved path and
        # SHA-256 but are not executed merely to construct a snapshot: their
        # governance explicitly denies deterministic provider authority.
        probe_version = (
            name in controls[0]
            or governed is None
            or bool(
                governed["revocation_policy"][
                    "blocked_version_substrings"
                ]
            )
        )
        fingerprint = (
            _runtime_tool_fingerprint(
                command,
                probe_version=probe_version,
                controls=controls,
            )
            if project_root is None
            else _runtime_tool_fingerprint(
                command,
                project_root=project_root,
                probe_version=probe_version,
                controls=controls,
            )
        )
        try:
            from tool_coverage_ledger import tool_identity_policy_issues

            policy_issues = tool_identity_policy_issues(name, fingerprint)
        except (ImportError, ValueError, OSError) as exc:
            raise SnapshotInputError(
                "toolchain governance evaluator is unavailable"
            ) from exc
        if policy_issues:
            raise SnapshotInputError(
                f"runtime tool {name} violates revocation policy: "
                + "; ".join(policy_issues)
            )
        entries.append((f"@runtime/tool/{name}", fingerprint))
    entries.append(
        (
            "@runtime/tool/slither",
            _runtime_python_distribution_fingerprint(
                "slither", project_root=project_root
            ),
        )
    )
    entries.append(
        (
            "@runtime/tool/protobuf",
            _runtime_python_distribution_fingerprint(
                "protobuf", project_root=project_root
            ),
        )
    )
    entries.append(("@runtime/python_packages", _installed_python_packages()))
    return tuple(entries)


def resolve_windows_codex_ca_bundle(
    environment: Mapping[str, str] | None = None,
    *,
    project_root: Path | None = None,
    platform_name: str | None = None,
) -> Path | None:
    """Resolve the CA file Codex can read inside Windows Low Integrity.

    The Windows-native certificate store is not reliably reachable from the
    restricted provider token.  Prefer an operator-selected bundle, then the
    CA bundle installed with this exact Python runtime.  The audit snapshot
    binds the selected path and bytes, so replacement invalidates resume.
    """

    if (platform_name or sys.platform) != "win32":
        return None
    values = dict(os.environ if environment is None else environment)
    by_case = {str(key).casefold(): str(value) for key, value in values.items()}
    explicit: str | None = None
    for name in ("CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"):
        value = by_case.get(name.casefold(), "").strip()
        if value:
            explicit = value
            break

    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    else:
        configured = sysconfig.get_paths()
        for key in ("purelib", "platlib"):
            root = configured.get(key)
            if isinstance(root, str) and root:
                candidate = Path(root) / "certifi" / "cacert.pem"
                if candidate not in candidates:
                    candidates.append(candidate)

    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            if explicit is not None:
                raise SnapshotInputError(
                    "configured Codex CA certificate is unavailable"
                ) from None
            continue
        if (
            not resolved.is_file()
            or resolved.is_symlink()
            or metadata.st_size <= 0
            or metadata.st_size > 8 * 1024 * 1024
        ):
            if explicit is not None:
                raise SnapshotInputError(
                    "configured Codex CA certificate is not a bounded regular file"
                )
            continue
        if project_root is not None and _is_descendant_or_equal(
            resolved, Path(project_root)
        ):
            raise SnapshotInputError(
                "Codex CA certificate cannot be controlled by the audit target"
            )
        return resolved
    return None


def _runtime_tool_entries(
    *,
    project_root: Path | None = None,
    config: Mapping[str, Any] | None = None,
) -> list[tuple[str, bytes]]:
    """Bind OS, interpreter, tools, and audit-semantic environment knobs."""
    entries = list(
        _fixed_runtime_tool_entries(project_root=project_root)
    )
    semantic_env = {
        key: value
        for key, value in os.environ.items()
        if key not in _OPERATIONAL_ENV_KEYS
        and any(key.startswith(prefix) for prefix in _SEMANTIC_ENV_PREFIXES)
    }
    entries.append(("@runtime/semantic_env", _canonical_json(semantic_env)))
    if (
        (config or {}).get("cli_backend") == "codex"
        and sys.platform == "win32"
    ):
        bundle = resolve_windows_codex_ca_bundle(
            os.environ,
            project_root=project_root,
        )
        if bundle is None:
            entries.append(("@runtime/codex_ca_certificate", b"UNAVAILABLE"))
        else:
            raw = bundle.read_bytes()
            entries.append((
                "@runtime/codex_ca_certificate",
                _canonical_json({
                    "path": str(bundle),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }),
            ))
    return entries


def build_audit_snapshot(
    config: Mapping[str, Any], implementation_root: Path
) -> dict[str, Any]:
    """Return a deterministic snapshot of all inputs that make evidence valid."""
    implementation_root = Path(implementation_root).resolve()
    if not implementation_root.is_dir():
        raise SnapshotInputError(
            f"implementation root is missing or not a directory: {implementation_root}"
        )
    components = {
        "source_scope": _source_component(config),
        "audit_config": _config_component(config),
        "methodology": _methodology_component(implementation_root),
        "toolchain": _toolchain_component(
            implementation_root,
            project_root=Path(str(config.get("project_root") or "")).resolve(),
            config=config,
        ),
    }
    binding = {
        "schema": SNAPSHOT_SCHEMA,
        "components": components,
    }
    binding["snapshot_digest"] = _sha256(_canonical_json(binding))
    return binding


def _valid_runtime_entry_manifest(value: Any) -> bool:
    if (
        not isinstance(value, dict)
        or len(value) > _MAX_RUNTIME_ENTRY_MANIFEST_ITEMS
    ):
        return False
    for identity, record in value.items():
        if (
            not isinstance(identity, str)
            or not identity.startswith("@runtime/")
            or "\x00" in identity
            or not identity
            or len(identity.encode("utf-8"))
            > _MAX_RUNTIME_ENTRY_IDENTITY_BYTES
            or not isinstance(record, dict)
            or set(record) != {"sha256", "byte_count"}
            or not isinstance(record.get("sha256"), str)
            or _HEX_64_RE.fullmatch(record["sha256"]) is None
            or isinstance(record.get("byte_count"), bool)
            or not isinstance(record.get("byte_count"), int)
            or record["byte_count"] < 0
        ):
            return False
    return True


def _valid_snapshot(snapshot: Any) -> bool:
    if (
        not isinstance(snapshot, dict)
        or set(snapshot) != {"schema", "components", "snapshot_digest"}
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or not isinstance(snapshot.get("snapshot_digest"), str)
        or _HEX_64_RE.fullmatch(snapshot["snapshot_digest"]) is None
    ):
        return False
    components = snapshot.get("components")
    if not isinstance(components, dict) or set(components) != set(_COMPONENTS):
        return False

    expected_keys = {
        "source_scope": {
            "digest", "path_set_digest", "file_count", "byte_count",
            "language", "pipeline", "git_head", "coverage_limitations",
        },
        "audit_config": {"digest", "field_count"},
        "methodology": {"digest", "path_set_digest", "file_count", "byte_count"},
        "toolchain": {"digest", "path_set_digest", "file_count", "byte_count"},
    }
    for name in _COMPONENTS:
        component = components.get(name)
        allowed_keys = expected_keys[name]
        if name == "toolchain" and isinstance(component, dict):
            # v1 snapshots produced before runtime-entry observability remain
            # valid.  New snapshots add one optional, digest-bound manifest;
            # component digests retain their original meaning and therefore
            # compare cleanly across the compatible representation change.
            component_keys = set(component)
            if component_keys == allowed_keys | {"runtime_entries"}:
                if not _valid_runtime_entry_manifest(
                    component.get("runtime_entries")
                ):
                    return False
            elif component_keys != allowed_keys:
                return False
        elif not isinstance(component, dict) or set(component) != allowed_keys:
            return False
        if not isinstance(component.get("digest"), str) or _HEX_64_RE.fullmatch(component["digest"]) is None:
            return False
        for key in ("path_set_digest",):
            if key in component and (
                not isinstance(component[key], str)
                or _HEX_64_RE.fullmatch(component[key]) is None
            ):
                return False
        for key in ("file_count", "byte_count", "field_count"):
            if key in component and (
                isinstance(component[key], bool)
                or not isinstance(component[key], int)
                or component[key] < 0
            ):
                return False
    source = components["source_scope"]
    if source["pipeline"] not in {"sc", "l1"}:
        return False
    if not isinstance(source["language"], str):
        return False
    if (
        not isinstance(source["coverage_limitations"], list)
        or not all(isinstance(item, str) for item in source["coverage_limitations"])
    ):
        return False
    if not isinstance(source["git_head"], str) or not (
        source["git_head"] == "UNAVAILABLE"
        or _GIT_HEAD_RE.fullmatch(source["git_head"]) is not None
    ):
        return False
    expected = dict(snapshot)
    supplied_digest = expected.pop("snapshot_digest", None)
    return supplied_digest == _sha256(_canonical_json(expected))


def _runtime_entry_changes(
    stored_toolchain: Mapping[str, Any],
    current_toolchain: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    """Explain runtime-only toolchain drift without exposing payload bytes."""

    stored = stored_toolchain.get("runtime_entries")
    current = current_toolchain.get("runtime_entries")
    if not isinstance(stored, dict) or not isinstance(current, dict):
        # A compatible legacy snapshot has no per-entry denominator.  Do not
        # invent a cause from the aggregate; the component mismatch remains
        # authoritative while entry-level evidence is honestly unavailable.
        return ()
    changes: list[dict[str, Any]] = []
    for identity in sorted(set(stored) | set(current)):
        old = stored.get(identity)
        new = current.get(identity)
        if old == new:
            continue
        changes.append(
            {
                "component": "toolchain",
                "identity": identity,
                "stored": None if old is None else dict(old),
                "current": None if new is None else dict(new),
            }
        )
    return tuple(changes)


def classify_snapshot(
    stored: Any, current: Mapping[str, Any], *, has_prior_progress: bool
) -> SnapshotVerdict:
    """Classify resume binding without interpreting checkpoint phase names."""
    if not _valid_snapshot(current):
        raise ValueError("current audit snapshot is invalid")
    if stored is None:
        if has_prior_progress:
            return SnapshotVerdict(LEGACY_UNBOUND, ("snapshot_binding",))
        return SnapshotVerdict(NEW)
    if not _valid_snapshot(stored):
        return SnapshotVerdict(LEGACY_UNBOUND, ("snapshot_binding",))

    changed = tuple(
        name
        for name in _COMPONENTS
        if stored["components"][name]["digest"]
        != current["components"][name]["digest"]
    )
    if changed:
        runtime_changes = (
            _runtime_entry_changes(
                stored["components"]["toolchain"],
                current["components"]["toolchain"],
            )
            if "toolchain" in changed
            else ()
        )
        return SnapshotVerdict(MISMATCH, changed, runtime_changes)
    return SnapshotVerdict(MATCH)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".pj-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(payload)
            handle.flush()
        os.replace(temporary, path)
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise


def _is_reparse_point(path: Path) -> bool:
    try:
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return False


@contextmanager
def _exclusive_startup_lock(lock_path: Path, timeout_seconds: float = 15.0):
    """Hold an OS-enforced lock outside the directory that may be renamed."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    if lock_path.stat().st_size == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    deadline = time.monotonic() + timeout_seconds
    acquired = False
    try:
        while not acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "timed out acquiring exclusive snapshot-startup ownership"
                    )
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()


@contextmanager
def snapshot_startup_guard(project_root: Path):
    """Serialize checkpoint classification, quarantine, and snapshot binding."""
    root = Path(project_root).resolve(strict=True)
    with _exclusive_startup_lock(root / _ARCHIVE_LOCK_NAME):
        yield


def _validate_scratchpad(project_root: Path, scratchpad: Path) -> tuple[Path, Path]:
    project_root = Path(project_root).resolve(strict=True)
    raw_scratchpad = Path(scratchpad).absolute()
    if raw_scratchpad == project_root or raw_scratchpad == Path.home().resolve():
        raise RuntimeError("refusing to archive a project/home root as a scratchpad")
    if raw_scratchpad.parent == raw_scratchpad:
        raise RuntimeError("refusing to archive a filesystem root")
    if raw_scratchpad.exists() and (
        raw_scratchpad.is_symlink() or _is_reparse_point(raw_scratchpad)
    ):
        raise RuntimeError("refusing to archive a symlink/junction scratchpad")
    resolved = raw_scratchpad.resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError as exc:
        raise RuntimeError("scratchpad must be contained by project_root") from exc
    if resolved == project_root:
        raise RuntimeError("scratchpad must not equal project_root")
    return project_root, resolved


def _owner_payload(project_root: Path, scratchpad: Path) -> dict[str, Any]:
    return {
        "schema": "plamen.scratchpad-owner.v1",
        "project_root_sha256": _sha256(str(project_root).encode("utf-8")),
        "scratchpad_name": scratchpad.name,
    }


def _ensure_owner_sentinel(project_root: Path, scratchpad: Path) -> None:
    owner = scratchpad / _SCRATCHPAD_OWNER_NAME
    expected = _owner_payload(project_root, scratchpad)
    if owner.exists():
        if owner.is_symlink() or not owner.is_file():
            raise RuntimeError("scratchpad ownership sentinel is not a regular file")
        try:
            actual = json.loads(owner.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError("scratchpad ownership sentinel is unreadable") from exc
        if actual != expected:
            raise RuntimeError("scratchpad ownership sentinel does not match this project")
    else:
        _atomic_json(owner, expected)


def _recover_archive_intent(
    project_root: Path, scratchpad: Path, intent_path: Path
) -> None:
    if not intent_path.exists():
        return
    try:
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        archive = Path(intent["archive_dir"])
    except Exception as exc:
        raise RuntimeError("snapshot archive intent is corrupt") from exc
    archive_root = project_root / _ARCHIVE_ROOT_NAME
    try:
        archive.resolve().relative_to(archive_root.resolve())
    except ValueError as exc:
        raise RuntimeError("snapshot archive intent escapes its archive root") from exc
    if archive.exists() and not scratchpad.exists():
        os.replace(archive, scratchpad)
        intent_path.unlink()
        return
    if scratchpad.exists() and not archive.exists():
        intent_path.unlink()
        return
    raise RuntimeError(
        "ambiguous interrupted snapshot archive; human review is required"
    )


def archive_stale_scratchpad(
    scratchpad: Path,
    *,
    project_root: Path,
    reason: str,
    preserve_names: set[str] | None = None,
    startup_lock_held: bool = False,
) -> ArchiveReceipt:
    """Atomically quarantine an entire stale scratchpad under startup lock.

    The only destructive transition is a same-volume directory rename. Control
    files are copied into a newly-created scratchpad only after the stale tree
    is safely quarantined. Any ordinary failure rolls the rename back; a small
    external intent journal makes process-crash recovery deterministic.
    """
    project_root, scratchpad = _validate_scratchpad(project_root, scratchpad)
    preserve = set(preserve_names or set())
    if any(Path(name).name != name for name in preserve):
        raise RuntimeError("preserve_names must contain base names only")
    lock_path = project_root / _ARCHIVE_LOCK_NAME
    intent_path = project_root / _ARCHIVE_INTENT_NAME
    archive_root = project_root / _ARCHIVE_ROOT_NAME

    lock_context = (
        nullcontext()
        if startup_lock_held
        else _exclusive_startup_lock(lock_path)
    )
    with lock_context:
        _recover_archive_intent(project_root, scratchpad, intent_path)
        scratchpad.mkdir(parents=True, exist_ok=True)
        _ensure_owner_sentinel(project_root, scratchpad)

        preserved_payloads: dict[str, bytes] = {}
        for name in sorted(preserve):
            path = scratchpad / name
            if not path.exists():
                continue
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                raise RuntimeError(f"refusing to copy unsafe preserved control file: {name}")
            preserved_payloads[name] = path.read_bytes()

        all_names = sorted(path.name for path in scratchpad.iterdir())
        moved = tuple(
            name for name in all_names
            if name not in preserve and name != _SCRATCHPAD_OWNER_NAME
        )
        preserved = tuple(name for name in all_names if name in preserved_payloads)
        archive_root.mkdir(parents=True, exist_ok=True)
        archive = archive_root / f"stale-{uuid.uuid4().hex}"
        while archive.exists():
            archive = archive_root / f"stale-{uuid.uuid4().hex}"
        _atomic_json(
            intent_path,
            {
                "schema": "plamen.snapshot-archive-intent.v1",
                "scratchpad": str(scratchpad),
                "archive_dir": str(archive),
                "reason": reason,
            },
        )

        renamed = False
        recreated = False
        try:
            os.replace(scratchpad, archive)
            renamed = True
            scratchpad.mkdir(parents=False, exist_ok=False)
            recreated = True
            _atomic_json(
                scratchpad / _SCRATCHPAD_OWNER_NAME,
                _owner_payload(project_root, scratchpad),
            )
            for name, payload in preserved_payloads.items():
                destination = scratchpad / name
                temporary = scratchpad / f".{name}.{uuid.uuid4().hex}.tmp"
                temporary.write_bytes(payload)
                os.replace(temporary, destination)
            _atomic_json(
                archive / "snapshot_mismatch_receipt.json",
                {
                    "schema": "plamen.snapshot-mismatch-archive.v1",
                    "reason": reason,
                    "status": "COMPLETE",
                    "moved_names": list(moved),
                    "preserved_names": list(preserved),
                },
            )
            intent_path.unlink()
        except Exception as exc:
            try:
                if renamed:
                    if recreated and scratchpad.exists():
                        shutil.rmtree(scratchpad)
                    if archive.exists():
                        os.replace(archive, scratchpad)
                if intent_path.exists():
                    intent_path.unlink()
            except Exception as rollback_exc:
                raise RuntimeError(
                    "snapshot quarantine failed and rollback was incomplete; "
                    "human review is required"
                ) from rollback_exc
            raise RuntimeError(
                f"could not atomically quarantine stale scratchpad: {exc}"
            ) from exc

        return ArchiveReceipt(archive, moved, preserved)
