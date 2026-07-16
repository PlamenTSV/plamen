"""Content-bound audit snapshots for safe deterministic resume.

The checkpoint says *where* execution stopped.  This module records *what* was
being audited and which methodology/tool implementation produced the evidence.
It deliberately has no dependency on the driver or checkpoint classes so the
snapshot can be built and tested before phase orchestration starts.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Iterable, Mapping
import uuid
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from production_source_scope import is_production_source_path

SNAPSHOT_SCHEMA = "plamen.audit-input-snapshot.v1"
NEW = "NEW"
MATCH = "MATCH"
MISMATCH = "MISMATCH"
LEGACY_UNBOUND = "LEGACY_UNBOUND"

_COMPONENTS = ("source_scope", "audit_config", "methodology", "toolchain")
_SOURCE_SUFFIXES = {
    "evm": (".sol", ".vy"),
    "solana": (".rs",),
    "soroban": (".rs",),
    "aptos": (".move",),
    "sui": (".move",),
    "daml": (".daml",),
    "go": (".go",),
    "rust": (".rs",),
}
_L1_SOURCE_SUFFIXES = (".go", ".rs", ".move", ".proto")
_ALL_SOURCE_SUFFIXES = tuple(
    sorted({suffix for values in _SOURCE_SUFFIXES.values() for suffix in values}
           | set(_L1_SOURCE_SUFFIXES))
)
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
    ".claude",
    ".codex",
    ".medusa-tests",
    "__pycache__",
    "build",
    "downloads",
    "generated",
    ".plamen-audit-inputs",
    "vendor",
}
_GENERATED_AUDIT_NAME_RE = re.compile(
    r"(?:^|[_\-.])(?:poc|exploit|verify|audit[_-]?report|fuzz[_-]?corpus)"
    r"(?:[_\-.]|$)",
    re.IGNORECASE,
)
_METHODOLOGY_DIRS = (
    "agents",
    "commands",
    "prompts",
    "rules",
    "skills",
    "plamen_l1",
    "codex-adapter/commands",
    "codex-adapter/skills",
)
_TOOLCHAIN_DIRS = (
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
    "requirements.txt",
    "requirements-dev.txt",
    "write_dedup.py",
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
_MAX_SNAPSHOT_FILES = 100_000
_MAX_STABLE_READ_RETRIES = 3
_ARCHIVE_ROOT_NAME = ".plamen-stale-snapshots"
_ARCHIVE_LOCK_NAME = ".plamen-snapshot-startup.lock"
_ARCHIVE_INTENT_NAME = ".plamen-snapshot-archive-intent.json"
_SCRATCHPAD_OWNER_NAME = ".plamen-scratchpad-owner.json"

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
_TOOL_FINGERPRINT_CACHE: dict[tuple[Any, ...], bytes] = {}
_PYTHON_PACKAGE_CACHE: dict[tuple[Any, ...], bytes] = {}


class SnapshotInputError(RuntimeError):
    """The audited input universe could not be frozen without ambiguity."""


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
        request = Request(url, headers={"User-Agent": "Plamen-Audit-Input-Freezer/1"})
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                payload = response.read(_MAX_REMOTE_DOCUMENT_BYTES + 1)
                effective = response.geturl()
                headers = response.headers
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
                "content_type": headers.get("Content-Type", ""),
                "etag": headers.get("ETag", ""),
                "last_modified": headers.get("Last-Modified", ""),
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


def _hash_path(path: Path) -> tuple[bytes, int]:
    """Stream-hash one stable regular file; never bless an unreadable state.

    A pre/post stat comparison prevents a walk-then-read mixed-time digest.  A
    changing file is retried a bounded number of times and then fails closed.
    Symlinks are content-bound together with their link target, while special
    files (devices, sockets, FIFOs) are rejected.
    """
    for _attempt in range(_MAX_STABLE_READ_RETRIES):
        try:
            link_target = os.readlink(path) if path.is_symlink() else None
            before = path.stat()
            if not stat.S_ISREG(before.st_mode):
                raise SnapshotInputError(f"audited input is not a regular file: {path}")
            hasher = hashlib.sha256()
            byte_count = 0
            if link_target is not None:
                prefix = b"SYMLINK\0" + os.fsencode(link_target) + b"\0"
                hasher.update(prefix)
                byte_count += len(prefix)
            with path.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    byte_count += len(chunk)
            after = path.stat()
            stable = (
                before.st_size == after.st_size
                and before.st_mtime_ns == after.st_mtime_ns
                and getattr(before, "st_ino", None) == getattr(after, "st_ino", None)
                and link_target == (os.readlink(path) if path.is_symlink() else None)
            )
            if stable:
                return hasher.digest(), byte_count
        except SnapshotInputError:
            raise
        except Exception as exc:
            raise SnapshotInputError(
                f"audited input is unreadable: {path} ({type(exc).__name__})"
            ) from exc
    raise SnapshotInputError(f"audited input changed while being frozen: {path}")


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
    entries: list[tuple[str, EntryPayload]] = []
    for directory in directories:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if any(part in {"__pycache__", ".git"} for part in path.parts):
                continue
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


def _project_context_files(project_root: Path) -> list[Path]:
    """Inventory every stable upstream file workers are allowed to consume.

    Build caches, dependency install trees, VCS internals, the scratchpad, and
    recognisable generated audit outputs are outside the read/freeze boundary.
    Pre-existing tests and documentation remain bound because they influence
    human/agent reasoning even when they are not production deployment units.
    """
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in _PROJECT_CONTEXT_SKIP_DIRS
            and not name.startswith(".scratchpad-stale-snapshot")
            and not name.startswith(".plamen-stale-snapshots")
        )
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if _is_generated_audit_artifact(path, project_root):
                continue
            files.append(path)
            if len(files) > _MAX_EXTERNAL_INPUT_FILES:
                raise SnapshotInputError(
                    "audit input tree exceeds the bounded file-count limit; "
                    "freeze a smaller explicit input bundle"
                )
    return files


def _casefold_production_source_files(
    project_root: Path, suffixes: tuple[str, ...]
) -> list[Path]:
    """Use the canonical production predicate with case-insensitive suffixes."""
    wanted = {suffix.lower() for suffix in suffixes}
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [
            name for name in dirnames
            if name not in _PROJECT_CONTEXT_SKIP_DIRS and not name.startswith(".")
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in wanted:
                continue
            if is_production_source_path(path, project_root):
                out.append(path)
    return sorted(out)


def _scope_file_targets(
    config: Mapping[str, Any], project_root: Path
) -> list[Path]:
    raw_scope = str(config.get("scope_file") or "").strip()
    if not raw_scope:
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
                        targets[str(child.resolve()).casefold()] = child.resolve()
                elif resolved.is_file():
                    targets[str(resolved).casefold()] = resolved
                else:
                    raise SnapshotInputError(f"scope target is missing: {token}")
    if text.strip() and not targets:
        raise SnapshotInputError(
            "scope_file contains no parseable auditable targets; use one path per row"
        )
    return [targets[key] for key in sorted(targets)]


def _git_head(project_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        value = result.stdout.strip()
        if result.returncode == 0 and _GIT_HEAD_RE.fullmatch(value.lower()):
            return value.lower()
    except Exception:
        pass
    return "UNAVAILABLE"


def _git_submodule_state(project_root: Path) -> bytes:
    """Bind dependency checkout identity and dirty/uninitialized markers."""
    try:
        result = subprocess.run(
            ["git", "-C", str(project_root), "submodule", "status", "--recursive"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
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


def _source_component(config: Mapping[str, Any]) -> dict[str, Any]:
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
    for path in _casefold_production_source_files(project_root, tuple(suffixes)):
        if _is_generated_verification_source(path, project_root):
            continue
        production_files.append(path)

    scope_targets = _scope_file_targets(config, project_root)
    if not production_files and not scope_targets:
        raise SnapshotInputError(
            "no auditable production source or explicit scope target was found"
        )
    limitations: list[str] = []
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
    for path in _project_context_files(project_root):
        relative = path.relative_to(project_root).as_posix()
        context_paths.add(str(path.resolve()).casefold())
        entries.append((f"context/{relative}", path))

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


def _config_component(config: Mapping[str, Any]) -> dict[str, Any]:
    semantic = _semantic_config(config)
    return {
        "digest": _sha256(_canonical_json(semantic)),
        "field_count": len(semantic),
    }


def _methodology_component(implementation_root: Path) -> dict[str, Any]:
    return _digest_entries(_tree_entries(implementation_root, _METHODOLOGY_DIRS))


def _toolchain_component(implementation_root: Path) -> dict[str, Any]:
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
    entries.extend(_runtime_tool_entries())
    return _digest_entries(entries)


def _command_version(command: tuple[str, ...]) -> bytes:
    try:
        result = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
        )
        output = (result.stdout or result.stderr).strip()
        return f"rc={result.returncode}\n{output[:4096]}".encode("utf-8", "replace")
    except FileNotFoundError:
        return b"UNAVAILABLE"
    except subprocess.TimeoutExpired:
        return b"TIMEOUT"
    except Exception as exc:
        return f"ERROR:{type(exc).__name__}".encode("ascii", "replace")


def _runtime_tool_fingerprint(command: tuple[str, ...]) -> bytes:
    executable = shutil.which(command[0])
    executable_stat: tuple[int, int, int] | None = None
    if executable:
        try:
            info = Path(executable).resolve().stat()
            executable_stat = (
                info.st_size,
                info.st_mtime_ns,
                getattr(info, "st_ino", 0),
            )
        except OSError as exc:
            raise SnapshotInputError(
                f"runtime tool cannot be inspected: {command[0]}"
            ) from exc
    cache_key = (
        command,
        os.environ.get("PATH", ""),
        str(Path(executable).resolve()) if executable else None,
        executable_stat,
    )
    cached = _TOOL_FINGERPRINT_CACHE.get(cache_key)
    if cached is not None:
        return cached
    identity: dict[str, Any] = {
        "command": list(command),
        "resolved_executable": executable or "UNAVAILABLE",
        "version": _command_version(command).decode("utf-8", "replace"),
    }
    if executable:
        executable_path = Path(executable).resolve()
        try:
            digest, size = _hash_path(executable_path)
            identity.update(
                {
                    "executable_sha256": digest.hex(),
                    "executable_bytes": size,
                }
            )
        except SnapshotInputError as exc:
            # An installed but unreadable tool is not equivalent to an absent
            # tool; make the snapshot construction fail closed.
            raise SnapshotInputError(
                f"runtime tool cannot be content-bound: {command[0]}"
            ) from exc
    result = _canonical_json(identity)
    _TOOL_FINGERPRINT_CACHE[cache_key] = result
    return result


def _installed_python_packages() -> bytes:
    try:
        from importlib import metadata

        path_state: list[tuple[str, int, int]] = []
        for raw in sys.path:
            if not raw:
                continue
            path = Path(raw)
            try:
                info = path.stat()
            except OSError:
                continue
            path_state.append((str(path.resolve()), info.st_size, info.st_mtime_ns))
        cache_key = tuple(sorted(path_state))
        cached = _PYTHON_PACKAGE_CACHE.get(cache_key)
        if cached is not None:
            return cached

        packages = sorted(
            {
                (
                    (dist.metadata.get("Name") or "UNKNOWN").lower(),
                    dist.version,
                )
                for dist in metadata.distributions()
            }
        )
        result = _canonical_json(packages)
        _PYTHON_PACKAGE_CACHE[cache_key] = result
        return result
    except Exception as exc:
        raise SnapshotInputError("installed Python package state is unreadable") from exc


def _fixed_runtime_tool_entries() -> tuple[tuple[str, bytes], ...]:
    """Probe runtime/tool identity on every snapshot construction.

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
    commands = {
        "git": ("git", "--version"),
        "codex": ("codex", "--version"),
        "claude": ("claude", "--version"),
        "forge": ("forge", "--version"),
        "solc": ("solc", "--version"),
        "slither": ("slither", "--version"),
        "cargo": ("cargo", "--version"),
        "rustc": ("rustc", "--version"),
        "go": ("go", "version"),
        "aptos": ("aptos", "--version"),
        "sui": ("sui", "--version"),
        "stellar": ("stellar", "--version"),
        "damlc": ("damlc", "version"),
    }
    for name, command in commands.items():
        entries.append((f"@runtime/tool/{name}", _runtime_tool_fingerprint(command)))
    entries.append(("@runtime/python_packages", _installed_python_packages()))
    return tuple(entries)


def _runtime_tool_entries() -> list[tuple[str, bytes]]:
    """Bind OS, interpreter, tools, and audit-semantic environment knobs."""
    entries = list(_fixed_runtime_tool_entries())
    semantic_env = {
        key: value
        for key, value in os.environ.items()
        if key not in _OPERATIONAL_ENV_KEYS
        and any(key.startswith(prefix) for prefix in _SEMANTIC_ENV_PREFIXES)
    }
    entries.append(("@runtime/semantic_env", _canonical_json(semantic_env)))
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
        "toolchain": _toolchain_component(implementation_root),
    }
    binding = {
        "schema": SNAPSHOT_SCHEMA,
        "components": components,
    }
    binding["snapshot_digest"] = _sha256(_canonical_json(binding))
    return binding


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
        if not isinstance(component, dict) or set(component) != expected_keys[name]:
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
        return SnapshotVerdict(MISMATCH, changed)
    return SnapshotVerdict(MATCH)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True), encoding="utf-8"
    )
    os.replace(temporary, path)


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
