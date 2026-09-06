"""P2-A: isolated, content-bound fuzz execution workspaces.

The audit snapshot intentionally excludes mutable/generated fuzz products.  A
fuzzer therefore needs a second, narrower authority boundary before an LLM may
generate a harness or execute a tool.  This module builds that boundary without
using prose or model claims as authority:

* relevant build inputs are read once with TOCTOU checks and copied into a
  driver-owned workspace;
* pre-existing tests and fuzz harness/configuration are copied only into a
  quarantine tree and are absent from the runnable tree;
* generated harnesses and compiler outputs have explicit write lanes;
* every tool invocation goes through a shell-free recorder which binds the
  executable/version, argv, environment overrides, raw output and return code;
* finalization revalidates the original source denominator and the immutable
  workspace bytes.  Any ambiguity is visible UNSCORED debt, never safety proof.

The module is deliberately driver-independent so its receipts can be replayed
and adversarially validated without launching an LLM.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence
import uuid

from owned_process_scope import (
    OwnedProcessScope,
    OwnedProcessScopeError,
    process_tree_termination_capability,
)


AUTHORITY_SCHEMA = "plamen.fuzz-workspace-authority.v1"
DEBT_SCHEMA = "plamen.fuzz-workspace-debt.v1"
COMMAND_SCHEMA = "plamen.fuzz-command-receipt.v1"
RESULT_SCHEMA = "plamen.fuzz-workspace-result.v1"
COMMAND_WITNESS_SCHEMA = "plamen.fuzz-command-runner-witness.v1"
PREPARED_CAMPAIGN_SCHEMA = "plamen.fuzz-prepared-campaign.v1"
SECURE_LAUNCHER_SCHEMA = "plamen.secure-fuzz-launcher-receipt.v1"
WORKSPACE_INDEX_SCHEMA = "plamen.fuzz-workspace-index.v1"
RESULT_INDEX_SCHEMA = "plamen.fuzz-workspace-result-index.v1"

WORKSPACE_INDEX_FILE = "fuzz_workspace_index.json"
RESULT_INDEX_FILE = "fuzz_workspace_result_index.json"

WORKSPACES_DIR = "_fuzz_workspaces"
DEFAULT_MAX_FILES = 30_000
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_COMMAND_LOG_BYTES = 128 * 1024 * 1024
MAX_VERSION_OUTPUT_BYTES = 16 * 1024
MAX_CONTROL_JSON_BYTES = 16 * 1024 * 1024
MAX_INDEX_ROWS = 128
MAX_INDEX_ISSUES_PER_ROW = 256

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_JOB_TOKEN_RE = re.compile(r"[^a-z0-9_.-]+")
_TEST_FILE_RE = re.compile(
    r"(?:^test[_-]|[_-]test\.(?:rs|go|move)$|\.t\.sol$|"
    r"\.(?:test|spec)\.(?:js|cjs|mjs|ts)$|^(?:fuzz|invariant)[_-])",
    re.IGNORECASE,
)
_FUZZ_CONFIG_RE = re.compile(
    r"^(?:medusa(?:\.[^.]+)?|echidna(?:\.[^.]+)?|trident(?:\.[^.]+)?)"
    r"\.(?:json|ya?ml|toml)$",
    re.IGNORECASE,
)

_TEST_DIR_NAMES = frozenset({
    "test", "tests", "fuzz", "fuzzing", "fuzzers", "trident-tests",
    ".medusa-tests", ".echidna-tests",
})
_SKIP_DIR_NAMES = frozenset({
    ".git", ".hg", ".svn", ".scratchpad", ".plamen", "__pycache__",
    "artifacts", "cache", "coverage", "dist", "node_modules", "out",
    "target", "build", "corpus", "crytic-export", WORKSPACES_DIR,
})
_SKIP_DIR_PREFIXES = (".scratchpad", ".plamen-stale-snapshots")


def _is_generated_control_directory(name: str) -> bool:
    folded = str(name).casefold()
    return (
        folded in {item.casefold() for item in _SKIP_DIR_NAMES}
        or folded.startswith(_SKIP_DIR_PREFIXES)
    )
_SOURCE_SUFFIXES = frozenset({
    ".sol", ".vy", ".rs", ".move", ".go", ".proto", ".daml",
    ".c", ".cc", ".cpp", ".h", ".hpp",
})
_RELEVANT_SUFFIXES = _SOURCE_SUFFIXES | frozenset({
    ".toml", ".lock", ".json", ".yaml", ".yml", ".txt",
    ".js", ".cjs", ".mjs", ".ts", ".sh", ".ps1", ".bat", ".cmd",
})
_CONFIG_NAMES = frozenset({
    ".gitmodules", "Anchor.toml", "Cargo.lock", "Cargo.toml", "Move.lock",
    "Move.toml", "Scarb.lock", "Scarb.toml", "foundry.toml", "go.mod",
    "go.sum", "go.work", "go.work.sum", "hardhat.config.js",
    "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts",
    "package-lock.json", "package.json", "pnpm-lock.yaml", "remappings.txt",
    "rust-toolchain", "rust-toolchain.toml", "sui.genesis.yaml", "yarn.lock",
})
_VERSION_ARGS: dict[str, tuple[str, ...]] = {
    "forge": ("--version",),
    "medusa": ("--version",),
    "cargo": ("--version",),
    "trident": ("--version",),
    "sui": ("--version",),
    "go": ("version",),
    "python": ("--version",),
    "python3": ("--version",),
    "python.exe": ("--version",),
}
_DEFAULT_ALLOWED_TOOLS: dict[tuple[str, str], tuple[str, ...]] = {
    ("evm", "invariant_fuzz"): ("forge",),
    ("evm", "medusa_fuzz"): ("forge", "medusa"),
    ("solana", "invariant_fuzz"): ("trident", "cargo"),
    ("soroban", "invariant_fuzz"): ("cargo",),
    ("sui", "invariant_fuzz"): ("sui",),
}
_GENERATED_ROOTS: dict[tuple[str, str], tuple[str, ...]] = {
    ("evm", "invariant_fuzz"): (".plamen-generated", "test/invariant"),
    ("evm", "medusa_fuzz"): (".plamen-generated", ".medusa-tests"),
    ("solana", "invariant_fuzz"): (
        ".plamen-generated", "Trident.toml", "trident-tests",
    ),
    ("soroban", "invariant_fuzz"): (".plamen-generated", "fuzz", "tests"),
    ("sui", "invariant_fuzz"): (".plamen-generated", "tests"),
}
_TOOL_OUTPUT_ROOTS = (
    ".plamen-tool-output", "out", "cache", "target", "build",
    ".fuzz-artifacts", ".anchor", ".trident", "test-ledger", "Move.lock",
)
_GENERATED_RUNTIME_COMPONENTS = frozenset({
    ".anchor", ".fuzz-artifacts", ".trident", "artifacts", "build",
    "cache", "corpus", "coverage", "out", "target", "test-ledger",
})
_SEMANTIC_ENV_PREFIXES = (
    "ANCHOR_", "CARGO_", "FOUNDRY_", "OPENSSL_", "PLAMEN_", "RUST",
    "SOLANA_", "SUI_", "TRIDENT_",
)
_SEMANTIC_ENV_NAMES = frozenset({"PATH", "PATHEXT", "RUSTFLAGS"})
_RUNNER_INTEGRITY_DEBT_CODES = frozenset({
    "AUTHORITY_DIGEST_INVALID", "AUTHORITY_PATH_ESCAPE",
    "AUTHORITY_SCHEMA_INVALID", "AUTHORITY_STATUS_INVALID",
    "AUTHORITY_VALIDATION_FAILED", "COMMAND_CWD_ESCAPE",
    "COMMAND_CWD_MISSING", "COMMAND_CWD_NOT_GENERATED", "COMMAND_INVALID",
    "COMMAND_PATH_ESCAPE", "COMMAND_PROVENANCE_UNAUTHENTICATED",
    "COMMAND_RECORDING_FAILED",
    "COMMAND_TIMEOUT_INVALID", "PORTABLE_PATH_COLLISION",
    "QUARANTINE_DIRTY", "SOURCE_DENOMINATOR_DRIFT", "SOURCE_READ_FAILED",
    "SOURCE_SNAPSHOT_DIGEST_INVALID", "SOURCE_SNAPSHOT_UNBOUND",
    "SOURCE_STAT_FAILED", "SOURCE_TOCTOU", "UNAPPROVED_TOOL",
    "INHERITED_ENVIRONMENT_UNSAFE", "PROCESS_CONTAINMENT_UNAVAILABLE",
    "PREEXISTING_HARNESS_PROVENANCE", "UNSAFE_LINK_OR_REPARSE",
    "WORKSPACE_INPUT_DRIFT",
    "WORKSPACE_INPUT_MISSING", "WRITE_OUTSIDE_GENERATED_LANE",
})

_NONEXECUTING_FLAGS = frozenset({
    "--help", "-h", "--list", "--list-tests", "--no-run", "--version",
})
_SAFE_INHERITED_ENV_NAMES = frozenset({
    "COMSPEC", "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT",
    "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR",
})


class FuzzWorkspaceError(RuntimeError):
    """A deterministic workspace boundary could not be established."""

    def __init__(self, code: str, message: str) -> None:
        self.code = str(code).strip().upper() or "FUZZ_WORKSPACE_ERROR"
        self.message = str(message).strip() or self.code
        super().__init__(f"{self.code}: {self.message}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def payload_digest(payload: Mapping[str, object]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "payload_digest"}
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def record_set_digest(records: Iterable[Mapping[str, object]]) -> str:
    normalized = [dict(row) for row in records]
    return hashlib.sha256(_canonical_json(normalized)).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with _filesystem_io_path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _assert_existing_path_chain_no_links(path.parent, Path(path.parent.anchor))
    data = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=str(path.parent),
        prefix=".plamen-", suffix=".tmp", delete=False,
    ) as stream:
        stream.write(data)
        temporary = Path(stream.name)
    os.replace(temporary, path)


def _is_descendant_or_equal(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _is_lexical_descendant_or_equal(path: Path, root: Path) -> bool:
    """Compare absolute spellings without following links/reparse points."""

    try:
        path_s = os.path.normcase(os.path.abspath(os.fspath(path)))
        root_s = os.path.normcase(os.path.abspath(os.fspath(root)))
        return os.path.commonpath((path_s, root_s)) == root_s
    except (OSError, ValueError):
        return False


def _filesystem_io_path(path: Path) -> Path:
    """Use Win32's extended namespace only for paths at MAX_PATH risk."""

    path = Path(path)
    if os.name != "nt":
        return path
    raw = os.path.abspath(os.fspath(path))
    if raw.startswith("\\\\?\\"):
        return Path(raw)
    if len(raw) < 248:
        return path
    if raw.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + raw[2:])
    return Path("\\\\?\\" + raw)


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = _filesystem_io_path(path).lstat()
    except OSError as exc:
        raise FuzzWorkspaceError("SOURCE_STAT_FAILED", f"{path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def _assert_existing_path_chain_no_links(path: Path, anchor: Path) -> None:
    """Reject links/reparse points in every existing component below ``anchor``.

    ``resolve`` is intentionally not used to establish authority: resolving a
    driver-owned path through a pre-positioned junction would bless the escape.
    """

    lexical_path = Path(os.path.abspath(os.fspath(path)))
    lexical_anchor = Path(os.path.abspath(os.fspath(anchor)))
    if not _is_lexical_descendant_or_equal(lexical_path, lexical_anchor):
        raise FuzzWorkspaceError("AUTHORITY_PATH_ESCAPE", str(path))
    relative = lexical_path.relative_to(lexical_anchor)
    current = lexical_anchor
    if current.exists() and _is_link_or_reparse(current):
        raise FuzzWorkspaceError("UNSAFE_LINK_OR_REPARSE", str(current))
    for part in relative.parts:
        current = current / part
        if not current.exists():
            break
        if _is_link_or_reparse(current):
            raise FuzzWorkspaceError("UNSAFE_LINK_OR_REPARSE", str(current))


def _stable_signature(info: os.stat_result) -> tuple[object, ...]:
    # Windows exposes creation time through ``st_ctime`` and rounds it
    # differently between ``stat(path)`` and ``fstat(fd)`` on some filesystems.
    # Device/inode/mode/size/mtime are stable across both APIs and still detect
    # replacement, truncation and byte mutation without false TOCTOU debt.
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_size,
        info.st_mtime_ns,
    )


def _stable_read(path: Path, *, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> bytes:
    """Read one regular file once and reject link/identity/content races."""

    if _is_link_or_reparse(path):
        raise FuzzWorkspaceError(
            "UNSAFE_LINK_OR_REPARSE", f"relevant input is a link/reparse point: {path}"
        )
    try:
        io_path = _filesystem_io_path(path)
        before = io_path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise FuzzWorkspaceError("NON_REGULAR_INPUT", str(path))
        if before.st_size > max_file_bytes:
            raise FuzzWorkspaceError(
                "INPUT_FILE_BYTE_LIMIT",
                f"{path} is {before.st_size} bytes (limit {max_file_bytes})",
            )
        with io_path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            data = stream.read(max_file_bytes + 1)
            after_open = os.fstat(stream.fileno())
        after_path = io_path.stat()
    except FuzzWorkspaceError:
        raise
    except OSError as exc:
        raise FuzzWorkspaceError("SOURCE_READ_FAILED", f"{path}: {exc}") from exc
    if len(data) > max_file_bytes:
        raise FuzzWorkspaceError("INPUT_FILE_BYTE_LIMIT", str(path))
    expected = _stable_signature(before)
    if not (
        expected == _stable_signature(opened)
        == _stable_signature(after_open) == _stable_signature(after_path)
        and len(data) == before.st_size
    ):
        raise FuzzWorkspaceError("SOURCE_TOCTOU", f"input changed during read: {path}")
    return data


def _path_key(relative: str) -> str:
    # A denominator that is safe on Linux but aliases on Windows is not a
    # portable workspace denominator.  Reject case-only collisions everywhere.
    return relative.replace("\\", "/").casefold()


def _is_test_or_harness(relative: Path) -> bool:
    parts = tuple(part.casefold() for part in relative.parts[:-1])
    name = relative.name
    if any(part in _TEST_DIR_NAMES for part in parts):
        return True
    if _TEST_FILE_RE.search(name):
        return True
    if _FUZZ_CONFIG_RE.match(name):
        return True
    return name.casefold() in {
        "medusa.json", "medusa.yaml", "medusa.yml", "echidna.yaml",
        "echidna.yml",
    }


def _classify_input(relative: Path) -> str | None:
    name = relative.name
    suffix = relative.suffix.casefold()
    if _is_test_or_harness(relative):
        return "test"
    if name in _CONFIG_NAMES or name.casefold() in {
        item.casefold() for item in _CONFIG_NAMES
    }:
        return "configuration"
    if suffix in _SOURCE_SUFFIXES:
        return "source"
    if suffix in _RELEVANT_SUFFIXES or name in {"Makefile", "Justfile"}:
        return "dependency"
    return None


def _evm_remapping_dependency_roots(source_root: Path) -> tuple[Path, ...]:
    """Return only explicitly remapped ``node_modules`` dependency roots.

    Copying an entire JavaScript installation would add executable tooling and
    an enormous mutable surface to a fuzz workspace.  Foundry nevertheless
    needs Solidity libraries that some hybrid projects map from node_modules.
    Bind exactly the lexical roots named by remappings.txt; nested
    node_modules remain excluded by the ordinary skip policy.
    """

    remappings = source_root / "remappings.txt"
    try:
        lines = remappings.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError):
        return ()
    node_root = source_root / "node_modules"
    roots: set[Path] = set()
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        _prefix, destination = line.split("=", 1)
        destination = destination.strip().replace("\\", "/").lstrip("./")
        if not destination.startswith("node_modules/"):
            continue
        relative = Path(destination.rstrip("/"))
        candidate = source_root / relative
        try:
            candidate.relative_to(node_root)
        except ValueError:
            continue
        if candidate.is_dir():
            roots.add(candidate.resolve(strict=True))
    return tuple(sorted(roots, key=lambda path: str(path).casefold()))


def _input_rows(
    source_root: Path,
    *,
    excluded_root: Path,
    max_files: int,
    max_total_bytes: int,
    max_file_bytes: int,
) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    source_root = source_root.resolve(strict=True)
    excluded_root = excluded_root.resolve(strict=False)
    rows: list[dict[str, object]] = []
    blobs: dict[str, bytes] = {}
    keys: dict[str, str] = {}
    total = 0
    remapped_dependency_roots = _evm_remapping_dependency_roots(source_root)
    node_modules_root = source_root / "node_modules"

    def remapped_traversal_path(path: Path) -> bool:
        try:
            candidate = path.resolve(strict=False)
        except OSError:
            return False
        return any(
            candidate == root
            or _is_lexical_descendant_or_equal(candidate, root)
            or _is_lexical_descendant_or_equal(root, candidate)
            for root in remapped_dependency_roots
        )

    for dirpath, dirnames, filenames in os.walk(source_root, followlinks=False):
        directory = Path(dirpath)
        retained: list[str] = []
        for name in sorted(dirnames):
            child = directory / name
            # Exclude only the actual driver-owned scratchpad spelling.  A
            # differently named symlink/reparse point resolving into it must be
            # rejected below, not silently treated as the excluded tree.
            if _is_lexical_descendant_or_equal(child, excluded_root):
                continue
            is_top_node_modules = child == node_modules_root
            if is_top_node_modules and remapped_dependency_roots:
                pass
            elif _is_generated_control_directory(name):
                continue
            if (
                _is_lexical_descendant_or_equal(child, node_modules_root)
                and not remapped_traversal_path(child)
            ):
                continue
            if _is_link_or_reparse(child):
                raise FuzzWorkspaceError(
                    "UNSAFE_LINK_OR_REPARSE", f"directory: {child}"
                )
            retained.append(name)
        dirnames[:] = retained

        for name in sorted(filenames):
            path = directory / name
            relative_path = path.relative_to(source_root)
            if (
                _is_lexical_descendant_or_equal(path, node_modules_root)
                and path.suffix.casefold() != ".sol"
            ):
                continue
            category = _classify_input(relative_path)
            if category is None:
                continue
            if _is_link_or_reparse(path):
                raise FuzzWorkspaceError(
                    "UNSAFE_LINK_OR_REPARSE", f"file: {path}"
                )
            relative = relative_path.as_posix()
            key = _path_key(relative)
            if key in keys:
                raise FuzzWorkspaceError(
                    "PORTABLE_PATH_COLLISION",
                    f"{keys[key]!r} aliases {relative!r}",
                )
            keys[key] = relative
            if len(rows) + 1 > max_files:
                raise FuzzWorkspaceError(
                    "INPUT_FILE_COUNT_LIMIT", f"more than {max_files} relevant files"
                )
            data = _stable_read(path, max_file_bytes=max_file_bytes)
            total += len(data)
            if total > max_total_bytes:
                raise FuzzWorkspaceError(
                    "INPUT_BYTE_LIMIT",
                    f"relevant inputs exceed {max_total_bytes} bytes",
                )
            disposition = "QUARANTINED" if category == "test" else "ACTIVE"
            row = {
                "relative_path": relative,
                "category": category,
                "disposition": disposition,
                "size": len(data),
                "sha256": _sha256_bytes(data),
            }
            rows.append(row)
            blobs[relative] = data
    rows.sort(key=lambda row: str(row["relative_path"]))
    return rows, blobs


def _denominators(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for category in ("source", "configuration", "test", "dependency"):
        selected = [dict(row) for row in rows if row.get("category") == category]
        result[category] = {
            "count": len(selected),
            "bytes": sum(int(row["size"]) for row in selected),
            "set_digest": record_set_digest(selected),
        }
    result["all"] = {
        "count": len(rows),
        "bytes": sum(int(row["size"]) for row in rows),
        "set_digest": record_set_digest(rows),
    }
    return result


def _job_slug(job_id: str, language: str, role: str, run_id: str) -> str:
    token = _JOB_TOKEN_RE.sub("-", str(job_id).strip().casefold()).strip("-._")
    token = (token or "fuzz")[:48]
    identity = "\0".join((run_id, language, role, job_id))
    return f"{token}-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:12]}"


def _issue(code: str, detail: str) -> dict[str, str]:
    return {"code": str(code).strip().upper(), "detail": str(detail).strip()}


def _normalize_issues(issues: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
    unique = {
        (str(row.get("code") or "FUZZ_WORKSPACE_ERROR").strip().upper(),
         str(row.get("detail") or "").strip())
        for row in issues
    }
    return [
        {"code": code, "detail": detail}
        for code, detail in sorted(unique)
    ]


def _debt_payload(
    *, run_id: str, job_id: str, authority_digest: str, issues: Iterable[Mapping[str, object]]
) -> dict[str, object]:
    normalized = _normalize_issues(issues)
    payload: dict[str, object] = {
        "schema_version": DEBT_SCHEMA,
        "run_id": run_id,
        "job_id": job_id,
        "status": "CLEAR" if not normalized else "UNSCORED",
        "authority_digest": authority_digest,
        "issues": normalized,
    }
    payload["payload_digest"] = payload_digest(payload)
    return payload


def _write_debt(
    path: Path, *, run_id: str, job_id: str, authority_digest: str,
    issues: Iterable[Mapping[str, object]], monotonic: bool = True,
) -> dict[str, object]:
    combined: list[Mapping[str, object]] = list(issues)
    if monotonic and path.is_file():
        try:
            prior = _read_json(path)
            if prior.get("schema_version") != DEBT_SCHEMA:
                raise ValueError("schema")
            if prior.get("payload_digest") != payload_digest(prior):
                raise ValueError("digest")
            same_identity = (
                prior.get("run_id") == run_id
                and prior.get("job_id") == job_id
                and prior.get("authority_digest") in {"", authority_digest}
            )
            if same_identity and isinstance(prior.get("issues"), list):
                combined.extend(
                    row for row in prior["issues"] if isinstance(row, dict)
                )
        except Exception as exc:
            combined.append(_issue(
                "DEBT_RECEIPT_INVALID",
                f"existing debt was not authenticated: {type(exc).__name__}: {exc}",
            ))
    payload = _debt_payload(
        run_id=run_id, job_id=job_id, authority_digest=authority_digest,
        issues=combined,
    )
    _atomic_json(path, payload)
    return payload


def _safe_remove_driver_staging(path: Path, workspace_parent: Path) -> None:
    try:
        resolved = path.resolve(strict=False)
        parent = workspace_parent.resolve(strict=False)
        if resolved.parent != parent or not resolved.name.startswith("."):
            return
        if path.exists():
            shutil.rmtree(path)
    except OSError:
        pass


def _read_json(path: Path) -> dict[str, object]:
    def reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite number: {value}")

    try:
        raw = _stable_read(Path(path), max_file_bytes=MAX_CONTROL_JSON_BYTES)
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except Exception as exc:
        raise FuzzWorkspaceError(
            "AUTHORITY_UNREADABLE", f"{path}: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise FuzzWorkspaceError("AUTHORITY_INVALID", "root must be an object")
    return payload


def _readonly(path: Path) -> None:
    try:
        _filesystem_io_path(path).chmod(
            stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH
        )
    except OSError:
        pass


def materialize_fuzz_workspace(
    *,
    scratchpad: Path,
    build_root: Path,
    project_root: Path,
    job_id: str,
    language: str,
    role: str,
    run_id: str,
    source_snapshot_digest: str,
    allowed_tools: Sequence[str] | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> dict[str, object]:
    """Materialize or validate one deterministic driver-owned fuzz workspace.

    Failure is returned as an ``UNSCORED`` payload and written to a durable debt
    sidecar.  No partial runnable tree is ever published.
    """

    scratchpad_raw = Path(os.path.abspath(os.fspath(scratchpad)))
    build_root_raw = Path(os.path.abspath(os.fspath(build_root)))
    project_root_raw = Path(os.path.abspath(os.fspath(project_root)))
    for root in (scratchpad_raw, build_root_raw, project_root_raw):
        _assert_existing_path_chain_no_links(root, Path(root.anchor))
    scratchpad = scratchpad_raw.resolve(strict=True)
    build_root = build_root_raw.resolve(strict=True)
    project_root = project_root_raw.resolve(strict=True)
    language_n = str(language).strip().casefold()
    role_n = str(role).strip().casefold()
    run_id_n = str(run_id).strip() or "UNBOUND"
    job_id_n = str(job_id).strip() or "fuzz"
    if not build_root.is_dir() or not project_root.is_dir():
        raise FuzzWorkspaceError("BUILD_ROOT_INVALID", str(build_root))
    if not _HEX64_RE.match(str(source_snapshot_digest).strip().casefold()):
        raise FuzzWorkspaceError("SOURCE_SNAPSHOT_DIGEST_INVALID", source_snapshot_digest)
    if max_files < 1 or max_total_bytes < 1 or max_file_bytes < 1:
        raise FuzzWorkspaceError("WORKSPACE_LIMIT_INVALID", "limits must be positive")

    slug = _job_slug(job_id_n, language_n, role_n, run_id_n)
    workspace_parent = scratchpad / WORKSPACES_DIR
    workspace_root = workspace_parent / slug
    active_root = workspace_root / "active"
    quarantine_root = workspace_root / "quarantine"
    generated_root = active_root / ".plamen-generated"
    runtime_root = workspace_root / "runtime"
    authority_path = workspace_root / "fuzz_workspace_authority.json"
    result_path = workspace_root / "fuzz_workspace_result.json"
    debt_path = scratchpad / f"fuzz_workspace_{slug}_debt.json"

    base_return: dict[str, object] = {
        "schema_version": AUTHORITY_SCHEMA,
        "status": "UNSCORED",
        "job_id": job_id_n,
        "run_id": run_id_n,
        "scratchpad_root": str(scratchpad),
        "project_root": str(project_root),
        "source_root": str(build_root),
        "workspace_root": str(workspace_root),
        "active_root": str(active_root),
        "quarantine_root": str(quarantine_root),
        "generated_root": str(generated_root),
        "runtime_root": str(runtime_root),
        "authority_path": str(authority_path),
        "result_path": str(result_path),
        "debt_path": str(debt_path),
    }

    try:
        _assert_existing_path_chain_no_links(workspace_parent, scratchpad)
    except FuzzWorkspaceError as exc:
        issue = _issue(exc.code, exc.message)
        _write_debt(
            debt_path, run_id=run_id_n, job_id=job_id_n,
            authority_digest="", issues=[issue],
        )
        return {**base_return, "issues": [issue]}

    if authority_path.is_file():
        try:
            payload = _read_json(authority_path)
            identity_matches = all((
                payload.get("run_id") == run_id_n,
                payload.get("job_id") == job_id_n,
                payload.get("language") == language_n,
                payload.get("role") == role_n,
                payload.get("source_snapshot_digest")
                == str(source_snapshot_digest).casefold(),
                payload.get("source_root") == str(build_root),
                payload.get("project_root") == str(project_root),
            ))
            issues = validate_fuzz_workspace_authority(
                authority_path, check_source=True
            ) if identity_matches else ["WORKSPACE_IDENTITY_DRIFT: identity changed"]
            if not issues:
                _write_debt(
                    debt_path, run_id=run_id_n, job_id=job_id_n,
                    authority_digest=str(payload.get("payload_digest") or ""),
                    issues=[],
                )
                return payload
            normalized = []
            for item in issues:
                code, _, detail = str(item).partition(":")
                normalized.append(_issue(code, detail.strip() or item))
            _write_debt(
                debt_path, run_id=run_id_n, job_id=job_id_n,
                authority_digest=str(payload.get("payload_digest") or ""),
                issues=normalized,
            )
            return {**base_return, "issues": normalized}
        except FuzzWorkspaceError as exc:
            issue = _issue(exc.code, exc.message)
            _write_debt(
                debt_path, run_id=run_id_n, job_id=job_id_n,
                authority_digest="", issues=[issue],
            )
            return {**base_return, "issues": [issue]}
    if workspace_root.exists():
        issue = _issue("DIRTY_WORKSPACE", "workspace exists without valid authority")
        _write_debt(
            debt_path, run_id=run_id_n, job_id=job_id_n,
            authority_digest="", issues=[issue],
        )
        return {**base_return, "issues": [issue]}

    staging = workspace_parent / f".{slug}.{uuid.uuid4().hex}.staging"
    try:
        rows, blobs = _input_rows(
            build_root,
            excluded_root=scratchpad,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_file_bytes=max_file_bytes,
        )
        workspace_parent.mkdir(parents=True, exist_ok=True)
        _assert_existing_path_chain_no_links(workspace_parent, scratchpad)
        (staging / "active").mkdir(parents=True)
        (staging / "quarantine").mkdir(parents=True)
        (staging / "active" / ".plamen-generated").mkdir(parents=True)
        (staging / "runtime" / "commands").mkdir(parents=True)
        (staging / "runtime" / "tool-output").mkdir(parents=True)
        for row in rows:
            relative = str(row["relative_path"])
            destination_root = (
                staging / "quarantine"
                if row["disposition"] == "QUARANTINED"
                else staging / "active"
            )
            destination = destination_root / Path(relative)
            destination_io = _filesystem_io_path(destination)
            destination_io.parent.mkdir(parents=True, exist_ok=True)
            data = blobs[relative]
            destination_io.write_bytes(data)
            if _sha256_file(destination) != (row["sha256"], row["size"]):
                raise FuzzWorkspaceError(
                    "MATERIALIZATION_COPY_DRIFT", relative
                )
            _readonly(destination)

        generated_roots = list(
            _GENERATED_ROOTS.get((language_n, role_n), (".plamen-generated",))
        )
        if ".plamen-generated" not in generated_roots:
            generated_roots.insert(0, ".plamen-generated")
        selected_tools = tuple(allowed_tools or _DEFAULT_ALLOWED_TOOLS.get(
            (language_n, role_n), ()
        ))
        selected_tools = tuple(sorted({
            Path(str(name)).name.casefold() for name in selected_tools if str(name).strip()
        }))
        payload: dict[str, object] = {
            "schema_version": AUTHORITY_SCHEMA,
            "status": "READY",
            "run_id": run_id_n,
            "job_id": job_id_n,
            "language": language_n,
            "role": role_n,
            "source_snapshot_digest": str(source_snapshot_digest).casefold(),
            "created_at": _utc_now(),
            "scratchpad_root": str(scratchpad),
            "project_root": str(project_root),
            "source_root": str(build_root),
            "workspace_root": str(workspace_root),
            "active_root": str(active_root),
            "quarantine_root": str(quarantine_root),
            "generated_root": str(generated_root),
            "runtime_root": str(runtime_root),
            "authority_path": str(authority_path),
            "result_path": str(result_path),
            "debt_path": str(debt_path),
            "limits": {
                "max_files": int(max_files),
                "max_total_bytes": int(max_total_bytes),
                "max_file_bytes": int(max_file_bytes),
                "max_command_log_bytes": MAX_COMMAND_LOG_BYTES,
            },
            "inputs": rows,
            "denominators": _denominators(rows),
            "allowed_tools": list(selected_tools),
            "generated_write_roots": sorted(set(generated_roots)),
            "tool_output_roots": list(_TOOL_OUTPUT_ROOTS),
            "execution_policy": {
                "pre_existing_tests": "QUARANTINED_READONLY_CONTEXT_NOT_EXECUTABLE_OR_CLONABLE",
                "pre_existing_fuzz_configuration": "QUARANTINED_READONLY_CONTEXT_NOT_EXECUTABLE_OR_CLONABLE",
                "project_root_write_authority": "NONE",
                "workspace_source_mutation_authority": "NONE",
                "tool_invocation_authority": "RECORDED_RUNNER_ONLY",
                "campaign_invocation_authority": "DRIVER_PREPARED_SECURE_LAUNCHER_ONLY",
                "model_result_authority": "CANDIDATE_ONLY",
            },
        }
        payload["payload_digest"] = payload_digest(payload)
        staging_authority = staging / authority_path.name
        _atomic_json(staging_authority, payload)
        os.replace(staging, workspace_root)
        _readonly(authority_path)
        _write_debt(
            debt_path, run_id=run_id_n, job_id=job_id_n,
            authority_digest=str(payload["payload_digest"]), issues=[],
        )
        return payload
    except FuzzWorkspaceError as exc:
        _safe_remove_driver_staging(staging, workspace_parent)
        issue = _issue(exc.code, exc.message)
        _write_debt(
            debt_path, run_id=run_id_n, job_id=job_id_n,
            authority_digest="", issues=[issue],
        )
        return {**base_return, "issues": [issue]}
    except Exception as exc:
        _safe_remove_driver_staging(staging, workspace_parent)
        issue = _issue(
            "WORKSPACE_MATERIALIZATION_FAILED", f"{type(exc).__name__}: {exc}"
        )
        _write_debt(
            debt_path, run_id=run_id_n, job_id=job_id_n,
            authority_digest="", issues=[issue],
        )
        return {**base_return, "issues": [issue]}


def _expected_record_file(authority: Mapping[str, object], row: Mapping[str, object]) -> Path:
    root = Path(str(
        authority["quarantine_root"]
        if row.get("disposition") == "QUARANTINED"
        else authority["active_root"]
    ))
    relative = Path(str(row["relative_path"]))
    target = root / relative
    if not _is_descendant_or_equal(target, root):
        raise FuzzWorkspaceError("AUTHORITY_PATH_ESCAPE", str(relative))
    return target


def _scan_tree_files(root: Path, *, max_files: int, max_bytes: int) -> list[Path]:
    found: list[Path] = []
    total = 0
    if not root.is_dir():
        return found
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directory = Path(dirpath)
        retained: list[str] = []
        for name in sorted(dirnames):
            child = directory / name
            if _is_link_or_reparse(child):
                raise FuzzWorkspaceError("UNSAFE_LINK_OR_REPARSE", str(child))
            retained.append(name)
        dirnames[:] = retained
        for name in sorted(filenames):
            path = directory / name
            if _is_link_or_reparse(path):
                raise FuzzWorkspaceError("UNSAFE_LINK_OR_REPARSE", str(path))
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise FuzzWorkspaceError("NON_REGULAR_WORKSPACE_FILE", str(path))
            found.append(path)
            total += info.st_size
            if len(found) > max_files:
                raise FuzzWorkspaceError("WORKSPACE_FILE_COUNT_LIMIT", str(max_files))
            if total > max_bytes:
                raise FuzzWorkspaceError("WORKSPACE_BYTE_LIMIT", str(max_bytes))
    return found


def _under_relative_root(relative: str, roots: Sequence[str]) -> bool:
    rel = Path(relative)
    for root_s in roots:
        root = Path(str(root_s))
        try:
            rel.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _validate_authority_shape(payload: Mapping[str, object]) -> list[str]:
    issues: list[str] = []
    if payload.get("schema_version") != AUTHORITY_SCHEMA:
        issues.append("AUTHORITY_SCHEMA_INVALID: schema mismatch")
    if payload.get("status") != "READY":
        issues.append("AUTHORITY_STATUS_INVALID: not READY")
    if payload.get("payload_digest") != payload_digest(payload):
        issues.append("AUTHORITY_DIGEST_INVALID: payload digest mismatch")
    if not _HEX64_RE.match(str(payload.get("source_snapshot_digest") or "")):
        issues.append("SOURCE_SNAPSHOT_DIGEST_INVALID: malformed")
    elif str(payload.get("source_snapshot_digest")) == "0" * 64:
        issues.append("SOURCE_SNAPSHOT_UNBOUND: audit snapshot digest is absent")
    if not isinstance(payload.get("inputs"), list):
        issues.append("AUTHORITY_INPUTS_INVALID: inputs must be a list")
        return issues
    rows = payload["inputs"]
    allowed_row_keys = {
        "relative_path", "category", "disposition", "size", "sha256",
    }
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != allowed_row_keys:
            issues.append(f"AUTHORITY_INPUTS_INVALID: row {index} shape")
            continue
        relative = str(row.get("relative_path") or "")
        relative_path = Path(relative.replace("\\", "/"))
        category = row.get("category")
        disposition = row.get("disposition")
        size = row.get("size")
        if (
            not relative or relative_path.is_absolute()
            or ".." in relative_path.parts or "\\" in relative
        ):
            issues.append(f"AUTHORITY_PATH_ESCAPE: row {index}")
        if category not in {"source", "configuration", "test", "dependency"}:
            issues.append(f"AUTHORITY_INPUTS_INVALID: row {index} category")
        if disposition not in {"ACTIVE", "QUARANTINED"}:
            issues.append(f"AUTHORITY_INPUTS_INVALID: row {index} disposition")
        if (category == "test") != (disposition == "QUARANTINED"):
            issues.append(f"AUTHORITY_INPUTS_INVALID: row {index} classification")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            issues.append(f"AUTHORITY_INPUTS_INVALID: row {index} size")
        if not _HEX64_RE.fullmatch(str(row.get("sha256") or "")):
            issues.append(f"AUTHORITY_INPUTS_INVALID: row {index} digest")
    if issues:
        return sorted(set(issues))
    relatives = [str(row.get("relative_path") or "") for row in rows if isinstance(row, dict)]
    if len(relatives) != len(rows) or relatives != sorted(relatives):
        issues.append("AUTHORITY_INPUT_ORDER_INVALID: denominator is not sorted")
    if len({_path_key(item) for item in relatives}) != len(relatives):
        issues.append("PORTABLE_PATH_COLLISION: authority aliases paths")
    if payload.get("denominators") != _denominators(
        [row for row in rows if isinstance(row, dict)]
    ):
        issues.append("AUTHORITY_DENOMINATOR_INVALID: digest/count mismatch")
    limits = payload.get("limits")
    if not isinstance(limits, dict) or any(
        not isinstance(limits.get(name), int)
        or isinstance(limits.get(name), bool)
        or int(limits.get(name)) < 1
        for name in (
            "max_files", "max_total_bytes", "max_file_bytes",
            "max_command_log_bytes",
        )
    ):
        issues.append("AUTHORITY_LIMITS_INVALID: positive exact integers required")
    for field in ("allowed_tools", "generated_write_roots", "tool_output_roots"):
        value = payload.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            issues.append(f"AUTHORITY_{field.upper()}_INVALID: string list required")
    for field in ("generated_write_roots", "tool_output_roots"):
        for item in payload.get(field, []) if isinstance(payload.get(field), list) else []:
            candidate = Path(str(item).replace("\\", "/"))
            if candidate.is_absolute() or ".." in candidate.parts:
                issues.append(f"AUTHORITY_{field.upper()}_INVALID: path escape")
    return issues


def validate_fuzz_workspace_authority(
    authority_path: Path, *, check_source: bool = True
) -> list[str]:
    """Side-effect-free validation of source, quarantine and active bytes."""

    try:
        payload = _read_json(Path(authority_path))
    except FuzzWorkspaceError as exc:
        return [f"{exc.code}: {exc.message}"]
    issues = _validate_authority_shape(payload)
    if issues:
        return sorted(set(issues))
    try:
        scratchpad_raw = Path(os.path.abspath(str(payload["scratchpad_root"])))
        workspace_raw = Path(os.path.abspath(str(payload["workspace_root"])))
        active_raw = Path(os.path.abspath(str(payload["active_root"])))
        quarantine_raw = Path(os.path.abspath(str(payload["quarantine_root"])))
        runtime_raw = Path(os.path.abspath(str(payload["runtime_root"])))
        generated_raw = Path(os.path.abspath(str(payload["generated_root"])))
        _assert_existing_path_chain_no_links(
            scratchpad_raw, Path(scratchpad_raw.anchor)
        )
        for child in (
            workspace_raw, active_raw, quarantine_raw, runtime_raw,
            generated_raw, Path(os.path.abspath(os.fspath(authority_path))),
        ):
            _assert_existing_path_chain_no_links(child, scratchpad_raw)
        scratchpad = scratchpad_raw.resolve(strict=True)
        workspace = workspace_raw.resolve(strict=True)
        active = active_raw.resolve(strict=True)
        quarantine = quarantine_raw.resolve(strict=True)
        runtime = runtime_raw.resolve(strict=True)
        if workspace.parent != (scratchpad / WORKSPACES_DIR).resolve(strict=True):
            raise FuzzWorkspaceError("AUTHORITY_PATH_ESCAPE", "workspace parent")
        for child in (active, quarantine, runtime, generated_raw):
            if not _is_descendant_or_equal(child, workspace):
                raise FuzzWorkspaceError("AUTHORITY_PATH_ESCAPE", str(child))

        expected_active: set[str] = set()
        expected_quarantine: set[str] = set()
        for row in payload["inputs"]:
            if not isinstance(row, dict):
                raise FuzzWorkspaceError("AUTHORITY_INPUTS_INVALID", "non-object row")
            target = _expected_record_file(payload, row)
            relative = str(row["relative_path"])
            if row.get("disposition") == "QUARANTINED":
                expected_quarantine.add(relative)
            else:
                expected_active.add(relative)
            if not target.is_file():
                issues.append(f"WORKSPACE_INPUT_MISSING: {relative}")
                continue
            digest, size = _sha256_file(target)
            if digest != row.get("sha256") or size != row.get("size"):
                issues.append(f"WORKSPACE_INPUT_DRIFT: {relative}")

        limits = payload.get("limits") if isinstance(payload.get("limits"), dict) else {}
        max_files = int(limits.get("max_files") or DEFAULT_MAX_FILES)
        max_bytes = int(limits.get("max_total_bytes") or DEFAULT_MAX_TOTAL_BYTES)
        active_files = _scan_tree_files(
            active, max_files=max_files * 3, max_bytes=max_bytes * 3
        )
        quarantine_files = _scan_tree_files(
            quarantine, max_files=max_files, max_bytes=max_bytes
        )
        generated_roots = [str(item) for item in payload.get("generated_write_roots", [])]
        tool_roots = [str(item) for item in payload.get("tool_output_roots", [])]
        for path in active_files:
            relative = path.relative_to(active).as_posix()
            if relative in expected_active:
                continue
            if not _under_relative_root(relative, [*generated_roots, *tool_roots]):
                issues.append(f"WRITE_OUTSIDE_GENERATED_LANE: {relative}")
        for path in quarantine_files:
            relative = path.relative_to(quarantine).as_posix()
            if relative not in expected_quarantine:
                issues.append(f"QUARANTINE_DIRTY: {relative}")

        if check_source:
            source_rows, _ = _input_rows(
                Path(str(payload["source_root"])),
                excluded_root=scratchpad,
                max_files=max_files,
                max_total_bytes=max_bytes,
                max_file_bytes=int(limits.get("max_file_bytes") or DEFAULT_MAX_FILE_BYTES),
            )
            if source_rows != payload["inputs"]:
                issues.append("SOURCE_DENOMINATOR_DRIFT: relevant source bytes/set changed")
    except FuzzWorkspaceError as exc:
        issues.append(f"{exc.code}: {exc.message}")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        issues.append(f"AUTHORITY_VALIDATION_FAILED: {type(exc).__name__}: {exc}")
    return sorted(set(issues))


def mark_fuzz_workspace_unscored(
    authority_path: Path, issues: Iterable[str | Mapping[str, object]]
) -> dict[str, object]:
    """Persist externally detected prelaunch debt without changing authority bytes."""

    payload = _read_json(Path(authority_path))
    normalized: list[dict[str, str]] = []
    for item in issues:
        if isinstance(item, Mapping):
            normalized.append(_issue(
                str(item.get("code") or "FUZZ_WORKSPACE_ERROR"),
                str(item.get("detail") or ""),
            ))
            continue
        code, _, detail = str(item).partition(":")
        normalized.append(_issue(code, detail.strip() or str(item)))
    return _write_debt(
        Path(str(payload["debt_path"])),
        run_id=str(payload["run_id"]),
        job_id=str(payload["job_id"]),
        authority_digest=str(payload["payload_digest"]),
        issues=normalized,
    )


def _command_receipt_paths(runtime_root: Path) -> tuple[Path, Path, Path]:
    command_root = runtime_root / "commands"
    command_root.mkdir(parents=True, exist_ok=True)
    ordinals = []
    for path in command_root.glob("[0-9][0-9][0-9]-command.json"):
        try:
            ordinals.append(int(path.name[:3]))
        except ValueError:
            continue
    ordinal = max(ordinals, default=0) + 1
    if ordinal > 999:
        raise FuzzWorkspaceError("COMMAND_COUNT_LIMIT", "more than 999 commands")
    stem = f"{ordinal:03d}"
    return (
        command_root / f"{stem}-command.json",
        command_root / f"{stem}-stdout.log",
        command_root / f"{stem}-stderr.log",
    )


def _basename_token(value: str) -> str:
    return Path(value).name.casefold()


def _tool_family(value: str) -> str:
    token = _basename_token(value)
    for suffix in (".exe", ".cmd", ".bat", ".com"):
        if token.endswith(suffix):
            return token[:-len(suffix)]
    return token


def _option_value(args: Sequence[str], names: frozenset[str]) -> str:
    for index, token in enumerate(args):
        token_n = str(token).strip().casefold()
        for name in names:
            if token_n == name and index + 1 < len(args):
                value = str(args[index + 1]).strip()
                return value if value and not value.startswith("-") else ""
            if token_n.startswith(name + "="):
                return str(token).split("=", 1)[1].strip()
    return ""


def _positive_option(args: Sequence[str], names: frozenset[str]) -> int | None:
    raw = _option_value(args, names)
    if not raw:
        return None
    try:
        parsed = int(raw, 10)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def _campaign_command_spec(
    language: str, role: str, argv: Sequence[str]
) -> dict[str, object] | None:
    """Parse a real campaign command into a backend-neutral execution shape.

    The grammar deliberately excludes help/list/compile-only forms and binds
    the selected harness/test plus any explicit case budget.  It never infers
    execution from arbitrary prose or from a tool's exit code alone.
    """

    if not argv:
        return None
    language_n = str(language).strip().casefold()
    role_n = str(role).strip().casefold()
    tool = _tool_family(str(argv[0]))
    raw_args = [str(item).strip() for item in argv[1:]]
    args = [item.casefold() for item in raw_args]
    if any(
        token in _NONEXECUTING_FLAGS
        or token.startswith("--help=")
        or token.startswith("--list=")
        for token in args
    ):
        return None

    kind = ""
    selector: dict[str, str] = {}
    cases: dict[str, int] = {}
    if (language_n, role_n) == ("evm", "invariant_fuzz"):
        if tool != "forge" or args[:1] != ["test"]:
            return None
        contract = _option_value(raw_args, frozenset({"--match-contract"}))
        test = _option_value(raw_args, frozenset({"--match-test"}))
        if not contract and not test:
            return None
        selector = {key: value for key, value in {
            "contract": contract, "test": test,
        }.items() if value}
        for field, flags in (
            ("invariant_runs", frozenset({"--invariant-runs"})),
            ("fuzz_runs", frozenset({"--fuzz-runs"})),
            ("invariant_depth", frozenset({"--invariant-depth"})),
        ):
            value = _positive_option(raw_args, flags)
            if value is not None:
                cases[field] = value
        kind = "FOUNDRY_INVARIANT"
    elif (language_n, role_n) == ("evm", "medusa_fuzz"):
        if tool != "medusa" or args[:1] != ["fuzz"]:
            return None
        selector = {
            "config": _option_value(raw_args, frozenset({"--config"})) or "DEFAULT"
        }
        value = _positive_option(raw_args, frozenset({"--test-limit"}))
        if value is not None:
            cases["test_limit"] = value
        kind = "MEDUSA_FUZZ"
    else:
        cargo_args_raw = raw_args[1:] if args[:1] and args[0].startswith("+") else raw_args
        cargo_args = [item.casefold() for item in cargo_args_raw]
        if tool == "trident" and (language_n, role_n) == ("solana", "invariant_fuzz"):
            if args[:2] != ["fuzz", "run"]:
                return None
            target = next((item for item in raw_args[2:] if item and not item.startswith("-")), "ALL")
            selector = {"target": target}
            kind = "TRIDENT_FUZZ"
        elif tool == "cargo" and (language_n, role_n) in {
            ("solana", "invariant_fuzz"), ("soroban", "invariant_fuzz"),
        }:
            if cargo_args[:2] == ["fuzz", "run"]:
                target = next((item for item in cargo_args_raw[2:] if item and not item.startswith("-")), "")
                if not target:
                    return None
                selector = {"target": target}
                for token in cargo_args_raw:
                    match = re.fullmatch(r"-runs=(\d+)", token, flags=re.IGNORECASE)
                    if match and int(match.group(1)) > 0:
                        cases["runs"] = int(match.group(1))
                kind = "CARGO_FUZZ"
            elif cargo_args[:1] == ["test"]:
                selected = next((
                    item for item in cargo_args_raw[1:]
                    if item and not item.startswith("-")
                ), "ALL")
                selector = {"test": selected}
                kind = "CARGO_TEST_FALLBACK"
            else:
                return None
        elif tool == "sui" and (language_n, role_n) == ("sui", "invariant_fuzz"):
            if args[:2] != ["move", "test"]:
                return None
            selected = next((item for item in raw_args[2:] if item and not item.startswith("-")), "ALL")
            selector = {"test": selected}
            value = _positive_option(raw_args, frozenset({"--rand-num-iters"}))
            if value is not None:
                cases["random_iterations"] = value
            kind = "SUI_MOVE_TEST"
        else:
            return None
    return {
        "kind": kind,
        "tool_family": tool,
        "selector": dict(sorted(selector.items())),
        "requested_cases": dict(sorted(cases.items())),
    }


def _campaign_command_kind(
    language: str, role: str, argv: Sequence[str]
) -> str:
    spec = _campaign_command_spec(language, role, argv)
    return str(spec["kind"]) if spec else ""


def _secure_launcher_issues(
    payload: Mapping[str, object], receipt: Mapping[str, object] | None
) -> list[dict[str, str]]:
    if not isinstance(receipt, Mapping):
        return [_issue(
            "FILESYSTEM_CONTAINMENT_UNAVAILABLE",
            "a driver-bound secure-launcher receipt was not supplied",
        )]
    problems: list[dict[str, str]] = []
    if receipt.get("schema_version") != SECURE_LAUNCHER_SCHEMA:
        problems.append(_issue("SECURE_LAUNCHER_RECEIPT_INVALID", "schema"))
    if receipt.get("payload_digest") != payload_digest(receipt):
        problems.append(_issue("SECURE_LAUNCHER_RECEIPT_INVALID", "digest"))
    if receipt.get("status") != "ENFORCED":
        problems.append(_issue("FILESYSTEM_CONTAINMENT_UNAVAILABLE", "not ENFORCED"))
    if receipt.get("authority_digest") != payload.get("payload_digest"):
        problems.append(_issue("SECURE_LAUNCHER_RECEIPT_INVALID", "authority"))
    if receipt.get("workspace_root") != payload.get("workspace_root"):
        problems.append(_issue("SECURE_LAUNCHER_RECEIPT_INVALID", "workspace"))
    if receipt.get("filesystem_policy") != "READONLY_INPUTS_EXPLICIT_WRITE_LANES":
        problems.append(_issue("FILESYSTEM_CONTAINMENT_UNAVAILABLE", "filesystem policy"))
    if receipt.get("process_tree_policy") not in {
        "WINDOWS_JOB_OBJECT_KILL_ON_CLOSE", "POSIX_DELEGATED_CGROUP_KILL",
    }:
        problems.append(_issue("PROCESS_CONTAINMENT_UNAVAILABLE", "process policy"))
    if receipt.get("network_policy") not in {"DENY", "LOOPBACK_ONLY"}:
        problems.append(_issue("NETWORK_CONTAINMENT_UNAVAILABLE", "network policy"))
    if not _HEX64_RE.fullmatch(str(receipt.get("phase_io_binding_digest") or "")):
        problems.append(_issue(
            "COMMAND_PROVENANCE_UNAUTHENTICATED", "PhaseIO binding absent"
        ))
    return _normalize_issues(problems)


def prepare_fuzz_campaign_contract(
    authority_path: Path,
    *,
    argv: Sequence[str],
    timeout_seconds: float,
    cwd_relative: str,
    selected_harnesses: Sequence[str],
    assertion_ids: Sequence[str],
    expected_case_count: int,
    secure_launcher_receipt: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build the backend-neutral contract a driver must bind before launch.

    This function defines the pure contract shape; it does not make its caller
    a driver.  ``READY`` therefore also requires a secure-launcher receipt with
    an external PhaseIO binding.  Without it the contract is durable UNSCORED
    and cannot authenticate a campaign command.
    """

    payload = _read_json(Path(authority_path))
    issues: list[dict[str, str]] = []
    for item in validate_fuzz_workspace_authority(Path(authority_path), check_source=True):
        code, _, detail = item.partition(":")
        issues.append(_issue(code, detail or item))
    command = [str(item) for item in argv]
    spec = _campaign_command_spec(
        str(payload.get("language") or ""), str(payload.get("role") or ""), command
    )
    if spec is None:
        issues.append(_issue("CAMPAIGN_COMMAND_INVALID", "not a strict campaign argv"))
    if not isinstance(expected_case_count, int) or isinstance(expected_case_count, bool) or expected_case_count < 1:
        issues.append(_issue("CAMPAIGN_CASE_DENOMINATOR_INVALID", str(expected_case_count)))
    if timeout_seconds <= 0 or timeout_seconds > 3600:
        issues.append(_issue("COMMAND_TIMEOUT_INVALID", str(timeout_seconds)))
    cwd_token = str(cwd_relative or ".").replace("\\", "/")
    if Path(cwd_token).is_absolute() or ".." in Path(cwd_token).parts:
        issues.append(_issue("COMMAND_CWD_ESCAPE", cwd_token))
    generated = _generated_harness_rows(payload)
    issues.extend(_generated_provenance_issues(payload, generated))
    generated_by_path = {str(row["relative_path"]): dict(row) for row in generated}
    selected = sorted(set(str(item).replace("\\", "/") for item in selected_harnesses))
    if not selected or any(item not in generated_by_path for item in selected):
        issues.append(_issue(
            "CAMPAIGN_HARNESS_DENOMINATOR_INVALID",
            "selected harnesses must be a non-empty subset of generated bytes",
        ))
    assertions = sorted(set(str(item).strip() for item in assertion_ids if str(item).strip()))
    if not assertions:
        issues.append(_issue("CAMPAIGN_ASSERTION_DENOMINATOR_INVALID", "empty"))
    issues.extend(_secure_launcher_issues(payload, secure_launcher_receipt))
    normalized = _normalize_issues(issues)
    prepared_root = Path(str(payload["runtime_root"])) / "prepared"
    _assert_existing_path_chain_no_links(prepared_root, Path(str(payload["runtime_root"])))
    prepared_root.mkdir(parents=True, exist_ok=True)
    contract_id = _sha256_bytes(_canonical_json({
        "authority_digest": str(payload["payload_digest"]),
        "argv": command,
        "cwd_relative": cwd_token,
        "timeout_seconds": float(timeout_seconds),
        "generated_harness_set_digest": record_set_digest(generated),
        "assertion_ids": assertions,
        "expected_case_count": expected_case_count,
    }))
    path = prepared_root / f"{contract_id[:16]}-prepared.json"
    contract: dict[str, object] = {
        "schema_version": PREPARED_CAMPAIGN_SCHEMA,
        "status": "READY" if not normalized else "UNSCORED",
        "run_id": str(payload["run_id"]),
        "job_id": str(payload["job_id"]),
        "authority_digest": str(payload["payload_digest"]),
        "contract_id": contract_id,
        "contract_path": str(path),
        "source_snapshot_digest": str(payload["source_snapshot_digest"]),
        "argv": command,
        "cwd_relative": cwd_token,
        "timeout_seconds": float(timeout_seconds),
        "command_spec": spec or {},
        "generated_harness_set_digest": record_set_digest(generated),
        "selected_harnesses": [generated_by_path[item] for item in selected if item in generated_by_path],
        "assertion_ids": assertions,
        "expected_case_count": expected_case_count,
        "secure_launcher_receipt": dict(secure_launcher_receipt or {}),
        "required_external_validator": "PHASE_IO_DRIVER_LEDGER",
        "issues": normalized,
    }
    contract["payload_digest"] = payload_digest(contract)
    _atomic_json(path, contract)
    return contract


def _validated_prepared_campaign(
    payload: Mapping[str, object], path: Path,
    *, argv: Sequence[str], timeout_seconds: float, cwd_relative: str,
) -> dict[str, object]:
    runtime = Path(str(payload["runtime_root"]))
    prepared_root = runtime / "prepared"
    _assert_existing_path_chain_no_links(path, prepared_root)
    contract = _read_json(path)
    if (
        contract.get("schema_version") != PREPARED_CAMPAIGN_SCHEMA
        or contract.get("payload_digest") != payload_digest(contract)
        or contract.get("status") != "READY"
        or contract.get("authority_digest") != payload.get("payload_digest")
        or contract.get("argv") != [str(item) for item in argv]
        or contract.get("cwd_relative") != str(cwd_relative or ".").replace("\\", "/")
        or contract.get("timeout_seconds") != float(timeout_seconds)
        or contract.get("generated_harness_set_digest")
        != record_set_digest(_generated_harness_rows(payload))
        or _secure_launcher_issues(payload, contract.get("secure_launcher_receipt"))
    ):
        raise FuzzWorkspaceError(
            "COMMAND_PROVENANCE_UNAUTHENTICATED", "prepared campaign contract invalid"
        )
    expected_name = f"{str(contract.get('contract_id') or '')[:16]}-prepared.json"
    if path.name != expected_name or contract.get("contract_path") != str(path):
        raise FuzzWorkspaceError(
            "COMMAND_PROVENANCE_UNAUTHENTICATED", "prepared contract path/digest mismatch"
        )
    return contract


def _campaign_execution_status(
    campaign_commands: Sequence[Mapping[str, object]],
) -> str:
    if not campaign_commands:
        return "NOT_EXECUTED"
    if any(row.get("returncode") == 0 for row in campaign_commands):
        return "EXECUTED_SUCCESS"
    if any(bool(row.get("timed_out")) for row in campaign_commands):
        return "TIMEOUT"
    return "EXECUTED_FAILED"


def _command_arg_path_issue(arg: str, workspace_root: Path) -> str | None:
    # No shell is involved, but path traversal could still make an approved tool
    # read or write outside the isolated workspace.  Absolute path arguments are
    # accepted only inside the workspace; parent components are always rejected.
    candidate = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
    if candidate.startswith(("http://", "https://")):
        return None
    normalized = candidate.replace("\\", "/")
    if ".." in Path(normalized).parts:
        return f"parent traversal argument: {arg}"
    path = Path(candidate)
    if path.is_absolute() and not _is_descendant_or_equal(path, workspace_root):
        # argv[0] is checked separately and may naturally be an absolute tool path.
        return f"absolute path outside workspace: {arg}"
    return None


def _tool_environment(payload: Mapping[str, object]) -> tuple[dict[str, str], dict[str, str]]:
    runtime = Path(str(payload["runtime_root"]))
    active = Path(str(payload["active_root"]))
    output = runtime / "tool-output"
    home = runtime / "home"
    temporary = runtime / "tmp"
    paths = {
        "FOUNDRY_OUT": output / "forge" / "out",
        "FOUNDRY_CACHE_PATH": output / "forge" / "cache",
        "FOUNDRY_BROADCAST": output / "forge" / "broadcast",
        "CARGO_TARGET_DIR": output / "cargo" / "target",
        "SUI_CONFIG_DIR": output / "sui" / "config",
    }
    for path in (*paths.values(), home, temporary):
        path.mkdir(parents=True, exist_ok=True)
    overrides = {
        key: str(path) for key, path in paths.items()
    }
    overrides.update({
        # The runnable tree intentionally contains no user-owned tests.  Force
        # Foundry to discover only the driver-owned generated test lane even if
        # a bound project config names a custom test directory.
        "FOUNDRY_TEST": str(active / "test"),
        "PLAMEN_FUZZ_WORKSPACE": str(active),
        "PLAMEN_FUZZ_AUTHORITY": str(payload["authority_path"]),
        "PLAMEN_FUZZ_GENERATED_ROOT": str(payload["generated_root"]),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "TMPDIR": str(temporary),
    })
    # The tool receives no arbitrary inherited variables.  A small OS lookup
    # set is copied explicitly; every writable/home/temp location is rebound
    # beneath the runtime lane.  Toolchain roots that must live elsewhere need
    # a future driver-prepared, read-only mount contract rather than ambient
    # environment authority.
    env = {
        name: value for name, value in os.environ.items()
        if str(name).upper() in _SAFE_INHERITED_ENV_NAMES
    }
    env.update(overrides)
    return env, overrides


def _unsafe_inherited_environment(
    payload: Mapping[str, object], overrides: Mapping[str, str]
) -> list[str]:
    workspace = Path(str(payload["workspace_root"]))
    override_names = {str(name).upper() for name in overrides}
    unsafe: list[str] = []
    for name, value in os.environ.items():
        name_u = str(name).upper()
        if name_u in override_names or name_u in _SAFE_INHERITED_ENV_NAMES:
            continue
        if not (
            name_u in _SEMANTIC_ENV_NAMES
            or any(name_u.startswith(prefix) for prefix in _SEMANTIC_ENV_PREFIXES)
        ):
            continue
        candidate = Path(str(value))
        if candidate.is_absolute() and not _is_descendant_or_equal(candidate, workspace):
            unsafe.append(name_u)
    return sorted(set(unsafe))


def _inherited_environment_fingerprint(
    inherited: Mapping[str, str], overrides: Mapping[str, str]
) -> dict[str, object]:
    """Hash inherited tool-relevant environment without persisting values."""

    rows: list[dict[str, object]] = []
    override_names = {str(name).upper() for name in overrides}
    for name, value in inherited.items():
        name_u = str(name).upper()
        if name_u in override_names:
            continue
        if not (
            name_u in _SEMANTIC_ENV_NAMES
            or any(name_u.startswith(prefix) for prefix in _SEMANTIC_ENV_PREFIXES)
        ):
            continue
        encoded = str(value).encode("utf-8", errors="surrogatepass")
        rows.append({
            "name": name_u,
            "bytes": len(encoded),
            "sha256": _sha256_bytes(encoded),
        })
    rows.sort(key=lambda row: str(row["name"]))
    return {"variables": rows, "set_digest": record_set_digest(rows)}


_WindowsKillOnCloseJob = OwnedProcessScope


def _transaction_write_authority(capability: Mapping[str, Any]) -> str | None:
    """Recognize only proof-grade write authorities supported by this runner."""

    if capability.get("exhaustive_write_confinement_authority") is True:
        return "EXHAUSTIVE"
    lease = capability.get("low_integrity_lease")
    if (
        capability.get("platform") == "WINDOWS"
        and capability.get("exhaustive_write_confinement_authority") is False
        and capability.get("serialized_low_integrity_stage_authority") is True
        and capability.get(
            "medium_integrity_source_and_canonical_protection"
        )
        is True
        and capability.get("write_confinement")
        == "LOW_INTEGRITY_TOKEN_PLUS_SERIALIZED_PLAMEN_STAGE_LEASE"
        and capability.get("write_confinement_limitation")
        == "UNRELATED_PREEXISTING_LOW_INTEGRITY_OBJECTS_OUT_OF_SCOPE"
        and isinstance(lease, Mapping)
        and lease.get("protocol")
        == "PLAMEN_WINDOWS_LOW_INTEGRITY_GLOBAL_LEASE_V1"
        and lease.get("namespace_authority")
        == "WINDOWS_KNOWN_FOLDER_LOCAL_APP_DATA"
        and lease.get("namespace_limitation")
        == "SAME_USER_MEDIUM_INTEGRITY_MUTATION_OUT_OF_SCOPE"
        and lease.get("scope")
        == "ALL_PLAMEN_LOW_INTEGRITY_LIFETIMES_FOR_THIS_WINDOWS_USER_PROFILE"
    ):
        return "SERIALIZED_PLAMEN_STAGE"
    return None


def _popen_contained(
    argv: Sequence[str], *, cwd: Path, env: Mapping[str, str],
    stdout: Any, stderr: Any, writable_roots: Sequence[Path] = (),
) -> tuple[subprocess.Popen[Any], _WindowsKillOnCloseJob, str]:
    capability = process_tree_termination_capability()
    write_authority = _transaction_write_authority(capability)
    if (
        capability.get("exhaustive_descendant_termination_authority") is not True
        or write_authority is None
    ):
        raise FuzzWorkspaceError(
            "PROCESS_CONTAINMENT_UNAVAILABLE",
            str(
                capability.get("limitation")
                or "exhaustive descendant containment is unavailable"
            ),
        )
    job = _WindowsKillOnCloseJob(
        writable_roots=tuple(Path(item) for item in writable_roots)
    )
    process: subprocess.Popen[Any] | None = None
    try:
        physical_argv = job.wrap_argv(tuple(str(item) for item in argv))
        process = job.create_process(
            physical_argv, cwd=str(cwd), env=dict(env), shell=False,
            popen_factory=None,
            stdout=stdout, stderr=stderr,
            **job.popen_kwargs(),
        )
        job.attach(process)
        observed_write_authority = (
            job.write_confinement_proven
            if write_authority == "EXHAUSTIVE"
            else job.serialized_stage_write_confinement_proven
        )
        if observed_write_authority is not True:
            raise FuzzWorkspaceError(
                "PROCESS_CONTAINMENT_UNAVAILABLE",
                "owned process write-confinement proof failed",
            )
        containment = (
            "WINDOWS_JOB_OBJECT_KILL_ON_CLOSE"
            if os.name == "nt"
            else str(capability["strategy"])
        )
        return process, job, containment
    except Exception:
        cleanup_failed = False
        if job.attached:
            try:
                job.terminate()
            except Exception:
                cleanup_failed = True
        elif process is not None:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                cleanup_failed = True
        try:
            job.close()
        except Exception:
            cleanup_failed = True
        if cleanup_failed:
            try:
                job.emergency_close()
            except Exception:
                pass
        raise


def _process_group_kwargs() -> tuple[dict[str, object], str]:
    # Retained as a capability-report helper for receipts/tests.  The runner no
    # longer claims a process group alone is a descendant containment boundary.
    if os.name == "nt":
        return ({}, "WINDOWS_JOB_OBJECT_KILL_ON_CLOSE")
    return ({}, "POSIX_CONTAINMENT_UNAVAILABLE")


def _terminate_process_tree(
    process: subprocess.Popen[Any], containment: _WindowsKillOnCloseJob
) -> None:
    """Terminate the provider-owned scope and prove its population reached zero."""

    try:
        containment.terminate()
    except OwnedProcessScopeError as exc:
        raise FuzzWorkspaceError(
            "PROCESS_CONTAINMENT_UNAVAILABLE",
            f"owned process scope termination failed: {exc}",
        ) from exc
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
    try:
        containment.close()
    except OwnedProcessScopeError as exc:
        raise FuzzWorkspaceError(
            "PROCESS_CONTAINMENT_UNAVAILABLE",
            f"owned process scope cleanup failed: {exc}",
        ) from exc


def _bounded_version(
    executable: str, tool_name: str, *, cwd: Path, env: Mapping[str, str]
) -> dict[str, object]:
    args = list(_VERSION_ARGS.get(tool_name, ("--version",)))
    argv = [executable, *args]
    try:
        process, containment, policy = _popen_contained(
            argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            raw, _ = process.communicate(timeout=20)
            timed_out = False
            _terminate_process_tree(process, containment)
            containment = None
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process, containment)
            containment = None
            raw, _ = process.communicate()
            timed_out = True
        finally:
            if containment is not None:
                containment.close()
        output = bytes(raw or b"")
        truncated = len(output) > MAX_VERSION_OUTPUT_BYTES
        bounded = output[:MAX_VERSION_OUTPUT_BYTES]
        return {
            "argv": argv,
            "returncode": 124 if timed_out else int(process.returncode),
            "timed_out": timed_out,
            "process_tree_policy": policy,
            "output_sha256": _sha256_bytes(output),
            "output_bytes": len(output),
            "output_preview": bounded.decode("utf-8", errors="replace"),
            "preview_truncated": truncated,
        }
    except Exception as exc:
        encoded = f"{type(exc).__name__}: {exc}".encode("utf-8", errors="replace")
        return {
            "argv": argv,
            "returncode": 126,
            "timed_out": False,
            "process_tree_policy": _process_group_kwargs()[1],
            "output_sha256": _sha256_bytes(encoded),
            "output_bytes": len(encoded),
            "output_preview": encoded.decode("utf-8", errors="replace"),
            "preview_truncated": False,
        }


def _file_receipt(path: Path, workspace_root: Path) -> dict[str, object]:
    digest, size = _sha256_file(path)
    return {
        "path": path.relative_to(workspace_root).as_posix(),
        "size": size,
        "sha256": digest,
        "over_limit": size > MAX_COMMAND_LOG_BYTES,
    }


def _write_runner_witness(
    receipt_path: Path, receipt: Mapping[str, object], payload: Mapping[str, object]
) -> dict[str, str]:
    witness_path = receipt_path.with_name(
        receipt_path.name.replace("-command.json", "-runner-witness.json")
    )
    terminal = dict(receipt)
    terminal.pop("payload_digest", None)
    terminal.pop("runner_witness", None)
    witness: dict[str, object] = {
        "schema_version": COMMAND_WITNESS_SCHEMA,
        "authority_digest": str(payload["payload_digest"]),
        "run_id": str(payload["run_id"]),
        "job_id": str(payload["job_id"]),
        "receipt_name": receipt_path.name,
        "terminal_receipt_digest": payload_digest(terminal),
        "finished_at": str(receipt.get("finished_at") or ""),
    }
    witness["payload_digest"] = payload_digest(witness)
    _atomic_json(witness_path, witness)
    return {
        "path": witness_path.relative_to(
            Path(str(payload["workspace_root"]))
        ).as_posix(),
        "payload_digest": str(witness["payload_digest"]),
    }


def _validate_runner_witness(
    receipt_path: Path, receipt: Mapping[str, object], payload: Mapping[str, object]
) -> None:
    reference = receipt.get("runner_witness")
    if not isinstance(reference, dict):
        raise FuzzWorkspaceError(
            "COMMAND_PROVENANCE_UNAUTHENTICATED", "runner witness missing"
        )
    workspace = Path(str(payload["workspace_root"]))
    runtime = Path(str(payload["runtime_root"]))
    witness_path = workspace / str(reference.get("path") or "")
    expected_path = receipt_path.with_name(
        receipt_path.name.replace("-command.json", "-runner-witness.json")
    )
    if (
        not _is_descendant_or_equal(witness_path, runtime / "commands")
        or witness_path.resolve(strict=False) != expected_path.resolve(strict=False)
        or not witness_path.is_file()
        or _is_link_or_reparse(witness_path)
    ):
        raise FuzzWorkspaceError(
            "COMMAND_PROVENANCE_UNAUTHENTICATED", "runner witness path invalid"
        )
    witness = _read_json(witness_path)
    if (
        witness.get("schema_version") != COMMAND_WITNESS_SCHEMA
        or witness.get("payload_digest") != payload_digest(witness)
        or reference.get("payload_digest") != witness.get("payload_digest")
        or witness.get("authority_digest") != payload.get("payload_digest")
        or witness.get("run_id") != payload.get("run_id")
        or witness.get("job_id") != payload.get("job_id")
        or witness.get("receipt_name") != receipt_path.name
    ):
        raise FuzzWorkspaceError(
            "COMMAND_PROVENANCE_UNAUTHENTICATED", "runner witness identity invalid"
        )
    terminal = dict(receipt)
    terminal.pop("payload_digest", None)
    terminal.pop("runner_witness", None)
    if witness.get("terminal_receipt_digest") != payload_digest(terminal):
        raise FuzzWorkspaceError(
            "COMMAND_PROVENANCE_UNAUTHENTICATED", "terminal receipt witness mismatch"
        )


def _append_debt_issue(payload: Mapping[str, object], issue: Mapping[str, object]) -> None:
    debt_path = Path(str(payload["debt_path"]))
    prior: list[Mapping[str, object]] = []
    if debt_path.is_file():
        try:
            prior_payload = _read_json(debt_path)
            if isinstance(prior_payload, dict) and isinstance(prior_payload.get("issues"), list):
                prior = [row for row in prior_payload["issues"] if isinstance(row, dict)]
        except Exception:
            prior = []
    _write_debt(
        debt_path,
        run_id=str(payload.get("run_id") or "UNBOUND"),
        job_id=str(payload.get("job_id") or "fuzz"),
        authority_digest=str(payload.get("payload_digest") or ""),
        issues=[*prior, issue],
    )


def run_recorded_command(
    authority_path: Path,
    argv: Sequence[str],
    timeout_seconds: float,
    *,
    cwd_relative: str = ".",
) -> int:
    """Execute one approved tool command without a shell and write exact receipts."""

    try:
        payload = _read_json(Path(authority_path))
        issues = validate_fuzz_workspace_authority(Path(authority_path), check_source=True)
        if issues:
            first = issues[0]
            code, _, detail = first.partition(":")
            _append_debt_issue(payload, _issue(code, detail or first))
            return 125
        if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)) or not argv:
            _append_debt_issue(payload, _issue("COMMAND_INVALID", "argv is empty"))
            return 125
        command = [str(item) for item in argv]
        if any(not item or "\x00" in item for item in command):
            _append_debt_issue(payload, _issue("COMMAND_INVALID", "empty/NUL argv"))
            return 125
        tool_name = _basename_token(command[0])
        tool_family = _tool_family(command[0])
        allowed = {str(item).casefold() for item in payload.get("allowed_tools", [])}
        allowed_families = {_tool_family(item) for item in allowed}
        if tool_name not in allowed and tool_family not in allowed_families:
            _append_debt_issue(
                payload, _issue("UNAPPROVED_TOOL", f"{tool_name} not in {sorted(allowed)}")
            )
            return 125
        workspace = Path(str(payload["workspace_root"]))
        for arg in command[1:]:
            issue = _command_arg_path_issue(arg, workspace)
            if issue:
                _append_debt_issue(payload, _issue("COMMAND_PATH_ESCAPE", issue))
                return 125
        if timeout_seconds <= 0 or timeout_seconds > 3600:
            _append_debt_issue(
                payload, _issue("COMMAND_TIMEOUT_INVALID", str(timeout_seconds))
            )
            return 125
        campaign_spec = _campaign_command_spec(
            str(payload.get("language") or ""),
            str(payload.get("role") or ""),
            command,
        )
        if campaign_spec is not None:
            _append_debt_issue(payload, _issue(
                "COMMAND_PROVENANCE_UNAUTHENTICATED",
                "campaign execution requires a driver-prepared contract and "
                "secure-launcher/PhaseIO attestation; the model-callable probe "
                "runner is not self-certifying",
            ))
            return 125
        executable = shutil.which(command[0])
        if executable is None and Path(command[0]).is_absolute() and Path(command[0]).is_file():
            executable = str(Path(command[0]).resolve())
        if executable is None:
            _append_debt_issue(payload, _issue("TOOL_UNAVAILABLE", command[0]))
            return 126
        command[0] = executable
        active = Path(str(payload["active_root"]))
        cwd_token = str(cwd_relative or ".").replace("\\", "/")
        if Path(cwd_token).is_absolute() or ".." in Path(cwd_token).parts:
            _append_debt_issue(
                payload, _issue("COMMAND_CWD_ESCAPE", cwd_token)
            )
            return 125
        command_cwd = (active / cwd_token).resolve(strict=False)
        if not _is_descendant_or_equal(command_cwd, active):
            _append_debt_issue(
                payload, _issue("COMMAND_CWD_ESCAPE", cwd_token)
            )
            return 125
        if command_cwd != active.resolve(strict=False):
            relative_cwd = command_cwd.relative_to(active.resolve(strict=False)).as_posix()
            generated_roots = [
                str(item) for item in payload.get("generated_write_roots", [])
            ]
            if not _under_relative_root(relative_cwd, generated_roots):
                _append_debt_issue(
                    payload, _issue("COMMAND_CWD_NOT_GENERATED", relative_cwd)
                )
                return 125
        if not command_cwd.is_dir():
            _append_debt_issue(
                payload, _issue("COMMAND_CWD_MISSING", cwd_token)
            )
            return 125
        runtime = Path(str(payload["runtime_root"]))
        receipt_path, stdout_path, stderr_path = _command_receipt_paths(runtime)
        env, overrides = _tool_environment(payload)
        unsafe_environment = _unsafe_inherited_environment(payload, overrides)
        if unsafe_environment:
            _append_debt_issue(payload, _issue(
                "INHERITED_ENVIRONMENT_UNSAFE",
                "outside-workspace semantic variables were withheld: "
                + ", ".join(unsafe_environment),
            ))
            return 125
        tool_digest = ""
        tool_size = 0
        try:
            tool_digest, tool_size = _sha256_file(Path(executable))
        except OSError:
            pass
        pre_generated = _generated_harness_rows(payload)
        receipt: dict[str, object] = {
            "schema_version": COMMAND_SCHEMA,
            "authority_digest": str(payload["payload_digest"]),
            "run_id": str(payload["run_id"]),
            "job_id": str(payload["job_id"]),
            "status": "RUNNING",
            "started_at": _utc_now(),
            "finished_at": "",
            "cwd": str(command_cwd),
            "argv": command,
            "timeout_seconds": float(timeout_seconds),
            "executable": {
                "path": executable,
                "size": tool_size,
                "sha256": tool_digest,
            },
            "tool_version": _bounded_version(
                executable, tool_name, cwd=command_cwd, env=env
            ),
            "environment_overrides": dict(sorted(overrides.items())),
            "inherited_environment_fingerprint": _inherited_environment_fingerprint(
                os.environ, overrides
            ),
            "process_tree_policy": _process_group_kwargs()[1],
            "generated_pre_set_digest": record_set_digest(pre_generated),
            "returncode": None,
            "timed_out": False,
            "stdout": {},
            "stderr": {},
        }
        receipt["payload_digest"] = payload_digest(receipt)
        _atomic_json(receipt_path, receipt)
        returncode = 126
        timed_out = False
        spawn_error = ""
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                process, containment, containment_policy = _popen_contained(
                    command, cwd=command_cwd, env=env,
                    stdout=stdout, stderr=stderr,
                    # The active tree is a disposable, driver-owned attempt
                    # view.  Tool writes are OS-confined to it; the fuzz
                    # authority separately rejects any mutation outside the
                    # declared generated/tool lanes before scoring.
                    writable_roots=(active,),
                )
                receipt["process_tree_policy"] = containment_policy
                try:
                    returncode = int(process.wait(timeout=float(timeout_seconds)))
                    _terminate_process_tree(process, containment)
                    containment = None
                except subprocess.TimeoutExpired as exc:
                    timed_out = True
                    returncode = 124
                    spawn_error = f"TimeoutExpired: {exc}"
                    _terminate_process_tree(process, containment)
                    containment = None
                finally:
                    if containment is not None:
                        containment.close()
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                returncode = 124
                spawn_error = f"TimeoutExpired: {exc}"
            except FuzzWorkspaceError as exc:
                returncode = 125
                spawn_error = f"{exc.code}: {exc.message}"
                _append_debt_issue(payload, _issue(exc.code, exc.message))
            except Exception as exc:
                returncode = 126
                spawn_error = f"{type(exc).__name__}: {exc}"
        if spawn_error:
            with stderr_path.open("ab") as stream:
                stream.write(("\n[PLAMEN RUNNER] " + spawn_error + "\n").encode("utf-8"))
        receipt.update({
            "status": "TIMEOUT" if timed_out else ("COMPLETED" if returncode == 0 else "FAILED"),
            "finished_at": _utc_now(),
            "returncode": returncode,
            "timed_out": timed_out,
            "stdout": _file_receipt(stdout_path, workspace),
            "stderr": _file_receipt(stderr_path, workspace),
            "generated_post_set_digest": record_set_digest(
                _generated_harness_rows(payload)
            ),
        })
        receipt["runner_witness"] = _write_runner_witness(
            receipt_path, receipt, payload
        )
        receipt["payload_digest"] = payload_digest(receipt)
        _atomic_json(receipt_path, receipt)
        if bool(receipt["stdout"].get("over_limit")) or bool(receipt["stderr"].get("over_limit")):
            _append_debt_issue(
                payload, _issue("COMMAND_LOG_BYTE_LIMIT", receipt_path.name)
            )
        return returncode
    except FuzzWorkspaceError as exc:
        try:
            payload = _read_json(Path(authority_path))
            _append_debt_issue(payload, _issue(exc.code, exc.message))
        except Exception:
            pass
        return 125
    except Exception as exc:
        try:
            payload = _read_json(Path(authority_path))
            _append_debt_issue(
                payload, _issue("COMMAND_RECORDING_FAILED", f"{type(exc).__name__}: {exc}")
            )
        except Exception:
            pass
        return 125


def _generated_harness_rows(payload: Mapping[str, object]) -> list[dict[str, object]]:
    active = Path(str(payload["active_root"]))
    roots = [str(item) for item in payload.get("generated_write_roots", [])]
    tool_roots = [str(item) for item in payload.get("tool_output_roots", [])]
    rows: list[dict[str, object]] = []
    if not active.is_dir():
        return rows
    max_files = int((payload.get("limits") or {}).get("max_files", DEFAULT_MAX_FILES))
    max_bytes = int((payload.get("limits") or {}).get("max_total_bytes", DEFAULT_MAX_TOTAL_BYTES))
    for path in _scan_tree_files(active, max_files=max_files * 3, max_bytes=max_bytes * 3):
        relative = path.relative_to(active).as_posix()
        if not _under_relative_root(relative, roots):
            continue
        if _under_relative_root(relative, tool_roots):
            continue
        if any(
            part.casefold() in _GENERATED_RUNTIME_COMPONENTS
            for part in Path(relative).parts
        ):
            continue
        digest, size = _sha256_file(path)
        rows.append({"relative_path": relative, "size": size, "sha256": digest})
    rows.sort(key=lambda row: str(row["relative_path"]))
    return rows


def _generated_provenance_issues(
    payload: Mapping[str, object], generated: Sequence[Mapping[str, object]]
) -> list[dict[str, str]]:
    quarantined: dict[tuple[str, int], list[str]] = {}
    for row in payload.get("inputs", []):
        if not isinstance(row, dict) or row.get("disposition") != "QUARANTINED":
            continue
        key = (str(row.get("sha256") or ""), int(row.get("size") or 0))
        quarantined.setdefault(key, []).append(str(row.get("relative_path") or ""))
    issues: list[dict[str, str]] = []
    for row in generated:
        key = (str(row.get("sha256") or ""), int(row.get("size") or 0))
        sources = sorted(quarantined.get(key, []))
        if sources:
            issues.append(_issue(
                "PREEXISTING_HARNESS_PROVENANCE",
                f"{row.get('relative_path')} exactly clones quarantined bytes from "
                + ", ".join(sources),
            ))
    return issues


def _command_receipts(payload: Mapping[str, object]) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    runtime = Path(str(payload["runtime_root"]))
    workspace = Path(str(payload["workspace_root"]))
    rows: list[dict[str, object]] = []
    issues: list[dict[str, str]] = []
    command_root = runtime / "commands"
    try:
        _assert_existing_path_chain_no_links(command_root, runtime)
    except FuzzWorkspaceError as exc:
        return [], [_issue(exc.code, exc.message)]
    receipt_paths = sorted(command_root.glob("[0-9][0-9][0-9]-command.json"))
    expected_witnesses = {
        path.name.replace("-command.json", "-runner-witness.json")
        for path in receipt_paths
    }
    for witness in sorted(command_root.glob("[0-9][0-9][0-9]-runner-witness.json")):
        if witness.name not in expected_witnesses:
            issues.append(_issue(
                "COMMAND_PROVENANCE_UNAUTHENTICATED",
                f"orphan runner witness: {witness.name}",
            ))
    for path in receipt_paths:
        try:
            if _is_link_or_reparse(path):
                raise FuzzWorkspaceError(
                    "COMMAND_PROVENANCE_UNAUTHENTICATED", "receipt is link/reparse"
                )
            receipt = _read_json(path)
            if receipt.get("schema_version") != COMMAND_SCHEMA:
                raise ValueError("schema")
            if receipt.get("payload_digest") != payload_digest(receipt):
                raise ValueError("digest")
            if receipt.get("authority_digest") != payload.get("payload_digest"):
                raise ValueError("authority digest")
            if receipt.get("status") not in {"COMPLETED", "FAILED", "TIMEOUT"}:
                raise ValueError("terminal status")
            receipt_cwd = Path(str(receipt.get("cwd") or "")).resolve(strict=False)
            active = Path(str(payload["active_root"])).resolve(strict=False)
            if not _is_descendant_or_equal(receipt_cwd, active):
                raise ValueError("cwd escape")
            if receipt_cwd != active:
                relative_cwd = receipt_cwd.relative_to(active).as_posix()
                if not _under_relative_root(
                    relative_cwd,
                    [str(item) for item in payload.get("generated_write_roots", [])],
                ):
                    raise ValueError("cwd is not a generated lane")
            for key in ("stdout", "stderr"):
                record = receipt.get(key)
                if not isinstance(record, dict):
                    raise ValueError(key)
                raw = workspace / str(record.get("path") or "")
                if not _is_descendant_or_equal(raw, runtime) or not raw.is_file():
                    raise ValueError(f"{key} path")
                digest, size = _sha256_file(raw)
                if digest != record.get("sha256") or size != record.get("size"):
                    raise ValueError(f"{key} drift")
                if _is_link_or_reparse(raw):
                    raise ValueError(f"{key} link/reparse")
            _validate_runner_witness(path, receipt, payload)
            rows.append(receipt)
        except FuzzWorkspaceError as exc:
            issues.append(_issue(exc.code, f"{path.name}: {exc.message}"))
        except Exception as exc:
            issues.append(_issue(
                "COMMAND_RECEIPT_INVALID", f"{path.name}: {type(exc).__name__}: {exc}"
            ))
    return rows, issues


def finalize_fuzz_workspace(
    authority_path: Path, *, _persist: bool = True
) -> dict[str, object]:
    """Freeze generated hashes and exact command outcomes into a result receipt."""

    payload = _read_json(Path(authority_path))
    validation = validate_fuzz_workspace_authority(Path(authority_path), check_source=True)
    issues: list[dict[str, str]] = []
    runner_observations: list[dict[str, str]] = []
    debt_path = Path(str(payload["debt_path"]))
    if debt_path.is_file():
        try:
            prior_debt = _read_json(debt_path)
            if prior_debt.get("schema_version") != DEBT_SCHEMA:
                raise ValueError("schema")
            if prior_debt.get("payload_digest") != payload_digest(prior_debt):
                raise ValueError("digest")
            for row in prior_debt.get("issues", []):
                if not isinstance(row, dict):
                    continue
                normalized_row = _issue(
                    str(row.get("code") or "FUZZ_WORKSPACE_ERROR"),
                    str(row.get("detail") or ""),
                )
                # Debt is monotonic authority state.  Operational failures are
                # observations, but they still preclude a proof-grade measured
                # campaign and therefore remain in the derived issue set.
                issues.append(normalized_row)
        except Exception as exc:
            issues.append(_issue(
                "DEBT_RECEIPT_INVALID", f"{type(exc).__name__}: {exc}"
            ))
    for item in validation:
        code, _, detail = item.partition(":")
        issues.append(_issue(code, detail or item))
    commands, command_issues = _command_receipts(payload)
    issues.extend(command_issues)
    if not commands:
        issues.append(_issue("NO_RECORDED_COMMAND", "no runner command receipt exists"))
    campaign_commands: list[dict[str, object]] = []
    for command in commands:
        command_argv = command.get("argv")
        kind = _campaign_command_kind(
            str(payload.get("language") or ""),
            str(payload.get("role") or ""),
            command_argv if isinstance(command_argv, list) else [],
        )
        if not kind:
            continue
        parsed_spec = _campaign_command_spec(
            str(payload.get("language") or ""),
            str(payload.get("role") or ""),
            command_argv if isinstance(command_argv, list) else [],
        )
        campaign_commands.append({
            "command_payload_digest": str(command.get("payload_digest") or ""),
            "kind": kind,
            "command_spec": parsed_spec or {
                "kind": kind, "tool_family": "UNBOUND",
                "selector": {}, "requested_cases": {},
            },
            "status": str(command.get("status") or ""),
            "returncode": command.get("returncode"),
            "timed_out": bool(command.get("timed_out")),
            "generated_pre_set_digest": str(
                command.get("generated_pre_set_digest") or ""
            ),
            "generated_post_set_digest": str(
                command.get("generated_post_set_digest") or ""
            ),
        })
    if not campaign_commands:
        issues.append(_issue(
            "NO_RECORDED_CAMPAIGN_COMMAND",
            "only probes/builds or no runner commands were recorded",
        ))
    for command in commands:
        for stream in ("stdout", "stderr"):
            record = command.get(stream)
            if isinstance(record, dict) and record.get("over_limit"):
                issues.append(_issue(
                    "COMMAND_LOG_BYTE_LIMIT", f"{stream} for {command.get('argv')}"
                ))
    generated = _generated_harness_rows(payload)
    issues.extend(_generated_provenance_issues(payload, generated))
    generated_digest = record_set_digest(generated)
    if campaign_commands and not generated:
        issues.append(_issue(
            "CAMPAIGN_WITHOUT_GENERATED_HARNESS",
            "a campaign command ran with an empty generated harness denominator",
        ))
    elif campaign_commands and not any(
        generated_digest in {
            str(row.get("generated_pre_set_digest") or ""),
            str(row.get("generated_post_set_digest") or ""),
        }
        for row in campaign_commands
    ):
        issues.append(_issue(
            "GENERATED_HARNESS_NOT_EXECUTED",
            "final generated harness bytes do not match any campaign boundary",
        ))
    normalized = _normalize_issues(issues)
    finished = max(
        (str(row.get("finished_at") or "") for row in commands), default=""
    )
    campaign_status = _campaign_execution_status(campaign_commands)
    if campaign_status == "TIMEOUT":
        issues.append(_issue(
            "CAMPAIGN_EXECUTION_TIMEOUT", "no campaign completed successfully"
        ))
    elif campaign_status == "EXECUTED_FAILED":
        issues.append(_issue(
            "CAMPAIGN_EXECUTION_FAILED", "no campaign completed successfully"
        ))
    normalized = _normalize_issues(issues)
    result: dict[str, object] = {
        "schema_version": RESULT_SCHEMA,
        "status": "MEASURED" if not normalized else "UNSCORED",
        "run_id": str(payload["run_id"]),
        "job_id": str(payload["job_id"]),
        "authority_digest": str(payload["payload_digest"]),
        "source_snapshot_digest": str(payload["source_snapshot_digest"]),
        "source_input_set_digest": str(payload["denominators"]["all"]["set_digest"]),
        "finalized_at": finished,
        "generated_harnesses": generated,
        "generated_harness_set_digest": generated_digest,
        "commands": commands,
        "command_count": len(commands),
        "campaign_commands": campaign_commands,
        "campaign_command_count": len(campaign_commands),
        "campaign_execution_status": campaign_status,
        "runner_observations": _normalize_issues(runner_observations),
        "issues": normalized,
        "proof_authority": (
            "EXECUTION_SCOPE_REQUIRES_CONSUMER"
            if not normalized and campaign_status == "EXECUTED_SUCCESS"
            else "NONE"
        ),
    }
    result["payload_digest"] = payload_digest(result)
    if _persist:
        _atomic_json(Path(str(payload["result_path"])), result)
        _write_debt(
            Path(str(payload["debt_path"])),
            run_id=str(payload["run_id"]), job_id=str(payload["job_id"]),
            authority_digest=str(payload["payload_digest"]), issues=normalized,
        )
    return result


def validate_fuzz_workspace_result(authority_path: Path) -> list[str]:
    try:
        authority = _read_json(Path(authority_path))
        result_path = Path(str(authority["result_path"]))
        result = _read_json(result_path)
        issues: list[str] = []
        if result.get("schema_version") != RESULT_SCHEMA:
            issues.append("RESULT_SCHEMA_INVALID: schema mismatch")
        if result.get("payload_digest") != payload_digest(result):
            issues.append("RESULT_DIGEST_INVALID: payload digest mismatch")
        if result.get("authority_digest") != authority.get("payload_digest"):
            issues.append("RESULT_AUTHORITY_DRIFT: authority digest mismatch")
        current_authority_issues = validate_fuzz_workspace_authority(
            Path(authority_path), check_source=True
        )
        issues.extend(current_authority_issues)
        commands, command_issues = _command_receipts(authority)
        issues.extend(f"{row['code']}: {row['detail']}" for row in command_issues)
        generated = _generated_harness_rows(authority)
        if result.get("commands") != commands:
            issues.append("RESULT_COMMAND_DRIFT: command denominator changed")
        if result.get("generated_harnesses") != generated:
            issues.append("RESULT_HARNESS_DRIFT: generated denominator changed")
        if result.get("generated_harness_set_digest") != record_set_digest(generated):
            issues.append("RESULT_HARNESS_DIGEST_INVALID: digest mismatch")
        expected_campaigns = []
        for command in commands:
            command_argv = command.get("argv")
            kind = _campaign_command_kind(
                str(authority.get("language") or ""),
                str(authority.get("role") or ""),
                command_argv if isinstance(command_argv, list) else [],
            )
            if kind:
                parsed_spec = _campaign_command_spec(
                    str(authority.get("language") or ""),
                    str(authority.get("role") or ""),
                    command_argv if isinstance(command_argv, list) else [],
                )
                expected_campaigns.append({
                    "command_payload_digest": str(command.get("payload_digest") or ""),
                    "kind": kind,
                    "command_spec": parsed_spec or {
                        "kind": kind, "tool_family": "UNBOUND",
                        "selector": {}, "requested_cases": {},
                    },
                    "status": str(command.get("status") or ""),
                    "returncode": command.get("returncode"),
                    "timed_out": bool(command.get("timed_out")),
                    "generated_pre_set_digest": str(
                        command.get("generated_pre_set_digest") or ""
                    ),
                    "generated_post_set_digest": str(
                        command.get("generated_post_set_digest") or ""
                    ),
                })
        if result.get("campaign_commands") != expected_campaigns:
            issues.append("RESULT_CAMPAIGN_DRIFT: campaign denominator changed")
        if result.get("campaign_command_count") != len(expected_campaigns):
            issues.append("RESULT_CAMPAIGN_COUNT_INVALID: count mismatch")
        if result.get("command_count") != len(commands):
            issues.append("RESULT_COMMAND_COUNT_INVALID: count mismatch")
        if result.get("campaign_execution_status") != _campaign_execution_status(
            expected_campaigns
        ):
            issues.append("RESULT_CAMPAIGN_STATUS_INVALID: status mismatch")
        expected_result = finalize_fuzz_workspace(
            Path(authority_path), _persist=False
        )
        if result != expected_result:
            issues.append(
                "RESULT_SEMANTICS_INVALID: status/debt/proof fields do not match re-derivation"
            )
        return sorted(set(issues))
    except Exception as exc:
        return [f"RESULT_UNREADABLE: {type(exc).__name__}: {exc}"]


def _index_issue_codes(values: Iterable[object]) -> tuple[list[str], int]:
    """Return a bounded, stable code projection while retaining the denominator."""

    codes: set[str] = set()
    total = 0
    for value in values:
        total += 1
        if isinstance(value, Mapping):
            raw = str(value.get("code") or "UNCLASSIFIED")
        else:
            raw = str(value).split(":", 1)[0]
        code = re.sub(r"[^A-Z0-9_]+", "_", raw.strip().upper()).strip("_")
        codes.add(code or "UNCLASSIFIED")
    return sorted(codes)[:MAX_INDEX_ISSUES_PER_ROW], total


def _index_row_digest(row: Mapping[str, object]) -> str:
    unsigned = {key: value for key, value in row.items() if key != "row_digest"}
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def _index_control_path(
    scratchpad: Path,
    path: Path | str,
    *,
    require_file: bool,
) -> str:
    """Return one link-safe path relative to the scratchpad authority root."""

    root = Path(os.path.abspath(os.fspath(scratchpad)))
    if not root.is_dir():
        raise FuzzWorkspaceError("INDEX_ROOT_MISSING", str(root))
    if not str(path).strip():
        raise FuzzWorkspaceError("INDEX_PATH_MISSING", "empty path")
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = Path(os.path.abspath(os.fspath(candidate)))
    if not _is_lexical_descendant_or_equal(candidate, root):
        raise FuzzWorkspaceError("INDEX_PATH_ESCAPE", str(candidate))
    if require_file:
        if not candidate.is_file():
            raise FuzzWorkspaceError("INDEX_INPUT_MISSING", str(candidate))
        _assert_existing_path_chain_no_links(candidate, root)
    else:
        if not candidate.parent.is_dir():
            raise FuzzWorkspaceError("INDEX_PARENT_MISSING", str(candidate.parent))
        _assert_existing_path_chain_no_links(candidate.parent, root)
        if candidate.exists():
            _assert_existing_path_chain_no_links(candidate, root)
    return candidate.relative_to(root).as_posix()


def _compare_only_json(path: Path, payload: Mapping[str, object], *, code: str) -> None:
    """Publish once; a resume validates bytes instead of silently reblessing drift."""

    if path.is_file():
        prior = _read_json(path)
        if prior != dict(payload):
            raise FuzzWorkspaceError(code, str(path))
        return
    _atomic_json(path, payload)


def _workspace_index_row(
    scratchpad: Path,
    job: Mapping[str, object],
) -> dict[str, object]:
    job_id = str(job.get("agent_id") or job.get("job_id") or "").strip()
    role = str(job.get("role") or "").strip()
    output = str(job.get("output") or "").strip()
    if not job_id or not role or not output:
        raise FuzzWorkspaceError(
            "INDEX_JOB_IDENTITY_INVALID", f"job_id={job_id!r} role={role!r} output={output!r}"
        )
    output_path = Path(output)
    if output_path.is_absolute() or ".." in output_path.parts or output_path.name != output:
        raise FuzzWorkspaceError("INDEX_OUTPUT_INVALID", output)

    authority_raw = str(job.get("fuzz_authority_path") or "").strip()
    if not authority_raw or not Path(authority_raw).is_file():
        row: dict[str, object] = {
            "job_id": job_id,
            "role": role,
            "output": output,
            "status": "UNSCORED",
            "authority_path": "",
            "authority_digest": "",
            "result_path": "",
            "debt_path": "",
            "source_snapshot_digest": "",
            "source_input_set_digest": "",
            "workspace_input_set_digest": "",
            "issue_codes": ["FUZZ_WORKSPACE_AUTHORITY_MISSING"],
            "issue_count": 1,
            "issues_truncated": False,
        }
        row["row_digest"] = _index_row_digest(row)
        return row

    authority_path = Path(authority_raw)
    authority_relative = _index_control_path(
        scratchpad, authority_path, require_file=True
    )
    authority = _read_json(authority_path)
    authority_issues = validate_fuzz_workspace_authority(
        authority_path, check_source=True
    )
    if str(authority.get("job_id") or "") != job_id:
        authority_issues.append("INDEX_JOB_ID_DRIFT: authority job differs")
    if str(authority.get("role") or "") != role:
        authority_issues.append("INDEX_ROLE_DRIFT: authority role differs")
    result_relative = _index_control_path(
        scratchpad, str(authority.get("result_path") or ""), require_file=False
    )
    debt_relative = _index_control_path(
        scratchpad, str(authority.get("debt_path") or ""), require_file=False
    )
    denominator = authority.get("denominators")
    denominator_map = denominator if isinstance(denominator, Mapping) else {}
    all_inputs = denominator_map.get("all")
    active_inputs = denominator_map.get("active")
    all_map = all_inputs if isinstance(all_inputs, Mapping) else {}
    active_map = active_inputs if isinstance(active_inputs, Mapping) else {}
    issue_codes, issue_count = _index_issue_codes(authority_issues)
    row = {
        "job_id": job_id,
        "role": role,
        "output": output,
        "status": (
            "READY"
            if str(authority.get("status") or "") == "READY" and not authority_issues
            else "UNSCORED"
        ),
        "authority_path": authority_relative,
        "authority_digest": str(authority.get("payload_digest") or ""),
        "result_path": result_relative,
        "debt_path": debt_relative,
        "source_snapshot_digest": str(authority.get("source_snapshot_digest") or ""),
        "source_input_set_digest": str(all_map.get("set_digest") or ""),
        "workspace_input_set_digest": str(active_map.get("set_digest") or ""),
        "issue_codes": issue_codes,
        "issue_count": issue_count,
        "issues_truncated": issue_count > len(issue_codes),
    }
    row["row_digest"] = _index_row_digest(row)
    return row


def _workspace_index_payload(
    scratchpad: Path,
    jobs: Sequence[Mapping[str, object]],
    *,
    run_id: str,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
) -> dict[str, object]:
    if not jobs or len(jobs) > MAX_INDEX_ROWS:
        raise FuzzWorkspaceError(
            "INDEX_CARDINALITY_INVALID", f"rows={len(jobs)} max={MAX_INDEX_ROWS}"
        )
    rows = sorted(
        (_workspace_index_row(Path(scratchpad), job) for job in jobs),
        key=lambda row: (str(row["job_id"]), str(row["output"])),
    )
    for field in ("job_id", "output"):
        values = [str(row[field]) for row in rows]
        if len(values) != len(set(values)):
            raise FuzzWorkspaceError("INDEX_DUPLICATE_IDENTITY", field)
    authority_paths = [
        str(row["authority_path"]) for row in rows if row["authority_path"]
    ]
    if len(authority_paths) != len(set(authority_paths)):
        raise FuzzWorkspaceError("INDEX_DUPLICATE_IDENTITY", "authority_path")
    payload: dict[str, object] = {
        "schema_version": WORKSPACE_INDEX_SCHEMA,
        "run_id": str(run_id),
        "pipeline": str(pipeline).strip().lower(),
        "mode": str(mode).strip().lower(),
        "ecosystem": str(ecosystem).strip().lower(),
        "backend": str(backend).strip().lower(),
        "row_count": len(rows),
        "rows": rows,
        "row_set_digest": record_set_digest(rows),
    }
    payload["payload_digest"] = payload_digest(payload)
    return payload


def write_fuzz_workspace_index(
    scratchpad: Path,
    jobs: Sequence[Mapping[str, object]],
    *,
    run_id: str,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
) -> dict[str, object]:
    """Write the single DRIVER-owned fuzz launch denominator compare-only."""

    root = Path(scratchpad)
    payload = _workspace_index_payload(
        root,
        jobs,
        run_id=run_id,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
    )
    _compare_only_json(
        root / WORKSPACE_INDEX_FILE,
        payload,
        code="WORKSPACE_INDEX_DRIFT",
    )
    return payload


def validate_fuzz_workspace_index(path: Path) -> list[str]:
    try:
        index_path = Path(path)
        payload = _read_json(index_path)
        issues: list[str] = []
        if payload.get("schema_version") != WORKSPACE_INDEX_SCHEMA:
            issues.append("WORKSPACE_INDEX_SCHEMA_INVALID")
        if payload.get("payload_digest") != payload_digest(payload):
            issues.append("WORKSPACE_INDEX_DIGEST_INVALID")
        rows = payload.get("rows")
        if not isinstance(rows, list) or not rows or len(rows) > MAX_INDEX_ROWS:
            return [*issues, "WORKSPACE_INDEX_ROWS_INVALID"]
        if payload.get("row_count") != len(rows):
            issues.append("WORKSPACE_INDEX_COUNT_INVALID")
        if payload.get("row_set_digest") != record_set_digest(
            row for row in rows if isinstance(row, Mapping)
        ):
            issues.append("WORKSPACE_INDEX_SET_DIGEST_INVALID")
        if not all(isinstance(row, Mapping) for row in rows):
            return [*issues, "WORKSPACE_INDEX_ROW_TYPE_INVALID"]
        root = index_path.parent
        observed_jobs: list[Mapping[str, object]] = []
        for row in rows:
            assert isinstance(row, Mapping)
            if row.get("row_digest") != _index_row_digest(row):
                issues.append(f"WORKSPACE_INDEX_ROW_DIGEST_INVALID:{row.get('job_id')}")
            authority_relative = str(row.get("authority_path") or "")
            observed_jobs.append({
                "agent_id": str(row.get("job_id") or ""),
                "role": str(row.get("role") or ""),
                "output": str(row.get("output") or ""),
                "fuzz_authority_path": (
                    str(root / authority_relative) if authority_relative else ""
                ),
            })
        expected = _workspace_index_payload(
            root,
            observed_jobs,
            run_id=str(payload.get("run_id") or ""),
            pipeline=str(payload.get("pipeline") or ""),
            mode=str(payload.get("mode") or ""),
            ecosystem=str(payload.get("ecosystem") or ""),
            backend=str(payload.get("backend") or ""),
        )
        if payload != expected:
            issues.append("WORKSPACE_INDEX_SEMANTICS_INVALID")
        return sorted(set(issues))
    except Exception as exc:
        return [f"WORKSPACE_INDEX_UNREADABLE:{type(exc).__name__}:{exc}"]


def resolve_fuzz_workspace_index_row(
    path: Path,
    *,
    job_id: str,
    output: str,
) -> dict[str, object]:
    """Return one authenticated launch row or fail closed on ambiguity."""

    index_path = Path(path)
    issues = validate_fuzz_workspace_index(index_path)
    if issues:
        raise FuzzWorkspaceError("WORKSPACE_INDEX_INVALID", "; ".join(issues))
    payload = _read_json(index_path)
    rows = payload.get("rows")
    if not isinstance(rows, list) or len(rows) > MAX_INDEX_ROWS:
        raise FuzzWorkspaceError("WORKSPACE_INDEX_ROWS_INVALID", str(index_path))
    matches = [
        dict(row)
        for row in rows
        if isinstance(row, Mapping)
        and str(row.get("job_id") or "") == str(job_id)
        and str(row.get("output") or "") == str(output)
    ]
    if len(matches) != 1:
        raise FuzzWorkspaceError(
            "WORKSPACE_INDEX_ROW_AMBIGUOUS",
            f"job_id={job_id!r} output={output!r} matches={len(matches)}",
        )
    return matches[0]


def _result_index_payload(
    workspace_index_path: Path,
) -> dict[str, object]:
    workspace_index = _read_json(Path(workspace_index_path))
    workspace_issues = validate_fuzz_workspace_index(Path(workspace_index_path))
    if workspace_issues:
        raise FuzzWorkspaceError(
            "WORKSPACE_INDEX_INVALID", "; ".join(workspace_issues)
        )
    root = Path(workspace_index_path).parent
    rows: list[dict[str, object]] = []
    for source_row in workspace_index["rows"]:
        if not isinstance(source_row, Mapping):
            raise FuzzWorkspaceError("RESULT_INDEX_SOURCE_ROW_INVALID", "not an object")
        output_relative = str(source_row.get("output") or "")
        output_path = root / output_relative
        _index_control_path(root, output_path, require_file=True)
        output_digest, output_size = _sha256_file(output_path)
        authority_relative = str(source_row.get("authority_path") or "")
        result_relative = str(source_row.get("result_path") or "")
        validation_issues: list[object] = []
        result: Mapping[str, object] = {}
        if authority_relative and result_relative:
            authority_path = root / authority_relative
            result_path = root / result_relative
            _index_control_path(root, authority_path, require_file=True)
            _index_control_path(root, result_path, require_file=True)
            result = _read_json(result_path)
            validation_issues.extend(validate_fuzz_workspace_result(authority_path))
        else:
            validation_issues.append("FUZZ_WORKSPACE_AUTHORITY_MISSING")
        result_issues = result.get("issues") if isinstance(result, Mapping) else []
        if isinstance(result_issues, list):
            validation_issues.extend(result_issues)
        issue_codes, issue_count = _index_issue_codes(validation_issues)
        row: dict[str, object] = {
            "job_id": str(source_row.get("job_id") or ""),
            "role": str(source_row.get("role") or ""),
            "output": output_relative,
            "output_sha256": output_digest,
            "output_size": output_size,
            "authority_path": authority_relative,
            "authority_digest": str(source_row.get("authority_digest") or ""),
            "result_path": result_relative,
            "result_digest": str(result.get("payload_digest") or ""),
            "status": (
                str(result.get("status") or "UNSCORED")
                if not validation_issues
                else "UNSCORED"
            ),
            "campaign_execution_status": str(
                result.get("campaign_execution_status") or "NOT_EXECUTED"
            ),
            "command_count": int(result.get("command_count") or 0),
            "campaign_command_count": int(result.get("campaign_command_count") or 0),
            "proof_authority": str(result.get("proof_authority") or "NONE"),
            "issue_codes": issue_codes,
            "issue_count": issue_count,
            "issues_truncated": issue_count > len(issue_codes),
        }
        row["row_digest"] = _index_row_digest(row)
        rows.append(row)
    rows.sort(key=lambda row: (str(row["job_id"]), str(row["output"])))
    payload: dict[str, object] = {
        "schema_version": RESULT_INDEX_SCHEMA,
        "run_id": str(workspace_index.get("run_id") or ""),
        "workspace_index_digest": str(workspace_index.get("payload_digest") or ""),
        "row_count": len(rows),
        "rows": rows,
        "row_set_digest": record_set_digest(rows),
    }
    payload["payload_digest"] = payload_digest(payload)
    return payload


def write_fuzz_workspace_result_index(
    workspace_index_path: Path,
) -> dict[str, object]:
    """Reconcile all fuzz leaves into one compare-only DRIVER result receipt."""

    index_path = Path(workspace_index_path)
    payload = _result_index_payload(index_path)
    _compare_only_json(
        index_path.parent / RESULT_INDEX_FILE,
        payload,
        code="RESULT_INDEX_DRIFT",
    )
    return payload


def validate_fuzz_workspace_result_index(path: Path) -> list[str]:
    try:
        result_path = Path(path)
        payload = _read_json(result_path)
        issues: list[str] = []
        if payload.get("schema_version") != RESULT_INDEX_SCHEMA:
            issues.append("RESULT_INDEX_SCHEMA_INVALID")
        if payload.get("payload_digest") != payload_digest(payload):
            issues.append("RESULT_INDEX_DIGEST_INVALID")
        expected = _result_index_payload(result_path.parent / WORKSPACE_INDEX_FILE)
        if payload != expected:
            issues.append("RESULT_INDEX_SEMANTICS_INVALID")
        return sorted(set(issues))
    except Exception as exc:
        return [f"RESULT_INDEX_UNREADABLE:{type(exc).__name__}:{exc}"]


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plamen P2-A fuzz workspace authority")
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run")
    run.add_argument("--authority", required=True)
    run.add_argument("--timeout", required=True, type=float)
    run.add_argument("--cwd-relative", default=".")
    run.add_argument("command", nargs=argparse.REMAINDER)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("--authority", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--authority", required=True)
    args = parser.parse_args(argv)
    if args.action == "run":
        command = list(args.command)
        if command and command[0] == "--":
            command = command[1:]
        return run_recorded_command(
            Path(args.authority), command, float(args.timeout),
            cwd_relative=str(args.cwd_relative),
        )
    if args.action == "finalize":
        result = finalize_fuzz_workspace(Path(args.authority))
        print(json.dumps({
            "status": result["status"],
            "result_path": str(_read_json(Path(args.authority))["result_path"]),
            "payload_digest": result["payload_digest"],
        }, sort_keys=True))
        return 0 if result["status"] == "MEASURED" else 2
    issues = validate_fuzz_workspace_authority(Path(args.authority), check_source=True)
    if issues:
        print("\n".join(issues), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "AUTHORITY_SCHEMA", "COMMAND_SCHEMA", "DEBT_SCHEMA", "RESULT_SCHEMA",
    "WORKSPACE_INDEX_SCHEMA", "RESULT_INDEX_SCHEMA",
    "WORKSPACE_INDEX_FILE", "RESULT_INDEX_FILE",
    "FuzzWorkspaceError", "finalize_fuzz_workspace",
    "mark_fuzz_workspace_unscored", "materialize_fuzz_workspace",
    "payload_digest", "record_set_digest",
    "run_recorded_command", "validate_fuzz_workspace_authority",
    "validate_fuzz_workspace_result", "write_fuzz_workspace_index",
    "validate_fuzz_workspace_index", "write_fuzz_workspace_result_index",
    "validate_fuzz_workspace_result_index", "resolve_fuzz_workspace_index_row",
]
