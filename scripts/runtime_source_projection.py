#!/usr/bin/env python3
"""Descriptor-bound source projection for a native Plamen generation.

The source tree is mutable release input.  This module can produce a candidate
manifest while writers are active, but only a separately reviewed ``FROZEN``
manifest is installation authority.  Validation and materialization never use
the source pathname after the caller has opened its root descriptor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Any, NoReturn


SCHEMA = "plamen.runtime-source-projection.v1"
POLICY_SCHEMA = "plamen.runtime-source-projection-policy.v1"
VERSION = 1
MAX_ROWS = 8192
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PATH_BYTES = 512
CHUNK = 1024 * 1024
PLATFORMS = ("darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64")
RUNTIME_ROOT = "lib/plamen/runtime"
ADAPTER_ROOT = "codex"

METHOD_ROOTS = (
    "agents", "opengrep-rules", "prompts", "rules", "skills", "commands",
    "methodology", "plamen_l1",
)
ADAPTER_TREE_ROOTS = ("agents", "skills", "commands")
RUNTIME_FIXED = (
    "VERSION", "plamen", "plamen.bat", "plamen.sh",
    "verification_policy/toolchain_runtime_closure.v1.json",
    "verification_policy/__init__.py",
    "verification_policy/js_toolchain_acquisition.v1.json",
    "verification_policy/foundry_acquisition.v1.json",
    "verification_policy/foundry_acquisition_receipt.v1.json",
    "verification_policy/foundry_runtime_source_manifest.v1.json",
    "verification_policy/apple_container_runtime_image_generation.v1.json",
    "verification_policy/opengrep_acquisition.v1.json",
    "verification_policy/opengrep_runtime_source_manifest.v1.json",
    "verification_policy/amd64_compat_acquisition.v1.json",
    "verification_policy/amd64_compat_acquisition_receipt.v1.json",
    "verification_policy/amd64_compat_runtime_source_manifest.v1.json",
    "verification_policy/medusa_acquisition.v1.json",
    "verification_policy/medusa_acquisition_receipt.v1.json",
    "verification_policy/medusa_runtime_source_manifest.v1.json",
    "verification_policy/solc_amd64_acquisition.v1.json",
    "verification_policy/solc_amd64_acquisition_receipt.v1.json",
    "verification_policy/solc_amd64_runtime_source_manifest.v1.json",
    "verification_policy/methodology_reachability.v1.json",
    "verification_policy/verification_method_registry.v1.json",
    "mcp.json.example", "codex-adapter/config.toml.example",
    "mcp-packages/package.json", "mcp-packages/package-lock.json",
    "mcp-packages/run-node-mcp.cmd", "mcp-packages/schema-sanitizer.js",
    "mcp-packages/update_config.py", "scripts/plamen_mcp_runtime.py",
)
NATIVE_REQUIRED = (
    "native/posix/plamen_guest_bootstrap.py",
    "scripts/plamen_driver.py", "scripts/posix_audit_entrypoint.py",
    "scripts/posix_native_authority_adapter.py",
    "scripts/posix_specialized_tool_worker.py",
    "scripts/report_output_routing.py",
    "scripts/native_runtime_bindings.py",
    "scripts/native_static_acquisition_policies.py",
    "scripts/native_operation4_acquisition_validation.py",
    "scripts/native_evm_static_acquisition_assets.py",
    "scripts/native_fixed_role_acquisition.py",
    "scripts/runtime_role10_acquisition.py",
    "scripts/backend_acquisition.py",
    "scripts/native_managed_evm_driver_preflight.py",
    "scripts/native_managed_evm_setup_effects.py",
    "scripts/posix_managed_evm_setup_transaction.py",
    "scripts/medusa_release_policy.py",
    "scripts/opengrep_release_policy.py",
    "verification_policy/native_backend_acquisition.v2.json",
    "verification_policy/native_runtime_bindings.v2.json",
    "verification_policy/runtime_role10_base_rootfs_acquisition.v1.json",
    "verification_policy/runtime_role10_base_rootfs_source_manifest.v1.json",
    "verification_policy/runtime_role10_debian_package_state_acquisition.v1.json",
    "verification_policy/runtime_role10_debian_package_state_source_manifest.v1.json",
    "verification_policy/runtime_role10_plamen_guest_acquisition.v1.json",
    "verification_policy/runtime_role10_cpython_acquisition.v1.json",
    "verification_policy/runtime_role10_cpython_source_manifest.v1.json",
    "verification_policy/runtime_role10_plamen_package_acquisition.v1.json",
    "verification_policy/foundry_acquisition.v1.json",
    "verification_policy/foundry_acquisition_receipt.v1.json",
    "verification_policy/foundry_runtime_source_manifest.v1.json",
    "verification_policy/amd64_compat_acquisition.v1.json",
    "verification_policy/amd64_compat_acquisition_receipt.v1.json",
    "verification_policy/amd64_compat_runtime_source_manifest.v1.json",
    "verification_policy/medusa_acquisition.v1.json",
    "verification_policy/medusa_acquisition_receipt.v1.json",
    "verification_policy/medusa_runtime_source_manifest.v1.json",
    "verification_policy/solc_amd64_acquisition.v1.json",
    "verification_policy/solc_amd64_acquisition_receipt.v1.json",
    "verification_policy/solc_amd64_runtime_source_manifest.v1.json",
    "verification_policy/apple_container_runtime_image_generation.v1.json",
    "verification_policy/opengrep_acquisition.v1.json",
    "verification_policy/opengrep_runtime_source_manifest.v1.json",
)
ADAPTER_FIXED = ("AGENTS.md",)
BACKEND_POLICY = "verification_policy/native_backend_acquisition.v2.json"
RUNTIME_CLOSURE_PATH = (
    "verification_policy/toolchain_runtime_closure.v1.json"
)
RUNTIME_CLOSURE_SCHEMA = "plamen.toolchain-runtime-closure.v1"
RUNTIME_CLOSURE_DERIVATION = "python-ast-typed-runtime-closure-v2"
RULE_PROJECTION = {
    "aptos-move-rules": ("rules",),
    "decurity-rules": ("rust", "solidity/security"),
    "opengrep-rules": ("rust", "solidity"),
}
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class ProjectionError(RuntimeError):
    pass


def _fail(message: str) -> NoReturn:
    raise ProjectionError(message) from None


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _strict_json(raw: bytes, label: str) -> Any:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_MANIFEST_BYTES:
        _fail(f"{label} is outside its byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=lambda pairs: _pairs(pairs, label),
            parse_constant=lambda value: (_fail(f"{label} contains {value}")),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is not strict JSON: {type(exc).__name__}")
    return value


def _decode_runtime_closure(raw: bytes) -> dict[str, Any]:
    """Validate the complete governed closure denominator before projection.

    The projection intentionally does not execute the mutable source-tree
    closure builder.  It does, however, require the reviewed manifest's exact
    schema, one-to-one file/asset denominator, ordering, and unique paths
    before any manifest row can enter the release roster.
    """

    closure = _strict_json(raw, "toolchain runtime closure")
    if not isinstance(closure, dict) or set(closure) != {
        "assets", "derivation", "entrypoints", "files", "manifest_control",
        "schema",
    }:
        _fail("toolchain runtime closure field set differs")
    if (
        closure["schema"] != RUNTIME_CLOSURE_SCHEMA
        or closure["derivation"] != RUNTIME_CLOSURE_DERIVATION
        or closure["manifest_control"] != {
            "kind": "control", "path": RUNTIME_CLOSURE_PATH,
        }
    ):
        _fail("toolchain runtime closure header differs")
    files = closure["files"]
    entrypoints = closure["entrypoints"]
    assets = closure["assets"]
    if (
        type(files) is not list
        or not files
        or len(files) > MAX_ROWS
        or any(type(path) is not str for path in files)
        or files != sorted(files)
        or len(files) != len(set(files))
        or RUNTIME_CLOSURE_PATH not in files
        or type(entrypoints) is not list
        or not entrypoints
        or len(entrypoints) != len(set(entrypoints))
        or any(type(path) is not str for path in entrypoints)
        or not set(entrypoints).issubset(files)
        or type(assets) is not list
        or len(assets) != len(files) - 1
    ):
        _fail("toolchain runtime closure denominator differs")
    for path in files:
        _relative(path)
    for path in entrypoints:
        _relative(path)
    asset_paths: list[str] = []
    for item in assets:
        if (
            not isinstance(item, dict)
            or set(item) != {"digest_mode", "kind", "path", "sha256"}
            or item.get("digest_mode") not in {"utf8-lf-v1", "raw-v1"}
            or item.get("kind")
            not in {"python-source", "runtime-data", "control"}
            or type(item.get("path")) is not str
            or not _HEX64.fullmatch(str(item.get("sha256", "")))
        ):
            _fail("toolchain runtime closure contains a malformed asset")
        asset_paths.append(_relative(item["path"]))
    if (
        asset_paths != sorted(asset_paths)
        or len(asset_paths) != len(set(asset_paths))
        or set(asset_paths) != set(files) - {RUNTIME_CLOSURE_PATH}
    ):
        _fail("toolchain runtime closure asset denominator differs")
    return closure


def _pairs(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            _fail(f"{label} contains a duplicate/non-string key")
        result[key] = value
    return result


def _relative(value: Any) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        _fail("projection contains an invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        _fail("projection contains an invalid relative path")
    if len(value.encode("utf-8")) > MAX_PATH_BYTES:
        _fail("projection path exceeds its byte bound")
    return value


def _root_identity(fd: int) -> dict[str, int]:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        _fail("source root descriptor is not a directory")
    return {
        "device": int(info.st_dev), "inode": int(info.st_ino),
        "mode": stat.S_IMODE(info.st_mode), "uid": int(info.st_uid),
        "gid": int(info.st_gid), "links": int(info.st_nlink),
    }


def _open_relative(root_fd: int, relative: str, *, directory: bool = False) -> int:
    parts = _relative(relative).split("/")
    current = os.dup(root_fd)
    try:
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if index != len(parts) - 1 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _read_file(root_fd: int, relative: str) -> tuple[bytes, os.stat_result]:
    fd = -1
    try:
        fd = _open_relative(root_fd, relative)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size < 0 or before.st_size > MAX_FILE_BYTES):
            _fail("source member is not an ordinary bounded single-link file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                _fail("source member exceeds its byte bound")
            chunks.append(chunk)
        after = os.fstat(fd)
        if _identity(before) != _identity(after) or total != before.st_size:
            _fail("source member changed during capture")
        return b"".join(chunks), before
    except OSError as exc:
        _fail(f"source member cannot be opened safely: {type(exc).__name__}")
    finally:
        if fd >= 0:
            os.close(fd)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev), int(info.st_ino), int(info.st_mode), int(info.st_uid),
        int(info.st_gid), int(info.st_nlink), int(info.st_size),
        int(info.st_mtime_ns), int(info.st_ctime_ns),
    )


def _walk_files(root_fd: int, relative_root: str) -> tuple[str, ...]:
    output: list[str] = []
    folded: set[str] = set()

    def walk(directory_fd: int, prefix: str) -> None:
        before = _identity(os.fstat(directory_fd))
        try:
            names = sorted(os.listdir(directory_fd), key=lambda item: item.encode("utf-8"))
        except OSError as exc:
            _fail(f"source directory census failed: {type(exc).__name__}")
        for name in names:
            if type(name) is not str or name in {"", ".", ".."} or "/" in name or "\x00" in name:
                _fail("source directory contains an invalid name")
            relative = f"{prefix}/{name}"
            _relative(relative)
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                _fail(f"source entry census failed: {type(exc).__name__}")
            if stat.S_ISDIR(info.st_mode):
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    walk(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    _fail("source tree contains a multiply-linked file")
                key = relative.casefold()
                if key in folded:
                    _fail("source tree contains a case-colliding file")
                folded.add(key)
                output.append(relative)
            else:
                _fail("source tree contains a link or special entry")
        if _identity(os.fstat(directory_fd)) != before:
            _fail("source directory changed during census")

    directory = _open_relative(root_fd, relative_root, directory=True)
    try:
        walk(directory, relative_root)
    finally:
        os.close(directory)
    return tuple(output)


def _release_roster(root_fd: int) -> tuple[dict[str, Any], dict[str, tuple[str, str]]]:
    closure_raw, _ = _read_file(
        root_fd, RUNTIME_CLOSURE_PATH
    )
    closure = _decode_runtime_closure(closure_raw)
    assets = closure["assets"]
    runtime: dict[str, str] = {path: "runtime-fixed" for path in RUNTIME_FIXED}
    closure_mismatches: list[str] = []
    for item in assets:
        if (not isinstance(item, dict) or set(item) != {"digest_mode", "kind", "path", "sha256"}
                or item.get("digest_mode") not in {"utf8-lf-v1", "raw-v1"}
                or item.get("kind") not in {"python-source", "runtime-data", "control"}
                or type(item.get("path")) is not str or not _HEX64.fullmatch(str(item.get("sha256", "")))):
            _fail("toolchain runtime closure contains a malformed asset")
        path = _relative(item["path"])
        if path in runtime and runtime[path] == "runtime-closure-asset":
            _fail("toolchain runtime closure contains a duplicate asset")
        asset_raw, _ = _read_file(root_fd, path)
        try:
            canonical = (
                asset_raw.decode("utf-8", "strict")
                .replace("\r\n", "\n").encode("utf-8")
                if item["digest_mode"] == "utf8-lf-v1" else asset_raw
            )
        except UnicodeError:
            _fail("toolchain runtime closure text asset is not UTF-8")
        if hashlib.sha256(canonical).hexdigest() != item["sha256"]:
            closure_mismatches.append(path)
        runtime[path] = "runtime-closure-asset"
    for root in METHOD_ROOTS:
        if root == "opengrep-rules":
            continue
        for path in _walk_files(root_fd, root):
            runtime[path] = "runtime-methodology-tree"
    runtime["opengrep-rules/rule-tree-authority.v1.json"] = (
        "runtime-rule-projection"
    )
    for tree, prefixes in RULE_PROJECTION.items():
        for prefix in prefixes:
            selected = f"opengrep-rules/{tree}/{prefix}"
            for relative in _walk_files(root_fd, selected):
                runtime[relative] = "runtime-rule-projection"
    for path in NATIVE_REQUIRED:
        runtime[path] = "native-runtime-required"
    adapter: dict[str, str] = {
        f"codex-adapter/{path}": "codex-adapter-fixed" for path in ADAPTER_FIXED
    }
    for root in ADAPTER_TREE_ROOTS:
        source_root = f"codex-adapter/{root}"
        for path in _walk_files(root_fd, source_root):
            adapter[path] = "codex-adapter-tree"
    overlap = set(runtime) & set(adapter)
    if overlap:
        _fail("runtime and adapter source rosters overlap")
    roster = {path: (RUNTIME_ROOT, path) for path in runtime}
    roster.update({
        path: (ADAPTER_ROOT, path[len("codex-adapter/"):]) for path in adapter
    })
    policy = {
        "adapter_fixed": list(ADAPTER_FIXED),
        "adapter_tree_roots": list(ADAPTER_TREE_ROOTS),
        "closure_authority_complete": not closure_mismatches,
        "closure_mismatch_paths": closure_mismatches,
        "method_tree_roots": list(METHOD_ROOTS),
        "native_required": list(NATIVE_REQUIRED),
        "rule_projection": {
            key: list(value) for key, value in sorted(RULE_PROJECTION.items())
        },
        "runtime_fixed": list(RUNTIME_FIXED),
        "schema": POLICY_SCHEMA,
        "selection": "governed-runtime-closure-and-rule-projection-v1",
    }
    roles = {**runtime, **adapter}
    return policy, {path: (roles[path], *roster[path]) for path in roster}


def generate_candidate(source_root_fd: int, *, source_commit: str) -> bytes:
    if type(source_commit) is not str or not _HEX40.fullmatch(source_commit):
        _fail("source commit is not an exact lowercase Git object ID")
    root_before = _root_identity(source_root_fd)
    policy, roster = _release_roster(source_root_fd)
    rows: list[dict[str, Any]] = []
    total = 0
    destination_keys: set[str] = set()
    for source_path in sorted(roster, key=lambda item: item.encode("utf-8")):
        role, destination_root, destination_path = roster[source_path]
        raw, info = _read_file(source_root_fd, source_path)
        total += len(raw)
        if len(rows) >= MAX_ROWS or total > MAX_TOTAL_BYTES:
            _fail("runtime projection exceeds its census bound")
        key = f"{destination_root}/{destination_path}".casefold()
        if key in destination_keys:
            _fail("runtime projection contains a case-colliding destination")
        destination_keys.add(key)
        source_mode = stat.S_IMODE(info.st_mode)
        rows.append({
            "class": "runtime" if destination_root == RUNTIME_ROOT else "adapter",
            "destination_path": destination_path,
            "destination_root": destination_root,
            # Runtime-package manifest v2 treats projected source as data.
            # The retained interpreter/entrypoint performs execution, so no
            # projected repository byte needs a pathname-executable mode.
            "installed_mode": 0o400,
            "role": role,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "source_mode": source_mode,
            "source_path": source_path,
        })
    if _root_identity(source_root_fd) != root_before:
        _fail("source root changed during projection capture")
    backend_raw, _ = _read_file(source_root_fd, BACKEND_POLICY)
    policy_raw = canonical_json(policy)
    counts = {
        "adapter": sum(row["class"] == "adapter" for row in rows),
        "runtime": sum(row["class"] == "runtime" for row in rows),
        "total": len(rows),
    }
    manifest = {
        "backend_acquisition_policy_sha256": hashlib.sha256(backend_raw).hexdigest(),
        "counts": counts,
        "platforms": list(PLATFORMS),
        "policy": policy,
        "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
        "roster_sha256": hashlib.sha256(canonical_json(rows)).hexdigest(),
        "rows": rows,
        "schema": SCHEMA,
        "source_commit": source_commit,
        "source_root_identity": root_before,
        "state": "CANDIDATE",
        "total_bytes": total,
        "version": VERSION,
    }
    return canonical_json(manifest)


def validate_manifest(
    manifest_raw: bytes, source_root_fd: int, *, require_frozen: bool = True,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    manifest = _strict_json(manifest_raw, "runtime source projection")
    if canonical_json(manifest) != manifest_raw:
        _fail("runtime source projection is not canonical JSON")
    expected_fields = {
        "backend_acquisition_policy_sha256", "counts", "platforms", "policy",
        "policy_sha256", "roster_sha256", "rows", "schema", "source_commit",
        "source_root_identity", "state", "total_bytes", "version",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        _fail("runtime source projection field set differs")
    if manifest["schema"] != SCHEMA or manifest["version"] != VERSION:
        _fail("runtime source projection schema/version differs")
    if manifest["state"] not in {"CANDIDATE", "FROZEN"} or (require_frozen and manifest["state"] != "FROZEN"):
        _fail("runtime source projection is not frozen authority")
    if manifest["platforms"] != list(PLATFORMS):
        _fail("runtime source projection platform roster differs")
    if expected_manifest_sha256 is not None and (
        not _HEX64.fullmatch(expected_manifest_sha256)
        or hashlib.sha256(manifest_raw).hexdigest() != expected_manifest_sha256
    ):
        _fail("runtime source projection manifest digest differs")
    if manifest["source_root_identity"] != _root_identity(source_root_fd):
        _fail("runtime source projection root identity differs")
    if hashlib.sha256(canonical_json(manifest["policy"])).hexdigest() != manifest["policy_sha256"]:
        _fail("runtime source projection policy digest differs")
    backend_raw, _ = _read_file(source_root_fd, BACKEND_POLICY)
    if hashlib.sha256(backend_raw).hexdigest() != manifest["backend_acquisition_policy_sha256"]:
        _fail("native backend acquisition policy differs")
    fresh_raw = generate_candidate(source_root_fd, source_commit=manifest["source_commit"])
    fresh = _strict_json(fresh_raw, "fresh runtime source projection")
    for field in ("counts", "policy", "policy_sha256", "roster_sha256", "rows", "total_bytes"):
        if manifest[field] != fresh[field]:
            _fail(f"runtime source projection {field} differs from source")
    return manifest


def freeze_candidate(candidate_raw: bytes, source_root_fd: int) -> bytes:
    manifest = validate_manifest(candidate_raw, source_root_fd, require_frozen=False)
    if manifest["state"] != "CANDIDATE":
        _fail("only a candidate projection can be frozen")
    if manifest["policy"].get("closure_authority_complete") is not True:
        _fail("stale toolchain runtime closure cannot be frozen")
    frozen = dict(manifest)
    frozen["state"] = "FROZEN"
    return canonical_json(frozen)


def _ensure_destination_directory(root_fd: int, relative_parent: str) -> int:
    current = os.dup(root_fd)
    try:
        for component in PurePosixPath(relative_parent).parts:
            if component in {"", "."}:
                continue
            try:
                os.mkdir(component, 0o700, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            info = os.fstat(child)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                os.close(child)
                _fail("materialization destination directory is not private")
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def materialize_validated(
    manifest_raw: bytes, source_root_fd: int, runtime_destination_fd: int,
    adapter_destination_fd: int, *, expected_manifest_sha256: str,
) -> dict[str, Any]:
    manifest = validate_manifest(
        manifest_raw, source_root_fd, require_frozen=True,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    destination_info = [os.fstat(runtime_destination_fd), os.fstat(adapter_destination_fd)]
    if any(not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
           or stat.S_IMODE(info.st_mode) != 0o700 for info in destination_info):
        _fail("materialization destination root is not a preowned private directory")
    try:
        if os.listdir(runtime_destination_fd) or os.listdir(adapter_destination_fd):
            _fail("materialization destination root is not empty")
    except OSError as exc:
        _fail(f"materialization destination census failed: {type(exc).__name__}")
    observed: list[dict[str, Any]] = []
    for row in manifest["rows"]:
        destination_fd = runtime_destination_fd if row["class"] == "runtime" else adapter_destination_fd
        parent = PurePosixPath(row["destination_path"]).parent.as_posix()
        leaf = PurePosixPath(row["destination_path"]).name
        parent_fd = _ensure_destination_directory(destination_fd, parent)
        source_fd = output_fd = -1
        digest = hashlib.sha256()
        size = 0
        try:
            source_fd = _open_relative(source_root_fd, row["source_path"])
            source_before = os.fstat(source_fd)
            output_fd = os.open(
                leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600, dir_fd=parent_fd,
            )
            while True:
                chunk = os.read(source_fd, CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output_fd, view)
                    if written <= 0:
                        _fail("runtime projection write made no progress")
                    view = view[written:]
            if (_identity(os.fstat(source_fd)) != _identity(source_before)
                    or size != row["size"] or digest.hexdigest() != row["sha256"]):
                _fail("source member changed during materialization")
            os.fchmod(output_fd, row["installed_mode"])
            os.fsync(output_fd)
            installed = os.fstat(output_fd)
            if (not stat.S_ISREG(installed.st_mode) or installed.st_nlink != 1
                    or stat.S_IMODE(installed.st_mode) != row["installed_mode"]):
                _fail("materialized runtime member identity differs")
            observed.append({"destination_key": f"{row['destination_root']}/{row['destination_path']}", "sha256": digest.hexdigest(), "size": size})
        finally:
            if output_fd >= 0:
                os.close(output_fd)
            if source_fd >= 0:
                os.close(source_fd)
            os.close(parent_fd)
    os.fsync(runtime_destination_fd)
    os.fsync(adapter_destination_fd)
    return {
        "count": len(observed),
        "manifest_sha256": expected_manifest_sha256,
        "post_materialization_sha256": hashlib.sha256(canonical_json(observed)).hexdigest(),
        "total_bytes": sum(row["size"] for row in observed),
    }


def _open_root(path: str) -> int:
    absolute = os.path.abspath(path)
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in PurePosixPath(absolute).parts[1:]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_root")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    source_fd = _open_root(args.source_root)
    try:
        raw = generate_candidate(source_fd, source_commit=args.source_commit)
    finally:
        os.close(source_fd)
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        os.write(1, raw + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
