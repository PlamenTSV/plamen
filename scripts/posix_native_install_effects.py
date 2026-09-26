"""Concrete filesystem effects for the POSIX cold-install coordinator.

The Darwin builder retains compilation/signing descriptors and therefore owns
the low-level native calls.  This adapter owns their filesystem contract: it
replays the complete frozen package snapshot, recognizes only an absent or a
fully validated predecessor, derives receipt authorities from fixed installed
paths, and exposes exact rollback/cleanup callbacks to the outer transaction.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, Callable

import posix_native_install_publication as public_shim
import posix_native_install_transaction as transaction


PACKAGE_SNAPSHOT_SCHEMA = "plamen.posix-native-install.package-snapshot.v2"
PACKAGE_EFFECTS_SCHEMA = "plamen.posix-native-install.package-effects.v1"
PACKAGE_PRESTATE_SCHEMA = "plamen.posix-native-install.package-prestate.v1"
_PACKAGE_NAMESPACES = frozenset({"package-source", "managed-runtime"})
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TXID = re.compile(r"[0-9a-f]{32}")
_MAX_RECEIPT = 4 * 1024 * 1024
_MAX_PACKAGE_ROWS = 32_768
_MAX_PACKAGE_LEAF = 2 * 1024 * 1024 * 1024
_MAX_PACKAGE_TOTAL = 16 * 1024 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024
_MANAGED_EVM_RECEIPT_SCHEMA = "plamen.managed-evm-installed-generation-receipt.v1"


class PosixNativeInstallEffectsError(RuntimeError):
    """An unauthenticated or incomplete concrete install effect."""


def _fail(message: str) -> None:
    raise PosixNativeInstallEffectsError(message) from None


def _safe_relative(value: object) -> str:
    if type(value) is not str or not value or "\x00" in value or "\\" in value:
        _fail("package snapshot path is malformed")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        _fail("package snapshot path is unsafe")
    return value


def _read_direct(path: Path, maximum: int) -> tuple[os.stat_result, bytes]:
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.getuid()}
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 <= before.st_size <= maximum
        ):
            _fail("installed artifact authority differs")
        raw = b""
        while len(raw) < before.st_size:
            part = os.read(fd, before.st_size - len(raw))
            if not part:
                break
            raw += part
        after = os.fstat(fd)
    except OSError:
        _fail("installed artifact is unavailable")
    finally:
        if fd >= 0:
            os.close(fd)
    stable = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    if len(raw) != before.st_size or stable(before) != stable(after):
        _fail("installed artifact changed during observation")
    return before, raw


def _hash_direct(path: Path, maximum: int) -> tuple[os.stat_result, str]:
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.getuid()}
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 <= before.st_size <= maximum
        ):
            _fail("package member authority differs")
        digest = hashlib.sha256(); total = 0
        while True:
            part = os.read(fd, _COPY_CHUNK)
            if not part:
                break
            total += len(part); digest.update(part)
        after = os.fstat(fd)
    except OSError:
        _fail("package member is unavailable")
    finally:
        if fd >= 0:
            os.close(fd)
    stable = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )
    if total != before.st_size or stable(before) != stable(after):
        _fail("package member changed during observation")
    return before, digest.hexdigest()


def _artifact(
    path: Path, kind: str, *, transaction_id: str | None = None,
) -> dict[str, Any]:
    _observed, raw = _read_direct(path, _MAX_RECEIPT)
    result = {
        "schema": transaction.ARTIFACT_SCHEMA,
        "kind": kind, "path": str(path), "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if kind == "package-receipt":
        if type(transaction_id) is not str or re.fullmatch(
            r"[0-9a-f]{32}", transaction_id,
        ) is None:
            _fail("committed package transaction id is unavailable")
        result["transaction_id"] = transaction_id
    return result


def _validate_snapshot(value: object) -> dict[str, Any]:
    fields = {
        "schema", "root", "manifest_sha256", "rows",
        "interpreter_authority", "front_authority",
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != PACKAGE_SNAPSHOT_SCHEMA
        or type(value.get("root")) is not str
        or not Path(value["root"]).is_absolute()
        or _HEX64.fullmatch(value.get("manifest_sha256", "")) is None
        or type(value.get("rows")) is not list
        or not value["rows"]
        or len(value["rows"]) > _MAX_PACKAGE_ROWS
    ):
        _fail("package snapshot authority is malformed")
    root = Path(value["root"])
    if not root.is_dir() or root.is_symlink():
        _fail("package snapshot root authority differs")
    paths: set[str] = set()
    namespace_counts = {name: 0 for name in _PACKAGE_NAMESPACES}
    normalized: list[dict[str, Any]] = []
    total_size = 0
    for row in value["rows"]:
        if (
            type(row) is not dict
            or set(row) != {"namespace", "path", "mode", "size", "sha256"}
            or row.get("namespace") not in _PACKAGE_NAMESPACES
            or type(row.get("mode")) is not int
            or row["mode"] not in {0o400, 0o500}
            or type(row.get("size")) is not int
            or not 0 <= row["size"] <= _MAX_PACKAGE_LEAF
            or _HEX64.fullmatch(row.get("sha256", "")) is None
        ):
            _fail("package snapshot row is malformed")
        relative = _safe_relative(row["path"])
        key = row["namespace"] + "/" + relative
        if key in paths:
            _fail("package snapshot path is duplicated")
        paths.add(key); namespace_counts[row["namespace"]] += 1
        total_size += row["size"]
        normalized.append(dict(row))
    if total_size > _MAX_PACKAGE_TOTAL:
        _fail("package snapshot total size exceeds policy")
    if any(count <= 0 for count in namespace_counts.values()):
        _fail("package snapshot namespace denominator is incomplete")
    if not any(
        row["namespace"] == "package-source" and row["path"] == "plamen.py"
        for row in normalized
    ):
        _fail("package snapshot front is absent")
    if not any(
        row["namespace"] == "managed-runtime" and row["path"] == "bin/python"
        for row in normalized
    ):
        _fail("package snapshot managed Python is absent")
    manifest = {
        "schema": PACKAGE_SNAPSHOT_SCHEMA, "rows": normalized,
    }
    manifest_raw = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    expected_manifest = hashlib.sha256(manifest_raw).hexdigest()
    if value["manifest_sha256"] != expected_manifest:
        _fail("package snapshot manifest digest differs")
    for field in ("interpreter_authority", "front_authority"):
        authority = value[field]
        if (
            type(authority) is not dict
            or set(authority) != {
                "schema", "path", "device", "inode", "mode", "size", "sha256",
            }
            or authority.get("schema")
            != "plamen.posix-native-install.file-authority.v1"
            or type(authority.get("path")) is not str
            or not Path(authority["path"]).is_absolute()
            or any(type(authority.get(name)) is not int for name in (
                "device", "inode", "mode", "size",
            ))
            or authority["size"] <= 0
            or _HEX64.fullmatch(authority.get("sha256", "")) is None
        ):
            _fail(f"package {field} differs")
    expected_targets = {
        "interpreter_authority": ("managed-runtime", "bin/python"),
        "front_authority": ("package-source", "plamen.py"),
    }
    for field, target in expected_targets.items():
        row = next(
            (item for item in normalized
             if (item["namespace"], item["path"]) == target), None,
        )
        authority = value[field]
        if row is None or any(
            authority[name] != row[name]
            for name in ("mode", "size", "sha256")
        ):
            _fail(f"package {field} row binding differs")
    result = dict(value); result["rows"] = normalized
    return result


def _replay_snapshot(snapshot: dict[str, Any]) -> None:
    root = Path(snapshot["root"])
    files, directories = _tree_census(root)
    expected_files = {
        row["namespace"] + "/" + row["path"] for row in snapshot["rows"]
    }
    expected_directories = set(_PACKAGE_NAMESPACES)
    for path in expected_files:
        parts = PurePosixPath(path).parts
        expected_directories.update(
            str(PurePosixPath(*parts[:size]))
            for size in range(1, len(parts))
        )
    if files != expected_files or directories != expected_directories:
        _fail("package snapshot denominator differs")
    for namespace in _PACKAGE_NAMESPACES:
        _replay_tree(root / namespace, _rows_for(snapshot, namespace))


def _rows_for(snapshot: dict[str, Any], namespace: str) -> list[dict[str, Any]]:
    return [dict(row) for row in snapshot["rows"] if row["namespace"] == namespace]


def _tree_census(root: Path) -> tuple[set[str], set[str]]:
    if not root.is_dir() or root.is_symlink():
        _fail("package tree authority differs")
    files: set[str] = set(); directories: set[str] = set()
    for current, names, leaves in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        relative_root = current_path.relative_to(root)
        for name in names:
            child = current_path / name
            information = os.lstat(child)
            if (
                not stat.S_ISDIR(information.st_mode)
                or stat.S_ISLNK(information.st_mode)
                or information.st_uid != os.getuid()
                or stat.S_IMODE(information.st_mode)
                & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                _fail("package tree contains an unsafe directory")
            directories.add(str((relative_root / name).as_posix()))
        for name in leaves:
            child = current_path / name
            information = os.lstat(child)
            if not stat.S_ISREG(information.st_mode) or stat.S_ISLNK(information.st_mode):
                _fail("package tree contains a non-regular member")
            files.add(str((relative_root / name).as_posix()))
    return files, directories


def _replay_tree(root: Path, rows: list[dict[str, Any]]) -> None:
    expected_files = {row["path"] for row in rows}
    expected_directories = {
        str(PurePosixPath(row["path"]).parent) for row in rows
        if str(PurePosixPath(row["path"]).parent) != "."
    }
    expanded: set[str] = set()
    for directory in expected_directories:
        parts = PurePosixPath(directory).parts
        expanded.update(str(PurePosixPath(*parts[:size])) for size in range(1, len(parts) + 1))
    files, directories = _tree_census(root)
    if files != expected_files or directories != expanded:
        _fail("package tree denominator differs")
    for row in rows:
        observed, digest = _hash_direct(root / row["path"], _MAX_PACKAGE_LEAF)
        if (
            stat.S_IMODE(observed.st_mode) != row["mode"]
            or observed.st_size != row["size"]
            or digest != row["sha256"]
        ):
            _fail("package tree member differs")


def _copy_tree_idempotent(source: Path, destination: Path, rows: list[dict[str, Any]]) -> None:
    destination.mkdir(mode=0o700, parents=False, exist_ok=True)
    if destination.is_symlink() or not destination.is_dir():
        _fail("durable package stage authority differs")
    for row in rows:
        target = destination / row["path"]
        current = destination
        for component in PurePosixPath(row["path"]).parts[:-1]:
            current = current / component
            try:
                information = os.lstat(current)
            except FileNotFoundError:
                current.mkdir(mode=0o700)
                information = os.lstat(current)
            if (
                not stat.S_ISDIR(information.st_mode)
                or stat.S_ISLNK(information.st_mode)
                or information.st_uid != os.getuid()
                or stat.S_IMODE(information.st_mode)
                & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                _fail("durable package stage parent differs")
        if os.path.lexists(target):
            observed, digest = _hash_direct(target, _MAX_PACKAGE_LEAF)
            if (
                stat.S_IMODE(observed.st_mode) != row["mode"]
                or observed.st_size != row["size"]
                or digest != row["sha256"]
            ):
                _fail("durable package stage residue differs")
            continue
        source_fd = descriptor = -1
        try:
            source_fd = os.open(
                source / row["path"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            before = os.fstat(source_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid not in {0, os.getuid()}
                or before.st_nlink != 1
                or before.st_size != row["size"]
                or stat.S_IMODE(before.st_mode) != row["mode"]
            ):
                _fail("package stage source authority differs")
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                | os.O_NOFOLLOW, 0o600,
            )
            digest = hashlib.sha256(); total = 0
            while True:
                part = os.read(source_fd, _COPY_CHUNK)
                if not part:
                    break
                digest.update(part); total += len(part)
                view = memoryview(part)
                while view:
                    count = os.write(descriptor, view)
                    if count <= 0:
                        _fail("durable package stage write failed")
                    view = view[count:]
            after = os.fstat(source_fd)
            if (
                total != row["size"] or digest.hexdigest() != row["sha256"]
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                _fail("package stage source changed during copy")
            os.fchmod(descriptor, row["mode"]); os.fsync(descriptor)
        except OSError:
            _fail("durable package stage publication failed")
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            if descriptor >= 0:
                os.close(descriptor)
    _replay_tree(destination, rows)


def _remove_exact_tree(root: Path, rows: list[dict[str, Any]]) -> None:
    if not os.path.lexists(root):
        return
    _replay_tree(root, rows)
    for row in sorted(rows, key=lambda item: len(PurePosixPath(item["path"]).parts), reverse=True):
        os.unlink(root / row["path"])
    _files, directories = _tree_census(root)
    for relative in sorted(directories, key=lambda value: len(PurePosixPath(value).parts), reverse=True):
        os.rmdir(root / relative)
    os.rmdir(root)


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _read_effects_state(path: Path) -> dict[str, Any] | None:
    if not os.path.lexists(path):
        return None
    _info, raw = _read_direct(path, _MAX_RECEIPT)
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError):
        _fail("package effects state is malformed")
    if _canonical(value) != raw or type(value) is not dict:
        _fail("package effects state is not canonical")
    return value


def _write_effects_state(path: Path, value: dict[str, Any]) -> None:
    raw = _canonical(value)
    temporary = path.with_name("." + path.name + ".next")
    if os.path.lexists(temporary):
        _info, existing = _read_direct(temporary, _MAX_RECEIPT)
        if existing != raw:
            _fail("package effects transition residue differs")
    else:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | os.O_NOFOLLOW, 0o600,
        )
        try:
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    _fail("package effects state write failed")
                view = view[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    os.replace(temporary, path)


def _ensure_home_directories(home: Path, components: tuple[str, ...]) -> Path:
    current = home
    for component in components:
        current = current / component
        try:
            information = os.lstat(current)
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            information = os.lstat(current)
        if (
            not stat.S_ISDIR(information.st_mode)
            or stat.S_ISLNK(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            _fail("managed runtime parent authority differs")
    return current


def _directory_identity(path: Path) -> dict[str, int]:
    try:
        information = os.lstat(path)
    except OSError:
        _fail("managed runtime directory authority is unavailable")
    if (
        not stat.S_ISDIR(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail("managed runtime directory authority differs")
    return {
        "device": int(information.st_dev), "inode": int(information.st_ino),
        "mode": int(information.st_mode), "uid": int(information.st_uid),
    }


def _same_content(path: Path, authority: dict[str, Any]) -> bool:
    try:
        information, digest = _hash_direct(path, _MAX_PACKAGE_LEAF)
    except PosixNativeInstallEffectsError:
        return False
    return (
        stat.S_IMODE(information.st_mode) == authority["mode"]
        and information.st_size == authority["size"]
        and digest == authority["sha256"]
    )


def _retained_regular_authority(path: Path, label: str) -> dict[str, Any]:
    try:
        information, raw = _read_direct(path, _MAX_RECEIPT)
    except PosixNativeInstallEffectsError:
        _fail(f"retained {label} authority differs")
    return {
        "schema": "plamen.posix-native-install.retained-input.v1",
        "kind": "regular", "path": str(path),
        "device": int(information.st_dev), "inode": int(information.st_ino),
        "mode": stat.S_IMODE(information.st_mode),
        "uid": int(information.st_uid), "size": int(information.st_size),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _retained_directory_authority(
    path: Path, label: str, *, private: bool,
) -> dict[str, Any]:
    try:
        information = os.lstat(path)
    except OSError:
        _fail(f"retained {label} authority is unavailable")
    mode = stat.S_IMODE(information.st_mode)
    if (
        not stat.S_ISDIR(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_uid != os.getuid()
        or mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (private and mode & 0o077)
    ):
        _fail(f"retained {label} authority differs")
    return {
        "schema": "plamen.posix-native-install.retained-input.v1",
        "kind": "directory", "path": str(path),
        "device": int(information.st_dev), "inode": int(information.st_ino),
        "mode": mode, "uid": int(information.st_uid),
    }


class ManagedEVMInstallInputs:
    """Explicit installer custody for one host managed-EVM generation.

    Paths are never derived from HOME.  The native provisioner opens and
    retains these exact five inputs for its mutation, while this wrapper binds
    their pre/post identities into the outer install transaction.  The native
    runtime capability remains opaque and is deliberately absent from every
    serialized stage or receipt.
    """

    __slots__ = (
        "policy_path", "managed_root", "project_root",
        "acquisition_receipt_path", "installed_receipt_path",
        "native_runtime_authority", "_binding", "_frozen",
    )

    def __init__(
        self, *, policy_path: Path, managed_root: Path, project_root: Path,
        acquisition_receipt_path: Path, installed_receipt_path: Path,
        native_runtime_authority: object,
    ):
        object.__setattr__(self, "_frozen", False)
        supplied = {
            "policy_path": policy_path, "managed_root": managed_root,
            "project_root": project_root,
            "acquisition_receipt_path": acquisition_receipt_path,
            "installed_receipt_path": installed_receipt_path,
        }
        normalized: dict[str, Path] = {}
        for name, value in supplied.items():
            path = Path(value).absolute()
            if not path.is_absolute() or path.is_symlink():
                _fail(f"managed EVM {name} is not an explicit direct path")
            if name != "installed_receipt_path":
                try:
                    if path.resolve(strict=True) != path:
                        _fail(f"managed EVM {name} uses an aliased ancestor")
                except OSError:
                    _fail(f"managed EVM {name} is unavailable")
            normalized[name] = path
            object.__setattr__(self, name, path)
        if native_runtime_authority is None:
            _fail("managed EVM native runtime authority is absent")
        object.__setattr__(self, "native_runtime_authority", native_runtime_authority)
        root = normalized["managed_root"]
        binding = {
            "schema": "plamen.posix-native-install.managed-evm-inputs.v1",
            "policy": _retained_regular_authority(
                normalized["policy_path"], "managed EVM policy",
            ),
            "project": _retained_directory_authority(
                normalized["project_root"], "audited project root", private=False,
            ),
            "managed_root": _retained_directory_authority(
                root, "managed EVM root", private=True,
            ),
            "cache": _retained_directory_authority(
                root / "cache", "managed EVM cache", private=True,
            ),
            "generations": _retained_directory_authority(
                root / "generations", "managed EVM generations", private=True,
            ),
            "acquisition_receipt": _retained_regular_authority(
                normalized["acquisition_receipt_path"],
                "managed EVM acquisition receipt",
            ),
            "installed_receipt_path": str(normalized["installed_receipt_path"]),
        }
        object.__setattr__(self, "_binding", binding)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, _name: str, _value: object) -> None:
        if getattr(self, "_frozen", False):
            raise TypeError("managed EVM install inputs are immutable")
        object.__setattr__(self, _name, _value)

    def replay_binding(self) -> dict[str, Any]:
        root = self.managed_root
        observed = {
            "schema": "plamen.posix-native-install.managed-evm-inputs.v1",
            "policy": _retained_regular_authority(
                self.policy_path, "managed EVM policy",
            ),
            "project": _retained_directory_authority(
                self.project_root, "audited project root", private=False,
            ),
            "managed_root": _retained_directory_authority(
                root, "managed EVM root", private=True,
            ),
            "cache": _retained_directory_authority(
                root / "cache", "managed EVM cache", private=True,
            ),
            "generations": _retained_directory_authority(
                root / "generations", "managed EVM generations", private=True,
            ),
            "acquisition_receipt": _retained_regular_authority(
                self.acquisition_receipt_path,
                "managed EVM acquisition receipt",
            ),
            "installed_receipt_path": str(self.installed_receipt_path),
        }
        if observed != self._binding:
            _fail("managed EVM retained inputs changed")
        return dict(observed)


class DarwinColdInstallEffects:
    """Real coordinator adapter around retained builder/package operations.

    Every supplied operation is mandatory.  In particular, package rollback
    may not be omitted merely because the legacy package transaction can commit:
    without exact post-commit compensation the combined production transaction
    must remain blocked.

    Authority handoff contract:

    * ``package_snapshot`` is the exact v2 package-source/managed-runtime
      census.  Its canonical manifest, immutable predecessor decision, and
      outer cold transaction id are bound by ``prestate_sha256`` before a
      callback sees a durable path.
    * ``package_commit(home, durable_source, stage, source)`` receives the
      no-follow-replayed legacy source root and must return only after the
      corresponding ``plamen.codex_install.v2`` receipt is COMMITTED.
      ``package_validate(home)`` returns that receipt's exact transaction id.
    * ``package_rollback(home, receipt, prior)`` receives both the exact
      successor artifact (including its package transaction id) and the exact
      ABSENT/VERIFIED predecessor captured before staging.  It must invoke the
      package front's authenticated post-COMMITTED rollback and return True.
    * Managed-runtime publication records the staged directory device/inode
      before rename.  Rollback removes only that exact generation and refuses
      a missing, drifted, or independently-created same-byte third state.
    * Native callbacks receive the outer source authority plus the exact
      package receipt.  Their install/deployment receipts remain independently
      validated before the public launcher is eligible for publication.
    * ``managed_evm_inputs`` binds explicit policy/project/cache/generations/
      acquisition authorities.  The existing managed provisioner consumes
      them only after package and native commit.  A native signer publishes a
      durable installed-generation receipt; validation re-admits that receipt
      to a fresh opaque ``ManagedEVMGenerationAuthority``.  Neither paths nor a
      serialized Python object are audit execution authority.
    """

    def __init__(
        self, *, home: Path, package_snapshot: object,
        package_commit: Callable[..., object],
        package_validate: Callable[..., object],
        package_rollback: Callable[..., object],
        native_stage: Callable[..., object],
        native_stage_validate: Callable[..., object],
        native_commit: Callable[..., object],
        native_validate: Callable[..., object],
        native_rollback: Callable[..., object],
        cleanup: Callable[..., object],
        managed_evm_inputs: ManagedEVMInstallInputs | None = None,
        managed_evm_receipt_publish: Callable[..., object] | None = None,
        managed_evm_receipt_validate: Callable[..., object] | None = None,
        managed_evm_receipt_rollback: Callable[..., object] | None = None,
        managed_evm_provision: Callable[..., object] | None = None,
        managed_evm_require: Callable[..., object] | None = None,
    ):
        self.home = home.absolute()
        if not self.home.is_dir() or self.home.is_symlink():
            _fail("install account home authority differs")
        self.snapshot = _validate_snapshot(package_snapshot)
        self.managed_evm_inputs = managed_evm_inputs
        if managed_evm_inputs is not None and type(
            managed_evm_inputs
        ) is not ManagedEVMInstallInputs:
            _fail("managed EVM installer custody is forged")
        if managed_evm_inputs is not None and (
            managed_evm_provision is None or managed_evm_require is None
        ):
            try:
                import managed_evm_python_toolchain as managed_evm_toolchain
            except ImportError:
                _fail("managed EVM provisioner is unavailable")
            if managed_evm_provision is None:
                managed_evm_provision = (
                    managed_evm_toolchain.provision_managed_evm_generation_authority
                )
            if managed_evm_require is None:
                managed_evm_require = (
                    managed_evm_toolchain.require_managed_evm_generation_authority
                )
        managed_operations = {
            "managed_evm_provision": managed_evm_provision,
            "managed_evm_require": managed_evm_require,
            "managed_evm_receipt_publish": managed_evm_receipt_publish,
            "managed_evm_receipt_validate": managed_evm_receipt_validate,
            "managed_evm_receipt_rollback": managed_evm_receipt_rollback,
        }
        if managed_evm_inputs is not None and any(
            not callable(value) for value in managed_operations.values()
        ):
            _fail("managed EVM setup effect roster is incomplete")
        operations = {
            "package_commit": package_commit,
            "package_validate": package_validate,
            "package_rollback": package_rollback,
            "native_stage": native_stage,
            "native_stage_validate": native_stage_validate,
            "native_commit": native_commit,
            "native_validate": native_validate,
            "native_rollback": native_rollback,
            "cleanup": cleanup,
        }
        if any(not callable(value) for value in operations.values()):
            _fail("retained install effect roster is incomplete")
        self._operations = operations
        self._operations.update(managed_operations)
        self.package_path = self.home / ".codex" / ".plamen-codex-install.json"
        self.native_path = (
            self.home / ".local/share/plamen/share/plamen/native-install-receipt-v2.bin"
        )
        self.deployment_path = (
            self.home / ".local/share/plamen/share/plamen/native-deployment-receipt-v2.bin"
        )
        self.public_path = self.home / ".local/bin/plamen"
        self.runtime_root = self.home / ".local/share/plamen/runtime/py312"
        self.managed_evm_receipt_path = (
            managed_evm_inputs.installed_receipt_path
            if managed_evm_inputs is not None else None
        )
        self._active_transaction_id: str | None = None
        self._managed_evm_generation_authority: object | None = None

    def _managed_evm_stage_binding(self) -> dict[str, Any]:
        if self.managed_evm_inputs is None:
            _fail("managed EVM project setup inputs are absent")
        binding = self.managed_evm_inputs.replay_binding()
        binding["interpreter_authority"] = dict(
            self.snapshot["interpreter_authority"]
        )
        return binding

    def _managed_evm_receipt(self) -> dict[str, Any]:
        if self.managed_evm_receipt_path is None:
            _fail("managed EVM installed-generation receipt path is absent")
        return _artifact(
            self.managed_evm_receipt_path,
            "managed-evm-generation-receipt",
        )

    def managed_evm_generation_authority(self) -> object:
        """Return only the freshly admitted opaque process-local authority."""
        authority = self._managed_evm_generation_authority
        if authority is None:
            _fail("managed EVM generation has not been admitted")
        self._operations["managed_evm_require"](authority)
        return authority

    def observe_managed_evm_setup_prestate(
        self, home: Path,
    ) -> dict[str, Any]:
        if self.managed_evm_inputs is None:
            _fail("managed EVM project setup inputs are absent")
        installed = self.observe_prior(home)
        if installed["state"] != "VERIFIED":
            _fail("managed EVM setup requires an authenticated native install")
        package = installed["package_receipt"]
        native = {
            "install_receipt": installed["native_install_receipt"],
            "deployment_receipt": installed["deployment_receipt"],
        }
        prior = None
        if os.path.lexists(self.managed_evm_receipt_path):
            prior = self._managed_evm_receipt()
            admitted = self._operations["managed_evm_receipt_validate"](
                self.home, prior, None, package, native,
                self.managed_evm_inputs,
            )
            self._operations["managed_evm_require"](admitted)
            self._managed_evm_generation_authority = admitted
        binding = self._managed_evm_stage_binding()
        return {
            "schema": "plamen.posix-managed-evm-setup.prestate.v1",
            "home": str(self.home), "package_receipt": package,
            "native_install_receipt": native["install_receipt"],
            "deployment_receipt": native["deployment_receipt"],
            "prior_managed_evm_generation_receipt": prior,
            "input_binding_sha256": hashlib.sha256(
                _canonical(binding)
            ).hexdigest(),
        }

    def _validate_managed_evm_setup_prestate(
        self, prestate: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        current = self.observe_prior(self.home)
        package = current["package_receipt"]
        native = {
            "install_receipt": current["native_install_receipt"],
            "deployment_receipt": current["deployment_receipt"],
        }
        if (
            current["state"] != "VERIFIED"
            or package != prestate.get("package_receipt")
            or native["install_receipt"] != prestate.get("native_install_receipt")
            or native["deployment_receipt"] != prestate.get("deployment_receipt")
            or hashlib.sha256(
                _canonical(self._managed_evm_stage_binding())
            ).hexdigest() != prestate.get("input_binding_sha256")
        ):
            _fail("managed EVM setup installed predecessor changed")
        return package, native

    def stage_managed_evm_setup(
        self, home: Path, transaction_root: Path, prestate: dict[str, Any],
    ) -> dict[str, Any]:
        if home.absolute() != self.home or not transaction_root.is_dir():
            _fail("managed EVM setup stage destination differs")
        self._validate_managed_evm_setup_prestate(prestate)
        transaction_id = transaction_root.name
        self._active_transaction_id = transaction_id
        payload = {
            "schema": "plamen.posix-managed-evm-setup.stage-binding.v1",
            "transaction_id": transaction_id,
            "prestate": prestate,
            "inputs": self._managed_evm_stage_binding(),
        }
        return {
            "schema": transaction.STAGE_SCHEMA, "kind": "managed-evm",
            "transaction_id": transaction_id,
            "manifest_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
            "artifact_count": 7,
        }

    def validate_managed_evm_setup_stage(
        self, stage: dict[str, Any], prestate: dict[str, Any],
    ) -> None:
        self._validate_managed_evm_setup_prestate(prestate)
        transaction_id = stage.get("transaction_id", "")
        self._active_transaction_id = transaction_id
        payload = {
            "schema": "plamen.posix-managed-evm-setup.stage-binding.v1",
            "transaction_id": transaction_id, "prestate": prestate,
            "inputs": self._managed_evm_stage_binding(),
        }
        if (
            stage.get("kind") != "managed-evm"
            or stage.get("artifact_count") != 7
            or stage.get("manifest_sha256")
            != hashlib.sha256(_canonical(payload)).hexdigest()
        ):
            _fail("managed EVM setup stage authority differs")

    def commit_managed_evm_setup(
        self, stage: dict[str, Any], prestate: dict[str, Any],
    ) -> dict[str, Any]:
        self.validate_managed_evm_setup_stage(stage, prestate)
        package, native = self._validate_managed_evm_setup_prestate(prestate)
        inputs = self.managed_evm_inputs
        if inputs is None:
            _fail("managed EVM project setup inputs are absent")
        authority = self._operations["managed_evm_provision"](
            inputs.policy_path,
            Path(self.snapshot["interpreter_authority"]["path"]),
            inputs.managed_root,
            acquisition_receipt_path=inputs.acquisition_receipt_path,
            project_root=inputs.project_root,
            native_runtime_authority=inputs.native_runtime_authority,
        )
        authority_binding = self._operations["managed_evm_require"](authority)
        if not isinstance(authority_binding, Mapping):
            _fail("managed EVM provisioner returned no opaque authority binding")
        result = self._operations["managed_evm_receipt_publish"](
            self.home, inputs.installed_receipt_path,
            stage["transaction_id"], authority, dict(authority_binding),
            self._managed_evm_stage_binding(), package, native,
        )
        if type(result) is not dict or result.get("schema") != _MANAGED_EVM_RECEIPT_SCHEMA:
            _fail("managed EVM installed-generation signer returned no authority")
        receipt = self._managed_evm_receipt()
        self.validate_managed_evm_setup_receipt(receipt, stage, prestate)
        return receipt

    def validate_managed_evm_setup_receipt(
        self, receipt: dict[str, Any], stage: dict[str, Any] | None,
        prestate: dict[str, Any],
    ) -> None:
        package, native = self._validate_managed_evm_setup_prestate(prestate)
        if self._managed_evm_receipt() != receipt:
            _fail("managed EVM installed-generation receipt changed")
        admitted = self._operations["managed_evm_receipt_validate"](
            self.home, receipt, stage, package, native,
            self.managed_evm_inputs,
        )
        self._operations["managed_evm_require"](admitted)
        self._managed_evm_generation_authority = admitted

    def rollback_managed_evm_setup(
        self, receipt: dict[str, Any] | None, stage: dict[str, Any],
        prestate: dict[str, Any],
    ) -> None:
        self.validate_managed_evm_setup_stage(stage, prestate)
        if receipt is not None and self._managed_evm_receipt() != receipt:
            _fail("managed EVM setup rollback successor differs")
        result = self._operations["managed_evm_receipt_rollback"](
            self.home, receipt, stage,
            prestate["prior_managed_evm_generation_receipt"],
            self.managed_evm_inputs,
        )
        if result is not True:
            _fail("managed EVM setup authenticated rollback is incomplete")
        self._managed_evm_generation_authority = None

    def _transaction_root(self, transaction_id: str) -> Path:
        if _TXID.fullmatch(transaction_id or "") is None:
            _fail("package transaction id is malformed")
        return self.home.joinpath(*transaction.CONTROL_SUFFIX, transaction_id)

    def _stage_roots(self, transaction_id: str) -> tuple[Path, Path, Path, Path]:
        root = self._transaction_root(transaction_id)
        package_stage = root / "package-stage"
        return (
            package_stage,
            package_stage / "package-source",
            package_stage / "managed-runtime",
            root / "managed-runtime.next",
        )

    def _state_path(self, transaction_id: str) -> Path:
        return self._transaction_root(transaction_id) / "package-effects.json"

    def _prestate_path(self, transaction_id: str) -> Path:
        return self._transaction_root(transaction_id) / "package-prestate.json"

    def _load_prestate(self, transaction_id: str) -> tuple[dict[str, Any], str]:
        path = self._prestate_path(transaction_id)
        value = _read_effects_state(path)
        fields = {
            "schema", "transaction_id", "manifest_sha256", "managed_action",
            "prior",
        }
        if (
            type(value) is not dict or set(value) != fields
            or value.get("schema") != PACKAGE_PRESTATE_SCHEMA
            or value.get("transaction_id") != transaction_id
            or value.get("manifest_sha256") != self.snapshot["manifest_sha256"]
            or value.get("managed_action") not in {"CREATE", "REUSE"}
            or type(value.get("prior")) is not dict
            or value["prior"].get("schema") != transaction.PRIOR_SCHEMA
            or value["prior"].get("state") not in {"ABSENT", "VERIFIED"}
        ):
            _fail("package effects prestate differs")
        raw = _canonical(value)
        return dict(value), hashlib.sha256(raw).hexdigest()

    def _validate_effects_state(
        self, value: object, transaction_id: str,
    ) -> dict[str, Any]:
        fields = {
            "schema", "transaction_id", "manifest_sha256", "phase",
            "managed_action", "prior", "package_receipt", "prestate_sha256",
            "managed_identity",
        }
        if (
            type(value) is not dict or set(value) != fields
            or value.get("schema") != PACKAGE_EFFECTS_SCHEMA
            or value.get("transaction_id") != transaction_id
            or value.get("manifest_sha256") != self.snapshot["manifest_sha256"]
            or value.get("phase") not in {
                "ARMED", "PACKAGE_COMMITTED", "RUNTIME_PUBLISHING",
                "COMMITTED", "ROLLED_BACK", "BLOCKED_THIRD_STATE",
            }
            or value.get("managed_action") not in {"CREATE", "REUSE"}
            or _HEX64.fullmatch(value.get("prestate_sha256", "")) is None
            or type(value.get("prior")) is not dict
            or value["prior"].get("schema") != transaction.PRIOR_SCHEMA
            or value["prior"].get("state") not in {"ABSENT", "VERIFIED"}
            or (
                value["phase"] in {
                    "PACKAGE_COMMITTED", "RUNTIME_PUBLISHING", "COMMITTED",
                    "BLOCKED_THIRD_STATE",
                }
                and type(value.get("package_receipt")) is not dict
            )
            or (value["phase"] == "ARMED" and value.get("package_receipt") is not None)
        ):
            _fail("package effects state differs")
        identity = value.get("managed_identity")
        identity_required = (
            value["managed_action"] == "CREATE"
            and value["phase"] in {"RUNTIME_PUBLISHING", "COMMITTED"}
        )
        if (
            (identity_required and (
                type(identity) is not dict
                or set(identity) != {"device", "inode", "mode", "uid"}
                or any(type(identity.get(name)) is not int for name in identity)
            ))
            or (not identity_required and identity is not None)
        ):
            _fail("package effects managed runtime identity differs")
        prestate, prestate_sha256 = self._load_prestate(transaction_id)
        if (
            value["prestate_sha256"] != prestate_sha256
            or value["prior"] != prestate["prior"]
            or value["managed_action"] != prestate["managed_action"]
        ):
            _fail("package effects immutable prestate binding differs")
        if value["managed_action"] == "REUSE":
            _replay_tree(self.runtime_root, _rows_for(self.snapshot, "managed-runtime"))
        return dict(value)

    def _load_effects_state(self, transaction_id: str) -> dict[str, Any]:
        value = _read_effects_state(self._state_path(transaction_id))
        if value is None:
            _fail("package effects state is absent")
        return self._validate_effects_state(value, transaction_id)

    def _write_state(self, value: dict[str, Any]) -> dict[str, Any]:
        validated = self._validate_effects_state(value, value.get("transaction_id", ""))
        _write_effects_state(self._state_path(validated["transaction_id"]), validated)
        return validated

    def _validate_installed_targets(self) -> None:
        managed_rows = _rows_for(self.snapshot, "managed-runtime")
        _replay_tree(self.runtime_root, managed_rows)
        if not _same_content(
            Path(self.snapshot["interpreter_authority"]["path"]),
            self.snapshot["interpreter_authority"],
        ):
            _fail("installed managed Python differs")
        if not _same_content(
            Path(self.snapshot["front_authority"]["path"]),
            self.snapshot["front_authority"],
        ):
            _fail("installed package front differs")

    def _validate_relocated_runtime(self, transaction_id: str) -> None:
        self._validate_installed_targets()
        forbidden_prefixes = tuple(os.fsencode(str(path)) for path in (
            self._transaction_root(transaction_id), Path(self.snapshot["root"]),
        )) + (b"/dev/fd/", b"/proc/self/fd/")
        for row in _rows_for(self.snapshot, "managed-runtime"):
            if row["path"] == "pyvenv.cfg" or row["path"].startswith("bin/"):
                path = self.runtime_root / row["path"]
                _observed, raw = _read_direct(path, min(_MAX_PACKAGE_LEAF, 8 * 1024 * 1024))
                if any(prefix in raw for prefix in forbidden_prefixes):
                    _fail("managed runtime retains its transaction-stage prefix")
        python = Path(self.snapshot["interpreter_authority"]["path"])
        front = Path(self.snapshot["front_authority"]["path"])
        closed_environment = {
            "HOME": str(self.home), "LANG": "C", "LC_ALL": "C",
            "PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0",
        }
        probe = subprocess.run(
            [str(python), "-I", "-B", "-c",
             "import InquirerPy,jsonschema,mcp,pathlib,pydantic,rich,sys;"
             "from google import protobuf;"
             "p=pathlib.Path(sys.prefix).absolute();"
             "e=pathlib.Path(sys.executable).absolute();"
             "raise SystemExit(0 if p==pathlib.Path(sys.argv[1]).absolute() "
             "and e==pathlib.Path(sys.argv[2]).absolute() else 91)",
             str(self.runtime_root), str(python)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=closed_environment, cwd=self.home,
            timeout=30,
        )
        if probe.returncode != 0 or len(probe.stdout) > 64 * 1024:
            _fail("published managed Python relocation probe failed")
        front_probe = subprocess.run(
            [str(python), "-I", "-B", str(front), "--version"],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=closed_environment, cwd=self.home,
            timeout=30,
        )
        if front_probe.returncode != 0 or len(front_probe.stdout) > 64 * 1024:
            _fail("published package front probe failed")

    def _package_receipt(self) -> dict[str, Any]:
        result = self._operations["package_validate"](self.home)
        if type(result) is not dict:
            _fail("committed package validator returned no authority")
        return _artifact(
            self.package_path, "package-receipt",
            transaction_id=result.get("transaction_id"),
        )

    def _native_receipts(self, package: dict[str, Any]) -> dict[str, Any]:
        result = self._operations["native_validate"](self.home, package)
        if type(result) is not dict:
            _fail("native receipt validator returned no authority")
        return {
            "install_receipt": _artifact(
                self.native_path, "native-install-receipt",
            ),
            "deployment_receipt": _artifact(
                self.deployment_path, "deployment-receipt",
            ),
        }

    def observe_prior(self, home: Path) -> dict[str, Any]:
        if home.absolute() != self.home:
            _fail("install effects account home differs")
        paths = (
            self.package_path, self.native_path, self.deployment_path,
            self.public_path, self.runtime_root,
        )
        present = tuple(os.path.lexists(path) for path in paths)
        if not any(present):
            result = {
                "schema": transaction.PRIOR_SCHEMA, "state": "ABSENT",
                "package_receipt": None, "native_install_receipt": None,
                "deployment_receipt": None, "public_launcher": None,
            }
            self._observed_prior = result
            return result
        if not all(present):
            _fail("existing package/native installation is partial")
        package = self._package_receipt()
        self._validate_installed_targets()
        native = self._native_receipts(package)
        public = public_shim.observe_file_authority(
            str(self.public_path), expected_mode=0o700,
        )
        result = {
            "schema": transaction.PRIOR_SCHEMA, "state": "VERIFIED",
            "package_receipt": package,
            "native_install_receipt": native["install_receipt"],
            "deployment_receipt": native["deployment_receipt"],
            "public_launcher": public,
        }
        self._observed_prior = result
        return result

    def stage_package(
        self, home: Path, transaction_root: Path, source: dict[str, Any],
    ) -> dict[str, Any]:
        if home.absolute() != self.home or not transaction_root.is_dir():
            _fail("package stage destination differs")
        _replay_snapshot(self.snapshot)
        transaction_id = transaction_root.name
        self._active_transaction_id = transaction_id
        package_stage, package_source, managed_stage, managed_next = (
            self._stage_roots(transaction_id)
        )
        state_path = self._state_path(transaction_id)
        existing_state = _read_effects_state(state_path)
        if existing_state is None:
            prior = getattr(self, "_observed_prior", None)
            if prior is None:
                prior = self.observe_prior(home)
            managed_action = "REUSE" if os.path.lexists(self.runtime_root) else "CREATE"
            if managed_action == "REUSE":
                _replay_tree(self.runtime_root, _rows_for(self.snapshot, "managed-runtime"))
            prestate = {
                "schema": PACKAGE_PRESTATE_SCHEMA,
                "transaction_id": transaction_id,
                "manifest_sha256": self.snapshot["manifest_sha256"],
                "managed_action": managed_action, "prior": prior,
            }
            prestate_path = self._prestate_path(transaction_id)
            existing_prestate = _read_effects_state(prestate_path)
            if existing_prestate is None:
                _write_effects_state(prestate_path, prestate)
            elif existing_prestate != prestate:
                _fail("package effects prestate residue differs")
            _loaded_prestate, prestate_sha256 = self._load_prestate(transaction_id)
            state = {
                "schema": PACKAGE_EFFECTS_SCHEMA,
                "transaction_id": transaction_id,
                "manifest_sha256": self.snapshot["manifest_sha256"],
                "phase": "ARMED", "managed_action": managed_action,
                "prior": prior, "package_receipt": None,
                "prestate_sha256": prestate_sha256,
                "managed_identity": None,
            }
            _write_effects_state(state_path, state)
        else:
            existing_state = self._validate_effects_state(
                existing_state, transaction_id,
            )
            if existing_state["phase"] == "ROLLED_BACK":
                prior = existing_state["prior"]
                managed_action = (
                    "REUSE" if os.path.lexists(self.runtime_root) else "CREATE"
                )
                if managed_action == "REUSE":
                    _replay_tree(
                        self.runtime_root,
                        _rows_for(self.snapshot, "managed-runtime"),
                    )
                existing_state.update({
                    "phase": "ARMED", "package_receipt": None,
                    "managed_identity": None,
                })
                _write_effects_state(state_path, existing_state)
        package_stage.mkdir(mode=0o700, exist_ok=True)
        _copy_tree_idempotent(
            Path(self.snapshot["root"]) / "package-source", package_source,
            _rows_for(self.snapshot, "package-source"),
        )
        _copy_tree_idempotent(
            Path(self.snapshot["root"]) / "managed-runtime", managed_stage,
            _rows_for(self.snapshot, "managed-runtime"),
        )
        if not os.path.lexists(managed_next):
            _copy_tree_idempotent(
                managed_stage, managed_next,
                _rows_for(self.snapshot, "managed-runtime"),
            )
        else:
            _replay_tree(managed_next, _rows_for(self.snapshot, "managed-runtime"))
        return {
            "schema": transaction.STAGE_SCHEMA, "kind": "package",
            "transaction_id": transaction_root.name,
            "manifest_sha256": self.snapshot["manifest_sha256"],
            "artifact_count": len(self.snapshot["rows"]),
            "prestate_sha256": self._load_prestate(transaction_id)[1],
            "interpreter_authority": self.snapshot["interpreter_authority"],
            "front_authority": self.snapshot["front_authority"],
        }

    def validate_package_stage(
        self, stage: dict[str, Any], source: dict[str, Any],
    ) -> None:
        if (
            stage.get("manifest_sha256") != self.snapshot["manifest_sha256"]
            or stage.get("artifact_count") != len(self.snapshot["rows"])
            or stage.get("prestate_sha256")
            != self._load_prestate(stage.get("transaction_id", ""))[1]
        ):
            _fail("package stage binding differs")
        transaction_id = stage.get("transaction_id", "")
        self._active_transaction_id = transaction_id
        _package_stage, package_source, managed_stage, managed_next = (
            self._stage_roots(transaction_id)
        )
        self._load_effects_state(transaction_id)
        _replay_tree(package_source, _rows_for(self.snapshot, "package-source"))
        _replay_tree(managed_stage, _rows_for(self.snapshot, "managed-runtime"))
        if os.path.lexists(managed_next):
            _replay_tree(managed_next, _rows_for(self.snapshot, "managed-runtime"))

    def stage_native(
        self, home: Path, transaction_root: Path, source: dict[str, Any],
        package_stage: dict[str, Any],
    ) -> object:
        return self._operations["native_stage"](
            home, transaction_root, source, package_stage,
        )

    def validate_native_stage(
        self, stage: dict[str, Any], source: dict[str, Any],
        package_stage: dict[str, Any],
    ) -> None:
        result = self._operations["native_stage_validate"](
            stage, source, package_stage,
        )
        if result is not True:
            _fail("native staged generation did not validate")

    def commit_package(
        self, package_stage: dict[str, Any], source: dict[str, Any],
    ) -> dict[str, Any]:
        transaction_id = package_stage.get("transaction_id", "")
        self.validate_package_stage(package_stage, source)
        state = self._load_effects_state(transaction_id)
        _package_stage, package_source, _managed_stage, managed_next = (
            self._stage_roots(transaction_id)
        )
        try:
            if state["phase"] == "ARMED":
                result = self._operations["package_commit"](
                    self.home, package_source, package_stage, source,
                )
                if type(result) is not dict:
                    _fail("package transaction returned no committed authority")
                receipt = self._package_receipt()
                state["package_receipt"] = receipt
                state["phase"] = "PACKAGE_COMMITTED"
                state = self._write_state(state)
            else:
                receipt = state["package_receipt"]
                if self._package_receipt() != receipt:
                    _fail("package commit replay differs")
            if state["managed_action"] == "CREATE":
                if state["phase"] == "COMMITTED":
                    if (
                        not os.path.lexists(self.runtime_root)
                        or _directory_identity(self.runtime_root)
                        != state["managed_identity"]
                    ):
                        _fail("committed managed runtime identity differs")
                    _replay_tree(
                        self.runtime_root,
                        _rows_for(self.snapshot, "managed-runtime"),
                    )
                elif state["phase"] == "PACKAGE_COMMITTED":
                    if os.path.lexists(self.runtime_root):
                        _fail("managed runtime appeared before publication")
                    state["managed_identity"] = _directory_identity(managed_next)
                    state["phase"] = "RUNTIME_PUBLISHING"
                    state = self._write_state(state)
                if state["phase"] not in {"RUNTIME_PUBLISHING", "COMMITTED"}:
                    _fail("managed runtime publication phase differs")
                if state["phase"] == "RUNTIME_PUBLISHING" and os.path.lexists(self.runtime_root):
                    if _directory_identity(self.runtime_root) != state["managed_identity"]:
                        _fail("managed runtime third state appeared during publication")
                    _replay_tree(
                        self.runtime_root,
                        _rows_for(self.snapshot, "managed-runtime"),
                    )
                elif state["phase"] == "RUNTIME_PUBLISHING":
                    if _directory_identity(managed_next) != state["managed_identity"]:
                        _fail("managed runtime stage identity changed")
                    _ensure_home_directories(
                        self.home, (".local", "share", "plamen", "runtime"),
                    )
                    os.replace(managed_next, self.runtime_root)
                    if _directory_identity(self.runtime_root) != state["managed_identity"]:
                        _fail("managed runtime publication identity differs")
            else:
                _replay_tree(
                    self.runtime_root,
                    _rows_for(self.snapshot, "managed-runtime"),
                )
            self._validate_relocated_runtime(transaction_id)
            state["phase"] = "COMMITTED"
            self._write_state(state)
            return receipt
        except Exception:
            # commit_package is one outer boundary.  If it cannot return a
            # receipt, compensate any package/runtime successor internally;
            # the outer journal cannot yet know that authority exists.
            current = _read_effects_state(self._state_path(transaction_id))
            if isinstance(current, dict):
                current = self._validate_effects_state(current, transaction_id)
                managed_third_state = False
                if current["managed_action"] == "CREATE" and os.path.lexists(self.runtime_root):
                    if (
                        current.get("managed_identity") is None
                        or _directory_identity(self.runtime_root)
                        != current["managed_identity"]
                    ):
                        managed_third_state = True
                    else:
                        _remove_exact_tree(
                            self.runtime_root,
                            _rows_for(self.snapshot, "managed-runtime"),
                        )
                if current["managed_action"] == "CREATE":
                    current["managed_identity"] = None
                committed = current.get("package_receipt")
                if committed is not None:
                    rolled_back = self._operations["package_rollback"](
                        self.home, committed, current["prior"],
                    )
                    if rolled_back is not True:
                        _fail("failed package boundary rollback is incomplete")
                current["phase"] = (
                    "BLOCKED_THIRD_STATE"
                    if managed_third_state else "ROLLED_BACK"
                )
                self._write_state(current)
                if managed_third_state:
                    _fail(
                        "failed package boundary encountered managed runtime third state"
                    )
            raise

    def validate_package_receipt(self, receipt: dict[str, Any]) -> None:
        observed = self._package_receipt()
        if observed != receipt:
            _fail("committed package receipt changed")
        if self._active_transaction_id is None:
            _fail("active package effects transaction is absent")
        state = self._load_effects_state(self._active_transaction_id)
        if state["phase"] != "COMMITTED" or state["package_receipt"] != receipt:
            _fail("committed package effects authority differs")
        self._validate_relocated_runtime(self._active_transaction_id)

    def commit_native(
        self, native_stage: dict[str, Any], source: dict[str, Any],
        package_receipt: dict[str, Any],
    ) -> dict[str, Any]:
        result = self._operations["native_commit"](
            self.home, native_stage, source, package_receipt,
        )
        if type(result) is not dict:
            _fail("native transaction returned no committed authority")
        return self._native_receipts(package_receipt)

    def validate_native_receipts(
        self, receipts: dict[str, Any], package_receipt: dict[str, Any],
    ) -> None:
        observed = self._native_receipts(package_receipt)
        if observed != receipts:
            _fail("native install/deployment receipts changed")

    def rollback_native(
        self, receipts: dict[str, Any], prior: dict[str, Any],
    ) -> None:
        result = self._operations["native_rollback"](
            self.home, receipts, prior,
        )
        if result is not True:
            _fail("native authenticated rollback is incomplete")

    def rollback_package(
        self, receipt: dict[str, Any], prior: dict[str, Any],
    ) -> None:
        if self._active_transaction_id is None:
            _fail("active package effects transaction is absent")
        state = self._load_effects_state(self._active_transaction_id)
        if state["package_receipt"] != receipt or state["prior"] != prior:
            _fail("package rollback authority differs")
        if state["managed_action"] == "CREATE":
            if not os.path.lexists(self.runtime_root):
                _fail("package rollback managed runtime disappeared")
            if (
                _directory_identity(self.runtime_root)
                != state.get("managed_identity")
            ):
                _fail("package rollback encountered managed runtime third state")
            _remove_exact_tree(
                self.runtime_root,
                _rows_for(self.snapshot, "managed-runtime"),
            )
            state["managed_identity"] = None
        result = self._operations["package_rollback"](
            self.home, receipt, prior,
        )
        if result is not True:
            _fail("package authenticated rollback is incomplete")
        state["phase"] = "ROLLED_BACK"
        self._write_state(state)

    def cleanup_stages(
        self, package_stage: dict[str, Any] | None,
        native_stage: dict[str, Any] | None,
    ) -> None:
        result = self._operations["cleanup"](
            self.home, package_stage, native_stage,
        )
        if result is not True:
            _fail("install private-stage cleanup is incomplete")
        if package_stage is None:
            return
        transaction_id = package_stage.get("transaction_id", "")
        package_root, package_source, managed_stage, managed_next = (
            self._stage_roots(transaction_id)
        )
        _remove_exact_tree(package_source, _rows_for(self.snapshot, "package-source"))
        _remove_exact_tree(managed_stage, _rows_for(self.snapshot, "managed-runtime"))
        _remove_exact_tree(managed_next, _rows_for(self.snapshot, "managed-runtime"))
        if os.path.lexists(package_root):
            files, directories = _tree_census(package_root)
            if files or directories:
                _fail("package private-stage cleanup residue differs")
            os.rmdir(package_root)


__all__ = [
    "DarwinColdInstallEffects", "ManagedEVMInstallInputs",
    "PACKAGE_SNAPSHOT_SCHEMA",
    "PosixNativeInstallEffectsError",
]
