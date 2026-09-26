"""Driver-owned immutable authority for one EVM analysis workspace.

The audit snapshot already freezes the audit-wide source and runtime inputs,
but individual EVM providers historically reconstructed build and tool
identity independently.  This module projects the snapshot-bound EVM build
workspace once, publishes it through a single PhaseIO transaction, and gives
all later providers one replayable identity.

Runtime discovery is intentionally absent.  Tool rows consume only an
already-bound snapshot observation and an optional independently signed
provider authority.  If no such authority exists the row is ``UNADMITTED``;
an observed executable can never become execution authority by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib
import types
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence
import weakref

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, PhaseIOContract, resolve_phase_io_contract
from js_lock_authority import (
    JSLockAuthorityError,
    KNOWN_UNSUPPORTED_LOCKFILES,
    SUPPORTED_LOCKFILES,
    select_js_lock_authority,
)
import rooted_path_io


WORKSPACE_RECEIPT_PATH = "evm_analysis_workspace_receipt.v1.json"
WORKSPACE_RECEIPT_IDENTITY = f"scratchpad:{WORKSPACE_RECEIPT_PATH}"
WORKSPACE_SCHEMA = "plamen.evm_analysis_workspace_receipt.v1"
WORKSPACE_REFERENCE_SCHEMA = "plamen.evm_analysis_workspace_reference.v1"
WORKSPACE_WORK_UNIT_ID = "evm_analysis_workspace_capture"
ANALYSIS_PROJECTION_RECEIPT_PATH = "evm_analysis_projection_receipt.v1.json"
ANALYSIS_PROJECTION_RECEIPT_IDENTITY = (
    f"scratchpad:{ANALYSIS_PROJECTION_RECEIPT_PATH}"
)
MATERIALIZATION_LINEAGE_PATH = "evm_tool_materialization_lineage.v2.json"
MATERIALIZATION_LINEAGE_IDENTITY = f"scratchpad:{MATERIALIZATION_LINEAGE_PATH}"
ANALYSIS_PROJECTION_SCHEMA = "plamen.private-analysis-projection-custody.v1"
ANALYSIS_PROJECTION_COMPONENT_KIND = "evm_analysis_projection.v1"
ANALYSIS_PROJECTION_WORK_UNIT_ID = "evm_analysis_projection_capture"
ANALYSIS_PROJECTION_STAGING_RECEIPT_CONFIG = (
    "_evm_analysis_projection_staging_receipt_path"
)
ANALYSIS_PROJECTION_NATIVE_AUTHORITY_CONFIG = (
    "_native_evm_analysis_projection_authority"
)
ANALYSIS_PROJECTION_STAGING_DIRECTORY = ".evm-analysis-projection-staging"
ANALYSIS_PROJECTION_STAGING_RECEIPT_PATH = (
    f"{ANALYSIS_PROJECTION_STAGING_DIRECTORY}/projection_receipt.v1.json"
)
MATERIALIZATION_LINEAGE_STAGING_CONFIG = (
    "_evm_tool_materialization_lineage_staging_path"
)
MATERIALIZATION_LINEAGE_STAGING_PATH = (
    f"{ANALYSIS_PROJECTION_STAGING_DIRECTORY}/materialization_lineage.v2.json"
)
_LAUNCH_TIMEOUT_SECONDS = 30
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._:/+-]{1,512}$", re.ASCII)
_TOOL_IDS = ("forge", "opengrep", "semgrep", "slither", "solc")
_MANIFEST_NAMES = (
    "foundry.toml",
    "remappings.txt",
    "hardhat.config.js",
    "hardhat.config.ts",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
)
_JS_LOCK_NAMES = (
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
    "yarn.lock", "bun.lock", "bun.lockb",
)
if frozenset(_JS_LOCK_NAMES) != SUPPORTED_LOCKFILES | KNOWN_UNSUPPORTED_LOCKFILES:
    raise RuntimeError("EVM workspace JavaScript lock roster differs from central selector")
_MAX_CONTROL_BYTES = 8 * 1024 * 1024
_MAX_MANIFEST_BYTES = 32 * 1024 * 1024
_MAX_DEPENDENCY_FILES = 200_000
_MAX_DEPENDENCY_DIRECTORIES = 100_000
_MAX_DEPENDENCY_BYTES = 16 * 1024 * 1024 * 1024
_MAX_DEPENDENCY_DEPTH = 128
_ROOT_AUTHORITY_SCHEMA = "plamen.evm_build_root_resolution.v1"
_DEPENDENCY_CLOSURE_SCHEMA = "plamen.evm_dependency_content_closure.v1"
_FaultInjector = Callable[[str], None]


class EVMAnalysisWorkspaceAuthorityError(RuntimeError):
    """The EVM workspace could not be captured or replayed exactly."""


class CommittedEVMAnalysisProjection:
    """Unserializable process-local proof of committed projection lineage."""

    __slots__ = (
        "_receipt", "_component", "_owner_work_unit_key", "__weakref__",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> "CommittedEVMAnalysisProjection":
        raise TypeError(
            "EVM analysis projection authorities are issued only by committed "
            "PhaseIO/ArtifactLedger replay"
        )

    @property
    def receipt(self) -> Mapping[str, Any]:
        return self._receipt

    @property
    def component(self) -> Mapping[str, Any]:
        return self._component

    @property
    def owner_work_unit_key(self) -> str:
        return self._owner_work_unit_key

    def __reduce__(self) -> object:
        raise TypeError("committed EVM analysis projections are not serializable")


_LIVE_ANALYSIS_PROJECTIONS: weakref.WeakSet[CommittedEVMAnalysisProjection] = (
    weakref.WeakSet()
)


class _FrozenSessionBoundAuthorityType(type):
    def __setattr__(cls, _name: str, _value: object) -> None:
        raise TypeError("session-bound EVM tool authority types are frozen")

    def __delattr__(cls, _name: str) -> None:
        raise TypeError("session-bound EVM tool authority types are frozen")


class SessionBoundEVMToolAuthority(metaclass=_FrozenSessionBoundAuthorityType):
    """Opaque authority joining one POSIX session to local tool projections.

    This capability does not launch a process and does not upgrade locally
    installed bytes to authentic upstream content.  It only authorizes the
    construction of a native-custodied ``SNAPSHOT_BOUND_LOCAL`` execution plan
    for the exact receipt/session/snapshot tuple that issued it.
    """

    __slots__ = (
        "_session_ref", "_receipt_sha256", "_run_id", "_snapshot_sha256",
        "_project_root", "_scratchpad", "_backend", "_projections",
        "_governance_sha256", "_version_lock_sha256", "_rule_tree_binding",
        "_managed_generation_authority", "_native_session", "__weakref__",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "SessionBoundEVMToolAuthority":
        raise TypeError(
            "session-bound EVM tool authorities are issued only by exact "
            "workspace/session replay"
        )

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("session-bound EVM tool authorities cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("session-bound EVM tool authorities are immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("session-bound EVM tool authorities are immutable")

    @property
    def tool_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._projections))

    def __reduce__(self) -> object:
        raise TypeError("session-bound EVM tool authorities are not serializable")


_LIVE_SESSION_BOUND_TOOL_AUTHORITIES: weakref.WeakKeyDictionary[
    SessionBoundEVMToolAuthority, tuple[object, ...]
] = weakref.WeakKeyDictionary()


@dataclass(frozen=True)
class EVMAnalysisWorkspaceOutcome:
    state: str
    reused: bool
    receipt_sha256: str
    owner_work_unit_key: str
    public_reference: Mapping[str, Any]


def _fail(message: str, exc: BaseException | None = None) -> None:
    if exc is None:
        raise EVMAnalysisWorkspaceAuthorityError(message)
    raise EVMAnalysisWorkspaceAuthorityError(message) from exc


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _canonical_file(value: object) -> bytes:
    return _canonical_json(value) + b"\n"


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _plain_json_shape(value: object) -> Any:
    """Return a detached JSON value with arrays restored as mutable lists.

    Opaque authorities deliberately freeze arrays as tuples.  Receipts are a
    JSON protocol, however, and exact receipt validation must see JSON array
    semantics after crossing that in-process authority boundary.
    """

    def thaw(item: object) -> Any:
        if isinstance(item, Mapping):
            return {str(key): thaw(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [thaw(child) for child in item]
        return item

    return json.loads(_canonical_json(thaw(value)).decode("utf-8"))


def _frozen_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    copied = _plain_json_shape(value)

    def freeze(item: Any) -> Any:
        if isinstance(item, dict):
            return MappingProxyType({key: freeze(child) for key, child in item.items()})
        if isinstance(item, list):
            return tuple(freeze(child) for child in item)
        return item

    return freeze(copied)


def _analysis_projection_component(
    audit_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    components = audit_snapshot.get("components")
    source = components.get("source_scope") if isinstance(components, Mapping) else None
    value = (
        components.get("evm_analysis_projection")
        if isinstance(components, Mapping) else None
    )
    keys = {
        "kind", "receipt_sha256", "receipt_byte_count",
        "materialization_lineage_sha256", "materialization_lineage_byte_count",
        "native_materialization_request_sha256",
        "original_source_scope_sha256", "source_copy_closure_sha256",
        "js_lock_selection_sha256",
        "dependency_materialization_receipt_sha256",
        "materialized_node_modules_closure_sha256",
        "analysis_workspace_closure_sha256",
        "native_projection_custody_sha256", "digest",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail("audit snapshot lacks exact EVM analysis projection component")
    unsigned = dict(value)
    stored = unsigned.pop("digest", None)
    digest_fields = keys - {
        "kind", "receipt_byte_count", "materialization_lineage_byte_count",
        "digest",
    }
    if (
        value.get("kind") != ANALYSIS_PROJECTION_COMPONENT_KIND
        or stored != _digest(unsigned)
        or type(value.get("receipt_byte_count")) is not int
        or not 0 < value["receipt_byte_count"] <= _MAX_CONTROL_BYTES
        or type(value.get("materialization_lineage_byte_count")) is not int
        or not 0 < value["materialization_lineage_byte_count"] <= _MAX_CONTROL_BYTES
        or any(_HEX64.fullmatch(str(value.get(field) or "")) is None for field in digest_fields)
        or not isinstance(source, Mapping)
        or value.get("original_source_scope_sha256") != source.get("digest")
    ):
        _fail("audit snapshot EVM analysis projection component is invalid")
    return dict(value)


def _validate_analysis_projection_receipt(
    value: object,
    *,
    component: Mapping[str, Any] | None,
) -> dict[str, Any]:
    keys = {
        "analysis_workspace_bytes", "analysis_workspace_closure_sha256",
        "analysis_workspace_directory_count", "analysis_workspace_file_count",
        "component_kind", "dependency_materialization_receipt_sha256",
        "guest_mount_identity_sha256", "guest_mount_path",
        "host_descriptor_identity_sha256", "invocation_sha256",
        "js_lock_selection_sha256", "materialized_node_modules_bytes",
        "materialized_node_modules_closure_sha256",
        "materialized_node_modules_directory_count",
        "materialized_node_modules_file_count",
        "native_projection_custody_sha256", "original_source_scope_sha256",
        "materialization_lineage_byte_count", "materialization_lineage_sha256",
        "native_materialization_request_sha256",
        "project_read_only", "receipt_byte_count", "receipt_sha256", "schema",
        "source_copy_bytes", "source_copy_closure_sha256",
        "source_copy_directory_count", "source_copy_file_count",
        "writable_mounts",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail("native EVM analysis projection receipt fields are malformed")
    unsigned = dict(value)
    stored = unsigned.pop("receipt_sha256", None)
    digest_fields = {
        "analysis_workspace_closure_sha256",
        "dependency_materialization_receipt_sha256",
        "guest_mount_identity_sha256", "host_descriptor_identity_sha256",
        "invocation_sha256", "materialized_node_modules_closure_sha256",
        "native_projection_custody_sha256", "original_source_scope_sha256",
        "materialization_lineage_sha256", "native_materialization_request_sha256",
        "js_lock_selection_sha256",
        "source_copy_closure_sha256",
    }
    if (
        value.get("schema") != ANALYSIS_PROJECTION_SCHEMA
        or value.get("component_kind") != ANALYSIS_PROJECTION_COMPONENT_KIND
        or stored != _digest(unsigned)
        or any(_HEX64.fullmatch(str(value.get(field) or "")) is None for field in digest_fields)
        or value.get("receipt_byte_count") != len(_canonical_json(value))
        or any(
            type(value.get(field)) is not int
            or not 0 < value[field] <= maximum
            for field, maximum in (
                ("receipt_byte_count", _MAX_CONTROL_BYTES),
                ("materialization_lineage_byte_count", _MAX_CONTROL_BYTES),
                ("source_copy_file_count", _MAX_DEPENDENCY_FILES),
                ("source_copy_directory_count", _MAX_DEPENDENCY_DIRECTORIES),
                ("source_copy_bytes", _MAX_DEPENDENCY_BYTES),
                ("materialized_node_modules_file_count", _MAX_DEPENDENCY_FILES),
                ("materialized_node_modules_directory_count", _MAX_DEPENDENCY_DIRECTORIES),
                ("materialized_node_modules_bytes", _MAX_DEPENDENCY_BYTES),
                ("analysis_workspace_file_count", _MAX_DEPENDENCY_FILES),
                ("analysis_workspace_directory_count", _MAX_DEPENDENCY_DIRECTORIES),
                ("analysis_workspace_bytes", _MAX_DEPENDENCY_BYTES),
            )
        )
        or value.get("guest_mount_path") != "/workspace/project"
        or value.get("project_read_only") is not True
        or value.get("writable_mounts")
        != ["/workspace/scratch", "/workspace/state"]
        or (
            component is not None
            and (
                value.get("original_source_scope_sha256")
                != component.get("original_source_scope_sha256")
                or value.get("source_copy_closure_sha256")
                != component.get("source_copy_closure_sha256")
                or value.get("js_lock_selection_sha256")
                != component.get("js_lock_selection_sha256")
                or value.get("dependency_materialization_receipt_sha256")
                != component.get("dependency_materialization_receipt_sha256")
                or value.get("materialized_node_modules_closure_sha256")
                != component.get("materialized_node_modules_closure_sha256")
                or value.get("analysis_workspace_closure_sha256")
                != component.get("analysis_workspace_closure_sha256")
                or value.get("native_projection_custody_sha256")
                != component.get("native_projection_custody_sha256")
                or value.get("materialization_lineage_sha256")
                != component.get("materialization_lineage_sha256")
                or value.get("materialization_lineage_byte_count")
                != component.get("materialization_lineage_byte_count")
                or value.get("native_materialization_request_sha256")
                != component.get("native_materialization_request_sha256")
                or value.get("receipt_sha256") != component.get("receipt_sha256")
                or value.get("receipt_byte_count")
                != component.get("receipt_byte_count")
            )
        )
    ):
        _fail("native EVM analysis projection lineage differs from audit snapshot")
    return dict(value)


def _file_digest(path: Path, *, limit: int) -> tuple[str, int]:
    try:
        observed = os.lstat(path)
    except OSError as exc:
        _fail(f"workspace input is unreadable: {path.name}", exc)
    attributes = int(getattr(observed, "st_file_attributes", 0) or 0)
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
        or observed.st_size < 0
        or observed.st_size > limit
    ):
        _fail(f"workspace input is not an ordinary bounded file: {path.name}")
    descriptor = -1
    try:
        descriptor = os.open(
            os.fspath(path),
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if int(opened.st_dev) != int(observed.st_dev) or int(opened.st_ino) != int(observed.st_ino):
            _fail(f"workspace input changed before capture: {path.name}")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            size += len(block)
            if size > limit:
                _fail(f"workspace input exceeds byte bound: {path.name}")
            digest.update(block)
    except OSError as exc:
        _fail(f"workspace input read failed: {path.name}", exc)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    replay = os.lstat(path)
    if (
        int(getattr(replay, "st_dev", -1)) != int(getattr(observed, "st_dev", -2))
        or int(getattr(replay, "st_ino", -1)) != int(getattr(observed, "st_ino", -2))
        or int(getattr(replay, "st_size", -1)) != size
        or int(getattr(replay, "st_nlink", -1)) != int(getattr(observed, "st_nlink", -2))
    ):
        _fail(f"workspace input changed during capture: {path.name}")
    return digest.hexdigest(), size


def _file_digest_at(
    directory_fd: int,
    name: str,
    *,
    directory_path: Path,
    display_name: str,
    limit: int,
) -> tuple[str, int] | None:
    """Hash one direct child through the held directory capability."""

    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        _fail("workspace descriptor-relative file name is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    used_path_fallback = False
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except (NotImplementedError, TypeError):
        # CPython/Windows exposes directory handles but not openat. Retain the
        # held parent capability, open the exact lexical child no-follow, and
        # replay both physical identities around the read.
        used_path_fallback = True
        try:
            descriptor = os.open(os.fspath(directory_path / name), flags)
        except OSError as exc:
            _fail(f"workspace input is unreadable: {display_name}", exc)
    except OSError as exc:
        _fail(f"workspace input is unreadable: {display_name}", exc)
    try:
        observed = os.fstat(descriptor)
        attributes = int(getattr(observed, "st_file_attributes", 0) or 0)
        if (
            not stat.S_ISREG(observed.st_mode)
            or bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
            or int(observed.st_nlink) != 1
            or observed.st_size < 0
            or observed.st_size > limit
        ):
            _fail(f"workspace input is not an ordinary bounded file: {display_name}")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            size += len(block)
            if size > limit:
                _fail(f"workspace input exceeds byte bound: {display_name}")
            digest.update(block)
        replay = os.fstat(descriptor)
        try:
            linked = (
                os.lstat(directory_path / name)
                if used_path_fallback
                else os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            )
            parent_replay = os.fstat(directory_fd)
            parent_linked = os.lstat(directory_path)
        except (NotImplementedError, TypeError, OSError) as exc:
            _fail("descriptor-relative workspace replay is unsupported", exc)
        if (
            int(replay.st_dev) != int(observed.st_dev)
            or int(replay.st_ino) != int(observed.st_ino)
            or int(replay.st_size) != size
            or int(linked.st_dev) != int(observed.st_dev)
            or int(linked.st_ino) != int(observed.st_ino)
            or int(parent_replay.st_dev) != int(parent_linked.st_dev)
            or int(parent_replay.st_ino) != int(parent_linked.st_ino)
        ):
            _fail(f"workspace input changed during capture: {display_name}")
        return digest.hexdigest(), size
    except OSError as exc:
        _fail(f"workspace input read failed: {display_name}", exc)
    finally:
        os.close(descriptor)


def _file_bytes_at(
    directory_fd: int,
    name: str,
    *,
    directory_path: Path,
    display_name: str,
    limit: int,
) -> bytes | None:
    """Read one direct child through a held directory capability.

    The returned bytes are valid only after the exact opened object, its link,
    and its held parent have all replayed unchanged.  This is intentionally a
    separate acquisition from manifest hashing so selector semantics cannot be
    supplied by a caller or reconstructed from a pathname after capture.
    """

    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        _fail("workspace descriptor-relative file name is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    used_path_fallback = False
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except (NotImplementedError, TypeError):
        used_path_fallback = True
        try:
            descriptor = os.open(os.fspath(directory_path / name), flags)
        except OSError as exc:
            _fail(f"workspace input is unreadable: {display_name}", exc)
    except OSError as exc:
        _fail(f"workspace input is unreadable: {display_name}", exc)
    try:
        observed = os.fstat(descriptor)
        attributes = int(getattr(observed, "st_file_attributes", 0) or 0)
        if (
            not stat.S_ISREG(observed.st_mode)
            or bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
            or int(observed.st_nlink) != 1
            or observed.st_size < 0
            or observed.st_size > limit
        ):
            _fail(f"workspace input is not an ordinary bounded file: {display_name}")
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            size += len(block)
            if size > limit:
                _fail(f"workspace input exceeds byte bound: {display_name}")
            chunks.append(block)
        replay = os.fstat(descriptor)
        try:
            linked = (
                os.lstat(directory_path / name)
                if used_path_fallback
                else os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            )
            parent_replay = os.fstat(directory_fd)
            parent_linked = os.lstat(directory_path)
        except (NotImplementedError, TypeError, OSError) as exc:
            _fail("descriptor-relative workspace replay is unsupported", exc)
        if (
            int(replay.st_dev) != int(observed.st_dev)
            or int(replay.st_ino) != int(observed.st_ino)
            or int(replay.st_size) != size
            or int(linked.st_dev) != int(observed.st_dev)
            or int(linked.st_ino) != int(observed.st_ino)
            or int(parent_replay.st_dev) != int(parent_linked.st_dev)
            or int(parent_replay.st_ino) != int(parent_linked.st_ino)
        ):
            _fail(f"workspace input changed during capture: {display_name}")
        return b"".join(chunks)
    except OSError as exc:
        _fail(f"workspace input read failed: {display_name}", exc)
    finally:
        os.close(descriptor)


def _directory_record(path: Path, *, rooted_alias: str) -> dict[str, Any]:
    try:
        observed = os.lstat(path)
    except OSError as exc:
        _fail(f"workspace directory is unreadable: {rooted_alias}", exc)
    attributes = int(getattr(observed, "st_file_attributes", 0) or 0)
    reparse_tag = int(getattr(observed, "st_reparse_tag", 0) or 0)
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
        or reparse_tag != 0
    ):
        _fail(f"workspace directory is a link/reparse point: {rooted_alias}")
    physical = {
        "device": int(getattr(observed, "st_dev", 0) or 0),
        "inode": int(getattr(observed, "st_ino", 0) or 0),
        "mode_type": int(stat.S_IFMT(observed.st_mode)),
        "file_attributes": attributes,
        "reparse_tag": reparse_tag,
    }
    if physical["inode"] <= 0 or physical["mode_type"] != stat.S_IFDIR:
        _fail(f"workspace directory physical identity is unavailable: {rooted_alias}")
    descriptor = -1
    try:
        descriptor = os.open(
            os.fspath(path),
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        held = os.fstat(descriptor)
    except OSError as exc:
        _fail(f"workspace directory descriptor capture failed: {rooted_alias}", exc)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        linked = os.lstat(path)
    except OSError as exc:
        _fail(f"workspace directory replay failed: {rooted_alias}", exc)
    if (
        int(held.st_dev) != physical["device"]
        or int(held.st_ino) != physical["inode"]
        or int(linked.st_dev) != physical["device"]
        or int(linked.st_ino) != physical["inode"]
    ):
        _fail(f"workspace directory changed during capture: {rooted_alias}")
    return {
        "absolute_path": str(path),
        "rooted_alias": rooted_alias,
        "physical_identity": physical,
        "descriptor_sha256": _digest({
            "rooted_alias": rooted_alias,
            "physical_identity": physical,
        }),
    }


def _dependency_content_closure_once(
    path: Path,
    *,
    rooted_alias: str,
    expected_root: Mapping[str, Any],
    excluded_top_level: frozenset[str] = frozenset(),
    exclude_node_modules_bin: bool = False,
) -> dict[str, Any]:
    """Hash one dependency tree through held, no-follow directory handles.

    The receipt deliberately stores one bounded Merkle-like stream digest
    rather than a pathname list.  Replay walks the same sorted relative-path
    denominator and therefore detects file additions, removals, type changes,
    mode changes, and byte changes without trusting directory mtimes.
    """

    root = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(os.fspath(root), flags)
    except OSError as exc:
        _fail(f"dependency root descriptor capture failed: {rooted_alias}", exc)
    stream = hashlib.sha256()
    file_count = 0
    directory_count = 0
    byte_count = 0

    def add(row: Mapping[str, Any]) -> None:
        try:
            raw = _canonical_json(row)
        except (TypeError, UnicodeError, ValueError) as exc:
            _fail("dependency closure contains an unencodable path", exc)
        stream.update(len(raw).to_bytes(8, "big"))
        stream.update(raw)

    def visit(directory_fd: int, directory_path: Path, parts: tuple[str, ...]) -> None:
        nonlocal file_count, directory_count, byte_count
        if len(parts) > _MAX_DEPENDENCY_DEPTH:
            _fail("dependency closure exceeds bounded directory depth")
        try:
            try:
                names = os.listdir(directory_fd)
                descriptor_relative = True
            except (NotImplementedError, TypeError):
                # Windows CPython may not accept a directory descriptor here.
                # Every child is still opened no-follow and both its parent
                # descriptor and lexical parent identity are replayed below.
                names = os.listdir(directory_path)
                descriptor_relative = False
        except OSError as exc:
            _fail(f"dependency directory is unreadable: {rooted_alias}", exc)
        if not all(isinstance(name, str) for name in names):
            _fail("dependency directory contains a non-text path")
        for name in sorted(names):
            if not parts and name in excluded_top_level:
                continue
            if (
                exclude_node_modules_bin
                and name == ".bin"
                and (
                    (not parts and root.name.casefold() == "node_modules")
                    or (parts and parts[-1].casefold() == "node_modules")
                )
            ):
                continue
            if (
                name in {"", ".", ".."}
                or "/" in name
                or "\\" in name
                or "\x00" in name
            ):
                _fail("dependency closure contains an unsafe path component")
            relative_parts = (*parts, name)
            relative = "/".join(relative_parts)
            child_path = directory_path / name
            try:
                observed = (
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if descriptor_relative
                    else os.lstat(child_path)
                )
            except (NotImplementedError, TypeError, OSError) as exc:
                _fail(f"dependency entry is unreadable: {rooted_alias}/{relative}", exc)
            attributes = int(getattr(observed, "st_file_attributes", 0) or 0)
            reparse_tag = int(getattr(observed, "st_reparse_tag", 0) or 0)
            if (
                stat.S_ISLNK(observed.st_mode)
                or bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
                or reparse_tag != 0
            ):
                _fail(f"dependency closure contains a link/reparse point: {relative}")
            mode = int(stat.S_IMODE(observed.st_mode))
            if stat.S_ISDIR(observed.st_mode):
                directory_count += 1
                if directory_count > _MAX_DEPENDENCY_DIRECTORIES:
                    _fail("dependency closure exceeds bounded directory count")
                add({"kind": "DIRECTORY", "relative_path": relative, "mode": mode})
                try:
                    try:
                        child_fd = os.open(name, flags, dir_fd=directory_fd)
                    except (NotImplementedError, TypeError):
                        child_fd = os.open(os.fspath(child_path), flags)
                    opened = os.fstat(child_fd)
                    if (
                        int(opened.st_dev) != int(observed.st_dev)
                        or int(opened.st_ino) != int(observed.st_ino)
                    ):
                        _fail(f"dependency directory changed before traversal: {relative}")
                    visit(child_fd, child_path, relative_parts)
                    replay = os.fstat(child_fd)
                    linked = os.lstat(child_path)
                    if (
                        int(replay.st_dev) != int(observed.st_dev)
                        or int(replay.st_ino) != int(observed.st_ino)
                        or int(linked.st_dev) != int(observed.st_dev)
                        or int(linked.st_ino) != int(observed.st_ino)
                    ):
                        _fail(f"dependency directory changed during traversal: {relative}")
                except OSError as exc:
                    _fail(f"dependency directory traversal failed: {relative}", exc)
                finally:
                    if "child_fd" in locals():
                        try:
                            os.close(child_fd)
                        except OSError:
                            pass
                        del child_fd
            elif stat.S_ISREG(observed.st_mode):
                captured = _file_digest_at(
                    directory_fd,
                    name,
                    directory_path=directory_path,
                    display_name=f"{rooted_alias}/{relative}",
                    limit=_MAX_DEPENDENCY_BYTES,
                )
                if captured is None:
                    _fail(f"dependency file vanished during traversal: {relative}")
                digest, size = captured
                file_count += 1
                byte_count += size
                if file_count > _MAX_DEPENDENCY_FILES:
                    _fail("dependency closure exceeds bounded file count")
                if byte_count > _MAX_DEPENDENCY_BYTES:
                    _fail("dependency closure exceeds bounded byte count")
                add({
                    "kind": "FILE",
                    "relative_path": relative,
                    "mode": mode,
                    "size": size,
                    "sha256": digest,
                })
            else:
                _fail(f"dependency closure contains a special file: {relative}")
        try:
            held = os.fstat(directory_fd)
            linked_parent = os.lstat(directory_path)
        except OSError as exc:
            _fail(f"dependency directory replay failed: {rooted_alias}", exc)
        if (
            int(held.st_dev) != int(linked_parent.st_dev)
            or int(held.st_ino) != int(linked_parent.st_ino)
        ):
            _fail(f"dependency directory changed during traversal: {rooted_alias}")

    try:
        opened_root = os.fstat(root_fd)
        physical = expected_root.get("physical_identity")
        if (
            not isinstance(physical, Mapping)
            or int(opened_root.st_dev) != physical.get("device")
            or int(opened_root.st_ino) != physical.get("inode")
        ):
            _fail(f"dependency root changed before content capture: {rooted_alias}")
        visit(root_fd, root, ())
    finally:
        os.close(root_fd)
    unsigned = {
        "schema_version": _DEPENDENCY_CLOSURE_SCHEMA,
        "file_count": file_count,
        "directory_count": directory_count,
        "byte_count": byte_count,
        "entry_stream_sha256": stream.hexdigest(),
    }
    if excluded_top_level:
        unsigned["excluded_top_level"] = sorted(excluded_top_level)
    if exclude_node_modules_bin:
        unsigned["excluded_path_policy"] = (
            "NODE_MODULES_BIN_DIRECTORIES_V2"
        )
    return {**unsigned, "closure_sha256": _digest(unsigned)}


def _dependency_content_closure(
    path: Path,
    *,
    rooted_alias: str,
    expected_root: Mapping[str, Any],
    excluded_top_level: frozenset[str] = frozenset(),
    exclude_node_modules_bin: bool = False,
) -> dict[str, Any]:
    """Capture twice so a mutation during enumeration cannot be committed."""

    first = _dependency_content_closure_once(
        path, rooted_alias=rooted_alias, expected_root=expected_root,
        excluded_top_level=excluded_top_level,
        exclude_node_modules_bin=exclude_node_modules_bin,
    )
    second = _dependency_content_closure_once(
        path, rooted_alias=rooted_alias, expected_root=expected_root,
        excluded_top_level=excluded_top_level,
        exclude_node_modules_bin=exclude_node_modules_bin,
    )
    if first != second:
        _fail(f"dependency content changed during capture: {rooted_alias}")
    return second


def _dependency_root_uses_node_modules_bin_policy(_path: Path) -> bool:
    """Enable the structural npm-launcher exclusion for dependency roots.

    npm's ``node_modules/.bin`` contains convenience launcher symlinks.  Those
    launchers are neither Solidity imports nor compiler inputs, and following
    them would violate the no-link dependency policy.  A compiled dependency
    root can itself be a package scope or remapping target below node_modules,
    so the policy cannot be selected from the root basename.  Enable it for
    every declared dependency root, then exclude only a ``.bin`` whose actual
    parent is ``node_modules`` (including when the root itself is that parent).
    Links anywhere else in package source remain fatal.
    """

    return True


def _derive_js_consumption_binding(
    js_consumption: Mapping[str, Any],
    *,
    build_root: Path,
    js_lock_authority: Mapping[str, Any],
    analysis_projection: Mapping[str, Any] | None,
    dependency_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive JS dependency consumption from the exact frozen materials.

    Capture and replay must apply this state transition only after the same
    dependency denominator is available.  In particular, a direct
    ``node_modules`` dependency root and a committed private projection are
    two equivalent ways to bind a selected lockfile to immutable installed
    bytes; neither branch may exist only in the producer or only in replay.
    """

    derived = dict(js_consumption)
    if derived.get("state") != "UNRESOLVED":
        return derived
    expected_modules = Path(os.path.abspath(os.fspath(build_root / "node_modules")))
    dependency_binds_modules = any(
        Path(str(row.get("absolute_path") or "")) == expected_modules
        for row in dependency_rows
    )
    if (
        js_lock_authority.get("state") == "SELECTED"
        and (analysis_projection is not None or dependency_binds_modules)
    ):
        derived["state"] = "BOUND"
    return derived


def _descriptor_held_build_root(
    project_root: Path,
    build_root: Path,
    *,
    projection_authority: CommittedEVMAnalysisProjection | None = None,
    allow_committed_disjoint: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], int]:
    """Open the project root and descend without following a path component."""

    project = Path(os.path.abspath(os.fspath(project_root)))
    build = Path(os.path.abspath(os.fspath(build_root)))
    if projection_authority is not None or allow_committed_disjoint:
        if projection_authority is not None:
            _require_live_analysis_projection(projection_authority)
        try:
            build.relative_to(project)
            related = True
        except ValueError:
            try:
                project.relative_to(build)
                related = True
            except ValueError:
                related = False
        if related:
            _fail("private EVM analysis projection is not disjoint from original source")
        project_record = _directory_record(project, rooted_alias="project:.")
        build_record = _directory_record(build, rooted_alias="projection:.")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptors: list[int] = []
        try:
            project_fd = os.open(os.fspath(project), flags)
            descriptors.append(project_fd)
            build_fd = os.open(os.fspath(build), flags)
            descriptors.append(build_fd)
            project_open = os.fstat(project_fd)
            build_open = os.fstat(build_fd)
            if (
                int(project_open.st_dev)
                != project_record["physical_identity"]["device"]
                or int(project_open.st_ino)
                != project_record["physical_identity"]["inode"]
                or int(build_open.st_dev)
                != build_record["physical_identity"]["device"]
                or int(build_open.st_ino)
                != build_record["physical_identity"]["inode"]
            ):
                _fail("private EVM analysis projection changed before capture")
            relation_unsigned = {
                "kind": "DISJOINT_PRIVATE_PROJECTION",
                "relative_path": ".",
                "project_descriptor_sha256": project_record["descriptor_sha256"],
                "build_descriptor_sha256": build_record["descriptor_sha256"],
            }
            return (
                project_record,
                build_record,
                {**relation_unsigned, "relation_sha256": _digest(relation_unsigned)},
                os.dup(build_fd),
            )
        except OSError as exc:
            _fail("descriptor-held private EVM analysis projection failed", exc)
        finally:
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise AssertionError("unreachable")
    try:
        relative = build.relative_to(project)
        relation_kind = "PROJECT_ROOT" if not relative.parts else "DESCENDANT"
        relation_path = "." if not relative.parts else relative.as_posix()
        anchor, descend = project, relative
    except ValueError:
        try:
            project_from_build = project.relative_to(build)
        except ValueError as exc:
            _fail("selected EVM build root is unrelated to the snapshot project root", exc)
        if not project_from_build.parts:
            _fail("selected EVM build-root relation is malformed")
        relation_kind = "ANCESTOR"
        relation_path = project_from_build.as_posix()
        anchor, descend = build, project_from_build
    if any(part in {"", ".", ".."} for part in descend.parts):
        _fail("selected EVM build root has an unsafe relative path")

    root_record = _directory_record(project, rooted_alias="project:.")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    try:
        root_fd = os.open(os.fspath(anchor), flags)
        descriptors.append(root_fd)
        anchor_record = _directory_record(
            anchor,
            rooted_alias="project:." if anchor == project else "build:.",
        )
        root_open = os.fstat(root_fd)
        root_physical = anchor_record["physical_identity"]
        if (
            int(root_open.st_dev) != root_physical["device"]
            or int(root_open.st_ino) != root_physical["inode"]
        ):
            _fail("snapshot project root changed before descriptor capture")
        current_fd = root_fd
        current_path = anchor
        for part in descend.parts:
            current_path = current_path / part
            _directory_record(
                current_path,
                rooted_alias="relation:" + current_path.relative_to(anchor).as_posix(),
            )
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except (NotImplementedError, TypeError):
                # Windows lacks dir_fd traversal.  The no-follow lstat record
                # above plus the root replay below is the available primitive.
                next_fd = os.open(os.fspath(current_path), flags)
            descriptors.append(next_fd)
            current_fd = next_fd
        held = os.fstat(current_fd)
        build_record = _directory_record(build, rooted_alias=(
            "project:." if relation_kind == "PROJECT_ROOT"
            else f"project:{relation_path}" if relation_kind == "DESCENDANT"
            else "build:."
        ))
        project_replay = _directory_record(project, rooted_alias="project:.")
        descended_record = build_record if relation_kind != "ANCESTOR" else project_replay
        if (
            int(held.st_dev) != descended_record["physical_identity"]["device"]
            or int(held.st_ino) != descended_record["physical_identity"]["inode"]
        ):
            _fail("selected EVM build root changed during descriptor traversal")
        replay = os.fstat(root_fd)
        if int(replay.st_dev) != root_physical["device"] or int(replay.st_ino) != root_physical["inode"]:
            _fail("snapshot project root changed during workspace capture")
        relation_unsigned = {
            "kind": relation_kind,
            "relative_path": relation_path,
            "project_descriptor_sha256": project_replay["descriptor_sha256"],
            "build_descriptor_sha256": build_record["descriptor_sha256"],
        }
        held_build_fd = os.dup(root_fd if relation_kind == "ANCESTOR" else current_fd)
        return (
            project_replay,
            build_record,
            {**relation_unsigned, "relation_sha256": _digest(relation_unsigned)},
            held_build_fd,
        )
    except OSError as exc:
        _fail("descriptor-held EVM build-root traversal failed", exc)
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    raise AssertionError("unreachable")


def capture_evm_build_root_resolver_authority(
    project_root: Path,
    build_root: Path,
) -> dict[str, Any]:
    """Return the exact resolver statement later consumed by workspace capture."""

    project, build, relation, descriptor = _descriptor_held_build_root(
        Path(project_root), Path(build_root)
    )
    os.close(descriptor)
    unsigned = {
        "schema_version": _ROOT_AUTHORITY_SCHEMA,
        "relation_kind": relation["kind"],
        "relative_path": relation["relative_path"],
        "project_descriptor_sha256": project["descriptor_sha256"],
        "build_descriptor_sha256": build["descriptor_sha256"],
    }
    return {**unsigned, "authority_sha256": _digest(unsigned)}


def _load_json_file(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    try:
        descriptor = os.open(
            os.fspath(path),
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > _MAX_CONTROL_BYTES:
            _fail(f"{label} is not a bounded regular file")
        raw = bytearray()
        while len(raw) <= _MAX_CONTROL_BYTES:
            block = os.read(descriptor, min(1024 * 1024, _MAX_CONTROL_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        replay = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = -1
        if int(replay.st_dev) != int(observed.st_dev) or int(replay.st_ino) != int(observed.st_ino):
            _fail(f"{label} changed during descriptor read")
        linked = os.lstat(path)
        if int(linked.st_dev) != int(observed.st_dev) or int(linked.st_ino) != int(observed.st_ino):
            _fail(f"{label} changed during descriptor read")
        value = json.loads(bytes(raw).decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is unreadable", exc)
    finally:
        if 'descriptor' in locals() and descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict) or not raw:
        _fail(f"{label} is malformed")
    return value, hashlib.sha256(raw).hexdigest()


def _governance_rows(implementation_root: Path) -> tuple[dict[str, Any], str, str]:
    governance_path = implementation_root / "verification_policy" / "toolchain_governance.v1.json"
    governance, governance_sha256 = _load_json_file(
        governance_path, label="toolchain governance"
    )
    reviewed = governance.get("reviewed_version_lock")
    if not isinstance(reviewed, Mapping):
        _fail("toolchain governance has no reviewed version-lock authority")
    lock_path = implementation_root / str(reviewed.get("path") or "")
    _lock, lock_sha256 = _load_json_file(lock_path, label="toolchain version lock")
    if reviewed.get("sha256") != lock_sha256:
        _fail("toolchain version-lock digest differs from governance")
    rows = governance.get("tools")
    if not isinstance(rows, list):
        _fail("toolchain governance tool roster is malformed")
    by_id = {
        str(row.get("tool_id")): dict(row)
        for row in rows
        if isinstance(row, Mapping)
    }
    if any(tool_id not in by_id for tool_id in _TOOL_IDS):
        _fail("toolchain governance omits an EVM analysis tool")
    return by_id, governance_sha256, lock_sha256


def _manifest_rows(
    build_root_fd: int,
    *,
    build_root_path: Path,
    relation: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in _MANIFEST_NAMES:
        captured = _file_digest_at(
            build_root_fd,
            name,
            directory_path=build_root_path,
            display_name=name,
            limit=_MAX_MANIFEST_BYTES,
        )
        if captured is None:
            continue
        digest, size = captured
        if relation["kind"] == "DESCENDANT":
            prefix = str(relation["relative_path"]).rstrip("/") + "/"
            rooted_alias = f"project:{prefix}{name}"
        elif relation["kind"] == "PROJECT_ROOT":
            rooted_alias = f"project:{name}"
        else:
            rooted_alias = f"build:{name}"
        rows.append({
            "rooted_alias": rooted_alias,
            "sha256": digest,
            "size": size,
        })
    names = {
        row["rooted_alias"].split(":", 1)[-1].rsplit("/", 1)[-1]
        for row in rows
    }
    if "foundry.toml" in names:
        build_system = "foundry"
    elif any(name.startswith("hardhat.config.") for name in names):
        build_system = "hardhat"
    else:
        build_system = "unresolved"
    js_lock = next(
        (
            row for row in rows
            if row["rooted_alias"].split(":", 1)[-1].rsplit("/", 1)[-1]
            in _JS_LOCK_NAMES
        ),
        None,
    )
    js_consumption: dict[str, Any] = {
        "state": "NOT_CONSUMED",
        "lock": None,
        "runtime_snapshot_entries": [],
    }
    if build_system == "foundry" and "package.json" in names:
        foundry_raw = _file_bytes_at(
            build_root_fd,
            "foundry.toml",
            directory_path=build_root_path,
            display_name="foundry.toml",
            limit=_MAX_MANIFEST_BYTES,
        )
        consumes_node_modules = False
        try:
            parsed_foundry = tomllib.loads(
                (foundry_raw or b"").decode("utf-8", "strict")
            )
            profiles = parsed_foundry.get("profile", {})
            if isinstance(profiles, Mapping):
                for profile in profiles.values():
                    libs = profile.get("libs") if isinstance(profile, Mapping) else None
                    if isinstance(libs, list) and any(
                        isinstance(item, str)
                        and item.replace("\\", "/").strip("/").split("/", 1)[0]
                        == "node_modules"
                        for item in libs
                    ):
                        consumes_node_modules = True
                        break
        except (UnicodeError, tomllib.TOMLDecodeError):
            consumes_node_modules = True
        if consumes_node_modules:
            js_consumption = {
                "state": "UNRESOLVED",
                "lock": js_lock,
                "runtime_snapshot_entries": [],
            }
    if build_system == "hardhat":
        js_consumption = {
            "state": "BOUND" if js_lock is not None else "UNRESOLVED",
            "lock": js_lock,
            "runtime_snapshot_entries": [],
        }
    return rows, build_system, js_consumption


def _validate_resolver_root_authority(
    value: object,
    *,
    project_record: Mapping[str, Any],
    build_record: Mapping[str, Any],
    relation: Mapping[str, Any],
) -> None:
    if not isinstance(value, Mapping):
        _fail("EVM build root lacks snapshot resolver authority")
    unsigned = dict(value)
    stored = unsigned.pop("authority_sha256", None)
    expected = {
        "schema_version": _ROOT_AUTHORITY_SCHEMA,
        "relation_kind": relation["kind"],
        "relative_path": relation["relative_path"],
        "project_descriptor_sha256": project_record["descriptor_sha256"],
        "build_descriptor_sha256": build_record["descriptor_sha256"],
    }
    if unsigned != expected or stored != _digest(expected):
        _fail("EVM build-root resolver authority differs from captured roots")


def _js_lock_selection_binding(
    raw_selection: object,
    manifests: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind the recon selector result to every captured lock candidate."""

    by_name = {
        str(row["rooted_alias"]).split(":", 1)[-1].rsplit("/", 1)[-1]: row
        for row in manifests
    }
    package = by_name.get("package.json")
    if package is None:
        unsigned = {"state": "NOT_APPLICABLE", "selection": None}
        return {**unsigned, "binding_sha256": _digest(unsigned)}
    if not isinstance(raw_selection, Mapping):
        unsigned = {
            "state": "TYPED_DEBT",
            "selection": None,
            "reason_code": "MANIFEST_CONSISTENT_JS_LOCK_UNAVAILABLE",
        }
        return {**unsigned, "binding_sha256": _digest(unsigned)}
    selection = dict(raw_selection)
    stored = selection.pop("selection_sha256", None)
    candidates = selection.get("candidates")
    selected_filename = selection.get("filename")
    selection_keys = {
        "candidates", "declared_package_manager", "direct_requirements_sha256",
        "family", "filename", "lockfile_sha256", "package_json_sha256",
        "reachable_selectors_sha256", "reachable_stanza_count", "schema",
        "selection_basis", "unused_selectors_sha256", "unused_stanza_count",
    }
    selected_family = selection.get("family")
    selected_lock_digest = selection.get("lockfile_sha256")
    selected_reachable_digest = selection.get("reachable_selectors_sha256")
    selected_unused_digest = selection.get("unused_selectors_sha256")
    selected_reachable_count = selection.get("reachable_stanza_count")
    selected_unused_count = selection.get("unused_stanza_count")
    declared_manager = selection.get("declared_package_manager")
    if (
        set(selection) != selection_keys
        or selection.get("schema") != "plamen.js-lock-selection.v2"
        or stored != _digest(selection)
        or selection.get("package_json_sha256") != package.get("sha256")
        or not isinstance(candidates, list)
        or not isinstance(selected_filename, str)
        or selected_filename not in SUPPORTED_LOCKFILES
        or selected_family not in {"npm", "yarn"}
        or (
            selected_family == "npm"
            and selected_filename not in {"package-lock.json", "npm-shrinkwrap.json"}
        )
        or (selected_family == "yarn" and selected_filename != "yarn.lock")
        or any(
            _HEX64.fullmatch(str(selection.get(field) or "")) is None
            for field in (
                "direct_requirements_sha256", "lockfile_sha256",
                "package_json_sha256", "reachable_selectors_sha256",
                "unused_selectors_sha256",
            )
        )
        or type(selected_reachable_count) is not int
        or not 0 <= selected_reachable_count <= _MAX_DEPENDENCY_FILES
        or type(selected_unused_count) is not int
        or not 0 <= selected_unused_count <= _MAX_DEPENDENCY_FILES
        or not isinstance(declared_manager, str)
        or selection.get("selection_basis")
        not in {
            "DECLARED_PACKAGE_MANAGER_LOCK",
            "UNIQUE_MANIFEST_CONSISTENT_LOCK",
        }
        or (
            selection.get("selection_basis") == "DECLARED_PACKAGE_MANAGER_LOCK"
            and not declared_manager.startswith(f"{selected_family}@")
        )
        or (
            selection.get("selection_basis")
            == "UNIQUE_MANIFEST_CONSISTENT_LOCK"
            and declared_manager != ""
        )
    ):
        _fail("EVM JavaScript lock-selection authority is malformed")
    expected_locks = {
        name: row
        for name, row in by_name.items()
        if name in _JS_LOCK_NAMES
    }
    candidate_names: set[str] = set()
    consistent: list[str] = []
    selected_candidate: Mapping[str, Any] | None = None
    candidate_keys = {
        "consistent", "error_codes", "family", "filename",
        "lockfile_sha256", "reachable_selectors_sha256",
        "reachable_stanza_count", "unused_selectors_sha256",
        "unused_stanza_count",
    }
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            _fail("EVM JavaScript lock candidate is malformed")
        filename = candidate.get("filename")
        manifest = expected_locks.get(str(filename))
        family = candidate.get("family")
        reachable_digest = candidate.get("reachable_selectors_sha256")
        unused_digest = candidate.get("unused_selectors_sha256")
        error_codes = candidate.get("error_codes")
        if (
            set(candidate) != candidate_keys
            or not isinstance(filename, str)
            or filename in candidate_names
            or manifest is None
            or candidate.get("lockfile_sha256") != manifest.get("sha256")
            or type(candidate.get("consistent")) is not bool
            or family not in {"npm", "yarn", "unsupported"}
            or (
                family == "npm"
                and filename not in {"package-lock.json", "npm-shrinkwrap.json"}
            )
            or (family == "yarn" and filename != "yarn.lock")
            or (family == "unsupported" and filename in SUPPORTED_LOCKFILES)
            or type(candidate.get("reachable_stanza_count")) is not int
            or not 0 <= candidate["reachable_stanza_count"] <= _MAX_DEPENDENCY_FILES
            or type(candidate.get("unused_stanza_count")) is not int
            or not 0 <= candidate["unused_stanza_count"] <= _MAX_DEPENDENCY_FILES
            or not isinstance(error_codes, list)
            or any(
                not isinstance(code, str)
                or not code
                or len(code) > 128
                for code in error_codes
            )
            or (candidate["consistent"] and error_codes != [])
            or (not candidate["consistent"] and not error_codes)
            or (
                family == "yarn"
                and candidate["consistent"]
                and (
                    _HEX64.fullmatch(str(reachable_digest or "")) is None
                    or _HEX64.fullmatch(str(unused_digest or "")) is None
                )
            )
            or (
                (family != "yarn" or not candidate["consistent"])
                and (reachable_digest != "" or unused_digest != "")
            )
        ):
            _fail("EVM JavaScript lock candidates differ from captured bytes")
        candidate_names.add(filename)
        if candidate["consistent"]:
            consistent.append(filename)
        if filename == selected_filename:
            selected_candidate = candidate
    selected_family_candidates = [
        candidate.get("filename")
        for candidate in candidates
        if isinstance(candidate, Mapping)
        and candidate.get("family") == selected_family
    ]
    if (
        candidate_names != set(expected_locks)
        or selected_filename not in consistent
        or (
            selection.get("selection_basis")
            == "UNIQUE_MANIFEST_CONSISTENT_LOCK"
            and consistent != [selected_filename]
        )
        or (
            selection.get("selection_basis")
            == "DECLARED_PACKAGE_MANAGER_LOCK"
            and selected_family_candidates != [selected_filename]
        )
    ):
        _fail("EVM JavaScript lock selection authority is inconsistent")
    if (
        selected_candidate is None
        or selected_candidate.get("family") != selected_family
        or selected_candidate.get("lockfile_sha256") != selected_lock_digest
        or selected_candidate.get("reachable_selectors_sha256")
        != selected_reachable_digest
        or selected_candidate.get("reachable_stanza_count")
        != selected_reachable_count
        or selected_candidate.get("unused_selectors_sha256")
        != selected_unused_digest
        or selected_candidate.get("unused_stanza_count") != selected_unused_count
    ):
        _fail("EVM JavaScript lock selection differs from selected candidate")
    complete_selection = {**selection, "selection_sha256": stored}
    unsigned = {"state": "SELECTED", "selection": complete_selection}
    return {**unsigned, "binding_sha256": _digest(unsigned)}


def _capture_js_lock_selection_binding(
    directory_fd: int,
    *,
    build_root_path: Path,
    manifests: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive lock semantics from exact bytes held by the workspace capture.

    Caller-supplied selector objects are deliberately not an input.  The
    central pure selector receives package.json and the complete known lock
    roster acquired descriptor-relative to the already authenticated build
    root.  A typed selector rejection is retained as workspace debt.
    """

    by_name = {
        str(row["rooted_alias"]).split(":", 1)[-1].rsplit("/", 1)[-1]: row
        for row in manifests
    }
    package_row = by_name.get("package.json")
    if package_row is None:
        return _js_lock_selection_binding(None, manifests)

    package_json = _file_bytes_at(
        directory_fd,
        "package.json",
        directory_path=build_root_path,
        display_name="package.json",
        limit=_MAX_MANIFEST_BYTES,
    )
    if (
        package_json is None
        or len(package_json) != package_row.get("size")
        or hashlib.sha256(package_json).hexdigest() != package_row.get("sha256")
    ):
        _fail("descriptor-captured package.json differs from manifest authority")

    lockfiles: dict[str, bytes] = {}
    for name in sorted((SUPPORTED_LOCKFILES | KNOWN_UNSUPPORTED_LOCKFILES) & by_name.keys()):
        row = by_name[name]
        captured = _file_bytes_at(
            directory_fd,
            name,
            directory_path=build_root_path,
            display_name=name,
            limit=_MAX_MANIFEST_BYTES,
        )
        if (
            captured is None
            or len(captured) != row.get("size")
            or hashlib.sha256(captured).hexdigest() != row.get("sha256")
        ):
            _fail(f"descriptor-captured {name} differs from manifest authority")
        lockfiles[name] = captured

    try:
        selected = select_js_lock_authority(package_json, lockfiles)
    except JSLockAuthorityError:
        return _js_lock_selection_binding(None, manifests)
    raw_selection = {
        **selected.binding_dict(),
        "selection_sha256": selected.selection_sha256,
    }
    return _js_lock_selection_binding(raw_selection, manifests)


def _runtime_authority_snapshot_bytes(authority: Mapping[str, Any]) -> bytes:
    value = dict(authority)
    value.pop("authority_digest", None)
    value.pop("authority_status", None)
    value.pop("reason", None)
    return _canonical_json(value)


def _signed_authority(value: object, *, tool_id: str) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    candidate = dict(value)
    stored = candidate.pop("authority_digest", None)
    if (
        value.get("tool_id") != tool_id
        or value.get("deterministic_provider_authority") is not True
        or not isinstance(stored, str)
        or _HEX64.fullmatch(stored) is None
        or hashlib.sha256(_canonical_json(candidate)).hexdigest() != stored
    ):
        return None
    return dict(value)


def _snapshot_bound_local_authority(
    value: object, *, tool_id: str
) -> dict[str, Any] | None:
    """Authenticate a self-bound local observation without elevating it.

    ``deterministic_provider_authority=False`` is required here.  Reviewed
    release authorities continue through ``_signed_authority``; this decoder is
    only for the explicitly weaker local-execution tier.
    """

    if not isinstance(value, Mapping):
        return None
    candidate = dict(value)
    stored = candidate.pop("authority_digest", None)
    if (
        value.get("tool_id") != tool_id
        or value.get("deterministic_provider_authority") is not False
        or not isinstance(stored, str)
        or _HEX64.fullmatch(stored) is None
        or hashlib.sha256(_canonical_json(candidate)).hexdigest() != stored
    ):
        return None
    return dict(value)


def _rule_tree_authority(implementation_root: Path) -> dict[str, Any]:
    base = implementation_root / "opengrep-rules"
    manifest = base / "rule-tree-authority.v1.json"
    try:
        from opengrep_rule_authority import (
            EXPECTED_RULE_AUTHORITY_SHA256,
            validate_installed_rule_authority,
        )

        available = validate_installed_rule_authority(base)
        raw, manifest_sha256 = _load_json_file(
            manifest, label="OpenGrep rule-tree authority"
        )
        if raw.get("authority_sha256") != EXPECTED_RULE_AUTHORITY_SHA256:
            _fail("OpenGrep rule-tree authority differs from release pin")
        trees = [
            {
                "name": name,
                "rooted_alias": f"implementation:opengrep-rules/{name}",
            }
            for name in sorted(available)
        ]
        unsigned = {
            "state": "ADMITTED",
            "manifest_rooted_alias": (
                "implementation:opengrep-rules/rule-tree-authority.v1.json"
            ),
            "manifest_sha256": manifest_sha256,
            "authority_sha256": raw["authority_sha256"],
            "trees": trees,
        }
        return {**unsigned, "binding_sha256": _digest(unsigned)}
    except Exception as exc:
        unsigned = {
            "state": "UNADMITTED",
            "manifest_rooted_alias": (
                "implementation:opengrep-rules/rule-tree-authority.v1.json"
            ),
            "manifest_sha256": None,
            "authority_sha256": None,
            "trees": [],
            "reason_codes": [f"RULE_TREE_AUTHORITY_UNAVAILABLE:{type(exc).__name__}"],
        }
        return {**unsigned, "binding_sha256": _digest(unsigned)}


def _rule_tree_execution_binding(implementation_root: Path) -> dict[str, Any]:
    """Replay the reviewed package and bind its exact read-only source root."""

    base = (Path(implementation_root) / "opengrep-rules").resolve(strict=True)
    authority = _rule_tree_authority(Path(implementation_root))
    if authority.get("state") != "ADMITTED":
        _fail("OpenGrep rule-tree execution source is unadmitted")
    root = _directory_record(base, rooted_alias="implementation:opengrep-rules")
    closure = _dependency_content_closure(
        base,
        rooted_alias="implementation:opengrep-rules",
        expected_root=root,
    )
    unsigned = {
        "schema": "plamen.opengrep-rule-tree-execution-binding.v1",
        "authority_binding_sha256": authority["binding_sha256"],
        "root": root,
        "content_closure": closure,
        "guest_path": "/workspace/source",
        "read_only": True,
    }
    return {**unsigned, "binding_sha256": _digest(unsigned)}


def build_evm_analysis_workspace_receipt(
    *,
    config: Mapping[str, Any],
    project_root: Path,
    run_id: str,
    audit_snapshot: Mapping[str, Any],
    owner_work_unit_key: str,
    implementation_root: Path,
    admitted_tool_authorities: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one snapshot-bound receipt without PATH lookup or subprocesses."""

    if not run_id or not _SAFE_TOKEN.fullmatch(run_id):
        _fail("workspace run_id is malformed")
    if not owner_work_unit_key or len(owner_work_unit_key.split("/")) != 6:
        _fail("workspace owner work-unit key is malformed")
    snapshot_digest = str(audit_snapshot.get("snapshot_digest") or "")
    components = audit_snapshot.get("components")
    source_scope = components.get("source_scope") if isinstance(components, Mapping) else None
    toolchain = components.get("toolchain") if isinstance(components, Mapping) else None
    if (
        _HEX64.fullmatch(snapshot_digest) is None
        or not isinstance(source_scope, Mapping)
        or _HEX64.fullmatch(str(source_scope.get("digest") or "")) is None
        or not isinstance(toolchain, Mapping)
    ):
        _fail("workspace requires a valid bound audit snapshot")

    project = Path(os.path.abspath(os.fspath(project_root)))
    raw_build_root = str(config.get("_resolved_build_root") or project)
    if not Path(raw_build_root).is_absolute():
        _fail("selected EVM build root must be absolute")
    build = Path(os.path.abspath(raw_build_root))
    projection_authority_raw = config.get("_committed_evm_analysis_projection")
    projection_authority = (
        _require_live_analysis_projection(projection_authority_raw)
        if projection_authority_raw is not None else None
    )
    project_record, build_record, root_relation, build_fd = (
        _descriptor_held_build_root(
            project, build, projection_authority=projection_authority
        )
    )
    try:
        if projection_authority is None:
            _validate_resolver_root_authority(
                config.get("_resolved_build_root_authority"),
                project_record=project_record,
                build_record=build_record,
                relation=root_relation,
            )
        manifests, build_system, js_consumption = _manifest_rows(
            build_fd, build_root_path=build, relation=root_relation
        )
        replay_manifests, replay_system, replay_js = _manifest_rows(
            build_fd, build_root_path=build, relation=root_relation
        )
        if (
            replay_manifests != manifests
            or replay_system != build_system
            or replay_js != js_consumption
        ):
            _fail("EVM workspace manifest bytes changed during capture")
        js_lock_authority = _capture_js_lock_selection_binding(
            build_fd,
            build_root_path=build,
            manifests=manifests,
        )
        replay_js_lock_authority = _capture_js_lock_selection_binding(
            build_fd,
            build_root_path=build,
            manifests=replay_manifests,
        )
        if replay_js_lock_authority != js_lock_authority:
            _fail("EVM JavaScript lock semantics changed during capture")

        analysis_projection: dict[str, Any] | None = None
        if projection_authority is not None:
            native_projection = _plain_json_shape(projection_authority.receipt)
            workspace_closure = _dependency_content_closure(
                build,
                rooted_alias="projection:.",
                expected_root=build_record,
            )
            source_copy_closure = _dependency_content_closure(
                build,
                rooted_alias="projection-source:.",
                expected_root=build_record,
                excluded_top_level=frozenset({"node_modules"}),
            )
            node_modules_path = build / "node_modules"
            node_modules_record = _directory_record(
                node_modules_path, rooted_alias="projection:node_modules"
            )
            node_modules_closure = _dependency_content_closure(
                node_modules_path,
                rooted_alias="projection:node_modules",
                expected_root=node_modules_record,
            )
            selection = js_lock_authority.get("selection")
            selection_sha256 = (
                selection.get("selection_sha256")
                if isinstance(selection, Mapping) else None
            )
            if (
                js_lock_authority.get("state") != "SELECTED"
                or selection_sha256
                != native_projection.get("js_lock_selection_sha256")
                or native_projection.get("host_descriptor_identity_sha256")
                != build_record["descriptor_sha256"]
                or native_projection.get("analysis_workspace_closure_sha256")
                != workspace_closure["closure_sha256"]
                or native_projection.get("analysis_workspace_bytes")
                != workspace_closure["byte_count"]
                or native_projection.get("analysis_workspace_file_count")
                != workspace_closure["file_count"]
                or native_projection.get("analysis_workspace_directory_count")
                != workspace_closure["directory_count"]
                or native_projection.get("source_copy_closure_sha256")
                != source_copy_closure["closure_sha256"]
                or native_projection.get("source_copy_bytes")
                != source_copy_closure["byte_count"]
                or native_projection.get("source_copy_file_count")
                != source_copy_closure["file_count"]
                or native_projection.get("source_copy_directory_count")
                != source_copy_closure["directory_count"]
                or native_projection.get("materialized_node_modules_closure_sha256")
                != node_modules_closure["closure_sha256"]
                or native_projection.get("materialized_node_modules_bytes")
                != node_modules_closure["byte_count"]
                or native_projection.get("materialized_node_modules_file_count")
                != node_modules_closure["file_count"]
                or native_projection.get("materialized_node_modules_directory_count")
                != node_modules_closure["directory_count"]
            ):
                _fail("private EVM analysis projection content lineage mismatch")
            projection_unsigned = {
                "state": "COMMITTED_READ_ONLY_GUEST_PROJECTION",
                "owner_work_unit_key": projection_authority.owner_work_unit_key,
                "snapshot_component": _plain_json_shape(
                    projection_authority.component
                ),
                "native_receipt": native_projection,
                "workspace_content_closure": workspace_closure,
                "source_copy_content_closure": source_copy_closure,
                "node_modules_root": node_modules_record,
                "node_modules_content_closure": node_modules_closure,
            }
            analysis_projection = {
                **projection_unsigned,
                "binding_sha256": _digest(projection_unsigned),
            }
    finally:
        os.close(build_fd)

    dependency_rows: list[dict[str, Any]] = []
    raw_dependencies = config.get("_resolved_compiled_dependency_roots") or ()
    if not isinstance(raw_dependencies, (list, tuple)):
        _fail("compiled dependency-root roster is malformed")
    for ordinal, raw in enumerate(raw_dependencies):
        path = Path(str(raw))
        if not path.is_absolute():
            _fail("compiled dependency root must be absolute")
        path = Path(os.path.abspath(os.fspath(path)))
        record = _directory_record(path, rooted_alias=f"dependency:{ordinal}")
        exclude_node_modules_bin = (
            _dependency_root_uses_node_modules_bin_policy(path)
        )
        dependency_rows.append({
            **record,
            "content_closure": _dependency_content_closure(
                path,
                rooted_alias=f"dependency:{ordinal}",
                expected_root=record,
                exclude_node_modules_bin=exclude_node_modules_bin,
            ),
        })
    if len({row["descriptor_sha256"] for row in dependency_rows}) != len(dependency_rows):
        _fail("compiled dependency-root roster contains duplicate physical roots")
    dependency_unsigned = {
        "snapshot_source_scope_sha256": str(source_scope["digest"]),
        "roots": dependency_rows,
    }
    dependency_closure = {
        **dependency_unsigned,
        "closure_sha256": _digest(dependency_unsigned),
    }
    js_consumption = _derive_js_consumption_binding(
        js_consumption,
        build_root=build,
        js_lock_authority=js_lock_authority,
        analysis_projection=analysis_projection,
        dependency_rows=dependency_rows,
    )
    manifest_digest = _digest(manifests)
    variant_unsigned = {
        "build_system": build_system,
        "build_root_descriptor_sha256": build_record["descriptor_sha256"],
        "manifest_set_sha256": manifest_digest,
        "dependency_closure_sha256": dependency_closure["closure_sha256"],
        "profile": "default" if build_system == "foundry" else "",
        "features": [],
        "tags": [],
        "remappings": [],
        "defines": [],
        "target_triples": [],
        "generated_source_policy": "BOUND_EXCLUDED",
    }
    build_variant = {
        **variant_unsigned,
        "build_variant_id": f"EVM-{_digest(variant_unsigned)[:24]}",
        "variant_sha256": _digest(variant_unsigned),
        "manifests": manifests,
    }
    preparation = config.get("_snapshot_input_preparation")
    preparation_value = dict(preparation) if isinstance(preparation, Mapping) else None
    preparation_valid = False
    if preparation_value is not None:
        preparation_unsigned = dict(preparation_value)
        preparation_digest = preparation_unsigned.pop("preparation_sha256", None)
        preparation_valid = bool(
            set(preparation_unsigned) == {"schema_version", "status", "reason"}
            and preparation_unsigned.get("schema_version")
            == "plamen.evm_input_preparation.v1"
            and preparation_digest == _digest(preparation_unsigned)
        )
    preparation_declares_ready = bool(
        preparation_valid and preparation_value.get("status") == "PREPARED"
    )
    if preparation_declares_ready and analysis_projection is None:
        _fail(
            "PREPARED EVM inputs lack committed native analysis projection"
        )
    if analysis_projection is not None and not preparation_declares_ready:
        _fail(
            "committed EVM analysis projection lacks PREPARED input state"
        )
    materialization_unsigned = {
        "state": (
            "SNAPSHOT_BOUND"
            if preparation_declares_ready and analysis_projection is not None
            else "UNREADY"
        ),
        "snapshot_sha256": snapshot_digest,
        "preparation_receipt": preparation_value if preparation_valid else None,
        "build_variant_sha256": build_variant["variant_sha256"],
        "dependency_closure_sha256": dependency_closure["closure_sha256"],
    }
    input_materialization = {
        **materialization_unsigned,
        "binding_sha256": _digest(materialization_unsigned),
    }

    governance_rows, governance_sha256, lock_sha256 = _governance_rows(
        Path(implementation_root)
    )
    runtime_entries = toolchain.get("runtime_entries")
    runtime_entries = runtime_entries if isinstance(runtime_entries, Mapping) else {}
    supplied = admitted_tool_authorities or {}
    rule_authority = _rule_tree_authority(Path(implementation_root))
    tool_rows: list[dict[str, Any]] = []
    for tool_id in _TOOL_IDS:
        governance = governance_rows[tool_id]
        governance_digest = _digest(governance)
        runtime_key = f"@runtime/tool/{tool_id}"
        runtime_entry = runtime_entries.get(runtime_key)
        snapshot_entry = (
            {"identity": runtime_key, **dict(runtime_entry)}
            if isinstance(runtime_entry, Mapping)
            else None
        )
        authority = _signed_authority(supplied.get(tool_id), tool_id=tool_id)
        governed_runtime = governance.get("runtime_authority")
        governance_admits = (
            isinstance(governed_runtime, Mapping)
            and governed_runtime.get("deterministic_provider_authority") is True
        )
        reasons: list[str] = []
        if input_materialization["state"] != "SNAPSHOT_BOUND":
            reasons.append("SNAPSHOT_BOUND_INPUT_MATERIALIZATION_UNAVAILABLE")
        if js_lock_authority["state"] == "TYPED_DEBT":
            reasons.append("MANIFEST_CONSISTENT_JS_LOCK_UNAVAILABLE")
        if js_consumption["state"] == "UNRESOLVED":
            reasons.append("JAVASCRIPT_DEPENDENCY_CONSUMPTION_UNBOUND")
        if snapshot_entry is None:
            reasons.append("SNAPSHOT_RUNTIME_IDENTITY_UNAVAILABLE")
        elif (
            set(runtime_entry) != {"sha256", "byte_count"}
            or _HEX64.fullmatch(str(runtime_entry.get("sha256") or "")) is None
            or type(runtime_entry.get("byte_count")) is not int
            or runtime_entry["byte_count"] <= 0
        ):
            reasons.append("SNAPSHOT_RUNTIME_IDENTITY_MALFORMED")
        if not governance_admits:
            reasons.append("GOVERNANCE_DENIES_DETERMINISTIC_AUTHORITY")
        if authority is None:
            reasons.append("SIGNED_RUNTIME_AUTHORITY_UNAVAILABLE")
        else:
            if authority.get("toolchain_governance_sha256") != governance_sha256:
                reasons.append("RUNTIME_GOVERNANCE_DIGEST_MISMATCH")
            if authority.get("toolchain_version_lock_sha256") != lock_sha256:
                reasons.append("RUNTIME_VERSION_LOCK_DIGEST_MISMATCH")
            executable = authority.get("resolved_executable")
            if (
                not isinstance(executable, str)
                or not os.path.isabs(executable)
            ):
                reasons.append("SIGNED_RUNTIME_EXECUTABLE_UNUSABLE")
            if authority.get("identity_kind") == "command" and (
                _HEX64.fullmatch(str(authority.get("executable_sha256") or "")) is None
                or type(authority.get("executable_bytes")) is not int
                or authority["executable_bytes"] <= 0
            ):
                reasons.append("SIGNED_RUNTIME_EXECUTABLE_IDENTITY_INCOMPLETE")
            if authority.get("identity_kind") == "python_distribution" and (
                not isinstance(authority.get("module_origin"), str)
                or not os.path.isabs(str(authority.get("module_origin")))
                or _HEX64.fullmatch(str(authority.get("module_sha256") or "")) is None
            ):
                reasons.append("SIGNED_RUNTIME_MODULE_IDENTITY_INCOMPLETE")
            frozen_bytes = _runtime_authority_snapshot_bytes(authority)
            if (
                snapshot_entry is None
                or snapshot_entry.get("sha256")
                != hashlib.sha256(frozen_bytes).hexdigest()
                or snapshot_entry.get("byte_count") != len(frozen_bytes)
            ):
                reasons.append("SIGNED_RUNTIME_SNAPSHOT_ENTRY_MISMATCH")
        if tool_id in {"opengrep", "semgrep"} and rule_authority["state"] != "ADMITTED":
            reasons.append("RULE_TREE_AUTHORITY_UNADMITTED")
        admitted = not reasons
        private_identity = authority if authority is not None else None
        row_unsigned = {
            "tool_id": tool_id,
            "admission_state": "ADMITTED" if admitted else "UNADMITTED",
            "governance_row_sha256": governance_digest,
            "governance_runtime_state": (
                str(governed_runtime.get("identity_status") or "INVALID")
                if isinstance(governed_runtime, Mapping) else "INVALID"
            ),
            "snapshot_runtime_identity": snapshot_entry,
            "signed_runtime_authority": private_identity,
            "rule_tree_authority_sha256": (
                rule_authority["binding_sha256"]
                if tool_id in {"opengrep", "semgrep"} else None
            ),
            "build_variant_sha256": build_variant["variant_sha256"],
            "dependency_closure_sha256": dependency_closure["closure_sha256"],
            "reason_codes": sorted(set(reasons)),
        }
        tool_rows.append({**row_unsigned, "tool_row_sha256": _digest(row_unsigned)})
    if build_system == "hardhat":
        js_entries = []
        for name in ("node", "npm"):
            item = runtime_entries.get(f"@runtime/tool/{name}")
            if isinstance(item, Mapping):
                js_entries.append({"identity": f"@runtime/tool/{name}", **dict(item)})
        js_consumption["runtime_snapshot_entries"] = js_entries

    solc_row = next(row for row in tool_rows if row["tool_id"] == "solc")
    source_closure = {
        "snapshot_source_scope_sha256": str(source_scope["digest"]),
        "path_set_sha256": str(source_scope.get("path_set_digest") or ""),
        "file_count": int(source_scope.get("file_count") or 0),
        "byte_count": int(source_scope.get("byte_count") or 0),
    }
    unsigned: dict[str, Any] = {
        "schema_version": WORKSPACE_SCHEMA,
        "state": (
            "BOUND"
            if all(row["admission_state"] == "ADMITTED" for row in tool_rows)
            else "BOUND_WITH_DEBT"
        ),
        "run_id": run_id,
        "owner": {
            "owner_kind": "DRIVER",
            "writer_identity": "driver",
            "model_identity": "Python",
            "work_unit_key": owner_work_unit_key,
        },
        "snapshot": {
            "snapshot_sha256": snapshot_digest,
            "source_scope_sha256": str(source_scope["digest"]),
            "toolchain_sha256": str(toolchain.get("digest") or ""),
        },
        "project_root": project_record,
        "build_root": build_record,
        "root_relation": root_relation,
        "analysis_projection": analysis_projection,
        "source_closure": source_closure,
        "input_materialization": input_materialization,
        "js_lock_authority": js_lock_authority,
        "dependency_closure": dependency_closure,
        "build_variant": build_variant,
        "solc_identity": {
            "admission_state": solc_row["admission_state"],
            "tool_row_sha256": solc_row["tool_row_sha256"],
            "snapshot_runtime_identity": solc_row["snapshot_runtime_identity"],
        },
        "js_consumption": js_consumption,
        "rule_tree_authority": rule_authority,
        "toolchain_controls": {
            "governance_sha256": governance_sha256,
            "version_lock_sha256": lock_sha256,
        },
        "tools": tool_rows,
    }
    return {**unsigned, "receipt_sha256": _digest(unsigned)}


def _validate_dependency_content_closure_shape(
    value: object,
    *,
    label: str,
    expected_excluded_top_level: frozenset[str] = frozenset(),
    expect_node_modules_bin_exclusion: bool = False,
) -> dict[str, Any]:
    expected_fields = {
        "schema_version", "file_count", "directory_count", "byte_count",
        "entry_stream_sha256", "closure_sha256",
    }
    if expected_excluded_top_level:
        expected_fields.add("excluded_top_level")
    if expect_node_modules_bin_exclusion:
        expected_fields.add("excluded_path_policy")
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        _fail(f"{label} content closure fields are malformed")
    unsigned = dict(value)
    stored = unsigned.pop("closure_sha256", None)
    if (
        value.get("schema_version") != _DEPENDENCY_CLOSURE_SCHEMA
        or type(value.get("file_count")) is not int
        or not 0 <= value["file_count"] <= _MAX_DEPENDENCY_FILES
        or type(value.get("directory_count")) is not int
        or not 0 <= value["directory_count"] <= _MAX_DEPENDENCY_DIRECTORIES
        or type(value.get("byte_count")) is not int
        or not 0 <= value["byte_count"] <= _MAX_DEPENDENCY_BYTES
        or _HEX64.fullmatch(str(value.get("entry_stream_sha256") or "")) is None
        or (
            expected_excluded_top_level
            and value.get("excluded_top_level")
            != sorted(expected_excluded_top_level)
        )
        or (
            expect_node_modules_bin_exclusion
            and value.get("excluded_path_policy")
            != "NODE_MODULES_BIN_DIRECTORIES_V2"
        )
        or stored != _digest(unsigned)
    ):
        _fail(f"{label} content closure integrity failure")
    return dict(value)


def _validate_source_copy_content_closure_shape(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "file_count", "directory_count", "byte_count",
        "entry_stream_sha256", "excluded_top_level", "closure_sha256",
    }:
        _fail("EVM projected source-copy closure fields are malformed")
    unsigned = dict(value)
    stored = unsigned.pop("closure_sha256", None)
    if (
        value.get("schema_version") != _DEPENDENCY_CLOSURE_SCHEMA
        or value.get("excluded_top_level") != ["node_modules"]
        or type(value.get("file_count")) is not int
        or not 0 <= value["file_count"] <= _MAX_DEPENDENCY_FILES
        or type(value.get("directory_count")) is not int
        or not 0 <= value["directory_count"] <= _MAX_DEPENDENCY_DIRECTORIES
        or type(value.get("byte_count")) is not int
        or not 0 <= value["byte_count"] <= _MAX_DEPENDENCY_BYTES
        or _HEX64.fullmatch(str(value.get("entry_stream_sha256") or "")) is None
        or stored != _digest(unsigned)
    ):
        _fail("EVM projected source-copy closure integrity failure")
    return dict(value)


def _validate_analysis_projection_binding(
    value: object,
    *,
    build_root: Mapping[str, Any],
    js_lock_authority: Mapping[str, Any],
    source_scope_sha256: object,
) -> dict[str, Any] | None:
    if value is None:
        return None
    keys = {
        "state", "owner_work_unit_key", "snapshot_component", "native_receipt",
        "workspace_content_closure", "source_copy_content_closure",
        "node_modules_root", "node_modules_content_closure", "binding_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail("EVM analysis projection workspace binding is malformed")
    unsigned = dict(value)
    stored = unsigned.pop("binding_sha256", None)
    owner = value.get("owner_work_unit_key")
    if (
        value.get("state") != "COMMITTED_READ_ONLY_GUEST_PROJECTION"
        or not isinstance(owner, str)
        or len(owner.split("/")) != 6
        or owner.split("/")[-2:] != ["recon", ANALYSIS_PROJECTION_WORK_UNIT_ID]
        or stored != _digest(unsigned)
    ):
        _fail("EVM analysis projection workspace authority is invalid")
    component = value.get("snapshot_component")
    component_keys = {
        "kind", "receipt_sha256", "receipt_byte_count",
        "materialization_lineage_sha256", "materialization_lineage_byte_count",
        "native_materialization_request_sha256",
        "original_source_scope_sha256", "source_copy_closure_sha256",
        "js_lock_selection_sha256",
        "dependency_materialization_receipt_sha256",
        "materialized_node_modules_closure_sha256",
        "analysis_workspace_closure_sha256",
        "native_projection_custody_sha256", "digest",
    }
    if not isinstance(component, Mapping) or set(component) != component_keys:
        _fail("EVM analysis projection snapshot component is absent")
    # Reuse the exact component validator without requiring the full snapshot.
    component_unsigned = dict(component)
    component_digest = component_unsigned.pop("digest", None)
    if (
        component.get("kind") != ANALYSIS_PROJECTION_COMPONENT_KIND
        or component_digest != _digest(component_unsigned)
        or component.get("original_source_scope_sha256") != source_scope_sha256
        or type(component.get("receipt_byte_count")) is not int
        or not 0 < component["receipt_byte_count"] <= _MAX_CONTROL_BYTES
        or type(component.get("materialization_lineage_byte_count")) is not int
        or not 0 < component["materialization_lineage_byte_count"] <= _MAX_CONTROL_BYTES
        or any(
            _HEX64.fullmatch(str(component.get(field) or "")) is None
            for field in component_keys - {
                "kind", "receipt_byte_count",
                "materialization_lineage_byte_count", "digest",
            }
        )
    ):
        _fail("EVM analysis projection snapshot component is malformed")
    native = _validate_analysis_projection_receipt(
        value.get("native_receipt"), component=component
    )
    workspace_closure = _validate_dependency_content_closure_shape(
        value.get("workspace_content_closure"), label="analysis projection"
    )
    source_closure = _validate_source_copy_content_closure_shape(
        value.get("source_copy_content_closure")
    )
    node_closure = _validate_dependency_content_closure_shape(
        value.get("node_modules_content_closure"), label="projected node_modules"
    )
    node_root = value.get("node_modules_root")
    selection = js_lock_authority.get("selection")
    if (
        not isinstance(node_root, Mapping)
        or set(node_root) != {
            "absolute_path", "rooted_alias", "physical_identity",
            "descriptor_sha256",
        }
        or node_root.get("rooted_alias") != "projection:node_modules"
        or native["host_descriptor_identity_sha256"]
        != build_root.get("descriptor_sha256")
        or native["analysis_workspace_closure_sha256"]
        != workspace_closure["closure_sha256"]
        or native["analysis_workspace_bytes"] != workspace_closure["byte_count"]
        or native["analysis_workspace_file_count"] != workspace_closure["file_count"]
        or native["analysis_workspace_directory_count"]
        != workspace_closure["directory_count"]
        or native["source_copy_closure_sha256"] != source_closure["closure_sha256"]
        or native["source_copy_bytes"] != source_closure["byte_count"]
        or native["source_copy_file_count"] != source_closure["file_count"]
        or native["source_copy_directory_count"] != source_closure["directory_count"]
        or native["materialized_node_modules_closure_sha256"]
        != node_closure["closure_sha256"]
        or native["materialized_node_modules_bytes"] != node_closure["byte_count"]
        or native["materialized_node_modules_file_count"] != node_closure["file_count"]
        or native["materialized_node_modules_directory_count"]
        != node_closure["directory_count"]
        or not isinstance(selection, Mapping)
        or native["js_lock_selection_sha256"]
        != selection.get("selection_sha256")
    ):
        _fail("EVM analysis projection workspace lineage is inconsistent")
    return dict(value)


def _validate_workspace_input_closure_shape(value: Mapping[str, Any]) -> None:
    dependency = value.get("dependency_closure")
    build_variant = value.get("build_variant")
    materialization = value.get("input_materialization")
    relation = value.get("root_relation")
    source = value.get("source_closure")
    js_lock_authority = value.get("js_lock_authority")
    if (
        not isinstance(dependency, Mapping)
        or set(dependency) != {
            "snapshot_source_scope_sha256", "roots", "closure_sha256"
        }
        or not isinstance(dependency.get("roots"), list)
        or not isinstance(build_variant, Mapping)
        or not isinstance(materialization, Mapping)
        or not isinstance(relation, Mapping)
        or not isinstance(source, Mapping)
        or not isinstance(js_lock_authority, Mapping)
    ):
        _fail("EVM workspace input-closure fields are malformed")
    rebound_js = _js_lock_selection_binding(
        (
            js_lock_authority.get("selection")
            if js_lock_authority.get("state") == "SELECTED"
            else None
        ),
        build_variant.get("manifests")
        if isinstance(build_variant.get("manifests"), list) else (),
    )
    if js_lock_authority.get("state") == "TYPED_DEBT":
        unsigned_js = dict(js_lock_authority)
        stored_js = unsigned_js.pop("binding_sha256", None)
        if (
            rebound_js.get("state") != "TYPED_DEBT"
            or set(unsigned_js) != {"state", "selection", "reason_code"}
            or unsigned_js.get("selection") is not None
            or unsigned_js.get("reason_code")
            != "MANIFEST_CONSISTENT_JS_LOCK_UNAVAILABLE"
            or stored_js != _digest(unsigned_js)
        ):
            _fail("EVM JavaScript lock typed debt is malformed")
    elif rebound_js != dict(js_lock_authority):
        _fail("EVM JavaScript lock-selection binding integrity failure")
    if set(materialization) != {
        "state", "snapshot_sha256", "preparation_receipt",
        "build_variant_sha256", "dependency_closure_sha256", "binding_sha256",
    }:
        _fail("EVM input-materialization binding fields are malformed")
    materialization_unsigned = dict(materialization)
    stored_materialization = materialization_unsigned.pop("binding_sha256", None)
    preparation = materialization.get("preparation_receipt")
    preparation_ready = False
    if preparation is not None:
        if not isinstance(preparation, Mapping):
            _fail("EVM input-preparation receipt is malformed")
        preparation_unsigned = dict(preparation)
        preparation_digest = preparation_unsigned.pop("preparation_sha256", None)
        preparation_ready = bool(
            set(preparation_unsigned) == {"schema_version", "status", "reason"}
            and preparation_unsigned.get("schema_version")
            == "plamen.evm_input_preparation.v1"
            and preparation_unsigned.get("status") == "PREPARED"
            and preparation_digest == _digest(preparation_unsigned)
        )
    if (
        materialization.get("state") not in {"SNAPSHOT_BOUND", "UNREADY"}
        or stored_materialization != _digest(materialization_unsigned)
        or materialization.get("snapshot_sha256")
        != value.get("snapshot", {}).get("snapshot_sha256")
        or materialization.get("build_variant_sha256")
        != build_variant.get("variant_sha256")
        or materialization.get("dependency_closure_sha256")
        != dependency.get("closure_sha256")
        or (materialization.get("state") == "SNAPSHOT_BOUND")
        != (preparation_ready and value.get("analysis_projection") is not None)
        or (preparation_ready and value.get("analysis_projection") is None)
    ):
        _fail("EVM input-materialization binding integrity failure")
    dependency_unsigned = dict(dependency)
    stored_dependency = dependency_unsigned.pop("closure_sha256", None)
    if (
        _HEX64.fullmatch(str(dependency.get("snapshot_source_scope_sha256") or "")) is None
        or stored_dependency != _digest(dependency_unsigned)
        or dependency.get("snapshot_source_scope_sha256")
        != source.get("snapshot_source_scope_sha256")
    ):
        _fail("EVM dependency closure integrity failure")
    seen_roots: set[str] = set()
    seen_descriptors: set[str] = set()
    for ordinal, row in enumerate(dependency["roots"]):
        if not isinstance(row, Mapping) or set(row) != {
            "absolute_path", "rooted_alias", "physical_identity",
            "descriptor_sha256", "content_closure",
        }:
            _fail("EVM dependency-root row fields are malformed")
        alias = row.get("rooted_alias")
        absolute = row.get("absolute_path")
        if alias != f"dependency:{ordinal}" or not isinstance(absolute, str) or not os.path.isabs(absolute):
            _fail("EVM dependency-root identity is malformed")
        descriptor = str(row.get("descriptor_sha256") or "")
        if alias in seen_roots or descriptor in seen_descriptors or _HEX64.fullmatch(descriptor) is None:
            _fail("EVM dependency-root denominator is duplicate or malformed")
        seen_roots.add(alias)
        seen_descriptors.add(descriptor)
        _validate_dependency_content_closure_shape(
            row.get("content_closure"),
            label=alias,
            expect_node_modules_bin_exclusion=(
                _dependency_root_uses_node_modules_bin_policy(Path(absolute))
            ),
        )

    manifests = build_variant.get("manifests")
    if (
        set(build_variant) != {
            "build_system", "build_root_descriptor_sha256",
            "manifest_set_sha256", "dependency_closure_sha256", "profile",
            "features", "tags", "remappings", "defines", "target_triples",
            "generated_source_policy", "build_variant_id", "variant_sha256",
            "manifests",
        }
        or not isinstance(manifests, list)
    ):
        _fail("EVM build manifest denominator is malformed")
    aliases: list[str] = []
    for row in manifests:
        if not isinstance(row, Mapping) or set(row) != {"rooted_alias", "sha256", "size"}:
            _fail("EVM build manifest row is malformed")
        alias = str(row.get("rooted_alias") or "")
        digest = str(row.get("sha256") or "")
        size = row.get("size")
        if (
            not alias
            or _HEX64.fullmatch(digest) is None
            or type(size) is not int
            or not 0 <= size <= _MAX_MANIFEST_BYTES
        ):
            _fail("EVM build manifest identity is malformed")
        aliases.append(alias)
    if len(aliases) != len(set(aliases)):
        _fail("EVM build manifest denominator contains duplicates")
    manifest_set_sha256 = _digest(manifests)
    if (
        build_variant.get("manifest_set_sha256") != manifest_set_sha256
        or build_variant.get("dependency_closure_sha256") != dependency.get("closure_sha256")
        or build_variant.get("build_root_descriptor_sha256")
        != value.get("build_root", {}).get("descriptor_sha256")
    ):
        _fail("EVM build variant input closure differs")
    variant_unsigned = {
        key: build_variant[key]
        for key in (
            "build_system", "build_root_descriptor_sha256",
            "manifest_set_sha256", "dependency_closure_sha256", "profile",
            "features", "tags", "remappings", "defines", "target_triples",
            "generated_source_policy",
        )
    }
    variant_id = build_variant.get("build_variant_id")
    variant_sha256 = build_variant.get("variant_sha256")
    if (
        not isinstance(variant_sha256, str)
        or
        variant_sha256 != _digest(variant_unsigned)
        or variant_id != f"EVM-{variant_sha256[:24]}"
    ):
        _fail("EVM build variant integrity failure")
    _validate_analysis_projection_binding(
        value.get("analysis_projection"),
        build_root=value.get("build_root", {}),
        js_lock_authority=js_lock_authority,
        source_scope_sha256=source.get("snapshot_source_scope_sha256"),
    )


def validate_evm_analysis_workspace_receipt(
    value: object,
    *,
    expected_run_id: str | None = None,
    expected_snapshot_sha256: str | None = None,
    expected_owner_work_unit_key: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("EVM workspace receipt is not an object")
    receipt = dict(value)
    stored = receipt.pop("receipt_sha256", None)
    if (
        value.get("schema_version") != WORKSPACE_SCHEMA
        or value.get("state") not in {"BOUND", "BOUND_WITH_DEBT"}
        or not isinstance(stored, str)
        or _HEX64.fullmatch(stored) is None
        or _digest(receipt) != stored
    ):
        _fail("EVM workspace receipt integrity failure")
    owner = value.get("owner")
    snapshot = value.get("snapshot")
    tools = value.get("tools")
    project_root = value.get("project_root")
    build_root = value.get("build_root")
    root_relation = value.get("root_relation")
    if (
        not isinstance(owner, Mapping)
        or set(owner) != {"owner_kind", "writer_identity", "model_identity", "work_unit_key"}
        or owner.get("owner_kind") != "DRIVER"
        or owner.get("writer_identity") != "driver"
        or owner.get("model_identity") != "Python"
        or not isinstance(snapshot, Mapping)
        or _HEX64.fullmatch(str(snapshot.get("snapshot_sha256") or "")) is None
        or not isinstance(tools, list)
        or [row.get("tool_id") for row in tools if isinstance(row, Mapping)] != list(_TOOL_IDS)
        or not isinstance(project_root, Mapping)
        or not isinstance(build_root, Mapping)
        or not isinstance(root_relation, Mapping)
    ):
        _fail("EVM workspace receipt authority fields are malformed")
    relation_unsigned = dict(root_relation)
    relation_digest = relation_unsigned.pop("relation_sha256", None)
    if (
        set(relation_unsigned) != {
            "kind", "relative_path", "project_descriptor_sha256",
            "build_descriptor_sha256",
        }
        or relation_unsigned.get("kind")
        not in {
            "PROJECT_ROOT", "DESCENDANT", "ANCESTOR",
            "DISJOINT_PRIVATE_PROJECTION",
        }
        or not isinstance(relation_unsigned.get("relative_path"), str)
        or not relation_unsigned["relative_path"]
        or _digest(relation_unsigned) != relation_digest
        or relation_unsigned["project_descriptor_sha256"]
        != project_root.get("descriptor_sha256")
        or relation_unsigned["build_descriptor_sha256"]
        != build_root.get("descriptor_sha256")
    ):
        _fail("EVM workspace root relation integrity failure")
    try:
        project_path = Path(str(project_root["absolute_path"]))
        build_path = Path(str(build_root["absolute_path"]))
        below = build_path.relative_to(project_path)
        actual_kind = "PROJECT_ROOT" if not below.parts else "DESCENDANT"
        actual_relative = "." if not below.parts else below.as_posix()
    except (KeyError, ValueError):
        try:
            above = project_path.relative_to(build_path)
        except (UnboundLocalError, ValueError):
            actual_kind = "DISJOINT_PRIVATE_PROJECTION"
            actual_relative = "."
        else:
            actual_kind = "ANCESTOR"
            actual_relative = above.as_posix()
    if (
        root_relation.get("kind") != actual_kind
        or root_relation.get("relative_path") != actual_relative
    ):
        _fail("EVM workspace root relation differs from bound paths")
    if (
        (actual_kind == "DISJOINT_PRIVATE_PROJECTION")
        != (value.get("analysis_projection") is not None)
    ):
        _fail("EVM disjoint root and committed projection authority differ")
    _validate_workspace_input_closure_shape(value)
    if expected_run_id is not None and value.get("run_id") != expected_run_id:
        _fail("EVM workspace receipt run_id differs")
    if expected_snapshot_sha256 is not None and snapshot.get("snapshot_sha256") != expected_snapshot_sha256:
        _fail("EVM workspace receipt snapshot differs")
    if expected_owner_work_unit_key is not None and owner.get("work_unit_key") != expected_owner_work_unit_key:
        _fail("EVM workspace receipt owner differs")
    for row in tools:
        unsigned = dict(row)
        row_digest = unsigned.pop("tool_row_sha256", None)
        if (
            set(row) != {
                "tool_id", "admission_state", "governance_row_sha256",
                "governance_runtime_state", "snapshot_runtime_identity",
                "signed_runtime_authority", "rule_tree_authority_sha256",
                "build_variant_sha256", "dependency_closure_sha256",
                "reason_codes", "tool_row_sha256",
            }
            or row.get("admission_state") not in {"ADMITTED", "UNADMITTED"}
            or _digest(unsigned) != row_digest
            or (row.get("admission_state") == "ADMITTED" and row.get("reason_codes"))
        ):
            _fail("EVM workspace tool-row integrity failure")
        signed = row.get("signed_runtime_authority")
        materialization_unready = (
            value["input_materialization"]["state"] != "SNAPSHOT_BOUND"
        )
        materialization_debt_declared = (
            "SNAPSHOT_BOUND_INPUT_MATERIALIZATION_UNAVAILABLE"
            in row.get("reason_codes", ())
        )
        if materialization_unready != materialization_debt_declared:
            _fail("EVM workspace tool/input-materialization debt is inconsistent")
        js_lock_debt = value["js_lock_authority"]["state"] == "TYPED_DEBT"
        js_lock_debt_declared = (
            "MANIFEST_CONSISTENT_JS_LOCK_UNAVAILABLE"
            in row.get("reason_codes", ())
        )
        if js_lock_debt != js_lock_debt_declared:
            _fail("EVM workspace tool/JavaScript-lock debt is inconsistent")
        if signed is not None:
            if (
                not isinstance(signed, Mapping)
                or _signed_authority(signed, tool_id=str(row.get("tool_id")))
                != dict(signed)
            ):
                _fail("EVM workspace signed tool authority integrity failure")
            snapshot_entry = row.get("snapshot_runtime_identity")
            frozen = _runtime_authority_snapshot_bytes(signed)
            exact = bool(
                isinstance(snapshot_entry, Mapping)
                and snapshot_entry.get("sha256")
                == hashlib.sha256(frozen).hexdigest()
                and snapshot_entry.get("byte_count") == len(frozen)
            )
            mismatch_declared = (
                "SIGNED_RUNTIME_SNAPSHOT_ENTRY_MISMATCH"
                in row.get("reason_codes", ())
            )
            if exact == mismatch_declared:
                _fail("EVM workspace signed tool/snapshot binding is inconsistent")
    return dict(value)


def workspace_public_reference(receipt: Mapping[str, Any]) -> dict[str, Any]:
    value = validate_evm_analysis_workspace_receipt(receipt)
    owner = value["owner"]
    tools = value["tools"]
    unsigned = {
        "schema_version": WORKSPACE_REFERENCE_SCHEMA,
        "artifact_identity": WORKSPACE_RECEIPT_IDENTITY,
        "receipt_sha256": value["receipt_sha256"],
        "owner_work_unit_key": owner["work_unit_key"],
        "snapshot_sha256": value["snapshot"]["snapshot_sha256"],
        "project_root": {
            "rooted_alias": value["project_root"]["rooted_alias"],
            "descriptor_sha256": value["project_root"]["descriptor_sha256"],
        },
        "build_root": {
            "rooted_alias": value["build_root"]["rooted_alias"],
            "descriptor_sha256": value["build_root"]["descriptor_sha256"],
        },
        "root_relation_sha256": value["root_relation"]["relation_sha256"],
        "source_closure_sha256": value["source_closure"]["snapshot_source_scope_sha256"],
        "dependency_closure_sha256": value["dependency_closure"]["closure_sha256"],
        "build_variant_sha256": value["build_variant"]["variant_sha256"],
        "input_materialization_state": value["input_materialization"]["state"],
        "input_materialization_sha256": value["input_materialization"][
            "binding_sha256"
        ],
        "js_lock_authority_state": value["js_lock_authority"]["state"],
        "js_lock_authority_sha256": value["js_lock_authority"]["binding_sha256"],
        "tool_rows": [
            {
                "tool_id": row["tool_id"],
                "admission_state": row["admission_state"],
                "tool_row_sha256": row["tool_row_sha256"],
                "rule_tree_authority_sha256": row["rule_tree_authority_sha256"],
            }
            for row in tools
        ],
    }
    return {**unsigned, "reference_sha256": _digest(unsigned)}


def require_admitted_workspace_tool(
    receipt: Mapping[str, Any], tool_id: str
) -> dict[str, Any]:
    value = validate_evm_analysis_workspace_receipt(receipt)
    matches = [row for row in value["tools"] if row["tool_id"] == tool_id]
    if len(matches) != 1 or matches[0]["admission_state"] != "ADMITTED":
        reasons = matches[0].get("reason_codes") if matches else ["TOOL_ROW_ABSENT"]
        _fail(
            f"workspace tool {tool_id} is not admitted: "
            + ",".join(str(reason) for reason in reasons)
        )
    row = dict(matches[0])
    signed = row.get("signed_runtime_authority")
    if not isinstance(signed, Mapping):
        _fail(f"workspace tool {tool_id} lacks signed execution authority")
    if signed.get("identity_kind") == "command":
        executable = Path(str(signed.get("resolved_executable") or ""))
        expected_digest = str(signed.get("executable_sha256") or "")
        expected_bytes = signed.get("executable_bytes")
        if (
            not executable.is_absolute()
            or _HEX64.fullmatch(expected_digest) is None
            or type(expected_bytes) is not int
            or expected_bytes <= 0
        ):
            _fail(f"workspace tool {tool_id} executable identity is malformed")
        observed_digest, observed_bytes = _file_digest(
            executable, limit=max(expected_bytes, 1)
        )
        if observed_digest != expected_digest or observed_bytes != expected_bytes:
            _fail(f"workspace tool {tool_id} executable changed after snapshot")
    elif signed.get("identity_kind") == "python_distribution":
        module = Path(str(signed.get("module_origin") or ""))
        expected_digest = str(signed.get("module_sha256") or "")
        try:
            module_size = os.lstat(module).st_size
        except OSError as exc:
            _fail(f"workspace tool {tool_id} module is unavailable", exc)
        if not module.is_absolute() or _HEX64.fullmatch(expected_digest) is None:
            _fail(f"workspace tool {tool_id} module identity is malformed")
        observed_digest, _observed_bytes = _file_digest(
            module, limit=max(int(module_size), 1)
        )
        if observed_digest != expected_digest:
            _fail(f"workspace tool {tool_id} module changed after snapshot")
    return row


def _dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str]:
    language = str(config.get("language") or "").strip().lower()
    ecosystem = {"solidity": "evm", "ethereum": "evm"}.get(language, language)
    return (
        str(config.get("pipeline") or "sc").strip().lower(),
        str(config.get("mode") or "core").strip().lower(),
        ecosystem,
        str(config.get("cli_backend") or "claude").strip().lower(),
    )


def _contract_and_launch(config: Mapping[str, Any]) -> tuple[PhaseIOContract, LaunchSpec]:
    pipeline, mode, ecosystem, backend = _dimensions(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="recon",
        work_unit_id=WORKSPACE_WORK_UNIT_ID,
        exact_inputs=(),
        exact_outputs=(WORKSPACE_RECEIPT_PATH,),
        exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=_LAUNCH_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=(),
    )
    return contract, launch


def _projection_contract_and_launch(
    config: Mapping[str, Any],
) -> tuple[PhaseIOContract, LaunchSpec]:
    pipeline, mode, ecosystem, backend = _dimensions(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="recon",
        work_unit_id=ANALYSIS_PROJECTION_WORK_UNIT_ID,
        exact_inputs=(),
        exact_outputs=(
            ANALYSIS_PROJECTION_RECEIPT_PATH,
            MATERIALIZATION_LINEAGE_PATH,
        ),
        exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=_LAUNCH_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=(),
    )
    return contract, launch


def _projection_staging_receipt_path(config: Mapping[str, Any]) -> Path:
    raw = str(config.get(ANALYSIS_PROJECTION_STAGING_RECEIPT_CONFIG) or "").strip()
    if not raw:
        scratchpad = str(config.get("scratchpad") or "").strip()
        if not scratchpad:
            _fail("snapshot-bound EVM projection lacks its private staging receipt")
        raw = str(
            Path(scratchpad).expanduser().resolve()
            / ANALYSIS_PROJECTION_STAGING_RECEIPT_PATH
        )
    path = Path(raw).expanduser()
    if not path.is_absolute():
        _fail("EVM projection staging receipt path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _materialization_lineage_staging_path(config: Mapping[str, Any]) -> Path:
    raw = str(config.get(MATERIALIZATION_LINEAGE_STAGING_CONFIG) or "").strip()
    if not raw:
        scratchpad = str(config.get("scratchpad") or "").strip()
        if not scratchpad:
            _fail("snapshot-bound EVM projection lacks materialization lineage")
        raw = str(
            Path(scratchpad).expanduser().resolve()
            / MATERIALIZATION_LINEAGE_STAGING_PATH
        )
    path = Path(raw).expanduser()
    if not path.is_absolute():
        _fail("EVM materialization lineage staging path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _read_materialization_lineage_bytes(
    path: Path,
    *,
    receipt: Mapping[str, Any],
) -> bytes:
    try:
        raw = rooted_path_io.read_bytes(
            Path(path),
            label="EVM tool materialization lineage",
            require_single_link=True,
        )
        if not 0 < len(raw) <= _MAX_CONTROL_BYTES:
            _fail("EVM tool materialization lineage exceeds its byte bound")
        parsed = json.loads(raw.decode("ascii", "strict"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        rooted_path_io.RootedPathIOError,
    ) as exc:
        _fail("EVM tool materialization lineage is unreadable", exc)
    if raw != _canonical_json(parsed):
        _fail("EVM tool materialization lineage is not canonical")
    try:
        lineage = _parse_materialization_lineage(raw)
    except Exception as exc:
        _fail("EVM tool materialization lineage is invalid", exc)
    terminal = lineage.get("native_materialization_terminal")
    source = lineage.get("source_snapshot")
    if (
        hashlib.sha256(raw).hexdigest()
        != receipt.get("materialization_lineage_sha256")
        or len(raw) != receipt.get("materialization_lineage_byte_count")
        or not isinstance(terminal, Mapping)
        or terminal.get("request_sha256")
        != receipt.get("native_materialization_request_sha256")
        or not isinstance(source, Mapping)
        or source.get("source_scope_sha256")
        != receipt.get("original_source_scope_sha256")
        or source.get("snapshot_sha256")
        != receipt.get("original_source_scope_sha256")
    ):
        _fail("EVM tool materialization lineage differs from projection custody")
    return raw


def _parse_materialization_lineage(raw: bytes) -> dict[str, Any]:
    from snapshot_bound_tool_authority import parse_materialization_lineage

    return parse_materialization_lineage(raw)


def _authenticated_native_projection_receipt_bytes(
    config: Mapping[str, Any],
    component: Mapping[str, Any],
) -> bytes:
    """Project receipt bytes only from the preloaded production extension."""

    try:
        module = sys.modules.get("_plamen_native_supervisor")
        if type(module) is not types.ModuleType:
            raise TypeError
        namespace = types.ModuleType.__getattribute__(module, "__dict__")
        spec = namespace.get("__spec__")
        if type(namespace) is not dict or type(spec) is not importlib.machinery.ModuleSpec:
            raise TypeError
        spec_namespace = object.__getattribute__(spec, "__dict__")
        loader = spec_namespace.get("loader")
        if type(loader) is not importlib.machinery.ExtensionFileLoader:
            raise TypeError
        loader_namespace = object.__getattribute__(loader, "__dict__")
        module_file = namespace.get("__file__")
        origin = spec_namespace.get("origin")
        if (
            namespace.get("__name__") != "_plamen_native_supervisor"
            or spec_namespace.get("name") != "_plamen_native_supervisor"
            or loader_namespace.get("name") != "_plamen_native_supervisor"
            or module_file != origin
            or loader_namespace.get("path") != origin
            or not isinstance(origin, str)
            or not any(
                origin.endswith(suffix)
                for suffix in importlib.machinery.EXTENSION_SUFFIXES
            )
            or namespace.get("BROKER_V2_ABI_SCHEMA") != "plamen.native-broker.v2"
            or namespace.get("BROKER_V2_PRODUCTION_ACQUISITION")
            != "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
            or namespace.get("TEST_ONLY_BUILD") is not False
            or namespace.get("BROKER_V2_INITIAL_AUTHORITY_AVAILABLE") is not True
        ):
            raise TypeError
        authority_type = namespace.get("EVMAnalysisProjectionAuthority")
        project = namespace.get("project_evm_analysis_projection_receipt")
        recover = namespace.get("recover_evm_analysis_projection_authority")
        authority = config.get(ANALYSIS_PROJECTION_NATIVE_AUTHORITY_CONFIG)
        if (
            type(authority_type) is not type
            or type.__getattribute__(authority_type, "__module__")
            != "_plamen_native_supervisor"
            or type.__getattribute__(authority_type, "__flags__") & (1 << 9)
            or type(project) is not types.BuiltinFunctionType
            or getattr(project, "__module__", None) != "_plamen_native_supervisor"
            or type(recover) is not types.BuiltinFunctionType
            or getattr(recover, "__module__", None) != "_plamen_native_supervisor"
        ):
            raise TypeError
        if authority is None:
            authority = recover(str(component["receipt_sha256"]))
            if isinstance(config, dict):
                config[ANALYSIS_PROJECTION_NATIVE_AUTHORITY_CONFIG] = authority
        if type(authority) is not authority_type:
            raise TypeError
        raw = project(authority)
        if type(raw) is not bytes or not 0 < len(raw) <= _MAX_CONTROL_BYTES:
            raise TypeError
        return raw
    except BaseException as exc:
        _fail("authenticated native EVM projection authority is unavailable", exc)


def _read_projection_receipt_bytes(
    path: Path,
    *,
    component: Mapping[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = rooted_path_io.read_bytes(
            Path(path),
            label="EVM analysis projection receipt",
            require_single_link=True,
        )
        if not 0 < len(raw) <= _MAX_CONTROL_BYTES:
            _fail("EVM analysis projection receipt exceeds its byte bound")
        value = json.loads(raw.decode("utf-8", "strict"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        rooted_path_io.RootedPathIOError,
    ) as exc:
        _fail("EVM analysis projection receipt is unreadable", exc)
    if raw != _canonical_json(value):
        _fail("EVM analysis projection receipt is not canonical")
    receipt = _validate_analysis_projection_receipt(value, component=component)
    if (
        receipt["receipt_sha256"] != component["receipt_sha256"]
        or len(raw) != component["receipt_byte_count"]
    ):
        _fail("EVM analysis projection bytes differ from audit snapshot")
    return raw, receipt


def ensure_committed_evm_analysis_projection(
    *,
    config: Mapping[str, Any],
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    audit_snapshot: Mapping[str, Any],
    fault_injector: _FaultInjector | None = None,
) -> CommittedEVMAnalysisProjection | None:
    """Adopt the exact pre-snapshot native receipt through one CREATE row.

    The native producer writes only the private staging receipt.  Once the
    snapshot binds those exact bytes, the driver arms a clean PhaseIO output,
    publishes the same bytes, and commits them.  A crash after publication is
    recoverable only when the extant output remains byte-identical.
    """

    pipeline, _mode, ecosystem, _backend = _dimensions(config)
    components = audit_snapshot.get("components")
    component_value = (
        components.get("evm_analysis_projection")
        if isinstance(components, Mapping) else None
    )
    if pipeline != "sc" or ecosystem != "evm" or component_value is None:
        return None
    component = _analysis_projection_component(audit_snapshot)
    native_raw = _authenticated_native_projection_receipt_bytes(config, component)
    root = Path(scratchpad)
    project = Path(project_root)
    destination = root / ANALYSIS_PROJECTION_RECEIPT_PATH
    lineage_destination = root / MATERIALIZATION_LINEAGE_PATH
    staging = _projection_staging_receipt_path(config)
    lineage_staging = _materialization_lineage_staging_path(config)
    try:
        if (
            staging.resolve() == destination.resolve()
            or lineage_staging.resolve() == lineage_destination.resolve()
        ):
            _fail("EVM projection staging and committed receipt paths overlap")
    except OSError as exc:
        _fail("EVM projection receipt path identity is unavailable", exc)
    staged_raw, _staged_receipt = _read_projection_receipt_bytes(
        staging, component=component
    )
    if staged_raw != native_raw:
        _fail("native EVM projection authority and staged receipt differ")
    lineage_raw = _read_materialization_lineage_bytes(
        lineage_staging, receipt=_staged_receipt
    )
    contract, launch = _projection_contract_and_launch(config)
    ledger = read_artifact_ledger(root)
    row = ledger.get("work_units", {}).get(contract.key)
    if row is None:
        if (
            rooted_path_io.lexists(destination)
            or rooted_path_io.lexists(lineage_destination)
        ):
            _fail("orphan committed EVM projection output lacks an armed owner")
        try:
            row = record_work_unit_inputs(
                root, project, contract, launch, run_id=run_id
            )
        except ArtifactLedgerError as exc:
            _fail("EVM projection PhaseIO input arm failed", exc)
    if not isinstance(row, Mapping):
        _fail("EVM projection PhaseIO row is malformed")
    if (
        row.get("run_id") != run_id
        or row.get("contract_digest") != contract.digest
        or row.get("launch_digest") != launch.digest
    ):
        _fail("EVM projection stored owner authority differs")
    if row.get("semantic_status") == "ACTIVE":
        committed = load_committed_evm_analysis_projection(
            root,
            project_root=project,
            run_id=run_id,
            audit_snapshot=audit_snapshot,
            config=config,
        )
    else:
        issues = validate_work_unit_inputs(
            root, project, contract, launch, run_id=run_id
        )
        if issues:
            _fail("EVM projection input replay failed: " + "; ".join(issues))
        if rooted_path_io.lexists(destination):
            existing_raw, _existing = _read_projection_receipt_bytes(
                destination, component=component
            )
            if existing_raw != staged_raw:
                _fail("armed EVM projection output differs from native staging")
        else:
            _atomic_write(destination, staged_raw)
        if rooted_path_io.lexists(lineage_destination):
            existing_lineage = _read_materialization_lineage_bytes(
                lineage_destination, receipt=_staged_receipt
            )
            if existing_lineage != lineage_raw:
                _fail("armed EVM materialization lineage differs from staging")
        else:
            _atomic_write(lineage_destination, lineage_raw)
        if fault_injector is not None:
            fault_injector("after_publish_before_commit")
        try:
            record_work_unit_artifacts(
                root,
                project,
                contract,
                launch,
                run_id=run_id,
                actor="DRIVER",
                expected_output_records={
                    ANALYSIS_PROJECTION_RECEIPT_IDENTITY: {
                        "sha256": hashlib.sha256(staged_raw).hexdigest(),
                        "size": len(staged_raw),
                    },
                    MATERIALIZATION_LINEAGE_IDENTITY: {
                        "sha256": hashlib.sha256(lineage_raw).hexdigest(),
                        "size": len(lineage_raw),
                    }
                },
            )
        except ArtifactLedgerError as exc:
            _fail("EVM projection PhaseIO output commit failed", exc)
        committed = load_committed_evm_analysis_projection(
            root,
            project_root=project,
            run_id=run_id,
            audit_snapshot=audit_snapshot,
            config=config,
        )
    if isinstance(config, dict):
        config["_committed_evm_analysis_projection"] = committed
    return committed


def load_committed_evm_analysis_projection(
    scratchpad: Path,
    *,
    project_root: Path,
    run_id: str,
    audit_snapshot: Mapping[str, Any],
    config: Mapping[str, Any],
) -> CommittedEVMAnalysisProjection:
    """Load the exact native projection only after PhaseIO ledger replay."""

    component = _analysis_projection_component(audit_snapshot)
    contract, launch = _projection_contract_and_launch(config)
    expected_key = (
        f"sc/{contract.mode}/evm/{contract.backend}/recon/"
        f"{ANALYSIS_PROJECTION_WORK_UNIT_ID}"
    )
    if contract.key != expected_key:
        _fail("EVM analysis projection owner key is not the fixed SC/EVM producer")
    issues = validate_work_unit_artifacts(
        Path(scratchpad), Path(project_root), contract, launch,
        run_id=run_id, actor="DRIVER",
    )
    if issues:
        _fail(
            "EVM analysis projection lacks committed PhaseIO lineage: "
            + "; ".join(issues)
        )
    path = Path(scratchpad) / ANALYSIS_PROJECTION_RECEIPT_PATH
    try:
        raw = rooted_path_io.read_bytes(
            path,
            label="EVM analysis projection receipt",
            require_single_link=True,
        )
        if not 0 < len(raw) <= _MAX_CONTROL_BYTES:
            _fail("EVM analysis projection receipt exceeds its byte bound")
        value = json.loads(raw.decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError, rooted_path_io.RootedPathIOError) as exc:
        _fail("EVM analysis projection receipt is unreadable", exc)
    if _canonical_json(value) != raw:
        _fail("EVM analysis projection receipt is not canonical")
    if (
        value.get("receipt_sha256") != component["receipt_sha256"]
        or len(raw) != component["receipt_byte_count"]
    ):
        _fail("committed EVM analysis projection bytes differ from audit snapshot")
    receipt = _validate_analysis_projection_receipt(value, component=component)
    lineage_path = Path(scratchpad) / MATERIALIZATION_LINEAGE_PATH
    _read_materialization_lineage_bytes(lineage_path, receipt=receipt)
    authority = object.__new__(CommittedEVMAnalysisProjection)
    authority._receipt = _frozen_mapping(receipt)
    authority._component = _frozen_mapping(component)
    authority._owner_work_unit_key = contract.key
    _LIVE_ANALYSIS_PROJECTIONS.add(authority)
    return authority


def _require_live_analysis_projection(
    value: object,
) -> CommittedEVMAnalysisProjection:
    if (
        not isinstance(value, CommittedEVMAnalysisProjection)
        or value not in _LIVE_ANALYSIS_PROJECTIONS
    ):
        _fail("disjoint EVM analysis root lacks committed projection authority")
    return value


def _replay_committed_analysis_projection_binding(
    scratchpad: Path,
    workspace: Mapping[str, Any],
) -> None:
    binding = workspace.get("analysis_projection")
    if binding is None:
        return
    if not isinstance(binding, Mapping):
        _fail("EVM workspace analysis projection binding is malformed")
    owner_key = str(binding.get("owner_work_unit_key") or "")
    parts = owner_key.split("/")
    if len(parts) != 6 or parts[-2:] != ["recon", ANALYSIS_PROJECTION_WORK_UNIT_ID]:
        _fail("EVM analysis projection owner key cannot derive PhaseIO authority")
    contract, launch = _projection_contract_and_launch({
        "pipeline": parts[0], "mode": parts[1], "language": parts[2],
        "cli_backend": parts[3],
    })
    if contract.key != owner_key:
        _fail("EVM analysis projection owner differs from PhaseIO contract")
    project = Path(str(workspace["project_root"]["absolute_path"]))
    issues = validate_work_unit_artifacts(
        Path(scratchpad), project, contract, launch,
        run_id=str(workspace["run_id"]), actor="DRIVER",
    )
    if issues:
        _fail(
            "EVM analysis projection committed replay failed: "
            + "; ".join(issues)
        )
    component = binding.get("snapshot_component")
    native = binding.get("native_receipt")
    if not isinstance(component, Mapping):
        _fail("EVM analysis projection snapshot component is absent")
    path = Path(scratchpad) / ANALYSIS_PROJECTION_RECEIPT_PATH
    try:
        raw = rooted_path_io.read_bytes(
            path,
            label="EVM analysis projection receipt",
            require_single_link=True,
        )
        parsed = json.loads(raw.decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError, rooted_path_io.RootedPathIOError) as exc:
        _fail("EVM analysis projection committed receipt is unreadable", exc)
    if (
        raw != _canonical_json(parsed)
        or parsed.get("receipt_sha256") != component.get("receipt_sha256")
        or len(raw) != component.get("receipt_byte_count")
        or parsed != native
        or component.get("original_source_scope_sha256")
        != workspace.get("source_closure", {}).get("snapshot_source_scope_sha256")
    ):
        _fail("EVM analysis projection committed receipt lineage changed")
    _validate_analysis_projection_receipt(parsed, component=component)


def _atomic_write(path: Path, raw: bytes) -> None:
    rooted_path_io.ensure_directory(path.parent, parents=True, label="workspace receipt parent")
    descriptor, temporary = rooted_path_io.exclusive_temp_file(
        path.parent, prefix=".evm-workspace.", suffix=".publishing.tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        rooted_path_io.durable_replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if rooted_path_io.lexists(temporary):
            rooted_path_io.unlink(temporary)


def _read_receipt(path: Path) -> dict[str, Any]:
    try:
        raw = rooted_path_io.read_bytes(
            path, label="EVM workspace receipt", require_single_link=True
        )
        value = json.loads(raw.decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError, rooted_path_io.RootedPathIOError) as exc:
        _fail("EVM workspace receipt is unreadable", exc)
    if _canonical_file(value) != raw:
        _fail("EVM workspace receipt is not canonical")
    return validate_evm_analysis_workspace_receipt(value)


def decode_evm_analysis_workspace_receipt_test_only(path: Path) -> dict[str, Any]:
    """Pure decoder for isolated tests; grants no production load authority."""

    return _read_receipt(Path(path))


def _replay_directory_identity(record: Mapping[str, Any], *, label: str) -> None:
    absolute = record.get("absolute_path")
    if not isinstance(absolute, str) or not os.path.isabs(absolute):
        _fail(f"{label} absolute path authority is malformed")
    current = _directory_record(Path(absolute), rooted_alias=str(record.get("rooted_alias") or ""))
    if current != dict(record):
        _fail(f"{label} physical identity changed after capture")


def replay_evm_analysis_workspace_execution_closure(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay every mutable build input before or after provider execution.

    Callers must invoke this immediately before launch and once more before a
    successful provider result is accepted.  This function grants no process
    launch authority; executable custody is a separate native capability.
    """

    value = validate_evm_analysis_workspace_receipt(receipt)
    project_path = Path(str(value["project_root"]["absolute_path"]))
    build_path = Path(str(value["build_root"]["absolute_path"]))
    projection_binding = value.get("analysis_projection")
    project, build, relation, build_fd = _descriptor_held_build_root(
        project_path,
        build_path,
        allow_committed_disjoint=projection_binding is not None,
    )
    try:
        if (
            project != value["project_root"]
            or build != value["build_root"]
            or relation != value["root_relation"]
        ):
            _fail("EVM workspace root authority changed before execution")
        manifests, build_system, js_consumption = _manifest_rows(
            build_fd,
            build_root_path=build_path,
            relation=relation,
        )
        replay_manifests, replay_system, replay_js = _manifest_rows(
            build_fd,
            build_root_path=build_path,
            relation=relation,
        )
        if (
            replay_manifests != manifests
            or replay_system != build_system
            or replay_js != js_consumption
        ):
            _fail("EVM workspace manifest bytes changed during replay")
        js_lock_authority = _capture_js_lock_selection_binding(
            build_fd,
            build_root_path=build_path,
            manifests=manifests,
        )
        replay_js_lock_authority = _capture_js_lock_selection_binding(
            build_fd,
            build_root_path=build_path,
            manifests=replay_manifests,
        )
        if replay_js_lock_authority != js_lock_authority:
            _fail("EVM JavaScript lock semantics changed during replay")
        live_projection_binding: dict[str, Any] | None = None
        if isinstance(projection_binding, Mapping):
            workspace_closure = _dependency_content_closure(
                build_path,
                rooted_alias="projection:.",
                expected_root=build,
            )
            source_copy_closure = _dependency_content_closure(
                build_path,
                rooted_alias="projection-source:.",
                expected_root=build,
                excluded_top_level=frozenset({"node_modules"}),
            )
            node_path = build_path / "node_modules"
            node_record = _directory_record(
                node_path, rooted_alias="projection:node_modules"
            )
            node_closure = _dependency_content_closure(
                node_path,
                rooted_alias="projection:node_modules",
                expected_root=node_record,
            )
            projection_unsigned = {
                "state": "COMMITTED_READ_ONLY_GUEST_PROJECTION",
                "owner_work_unit_key": projection_binding["owner_work_unit_key"],
                "snapshot_component": _plain_json_shape(
                    projection_binding["snapshot_component"]
                ),
                "native_receipt": _plain_json_shape(
                    projection_binding["native_receipt"]
                ),
                "workspace_content_closure": workspace_closure,
                "source_copy_content_closure": source_copy_closure,
                "node_modules_root": node_record,
                "node_modules_content_closure": node_closure,
            }
            live_projection_binding = {
                **projection_unsigned,
                "binding_sha256": _digest(projection_unsigned),
            }
    finally:
        os.close(build_fd)

    replayed_roots: list[dict[str, Any]] = []
    for row in value["dependency_closure"]["roots"]:
        alias = str(row["rooted_alias"])
        path = Path(str(row["absolute_path"]))
        live_record = _directory_record(path, rooted_alias=alias)
        expected_record = {
            key: row[key]
            for key in (
                "absolute_path", "rooted_alias", "physical_identity",
                "descriptor_sha256",
            )
        }
        if live_record != expected_record:
            _fail(f"EVM dependency root physical identity changed: {alias}")
        live_closure = _dependency_content_closure(
            path,
            rooted_alias=alias,
            expected_root=expected_record,
            exclude_node_modules_bin=(
                _dependency_root_uses_node_modules_bin_policy(path)
            ),
        )
        if live_closure != row["content_closure"]:
            _fail(f"EVM dependency content changed after capture: {alias}")
        replayed_roots.append(dict(row))
    dependency_unsigned = {
        "snapshot_source_scope_sha256": value["dependency_closure"][
            "snapshot_source_scope_sha256"
        ],
        "roots": replayed_roots,
    }
    if _digest(dependency_unsigned) != value["dependency_closure"]["closure_sha256"]:
        _fail("EVM dependency closure changed after capture")

    js_consumption = _derive_js_consumption_binding(
        js_consumption,
        build_root=build_path,
        js_lock_authority=js_lock_authority,
        analysis_projection=live_projection_binding,
        dependency_rows=replayed_roots,
    )
    replay_checks = {
        "manifests": manifests == value["build_variant"]["manifests"],
        "manifest_digest": (
            _digest(manifests) == value["build_variant"]["manifest_set_sha256"]
        ),
        "build_system": build_system == value["build_variant"]["build_system"],
        "js_consumption": js_consumption == value["js_consumption"],
        "js_lock_authority": js_lock_authority == value["js_lock_authority"],
        "analysis_projection": live_projection_binding == projection_binding,
    }
    failed_replays = sorted(key for key, matched in replay_checks.items() if not matched)
    if failed_replays:
        _fail(
            "EVM workspace capture changed during replay: "
            + ", ".join(failed_replays)
        )
    return value


def require_custodied_workspace_tool_for_execution(
    receipt: Mapping[str, Any],
    tool_id: str,
    *,
    native_custody: object | None = None,
) -> dict[str, Any]:
    """Reject the legacy path-return execution adapter.

    A pathname plus a matching digest is not a launch capability: the pathname
    can be exchanged before ``execve``/``posix_spawn``.  Native execution is
    available only through ``build_session_bound_evm_tool_execution_plan`` and
    ``snapshot_bound_tool_authority.execute_snapshot_bound_tool``.  This old
    row-returning shape can never safely consume custody, so arbitrary truthy
    objects remain rejected.
    """

    replay_evm_analysis_workspace_execution_closure(receipt)
    require_admitted_workspace_tool(receipt, tool_id)
    if native_custody is None:
        _fail(
            f"workspace tool {tool_id} native immutable executable custody is unavailable"
        )
    _fail(
        f"workspace tool {tool_id} direct path-return execution is forbidden; "
        "use the session-bound native execution plan"
    )


def _session_bound_tool_authority_modules() -> tuple[Any, Any, Any]:
    """Load the three reviewed authorities only at the issuance boundary."""

    try:
        import posix_v2_compat_runtime as compat_runtime
        import snapshot_bound_tool_authority as local_tools
        import toolchain_control_authority as toolchain_controls
    except Exception as exc:
        _fail("snapshot-bound local tool authority modules are unavailable", exc)
    return compat_runtime, local_tools, toolchain_controls


def _session_binding(session: object, *, native: bool) -> tuple[object, dict[str, Any]]:
    """Re-admit one exact POSIX session without projecting launch authority."""

    if native:
        try:
            import posix_backend_execution as execution

            request = execution.authenticated_native_guest_request(session)
            document = request.source_config.document
            binding = {
                "run_id": request.run_id,
                "project_root": document["project_root"],
                "scratchpad": document["scratchpad"],
                "backend": request.backend,
            }
        except Exception as exc:
            _fail("native EVM tool session is unavailable", exc)
        return session, binding
    compat_runtime, _local_tools, _controls = (
        _session_bound_tool_authority_modules()
    )
    try:
        admitted = compat_runtime.require_posix_v2_compat_session(session)
        return admitted, dict(admitted.binding)
    except Exception as exc:
        _fail("compatibility EVM tool session is unavailable", exc)


def _require_session_bound_evm_tool_authority(
    authority: object,
    receipt: Mapping[str, Any],
) -> tuple[SessionBoundEVMToolAuthority, object]:
    """Replay an opaque tool capability and its still-live POSIX session."""

    if (
        type(authority) is not SessionBoundEVMToolAuthority
        or authority not in _LIVE_SESSION_BOUND_TOOL_AUTHORITIES
    ):
        _fail("session-bound EVM tool authority is absent, forged, or expired")
    value = replay_evm_analysis_workspace_execution_closure(receipt)
    try:
        session = authority._session_ref()
    except (AttributeError, TypeError) as exc:
        _fail("session-bound EVM tool authority shell is malformed", exc)
    session, binding = _session_binding(
        session, native=bool(authority._native_session)
    )
    owner_parts = str(value["owner"]["work_unit_key"]).split("/")
    expected = (
        value["receipt_sha256"],
        value["run_id"],
        value["snapshot"]["snapshot_sha256"],
        value["project_root"]["absolute_path"],
        binding.get("scratchpad"),
        owner_parts[3] if len(owner_parts) == 6 else "",
        value["toolchain_controls"]["governance_sha256"],
        value["toolchain_controls"]["version_lock_sha256"],
    )
    observed = (
        id(session),
        authority._receipt_sha256,
        authority._run_id,
        authority._snapshot_sha256,
        authority._project_root,
        authority._scratchpad,
        authority._backend,
        authority._governance_sha256,
        authority._version_lock_sha256,
        tuple(
            (tool_id, hashlib.sha256(raw).hexdigest())
            for tool_id, raw in sorted(authority._projections.items())
        ),
        id(authority._rule_tree_binding) if authority._rule_tree_binding is not None else 0,
        (
            id(authority._managed_generation_authority)
            if authority._managed_generation_authority is not None else 0
        ),
        authority._native_session,
    )
    registered = _LIVE_SESSION_BOUND_TOOL_AUTHORITIES.get(authority)
    if (
        expected != observed[1:9]
        or registered != observed
        or binding.get("run_id") != authority._run_id
        or binding.get("project_root") != authority._project_root
        or binding.get("scratchpad") != authority._scratchpad
        or binding.get("backend") != authority._backend
    ):
        _fail("session-bound EVM tool authority belongs to another audit")
    try:
        if set(authority._projections) & {"opengrep", "semgrep"}:
            _local_tools._require_reviewed_opengrep_rule_input_authority(
                authority._rule_tree_binding,
                project_root=Path(str(value["build_root"]["absolute_path"])),
            )
        elif authority._rule_tree_binding is not None:
            _fail("session authority carries an unused OpenGrep rule capability")
        if "slither" in authority._projections:
            import managed_evm_python_toolchain as managed_toolchain
            managed_toolchain.require_managed_evm_generation_authority(
                authority._managed_generation_authority
            )
        elif authority._managed_generation_authority is not None:
            _fail("session authority carries an unused Slither generation capability")
    except EVMAnalysisWorkspaceAuthorityError:
        raise
    except Exception as exc:
        _fail("session-bound EVM analysis input changed after issuance", exc)
    return authority, session


def issue_session_bound_evm_tool_authority(
    receipt: Mapping[str, Any],
    *,
    posix_session_authority: object | None = None,
    native_runtime_authority: object | None = None,
    scratchpad: Path,
    observed_tool_authorities: Mapping[str, Mapping[str, Any]],
    implementation_root: Path,
    managed_evm_generation_authority: object | None = None,
) -> SessionBoundEVMToolAuthority:
    """Bind reviewed local tool observations to one live POSIX audit session.

    Issuance preserves the governance distinction between authentic reviewed
    content and ``SNAPSHOT_BOUND_LOCAL``.  A local observation can support a
    native-custodied heuristic execution, but never a clean-audit conclusion.
    Unavailable or malformed observations are omitted rather than guessed.
    """

    value = replay_evm_analysis_workspace_execution_closure(receipt)
    if value["input_materialization"]["state"] != "SNAPSHOT_BOUND":
        _fail("session-bound EVM tools require snapshot-bound materialization")
    if value.get("analysis_projection") is None:
        _fail("session-bound EVM tools require a committed analysis projection")
    if not isinstance(observed_tool_authorities, Mapping):
        _fail("local EVM tool observation roster is malformed")
    unknown = set(observed_tool_authorities) - set(_TOOL_IDS)
    if unknown:
        _fail("local EVM tool observation roster contains unknown tools")

    _compat_runtime, local_tools, toolchain_controls = (
        _session_bound_tool_authority_modules()
    )
    if (posix_session_authority is None) == (native_runtime_authority is None):
        _fail("local EVM tool issuance requires exactly one POSIX session")
    native_session = native_runtime_authority is not None
    session, session_binding = _session_binding(
        (
            native_runtime_authority
            if native_session else posix_session_authority
        ),
        native=native_session,
    )
    owner_parts = str(value["owner"]["work_unit_key"]).split("/")
    backend = owner_parts[3] if len(owner_parts) == 6 else ""
    scratch = os.fspath(Path(scratchpad).expanduser().resolve())
    if (
        session_binding.get("run_id") != value["run_id"]
        or session_binding.get("backend") != backend
        or session_binding.get("project_root")
        != value["project_root"]["absolute_path"]
        or session_binding.get("scratchpad") != scratch
    ):
        _fail("local EVM tool issuance session belongs to another audit")

    implementation = Path(implementation_root).expanduser().resolve()
    try:
        controls = toolchain_controls.load_toolchain_controls(
            implementation
            / "verification_policy"
            / toolchain_controls.TOOLCHAIN_GOVERNANCE_FILENAME,
            implementation
            / "verification_policy"
            / toolchain_controls.TOOLCHAIN_VERSION_LOCK_FILENAME,
        )
        policies = {
            row.tool_id: row
            for row in toolchain_controls.snapshot_bound_local_policies(controls)
        }
    except Exception as exc:
        _fail("reviewed local EVM tool policy is unavailable", exc)
    if (
        controls.governance_sha256
        != value["toolchain_controls"]["governance_sha256"]
        or controls.lock_sha256
        != value["toolchain_controls"]["version_lock_sha256"]
    ):
        _fail("local EVM tool policy differs from the workspace snapshot")

    rows = {str(row["tool_id"]): row for row in value["tools"]}
    projections: dict[str, bytes] = {}
    managed_binding: Mapping[str, Any] | None = None
    if managed_evm_generation_authority is not None:
        try:
            import managed_evm_python_toolchain as managed_toolchain
            managed_binding = managed_toolchain.require_managed_evm_generation_authority(
                managed_evm_generation_authority
            )
        except Exception as exc:
            _fail("managed EVM generation authority is unavailable", exc)
    for tool_id, raw_authority in sorted(observed_tool_authorities.items()):
        # Native v2 has one reviewed scanner image member: OpenGrep.  Semgrep
        # remains a workspace observation for legacy/non-EVM reporting, but it
        # cannot be admitted into this session-bound execution capability as an
        # alias for a different authenticated anchor.
        if tool_id == "semgrep":
            continue
        authority = _snapshot_bound_local_authority(
            raw_authority, tool_id=tool_id
        )
        policy = policies.get(tool_id)
        row = rows.get(tool_id)
        if authority is None or policy is None or row is None:
            continue
        projection = _runtime_authority_snapshot_bytes(authority)
        snapshot_entry = row.get("snapshot_runtime_identity")
        if (
            policy.authority_tier != "SNAPSHOT_BOUND_LOCAL"
            or policy.execution_authority is not True
            or policy.authentic_content_authority is not False
            or policy.can_certify_clean is not False
            or not isinstance(snapshot_entry, Mapping)
            or snapshot_entry.get("sha256")
            != hashlib.sha256(projection).hexdigest()
            or snapshot_entry.get("byte_count") != len(projection)
        ):
            continue
        try:
            decoded = local_tools.validate_snapshot_bound_local_tool_projection(
                projection, tool_id, controls
            )
        except Exception:
            continue
        if tool_id == "slither" and (
            managed_binding is None
            or decoded.get("resolved_executable")
            != managed_binding.get("interpreter_absolute_path")
            or decoded.get("interpreter_sha256")
            != managed_binding.get("interpreter_sha256")
            or decoded.get("version") != managed_binding.get("slither_version")
            or decoded.get("module_origin")
            != managed_binding.get("slither_module_origin")
            or decoded.get("module_sha256")
            != managed_binding.get("slither_module_sha256")
            or decoded.get("managed_generation_binding_sha256")
            != managed_binding.get("binding_sha256")
            or decoded.get("entrypoint_path")
            != managed_binding.get("slither_entrypoint")
            or decoded.get("entrypoint_sha256")
            != managed_binding.get("slither_entrypoint_sha256")
        ):
            continue
        projections[tool_id] = bytes(projection)
    if not projections:
        _fail("no reviewed snapshot-bound local EVM tool projection is eligible")

    rule_tree_authority: object | None = None
    if set(projections) & {"opengrep", "semgrep"}:
        try:
            rule_tree_authority = (
                local_tools.issue_reviewed_opengrep_rule_input_authority(
                    implementation_root=implementation,
                    project_root=Path(str(value["build_root"]["absolute_path"])),
                )
            )
        except Exception as exc:
            _fail("reviewed OpenGrep execution rule tree is unavailable", exc)

    issued = object.__new__(SessionBoundEVMToolAuthority)
    object.__setattr__(issued, "_session_ref", weakref.ref(session))
    object.__setattr__(issued, "_receipt_sha256", str(value["receipt_sha256"]))
    object.__setattr__(issued, "_run_id", str(value["run_id"]))
    object.__setattr__(
        issued, "_snapshot_sha256", str(value["snapshot"]["snapshot_sha256"])
    )
    object.__setattr__(
        issued, "_project_root", str(value["project_root"]["absolute_path"])
    )
    object.__setattr__(issued, "_scratchpad", scratch)
    object.__setattr__(issued, "_backend", backend)
    object.__setattr__(issued, "_projections", MappingProxyType(dict(projections)))
    object.__setattr__(
        issued, "_governance_sha256", controls.governance_sha256
    )
    object.__setattr__(
        issued, "_version_lock_sha256", controls.lock_sha256
    )
    object.__setattr__(issued, "_rule_tree_binding", rule_tree_authority)
    object.__setattr__(
        issued, "_managed_generation_authority",
        managed_evm_generation_authority if "slither" in projections else None,
    )
    object.__setattr__(issued, "_native_session", native_session)
    _LIVE_SESSION_BOUND_TOOL_AUTHORITIES[issued] = (
        id(session),
        issued._receipt_sha256,
        issued._run_id,
        issued._snapshot_sha256,
        issued._project_root,
        issued._scratchpad,
        issued._backend,
        issued._governance_sha256,
        issued._version_lock_sha256,
        tuple(
            (tool_id, hashlib.sha256(raw).hexdigest())
            for tool_id, raw in sorted(issued._projections.items())
        ),
        id(issued._rule_tree_binding) if issued._rule_tree_binding is not None else 0,
        (
            id(issued._managed_generation_authority)
            if issued._managed_generation_authority is not None else 0
        ),
        issued._native_session,
    )
    # Recheck session liveness after all filesystem/control observations.
    _require_session_bound_evm_tool_authority(issued, value)
    return issued


def build_session_bound_evm_tool_execution_plan(
    receipt: Mapping[str, Any],
    tool_id: str,
    *,
    session_tool_authority: SessionBoundEVMToolAuthority,
    native_runtime_authority: object,
    argv: Sequence[str],
    environment: Mapping[str, str],
    cwd: str,
    tool_scratch_root: Path,
    tool_state_root: Path,
    implementation_root: Path,
) -> object:
    """Construct one native-only plan from an issued workspace capability.

    Returning the opaque plan does not execute it.  Callers must submit it to
    ``snapshot_bound_tool_authority.execute_snapshot_bound_tool``; extracting a
    pathname and launching it directly remains outside this authority model.
    """

    authority, _session = _require_session_bound_evm_tool_authority(
        session_tool_authority, receipt
    )
    if tool_id not in authority._projections:
        _fail(f"workspace tool {tool_id} lacks local snapshot authority")
    value = replay_evm_analysis_workspace_execution_closure(receipt)
    rows = [row for row in value["tools"] if row["tool_id"] == tool_id]
    if len(rows) != 1:
        _fail(f"workspace tool {tool_id} row is absent")
    row = rows[0]
    if tool_id in {"opengrep", "semgrep"} and (
        value["rule_tree_authority"].get("state") != "ADMITTED"
        or row.get("rule_tree_authority_sha256")
        != value["rule_tree_authority"].get("binding_sha256")
    ):
        _fail(f"workspace tool {tool_id} rule-tree authority is unavailable")

    projection_binding = value.get("analysis_projection")
    if not isinstance(projection_binding, Mapping):
        _fail("workspace tool plan lacks committed materialization lineage")
    component = projection_binding.get("snapshot_component")
    if not isinstance(component, Mapping):
        _fail("workspace tool plan materialization component is malformed")
    lineage_path = Path(authority._scratchpad) / MATERIALIZATION_LINEAGE_PATH
    try:
        lineage_raw = rooted_path_io.read_bytes(
            lineage_path,
            label="EVM tool execution materialization lineage",
            require_single_link=True,
        )
    except (OSError, rooted_path_io.RootedPathIOError) as exc:
        _fail("workspace tool materialization lineage is unavailable", exc)
    lineage_entry = {
        "sha256": hashlib.sha256(lineage_raw).hexdigest(),
        "byte_count": len(lineage_raw),
    }
    if (
        lineage_entry["sha256"] != component.get("materialization_lineage_sha256")
        or lineage_entry["byte_count"]
        != component.get("materialization_lineage_byte_count")
    ):
        _fail("workspace tool materialization lineage differs from snapshot")

    _compat, local_tools, toolchain_controls = (
        _session_bound_tool_authority_modules()
    )
    implementation = Path(implementation_root).expanduser().resolve()
    try:
        controls = toolchain_controls.load_toolchain_controls(
            implementation
            / "verification_policy"
            / toolchain_controls.TOOLCHAIN_GOVERNANCE_FILENAME,
            implementation
            / "verification_policy"
            / toolchain_controls.TOOLCHAIN_VERSION_LOCK_FILENAME,
        )
    except Exception as exc:
        _fail("workspace tool plan controls are unavailable", exc)
    if (
        controls.governance_sha256 != authority._governance_sha256
        or controls.lock_sha256 != authority._version_lock_sha256
    ):
        _fail("workspace tool plan controls changed after issuance")

    projection = authority._projections[tool_id]
    snapshot_entry = row.get("snapshot_runtime_identity")
    if not isinstance(snapshot_entry, Mapping):
        _fail(f"workspace tool {tool_id} snapshot identity is unavailable")
    decoded = local_tools.validate_snapshot_bound_local_tool_projection(
        projection, tool_id, controls
    )
    analysis_input_authority: object | None = None
    source_path: Path | None = None
    if tool_id in {"opengrep", "semgrep"}:
        analysis_input_authority = authority._rule_tree_binding
    elif tool_id == "slither":
        analysis_input_authority = authority._managed_generation_authority
    else:
        source_path = Path(str(decoded["resolved_executable"]))
    build_root = Path(str(value["build_root"]["absolute_path"]))
    try:
        plan = local_tools.build_snapshot_bound_tool_execution_plan(
            native_runtime_authority=native_runtime_authority,
            run_id=str(value["run_id"]),
            audit_snapshot_sha256=str(value["snapshot"]["snapshot_sha256"]),
            tool_id=tool_id,
            projection_bytes=projection,
            snapshot_entry=dict(snapshot_entry),
            source_path=source_path,
            analysis_input_authority=analysis_input_authority,
            project_root=build_root,
            materialization_lineage_bytes=lineage_raw,
            materialization_lineage_entry=lineage_entry,
            argv=argv,
            environment=dict(environment),
            cwd=cwd,
            scratch_root=Path(tool_scratch_root),
            state_root=Path(tool_state_root),
            source_scope_sha256=str(value["source_closure"]["snapshot_source_scope_sha256"]),
            controls=controls,
        )
    except Exception as exc:
        _fail(f"workspace tool {tool_id} native execution plan was rejected", exc)
    _require_session_bound_evm_tool_authority(authority, value)
    replay_evm_analysis_workspace_execution_closure(value)
    return plan


def execute_session_bound_evm_tool(
    receipt: Mapping[str, Any],
    tool_id: str,
    *,
    session_tool_authority: SessionBoundEVMToolAuthority,
    native_runtime_authority: object,
    argv: Sequence[str],
    environment: Mapping[str, str],
    cwd: str,
    tool_scratch_root: Path,
    tool_state_root: Path,
    implementation_root: Path,
) -> object:
    """Execute one exact plan and return only opaque native-bound evidence."""

    plan = build_session_bound_evm_tool_execution_plan(
        receipt,
        tool_id,
        session_tool_authority=session_tool_authority,
        native_runtime_authority=native_runtime_authority,
        argv=argv,
        environment=environment,
        cwd=cwd,
        tool_scratch_root=tool_scratch_root,
        tool_state_root=tool_state_root,
        implementation_root=implementation_root,
    )
    authority, _session = _require_session_bound_evm_tool_authority(
        session_tool_authority, receipt
    )
    value = replay_evm_analysis_workspace_execution_closure(receipt)
    _compat, local_tools, _controls = _session_bound_tool_authority_modules()
    try:
        evidence = local_tools.execute_snapshot_bound_tool(
            plan,
            native_runtime_authority=native_runtime_authority,
            project_root=Path(str(value["build_root"]["absolute_path"])),
            scratch_root=Path(tool_scratch_root),
            state_root=Path(tool_state_root),
        )
    except Exception as exc:
        _fail(f"workspace tool {tool_id} native execution failed", exc)
    _require_session_bound_evm_tool_authority(authority, value)
    replay_evm_analysis_workspace_execution_closure(value)
    return evidence


def ensure_evm_analysis_workspace_authority(
    *,
    config: Mapping[str, Any],
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    audit_snapshot: Mapping[str, Any],
    implementation_root: Path,
    admitted_tool_authorities: Mapping[str, Mapping[str, Any]] | None = None,
    fault_injector: _FaultInjector | None = None,
) -> EVMAnalysisWorkspaceOutcome | None:
    pipeline, _mode, ecosystem, _backend = _dimensions(config)
    if pipeline != "sc" or ecosystem != "evm":
        return None
    root = Path(scratchpad)
    project = Path(project_root)
    contract, launch = _contract_and_launch(config)
    ledger = read_artifact_ledger(root)
    row = ledger.get("work_units", {}).get(contract.key)
    committed = False
    if row is None:
        try:
            row = record_work_unit_inputs(
                root, project, contract, launch, run_id=run_id
            )
        except ArtifactLedgerError as exc:
            _fail("EVM workspace PhaseIO input arm failed", exc)
    if not isinstance(row, Mapping):
        _fail("EVM workspace PhaseIO row is malformed")
    if (
        row.get("run_id") != run_id
        or row.get("contract_digest") != contract.digest
        or row.get("launch_digest") != launch.digest
    ):
        _fail("EVM workspace stored owner authority differs")
    if row.get("semantic_status") == "ACTIVE":
        issues = validate_work_unit_artifacts(
            root, project, contract, launch, run_id=run_id, actor="DRIVER"
        )
        if issues:
            _fail("EVM workspace committed replay failed: " + "; ".join(issues))
        committed = True
    else:
        issues = validate_work_unit_inputs(
            root, project, contract, launch, run_id=run_id
        )
        if issues:
            _fail("EVM workspace input replay failed: " + "; ".join(issues))

    if committed:
        receipt = _read_receipt(root / WORKSPACE_RECEIPT_PATH)
        if (
            receipt["run_id"] != run_id
            or receipt["snapshot"]["snapshot_sha256"] != audit_snapshot.get("snapshot_digest")
            or receipt["owner"]["work_unit_key"] != contract.key
        ):
            _fail("EVM workspace committed receipt belongs to another authority")
        _replay_committed_analysis_projection_binding(root, receipt)
        replay_evm_analysis_workspace_execution_closure(receipt)
    else:
        effective_config: dict[str, Any] = dict(config)
        components = audit_snapshot.get("components")
        projection_component = (
            components.get("evm_analysis_projection")
            if isinstance(components, Mapping) else None
        )
        if projection_component is not None:
            effective_config["_committed_evm_analysis_projection"] = (
                load_committed_evm_analysis_projection(
                    root,
                    project_root=project,
                    run_id=run_id,
                    audit_snapshot=audit_snapshot,
                    config=config,
                )
            )
        receipt = build_evm_analysis_workspace_receipt(
            config=effective_config,
            project_root=project,
            run_id=run_id,
            audit_snapshot=audit_snapshot,
            owner_work_unit_key=contract.key,
            implementation_root=Path(implementation_root),
            admitted_tool_authorities=admitted_tool_authorities,
        )
        raw = _canonical_file(receipt)
        _atomic_write(root / WORKSPACE_RECEIPT_PATH, raw)
        if fault_injector is not None:
            fault_injector("after_publish_before_commit")
        try:
            committed_row = record_work_unit_artifacts(
                root,
                project,
                contract,
                launch,
                run_id=run_id,
                actor="DRIVER",
                expected_output_records={
                    WORKSPACE_RECEIPT_IDENTITY: {
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size": len(raw),
                    }
                },
            )
        except ArtifactLedgerError as exc:
            _fail("EVM workspace PhaseIO output commit failed", exc)
        if committed_row.get("semantic_status") != "ACTIVE":
            _fail("EVM workspace PhaseIO output was not activated")
        issues = validate_work_unit_artifacts(
            root, project, contract, launch, run_id=run_id, actor="DRIVER"
        )
        if issues:
            _fail("EVM workspace output replay failed: " + "; ".join(issues))
        replay_evm_analysis_workspace_execution_closure(receipt)
    reference = workspace_public_reference(receipt)
    return EVMAnalysisWorkspaceOutcome(
        state=str(receipt["state"]),
        reused=committed,
        receipt_sha256=str(receipt["receipt_sha256"]),
        owner_work_unit_key=contract.key,
        public_reference=reference,
    )


def load_evm_analysis_workspace_authority(
    scratchpad: Path,
    *,
    expected_run_id: str | None = None,
    expected_snapshot_sha256: str | None = None,
    expected_owner_work_unit_key: str | None = None,
) -> dict[str, Any]:
    root = Path(scratchpad)
    value = validate_evm_analysis_workspace_receipt(
        _read_receipt(root / WORKSPACE_RECEIPT_PATH),
        expected_run_id=expected_run_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
        expected_owner_work_unit_key=expected_owner_work_unit_key,
    )
    owner_key = str(value["owner"]["work_unit_key"])
    parts = owner_key.split("/")
    if len(parts) != 6 or parts[-2:] != ["recon", WORKSPACE_WORK_UNIT_ID]:
        _fail("EVM workspace owner key cannot derive PhaseIO authority")
    contract, launch = _contract_and_launch({
        "pipeline": parts[0],
        "mode": parts[1],
        "language": parts[2],
        "cli_backend": parts[3],
    })
    if contract.key != owner_key:
        _fail("EVM workspace owner key differs from derived PhaseIO contract")
    issues = validate_work_unit_artifacts(
        root,
        Path(str(value["project_root"]["absolute_path"])),
        contract,
        launch,
        run_id=str(value["run_id"]),
        actor="DRIVER",
    )
    if issues:
        _fail("EVM workspace production load lacks committed lineage: " + "; ".join(issues))
    _replay_committed_analysis_projection_binding(root, value)
    return replay_evm_analysis_workspace_execution_closure(value)


__all__ = [
    "EVMAnalysisWorkspaceAuthorityError",
    "EVMAnalysisWorkspaceOutcome",
    "SessionBoundEVMToolAuthority",
    "WORKSPACE_RECEIPT_IDENTITY",
    "WORKSPACE_RECEIPT_PATH",
    "WORKSPACE_REFERENCE_SCHEMA",
    "WORKSPACE_SCHEMA",
    "WORKSPACE_WORK_UNIT_ID",
    "ANALYSIS_PROJECTION_STAGING_RECEIPT_CONFIG",
    "ANALYSIS_PROJECTION_NATIVE_AUTHORITY_CONFIG",
    "ANALYSIS_PROJECTION_STAGING_DIRECTORY",
    "ANALYSIS_PROJECTION_STAGING_RECEIPT_PATH",
    "MATERIALIZATION_LINEAGE_IDENTITY",
    "MATERIALIZATION_LINEAGE_PATH",
    "MATERIALIZATION_LINEAGE_STAGING_CONFIG",
    "MATERIALIZATION_LINEAGE_STAGING_PATH",
    "build_evm_analysis_workspace_receipt",
    "build_session_bound_evm_tool_execution_plan",
    "capture_evm_build_root_resolver_authority",
    "decode_evm_analysis_workspace_receipt_test_only",
    "ensure_committed_evm_analysis_projection",
    "ensure_evm_analysis_workspace_authority",
    "load_committed_evm_analysis_projection",
    "load_evm_analysis_workspace_authority",
    "issue_session_bound_evm_tool_authority",
    "require_admitted_workspace_tool",
    "require_custodied_workspace_tool_for_execution",
    "replay_evm_analysis_workspace_execution_closure",
    "validate_evm_analysis_workspace_receipt",
    "workspace_public_reference",
]
