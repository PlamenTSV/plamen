#!/usr/bin/env python3
"""Fail-closed contract for out-of-tree JavaScript dependency materialization.

This module selects a lock authority and describes two bounded Yarn Classic
transactions: one online install through verified egress followed by a clean,
no-network replay.  It deliberately does not create directories, extract
archives, copy caches, start processes, or authorize those effects.  A future
native lifecycle owner must retain the source and toolchain objects, enforce
the declared bounds, and produce the receipts described by the contract.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import PurePath, PurePosixPath, PureWindowsPath
import re
from typing import Any

import js_lock_authority as LOCK
import js_toolchain_authority as TOOLCHAIN


SCHEMA = "plamen.js-dependency-materialization-contract.v2"
SOURCE_ACCESS = "IMMUTABLE_READ_ONLY_SNAPSHOT"
WORKSPACE_ACCESS = "PRIVATE_EMPTY_OUT_OF_TREE"
EXECUTION_STATE = "PLAN_ONLY_NATIVE_LIFECYCLE_REQUIRED"
TREE_DIGEST_ALGORITHM = "PLAMEN_CANONICAL_TREE_SHA256_V1"

MAX_PACKAGE_JSON_BYTES = 4 * 1024 * 1024
MAX_LOCKFILE_BYTES = 32 * 1024 * 1024
MAX_LOCKFILES_BYTES = 64 * 1024 * 1024
MAX_PHASE_TIMEOUT_SECONDS = 2 * 60 * 60
MAX_DEPENDENCY_ENTRIES = 500_000
MAX_DEPENDENCY_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_CACHE_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024

_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_GENERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)


class JSDependencyMaterializationError(RuntimeError):
    """The dependency contract cannot be constructed safely."""

    def __init__(
        self,
        code: str,
        *,
        cause_code: str = "",
        packaging_debt: tuple[TOOLCHAIN.PackagingDebt, ...] = (),
    ) -> None:
        self.code = code
        self.cause_code = cause_code
        self.packaging_debt = packaging_debt
        super().__init__(code)


@dataclass(frozen=True)
class ImmutableJSSourceInputs:
    """Bytes retained from one already authenticated, read-only snapshot."""

    source_root: str
    source_snapshot_sha256: str
    package_json: bytes
    lockfiles: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class PrivateDependencyWorkspaceInputs:
    """Bounds for a new private workspace that is disjoint from the source."""

    private_root: str
    generation_id: str
    phase_timeout_seconds: int
    max_dependency_entries: int
    max_dependency_expanded_bytes: int
    max_cache_expanded_bytes: int


@dataclass(frozen=True)
class ToolchainBinding:
    bootstrap_anchor_sha256: str
    bootstrap_install_provenance_sha256: str
    bootstrap_signed_set_sha256: str
    bootstrap_source_census_sha256: str
    manifest_content_sha256: str
    runtime_closure_sha256: str
    upstream_verification_sha256: str
    node_artifact_id: str
    node_archive_sha256: str
    node_archive_path: str
    node_executable_path: str
    yarn_artifact_id: str
    yarn_archive_sha256: str
    yarn_archive_size: int
    yarn_archive_path: str
    yarn_cli_path: str
    binding_sha256: str

    def binding_dict(self) -> dict[str, Any]:
        return {
            "bootstrap_anchor_sha256": self.bootstrap_anchor_sha256,
            "bootstrap_install_provenance_sha256": (
                self.bootstrap_install_provenance_sha256
            ),
            "bootstrap_signed_set_sha256": self.bootstrap_signed_set_sha256,
            "bootstrap_source_census_sha256": (
                self.bootstrap_source_census_sha256
            ),
            "manifest_content_sha256": self.manifest_content_sha256,
            "node_archive_path": self.node_archive_path,
            "node_archive_sha256": self.node_archive_sha256,
            "node_artifact_id": self.node_artifact_id,
            "node_executable_path": self.node_executable_path,
            "runtime_closure_sha256": self.runtime_closure_sha256,
            "upstream_verification_sha256": self.upstream_verification_sha256,
            "yarn_archive_path": self.yarn_archive_path,
            "yarn_archive_sha256": self.yarn_archive_sha256,
            "yarn_archive_size": self.yarn_archive_size,
            "yarn_artifact_id": self.yarn_artifact_id,
            "yarn_cli_path": self.yarn_cli_path,
            "binding_sha256": self.binding_sha256,
        }


@dataclass(frozen=True)
class DependencyPhaseContract:
    phase: str
    cwd: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    network_mode: str
    egress_target_id: str
    private_root: str
    home_root: str
    modules_root: str
    cache_root: str
    temp_root: str
    phase_timeout_seconds: int
    max_dependency_entries: int
    max_dependency_expanded_bytes: int
    max_cache_expanded_bytes: int
    required_preconditions: tuple[str, ...]

    def binding_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "cache_root": self.cache_root,
            "cwd": self.cwd,
            "egress_target_id": self.egress_target_id,
            "environment": [[key, value] for key, value in self.environment],
            "home_root": self.home_root,
            "max_cache_expanded_bytes": self.max_cache_expanded_bytes,
            "max_dependency_entries": self.max_dependency_entries,
            "max_dependency_expanded_bytes": self.max_dependency_expanded_bytes,
            "modules_root": self.modules_root,
            "network_mode": self.network_mode,
            "phase": self.phase,
            "phase_timeout_seconds": self.phase_timeout_seconds,
            "private_root": self.private_root,
            "required_preconditions": list(self.required_preconditions),
            "temp_root": self.temp_root,
        }


@dataclass(frozen=True)
class CleanOfflineReplayContract:
    online_cache_root: str
    retained_cache_snapshot_root: str
    offline_cache_seed_root: str
    cache_handoff: str
    source_snapshot_sha256: str
    required_online_receipt_fields: tuple[str, ...]
    required_offline_receipt_fields: tuple[str, ...]
    required_receipt_equalities: tuple[tuple[str, str], ...]
    required_terminal_conditions: tuple[str, ...]
    tree_digest_algorithm: str

    def binding_dict(self) -> dict[str, Any]:
        return {
            "cache_handoff": self.cache_handoff,
            "offline_cache_seed_root": self.offline_cache_seed_root,
            "online_cache_root": self.online_cache_root,
            "required_receipt_equalities": [
                [online, offline]
                for online, offline in self.required_receipt_equalities
            ],
            "required_terminal_conditions": list(
                self.required_terminal_conditions
            ),
            "required_offline_receipt_fields": list(
                self.required_offline_receipt_fields
            ),
            "required_online_receipt_fields": list(
                self.required_online_receipt_fields
            ),
            "retained_cache_snapshot_root": self.retained_cache_snapshot_root,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "tree_digest_algorithm": self.tree_digest_algorithm,
        }


@dataclass(frozen=True)
class GuestExecutionBinding:
    target_os: str
    target_arch: str
    controller_transaction_root: str
    controller_scratch_root: str
    controller_state_root: str
    guest_project_root: str
    guest_scratch_root: str
    guest_state_root: str
    project_access: str
    scratch_access: str
    state_access: str
    binding_sha256: str

    def binding_dict(self) -> dict[str, Any]:
        return {
            "binding_sha256": self.binding_sha256,
            "controller_scratch_root": self.controller_scratch_root,
            "controller_state_root": self.controller_state_root,
            "controller_transaction_root": self.controller_transaction_root,
            "guest_project_root": self.guest_project_root,
            "guest_scratch_root": self.guest_scratch_root,
            "guest_state_root": self.guest_state_root,
            "project_access": self.project_access,
            "scratch_access": self.scratch_access,
            "state_access": self.state_access,
            "target_arch": self.target_arch,
            "target_os": self.target_os,
        }


@dataclass(frozen=True)
class JSDependencyMaterializationContract:
    schema: str
    generation_id: str
    source_access: str
    workspace_access: str
    source_root: str
    source_snapshot_sha256: str
    package_json_sha256: str
    lock_selection: LOCK.JSLockSelection
    toolchain: ToolchainBinding
    execution: GuestExecutionBinding
    online: DependencyPhaseContract
    offline_replay: DependencyPhaseContract
    replay: CleanOfflineReplayContract
    execution_state: str
    contract_sha256: str

    def binding_dict(self) -> dict[str, Any]:
        return {
            "execution_state": self.execution_state,
            "execution": self.execution.binding_dict(),
            "generation_id": self.generation_id,
            "lock_selection": self.lock_selection.binding_dict()
            | {"selection_sha256": self.lock_selection.selection_sha256},
            "offline_replay": self.offline_replay.binding_dict(),
            "online": self.online.binding_dict(),
            "package_json_sha256": self.package_json_sha256,
            "replay": self.replay.binding_dict(),
            "schema": self.schema,
            "source_access": self.source_access,
            "source_root": self.source_root,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "toolchain": self.toolchain.binding_dict(),
            "workspace_access": self.workspace_access,
        }


def _fail(
    code: str,
    *,
    cause_code: str = "",
    packaging_debt: tuple[TOOLCHAIN.PackagingDebt, ...] = (),
) -> None:
    raise JSDependencyMaterializationError(
        code, cause_code=cause_code, packaging_debt=packaging_debt
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex64(value: object, code: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(code)
    return value


def _bounded_positive(value: object, maximum: int, code: str) -> int:
    if type(value) is not int or value <= 0 or value > maximum:
        _fail(code)
    return value


def _pure_absolute(value: object, target_os: str, code: str) -> PurePath:
    if type(value) is not str or not value or "\x00" in value:
        _fail(code)
    parsed: PurePath = (
        PureWindowsPath(value)
        if target_os == "windows"
        else PurePosixPath(value)
    )
    if not parsed.is_absolute() or any(part == ".." for part in parsed.parts):
        _fail(code)
    return parsed


def _contains(parent: PurePath, child: PurePath) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_inputs(
    source: ImmutableJSSourceInputs,
    workspace: PrivateDependencyWorkspaceInputs,
    *,
    target_os: str,
) -> tuple[PurePath, PurePath, dict[str, bytes]]:
    if type(source) is not ImmutableJSSourceInputs:
        _fail("SOURCE_INPUT_TYPE_INVALID")
    if type(workspace) is not PrivateDependencyWorkspaceInputs:
        _fail("WORKSPACE_INPUT_TYPE_INVALID")
    source_root = _pure_absolute(
        source.source_root, target_os, "SOURCE_ROOT_INVALID"
    )
    private_root = _pure_absolute(
        workspace.private_root, target_os, "PRIVATE_ROOT_INVALID"
    )
    if _contains(source_root, private_root) or _contains(private_root, source_root):
        _fail("SOURCE_PRIVATE_ROOTS_OVERLAP")
    _hex64(source.source_snapshot_sha256, "SOURCE_SNAPSHOT_SHA256_INVALID")
    if (
        type(source.package_json) is not bytes
        or not source.package_json
        or len(source.package_json) > MAX_PACKAGE_JSON_BYTES
    ):
        _fail("PACKAGE_JSON_SIZE_INVALID")
    if type(source.lockfiles) is not tuple or not source.lockfiles:
        _fail("LOCKFILE_INPUTS_INVALID")
    lockfiles: dict[str, bytes] = {}
    total = 0
    for row in source.lockfiles:
        if type(row) is not tuple or len(row) != 2:
            _fail("LOCKFILE_INPUTS_INVALID")
        filename, data = row
        if (
            type(filename) is not str
            or type(data) is not bytes
            or not data
            or len(data) > MAX_LOCKFILE_BYTES
            or filename in lockfiles
        ):
            _fail("LOCKFILE_INPUTS_INVALID")
        lockfiles[filename] = data
        total += len(data)
    if total > MAX_LOCKFILES_BYTES:
        _fail("LOCKFILE_INPUTS_TOO_LARGE")
    if (
        type(workspace.generation_id) is not str
        or _GENERATION_ID.fullmatch(workspace.generation_id) is None
    ):
        _fail("WORKSPACE_GENERATION_ID_INVALID")
    _bounded_positive(
        workspace.phase_timeout_seconds,
        MAX_PHASE_TIMEOUT_SECONDS,
        "PHASE_TIMEOUT_INVALID",
    )
    _bounded_positive(
        workspace.max_dependency_entries,
        MAX_DEPENDENCY_ENTRIES,
        "DEPENDENCY_ENTRY_BOUND_INVALID",
    )
    _bounded_positive(
        workspace.max_dependency_expanded_bytes,
        MAX_DEPENDENCY_EXPANDED_BYTES,
        "DEPENDENCY_BYTE_BOUND_INVALID",
    )
    _bounded_positive(
        workspace.max_cache_expanded_bytes,
        MAX_CACHE_EXPANDED_BYTES,
        "CACHE_BYTE_BOUND_INVALID",
    )
    return source_root, private_root, lockfiles


def _toolchain_binding(
    repository_root: os.PathLike[str] | str,
    private_root: PurePath,
    *,
    bootstrap_authority: TOOLCHAIN.TrustedJSBootstrapAuthority,
    target_os: str,
    target_arch: str,
) -> tuple[TOOLCHAIN.AuthorityManifest, ToolchainBinding]:
    try:
        authority = TOOLCHAIN.load_authority_manifest(
            repository_root,
            bootstrap_authority=bootstrap_authority,
        )
        node, yarn = TOOLCHAIN.select_artifacts(
            authority, os_name=target_os, arch=target_arch
        )
    except TOOLCHAIN.JSToolchainAuthorityError as exc:
        _fail("JS_TOOLCHAIN_AUTHORITY_INVALID", cause_code=exc.code)
    if (
        yarn.sha256 is None
        or _HEX64.fullmatch(yarn.sha256) is None
        or yarn.size is None
        or yarn.size <= 0
        or yarn.identity_state != "CONTENT_DIGEST_AND_SIGNATURE_PINNED"
        or yarn.upstream_authentication
        != "VERIFIED_YARN_DETACHED_OPENPGP_SIGNATURE"
        or _HEX64.fullmatch(authority.upstream_verification_sha256) is None
    ):
        _fail("YARN_REVIEWED_DIGEST_MISSING")
    if node.sha256 is None or _HEX64.fullmatch(node.sha256) is None:
        _fail("NODE_REVIEWED_DIGEST_MISSING")
    try:
        archives = TOOLCHAIN.require_packaged_artifacts(
            authority,
            repository_root,
            os_name=target_os,
            arch=target_arch,
        )
    except TOOLCHAIN.JSToolchainPackagingError as exc:
        debt = tuple(exc.debt)
        yarn_debt = tuple(
            item for item in debt if item.artifact_id == yarn.artifact_id
        )
        node_debt = tuple(
            item for item in debt if item.artifact_id == node.artifact_id
        )
        if yarn_debt:
            code = "YARN_TOOLCHAIN_BYTES_UNAVAILABLE"
        elif node_debt:
            code = "NODE_TOOLCHAIN_BYTES_UNAVAILABLE"
        else:
            code = "JS_TOOLCHAIN_BYTES_UNAVAILABLE"
        _fail(code, packaging_debt=debt)
    except TOOLCHAIN.JSToolchainAuthorityError as exc:
        _fail("JS_TOOLCHAIN_BYTES_UNAVAILABLE", cause_code=exc.code)

    toolchain_root = private_root / "toolchain"
    node_executable = (
        toolchain_root
        / "node"
        / node.archive_root
        / PurePosixPath(node.executable)
    )
    yarn_cli = (
        toolchain_root
        / "yarn"
        / yarn.archive_root
        / PurePosixPath(yarn.executable)
    )
    binding_without_digest = {
        "bootstrap_anchor_sha256": authority.bootstrap_anchor_sha256,
        "bootstrap_install_provenance_sha256": (
            bootstrap_authority.install_provenance_sha256
        ),
        "bootstrap_signed_set_sha256": authority.bootstrap_signed_set_sha256,
        "bootstrap_source_census_sha256": bootstrap_authority.source_census_sha256,
        "manifest_content_sha256": authority.content_sha256,
        "runtime_closure_sha256": authority.runtime_closure_sha256,
        "upstream_verification_sha256": authority.upstream_verification_sha256,
        "node_artifact_id": node.artifact_id,
        "node_archive_sha256": node.sha256,
        "node_archive_path": str(archives[node.artifact_id]),
        "node_executable_path": str(node_executable),
        "yarn_artifact_id": yarn.artifact_id,
        "yarn_archive_sha256": yarn.sha256,
        "yarn_archive_size": yarn.size,
        "yarn_archive_path": str(archives[yarn.artifact_id]),
        "yarn_cli_path": str(yarn_cli),
    }
    return authority, ToolchainBinding(
        **binding_without_digest,
        binding_sha256=_sha256(_canonical_bytes(binding_without_digest)),
    )


def _phase(
    authority: TOOLCHAIN.AuthorityManifest,
    toolchain: ToolchainBinding,
    source_root: PurePath,
    phase_root: PurePath,
    workspace: PrivateDependencyWorkspaceInputs,
    *,
    phase: str,
    target_os: str,
    windows_system_root: str | None,
) -> DependencyPhaseContract:
    roots = TOOLCHAIN.writable_roots(str(phase_root), target_os=target_os)
    environment = TOOLCHAIN.closed_environment(
        authority,
        node_binary=toolchain.node_executable_path,
        roots=roots,
        phase=phase,
        target_os=target_os,
        windows_system_root=windows_system_root,
    )
    argv = TOOLCHAIN.yarn_install_argv(
        authority,
        node_binary=toolchain.node_executable_path,
        yarn_cli=toolchain.yarn_cli_path,
        roots=roots,
        phase=phase,
        target_os=target_os,
    )
    requirement = TOOLCHAIN.network_requirement(authority, phase)
    if phase == "online":
        preconditions = (
            "SOURCE_SNAPSHOT_RETAINED_READ_ONLY",
            "ONLINE_PRIVATE_ROOT_PROVEN_EMPTY",
            "TOOLCHAIN_ARCHIVES_RETAINED_AND_DIGEST_VERIFIED",
            "TOOLCHAIN_EXTRACTION_RECEIPT_VERIFIED",
            "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST_ACTIVE_BEFORE_PROCESS_START",
        )
    else:
        preconditions = (
            "SAME_SOURCE_SNAPSHOT_RETAINED_READ_ONLY",
            "OFFLINE_PRIVATE_ROOT_PROVEN_EMPTY",
            "ONLINE_TERMINAL_RECEIPT_VERIFIED",
            "ONLINE_CACHE_SNAPSHOT_RETAINED_READ_ONLY",
            "OFFLINE_CACHE_SEED_COPIED_BYTE_EXACTLY",
            "NO_NETWORK_ACTIVE_BEFORE_PROCESS_START",
        )
    return DependencyPhaseContract(
        phase=phase,
        cwd=str(source_root),
        argv=argv,
        environment=tuple(sorted(environment.items())),
        network_mode=requirement.mode,
        egress_target_id=(
            "" if requirement.target is None else requirement.target.target_id
        ),
        private_root=roots.private_root,
        home_root=roots.home_root,
        modules_root=roots.modules_root,
        cache_root=roots.cache_root,
        temp_root=roots.temp_root,
        phase_timeout_seconds=workspace.phase_timeout_seconds,
        max_dependency_entries=workspace.max_dependency_entries,
        max_dependency_expanded_bytes=workspace.max_dependency_expanded_bytes,
        max_cache_expanded_bytes=workspace.max_cache_expanded_bytes,
        required_preconditions=preconditions,
    )


def build_js_dependency_materialization_contract(
    source: ImmutableJSSourceInputs,
    workspace: PrivateDependencyWorkspaceInputs,
    *,
    bootstrap_authority: TOOLCHAIN.TrustedJSBootstrapAuthority,
    repository_root: os.PathLike[str] | str,
    target_os: str,
    target_arch: str,
    windows_system_root: str | None = None,
) -> JSDependencyMaterializationContract:
    """Return a non-executable, fully bound online/offline Yarn contract.

    The call performs only validation and read-only verification through
    :mod:`js_toolchain_authority`.  In particular, it never creates the roots
    named in the result and never starts Yarn.
    """

    if type(target_os) is not str or type(target_arch) is not str:
        _fail("TARGET_PLATFORM_INVALID")
    try:
        normalized_os, normalized_arch = TOOLCHAIN.normalized_platform(
            target_os, target_arch
        )
    except TOOLCHAIN.JSToolchainAuthorityError as exc:
        _fail("TARGET_PLATFORM_INVALID", cause_code=exc.code)
    source_root, private_root, lockfiles = _validate_inputs(
        source, workspace, target_os=normalized_os
    )
    try:
        selection = LOCK.select_js_lock_authority(
            source.package_json, lockfiles
        )
    except LOCK.JSLockAuthorityError as exc:
        _fail("JS_LOCK_SELECTION_FAILED", cause_code=exc.code)
    if selection.family != "yarn" or selection.filename != "yarn.lock":
        _fail("JS_LOCK_FAMILY_NOT_IMPLEMENTED")

    controller_scratch_root = private_root / "scratch"
    controller_state_root = private_root / "state"
    if normalized_os == "windows":
        guest_project_root: PurePath = PureWindowsPath(r"C:\workspace\project")
        guest_scratch_root: PurePath = PureWindowsPath(r"C:\workspace\scratch")
        guest_state_root: PurePath = PureWindowsPath(r"C:\workspace\state")
    else:
        guest_project_root = PurePosixPath("/workspace/project")
        guest_scratch_root = PurePosixPath("/workspace/scratch")
        guest_state_root = PurePosixPath("/workspace/state")
    execution_without_digest = {
        "controller_scratch_root": str(controller_scratch_root),
        "controller_state_root": str(controller_state_root),
        "controller_transaction_root": str(private_root),
        "guest_project_root": str(guest_project_root),
        "guest_scratch_root": str(guest_scratch_root),
        "guest_state_root": str(guest_state_root),
        "project_access": "IMMUTABLE_READ_ONLY",
        "scratch_access": "PRIVATE_READ_WRITE",
        "state_access": "PRIVATE_READ_WRITE",
        "target_arch": normalized_arch,
        "target_os": normalized_os,
    }
    execution = GuestExecutionBinding(
        **execution_without_digest,
        binding_sha256=_sha256(_canonical_bytes(execution_without_digest)),
    )

    authority, toolchain = _toolchain_binding(
        repository_root,
        controller_scratch_root,
        bootstrap_authority=bootstrap_authority,
        target_os=normalized_os,
        target_arch=normalized_arch,
    )
    online_root = controller_scratch_root / "online"
    offline_root = controller_scratch_root / "offline-replay"
    online = _phase(
        authority,
        toolchain,
        source_root,
        online_root,
        workspace,
        phase="online",
        target_os=normalized_os,
        windows_system_root=windows_system_root,
    )
    offline = _phase(
        authority,
        toolchain,
        source_root,
        offline_root,
        workspace,
        phase="offline",
        target_os=normalized_os,
        windows_system_root=windows_system_root,
    )
    cache_snapshot = controller_scratch_root / "online-cache-snapshot"
    replay = CleanOfflineReplayContract(
        online_cache_root=online.cache_root,
        retained_cache_snapshot_root=str(cache_snapshot),
        offline_cache_seed_root=offline.cache_root,
        cache_handoff="COPY_VERIFIED_TREE_INTO_EMPTY_OFFLINE_CACHE",
        source_snapshot_sha256=source.source_snapshot_sha256,
        required_online_receipt_fields=(
            "source_snapshot_sha256",
            "lock_selection_sha256",
            "toolchain_binding_sha256",
            "modules_tree_sha256",
            "modules_entry_count",
            "modules_expanded_bytes",
            "cache_tree_sha256",
            "cache_entry_count",
            "cache_expanded_bytes",
            "exit_code",
            "network_admission_sha256",
        ),
        required_offline_receipt_fields=(
            "source_snapshot_sha256",
            "lock_selection_sha256",
            "toolchain_binding_sha256",
            "seed_cache_tree_sha256",
            "modules_tree_sha256",
            "modules_entry_count",
            "modules_expanded_bytes",
            "exit_code",
            "network_denial_sha256",
        ),
        required_receipt_equalities=(
            ("source_snapshot_sha256", "source_snapshot_sha256"),
            ("lock_selection_sha256", "lock_selection_sha256"),
            ("toolchain_binding_sha256", "toolchain_binding_sha256"),
            ("cache_tree_sha256", "seed_cache_tree_sha256"),
            ("modules_tree_sha256", "modules_tree_sha256"),
            ("modules_entry_count", "modules_entry_count"),
            ("modules_expanded_bytes", "modules_expanded_bytes"),
        ),
        required_terminal_conditions=(
            "ONLINE_EXIT_CODE_ZERO",
            "OFFLINE_EXIT_CODE_ZERO",
            "ONLINE_LIMITS_NOT_EXCEEDED",
            "OFFLINE_LIMITS_NOT_EXCEEDED",
            "OFFLINE_NETWORK_DENIAL_REMAINED_ACTIVE",
        ),
        tree_digest_algorithm=TREE_DIGEST_ALGORITHM,
    )
    provisional = JSDependencyMaterializationContract(
        schema=SCHEMA,
        generation_id=workspace.generation_id,
        source_access=SOURCE_ACCESS,
        workspace_access=WORKSPACE_ACCESS,
        source_root=str(source_root),
        source_snapshot_sha256=source.source_snapshot_sha256,
        package_json_sha256=_sha256(source.package_json),
        lock_selection=selection,
        toolchain=toolchain,
        execution=execution,
        online=online,
        offline_replay=offline,
        replay=replay,
        execution_state=EXECUTION_STATE,
        contract_sha256="",
    )
    return JSDependencyMaterializationContract(
        **{
            **provisional.__dict__,
            "contract_sha256": _sha256(_canonical_bytes(provisional.binding_dict())),
        }
    )


__all__ = [
    "CleanOfflineReplayContract",
    "DependencyPhaseContract",
    "EXECUTION_STATE",
    "GuestExecutionBinding",
    "ImmutableJSSourceInputs",
    "JSDependencyMaterializationContract",
    "JSDependencyMaterializationError",
    "MAX_CACHE_EXPANDED_BYTES",
    "MAX_DEPENDENCY_ENTRIES",
    "MAX_DEPENDENCY_EXPANDED_BYTES",
    "MAX_PHASE_TIMEOUT_SECONDS",
    "PrivateDependencyWorkspaceInputs",
    "SCHEMA",
    "ToolchainBinding",
    "build_js_dependency_materialization_contract",
]
