#!/usr/bin/env python3
"""Governed runtime for the JavaScript dependency materialization contract.

The pure contract in :mod:`js_dependency_materializer_authority` decides which
lockfile and vendored Node/Yarn identities are authoritative.  This module
performs the state-machine and filesystem verification around a *native*
executor.  It never falls back to ``subprocess``, ``PATH``, ambient npm/Yarn,
or an unenforced network namespace.

Production execution is deliberately unavailable unless the installed native
supervisor supplies an opaque ``JSDependencyMaterializerAuthority`` and the
matching ``execute_js_dependency_materializer`` entry point.  Python validates
every request/terminal receipt and independently replays source, archive, and
output-tree identities before committing its crash-safe terminal receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import importlib
import importlib.machinery
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import stat
import sys
import tempfile
import types
from typing import Any, Mapping, NoReturn
from urllib.parse import urlsplit

import js_dependency_materializer_authority as CONTRACT
import js_lock_authority as LOCK
import js_toolchain_authority as TOOLCHAIN


RUNTIME_SCHEMA = "plamen.js-dependency-materialization-runtime.v2"
ADMISSION_SCHEMA = "plamen.js-dependency-native-admission.v2"
REQUEST_SCHEMA = "plamen.js-dependency-native-request.v2"
NATIVE_TERMINAL_SCHEMA = "plamen.js-dependency-native-terminal.v2"
RECEIPT_SCHEMA = "plamen.js-dependency-materialization-receipt.v2"
MARKER_SCHEMA = "plamen.js-dependency-private-root.v2"
JOURNAL_SCHEMA = "plamen.js-dependency-materialization-journal.v2"
NATIVE_MODULE_NAME = "_plamen_native_supervisor"
NATIVE_ABI_SCHEMA = "plamen.native-broker.v2"
NATIVE_PRODUCTION_ACQUISITION = "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
NATIVE_RUNTIME_IDENTITY_SCHEMA = (
    "plamen.js-dependency-materializer-runtime-identity.v1"
)
TREE_DIGEST_ALGORITHM = CONTRACT.TREE_DIGEST_ALGORITHM
EMPTY_EGRESS_SHA256 = hashlib.sha256(b"[]").hexdigest()

MAX_NATIVE_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_NATIVE_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_NATIVE_RUNTIME_IDENTITY_BYTES = 64 * 1024
MAX_TOOLCHAIN_ENTRIES = 200_000
MAX_TOOLCHAIN_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_EGRESS_ORIGINS = TOOLCHAIN.MAX_LOCK_EGRESS_ORIGINS
_READ_CHUNK = 1024 * 1024
_HEX64 = __import__("re").compile(r"[0-9a-f]{64}\Z", __import__("re").ASCII)
_OPERATIONS = (
    "PREPARE_TOOLCHAIN",
    "ONLINE_INSTALL",
    "CACHE_HANDOFF",
    "OFFLINE_REPLAY",
)
_STATES = (
    "INITIALIZED",
    "TOOLCHAIN_READY",
    "ONLINE_COMPLETE",
    "CACHE_HANDOFF_COMPLETE",
    "OFFLINE_COMPLETE",
    "COMMITTED",
)
_RC_FILES = frozenset({".yarnrc", ".yarnrc.yml", ".npmrc"})
_EXACT_YARN_FLAGS = tuple(TOOLCHAIN.FIXED_YARN_INSTALL_FLAGS)
_CLOSED_ENVIRONMENT_KEYS = frozenset(
    {
        "HOME",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "PATH",
        "NODE_ENV",
        "YARN_CACHE_FOLDER",
        "YARN_GLOBAL_FOLDER",
        "YARN_IGNORE_PATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        "PLAMEN_JS_NETWORK_MODE",
        "PLAMEN_JS_EGRESS_TARGET_ID",
        "PLAMEN_JS_EGRESS_TARGET_AUTHORITY_SHA256",
        "SYSTEMROOT",
        "WINDIR",
    }
)


class JSDependencyRuntimeError(RuntimeError):
    """Typed, fail-closed runtime failure."""

    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        super().__init__(message or code)


def _fail(code: str, message: str = "") -> NoReturn:
    raise JSDependencyRuntimeError(code, message)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            _plain(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise JSDependencyRuntimeError(
            "CANONICAL_JSON_INVALID", "runtime value is not canonical JSON"
        ) from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _hex64(value: object, code: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(code)
    return value


@dataclass(frozen=True)
class NativeMaterializerAuthorities:
    """Digests supplied by the authenticated launcher, not ambient discovery."""

    custody_receipt_sha256: str
    online_network_admission_sha256: str
    offline_network_denial_sha256: str
    native_extension_sha256: str
    native_deployment_receipt_sha256: str

    def binding_dict(self) -> dict[str, str]:
        return {
            "custody_receipt_sha256": self.custody_receipt_sha256,
            "offline_network_denial_sha256": self.offline_network_denial_sha256,
            "native_deployment_receipt_sha256": self.native_deployment_receipt_sha256,
            "native_extension_sha256": self.native_extension_sha256,
            "online_network_admission_sha256": self.online_network_admission_sha256,
        }


@dataclass(frozen=True)
class TreeIdentity:
    sha256: str
    entry_count: int
    expanded_bytes: int

    def binding_dict(self) -> dict[str, Any]:
        return {
            "algorithm": TREE_DIGEST_ALGORITHM,
            "entry_count": self.entry_count,
            "expanded_bytes": self.expanded_bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class JSDependencyMaterializationResult:
    private_root: str
    modules_root: str
    receipt_path: str
    receipt_sha256: str
    receipt: Mapping[str, Any]


@dataclass(frozen=True)
class NativeGuestEVMAnalysisProjectionResult:
    """Purpose-scoped result of the complete JS-to-analysis transaction."""

    dependency_materialization: JSDependencyMaterializationResult
    native_projection_authority: object = field(repr=False, compare=False)
    projection_receipt: bytes = field(repr=False)
    materialization_lineage: bytes = field(repr=False)
    workspace_binding: Mapping[str, Any]
    projection_receipt_path: str
    materialization_lineage_path: str


@dataclass(frozen=True)
class _NativeRuntime:
    authority: object
    session_lease: object
    execution_lease_type: type | None
    terminal_replay_lease_type: type | None
    prepare_execution: Any
    execute: Any
    replay_terminal: Any
    module_sha256: str
    session_admission_sha256: str


@dataclass(frozen=True)
class _InstalledNativeBridge:
    """Exact preloaded production extension surface and its one-shot authority."""

    module: types.ModuleType
    initial_authority: object
    authority_type: type
    session_type: type
    execution_type: type
    terminal_replay_type: type
    runtime_identity: Any
    authenticate: Any
    prepare: Any
    execute: Any
    replay_terminal: Any
    extension_path: Path
    extension_sha256: str


@dataclass
class _RetainedSource:
    root: Path
    guard: dict[str, Any]
    root_descriptor: int
    descriptors: dict[str, int]
    descriptor_stats: dict[str, tuple[int, ...]]
    package_json: bytes
    selected_lockfile: bytes

    def verify(self, contract: CONTRACT.JSDependencyMaterializationContract) -> None:
        if _source_preflight(contract) != self.guard:
            _fail("SOURCE_CHANGED_DURING_MATERIALIZATION")
        try:
            root_path = self.root.lstat()
            root_open = os.fstat(self.root_descriptor)
            if _stable_stat(root_path) != _stable_stat(root_open):
                _fail("SOURCE_DESCRIPTOR_REPLAY_FAILED")
            for name, descriptor in self.descriptors.items():
                opened = os.fstat(descriptor)
                linked = (self.root / name).lstat()
                if (
                    _stable_stat(opened) != self.descriptor_stats[name]
                    or _stable_stat(linked) != self.descriptor_stats[name]
                ):
                    _fail("SOURCE_DESCRIPTOR_REPLAY_FAILED")
        except OSError as exc:
            raise JSDependencyRuntimeError(
                "SOURCE_DESCRIPTOR_REPLAY_FAILED", str(self.root)
            ) from exc

    def close(self) -> None:
        for descriptor in (*self.descriptors.values(), self.root_descriptor):
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass
class _RetainedArchives:
    binding: dict[str, Any]
    source_binding: dict[str, Any]
    descriptors: dict[str, int]
    descriptor_stats: dict[str, tuple[int, ...]]
    manifest_bytes: bytes
    root: Path | None = None
    root_descriptor: int = -1
    root_stat: tuple[int, ...] | None = None

    def verify(self, contract: CONTRACT.JSDependencyMaterializationContract) -> None:
        if _archive_preflight(contract) != self.source_binding:
            _fail("TOOLCHAIN_ARCHIVE_CHANGED_DURING_MATERIALIZATION")
        try:
            for artifact_id, descriptor in self.descriptors.items():
                row = self.source_binding[artifact_id]
                opened = os.fstat(descriptor)
                linked = Path(row["path"]).lstat()
                if (
                    _stable_stat(opened) != self.descriptor_stats[artifact_id]
                    or _stable_stat(linked) != self.descriptor_stats[artifact_id]
                ):
                    _fail("TOOLCHAIN_ARCHIVE_DESCRIPTOR_REPLAY_FAILED")
        except OSError as exc:
            raise JSDependencyRuntimeError(
                "TOOLCHAIN_ARCHIVE_DESCRIPTOR_REPLAY_FAILED"
            ) from exc
        if self.root is not None:
            _verify_archive_root(self)

    def close(self) -> None:
        if self.root_descriptor >= 0:
            try:
                os.close(self.root_descriptor)
            except OSError:
                pass
            self.root_descriptor = -1
        for descriptor in self.descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validate_authorities(value: object) -> NativeMaterializerAuthorities:
    if type(value) is not NativeMaterializerAuthorities:
        _fail("NATIVE_AUTHORITIES_TYPE_INVALID")
    for label, digest in (
        ("NATIVE_CUSTODY_RECEIPT_INVALID", value.custody_receipt_sha256),
        ("ONLINE_NETWORK_ADMISSION_INVALID", value.online_network_admission_sha256),
        ("OFFLINE_NETWORK_DENIAL_INVALID", value.offline_network_denial_sha256),
        ("NATIVE_EXTENSION_SHA256_INVALID", value.native_extension_sha256),
        (
            "NATIVE_DEPLOYMENT_RECEIPT_INVALID",
            value.native_deployment_receipt_sha256,
        ),
    ):
        _hex64(digest, label)
    if len(set(value.binding_dict().values())) != len(value.binding_dict()):
        _fail("NATIVE_AUTHORITIES_ALIAS")
    return value


def _installed_native_bridge() -> _InstalledNativeBridge:
    """Authenticate the already-loaded production bridge without importing it.

    Import search is not an authority boundary.  The installer-owned launcher
    must preload the exact extension and finish its broker-v2 handshake before
    this caller runs; test-only extensions and Python module lookalikes are
    rejected before contract construction or filesystem mutation.
    """

    try:
        module_table = types.ModuleType.__getattribute__(sys, "__dict__").get(
            "modules"
        )
        if type(module_table) is not dict:
            raise TypeError
        module = module_table.get(NATIVE_MODULE_NAME)
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
        origin = spec_namespace.get("origin")
        metadata = (
            namespace.get("__name__"),
            namespace.get("__file__"),
            spec_namespace.get("name"),
            origin,
            loader_namespace.get("name"),
            loader_namespace.get("path"),
        )
        if any(
            type(item) is not str or not item or "\x00" in item
            for item in metadata
        ):
            raise TypeError
        (
            module_name,
            module_file,
            spec_name,
            _origin,
            loader_name,
            loader_path,
        ) = metadata
        if (
            module_name != NATIVE_MODULE_NAME
            or module_file != origin
            or spec_name != NATIVE_MODULE_NAME
            or loader_name != NATIVE_MODULE_NAME
            or loader_path != origin
            or namespace.get("BROKER_V2_ABI_SCHEMA") != NATIVE_ABI_SCHEMA
            or namespace.get("BROKER_V2_PRODUCTION_ACQUISITION")
            != NATIVE_PRODUCTION_ACQUISITION
            or namespace.get("BROKER_V2_INITIAL_AUTHORITY_AVAILABLE") is not True
            or namespace.get("TEST_ONLY_BUILD") is not False
            or not any(
                origin.endswith(suffix)
                for suffix in importlib.machinery.EXTENSION_SUFFIXES
            )
        ):
            raise TypeError

        type_names = (
            "JSDependencyMaterializerAuthority",
            "JSDependencyMaterializerSessionLease",
            "JSDependencyMaterializerExecutionLease",
            "JSDependencyMaterializerTerminalReplayLease",
        )
        function_names = (
            "js_dependency_materializer_runtime_identity",
            "authenticate_js_dependency_materializer_capability",
            "prepare_js_dependency_materializer_execution",
            "execute_js_dependency_materializer",
            "replay_js_dependency_materializer_terminal",
        )
        native_types = tuple(namespace.get(name) for name in type_names)
        native_functions = tuple(namespace.get(name) for name in function_names)
        if any(type(item) is not type for item in native_types):
            raise TypeError
        for native_type in native_types:
            flags = type.__getattribute__(native_type, "__flags__")
            if (
                type.__getattribute__(native_type, "__module__")
                != NATIVE_MODULE_NAME
                or flags & (1 << 8) == 0
                or flags & (1 << 9)
                or flags & (1 << 10)
            ):
                raise TypeError
        if any(
            type(function) is not types.BuiltinFunctionType
            or getattr(function, "__module__", None) != NATIVE_MODULE_NAME
            or getattr(function, "__name__", None) != name
            or getattr(function, "__self__", None) is not module
            for name, function in zip(function_names, native_functions, strict=True)
        ):
            raise TypeError
        authority_type, session_type, execution_type, replay_type = native_types
        initial = namespace.get("JS_DEPENDENCY_MATERIALIZER_INITIAL_AUTHORITY")
        if type(initial) is not authority_type:
            raise TypeError

        extension_path = _safe_absolute(origin, "NATIVE_EXTENSION_PATH_INVALID")
        if os.fspath(extension_path) != origin:
            raise TypeError
        _reject_alias_ancestry(extension_path, allow_missing_leaf=False)
        info = extension_path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or int(info.st_nlink) != 1
            or int(info.st_size) < 1
            or int(info.st_size) > MAX_TOOLCHAIN_EXPANDED_BYTES
            or (
                os.name != "nt"
                and (
                    int(info.st_uid) not in {0, int(os.geteuid())}
                    or int(info.st_mode) & 0o022
                )
            )
        ):
            raise TypeError
        extension_raw, extension_stat = _read_regular_file(
            extension_path, maximum=MAX_TOOLCHAIN_EXPANDED_BYTES
        )
        if _stable_stat(info) != extension_stat:
            raise TypeError
        extension_sha256 = hashlib.sha256(extension_raw).hexdigest()
        runtime_identity, authenticate, prepare, execute, replay_terminal = (
            native_functions
        )
        return _InstalledNativeBridge(
            module=module,
            initial_authority=initial,
            authority_type=authority_type,
            session_type=session_type,
            execution_type=execution_type,
            terminal_replay_type=replay_type,
            runtime_identity=runtime_identity,
            authenticate=authenticate,
            prepare=prepare,
            execute=execute,
            replay_terminal=replay_terminal,
            extension_path=extension_path,
            extension_sha256=extension_sha256,
        )
    except JSDependencyRuntimeError:
        raise
    except BaseException as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_MATERIALIZER_UNAVAILABLE",
            "authenticated installed JavaScript materializer bridge is unavailable",
        ) from exc


def _parse_authenticated_runtime_identity(
    raw: object,
    *,
    expected_native_extension_sha256: str,
) -> tuple[TOOLCHAIN.TrustedJSBootstrapAuthority, NativeMaterializerAuthorities]:
    """Map an authenticated native 0x2105 projection to typed authorities."""

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_NATIVE_RUNTIME_IDENTITY_BYTES:
        _fail("NATIVE_RUNTIME_IDENTITY_BYTES_INVALID")
    try:
        identity = json.loads(raw.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise JSDependencyRuntimeError("NATIVE_RUNTIME_IDENTITY_JSON_INVALID") from exc
    expected_keys = {
        "anchor_relative_path",
        "anchor_sha256",
        "custody_receipt_sha256",
        "install_provenance_sha256",
        "native_deployment_receipt_sha256",
        "native_extension_sha256",
        "offline_network_denial_sha256",
        "online_network_admission_sha256",
        "schema",
        "source_census_sha256",
        "trust_boundary",
    }
    if (
        type(identity) is not dict
        or set(identity) != expected_keys
        or raw != _canonical(identity)
        or identity.get("schema") != NATIVE_RUNTIME_IDENTITY_SCHEMA
        or identity.get("anchor_relative_path")
        != TOOLCHAIN.BOOTSTRAP_RELATIVE_PATH.as_posix()
        or identity.get("trust_boundary") != TOOLCHAIN.BOOTSTRAP_TRUST_BOUNDARY
    ):
        _fail("NATIVE_RUNTIME_IDENTITY_SCHEMA_INVALID")
    for field in (
        "anchor_sha256",
        "custody_receipt_sha256",
        "install_provenance_sha256",
        "native_deployment_receipt_sha256",
        "native_extension_sha256",
        "offline_network_denial_sha256",
        "online_network_admission_sha256",
        "source_census_sha256",
    ):
        _hex64(identity.get(field), "NATIVE_RUNTIME_IDENTITY_DIGEST_INVALID")
    expected_native_extension_sha256 = _hex64(
        expected_native_extension_sha256,
        "NATIVE_EXTENSION_SHA256_INVALID",
    )
    if identity["native_extension_sha256"] != expected_native_extension_sha256:
        _fail("NATIVE_RUNTIME_IDENTITY_EXTENSION_MISMATCH")
    try:
        expected_provenance = TOOLCHAIN.bootstrap_install_provenance_sha256(
            anchor_relative_path=identity["anchor_relative_path"],
            anchor_sha256=identity["anchor_sha256"],
            source_census_sha256=identity["source_census_sha256"],
            trust_boundary=identity["trust_boundary"],
        )
    except TOOLCHAIN.JSToolchainAuthorityError as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_RUNTIME_IDENTITY_BOOTSTRAP_INVALID"
        ) from exc
    if identity["install_provenance_sha256"] != expected_provenance:
        _fail("NATIVE_RUNTIME_IDENTITY_PROVENANCE_MISMATCH")
    bootstrap = TOOLCHAIN.TrustedJSBootstrapAuthority(
        anchor_relative_path=identity["anchor_relative_path"],
        anchor_sha256=identity["anchor_sha256"],
        source_census_sha256=identity["source_census_sha256"],
        install_provenance_sha256=identity["install_provenance_sha256"],
        trust_boundary=identity["trust_boundary"],
    )
    authorities = _validate_authorities(
        NativeMaterializerAuthorities(
            custody_receipt_sha256=identity["custody_receipt_sha256"],
            online_network_admission_sha256=identity[
                "online_network_admission_sha256"
            ],
            offline_network_denial_sha256=identity[
                "offline_network_denial_sha256"
            ],
            native_extension_sha256=identity["native_extension_sha256"],
            native_deployment_receipt_sha256=identity[
                "native_deployment_receipt_sha256"
            ],
        )
    )
    return bootstrap, authorities


def _installed_runtime_authorities(
    bridge: _InstalledNativeBridge,
) -> tuple[TOOLCHAIN.TrustedJSBootstrapAuthority, NativeMaterializerAuthorities]:
    try:
        raw = bridge.runtime_identity(bridge.initial_authority)
    except BaseException as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_RUNTIME_IDENTITY_UNAVAILABLE",
            "native custody did not project its authenticated runtime identity",
        ) from exc
    return _parse_authenticated_runtime_identity(
        raw,
        expected_native_extension_sha256=bridge.extension_sha256,
    )


def _require_native_capability(
    value: object, admission: bytes, *, expected_extension_sha256: str
) -> _NativeRuntime:
    """Acquire an opaque native session lease before any filesystem mutation.

    A Python ``ModuleType`` carrying similarly named classes is not an
    authority.  The provider must be a physically bound CPython extension and
    must mint both the session and per-execution lease objects itself.
    """

    bridge = _installed_native_bridge()
    module = bridge.module
    authority_type = bridge.authority_type
    session_type = bridge.session_type
    execution_type = bridge.execution_type
    terminal_replay_type = bridge.terminal_replay_type
    authenticate = bridge.authenticate
    prepare = bridge.prepare
    execute = bridge.execute
    replay_terminal = bridge.replay_terminal
    if (
        value is not bridge.initial_authority
        or type(value) is not authority_type
        or expected_extension_sha256 != bridge.extension_sha256
    ):
        _fail("NATIVE_MATERIALIZER_CAPABILITY_INVALID")
    try:
        session = authenticate(value, admission)
    except BaseException as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_MATERIALIZER_ADMISSION_FAILED",
            "native custody did not admit the exact materialization contract",
        ) from exc
    if type(session) is not session_type:
        _fail("NATIVE_MATERIALIZER_SESSION_LEASE_INVALID")
    return _NativeRuntime(
        authority=value,
        session_lease=session,
        execution_lease_type=execution_type,
        terminal_replay_lease_type=terminal_replay_type,
        prepare_execution=prepare,
        execute=execute,
        replay_terminal=replay_terminal,
        module_sha256=bridge.extension_sha256,
        session_admission_sha256=hashlib.sha256(admission).hexdigest(),
    )


def _require_native_guest_bundle_capability(
    value: object, admission: bytes, *, expected_extension_sha256: str,
) -> _NativeRuntime:
    """Acquire JS custody through the complete role-2 runtime bundle only."""

    try:
        import posix_backend_execution as runtime

        raw = runtime.native_guest_js_materializer_runtime_identity(value)
        _bootstrap, observed = _parse_authenticated_runtime_identity(
            raw,
            expected_native_extension_sha256=expected_extension_sha256,
        )
        if observed.native_extension_sha256 != expected_extension_sha256:
            _fail("NATIVE_RUNTIME_IDENTITY_EXTENSION_MISMATCH")
        session = runtime.authenticate_native_guest_js_materializer(
            value, admission,
        )
    except JSDependencyRuntimeError:
        raise
    except BaseException as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_MATERIALIZER_ADMISSION_FAILED",
            "opaque native runtime custody did not admit the JS contract",
        ) from exc
    return _NativeRuntime(
        authority=value,
        session_lease=session,
        execution_lease_type=None,
        terminal_replay_lease_type=None,
        prepare_execution=runtime.prepare_native_guest_js_materializer_execution,
        execute=runtime.execute_native_guest_js_materializer,
        replay_terminal=runtime.replay_native_guest_js_materializer_terminal,
        module_sha256=expected_extension_sha256,
        session_admission_sha256=hashlib.sha256(admission).hexdigest(),
    )


def _invoke_native(
    native: _NativeRuntime,
    request: bytes,
    *,
    source_descriptor: int,
    scratch_descriptor: int,
    state_descriptor: int,
    archive_root_descriptor: int,
) -> bytes:
    try:
        execution_lease = native.prepare_execution(
            native.authority,
            native.session_lease,
            request,
            source_descriptor,
            scratch_descriptor,
            state_descriptor,
            archive_root_descriptor,
        )
        if (
            native.execution_lease_type is not None
            and type(execution_lease) is not native.execution_lease_type
        ):
            _fail("NATIVE_MATERIALIZER_EXECUTION_LEASE_INVALID")
        result = native.execute(
            native.authority, native.session_lease, execution_lease
        )
    except BaseException as exc:
        if isinstance(exc, JSDependencyRuntimeError):
            raise
        raise JSDependencyRuntimeError(
            "NATIVE_MATERIALIZER_EXECUTION_FAILED",
            "native materializer did not return a terminal receipt",
        ) from exc
    if type(result) is not bytes or not result or len(result) > MAX_NATIVE_RECEIPT_BYTES:
        _fail("NATIVE_TERMINAL_BYTES_INVALID")
    return result


def _attest_native_terminal_replay(
    native: _NativeRuntime,
    request: bytes,
    terminal: bytes,
    *,
    source_descriptor: int,
    scratch_descriptor: int,
    state_descriptor: int,
    archive_root_descriptor: int,
) -> None:
    """Require native durable-state replay for every terminal receipt.

    Canonical JSON plus a self-digest is tamper evidence, not producer
    authority.  Resume therefore asks the authenticated native provider to
    prove that it previously committed this exact request/terminal pair under
    the live operation-key lease before Python may use a journal row.
    """

    try:
        lease = native.replay_terminal(
            native.authority,
            native.session_lease,
            request,
            terminal,
            source_descriptor,
            scratch_descriptor,
            state_descriptor,
            archive_root_descriptor,
        )
    except BaseException as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_TERMINAL_REPLAY_FAILED",
            "native custody did not attest the stored terminal receipt",
        ) from exc
    if (
        native.terminal_replay_lease_type is not None
        and type(lease) is not native.terminal_replay_lease_type
    ):
        _fail("NATIVE_TERMINAL_REPLAY_LEASE_INVALID")


def _stable_stat(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(getattr(info, "st_file_attributes", 0)),
        int(getattr(info, "st_reparse_tag", 0)),
    )


def _is_reparse(info: os.stat_result) -> bool:
    return bool(
        int(getattr(info, "st_file_attributes", 0))
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    )


def _read_regular_file(
    path: Path, *, maximum: int, expected_sha256: str | None = None
) -> tuple[bytes, tuple[int, ...]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if os.name != "nt" and not nofollow:
        _fail("NOFOLLOW_UNAVAILABLE")
    flags |= nofollow
    descriptor = -1
    try:
        linked_before = path.lstat()
        if stat.S_ISLNK(linked_before.st_mode) or _is_reparse(linked_before):
            _fail("FILE_ALIAS_REJECTED")
        descriptor = os.open(path, flags)
        os.set_inheritable(descriptor, False)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or int(before.st_nlink) != 1
            or int(before.st_size) < 0
            or int(before.st_size) > maximum
            or _stable_stat(linked_before) != _stable_stat(before)
        ):
            _fail("FILE_IDENTITY_UNSAFE")
        chunks: list[bytes] = []
        remaining = int(before.st_size)
        while remaining:
            block = os.read(descriptor, min(_READ_CHUNK, remaining))
            if not block:
                _fail("FILE_TRUNCATED_DURING_READ")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            _fail("FILE_GREW_DURING_READ")
        after = os.fstat(descriptor)
        linked_after = path.lstat()
        if (
            _stable_stat(before) != _stable_stat(after)
            or _stable_stat(after) != _stable_stat(linked_after)
        ):
            _fail("FILE_CHANGED_DURING_READ")
        raw = b"".join(chunks)
    except JSDependencyRuntimeError:
        raise
    except OSError as exc:
        raise JSDependencyRuntimeError("FILE_UNREADABLE", str(path)) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        _fail("FILE_DIGEST_MISMATCH")
    return raw, _stable_stat(after)


def _safe_absolute(path: object, code: str) -> Path:
    if type(path) is not str or not path or "\x00" in path:
        _fail(code)
    value = Path(path)
    if not value.is_absolute() or str(value) != os.path.normpath(str(value)):
        _fail(code)
    return value


def _inside(parent: Path, child: Path) -> bool:
    try:
        return os.path.commonpath((os.fspath(parent), os.fspath(child))) == os.fspath(parent)
    except ValueError:
        return False


def _reject_alias_ancestry(path: Path, *, allow_missing_leaf: bool) -> None:
    cursor = path
    first = True
    while True:
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            if not (allow_missing_leaf and first):
                _fail("PATH_ANCESTRY_MISSING")
        except OSError as exc:
            raise JSDependencyRuntimeError("PATH_ANCESTRY_UNREADABLE", str(path)) from exc
        else:
            if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
                _fail("PATH_ALIAS_REJECTED")
            if os.name != "nt" and int(info.st_mode) & 0o022 and cursor != Path("/tmp"):
                # /tmp itself is sticky and expected; descendants are not trusted.
                if not (cursor == Path("/") or (int(info.st_mode) & stat.S_ISVTX)):
                    _fail("PATH_ANCESTRY_WRITABLE_BY_OTHERS")
        parent = cursor.parent
        if parent == cursor:
            return
        cursor = parent
        first = False


def _phase_environment(phase: CONTRACT.DependencyPhaseContract) -> dict[str, str]:
    environment: dict[str, str] = {}
    for row in phase.environment:
        if (
            type(row) is not tuple
            or len(row) != 2
            or type(row[0]) is not str
            or type(row[1]) is not str
            or not row[0]
            or "\x00" in row[0]
            or "\x00" in row[1]
            or row[0] in environment
        ):
            _fail("PHASE_ENVIRONMENT_INVALID")
        environment[row[0]] = row[1]
    return environment


def _base_registry_binding(
    phase: CONTRACT.DependencyPhaseContract,
    environment: Mapping[str, str],
) -> dict[str, str] | None:
    if phase.network_mode == "NO_NETWORK":
        return None
    registry = phase.argv[-1]
    parsed = urlsplit(registry)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port not in (None, 443)
        or not phase.egress_target_id
    ):
        _fail("ONLINE_REGISTRY_IDENTITY_INVALID")
    return {
        "authority_sha256": _hex64(
            environment.get("PLAMEN_JS_EGRESS_TARGET_AUTHORITY_SHA256"),
            "ONLINE_EGRESS_AUTHORITY_INVALID",
        ),
        "registry_url": registry,
        "target_id": phase.egress_target_id,
    }


def _network_policy(
    phase: CONTRACT.DependencyPhaseContract,
    environment: Mapping[str, str],
    dependency_expectation: Mapping[str, Any],
    *,
    authority_sha256: str,
) -> dict[str, Any]:
    if phase.network_mode == "NO_NETWORK":
        body = {
            "allowed_origins": [],
            "authority_sha256": authority_sha256,
            "base_registry": None,
            "credentials": "FORBIDDEN",
            "dns_mode": "DENY_ALL",
            "kind": "DENY_ALL",
        }
        return body | {"policy_sha256": _digest(body)}
    base_registry = _base_registry_binding(phase, environment)
    assert base_registry is not None
    parsed = urlsplit(base_registry["registry_url"])
    raw_origins = dependency_expectation.get("resolved_origins")
    if (
        type(raw_origins) is not list
        or not 0 < len(raw_origins) <= MAX_EGRESS_ORIGINS
    ):
        _fail("ONLINE_EGRESS_ORIGIN_ALLOWLIST_INVALID")
    origins: set[tuple[str, str, int]] = set()
    for row in raw_origins:
        if (
            type(row) is not list
            or len(row) != 3
            or row[0] != "https"
            or type(row[1]) is not str
            or not row[1]
            or row[1] != row[1].lower()
            or type(row[2]) is not int
            or row[2] != 443
        ):
            _fail("ONLINE_EGRESS_ORIGIN_ALLOWLIST_INVALID")
        origins.add((row[0], row[1], row[2]))
    origins.add(("https", str(parsed.hostname).lower(), 443))
    if len(origins) > MAX_EGRESS_ORIGINS:
        _fail("ONLINE_EGRESS_ORIGIN_BOUND_EXCEEDED")
    allowed = [
        {"host": host, "port": port, "scheme": scheme}
        for scheme, host, port in sorted(origins)
    ]
    body = {
        "allowed_origins": allowed,
        "authority_sha256": authority_sha256,
        "base_registry": base_registry,
        "credentials": "FORBIDDEN",
        "dns_mode": "NATIVE_BROKER_ALLOWLIST_ONLY",
        "kind": "EXACT_REACHABLE_LOCK_HTTPS_ORIGIN_ALLOWLIST",
    }
    return body | {"policy_sha256": _digest(body)}


def _validate_exact_phase(
    contract: CONTRACT.JSDependencyMaterializationContract,
    phase: CONTRACT.DependencyPhaseContract,
    *,
    offline: bool,
) -> dict[str, str]:
    expected_name = "offline" if offline else "online"
    private_root = Path(contract.online.private_root).parent
    expected_phase_root = private_root / (
        "offline-replay" if offline else "online"
    )
    expected_roots = {
        "private_root": str(expected_phase_root),
        "home_root": str(expected_phase_root / "home"),
        "modules_root": str(expected_phase_root / "modules"),
        "cache_root": str(expected_phase_root / "cache"),
        "temp_root": str(expected_phase_root / "temp"),
    }
    expected_preconditions = (
        (
            "SAME_SOURCE_SNAPSHOT_RETAINED_READ_ONLY",
            "OFFLINE_PRIVATE_ROOT_PROVEN_EMPTY",
            "ONLINE_TERMINAL_RECEIPT_VERIFIED",
            "ONLINE_CACHE_SNAPSHOT_RETAINED_READ_ONLY",
            "OFFLINE_CACHE_SEED_COPIED_BYTE_EXACTLY",
            "NO_NETWORK_ACTIVE_BEFORE_PROCESS_START",
        )
        if offline
        else (
            "SOURCE_SNAPSHOT_RETAINED_READ_ONLY",
            "ONLINE_PRIVATE_ROOT_PROVEN_EMPTY",
            "TOOLCHAIN_ARCHIVES_RETAINED_AND_DIGEST_VERIFIED",
            "TOOLCHAIN_EXTRACTION_RECEIPT_VERIFIED",
            "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST_ACTIVE_BEFORE_PROCESS_START",
        )
    )
    if (
        phase.phase != expected_name
        or any(getattr(phase, key) != value for key, value in expected_roots.items())
        or phase.required_preconditions != expected_preconditions
        or type(phase.phase_timeout_seconds) is not int
        or not 0 < phase.phase_timeout_seconds <= CONTRACT.MAX_PHASE_TIMEOUT_SECONDS
        or type(phase.max_dependency_entries) is not int
        or not 0 < phase.max_dependency_entries <= CONTRACT.MAX_DEPENDENCY_ENTRIES
        or type(phase.max_dependency_expanded_bytes) is not int
        or not 0
        < phase.max_dependency_expanded_bytes
        <= CONTRACT.MAX_DEPENDENCY_EXPANDED_BYTES
        or type(phase.max_cache_expanded_bytes) is not int
        or not 0 < phase.max_cache_expanded_bytes <= CONTRACT.MAX_CACHE_EXPANDED_BYTES
    ):
        _fail("PHASE_BINDING_INVALID")
    root = Path(phase.private_root)
    expected_base = (
        contract.toolchain.node_executable_path,
        contract.toolchain.yarn_cli_path,
        "install",
        *_EXACT_YARN_FLAGS,
        "--modules-folder",
        phase.modules_root,
        "--cache-folder",
        phase.cache_root,
        "--mutex",
        f"file:{Path(phase.temp_root) / 'yarn-install.mutex'}",
    )
    if offline:
        expected_argv = expected_base + ("--offline",)
    else:
        if len(phase.argv) != len(expected_base) + 2 or phase.argv[-2] != "--registry":
            _fail("YARN_OPERATION_CONTRACT_INVALID")
        expected_argv = expected_base + ("--registry", phase.argv[-1])
    if phase.argv != expected_argv or any(
        item.startswith("--ignore-scripts=") for item in phase.argv
    ):
        _fail("YARN_OPERATION_CONTRACT_INVALID")
    environment = _phase_environment(phase)
    expected_environment = {
        "HOME": phase.home_root,
        "USERPROFILE": phase.home_root,
        "XDG_CONFIG_HOME": str(Path(phase.home_root) / ".config"),
        "XDG_CACHE_HOME": phase.cache_root,
        "PATH": str(Path(contract.toolchain.node_executable_path).parent),
        "NODE_ENV": "development",
        "YARN_CACHE_FOLDER": phase.cache_root,
        "YARN_GLOBAL_FOLDER": str(Path(phase.cache_root) / "global"),
        "YARN_IGNORE_PATH": "1",
        "TMPDIR": phase.temp_root,
        "TMP": phase.temp_root,
        "TEMP": phase.temp_root,
        "PLAMEN_JS_NETWORK_MODE": phase.network_mode,
    }
    if not offline:
        expected_environment.update(
            {
                "PLAMEN_JS_EGRESS_TARGET_ID": phase.egress_target_id,
                "PLAMEN_JS_EGRESS_TARGET_AUTHORITY_SHA256": environment.get(
                    "PLAMEN_JS_EGRESS_TARGET_AUTHORITY_SHA256", ""
                ),
            }
        )
    if os.name == "nt":
        expected_environment.update(
            {
                "SYSTEMROOT": environment.get("SYSTEMROOT", ""),
                "WINDIR": environment.get("WINDIR", ""),
            }
        )
    if environment != expected_environment or set(environment) - _CLOSED_ENVIRONMENT_KEYS:
        _fail("PHASE_ENVIRONMENT_NOT_CLOSED")
    private = _safe_absolute(str(root.parent), "PRIVATE_ROOT_INVALID")
    for rendered in (
        phase.private_root,
        phase.home_root,
        phase.modules_root,
        phase.cache_root,
        phase.temp_root,
    ):
        candidate = _safe_absolute(rendered, "WRITABLE_ROOT_INVALID")
        if not _inside(private, candidate) or candidate == private:
            _fail("WRITABLE_ROOT_ESCAPE")
    _base_registry_binding(phase, environment)
    return environment


def _validate_contract_shape(contract: object, expected_sha256: object) -> CONTRACT.JSDependencyMaterializationContract:
    if type(contract) is not CONTRACT.JSDependencyMaterializationContract:
        _fail("CONTRACT_TYPE_INVALID")
    expected = _hex64(expected_sha256, "EXPECTED_CONTRACT_SHA256_INVALID")
    if (
        contract.schema != CONTRACT.SCHEMA
        or contract.execution_state != CONTRACT.EXECUTION_STATE
        or contract.source_access != CONTRACT.SOURCE_ACCESS
        or contract.workspace_access != CONTRACT.WORKSPACE_ACCESS
    ):
        _fail("CONTRACT_SCHEMA_INVALID")
    observed_contract = _digest(contract.binding_dict())
    if contract.contract_sha256 != observed_contract or observed_contract != expected:
        _fail("CONTRACT_DIGEST_MISMATCH")
    toolchain = contract.toolchain.binding_dict()
    stored_toolchain = toolchain.pop("binding_sha256", None)
    if stored_toolchain != _digest(toolchain):
        _fail("TOOLCHAIN_BINDING_DIGEST_MISMATCH")
    lock = contract.lock_selection.binding_dict()
    if contract.lock_selection.selection_sha256 != _digest(lock):
        _fail("LOCK_SELECTION_DIGEST_MISMATCH")
    if contract.lock_selection.family != "yarn" or contract.lock_selection.filename != "yarn.lock":
        _fail("LOCK_FAMILY_NOT_EXECUTABLE")
    source = _safe_absolute(contract.source_root, "SOURCE_ROOT_INVALID")
    if type(contract.execution) is not CONTRACT.GuestExecutionBinding:
        _fail("GUEST_EXECUTION_BINDING_INVALID")
    execution = contract.execution.binding_dict()
    stored_execution = execution.pop("binding_sha256", None)
    if stored_execution != _digest(execution):
        _fail("GUEST_EXECUTION_BINDING_DIGEST_MISMATCH")
    transaction = _safe_absolute(
        contract.execution.controller_transaction_root,
        "CONTROLLER_TRANSACTION_ROOT_INVALID",
    )
    scratch = _safe_absolute(
        contract.execution.controller_scratch_root,
        "CONTROLLER_SCRATCH_ROOT_INVALID",
    )
    state = _safe_absolute(
        contract.execution.controller_state_root,
        "CONTROLLER_STATE_ROOT_INVALID",
    )
    if (
        scratch.parent != transaction
        or state.parent != transaction
        or scratch == state
        or _inside(source, transaction)
        or _inside(transaction, source)
        or contract.execution.project_access != "IMMUTABLE_READ_ONLY"
        or contract.execution.scratch_access != "PRIVATE_READ_WRITE"
        or contract.execution.state_access != "PRIVATE_READ_WRITE"
        or contract.execution.target_os not in {"darwin", "linux", "windows"}
        or contract.execution.target_arch not in {"arm64", "x86_64"}
    ):
        _fail("GUEST_EXECUTION_BINDING_INVALID")
    expected_guest = (
        (r"C:\workspace\project", r"C:\workspace\scratch", r"C:\workspace\state")
        if contract.execution.target_os == "windows"
        else ("/workspace/project", "/workspace/scratch", "/workspace/state")
    )
    if (
        contract.execution.guest_project_root,
        contract.execution.guest_scratch_root,
        contract.execution.guest_state_root,
    ) != expected_guest:
        _fail("GUEST_EXECUTION_PATH_INVALID")
    private = _safe_absolute(contract.online.private_root, "PRIVATE_ROOT_INVALID").parent
    if (
        private != scratch
        or str(private)
        != str(_safe_absolute(contract.offline_replay.private_root, "PRIVATE_ROOT_INVALID").parent)
        or not _inside(scratch, Path(contract.toolchain.node_executable_path))
        or not _inside(scratch, Path(contract.toolchain.yarn_cli_path))
    ):
        _fail("PRIVATE_ROOT_BINDING_MISMATCH")
    if _inside(source, private) or _inside(private, source):
        _fail("SOURCE_PRIVATE_ROOTS_OVERLAP")
    for phase, expected_mode in (
        (contract.online, "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST"),
        (contract.offline_replay, "NO_NETWORK"),
    ):
        if phase.cwd != contract.source_root or phase.network_mode != expected_mode:
            _fail("PHASE_BINDING_INVALID")
        if phase.argv[:2] != (
            contract.toolchain.node_executable_path,
            contract.toolchain.yarn_cli_path,
        ):
            _fail("PHASE_TOOLCHAIN_BINDING_INVALID")
    _validate_exact_phase(contract, contract.online, offline=False)
    _validate_exact_phase(contract, contract.offline_replay, offline=True)
    if contract.replay.binding_dict() != {
        "cache_handoff": "COPY_VERIFIED_TREE_INTO_EMPTY_OFFLINE_CACHE",
        "offline_cache_seed_root": contract.offline_replay.cache_root,
        "online_cache_root": contract.online.cache_root,
        "required_receipt_equalities": [
            ["source_snapshot_sha256", "source_snapshot_sha256"],
            ["lock_selection_sha256", "lock_selection_sha256"],
            ["toolchain_binding_sha256", "toolchain_binding_sha256"],
            ["cache_tree_sha256", "seed_cache_tree_sha256"],
            ["modules_tree_sha256", "modules_tree_sha256"],
            ["modules_entry_count", "modules_entry_count"],
            ["modules_expanded_bytes", "modules_expanded_bytes"],
        ],
        "required_terminal_conditions": [
            "ONLINE_EXIT_CODE_ZERO",
            "OFFLINE_EXIT_CODE_ZERO",
            "ONLINE_LIMITS_NOT_EXCEEDED",
            "OFFLINE_LIMITS_NOT_EXCEEDED",
            "OFFLINE_NETWORK_DENIAL_REMAINED_ACTIVE",
        ],
        "required_offline_receipt_fields": [
            "source_snapshot_sha256",
            "lock_selection_sha256",
            "toolchain_binding_sha256",
            "seed_cache_tree_sha256",
            "modules_tree_sha256",
            "modules_entry_count",
            "modules_expanded_bytes",
            "exit_code",
            "network_denial_sha256",
        ],
        "required_online_receipt_fields": [
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
        ],
        "retained_cache_snapshot_root": str(private / "online-cache-snapshot"),
        "source_snapshot_sha256": contract.source_snapshot_sha256,
        "tree_digest_algorithm": TREE_DIGEST_ALGORITHM,
    }:
        _fail("REPLAY_CONTRACT_INVALID")
    return contract


def _source_preflight(contract: CONTRACT.JSDependencyMaterializationContract) -> dict[str, Any]:
    root = Path(contract.source_root)
    _reject_alias_ancestry(root, allow_missing_leaf=False)
    try:
        root_before = root.lstat()
        names = set(os.listdir(root))
    except OSError as exc:
        raise JSDependencyRuntimeError("SOURCE_ROOT_UNREADABLE", str(root)) from exc
    if (
        not stat.S_ISDIR(root_before.st_mode)
        or stat.S_ISLNK(root_before.st_mode)
        or _is_reparse(root_before)
    ):
        _fail("SOURCE_ROOT_UNSAFE")
    rc_present = sorted(names & _RC_FILES)
    if rc_present:
        _fail("PROJECT_PACKAGE_MANAGER_CONFIG_REJECTED", ",".join(rc_present))
    candidate_names = {
        item.filename for item in contract.lock_selection.candidates
    }
    observed_lock_names = names & (LOCK.SUPPORTED_LOCKFILES | LOCK.KNOWN_UNSUPPORTED_LOCKFILES)
    if observed_lock_names != candidate_names:
        _fail("LOCKFILE_SET_CHANGED")
    package, package_stat = _read_regular_file(
        root / "package.json",
        maximum=CONTRACT.MAX_PACKAGE_JSON_BYTES,
        expected_sha256=contract.package_json_sha256,
    )
    locks: dict[str, bytes] = {}
    stats: dict[str, tuple[int, ...]] = {"package.json": package_stat}
    total = 0
    for name in sorted(candidate_names):
        raw, identity = _read_regular_file(
            root / name, maximum=CONTRACT.MAX_LOCKFILE_BYTES
        )
        locks[name] = raw
        stats[name] = identity
        total += len(raw)
    if total > CONTRACT.MAX_LOCKFILES_BYTES:
        _fail("LOCKFILES_TOO_LARGE")
    try:
        selection = LOCK.select_js_lock_authority(package, locks)
    except LOCK.JSLockAuthorityError as exc:
        raise JSDependencyRuntimeError(
            "LOCK_SELECTION_REPLAY_FAILED", exc.code
        ) from exc
    if selection != contract.lock_selection:
        _fail("LOCK_SELECTION_REPLAY_MISMATCH")
    try:
        root_after = root.lstat()
    except OSError as exc:
        raise JSDependencyRuntimeError("SOURCE_ROOT_UNREADABLE", str(root)) from exc
    if _stable_stat(root_before) != _stable_stat(root_after):
        _fail("SOURCE_ROOT_CHANGED_DURING_PREFLIGHT")
    identity = {
        "lock_selection_sha256": selection.selection_sha256,
        "package_json_sha256": hashlib.sha256(package).hexdigest(),
        "root_stat": list(_stable_stat(root_after)),
        "source_snapshot_sha256": contract.source_snapshot_sha256,
        "source_files": {
            name: {"sha256": hashlib.sha256((package if name == "package.json" else locks[name])).hexdigest(), "stat": list(value)}
            for name, value in sorted(stats.items())
        },
    }
    identity["guard_sha256"] = _digest(identity)
    return identity


def _retain_source(contract: CONTRACT.JSDependencyMaterializationContract) -> _RetainedSource:
    """Retain the source directory and every selected-input descriptor."""

    guard = _source_preflight(contract)
    root = Path(contract.source_root)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = -1
    descriptors: dict[str, int] = {}
    stats: dict[str, tuple[int, ...]] = {}
    try:
        root_descriptor = os.open(root, flags)
        os.set_inheritable(root_descriptor, False)
        root_info = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or _stable_stat(root_info) != tuple(guard["root_stat"])
        ):
            _fail("SOURCE_DESCRIPTOR_REPLAY_FAILED")
        for name, row in sorted(guard["source_files"].items()):
            file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if os.name != "nt":
                file_flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(root / name, file_flags)
            os.set_inheritable(descriptor, False)
            observed = _stable_stat(os.fstat(descriptor))
            if observed != tuple(row["stat"]):
                _fail("SOURCE_DESCRIPTOR_REPLAY_FAILED")
            descriptors[name] = descriptor
            stats[name] = observed
        def retained_bytes(name: str) -> bytes:
            descriptor = descriptors[name]
            size = int(stats[name][6])
            os.lseek(descriptor, 0, os.SEEK_SET)
            result = b""
            while len(result) < size:
                block = os.read(
                    descriptor,
                    min(_READ_CHUNK, size - len(result)),
                )
                if not block:
                    _fail("SOURCE_DESCRIPTOR_REPLAY_FAILED")
                result += block
            if os.read(descriptor, 1):
                _fail("SOURCE_DESCRIPTOR_REPLAY_FAILED")
            return result

        package_json = retained_bytes("package.json")
        selected_lockfile = retained_bytes(contract.lock_selection.filename)
        if hashlib.sha256(package_json).hexdigest() != contract.package_json_sha256:
            _fail("SOURCE_DESCRIPTOR_REPLAY_FAILED")
        if (
            hashlib.sha256(selected_lockfile).hexdigest()
            != contract.lock_selection.lockfile_sha256
        ):
            _fail("SOURCE_DESCRIPTOR_REPLAY_FAILED")
        retained = _RetainedSource(
            root,
            guard,
            root_descriptor,
            descriptors,
            stats,
            package_json,
            selected_lockfile,
        )
        retained.verify(contract)
        return retained
    except BaseException:
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        if root_descriptor >= 0:
            try:
                os.close(root_descriptor)
            except OSError:
                pass
        raise


def _strict_json_object(raw: bytes, code: str) -> dict[str, Any]:
    class DuplicateKey(ValueError):
        pass

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in rows:
            if key in value:
                raise DuplicateKey(key)
            value[key] = item
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey) as exc:
        raise JSDependencyRuntimeError(code) from exc
    if type(value) is not dict:
        _fail(code)
    return value


def _dependency_expectation(
    package_json: bytes,
    selected_lockfile: bytes,
    selection: LOCK.JSLockSelection,
) -> dict[str, Any]:
    package = _strict_json_object(package_json, "PACKAGE_JSON_REPLAY_INVALID")
    patterns: dict[str, str] = {}
    required_names: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = package.get(section, {})
        if type(dependencies) is not dict:
            _fail("PACKAGE_JSON_REPLAY_INVALID")
        for name, specifier in dependencies.items():
            if type(name) is not str or type(specifier) is not str:
                _fail("PACKAGE_JSON_REPLAY_INVALID")
            pattern = f"{name}@{specifier}"
            prior = patterns.get(name)
            if prior is not None and prior != pattern:
                _fail("PACKAGE_JSON_REPLAY_INVALID")
            patterns[name] = pattern
            if section != "optionalDependencies":
                required_names.add(name)
    try:
        integrity_authority = LOCK.derive_yarn_integrity_authority(
            package_json, selected_lockfile, selection
        )
    except LOCK.JSLockAuthorityError as exc:
        raise JSDependencyRuntimeError(
            "YARN_INTEGRITY_AUTHORITY_REPLAY_FAILED", exc.code
        ) from exc
    body = {
        "direct_patterns": sorted(patterns.values()),
        "required_direct_names": sorted(required_names),
        "direct_packages": [list(row) for row in integrity_authority.direct_packages],
        "direct_packages_sha256": integrity_authority.direct_packages_sha256,
        "lockfile_entries": [
            list(row) for row in integrity_authority.lockfile_entries
        ],
        "lockfile_entries_sha256": integrity_authority.lockfile_entries_sha256,
        "resolved_origins": [
            list(row) for row in integrity_authority.resolved_origins
        ],
        "resolved_origins_sha256": integrity_authority.resolved_origins_sha256,
        "yarn_integrity_authority_sha256": integrity_authority.authority_sha256,
        "reachable_selectors_sha256": selection.reachable_selectors_sha256,
        "reachable_stanza_count": selection.reachable_stanza_count,
    }
    return body | {"expectation_sha256": _digest(body)}


def _validate_dependency_completeness(
    modules_root: Path,
    *,
    expectation: Mapping[str, Any],
    tree: TreeIdentity,
) -> dict[str, Any]:
    if expectation["reachable_stanza_count"] and tree.entry_count == 0:
        _fail("DEPENDENCY_TREE_EMPTY")
    integrity_raw, _stat = _read_regular_file(
        modules_root / ".yarn-integrity", maximum=MAX_NATIVE_OUTPUT_BYTES
    )
    integrity = _strict_json_object(
        integrity_raw, "YARN_INTEGRITY_INVALID"
    )
    top = integrity.get("topLevelPatterns")
    entries = integrity.get("lockfileEntries")
    if (
        type(top) is not list
        or not all(type(item) is str for item in top)
        or sorted(top) != expectation["direct_patterns"]
        or type(entries) is not dict
        or not all(type(key) is str and type(value) is str for key, value in entries.items())
        or sorted(entries.items())
        != [tuple(row) for row in expectation["lockfile_entries"]]
        or _digest([list(row) for row in sorted(entries.items())])
        != expectation["lockfile_entries_sha256"]
    ):
        _fail("YARN_INTEGRITY_LOCK_CLOSURE_MISMATCH")
    package_rows: list[dict[str, str]] = []
    direct_versions = {
        str(row[0]): str(row[2]) for row in expectation["direct_packages"]
    }
    for name in expectation["required_direct_names"]:
        package_path = modules_root.joinpath(*name.split("/"), "package.json")
        _reject_alias_ancestry(package_path, allow_missing_leaf=False)
        raw, _identity = _read_regular_file(
            package_path, maximum=CONTRACT.MAX_PACKAGE_JSON_BYTES
        )
        manifest = _strict_json_object(raw, "INSTALLED_PACKAGE_JSON_INVALID")
        if (
            manifest.get("name") != name
            or manifest.get("version") != direct_versions.get(name)
        ):
            _fail("INSTALLED_DIRECT_PACKAGE_IDENTITY_MISMATCH")
        package_rows.append(
            {
                "name": name,
                "version": direct_versions[name],
                "package_json_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    body = {
        "expectation_sha256": expectation["expectation_sha256"],
        "integrity_sha256": hashlib.sha256(integrity_raw).hexdigest(),
        "required_direct_packages": package_rows,
    }
    return body | {"completeness_sha256": _digest(body)}


def _archive_preflight(contract: CONTRACT.JSDependencyMaterializationContract) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for artifact_id, path, digest, maximum in (
        (
            contract.toolchain.node_artifact_id,
            contract.toolchain.node_archive_path,
            contract.toolchain.node_archive_sha256,
            MAX_TOOLCHAIN_EXPANDED_BYTES,
        ),
        (
            contract.toolchain.yarn_artifact_id,
            contract.toolchain.yarn_archive_path,
            contract.toolchain.yarn_archive_sha256,
            max(contract.toolchain.yarn_archive_size, 1),
        ),
    ):
        candidate = _safe_absolute(path, "TOOLCHAIN_ARCHIVE_PATH_INVALID")
        raw, identity = _read_regular_file(
            candidate, maximum=maximum, expected_sha256=digest
        )
        if artifact_id == contract.toolchain.yarn_artifact_id and len(raw) != contract.toolchain.yarn_archive_size:
            _fail("YARN_ARCHIVE_SIZE_MISMATCH")
        rows[artifact_id] = {
            "path": str(candidate),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "stat": list(identity),
        }
    rows["binding_sha256"] = _digest(rows)
    return rows


def _archive_root_binding(
    contract: CONTRACT.JSDependencyMaterializationContract,
    source_binding: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    archive_rows = [
        {
            "artifact_id": artifact_id,
            "filename": f"{source_binding[artifact_id]['sha256']}.archive",
            "sha256": source_binding[artifact_id]["sha256"],
            "size": source_binding[artifact_id]["size"],
        }
        for artifact_id in sorted(
            (
                contract.toolchain.node_artifact_id,
                contract.toolchain.yarn_artifact_id,
            )
        )
    ]
    if len({row["filename"] for row in archive_rows}) != len(archive_rows):
        _fail("TOOLCHAIN_ARCHIVE_CONTENT_ADDRESS_ALIAS")
    manifest = {
        "archive_census_sha256": _digest(archive_rows),
        "archive_count": len(archive_rows),
        "archives": archive_rows,
        "schema": "plamen.js-archive-root-manifest.v1",
    }
    manifest_bytes = _canonical(manifest)
    binding_body = {
        "archive_census_sha256": manifest["archive_census_sha256"],
        "archive_count": manifest["archive_count"],
        "archive_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "archive_root": str(
            Path(contract.execution.controller_transaction_root) / "archive-root"
        ),
        "archives": archive_rows,
    }
    return binding_body | {"binding_sha256": _digest(binding_body)}, manifest_bytes


def _retain_archives(
    contract: CONTRACT.JSDependencyMaterializationContract,
) -> _RetainedArchives:
    source_binding = _archive_preflight(contract)
    descriptors: dict[str, int] = {}
    stats: dict[str, tuple[int, ...]] = {}
    try:
        for artifact_id in (
            contract.toolchain.node_artifact_id,
            contract.toolchain.yarn_artifact_id,
        ):
            path = Path(source_binding[artifact_id]["path"])
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if os.name != "nt":
                flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            os.set_inheritable(descriptor, False)
            observed = _stable_stat(os.fstat(descriptor))
            if observed != tuple(source_binding[artifact_id]["stat"]):
                _fail("TOOLCHAIN_ARCHIVE_DESCRIPTOR_REPLAY_FAILED")
            descriptors[artifact_id] = descriptor
            stats[artifact_id] = observed
        binding, manifest_bytes = _archive_root_binding(contract, source_binding)
        retained = _RetainedArchives(
            binding,
            source_binding,
            descriptors,
            stats,
            manifest_bytes,
        )
        retained.verify(contract)
        return retained
    except BaseException:
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _descriptor_bytes(descriptor: int, size: int, code: str) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        blocks: list[bytes] = []
        observed = 0
        while observed < size:
            block = os.read(descriptor, min(_READ_CHUNK, size - observed))
            if not block:
                _fail(code)
            blocks.append(block)
            observed += len(block)
        if os.read(descriptor, 1):
            _fail(code)
        return b"".join(blocks)
    except OSError as exc:
        raise JSDependencyRuntimeError(code) from exc


def _verify_archive_root(retained: _RetainedArchives) -> None:
    root = retained.root
    expected_root_stat = retained.root_stat
    if root is None or retained.root_descriptor < 0 or expected_root_stat is None:
        _fail("TOOLCHAIN_ARCHIVE_ROOT_NOT_RETAINED")
    try:
        opened = os.fstat(retained.root_descriptor)
        linked = root.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or _is_reparse(linked)
            or _stable_stat(opened) != expected_root_stat
            or _stable_stat(linked) != expected_root_stat
        ):
            _fail("TOOLCHAIN_ARCHIVE_ROOT_CHANGED")
        expected_names = {
            "archive-manifest.json",
            *(row["filename"] for row in retained.binding["archives"]),
        }
        observed_names = {entry.name for entry in os.scandir(root)}
        if observed_names != expected_names:
            _fail("TOOLCHAIN_ARCHIVE_ROOT_CENSUS_MISMATCH")
        manifest_raw, _manifest_stat = _read_regular_file(
            root / "archive-manifest.json", maximum=64 * 1024
        )
        if (
            manifest_raw != retained.manifest_bytes
            or hashlib.sha256(manifest_raw).hexdigest()
            != retained.binding["archive_manifest_sha256"]
        ):
            _fail("TOOLCHAIN_ARCHIVE_MANIFEST_MISMATCH")
        for row in retained.binding["archives"]:
            raw, _identity = _read_regular_file(
                root / row["filename"],
                maximum=max(int(row["size"]), 1),
                expected_sha256=row["sha256"],
            )
            if len(raw) != row["size"]:
                _fail("TOOLCHAIN_ARCHIVE_ROOT_CENSUS_MISMATCH")
    except OSError as exc:
        raise JSDependencyRuntimeError("TOOLCHAIN_ARCHIVE_ROOT_CHANGED") from exc


def _stage_archive_root(
    retained: _RetainedArchives,
    private_root: Path,
) -> None:
    root = Path(retained.binding["archive_root"])
    if root.parent != private_root:
        _fail("TOOLCHAIN_ARCHIVE_ROOT_SCOPE_INVALID")
    if not root.exists():
        try:
            root.mkdir(mode=0o700)
        except OSError as exc:
            raise JSDependencyRuntimeError(
                "TOOLCHAIN_ARCHIVE_ROOT_CREATE_FAILED", str(root)
            ) from exc
        for row in retained.binding["archives"]:
            raw = _descriptor_bytes(
                retained.descriptors[row["artifact_id"]],
                int(row["size"]),
                "TOOLCHAIN_ARCHIVE_DESCRIPTOR_REPLAY_FAILED",
            )
            if hashlib.sha256(raw).hexdigest() != row["sha256"]:
                _fail("TOOLCHAIN_ARCHIVE_DESCRIPTOR_REPLAY_FAILED")
            _atomic_write_new(root / row["filename"], raw, mode=0o400)
        _atomic_write_new(
            root / "archive-manifest.json", retained.manifest_bytes, mode=0o400
        )
        _fsync_directory(root)
    _reject_alias_ancestry(root, allow_missing_leaf=False)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        retained.root_descriptor = os.open(root, flags)
        os.set_inheritable(retained.root_descriptor, False)
        retained.root = root
        retained.root_stat = _stable_stat(os.fstat(retained.root_descriptor))
    except OSError as exc:
        raise JSDependencyRuntimeError(
            "TOOLCHAIN_ARCHIVE_ROOT_RETAIN_FAILED", str(root)
        ) from exc
    _verify_archive_root(retained)


def _scan_tree(root: Path, *, max_entries: int, max_bytes: int) -> TreeIdentity:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise JSDependencyRuntimeError("OUTPUT_TREE_MISSING", str(root)) from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or _is_reparse(root_info)
    ):
        _fail("OUTPUT_TREE_ROOT_UNSAFE")
    root_device = int(root_info.st_dev)
    digest = hashlib.sha256()
    digest.update((TREE_DIGEST_ALGORITHM + "\n").encode("ascii"))
    entries = 0
    expanded = 0
    seen_files: set[tuple[int, int]] = set()

    def visit(directory: Path, prefix: str) -> None:
        nonlocal entries, expanded
        try:
            children = sorted(
                os.scandir(directory), key=lambda item: os.fsencode(item.name)
            )
        except OSError as exc:
            raise JSDependencyRuntimeError("OUTPUT_TREE_UNREADABLE", str(directory)) from exc
        for entry in children:
            name = entry.name
            if name in {".", ".."} or "/" in name or "\x00" in name:
                _fail("OUTPUT_TREE_NAME_INVALID")
            relative = name if not prefix else prefix + "/" + name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise JSDependencyRuntimeError("OUTPUT_TREE_UNREADABLE", relative) from exc
            if int(info.st_dev) != root_device:
                _fail("OUTPUT_TREE_MOUNT_ESCAPE")
            if _is_reparse(info):
                _fail("OUTPUT_TREE_SPECIAL_FILE_REJECTED")
            entries += 1
            if entries > max_entries:
                _fail("OUTPUT_TREE_ENTRY_BOUND_EXCEEDED")
            if stat.S_ISDIR(info.st_mode):
                row = ["d", relative, int(info.st_mode) & 0o777]
                digest.update(_canonical(row) + b"\n")
                visit(Path(entry.path), relative)
            elif stat.S_ISREG(info.st_mode):
                identity = (int(info.st_dev), int(info.st_ino))
                if int(info.st_nlink) != 1 or identity in seen_files:
                    _fail("OUTPUT_TREE_HARDLINK_REJECTED")
                seen_files.add(identity)
                raw, stable = _read_regular_file(
                    Path(entry.path), maximum=max_bytes
                )
                expanded += len(raw)
                if expanded > max_bytes:
                    _fail("OUTPUT_TREE_BYTE_BOUND_EXCEEDED")
                row = [
                    "f",
                    relative,
                    int(stable[2]) & 0o777,
                    len(raw),
                    hashlib.sha256(raw).hexdigest(),
                ]
                digest.update(_canonical(row) + b"\n")
            else:
                _fail("OUTPUT_TREE_SPECIAL_FILE_REJECTED")
    visit(root, "")
    try:
        after = root.lstat()
    except OSError as exc:
        raise JSDependencyRuntimeError("OUTPUT_TREE_UNREADABLE", str(root)) from exc
    if _stable_stat(root_info) != _stable_stat(after):
        _fail("OUTPUT_TREE_CHANGED_DURING_SCAN")
    return TreeIdentity(digest.hexdigest(), entries, expanded)


def _owned_private_root(root: Path, contract_sha256: str, custody_sha256: str) -> dict[str, Any]:
    marker_path = root / ".plamen-js-materializer-owner.json"
    expected_base = {
        "contract_sha256": contract_sha256,
        "custody_receipt_sha256": custody_sha256,
        "schema": MARKER_SCHEMA,
    }
    if not root.exists():
        _reject_alias_ancestry(root.parent, allow_missing_leaf=False)
        try:
            root.mkdir(mode=0o700)
        except OSError as exc:
            raise JSDependencyRuntimeError("PRIVATE_ROOT_CREATE_FAILED", str(root)) from exc
        payload = expected_base | {"marker_sha256": _digest(expected_base)}
        _atomic_write_new(marker_path, _canonical(payload) + b"\n", mode=0o400)
        return payload
    _reject_alias_ancestry(root, allow_missing_leaf=False)
    try:
        info = root.lstat()
    except OSError as exc:
        raise JSDependencyRuntimeError("PRIVATE_ROOT_UNREADABLE", str(root)) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
    ):
        _fail("PRIVATE_ROOT_UNSAFE")
    if os.name != "nt" and (
        int(info.st_uid) != int(os.geteuid()) or int(info.st_mode) & 0o077
    ):
        _fail("PRIVATE_ROOT_OWNERSHIP_INVALID")
    raw, _identity = _read_regular_file(marker_path, maximum=64 * 1024)
    try:
        marker = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JSDependencyRuntimeError("PRIVATE_ROOT_MARKER_INVALID") from exc
    if (
        type(marker) is not dict
        or set(marker) != {*expected_base, "marker_sha256"}
        or {key: marker.get(key) for key in expected_base} != expected_base
        or marker.get("marker_sha256") != _digest(expected_base)
        or raw != _canonical(marker) + b"\n"
    ):
        _fail("PRIVATE_ROOT_MARKER_INVALID")
    return marker


def _owned_mount_roots(
    contract: CONTRACT.JSDependencyMaterializationContract,
) -> tuple[Path, Path]:
    transaction = Path(contract.execution.controller_transaction_root)
    scratch = Path(contract.execution.controller_scratch_root)
    state = Path(contract.execution.controller_state_root)
    for target in (scratch, state):
        if not target.exists():
            try:
                target.mkdir(mode=0o700)
            except OSError as exc:
                raise JSDependencyRuntimeError(
                    "CONTROLLER_MOUNT_ROOT_CREATE_FAILED", str(target)
                ) from exc
        _reject_alias_ancestry(target, allow_missing_leaf=False)
        try:
            info = target.lstat()
        except OSError as exc:
            raise JSDependencyRuntimeError(
                "CONTROLLER_MOUNT_ROOT_UNREADABLE", str(target)
            ) from exc
        if (
            target.parent != transaction
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or _is_reparse(info)
            or (
                os.name != "nt"
                and (
                    int(info.st_uid) != int(os.geteuid())
                    or int(info.st_mode) & 0o077
                )
            )
        ):
            _fail("CONTROLLER_MOUNT_ROOT_UNSAFE")
    scratch_info = scratch.lstat()
    state_info = state.lstat()
    if (int(scratch_info.st_dev), int(scratch_info.st_ino)) == (
        int(state_info.st_dev),
        int(state_info.st_ino),
    ):
        _fail("CONTROLLER_MOUNT_ROOTS_ALIAS")
    return scratch, state


def _atomic_write_new(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, mode)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                _fail("TRANSACTIONAL_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise JSDependencyRuntimeError("TRANSACTIONAL_WRITE_FAILED", str(path)) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _fsync_directory(path.parent)


def _atomic_replace(path: Path, raw: bytes) -> None:
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, rendered = tempfile.mkstemp(prefix=".plamen-js-txn-", dir=path.parent)
        temporary = Path(rendered)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                _fail("TRANSACTIONAL_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    except OSError as exc:
        raise JSDependencyRuntimeError("TRANSACTIONAL_WRITE_FAILED", str(path)) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        # The native state descriptor owns Windows FlushFileBuffers custody;
        # Python cannot securely open a directory with POSIX O_DIRECTORY.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    except OSError as exc:
        raise JSDependencyRuntimeError("DIRECTORY_SYNC_FAILED", str(path)) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_journal(path: Path, *, contract_sha256: str) -> dict[str, Any]:
    if not path.exists():
        return {
            "contract_sha256": contract_sha256,
            "native_receipts": {},
            "schema": JOURNAL_SCHEMA,
            "state": "INITIALIZED",
        }
    raw, _identity = _read_regular_file(path, maximum=MAX_NATIVE_OUTPUT_BYTES)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JSDependencyRuntimeError("JOURNAL_INVALID") from exc
    if (
        type(value) is not dict
        or set(value) != {"contract_sha256", "native_receipts", "schema", "state"}
        or value.get("schema") != JOURNAL_SCHEMA
        or value.get("contract_sha256") != contract_sha256
        or value.get("state") not in _STATES
        or type(value.get("native_receipts")) is not dict
        or raw != _canonical(value) + b"\n"
    ):
        _fail("JOURNAL_INVALID")
    return value


def _store_journal(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_replace(path, _canonical(value) + b"\n")


def _remove_owned_subtree(private_root: Path, target: Path) -> None:
    if target == private_root or not _inside(private_root, target):
        _fail("CLEANUP_SCOPE_INVALID")
    try:
        info = target.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise JSDependencyRuntimeError("CLEANUP_TARGET_UNREADABLE", str(target)) from exc
    if (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not _is_reparse(info)
    ):
        try:
            children = list(os.scandir(target))
        except OSError as exc:
            raise JSDependencyRuntimeError("CLEANUP_TARGET_UNREADABLE", str(target)) from exc
        for child in children:
            _remove_owned_subtree(private_root, Path(child.path))
        try:
            target.rmdir()
        except OSError as exc:
            raise JSDependencyRuntimeError("CLEANUP_FAILED", str(target)) from exc
    else:
        try:
            target.unlink()
        except OSError as exc:
            raise JSDependencyRuntimeError("CLEANUP_FAILED", str(target)) from exc


def _tree_row(path: str, identity: TreeIdentity) -> dict[str, Any]:
    return {"path": path, **identity.binding_dict()}


def _guest_path(
    contract: CONTRACT.JSDependencyMaterializationContract, value: str
) -> str:
    """Translate one bound controller path into its explicit guest mount."""

    execution = contract.execution
    windows = execution.target_os == "windows"
    pure_type = PureWindowsPath if windows else PurePosixPath
    controller = pure_type(value)
    roots = (
        (pure_type(contract.source_root), pure_type(execution.guest_project_root)),
        (
            pure_type(execution.controller_scratch_root),
            pure_type(execution.guest_scratch_root),
        ),
        (
            pure_type(execution.controller_state_root),
            pure_type(execution.guest_state_root),
        ),
    )
    for controller_root, guest_root in roots:
        try:
            relative = controller.relative_to(controller_root)
        except ValueError:
            continue
        return str(guest_root / relative)
    _fail("CONTROLLER_PATH_HAS_NO_GUEST_BINDING", value)


def _guest_token(
    contract: CONTRACT.JSDependencyMaterializationContract, value: str
) -> str:
    if value.startswith("file:"):
        return "file:" + _guest_path(contract, value[5:])
    execution = contract.execution
    separators = ("\\",) if execution.target_os == "windows" else ("/",)
    roots = (
        contract.source_root,
        execution.controller_scratch_root,
        execution.controller_state_root,
    )
    if value in roots or any(
        value.startswith(root + separator)
        for root in roots
        for separator in separators
    ):
        return _guest_path(contract, value)
    return value


def _guest_environment(
    contract: CONTRACT.JSDependencyMaterializationContract,
    environment: list[list[str]],
) -> list[list[str]]:
    return [
        [key, _guest_token(contract, value)] for key, value in environment
    ]


def _request(
    *,
    operation: str,
    contract: CONTRACT.JSDependencyMaterializationContract,
    authorities: NativeMaterializerAuthorities,
    native: _NativeRuntime,
    source_guard: Mapping[str, Any],
    archives: Mapping[str, Any],
    dependency_expectation: Mapping[str, Any],
    expected_inputs: Mapping[str, tuple[str, TreeIdentity]],
    outputs: Mapping[str, tuple[str, int, int]],
) -> dict[str, Any]:
    if operation not in _OPERATIONS:
        _fail("OPERATION_INVALID")
    phase = contract.online if operation == "ONLINE_INSTALL" else contract.offline_replay
    if operation == "PREPARE_TOOLCHAIN":
        argv: list[str] = []
        environment: list[list[str]] = []
        cwd = str(Path(contract.online.private_root).parent)
    elif operation == "CACHE_HANDOFF":
        argv = []
        environment = []
        cwd = str(Path(contract.online.private_root).parent)
    else:
        argv = list(phase.argv)
        environment = [[key, value] for key, value in phase.environment]
        cwd = phase.cwd
    online = operation == "ONLINE_INSTALL"
    network_mode = (
        "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST" if online else "NO_NETWORK"
    )
    network_authority = (
        authorities.online_network_admission_sha256
        if online
        else authorities.offline_network_denial_sha256
    )
    environment_map = _phase_environment(phase)
    network_policy = _network_policy(
        phase,
        environment_map,
        dependency_expectation,
        authority_sha256=network_authority,
    )
    guest_outputs = {
        name: _guest_path(contract, bound[0])
        for name, bound in sorted(outputs.items())
    }
    guest_expected_inputs = {
        name: _tree_row(_guest_path(contract, path), identity)
        for name, (path, identity) in sorted(expected_inputs.items())
    }
    guest_argv = [_guest_token(contract, value) for value in argv]
    guest_environment = _guest_environment(contract, environment)
    mounts = [
        {
            "access": contract.execution.project_access,
            "controller_path": contract.source_root,
            "guest_path": contract.execution.guest_project_root,
            "role": "project",
        },
        {
            "access": contract.execution.scratch_access,
            "controller_path": contract.execution.controller_scratch_root,
            "guest_path": contract.execution.guest_scratch_root,
            "role": "scratch",
        },
        {
            "access": contract.execution.state_access,
            "controller_path": contract.execution.controller_state_root,
            "guest_path": contract.execution.guest_state_root,
            "role": "state",
        },
    ]
    body: dict[str, Any] = {
        "archives": archives,
        "argv": argv,
        "bounds": {
            name: {"max_bytes": bound[2], "max_entries": bound[1]}
            for name, bound in sorted(outputs.items())
        },
        "contract_sha256": contract.contract_sha256,
        "cwd": cwd,
        "dependency_expectation_sha256": dependency_expectation[
            "expectation_sha256"
        ],
        "environment": environment,
        "expected_inputs": {
            name: _tree_row(path, identity)
            for name, (path, identity) in sorted(expected_inputs.items())
        },
        "generation_id": contract.generation_id,
        "guest_execution_binding_sha256": contract.execution.binding_sha256,
        "guest_argv": guest_argv,
        "guest_cwd": _guest_path(contract, cwd),
        "guest_environment": guest_environment,
        "guest_expected_inputs": guest_expected_inputs,
        "guest_outputs": guest_outputs,
        "guest_platform": {
            "arch": contract.execution.target_arch,
            "os": contract.execution.target_os,
        },
        "launch_object_kind": "PRIVATE_IMMUTABLE_PROJECTED_CLOSURE",
        "mounts": mounts,
        "native_custody_receipt_sha256": authorities.custody_receipt_sha256,
        "native_deployment_receipt_sha256": authorities.native_deployment_receipt_sha256,
        "native_module_sha256": native.module_sha256,
        "network_authority_sha256": network_authority,
        "network_mode": network_mode,
        "network_policy": network_policy,
        "operation": operation,
        "outputs": {name: bound[0] for name, bound in sorted(outputs.items())},
        "schema": REQUEST_SCHEMA,
        "projected_closure_manifest_sha256": contract.toolchain.runtime_closure_sha256,
        "required_dynamic_identity_kind": (
            "APPLE_CODEDIRECTORY_CDHASH"
            if sys.platform == "darwin"
            else "WINDOWS_PROCESS_IMAGE_FILE_ID"
            if os.name == "nt"
            else "LINUX_PROCFS_EXECUTABLE_IDENTITY"
        ),
        "session_admission_sha256": native.session_admission_sha256,
        "source_access": "READ_ONLY_DESCRIPTOR_RETAINED",
        "source_guard_sha256": source_guard["guard_sha256"],
        "source_snapshot_sha256": contract.source_snapshot_sha256,
        "timeout_seconds": phase.phase_timeout_seconds,
        "toolchain_binding_sha256": contract.toolchain.binding_sha256,
        "write_access": "DECLARED_PRIVATE_OUTPUT_ROOTS_ONLY",
    }
    body["request_sha256"] = _digest(body)
    return body


def _parse_native_terminal(
    raw: bytes,
    *,
    request: Mapping[str, Any],
    observed_outputs: Mapping[str, TreeIdentity],
) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JSDependencyRuntimeError("NATIVE_TERMINAL_INVALID") from exc
    keys = {
        "bounds_enforced",
        "contract_sha256",
        "cleanup_complete",
        "dependency_expectation_sha256",
        "duration_ms",
        "exhaustive_descendant_termination",
        "exclusive_operation_key_lease",
        "exit_code",
        "generation_id",
        "guest_execution_binding_sha256",
        "launch_object_kind",
        "native_custody_receipt_sha256",
        "native_deployment_receipt_sha256",
        "native_module_sha256",
        "network_authority_sha256",
        "network_mode",
        "network_policy_sha256",
        "network_violation",
        "native_provider_authenticated",
        "observed_egress_origins",
        "observed_egress_sha256",
        "operation",
        "output_trees",
        "population_zero",
        "post_spawn_dynamic_identity_sha256",
        "post_spawn_dynamic_identity_kind",
        "projected_closure_manifest_sha256",
        "request_sha256",
        "schema",
        "session_admission_sha256",
        "scratch_writes_only",
        "source_read_only",
        "stderr_bytes",
        "stderr_sha256",
        "stdout_bytes",
        "stdout_sha256",
        "terminal_receipt_sha256",
        "timed_out",
        "toolchain_identity_sha256",
    }
    if type(value) is not dict or set(value) != keys:
        _fail("NATIVE_TERMINAL_SCHEMA_INVALID")
    stored = value.get("terminal_receipt_sha256")
    unsigned = dict(value)
    unsigned.pop("terminal_receipt_sha256", None)
    if stored != _digest(unsigned) or raw != _canonical(value) + b"\n":
        _fail("NATIVE_TERMINAL_DIGEST_INVALID")
    for field in (
        "request_sha256",
        "contract_sha256",
        "dependency_expectation_sha256",
        "guest_execution_binding_sha256",
        "native_custody_receipt_sha256",
        "native_deployment_receipt_sha256",
        "native_module_sha256",
        "network_authority_sha256",
        "network_policy_sha256",
        "observed_egress_sha256",
        "post_spawn_dynamic_identity_sha256",
        "stderr_sha256",
        "stdout_sha256",
        "toolchain_identity_sha256",
        "terminal_receipt_sha256",
        "session_admission_sha256",
    ):
        _hex64(value.get(field), "NATIVE_TERMINAL_DIGEST_INVALID")
    if (
        value["schema"] != NATIVE_TERMINAL_SCHEMA
        or value["request_sha256"] != request["request_sha256"]
        or value["contract_sha256"] != request["contract_sha256"]
        or value["generation_id"] != request["generation_id"]
        or value["guest_execution_binding_sha256"]
        != request["guest_execution_binding_sha256"]
        or value["operation"] != request["operation"]
        or value["launch_object_kind"] != request["launch_object_kind"]
        or value["projected_closure_manifest_sha256"]
        != request["projected_closure_manifest_sha256"]
        or value["post_spawn_dynamic_identity_kind"]
        != request["required_dynamic_identity_kind"]
        or value["native_custody_receipt_sha256"] != request["native_custody_receipt_sha256"]
        or value["native_deployment_receipt_sha256"]
        != request["native_deployment_receipt_sha256"]
        or value["native_module_sha256"] != request["native_module_sha256"]
        or value["session_admission_sha256"] != request["session_admission_sha256"]
        or value["dependency_expectation_sha256"]
        != request["dependency_expectation_sha256"]
        or value["network_authority_sha256"] != request["network_authority_sha256"]
        or value["network_policy_sha256"]
        != request["network_policy"]["policy_sha256"]
        or value["network_mode"] != request["network_mode"]
        or value["toolchain_identity_sha256"] != request["toolchain_binding_sha256"]
        or value["exit_code"] != 0
        or value["timed_out"] is not False
        or value["network_violation"] is not False
        or value["source_read_only"] is not True
        or value["scratch_writes_only"] is not True
        or value["bounds_enforced"] is not True
        or value["exhaustive_descendant_termination"] is not True
        or value["exclusive_operation_key_lease"] is not True
        or value["native_provider_authenticated"] is not True
        or value["population_zero"] is not True
        or value["cleanup_complete"] is not True
    ):
        _fail("NATIVE_TERMINAL_AUTHORITY_INVALID")
    observed_origins = value["observed_egress_origins"]
    allowed_origins = request["network_policy"]["allowed_origins"]
    if (
        type(observed_origins) is not list
        or len(observed_origins) > MAX_EGRESS_ORIGINS
        or any(type(row) is not dict for row in observed_origins)
        or any(
            set(row) != {"host", "port", "scheme"}
            or row.get("scheme") != "https"
            or type(row.get("host")) is not str
            or not row["host"]
            or row["host"] != row["host"].lower()
            or type(row.get("port")) is not int
            or row["port"] != 443
            for row in observed_origins
        )
        or observed_origins
        != sorted(
            observed_origins,
            key=lambda row: (
                str(row.get("scheme", "")),
                str(row.get("host", "")),
                row.get("port", -1),
            ),
        )
        or len({_canonical(row) for row in observed_origins})
        != len(observed_origins)
        or any(row not in allowed_origins for row in observed_origins)
        or value["observed_egress_sha256"] != _digest(observed_origins)
    ):
        _fail(
            "OFFLINE_NETWORK_ACTIVITY_OBSERVED"
            if request["network_mode"] == "NO_NETWORK"
            else "ONLINE_EGRESS_IDENTITY_MISMATCH"
        )
    if request["network_mode"] == "NO_NETWORK" and observed_origins != []:
        _fail("OFFLINE_NETWORK_ACTIVITY_OBSERVED")
    for field in ("duration_ms", "stdout_bytes", "stderr_bytes"):
        item = value[field]
        if type(item) is not int or item < 0:
            _fail("NATIVE_TERMINAL_BOUND_INVALID")
    if value["duration_ms"] > int(request["timeout_seconds"]) * 1000:
        _fail("NATIVE_TERMINAL_TIMEOUT_BOUND_EXCEEDED")
    if value["stdout_bytes"] + value["stderr_bytes"] > MAX_NATIVE_OUTPUT_BYTES:
        _fail("NATIVE_OUTPUT_BOUND_EXCEEDED")
    expected_rows = {
        name: _tree_row(str(request["outputs"][name]), identity)
        for name, identity in sorted(observed_outputs.items())
    }
    if value["output_trees"] != expected_rows:
        _fail("NATIVE_OUTPUT_TREE_MISMATCH")
    return value


def _replay_stored_terminal(
    terminal: object,
    *,
    native: _NativeRuntime,
    request: Mapping[str, Any],
    observed_outputs: Mapping[str, TreeIdentity],
    source_descriptor: int,
    scratch_descriptor: int,
    state_descriptor: int,
    archive_root_descriptor: int,
) -> dict[str, Any]:
    if type(terminal) is not dict:
        _fail("JOURNAL_NATIVE_RECEIPT_INVALID")
    request_raw = _canonical(request) + b"\n"
    terminal_raw = _canonical(terminal) + b"\n"
    _attest_native_terminal_replay(
        native,
        request_raw,
        terminal_raw,
        source_descriptor=source_descriptor,
        scratch_descriptor=scratch_descriptor,
        state_descriptor=state_descriptor,
        archive_root_descriptor=archive_root_descriptor,
    )
    return _parse_native_terminal(
        terminal_raw,
        request=request,
        observed_outputs=observed_outputs,
    )


def _validate_source_and_archives(
    contract: CONTRACT.JSDependencyMaterializationContract,
    source_before: Mapping[str, Any],
    archives_before: Mapping[str, Any],
) -> None:
    if _source_preflight(contract) != source_before:
        _fail("SOURCE_CHANGED_DURING_MATERIALIZATION")
    observed_source = _archive_preflight(contract)
    observed_binding, _manifest = _archive_root_binding(contract, observed_source)
    if observed_binding != archives_before:
        _fail("TOOLCHAIN_ARCHIVE_CHANGED_DURING_MATERIALIZATION")


def _validate_toolchain_tree(root: Path, expected: TreeIdentity) -> None:
    observed = _scan_tree(
        root,
        max_entries=MAX_TOOLCHAIN_ENTRIES,
        max_bytes=MAX_TOOLCHAIN_EXPANDED_BYTES,
    )
    if observed != expected:
        _fail("MATERIALIZED_TOOLCHAIN_CHANGED")


def _execute_operation(
    native: _NativeRuntime,
    request: dict[str, Any],
    *,
    source_descriptor: int,
    scratch_descriptor: int,
    state_descriptor: int,
    archive_root_descriptor: int,
    output_specs: Mapping[str, tuple[str, int, int]],
) -> tuple[dict[str, Any], dict[str, TreeIdentity]]:
    request_raw = _canonical(request) + b"\n"
    raw = _invoke_native(
        native,
        request_raw,
        source_descriptor=source_descriptor,
        scratch_descriptor=scratch_descriptor,
        state_descriptor=state_descriptor,
        archive_root_descriptor=archive_root_descriptor,
    )
    _attest_native_terminal_replay(
        native,
        request_raw,
        raw,
        source_descriptor=source_descriptor,
        scratch_descriptor=scratch_descriptor,
        state_descriptor=state_descriptor,
        archive_root_descriptor=archive_root_descriptor,
    )
    observed: dict[str, TreeIdentity] = {}
    for name, (path, max_entries, max_bytes) in sorted(output_specs.items()):
        observed[name] = _scan_tree(
            Path(path), max_entries=max_entries, max_bytes=max_bytes
        )
    terminal = _parse_native_terminal(raw, request=request, observed_outputs=observed)
    return terminal, observed


def _receipt_from_journal(journal: Mapping[str, Any], receipt_path: Path) -> JSDependencyMaterializationResult:
    raw, _identity = _read_regular_file(receipt_path, maximum=MAX_NATIVE_OUTPUT_BYTES)
    try:
        receipt = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JSDependencyRuntimeError("FINAL_RECEIPT_INVALID") from exc
    stored = receipt.get("receipt_sha256") if isinstance(receipt, dict) else None
    unsigned = dict(receipt) if isinstance(receipt, dict) else {}
    unsigned.pop("receipt_sha256", None)
    if (
        type(receipt) is not dict
        or receipt.get("schema") != RECEIPT_SCHEMA
        or stored != _digest(unsigned)
        or raw != _canonical(receipt) + b"\n"
        or receipt.get("contract_sha256") != journal["contract_sha256"]
    ):
        _fail("FINAL_RECEIPT_INVALID")
    return JSDependencyMaterializationResult(
        private_root=str(receipt["private_root"]),
        modules_root=str(receipt["modules_root"]),
        receipt_path=str(receipt_path),
        receipt_sha256=str(stored),
        receipt=receipt,
    )


def _execute_materialization_with_runtime(
    contract: CONTRACT.JSDependencyMaterializationContract,
    *,
    authorities: NativeMaterializerAuthorities,
    native: _NativeRuntime,
    retained_source: _RetainedSource,
    retained_archives: _RetainedArchives,
    scratch_descriptor: int,
    state_descriptor: int,
) -> JSDependencyMaterializationResult:
    private_root = Path(contract.execution.controller_transaction_root)
    state_root = Path(contract.execution.controller_state_root)
    journal_path = state_root / "materialization.journal.json"
    receipt_path = state_root / "materialization.receipt.json"
    journal = _load_journal(journal_path, contract_sha256=contract.contract_sha256)

    source = retained_source.guard
    archives = retained_archives.binding
    dependency_expectation = _dependency_expectation(
        retained_source.package_json,
        retained_source.selected_lockfile,
        contract.lock_selection,
    )
    receipts: dict[str, Any] = dict(journal["native_receipts"])
    state_index = _STATES.index(str(journal["state"]))

    toolchain_root = Path(contract.execution.controller_scratch_root) / "toolchain"
    online_modules = Path(contract.online.modules_root)
    online_cache = Path(contract.online.cache_root)
    cache_snapshot = Path(contract.replay.retained_cache_snapshot_root)
    offline_cache = Path(contract.offline_replay.cache_root)
    offline_modules = Path(contract.offline_replay.modules_root)
    if retained_archives.root_descriptor < 0:
        _fail("TOOLCHAIN_ARCHIVE_ROOT_NOT_RETAINED")
    archive_root_descriptor = retained_archives.root_descriptor
    replay_custody = {
        "native": native,
        "source_descriptor": retained_source.root_descriptor,
        "scratch_descriptor": scratch_descriptor,
        "state_descriptor": state_descriptor,
        "archive_root_descriptor": archive_root_descriptor,
    }

    if state_index < _STATES.index("TOOLCHAIN_READY"):
        _remove_owned_subtree(private_root, toolchain_root)
        specs = {
            "toolchain": (
                str(toolchain_root),
                MAX_TOOLCHAIN_ENTRIES,
                MAX_TOOLCHAIN_EXPANDED_BYTES,
            )
        }
        request = _request(
            operation="PREPARE_TOOLCHAIN",
            contract=contract,
            authorities=authorities,
            native=native,
            source_guard=source,
            archives=archives,
            dependency_expectation=dependency_expectation,
            expected_inputs={},
            outputs=specs,
        )
        terminal, _trees = _execute_operation(
            native,
            request,
            source_descriptor=retained_source.root_descriptor,
            scratch_descriptor=scratch_descriptor,
            state_descriptor=state_descriptor,
            archive_root_descriptor=archive_root_descriptor,
            output_specs=specs,
        )
        _validate_source_and_archives(contract, source, archives)
        retained_source.verify(contract)
        retained_archives.verify(contract)
        receipts["PREPARE_TOOLCHAIN"] = terminal
        journal = {**journal, "native_receipts": receipts, "state": "TOOLCHAIN_READY"}
        _store_journal(journal_path, journal)
        state_index = _STATES.index("TOOLCHAIN_READY")
    toolchain_tree = _scan_tree(
        toolchain_root,
        max_entries=MAX_TOOLCHAIN_ENTRIES,
        max_bytes=MAX_TOOLCHAIN_EXPANDED_BYTES,
    )
    for executable in (
        Path(contract.toolchain.node_executable_path),
        Path(contract.toolchain.yarn_cli_path),
    ):
        if not _inside(toolchain_root, executable):
            _fail("TOOLCHAIN_EXECUTABLE_ESCAPE")
        _read_regular_file(executable, maximum=MAX_TOOLCHAIN_EXPANDED_BYTES)
    prepare_request = _request(
        operation="PREPARE_TOOLCHAIN",
        contract=contract,
        authorities=authorities,
        native=native,
        source_guard=source,
        archives=archives,
        dependency_expectation=dependency_expectation,
        expected_inputs={},
        outputs={
            "toolchain": (
                str(toolchain_root),
                MAX_TOOLCHAIN_ENTRIES,
                MAX_TOOLCHAIN_EXPANDED_BYTES,
            )
        },
    )
    _replay_stored_terminal(
        receipts.get("PREPARE_TOOLCHAIN"),
        request=prepare_request,
        observed_outputs={"toolchain": toolchain_tree},
        **replay_custody,
    )

    if state_index < _STATES.index("ONLINE_COMPLETE"):
        _remove_owned_subtree(private_root, Path(contract.online.private_root))
        specs = {
            "cache": (
                str(online_cache),
                contract.online.max_dependency_entries,
                contract.online.max_cache_expanded_bytes,
            ),
            "modules": (
                str(online_modules),
                contract.online.max_dependency_entries,
                contract.online.max_dependency_expanded_bytes,
            ),
        }
        request = _request(
            operation="ONLINE_INSTALL",
            contract=contract,
            authorities=authorities,
            native=native,
            source_guard=source,
            archives=archives,
            dependency_expectation=dependency_expectation,
            expected_inputs={"toolchain": (str(toolchain_root), toolchain_tree)},
            outputs=specs,
        )
        terminal, _trees = _execute_operation(
            native,
            request,
            source_descriptor=retained_source.root_descriptor,
            scratch_descriptor=scratch_descriptor,
            state_descriptor=state_descriptor,
            archive_root_descriptor=archive_root_descriptor,
            output_specs=specs,
        )
        _validate_source_and_archives(contract, source, archives)
        retained_source.verify(contract)
        retained_archives.verify(contract)
        _validate_toolchain_tree(toolchain_root, toolchain_tree)
        receipts["ONLINE_INSTALL"] = terminal
        journal = {**journal, "native_receipts": receipts, "state": "ONLINE_COMPLETE"}
        _store_journal(journal_path, journal)
        state_index = _STATES.index("ONLINE_COMPLETE")
    online_modules_tree = _scan_tree(
        online_modules,
        max_entries=contract.online.max_dependency_entries,
        max_bytes=contract.online.max_dependency_expanded_bytes,
    )
    online_cache_tree = _scan_tree(
        online_cache,
        max_entries=contract.online.max_dependency_entries,
        max_bytes=contract.online.max_cache_expanded_bytes,
    )
    online_completeness = _validate_dependency_completeness(
        online_modules,
        expectation=dependency_expectation,
        tree=online_modules_tree,
    )
    online_request = _request(
        operation="ONLINE_INSTALL",
        contract=contract,
        authorities=authorities,
        native=native,
        source_guard=source,
        archives=archives,
        dependency_expectation=dependency_expectation,
        expected_inputs={"toolchain": (str(toolchain_root), toolchain_tree)},
        outputs={
            "cache": (
                str(online_cache),
                contract.online.max_dependency_entries,
                contract.online.max_cache_expanded_bytes,
            ),
            "modules": (
                str(online_modules),
                contract.online.max_dependency_entries,
                contract.online.max_dependency_expanded_bytes,
            ),
        },
    )
    _replay_stored_terminal(
        receipts.get("ONLINE_INSTALL"),
        request=online_request,
        observed_outputs={"cache": online_cache_tree, "modules": online_modules_tree},
        **replay_custody,
    )

    if state_index < _STATES.index("CACHE_HANDOFF_COMPLETE"):
        _remove_owned_subtree(private_root, cache_snapshot)
        _remove_owned_subtree(private_root, Path(contract.offline_replay.private_root))
        specs = {
            "offline_cache_seed": (
                str(offline_cache),
                contract.offline_replay.max_dependency_entries,
                contract.offline_replay.max_cache_expanded_bytes,
            ),
            "retained_cache_snapshot": (
                str(cache_snapshot),
                contract.online.max_dependency_entries,
                contract.online.max_cache_expanded_bytes,
            ),
        }
        request = _request(
            operation="CACHE_HANDOFF",
            contract=contract,
            authorities=authorities,
            native=native,
            source_guard=source,
            archives=archives,
            dependency_expectation=dependency_expectation,
            expected_inputs={
                "online_cache": (str(online_cache), online_cache_tree),
                "toolchain": (str(toolchain_root), toolchain_tree),
            },
            outputs=specs,
        )
        terminal, trees = _execute_operation(
            native,
            request,
            source_descriptor=retained_source.root_descriptor,
            scratch_descriptor=scratch_descriptor,
            state_descriptor=state_descriptor,
            archive_root_descriptor=archive_root_descriptor,
            output_specs=specs,
        )
        if (
            trees["offline_cache_seed"] != online_cache_tree
            or trees["retained_cache_snapshot"] != online_cache_tree
        ):
            _fail("CACHE_HANDOFF_NOT_BYTE_EXACT")
        _validate_source_and_archives(contract, source, archives)
        retained_source.verify(contract)
        retained_archives.verify(contract)
        _validate_toolchain_tree(toolchain_root, toolchain_tree)
        receipts["CACHE_HANDOFF"] = terminal
        journal = {**journal, "native_receipts": receipts, "state": "CACHE_HANDOFF_COMPLETE"}
        _store_journal(journal_path, journal)
        state_index = _STATES.index("CACHE_HANDOFF_COMPLETE")
    offline_cache_tree = _scan_tree(
        offline_cache,
        max_entries=contract.offline_replay.max_dependency_entries,
        max_bytes=contract.offline_replay.max_cache_expanded_bytes,
    )
    retained_cache_tree = _scan_tree(
        cache_snapshot,
        max_entries=contract.online.max_dependency_entries,
        max_bytes=contract.online.max_cache_expanded_bytes,
    )
    if offline_cache_tree != online_cache_tree or retained_cache_tree != online_cache_tree:
        _fail("CACHE_HANDOFF_POSTCOMMIT_MUTATION")
    cache_request = _request(
        operation="CACHE_HANDOFF",
        contract=contract,
        authorities=authorities,
        native=native,
        source_guard=source,
        archives=archives,
        dependency_expectation=dependency_expectation,
        expected_inputs={
            "online_cache": (str(online_cache), online_cache_tree),
            "toolchain": (str(toolchain_root), toolchain_tree),
        },
        outputs={
            "offline_cache_seed": (
                str(offline_cache),
                contract.offline_replay.max_dependency_entries,
                contract.offline_replay.max_cache_expanded_bytes,
            ),
            "retained_cache_snapshot": (
                str(cache_snapshot),
                contract.online.max_dependency_entries,
                contract.online.max_cache_expanded_bytes,
            ),
        },
    )
    _replay_stored_terminal(
        receipts.get("CACHE_HANDOFF"),
        request=cache_request,
        observed_outputs={
            "offline_cache_seed": offline_cache_tree,
            "retained_cache_snapshot": retained_cache_tree,
        },
        **replay_custody,
    )

    if state_index < _STATES.index("OFFLINE_COMPLETE"):
        # Preserve the already verified offline cache while clearing any
        # uncommitted modules/temp/home residue from a crashed replay.
        for target in (
            offline_modules,
            Path(contract.offline_replay.temp_root),
            Path(contract.offline_replay.home_root),
        ):
            _remove_owned_subtree(private_root, target)
        specs = {
            "modules": (
                str(offline_modules),
                contract.offline_replay.max_dependency_entries,
                contract.offline_replay.max_dependency_expanded_bytes,
            )
        }
        request = _request(
            operation="OFFLINE_REPLAY",
            contract=contract,
            authorities=authorities,
            native=native,
            source_guard=source,
            archives=archives,
            dependency_expectation=dependency_expectation,
            expected_inputs={
                "offline_cache_seed": (str(offline_cache), offline_cache_tree),
                "toolchain": (str(toolchain_root), toolchain_tree),
            },
            outputs=specs,
        )
        terminal, _trees = _execute_operation(
            native,
            request,
            source_descriptor=retained_source.root_descriptor,
            scratch_descriptor=scratch_descriptor,
            state_descriptor=state_descriptor,
            archive_root_descriptor=archive_root_descriptor,
            output_specs=specs,
        )
        _validate_source_and_archives(contract, source, archives)
        retained_source.verify(contract)
        retained_archives.verify(contract)
        _validate_toolchain_tree(toolchain_root, toolchain_tree)
        receipts["OFFLINE_REPLAY"] = terminal
        journal = {**journal, "native_receipts": receipts, "state": "OFFLINE_COMPLETE"}
        _store_journal(journal_path, journal)
    offline_modules_tree = _scan_tree(
        offline_modules,
        max_entries=contract.offline_replay.max_dependency_entries,
        max_bytes=contract.offline_replay.max_dependency_expanded_bytes,
    )
    offline_completeness = _validate_dependency_completeness(
        offline_modules,
        expectation=dependency_expectation,
        tree=offline_modules_tree,
    )
    if offline_modules_tree != online_modules_tree:
        _fail("OFFLINE_REPLAY_TREE_MISMATCH")
    if offline_completeness != online_completeness:
        _fail("OFFLINE_REPLAY_COMPLETENESS_MISMATCH")
    _validate_source_and_archives(contract, source, archives)
    retained_source.verify(contract)
    retained_archives.verify(contract)
    _validate_toolchain_tree(toolchain_root, toolchain_tree)
    offline_request = _request(
        operation="OFFLINE_REPLAY",
        contract=contract,
        authorities=authorities,
        native=native,
        source_guard=source,
        archives=archives,
        dependency_expectation=dependency_expectation,
        expected_inputs={
            "offline_cache_seed": (str(offline_cache), offline_cache_tree),
            "toolchain": (str(toolchain_root), toolchain_tree),
        },
        outputs={
            "modules": (
                str(offline_modules),
                contract.offline_replay.max_dependency_entries,
                contract.offline_replay.max_dependency_expanded_bytes,
            )
        },
    )
    _replay_stored_terminal(
        receipts.get("OFFLINE_REPLAY"),
        request=offline_request,
        observed_outputs={"modules": offline_modules_tree},
        **replay_custody,
    )

    receipt_digests = {
        operation: terminal["terminal_receipt_sha256"]
        for operation, terminal in sorted(receipts.items())
    }
    if set(receipt_digests) != set(_OPERATIONS):
        _fail("NATIVE_RECEIPT_SET_INCOMPLETE")
    final_body = {
        "archive_binding_sha256": archives["binding_sha256"],
        "cache_tree": online_cache_tree.binding_dict(),
        "contract_sha256": contract.contract_sha256,
        "generation_id": contract.generation_id,
        "guest_execution": contract.execution.binding_dict(),
        "lock_selection": contract.lock_selection.binding_dict()
        | {"selection_sha256": contract.lock_selection.selection_sha256},
        "lock_selection_sha256": contract.lock_selection.selection_sha256,
        "modules_root": str(offline_modules),
        "modules_tree": offline_modules_tree.binding_dict(),
        "dependency_completeness": offline_completeness,
        "dependency_expectation": dependency_expectation,
        "native_authorities": authorities.binding_dict(),
        "native_receipts": receipt_digests,
        "private_root": str(private_root),
        "schema": RECEIPT_SCHEMA,
        "source_guard_sha256": source["guard_sha256"],
        "source_snapshot_sha256": contract.source_snapshot_sha256,
        "terminal_state": "OFFLINE_REPLAY_VERIFIED",
        "toolchain_binding_sha256": contract.toolchain.binding_sha256,
        "toolchain_tree": toolchain_tree.binding_dict(),
    }
    final = final_body | {"receipt_sha256": _digest(final_body)}
    if receipt_path.exists():
        existing, _identity = _read_regular_file(receipt_path, maximum=MAX_NATIVE_OUTPUT_BYTES)
        if existing != _canonical(final) + b"\n":
            _fail("FINAL_RECEIPT_CONFLICT")
    else:
        _atomic_write_new(receipt_path, _canonical(final) + b"\n", mode=0o400)
    journal = {**journal, "native_receipts": receipts, "state": "COMMITTED"}
    _store_journal(journal_path, journal)
    return _receipt_from_journal(journal, receipt_path)


def execute_js_dependency_materialization(
    contract: CONTRACT.JSDependencyMaterializationContract,
    *,
    expected_contract_sha256: str,
    authorities: NativeMaterializerAuthorities,
    native_capability: object | None = None,
    native_runtime_authority: object | None = None,
) -> JSDependencyMaterializationResult:
    """Execute or resume one exact native-governed dependency transaction.

    Source descriptors are retained from admission through final replay.  The
    native provider must grant an exclusive session lease before the private
    root is created, so a second process cannot observe or mutate a half-owned
    generation before exclusivity exists.
    """

    contract = _validate_contract_shape(contract, expected_contract_sha256)
    authorities = _validate_authorities(authorities)
    retained = _retain_source(contract)
    retained_archives: _RetainedArchives | None = None
    scratch_descriptor = -1
    state_descriptor = -1
    try:
        retained_archives = _retain_archives(contract)
        archives = retained_archives.binding
        dependency_expectation = _dependency_expectation(
            retained.package_json,
            retained.selected_lockfile,
            contract.lock_selection,
        )
        admission_body = {
            "archive_binding_sha256": archives["binding_sha256"],
            "contract_sha256": contract.contract_sha256,
            "dependency_expectation_sha256": dependency_expectation[
                "expectation_sha256"
            ],
            "generation_id": contract.generation_id,
            "guest_execution_binding_sha256": contract.execution.binding_sha256,
            "exclusive_operation_key_required": True,
            "native_authorities": authorities.binding_dict(),
            "operation_key": _digest(
                {
                    "contract_sha256": contract.contract_sha256,
                    "private_root": contract.execution.controller_transaction_root,
                }
            ),
            "private_root": contract.execution.controller_transaction_root,
            "schema": ADMISSION_SCHEMA,
            "source_guard_sha256": retained.guard["guard_sha256"],
            "source_root": contract.source_root,
            "source_snapshot_sha256": contract.source_snapshot_sha256,
            "toolchain_binding_sha256": contract.toolchain.binding_sha256,
        }
        admission = _canonical(
            admission_body | {"admission_sha256": _digest(admission_body)}
        ) + b"\n"
        if (native_capability is None) == (native_runtime_authority is None):
            _fail("NATIVE_MATERIALIZER_CAPABILITY_INVALID")
        native = (
            _require_native_capability(
                native_capability,
                admission,
                expected_extension_sha256=authorities.native_extension_sha256,
            )
            if native_runtime_authority is None
            else _require_native_guest_bundle_capability(
                native_runtime_authority,
                admission,
                expected_extension_sha256=authorities.native_extension_sha256,
            )
        )
        # No materializer-owned path is mutated before the opaque native
        # session above has acquired the operation-key lease.
        private_root = Path(contract.execution.controller_transaction_root)
        _owned_private_root(
            private_root,
            contract.contract_sha256,
            authorities.custody_receipt_sha256,
        )
        _stage_archive_root(retained_archives, private_root)
        scratch_root, state_root = _owned_mount_roots(contract)
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if os.name != "nt":
            directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(
                os, "O_NOFOLLOW", 0
            )
        scratch_descriptor = os.open(scratch_root, directory_flags)
        state_descriptor = os.open(state_root, directory_flags)
        os.set_inheritable(scratch_descriptor, False)
        os.set_inheritable(state_descriptor, False)
        scratch_identity = os.fstat(scratch_descriptor)
        state_identity = os.fstat(state_descriptor)
        if (int(scratch_identity.st_dev), int(scratch_identity.st_ino)) == (
            int(state_identity.st_dev),
            int(state_identity.st_ino),
        ):
            _fail("CONTROLLER_MOUNT_ROOTS_ALIAS")
        result = _execute_materialization_with_runtime(
            contract,
            authorities=authorities,
            native=native,
            retained_source=retained,
            retained_archives=retained_archives,
            scratch_descriptor=scratch_descriptor,
            state_descriptor=state_descriptor,
        )
        retained.verify(contract)
        return result
    finally:
        if scratch_descriptor >= 0:
            try:
                os.close(scratch_descriptor)
            except OSError:
                pass
        if state_descriptor >= 0:
            try:
                os.close(state_descriptor)
            except OSError:
                pass
        if retained_archives is not None:
            retained_archives.close()
        retained.close()


def execute_installed_js_dependency_materialization(
    source: CONTRACT.ImmutableJSSourceInputs,
    workspace: CONTRACT.PrivateDependencyWorkspaceInputs,
    *,
    repository_root: os.PathLike[str] | str,
    target_os: str,
    target_arch: str,
    windows_system_root: str | None = None,
) -> JSDependencyMaterializationResult:
    """Build and execute one contract from installed native authority only.

    This is the production caller.  It deliberately accepts no bootstrap
    digest, network receipt, custody receipt, native extension path, native
    capability, or callback from Python callers.  Those values are projected
    by the authenticated broker-v2 session through method 0x2105 and converted
    to typed authorities only after exact canonical-schema and extension-byte
    replay.
    """

    bridge = _installed_native_bridge()
    bootstrap_authority, native_authorities = _installed_runtime_authorities(
        bridge
    )
    contract = CONTRACT.build_js_dependency_materialization_contract(
        source,
        workspace,
        bootstrap_authority=bootstrap_authority,
        repository_root=repository_root,
        target_os=target_os,
        target_arch=target_arch,
        windows_system_root=windows_system_root,
    )
    if _installed_native_bridge() != bridge:
        _fail("NATIVE_MATERIALIZER_BRIDGE_CHANGED_DURING_CONTRACT_BUILD")
    return execute_js_dependency_materialization(
        contract,
        expected_contract_sha256=contract.contract_sha256,
        authorities=native_authorities,
        native_capability=bridge.initial_authority,
    )


def execute_native_guest_js_dependency_materialization(
    source: CONTRACT.ImmutableJSSourceInputs,
    workspace: CONTRACT.PrivateDependencyWorkspaceInputs,
    *,
    repository_root: os.PathLike[str] | str,
    target_os: str,
    target_arch: str,
    native_runtime_authority: object,
    windows_system_root: str | None = None,
) -> JSDependencyMaterializationResult:
    """Execute through the already-acquired opaque native guest bundle.

    This is the production audit-start path.  It never reads the module-global
    JS INITIAL authority: the role-2 acquisition retained that distinct native
    capability before consuming ``INITIAL_AUTHORITY`` and exposes only the five
    narrow method-exact operations needed by this transaction.
    """

    try:
        import posix_backend_execution as runtime

        raw = runtime.native_guest_js_materializer_runtime_identity(
            native_runtime_authority
        )
        parsed = json.loads(raw.decode("ascii", "strict"))
        expected_extension_sha256 = (
            parsed.get("native_extension_sha256")
            if type(parsed) is dict else None
        )
        _hex64(
            expected_extension_sha256,
            "NATIVE_EXTENSION_SHA256_INVALID",
        )
        bootstrap_authority, native_authorities = (
            _parse_authenticated_runtime_identity(
                raw,
                expected_native_extension_sha256=expected_extension_sha256,
            )
        )
    except JSDependencyRuntimeError:
        raise
    except BaseException as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_MATERIALIZER_UNAVAILABLE",
            "opaque native JS materializer runtime identity is unavailable",
        ) from exc
    contract = CONTRACT.build_js_dependency_materialization_contract(
        source,
        workspace,
        bootstrap_authority=bootstrap_authority,
        repository_root=repository_root,
        target_os=target_os,
        target_arch=target_arch,
        windows_system_root=windows_system_root,
    )
    if (
        runtime.native_guest_js_materializer_runtime_identity(
            native_runtime_authority
        )
        != raw
    ):
        _fail("NATIVE_MATERIALIZER_BRIDGE_CHANGED_DURING_CONTRACT_BUILD")
    return execute_js_dependency_materialization(
        contract,
        expected_contract_sha256=contract.contract_sha256,
        authorities=native_authorities,
        native_runtime_authority=native_runtime_authority,
    )


def execute_native_guest_js_and_evm_analysis_projection(
    source: CONTRACT.ImmutableJSSourceInputs,
    workspace: CONTRACT.PrivateDependencyWorkspaceInputs,
    *,
    repository_root: os.PathLike[str] | str,
    target_os: str,
    target_arch: str,
    native_runtime_authority: object,
    original_source_scope_sha256: str,
    windows_system_root: str | None = None,
) -> NativeGuestEVMAnalysisProjectionResult:
    """Run the complete authenticated JS-to-EVM projection transaction.

    The source project and materialized modules are reopened as no-follow
    directory descriptors.  Native code creates the analysis workspace under
    a fresh private scratch directory, authenticates the compiler image member,
    and retains the resulting descriptor authority.  No source ``node_modules``,
    ambient executable, compiler path, or caller-generated receipt is admitted.
    """

    _hex64(original_source_scope_sha256, "PROJECTION_SOURCE_SCOPE_INVALID")
    dependency = execute_native_guest_js_dependency_materialization(
        source,
        workspace,
        repository_root=repository_root,
        target_os=target_os,
        target_arch=target_arch,
        native_runtime_authority=native_runtime_authority,
        windows_system_root=windows_system_root,
    )
    project = _safe_absolute(source.source_root, "SOURCE_ROOT_INVALID")
    modules = _safe_absolute(dependency.modules_root, "MODULES_ROOT_INVALID")
    private_root = _safe_absolute(
        workspace.private_root, "PRIVATE_ROOT_INVALID"
    )
    control_root = private_root / "evm-analysis-projection"
    scratch_root = control_root / "scratch"
    state_root = control_root / "state"
    for path in (project, modules, private_root):
        _reject_alias_ancestry(path, allow_missing_leaf=False)
    if (
        not _inside(private_root, modules)
        or _inside(project, private_root)
        or _inside(private_root, project)
        or control_root.exists()
        or control_root.is_symlink()
    ):
        _fail("PROJECTION_ROOT_RELATION_INVALID")
    try:
        os.mkdir(control_root, 0o700)
        os.mkdir(scratch_root, 0o700)
        os.mkdir(state_root, 0o700)
    except OSError as exc:
        raise JSDependencyRuntimeError(
            "PROJECTION_CONTROL_ROOT_CREATE_FAILED", str(control_root)
        ) from exc
    _reject_alias_ancestry(scratch_root, allow_missing_leaf=False)
    _reject_alias_ancestry(state_root, allow_missing_leaf=False)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptors: list[int] = []
    try:
        project_fd = os.open(project, flags)
        descriptors.append(project_fd)
        scratch_fd = os.open(scratch_root, flags)
        descriptors.append(scratch_fd)
        state_fd = os.open(state_root, flags)
        descriptors.append(state_fd)
        modules_fd = os.open(modules, flags)
        descriptors.append(modules_fd)
        identities = [os.fstat(fd) for fd in descriptors]
        if len({(int(row.st_dev), int(row.st_ino)) for row in identities}) != 4:
            _fail("PROJECTION_DESCRIPTOR_ALIAS")
        if any(not stat.S_ISDIR(row.st_mode) for row in identities):
            _fail("PROJECTION_DESCRIPTOR_KIND_INVALID")
        import posix_backend_execution as runtime

        authority = runtime.commit_native_guest_evm_analysis_projection(
            native_runtime_authority,
            dependency_materialization_receipt=dependency.receipt,
            original_source_scope_sha256=original_source_scope_sha256,
            project_fd=project_fd,
            scratch_fd=scratch_fd,
            state_fd=state_fd,
            modules_fd=modules_fd,
        )
        receipt = runtime.project_native_guest_evm_analysis_projection_receipt(
            native_runtime_authority, authority,
        )
        lineage = runtime.project_native_guest_evm_analysis_projection_lineage(
            native_runtime_authority, authority,
        )
        binding_raw = (
            runtime.project_native_guest_evm_analysis_projection_workspace_binding(
                native_runtime_authority, authority,
            )
        )
    except JSDependencyRuntimeError:
        raise
    except BaseException as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_EVM_PROJECTION_FAILED",
            "native EVM analysis projection transaction failed closed",
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        receipt_value = json.loads(receipt.decode("utf-8", "strict"))
        lineage_value = json.loads(lineage.decode("utf-8", "strict"))
        binding = json.loads(binding_raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise JSDependencyRuntimeError(
            "NATIVE_EVM_PROJECTION_RESULT_INVALID"
        ) from exc
    if (
        type(receipt_value) is not dict
        or type(lineage_value) is not dict
        or type(binding) is not dict
        or receipt != _canonical(receipt_value)
        or lineage != _canonical(lineage_value)
        or binding_raw != _canonical(binding)
        or binding.get("projection_receipt_sha256")
        != hashlib.sha256(receipt).hexdigest()
        or binding.get("workspace_path")
        != os.fspath(scratch_root / "analysis-workspace")
    ):
        _fail("NATIVE_EVM_PROJECTION_RESULT_INVALID")
    receipt_path = state_root / "projection-receipt.json"
    lineage_path = state_root / "materialization-lineage.json"
    if not lineage_path.is_file():
        _fail("NATIVE_EVM_PROJECTION_LINEAGE_ABSENT")
    observed_lineage, _lineage_stat = _read_regular_file(
        lineage_path, maximum=MAX_NATIVE_RECEIPT_BYTES
    )
    if observed_lineage != lineage:
        _fail("NATIVE_EVM_PROJECTION_LINEAGE_MISMATCH")
    _atomic_write_new(receipt_path, receipt, mode=0o400)
    return NativeGuestEVMAnalysisProjectionResult(
        dependency_materialization=dependency,
        native_projection_authority=authority,
        projection_receipt=receipt,
        materialization_lineage=lineage,
        workspace_binding=binding,
        projection_receipt_path=os.fspath(receipt_path),
        materialization_lineage_path=os.fspath(lineage_path),
    )


__all__ = [
    "ADMISSION_SCHEMA",
    "EMPTY_EGRESS_SHA256",
    "JSDependencyMaterializationResult",
    "NativeGuestEVMAnalysisProjectionResult",
    "JSDependencyRuntimeError",
    "NATIVE_TERMINAL_SCHEMA",
    "NativeMaterializerAuthorities",
    "RECEIPT_SCHEMA",
    "REQUEST_SCHEMA",
    "RUNTIME_SCHEMA",
    "TREE_DIGEST_ALGORITHM",
    "execute_installed_js_dependency_materialization",
    "execute_native_guest_js_dependency_materialization",
    "execute_native_guest_js_and_evm_analysis_projection",
    "execute_js_dependency_materialization",
]
