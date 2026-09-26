"""Native-only execution authority for snapshot-bound local EVM tools.

``SNAPSHOT_BOUND_LOCAL`` is deliberately weaker than release authenticity.  A
successful native execution can support positive findings, but never authentic
upstream content, findings completeness, or a clean-audit conclusion.

Python objects and JSON self-digests are data, not authority.  The only launch
authority accepted here is an opaque immutable type issued by the authenticated
native supervisor.  On Darwin that supervisor projects the held source
descriptor into an Apple Container guest, retains every descriptor through the
terminal transition, and returns a terminal record bound to the exact request.
Until that bridge is installed, this module fails before any mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
from importlib.machinery import EXTENSION_SUFFIXES, ExtensionFileLoader, ModuleSpec
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import tempfile
from typing import Any, Mapping, Sequence
import types
import unicodedata
import weakref

from toolchain_control_authority import (
    SNAPSHOT_BOUND_LOCAL,
    SnapshotBoundLocalPolicy,
    ToolchainControls,
    snapshot_bound_local_policies,
)


EXECUTION_REQUEST_SCHEMA = "plamen.snapshot-bound-tool-execution-request.v3"
TERMINAL_SCHEMA = "plamen.snapshot-bound-tool-execution-terminal.v3"
MATERIALIZATION_LINEAGE_SCHEMA = "plamen.evm-tool-materialization-lineage.v2"
NATIVE_MATERIALIZATION_REQUEST_SCHEMA = "plamen.native-materialization-request.v1"
SOURCE_DESCRIPTOR_SCHEMA = "plamen.snapshot-bound-source-descriptor.v2"
TRUNCATION_DEBT_SCHEMA = "plamen.tool-output-truncation-debt.v1"
BUNDLE_SCHEMA = "plamen.snapshot-bound-tool-authority-bundle.v3"
CAPABILITY_SCHEMA = "plamen.evm-tool-capability-groups.v2"

TRUST_ASSUMPTION = "OPERATOR_LOCAL_TOOL_INSTALL"
EVIDENCE_CEILING = "POSITIVE_FINDINGS_AND_HEURISTIC_COVERAGE_ONLY"
MAX_LOCAL_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_DISTRIBUTION_FILES = 32_768
MAX_DISTRIBUTION_BYTES = 4 * 1024 * 1024 * 1024
MAX_DISTRIBUTION_DEPTH = 32
MAX_TERMINAL_BYTES = 256 * 1024
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_TOOL_DURATION_MS = 30 * 60 * 1000
MAX_TOOL_MEMORY_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOOL_STDOUT_BYTES = 8 * 1024 * 1024
MAX_TOOL_STDERR_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_FILES = 65_536
MAX_OUTPUT_BYTES = 4 * 1024 * 1024 * 1024

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_TOOL_IDS = ("forge", "opengrep", "semgrep", "slither", "solc")
_COMMAND_TOOLS = frozenset({"forge", "opengrep", "semgrep", "solc"})
_EXPECTED_IDENTITY_STATUS = {
    "forge": "DEBT",
    "opengrep": "DEBT",
    "semgrep": "DEBT",
    "slither": "OBSERVED_NONAUTHORITATIVE",
    "solc": "EXTERNAL_MANAGER",
}
_FOUNDRY_EVM_LANES = ("forge", "opengrep", "slither", "solc")
_BRIDGE_MODULE = "_plamen_native_supervisor"
_BRIDGE_ABI = "plamen.native-broker.v2"
_BRIDGE_PRODUCTION_ACQUISITION = "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
_NATIVE_CALLABLE_NAMES = (
    "acquire_darwin_tool_custody",
    "prepare_darwin_tool_execution",
    "execute_darwin_tool",
    "project_darwin_tool_execution_terminal",
    "darwin_tool_runtime_identity",
)
_DENIED_ENVIRONMENT_NAMES = frozenset({
    "BASH_ENV", "ENV", "GCONV_PATH", "NODE_OPTIONS", "PERL5OPT", "PYTHONHOME",
    "PYTHONINSPECT", "PYTHONPATH", "PYTHONSTARTUP", "RUBYOPT", "SHELLOPTS",
})
_DENIED_ENVIRONMENT_PREFIXES = ("DYLD_", "LD_")


class SnapshotBoundToolAuthorityError(RuntimeError):
    """A local tool request or terminal cannot be admitted safely."""


class NativeToolCustodyUnavailable(SnapshotBoundToolAuthorityError):
    """The current real platform has no authenticated native tool bridge."""

    def __init__(self, platform_id: str, code: str) -> None:
        self.platform_id = platform_id
        self.code = code
        super().__init__(f"{platform_id}:{code}")


class _FrozenReviewedAnalysisInputAuthorityType(type):
    def __setattr__(cls, _name: str, _value: object) -> None:
        raise TypeError("reviewed analysis-input authority types are frozen")

    def __delattr__(cls, _name: str) -> None:
        raise TypeError("reviewed analysis-input authority types are frozen")


class ReviewedAnalysisInputAuthority(
    metaclass=_FrozenReviewedAnalysisInputAuthorityType
):
    """Opaque process-local proof for one reviewed read-only input tree."""

    __slots__ = (
        "_kind", "_implementation_root", "_project_root", "_source_path",
        "_source_descriptor", "_release_authority_sha256", "__weakref__",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "ReviewedAnalysisInputAuthority":
        raise TypeError("reviewed analysis-input authorities are issuer-created")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("reviewed analysis-input authorities cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("reviewed analysis-input authorities are immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("reviewed analysis-input authorities are immutable")

    def __reduce__(self) -> object:
        raise TypeError("reviewed analysis-input authorities are not serializable")


_LIVE_REVIEWED_ANALYSIS_INPUTS: weakref.WeakKeyDictionary[
    ReviewedAnalysisInputAuthority, tuple[object, ...]
] = weakref.WeakKeyDictionary()


def _fail(message: str, cause: BaseException | None = None) -> None:
    error = SnapshotBoundToolAuthorityError(message)
    if cause is None:
        raise error
    raise error from cause


def _plain(value: Any) -> Any:
    """Copy only the JSON data model without invoking user conversion hooks.

    Authority preimages must never be derived from a caller-controlled
    ``Mapping`` implementation or from key stringification.  Both used to let
    a stateful object present one value during validation and another during
    canonicalization (and allowed ``1``/``"1"`` key collisions).
    """

    if type(value) is dict:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or key in result:
                _fail("tool authority object contains a non-string or duplicate key")
            result[key] = _plain(item)
        return result
    if type(value) in {tuple, list}:
        return [_plain(item) for item in value]
    if value is None or type(value) in {str, int, bool}:
        return value
    _fail("tool authority value is outside the exact JSON data model")
    raise AssertionError("unreachable")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            _plain(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        _fail("tool authority value is not canonical JSON", exc)
    raise AssertionError("unreachable")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_object(
    raw: bytes, label: str, *, maximum: int = MAX_TERMINAL_BYTES
) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        _fail(f"{label} bytes are missing or unbounded")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is not JSON", exc)
    if not isinstance(value, dict) or raw != _canonical(value):
        _fail(f"{label} is not an exact canonical object")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        _fail(f"{label} is not a lowercase SHA-256")
    return value


def _guest_path(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or (value != "/" and ("//" in value or value.endswith("/")))
        or "\\" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        _fail(f"{label} is not an exact absolute guest path")
    parsed = PurePosixPath(value)
    if (
        str(parsed) != value
        or any(part in {".", ".."} for part in parsed.parts)
    ):
        _fail(f"{label} is not an exact absolute guest path")
    return value


def _positive(value: Any, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > maximum
    ):
        _fail(f"{label} is outside its reviewed bound")
    return value


def _nonnegative(value: Any, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > maximum
    ):
        _fail(f"{label} is outside its reviewed bound")
    return value


def _real_platform_id() -> str:
    if sys.platform == "darwin":
        return "MACOS"
    if sys.platform.startswith("linux"):
        return "LINUX"
    if sys.platform == "win32":
        return "WINDOWS"
    return f"UNSUPPORTED:{sys.platform}"


def native_tool_custody_status(
    native_initial_authority: object | None = None,
    *,
    native_runtime_authority: object | None = None,
) -> dict[str, str]:
    """Report real-platform bridge debt without accepting a platform label."""

    platform_id = _real_platform_id()
    if platform_id != "MACOS":
        return {
            "platform": platform_id,
            "state": "UNAVAILABLE",
            "reason": f"{platform_id}_NATIVE_TOOL_CUSTODY_NOT_IMPLEMENTED",
        }
    try:
        if native_runtime_authority is not None:
            _native_guest_runtime_identity(native_runtime_authority)
        else:
            _native_bridge(native_initial_authority)
    except NativeToolCustodyUnavailable as exc:
        return {"platform": platform_id, "state": "UNAVAILABLE", "reason": exc.code}
    return {"platform": platform_id, "state": "AVAILABLE", "reason": ""}


def _native_guest_runtime_module() -> Any:
    """Return the role-2 bundle owner used after INITIAL_AUTHORITY consume."""

    try:
        import posix_backend_execution as runtime
    except BaseException as exc:
        raise NativeToolCustodyUnavailable(
            _real_platform_id(), "NATIVE_GUEST_RUNTIME_AUTHORITY_UNAVAILABLE"
        ) from exc
    return runtime


def _native_guest_runtime_identity(authority: object) -> dict[str, Any]:
    """Project the exact native identity from one opaque role-2 bundle."""

    runtime = _native_guest_runtime_module()
    try:
        raw = runtime.native_guest_snapshot_tool_runtime_identity(authority)
    except BaseException as exc:
        raise NativeToolCustodyUnavailable(
            _real_platform_id(), "NATIVE_GUEST_RUNTIME_AUTHORITY_UNAVAILABLE"
        ) from exc
    identity = _canonical_object(raw, "native guest tool runtime identity")
    if set(identity) != {
        "schema", "platform", "extension_path", "extension_sha256",
        "extension_byte_count", "native_deployment_receipt_sha256",
        "runtime_closure_sha256", "broker_peer_identity_sha256",
    } or identity.get("schema") != "plamen.darwin-tool-runtime-identity.v1":
        _fail("native guest tool runtime identity schema differs")
    for field in (
        "extension_sha256", "native_deployment_receipt_sha256",
        "runtime_closure_sha256", "broker_peer_identity_sha256",
    ):
        _digest(identity.get(field), f"native guest runtime {field}")
    if identity.get("platform") != _real_platform_id():
        _fail("native guest tool runtime belongs to another platform")
    return identity


def _native_bridge(native_initial_authority: object) -> Any:
    platform_id = _real_platform_id()
    if platform_id != "MACOS":
        raise NativeToolCustodyUnavailable(
            platform_id, f"{platform_id}_NATIVE_TOOL_CUSTODY_NOT_IMPLEMENTED"
        )
    try:
        module_table = types.ModuleType.__getattribute__(sys, "__dict__").get(
            "modules"
        )
        if type(module_table) is not dict:
            raise TypeError
        module = module_table.get(_BRIDGE_MODULE)
        if type(module) is not types.ModuleType:
            raise TypeError
        namespace = types.ModuleType.__getattribute__(module, "__dict__")
        spec = namespace.get("__spec__")
        if type(namespace) is not dict or type(spec) is not ModuleSpec:
            raise TypeError
        spec_namespace = object.__getattribute__(spec, "__dict__")
        loader = spec_namespace.get("loader")
        if type(loader) is not ExtensionFileLoader:
            raise TypeError
        loader_namespace = object.__getattribute__(loader, "__dict__")
        origin = spec_namespace.get("origin")
        metadata = (
            namespace.get("__name__"),
            namespace.get("__file__"),
            namespace.get("BROKER_V2_ABI_SCHEMA"),
            namespace.get("BROKER_V2_PRODUCTION_ACQUISITION"),
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
            abi_schema,
            acquisition,
            spec_name,
            _origin,
            loader_name,
            loader_path,
        ) = metadata
        if (
            module_name != _BRIDGE_MODULE
            or module_file != origin
            or spec_name != _BRIDGE_MODULE
            or loader_name != _BRIDGE_MODULE
            or loader_path != origin
            or abi_schema != _BRIDGE_ABI
            or acquisition != _BRIDGE_PRODUCTION_ACQUISITION
            or namespace.get("TEST_ONLY_BUILD") is not False
            or namespace.get("BROKER_V2_INITIAL_AUTHORITY_AVAILABLE") is not True
            or not any(origin.endswith(suffix) for suffix in EXTENSION_SUFFIXES)
        ):
            raise TypeError
    except BaseException as exc:
        raise NativeToolCustodyUnavailable(
            platform_id, "DARWIN_TOOL_CUSTODY_EXTENSION_UNAUTHENTICATED"
        ) from exc
    custody_type = namespace.get("DarwinToolCustodyAuthority")
    lease_type = namespace.get("DarwinToolExecutionLease")
    terminal_type = namespace.get("DarwinToolExecutionTerminal")
    initial_type = namespace.get("NativeAuthorityConsumer")
    initial = namespace.get("INITIAL_AUTHORITY")
    callables = tuple(namespace.get(name) for name in _NATIVE_CALLABLE_NAMES)
    immutable_type_flag = 1 << 8
    heap_type_flag = 1 << 9
    native_types = (custody_type, lease_type, terminal_type, initial_type)
    if (
        any(type(item) is not type for item in native_types)
        or type(initial) is not initial_type
        or native_initial_authority is not initial
        or any(
            type.__getattribute__(item, "__module__") != _BRIDGE_MODULE
            or type.__getattribute__(item, "__flags__") & immutable_type_flag == 0
            or type.__getattribute__(item, "__flags__") & heap_type_flag
            for item in native_types
        )
        or not all(
            type(item) is types.BuiltinFunctionType
            and getattr(item, "__module__", None) == _BRIDGE_MODULE
            and getattr(item, "__name__", None) == name
            for name, item in zip(_NATIVE_CALLABLE_NAMES, callables, strict=True)
        )
    ):
        raise NativeToolCustodyUnavailable(
            platform_id, "DARWIN_TOOL_CUSTODY_EXTENSION_UNAUTHENTICATED"
        )
    return module


def _extension_file_binding(module: Any, native_initial_authority: object) -> dict[str, Any]:
    namespace = types.ModuleType.__getattribute__(module, "__dict__")
    spec = namespace.get("__spec__")
    if type(namespace) is not dict or type(spec) is not ModuleSpec:
        _fail("native tool extension metadata changed after authentication")
    origin = Path(
        str(object.__getattribute__(spec, "__dict__").get("origin") or "")
    )
    raw_origin = os.fspath(origin)
    exact_origin = Path(os.path.abspath(raw_origin))
    if (
        not origin.is_absolute()
        or raw_origin != os.path.normpath(raw_origin)
        or raw_origin != os.fspath(exact_origin)
    ):
        _fail("native tool extension path is not exact absolute canonical spelling")
    _reject_aliases_and_unsafe_ancestry(origin, "native tool extension")
    _reject_case_alias(origin, "native tool extension")
    fd = os.open(
        origin,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or int(info.st_nlink) != 1
            or int(info.st_size) < 1
            or int(info.st_size) > MAX_LOCAL_EXECUTABLE_BYTES
        ):
            _fail("native tool extension identity is unsafe")
        digest = _descriptor_hash(fd, int(info.st_size))
        after = os.fstat(fd)
        if _stat_identity(info) != _stat_identity(after):
            _fail("native tool extension changed during identity capture")
        observed = {
            "path": os.fspath(origin),
            "sha256": digest,
            "byte_count": int(info.st_size),
            "platform": _real_platform_id(),
        }
    finally:
        os.close(fd)
    runtime_identity = namespace.get("darwin_tool_runtime_identity")
    if (
        type(runtime_identity) is not types.BuiltinFunctionType
        or getattr(runtime_identity, "__module__", None) != _BRIDGE_MODULE
        or getattr(runtime_identity, "__name__", None)
        != "darwin_tool_runtime_identity"
    ):
        _fail("native tool runtime identity callable changed after authentication")
    raw = runtime_identity(native_initial_authority)
    identity = _canonical_object(raw, "native tool runtime identity")
    if set(identity) != {
        "schema", "platform", "extension_path", "extension_sha256",
        "extension_byte_count", "native_deployment_receipt_sha256",
        "runtime_closure_sha256", "broker_peer_identity_sha256",
    } or identity.get("schema") != "plamen.darwin-tool-runtime-identity.v1":
        _fail("native tool runtime identity schema differs")
    for field in (
        "extension_sha256", "native_deployment_receipt_sha256",
        "runtime_closure_sha256", "broker_peer_identity_sha256",
    ):
        _digest(identity.get(field), f"native runtime {field}")
    if (
        identity.get("platform") != _real_platform_id()
        or identity.get("extension_path") != observed["path"]
        or identity.get("extension_sha256") != observed["sha256"]
        or identity.get("extension_byte_count") != observed["byte_count"]
    ):
        _fail("loaded extension differs from native deployment/runtime authority")
    return identity


def acquire_native_tool_custody(native_initial_authority: object) -> object:
    """Acquire native custody from the already-authenticated bootstrap.

    There is intentionally no caller-supplied JSON admission document or
    expected digest.  The extension validates its retained code descriptor,
    installed deployment receipt, and broker/custody peers before minting the
    opaque capability.
    """

    bridge = _native_bridge(native_initial_authority)
    _extension_file_binding(bridge, native_initial_authority)
    namespace = types.ModuleType.__getattribute__(bridge, "__dict__")
    acquire = namespace.get("acquire_darwin_tool_custody")
    authority = acquire(native_initial_authority)
    if (
        _native_bridge(native_initial_authority) is not bridge
        or types.ModuleType.__getattribute__(bridge, "__dict__").get(
            "acquire_darwin_tool_custody"
        ) is not acquire
    ):
        _fail("native custody bridge changed during authority acquisition")
    if type(authority) is not namespace.get("DarwinToolCustodyAuthority"):
        _fail("native supervisor returned the wrong custody capability type")
    return authority


def _require_native_custody(
    native_initial_authority: object, authority: object
) -> Any:
    bridge = _native_bridge(native_initial_authority)
    _extension_file_binding(bridge, native_initial_authority)
    namespace = types.ModuleType.__getattribute__(bridge, "__dict__")
    if type(authority) is not namespace.get("DarwinToolCustodyAuthority"):
        _fail("tool execution lacks an opaque native custody capability")
    return bridge


def _policy_for(tool_id: str, controls: ToolchainControls) -> SnapshotBoundLocalPolicy:
    policies = {row.tool_id: row for row in snapshot_bound_local_policies(controls)}
    policy = policies.get(tool_id)
    if policy is None:
        _fail(f"tool has no reviewed local policy: {tool_id}")
    return policy


def _validate_projection(
    raw: bytes, tool_id: str, controls: ToolchainControls
) -> dict[str, Any]:
    value = _canonical_object(raw, "runtime tool snapshot projection")
    policy = _policy_for(tool_id, controls)
    common = {
        "schema", "tool_id", "identity_kind", "command", "resolved_executable",
        "version", "expected_identity", "observed_identity", "identity_status",
        "deterministic_provider_authority", "toolchain_version_lock_sha256",
        "toolchain_governance_sha256",
    }
    command_extra = {"executable_sha256", "executable_bytes"}
    slither_extra = {
        "interpreter_implementation", "interpreter_version", "interpreter_sha256",
        "interpreter_bytes", "distribution_files_sha256",
        "distribution_path_set_sha256", "distribution_file_count",
        "distribution_bytes", "record_member_files_sha256",
        "record_member_path_set_sha256", "record_member_file_count",
        "record_member_native_identity_count", "record_member_bytes", "record_path",
        "record_sha256", "record_bytes", "record_row_count",
        "record_normalized_rows_sha256", "module_origin", "module_sha256",
    }
    managed_slither_extra = {
        "managed_generation_binding_sha256", "entrypoint_path",
        "entrypoint_sha256", "entrypoint_bytes",
    }
    expected_keys = common | (
        command_extra if tool_id in _COMMAND_TOOLS else slither_extra
    )
    if tool_id == "slither" and set(value) == expected_keys | managed_slither_extra:
        expected_keys |= managed_slither_extra
    command = value.get("command")
    if (
        tool_id not in _TOOL_IDS
        or set(value) != expected_keys
        or value.get("schema") != "plamen.runtime-tool-identity.v2"
        or value.get("tool_id") != tool_id
        or value.get("identity_kind") != policy.identity_kind
        or not isinstance(command, list)
        or not command
        or not all(isinstance(item, str) and item for item in command)
        or value.get("deterministic_provider_authority") is not False
        or value.get("identity_status") != _EXPECTED_IDENTITY_STATUS[tool_id]
        or value.get("toolchain_version_lock_sha256") != controls.lock_sha256
        or value.get("toolchain_governance_sha256") != controls.governance_sha256
        or not isinstance(value.get("expected_identity"), dict)
        or not isinstance(value.get("observed_identity"), dict)
        or str(value.get("version") or "").upper().startswith(
            ("UNAVAILABLE", "TIMEOUT", "ERROR:", "PROBE_FAILED:")
        )
    ):
        _fail("runtime tool projection schema or reviewed controls differ")
    if tool_id in _COMMAND_TOOLS:
        if command[0] != tool_id:
            _fail("runtime tool projection command differs from the tool")
        _digest(value.get("executable_sha256"), "runtime executable digest")
        _positive(
            value.get("executable_bytes"),
            "runtime executable byte count",
            MAX_LOCAL_EXECUTABLE_BYTES,
        )
    else:
        if command != ["python-importlib-metadata", "slither-analyzer"]:
            _fail("Slither projection is not the managed guest CLI distribution")
        if (
            value.get("interpreter_implementation") != "CPython"
            or not str(value.get("interpreter_version") or "").startswith("3.12.")
        ):
            _fail("Slither requires managed guest CPython 3.12")
        for field in (
            "interpreter_sha256", "distribution_files_sha256",
            "distribution_path_set_sha256", "record_member_files_sha256",
            "record_member_path_set_sha256", "record_sha256",
            "record_normalized_rows_sha256", "module_sha256",
        ):
            _digest(value.get(field), f"Slither {field}")
        for field, maximum in (
            ("interpreter_bytes", MAX_LOCAL_EXECUTABLE_BYTES),
            ("distribution_file_count", MAX_DISTRIBUTION_FILES),
            ("distribution_bytes", MAX_DISTRIBUTION_BYTES),
            ("record_member_file_count", MAX_DISTRIBUTION_FILES),
            ("record_member_native_identity_count", MAX_DISTRIBUTION_FILES),
            ("record_member_bytes", MAX_DISTRIBUTION_BYTES),
            ("record_bytes", MAX_LOCAL_EXECUTABLE_BYTES),
            ("record_row_count", MAX_DISTRIBUTION_FILES),
        ):
            _positive(value.get(field), f"Slither {field}", maximum)
        if "managed_generation_binding_sha256" in value:
            _digest(
                value.get("managed_generation_binding_sha256"),
                "Slither managed generation binding",
            )
            _digest(value.get("entrypoint_sha256"), "Slither entrypoint digest")
            _positive(
                value.get("entrypoint_bytes"),
                "Slither entrypoint byte count",
                MAX_LOCAL_EXECUTABLE_BYTES,
            )
            entrypoint = value.get("entrypoint_path")
            if type(entrypoint) is not str or not os.path.isabs(entrypoint):
                _fail("Slither managed entrypoint path is not absolute")
    return value


def validate_snapshot_bound_local_tool_projection(
    raw: bytes,
    tool_id: str,
    controls: ToolchainControls,
) -> dict[str, Any]:
    """Validate one snapshot projection without granting launch authority.

    The returned dictionary is ordinary data.  Production execution still
    requires :func:`build_snapshot_bound_tool_execution_plan` followed by an
    authenticated native custody capability.  This narrow public decoder lets
    the EVM workspace bind the exact snapshot bytes to its run-scoped POSIX
    session without reaching through this module's private validation API.
    """

    return dict(_validate_projection(raw, tool_id, controls))


_LINEAGE_KEYS = {
    "schema", "lineage_id", "build_system", "source_snapshot",
    "private_source_projection", "dependencies", "compiler", "guest_mount",
    "native_materialization_terminal",
}


def parse_materialization_lineage(raw: bytes) -> dict[str, Any]:
    """Parse typed lineage data; parsing does not grant execution authority."""

    value = _canonical_object(raw, "tool materialization lineage")
    if set(value) != _LINEAGE_KEYS or value.get("schema") != MATERIALIZATION_LINEAGE_SCHEMA:
        _fail("tool materialization lineage schema differs")
    lineage_id = value.get("lineage_id")
    if not isinstance(lineage_id, str) or _SAFE_ID.fullmatch(lineage_id) is None:
        _fail("tool materialization lineage id is invalid")
    if value.get("build_system") not in {"foundry", "hardhat", "unresolved"}:
        _fail("tool materialization build system is invalid")
    exact = (
        ("source_snapshot", "plamen.audit-source-snapshot-binding.v1",
         {"schema", "snapshot_sha256", "source_scope_sha256"}),
        ("private_source_projection", "plamen.private-source-projection.v1",
         {"schema", "lineage_id", "source_snapshot_sha256", "descriptor_sha256", "tree_sha256", "read_only"}),
        ("dependencies", "plamen.evm-dependency-materialization-native.v1",
         {"schema", "lineage_id", "build_system", "provider_receipt_schema", "provider_receipt_sha256", "closure_sha256", "complete"}),
        ("compiler", "plamen.solc-materialization-native.v1",
         {"schema", "lineage_id", "provider_receipt_schema", "provider_receipt_sha256", "version", "artifact_sha256", "artifact_bytes", "complete"}),
        ("guest_mount", "plamen.guest-read-only-mount.v1",
         {"schema", "lineage_id", "mount_id", "guest_path", "source_projection_sha256", "read_only"}),
        ("native_materialization_terminal", "plamen.native-materialization-terminal.v1",
         {"schema", "lineage_id", "request_sha256", "terminal_sha256", "complete"}),
    )
    for name, schema, keys in exact:
        row = value.get(name)
        if not isinstance(row, dict) or set(row) != keys or row.get("schema") != schema:
            _fail(f"typed materialization {name} schema differs")
        for key, item in row.items():
            if key.endswith("sha256"):
                _digest(item, f"materialization {name}.{key}")
        if "lineage_id" in row and row["lineage_id"] != lineage_id:
            _fail(f"materialization {name} belongs to another lineage")
    source = value["source_snapshot"]
    projection = value["private_source_projection"]
    dependencies = value["dependencies"]
    compiler = value["compiler"]
    mount = value["guest_mount"]
    terminal = value["native_materialization_terminal"]
    dependency_schema_by_build = {
        "foundry": "plamen.foundry-dependency-materialization-native-result.v1",
        "hardhat": "plamen.js-dependency-materialization-receipt.v2",
        "unresolved": "plamen.no-dependency-materialization-native-result.v1",
    }
    materialization_request = {
        "schema": NATIVE_MATERIALIZATION_REQUEST_SCHEMA,
        "lineage_id": lineage_id,
        "build_system": value["build_system"],
        "source_snapshot": source,
        "private_source_projection": projection,
        "dependencies": dependencies,
        "compiler": compiler,
        "guest_mount": mount,
    }
    if (
        source["snapshot_sha256"] != source["source_scope_sha256"]
        or
        projection["source_snapshot_sha256"] != source["snapshot_sha256"]
        or mount["source_projection_sha256"] != projection["tree_sha256"]
        or projection["read_only"] is not True
        or mount["read_only"] is not True
        or dependencies["build_system"] != value["build_system"]
        or dependencies["provider_receipt_schema"]
        != dependency_schema_by_build[value["build_system"]]
        or compiler["provider_receipt_schema"]
        != "plamen.managed-evm-python-native-admission.v1"
        or compiler["version"] != "0.8.26"
        or mount["mount_id"] != "project"
        or mount["guest_path"] != "/workspace/project"
        or dependencies["complete"] is not True
        or compiler["complete"] is not True
        or terminal["complete"] is not True
        or terminal["request_sha256"] != _sha(_canonical(materialization_request))
    ):
        _fail("typed dependency/compiler/source materialization lineage differs")
    _positive(compiler["artifact_bytes"], "materialized solc bytes", MAX_LOCAL_EXECUTABLE_BYTES)
    return value


def _reject_aliases_and_unsafe_ancestry(path: Path, label: str) -> None:
    cursor = path
    trusted_uids = {0, int(os.geteuid())} if os.name != "nt" else set()
    while True:
        try:
            info = cursor.lstat()
        except OSError as exc:
            _fail(f"{label} ancestry is unreadable", exc)
        reparse = bool(
            int(getattr(info, "st_file_attributes", 0))
            & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        )
        if stat.S_ISLNK(info.st_mode) or reparse:
            _fail(f"{label} has a link/reparse ancestor")
        if os.name != "nt" and (
            int(info.st_uid) not in trusted_uids or int(info.st_mode) & 0o022
        ):
            _fail(f"{label} has untrusted owner or writable ancestry")
        parent = cursor.parent
        if parent == cursor:
            return
        cursor = parent


def _reject_case_alias(path: Path, label: str) -> None:
    if unicodedata.normalize("NFC", os.fspath(path)) != os.fspath(path):
        _fail(f"{label} path is not NFC-normalized")
    try:
        siblings = [name for name in os.listdir(path.parent) if name.casefold() == path.name.casefold()]
    except OSError as exc:
        _fail(f"{label} parent cannot be enumerated", exc)
    if siblings != [path.name]:
        _fail(f"{label} path has a case or normalization alias")


def _descriptor_hash(fd: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = os.pread(fd, min(1024 * 1024, size - offset), offset)
        if not block:
            _fail("source descriptor became short during capture")
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev), int(info.st_ino), int(info.st_mode), int(info.st_nlink),
        int(info.st_uid), int(info.st_gid), int(info.st_size),
        int(info.st_mtime_ns), int(info.st_ctime_ns),
    )


def _tree_rows(
    fd: int,
    *,
    depth: int = 0,
    prefix: str = "",
    budget: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    if budget is None:
        budget = {"members": 0, "files": 0, "bytes": 0}
    if depth > MAX_DISTRIBUTION_DEPTH:
        _fail("Slither distribution exceeds the directory depth bound")
    try:
        names = os.listdir(fd)
    except OSError as exc:
        _fail("Slither distribution descriptor cannot be enumerated", exc)
    if names != sorted(names, key=lambda item: item.encode("utf-8")):
        names = sorted(names, key=lambda item: item.encode("utf-8"))
    if len({name.casefold() for name in names}) != len(names):
        _fail("Slither distribution has case-colliding members")
    rows: list[dict[str, Any]] = []
    for name in names:
        if (
            not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or unicodedata.normalize("NFC", name) != name
        ):
            _fail("Slither distribution has an unsafe member name")
        relative = f"{prefix}/{name}" if prefix else name
        before_link = os.stat(name, dir_fd=fd, follow_symlinks=False)
        budget["members"] += 1
        if budget["members"] > MAX_DISTRIBUTION_FILES:
            _fail("Slither distribution exceeds the member bound")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        if stat.S_ISDIR(before_link.st_mode):
            child = os.open(name, flags | getattr(os, "O_DIRECTORY", 0), dir_fd=fd)
            try:
                opened = os.fstat(child)
                if _stat_identity(before_link) != _stat_identity(opened):
                    _fail("Slither directory identity changed during capture")
                rows.append({"path": relative, "kind": "directory", "mode": stat.S_IMODE(opened.st_mode)})
                rows.extend(
                    _tree_rows(
                        child,
                        depth=depth + 1,
                        prefix=relative,
                        budget=budget,
                    )
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(before_link.st_mode):
            candidate_size = int(before_link.st_size)
            budget["files"] += 1
            if (
                budget["files"] > MAX_DISTRIBUTION_FILES
                or candidate_size > MAX_LOCAL_EXECUTABLE_BYTES
                or budget["bytes"] + candidate_size > MAX_DISTRIBUTION_BYTES
            ):
                _fail("Slither distribution exceeds the file/byte bound")
            budget["bytes"] += candidate_size
            child = os.open(name, flags, dir_fd=fd)
            try:
                opened = os.fstat(child)
                if (
                    _stat_identity(before_link) != _stat_identity(opened)
                    or int(opened.st_nlink) != 1
                    or int(opened.st_size) > MAX_LOCAL_EXECUTABLE_BYTES
                ):
                    _fail("Slither file has unstable or aliased identity")
                digest = _descriptor_hash(child, int(opened.st_size))
                after = os.fstat(child)
                if _stat_identity(opened) != _stat_identity(after):
                    _fail("Slither file changed during capture")
                rows.append({
                    "path": relative, "kind": "file", "mode": stat.S_IMODE(after.st_mode),
                    "size": int(after.st_size), "sha256": digest,
                })
            finally:
                os.close(child)
        else:
            _fail("Slither distribution contains a link or special member")
    return rows


def _fold_tree_files(rows: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    """Use the audit-snapshot Python-distribution fold, excluding directories."""

    content = hashlib.sha256()
    paths = hashlib.sha256()
    for row in rows:
        if row["kind"] != "file":
            continue
        encoded = str(row["path"]).encode("utf-8")
        size = int(row["size"])
        paths.update(len(encoded).to_bytes(8, "big"))
        paths.update(encoded)
        content.update(len(encoded).to_bytes(8, "big"))
        content.update(encoded)
        content.update(bytes.fromhex(str(row["sha256"])))
        content.update(size.to_bytes(8, "big"))
    return content.hexdigest(), paths.hexdigest()


def _open_source(path: Path, *, project_root: Path, directory: bool) -> tuple[int, dict[str, Any]]:
    raw = os.fspath(path)
    candidate = Path(os.path.abspath(raw))
    if not path.is_absolute() or raw != os.path.normpath(raw) or raw != os.fspath(candidate):
        _fail("source path is not exact absolute canonical spelling")
    target = Path(project_root).resolve(strict=True)
    _reject_aliases_and_unsafe_ancestry(candidate, "tool source")
    _reject_case_alias(candidate, "tool source")
    try:
        if os.path.commonpath((candidate, target)) == os.fspath(target):
            _fail("tool source resolves inside the audit target")
    except ValueError:
        pass
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    fd = os.open(candidate, flags)
    os.set_inheritable(fd, False)
    try:
        info = os.fstat(fd)
        if (
            directory != stat.S_ISDIR(info.st_mode)
            or int(info.st_nlink) < 1
            or (not directory and int(info.st_nlink) != 1)
        ):
            _fail("tool source descriptor type or hardlink identity differs")
        base = {
            "schema": SOURCE_DESCRIPTOR_SCHEMA,
            "platform": _real_platform_id(),
            "path": raw,
            "path_utf8_sha256": _sha(raw.encode("utf-8")),
            "device": int(info.st_dev), "inode": int(info.st_ino),
            "owner_uid": int(info.st_uid), "owner_gid": int(info.st_gid),
            "mode": stat.S_IMODE(info.st_mode), "link_count": int(info.st_nlink),
            "kind": "directory" if directory else "file",
        }
        if directory:
            before = _stat_identity(info)
            budget = {"members": 0, "files": 0, "bytes": 0}
            rows = _tree_rows(fd, budget=budget)
            after = os.fstat(fd)
            if _stat_identity(info) != _stat_identity(after):
                _fail("Slither distribution root changed during capture")
            files = [row for row in rows if row["kind"] == "file"]
            total = budget["bytes"]
            if (
                before != _stat_identity(after)
                or len(rows) != budget["members"]
                or len(files) != budget["files"]
                or total > MAX_DISTRIBUTION_BYTES
            ):
                _fail("Slither physical distribution closure exceeds bounds")
            content_sha256, path_set_sha256 = _fold_tree_files(rows)
            base.update({
                "tree_rows_sha256": _sha(_canonical(rows)),
                "tree_files_sha256": content_sha256,
                "tree_path_set_sha256": path_set_sha256,
                "tree_member_count": len(rows),
                "tree_file_count": len(files), "tree_bytes": total,
            })
        else:
            size = _positive(
                int(info.st_size), "tool source bytes", MAX_LOCAL_EXECUTABLE_BYTES
            )
            digest = _descriptor_hash(fd, size)
            after = os.fstat(fd)
            if _stat_identity(info) != _stat_identity(after):
                _fail("tool source changed during descriptor capture")
            base.update({"size": size, "sha256": digest})
        base["descriptor_sha256"] = _sha(_canonical(base))
        return fd, base
    except BaseException:
        os.close(fd)
        raise


def _sealed_command_analysis_source(
    *,
    state_root: Path,
    project_root: Path,
    tool_id: str,
    audit_snapshot_sha256: str,
    source_scope_sha256: str,
    snapshot_projection_sha256: str,
) -> Path:
    """Materialize one immutable, no-link analysis-input receipt directory.

    Forge/Solc executable authority comes from the snapshot projection and the
    authenticated image member, never from this directory.  This separate
    source role prevents an ambient/symlink-heavy ``bin`` parent from becoming
    analysis input while retaining one uniform directory-mount ABI.
    """

    payload = _canonical({
        "audit_snapshot_sha256": _digest(
            audit_snapshot_sha256, "sealed analysis audit snapshot"
        ),
        "schema": "plamen.snapshot-tool-analysis-input.v1",
        "snapshot_projection_sha256": _digest(
            snapshot_projection_sha256, "sealed analysis projection"
        ),
        "source_scope_sha256": _digest(
            source_scope_sha256, "sealed analysis source scope"
        ),
        "tool_id": tool_id,
    })
    leaf_name = _sha(payload)
    parent = Path(state_root).resolve(strict=True).parent
    try:
        if os.path.commonpath((parent, Path(project_root).resolve(strict=True))) == os.fspath(
            Path(project_root).resolve(strict=True)
        ):
            _fail("sealed command analysis source would be inside the audit target")
    except ValueError:
        pass
    root = parent / ".plamen-command-analysis-input-v1"
    root.mkdir(mode=0o700, exist_ok=True)
    root_info = root.lstat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or (os.name != "nt" and (
            int(root_info.st_uid) != int(os.geteuid())
            or stat.S_IMODE(root_info.st_mode) & 0o077
        ))
    ):
        _fail("sealed command analysis source root is unsafe")
    leaf = root / leaf_name
    if not leaf.exists():
        staging = Path(tempfile.mkdtemp(prefix=f".{leaf_name}.", dir=root))
        try:
            manifest = staging / "source-binding.json"
            descriptor = os.open(
                manifest,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                if os.write(descriptor, payload) != len(payload):
                    _fail("sealed command analysis source write was short")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            manifest.chmod(0o444)
            staging.chmod(0o555)
            try:
                os.rename(staging, leaf)
            except OSError as exc:
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                staging.chmod(0o700)
                manifest.unlink()
                staging.rmdir()
        except BaseException:
            try:
                staging.chmod(0o700)
            except OSError:
                pass
            try:
                (staging / "source-binding.json").unlink()
            except OSError:
                pass
            try:
                staging.rmdir()
            except OSError:
                pass
            raise
    manifest = leaf / "source-binding.json"
    try:
        leaf_info = leaf.lstat()
        manifest_info = manifest.lstat()
        descriptor = os.open(
            manifest,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            observed = os.pread(descriptor, len(payload) + 1, 0)
        finally:
            os.close(descriptor)
    except OSError as exc:
        _fail("sealed command analysis source is unavailable", exc)
    if (
        not stat.S_ISDIR(leaf_info.st_mode)
        or stat.S_IMODE(leaf_info.st_mode) != 0o555
        or not stat.S_ISREG(manifest_info.st_mode)
        or int(manifest_info.st_nlink) != 1
        or stat.S_IMODE(manifest_info.st_mode) != 0o444
        or observed != payload
    ):
        _fail("sealed command analysis source differs from its binding")
    return leaf


def _installed_opengrep_rule_authority(
    implementation_root: Path,
) -> tuple[Path, str]:
    """Replay the code-pinned installed rule package without consulting Git."""

    try:
        from opengrep_rule_authority import (
            EXPECTED_RULE_AUTHORITY_SHA256,
            validate_installed_rule_authority,
        )
        base = (Path(implementation_root) / "opengrep-rules").resolve(strict=True)
        available = validate_installed_rule_authority(base)
    except Exception as exc:
        _fail("reviewed OpenGrep rule package is unavailable", exc)
    if not available or not isinstance(EXPECTED_RULE_AUTHORITY_SHA256, str):
        _fail("reviewed OpenGrep rule package has no admitted trees")
    _digest(EXPECTED_RULE_AUTHORITY_SHA256, "OpenGrep release authority digest")
    return base, EXPECTED_RULE_AUTHORITY_SHA256


def issue_reviewed_opengrep_rule_input_authority(
    *, implementation_root: Path, project_root: Path
) -> ReviewedAnalysisInputAuthority:
    """Issue an opaque authority for the exact installed OpenGrep rule tree."""

    implementation = Path(implementation_root).expanduser().resolve(strict=True)
    project = Path(project_root).expanduser().resolve(strict=True)
    source, release_sha256 = _installed_opengrep_rule_authority(implementation)
    fd = -1
    try:
        fd, descriptor = _open_source(
            source, project_root=project, directory=True
        )
    finally:
        if fd >= 0:
            os.close(fd)
    authority = object.__new__(ReviewedAnalysisInputAuthority)
    object.__setattr__(authority, "_kind", "opengrep-rule-tree")
    object.__setattr__(authority, "_implementation_root", os.fspath(implementation))
    object.__setattr__(authority, "_project_root", os.fspath(project))
    object.__setattr__(authority, "_source_path", os.fspath(source))
    object.__setattr__(authority, "_source_descriptor", _plain(descriptor))
    object.__setattr__(
        authority, "_release_authority_sha256", release_sha256
    )
    binding = (
        authority._kind,
        authority._implementation_root,
        authority._project_root,
        authority._source_path,
        _sha(_canonical(authority._source_descriptor)),
        authority._release_authority_sha256,
    )
    _LIVE_REVIEWED_ANALYSIS_INPUTS[authority] = binding
    _require_reviewed_opengrep_rule_input_authority(
        authority, project_root=project
    )
    return authority


def _require_reviewed_opengrep_rule_input_authority(
    authority: object, *, project_root: Path
) -> tuple[Path, dict[str, Any]]:
    if (
        type(authority) is not ReviewedAnalysisInputAuthority
        or authority not in _LIVE_REVIEWED_ANALYSIS_INPUTS
    ):
        _fail("reviewed OpenGrep analysis-input authority is forged or expired")
    try:
        observed = (
            authority._kind,
            authority._implementation_root,
            authority._project_root,
            authority._source_path,
            _sha(_canonical(authority._source_descriptor)),
            authority._release_authority_sha256,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        _fail("reviewed OpenGrep analysis-input authority is malformed", exc)
    if _LIVE_REVIEWED_ANALYSIS_INPUTS.get(authority) != observed:
        _fail("reviewed OpenGrep analysis-input authority changed")
    project = Path(project_root).expanduser().resolve(strict=True)
    if authority._kind != "opengrep-rule-tree" or os.fspath(project) != authority._project_root:
        _fail("reviewed OpenGrep analysis input belongs to another project")
    source, release_sha256 = _installed_opengrep_rule_authority(
        Path(authority._implementation_root)
    )
    if (
        os.fspath(source) != authority._source_path
        or release_sha256 != authority._release_authority_sha256
    ):
        _fail("reviewed OpenGrep release authority changed after issuance")
    fd = -1
    try:
        fd, descriptor = _open_source(
            source, project_root=project, directory=True
        )
    finally:
        if fd >= 0:
            os.close(fd)
    if descriptor != authority._source_descriptor:
        _fail("reviewed OpenGrep rule tree changed after issuance")
    return source, descriptor


def _require_managed_slither_input_authority(
    authority: object, *, project_root: Path
) -> tuple[Path, dict[str, Any], Mapping[str, Any]]:
    """Replay the opaque managed generation before every native plan."""

    try:
        import managed_evm_python_toolchain as managed
        binding = managed.require_managed_evm_generation_authority(authority)
    except Exception as exc:
        _fail("managed Slither generation authority is unavailable", exc)
    source = Path(str(binding["generation_absolute_path"]))
    fd = -1
    try:
        fd, descriptor = _open_source(
            source, project_root=Path(project_root), directory=True
        )
    finally:
        if fd >= 0:
            os.close(fd)
    if (
        descriptor.get("device") != binding.get("generation_device")
        or descriptor.get("inode") != binding.get("generation_inode")
        or format(int(descriptor.get("mode", -1)), "04o")
        != binding.get("generation_mode_octal")
    ):
        _fail("managed Slither generation root identity differs")
    return source, descriptor, binding


class SnapshotBoundToolExecutionPlan:
    """Opaque, process-local, one-shot native execution request."""

    __slots__ = (
        "_tool_id", "_source_path", "_source_is_directory",
        "_request_bytes", "_request_sha256", "__weakref__",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> "SnapshotBoundToolExecutionPlan":
        raise TypeError("tool execution plans are issued only after bound validation")

    @property
    def tool_id(self) -> str:
        return self._tool_id

    @property
    def source_path(self) -> str:
        return self._source_path

    @property
    def source_is_directory(self) -> bool:
        return self._source_is_directory

    @property
    def request(self) -> Mapping[str, Any]:
        return _canonical_object(self._request_bytes, "tool execution request")

    @property
    def request_bytes(self) -> bytes:
        return bytes(self._request_bytes)

    @property
    def request_sha256(self) -> str:
        return self._request_sha256

    def __reduce__(self) -> object:
        raise TypeError("tool execution plans are not serializable")


_LIVE_PLANS: weakref.WeakKeyDictionary[
    SnapshotBoundToolExecutionPlan, tuple[str, str, bool, str]
] = weakref.WeakKeyDictionary()
_CONSUMED_PLANS: weakref.WeakSet[SnapshotBoundToolExecutionPlan] = weakref.WeakSet()


def build_snapshot_bound_tool_execution_plan(
    *,
    native_initial_authority: object | None = None,
    native_runtime_authority: object | None = None,
    run_id: str,
    audit_snapshot_sha256: str,
    tool_id: str,
    projection_bytes: bytes,
    snapshot_entry: Mapping[str, Any],
    project_root: Path,
    materialization_lineage_bytes: bytes,
    materialization_lineage_entry: Mapping[str, Any],
    argv: Sequence[str],
    environment: Mapping[str, str],
    cwd: str,
    scratch_root: Path,
    state_root: Path,
    source_scope_sha256: str,
    controls: ToolchainControls,
    source_path: Path | None = None,
    analysis_input_authority: object | None = None,
) -> SnapshotBoundToolExecutionPlan:
    """Build non-authoritative data for one future native execution."""

    if (native_runtime_authority is None) == (native_initial_authority is None):
        _fail("tool plan requires exactly one native runtime authority")
    if native_runtime_authority is not None:
        native_runtime_identity = _native_guest_runtime_identity(
            native_runtime_authority
        )
    else:
        bridge = _native_bridge(native_initial_authority)
        native_runtime_identity = _extension_file_binding(
            bridge, native_initial_authority
        )
    projection = _validate_projection(projection_bytes, tool_id, controls)
    if (
        type(snapshot_entry) is not dict
        or set(snapshot_entry) != {"sha256", "byte_count"}
        or snapshot_entry.get("sha256") != _sha(projection_bytes)
        or snapshot_entry.get("byte_count") != len(projection_bytes)
    ):
        _fail("tool projection differs from the exact audit snapshot entry")
    lineage = parse_materialization_lineage(materialization_lineage_bytes)
    if not isinstance(run_id, str) or _SAFE_ID.fullmatch(run_id) is None:
        _fail("tool execution run id is invalid")
    audit_snapshot_sha256 = _digest(
        audit_snapshot_sha256, "audit snapshot digest"
    )
    if (
        not isinstance(materialization_lineage_entry, Mapping)
        or type(materialization_lineage_entry) is not dict
        or set(materialization_lineage_entry) != {"sha256", "byte_count"}
        or materialization_lineage_entry.get("sha256")
        != _sha(materialization_lineage_bytes)
        or materialization_lineage_entry.get("byte_count")
        != len(materialization_lineage_bytes)
    ):
        _fail("materialization lineage differs from the exact audit snapshot entry")
    if (
        lineage["source_snapshot"]["source_scope_sha256"] != source_scope_sha256
    ):
        _fail("tool materialization belongs to another source scope")
    if type(argv) not in {tuple, list} or not argv or not all(
        type(item) is str and item and "\x00" not in item for item in argv
    ):
        _fail("tool argv is empty or malformed")
    if type(environment) is not dict or not all(
        type(key) is str
        and key
        and "=" not in key
        and "\x00" not in key
        and type(value) is str
        and "\x00" not in value
        for key, value in environment.items()
    ):
        _fail("tool environment is malformed")
    if list(environment) != sorted(environment):
        _fail("tool environment is not canonical")
    if any(
        key in _DENIED_ENVIRONMENT_NAMES
        or key.startswith(_DENIED_ENVIRONMENT_PREFIXES)
        for key in environment
    ):
        _fail("tool environment can alter the admitted executable closure")
    cwd = _guest_path(cwd, "guest cwd")
    expected_project_mount = lineage["guest_mount"]
    project_guest = PurePosixPath(expected_project_mount["guest_path"])
    cwd_guest = PurePosixPath(cwd)
    if cwd_guest != project_guest and project_guest not in cwd_guest.parents:
        _fail("guest cwd is outside the read-only project mount")
    scratch_fd = state_fd = -1
    try:
        scratch_fd, scratch_binding = _directory_fd(
            Path(scratch_root), "tool scratch root"
        )
        state_fd, state_binding = _directory_fd(Path(state_root), "tool state root")
        _require_disjoint_execution_roots(
            Path(project_root), Path(scratch_root), Path(state_root),
            scratch_binding, state_binding,
        )
    finally:
        for descriptor in (state_fd, scratch_fd):
            if descriptor >= 0:
                os.close(descriptor)
    mount_rows = [
        {
            "mount_id": "project",
            "guest_path": "/workspace/project",
            "mode": "READ_ONLY",
            "source_sha256": expected_project_mount["source_projection_sha256"],
        },
        {
            "mount_id": "scratch",
            "guest_path": "/workspace/scratch",
            "mode": "READ_WRITE_EXCLUSIVE",
            "source_sha256": scratch_binding["descriptor_sha256"],
        },
        {
            "mount_id": "state",
            "guest_path": "/workspace/state",
            "mode": "READ_WRITE_EXCLUSIVE",
            "source_sha256": state_binding["descriptor_sha256"],
        },
    ]
    source_is_directory = tool_id in {
        "forge", "opengrep", "semgrep", "slither", "solc",
    }
    admitted_source: dict[str, Any] | None = None
    managed_binding: Mapping[str, Any] | None = None
    command_executable_source: Mapping[str, Any] | None = None
    if tool_id in {"opengrep", "semgrep"}:
        if source_path is not None:
            _fail("OpenGrep input must come from opaque reviewed rule authority")
        selected_source, admitted_source = (
            _require_reviewed_opengrep_rule_input_authority(
                analysis_input_authority, project_root=Path(project_root)
            )
        )
    elif tool_id == "slither":
        if source_path is not None:
            _fail("Slither input must come from opaque managed generation authority")
        selected_source, admitted_source, managed_binding = (
            _require_managed_slither_input_authority(
                analysis_input_authority, project_root=Path(project_root)
            )
        )
    else:
        if analysis_input_authority is not None or source_path is None:
            _fail("command tool source requires one exact source path")
        executable_fd, command_executable_source = _open_source(
            Path(source_path), project_root=Path(project_root), directory=False
        )
        try:
            if (
                command_executable_source["sha256"]
                != projection["executable_sha256"]
                or command_executable_source["size"]
                != projection["executable_bytes"]
                or command_executable_source["path"]
                != projection["resolved_executable"]
            ):
                _fail("command executable descriptor differs from its snapshot")
        finally:
            os.close(executable_fd)
        # The executable remains bound independently by the snapshot projection
        # and authenticated image member.  Never treat its ambient bin parent as
        # source input: it may be broad or symlink-heavy.
        selected_source = _sealed_command_analysis_source(
            state_root=Path(state_root),
            project_root=Path(project_root),
            tool_id=tool_id,
            audit_snapshot_sha256=audit_snapshot_sha256,
            source_scope_sha256=source_scope_sha256,
            snapshot_projection_sha256=_sha(projection_bytes),
        )
    fd, source = _open_source(
        Path(selected_source),
        project_root=Path(project_root),
        directory=source_is_directory,
    )
    try:
        if admitted_source is not None and source != admitted_source:
            _fail("analysis input changed after opaque authority replay")
        if tool_id == "slither" and (
            managed_binding is None
            or projection["resolved_executable"]
            != managed_binding.get("interpreter_absolute_path")
            or projection["interpreter_sha256"]
            != managed_binding.get("interpreter_sha256")
            or projection["version"] != managed_binding.get("slither_version")
            or projection["module_origin"]
            != managed_binding.get("slither_module_origin")
            or projection["module_sha256"]
            != managed_binding.get("slither_module_sha256")
            or projection.get("managed_generation_binding_sha256")
            != managed_binding.get("binding_sha256")
            or projection.get("entrypoint_path")
            != managed_binding.get("slither_entrypoint")
            or projection.get("entrypoint_sha256")
            != managed_binding.get("slither_entrypoint_sha256")
        ):
            _fail("Slither projection differs from its managed generation")
    finally:
        os.close(fd)
    if source_is_directory:
        mount_rows.insert(0, {
            "mount_id": "analysis-input",
            "guest_path": "/workspace/source",
            "mode": "READ_ONLY",
            "source_sha256": source["descriptor_sha256"],
        })
    policy = _policy_for(tool_id, controls)
    request = {
        "schema": EXECUTION_REQUEST_SCHEMA,
        "platform": _real_platform_id(),
        "run_id": run_id,
        "audit_snapshot_sha256": audit_snapshot_sha256,
        "tool_id": tool_id,
        "authority_tier": SNAPSHOT_BOUND_LOCAL,
        "execution_authority": True,
        "authentic_content_authority": False,
        "can_certify_clean": False,
        "evidence_ceiling": EVIDENCE_CEILING,
        "trust_assumption": TRUST_ASSUMPTION,
        "snapshot_projection_sha256": _sha(projection_bytes),
        "snapshot_projection_bytes": len(projection_bytes),
        "toolchain_governance_sha256": policy.governance_sha256,
        "toolchain_version_lock_sha256": policy.version_lock_sha256,
        "materialization_lineage_sha256": _sha(materialization_lineage_bytes),
        "native_runtime_identity": native_runtime_identity,
        "source_descriptor": source,
        "argv": list(argv),
        "environment": dict(environment),
        "cwd": cwd,
        "mounts": mount_rows,
        "source_scope_sha256": _digest(source_scope_sha256, "source scope digest"),
        "build_system": lineage["build_system"],
        "egress_policy": "DENY_ALL",
        "limits": {
            "duration_ms": MAX_TOOL_DURATION_MS,
            "memory_bytes": MAX_TOOL_MEMORY_BYTES,
            "stdout_bytes": MAX_TOOL_STDOUT_BYTES,
            "stderr_bytes": MAX_TOOL_STDERR_BYTES,
            "output_files": MAX_OUTPUT_FILES,
            "output_bytes": MAX_OUTPUT_BYTES,
        },
    }
    request_bytes = _canonical(request)
    plan = object.__new__(SnapshotBoundToolExecutionPlan)
    plan._tool_id = tool_id
    plan._source_path = os.fspath(selected_source)
    plan._source_is_directory = source_is_directory
    plan._request_bytes = request_bytes
    plan._request_sha256 = _sha(request_bytes)
    _LIVE_PLANS[plan] = (
        plan._tool_id,
        plan._source_path,
        plan._source_is_directory,
        plan._request_sha256,
    )
    return plan


def _validate_plan(
    plan: SnapshotBoundToolExecutionPlan, *, require_unconsumed: bool = False
) -> dict[str, Any]:
    if type(plan) is not SnapshotBoundToolExecutionPlan:
        _fail("tool execution plan type differs")
    try:
        binding = _LIVE_PLANS[plan]
        current = (
            plan._tool_id,
            plan._source_path,
            plan._source_is_directory,
            plan._request_sha256,
        )
        request_bytes = bytes(plan._request_bytes)
    except (AttributeError, KeyError, TypeError) as exc:
        _fail("tool execution plan was not issued by this process", exc)
    request = _canonical_object(request_bytes, "tool execution request")
    if (
        binding != current
        or _canonical(request) != request_bytes
        or _sha(request_bytes) != plan._request_sha256
        or request.get("schema") != EXECUTION_REQUEST_SCHEMA
        or request.get("tool_id") != plan._tool_id
        or request.get("platform") != _real_platform_id()
        or _SAFE_ID.fullmatch(str(request.get("run_id") or "")) is None
        or _HEX64.fullmatch(str(request.get("audit_snapshot_sha256") or ""))
        is None
    ):
        _fail("tool execution plan changed after construction")
    if require_unconsumed and plan in _CONSUMED_PLANS:
        _fail("tool execution plan is already consumed")
    return request


def _directory_fd(path: Path, label: str) -> tuple[int, dict[str, Any]]:
    raw = os.fspath(path)
    candidate = Path(os.path.abspath(raw))
    if not path.is_absolute() or raw != os.path.normpath(raw) or raw != os.fspath(candidate):
        _fail(f"{label} path is not exact absolute canonical spelling")
    _reject_aliases_and_unsafe_ancestry(candidate, label)
    _reject_case_alias(candidate, label)
    fd = os.open(
        candidate,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    os.set_inheritable(fd, False)
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o077
        or (os.name != "nt" and int(info.st_uid) != int(os.geteuid()))
    ):
        os.close(fd)
        _fail(f"{label} is not a private owned directory")
    try:
        members = os.listdir(fd)
    except OSError as exc:
        os.close(fd)
        _fail(f"{label} cannot be enumerated", exc)
    after = os.fstat(fd)
    if members or _stat_identity(info) != _stat_identity(after):
        os.close(fd)
        _fail(f"{label} is not a stable empty execution directory")
    binding = {
        "schema": "plamen.private-execution-directory-descriptor.v1",
        "platform": _real_platform_id(),
        "path": raw,
        "path_utf8_sha256": _sha(raw.encode("utf-8")),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "owner_uid": int(info.st_uid),
        "owner_gid": int(info.st_gid),
        "mode": stat.S_IMODE(info.st_mode),
        "link_count": int(info.st_nlink),
    }
    binding["descriptor_sha256"] = _sha(_canonical(binding))
    return fd, binding


def _audited_project_fd(path: Path) -> tuple[int, dict[str, Any]]:
    raw = os.fspath(path)
    candidate = Path(os.path.abspath(raw))
    if not path.is_absolute() or raw != os.path.normpath(raw) or raw != os.fspath(candidate):
        _fail("audited project root path is not exact absolute canonical spelling")
    _reject_aliases_and_unsafe_ancestry(candidate, "audited project root")
    _reject_case_alias(candidate, "audited project root")
    fd = os.open(
        candidate,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    os.set_inheritable(fd, False)
    info = os.fstat(fd)
    after = candidate.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
        or (os.name != "nt" and int(info.st_uid) != int(os.geteuid()))
        or _stat_identity(info) != _stat_identity(after)
    ):
        os.close(fd)
        _fail("audited project root is not a stable owned read-only capability")
    return fd, {
        "path": raw,
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": stat.S_IMODE(info.st_mode),
    }


def _require_disjoint_execution_roots(
    project_root: Path,
    scratch_root: Path,
    state_root: Path,
    scratch_binding: Mapping[str, Any],
    state_binding: Mapping[str, Any],
) -> None:
    try:
        project = Path(project_root).resolve(strict=True)
    except OSError as exc:
        _fail("tool project root cannot be resolved for mount isolation", exc)
    scratch = Path(os.path.abspath(os.fspath(scratch_root)))
    state = Path(os.path.abspath(os.fspath(state_root)))
    if scratch_binding["device"] == state_binding["device"] and (
        scratch_binding["inode"] == state_binding["inode"]
    ):
        _fail("tool scratch and state roots share one physical identity")
    roots = (project, scratch, state)
    if any(
        left == right or left in right.parents or right in left.parents
        for index, left in enumerate(roots)
        for right in roots[index + 1 :]
    ):
        _fail("tool project/scratch/state roots are not disjoint")


def _validate_terminal(raw: bytes, plan: SnapshotBoundToolExecutionPlan) -> dict[str, Any]:
    terminal = _canonical_object(raw, "native tool terminal")
    keys = {
        "schema", "request_sha256", "run_id", "audit_snapshot_sha256",
        "tool_id", "source_descriptor_sha256",
        "materialization_lineage_sha256", "toolchain_governance_sha256",
        "toolchain_version_lock_sha256", "native_runtime_identity_sha256",
        "argv_sha256", "environment_sha256",
        "cwd_sha256", "mounts_sha256", "source_scope_sha256",
        "post_spawn_dynamic_identity_sha256", "egress_policy", "egress_denied",
        "exit_state", "returncode", "duration_ms", "peak_memory_bytes",
        "stdout_sha256", "stdout_observed_bytes", "stdout_retained_bytes",
        "stderr_sha256", "stderr_observed_bytes", "stderr_retained_bytes",
        "output_tree_sha256", "output_file_count", "output_bytes",
        "output_limit_exceeded", "population_zero", "cleanup_complete",
        "truncation_debt",
    }
    request = _validate_plan(plan)
    if set(terminal) != keys or terminal.get("schema") != TERMINAL_SCHEMA:
        _fail("native tool terminal schema differs")
    expected = {
        "request_sha256": plan.request_sha256,
        "run_id": request["run_id"],
        "audit_snapshot_sha256": request["audit_snapshot_sha256"],
        "tool_id": plan.tool_id,
        "source_descriptor_sha256": request["source_descriptor"]["descriptor_sha256"],
        "materialization_lineage_sha256": request["materialization_lineage_sha256"],
        "toolchain_governance_sha256": request["toolchain_governance_sha256"],
        "toolchain_version_lock_sha256": request["toolchain_version_lock_sha256"],
        "native_runtime_identity_sha256": _sha(
            _canonical(request["native_runtime_identity"])
        ),
        "argv_sha256": _sha(_canonical(request["argv"])),
        "environment_sha256": _sha(_canonical(request["environment"])),
        "cwd_sha256": _sha(_canonical(request["cwd"])),
        "mounts_sha256": _sha(_canonical(request["mounts"])),
        "source_scope_sha256": request["source_scope_sha256"],
    }
    if any(terminal.get(key) != value for key, value in expected.items()):
        _fail("native terminal belongs to another execution request")
    for field in (
        "post_spawn_dynamic_identity_sha256", "stdout_sha256", "stderr_sha256",
        "output_tree_sha256",
    ):
        _digest(terminal.get(field), f"terminal {field}")
    duration = _nonnegative(terminal.get("duration_ms"), "tool duration", MAX_TOOL_DURATION_MS)
    memory = _nonnegative(terminal.get("peak_memory_bytes"), "tool memory", MAX_TOOL_MEMORY_BYTES)
    del duration, memory
    stdout_observed = _nonnegative(
        terminal.get("stdout_observed_bytes"), "stdout observed bytes", MAX_TOOL_STDOUT_BYTES
    )
    stdout_retained = _nonnegative(
        terminal.get("stdout_retained_bytes"), "stdout retained bytes", MAX_TOOL_STDOUT_BYTES
    )
    stderr_observed = _nonnegative(
        terminal.get("stderr_observed_bytes"), "stderr observed bytes", MAX_TOOL_STDERR_BYTES
    )
    stderr_retained = _nonnegative(
        terminal.get("stderr_retained_bytes"), "stderr retained bytes", MAX_TOOL_STDERR_BYTES
    )
    if stdout_retained > stdout_observed or stderr_retained > stderr_observed:
        _fail("native terminal retained more stream bytes than it observed")
    _nonnegative(terminal.get("output_file_count"), "tool output files", MAX_OUTPUT_FILES)
    _nonnegative(terminal.get("output_bytes"), "tool output bytes", MAX_OUTPUT_BYTES)
    truncated = stdout_observed != stdout_retained or stderr_observed != stderr_retained
    debt = terminal.get("truncation_debt")
    if truncated:
        if (
            terminal.get("exit_state") != "COMPLETED_WITH_TRUNCATION_DEBT"
            or not isinstance(debt, dict)
            or set(debt) != {"schema", "streams", "findings_complete", "can_certify_clean"}
            or debt.get("schema") != TRUNCATION_DEBT_SCHEMA
            or debt.get("streams")
            != [
                name
                for name, observed, retained in (
                    ("stderr", stderr_observed, stderr_retained),
                    ("stdout", stdout_observed, stdout_retained),
                )
                if observed != retained
            ]
            or debt.get("findings_complete") is not False
            or debt.get("can_certify_clean") is not False
        ):
            _fail("truncated native output lacks exact typed debt")
    elif debt is not None or terminal.get("exit_state") != "COMPLETED":
        _fail("native completion state disagrees with retained output")
    if (
        isinstance(terminal.get("returncode"), bool)
        or terminal.get("returncode") != 0
        or terminal.get("egress_policy") != "DENY_ALL"
        or terminal.get("egress_denied") is not True
        or terminal.get("output_limit_exceeded") is not False
        or terminal.get("population_zero") is not True
        or terminal.get("cleanup_complete") is not True
    ):
        _fail("native terminal lacks bounded execution/extinction authority")
    return terminal


class SnapshotBoundToolExecutionEvidence:
    """Non-authoritative immutable view of a completed native terminal."""

    __slots__ = (
        "_request_bytes", "_terminal_bytes", "_lineage_sha256", "_build_system",
        "__weakref__",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> "SnapshotBoundToolExecutionEvidence":
        raise TypeError("execution evidence is returned only by the native execution path")

    @property
    def tool_id(self) -> str:
        return str(
            _canonical_object(self._terminal_bytes, "native tool terminal")["tool_id"]
        )

    @property
    def lineage_sha256(self) -> str:
        return self._lineage_sha256

    @property
    def findings_complete(self) -> bool:
        terminal = _canonical_object(self._terminal_bytes, "native tool terminal")
        return terminal["truncation_debt"] is None

    def public_receipt(self) -> dict[str, Any]:
        try:
            expected = _LIVE_EVIDENCE[self]
            current = (
                _sha(bytes(self._request_bytes)),
                _sha(bytes(self._terminal_bytes)),
                self._lineage_sha256,
                self._build_system,
            )
        except (AttributeError, KeyError, TypeError) as exc:
            _fail("tool execution evidence was not issued by this process", exc)
        if current != expected:
            _fail("tool execution evidence changed after native completion")
        if self not in _LIVE_EVIDENCE:
            _fail("tool execution evidence was not issued by this process")
        terminal = _canonical_object(self._terminal_bytes, "native tool terminal")
        return {
            "schema": "plamen.snapshot-bound-tool-execution-evidence.v1",
            "evidence_only": True,
            "execution_authority_reusable": False,
            "authority_tier": SNAPSHOT_BOUND_LOCAL,
            "authentic_content_authority": False,
            "can_certify_clean": False,
            "request_sha256": _sha(self._request_bytes),
            "terminal_sha256": _sha(self._terminal_bytes),
            "terminal": terminal,
        }

    def __reduce__(self) -> object:
        raise TypeError("native tool execution evidence is not serializable")


_LIVE_EVIDENCE: weakref.WeakKeyDictionary[
    SnapshotBoundToolExecutionEvidence, tuple[str, str, str, str]
] = weakref.WeakKeyDictionary()


def execute_snapshot_bound_tool(
    plan: SnapshotBoundToolExecutionPlan,
    *,
    native_initial_authority: object | None = None,
    native_custody: object | None = None,
    native_runtime_authority: object | None = None,
    project_root: Path,
    scratch_root: Path,
    state_root: Path,
) -> SnapshotBoundToolExecutionEvidence:
    """Execute exactly once through an authenticated native lease."""

    if native_runtime_authority is not None:
        if native_initial_authority is not None or native_custody is not None:
            _fail("native runtime bundle cannot be mixed with raw custody")
        runtime = _native_guest_runtime_module()
        _native_guest_runtime_identity(native_runtime_authority)
        prepare = runtime.prepare_native_guest_snapshot_tool_execution
        execute = runtime.execute_native_guest_snapshot_tool_execution
        project = runtime.project_native_guest_snapshot_tool_terminal
        bridge = None
        lease_type = terminal_type = None
    else:
        if native_initial_authority is None or native_custody is None:
            _fail("tool execution lacks native runtime authority")
        bridge = _require_native_custody(native_initial_authority, native_custody)
        namespace = types.ModuleType.__getattribute__(bridge, "__dict__")
        prepare = namespace.get("prepare_darwin_tool_execution")
        execute = namespace.get("execute_darwin_tool")
        project = namespace.get("project_darwin_tool_execution_terminal")
        lease_type = namespace.get("DarwinToolExecutionLease")
        terminal_type = namespace.get("DarwinToolExecutionTerminal")
    request = _validate_plan(plan, require_unconsumed=True)
    # Claim before opening any writable execution root or asking the native
    # supervisor to prepare.  Every failure burns the request, so a partial
    # launch can never be retried as though it were fresh.
    _CONSUMED_PLANS.add(plan)
    source_path = plan._source_path
    source_is_directory = plan._source_is_directory
    request_bytes = bytes(plan._request_bytes)
    source_fd = scratch_fd = state_fd = audited_project_fd = -1
    try:
        source_fd, before = _open_source(
            Path(source_path),
            project_root=Path(project_root),
            directory=source_is_directory,
        )
        if before != request["source_descriptor"]:
            _fail("tool source changed before native lease preparation")
        scratch_fd, scratch_binding = _directory_fd(
            Path(scratch_root), "tool scratch root"
        )
        state_fd, state_binding = _directory_fd(Path(state_root), "tool state root")
        audited_project_fd, audited_project_binding = _audited_project_fd(
            Path(project_root)
        )
        _require_disjoint_execution_roots(
            Path(project_root), Path(scratch_root), Path(state_root),
            scratch_binding, state_binding,
        )
        if audited_project_binding["path"] != str(Path(project_root).resolve(strict=True)):
            _fail("audited project root changed before native lease preparation")
        mount_by_id = {row["mount_id"]: row for row in request["mounts"]}
        if (
            mount_by_id["scratch"]["source_sha256"]
            != scratch_binding["descriptor_sha256"]
            or mount_by_id["state"]["source_sha256"]
            != state_binding["descriptor_sha256"]
        ):
            _fail("writable execution root changed after plan construction")
        if native_runtime_authority is not None:
            lease = prepare(
                native_runtime_authority,
                request_bytes,
                source_fd,
                scratch_fd,
                state_fd,
                audited_project_fd,
            )
            terminal = execute(native_runtime_authority, lease)
            terminal_bytes = project(native_runtime_authority, terminal)
        else:
            lease = prepare(
                native_custody,
                request_bytes,
                source_fd,
                scratch_fd,
                state_fd,
                audited_project_fd,
            )
            if type(lease) is not lease_type:
                _fail("native supervisor returned the wrong execution lease type")
            terminal = execute(native_custody, lease)
            if type(terminal) is not terminal_type:
                _fail("native supervisor returned the wrong execution terminal type")
            terminal_bytes = project(terminal)
        if not isinstance(terminal_bytes, bytes):
            _fail("native supervisor returned a non-byte terminal")
        if native_runtime_authority is not None:
            if (
                _native_guest_runtime_module() is not runtime
                or runtime.prepare_native_guest_snapshot_tool_execution is not prepare
                or runtime.execute_native_guest_snapshot_tool_execution is not execute
                or runtime.project_native_guest_snapshot_tool_terminal is not project
            ):
                _fail("native guest runtime bridge changed during launch")
            _native_guest_runtime_identity(native_runtime_authority)
        elif (
            _native_bridge(native_initial_authority) is not bridge
            or types.ModuleType.__getattribute__(bridge, "__dict__").get(
                "prepare_darwin_tool_execution"
            ) is not prepare
            or types.ModuleType.__getattribute__(bridge, "__dict__").get(
                "execute_darwin_tool"
            ) is not execute
            or types.ModuleType.__getattribute__(bridge, "__dict__").get(
                "project_darwin_tool_execution_terminal"
            ) is not project
        ):
            _fail("native execution bridge changed during launch")
        terminal = _validate_terminal(terminal_bytes, plan)
        _rewind = os.lseek(source_fd, 0, os.SEEK_SET) if not source_is_directory else 0
        del _rewind
        _fd, after = _open_source(
            Path(source_path),
            project_root=Path(project_root),
            directory=source_is_directory,
        )
        os.close(_fd)
        if after != before:
            _fail("tool source changed across native execution")
        evidence = object.__new__(SnapshotBoundToolExecutionEvidence)
        evidence._request_bytes = bytes(plan.request_bytes)
        evidence._terminal_bytes = bytes(terminal_bytes)
        evidence._lineage_sha256 = request["materialization_lineage_sha256"]
        evidence._build_system = request["build_system"]
        _LIVE_EVIDENCE[evidence] = (
            _sha(evidence._request_bytes),
            _sha(evidence._terminal_bytes),
            evidence._lineage_sha256,
            evidence._build_system,
        )
        return evidence
    finally:
        for fd in (audited_project_fd, state_fd, scratch_fd, source_fd):
            if fd >= 0:
                os.close(fd)


def execute_snapshot_bound_foundry_evm_suite(
    plans: Mapping[str, SnapshotBoundToolExecutionPlan],
    *,
    native_initial_authority: object,
    project_root: Path,
    scratch_roots: Mapping[str, Path],
    state_roots: Mapping[str, Path],
) -> "SnapshotBoundToolAuthorityBundle":
    """Execute the exact four native Foundry/EVM analysis lanes once.

    This is the production caller for the DODO-shaped Foundry audit lane.  It
    acquires custody itself, admits no caller-provided executor, and refuses to
    start until every lane is bound to one run, audit snapshot, source scope,
    materialization lineage, and disjoint pair of private writable roots.
    """

    if (
        type(plans) is not dict
        or type(scratch_roots) is not dict
        or type(state_roots) is not dict
    ):
        _fail("Foundry EVM suite inputs must be exact plain dictionaries")
    expected = set(_FOUNDRY_EVM_LANES)
    if (
        set(plans) != expected
        or set(scratch_roots) != expected
        or set(state_roots) != expected
    ):
        _fail("Foundry EVM suite requires exact forge/opengrep/slither/solc lanes")

    admitted_plans: list[SnapshotBoundToolExecutionPlan] = []
    common: tuple[str, ...] | None = None
    writable_identities: set[tuple[int, int]] = set()
    writable_paths: list[Path] = []
    concrete_path_type = type(Path())
    if type(project_root) is not concrete_path_type:
        _fail("Foundry EVM suite project root must be one exact native Path")
    project = project_root.resolve(strict=True)
    roots_by_tool: dict[str, tuple[Path, Path]] = {}
    for tool_id in _FOUNDRY_EVM_LANES:
        plan = plans[tool_id]
        request = _validate_plan(plan, require_unconsumed=True)
        current = (
            str(request["run_id"]),
            str(request["audit_snapshot_sha256"]),
            str(request["source_scope_sha256"]),
            str(request["materialization_lineage_sha256"]),
            str(request["build_system"]),
            str(request["platform"]),
            str(request["toolchain_governance_sha256"]),
            str(request["toolchain_version_lock_sha256"]),
            _sha(_canonical(request["native_runtime_identity"])),
        )
        if plan.tool_id != tool_id or request.get("tool_id") != tool_id:
            _fail("Foundry EVM suite plan is assigned to the wrong tool lane")
        if request.get("build_system") != "foundry":
            _fail("Foundry EVM suite contains a non-Foundry materialization")
        if common is None:
            common = current
        elif current != common:
            _fail("Foundry EVM suite plans do not share one snapshot lineage")
        admitted_plans.append(plan)

        lane_roots: list[Path] = []
        for label, root_value in (
            (f"{tool_id} scratch root", scratch_roots[tool_id]),
            (f"{tool_id} state root", state_roots[tool_id]),
        ):
            if type(root_value) is not concrete_path_type:
                _fail("Foundry EVM suite writable root must be one exact native Path")
            fd = -1
            try:
                fd, binding = _directory_fd(root_value, label)
            finally:
                if fd >= 0:
                    os.close(fd)
            identity = (int(binding["device"]), int(binding["inode"]))
            if identity in writable_identities:
                _fail("Foundry EVM suite writable roots share one physical identity")
            writable_identities.add(identity)
            resolved_root = root_value.resolve(strict=True)
            writable_paths.append(resolved_root)
            lane_roots.append(resolved_root)
        roots_by_tool[tool_id] = (lane_roots[0], lane_roots[1])

    all_paths = [project, *writable_paths]
    if any(
        left == right or left in right.parents or right in left.parents
        for index, left in enumerate(all_paths)
        for right in all_paths[index + 1 :]
    ):
        _fail("Foundry EVM suite project and writable roots are not disjoint")

    bridge = _native_bridge(native_initial_authority)
    native_custody = acquire_native_tool_custody(native_initial_authority)
    evidence: list[SnapshotBoundToolExecutionEvidence] = []
    for plan in admitted_plans:
        if _native_bridge(native_initial_authority) is not bridge:
            _fail("native Foundry EVM suite bridge changed between lanes")
        scratch_root, state_root = roots_by_tool[plan.tool_id]
        evidence.append(
            execute_snapshot_bound_tool(
                plan,
                native_initial_authority=native_initial_authority,
                native_custody=native_custody,
                project_root=project,
                scratch_root=scratch_root,
                state_root=state_root,
            )
        )
    return build_snapshot_bound_tool_evidence_bundle(
        evidence, build_system="foundry"
    )


@dataclass(frozen=True)
class ToolSelection:
    tool_id: str
    state: str
    selected_by: str


@dataclass(frozen=True)
class CapabilityGroup:
    capability_id: str
    mode: str
    required_tools: tuple[str, ...]
    selected_tools: tuple[str, ...]
    state: str
    reason: str


class SnapshotBoundToolAuthorityBundle:
    """Evidence bundle; it is never accepted as a future launch capability."""

    __slots__ = ("_receipt_bytes", "__weakref__")

    def __new__(cls, *_args: object, **_kwargs: object) -> "SnapshotBoundToolAuthorityBundle":
        raise TypeError("tool bundles are issued only by one native bundle execution")

    def public_receipt(self) -> dict[str, Any]:
        try:
            expected = _LIVE_BUNDLES[self]
            current = _sha(bytes(self._receipt_bytes))
        except (AttributeError, KeyError, TypeError) as exc:
            _fail("tool evidence bundle was not issued by this process", exc)
        if current != expected:
            _fail("tool evidence bundle changed after construction")
        if self not in _LIVE_BUNDLES:
            _fail("tool evidence bundle was not issued by this process")
        return _canonical_object(
            self._receipt_bytes,
            "tool evidence bundle",
            maximum=MAX_BUNDLE_BYTES,
        )

    def __reduce__(self) -> object:
        raise TypeError("tool evidence bundles are not serializable")


_LIVE_BUNDLES: weakref.WeakKeyDictionary[
    SnapshotBoundToolAuthorityBundle, str
] = weakref.WeakKeyDictionary()


def _capability(
    capability_id: str,
    mode: str,
    tools: Sequence[str],
    admitted: Mapping[str, SnapshotBoundToolExecutionEvidence],
) -> CapabilityGroup:
    available = tuple(tool for tool in tools if tool in admitted)
    bound = len(available) == len(tools) if mode == "ALL_OF" else bool(available)
    return CapabilityGroup(
        capability_id, mode, tuple(tools),
        available if mode == "ALL_OF" else available[:1],
        "BOUND" if bound else "UNAVAILABLE",
        "" if bound else f"{mode} native tool execution is unavailable",
    )


def build_snapshot_bound_tool_evidence_bundle(
    evidence: Sequence[SnapshotBoundToolExecutionEvidence], *, build_system: str
) -> SnapshotBoundToolAuthorityBundle:
    """Internal post-execution evidence grouping; never an execution issuer."""

    if build_system not in {"foundry", "hardhat", "unresolved"}:
        _fail("bundle build system differs")
    admitted: dict[str, SnapshotBoundToolExecutionEvidence] = {}
    lineage: str | None = None
    for row in evidence:
        if type(row) is not SnapshotBoundToolExecutionEvidence or row not in _LIVE_EVIDENCE:
            _fail("bundle contains non-native evidence")
        receipt = row.public_receipt()
        if receipt["request_sha256"] != _sha(row._request_bytes):
            _fail("bundle evidence request changed")
        if row.tool_id in admitted:
            _fail("bundle contains duplicate tool evidence")
        if lineage is None:
            lineage = row.lineage_sha256
        elif lineage != row.lineage_sha256:
            _fail("all tool/project/dependency/compiler evidence must share one lineage")
        if row._build_system != build_system:
            _fail("bundle build system differs from native materialization lineage")
        admitted[row.tool_id] = row
    selections: list[ToolSelection] = []
    for tool in _TOOL_IDS:
        if tool == "semgrep" and "opengrep" in admitted:
            state, selected_by = ("SUPERSEDED" if tool in admitted else "NOT_SELECTED"), "opengrep"
        elif tool == "opengrep" and tool in admitted:
            state, selected_by = "SELECTED", "static-pattern"
        elif tool == "semgrep" and tool in admitted:
            state, selected_by = "SELECTED", "static-pattern"
        elif tool == "forge" and build_system != "foundry":
            state, selected_by = "NOT_SELECTED", f"{build_system}-project-build"
        else:
            state, selected_by = ("SELECTED" if tool in admitted else "UNAVAILABLE"), tool
        selections.append(ToolSelection(tool, state, selected_by))
    capabilities = [
        _capability("evm.compiler", "ALL_OF", ("solc",), admitted),
        _capability("evm.precise-graph", "ALL_OF", ("slither", "solc"), admitted),
        _capability("evm.static-pattern", "ONE_OF", ("opengrep", "semgrep"), admitted),
    ]
    if build_system == "foundry":
        capabilities.append(_capability("evm.project-build", "ALL_OF", ("forge", "solc"), admitted))
    elif build_system == "hardhat":
        capabilities.append(CapabilityGroup(
            "evm.project-build", "ALL_OF", ("node", "package-manager", "hardhat"), (),
            "UNAVAILABLE", "Hardhat requires the separately authenticated JS execution bundle",
        ))
    receipt = {
        "schema": BUNDLE_SCHEMA,
        "evidence_only": True,
        "execution_authority_reusable": False,
        "authority_tier": SNAPSHOT_BOUND_LOCAL,
        "authentic_content_authority": False,
        "can_certify_clean": False,
        "materialization_lineage_sha256": lineage or "",
        "build_system": build_system,
        "tool_evidence": [admitted[key].public_receipt() for key in sorted(admitted)],
        "tool_selections": [row.__dict__ for row in selections],
        "capability_groups": [
            {"schema": CAPABILITY_SCHEMA, **row.__dict__} for row in capabilities
        ],
        # Local heuristic tools can establish that their retained streams are
        # whole, never that the audit's finding denominator is complete.
        "captured_streams_complete": bool(admitted)
        and all(row.findings_complete for row in admitted.values()),
        "findings_complete": False,
    }
    receipt["bundle_sha256"] = _sha(_canonical(receipt))
    bundle = object.__new__(SnapshotBoundToolAuthorityBundle)
    bundle._receipt_bytes = _canonical(receipt)
    if len(bundle._receipt_bytes) > MAX_BUNDLE_BYTES:
        _fail("tool evidence bundle exceeds its byte bound")
    _LIVE_BUNDLES[bundle] = _sha(bundle._receipt_bytes)
    return bundle


__all__ = [
    "BUNDLE_SCHEMA", "CAPABILITY_SCHEMA", "EXECUTION_REQUEST_SCHEMA",
    "MATERIALIZATION_LINEAGE_SCHEMA", "NATIVE_MATERIALIZATION_REQUEST_SCHEMA",
    "SOURCE_DESCRIPTOR_SCHEMA", "TERMINAL_SCHEMA",
    "TRUNCATION_DEBT_SCHEMA", "CapabilityGroup", "NativeToolCustodyUnavailable",
    "SnapshotBoundToolAuthorityBundle", "SnapshotBoundToolAuthorityError",
    "SnapshotBoundToolExecutionEvidence", "SnapshotBoundToolExecutionPlan",
    "ReviewedAnalysisInputAuthority",
    "ToolSelection", "acquire_native_tool_custody",
    "build_snapshot_bound_tool_evidence_bundle",
    "build_snapshot_bound_tool_execution_plan", "execute_snapshot_bound_tool",
    "execute_snapshot_bound_foundry_evm_suite",
    "native_tool_custody_status", "parse_materialization_lineage",
    "issue_reviewed_opengrep_rule_input_authority",
    "validate_snapshot_bound_local_tool_projection",
]
