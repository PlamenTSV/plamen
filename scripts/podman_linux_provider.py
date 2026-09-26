#!/usr/bin/env python3
"""Inert, capability-oriented projection for one pinned rootless Podman stack.

The module performs no host inspection, configuration reads, subprocesses, or
network operations when imported. The admission-only native source lives in
``native/linux/plamen_broker_v2_podman_admission.[ch]`` and owns retained
component/package/root/cgroup descriptors. It deliberately grants no lifecycle
capability. The sibling lifecycle source owns the closed state machine and
durable restart journal, but its executor remains hard-stopped until Linux
validation. Later native slices must still own one-shot execution,
mount/cgroup keepers, population-zero cleanup, and recovery reconciliation.
Python objects here are flow tokens, not a secrecy or same-process security
boundary.

Only a closed local-OCI/container lifecycle is expressible. Pull, build, push,
login, remote transports, ambient configuration, and general egress have no
command grammar here.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import math
import os
import platform
import re
import stat
import time
import unicodedata
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Protocol, TypeVar, runtime_checkable


SUPPORTED_PODMAN_VERSION = "6.1.1"
SUPPORTED_CONMON_VERSION = "2.2.1"
SUPPORTED_CRUN_VERSION = "1.28"
SUPPORTED_SHADOW_UTILS_VERSION = "4.18.0"
SUPPORTED_FUSE_OVERLAYFS_VERSION = "1.17"
PROVIDER_SCHEMA = "plamen.podman-linux.provider.v3"
JOURNAL_SCHEMA = "plamen.podman-linux.mutation.v4"
NATIVE_ADMISSION_SCHEMA = "plamen.podman-linux.native-admission.v1"
NATIVE_ADMISSION_STATUS = "ADMISSION_CUSTODY_AND_EXECUTOR_SOURCE_PRESENT"
NATIVE_ADMISSION_LIFECYCLE_AVAILABLE = False
NATIVE_ADMISSION_COMPONENT_ROSTER = (
    ("podman", SUPPORTED_PODMAN_VERSION),
    ("conmon", SUPPORTED_CONMON_VERSION),
    ("crun", SUPPORTED_CRUN_VERSION),
    ("newuidmap", SUPPORTED_SHADOW_UTILS_VERSION),
    ("newgidmap", SUPPORTED_SHADOW_UTILS_VERSION),
    ("fuse-overlayfs", SUPPORTED_FUSE_OVERLAYFS_VERSION),
    ("systemd", "EXACT_NATIVE_PACKAGE_RECEIPT"),
)
NATIVE_LIFECYCLE_SCHEMA = "plamen.podman-linux.native-lifecycle.v1"
NATIVE_LIFECYCLE_STATUS = (
    "NATIVE_DESCRIPTOR_EXECUTOR_AND_DURABLE_RECOVERY_IMPLEMENTED_"
    "LIVE_ROOTLESS_LINUX_RECEIPTS_PENDING"
)
NATIVE_LIFECYCLE_AVAILABLE = False
NATIVE_LIFECYCLE_REQUIRED_RECEIPTS = (
    "compiled-native-identity",
    "native-admission",
    "native-lifecycle",
)

MAX_OUTPUT = 1_048_576
MAX_ARG_BYTES = 32_768
MAX_JSON_DEPTH = 12
MAX_JSON_ITEMS = 8_192
MAX_ENV_ITEMS = 128
MAX_TIMEOUT_SECONDS = 86_400.0

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_IMAGE_RE = re.compile(
    r"^(?P<repo>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+)"
    r"@sha256:(?P<digest>[0-9a-f]{64})$"
)
_NS_NETWORK_RE = re.compile(r"^ns:/proc/self/fd/(?P<fd>[3-9]|[1-9][0-9]{1,2})$")
_FORBIDDEN_ENV = frozenset({
    "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINERS_CONF",
    "CONTAINERS_CONF_OVERRIDE", "CONTAINERS_STORAGE_CONF",
    "CONTAINERS_REGISTRIES_CONF", "REGISTRIES_CONFIG_PATH",
    "REGISTRY_AUTH_FILE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "NO_PROXY", "DOCKER_HOST", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "PYTHONPATH", "PYTHONHOME", "SSH_AUTH_SOCK", "GIT_ASKPASS",
})
_SECRET_PARTS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE", "CREDENTIAL", "AUTH")
_PROTECTED_PATHS = (
    "/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
    "/proc/sched_debug", "/proc/scsi", "/proc/timer_list", "/proc/timer_stats",
    "/sys/firmware", "/sys/fs/cgroup", "/sys/fs/selinux",
    "/sys/devices/virtual/powercap",
)
_EMPTY_XATTR_SHA256 = hashlib.sha256(b"").hexdigest()
_ISOLATED_CONFIG_SHA256 = hashlib.sha256(
    b"containers.conf=/dev/null\nstorage.conf=/dev/null\nregistries.conf=/dev/null\n"
    b"auth=/dev/null\nhooks=empty\nnetworks=empty\nmounts=empty\n"
).hexdigest()


class ProviderError(RuntimeError):
    """A bounded error whose text contains no authority output, paths, or secrets."""


class ContractError(ProviderError): pass
class PreflightError(ProviderError): pass
class AdmissionError(ProviderError): pass
class StateError(ProviderError): pass
class AmbiguousMutationError(ProviderError): pass
class BoundsError(ProviderError): pass


class _JournalRollback(StateError):
    """Internal signal: the reloadable record is older than its durable anchor."""


T = TypeVar("T")


def _sanitized(call: Callable[[], T], error: type[ProviderError], message: str) -> T:
    """Translate untrusted exceptions after leaving the handler (no cause/context)."""
    failed = False
    value: T | None = None
    try:
        value = call()
    except Exception:
        failed = True
    if failed:
        raise error(message)
    return value  # type: ignore[return-value]


def _hash(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _check_json(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if depth > MAX_JSON_DEPTH or count[0] > MAX_JSON_ITEMS:
        raise BoundsError("structured data exceeds bounds")
    if value is None or type(value) in (bool, int, str):
        if type(value) is int and abs(value) > (1 << 63) - 1:
            raise BoundsError("integer exceeds bounds")
        if type(value) is str and ("\x00" in value or len(value.encode("utf-8")) > MAX_OUTPUT):
            raise BoundsError("string exceeds bounds")
        return
    if type(value) is list:
        for item in value:
            _check_json(item, depth + 1, count)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ContractError("object keys must be strings")
            _check_json(key, depth + 1, count)
            _check_json(item, depth + 1, count)
        return
    raise ContractError("unsupported structured value")


def _canonical_json(value: object) -> bytes:
    _check_json(value)
    return _sanitized(
        lambda: json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False).encode("ascii"),
        ContractError, "non-canonical data",
    )


def _authority_document(value: object) -> object:
    """Lossless JSON projection for frozen authority evidence."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _authority_document(getattr(value, field.name))
                for field in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Path):
        return os.fspath(value)
    if type(value) is tuple:
        return [_authority_document(item) for item in value]
    if type(value) is list:
        return [_authority_document(item) for item in value]
    if type(value) is dict:
        return {key: _authority_document(item) for key, item in value.items()}
    return value


def _strict_object(blob: bytes, keys: frozenset[str]) -> dict[str, Any]:
    if type(blob) is not bytes or not blob or len(blob) > MAX_OUTPUT:
        raise ContractError("invalid structured output")

    def decode() -> object:
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            output: dict[str, object] = {}
            for key, item in pairs:
                if key in output:
                    raise ValueError
                output[key] = item
            return output
        return json.loads(blob.decode("utf-8"),
                          parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()),
                          object_pairs_hook=unique)

    value = _sanitized(decode, ContractError, "invalid structured output")
    if type(value) is not dict or frozenset(value) != keys:
        raise ContractError("unexpected structured output schema")
    _check_json(value)
    return value


def _clean_text(value: object, label: str, maximum: int = 256) -> str:
    if type(value) is not str or not value:
        raise ContractError(f"invalid {label}")
    encoded = _sanitized(lambda: value.encode("utf-8"), ContractError, f"invalid {label}")
    if (len(encoded) > maximum or value != unicodedata.normalize("NFC", value)
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ContractError(f"invalid {label}")
    return value


def _decimal(value: object, label: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise BoundsError(f"invalid {label}")
    return value


def _timeout(value: object) -> float:
    if type(value) not in (int, float):
        raise BoundsError("invalid timeout")
    number = _sanitized(lambda: float(value), BoundsError, "invalid timeout")
    if not math.isfinite(number) or not 0.001 <= number <= MAX_TIMEOUT_SECONDS:
        raise BoundsError("invalid timeout")
    return number


def _absolute(path: object, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path == Path("/"):
        raise ContractError(f"invalid {label}")
    raw = os.fspath(path)
    if (raw != unicodedata.normalize("NFC", raw) or "," in raw or "\x00" in raw
            or len(os.fsencode(raw)) > 1024
            or any(part in ("", ".", "..") for part in PurePosixPath(raw).parts[1:])):
        raise ContractError(f"invalid {label}")
    return path


def _path_key(path: Path) -> tuple[str, ...]:
    return tuple(os.path.normcase(unicodedata.normalize("NFKC", part))
                 for part in PurePosixPath(os.fspath(path)).parts)


def _paths_related(left: Path, right: Path) -> bool:
    a, b = _path_key(left), _path_key(right)
    return a[:len(b)] == b or b[:len(a)] == a


def _validated(value: object, error: type[ProviderError], message: str,
               *args: object, **kwargs: object) -> None:
    failed = False
    try:
        getattr(value, "validate")(*args, **kwargs)
    except Exception:
        failed = True
    if failed:
        raise error(message)


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutableIdentity:
    path: Path = dataclasses.field(repr=False)
    device: int
    inode: int
    size: int
    uid: int
    mode: int
    nlink: int
    sha256: str
    component_chain_sha256: str
    xattr_sha256: str

    def validate(self, label: str) -> None:
        if type(self) is not ExecutableIdentity:
            raise PreflightError("invalid executable identity")
        _absolute(self.path, label)
        for value in (self.device, self.inode, self.size, self.uid, self.mode):
            _decimal(value, "executable identity", 0, (1 << 63) - 1)
        # A pathname-pinned digest is not durable executable authority while any
        # host principal can rewrite the inode. Native runners must additionally
        # execute through the held descriptor and recensus content immediately
        # before each invocation.
        if self.nlink != 1 or not stat.S_ISREG(self.mode) or self.mode & 0o222:
            raise PreflightError("unsafe executable identity")
        if any(not _SHA256_RE.fullmatch(value) for value in
               (self.sha256, self.component_chain_sha256, self.xattr_sha256)):
            raise PreflightError("invalid executable digest")
        if self.xattr_sha256 != _EMPTY_XATTR_SHA256:
            raise PreflightError("executable attributes forbidden")


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseProvenance:
    component: str
    version: str
    source_commit_sha256: str
    release_manifest_sha256: str
    signer_key_sha256: str
    binary_sha256: str
    offline_signature_verified: bool

    def validate(self, component: str, version: str, executable: ExecutableIdentity) -> None:
        if type(self) is not ReleaseProvenance or (self.component, self.version) != (component, version):
            raise PreflightError("component release provenance mismatch")
        if any(not _SHA256_RE.fullmatch(value) for value in (
            self.source_commit_sha256, self.release_manifest_sha256,
            self.signer_key_sha256, self.binary_sha256,
        )) or self.binary_sha256 != executable.sha256 or self.offline_signature_verified is not True:
            raise PreflightError("component release provenance incomplete")


@dataclasses.dataclass(frozen=True, slots=True)
class ComponentIdentities:
    podman: ExecutableIdentity
    conmon: ExecutableIdentity
    crun: ExecutableIdentity
    newuidmap: ExecutableIdentity
    newgidmap: ExecutableIdentity
    overlay_helper: ExecutableIdentity
    provenance: tuple[ReleaseProvenance, ...]

    @staticmethod
    def pins() -> tuple[tuple[str, str], ...]:
        return (
            ("podman", SUPPORTED_PODMAN_VERSION),
            ("conmon", SUPPORTED_CONMON_VERSION),
            ("crun", SUPPORTED_CRUN_VERSION),
            ("newuidmap", SUPPORTED_SHADOW_UTILS_VERSION),
            ("newgidmap", SUPPORTED_SHADOW_UTILS_VERSION),
            ("fuse-overlayfs", SUPPORTED_FUSE_OVERLAYFS_VERSION),
        )

    def validate(self) -> None:
        if type(self) is not ComponentIdentities or type(self.provenance) is not tuple or len(self.provenance) != 6:
            raise PreflightError("invalid component roster")
        executables = (self.podman, self.conmon, self.crun, self.newuidmap,
                       self.newgidmap, self.overlay_helper)
        identities: set[tuple[int, int]] = set()
        for (label, version), executable, provenance in zip(
                self.pins(), executables, self.provenance, strict=True):
            _validated(executable, PreflightError, "invalid component executable", label)
            _validated(provenance, PreflightError, "invalid release provenance",
                       label, version, executable)
            identity = (executable.device, executable.inode)
            if identity in identities:
                raise PreflightError("component executable identities collide")
            identities.add(identity)

    @property
    def digest(self) -> str:
        _validated(self, PreflightError, "invalid component identities")
        return _hash(_canonical_json({
            "pins": [list(item) for item in self.pins()],
            "executables": [
                {"path": os.fspath(executable.path), "dev": executable.device,
                 "ino": executable.inode, "sha256": executable.sha256,
                 "chain": executable.component_chain_sha256}
                for executable in (self.podman, self.conmon, self.crun,
                                   self.newuidmap, self.newgidmap, self.overlay_helper)
            ],
            "provenance": [dataclasses.asdict(item) for item in self.provenance],
        }))


@dataclasses.dataclass(frozen=True, slots=True)
class HostFacts:
    system: str
    machine: str
    effective_uid: int
    real_uid: int
    real_gid: int
    rootless: bool
    cgroup_version: str
    cgroup_delegated: bool
    cgroup_kill: bool
    delegated_controllers: tuple[str, ...]
    user_namespaces: bool
    subuid_ranges: int
    subgid_ranges: int
    keep_id_supported: bool
    memory_swap_controller: bool
    fuse_overlayfs_supported: bool
    home_path: Path = dataclasses.field(repr=False)
    credential_roots: tuple[Path, ...] = dataclasses.field(repr=False)

    def validate(self) -> None:
        if type(self) is not HostFacts or self.system != "Linux" or self.machine not in {"x86_64", "aarch64"}:
            raise PreflightError("unsupported host")
        for value in (self.effective_uid, self.real_uid, self.real_gid):
            _decimal(value, "host identity", 1, (1 << 31) - 1)
        if self.effective_uid != self.real_uid or self.rootless is not True:
            raise PreflightError("real nonroot user required")
        if self.cgroup_version != "v2" or self.cgroup_delegated is not True or self.cgroup_kill is not True:
            raise PreflightError("delegated cgroup v2 with cgroup.kill required")
        if self.delegated_controllers != ("cpu", "memory", "pids") or self.memory_swap_controller is not True:
            raise PreflightError("required cgroup controllers unavailable")
        if self.user_namespaces is not True or self.keep_id_supported is not True or self.fuse_overlayfs_supported is not True:
            raise PreflightError("rootless namespace/overlay prerequisites missing")
        _decimal(self.subuid_ranges, "subuid range", 65_536, (1 << 31) - 1)
        _decimal(self.subgid_ranges, "subgid range", 65_536, (1 << 31) - 1)
        _absolute(self.home_path, "host home")
        if type(self.credential_roots) is not tuple or len(self.credential_roots) > 32:
            raise PreflightError("invalid credential roots")
        seen: list[Path] = []
        for root in self.credential_roots:
            _absolute(root, "credential root")
            if any(_paths_related(root, other) for other in seen):
                raise PreflightError("credential roots overlap")
            seen.append(root)

    @property
    def digest(self) -> str:
        _validated(self, PreflightError, "invalid host facts")
        return _hash(_canonical_json({
            "system": self.system, "machine": self.machine,
            "uid": self.real_uid, "gid": self.real_gid,
            "cgroup": [self.cgroup_version, list(self.delegated_controllers)],
            "subids": [self.subuid_ranges, self.subgid_ranges],
            "home": os.fspath(self.home_path),
            "credential_roots": [os.fspath(path) for path in self.credential_roots],
        }))


@dataclasses.dataclass(frozen=True, slots=True)
class ProviderRoots:
    storage: Path
    runroot: Path
    tmp: Path
    home: Path
    runtime_dir: Path
    overlay_root: Path

    def validate(self, host: HostFacts | None = None) -> None:
        if type(self) is not ProviderRoots:
            raise PreflightError("invalid provider roots")
        roots = tuple(_absolute(item, "private provider root") for item in dataclasses.astuple(self))
        for index, left in enumerate(roots):
            for right in roots[index + 1:]:
                if _paths_related(left, right):
                    raise PreflightError("provider roots overlap")
        if host is not None:
            sensitive = (host.home_path,) + host.credential_roots
            if any(_paths_related(root, item) for root in roots for item in sensitive):
                raise PreflightError("provider root overlaps sensitive root")

    @property
    def digest(self) -> str:
        self.validate()
        return _hash(_canonical_json([os.fspath(path) for path in dataclasses.astuple(self)]))


@dataclasses.dataclass(frozen=True, slots=True)
class PathAuthorityContract:
    schema: str
    authority_id: str
    componentwise_nofollow: bool
    keeps_descriptors_open: bool
    verifies_rename_identity: bool
    verifies_tree_snapshot: bool
    rejects_links: bool
    rejects_special_files: bool
    rejects_sockets: bool
    rejects_xattrs: bool
    rejects_sensitive_roots: bool
    verifies_mountinfo: bool
    holds_mount_keeper: bool
    enforces_byte_quotas: bool
    verifies_mapped_ownership: bool
    atomic_artifact_commit: bool
    absent_artifact_slot_admission: bool
    atomic_noreplace_publication: bool
    descriptor_relative_artifact_readback: bool
    fsyncs_artifact_and_parent: bool
    complete_artifact_census: bool
    idempotent_authenticated_release: bool
    bounded_artifact_packaging: bool
    authenticated_artifact_receipts: bool
    reservation_scoped_admission: bool
    idempotent_orphan_cleanup: bool

    def validate(self) -> None:
        if type(self) is not PathAuthorityContract or self.schema != PROVIDER_SCHEMA or not _NAME_RE.fullmatch(self.authority_id):
            raise PreflightError("invalid path authority")
        if any(value is not True for value in dataclasses.astuple(self)[2:]):
            raise PreflightError("path authority property unavailable")


@dataclasses.dataclass(frozen=True, slots=True)
class PathBinding:
    token: str = dataclasses.field(repr=False)
    purpose: str
    source: Path = dataclasses.field(repr=False)
    target: str
    readonly: bool
    kind: str
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    byte_limit: int
    component_chain_sha256: str
    realpath_sha256: str
    snapshot_sha256: str
    xattr_sha256: str
    mount_id: int
    parent_mount_id: int
    filesystem: str
    mount_options_sha256: str
    mapped_uid: int
    mapped_gid: int
    keep_id_writable: bool
    has_symlink: bool
    has_hardlink: bool
    has_special_file: bool
    has_socket: bool
    sensitive_overlap: bool

    def validate(self) -> None:
        if type(self) is not PathBinding or not _SHA256_RE.fullmatch(self.token):
            raise AdmissionError("invalid path binding")
        _absolute(self.source, "bound source")
        _clean_text(self.purpose, "binding purpose", 64)
        if self.target and (not self.target.startswith("/") or ".." in PurePosixPath(self.target).parts or len(self.target) > 256):
            raise AdmissionError("invalid binding target")
        if self.kind not in {"directory", "regular"} or type(self.readonly) is not bool:
            raise AdmissionError("invalid binding kind")
        for value in (self.device, self.inode, self.mode, self.uid, self.gid,
                      self.mount_id, self.parent_mount_id, self.mapped_uid, self.mapped_gid):
            _decimal(value, "binding identity", 0, (1 << 63) - 1)
        _decimal(self.nlink, "binding link count", 1, (1 << 31) - 1)
        _decimal(self.byte_limit, "binding byte limit", 1, 64 * 1024**3)
        _clean_text(self.filesystem, "filesystem", 64)
        if ((self.kind == "regular" and (not stat.S_ISREG(self.mode) or self.nlink != 1))
                or (self.kind == "directory" and not stat.S_ISDIR(self.mode))):
            raise AdmissionError("binding type/link mismatch")
        digests = (self.component_chain_sha256, self.realpath_sha256,
                   self.snapshot_sha256, self.xattr_sha256, self.mount_options_sha256)
        if any(not _SHA256_RE.fullmatch(value) for value in digests):
            raise AdmissionError("invalid binding digest")
        if self.realpath_sha256 != _hash(os.fsencode(os.fspath(self.source))):
            raise AdmissionError("bound canonical path mismatch")
        flags = (self.keep_id_writable, self.has_symlink, self.has_hardlink,
                 self.has_special_file, self.has_socket, self.sensitive_overlap)
        if any(type(value) is not bool for value in flags):
            raise AdmissionError("invalid binding evidence")
        if self.has_symlink or self.has_hardlink or self.has_special_file or self.has_socket or self.sensitive_overlap:
            raise AdmissionError("unsafe bound tree")
        if self.xattr_sha256 != _EMPTY_XATTR_SHA256:
            raise AdmissionError("binding attributes forbidden")

    @property
    def document(self) -> dict[str, object]:
        _validated(self, AdmissionError, "invalid path binding")
        return {
            "token": self.token, "purpose": self.purpose, "source": os.fspath(self.source),
            "target": self.target, "readonly": self.readonly, "kind": self.kind,
            "dev": self.device, "ino": self.inode, "mode": self.mode,
            "uid": self.uid, "gid": self.gid, "nlink": self.nlink,
            "limit": self.byte_limit, "chain": self.component_chain_sha256,
            "realpath": self.realpath_sha256, "snapshot": self.snapshot_sha256,
            "xattr": self.xattr_sha256, "mount_id": self.mount_id,
            "parent_mount_id": self.parent_mount_id, "filesystem": self.filesystem,
            "mount_options": self.mount_options_sha256,
            "mapped_uid": self.mapped_uid, "mapped_gid": self.mapped_gid,
            "keep_id_writable": self.keep_id_writable,
            "has_symlink": self.has_symlink,
            "has_hardlink": self.has_hardlink,
            "has_special_file": self.has_special_file,
            "has_socket": self.has_socket,
            "sensitive_overlap": self.sensitive_overlap,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactDestination:
    """Authority for one absent directory entry, not for a fictional file inode.

    The native authority holds ``parent`` and the exact ``basename``. Publication
    creates a new inode with renameat2(RENAME_NOREPLACE), or a semantically
    equivalent no-replace operation, then reopens that entry relative to the
    still-held parent descriptor.
    """

    schema: str
    authority_id: str
    token: str = dataclasses.field(repr=False)
    path: Path = dataclasses.field(repr=False)
    parent: PathBinding
    basename: str
    byte_limit: int
    mapped_uid: int
    mapped_gid: int
    absent_at_admission: bool
    parent_descriptor_held: bool
    componentwise_nofollow: bool
    authenticated: bool

    def validate(self, contract: "PathAuthorityContract") -> None:
        if (type(self) is not ArtifactDestination
                or self.schema != PROVIDER_SCHEMA
                or self.authority_id != contract.authority_id
                or not _SHA256_RE.fullmatch(self.token)):
            raise AdmissionError("invalid artifact destination authority")
        _absolute(self.path, "artifact destination")
        _validated(self.parent, AdmissionError,
                   "invalid artifact parent binding")
        if (self.parent.source != self.path.parent
                or self.parent.purpose != "export-parent"
                or self.parent.target != "" or self.parent.readonly
                or self.parent.kind != "directory"
                or self.basename != self.path.name
                or not self.basename or self.basename in {".", ".."}
                or "/" in self.basename or "\x00" in self.basename):
            raise AdmissionError("artifact destination slot mismatch")
        _clean_text(self.basename, "artifact basename", 255)
        _decimal(self.byte_limit, "artifact byte limit", 1, 64 * 1024**3)
        for value in (self.mapped_uid, self.mapped_gid):
            _decimal(value, "artifact mapped owner", 0, (1 << 31) - 1)
        if ((self.parent.mapped_uid, self.parent.mapped_gid,
             self.parent.keep_id_writable) !=
                (self.mapped_uid, self.mapped_gid, True)
                or any(value is not True for value in (
                    self.absent_at_admission, self.parent_descriptor_held,
                    self.componentwise_nofollow, self.authenticated))):
            raise AdmissionError("artifact destination is not an absent held slot")

    @property
    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema, "authority": self.authority_id,
            "token": self.token, "path": os.fspath(self.path),
            "parent": self.parent.document, "basename": self.basename,
            "limit": self.byte_limit, "mapped_uid": self.mapped_uid,
            "mapped_gid": self.mapped_gid,
            "absent": self.absent_at_admission,
            "parent_descriptor_held": self.parent_descriptor_held,
            "componentwise_nofollow": self.componentwise_nofollow,
            "authenticated": self.authenticated,
        }

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(self.document))


@dataclasses.dataclass(frozen=True, slots=True)
class OverlayTopology:
    schema: str
    authority_id: str
    lower_token: str
    upper_token: str
    work_token: str
    merged_token: str
    keeper_token: str
    topology_sha256: str
    overlay_mount_id: int
    lower_mount_id: int
    filesystem: str
    mounted: bool
    lower_readonly: bool
    upper_work_same_filesystem: bool
    work_empty_at_mount: bool
    nodev_nosuid: bool
    mapped_uid: int
    mapped_gid: int

    def validate(self, authority: PathAuthorityContract, bindings: tuple[PathBinding, ...], uid: int, gid: int) -> None:
        if type(self) is not OverlayTopology or self.schema != PROVIDER_SCHEMA or self.authority_id != authority.authority_id:
            raise AdmissionError("invalid overlay topology")
        by_purpose = {binding.purpose: binding for binding in bindings}
        if set(by_purpose) < {"project-lower", "project-upper", "project-work", "project-merged"}:
            raise AdmissionError("overlay bindings incomplete")
        expected = tuple(by_purpose[name].token for name in
                         ("project-lower", "project-upper", "project-work", "project-merged"))
        if (self.lower_token, self.upper_token, self.work_token, self.merged_token) != expected:
            raise AdmissionError("overlay binding identity mismatch")
        if not _SHA256_RE.fullmatch(self.keeper_token) or not _SHA256_RE.fullmatch(self.topology_sha256):
            raise AdmissionError("invalid overlay keeper identity")
        _decimal(self.overlay_mount_id, "overlay mount", 1, (1 << 63) - 1)
        _decimal(self.lower_mount_id, "lower mount", 1, (1 << 63) - 1)
        _clean_text(self.filesystem, "overlay filesystem", 64)
        if any(value is not True for value in (self.mounted, self.lower_readonly,
                                                self.upper_work_same_filesystem,
                                                self.work_empty_at_mount, self.nodev_nosuid)):
            raise AdmissionError("unsafe overlay topology")
        if (self.mapped_uid, self.mapped_gid) != (uid, gid):
            raise AdmissionError("overlay mapping mismatch")
        merged = by_purpose["project-merged"]
        upper, work = by_purpose["project-upper"], by_purpose["project-work"]
        if (merged.mount_id != self.overlay_mount_id or upper.filesystem != work.filesystem
                or self.filesystem != merged.filesystem or merged.readonly
                or not by_purpose["project-lower"].readonly):
            raise AdmissionError("overlay semantics mismatch")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactCommit:
    """Authority proof for a complete, atomic post-extinction artifact archive."""

    schema: str
    authority_id: str
    destination_token: str
    binding: PathBinding
    commit_token: str
    attempt_id: str
    manifest_sha256: str
    source_set_sha256: str
    archive_sha256: str
    census_sha256: str
    entry_count: int
    byte_count: int
    committed_monotonic_ns: int
    atomic_no_replace: bool
    destination_was_absent: bool
    temporary_file_fsync: bool
    file_fsync: bool
    parent_fsync: bool
    reopened_after_publish: bool
    descriptor_relative_readback: bool
    complete_census: bool
    regular_files_only: bool
    links_rejected: bool
    authenticated: bool
    archive_format: str
    manifest_embedded: bool
    census_matches_archive: bool
    deterministic_metadata: bool

    def validate(self, contract: PathAuthorityContract,
                 destination: ArtifactDestination,
                 attempt_id: str, manifest_sha256: str,
                 source_set_sha256: str) -> None:
        if (type(self) is not ArtifactCommit or self.schema != PROVIDER_SCHEMA
                or self.authority_id != contract.authority_id):
            raise AdmissionError("invalid artifact commit authority")
        _validated(self.binding, AdmissionError, "invalid artifact binding")
        for digest in (self.destination_token, self.commit_token,
                       self.manifest_sha256,
                       self.source_set_sha256, self.archive_sha256,
                       self.census_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise AdmissionError("invalid artifact commit identity")
        if (self.destination_token != destination.token
                or self.attempt_id != attempt_id
                or self.manifest_sha256 != manifest_sha256
                or self.source_set_sha256 != source_set_sha256
                or self.archive_sha256 != self.binding.snapshot_sha256):
            raise AdmissionError("artifact commit context mismatch")
        # Atomic publication creates a *new* inode. The stable authority is the
        # held parent FD plus basename; requiring the prior file inode to remain
        # unchanged would make atomic rename publication impossible.
        if (self.binding.source != destination.path
                or self.binding.device != destination.parent.device
                or (self.binding.device, self.binding.inode) ==
                   (destination.parent.device, destination.parent.inode)
                or self.binding.purpose != "export" or self.binding.target != ""
                or self.binding.readonly or self.binding.kind != "regular"
                or self.binding.mode != (stat.S_IFREG | 0o600)
                or (self.binding.uid, self.binding.gid) !=
                   (destination.parent.uid, destination.parent.gid)
                or self.binding.byte_limit != destination.byte_limit
                or (self.binding.mapped_uid, self.binding.mapped_gid,
                    self.binding.keep_id_writable) !=
                   (destination.mapped_uid, destination.mapped_gid, True)):
            raise AdmissionError("artifact destination semantics changed")
        _decimal(self.entry_count, "artifact entry count", 1, MAX_JSON_ITEMS)
        _decimal(self.byte_count, "artifact byte count", 1,
                 destination.byte_limit)
        _decimal(self.committed_monotonic_ns, "artifact commit time", 1,
                 (1 << 63) - 1)
        if self.committed_monotonic_ns > time.monotonic_ns():
            raise AdmissionError("artifact commit time is in the future")
        properties = (
            self.atomic_no_replace, self.destination_was_absent,
            self.temporary_file_fsync, self.file_fsync, self.parent_fsync,
            self.reopened_after_publish, self.descriptor_relative_readback,
            self.complete_census, self.regular_files_only,
            self.links_rejected, self.authenticated,
            self.manifest_embedded, self.census_matches_archive,
            self.deterministic_metadata,
        )
        if (self.archive_format != "pax-tar-v1"
                or any(value is not True for value in properties)):
            raise AdmissionError("artifact commit proof incomplete")

    @property
    def digest(self) -> str:
        data = dataclasses.asdict(self)
        data["binding"] = self.binding.document
        return _hash(_canonical_json(data))


@dataclasses.dataclass(frozen=True, slots=True)
class ResourceReleaseReceipt:
    schema: str
    authority_id: str
    kind: str
    resource_token: str
    context_sha256: str
    release_nonce: str
    released_monotonic_ns: int
    released: bool
    extinct: bool
    authenticated: bool
    authentication_sha256: str

    def validate(self, *, authority_id: str, kind: str, token: str,
                 context_sha256: str, release_nonce: str) -> None:
        if (type(self) is not ResourceReleaseReceipt
                or self.schema != PROVIDER_SCHEMA
                or self.authority_id != authority_id
                or self.kind != kind or self.resource_token != token
                or self.context_sha256 != context_sha256
                or self.release_nonce != release_nonce):
            raise StateError("release receipt context mismatch")
        for digest in (self.resource_token, self.context_sha256,
                       self.release_nonce, self.authentication_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise StateError("invalid release receipt identity")
        _decimal(self.released_monotonic_ns, "release observation time", 1,
                 (1 << 63) - 1)
        if any(value is not True for value in
               (self.released, self.extinct, self.authenticated)):
            raise StateError("resource release incomplete")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class AdmissionReservation:
    """Durable intent written before any attempt-scoped resource acquisition."""

    schema: str
    authority_id: str
    attempt_id: str
    base_spec_sha256: str
    token: str
    generation: int
    cleanup_label_sha256: str
    reserved_monotonic_ns: int
    durable: bool
    externally_anchored: bool
    authenticated: bool

    def validate(self, contract: "JournalContract", attempt_id: str,
                 base_spec_sha256: str) -> None:
        if (type(self) is not AdmissionReservation
                or self.schema != JOURNAL_SCHEMA
                or self.authority_id != contract.authority_id
                or self.attempt_id != attempt_id
                or self.base_spec_sha256 != base_spec_sha256):
            raise StateError("admission reservation context mismatch")
        for digest in (self.base_spec_sha256, self.token,
                       self.cleanup_label_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise StateError("invalid admission reservation identity")
        _decimal(self.generation, "admission generation", 1,
                 (1 << 63) - 1)
        _decimal(self.reserved_monotonic_ns, "admission reservation time", 1,
                 (1 << 63) - 1)
        if any(value is not True for value in
               (self.durable, self.externally_anchored,
                self.authenticated)):
            raise StateError("admission reservation is not durable")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class AdmissionStageReceipt:
    schema: str
    authority_id: str
    reservation_sha256: str
    stage: str
    ordinal: int
    resource_sha256: str
    previous_stage_sha256: str
    committed_monotonic_ns: int
    durable: bool
    authenticated: bool
    authentication_sha256: str

    def validate(self, contract: "JournalContract",
                 reservation: AdmissionReservation,
                 stage: str, ordinal: int,
                 resource_sha256: str,
                 previous_stage_sha256: str) -> None:
        if (type(self) is not AdmissionStageReceipt
                or self.schema != JOURNAL_SCHEMA
                or self.authority_id != contract.authority_id
                or self.reservation_sha256 != reservation.digest
                or self.stage != stage or self.ordinal != ordinal
                or self.resource_sha256 != resource_sha256
                or self.previous_stage_sha256 != previous_stage_sha256):
            raise StateError("admission stage receipt mismatch")
        for digest in (self.reservation_sha256, self.resource_sha256,
                       self.previous_stage_sha256,
                       self.authentication_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise StateError("invalid admission stage identity")
        _decimal(self.ordinal, "admission stage ordinal", 1, 5)
        _decimal(self.committed_monotonic_ns,
                 "admission stage commit time", 1, (1 << 63) - 1)
        if any(value is not True for value in
               (self.durable, self.authenticated)):
            raise StateError("admission stage is not durable")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class AdmissionCleanupReceipt:
    schema: str
    authority_id: str
    kind: str
    reservation_sha256: str
    attempt_id: str
    cleanup_nonce: str
    released_monotonic_ns: int
    resources_extinct: bool
    idempotent: bool
    authenticated: bool
    authentication_sha256: str

    def validate(self, *, authority_id: str, kind: str,
                 reservation: AdmissionReservation,
                 cleanup_nonce: str) -> None:
        if (type(self) is not AdmissionCleanupReceipt
                or self.schema != JOURNAL_SCHEMA
                or self.authority_id != authority_id
                or self.kind != kind
                or self.reservation_sha256 != reservation.digest
                or self.attempt_id != reservation.attempt_id
                or self.cleanup_nonce != cleanup_nonce):
            raise StateError("admission cleanup receipt mismatch")
        for digest in (self.reservation_sha256, self.cleanup_nonce,
                       self.authentication_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise StateError("invalid admission cleanup identity")
        _decimal(self.released_monotonic_ns,
                 "admission cleanup observation time", 1,
                 (1 << 63) - 1)
        if any(value is not True for value in
               (self.resources_extinct, self.idempotent,
                self.authenticated)):
            raise StateError("admission resources remain")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@runtime_checkable
class PathAuthority(Protocol):
    def security_contract(self) -> PathAuthorityContract: ...
    def admit(self, source: Path, *, purpose: str, target: str, readonly: bool,
              kind: str, byte_limit: int, mapped_uid: int, mapped_gid: int,
              reservation: AdmissionReservation | None = None) -> PathBinding: ...
    def revalidate(self, binding: PathBinding) -> PathBinding: ...
    def admit_overlay(self, bindings: tuple[PathBinding, ...], *, uid: int,
                      gid: int,
                      reservation: AdmissionReservation) -> OverlayTopology: ...
    def revalidate_overlay(self, topology: OverlayTopology, bindings: tuple[PathBinding, ...]) -> OverlayTopology: ...
    def admit_export(self, destination: Path, *, byte_limit: int,
                     mapped_uid: int,
                     mapped_gid: int) -> ArtifactDestination: ...
    def revalidate_export(self, destination: ArtifactDestination) -> ArtifactDestination: ...
    def package_artifacts(self, sources: tuple[PathBinding, ...],
                          destination: ArtifactDestination, *, attempt_id: str,
                          manifest_sha256: str,
                          timeout: float) -> ArtifactCommit: ...
    def validate_export(self, destination: ArtifactDestination, *,
                        expected_commit: ArtifactCommit | None,
                        attempt_id: str,
                        manifest_sha256: str,
                        source_set_sha256: str,
                        timeout: float) -> ArtifactCommit: ...
    def verify_artifact(self, commit: ArtifactCommit) -> bool: ...
    def release_overlay(self, topology: OverlayTopology, *,
                        context_sha256: str,
                        release_nonce: str) -> ResourceReleaseReceipt: ...
    def verify_release(self, receipt: ResourceReleaseReceipt) -> bool: ...
    def cleanup_admission(self, reservation: AdmissionReservation, *,
                          cleanup_nonce: str) -> AdmissionCleanupReceipt: ...
    def verify_admission_cleanup(self, receipt: AdmissionCleanupReceipt) -> bool: ...


class NetworkKind(enum.Enum):
    PRIVATE_SHIM = "private-shim"
    VERIFIED_NARROW_PROXY = "verified-narrow-proxy"


@dataclasses.dataclass(frozen=True, slots=True)
class NetworkAuthorityContract:
    schema: str
    authority_id: str
    private_issued_proofs: bool
    authenticated_receipts: bool
    keeps_endpoint_descriptor: bool
    revocation_checked_each_call: bool
    denies_general_egress: bool
    no_dns: bool
    no_host_bridge_slirp_pasta: bool
    idempotent_authenticated_release: bool
    reservation_scoped_admission: bool
    idempotent_orphan_cleanup: bool

    def validate(self) -> None:
        if type(self) is not NetworkAuthorityContract or self.schema != PROVIDER_SCHEMA or not _NAME_RE.fullmatch(self.authority_id):
            raise PreflightError("invalid network authority")
        if any(value is not True for value in dataclasses.astuple(self)[2:]):
            raise PreflightError("network authority property unavailable")


@dataclasses.dataclass(frozen=True, slots=True)
class NetworkProof:
    schema: str
    authority_id: str
    kind: NetworkKind
    policy_sha256: str
    endpoint_sha256: str
    endpoint_token: str
    endpoint_kind: str
    generation: int
    expires_monotonic_ns: int
    podman_network: str
    inherited_fd: int
    authenticated: bool
    proxy_only: bool
    no_dns: bool
    revoked: bool

    def validate(self, authority: NetworkAuthorityContract,
                 require_active: bool = True) -> None:
        if type(self) is not NetworkProof or self.schema != PROVIDER_SCHEMA or self.authority_id != authority.authority_id:
            raise AdmissionError("invalid network proof")
        if type(self.kind) is not NetworkKind or any(not _SHA256_RE.fullmatch(value) for value in
                                                      (self.policy_sha256, self.endpoint_sha256, self.endpoint_token)):
            raise AdmissionError("invalid network identity")
        _decimal(self.generation, "network generation", 1, (1 << 63) - 1)
        _decimal(self.expires_monotonic_ns, "network expiry", 1, (1 << 63) - 1)
        _decimal(self.inherited_fd, "network descriptor", 3, 999)
        if type(self.revoked) is not bool:
            raise AdmissionError("invalid network revocation state")
        if (require_active and
                (self.expires_monotonic_ns <= time.monotonic_ns()
                 or self.revoked is not False)):
            raise AdmissionError("network authority expired or revoked")
        if any(value is not True for value in (self.authenticated, self.proxy_only, self.no_dns)):
            raise AdmissionError("network proof incomplete")
        if self.kind is NetworkKind.PRIVATE_SHIM:
            if self.endpoint_kind != "connected-seqpacket-fd" or self.podman_network != "none":
                raise AdmissionError("private shim transport mismatch")
        else:
            match = _NS_NETWORK_RE.fullmatch(self.podman_network)
            if self.endpoint_kind != "network-namespace-fd" or match is None or int(match.group("fd")) != self.inherited_fd:
                raise AdmissionError("narrow proxy namespace mismatch")

    @property
    def digest(self) -> str:
        data = dataclasses.asdict(self)
        data["kind"] = self.kind.value
        return _hash(_canonical_json(data))


@runtime_checkable
class NetworkAuthority(Protocol):
    def security_contract(self) -> NetworkAuthorityContract: ...
    def admit(self, policy_sha256: str,
              reservation: AdmissionReservation) -> NetworkProof: ...
    def revalidate(self, proof: NetworkProof) -> NetworkProof: ...
    def release(self, proof: NetworkProof, *, context_sha256: str,
                release_nonce: str) -> ResourceReleaseReceipt: ...
    def verify_release(self, receipt: ResourceReleaseReceipt) -> bool: ...
    def cleanup_admission(self, reservation: AdmissionReservation, *,
                          cleanup_nonce: str) -> AdmissionCleanupReceipt: ...
    def verify_admission_cleanup(self, receipt: AdmissionCleanupReceipt) -> bool: ...


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutionLease:
    schema: str
    authority_id: str
    attempt_seed: str
    token: str
    cgroup_token: str
    keeper_token: str
    cgroup_path: str
    cgroup_device: int
    cgroup_inode: int
    cgroup_mount_id: int
    conmon_scope_sha256: str
    uidmap_sha256: str
    keeper_pid: int
    delegated: bool

    def validate(self, contract: "RunnerContract", seed: str) -> None:
        if type(self) is not ExecutionLease or self.schema != PROVIDER_SCHEMA or self.authority_id != contract.authority_id or self.attempt_seed != seed:
            raise AdmissionError("invalid execution lease")
        if any(not _SHA256_RE.fullmatch(value) for value in
               (self.token, self.cgroup_token, self.keeper_token,
                self.conmon_scope_sha256, self.uidmap_sha256)):
            raise AdmissionError("invalid execution lease identity")
        _absolute(Path(self.cgroup_path), "attempt cgroup")
        for value in (self.cgroup_device, self.cgroup_inode, self.cgroup_mount_id, self.keeper_pid):
            _decimal(value, "execution lease identity", 1, (1 << 63) - 1)
        if self.delegated is not True:
            raise AdmissionError("execution cgroup not delegated")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class CleanupLease:
    """Egress-independent authority retained exclusively for teardown."""

    schema: str
    authority_id: str
    attempt_seed: str
    token: str
    execution_lease_sha256: str
    cgroup_token: str
    keeper_token: str
    no_egress: bool
    may_kill: bool
    may_remove: bool
    authenticated: bool

    def validate(self, contract: "RunnerContract",
                 lease: ExecutionLease) -> None:
        if (type(self) is not CleanupLease or self.schema != PROVIDER_SCHEMA
                or self.authority_id != contract.authority_id
                or self.attempt_seed != lease.attempt_seed
                or self.execution_lease_sha256 != lease.digest
                or self.cgroup_token != lease.cgroup_token
                or self.keeper_token != lease.keeper_token):
            raise AdmissionError("invalid cleanup authority")
        if not _SHA256_RE.fullmatch(self.token):
            raise AdmissionError("invalid cleanup authority identity")
        if any(value is not True for value in
               (self.no_egress, self.may_kill, self.may_remove,
                self.authenticated)):
            raise AdmissionError("cleanup authority incomplete")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class ObservationChallenge:
    schema: str
    authority_id: str
    scope: str
    nonce: str
    generation: int
    issued_monotonic_ns: int
    authenticated: bool

    def validate(self, contract: "JournalContract", scope: str) -> None:
        if (type(self) is not ObservationChallenge
                or self.schema != JOURNAL_SCHEMA
                or self.authority_id != contract.authority_id
                or self.scope != scope
                or not _SHA256_RE.fullmatch(self.nonce)):
            raise StateError("invalid observation challenge")
        _clean_text(self.scope, "observation scope", 192)
        _decimal(self.generation, "observation generation", 1,
                 (1 << 63) - 1)
        _decimal(self.issued_monotonic_ns, "challenge issue time", 1,
                 (1 << 63) - 1)
        if (self.issued_monotonic_ns > time.monotonic_ns()
                or self.authenticated is not True):
            raise StateError("invalid observation challenge")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class ObservationAnchor:
    schema: str
    authority_id: str
    scope: str
    challenge_sha256: str
    observation_sha256: str
    sequence: int
    generation: int
    observed_monotonic_ns: int
    authentication_sha256: str
    durable: bool
    current: bool
    authenticated: bool

    def validate(self, contract: "JournalContract",
                 challenge: ObservationChallenge, observation_sha256: str,
                 sequence: int, observed_ns: int) -> None:
        if (type(self) is not ObservationAnchor
                or self.schema != JOURNAL_SCHEMA
                or self.authority_id != contract.authority_id
                or self.scope != challenge.scope
                or self.challenge_sha256 != challenge.digest
                or self.observation_sha256 != observation_sha256
                or self.sequence != sequence
                or self.generation != challenge.generation
                or self.observed_monotonic_ns != observed_ns):
            raise StateError("observation anchor mismatch")
        for digest in (self.challenge_sha256, self.observation_sha256,
                       self.authentication_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise StateError("invalid observation anchor")
        _decimal(self.sequence, "anchored observation sequence", 1,
                 (1 << 63) - 1)
        _decimal(self.generation, "anchored observation generation", 1,
                 (1 << 63) - 1)
        _decimal(self.observed_monotonic_ns, "anchored observation time", 1,
                 (1 << 63) - 1)
        if (self.sequence != self.generation
                or self.observed_monotonic_ns <
                   challenge.issued_monotonic_ns
                or self.observed_monotonic_ns > time.monotonic_ns()
                or any(value is not True for value in
                       (self.durable, self.current,
                        self.authenticated))):
            raise StateError("observation anchor not durable")


@dataclasses.dataclass(frozen=True, slots=True)
class ComponentObservation:
    schema: str
    authority_id: str
    component_digest: str
    content_set_sha256: str
    challenge_sha256: str
    sequence: int
    observed_monotonic_ns: int
    descriptors_held: bool
    authenticated: bool

    def validate(self, contract: "RunnerContract",
                 components: ComponentIdentities,
                 challenge: ObservationChallenge) -> None:
        content = _hash(_canonical_json([
            {"dev": item.device, "ino": item.inode, "size": item.size,
             "mode": item.mode, "sha256": item.sha256,
             "chain": item.component_chain_sha256,
             "xattr": item.xattr_sha256}
            for item in (components.podman, components.conmon,
                         components.crun, components.newuidmap,
                         components.newgidmap, components.overlay_helper)
        ]))
        if (type(self) is not ComponentObservation
                or self.schema != PROVIDER_SCHEMA
                or self.authority_id != contract.authority_id
                or self.component_digest != components.digest
                or self.content_set_sha256 != content
                or self.challenge_sha256 != challenge.digest):
            raise PreflightError("component content observation mismatch")
        _decimal(self.sequence, "component observation sequence", 1,
                 (1 << 63) - 1)
        _decimal(self.observed_monotonic_ns, "component observation time", 1,
                 (1 << 63) - 1)
        if (self.observed_monotonic_ns < challenge.issued_monotonic_ns
                or self.observed_monotonic_ns > time.monotonic_ns()
                or self.descriptors_held is not True
                or self.authenticated is not True):
            raise PreflightError("component content observation incomplete")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class ExtinctionObservation:
    schema: str
    authority_id: str
    cleanup_sha256: str
    lease_sha256: str
    cgroup_token: str
    keeper_token: str
    challenge_sha256: str
    sequence: int
    observed_monotonic_ns: int
    cgroup_populated: int
    descendants: int
    conmon_extinct: bool
    authenticated: bool

    def validate(self, contract: "RunnerContract", lease: ExecutionLease,
                 cleanup: CleanupLease,
                 challenge: ObservationChallenge) -> None:
        if (type(self) is not ExtinctionObservation
                or self.schema != PROVIDER_SCHEMA
                or self.authority_id != contract.authority_id
                or self.cleanup_sha256 != cleanup.digest
                or self.lease_sha256 != lease.digest
                or self.cgroup_token != lease.cgroup_token
                or self.keeper_token != lease.keeper_token
                or self.challenge_sha256 != challenge.digest):
            raise StateError("extinction observation context mismatch")
        _decimal(self.sequence, "extinction sequence", 1, (1 << 63) - 1)
        _decimal(self.observed_monotonic_ns, "extinction observation time", 1,
                 (1 << 63) - 1)
        if self.observed_monotonic_ns < challenge.issued_monotonic_ns or self.observed_monotonic_ns > time.monotonic_ns():
            raise StateError("stale extinction observation")
        if (type(self.cgroup_populated) is not int
                or type(self.descendants) is not int
                or self.cgroup_populated != 0 or self.descendants != 0
                or self.conmon_extinct is not True
                or self.authenticated is not True):
            raise StateError("container descendants remain")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class RunnerContract:
    schema: str
    authority_id: str
    component_digest: str
    host_facts_sha256: str
    provider_roots_sha256: str
    root_bindings_sha256: str
    isolated_config_sha256: str
    descriptor_bound_exec: bool
    descriptor_bound_components: bool
    descriptor_bound_helpers: bool
    release_provenance_verified: bool
    one_shot_capabilities: bool
    closed_environment: bool
    ignores_ambient_config: bool
    local_transport_only: bool
    keeps_all_descriptors: bool
    tracks_process_tree: bool
    observes_cgroup_population: bool
    observes_exact_exit: bool
    bounded_capture: bool
    timeout_uses_cgroup_kill: bool
    exceptions_after_cleanup: bool
    authenticated_cleanup_authority: bool
    cleanup_egress_independent: bool
    fresh_component_content_proof: bool
    fresh_extinction_observation: bool
    idempotent_authenticated_release: bool
    rollback_safe_emergency_extinction: bool
    reservation_scoped_admission: bool
    idempotent_orphan_cleanup: bool

    def validate(self, components: ComponentIdentities, roots: ProviderRoots,
                 host: HostFacts, root_digest: str) -> None:
        if type(self) is not RunnerContract or self.schema != PROVIDER_SCHEMA or not _NAME_RE.fullmatch(self.authority_id):
            raise PreflightError("invalid runner contract")
        if (self.component_digest != components.digest or self.host_facts_sha256 != host.digest
                or self.provider_roots_sha256 != roots.digest or self.root_bindings_sha256 != root_digest
                or self.isolated_config_sha256 != _ISOLATED_CONFIG_SHA256):
            raise PreflightError("runner identity/configuration mismatch")
        if any(value is not True for value in dataclasses.astuple(self)[7:]):
            raise PreflightError("runner security property unavailable")


@dataclasses.dataclass(frozen=True, slots=True)
class InvocationReceipt:
    schema: str
    authority_id: str
    capability_nonce: str
    component_digest: str
    component_observation_sha256: str
    argv_sha256: str
    env_sha256: str
    binding_digest: str
    binding_tokens: tuple[str, ...]
    output_token: str | None
    network_proof_sha256: str | None
    network_endpoint_token: str | None
    lease_sha256: str | None
    cgroup_token: str | None
    conmon_scope_sha256: str | None
    cleanup_sha256: str | None
    cleanup_token: str | None
    descriptor_exec_used: bool
    closed_environment_used: bool
    ambient_config_ignored: bool
    local_transport_only: bool
    all_descriptors_held: bool
    process_tree_accounted: bool
    provider_descendants_extinct: bool
    conmon_extinct: bool
    cgroup_populated: int
    exact_exit_observed: bool
    egress_independent_cleanup: bool


@dataclasses.dataclass(frozen=True, slots=True)
class RunnerResult:
    returncode: int
    stdout: bytes = dataclasses.field(repr=False)
    stderr: bytes = dataclasses.field(repr=False)
    receipt: InvocationReceipt


_CAPABILITIES: dict[int, tuple[str, str]] = {}
_PLANS: dict[int, tuple[str, str, str, bool, str | None]] = {}


class _RunnerCapability:
    __slots__ = ("nonce", "operation")
    def __new__(cls, *_args: object, **_kwargs: object) -> "_RunnerCapability":
        raise TypeError("private-issued capability")


class _InvocationPlan:
    __slots__ = ("nonce", "operation", "argv", "mutating", "journal_nonce")
    def __new__(cls, *_args: object, **_kwargs: object) -> "_InvocationPlan":
        raise TypeError("private-issued invocation plan")


def _issue_capability(operation: str) -> _RunnerCapability:
    capability = object.__new__(_RunnerCapability)
    nonce = _hash(os.urandom(32))
    object.__setattr__(capability, "nonce", nonce)
    object.__setattr__(capability, "operation", operation)
    _CAPABILITIES[id(capability)] = (nonce, operation)
    return capability


def _consume_capability(capability: object, operation: str) -> str:
    if type(capability) is not _RunnerCapability:
        raise ContractError("invalid runner capability")
    item = _CAPABILITIES.pop(id(capability), None)
    if item != (getattr(capability, "nonce", None), operation):
        raise ContractError("invalid or replayed runner capability")
    return item[0]


def _issue_plan(operation: str, argv: tuple[str, ...], mutating: bool,
                journal_nonce: str | None) -> _InvocationPlan:
    plan = object.__new__(_InvocationPlan)
    nonce = _hash(os.urandom(32))
    digest = _hash(_canonical_json(list(argv)))
    for name, value in (("nonce", nonce), ("operation", operation), ("argv", argv),
                        ("mutating", mutating), ("journal_nonce", journal_nonce)):
        object.__setattr__(plan, name, value)
    _PLANS[id(plan)] = (nonce, operation, digest, mutating, journal_nonce)
    return plan


def _consume_plan(plan: object) -> tuple[str, tuple[str, ...], bool, str | None]:
    if type(plan) is not _InvocationPlan:
        raise ContractError("invalid invocation plan")
    item = _PLANS.pop(id(plan), None)
    argv = getattr(plan, "argv", None)
    expected = (getattr(plan, "nonce", None), getattr(plan, "operation", None),
                _hash(_canonical_json(list(argv))) if type(argv) is tuple else None,
                getattr(plan, "mutating", None), getattr(plan, "journal_nonce", None))
    if item is None or item != expected:
        raise ContractError("invalid or replayed invocation plan")
    return item[1], argv, item[3], item[4]


@runtime_checkable
class Runner(Protocol):
    def security_contract(self, components: ComponentIdentities, roots: ProviderRoots,
                          host: HostFacts, root_bindings: tuple[PathBinding, ...]) -> RunnerContract: ...
    def acquire_lease(self, attempt_seed: str, *, uid: int, gid: int,
                      reservation: AdmissionReservation) -> ExecutionLease: ...
    def revalidate_lease(self, lease: ExecutionLease) -> ExecutionLease: ...
    def acquire_cleanup(self, lease: ExecutionLease) -> CleanupLease: ...
    def revalidate_cleanup(self, cleanup: CleanupLease) -> CleanupLease: ...
    def observe_components(self, components: ComponentIdentities,
                           challenge: ObservationChallenge) -> ComponentObservation: ...
    def observe_extinction(self, lease: ExecutionLease,
                           cleanup: CleanupLease,
                           challenge: ObservationChallenge) -> ExtinctionObservation: ...
    def emergency_extinguish(self, lease: ExecutionLease,
                             cleanup: CleanupLease,
                             challenge: ObservationChallenge,
                             expected_container_id: str | None, *,
                             timeout: float) -> ExtinctionObservation: ...
    def release_execution(self, lease: ExecutionLease, cleanup: CleanupLease,
                          *, context_sha256: str,
                          release_nonce: str) -> tuple[ResourceReleaseReceipt, ...]: ...
    def verify_release(self, receipt: ResourceReleaseReceipt) -> bool: ...
    def cleanup_admission(self, reservation: AdmissionReservation, *,
                          cleanup_nonce: str) -> AdmissionCleanupReceipt: ...
    def verify_admission_cleanup(self, receipt: AdmissionCleanupReceipt) -> bool: ...
    def __call__(self, argv: tuple[str, ...], *, env: tuple[str, ...],
                 components: ComponentIdentities, bindings: tuple[PathBinding, ...],
                 output: PathBinding | None, network: NetworkProof | None,
                 lease: ExecutionLease | None, cleanup: CleanupLease | None,
                 component_observation: ComponentObservation,
                 timeout: float, output_limit: int,
                 capability: _RunnerCapability) -> RunnerResult: ...


class MutationState(enum.Enum):
    PENDING = "pending"
    COMPLETE = "complete"
    ABORTED = "aborted"


@dataclasses.dataclass(frozen=True, slots=True)
class MutationRecord:
    schema: str
    attempt_id: str
    generation: int
    previous_record_sha256: str
    base_spec_sha256: str
    context_sha256: str
    bindings_sha256: str
    network_sha256: str
    lease_sha256: str
    cleanup_sha256: str
    admission: AdmissionReservation
    admission_stages: tuple[AdmissionStageReceipt, ...]
    root_bindings: tuple[PathBinding, ...]
    bindings: tuple[PathBinding, ...]
    topology: OverlayTopology
    network: NetworkProof
    lease: ExecutionLease
    cleanup: CleanupLease
    operation: str
    previous_operation: str | None
    nonce: str
    state: MutationState
    expected_container_id: str | None
    operation_binding: PathBinding | None
    operation_snapshot_before: str | None
    artifact_destination: ArtifactDestination | None
    artifact_commit: ArtifactCommit | None
    artifact_manifest_sha256: str | None
    artifact_sources_sha256: str | None
    release_receipts: tuple[ResourceReleaseReceipt, ...]
    postcondition_sha256: str | None

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(_authority_document(self)))

    def validate(self) -> None:
        if type(self) is not MutationRecord or self.schema != JOURNAL_SCHEMA or not _NAME_RE.fullmatch(self.attempt_id):
            raise ContractError("invalid journal record")
        _decimal(self.generation, "journal generation", 1,
                 (1 << 63) - 1)
        if any(not _SHA256_RE.fullmatch(value) for value in
               (self.previous_record_sha256, self.base_spec_sha256,
                self.context_sha256, self.bindings_sha256,
                self.network_sha256, self.lease_sha256,
                self.cleanup_sha256, self.nonce)):
            raise ContractError("invalid journal identity")
        if type(self.admission) is not AdmissionReservation:
            raise ContractError("journal admission reservation missing")
        if (self.admission.attempt_id != self.attempt_id
                or self.admission.base_spec_sha256 !=
                   self.base_spec_sha256):
            raise ContractError("journal admission reservation mismatch")
        if (type(self.root_bindings) is not tuple or type(self.bindings) is not tuple
                or any(type(item) is not PathBinding
                       for item in self.root_bindings + self.bindings)
                or type(self.topology) is not OverlayTopology
                or type(self.network) is not NetworkProof
                or type(self.lease) is not ExecutionLease
                or type(self.cleanup) is not CleanupLease):
            raise ContractError("journal context evidence missing")
        if (type(self.admission_stages) is not tuple
                or len(self.admission_stages) != 5
                or any(type(item) is not AdmissionStageReceipt
                       for item in self.admission_stages)):
            raise ContractError("journal admission stage roster missing")
        expected_stages = ("paths", "overlay", "network", "execution",
                           "cleanup")
        expected_resources = (
            self.bindings_sha256, self.topology.digest,
            self.network_sha256, self.lease_sha256,
            self.cleanup_sha256,
        )
        previous_stage = "0" * 64
        for ordinal, (stage, resource, receipt) in enumerate(
                zip(expected_stages, expected_resources,
                    self.admission_stages, strict=True), 1):
            if (receipt.stage != stage or receipt.ordinal != ordinal
                    or receipt.reservation_sha256 != self.admission.digest
                    or receipt.resource_sha256 != resource
                    or receipt.previous_stage_sha256 != previous_stage):
                raise ContractError("journal admission stage chain mismatch")
            previous_stage = receipt.digest
        for binding in self.root_bindings + self.bindings:
            _validated(binding, ContractError, "invalid journal binding")
        calculated = _hash(_canonical_json(
            [item.document for item in self.bindings]))
        if (calculated != self.bindings_sha256
                or self.network.digest != self.network_sha256
                or self.lease.digest != self.lease_sha256
                or self.cleanup.digest != self.cleanup_sha256):
            raise ContractError("journal context evidence digest mismatch")
        operations = {"load", "create", "start", "cancel", "export",
                      "delete", "release"}
        if self.operation not in operations or type(self.state) is not MutationState:
            raise ContractError("invalid journal operation")
        if self.previous_operation is not None and self.previous_operation not in operations:
            raise ContractError("invalid prior journal operation")
        for value in (self.expected_container_id, self.operation_snapshot_before,
                      self.artifact_manifest_sha256,
                      self.artifact_sources_sha256,
                      self.postcondition_sha256):
            if value is not None and not _SHA256_RE.fullmatch(value):
                raise ContractError("invalid journal digest")
        if self.operation_binding is not None:
            _validated(self.operation_binding, ContractError, "invalid journal binding")
        if (self.operation == "load") != (self.operation_binding is not None):
            raise ContractError("journal operation binding mismatch")
        if self.operation == "export":
            if (self.artifact_manifest_sha256 is None
                    or self.artifact_sources_sha256 is None
                    or type(self.artifact_destination) is not ArtifactDestination):
                raise ContractError("journal artifact proof missing")
            _validated(self.artifact_destination, ContractError,
                       "invalid journal artifact destination",
                       # The authority identity is checked again by the provider.
                       PathAuthorityContract(
                           PROVIDER_SCHEMA,
                           self.artifact_destination.authority_id,
                           *([True] * 24)))
            if (self.state is MutationState.COMPLETE) != (
                    self.artifact_commit is not None):
                raise ContractError("journal artifact commit state mismatch")
            if self.artifact_commit is not None:
                _validated(
                    self.artifact_commit, ContractError,
                    "invalid journal artifact commit",
                    PathAuthorityContract(
                        PROVIDER_SCHEMA,
                        self.artifact_destination.authority_id,
                        *([True] * 24)),
                    self.artifact_destination, self.attempt_id,
                    self.artifact_manifest_sha256,
                    self.artifact_sources_sha256)
        elif (self.artifact_manifest_sha256 is not None
              or self.artifact_sources_sha256 is not None
              or self.artifact_destination is not None
              or self.artifact_commit is not None):
            raise ContractError("unexpected journal artifact proof")
        if self.state is MutationState.ABORTED and self.postcondition_sha256 is not None:
            raise ContractError("aborted mutation has postcondition")
        if (type(self.release_receipts) is not tuple
                or any(type(item) is not ResourceReleaseReceipt
                       for item in self.release_receipts)):
            raise ContractError("invalid journal release receipts")
        if self.operation == "release" and self.state is MutationState.COMPLETE:
            if len(self.release_receipts) != 6:
                raise ContractError("journal release roster incomplete")
        elif self.release_receipts:
            raise ContractError("unexpected journal release receipts")


@dataclasses.dataclass(frozen=True, slots=True)
class JournalAnchor:
    schema: str
    authority_id: str
    attempt_id: str
    generation: int
    record_sha256: str
    previous_record_sha256: str
    monotonic_counter: int
    authentication_sha256: str
    durable: bool
    current: bool
    authenticated: bool

    def validate(self, contract: "JournalContract",
                 record: MutationRecord) -> None:
        if (type(self) is not JournalAnchor or self.schema != JOURNAL_SCHEMA
                or self.authority_id != contract.authority_id
                or self.attempt_id != record.attempt_id
                or self.generation != record.generation
                or self.record_sha256 != record.digest
                or self.previous_record_sha256 !=
                   record.previous_record_sha256):
            raise _JournalRollback("journal rollback or fork detected")
        for digest in (self.record_sha256, self.previous_record_sha256,
                       self.authentication_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise _JournalRollback("invalid journal anchor")
        _decimal(self.monotonic_counter, "journal monotonic counter", 1,
                 (1 << 63) - 1)
        if (self.monotonic_counter < self.generation
                or any(value is not True for value in
                       (self.durable, self.current, self.authenticated))):
            raise _JournalRollback("journal anchor is not current")


@dataclasses.dataclass(frozen=True, slots=True)
class JournalSnapshot:
    """One atomic read of a record and its external monotonic anchor."""

    schema: str
    authority_id: str
    record: MutationRecord
    anchor: JournalAnchor
    read_nonce: str
    authentication_sha256: str
    atomic_read: bool
    current_at_read: bool
    authenticated: bool

    def validate(self, contract: "JournalContract") -> None:
        if (type(self) is not JournalSnapshot
                or self.schema != JOURNAL_SCHEMA
                or self.authority_id != contract.authority_id
                or type(self.record) is not MutationRecord
                or type(self.anchor) is not JournalAnchor):
            raise _JournalRollback("invalid journal snapshot")
        for digest in (self.read_nonce, self.authentication_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise _JournalRollback("invalid journal snapshot identity")
        _validated(self.record, _JournalRollback,
                   "invalid journal snapshot record")
        _validated(self.anchor, _JournalRollback,
                   "journal snapshot rollback or fork detected",
                   contract, self.record)
        if any(value is not True for value in
               (self.atomic_read, self.current_at_read,
                self.authenticated)):
            raise _JournalRollback("journal snapshot is not current")


@dataclasses.dataclass(frozen=True, slots=True)
class AttemptRecoverySnapshot:
    """One authority-atomic attempt-head read and admission cleanup claim."""

    schema: str
    authority_id: str
    attempt_id: str
    base_spec_sha256: str
    record_snapshot: JournalSnapshot | None
    admission: AdmissionReservation | None
    admission_stages: tuple[AdmissionStageReceipt, ...]
    cleanup_claim_sha256: str | None
    monotonic_counter: int
    read_nonce: str
    authentication_sha256: str
    atomic_read: bool
    cleanup_claimed: bool
    current_at_read: bool
    authenticated: bool

    def validate(self, contract: "JournalContract", attempt_id: str,
                 base_spec_sha256: str) -> None:
        if (type(self) is not AttemptRecoverySnapshot
                or self.schema != JOURNAL_SCHEMA
                or self.authority_id != contract.authority_id
                or self.attempt_id != attempt_id
                or self.base_spec_sha256 != base_spec_sha256):
            raise _JournalRollback("attempt recovery snapshot mismatch")
        for digest in (self.base_spec_sha256, self.read_nonce,
                       self.authentication_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise _JournalRollback("invalid attempt recovery identity")
        _decimal(self.monotonic_counter, "attempt recovery counter", 1,
                 (1 << 63) - 1)
        if any(value is not True for value in
               (self.atomic_read, self.current_at_read,
                self.authenticated)):
            raise _JournalRollback("attempt recovery snapshot not durable")
        if (self.record_snapshot is not None
                and self.admission is not None):
            raise _JournalRollback("attempt has conflicting durable heads")
        if self.record_snapshot is not None:
            _validated(self.record_snapshot, _JournalRollback,
                       "invalid mutation head in attempt snapshot", contract)
            if (self.record_snapshot.record.attempt_id != attempt_id
                    or self.record_snapshot.record.base_spec_sha256 !=
                       base_spec_sha256
                    or self.admission_stages
                    or self.cleanup_claim_sha256 is not None
                    or self.cleanup_claimed is not False):
                raise _JournalRollback("mutation attempt snapshot changed")
        elif self.admission is not None:
            _validated(self.admission, _JournalRollback,
                       "invalid admission head in attempt snapshot",
                       contract, attempt_id, base_spec_sha256)
            if (type(self.admission_stages) is not tuple
                    or len(self.admission_stages) > 5
                    or any(type(item) is not AdmissionStageReceipt
                           for item in self.admission_stages)
                    or self.cleanup_claim_sha256 is None
                    or not _SHA256_RE.fullmatch(self.cleanup_claim_sha256)
                    or self.cleanup_claimed is not True):
                raise _JournalRollback("admission cleanup claim incomplete")
        elif (self.admission_stages
              or self.cleanup_claim_sha256 is not None
              or self.cleanup_claimed is not False):
            raise _JournalRollback("empty attempt snapshot has state")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(_authority_document(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class AdmissionRetirement:
    """Durable retirement of one reservation generation, not the attempt."""

    schema: str
    authority_id: str
    attempt_id: str
    reservation_sha256: str
    reservation_generation: int
    cleanup_claim_sha256: str
    cleanup_receipts_sha256: str
    monotonic_counter: int
    retired_monotonic_ns: int
    durable: bool
    externally_anchored: bool
    authenticated: bool

    def validate(self, contract: "JournalContract",
                 reservation: AdmissionReservation,
                 cleanup_claim_sha256: str,
                 receipts: tuple[AdmissionCleanupReceipt, ...]) -> None:
        roster = _hash(_canonical_json([item.digest for item in receipts]))
        if (type(self) is not AdmissionRetirement
                or self.schema != JOURNAL_SCHEMA
                or self.authority_id != contract.authority_id
                or self.attempt_id != reservation.attempt_id
                or self.reservation_sha256 != reservation.digest
                or self.reservation_generation != reservation.generation
                or self.cleanup_claim_sha256 != cleanup_claim_sha256
                or self.cleanup_receipts_sha256 != roster):
            raise StateError("admission retirement context mismatch")
        for digest in (self.reservation_sha256,
                       self.cleanup_claim_sha256,
                       self.cleanup_receipts_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise StateError("invalid admission retirement identity")
        _decimal(self.monotonic_counter, "admission retirement counter", 1,
                 (1 << 63) - 1)
        _decimal(self.retired_monotonic_ns, "admission retirement time", 1,
                 (1 << 63) - 1)
        if any(value is not True for value in
               (self.durable, self.externally_anchored,
                self.authenticated)):
            raise StateError("admission retirement is not durable")

    @property
    def digest(self) -> str:
        return _hash(_canonical_json(dataclasses.asdict(self)))


@dataclasses.dataclass(frozen=True, slots=True)
class JournalContract:
    """Claims reserved to a native durable authority.

    ``external_monotonic_anchor`` and ``durable_observation_challenges``
    cannot truthfully be implemented with Python process memory or a
    rewriteable record file. Preflight refuses any false property.
    """
    schema: str
    authority_id: str
    durable_before_return: bool
    atomic_replace: bool
    single_writer_lock: bool
    reloadable: bool
    monotonic_records: bool
    stores_full_binding_records: bool
    stable_attempt_lookup: bool
    authenticated_records: bool
    supports_aborted_transitions: bool
    hash_chained_records: bool
    external_monotonic_anchor: bool
    durable_observation_challenges: bool
    rollback_safe_cleanup: bool
    retains_authenticated_cleanup_context: bool
    atomic_record_anchor_reads: bool
    journals_precontext_admission: bool
    mutation_adopts_admission_atomically: bool
    idempotent_orphan_admission_cleanup: bool
    serializes_admission_owner: bool
    authenticated_incremental_admission: bool
    atomic_attempt_recovery_claims: bool
    authenticated_absence_proofs: bool

    def validate(self) -> None:
        if type(self) is not JournalContract or self.schema != PROVIDER_SCHEMA or not _NAME_RE.fullmatch(self.authority_id):
            raise PreflightError("invalid journal contract")
        if any(value is not True for value in dataclasses.astuple(self)[2:]):
            raise PreflightError("journal durability property unavailable")


@runtime_checkable
class MutationJournal(Protocol):
    def security_contract(self) -> JournalContract: ...
    def load(self, attempt_id: str) -> MutationRecord | None: ...
    def load_anchor(self, attempt_id: str) -> JournalAnchor | None: ...
    def load_current(self, attempt_id: str) -> JournalSnapshot | None: ...
    def verify_snapshot(self, snapshot: JournalSnapshot) -> bool: ...
    def load_cleanup_record(self, attempt_id: str) -> MutationRecord | None: ...
    def verify_cleanup_record(self, record: MutationRecord) -> bool: ...
    def write(self, record: MutationRecord) -> JournalAnchor: ...
    def verify_anchor(self, anchor: JournalAnchor) -> bool: ...
    def issue_observation_challenge(self, scope: str) -> ObservationChallenge: ...
    def commit_observation(self, challenge: ObservationChallenge, *,
                           observation_sha256: str, sequence: int,
                           observed_monotonic_ns: int) -> ObservationAnchor: ...
    def verify_observation_anchor(self, anchor: ObservationAnchor) -> bool: ...
    def load_admission(self, attempt_id: str) -> AdmissionReservation | None: ...
    def reserve_admission(self, attempt_id: str, *,
                          base_spec_sha256: str) -> AdmissionReservation: ...
    def verify_admission(self, reservation: AdmissionReservation) -> bool: ...
    def commit_admission_stage(
            self, reservation: AdmissionReservation, *, stage: str,
            ordinal: int, resource_sha256: str,
            previous_stage_sha256: str) -> AdmissionStageReceipt: ...
    def load_admission_stages(
            self, reservation: AdmissionReservation
    ) -> tuple[AdmissionStageReceipt, ...]: ...
    def verify_admission_stage(self, receipt: AdmissionStageReceipt) -> bool: ...
    def claim_attempt_recovery(
            self, attempt_id: str, *, base_spec_sha256: str
    ) -> AttemptRecoverySnapshot: ...
    def verify_attempt_recovery(
            self, snapshot: AttemptRecoverySnapshot) -> bool: ...
    def complete_admission_cleanup(
            self, reservation: AdmissionReservation,
            cleanup_claim_sha256: str,
            receipts: tuple[AdmissionCleanupReceipt, ...]
    ) -> AdmissionRetirement: ...
    def verify_admission_retirement(
            self, retirement: AdmissionRetirement) -> bool: ...


@dataclasses.dataclass(frozen=True, slots=True)
class ImageSpec:
    reference: str
    digest: str
    os: str = "linux"
    architecture: str = "amd64"

    def validate(self) -> None:
        if type(self) is not ImageSpec:
            raise AdmissionError("invalid image specification")
        match = _IMAGE_RE.fullmatch(_clean_text(self.reference, "image reference", 512))
        if match is None or self.digest != match.group("digest") or not _SHA256_RE.fullmatch(self.digest):
            raise AdmissionError("image must be canonical and digest-addressed")
        if self.os != "linux" or self.architecture not in {"amd64", "arm64"}:
            raise AdmissionError("unsupported image platform")


_MOUNT_ROSTER = MappingProxyType({
    "project-lower": ("", True, "directory", 8 * 1024**3),
    "project-upper": ("", False, "directory", 8 * 1024**3),
    "project-work": ("", False, "directory", 1024**3),
    "project-merged": ("/workspace/project", False, "directory", 8 * 1024**3),
    "runtime": ("/opt/plamen", True, "directory", 1024**3),
    "state": ("/workspace/state", False, "directory", 4 * 1024**3),
    "scratch": ("/workspace/scratch", False, "directory", 16 * 1024**3),
    "seccomp": ("", True, "regular", 1024**2),
})
_CONTAINER_MOUNTS = ("project-merged", "runtime", "state", "scratch")


@dataclasses.dataclass(frozen=True, slots=True)
class MountRequest:
    purpose: str
    source: Path = dataclasses.field(repr=False)


@dataclasses.dataclass(frozen=True, slots=True)
class ContainerSpec:
    run_id: str
    attempt_number: int
    image: ImageSpec
    entrypoint: str
    arguments: tuple[str, ...] = dataclasses.field(repr=False)
    environment: tuple[str, ...] = dataclasses.field(repr=False)
    mounts: tuple[MountRequest, ...]
    network_policy_sha256: str
    seccomp_sha256: str
    uid: int = 65532
    gid: int = 65532
    pids_limit: int = 512
    memory_bytes: int = 4 * 1024**3
    cpu_millis: int = 2000
    nofile_limit: int = 4096
    tmpfs_bytes: int = 512 * 1024**2

    def validate(self) -> None:
        if type(self) is not ContainerSpec:
            raise ContractError("invalid container specification")
        _clean_text(self.run_id, "run id", 128)
        _decimal(self.attempt_number, "attempt number", 1, 1_000_000)
        _validated(self.image, AdmissionError, "invalid image specification")
        _clean_text(self.entrypoint, "entrypoint", 512)
        if (not self.entrypoint.startswith("/") or ".." in PurePosixPath(self.entrypoint).parts
                or any(part in ("", ".") for part in PurePosixPath(self.entrypoint).parts[1:])):
            raise ContractError("invalid entrypoint")
        if type(self.arguments) is not tuple or len(self.arguments) > 256:
            raise BoundsError("invalid arguments")
        for item in self.arguments:
            _clean_text(item, "argument", 2048)
        if sum(len(os.fsencode(item)) + 1 for item in (self.entrypoint,) + self.arguments) > MAX_ARG_BYTES:
            raise BoundsError("argument vector exceeds bounds")
        if type(self.environment) is not tuple or len(self.environment) > MAX_ENV_ITEMS:
            raise BoundsError("invalid environment")
        names: set[str] = set()
        for item in self.environment:
            _clean_text(item, "environment", 2048)
            if "=" not in item:
                raise ContractError("environment values must be explicit")
            name = item.split("=", 1)[0]
            if (not _ENV_RE.fullmatch(name) or name in names or name in _FORBIDDEN_ENV
                    or any(part in name for part in _SECRET_PARTS)):
                raise ContractError("unsafe environment name")
            names.add(name)
        if type(self.mounts) is not tuple or len(self.mounts) != len(_MOUNT_ROSTER):
            raise ContractError("mount roster incomplete")
        if tuple(item.purpose for item in self.mounts if type(item) is MountRequest) != tuple(_MOUNT_ROSTER):
            raise ContractError("mount roster not canonical")
        paths: list[Path] = []
        for item in self.mounts:
            source = _absolute(item.source, "mount source")
            if any(_paths_related(source, prior) for prior in paths):
                raise ContractError("mount sources overlap")
            paths.append(source)
        for digest in (self.network_policy_sha256, self.seccomp_sha256):
            if not _SHA256_RE.fullmatch(digest):
                raise ContractError("invalid policy digest")
        _decimal(self.uid, "container uid", 1, (1 << 31) - 1)
        _decimal(self.gid, "container gid", 1, (1 << 31) - 1)
        _decimal(self.pids_limit, "pids limit", 16, 4096)
        _decimal(self.memory_bytes, "memory", 256 * 1024**2, 64 * 1024**3)
        _decimal(self.cpu_millis, "cpu", 100, 64_000)
        _decimal(self.nofile_limit, "nofile", 64, 65_536)
        _decimal(self.tmpfs_bytes, "tmpfs", 16 * 1024**2, 4 * 1024**3)

    @property
    def base_fingerprint(self) -> str:
        self.validate()
        return _hash(_canonical_json({
            "schema": PROVIDER_SCHEMA, "run": self.run_id, "number": self.attempt_number,
            "image": dataclasses.asdict(self.image), "entrypoint": self.entrypoint,
            "arguments": list(self.arguments), "environment": list(self.environment),
            "mount_requests": [{"purpose": item.purpose, "source": os.fspath(item.source)} for item in self.mounts],
            "network": self.network_policy_sha256, "seccomp": self.seccomp_sha256,
            "uid": self.uid, "gid": self.gid, "pids": self.pids_limit,
            "memory": self.memory_bytes, "cpu": self.cpu_millis,
            "nofile": self.nofile_limit, "tmpfs": self.tmpfs_bytes,
        }))


@dataclasses.dataclass(frozen=True, slots=True)
class _BoundContext:
    spec: ContainerSpec
    bindings: tuple[PathBinding, ...]
    topology: OverlayTopology
    network: NetworkProof
    lease: ExecutionLease
    cleanup: CleanupLease
    admission: AdmissionReservation
    admission_stages: tuple[AdmissionStageReceipt, ...]
    bindings_sha256: str
    context_sha256: str
    attempt_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class ImageObservation:
    id: str
    digest: str
    os: str
    architecture: str
    repo_digests: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ImageArchive:
    path: Path = dataclasses.field(repr=False)
    content_sha256: str
    image_digest: str
    single_image: bool
    oci_layout_verified: bool

    def validate(self, digest: str) -> None:
        _absolute(self.path, "image archive")
        if (not _SHA256_RE.fullmatch(self.content_sha256) or self.image_digest != digest
                or self.single_image is not True or self.oci_layout_verified is not True):
            raise AdmissionError("image archive identity mismatch")


class ContainerState(enum.Enum):
    ABSENT = "absent"
    CREATED = "created"
    RUNNING = "running"
    EXITED = "exited"


@dataclasses.dataclass(frozen=True, slots=True)
class ContainerObservation:
    state: ContainerState
    container_id: str | None
    exit_code: int | None
    observation_sha256: str


_RECEIPTS: dict[int, str] = {}


class ProviderReceipt:
    __slots__ = ("_document", "_digest")
    def __new__(cls, *_args: object, **_kwargs: object) -> "ProviderReceipt":
        raise TypeError("private-issued receipt")
    @property
    def document(self) -> Mapping[str, object]: return self._document
    @property
    def digest(self) -> str: return self._digest


def _receipt(document: dict[str, object]) -> ProviderReceipt:
    result = object.__new__(ProviderReceipt)
    digest = _hash(_canonical_json(document))
    object.__setattr__(result, "_document", MappingProxyType(dict(document)))
    object.__setattr__(result, "_digest", digest)
    _RECEIPTS[id(result)] = digest
    return result


def verify_receipt(receipt: object) -> bool:
    if type(receipt) is not ProviderReceipt:
        return False
    try:
        return (_RECEIPTS.get(id(receipt)) == receipt.digest
                == _hash(_canonical_json(dict(receipt.document))))
    except Exception:
        return False


_IMAGE_KEYS = frozenset({"id", "digest", "os", "architecture", "repo_digests"})
_CONTAINER_KEYS = frozenset({
    "id", "name", "image_digest", "state", "running", "exit_code", "pid",
    "conmon_pid", "cgroup_path", "labels", "hostname", "use_image_hosts",
    "use_image_hostname", "network_mode", "user", "userns_mode", "env",
    "mounts", "tmpfs", "effective_caps", "bounding_caps", "oci_runtime",
    "restart_policy", "read_only", "privileged", "devices", "cap_add",
    "pid_mode", "ipc_mode", "uts_mode", "cgroup_mode", "cgroups", "memory",
    "memory_swap", "nano_cpus", "pids_limit", "ulimits", "security_opt",
    "log_driver", "healthcheck", "systemd", "sdnotify",
})

_IMAGE_INSPECT_TEMPLATE = (
    "{\"id\":{{json .Id}},\"digest\":{{json .Digest}},"
    "\"os\":{{json .Os}},\"architecture\":{{json .Architecture}},"
    "\"repo_digests\":{{json .RepoDigests}}}"
)
_CONTAINER_INSPECT_TEMPLATE = (
    "{\"id\":{{json .Id}},\"name\":{{json .Name}},"
    "\"image_digest\":{{json .ImageDigest}},\"state\":{{json .State.Status}},"
    "\"running\":{{json .State.Running}},\"exit_code\":{{json .State.ExitCode}},"
    "\"pid\":{{json .State.Pid}},\"conmon_pid\":{{json .State.ConmonPid}},"
    "\"cgroup_path\":{{json .State.CgroupPath}},\"labels\":{{json .Config.Labels}},"
    "\"hostname\":{{json .Config.Hostname}},\"use_image_hosts\":{{json .Config.UseImageHosts}},"
    "\"use_image_hostname\":{{json .Config.UseImageHostname}},"
    "\"network_mode\":{{json .HostConfig.NetworkMode}},\"user\":{{json .Config.User}},"
    "\"userns_mode\":{{json .HostConfig.UsernsMode}},\"env\":{{json .Config.Env}},"
    "\"mounts\":{{json .Mounts}},\"tmpfs\":{{json .HostConfig.Tmpfs}},"
    "\"effective_caps\":{{json .EffectiveCaps}},\"bounding_caps\":{{json .BoundingCaps}},"
    "\"oci_runtime\":{{json .OCIRuntime}},\"restart_policy\":{{json .HostConfig.RestartPolicy.Name}},"
    "\"read_only\":{{json .HostConfig.ReadonlyRootfs}},"
    "\"privileged\":{{json .HostConfig.Privileged}},\"devices\":{{json .HostConfig.Devices}},"
    "\"cap_add\":{{json .HostConfig.CapAdd}},\"pid_mode\":{{json .HostConfig.PidMode}},"
    "\"ipc_mode\":{{json .HostConfig.IpcMode}},\"uts_mode\":{{json .HostConfig.UTSMode}},"
    "\"cgroup_mode\":{{json .HostConfig.CgroupMode}},\"cgroups\":{{json .HostConfig.Cgroups}},"
    "\"memory\":{{json .HostConfig.Memory}},\"memory_swap\":{{json .HostConfig.MemorySwap}},"
    "\"nano_cpus\":{{json .HostConfig.NanoCpus}},\"pids_limit\":{{json .HostConfig.PidsLimit}},"
    "\"ulimits\":{{json .HostConfig.Ulimits}},\"security_opt\":{{json .HostConfig.SecurityOpt}},"
    "\"log_driver\":{{json .HostConfig.LogConfig.Type}},"
    "\"healthcheck\":{{json .Config.Healthcheck}},\"systemd\":{{json .HostConfig.SystemdMode}},"
    "\"sdnotify\":{{json .HostConfig.SdNotifyMode}}}"
)


class PodmanLinuxProvider:
    """Rootless Linux provider. All native effects belong to injected authorities."""

    def __init__(self, *, components: ComponentIdentities, roots: ProviderRoots,
                 runner: Runner, paths: PathAuthority, journal: MutationJournal,
                 network: NetworkAuthority, host_facts: HostFacts) -> None:
        self._components, self._roots, self._runner = components, roots, runner
        self._paths, self._journal, self._network, self._host = paths, journal, network, host_facts
        self._runner_contract: RunnerContract | None = None
        self._path_contract: PathAuthorityContract | None = None
        self._journal_contract: JournalContract | None = None
        self._network_contract: NetworkAuthorityContract | None = None
        self._root_bindings: tuple[PathBinding, ...] = ()
        self._contexts: dict[tuple[str, int], _BoundContext] = {}
        self._active_mutation: tuple[
            str, str, str, str | None, PathBinding | None, str
        ] | None = None
        self._rendered_create: dict[str, str] = {}
        self._effect_entered: set[str] = set()
        self._component_sequence = 0
        self._component_observed_ns = 0
        self._extinction_sequences: dict[str, tuple[int, int]] = {}
        self._released_attempts: set[str] = set()

    def _authority_call(self, call: Callable[[], T], error: type[ProviderError], message: str) -> T:
        return _sanitized(call, error, message)

    def preflight(self) -> ProviderReceipt:
        if platform.system() != "Linux":
            raise PreflightError("native Linux host required")
        _validated(self._host, PreflightError, "invalid host facts")
        _validated(self._components, PreflightError, "invalid component identities")
        _validated(self._roots, PreflightError, "invalid provider roots", self._host)
        path_contract = self._authority_call(self._paths.security_contract, PreflightError, "path authority preflight failed")
        journal_contract = self._authority_call(self._journal.security_contract, PreflightError, "journal preflight failed")
        network_contract = self._authority_call(self._network.security_contract, PreflightError, "network preflight failed")
        _validated(path_contract, PreflightError, "invalid path authority contract")
        _validated(journal_contract, PreflightError, "invalid journal contract")
        _validated(network_contract, PreflightError, "invalid network authority contract")
        self._path_contract = path_contract
        roots: list[PathBinding] = []
        identities: set[tuple[int, int]] = set()
        purposes = ("provider-storage", "provider-runroot", "provider-tmp",
                    "provider-home", "provider-runtime", "provider-overlay")
        for purpose, source in zip(purposes, dataclasses.astuple(self._roots), strict=True):
            binding = self._admit_path(source, purpose=purpose, target="", readonly=False,
                                       kind="directory", byte_limit=32 * 1024**3,
                                       mapped_uid=self._host.real_uid, mapped_gid=self._host.real_gid)
            if (binding.device, binding.inode) in identities or binding.uid != self._host.real_uid:
                raise PreflightError("provider root identity unsafe")
            identities.add((binding.device, binding.inode))
            roots.append(binding)
        self._root_bindings = tuple(roots)
        root_digest = self._bindings_digest(self._root_bindings)
        runner_contract = self._authority_call(
            lambda: self._runner.security_contract(self._components, self._roots,
                                                    self._host, self._root_bindings),
            PreflightError, "runner preflight failed",
        )
        _validated(runner_contract, PreflightError, "invalid runner contract",
                   self._components, self._roots, self._host, root_digest)
        if len({runner_contract.authority_id, path_contract.authority_id,
                journal_contract.authority_id, network_contract.authority_id}) != 4:
            raise PreflightError("authority identities collide")
        self._runner_contract, self._journal_contract, self._network_contract = (
            runner_contract, journal_contract, network_contract)
        executables = (self._components.podman, self._components.conmon, self._components.crun,
                       self._components.newuidmap, self._components.newgidmap,
                       self._components.overlay_helper)
        for (label, version), executable in zip(ComponentIdentities.pins(), executables, strict=True):
            plan = self._plan(f"version-{label}", (os.fspath(executable.path), "--version"))
            result = self._invoke(plan, bindings=(), output=None, network=None,
                                  lease=None, timeout=10.0)
            text = _sanitized(lambda: result.stdout.decode("ascii", "strict").strip(),
                              PreflightError, "component version output mismatch")
            first = text.splitlines()[0] if text.splitlines() else ""
            patterns = {
                "podman": rf"podman version {re.escape(version)}(?:, commit: [0-9a-f]{{1,64}})?",
                "conmon": rf"conmon version {re.escape(version)}(?:, commit: [0-9a-f]{{1,64}})?",
                "crun": rf"crun version {re.escape(version)}(?:, commit: [0-9a-f]{{1,64}})?",
                "newuidmap": rf"newuidmap from shadow-utils {re.escape(version)}",
                "newgidmap": rf"newgidmap from shadow-utils {re.escape(version)}",
                "fuse-overlayfs": rf"fuse-overlayfs: version {re.escape(version)}",
            }
            if len(text) > 4096 or re.fullmatch(patterns[label], first) is None:
                raise PreflightError("component version output mismatch")
        return _receipt({"schema": PROVIDER_SCHEMA, "kind": "preflight",
                         "components": self._components.digest,
                         "root_bindings": root_digest,
                         "mapping": "keep-id", "host": "linux-rootless"})

    def _require_ready(self) -> None:
        if any(value is None for value in (self._runner_contract, self._path_contract,
                                           self._journal_contract, self._network_contract)):
            raise PreflightError("provider preflight incomplete")

    @staticmethod
    def _bindings_digest(bindings: tuple[PathBinding, ...]) -> str:
        return _hash(_canonical_json([binding.document for binding in bindings]))

    def _admit_path(self, source: Path, *, purpose: str, target: str, readonly: bool,
                    kind: str, byte_limit: int, mapped_uid: int,
                    mapped_gid: int,
                    reservation: AdmissionReservation | None = None
                    ) -> PathBinding:
        binding = self._authority_call(
            lambda: self._paths.admit(source, purpose=purpose, target=target,
                                      readonly=readonly, kind=kind, byte_limit=byte_limit,
                                      mapped_uid=mapped_uid,
                                      mapped_gid=mapped_gid,
                                      reservation=reservation),
            AdmissionError, "path admission failed",
        )
        if type(binding) is not PathBinding:
            raise AdmissionError("invalid path binding type")
        _validated(binding, AdmissionError, "invalid path binding")
        actual = (binding.source, binding.purpose, binding.target, binding.readonly,
                  binding.kind, binding.byte_limit, binding.mapped_uid, binding.mapped_gid)
        expected = (source, purpose, target, readonly, kind, byte_limit, mapped_uid, mapped_gid)
        if actual != expected:
            raise AdmissionError("path authority changed binding semantics")
        return binding

    def _revalidate_binding(self, binding: PathBinding) -> None:
        current = self._authority_call(lambda: self._paths.revalidate(binding),
                                       AdmissionError, "path revalidation failed")
        if type(current) is not PathBinding or current != binding:
            raise AdmissionError("path binding changed")

    def _reject_relations(self, bindings: tuple[PathBinding, ...], *, allow_overlay: bool = False) -> None:
        sensitive = (self._host.home_path,) + self._host.credential_roots
        for index, binding in enumerate(bindings):
            if any(_paths_related(binding.source, root) for root in sensitive):
                raise AdmissionError("binding overlaps sensitive root")
            for other in bindings[index + 1:]:
                if (binding.device, binding.inode) == (other.device, other.inode):
                    raise AdmissionError("binding identities alias")
                if _paths_related(binding.source, other.source):
                    raise AdmissionError("binding paths overlap")
        for binding in bindings:
            for root_binding in self._root_bindings:
                related = _paths_related(binding.source, root_binding.source)
                declared = (allow_overlay and binding.purpose in {
                    "project-upper", "project-work", "project-merged"
                } and root_binding.purpose == "provider-overlay")
                if related and not declared:
                    raise AdmissionError("binding overlaps provider authority")

    def _admit_export_destination(
            self, destination: Path, *, byte_limit: int,
            mapped_uid: int, mapped_gid: int) -> ArtifactDestination:
        output = self._authority_call(
            lambda: self._paths.admit_export(
                destination, byte_limit=byte_limit,
                mapped_uid=mapped_uid, mapped_gid=mapped_gid),
            AdmissionError, "artifact destination admission failed")
        if type(output) is not ArtifactDestination:
            raise AdmissionError("invalid artifact destination type")
        assert self._path_contract is not None
        _validated(output, AdmissionError,
                   "invalid artifact destination", self._path_contract)
        if (output.path, output.byte_limit, output.mapped_uid,
                output.mapped_gid) != (
                destination, byte_limit, mapped_uid, mapped_gid):
            raise AdmissionError("artifact destination semantics changed")
        self._revalidate_export_destination(output)
        return output

    def _revalidate_export_destination(
            self, destination: ArtifactDestination) -> None:
        current = self._authority_call(
            lambda: self._paths.revalidate_export(destination),
            AdmissionError, "artifact destination revalidation failed")
        if type(current) is not ArtifactDestination or current != destination:
            raise AdmissionError("artifact destination slot changed")

    def _reject_export_destination(self, output: ArtifactDestination,
                                   context: _BoundContext) -> None:
        """Keep an output file outside every authority-bearing input tree."""
        sensitive = (self._host.home_path,) + self._host.credential_roots
        if (output.parent.sensitive_overlap
                or any(_paths_related(output.path, root) for root in sensitive)):
            raise AdmissionError("export destination overlaps sensitive tree")
        protected = self._root_bindings + context.bindings
        for binding in protected:
            if (_paths_related(output.path, binding.source)
                    or (output.parent.device, output.parent.inode) ==
                       (binding.device, binding.inode)):
                raise AdmissionError("export destination overlaps admitted tree")
        # Executable parents are security trees even though only executable FDs
        # are handed to the native runner.
        executables = (
            self._components.podman, self._components.conmon,
            self._components.crun, self._components.newuidmap,
            self._components.newgidmap, self._components.overlay_helper,
        )
        if any(_paths_related(output.path, item.path.parent)
               or (output.parent.device, output.parent.inode) ==
                  (item.device, item.inode)
               for item in executables):
            raise AdmissionError("export destination overlaps executable tree")

    @staticmethod
    def _artifact_sources(context: _BoundContext) -> tuple[PathBinding, ...]:
        # Podman container export intentionally is not used: OCI rootfs export
        # excludes bind-mounted audit products. These are packaged after process
        # extinction by the descriptor-owning path authority.
        purposes = ("project-merged", "state", "scratch")
        return tuple(next(item for item in context.bindings
                          if item.purpose == purpose)
                     for purpose in purposes)

    def _artifact_identity(self, context: _BoundContext) -> tuple[
            tuple[PathBinding, ...], str, str]:
        sources = self._artifact_sources(context)
        source_set = self._bindings_digest(sources)
        manifest = _hash(_canonical_json({
            "schema": PROVIDER_SCHEMA, "attempt": context.attempt_id,
            "context": context.context_sha256,
            "sources": [item.document for item in sources],
        }))
        return sources, source_set, manifest

    def _validate_artifact_commit(self, commit: object,
                                  destination: ArtifactDestination,
                                  context: _BoundContext,
                                  source_set: str,
                                  manifest: str) -> ArtifactCommit:
        if type(commit) is not ArtifactCommit:
            raise StateError("invalid artifact commit type")
        assert self._path_contract is not None
        _validated(commit, StateError, "invalid artifact commit",
                   self._path_contract, destination, context.attempt_id,
                   manifest, source_set)
        self._revalidate_binding(commit.binding)
        authenticated = self._authority_call(
            lambda: self._paths.verify_artifact(commit), StateError,
            "artifact commit authentication failed")
        if authenticated is not True:
            raise StateError("artifact commit authentication failed")
        self._revalidate_export_destination(destination)
        # The newly published file is separately admitted and must not alias or
        # nest any input/authority tree.
        self._reject_export_destination(destination, context)
        for binding in self._root_bindings + context.bindings:
            if ((commit.binding.device, commit.binding.inode) ==
                    (binding.device, binding.inode)):
                raise StateError("artifact published inode aliases input")
        return commit

    def _admit_mounts(
            self, spec: ContainerSpec,
            reservation: AdmissionReservation) -> tuple[PathBinding, ...]:
        bindings: list[PathBinding] = []
        for request in spec.mounts:
            target, readonly, kind, limit = _MOUNT_ROSTER[request.purpose]
            mapped_uid, mapped_gid = ((0, 0) if readonly else (spec.uid, spec.gid))
            binding = self._admit_path(request.source, purpose=request.purpose,
                                       target=target, readonly=readonly, kind=kind,
                                       byte_limit=limit, mapped_uid=mapped_uid,
                                       mapped_gid=mapped_gid,
                                       reservation=reservation)
            if request.purpose == "seccomp" and binding.snapshot_sha256 != spec.seccomp_sha256:
                raise AdmissionError("seccomp policy identity mismatch")
            if not readonly and (binding.uid, binding.gid, binding.mapped_uid,
                                 binding.mapped_gid, binding.keep_id_writable) != (
                    self._host.real_uid, self._host.real_gid, spec.uid, spec.gid, True):
                raise AdmissionError("writable mount lacks usable keep-id mapping")
            self._revalidate_binding(binding)
            bindings.append(binding)
        result = tuple(bindings)
        self._reject_relations(result, allow_overlay=True)
        return result

    def _network_proof(self, spec: ContainerSpec,
                       reservation: AdmissionReservation) -> NetworkProof:
        assert self._network_contract is not None
        proof = self._authority_call(lambda: self._network.admit(
            spec.network_policy_sha256, reservation),
                                     AdmissionError, "network admission failed")
        _validated(proof, AdmissionError, "invalid network proof", self._network_contract)
        if proof.policy_sha256 != spec.network_policy_sha256:
            raise AdmissionError("network policy mismatch")
        # Podman 6.1.1 documents --preserve-fd for `run`, not `create`.
        # A split create/start lifecycle therefore admits only an authority-held
        # narrow network-namespace FD. PRIVATE_SHIM remains fail-closed here.
        if proof.kind is not NetworkKind.VERIFIED_NARROW_PROXY:
            raise AdmissionError("network proof unsupported by split lifecycle")
        current = self._authority_call(lambda: self._network.revalidate(proof),
                                       AdmissionError, "network revalidation failed")
        if current != proof:
            raise AdmissionError("network proof changed or revoked")
        return proof

    def _attempt_id(self, spec: ContainerSpec) -> str:
        """Durable journal address independent of leased/ephemeral evidence."""
        _validated(spec, ContractError, "invalid container specification")
        return "plamen-" + _hash(_canonical_json({
            "schema": PROVIDER_SCHEMA,
            "run": spec.run_id,
            "number": spec.attempt_number,
            "base": spec.base_fingerprint,
            "components": self._components.digest,
            "roots": self._roots.digest,
            "host": self._host.digest,
        }))[:32]

    def _context_digest(self, spec: ContainerSpec,
                        bindings: tuple[PathBinding, ...],
                        topology: OverlayTopology, network: NetworkProof,
                        lease: ExecutionLease, cleanup: CleanupLease,
                        admission: AdmissionReservation) -> str:
        return self._context_digest_evidence(
            spec, bindings, topology, network, lease, cleanup,
            self._root_bindings, admission)

    @staticmethod
    def _context_digest_evidence(
            spec: ContainerSpec, bindings: tuple[PathBinding, ...],
            topology: OverlayTopology, network: NetworkProof,
            lease: ExecutionLease, cleanup: CleanupLease,
            root_bindings: tuple[PathBinding, ...],
            admission: AdmissionReservation) -> str:
        network_doc = dataclasses.asdict(network)
        network_doc["kind"] = network.kind.value
        return _hash(_canonical_json({
            "base": spec.base_fingerprint,
            "bindings": [item.document for item in bindings],
            "overlay": dataclasses.asdict(topology), "network": network_doc,
            "lease": dataclasses.asdict(lease),
            "cleanup": dataclasses.asdict(cleanup),
            "admission": admission.digest,
            "root_bindings": PodmanLinuxProvider._bindings_digest(
                root_bindings),
        }))

    def _context_from_record(self, spec: ContainerSpec,
                             record: MutationRecord,
                             *, require_network: bool,
                             revalidate: bool = True) -> _BoundContext:
        if (record.attempt_id != self._attempt_id(spec)
                or record.base_spec_sha256 != spec.base_fingerprint):
            raise StateError("journal stable address changed")
        self._adopt_record_roots(record.root_bindings)
        context = _BoundContext(
            spec, record.bindings, record.topology, record.network,
            record.lease, record.cleanup, record.admission,
            record.admission_stages,
            record.bindings_sha256,
            record.context_sha256, record.attempt_id,
        )
        if self._context_digest(
                spec, context.bindings, context.topology, context.network,
                context.lease, context.cleanup,
                context.admission) != context.context_sha256:
            raise StateError("journal context digest mismatch")
        assert self._path_contract is not None
        assert self._network_contract is not None
        assert self._runner_contract is not None
        _validated(context.topology, StateError,
                   "invalid journal overlay topology", self._path_contract,
                   context.bindings, spec.uid, spec.gid)
        _validated(context.lease, StateError,
                   "invalid journal execution lease", self._runner_contract,
                   context.lease.attempt_seed)
        _validated(context.cleanup, StateError,
                   "invalid journal cleanup authority", self._runner_contract,
                   context.lease)
        _validated(context.network, StateError,
                   "invalid journal network proof", self._network_contract,
                   False)
        self._assert_record_context(record, context)
        if revalidate:
            self._revalidate_context(context, require_network=require_network)
        return context

    def _adopt_record_roots(
            self, bindings: tuple[PathBinding, ...]) -> None:
        """Resume persisted root capabilities instead of issuing recovery ones."""
        purposes = ("provider-storage", "provider-runroot", "provider-tmp",
                    "provider-home", "provider-runtime", "provider-overlay")
        sources = dataclasses.astuple(self._roots)
        if type(bindings) is not tuple or len(bindings) != len(purposes):
            raise StateError("journal provider root roster mismatch")
        identities: set[tuple[int, int]] = set()
        for binding, purpose, source in zip(
                bindings, purposes, sources, strict=True):
            _validated(binding, StateError, "invalid journal provider root")
            expected = (source, purpose, "", False, "directory",
                        32 * 1024**3, self._host.real_uid,
                        self._host.real_gid)
            actual = (binding.source, binding.purpose, binding.target,
                      binding.readonly, binding.kind, binding.byte_limit,
                      binding.mapped_uid, binding.mapped_gid)
            identity = (binding.device, binding.inode)
            if (actual != expected or binding.uid != self._host.real_uid
                    or binding.gid != self._host.real_gid
                    or binding.keep_id_writable is not True
                    or identity in identities):
                raise StateError("journal provider root semantics changed")
            identities.add(identity)
            self._revalidate_binding(binding)
        root_digest = self._bindings_digest(bindings)
        contract = self._authority_call(
            lambda: self._runner.security_contract(
                self._components, self._roots, self._host, bindings),
            StateError, "runner root capability resume failed")
        _validated(contract, StateError, "invalid resumed runner contract",
                   self._components, self._roots, self._host, root_digest)
        if (self._runner_contract is None
                or contract.authority_id != self._runner_contract.authority_id):
            raise StateError("runner authority changed during recovery")
        self._root_bindings = bindings
        self._runner_contract = contract

    def _load_admission(
            self, spec: ContainerSpec) -> AdmissionReservation | None:
        attempt = self._attempt_id(spec)
        reservation = self._authority_call(
            lambda: self._journal.load_admission(attempt), StateError,
            "admission reservation read failed")
        if reservation is None:
            return None
        if type(reservation) is not AdmissionReservation:
            raise StateError("invalid admission reservation type")
        assert self._journal_contract is not None
        _validated(reservation, StateError,
                   "invalid admission reservation",
                   self._journal_contract, attempt,
                   spec.base_fingerprint)
        verified = self._authority_call(
            lambda: self._journal.verify_admission(reservation), StateError,
            "admission reservation authentication failed")
        if verified is not True:
            raise StateError("admission reservation authentication failed")
        return reservation

    def _reserve_admission(self, spec: ContainerSpec) -> AdmissionReservation:
        if self._load_admission(spec) is not None:
            raise AmbiguousMutationError(
                "earlier context admission requires recovery")
        attempt = self._attempt_id(spec)
        reservation = self._authority_call(
            lambda: self._journal.reserve_admission(
                attempt, base_spec_sha256=spec.base_fingerprint),
            AmbiguousMutationError,
            "context admission reservation failed")
        if type(reservation) is not AdmissionReservation:
            raise AmbiguousMutationError("invalid admission reservation type")
        assert self._journal_contract is not None
        _validated(reservation, AmbiguousMutationError,
                   "invalid admission reservation",
                   self._journal_contract, attempt,
                   spec.base_fingerprint)
        verified = self._authority_call(
            lambda: self._journal.verify_admission(reservation),
            AmbiguousMutationError,
            "admission reservation authentication failed")
        if verified is not True:
            raise AmbiguousMutationError(
                "admission reservation authentication failed")
        return reservation

    def _claim_attempt_recovery(
            self, spec: ContainerSpec) -> AttemptRecoverySnapshot:
        """Atomically read the attempt head and claim any admission cleanup."""
        attempt = self._attempt_id(spec)
        snapshot = self._authority_call(
            lambda: self._journal.claim_attempt_recovery(
                attempt, base_spec_sha256=spec.base_fingerprint),
            _JournalRollback, "atomic attempt recovery claim unavailable")
        if type(snapshot) is not AttemptRecoverySnapshot:
            raise _JournalRollback("invalid attempt recovery snapshot type")
        assert self._journal_contract is not None
        _validated(snapshot, _JournalRollback,
                   "invalid attempt recovery snapshot",
                   self._journal_contract, attempt,
                   spec.base_fingerprint)
        verified = self._authority_call(
            lambda: self._journal.verify_attempt_recovery(snapshot),
            _JournalRollback,
            "attempt recovery snapshot authentication failed")
        if verified is not True:
            raise _JournalRollback(
                "attempt recovery snapshot authentication failed")
        if snapshot.record_snapshot is not None:
            record_verified = self._authority_call(
                lambda: self._journal.verify_snapshot(
                    snapshot.record_snapshot),
                _JournalRollback,
                "nested journal snapshot authentication failed")
            if record_verified is not True:
                raise _JournalRollback(
                    "nested journal snapshot authentication failed")
        elif snapshot.admission is not None:
            admission_verified = self._authority_call(
                lambda: self._journal.verify_admission(
                    snapshot.admission),
                _JournalRollback,
                "claimed admission authentication failed")
            if admission_verified is not True:
                raise _JournalRollback(
                    "claimed admission authentication failed")
        return snapshot

    def _commit_admission_stage(
            self, reservation: AdmissionReservation, *, stage: str,
            ordinal: int, resource_sha256: str,
            receipts: list[AdmissionStageReceipt]) -> None:
        expected = ("paths", "overlay", "network", "execution", "cleanup")
        if (not 1 <= ordinal <= len(expected)
                or stage != expected[ordinal - 1]
                or len(receipts) != ordinal - 1
                or not _SHA256_RE.fullmatch(resource_sha256)):
            raise StateError("invalid admission stage transition")
        previous = receipts[-1].digest if receipts else "0" * 64
        receipt = self._authority_call(
            lambda: self._journal.commit_admission_stage(
                reservation, stage=stage, ordinal=ordinal,
                resource_sha256=resource_sha256,
                previous_stage_sha256=previous),
            AmbiguousMutationError,
            "admission stage commit failed")
        if type(receipt) is not AdmissionStageReceipt:
            raise AmbiguousMutationError("invalid admission stage receipt")
        assert self._journal_contract is not None
        _validated(receipt, AmbiguousMutationError,
                   "invalid admission stage receipt",
                   self._journal_contract, reservation, stage, ordinal,
                   resource_sha256, previous)
        verified = self._authority_call(
            lambda: self._journal.verify_admission_stage(receipt),
            AmbiguousMutationError,
            "admission stage authentication failed")
        if verified is not True:
            raise AmbiguousMutationError(
                "admission stage authentication failed")
        receipts.append(receipt)

    def _cleanup_admission(
            self, reservation: AdmissionReservation,
            recovery_snapshot: AttemptRecoverySnapshot | None = None, *,
            spec: ContainerSpec | None = None,
            ) -> ProviderReceipt:
        """Idempotently unwind every possible resource-acquisition prefix."""
        if recovery_snapshot is None:
            if spec is None:
                raise StateError("admission specification unavailable")
            recovery_snapshot = self._claim_attempt_recovery(
                spec)
        if (type(recovery_snapshot) is not AttemptRecoverySnapshot
                or recovery_snapshot.admission != reservation
                or recovery_snapshot.cleanup_claim_sha256 is None
                or recovery_snapshot.cleanup_claimed is not True):
            raise StateError("admission cleanup claim changed")
        stages = recovery_snapshot.admission_stages
        stages_authenticated = True
        if (type(stages) is not tuple or len(stages) > 5
                or any(type(item) is not AdmissionStageReceipt
                       for item in stages)):
            stages = ()
            stages_authenticated = False
        assert self._journal_contract is not None
        previous = "0" * 64
        expected = ("paths", "overlay", "network", "execution", "cleanup")
        if stages_authenticated:
            try:
                for ordinal, receipt in enumerate(stages, 1):
                    receipt.validate(
                        self._journal_contract, reservation,
                        expected[ordinal - 1], ordinal,
                        receipt.resource_sha256, previous)
                    if self._journal.verify_admission_stage(receipt) is not True:
                        raise ValueError
                    previous = receipt.digest
            except Exception:
                stages_authenticated = False
        # Stage damage or rollback must not become a kill switch: each native
        # authority discovers attempt resources through the authenticated
        # reservation/cleanup label and conservatively extinguishes them.
        nonce = _hash(os.urandom(32))
        assert self._network_contract is not None
        assert self._path_contract is not None
        assert self._runner_contract is not None
        authorities = (
            ("network", self._network_contract.authority_id,
             self._network.cleanup_admission,
             self._network.verify_admission_cleanup),
            ("paths", self._path_contract.authority_id,
             self._paths.cleanup_admission,
             self._paths.verify_admission_cleanup),
            ("runner", self._runner_contract.authority_id,
             self._runner.cleanup_admission,
             self._runner.verify_admission_cleanup),
        )
        checked: list[AdmissionCleanupReceipt] = []
        failed = False
        for kind, authority_id, cleanup, verify in authorities:
            receipt: AdmissionCleanupReceipt | None = None
            try:
                candidate = cleanup(reservation, cleanup_nonce=nonce)
                if type(candidate) is not AdmissionCleanupReceipt:
                    raise TypeError
                candidate.validate(
                    authority_id=authority_id, kind=kind,
                    reservation=reservation, cleanup_nonce=nonce)
                if verify(candidate) is not True:
                    raise ValueError
                receipt = candidate
            except Exception:
                failed = True
            if receipt is not None:
                checked.append(receipt)
        # Exercise every independent authority even after a partial failure.
        # The durable reservation remains live unless the entire idempotent
        # unwind roster authenticates, so a cold process can safely retry.
        if failed or len(checked) != len(authorities):
            raise StateError("admission resources may remain")
        retirement = self._authority_call(
            lambda: self._journal.complete_admission_cleanup(
                reservation, recovery_snapshot.cleanup_claim_sha256,
                tuple(checked)), StateError,
            "admission cleanup commit failed")
        if type(retirement) is not AdmissionRetirement:
            raise StateError("invalid admission retirement type")
        assert self._journal_contract is not None
        _validated(retirement, StateError,
                   "invalid admission retirement",
                   self._journal_contract, reservation,
                   recovery_snapshot.cleanup_claim_sha256,
                   tuple(checked))
        retirement_verified = self._authority_call(
            lambda: self._journal.verify_admission_retirement(retirement),
            StateError, "admission retirement authentication failed")
        if retirement_verified is not True:
            raise StateError("admission retirement authentication failed")
        return _receipt({
            "schema": PROVIDER_SCHEMA, "kind": "admission-recovery",
            "attempt": reservation.attempt_id,
            "status": "reservation-resources-extinct",
            "reservation": reservation.digest,
            "reservation_generation": reservation.generation,
            "retirement": retirement.digest,
            "stages": ([item.stage for item in stages]
                       if stages_authenticated else []),
            "stages_authenticated": stages_authenticated,
            "receipts": [item.digest for item in checked],
        })

    def _context(self, spec: ContainerSpec, *,
                 require_network: bool = True) -> _BoundContext:
        self._require_ready()
        _validated(spec, ContractError, "invalid container specification")
        key = (spec.run_id, spec.attempt_number)
        prior = self._contexts.get(key)
        if prior is not None:
            if prior.spec.base_fingerprint != spec.base_fingerprint:
                raise StateError("attempt key replayed with another specification")
            if prior.attempt_id in self._released_attempts:
                raise StateError("attempt resources already released")
            self._revalidate_context(prior, require_network=require_network)
            return prior
        attempt = self._attempt_id(spec)
        durable = self._record(attempt)
        if durable is not None:
            if (durable.operation == "release"
                    and durable.state is MutationState.COMPLETE):
                self._released_attempts.add(attempt)
                raise StateError("attempt resources already released")
            context = self._context_from_record(
                spec, durable, require_network=require_network)
            self._contexts[key] = context
            return context
        reservation = self._reserve_admission(spec)
        stages: list[AdmissionStageReceipt] = []
        failed = False
        context: _BoundContext | None = None
        try:
            bindings = self._admit_mounts(spec, reservation)
            bindings_digest = self._bindings_digest(bindings)
            self._commit_admission_stage(
                reservation, stage="paths", ordinal=1,
                resource_sha256=bindings_digest, receipts=stages)
            assert self._path_contract is not None
            assert self._runner_contract is not None
            topology = self._authority_call(
                lambda: self._paths.admit_overlay(
                    bindings, uid=spec.uid, gid=spec.gid,
                    reservation=reservation),
                AdmissionError, "overlay admission failed",
            )
            _validated(topology, AdmissionError,
                       "invalid overlay topology", self._path_contract,
                       bindings, spec.uid, spec.gid)
            self._commit_admission_stage(
                reservation, stage="overlay", ordinal=2,
                resource_sha256=topology.digest, receipts=stages)
            proof = self._network_proof(spec, reservation)
            self._commit_admission_stage(
                reservation, stage="network", ordinal=3,
                resource_sha256=proof.digest, receipts=stages)
            seed = "plamen-seed-" + _hash(_canonical_json({
                "base": spec.base_fingerprint,
                "bindings": bindings_digest,
                "overlay": topology.digest, "network": proof.digest,
            }))[:32]
            lease = self._authority_call(
                lambda: self._runner.acquire_lease(
                    seed, uid=spec.uid, gid=spec.gid,
                    reservation=reservation),
                AdmissionError, "execution lease admission failed",
            )
            _validated(lease, AdmissionError, "invalid execution lease",
                       self._runner_contract, seed)
            self._commit_admission_stage(
                reservation, stage="execution", ordinal=4,
                resource_sha256=lease.digest, receipts=stages)
            cleanup = self._authority_call(
                lambda: self._runner.acquire_cleanup(lease), AdmissionError,
                "cleanup authority admission failed",
            )
            if type(cleanup) is not CleanupLease:
                raise AdmissionError("invalid cleanup authority type")
            _validated(cleanup, AdmissionError,
                       "invalid cleanup authority",
                       self._runner_contract, lease)
            self._commit_admission_stage(
                reservation, stage="cleanup", ordinal=5,
                resource_sha256=cleanup.digest, receipts=stages)
            context_digest = self._context_digest(
                spec, bindings, topology, proof, lease, cleanup,
                reservation)
            context = _BoundContext(
                spec, bindings, topology, proof, lease, cleanup,
                reservation, tuple(stages), bindings_digest,
                context_digest, attempt)
            self._revalidate_context(
                context, require_network=require_network)
        except Exception:
            failed = True
        if failed or context is None:
            cleaned = True
            try:
                self._cleanup_admission(reservation, spec=spec)
            except Exception:
                cleaned = False
            if not cleaned:
                raise AmbiguousMutationError(
                    "context admission failed; recovery required")
            raise AdmissionError("context admission failed and was unwound")
        self._contexts[key] = context
        return context

    def _revalidate_context(self, context: _BoundContext, *,
                            require_network: bool = True) -> None:
        for binding in self._root_bindings + context.bindings:
            self._revalidate_binding(binding)
        assert self._path_contract is not None
        assert self._runner_contract is not None
        assert self._network_contract is not None
        topology = self._authority_call(
            lambda: self._paths.revalidate_overlay(context.topology, context.bindings),
            AdmissionError, "overlay revalidation failed",
        )
        if topology != context.topology:
            raise AdmissionError("overlay topology changed")
        _validated(topology, AdmissionError, "invalid overlay topology",
                   self._path_contract, context.bindings,
                   context.spec.uid, context.spec.gid)
        if require_network:
            network = self._authority_call(
                lambda: self._network.revalidate(context.network),
                AdmissionError, "network revalidation failed")
            if network != context.network:
                raise AdmissionError("network proof changed or revoked")
            _validated(network, AdmissionError, "invalid network proof",
                       self._network_contract)
        lease = self._authority_call(lambda: self._runner.revalidate_lease(context.lease),
                                     AdmissionError, "execution lease revalidation failed")
        if lease != context.lease:
            raise AdmissionError("execution lease changed")
        _validated(lease, AdmissionError, "invalid execution lease",
                   self._runner_contract, context.lease.attempt_seed)
        cleanup = self._authority_call(
            lambda: self._runner.revalidate_cleanup(context.cleanup),
            AdmissionError, "cleanup authority revalidation failed")
        if cleanup != context.cleanup:
            raise AdmissionError("cleanup authority changed")
        _validated(cleanup, AdmissionError, "invalid cleanup authority",
                   self._runner_contract, context.lease)

    def _observation_challenge(self, scope: str) -> ObservationChallenge:
        """Obtain a native durable, single-use challenge.

        Production must hard-stop unless this authority is backed by an
        authenticated external monotonic store. Python process memory is not an
        anti-replay boundary.
        """
        challenge = self._authority_call(
            lambda: self._journal.issue_observation_challenge(scope),
            StateError, "observation challenge unavailable")
        if type(challenge) is not ObservationChallenge:
            raise StateError("invalid observation challenge type")
        assert self._journal_contract is not None
        _validated(challenge, StateError, "invalid observation challenge",
                   self._journal_contract, scope)
        return challenge

    def _commit_observation(self, challenge: ObservationChallenge,
                            observation: ComponentObservation |
                            ExtinctionObservation) -> None:
        anchor = self._authority_call(
            lambda: self._journal.commit_observation(
                challenge, observation_sha256=observation.digest,
                sequence=observation.sequence,
                observed_monotonic_ns=observation.observed_monotonic_ns),
            StateError, "observation anchor commit failed")
        if type(anchor) is not ObservationAnchor:
            raise StateError("invalid observation anchor type")
        assert self._journal_contract is not None
        _validated(anchor, StateError, "invalid observation anchor",
                   self._journal_contract, challenge, observation.digest,
                   observation.sequence, observation.observed_monotonic_ns)
        verified = self._authority_call(
            lambda: self._journal.verify_observation_anchor(anchor),
            StateError, "observation anchor authentication failed")
        if verified is not True:
            raise StateError("observation anchor authentication failed")

    def _extinction(self, context: _BoundContext) -> ExtinctionObservation:
        """Acquire a new authenticated cgroup/conmon census every time."""
        assert self._runner_contract is not None
        challenge = self._observation_challenge(
            "extinction:" + context.attempt_id)
        observation = self._authority_call(
            lambda: self._runner.observe_extinction(
                context.lease, context.cleanup, challenge),
            StateError, "extinction observation failed")
        if type(observation) is not ExtinctionObservation:
            raise StateError("invalid extinction observation type")
        _validated(observation, StateError,
                   "invalid extinction observation", self._runner_contract,
                   context.lease, context.cleanup, challenge)
        if observation.sequence != challenge.generation:
            raise StateError("extinction sequence/challenge mismatch")
        self._commit_observation(challenge, observation)
        self._extinction_sequences[context.attempt_id] = (
            observation.sequence, observation.observed_monotonic_ns)
        return observation

    @staticmethod
    def _extinction_document(
            observation: ExtinctionObservation) -> dict[str, object]:
        return {
            "extinction": observation.digest,
            "extinction_sequence": observation.sequence,
            "observed_monotonic_ns": observation.observed_monotonic_ns,
            "descendants": observation.descendants,
            "cgroup_populated": observation.cgroup_populated,
            "conmon_extinct": observation.conmon_extinct,
        }

    def _global_argv(self) -> tuple[str, ...]:
        return (
            os.fspath(self._components.podman.path), "--remote=false",
            "--root", os.fspath(self._roots.storage),
            "--runroot", os.fspath(self._roots.runroot),
            "--tmpdir", os.fspath(self._roots.tmp),
            "--runtime", os.fspath(self._components.crun.path),
            "--conmon", os.fspath(self._components.conmon.path),
            "--cgroup-manager", "cgroupfs", "--events-backend", "file",
            "--storage-driver", "overlay", "--storage-opt",
            "mount_program=" + os.fspath(self._components.overlay_helper.path),
            "--volumepath", os.fspath(self._roots.storage / "volumes"),
            "--network-config-dir", os.fspath(self._roots.home / "empty-networks"),
            "--hooks-dir", os.fspath(self._roots.home / "empty-hooks"),
        )

    def _host_env(self) -> tuple[str, ...]:
        return (
            "CONTAINERS_CONF=/dev/null", "CONTAINERS_CONF_OVERRIDE=/dev/null",
            "CONTAINERS_REGISTRIES_CONF=/dev/null", "CONTAINERS_STORAGE_CONF=/dev/null",
            "HOME=" + os.fspath(self._roots.home), "LANG=C", "LC_ALL=C",
            "PATH=/usr/bin:/bin", "PODMAN_CONNECTIONS_CONF=/dev/null",
            "PODMAN_NO_PAUSE_PROCESS=1", "REGISTRIES_CONFIG_PATH=/dev/null",
            "REGISTRY_AUTH_FILE=/dev/null", "TMPDIR=" + os.fspath(self._roots.tmp),
            "XDG_CONFIG_HOME=" + os.fspath(self._roots.home / ".config"),
            "XDG_DATA_HOME=" + os.fspath(self._roots.storage),
            "XDG_RUNTIME_DIR=" + os.fspath(self._roots.runtime_dir),
        )

    def _plan(self, operation: str, argv: tuple[str, ...], *, mutating: bool = False,
              journal_nonce: str | None = None) -> _InvocationPlan:
        if type(argv) is not tuple or not argv or any(type(item) is not str or "\x00" in item for item in argv):
            raise ContractError("invalid command vector")
        if len(_canonical_json(list(argv))) > MAX_ARG_BYTES:
            raise BoundsError("command vector exceeds bounds")
        executables = (self._components.podman, self._components.conmon, self._components.crun,
                       self._components.newuidmap, self._components.newgidmap,
                       self._components.overlay_helper)
        versions = {f"version-{label}": (os.fspath(executable.path), "--version")
                    for (label, _version), executable in zip(
                        ComponentIdentities.pins(), executables, strict=True)}
        if operation in versions:
            valid = argv == versions[operation]
        else:
            prefix = self._global_argv()
            tail = argv[len(prefix):]
            canonical_prefix = argv[:len(prefix)] == prefix
            valid = False
            if operation == "image-exists":
                valid = (canonical_prefix and len(tail) == 3
                         and tail[:2] == ("image", "exists")
                         and _IMAGE_RE.fullmatch(tail[2]) is not None)
            elif operation == "image-inspect":
                valid = (canonical_prefix and len(tail) == 5
                         and tail[:3] == ("image", "inspect", "--format")
                         and tail[3] == _IMAGE_INSPECT_TEMPLATE
                         and _IMAGE_RE.fullmatch(tail[4]) is not None)
            elif operation == "image-load":
                valid = (canonical_prefix and len(tail) == 5
                         and tail[:4] == ("image", "load", "--quiet", "--input")
                         and isinstance(_sanitized(lambda: _absolute(Path(tail[4]), "image archive"),
                                                   ContractError, "invalid image-load command"), Path))
            elif operation == "container-exists":
                valid = (canonical_prefix and len(tail) == 3
                         and tail[:2] == ("container", "exists")
                         and _NAME_RE.fullmatch(tail[2]) is not None)
            elif operation == "container-inspect":
                valid = (canonical_prefix and len(tail) == 5
                         and tail[:3] == ("container", "inspect", "--format")
                         and tail[3] == _CONTAINER_INSPECT_TEMPLATE
                         and _NAME_RE.fullmatch(tail[4]) is not None)
            elif operation == "container-create":
                # The create plan is issued only while the matching journal nonce
                # is active; require every invariant-bearing flag and exactly one
                # digest image following the entrypoint pair.
                required = {"--pull=never", "--read-only", "--read-only-tmpfs=false",
                            "--cap-drop=all", "--unsetenv-all", "--http-proxy=false",
                            "--image-volume=ignore", "--no-healthcheck",
                            "--hosts-file=none", "--sdnotify=ignore",
                            "--systemd=false", "--log-driver=none"}
                entry_indexes = [i for i, item in enumerate(tail) if item == "--entrypoint"]
                valid = (canonical_prefix and tail[:1] == ("create",)
                         and required.issubset(tail) and len(entry_indexes) == 1
                         and entry_indexes[0] + 2 < len(tail)
                         and _IMAGE_RE.fullmatch(tail[entry_indexes[0] + 2]) is not None
                         and sum(1 for item in tail if item.startswith("--network=")) == 1
                         and not any(item in tail for item in
                                     ("--privileged", "--device", "--network=host",
                                      "--network=bridge", "--network=slirp4netns",
                                      "--network=pasta")))
            elif operation == "container-start":
                valid = (canonical_prefix and len(tail) == 4
                         and tail[:3] == ("container", "start", "--attach=false")
                         and _SHA256_RE.fullmatch(tail[3]) is not None)
            elif operation == "container-wait":
                valid = (canonical_prefix and len(tail) == 7
                         and tail[:6] == ("container", "wait", "--condition",
                                          "exited", "--interval", "250ms")
                         and _SHA256_RE.fullmatch(tail[6]) is not None)
            elif operation == "container-cancel":
                valid = (canonical_prefix and len(tail) == 5
                         and tail[:4] == ("container", "kill", "--signal", "KILL")
                         and _SHA256_RE.fullmatch(tail[4]) is not None)
            elif operation == "container-delete":
                valid = (canonical_prefix and len(tail) == 3
                         and tail[:2] == ("container", "rm")
                         and _SHA256_RE.fullmatch(tail[2]) is not None)
        mutation_ops = {"image-load", "container-create", "container-start",
                        "container-cancel", "container-delete"}
        active = self._active_mutation
        if valid and operation == "container-create":
            valid = (active is not None
                     and self._rendered_create.get(
                         _hash(_canonical_json(list(argv)))) == active[0])
        elif valid and operation == "image-load":
            valid = (active is not None and active[4] is not None
                     and tail[4] == os.fspath(active[4].source))
        elif valid and operation in {"container-start", "container-cancel",
                                     "container-delete"}:
            valid = active is not None and tail[-1] == active[3]
        if not valid or mutating != (operation in mutation_ops):
            raise ContractError("operation outside closed command grammar")
        if mutating:
            if (journal_nonce is None or self._active_mutation is None
                    or self._active_mutation[1:3] != (operation, journal_nonce)):
                raise ContractError("mutation lacks durable journal capability")
        elif journal_nonce is not None:
            raise ContractError("read operation cannot carry mutation authority")
        return _issue_plan(operation, argv, mutating, journal_nonce)

    def _invoke(self, plan: _InvocationPlan, *, bindings: tuple[PathBinding, ...],
                output: PathBinding | None, network: NetworkProof | None,
                lease: ExecutionLease | None, timeout: float,
                cleanup: CleanupLease | None = None,
                allowed: frozenset[int] = frozenset({0}),
                terminal: bool = False) -> RunnerResult:
        operation, argv, mutating, journal_nonce = _consume_plan(plan)
        timeout = _timeout(timeout)
        contract = self._runner_contract
        if contract is None:
            raise PreflightError("runner contract unavailable")
        if mutating and (self._active_mutation is None
                         or self._active_mutation[1:3] != (operation, journal_nonce)):
            raise ContractError("mutation authority revoked")
        complete_bindings = self._root_bindings + bindings
        for binding in complete_bindings:
            self._revalidate_binding(binding)
        if output is not None:
            self._revalidate_binding(output)
        if network is not None and cleanup is not None:
            raise ContractError("data-plane and cleanup authorities cannot mix")
        if network is not None:
            assert self._network_contract is not None
            current = self._authority_call(lambda: self._network.revalidate(network),
                                           AdmissionError, "network revalidation failed")
            if current != network:
                raise AdmissionError("network proof changed or revoked")
            _validated(network, AdmissionError, "invalid network proof", self._network_contract)
        if lease is not None:
            current_lease = self._authority_call(lambda: self._runner.revalidate_lease(lease),
                                                 AdmissionError, "execution lease revalidation failed")
            if current_lease != lease:
                raise AdmissionError("execution lease changed")
        if cleanup is not None:
            if lease is None:
                raise ContractError("cleanup requires execution lease")
            current_cleanup = self._authority_call(
                lambda: self._runner.revalidate_cleanup(cleanup),
                AdmissionError, "cleanup authority revalidation failed")
            if current_cleanup != cleanup:
                raise AdmissionError("cleanup authority changed")
            _validated(cleanup, AdmissionError, "invalid cleanup authority",
                       contract, lease)
        challenge = self._observation_challenge(
            "components:" + self._components.digest)
        component_observation = self._authority_call(
            lambda: self._runner.observe_components(
                self._components, challenge),
            PreflightError, "component content observation failed")
        if type(component_observation) is not ComponentObservation:
            raise PreflightError("invalid component content observation type")
        _validated(component_observation, PreflightError,
                   "invalid component content observation", contract,
                   self._components, challenge)
        if (component_observation.sequence != challenge.generation
                or component_observation.sequence <= self._component_sequence
                or component_observation.observed_monotonic_ns
                <= self._component_observed_ns):
            raise PreflightError("stale component content observation")
        anchored = True
        try:
            self._commit_observation(challenge, component_observation)
        except StateError:
            anchored = False
        if not anchored:
            raise PreflightError("component observation was not durably anchored")
        self._component_sequence = component_observation.sequence
        self._component_observed_ns = component_observation.observed_monotonic_ns
        capability = _issue_capability(operation)
        env = self._host_env()
        failed = False
        result: RunnerResult | None = None
        try:
            if mutating and journal_nonce is not None:
                # Crossing this line hands the one-shot effect capability to the
                # native runner. Any later failure is conservatively ambiguous.
                self._effect_entered.add(journal_nonce)
            result = self._runner(argv, env=env, components=self._components,
                                  bindings=complete_bindings, output=output,
                                  network=network, lease=lease, cleanup=cleanup,
                                  component_observation=component_observation,
                                  timeout=timeout,
                                  output_limit=MAX_OUTPUT, capability=capability)
        except Exception:
            failed = True
        if failed:
            try:
                _consume_capability(capability, operation)
            except Exception:
                pass
            raise ProviderError("runner invocation failed")
        assert result is not None
        nonce = _consume_capability(capability, operation)
        if type(result) is not RunnerResult or type(result.receipt) is not InvocationReceipt:
            raise ContractError("invalid runner result")
        if type(result.returncode) is not int or result.returncode not in allowed:
            raise ProviderError("provider command failed")
        if (type(result.stdout) is not bytes or type(result.stderr) is not bytes
                or max(len(result.stdout), len(result.stderr)) > MAX_OUTPUT):
            raise BoundsError("runner output exceeds bounds")
        receipt = result.receipt
        binding_digest = self._bindings_digest(complete_bindings)
        checks = (
            receipt.schema == PROVIDER_SCHEMA,
            receipt.authority_id == contract.authority_id,
            receipt.capability_nonce == nonce,
            receipt.component_digest == self._components.digest,
            receipt.component_observation_sha256 == component_observation.digest,
            receipt.argv_sha256 == _hash(_canonical_json(list(argv))),
            receipt.env_sha256 == _hash(_canonical_json(list(env))),
            receipt.binding_digest == binding_digest,
            receipt.binding_tokens == tuple(item.token for item in complete_bindings),
            receipt.output_token == (output.token if output else None),
            receipt.network_proof_sha256 == (network.digest if network else None),
            receipt.network_endpoint_token == (network.endpoint_token if network else None),
            receipt.lease_sha256 == (lease.digest if lease else None),
            receipt.cgroup_token == (lease.cgroup_token if lease else None),
            receipt.conmon_scope_sha256 == (lease.conmon_scope_sha256 if lease else None),
            receipt.cleanup_sha256 == (cleanup.digest if cleanup else None),
            receipt.cleanup_token == (cleanup.token if cleanup else None),
            receipt.descriptor_exec_used is True,
            receipt.closed_environment_used is True,
            receipt.ambient_config_ignored is True,
            receipt.local_transport_only is True,
            receipt.all_descriptors_held is True,
            receipt.process_tree_accounted is True,
            receipt.provider_descendants_extinct is True,
            receipt.exact_exit_observed is True,
            receipt.egress_independent_cleanup is (cleanup is not None),
        )
        if (not all(checks) or type(receipt.cgroup_populated) is not int
                or receipt.cgroup_populated not in (0, 1)):
            raise ContractError("runner security receipt mismatch")
        if terminal and (receipt.cgroup_populated != 0 or receipt.conmon_extinct is not True):
            raise StateError("container descendants remain")
        return result

    def _record(self, attempt: str) -> MutationRecord | None:
        snapshot = self._authority_call(
            lambda: self._journal.load_current(attempt), _JournalRollback,
            "atomic journal snapshot unavailable")
        if snapshot is None:
            return None
        if type(snapshot) is not JournalSnapshot:
            raise _JournalRollback("invalid journal snapshot type")
        assert self._journal_contract is not None
        _validated(snapshot, _JournalRollback,
                   "invalid atomic journal snapshot",
                   self._journal_contract)
        verified = self._authority_call(
            lambda: self._journal.verify_snapshot(snapshot),
            _JournalRollback, "journal snapshot authentication failed")
        if verified is not True:
            raise _JournalRollback("journal snapshot authentication failed")
        return snapshot.record

    def _rollback_cleanup(self, spec: ContainerSpec,
                          requested_container_id: str | None,
                          timeout: float,
                          ) -> ProviderReceipt:
        """Extinguish an attempt without trusting the rolled-back head.

        This is deliberately outside Podman's lifecycle grammar. The native
        journal returns a previously authenticated cleanup context from its
        append-only store, and the native runner may only kill/remove resources
        under that context's cgroup/keeper authority. It has no network or
        general execution capability.
        """
        attempt = self._attempt_id(spec)
        timeout = _timeout(timeout)
        record = self._authority_call(
            lambda: self._journal.load_cleanup_record(attempt), StateError,
            "authenticated cleanup context unavailable")
        if type(record) is not MutationRecord:
            raise StateError("authenticated cleanup context unavailable")
        _validated(record, StateError,
                   "invalid authenticated cleanup context")
        authenticated = self._authority_call(
            lambda: self._journal.verify_cleanup_record(record), StateError,
            "cleanup context authentication failed")
        if authenticated is not True:
            raise StateError("cleanup context authentication failed")
        if (record.attempt_id != attempt
                or (requested_container_id is not None
                    and record.expected_container_id not in
                    (None, requested_container_id))):
            raise StateError("cleanup context target mismatch")
        assert self._path_contract is not None
        assert self._network_contract is not None
        assert self._runner_contract is not None
        if (record.base_spec_sha256 != spec.base_fingerprint
                or record.bindings_sha256 !=
                   self._bindings_digest(record.bindings)
                or record.context_sha256 != self._context_digest_evidence(
                    spec, record.bindings, record.topology, record.network,
                    record.lease, record.cleanup, record.root_bindings,
                    record.admission)):
            raise StateError("cleanup context specification mismatch")
        # Do not touch project, overlay, network, or provider-root paths here:
        # unrelated path drift must never prevent cgroup extinction. Only the
        # authenticated native execution/cleanup capabilities are refreshed.
        _validated(record.topology, StateError,
                   "invalid cleanup overlay evidence", self._path_contract,
                   record.bindings, spec.uid, spec.gid)
        _validated(record.network, StateError,
                   "invalid cleanup network evidence",
                   self._network_contract, False)
        seed = "plamen-seed-" + _hash(_canonical_json({
            "base": spec.base_fingerprint,
            "bindings": record.bindings_sha256,
            "overlay": record.topology.digest,
            "network": record.network.digest,
        }))[:32]
        _validated(record.lease, StateError,
                   "invalid cleanup execution lease",
                   self._runner_contract, seed)
        _validated(record.cleanup, StateError,
                   "invalid cleanup authority", self._runner_contract,
                   record.lease)
        lease = self._authority_call(
            lambda: self._runner.revalidate_lease(record.lease), StateError,
            "cleanup execution lease unavailable")
        cleanup = self._authority_call(
            lambda: self._runner.revalidate_cleanup(record.cleanup),
            StateError, "cleanup authority unavailable")
        if lease != record.lease or cleanup != record.cleanup:
            raise StateError("cleanup authority changed")
        challenge = self._observation_challenge(
            "emergency-extinction:" + attempt)
        observation = self._authority_call(
            lambda: self._runner.emergency_extinguish(
                record.lease, record.cleanup, challenge,
                record.expected_container_id or requested_container_id,
                timeout=timeout),
            StateError, "emergency extinction failed")
        if type(observation) is not ExtinctionObservation:
            raise StateError("invalid emergency extinction observation")
        assert self._runner_contract is not None
        _validated(observation, StateError,
                   "invalid emergency extinction observation",
                   self._runner_contract, record.lease, record.cleanup,
                   challenge)
        if observation.sequence != challenge.generation:
            raise StateError("emergency extinction challenge mismatch")
        self._commit_observation(challenge, observation)
        document: dict[str, object] = {
            "schema": PROVIDER_SCHEMA, "kind": "rollback-safe-cleanup",
            "attempt": attempt, "status": "extinguished",
            "container_id": record.expected_container_id,
        }
        document.update(self._extinction_document(observation))
        return _receipt(document)

    @staticmethod
    def _successor(record: MutationRecord, **changes: object
                   ) -> MutationRecord:
        return dataclasses.replace(
            record, generation=record.generation + 1,
            previous_record_sha256=record.digest, **changes)

    def _write(self, record: MutationRecord) -> JournalAnchor:
        _validated(record, ContractError, "invalid journal record")
        anchor = self._authority_call(lambda: self._journal.write(record),
                                      AmbiguousMutationError,
                                      "journal write outcome ambiguous")
        if type(anchor) is not JournalAnchor:
            raise AmbiguousMutationError("journal anchor missing")
        assert self._journal_contract is not None
        _validated(anchor, AmbiguousMutationError,
                   "journal anchor mismatch", self._journal_contract, record)
        verified = self._authority_call(
            lambda: self._journal.verify_anchor(anchor),
            AmbiguousMutationError, "journal anchor authentication failed")
        if verified is not True:
            raise AmbiguousMutationError(
                "journal anchor authentication failed")
        return anchor

    def _assert_record_context(self, record: MutationRecord,
                               context: _BoundContext) -> None:
        if (record.base_spec_sha256, record.context_sha256,
                record.bindings_sha256, record.network_sha256,
                record.lease_sha256, record.cleanup_sha256) != (
                context.spec.base_fingerprint, context.context_sha256,
                context.bindings_sha256, context.network.digest,
                context.lease.digest, context.cleanup.digest):
            raise StateError("journal context replay or authority change")
        if (record.root_bindings, record.bindings, record.topology,
                record.network, record.lease, record.cleanup,
                record.admission, record.admission_stages) != (
                self._root_bindings, context.bindings, context.topology,
                context.network, context.lease, context.cleanup,
                context.admission, context.admission_stages):
            raise StateError("journal full binding evidence changed")
        assert self._journal_contract is not None
        _validated(record.admission, StateError,
                   "journal admission reservation changed",
                   self._journal_contract, context.attempt_id,
                   context.spec.base_fingerprint)
        resources = (
            context.bindings_sha256, context.topology.digest,
            context.network.digest, context.lease.digest,
            context.cleanup.digest,
        )
        previous = "0" * 64
        for ordinal, (stage, resource, receipt) in enumerate(zip(
                ("paths", "overlay", "network", "execution", "cleanup"),
                resources, context.admission_stages, strict=True), 1):
            _validated(receipt, StateError,
                       "journal admission stage changed",
                       self._journal_contract, context.admission, stage,
                       ordinal, resource, previous)
            authenticated = self._authority_call(
                lambda item=receipt:
                    self._journal.verify_admission_stage(item),
                StateError, "journal admission stage authentication failed")
            if authenticated is not True:
                raise StateError(
                    "journal admission stage authentication failed")
            previous = receipt.digest

    def _assert_live_admission(self, context: _BoundContext) -> None:
        """Authenticate an unadopted context immediately before first effect."""
        reservation = self._load_admission(context.spec)
        if reservation != context.admission:
            raise StateError("context admission was retired or replaced")
        stages = self._authority_call(
            lambda: self._journal.load_admission_stages(reservation),
            StateError, "admission stage read failed")
        if stages != context.admission_stages:
            raise StateError("context admission stage roster changed")
        assert self._journal_contract is not None
        resources = (
            context.bindings_sha256, context.topology.digest,
            context.network.digest, context.lease.digest,
            context.cleanup.digest,
        )
        previous = "0" * 64
        for ordinal, (stage, resource, receipt) in enumerate(zip(
                ("paths", "overlay", "network", "execution", "cleanup"),
                resources, stages, strict=True), 1):
            _validated(receipt, StateError,
                       "live admission stage changed",
                       self._journal_contract, reservation, stage,
                       ordinal, resource, previous)
            authenticated = self._authority_call(
                lambda item=receipt:
                    self._journal.verify_admission_stage(item),
                StateError, "live admission stage authentication failed")
            if authenticated is not True:
                raise StateError("live admission stage authentication failed")
            previous = receipt.digest

    def _mutate(self, context: _BoundContext, operation: str,
                runner_operation: str, expected_id: str | None,
                operation_binding: PathBinding | None,
                action: Callable[[str], object],
                verify: Callable[[object, str | None], object], *,
                artifact_manifest_sha256: str | None = None,
                artifact_sources_sha256: str | None = None,
                artifact_destination: ArtifactDestination | None = None,
                require_network: bool = True) -> object:
        self._revalidate_context(context, require_network=require_network)
        existing = self._record(context.attempt_id)
        previous: str | None = None
        if existing is not None:
            self._assert_record_context(existing, context)
            if existing.state is MutationState.PENDING:
                raise AmbiguousMutationError("earlier mutation requires recovery")
            if existing.state is MutationState.ABORTED:
                if existing.operation != operation:
                    raise StateError("aborted mutation must be retried or recovered")
                previous = existing.previous_operation
            else:
                previous = existing.operation
        else:
            self._assert_live_admission(context)
        allowed_previous = {
            "load": {None}, "create": {None, "load"}, "start": {"create"},
            "cancel": {"start"}, "export": {"start", "cancel"},
            "delete": {"create", "start", "cancel", "export"},
            "release": {"delete"},
        }
        if previous not in allowed_previous[operation]:
            raise StateError("invalid lifecycle transition")
        nonce = _hash(os.urandom(32))
        pending = MutationRecord(
            schema=JOURNAL_SCHEMA, attempt_id=context.attempt_id,
            generation=(existing.generation + 1 if existing else 1),
            previous_record_sha256=(existing.digest if existing else "0" * 64),
            base_spec_sha256=context.spec.base_fingerprint,
            context_sha256=context.context_sha256,
            bindings_sha256=context.bindings_sha256,
            network_sha256=context.network.digest,
            lease_sha256=context.lease.digest,
            cleanup_sha256=context.cleanup.digest,
            admission=context.admission,
            admission_stages=context.admission_stages,
            root_bindings=self._root_bindings, bindings=context.bindings,
            topology=context.topology, network=context.network,
            lease=context.lease, cleanup=context.cleanup,
            operation=operation, previous_operation=previous, nonce=nonce,
            state=MutationState.PENDING,
            expected_container_id=expected_id,
            operation_binding=operation_binding,
            operation_snapshot_before=(
                operation_binding.snapshot_sha256
                if operation_binding else None),
            artifact_destination=artifact_destination,
            artifact_commit=None,
            artifact_manifest_sha256=artifact_manifest_sha256,
            artifact_sources_sha256=artifact_sources_sha256,
            release_receipts=(),
            postcondition_sha256=None,
        )
        self._write(pending)
        if self._record(context.attempt_id) != pending:
            raise AmbiguousMutationError("pending journal record not durable")
        self._active_mutation = (
            context.attempt_id, runner_operation, nonce, expected_id,
            operation_binding, context.context_sha256,
        )
        failed = False
        result: object | None = None
        committed = expected_id
        post_object: object = None
        try:
            result = action(nonce)
            if operation == "create":
                raw = result.stdout.decode("ascii", "strict").strip()
                if not _SHA256_RE.fullmatch(raw):
                    raise StateError
                committed = raw
            post_object = verify(result, committed)
        except Exception:
            failed = True
        finally:
            self._active_mutation = None
        if failed or result is None:
            if nonce not in self._effect_entered:
                aborted = self._successor(
                    pending, state=MutationState.ABORTED)
                self._write(aborted)
                if self._record(context.attempt_id) != aborted:
                    raise AmbiguousMutationError(
                        "aborted journal record not durable")
                raise ProviderError("mutation rejected before effect")
            raise AmbiguousMutationError("mutation outcome ambiguous")
        post = _hash(_canonical_json({"operation": operation,
                                      "postcondition": post_object,
                                      "nonce": nonce}))
        release_receipts: tuple[ResourceReleaseReceipt, ...] = ()
        if operation == "release":
            if (type(result) is not tuple
                    or len(result) != 6
                    or any(type(item) is not ResourceReleaseReceipt
                           for item in result)):
                raise AmbiguousMutationError("release receipt roster changed")
            release_receipts = result
        artifact_commit = (result if operation == "export" else None)
        if artifact_commit is not None and type(artifact_commit) is not ArtifactCommit:
            raise AmbiguousMutationError("artifact commit changed")
        complete = self._successor(
            pending, state=MutationState.COMPLETE,
            expected_container_id=committed,
            artifact_commit=artifact_commit,
            release_receipts=release_receipts,
            postcondition_sha256=post)
        self._write(complete)
        if self._record(context.attempt_id) != complete:
            raise AmbiguousMutationError("completion journal record not durable")
        self._effect_entered.discard(nonce)
        return result

    def _image_exists(self, image: ImageSpec, timeout: float) -> bool:
        argv = self._global_argv() + ("image", "exists", image.reference)
        result = self._invoke(self._plan("image-exists", argv), bindings=(),
                              output=None, network=None, lease=None,
                              timeout=timeout, allowed=frozenset({0, 1, 125}))
        if result.stdout.strip() or result.returncode == 125:
            raise AdmissionError("local image store could not be inspected")
        return result.returncode == 0

    def inspect_image(self, image: ImageSpec, *, timeout: float = 30.0,
                      missing_ok: bool = False) -> ImageObservation | None:
        self._require_ready()
        _validated(image, AdmissionError, "invalid image specification")
        if not self._image_exists(image, timeout):
            if missing_ok:
                return None
            raise AdmissionError("local image unavailable; pulling forbidden")
        argv = self._global_argv() + ("image", "inspect", "--format",
                                      _IMAGE_INSPECT_TEMPLATE,
                                      image.reference)
        result = self._invoke(self._plan("image-inspect", argv), bindings=(),
                              output=None, network=None, lease=None,
                              timeout=timeout)
        obj = _strict_object(result.stdout, _IMAGE_KEYS)
        if (any(type(obj[key]) is not str for key in
                ("id", "digest", "os", "architecture"))
                or type(obj["repo_digests"]) is not list):
            raise AdmissionError("invalid image observation")
        digest = obj["digest"].removeprefix("sha256:")
        identity = obj["id"].removeprefix("sha256:")
        repo = tuple(obj["repo_digests"])
        host_arch = {"x86_64": "amd64", "aarch64": "arm64"}[self._host.machine]
        if (not _SHA256_RE.fullmatch(digest) or not _SHA256_RE.fullmatch(identity)
                or (digest, obj["os"], obj["architecture"]) !=
                (image.digest, image.os, image.architecture)
                or image.architecture != host_arch or image.reference not in repo
                or any(type(item) is not str or _IMAGE_RE.fullmatch(item) is None
                       for item in repo)):
            raise AdmissionError("image identity/platform mismatch")
        return ImageObservation(identity, digest, image.os,
                                image.architecture, repo)

    def ensure_local_image(self, spec: ContainerSpec,
                           archive: ImageArchive | None = None, *,
                           timeout: float = 120.0) -> ProviderReceipt:
        context = self._context(spec)
        present = self.inspect_image(spec.image, timeout=timeout, missing_ok=True)
        if present is None:
            if type(archive) is not ImageArchive:
                raise AdmissionError("local image unavailable; pulling forbidden")
            _validated(archive, AdmissionError, "invalid image archive",
                       spec.image.digest)
            binding = self._admit_path(
                archive.path, purpose="image-archive", target="", readonly=True,
                kind="regular", byte_limit=16 * 1024**3,
                mapped_uid=0, mapped_gid=0,
            )
            if binding.snapshot_sha256 != archive.content_sha256:
                raise AdmissionError("image archive changed")
            self._reject_relations((binding,))

            def action(nonce: str) -> RunnerResult:
                argv = self._global_argv() + (
                    "image", "load", "--quiet", "--input",
                    os.fspath(binding.source),
                )
                return self._invoke(
                    self._plan("image-load", argv, mutating=True,
                               journal_nonce=nonce),
                    bindings=context.bindings + (binding,), output=None,
                    network=context.network, lease=context.lease,
                    timeout=timeout,
                )

            def verify(_result: RunnerResult,
                       _expected: str | None) -> object:
                found = self.inspect_image(spec.image, timeout=timeout)
                assert found is not None
                return {"image_id": found.id, "digest": found.digest,
                        "archive": binding.snapshot_sha256}

            self._mutate(context, "load", "image-load", None, binding,
                         action, verify)
            present = self.inspect_image(spec.image, timeout=timeout)
        assert present is not None
        return _receipt({"schema": PROVIDER_SCHEMA, "kind": "image-admission",
                         "attempt": context.attempt_id,
                         "context": context.context_sha256,
                         "digest": present.digest, "image_id": present.id})

    @staticmethod
    def _cpu_text(millis: int) -> str:
        whole, fraction = divmod(millis, 1000)
        return str(whole) if not fraction else f"{whole}.{fraction:03d}".rstrip("0")

    def _labels(self, context: _BoundContext) -> tuple[str, ...]:
        return (
            "io.plamen.provider=podman-linux-v2",
            "io.plamen.attempt=" + context.attempt_id,
            "io.plamen.context-sha256=" + context.context_sha256,
            "io.plamen.bindings-sha256=" + context.bindings_sha256,
            "io.plamen.network-sha256=" + context.network.digest,
            "io.plamen.lease-sha256=" + context.lease.digest,
            "io.plamen.cleanup-sha256=" + context.cleanup.digest,
            "io.plamen.overlay-sha256=" + context.topology.digest,
        )

    def render_create_argv(self, spec: ContainerSpec) -> tuple[str, ...]:
        context = self._context(spec)
        seccomp = next(item for item in context.bindings
                       if item.purpose == "seccomp")
        argv = list(self._global_argv())
        network_args = ["--network=" + context.network.podman_network]
        argv += [
            "create", "--name", context.attempt_id, "--pull=never",
            "--read-only", "--read-only-tmpfs=false", *network_args,
            "--userns=keep-id:uid=" + str(spec.uid) + ",gid=" + str(spec.gid)
            + ",size=65536",
            "--user", f"{spec.uid}:{spec.gid}", "--cgroup-parent",
            context.lease.cgroup_path, "--cgroupns=private",
            "--cgroups=enabled", "--pid=private", "--ipc=private",
            "--uts=private", "--cap-drop=all", "--security-opt",
            "no-new-privileges", "--security-opt",
            "seccomp=" + os.fspath(seccomp.source), "--pids-limit",
            str(spec.pids_limit), "--memory", str(spec.memory_bytes),
            "--memory-swap", str(spec.memory_bytes), "--cpus",
            self._cpu_text(spec.cpu_millis), "--ulimit",
            f"nofile={spec.nofile_limit}:{spec.nofile_limit}", "--ulimit",
            "core=0:0", "--restart=no", "--unsetenv-all",
            "--http-proxy=false", "--image-volume=ignore",
            "--no-healthcheck", "--hostname", context.attempt_id,
            "--hosts-file=none", "--sdnotify=ignore", "--systemd=false",
            "--log-driver=none",
        ]
        for protected in _PROTECTED_PATHS:
            argv += ["--security-opt", "mask=" + protected]
        for label in self._labels(context):
            argv += ["--label", label]
        for item in spec.environment:
            argv += ["--env", item]
        for purpose in _CONTAINER_MOUNTS:
            binding = next(item for item in context.bindings
                           if item.purpose == purpose)
            mode = "true" if binding.readonly else "false"
            argv += [
                "--mount",
                f"type=bind,source={binding.source},destination={binding.target},"
                f"ro={mode},bind-propagation=rprivate,bind-nonrecursive",
            ]
        for target in ("/tmp", "/run", "/var/tmp", "/dev/shm"):
            argv += [
                "--tmpfs",
                f"{target}:rw,nodev,nosuid,noexec,size={spec.tmpfs_bytes},"
                "notmpcopyup",
            ]
        argv += ["--entrypoint", spec.entrypoint, spec.image.reference,
                 *spec.arguments]
        rendered = tuple(argv)
        forbidden = ("--privileged", "--device", "--network=host",
                     "--network=bridge", "--network=slirp4netns",
                     "--network=pasta")
        if any(item in rendered for item in forbidden):
            raise ContractError("unsafe create command")
        self._rendered_create[_hash(_canonical_json(list(rendered)))] = context.attempt_id
        return rendered

    def create(self, spec: ContainerSpec, *,
               timeout: float = 120.0) -> ProviderReceipt:
        context = self._context(spec)
        self.inspect_image(spec.image, timeout=timeout)
        if self._inspect(context, min(timeout, 30.0), True).state is not ContainerState.ABSENT:
            raise StateError("deterministic container identity exists")

        def action(nonce: str) -> RunnerResult:
            argv = self.render_create_argv(spec)
            return self._invoke(
                self._plan("container-create", argv, mutating=True,
                           journal_nonce=nonce),
                bindings=context.bindings, output=None,
                network=context.network, lease=context.lease,
                timeout=timeout,
            )

        def verify(_result: RunnerResult,
                   identity: str | None) -> object:
            observed = self._inspect(context, min(timeout, 30.0), False)
            if (identity is None or observed.container_id != identity
                    or observed.state is not ContainerState.CREATED):
                raise StateError("create postcondition mismatch")
            return {"container": identity,
                    "observation": observed.observation_sha256}

        result = self._mutate(context, "create", "container-create", None,
                              None, action, verify)
        if type(result) is not RunnerResult:
            raise StateError("create runner result changed")
        identity = result.stdout.decode("ascii", "strict").strip()
        return _receipt({"schema": PROVIDER_SCHEMA, "kind": "create",
                         "attempt": context.attempt_id,
                         "container_id": identity,
                         "context": context.context_sha256})

    def _inspect(self, context: _BoundContext, timeout: float,
                 absent_ok: bool, *, cleanup: bool = False) -> ContainerObservation:
        self._revalidate_context(context, require_network=not cleanup)
        invocation_network = None if cleanup else context.network
        invocation_cleanup = context.cleanup if cleanup else None
        prefix = self._global_argv()
        argv = prefix + ("container", "exists", context.attempt_id)
        exists = self._invoke(
            self._plan("container-exists", argv),
            bindings=context.bindings, output=None, network=invocation_network,
            lease=context.lease, cleanup=invocation_cleanup, timeout=timeout,
            allowed=frozenset({0, 1, 125}),
        )
        if exists.stdout.strip() or exists.returncode == 125:
            raise StateError("container store could not be inspected")
        if exists.returncode == 1:
            if absent_ok:
                return ContainerObservation(ContainerState.ABSENT, None, None,
                                            _hash(b"absent"))
            raise StateError("container absent")
        argv = prefix + ("container", "inspect", "--format",
                         _CONTAINER_INSPECT_TEMPLATE,
                         context.attempt_id)
        result = self._invoke(
            self._plan("container-inspect", argv),
            bindings=context.bindings, output=None, network=invocation_network,
            lease=context.lease, cleanup=invocation_cleanup, timeout=timeout,
        )
        obj = _strict_object(result.stdout, _CONTAINER_KEYS)
        return _sanitized(lambda: self._validate_container(context, obj),
                          StateError, "invalid container observation")

    def inspect(self, spec: ContainerSpec, *, timeout: float = 30.0,
                absent_ok: bool = False) -> ContainerObservation:
        return self._inspect(self._context(spec), timeout, absent_ok)

    def _validate_container(self, context: _BoundContext,
                            obj: dict[str, Any]) -> ContainerObservation:
        spec = context.spec
        identity = obj["id"]
        if type(identity) is not str or not _SHA256_RE.fullmatch(identity):
            raise StateError("invalid container identity")
        if (obj["name"] != context.attempt_id
                or obj["image_digest"].removeprefix("sha256:")
                != spec.image.digest):
            raise StateError("container recreated or substituted")
        record = self._record(context.attempt_id)
        if record is not None:
            self._assert_record_context(record, context)
            if (record.expected_container_id is not None
                    and identity != record.expected_container_id):
                raise StateError("container identity recreated")
        if obj["labels"] != dict(item.split("=", 1)
                                  for item in self._labels(context)):
            raise StateError("container labels mismatch")
        expected_userns = f"keep-id:uid={spec.uid},gid={spec.gid},size=65536"
        if (obj["network_mode"] != context.network.podman_network
                or obj["user"] != f"{spec.uid}:{spec.gid}"
                or obj["userns_mode"] != expected_userns
                or obj["hostname"] != context.attempt_id
                or obj["use_image_hosts"] is not False
                or obj["use_image_hostname"] is not False):
            raise StateError("container isolation mismatch")
        if (obj["env"] != list(spec.environment)
                or obj["effective_caps"] not in ([], None)
                or obj["bounding_caps"] not in ([], None)):
            raise StateError("container authority mismatch")
        if (obj["read_only"] is not True or obj["privileged"] is not False
                or obj["devices"] not in ([], None)
                or obj["cap_add"] not in ([], None)):
            raise StateError("container privilege mismatch")
        if (obj["pid_mode"], obj["ipc_mode"], obj["uts_mode"],
                obj["cgroup_mode"], obj["cgroups"]) != (
                "private", "private", "private", "private", "enabled"):
            raise StateError("container namespace mismatch")
        if (obj["memory"], obj["memory_swap"], obj["nano_cpus"],
                obj["pids_limit"]) != (
                spec.memory_bytes, spec.memory_bytes,
                spec.cpu_millis * 1_000_000, spec.pids_limit):
            raise StateError("container resource mismatch")
        if (obj["oci_runtime"] not in
                ("crun", os.fspath(self._components.crun.path))
                or obj["restart_policy"] != "no"
                or obj["log_driver"] != "none"
                or obj["healthcheck"] is not None
                or obj["systemd"] is not False
                or obj["sdnotify"] != "ignore"):
            raise StateError("container runtime policy mismatch")
        expected_ulimits = [
            {"Name": "nofile", "Soft": spec.nofile_limit,
             "Hard": spec.nofile_limit},
            {"Name": "core", "Soft": 0, "Hard": 0},
        ]
        if obj["ulimits"] != expected_ulimits:
            raise StateError("container ulimit mismatch")
        seccomp = next(item for item in context.bindings
                       if item.purpose == "seccomp")
        expected_security = [
            "no-new-privileges", "seccomp=" + os.fspath(seccomp.source),
            *("mask=" + item for item in _PROTECTED_PATHS),
        ]
        if obj["security_opt"] != expected_security:
            raise StateError("container security options mismatch")
        tmpfs_options = ("rw,nodev,nosuid,noexec,size=" +
                         str(spec.tmpfs_bytes) + ",notmpcopyup")
        if obj["tmpfs"] != {path: tmpfs_options for path in
                            ("/tmp", "/run", "/var/tmp", "/dev/shm")}:
            raise StateError("container tmpfs mismatch")
        expected_mounts = [
            next(item for item in context.bindings
                 if item.purpose == purpose)
            for purpose in _CONTAINER_MOUNTS
        ]
        if (type(obj["mounts"]) is not list
                or len(obj["mounts"]) != len(expected_mounts)):
            raise StateError("container mount roster mismatch")
        for mount, binding in zip(obj["mounts"], expected_mounts, strict=True):
            if (type(mount) is not dict or frozenset(mount) !=
                    {"Type", "Source", "Destination", "RW",
                     "Propagation", "Options"}):
                raise StateError("invalid mount observation")
            expected = ("bind", os.fspath(binding.source), binding.target,
                        not binding.readonly, "rprivate",
                        ["bind", "rprivate", "bind-nonrecursive"])
            actual = (mount["Type"], mount["Source"], mount["Destination"],
                      mount["RW"], mount["Propagation"], mount["Options"])
            if actual != expected:
                raise StateError("container mount identity/propagation mismatch")
        status = {
            "configured": ContainerState.CREATED,
            "created": ContainerState.CREATED,
            "running": ContainerState.RUNNING,
            "exited": ContainerState.EXITED,
            "stopped": ContainerState.EXITED,
        }.get(obj["state"])
        if (status is None or type(obj["running"]) is not bool
                or type(obj["pid"]) is not int
                or type(obj["conmon_pid"]) is not int):
            raise StateError("unknown container state")
        if (status is ContainerState.RUNNING) != obj["running"]:
            raise StateError("inconsistent container state")
        if obj["cgroup_path"] != context.lease.cgroup_path:
            raise StateError("attempt cgroup identity mismatch")
        if status is ContainerState.RUNNING and (obj["pid"] <= 0
                                                  or obj["conmon_pid"] <= 0):
            raise StateError("running process roster incomplete")
        if status is not ContainerState.RUNNING and obj["conmon_pid"] != 0:
            raise StateError("terminal container retains conmon")
        exit_code: int | None = None
        if status is ContainerState.EXITED:
            exit_code = _decimal(obj["exit_code"], "exit code", 0, 255)
            if obj["pid"] != 0:
                raise StateError("exited container retains process")
        elif obj["exit_code"] not in (0, None):
            raise StateError("premature exit status")
        return ContainerObservation(status, identity, exit_code,
                                    _hash(_canonical_json(obj)))

    def start(self, spec: ContainerSpec, container_id: str, *,
              timeout: float = 60.0) -> ProviderReceipt:
        context = self._context(spec)
        if not _SHA256_RE.fullmatch(container_id):
            raise StateError("invalid container identity")
        before = self._inspect(context, min(timeout, 30.0), False)
        if (before.state is not ContainerState.CREATED
                or before.container_id != container_id):
            raise StateError("container not launchable")

        def action(nonce: str) -> RunnerResult:
            argv = self._global_argv() + (
                "container", "start", "--attach=false", container_id,
            )
            return self._invoke(
                self._plan("container-start", argv, mutating=True,
                           journal_nonce=nonce),
                bindings=context.bindings, output=None,
                network=context.network, lease=context.lease,
                timeout=timeout,
            )

        def verify(_result: RunnerResult,
                   expected: str | None) -> object:
            after = self._inspect(context, min(timeout, 30.0), False)
            if (after.state is not ContainerState.RUNNING
                    or after.container_id != expected):
                raise StateError("start postcondition mismatch")
            return {"container": expected,
                    "observation": after.observation_sha256}

        self._mutate(context, "start", "container-start", container_id,
                     None, action, verify)
        return _receipt({"schema": PROVIDER_SCHEMA, "kind": "start",
                         "attempt": context.attempt_id,
                         "container_id": container_id,
                         "context": context.context_sha256})

    def wait(self, spec: ContainerSpec, container_id: str, *,
             timeout: float = MAX_TIMEOUT_SECONDS) -> ProviderReceipt:
        context = self._context(spec, require_network=False)
        before = self._inspect(context, min(timeout, 30.0), False,
                               cleanup=True)
        if (before.container_id != container_id
                or before.state not in
                {ContainerState.RUNNING, ContainerState.EXITED}):
            raise StateError("container not waitable")
        argv = self._global_argv() + (
            "container", "wait", "--condition", "exited", "--interval",
            "250ms", container_id,
        )
        result = self._invoke(
            self._plan("container-wait", argv), bindings=context.bindings,
            output=None, network=None, lease=context.lease,
            cleanup=context.cleanup, timeout=timeout, terminal=True,
        )
        raw = _sanitized(lambda: result.stdout.decode("ascii", "strict").strip(),
                         StateError, "invalid container exit status")
        if re.fullmatch(r"0|[1-9][0-9]{0,2}", raw) is None or int(raw) > 255:
            raise StateError("invalid container exit status")
        code = int(raw)
        after = self._inspect(context, 30.0, False, cleanup=True)
        if (after.state is not ContainerState.EXITED
                or after.container_id != container_id
                or after.exit_code != code):
            raise StateError("wait postcondition mismatch")
        extinction = self._extinction(context)
        document = {"schema": PROVIDER_SCHEMA, "kind": "wait",
                    "attempt": context.attempt_id,
                    "container_id": container_id, "exit_code": code}
        document.update(self._extinction_document(extinction))
        return _receipt(document)

    def cancel(self, spec: ContainerSpec, container_id: str, *,
               timeout: float = 60.0) -> ProviderReceipt:
        try:
            context = self._context(spec, require_network=False)
            # Cached contexts do not bypass the externally anchored journal
            # head check before a teardown transition.
            self._record(context.attempt_id)
        except _JournalRollback:
            return self._rollback_cleanup(spec, container_id, timeout)
        before = self._inspect(context, 30.0, False, cleanup=True)
        if (before.container_id != container_id
                or before.state is not ContainerState.RUNNING):
            raise StateError("container not cancellable")

        def action(nonce: str) -> RunnerResult:
            argv = self._global_argv() + (
                "container", "kill", "--signal", "KILL", container_id,
            )
            return self._invoke(
                self._plan("container-cancel", argv, mutating=True,
                           journal_nonce=nonce),
                bindings=context.bindings, output=None,
                network=None, lease=context.lease, cleanup=context.cleanup,
                timeout=timeout, terminal=True,
            )

        def verify(_result: RunnerResult,
                   expected: str | None) -> object:
            after = self._inspect(context, min(timeout, 30.0), False,
                                  cleanup=True)
            if (after.state is not ContainerState.EXITED
                    or after.container_id != expected):
                raise StateError("cancel postcondition mismatch")
            return {"container": expected,
                    "observation": after.observation_sha256}

        self._mutate(context, "cancel", "container-cancel", container_id,
                     None, action, verify, require_network=False)
        extinction = self._extinction(context)
        document = {"schema": PROVIDER_SCHEMA, "kind": "cancel",
                    "attempt": context.attempt_id,
                    "container_id": container_id}
        document.update(self._extinction_document(extinction))
        return _receipt(document)

    def export(self, spec: ContainerSpec, container_id: str,
               destination: Path, *, timeout: float = 120.0) -> ProviderReceipt:
        # Packaging is deliberately outside Podman. `podman container export`
        # serializes only the container rootfs and omits the bind-mounted audit
        # products this provider is responsible for returning.
        timeout = _timeout(timeout)
        context = self._context(spec, require_network=False)
        before = self._inspect(context, 30.0, False, cleanup=True)
        if (before.container_id != container_id
                or before.state is not ContainerState.EXITED):
            raise StateError("only exited container can be exported")
        # Gate the host-side package effect on a fresh extinction census. A
        # second census below binds the returned receipt after the commit.
        self._extinction(context)
        output = self._admit_export_destination(
            _absolute(destination, "export destination"),
            byte_limit=16 * 1024**3, mapped_uid=spec.uid,
            mapped_gid=spec.gid)
        if (output.parent.uid, output.parent.gid,
                output.mapped_uid, output.mapped_gid,
                output.parent.keep_id_writable) != (
                    self._host.real_uid, self._host.real_gid,
                    spec.uid, spec.gid, True):
            raise AdmissionError("export destination lacks usable keep-id mapping")
        self._reject_export_destination(output, context)
        sources, source_set, manifest = self._artifact_identity(context)
        exported: dict[str, ArtifactCommit] = {}

        def action(nonce: str) -> object:
            self._effect_entered.add(nonce)
            return self._authority_call(
                lambda: self._paths.package_artifacts(
                    sources, output, attempt_id=context.attempt_id,
                    manifest_sha256=manifest, timeout=timeout),
                AmbiguousMutationError, "artifact packaging outcome ambiguous",
            )

        def verify(result: object,
                   expected: str | None) -> object:
            commit = self._validate_artifact_commit(
                result, output, context, source_set, manifest)
            exported["commit"] = commit
            return {"container": expected,
                    "artifact": commit.archive_sha256,
                    "commit": commit.digest,
                    "census": commit.census_sha256}

        self._mutate(
            context, "export", "artifact-package", container_id, None,
            action, verify, artifact_manifest_sha256=manifest,
            artifact_sources_sha256=source_set,
            artifact_destination=output, require_network=False)
        commit = exported["commit"]
        extinction = self._extinction(context)
        document = {"schema": PROVIDER_SCHEMA, "kind": "export",
                    "attempt": context.attempt_id,
                    "container_id": container_id,
                    "artifact": commit.archive_sha256,
                    "artifact_commit": commit.digest,
                    "artifact_census": commit.census_sha256,
                    "artifact_entries": commit.entry_count,
                    "artifact_bytes": commit.byte_count}
        document.update(self._extinction_document(extinction))
        return _receipt(document)

    def delete(self, spec: ContainerSpec, container_id: str, *,
               timeout: float = 60.0) -> ProviderReceipt:
        context = self._context(spec, require_network=False)
        before = self._inspect(context, 30.0, False, cleanup=True)
        if (before.container_id != container_id
                or before.state not in
                {ContainerState.CREATED, ContainerState.EXITED}):
            raise StateError("container not deletable")

        def action(nonce: str) -> RunnerResult:
            argv = self._global_argv() + ("container", "rm", container_id)
            return self._invoke(
                self._plan("container-delete", argv, mutating=True,
                           journal_nonce=nonce),
                bindings=context.bindings, output=None,
                network=None, lease=context.lease, cleanup=context.cleanup,
                timeout=timeout, terminal=True,
            )

        def verify(_result: RunnerResult,
                   expected: str | None) -> object:
            after = self._inspect(context, 30.0, True, cleanup=True)
            if after.state is not ContainerState.ABSENT:
                raise StateError("delete postcondition mismatch")
            return {"container": expected,
                    "observation": after.observation_sha256}

        self._mutate(context, "delete", "container-delete", container_id,
                     None, action, verify, require_network=False)
        extinction = self._extinction(context)
        document = {"schema": PROVIDER_SCHEMA, "kind": "delete",
                    "attempt": context.attempt_id,
                    "container_id": container_id}
        document.update(self._extinction_document(extinction))
        return _receipt(document)

    def _validate_release_receipt(
            self, receipt: object, *, authority_id: str, kind: str,
            token: str, context: _BoundContext, nonce: str,
            verifier: Callable[[ResourceReleaseReceipt], bool]
    ) -> ResourceReleaseReceipt:
        if type(receipt) is not ResourceReleaseReceipt:
            raise StateError("invalid release receipt type")
        self._authority_call(
            lambda: receipt.validate(
                authority_id=authority_id, kind=kind, token=token,
                context_sha256=context.context_sha256,
                release_nonce=nonce),
            StateError, "invalid release receipt")
        verified = self._authority_call(
            lambda: verifier(receipt), StateError,
            "release receipt authentication failed")
        if verified is not True:
            raise StateError("release receipt authentication failed")
        return receipt

    def _validate_release_roster(
            self, receipts: tuple[ResourceReleaseReceipt, ...],
            context: _BoundContext,
            nonce: str) -> tuple[ResourceReleaseReceipt, ...]:
        assert self._path_contract is not None
        assert self._network_contract is not None
        assert self._runner_contract is not None
        expected = (
            (self._network_contract.authority_id, "namespace-endpoint",
             context.network.endpoint_token, self._network.verify_release),
            (self._path_contract.authority_id, "overlay-keeper",
             context.topology.keeper_token, self._paths.verify_release),
            (self._runner_contract.authority_id, "cleanup-authority",
             context.cleanup.token, self._runner.verify_release),
            (self._runner_contract.authority_id, "execution-lease",
             context.lease.token, self._runner.verify_release),
            (self._runner_contract.authority_id, "execution-cgroup",
             context.lease.cgroup_token, self._runner.verify_release),
            (self._runner_contract.authority_id, "execution-keeper",
             context.lease.keeper_token, self._runner.verify_release),
        )
        if type(receipts) is not tuple or len(receipts) != len(expected):
            raise StateError("release receipt roster mismatch")
        return tuple(self._validate_release_receipt(
            receipt, authority_id=authority_id, kind=kind, token=token,
            context=context, nonce=nonce, verifier=verifier)
            for receipt, (authority_id, kind, token, verifier) in zip(
                receipts, expected, strict=True))

    def _perform_release(self, context: _BoundContext,
                         nonce: str) -> tuple[ResourceReleaseReceipt, ...]:
        assert self._path_contract is not None
        assert self._network_contract is not None
        assert self._runner_contract is not None
        self._effect_entered.add(nonce)
        endpoint = self._authority_call(
            lambda: self._network.release(
                context.network, context_sha256=context.context_sha256,
                release_nonce=nonce),
            AmbiguousMutationError, "endpoint release outcome ambiguous")
        endpoint = self._validate_release_receipt(
            endpoint, authority_id=self._network_contract.authority_id,
            kind="namespace-endpoint", token=context.network.endpoint_token,
            context=context, nonce=nonce, verifier=self._network.verify_release)
        overlay = self._authority_call(
            lambda: self._paths.release_overlay(
                context.topology, context_sha256=context.context_sha256,
                release_nonce=nonce),
            AmbiguousMutationError, "overlay release outcome ambiguous")
        overlay = self._validate_release_receipt(
            overlay, authority_id=self._path_contract.authority_id,
            kind="overlay-keeper", token=context.topology.keeper_token,
            context=context, nonce=nonce, verifier=self._paths.verify_release)
        execution = self._authority_call(
            lambda: self._runner.release_execution(
                context.lease, context.cleanup,
                context_sha256=context.context_sha256,
                release_nonce=nonce),
            AmbiguousMutationError, "execution release outcome ambiguous")
        if type(execution) is not tuple or len(execution) != 4:
            raise StateError("execution release roster mismatch")
        expected = (
            ("cleanup-authority", context.cleanup.token),
            ("execution-lease", context.lease.token),
            ("execution-cgroup", context.lease.cgroup_token),
            ("execution-keeper", context.lease.keeper_token),
        )
        checked = tuple(self._validate_release_receipt(
            receipt, authority_id=self._runner_contract.authority_id,
            kind=kind, token=token, context=context, nonce=nonce,
            verifier=self._runner.verify_release)
            for receipt, (kind, token) in zip(execution, expected, strict=True))
        return self._validate_release_roster(
            (endpoint, overlay) + checked, context, nonce)

    def release(self, spec: ContainerSpec) -> ProviderReceipt:
        """Release endpoint, overlay, lease, cgroup, and keeper authorities."""
        context = self._context(spec, require_network=False)
        extinction = self._extinction(context)
        released: dict[str, tuple[ResourceReleaseReceipt, ...]] = {}

        def action(nonce: str) -> object:
            receipts = self._perform_release(context, nonce)
            released["receipts"] = receipts
            return receipts

        def verify(result: object, _expected: str | None) -> object:
            if type(result) is not tuple or result != released.get("receipts"):
                raise StateError("release receipt roster changed")
            return {"receipts": [item.digest for item in result]}

        self._mutate(context, "release", "authority-release", None, None,
                     action, verify, require_network=False)
        receipts = released["receipts"]
        self._released_attempts.add(context.attempt_id)
        document = {"schema": PROVIDER_SCHEMA, "kind": "release",
                    "attempt": context.attempt_id,
                    "receipts": [item.digest for item in receipts],
                    "resources": [item.kind for item in receipts]}
        document.update(self._extinction_document(extinction))
        return _receipt(document)

    def recover(self, spec: ContainerSpec, *,
                timeout: float = 30.0) -> ProviderReceipt:
        """Reconcile a pending effect by observation; never replay it."""
        self._require_ready()
        _validated(spec, ContractError, "invalid container specification")
        attempt = self._attempt_id(spec)
        try:
            recovery_snapshot = self._claim_attempt_recovery(spec)
        except _JournalRollback:
            return self._rollback_cleanup(spec, None, timeout)
        if recovery_snapshot.record_snapshot is None:
            if recovery_snapshot.admission is not None:
                return self._cleanup_admission(
                    recovery_snapshot.admission, recovery_snapshot)
            return _receipt({"schema": PROVIDER_SCHEMA, "kind": "recovery",
                             "attempt": attempt,
                             "status": "clean"})
        record = recovery_snapshot.record_snapshot.record
        context = self._context_from_record(
            spec, record, require_network=False,
            revalidate=record.operation != "release")
        self._contexts[(spec.run_id, spec.attempt_number)] = context
        self._assert_record_context(record, context)
        if record.state is MutationState.COMPLETE:
            if record.operation == "release":
                checked = self._validate_release_roster(
                    record.release_receipts, context, record.nonce)
                self._released_attempts.add(context.attempt_id)
            if record.operation == "export":
                if (record.artifact_destination is None
                        or record.artifact_commit is None
                        or record.artifact_manifest_sha256 is None
                        or record.artifact_sources_sha256 is None):
                    raise AmbiguousMutationError(
                        "complete export lacks durable artifact evidence")
                self._revalidate_export_destination(
                    record.artifact_destination)
                observed_commit = self._authority_call(
                    lambda: self._paths.validate_export(
                        record.artifact_destination,
                        expected_commit=record.artifact_commit,
                        attempt_id=context.attempt_id,
                        manifest_sha256=
                        record.artifact_manifest_sha256,
                        source_set_sha256=
                        record.artifact_sources_sha256,
                        timeout=_timeout(timeout)),
                    AmbiguousMutationError,
                    "complete export durable readback failed")
                observed_commit = self._validate_artifact_commit(
                    observed_commit, record.artifact_destination, context,
                    record.artifact_sources_sha256,
                    record.artifact_manifest_sha256)
                if observed_commit != record.artifact_commit:
                    raise AmbiguousMutationError(
                        "complete export archive or census changed")
            document = {"schema": PROVIDER_SCHEMA, "kind": "recovery",
                        "attempt": context.attempt_id,
                        "status": "complete",
                        "operation": record.operation}
            if record.operation == "release":
                document["receipts"] = [item.digest for item in checked]
            if record.operation == "export":
                document.update({
                    "artifact": observed_commit.archive_sha256,
                    "artifact_commit": observed_commit.digest,
                    "artifact_census": observed_commit.census_sha256,
                    "artifact_entries": observed_commit.entry_count,
                    "artifact_bytes": observed_commit.byte_count,
                })
            if record.operation in {"cancel", "export", "delete"}:
                document.update(self._extinction_document(
                    self._extinction(context)))
            return _receipt(document)
        if record.state is MutationState.ABORTED:
            return _receipt({"schema": PROVIDER_SCHEMA, "kind": "recovery",
                             "attempt": context.attempt_id,
                             "status": "aborted-safe-retry",
                             "operation": record.operation})
        recovered_id = record.expected_container_id
        extinction: ExtinctionObservation | None = None
        recovered_commit: ArtifactCommit | None = None
        if record.operation == "load":
            if record.operation_binding is None:
                raise AmbiguousMutationError("pending load lacks archive identity")
            self._revalidate_binding(record.operation_binding)
            image = self.inspect_image(spec.image, timeout=timeout,
                                       missing_ok=True)
            if image is None:
                raise AmbiguousMutationError("pending load has no committed image")
            post_object: object = {
                "image_id": image.id, "digest": image.digest,
                "archive": record.operation_binding.snapshot_sha256,
            }
        elif record.operation == "export":
            if (record.artifact_destination is None
                    or record.artifact_manifest_sha256 is None
                    or record.artifact_sources_sha256 is None):
                raise AmbiguousMutationError("pending export lacks artifact identity")
            self._revalidate_export_destination(record.artifact_destination)
            commit = self._authority_call(
                lambda: self._paths.validate_export(
                    record.artifact_destination, expected_commit=None,
                    attempt_id=context.attempt_id,
                    manifest_sha256=record.artifact_manifest_sha256,
                    source_set_sha256=record.artifact_sources_sha256,
                    timeout=_timeout(timeout)),
                AmbiguousMutationError, "pending export validation failed",
            )
            commit = self._validate_artifact_commit(
                commit, record.artifact_destination, context,
                record.artifact_sources_sha256,
                record.artifact_manifest_sha256)
            recovered_commit = commit
            observation = self._inspect(context, timeout, False, cleanup=True)
            if (observation.container_id != record.expected_container_id
                    or observation.state is not ContainerState.EXITED):
                raise AmbiguousMutationError("pending export container changed")
            post_object = {"container": record.expected_container_id,
                           "artifact": commit.archive_sha256,
                           "commit": commit.digest,
                           "census": commit.census_sha256}
            extinction = self._extinction(context)
        elif record.operation == "release":
            extinction = self._extinction(context)
            receipts = self._perform_release(context, record.nonce)
            post_object = {"receipts": [item.digest for item in receipts]}
            self._released_attempts.add(context.attempt_id)
        else:
            observation = self._inspect(context, timeout, True, cleanup=True)
            expected = {
                "create": ContainerState.CREATED,
                "start": ContainerState.RUNNING,
                "cancel": ContainerState.EXITED,
                "delete": ContainerState.ABSENT,
            }.get(record.operation)
            if expected is None or observation.state is not expected:
                raise AmbiguousMutationError("pending mutation cannot reconcile")
            if (record.expected_container_id is not None
                    and observation.container_id not in
                    (None, record.expected_container_id)):
                raise StateError("container identity recreated")
            recovered_id = (observation.container_id
                            if record.operation == "create"
                            else record.expected_container_id)
            post_object = {"container": recovered_id,
                           "observation": observation.observation_sha256}
            if record.operation in {"cancel", "delete"}:
                extinction = self._extinction(context)
        post = _hash(_canonical_json({"operation": record.operation,
                                      "postcondition": post_object,
                                      "nonce": record.nonce}))
        recovered_releases = (receipts
                              if record.operation == "release" else ())
        complete = self._successor(
            record, state=MutationState.COMPLETE,
            expected_container_id=recovered_id,
            artifact_commit=recovered_commit,
            release_receipts=recovered_releases,
            postcondition_sha256=post)
        self._write(complete)
        if self._record(context.attempt_id) != complete:
            raise AmbiguousMutationError("recovery journal record not durable")
        document = {"schema": PROVIDER_SCHEMA, "kind": "recovery",
                    "attempt": context.attempt_id,
                    "status": "reconciled",
                    "operation": record.operation,
                    "postcondition": post}
        if extinction is not None:
            document.update(self._extinction_document(extinction))
        return _receipt(document)


__all__ = [
    "AdmissionCleanupReceipt", "AdmissionError", "AdmissionReservation",
    "AdmissionRetirement",
    "AdmissionStageReceipt", "AmbiguousMutationError", "ArtifactCommit",
    "ArtifactDestination", "AttemptRecoverySnapshot",
    "BoundsError", "CleanupLease", "ComponentIdentities",
    "ComponentObservation", "ContainerObservation", "ContainerSpec",
    "ContainerState", "ContractError", "ExecutableIdentity",
    "ExecutionLease", "ExtinctionObservation", "HostFacts", "ImageArchive", "ImageObservation",
    "ImageSpec", "InvocationReceipt", "JOURNAL_SCHEMA", "JournalAnchor",
    "JournalContract", "JournalSnapshot",
    "MountRequest", "MutationRecord", "MutationState",
    "NetworkAuthorityContract", "NetworkKind", "NetworkProof",
    "ObservationAnchor", "ObservationChallenge", "OverlayTopology",
    "NATIVE_ADMISSION_COMPONENT_ROSTER", "NATIVE_ADMISSION_LIFECYCLE_AVAILABLE",
    "NATIVE_ADMISSION_SCHEMA", "NATIVE_ADMISSION_STATUS",
    "NATIVE_LIFECYCLE_AVAILABLE", "NATIVE_LIFECYCLE_REQUIRED_RECEIPTS",
    "NATIVE_LIFECYCLE_SCHEMA", "NATIVE_LIFECYCLE_STATUS",
    "PROVIDER_SCHEMA", "PathAuthorityContract",
    "PathBinding", "PodmanLinuxProvider", "PreflightError", "ProviderError",
    "ProviderReceipt", "ProviderRoots", "ReleaseProvenance",
    "ResourceReleaseReceipt",
    "RunnerContract", "RunnerResult", "StateError",
    "SUPPORTED_CONMON_VERSION", "SUPPORTED_CRUN_VERSION",
    "SUPPORTED_FUSE_OVERLAYFS_VERSION", "SUPPORTED_PODMAN_VERSION",
    "SUPPORTED_SHADOW_UTILS_VERSION", "verify_receipt",
]
