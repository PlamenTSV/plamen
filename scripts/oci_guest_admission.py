"""Fail-closed admission contracts for the governed Linux OCI audit guest.

Admission binds a canonical provider receipt to trusted launch expectations and
durably consumes its replay key.  Launch is synchronous under an injected
source namespace/content lease; no reusable launch authority is returned.

The weak-key issuer registries prevent ordinary constructor/slot forging only
inside an explicitly trusted interpreter which never executes project-owned
Python.  Pure-Python state is forgeable by malicious same-process mutation and
is not represented here as a sandbox boundary; production must enforce that
process boundary externally.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import PurePosixPath
import re
import stat
import threading
from types import MappingProxyType
from typing import Any, Callable, ContextManager, Generic, Iterator, Mapping, Protocol, TypeVar
import unicodedata
import weakref


SCHEMA = "plamen.oci_guest_admission.v1"
SCHEMA_V2 = "plamen.oci_guest_admission.v2"
TEST_ONLY_SCHEMA_V2 = "plamen.oci_guest_admission.test_only.v2"
TERMINAL_SCHEMA = "plamen.oci_guest_terminal.v1"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_MOUNTS = 3
MAX_MOUNTS_V2 = 10
MAX_HELPERS = 32
MAX_STRING_BYTES = 4096
MAX_TREE_ENTRIES = 1_000_000
MAX_TREE_BYTES = 1 << 40
MAX_TREE_DEPTH = 128
LANDLOCK_MIN_ABI = 5
LANDLOCK_MAX_TESTED_ABI = 11
SOURCE_SNAPSHOT_FORMAT = "PLAMEN_TREE_V1"
MASKED_PATHS = ("/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/scsi", "/sys/firmware")
READONLY_PATHS = ("/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger")

LANDLOCK_HANDLED_ACCESS_FS = (
    "EXECUTE", "WRITE_FILE", "READ_FILE", "READ_DIR", "REMOVE_DIR",
    "REMOVE_FILE", "MAKE_CHAR", "MAKE_DIR", "MAKE_REG", "MAKE_SOCK",
    "MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE", "IOCTL_DEV",
)
_MOUNT_POLICY = (
    ("project-source", "/workspace/project", "ro"),
    ("runtime", "/opt/plamen", "ro"),
    ("scratchpad", "/workspace/scratch", "rw"),
)
_MOUNT_POLICY_V2 = (
    ("project-merged", "/workspace/project", "rw"),
    ("scratch", "/workspace/scratch", "rw"),
    ("state", "/workspace/state", "rw"),
    ("control", "/workspace/control", "ro"),
    ("seccomp", "/run/plamen/seccomp", "ro"),
    ("credentials", "/run/plamen/credentials", "ro"),
    ("backend-context", "/run/plamen/backend", "ro"),
    ("runtime", "/opt/plamen", "ro"),
    ("docs", "/workspace/docs", "ro"),
    ("scope", "/workspace/scope", "ro"),
)
_HOST_LOWER_POLICY_V2 = ("target-lower", "HOST_OVERLAY_LOWER", "ro")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_OCI_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OCI_REFERENCE = re.compile(r"[a-z0-9](?:[a-z0-9._:-]{0,253})/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}\Z")
_ATTEMPT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")

_TOP_KEYS = frozenset({"schema", "image", "bindings", "rootfs", "mounts", "capabilities", "execution"})
_TOP_KEYS_V2 = frozenset({
    "schema", "image", "provider", "bindings", "rootfs", "mounts",
    "overlay", "capabilities", "execution", "lifecycle",
})
_IMAGE_KEYS = frozenset({"manifest_digest", "platform"})
_IMAGE_KEYS_V2 = frozenset({
    "reference", "index_digest", "manifest_digest", "config_digest",
    "apple_container_configuration_sha256", "platform",
})
_PLATFORM_KEYS = frozenset({"os", "architecture"})
_BINDING_KEYS = frozenset({"config_sha256", "launch_envelope_sha256", "runtime_closure_sha256", "helpers", "provider_attempt_id"})
_BINDING_KEYS_V2 = frozenset({
    "config_sha256", "launch_envelope_sha256", "runtime_closure_sha256",
    "helpers", "provider_attempt_id", "runtime_materialization",
    "image_closure_sha256", "backend_admission_sha256",
})
_RUNTIME_MATERIALIZATION_KEYS_V2 = frozenset({
    "source_roster_sha256", "composition_manifest_sha256", "archive_sha256",
    "archive_diff_id", "archive_size", "receipt_sha256",
    "installed_census_sha256", "sbom_sha256", "provenance_sha256",
    "entry_count", "expanded_bytes",
})
_HELPER_KEYS = frozenset({"path", "sha256"})
_ROOTFS_KEYS = frozenset({"readonly"})
_IDENTITY_KEYS = frozenset({"device", "inode", "uid", "gid", "mode", "object_kind", "snapshot_format", "snapshot_sha256", "regular_file_count", "directory_count", "total_bytes", "max_depth", "native_mount_id", "native_mount_id_kind", "mount_topology_sha256", "mount_proof_authenticated", "submounts_absent", "symlink_entries_absent", "special_files_absent", "hardlinks_absent", "xattrs_absent", "compressed_files_absent"})
_MOUNT_KEYS = frozenset({"kind", "source_root", "source_root_identity", "source", "source_identity", "destination", "mode", "purpose"})
_MOUNT_KEYS_V2 = frozenset((*_MOUNT_KEYS, "provider_mount_identity_sha256"))
_HOST_LOWER_KEYS_V2 = frozenset({
    "kind", "source_root", "source_root_identity", "source", "source_identity",
    "attachment", "mode", "purpose", "provider_mount_identity_sha256",
})
_PROVIDER_KEYS_V2 = frozenset({"kind", "identity_sha256", "provider_attempt_id"})
_OVERLAY_KEYS_V2 = frozenset({
    "target_lower", "project_merged_provider_mount_identity_sha256",
    "lower_binding_sha256",
})
_LIFECYCLE_KEYS_V2 = frozenset({
    "state", "create_stopped", "initial_process_count", "workload_nonexecuting",
    "precreate_layout_sha256", "postcreate_layout_sha256",
})
_CAPABILITY_KEYS = frozenset({"cgroup_v2", "landlock"})
_CGROUP_KEYS = frozenset({"filesystem", "path", "filesystem_device", "inode", "identity_sha256", "provider_attempt_id", "delegated", "provider_owns_tree", "pre_execution_assignment", "cgroup_type", "cgroup_kill", "termination_scope", "exhaustive_descendant_termination_authority"})
_LANDLOCK_KEYS = frozenset({"abi_version", "handled_access_fs", "ruleset_sha256", "active", "ruleset_status", "no_new_privs", "thread_state", "restricted_thread_count", "allowed_write_paths", "write_confinement", "exhaustive_write_confinement_authority"})
_EXECUTION_KEYS = frozenset({"uid", "gid", "supplemental_groups", "capabilities_drop", "capabilities_add", "inherited_environment", "ssh_agent_forwarding", "published_sockets", "host_devices", "nested_virtualization", "init", "no_new_privileges", "seccomp_status", "seccomp_profile_sha256", "masked_paths", "readonly_paths", "network_mode", "network_enforcement", "network_policy_sha256", "no_dns"})
_SENSITIVE_COMPONENTS = frozenset({".aws", ".claude", ".codex", ".config", ".docker", ".gnupg", ".netrc", ".ssh", "credentials", "id_ed25519", "id_rsa", "keychain", "keychains", "keyring", "passwords", "secrets", "ssh-agent", "tokens"})


class GuestAdmissionError(RuntimeError):
    """A receipt, expected binding, or launch-boundary proof is invalid."""


def _has_callable(value: Any, name: str) -> bool:
    try:
        member = getattr(value, name)
    except BaseException:
        return False
    return callable(member)


def _exact_dict(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise GuestAdmissionError(f"{label} keys are invalid")
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        try:
            key_bytes = key.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise GuestAdmissionError("guest receipt object key is not valid UTF-8") from None
        if len(key_bytes) > MAX_STRING_BYTES:
            raise GuestAdmissionError("guest receipt object key exceeds its byte bound")
        if key in result:
            raise GuestAdmissionError("guest receipt contains a duplicate object key")
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise GuestAdmissionError("guest receipt contains an unsupported numeric constant")


def _bounded_int_token(token: str) -> int:
    if len(token) > 20:
        raise GuestAdmissionError("guest receipt integer exceeds its token bound")
    return int(token)


def _reject_float(_token: str) -> None:
    raise GuestAdmissionError("guest receipt floats are unsupported")


def _validate_json_bounds(value: Any, *, depth: int = 0) -> None:
    if depth > 12:
        raise GuestAdmissionError("guest receipt exceeds its depth bound")
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is str:
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise GuestAdmissionError("guest receipt string is not valid UTF-8") from None
        if len(encoded) > MAX_STRING_BYTES:
            raise GuestAdmissionError("guest receipt string exceeds its byte bound")
        return
    if type(value) is list:
        if len(value) > MAX_HELPERS:
            raise GuestAdmissionError("guest receipt array exceeds its item bound")
        for item in value:
            _validate_json_bounds(item, depth=depth + 1)
        return
    if type(value) is dict:
        if len(value) > 32:
            raise GuestAdmissionError("guest receipt object exceeds its item bound")
        for key, item in value.items():
            if type(key) is not str:
                raise GuestAdmissionError("guest receipt object key is not text")
            _validate_json_bounds(key, depth=depth + 1)
            _validate_json_bounds(item, depth=depth + 1)
        return
    raise GuestAdmissionError("guest receipt contains an unsupported JSON value")


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def canonical_receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    """Render the only accepted byte representation for either receipt schema."""
    if type(receipt) is not dict:
        raise GuestAdmissionError("guest receipt renderer requires an exact dictionary")
    _validate_json_bounds(receipt)
    raw = _canonical_bytes(receipt)
    if len(raw) > MAX_RECEIPT_BYTES:
        raise GuestAdmissionError("guest receipt exceeds its byte ceiling")
    return raw


def _load_receipt(raw: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise GuestAdmissionError("guest receipt must use exact bytes")
    if type(maximum_bytes) is not int or isinstance(maximum_bytes, bool) or not 1 <= maximum_bytes <= MAX_RECEIPT_BYTES:
        raise GuestAdmissionError("guest receipt byte ceiling is invalid")
    if len(raw) > maximum_bytes:
        raise GuestAdmissionError("guest receipt exceeds its byte ceiling")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise GuestAdmissionError("guest receipt is not valid UTF-8") from None
    if text.startswith("\ufeff"):
        raise GuestAdmissionError("guest receipt UTF-8 BOM is unsupported")
    try:
        value = json.loads(text, object_pairs_hook=_strict_object, parse_constant=_reject_constant, parse_int=_bounded_int_token, parse_float=_reject_float)
    except GuestAdmissionError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError):
        raise GuestAdmissionError("guest receipt JSON is invalid") from None
    _validate_json_bounds(value)
    if type(value) is not dict:
        raise GuestAdmissionError("guest receipt root must be an object")
    if raw != _canonical_bytes(value):
        raise GuestAdmissionError("guest receipt bytes are not canonical")
    return value


def _plain_digest(value: Any, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise GuestAdmissionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _image_digest(value: Any, label: str) -> str:
    if type(value) is not str or _OCI_SHA256.fullmatch(value) is None:
        raise GuestAdmissionError(f"{label} must be an OCI sha256 digest")
    return value


def _domain_int(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise GuestAdmissionError(f"{label} must be an integer")
    if not (1 if positive else 0) <= value <= 2**63 - 1:
        raise GuestAdmissionError(f"{label} is outside its domain")
    return value


def _canonical_posix_path(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise GuestAdmissionError(f"{label} must be a nonempty path")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise GuestAdmissionError(f"{label} is not valid UTF-8") from None
    if len(encoded) > MAX_STRING_BYTES:
        raise GuestAdmissionError(f"{label} exceeds its byte bound")
    if value != unicodedata.normalize("NFC", value):
        raise GuestAdmissionError(f"{label} is not NFC-normalized")
    if "\\" in value or "\x00" in value or any(ord(character) < 32 for character in value):
        raise GuestAdmissionError(f"{label} contains unsupported path bytes")
    if not value.startswith("/") or value.startswith("//"):
        raise GuestAdmissionError(f"{label} must be one canonical absolute POSIX path")
    if value != "/" and value.endswith("/"):
        raise GuestAdmissionError(f"{label} has a trailing separator")
    parts = value.split("/")[1:]
    if any(part in {"", ".", ".."} for part in parts) or str(PurePosixPath(value)) != value:
        raise GuestAdmissionError(f"{label} contains a path alias")
    return value


def _path_identity(value: str) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFKC", part).casefold() for part in value.split("/") if part)


def _is_same_or_parent(parent: str, child: str) -> bool:
    left, right = _path_identity(parent), _path_identity(child)
    return len(left) <= len(right) and right[:len(left)] == left


def _is_strict_parent(parent: str, child: str) -> bool:
    return _path_identity(parent) != _path_identity(child) and _is_same_or_parent(parent, child)


def _attempt(value: Any, label: str) -> str:
    if type(value) is not str or _ATTEMPT_ID.fullmatch(value) is None:
        raise GuestAdmissionError(f"{label} is invalid")
    return value


def _reject_sensitive_source(source: str, host_home: str) -> None:
    identity = _path_identity(source)
    lowered = "/" + "/".join(identity)
    if source == "/" or _is_same_or_parent(source, host_home):
        raise GuestAdmissionError("mount source would expose the host home")
    if not _is_strict_parent(host_home, source):
        raise GuestAdmissionError("mount source is outside the governed host home")
    if any(part in _SENSITIVE_COMPONENTS or "keychain" in part for part in identity):
        raise GuestAdmissionError("mount source names a credential or keychain location")
    if lowered.endswith(".sock") or "/com.apple.launchd." in lowered or "/tmp/ssh-" in lowered or "/ssh-agent" in lowered or "/containerd" in lowered or "/docker" in lowered:
        raise GuestAdmissionError("mount source names a host agent or container socket")


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    object_kind: str
    snapshot_format: str
    snapshot_sha256: str
    regular_file_count: int
    directory_count: int
    total_bytes: int
    max_depth: int
    native_mount_id: int
    native_mount_id_kind: str
    mount_topology_sha256: str
    mount_proof_authenticated: bool
    submounts_absent: bool
    symlink_entries_absent: bool
    special_files_absent: bool
    hardlinks_absent: bool
    xattrs_absent: bool
    compressed_files_absent: bool

    def __post_init__(self) -> None:
        _domain_int(self.device, "source device")
        _domain_int(self.inode, "source inode", positive=True)
        _domain_int(self.uid, "source uid")
        _domain_int(self.gid, "source gid")
        if _domain_int(self.mode, "source mode") > 0o7777:
            raise GuestAdmissionError("source mode must contain permission bits only")
        if self.object_kind != "directory" or self.snapshot_format != SOURCE_SNAPSHOT_FORMAT:
            raise GuestAdmissionError("mount source identity type/format is unsupported")
        _plain_digest(self.snapshot_sha256, "source snapshot sha256")
        regular = _domain_int(self.regular_file_count, "source regular-file count")
        directories = _domain_int(self.directory_count, "source directory count", positive=True)
        total = _domain_int(self.total_bytes, "source total bytes")
        depth = _domain_int(self.max_depth, "source maximum depth")
        if regular + directories > MAX_TREE_ENTRIES or total > MAX_TREE_BYTES or depth > MAX_TREE_DEPTH:
            raise GuestAdmissionError("source tree census exceeds its bound")
        _domain_int(self.native_mount_id, "native mount ID", positive=True)
        if self.native_mount_id_kind not in {
            "STATX_MNT_ID_UNIQUE", "PROVIDER_AUTHENTICATED_MOUNT_ID"
        }:
            raise GuestAdmissionError("native mount-ID proof kind is unsupported")
        _plain_digest(self.mount_topology_sha256, "mount topology sha256")
        safe = (
            self.mount_proof_authenticated is True and self.submounts_absent is True
            and
            self.symlink_entries_absent is True and self.special_files_absent is True
            and self.hardlinks_absent is True and self.xattrs_absent is True
            and self.compressed_files_absent is True
        )
        if not safe:
            raise GuestAdmissionError("source snapshot lacks authenticated no-submount proof or contains an unsafe object")


@dataclass(frozen=True, slots=True)
class HelperBinding:
    path: str
    sha256: str

    def __post_init__(self) -> None:
        _canonical_posix_path(self.path, "helper path")
        _plain_digest(self.sha256, "helper sha256")


@dataclass(frozen=True, slots=True)
class MountBinding:
    source_root: str
    source_root_identity: SourceIdentity
    source: str
    source_identity: SourceIdentity
    destination: str
    mode: str
    purpose: str
    kind: str = "bind"

    def __post_init__(self) -> None:
        root = _canonical_posix_path(self.source_root, "mount source root")
        source = _canonical_posix_path(self.source, "mount source")
        _canonical_posix_path(self.destination, "mount destination")
        if type(self.source_root_identity) is not SourceIdentity or type(self.source_identity) is not SourceIdentity:
            raise GuestAdmissionError("mount source identity is invalid")
        if not _is_same_or_parent(root, source):
            raise GuestAdmissionError("mount source is outside its governed source root")
        if self.kind != "bind" or type(self.purpose) is not str:
            raise GuestAdmissionError("guest mount type/purpose is invalid")


def _source_descriptor_identity(identity: SourceIdentity) -> tuple[int, int]:
    """Underlying object identity used to reject cross-role source reuse.

    A bind mount can give the same filesystem object a different provider mount
    ID and topology proof.  Those authenticated mount identities are checked
    separately; they must never make a repeated ``(device, inode)`` appear to
    be a distinct source object.
    """
    return identity.device, identity.inode


@dataclass(frozen=True, slots=True)
class SupervisorMountBindingV2:
    """One exact supervisor guest mount in the V2 stopped-guest contract."""

    source_root: str
    source_root_identity: SourceIdentity
    source: str
    source_identity: SourceIdentity
    destination: str
    mode: str
    purpose: str
    provider_mount_identity_sha256: str
    kind: str = "bind"

    def __post_init__(self) -> None:
        root = _canonical_posix_path(self.source_root, "V2 mount source root")
        source = _canonical_posix_path(self.source, "V2 mount source")
        _canonical_posix_path(self.destination, "V2 mount destination")
        if (
            type(self.source_root_identity) is not SourceIdentity
            or type(self.source_identity) is not SourceIdentity
        ):
            raise GuestAdmissionError("V2 mount source identity is invalid")
        # Each supervisor role owns one independently pinned tree.  A shared
        # ancestor FD would let one role's authority be substituted for another.
        if root != source or self.source_root_identity != self.source_identity:
            raise GuestAdmissionError("V2 mount must bind one exact independently pinned source root")
        if self.kind != "bind" or type(self.purpose) is not str:
            raise GuestAdmissionError("V2 guest mount type/purpose is invalid")
        _plain_digest(
            self.provider_mount_identity_sha256,
            "V2 provider mount identity sha256",
        )


@dataclass(frozen=True, slots=True)
class HostOverlayLowerBindingV2:
    """Host-only read-only lower tree; never present in the guest mount list."""

    source_root: str
    source_root_identity: SourceIdentity
    source: str
    source_identity: SourceIdentity
    provider_mount_identity_sha256: str
    purpose: str = "target-lower"
    attachment: str = "HOST_OVERLAY_LOWER"
    mode: str = "ro"
    kind: str = "bind"

    def __post_init__(self) -> None:
        root = _canonical_posix_path(self.source_root, "V2 target-lower source root")
        source = _canonical_posix_path(self.source, "V2 target-lower source")
        if (
            type(self.source_root_identity) is not SourceIdentity
            or type(self.source_identity) is not SourceIdentity
        ):
            raise GuestAdmissionError("V2 target-lower identity is invalid")
        if root != source or self.source_root_identity != self.source_identity:
            raise GuestAdmissionError("V2 target-lower must bind one exact pinned root")
        if (self.purpose, self.attachment, self.mode, self.kind) != (
            *_HOST_LOWER_POLICY_V2, "bind",
        ):
            raise GuestAdmissionError("V2 target-lower violates the host-only policy")
        _plain_digest(
            self.provider_mount_identity_sha256,
            "V2 target-lower provider mount identity sha256",
        )


def _lower_binding_sha256_v2(
    target_lower: HostOverlayLowerBindingV2,
    project_merged: SupervisorMountBindingV2,
) -> str:
    """Bind the native lower mount and content proof to the merged mount proof."""
    return hashlib.sha256(_canonical_bytes({
        "schema": "plamen.oci_overlay_lower_binding.v2",
        "target_lower_provider_mount_identity_sha256": (
            target_lower.provider_mount_identity_sha256
        ),
        "target_lower_snapshot_sha256": target_lower.source_identity.snapshot_sha256,
        "target_lower_mount_topology_sha256": (
            target_lower.source_identity.mount_topology_sha256
        ),
        "project_merged_provider_mount_identity_sha256": (
            project_merged.provider_mount_identity_sha256
        ),
        "project_merged_snapshot_sha256": project_merged.source_identity.snapshot_sha256,
        "project_merged_mount_topology_sha256": (
            project_merged.source_identity.mount_topology_sha256
        ),
    })).hexdigest()


@dataclass(frozen=True, slots=True)
class CgroupAuthority:
    path: str
    filesystem_device: int
    inode: int
    identity_sha256: str
    provider_attempt_id: str
    filesystem: str = "cgroup2"
    delegated: bool = True
    provider_owns_tree: bool = True
    pre_execution_assignment: bool = True
    cgroup_type: str = "domain"
    cgroup_kill: str = "AVAILABLE_WRITABLE"
    termination_scope: str = "CGROUP_V2_SUBTREE"
    exhaustive_descendant_termination_authority: bool = True

    def __post_init__(self) -> None:
        attempt = _attempt(self.provider_attempt_id, "cgroup provider attempt ID")
        if _canonical_posix_path(self.path, "cgroup path") != f"/sys/fs/cgroup/plamen/{attempt}":
            raise GuestAdmissionError("cgroup path is not bound to the provider attempt")
        _domain_int(self.filesystem_device, "cgroup filesystem device", positive=True)
        _domain_int(self.inode, "cgroup inode", positive=True)
        _plain_digest(self.identity_sha256, "cgroup identity sha256")
        exact = (
            self.filesystem == "cgroup2" and self.delegated is True
            and self.provider_owns_tree is True and self.pre_execution_assignment is True
            and self.cgroup_type == "domain" and self.cgroup_kill == "AVAILABLE_WRITABLE"
            and self.termination_scope == "CGROUP_V2_SUBTREE"
            and self.exhaustive_descendant_termination_authority is True
        )
        if not exact:
            raise GuestAdmissionError("cgroup-v2 authority is insufficient")


@dataclass(frozen=True, slots=True)
class LandlockAuthority:
    abi_version: int
    ruleset_sha256: str
    handled_access_fs: tuple[str, ...] = LANDLOCK_HANDLED_ACCESS_FS
    active: bool = True
    ruleset_status: str = "ENFORCED_BEFORE_EXEC"
    no_new_privs: bool = True
    thread_state: str = "SINGLE_THREADED_CALLER_RESTRICTED_BEFORE_EXEC"
    restricted_thread_count: int = 1
    allowed_write_paths: tuple[str, ...] = ("/workspace/scratch",)
    write_confinement: str = "LANDLOCK_PATH_BENEATH_EXACT"
    exhaustive_write_confinement_authority: bool = True

    def __post_init__(self) -> None:
        if type(self.abi_version) is not int or isinstance(self.abi_version, bool) or not LANDLOCK_MIN_ABI <= self.abi_version <= LANDLOCK_MAX_TESTED_ABI:
            raise GuestAdmissionError("Landlock ABI is outside the supported security domain")
        _plain_digest(self.ruleset_sha256, "Landlock ruleset sha256")
        if type(self.handled_access_fs) is not tuple or self.handled_access_fs != LANDLOCK_HANDLED_ACCESS_FS:
            raise GuestAdmissionError("Landlock handled filesystem rights are incomplete")
        if type(self.allowed_write_paths) is not tuple:
            raise GuestAdmissionError("Landlock allowed write paths are invalid")
        for path in self.allowed_write_paths:
            _canonical_posix_path(path, "Landlock allowed write path")
        exact = (
            self.active is True and self.ruleset_status == "ENFORCED_BEFORE_EXEC"
            and self.no_new_privs is True
            and self.thread_state == "SINGLE_THREADED_CALLER_RESTRICTED_BEFORE_EXEC"
            and type(self.restricted_thread_count) is int
            and self.restricted_thread_count == 1
            and self.write_confinement == "LANDLOCK_PATH_BENEATH_EXACT"
            and self.exhaustive_write_confinement_authority is True
        )
        if not exact:
            raise GuestAdmissionError("Landlock authority is insufficient")


@dataclass(frozen=True, slots=True)
class ExecutionAuthority:
    """Exact non-filesystem process and network posture proven by the launcher."""

    uid: int
    gid: int
    seccomp_profile_sha256: str
    network_policy_sha256: str
    supplemental_groups: tuple[int, ...] = ()
    capabilities_drop: tuple[str, ...] = ("ALL",)
    capabilities_add: tuple[str, ...] = ()
    inherited_environment: bool = False
    ssh_agent_forwarding: bool = False
    published_sockets: tuple[str, ...] = ()
    host_devices: tuple[str, ...] = ()
    nested_virtualization: bool = False
    init: bool = True
    no_new_privileges: bool = True
    seccomp_status: str = "ENFORCED_BEFORE_EXEC"
    masked_paths: tuple[str, ...] = MASKED_PATHS
    readonly_paths: tuple[str, ...] = READONLY_PATHS
    network_mode: str = "GOVERNED_PROXY_ONLY"
    network_enforcement: str = "VERIFIED_NARROW_PROXY"
    no_dns: bool = True

    def __post_init__(self) -> None:
        uid = _domain_int(self.uid, "guest uid", positive=True)
        gid = _domain_int(self.gid, "guest gid", positive=True)
        if uid > 2**31 - 1 or gid > 2**31 - 1:
            raise GuestAdmissionError("guest uid/gid is outside its domain")
        _plain_digest(self.seccomp_profile_sha256, "seccomp profile sha256")
        _plain_digest(self.network_policy_sha256, "network policy sha256")
        if type(self.supplemental_groups) is not tuple or self.supplemental_groups:
            raise GuestAdmissionError("guest supplemental groups must be empty")
        for roster, label in ((self.published_sockets, "published sockets"), (self.host_devices, "host devices")):
            if type(roster) is not tuple or roster:
                raise GuestAdmissionError(f"guest {label} must be empty")
        if type(self.masked_paths) is not tuple or type(self.readonly_paths) is not tuple:
            raise GuestAdmissionError("guest protected path rosters are invalid")
        for path in (*self.masked_paths, *self.readonly_paths):
            _canonical_posix_path(path, "guest protected path")
        exact = (
            self.capabilities_drop == ("ALL",) and self.capabilities_add == ()
            and self.inherited_environment is False and self.ssh_agent_forwarding is False
            and self.nested_virtualization is False and self.init is True
            and self.no_new_privileges is True and self.seccomp_status == "ENFORCED_BEFORE_EXEC"
            and self.masked_paths == MASKED_PATHS and self.readonly_paths == READONLY_PATHS
            and self.network_mode == "GOVERNED_PROXY_ONLY"
            and self.network_enforcement == "VERIFIED_NARROW_PROXY" and self.no_dns is True
        )
        if not exact:
            raise GuestAdmissionError("guest process/network authority is insufficient")


@dataclass(frozen=True, slots=True)
class ExecutionAuthorityV2:
    """Supervisor-compatible V2 process and exact narrow-network posture."""

    uid: int
    gid: int
    seccomp_profile_sha256: str
    network_policy_sha256: str
    supplemental_groups: tuple[int, ...] = ()
    capabilities_drop: tuple[str, ...] = ("ALL",)
    capabilities_add: tuple[str, ...] = ()
    inherited_environment: bool = False
    ssh_agent_forwarding: bool = False
    published_sockets: tuple[str, ...] = ()
    host_devices: tuple[str, ...] = ()
    nested_virtualization: bool = False
    init: bool = True
    no_new_privileges: bool = True
    seccomp_status: str = "ENFORCED_BEFORE_EXEC"
    masked_paths: tuple[str, ...] = MASKED_PATHS
    readonly_paths: tuple[str, ...] = READONLY_PATHS
    network_mode: str = "NARROW_TRUSTED_PROXY_ONLY"
    network_enforcement: str = "VERIFIED_NARROW_PROXY"
    no_dns: bool = True

    def __post_init__(self) -> None:
        uid = _domain_int(self.uid, "V2 guest uid", positive=True)
        gid = _domain_int(self.gid, "V2 guest gid", positive=True)
        if uid > 2**31 - 1 or gid > 2**31 - 1:
            raise GuestAdmissionError("V2 guest uid/gid is outside its domain")
        _plain_digest(self.seccomp_profile_sha256, "V2 seccomp profile sha256")
        _plain_digest(self.network_policy_sha256, "V2 network policy sha256")
        if type(self.supplemental_groups) is not tuple or self.supplemental_groups:
            raise GuestAdmissionError("V2 guest supplemental groups must be empty")
        for roster, label in (
            (self.published_sockets, "published sockets"),
            (self.host_devices, "host devices"),
        ):
            if type(roster) is not tuple or roster:
                raise GuestAdmissionError(f"V2 guest {label} must be empty")
        if type(self.masked_paths) is not tuple or type(self.readonly_paths) is not tuple:
            raise GuestAdmissionError("V2 guest protected path rosters are invalid")
        for path in (*self.masked_paths, *self.readonly_paths):
            _canonical_posix_path(path, "V2 guest protected path")
        exact = (
            self.capabilities_drop == ("ALL",) and self.capabilities_add == ()
            and self.inherited_environment is False
            and self.ssh_agent_forwarding is False
            and self.nested_virtualization is False and self.init is True
            and self.no_new_privileges is True
            and self.seccomp_status == "ENFORCED_BEFORE_EXEC"
            and self.masked_paths == MASKED_PATHS
            and self.readonly_paths == READONLY_PATHS
            and self.network_mode == "NARROW_TRUSTED_PROXY_ONLY"
            and self.network_enforcement == "VERIFIED_NARROW_PROXY"
            and self.no_dns is True
        )
        if not exact:
            raise GuestAdmissionError("V2 guest process/network authority is insufficient")


def _validate_unique_paths(paths: tuple[str, ...], label: str) -> None:
    identities = tuple(_path_identity(path) for path in paths)
    if len(set(identities)) != len(identities):
        raise GuestAdmissionError(f"{label} contains duplicate/case/Unicode aliases")


def _validate_mount_roster(mounts: tuple[MountBinding, ...], host_home: str) -> None:
    if len(mounts) != len(_MOUNT_POLICY):
        raise GuestAdmissionError("guest mount roster must contain the closed purpose set")
    _validate_unique_paths(tuple(row.source_root for row in mounts), "mount source roots")
    _validate_unique_paths(tuple(row.source for row in mounts), "mount sources")
    _validate_unique_paths(tuple(row.destination for row in mounts), "mount destinations")
    for row, policy in zip(mounts, _MOUNT_POLICY, strict=True):
        purpose, destination, mode = policy
        if (row.purpose, row.destination, row.mode, row.kind) != (purpose, destination, mode, "bind"):
            raise GuestAdmissionError("guest mount roster violates the closed purpose policy")
        _reject_sensitive_source(row.source_root, host_home)
        _reject_sensitive_source(row.source, host_home)
        if not _is_same_or_parent(row.source_root, row.source):
            raise GuestAdmissionError("mount source is outside its governed source root")
    for index, left in enumerate(mounts):
        for right in mounts[index + 1:]:
            for left_path in (left.source_root, left.source):
                for right_path in (right.source_root, right.source):
                    if _is_same_or_parent(left_path, right_path) or _is_same_or_parent(right_path, left_path):
                        raise GuestAdmissionError("governed mount source trees overlap")


def _validate_v2_source_path(
    purpose: str, source: str, host_home: str,
) -> None:
    identity = _path_identity(source)
    lowered = "/" + "/".join(identity)
    if source == "/" or _is_same_or_parent(source, host_home):
        raise GuestAdmissionError("V2 mount source would expose the host home")
    if not _is_strict_parent(host_home, source):
        raise GuestAdmissionError("V2 mount source is outside the governed host home")
    if (
        lowered.endswith(".sock") or "/com.apple.launchd." in lowered
        or "/tmp/ssh-" in lowered or "/ssh-agent" in lowered
        or "/containerd" in lowered or "/docker" in lowered
    ):
        raise GuestAdmissionError("V2 mount source names a host agent or container socket")
    sensitive = tuple(
        part for part in identity
        if part in _SENSITIVE_COMPONENTS or "keychain" in part
    )
    # The dedicated credential role may name its private credential staging
    # directory. No other guest-visible role may alias such a path.
    if sensitive and not (
        purpose == "credentials"
        and sensitive == (identity[-1],)
        and identity[-1] in {"credentials", "secrets"}
    ):
        raise GuestAdmissionError("V2 mount source names a credential or keychain location")


def _validate_mount_roster_v2(
    mounts: tuple[SupervisorMountBindingV2, ...],
    target_lower: HostOverlayLowerBindingV2,
    host_home: str,
    lower_binding_sha256: str,
) -> None:
    if len(mounts) != len(_MOUNT_POLICY_V2):
        raise GuestAdmissionError("V2 guest mount roster must contain the closed purpose set")
    if tuple((row.purpose, row.destination, row.mode) for row in mounts) != _MOUNT_POLICY_V2:
        raise GuestAdmissionError("V2 guest mount roster violates the closed purpose policy")
    if any(row.kind != "bind" for row in mounts):
        raise GuestAdmissionError("V2 guest mount kind violates the closed purpose policy")
    _validate_unique_paths(tuple(row.source for row in mounts), "V2 mount sources")
    _validate_unique_paths(tuple(row.destination for row in mounts), "V2 mount destinations")
    provider_identities = tuple(
        row.provider_mount_identity_sha256 for row in mounts
    ) + (target_lower.provider_mount_identity_sha256,)
    if len(set(provider_identities)) != len(provider_identities):
        raise GuestAdmissionError("V2 provider mount identities overlap across roles")
    descriptor_identities = tuple(
        _source_descriptor_identity(row.source_identity) for row in mounts
    ) + (_source_descriptor_identity(target_lower.source_identity),)
    if len(set(descriptor_identities)) != len(descriptor_identities):
        raise GuestAdmissionError("V2 source descriptors overlap across roles")
    all_sources = tuple(row.source for row in mounts) + (target_lower.source,)
    for index, left in enumerate(all_sources):
        for right in all_sources[index + 1:]:
            if _is_same_or_parent(left, right) or _is_same_or_parent(right, left):
                raise GuestAdmissionError("V2 governed mount source trees overlap")
    for row in mounts:
        _validate_v2_source_path(row.purpose, row.source, host_home)
    _validate_v2_source_path(target_lower.purpose, target_lower.source, host_home)
    project_merged = mounts[0]
    if lower_binding_sha256 != _lower_binding_sha256_v2(target_lower, project_merged):
        raise GuestAdmissionError("V2 target-lower binding differs from project-merged proof")


def _validate_helpers_v2(
    helpers: tuple[HelperBinding, ...],
    mounts: tuple[SupervisorMountBindingV2, ...],
) -> None:
    by_purpose = {row.purpose: row for row in mounts}
    runtime = by_purpose["runtime"].destination
    writable = tuple(row.destination for row in mounts if row.mode == "rw")
    for helper in helpers:
        if not _is_strict_parent(runtime, helper.path):
            raise GuestAdmissionError("V2 guest helper is outside the read-only runtime mount")
        if any(_is_same_or_parent(path, helper.path) for path in writable):
            raise GuestAdmissionError("V2 guest helper overlaps a writable mount")


def _validate_helpers(helpers: tuple[HelperBinding, ...], mounts: tuple[MountBinding, ...]) -> None:
    runtime = mounts[1].destination
    writable = tuple(row.destination for row in mounts if row.mode == "rw")
    for helper in helpers:
        if not _is_strict_parent(runtime, helper.path):
            raise GuestAdmissionError("guest helper is outside the read-only runtime mount")
        if any(_is_same_or_parent(path, helper.path) for path in writable):
            raise GuestAdmissionError("guest helper overlaps a writable mount")


@dataclass(frozen=True, slots=True)
class GuestAdmissionExpectation:
    image_manifest_digest: str
    config_sha256: str
    launch_envelope_sha256: str
    runtime_closure_sha256: str
    provider_attempt_id: str
    helpers: tuple[HelperBinding, ...]
    mounts: tuple[MountBinding, ...]
    cgroup: CgroupAuthority
    landlock: LandlockAuthority
    execution: ExecutionAuthority
    host_home: str

    def __post_init__(self) -> None:
        _image_digest(self.image_manifest_digest, "expected image manifest digest")
        _plain_digest(self.config_sha256, "expected config sha256")
        _plain_digest(self.launch_envelope_sha256, "expected launch envelope sha256")
        _plain_digest(self.runtime_closure_sha256, "expected runtime closure sha256")
        attempt = _attempt(self.provider_attempt_id, "expected provider attempt ID")
        if type(self.helpers) is not tuple or not self.helpers or len(self.helpers) > MAX_HELPERS or any(type(row) is not HelperBinding for row in self.helpers):
            raise GuestAdmissionError("expected helper roster is invalid")
        _validate_unique_paths(tuple(row.path for row in self.helpers), "helper roster")
        if type(self.mounts) is not tuple or any(type(row) is not MountBinding for row in self.mounts):
            raise GuestAdmissionError("expected mount roster is invalid")
        if type(self.cgroup) is not CgroupAuthority or self.cgroup.provider_attempt_id != attempt:
            raise GuestAdmissionError("expected cgroup authority is not attempt-bound")
        if type(self.landlock) is not LandlockAuthority:
            raise GuestAdmissionError("expected Landlock authority is invalid")
        if type(self.execution) is not ExecutionAuthority:
            raise GuestAdmissionError("expected process/network authority is invalid")
        home = _canonical_posix_path(self.host_home, "host home")
        if home == "/":
            raise GuestAdmissionError("host home cannot be the filesystem root")
        _validate_mount_roster(self.mounts, home)
        _validate_helpers(self.helpers, self.mounts)
        if self.landlock.allowed_write_paths != tuple(row.destination for row in self.mounts if row.mode == "rw"):
            raise GuestAdmissionError("Landlock write paths differ from the writable mount roster")


@dataclass(frozen=True, slots=True)
class RuntimeMaterializationBindingV2:
    source_roster_sha256: str
    composition_manifest_sha256: str
    archive_sha256: str
    archive_diff_id: str
    archive_size: int
    receipt_sha256: str
    installed_census_sha256: str
    sbom_sha256: str
    provenance_sha256: str
    entry_count: int
    expanded_bytes: int

    def __post_init__(self) -> None:
        for name in (
            "source_roster_sha256", "composition_manifest_sha256",
            "archive_sha256", "receipt_sha256", "installed_census_sha256",
            "sbom_sha256", "provenance_sha256",
        ):
            _plain_digest(getattr(self, name), f"V2 runtime materialization {name}")
        _image_digest(self.archive_diff_id, "V2 runtime materialization archive DiffID")
        if self.archive_diff_id != "sha256:" + self.archive_sha256:
            raise GuestAdmissionError("V2 materialized archive digest and DiffID differ")
        _domain_int(self.archive_size, "V2 materialized archive size", positive=True)
        _domain_int(self.entry_count, "V2 installed runtime entry count", positive=True)
        _domain_int(self.expanded_bytes, "V2 installed runtime expanded bytes")


def _runtime_materialization_row_v2(value: Any) -> RuntimeMaterializationBindingV2:
    row = _exact_dict(value, _RUNTIME_MATERIALIZATION_KEYS_V2, "V2 runtime materialization")
    return RuntimeMaterializationBindingV2(**row)


def _image_closure_sha256_v2(expectation: "GuestAdmissionExpectationV2") -> str:
    return hashlib.sha256(_canonical_bytes({
        "apple_container_configuration_sha256": expectation.apple_container_configuration_sha256,
        "config_digest": expectation.image_config_digest,
        "index_digest": expectation.image_index_digest,
        "manifest_digest": expectation.image_manifest_digest,
        "platform": {"architecture": expectation.platform_architecture, "os": expectation.platform_os},
        "reference": expectation.image_reference,
    })).hexdigest()


def _backend_admission_sha256_v2(expectation: "GuestAdmissionExpectationV2") -> str:
    return hashlib.sha256(_canonical_bytes({
        "config_sha256": expectation.config_sha256,
        "helpers": [{"path": row.path, "sha256": row.sha256} for row in expectation.helpers],
        "image_closure_sha256": expectation.image_closure_sha256,
        "launch_envelope_sha256": expectation.launch_envelope_sha256,
        "provider_attempt_id": expectation.provider_attempt_id,
        "runtime_closure_sha256": expectation.runtime_closure_sha256,
        "runtime_materialization": {
            name: getattr(expectation.runtime_materialization, name)
            for name in _RUNTIME_MATERIALIZATION_KEYS_V2
        },
    })).hexdigest()


@dataclass(frozen=True, slots=True)
class GuestAdmissionExpectationV2:
    """Exact authority inputs for the supervisor-compatible stopped guest."""

    image_reference: str
    image_index_digest: str
    image_manifest_digest: str
    image_config_digest: str
    apple_container_configuration_sha256: str
    platform_os: str
    platform_architecture: str
    provider_kind: str
    provider_identity_sha256: str
    config_sha256: str
    launch_envelope_sha256: str
    runtime_closure_sha256: str
    runtime_materialization: RuntimeMaterializationBindingV2
    image_closure_sha256: str
    backend_admission_sha256: str
    provider_attempt_id: str
    helpers: tuple[HelperBinding, ...]
    mounts: tuple[SupervisorMountBindingV2, ...]
    target_lower: HostOverlayLowerBindingV2
    lower_binding_sha256: str
    precreate_layout_sha256: str
    postcreate_layout_sha256: str
    cgroup: CgroupAuthority
    landlock: LandlockAuthority
    execution: ExecutionAuthorityV2
    host_home: str

    def __post_init__(self) -> None:
        if type(self.image_reference) is not str or _OCI_REFERENCE.fullmatch(self.image_reference) is None:
            raise GuestAdmissionError("V2 expected image reference is malformed")
        index_digest = _image_digest(self.image_index_digest, "V2 expected image index digest")
        _image_digest(self.image_manifest_digest, "V2 expected image manifest digest")
        _image_digest(self.image_config_digest, "V2 expected image config digest")
        _plain_digest(self.apple_container_configuration_sha256, "V2 expected Apple Container configuration sha256")
        if self.image_reference.rsplit("@", 1)[1] != index_digest:
            raise GuestAdmissionError("V2 image reference does not bind its index")
        if self.platform_os != "linux" or self.platform_architecture not in {"arm64", "amd64"}:
            raise GuestAdmissionError("V2 expected platform must be exactly linux/arm64 or linux/amd64")
        if self.provider_kind not in {"APPLE_CONTAINER", "PODMAN_ROOTLESS"}:
            raise GuestAdmissionError("V2 provider kind is unsupported")
        _plain_digest(self.provider_identity_sha256, "V2 provider identity sha256")
        _plain_digest(self.config_sha256, "V2 expected config sha256")
        _plain_digest(self.launch_envelope_sha256, "V2 expected launch envelope sha256")
        _plain_digest(self.runtime_closure_sha256, "V2 expected runtime closure sha256")
        if type(self.runtime_materialization) is not RuntimeMaterializationBindingV2:
            raise GuestAdmissionError("V2 runtime materialization binding is invalid")
        if _plain_digest(self.image_closure_sha256, "V2 image closure sha256") != _image_closure_sha256_v2(self):
            raise GuestAdmissionError("V2 image closure digest is invalid")
        if _plain_digest(self.backend_admission_sha256, "V2 backend admission sha256") != _backend_admission_sha256_v2(self):
            raise GuestAdmissionError("V2 backend admission digest is invalid")
        attempt = _attempt(self.provider_attempt_id, "V2 expected provider attempt ID")
        if (
            type(self.helpers) is not tuple or not self.helpers
            or len(self.helpers) > MAX_HELPERS
            or any(type(row) is not HelperBinding for row in self.helpers)
        ):
            raise GuestAdmissionError("V2 expected helper roster is invalid")
        _validate_unique_paths(tuple(row.path for row in self.helpers), "V2 helper roster")
        if (
            type(self.mounts) is not tuple
            or any(type(row) is not SupervisorMountBindingV2 for row in self.mounts)
        ):
            raise GuestAdmissionError("V2 expected mount roster is invalid")
        if type(self.target_lower) is not HostOverlayLowerBindingV2:
            raise GuestAdmissionError("V2 expected target-lower binding is invalid")
        lower_digest = _plain_digest(
            self.lower_binding_sha256, "V2 lower binding sha256"
        )
        _plain_digest(self.precreate_layout_sha256, "V2 pre-create layout sha256")
        _plain_digest(self.postcreate_layout_sha256, "V2 post-create layout sha256")
        if type(self.cgroup) is not CgroupAuthority or self.cgroup.provider_attempt_id != attempt:
            raise GuestAdmissionError("V2 expected cgroup authority is not attempt-bound")
        if type(self.landlock) is not LandlockAuthority:
            raise GuestAdmissionError("V2 expected Landlock authority is invalid")
        if type(self.execution) is not ExecutionAuthorityV2:
            raise GuestAdmissionError("V2 expected process/network authority is invalid")
        home = _canonical_posix_path(self.host_home, "V2 host home")
        if home == "/":
            raise GuestAdmissionError("V2 host home cannot be the filesystem root")
        _validate_mount_roster_v2(
            self.mounts, self.target_lower, home, lower_digest,
        )
        _validate_helpers_v2(self.helpers, self.mounts)
        if self.landlock.allowed_write_paths != tuple(
            row.destination for row in self.mounts if row.mode == "rw"
        ):
            raise GuestAdmissionError(
                "V2 Landlock write paths differ from the writable mount roster"
            )


class PersistentReplayConsumer(Protocol):
    """Crash-safe atomic insert-if-absent store; True means first durable use."""
    def consume(self, provider_attempt_id: str, receipt_sha256: str) -> bool: ...


class DurableLaunchSupervisor(Protocol):
    """Crash-safe attempt journal armed before any provider mutation.

    ``arm`` performs an authenticated atomic ABSENT->ARMED transition binding
    the exact cgroup and admission digest. ``mark_running`` is an ARMED->RUNNING
    compare-and-swap; ``mark_terminal`` is an ARMED/RUNNING->TERMINAL
    compare-and-swap binding terminal evidence. Conflicts return False. A
    supervisor must recover and kill/observe every ARMED or RUNNING attempt
    after host-process death. Each method returns exactly True only after its
    state transition is durable. The Python protocol does not itself provide
    authentication or persistence; production injects that external service.
    """
    def arm(self, cgroup: CgroupAuthority, admission_receipt_sha256: str) -> bool: ...
    def mark_running(self, cgroup: CgroupAuthority) -> bool: ...
    def mark_terminal(self, cgroup: CgroupAuthority, terminal_receipt_sha256: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class TestOnlyV2StoppedGuestObservation:
    """Non-authorizing structured observation for unit control-flow tests."""

    phase: str
    provider_attempt_id: str
    provider_kind: str
    provider_identity_sha256: str
    image_reference: str
    image_index_digest: str
    image_manifest_digest: str
    image_config_digest: str
    apple_container_configuration_sha256: str
    image_closure_sha256: str
    backend_admission_sha256: str
    platform_os: str
    platform_architecture: str
    network_mode: str
    network_policy_sha256: str
    lifecycle_state: str
    workload_process_count: int
    precreate_layout_sha256: str
    postcreate_layout_sha256: str
    mounts: tuple[SupervisorMountBindingV2, ...]
    target_lower: HostOverlayLowerBindingV2
    lower_binding_sha256: str

    def __post_init__(self) -> None:
        if self.phase not in {"PRE_ADMISSION", "POST_ADMISSION", "PRE_START"}:
            raise GuestAdmissionError("V2 native observation phase is invalid")
        _attempt(self.provider_attempt_id, "V2 native observation attempt ID")
        if self.provider_kind not in {"APPLE_CONTAINER", "PODMAN_ROOTLESS"}:
            raise GuestAdmissionError("V2 native observation provider is unsupported")
        _plain_digest(self.provider_identity_sha256, "V2 native provider identity sha256")
        if type(self.image_reference) is not str or _OCI_REFERENCE.fullmatch(self.image_reference) is None:
            raise GuestAdmissionError("V2 native image reference is malformed")
        index = _image_digest(self.image_index_digest, "V2 native image index digest")
        if self.image_reference.rsplit("@", 1)[1] != index:
            raise GuestAdmissionError("V2 native image reference does not bind its index")
        _image_digest(self.image_manifest_digest, "V2 native image manifest digest")
        _image_digest(self.image_config_digest, "V2 native image config digest")
        _plain_digest(self.apple_container_configuration_sha256, "V2 native Apple Container configuration sha256")
        _plain_digest(self.image_closure_sha256, "V2 native image closure sha256")
        _plain_digest(self.backend_admission_sha256, "V2 native backend admission sha256")
        if self.platform_os != "linux" or self.platform_architecture not in {"arm64", "amd64"}:
            raise GuestAdmissionError("V2 native observed platform is unsupported")
        if self.network_mode != "NARROW_TRUSTED_PROXY_ONLY":
            raise GuestAdmissionError("V2 native observed network mode is invalid")
        _plain_digest(self.network_policy_sha256, "V2 native network policy sha256")
        if self.lifecycle_state != "CREATED_STOPPED":
            raise GuestAdmissionError("V2 guest was not observed created and stopped")
        if (
            type(self.workload_process_count) is not int
            or isinstance(self.workload_process_count, bool)
            or not 0 <= self.workload_process_count <= 2**31 - 1
        ):
            raise GuestAdmissionError("V2 guest workload-process observation is invalid")
        _plain_digest(self.precreate_layout_sha256, "V2 native pre-create layout sha256")
        _plain_digest(self.postcreate_layout_sha256, "V2 native post-create layout sha256")
        if (
            type(self.mounts) is not tuple
            or len(self.mounts) != len(_MOUNT_POLICY_V2)
            or any(type(row) is not SupervisorMountBindingV2 for row in self.mounts)
            or tuple((row.purpose, row.destination, row.mode) for row in self.mounts)
            != _MOUNT_POLICY_V2
        ):
            raise GuestAdmissionError("V2 native observed mount roster is invalid")
        if type(self.target_lower) is not HostOverlayLowerBindingV2:
            raise GuestAdmissionError("V2 native target-lower observation is invalid")
        digest = _plain_digest(self.lower_binding_sha256, "V2 native lower binding sha256")
        if digest != _lower_binding_sha256_v2(self.target_lower, self.mounts[0]):
            raise GuestAdmissionError("V2 native lower binding proof is invalid")
        provider_mounts = tuple(
            row.provider_mount_identity_sha256 for row in self.mounts
        ) + (self.target_lower.provider_mount_identity_sha256,)
        if len(set(provider_mounts)) != len(provider_mounts):
            raise GuestAdmissionError("V2 native provider mount identities overlap")
        descriptors = tuple(
            _source_descriptor_identity(row.source_identity) for row in self.mounts
        ) + (_source_descriptor_identity(self.target_lower.source_identity),)
        if len(set(descriptors)) != len(descriptors):
            raise GuestAdmissionError("V2 native source descriptors overlap")


class TestOnlyStoppedGuestProviderV2(Protocol):
    """Fake-only service which models one already-created, stopped guest."""

    def observe_stopped_guest(
        self, provider_attempt_id: str, phase: str,
    ) -> TestOnlyV2StoppedGuestObservation: ...


class TestOnlyStoppedGuestAdmissionAuthorityV2:
    """Explicitly non-production authority for unit control-flow tests."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("TEST_ONLY V2 authority is issued by the fake-only binder")

    def __bool__(self) -> bool:
        raise TypeError("V2 stopped-guest authority is not a truthy flag")

    def __copy__(self) -> "TestOnlyStoppedGuestAdmissionAuthorityV2":
        raise TypeError("V2 stopped-guest authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> "TestOnlyStoppedGuestAdmissionAuthorityV2":
        raise TypeError("V2 stopped-guest authority cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("V2 stopped-guest authority cannot be serialized")


class TestOnlyV2ProviderCleanupRequired(GuestAdmissionError):
    """Typed TEST_ONLY signal requiring provider-specific guest extinction.

    This is a status, not proof that cleanup occurred and not termination
    authority.  The enclosing supervisor must kill, verify extinction, export
    any authorized artifacts, and delete the provider guest before proceeding.
    """

    __slots__ = ("provider_attempt_id", "phase")

    def __init__(self, provider_attempt_id: str, phase: str) -> None:
        self.provider_attempt_id = _attempt(
            provider_attempt_id, "V2 cleanup provider attempt ID",
        )
        if phase not in {"PRE_ADMISSION", "POST_ADMISSION", "PRE_START", "START"}:
            raise GuestAdmissionError("V2 cleanup phase is invalid")
        self.phase = phase
        super().__init__(
            f"V2 provider cleanup is required after {phase} for attempt "
            f"{self.provider_attempt_id}"
        )


@dataclass(frozen=True, slots=True)
class RevalidatedMount:
    source_root_identity: SourceIdentity
    source_identity: SourceIdentity


@dataclass(frozen=True, slots=True)
class PinnedSourceReference:
    """Opaque provider handle plus the retained parent/name/tree identity."""
    handle: str
    parent_device: int
    parent_inode: int
    entry_name: str
    identity: SourceIdentity

    def __post_init__(self) -> None:
        if type(self.handle) is not str or re.fullmatch(r"pin:[0-9a-f]{64}", self.handle) is None:
            raise GuestAdmissionError("provider source pin handle is invalid")
        _domain_int(self.parent_device, "source parent device")
        _domain_int(self.parent_inode, "source parent inode", positive=True)
        if type(self.entry_name) is not str or not self.entry_name or "/" in self.entry_name or self.entry_name in {".", ".."}:
            raise GuestAdmissionError("source retained entry name is invalid")
        try:
            entry_bytes = self.entry_name.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise GuestAdmissionError("source retained entry name is not valid UTF-8") from None
        if len(entry_bytes) > 255:
            raise GuestAdmissionError("source retained entry name exceeds its bound")
        if type(self.identity) is not SourceIdentity:
            raise GuestAdmissionError("pinned source identity is invalid")


@dataclass(frozen=True, slots=True)
class PinnedProviderMount:
    purpose: str
    destination: str
    mode: str
    source_root: PinnedSourceReference
    source: PinnedSourceReference

    def __post_init__(self) -> None:
        if (self.purpose, self.destination, self.mode) not in _MOUNT_POLICY:
            raise GuestAdmissionError("pinned provider mount violates the closed policy")
        if type(self.source_root) is not PinnedSourceReference or type(self.source) is not PinnedSourceReference:
            raise GuestAdmissionError("pinned provider mount references are invalid")


@dataclass(frozen=True, slots=True)
class CreatedMountReceipt:
    purpose: str
    destination: str
    mode: str
    source_root_identity: SourceIdentity
    source_identity: SourceIdentity

    def __post_init__(self) -> None:
        if (self.purpose, self.destination, self.mode) not in _MOUNT_POLICY:
            raise GuestAdmissionError("created mount receipt violates the closed policy")
        if type(self.source_root_identity) is not SourceIdentity or type(self.source_identity) is not SourceIdentity:
            raise GuestAdmissionError("created mount receipt identity is invalid")


@dataclass(frozen=True, slots=True)
class ProviderCreateReceipt:
    provider_attempt_id: str
    mounts: tuple[CreatedMountReceipt, ...]

    def __post_init__(self) -> None:
        _attempt(self.provider_attempt_id, "provider create receipt attempt ID")
        if type(self.mounts) is not tuple or len(self.mounts) != len(_MOUNT_POLICY) or any(type(row) is not CreatedMountReceipt for row in self.mounts):
            raise GuestAdmissionError("provider create receipt mount roster is invalid")
        if tuple((row.purpose, row.destination, row.mode) for row in self.mounts) != _MOUNT_POLICY:
            raise GuestAdmissionError("provider create receipt mount roster violates the closed policy")


_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class ProviderCreateResult(Generic[_T]):
    value: _T
    receipt: ProviderCreateReceipt


@dataclass(frozen=True, slots=True)
class NativeMountProof:
    """Authenticated native/provider result, never a self-authenticating bool.

    Production accepts this value only through its configured pinning authority
    and must obtain all fields from one native descriptor-bound observation.
    Direct construction exists so fake-only unit tests can model that boundary.
    """
    descriptor_device: int
    descriptor_inode: int
    native_mount_id: int
    native_mount_id_kind: str
    mount_topology_sha256: str
    authenticated: bool
    submounts_absent: bool

    def __post_init__(self) -> None:
        _domain_int(self.descriptor_device, "native-proof descriptor device")
        _domain_int(self.descriptor_inode, "native-proof descriptor inode", positive=True)
        _domain_int(self.native_mount_id, "native mount ID", positive=True)
        if self.native_mount_id_kind not in {
            "STATX_MNT_ID_UNIQUE", "PROVIDER_AUTHENTICATED_MOUNT_ID"
        }:
            raise GuestAdmissionError("native mount-ID proof kind is unsupported")
        _plain_digest(self.mount_topology_sha256, "mount topology sha256")
        if self.authenticated is not True or self.submounts_absent is not True:
            raise GuestAdmissionError("authenticated native no-submount proof is required")


class ProviderMountPinningAuthority(Protocol):
    """Provider-specific, unsupported-by-default descriptor mount authority.

    Returning support requires all of: mounting from the opaque retained handle
    without reopening a caller pathname, keeping the namespace/content pinned
    for the context lifetime, and exhaustive xattr/compression inspection for
    every descriptor passed to ``source_metadata_is_safe``.  The native mount
    proof must be produced by an authenticated native helper/provider, bind the
    same descriptor device/inode, and exhaustively prove that no descendant is
    a separate mount (including same-device bind/nested mounts).  A caller-made
    Python object or boolean is not authentication.
    """
    def supports_descriptor_mounts(self) -> bool: ...
    def source_metadata_is_safe(self, fd: int, status: os.stat_result) -> bool: ...
    def native_mount_proof(self, directory_fd: int) -> NativeMountProof: ...
    def acquire_pin(
        self, *, provider_attempt_id: str, parent_fd: int, entry_name: str,
        directory_fd: int,
    ) -> ContextManager[str]: ...


class SourceRevalidator(Protocol):
    def create_with_leases(
        self, provider_attempt_id: str, mounts: tuple[MountBinding, ...],
        launch_view: "GuestLaunchAdmission",
        launcher: Callable[["GuestLaunchAdmission", tuple[PinnedProviderMount, ...]], ProviderCreateResult[_T]],
    ) -> _T: ...


def _open_parent_and_directory_nofollow(path: str) -> tuple[int, str, int]:
    """Retain the final parent and child FDs after a componentwise nofollow walk."""
    canonical = _canonical_posix_path(path, "source path")
    if canonical == "/":
        raise GuestAdmissionError("source root cannot be the filesystem root")
    if any(not hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")):
        raise GuestAdmissionError("platform lacks descriptor no-follow directory support")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = -1
    try:
        current = os.open("/", flags)
        components = canonical.split("/")[1:]
        for component in components[:-1]:
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        child = os.open(components[-1], flags, dir_fd=current)
        return current, components[-1], child
    except (OSError, ValueError):
        if current >= 0:
            os.close(current)
        raise GuestAdmissionError("source path failed componentwise no-follow open") from None


def _assert_retained_entry(parent_fd: int, entry_name: str, directory_fd: int) -> None:
    try:
        named = os.stat(entry_name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise GuestAdmissionError("provider-visible retained source name changed") from None
    held = _fstat(directory_fd)
    if not stat.S_ISDIR(named.st_mode) or _stat_fingerprint(named) != _stat_fingerprint(held):
        raise GuestAdmissionError("provider-visible retained source name changed")


def _assert_metadata_safe(
    authority: ProviderMountPinningAuthority, fd: int, status: os.stat_result
) -> None:
    failed = False
    try:
        safe = authority.source_metadata_is_safe(fd, status)
    except BaseException:
        failed = True
        safe = False
    if failed:
        # Raise after leaving the handler: injected diagnostics must not remain
        # reachable through __context__ even when the authority includes host
        # paths, provider argv, proxy data, or credentials in its exception.
        raise GuestAdmissionError("source metadata proof failed")
    if safe is not True:
        raise GuestAdmissionError("source tree contains xattrs or compressed objects")


def _native_mount_proof(
    authority: ProviderMountPinningAuthority, fd: int, status: os.stat_result
) -> NativeMountProof:
    failed = False
    try:
        proof = authority.native_mount_proof(fd)
    except BaseException:
        failed = True
        proof = None
    if failed or type(proof) is not NativeMountProof:
        raise GuestAdmissionError("authenticated native mount-ID/no-submount proof is unavailable")
    if (
        proof.descriptor_device != status.st_dev
        or proof.descriptor_inode != status.st_ino
    ):
        raise GuestAdmissionError("native mount proof names a different source descriptor")
    return proof


def _stat_fingerprint(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev, status.st_ino, status.st_mode, status.st_uid, status.st_gid,
        status.st_nlink, status.st_size, status.st_mtime_ns, status.st_ctime_ns,
    )


def _fstat(fd: int) -> os.stat_result:
    try:
        return os.fstat(fd)
    except OSError:
        raise GuestAdmissionError("source descriptor identity is unavailable") from None


def _hash_field(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _scan_tree(
    fd: int, *, root_device: int, depth: int, budget: dict[str, int],
    metadata_authority: ProviderMountPinningAuthority,
) -> bytes:
    if depth > MAX_TREE_DEPTH:
        raise GuestAdmissionError("source tree exceeds its depth bound")
    before = _fstat(fd)
    if not stat.S_ISDIR(before.st_mode) or before.st_dev != root_device:
        raise GuestAdmissionError("source tree crosses an unsupported filesystem boundary")
    _assert_metadata_safe(metadata_authority, fd, before)
    try:
        names = os.listdir(fd)
    except OSError:
        raise GuestAdmissionError("source directory census failed") from None
    encoded_names: list[tuple[bytes, str]] = []
    normalized_names: set[str] = set()
    for name in names:
        if type(name) is not str or not name or name in {".", ".."} or "/" in name:
            raise GuestAdmissionError("source tree contains an invalid entry name")
        if name != unicodedata.normalize("NFC", name) or "\\" in name or any(ord(character) < 32 for character in name):
            raise GuestAdmissionError("source tree contains a noncanonical entry name")
        normalized = unicodedata.normalize("NFKC", name).casefold()
        if normalized in normalized_names:
            raise GuestAdmissionError("source tree contains a case/Unicode entry alias")
        normalized_names.add(normalized)
        try:
            encoded = name.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise GuestAdmissionError("source tree entry name is not valid UTF-8") from None
        if len(encoded) > 255:
            raise GuestAdmissionError("source tree entry name exceeds its bound")
        encoded_names.append((encoded, name))
    encoded_names.sort(key=lambda row: row[0])
    tree = hashlib.sha256()
    _hash_field(tree, b"directory")
    for encoded, name in encoded_names:
        budget["entries"] += 1
        if budget["entries"] > MAX_TREE_ENTRIES:
            raise GuestAdmissionError("source tree exceeds its entry bound")
        try:
            listed = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError:
            raise GuestAdmissionError("source tree entry census failed") from None
        if stat.S_ISLNK(listed.st_mode):
            raise GuestAdmissionError("source tree contains a symlink")
        if listed.st_dev != root_device:
            raise GuestAdmissionError("source tree crosses an unsupported filesystem boundary")
        if stat.S_ISDIR(listed.st_mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                child_fd = os.open(name, flags, dir_fd=fd)
            except OSError:
                raise GuestAdmissionError("source directory changed during census") from None
            try:
                opened = _fstat(child_fd)
                if _stat_fingerprint(opened) != _stat_fingerprint(listed):
                    raise GuestAdmissionError("source directory changed during census")
                budget["directories"] += 1
                budget["max_depth"] = max(budget["max_depth"], depth + 1)
                child_digest = _scan_tree(
                    child_fd, root_device=root_device, depth=depth + 1, budget=budget,
                    metadata_authority=metadata_authority,
                )
            finally:
                os.close(child_fd)
            _hash_field(tree, b"d")
            _hash_field(tree, encoded)
            _hash_field(tree, str(stat.S_IMODE(opened.st_mode)).encode("ascii"))
            _hash_field(tree, str(opened.st_uid).encode("ascii"))
            _hash_field(tree, str(opened.st_gid).encode("ascii"))
            _hash_field(tree, child_digest)
        elif stat.S_ISREG(listed.st_mode):
            if listed.st_nlink != 1:
                raise GuestAdmissionError("source regular file has multiple hard links")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                child_fd = os.open(name, flags, dir_fd=fd)
            except OSError:
                raise GuestAdmissionError("source regular file changed during census") from None
            try:
                opened = _fstat(child_fd)
                if _stat_fingerprint(opened) != _stat_fingerprint(listed):
                    raise GuestAdmissionError("source regular file metadata is unsafe or changed")
                _assert_metadata_safe(metadata_authority, child_fd, opened)
                budget["files"] += 1
                budget["bytes"] += opened.st_size
                if budget["bytes"] > MAX_TREE_BYTES:
                    raise GuestAdmissionError("source tree exceeds its byte bound")
                content = hashlib.sha256()
                remaining = opened.st_size
                try:
                    while remaining:
                        block = os.read(child_fd, min(1024 * 1024, remaining))
                        if not block:
                            raise GuestAdmissionError("source regular file was truncated during census")
                        content.update(block)
                        remaining -= len(block)
                    if os.read(child_fd, 1):
                        raise GuestAdmissionError("source regular file grew during census")
                except OSError:
                    raise GuestAdmissionError("source regular file read failed") from None
                after = _fstat(child_fd)
                if _stat_fingerprint(after) != _stat_fingerprint(opened):
                    raise GuestAdmissionError("source regular file changed during census")
                _assert_metadata_safe(metadata_authority, child_fd, after)
            finally:
                os.close(child_fd)
            _hash_field(tree, b"f")
            _hash_field(tree, encoded)
            _hash_field(tree, str(stat.S_IMODE(opened.st_mode)).encode("ascii"))
            _hash_field(tree, str(opened.st_uid).encode("ascii"))
            _hash_field(tree, str(opened.st_gid).encode("ascii"))
            _hash_field(tree, str(opened.st_size).encode("ascii"))
            _hash_field(tree, content.digest())
        else:
            raise GuestAdmissionError("source tree contains a special file")
    after = _fstat(fd)
    if _stat_fingerprint(after) != _stat_fingerprint(before):
        raise GuestAdmissionError("source directory changed during census")
    _assert_metadata_safe(metadata_authority, fd, after)
    return tree.digest()


def _snapshot_identity(fd: int, metadata_authority: ProviderMountPinningAuthority) -> SourceIdentity:
    try:
        root = _fstat(fd)
    except GuestAdmissionError:
        raise
    if not stat.S_ISDIR(root.st_mode):
        raise GuestAdmissionError("mount source descriptor is not a directory")
    budget = {"entries": 0, "files": 0, "directories": 1, "bytes": 0, "max_depth": 0}
    mount_proof = _native_mount_proof(metadata_authority, fd, root)
    digest = _scan_tree(
        fd, root_device=root.st_dev, depth=0, budget=budget,
        metadata_authority=metadata_authority,
    ).hex()
    return SourceIdentity(
        device=root.st_dev, inode=root.st_ino, uid=root.st_uid, gid=root.st_gid,
        mode=stat.S_IMODE(root.st_mode),
        object_kind="directory", snapshot_format=SOURCE_SNAPSHOT_FORMAT, snapshot_sha256=digest,
        regular_file_count=budget["files"], directory_count=budget["directories"],
        total_bytes=budget["bytes"], max_depth=budget["max_depth"],
        native_mount_id=mount_proof.native_mount_id,
        native_mount_id_kind=mount_proof.native_mount_id_kind,
        mount_topology_sha256=mount_proof.mount_topology_sha256,
        mount_proof_authenticated=mount_proof.authenticated,
        submounts_absent=mount_proof.submounts_absent,
        symlink_entries_absent=True, special_files_absent=True, hardlinks_absent=True,
        xattrs_absent=True, compressed_files_absent=True,
    )


def snapshot_source_identity(
    path: str, *, metadata_authority: ProviderMountPinningAuthority
) -> SourceIdentity:
    """Trusted expectation helper using the exact descriptor-relative census."""
    parent_fd, _name, source_fd = _open_parent_and_directory_nofollow(path)
    try:
        return _snapshot_identity(source_fd, metadata_authority)
    finally:
        os.close(source_fd)
        os.close(parent_fd)


class DescriptorSnapshotSourceRevalidator:
    """Perform provider create using only provider-pinned descriptor handles.

    This class is an exception-sanitizing trust boundary.  Its injected pinning
    authority and launcher may contain sensitive provider diagnostics, so no
    exception originating below this boundary is exposed to the caller.
    """
    __slots__ = ("_pinning_authority", "__weakref__")

    def __init__(self, pinning_authority: ProviderMountPinningAuthority) -> None:
        if pinning_authority is None or not all(
            _has_callable(pinning_authority, name)
            for name in ("acquire_pin", "supports_descriptor_mounts", "source_metadata_is_safe", "native_mount_proof")
        ):
            raise GuestAdmissionError("a provider descriptor-pinning authority is required")
        self._pinning_authority = pinning_authority
        with _SOURCE_REVALIDATOR_LOCK:
            _SOURCE_REVALIDATOR_REGISTRY.add(self)

    def create_with_leases(
        self, provider_attempt_id: str, mounts: tuple[MountBinding, ...],
        launch_view: "GuestLaunchAdmission",
        launcher: Callable[["GuestLaunchAdmission", tuple[PinnedProviderMount, ...]], ProviderCreateResult[_T]],
    ) -> _T:
        failed = False
        try:
            result = self._create_with_leases(
                provider_attempt_id, mounts, launch_view, launcher
            )
        except BaseException:
            failed = True
            result = None
        if failed:
            # Deliberately raised outside the handler so both __cause__ and
            # __context__ are empty, not merely hidden from traceback display.
            raise GuestAdmissionError("provider source validation/create failed")
        return result  # type: ignore[return-value]

    def _create_with_leases(
        self, provider_attempt_id: str, mounts: tuple[MountBinding, ...],
        launch_view: "GuestLaunchAdmission",
        launcher: Callable[["GuestLaunchAdmission", tuple[PinnedProviderMount, ...]], ProviderCreateResult[_T]],
    ) -> _T:
        _attempt(provider_attempt_id, "source-revalidation attempt ID")
        if type(mounts) is not tuple or any(type(row) is not MountBinding for row in mounts):
            raise GuestAdmissionError("source revalidation mount roster is invalid")
        try:
            supported = self._pinning_authority.supports_descriptor_mounts()
        except Exception:
            raise GuestAdmissionError("provider descriptor pinning support probe failed") from None
        if supported is not True:
            raise GuestAdmissionError("provider cannot consume retained descriptor mounts")
        with ExitStack() as stack:
            pinned: list[PinnedProviderMount] = []
            created_expected: list[CreatedMountReceipt] = []
            retained: list[tuple[int, str, int, int, str, int, MountBinding]] = []
            for mount in mounts:
                root_parent, root_name, root_fd = _open_parent_and_directory_nofollow(mount.source_root)
                stack.callback(os.close, root_parent)
                stack.callback(os.close, root_fd)
                source_parent, source_name, source_fd = _open_parent_and_directory_nofollow(mount.source)
                stack.callback(os.close, source_parent)
                stack.callback(os.close, source_fd)
                try:
                    root_handle = stack.enter_context(self._pinning_authority.acquire_pin(
                        provider_attempt_id=provider_attempt_id, parent_fd=root_parent,
                        entry_name=root_name, directory_fd=root_fd,
                    ))
                    source_handle = stack.enter_context(self._pinning_authority.acquire_pin(
                        provider_attempt_id=provider_attempt_id, parent_fd=source_parent,
                        entry_name=source_name, directory_fd=source_fd,
                    ))
                except GuestAdmissionError:
                    raise
                except Exception:
                    raise GuestAdmissionError("provider source pin acquisition failed") from None
                root_identity = _snapshot_identity(root_fd, self._pinning_authority)
                source_identity = _snapshot_identity(source_fd, self._pinning_authority)
                _assert_retained_entry(root_parent, root_name, root_fd)
                _assert_retained_entry(source_parent, source_name, source_fd)
                if root_identity != mount.source_root_identity or source_identity != mount.source_identity:
                    raise GuestAdmissionError("mount source identity changed before provider create")
                root_parent_stat = _fstat(root_parent)
                source_parent_stat = _fstat(source_parent)
                root_ref = PinnedSourceReference(root_handle, root_parent_stat.st_dev, root_parent_stat.st_ino, root_name, root_identity)
                source_ref = PinnedSourceReference(source_handle, source_parent_stat.st_dev, source_parent_stat.st_ino, source_name, source_identity)
                pinned.append(PinnedProviderMount(mount.purpose, mount.destination, mount.mode, root_ref, source_ref))
                created_expected.append(CreatedMountReceipt(mount.purpose, mount.destination, mount.mode, root_identity, source_identity))
                retained.append((root_parent, root_name, root_fd, source_parent, source_name, source_fd, mount))
            handles = tuple(
                handle
                for mount in pinned
                for handle in (mount.source_root.handle, mount.source.handle)
            )
            if len(set(handles)) != len(handles):
                raise GuestAdmissionError("provider source pin handles are not unique")
            try:
                outcome = launcher(launch_view, tuple(pinned))
            except Exception:
                raise
            if type(outcome) is not ProviderCreateResult or type(outcome.receipt) is not ProviderCreateReceipt:
                raise GuestAdmissionError("provider create did not return a typed mount receipt")
            if outcome.receipt.provider_attempt_id != provider_attempt_id or outcome.receipt.mounts != tuple(created_expected):
                raise GuestAdmissionError("created mounts differ from the held source leases")
            # Re-census while pins are still held.  The pin authority must make
            # this stable; any change fails even after provider create.
            for root_parent, root_name, root_fd, source_parent, source_name, source_fd, mount in retained:
                _assert_retained_entry(root_parent, root_name, root_fd)
                _assert_retained_entry(source_parent, source_name, source_fd)
                if _snapshot_identity(root_fd, self._pinning_authority) != mount.source_root_identity or _snapshot_identity(source_fd, self._pinning_authority) != mount.source_identity:
                    raise GuestAdmissionError("held source identity changed during provider create")
            return outcome.value


class GuestLaunchAdmission:
    """Registry-backed view valid only while a synchronous launcher runs."""
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> "GuestLaunchAdmission":
        raise TypeError("guest launch admission is supplied only to the launcher callback")

    def _read(self, name: str) -> Any:
        if type(self) is not GuestLaunchAdmission:
            raise GuestAdmissionError("guest launch admission is no longer active")
        with _ISSUER_LOCK:
            fields = _LAUNCH_REGISTRY.get(self)
            if fields is None:
                raise GuestAdmissionError("guest launch admission is no longer active")
            return fields[name]

    schema = property(lambda self: self._read("schema"))
    receipt_sha256 = property(lambda self: self._read("receipt_sha256"))
    image_manifest_digest = property(lambda self: self._read("image_manifest_digest"))
    config_sha256 = property(lambda self: self._read("config_sha256"))
    launch_envelope_sha256 = property(lambda self: self._read("launch_envelope_sha256"))
    runtime_closure_sha256 = property(lambda self: self._read("runtime_closure_sha256"))
    provider_attempt_id = property(lambda self: self._read("provider_attempt_id"))
    helpers = property(lambda self: self._read("helpers"))
    cgroup = property(lambda self: self._read("cgroup"))
    landlock = property(lambda self: self._read("landlock"))
    execution = property(lambda self: self._read("execution"))

    def __bool__(self) -> bool:
        raise TypeError("guest launch admission is not a truthy flag")

    def __copy__(self) -> "GuestLaunchAdmission":
        raise TypeError("guest launch admission cannot be copied")

    def __deepcopy__(self, _memo: object) -> "GuestLaunchAdmission":
        raise TypeError("guest launch admission cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("guest launch admission cannot be serialized")


def _same_text(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


@dataclass(slots=True)
class _AdmissionState:
    expectation: GuestAdmissionExpectation
    receipt_sha256: str
    termination_observer: "CgroupTerminationObserver"
    supervisor: DurableLaunchSupervisor
    consumed: bool
    lock: threading.Lock


@dataclass(slots=True)
class _AdmissionStateV2:
    expectation: GuestAdmissionExpectationV2
    receipt_sha256: str
    admission_sha256: str
    stopped_authority: TestOnlyStoppedGuestAdmissionAuthorityV2
    consumed: bool
    lock: threading.Lock


class CgroupTerminationCapability:
    """Registry-backed, one-shot authority issued only after provider create."""
    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("cgroup termination capabilities are issued after guest launch")

    def __copy__(self) -> "CgroupTerminationCapability":
        raise TypeError("cgroup termination capabilities cannot be copied")

    def __deepcopy__(self, _memo: object) -> "CgroupTerminationCapability":
        raise TypeError("cgroup termination capabilities cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("cgroup termination capabilities cannot be serialized")

    def __bool__(self) -> bool:
        raise TypeError("cgroup termination capability must be consumed")

    def terminate(self) -> "CgroupTerminalEvidence":
        if type(self) is not CgroupTerminationCapability:
            raise GuestAdmissionError("issued cgroup termination capability is required")
        with _ISSUER_LOCK:
            state = _TERMINATION_REGISTRY.get(self)
            if state is None:
                raise GuestAdmissionError("issued cgroup termination capability is required")
            cgroup, observer, supervisor, consumed = state
            if consumed:
                raise GuestAdmissionError("cgroup termination capability was already consumed")
            # Kill/write/read may become ambiguous, so burn before the call.
            _TERMINATION_REGISTRY[self] = (cgroup, observer, supervisor, True)
        observer_failed = False
        try:
            observation = observer.kill_then_observe(cgroup)
        except BaseException:
            observer_failed = True
            observation = None
        if observer_failed:
            raise GuestAdmissionError("cgroup kill/observation failed ambiguously")
        evidence = _terminal_evidence_from_observation(cgroup, observation)
        supervisor_failed = False
        try:
            recorded = supervisor.mark_terminal(cgroup, evidence.receipt_sha256)
        except BaseException:
            supervisor_failed = True
            recorded = False
        if supervisor_failed or recorded is not True:
            raise GuestAdmissionError("durable terminal-state recording failed")
        return evidence


@dataclass(frozen=True, slots=True)
class LaunchedGuest(Generic[_T]):
    value: _T
    termination: CgroupTerminationCapability


_ISSUER_LOCK = threading.RLock()
_SOURCE_REVALIDATOR_LOCK = threading.RLock()
_SOURCE_REVALIDATOR_REGISTRY: weakref.WeakSet[
    DescriptorSnapshotSourceRevalidator
] = weakref.WeakSet()
_ADMISSION_REGISTRY: weakref.WeakKeyDictionary[OciGuestAdmission, _AdmissionState]
_TEST_ONLY_ADMISSION_REGISTRY_V2: weakref.WeakKeyDictionary[
    "TestOnlySupervisorGuestAdmissionV2", _AdmissionStateV2
]
_TEST_ONLY_STOPPED_AUTHORITY_REGISTRY_V2: weakref.WeakKeyDictionary[
    TestOnlyStoppedGuestAdmissionAuthorityV2, TestOnlyStoppedGuestProviderV2
] = weakref.WeakKeyDictionary()
_LAUNCH_REGISTRY: weakref.WeakKeyDictionary[GuestLaunchAdmission, Mapping[str, Any]] = weakref.WeakKeyDictionary()
_TERMINATION_REGISTRY: weakref.WeakKeyDictionary[
    CgroupTerminationCapability,
    tuple[CgroupAuthority, "CgroupTerminationObserver", DurableLaunchSupervisor, bool],
] = weakref.WeakKeyDictionary()


def _cleanup_failed_create(state: _AdmissionState) -> bool:
    """Kill/reap an armed attempt and durably close its supervisor record."""
    observer_failed = False
    try:
        observation = state.termination_observer.kill_then_observe(state.expectation.cgroup)
    except BaseException:
        observer_failed = True
        observation = None
    if observer_failed:
        return False
    try:
        evidence = _terminal_evidence_from_observation(state.expectation.cgroup, observation)
    except BaseException:
        return False
    supervisor_failed = False
    try:
        recorded = state.supervisor.mark_terminal(
            state.expectation.cgroup, evidence.receipt_sha256
        )
    except BaseException:
        supervisor_failed = True
        recorded = False
    return not supervisor_failed and recorded is True


def bind_native_stopped_guest_authority_v2(
    _provider: object,
) -> None:
    """Production hard-stop until the native/out-of-process verifier lands.

    Import names, ``__module__`` strings, Python registries and sentinels are
    introspectable and mutable, so none of them may mint production admission.
    The integration must replace this hard-stop with a receipt/capability whose
    authenticity is established outside this interpreter.
    """
    raise GuestAdmissionError(
        "authenticated native/out-of-process V2 admission integration is unavailable"
    )


def _bind_stopped_guest_authority_v2_for_testing(
    provider: TestOnlyStoppedGuestProviderV2,
) -> TestOnlyStoppedGuestAdmissionAuthorityV2:
    """Fake-only unit-test seam; production callers must use the native binder."""
    if not _has_callable(provider, "observe_stopped_guest"):
        raise GuestAdmissionError("fake V2 observation provider is invalid")
    authority = object.__new__(TestOnlyStoppedGuestAdmissionAuthorityV2)
    with _ISSUER_LOCK:
        _TEST_ONLY_STOPPED_AUTHORITY_REGISTRY_V2[authority] = provider
    return authority


def _read_stopped_guest_v2(
    authority: TestOnlyStoppedGuestAdmissionAuthorityV2,
    expectation: GuestAdmissionExpectationV2,
    phase: str,
) -> TestOnlyV2StoppedGuestObservation:
    """Obtain one typed fake-provider observation without accepting it yet."""
    if type(authority) is not TestOnlyStoppedGuestAdmissionAuthorityV2:
        raise GuestAdmissionError("issued TEST_ONLY V2 stopped-guest authority is required")
    with _ISSUER_LOCK:
        provider = _TEST_ONLY_STOPPED_AUTHORITY_REGISTRY_V2.get(authority)
    if provider is None:
        raise GuestAdmissionError("issued TEST_ONLY V2 stopped-guest authority is required")
    try:
        observed = provider.observe_stopped_guest(
            expectation.provider_attempt_id, phase,
        )
    except BaseException:
        raise GuestAdmissionError("native V2 stopped-guest observation failed") from None
    if type(observed) is not TestOnlyV2StoppedGuestObservation:
        raise GuestAdmissionError("TEST_ONLY V2 stopped-guest observation is untyped")
    return observed


def _validate_stopped_guest_observation_v2(
    observed: TestOnlyV2StoppedGuestObservation,
    expectation: GuestAdmissionExpectationV2,
    phase: str,
) -> TestOnlyV2StoppedGuestObservation:
    """Validate an already-obtained observation against the exact authority."""
    exact = (
        observed.phase == phase
        and observed.provider_attempt_id == expectation.provider_attempt_id
        and observed.provider_kind == expectation.provider_kind
        and observed.provider_identity_sha256 == expectation.provider_identity_sha256
        and observed.image_reference == expectation.image_reference
        and observed.image_index_digest == expectation.image_index_digest
        and observed.image_manifest_digest == expectation.image_manifest_digest
        and observed.image_config_digest == expectation.image_config_digest
        and observed.apple_container_configuration_sha256
        == expectation.apple_container_configuration_sha256
        and observed.image_closure_sha256 == expectation.image_closure_sha256
        and observed.backend_admission_sha256
        == expectation.backend_admission_sha256
        and observed.platform_os == expectation.platform_os
        and observed.platform_architecture == expectation.platform_architecture
        and observed.network_mode == expectation.execution.network_mode
        and observed.network_policy_sha256
        == expectation.execution.network_policy_sha256
        and observed.lifecycle_state == "CREATED_STOPPED"
        and type(observed.workload_process_count) is int
        and observed.workload_process_count == 0
        and observed.precreate_layout_sha256
        == expectation.precreate_layout_sha256
        and observed.postcreate_layout_sha256
        == expectation.postcreate_layout_sha256
        and observed.mounts == expectation.mounts
        and observed.target_lower == expectation.target_lower
        and observed.lower_binding_sha256 == expectation.lower_binding_sha256
    )
    if not exact:
        raise GuestAdmissionError(
            "native V2 stopped-guest observation differs from launch authority"
        )
    return observed


def _observe_stopped_guest_v2(
    authority: TestOnlyStoppedGuestAdmissionAuthorityV2,
    expectation: GuestAdmissionExpectationV2,
    phase: str,
) -> TestOnlyV2StoppedGuestObservation:
    return _validate_stopped_guest_observation_v2(
        _read_stopped_guest_v2(authority, expectation, phase),
        expectation,
        phase,
    )


class TestOnlySupervisorGuestAdmissionV2:
    """TEST_ONLY one-shot evidence used to exercise pre-start control flow.

    Provider-specific kill, extinction, export and delete remain responsibilities
    of the enclosing POSIX supervisor. This contract deliberately issues no
    generic termination authority.
    """

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("TEST_ONLY V2 admissions use the fake-only admission seam")

    def __bool__(self) -> bool:
        raise TypeError("V2 supervisor admission must be consumed for start")

    def __copy__(self) -> "TestOnlySupervisorGuestAdmissionV2":
        raise TypeError("V2 supervisor admission cannot be copied")

    def __deepcopy__(self, _memo: object) -> "TestOnlySupervisorGuestAdmissionV2":
        raise TypeError("V2 supervisor admission cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("V2 supervisor admission cannot be serialized")

    def _state(self) -> _AdmissionStateV2:
        if type(self) is not TestOnlySupervisorGuestAdmissionV2:
            raise GuestAdmissionError("issued TEST_ONLY V2 supervisor admission is required")
        with _ISSUER_LOCK:
            state = _TEST_ONLY_ADMISSION_REGISTRY_V2.get(self)
        if state is None:
            raise GuestAdmissionError("issued TEST_ONLY V2 supervisor admission is required")
        return state

    receipt_sha256 = property(lambda self: self._state().receipt_sha256)
    admission_sha256 = property(lambda self: self._state().admission_sha256)
    provider_attempt_id = property(
        lambda self: self._state().expectation.provider_attempt_id
    )
    schema = property(lambda self: (self._state(), TEST_ONLY_SCHEMA_V2)[1])

    @property
    def consumed(self) -> bool:
        return self._state().consumed

    def consume_for_start(
        self,
        expectation: GuestAdmissionExpectationV2,
        *,
        stopped_guest_authority: TestOnlyStoppedGuestAdmissionAuthorityV2,
        starter: Callable[["TestOnlySupervisorGuestAdmissionV2"], _T],
    ) -> _T:
        """Revalidate the stopped guest, burn this capability, then start once."""
        if type(expectation) is not GuestAdmissionExpectationV2:
            raise GuestAdmissionError("typed V2 guest expectation is required for start")
        if not callable(starter):
            raise GuestAdmissionError("a synchronous V2 workload starter is required")
        state = self._state()
        with state.lock:
            if state.consumed:
                raise GuestAdmissionError("V2 supervisor admission was already consumed")
            if expectation != state.expectation:
                raise GuestAdmissionError("V2 start values differ from admitted values")
            if stopped_guest_authority is not state.stopped_authority:
                raise GuestAdmissionError("V2 stopped-guest authority was substituted")
            # Observation itself crosses a native/provider boundary and can
            # prove that a workload already escaped the stopped state. Burn
            # atomically under the admission lock before obtaining or
            # validating that observation; no fail-then-clear retry is safe.
            state.consumed = True
            try:
                _observe_stopped_guest_v2(
                    stopped_guest_authority, expectation, "PRE_START",
                )
            except BaseException:
                raise TestOnlyV2ProviderCleanupRequired(
                    expectation.provider_attempt_id, "PRE_START",
                ) from None
            # Starting is irreversible/ambiguous. Provider-specific extinction
            # remains outside this admission contract on every failure.
            try:
                return starter(self)
            except BaseException:
                raise TestOnlyV2ProviderCleanupRequired(
                    expectation.provider_attempt_id, "START",
                ) from None


class OciGuestAdmission:
    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("OCI guest admission capabilities are issued by admit_oci_guest")

    def __bool__(self) -> bool:
        raise TypeError("OCI guest admission must be consumed by the typed launcher")

    def __copy__(self) -> "OciGuestAdmission":
        raise TypeError("OCI guest admission capabilities cannot be copied")

    def __deepcopy__(self, _memo: object) -> "OciGuestAdmission":
        raise TypeError("OCI guest admission capabilities cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("OCI guest admission capabilities cannot be serialized")

    @property
    def consumed(self) -> bool:
        if type(self) is not OciGuestAdmission:
            raise GuestAdmissionError("issued OCI guest admission capability is required")
        with _ISSUER_LOCK:
            state = _ADMISSION_REGISTRY.get(self)
            if state is None:
                raise GuestAdmissionError("issued OCI guest admission capability is required")
            return state.consumed

    def consume_for_launch(
        self,
        expectation: GuestAdmissionExpectation,
        *,
        source_revalidator: DescriptorSnapshotSourceRevalidator,
        launcher: Callable[[GuestLaunchAdmission, tuple[PinnedProviderMount, ...]], ProviderCreateResult[_T]],
    ) -> LaunchedGuest[_T]:
        """Invoke provider create while every source lease and launch view is live.

        Launcher or durable-arm failure consumes the capability because provider
        state may be ambiguous. A source failure before the guarded callback does
        not consume this local object, but durable replay admission has already
        been consumed.
        """
        if type(expectation) is not GuestAdmissionExpectation:
            raise GuestAdmissionError("typed guest launch expectation is required")
        with _SOURCE_REVALIDATOR_LOCK:
            trusted_revalidator = (
                type(source_revalidator) is DescriptorSnapshotSourceRevalidator
                and source_revalidator in _SOURCE_REVALIDATOR_REGISTRY
            )
        if not trusted_revalidator:
            raise GuestAdmissionError(
                "an issued descriptor/native-proof revalidator is required at provider create"
            )
        if not callable(launcher):
            raise GuestAdmissionError("a synchronous provider-create launcher is required")
        if type(self) is not OciGuestAdmission:
            raise GuestAdmissionError("issued OCI guest admission capability is required")
        with _ISSUER_LOCK:
            state = _ADMISSION_REGISTRY.get(self)
        if state is None:
            raise GuestAdmissionError("issued OCI guest admission capability is required")
        with state.lock:
            if state.consumed:
                raise GuestAdmissionError("OCI guest admission capability was already consumed")
            if expectation != state.expectation:
                raise GuestAdmissionError("guest launch values differ from admitted values")
            view = object.__new__(GuestLaunchAdmission)
            fields = MappingProxyType({
                "schema": SCHEMA, "receipt_sha256": state.receipt_sha256,
                "image_manifest_digest": expectation.image_manifest_digest,
                "config_sha256": expectation.config_sha256,
                "launch_envelope_sha256": expectation.launch_envelope_sha256,
                "runtime_closure_sha256": expectation.runtime_closure_sha256,
                "provider_attempt_id": expectation.provider_attempt_id,
                "helpers": expectation.helpers, "cgroup": expectation.cgroup,
                "landlock": expectation.landlock, "execution": expectation.execution,
            })
            with _ISSUER_LOCK:
                _LAUNCH_REGISTRY[view] = fields

            def guarded_launcher(
                active_view: GuestLaunchAdmission,
                pins: tuple[PinnedProviderMount, ...],
            ) -> ProviderCreateResult[_T]:
                if active_view is not view:
                    raise GuestAdmissionError("source revalidator substituted the launch view")
                if state.consumed:
                    raise GuestAdmissionError("provider create callback was invoked more than once")
                # Burn the local launch authority before crossing even the
                # durable-arm boundary.  An exception from arm is itself
                # ambiguous: it may have committed its journal record before
                # transport/process failure.  The outer path therefore always
                # executes the bound kill/observe/terminal transition.
                state.consumed = True
                try:
                    armed = state.supervisor.arm(expectation.cgroup, state.receipt_sha256)
                except BaseException:
                    armed = False
                if armed is not True:
                    raise GuestAdmissionError("durable supervisor could not arm cleanup")
                return launcher(active_view, pins)

            create_failed = False
            try:
                value = source_revalidator.create_with_leases(
                    expectation.provider_attempt_id, expectation.mounts, view, guarded_launcher
                )
            except BaseException:
                create_failed = True
                value = None
            finally:
                with _ISSUER_LOCK:
                    _LAUNCH_REGISTRY.pop(view, None)
            if create_failed:
                if state.consumed:
                    cleanup_verified = _cleanup_failed_create(state)
                    if cleanup_verified:
                        raise GuestAdmissionError(
                            "provider-create attempt failed or became ambiguous; cgroup cleanup was verified"
                        )
                    raise GuestAdmissionError(
                        "provider-create attempt failed or became ambiguous; durable cleanup is unproven"
                    )
                raise GuestAdmissionError(
                    "source validation or durable cleanup arming failed before provider create"
                )
            if not state.consumed:
                raise GuestAdmissionError("source revalidator did not invoke provider create")

            post_create_failed = False
            terminal: CgroupTerminationCapability | None = None
            try:
                running_recorded = state.supervisor.mark_running(expectation.cgroup)
                if running_recorded is not True:
                    raise GuestAdmissionError("durable running state was not recorded")
                terminal = object.__new__(CgroupTerminationCapability)
                with _ISSUER_LOCK:
                    _TERMINATION_REGISTRY[terminal] = (
                        expectation.cgroup, state.termination_observer,
                        state.supervisor, False,
                    )
                launched = LaunchedGuest(value, terminal)
            except BaseException:
                post_create_failed = True
            if post_create_failed:
                if terminal is not None:
                    with _ISSUER_LOCK:
                        _TERMINATION_REGISTRY.pop(terminal, None)
                cleanup_verified = _cleanup_failed_create(state)
                if cleanup_verified:
                    raise GuestAdmissionError(
                        "provider create succeeded but finalization failed; cleanup was verified"
                    )
                raise GuestAdmissionError(
                    "provider create succeeded but finalization failed; durable cleanup is unproven"
                )
            return launched


_ADMISSION_REGISTRY = weakref.WeakKeyDictionary()
_TEST_ONLY_ADMISSION_REGISTRY_V2 = weakref.WeakKeyDictionary()


def _identity_row(value: Any, label: str) -> SourceIdentity:
    row = _exact_dict(value, _IDENTITY_KEYS, label)
    return SourceIdentity(
        device=row["device"], inode=row["inode"], uid=row["uid"], gid=row["gid"], mode=row["mode"],
        object_kind=row["object_kind"], snapshot_format=row["snapshot_format"],
        snapshot_sha256=row["snapshot_sha256"], regular_file_count=row["regular_file_count"],
        directory_count=row["directory_count"], total_bytes=row["total_bytes"],
        max_depth=row["max_depth"], native_mount_id=row["native_mount_id"],
        native_mount_id_kind=row["native_mount_id_kind"],
        mount_topology_sha256=row["mount_topology_sha256"],
        mount_proof_authenticated=row["mount_proof_authenticated"],
        submounts_absent=row["submounts_absent"],
        symlink_entries_absent=row["symlink_entries_absent"],
        special_files_absent=row["special_files_absent"], hardlinks_absent=row["hardlinks_absent"],
        xattrs_absent=row["xattrs_absent"], compressed_files_absent=row["compressed_files_absent"],
    )


def _helper_rows(value: Any) -> tuple[HelperBinding, ...]:
    if type(value) is not list or not value or len(value) > MAX_HELPERS:
        raise GuestAdmissionError("guest helper roster size is invalid")
    rows = tuple(HelperBinding(**_exact_dict(item, _HELPER_KEYS, f"guest helper {index}")) for index, item in enumerate(value))
    _validate_unique_paths(tuple(row.path for row in rows), "guest helper roster")
    return rows


def _mount_rows(value: Any, host_home: str) -> tuple[MountBinding, ...]:
    if type(value) is not list or len(value) != len(_MOUNT_POLICY):
        raise GuestAdmissionError("guest mount roster size is invalid")
    rows: list[MountBinding] = []
    for index, item in enumerate(value):
        row = _exact_dict(item, _MOUNT_KEYS, f"guest mount {index}")
        rows.append(MountBinding(
            source_root=row["source_root"],
            source_root_identity=_identity_row(row["source_root_identity"], f"guest mount {index} source-root identity"),
            source=row["source"], source_identity=_identity_row(row["source_identity"], f"guest mount {index} source identity"),
            destination=row["destination"], mode=row["mode"], purpose=row["purpose"], kind=row["kind"],
        ))
    result = tuple(rows)
    _validate_mount_roster(result, host_home)
    return result


def _cgroup_row(value: Any) -> CgroupAuthority:
    return CgroupAuthority(**_exact_dict(value, _CGROUP_KEYS, "guest cgroup receipt"))


def _landlock_row(value: Any) -> LandlockAuthority:
    row = _exact_dict(value, _LANDLOCK_KEYS, "guest Landlock receipt")
    if type(row["handled_access_fs"]) is not list or type(row["allowed_write_paths"]) is not list:
        raise GuestAdmissionError("guest Landlock right/path rosters are invalid")
    values = dict(row)
    values["handled_access_fs"] = tuple(values["handled_access_fs"])
    values["allowed_write_paths"] = tuple(values["allowed_write_paths"])
    return LandlockAuthority(**values)


def _execution_row(value: Any) -> ExecutionAuthority:
    row = _exact_dict(value, _EXECUTION_KEYS, "guest process/network receipt")
    roster_fields = ("supplemental_groups", "capabilities_drop", "capabilities_add", "published_sockets", "host_devices", "masked_paths", "readonly_paths")
    values = dict(row)
    for field in roster_fields:
        if type(values[field]) is not list:
            raise GuestAdmissionError("guest process/network roster is invalid")
        values[field] = tuple(values[field])
    return ExecutionAuthority(**values)


def admit_oci_guest(
    receipt_raw: bytes,
    expectation: GuestAdmissionExpectation,
    *,
    replay_consumer: PersistentReplayConsumer,
    termination_observer: CgroupTerminationObserver,
    durable_supervisor: DurableLaunchSupervisor,
    maximum_bytes: int = MAX_RECEIPT_BYTES,
) -> OciGuestAdmission:
    """Verify a trusted-channel receipt, then durably consume its replay key."""
    if type(expectation) is not GuestAdmissionExpectation:
        raise GuestAdmissionError("typed guest admission expectation is required")
    if replay_consumer is None or not _has_callable(replay_consumer, "consume"):
        raise GuestAdmissionError("a persistent atomic replay consumer is required")
    if termination_observer is None or not _has_callable(termination_observer, "kill_then_observe"):
        raise GuestAdmissionError("a bound cgroup kill observer is required")
    if durable_supervisor is None or not all(
        _has_callable(durable_supervisor, name)
        for name in ("arm", "mark_running", "mark_terminal")
    ):
        raise GuestAdmissionError("a durable launch supervisor is required")
    receipt = _load_receipt(receipt_raw, maximum_bytes=maximum_bytes)
    _exact_dict(receipt, _TOP_KEYS, "guest receipt")
    if receipt["schema"] != SCHEMA:
        raise GuestAdmissionError("guest receipt schema is unsupported")

    image = _exact_dict(receipt["image"], _IMAGE_KEYS, "guest image")
    platform = _exact_dict(image["platform"], _PLATFORM_KEYS, "guest image platform")
    observed_image = _image_digest(image["manifest_digest"], "guest image manifest digest")
    if platform != {"os": "linux", "architecture": "arm64"}:
        raise GuestAdmissionError("guest image platform must be exactly linux/arm64")
    if not _same_text(observed_image, expectation.image_manifest_digest):
        raise GuestAdmissionError("guest image manifest digest differs from launch authority")

    bindings = _exact_dict(receipt["bindings"], _BINDING_KEYS, "guest bindings")
    config = _plain_digest(bindings["config_sha256"], "guest config sha256")
    envelope = _plain_digest(bindings["launch_envelope_sha256"], "guest launch envelope sha256")
    closure = _plain_digest(bindings["runtime_closure_sha256"], "guest runtime closure sha256")
    attempt = _attempt(bindings["provider_attempt_id"], "guest provider attempt ID")
    helpers = _helper_rows(bindings["helpers"])
    if not _same_text(config, expectation.config_sha256):
        raise GuestAdmissionError("guest config digest differs from launch authority")
    if not _same_text(envelope, expectation.launch_envelope_sha256):
        raise GuestAdmissionError("guest launch envelope digest differs from launch authority")
    if not _same_text(closure, expectation.runtime_closure_sha256):
        raise GuestAdmissionError("guest runtime closure digest differs from launch authority")
    if not _same_text(attempt, expectation.provider_attempt_id):
        raise GuestAdmissionError("guest provider attempt ID differs from launch authority")
    if helpers != expectation.helpers:
        raise GuestAdmissionError("guest helper roster differs from launch authority")

    if _exact_dict(receipt["rootfs"], _ROOTFS_KEYS, "guest rootfs")["readonly"] is not True:
        raise GuestAdmissionError("guest rootfs is not read-only")
    mounts = _mount_rows(receipt["mounts"], expectation.host_home)
    _validate_helpers(helpers, mounts)
    if mounts != expectation.mounts:
        raise GuestAdmissionError("guest mount roster differs from launch authority")

    capabilities = _exact_dict(receipt["capabilities"], _CAPABILITY_KEYS, "guest capabilities")
    if _cgroup_row(capabilities["cgroup_v2"]) != expectation.cgroup:
        raise GuestAdmissionError("guest cgroup-v2 authority differs from launch authority")
    if _landlock_row(capabilities["landlock"]) != expectation.landlock:
        raise GuestAdmissionError("guest Landlock authority differs from launch authority")
    if _execution_row(receipt["execution"]) != expectation.execution:
        raise GuestAdmissionError("guest process/network authority differs from launch authority")

    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    replay_failed = False
    try:
        first = replay_consumer.consume(expectation.provider_attempt_id, receipt_sha256)
    except BaseException:
        replay_failed = True
        first = False
    if replay_failed:
        raise GuestAdmissionError("persistent replay consumption failed")
    if first is not True:
        raise GuestAdmissionError("guest provider attempt receipt was already consumed")
    capability = object.__new__(OciGuestAdmission)
    with _ISSUER_LOCK:
        _ADMISSION_REGISTRY[capability] = _AdmissionState(
            expectation, receipt_sha256, termination_observer, durable_supervisor,
            False, threading.Lock()
        )
    return capability


def _mount_rows_v2(
    value: Any, host_home: str, target_lower: HostOverlayLowerBindingV2,
    lower_binding_sha256: str,
) -> tuple[SupervisorMountBindingV2, ...]:
    if type(value) is not list or len(value) != len(_MOUNT_POLICY_V2):
        raise GuestAdmissionError("V2 guest mount roster size is invalid")
    rows: list[SupervisorMountBindingV2] = []
    for index, item in enumerate(value):
        row = _exact_dict(item, _MOUNT_KEYS_V2, f"V2 guest mount {index}")
        rows.append(SupervisorMountBindingV2(
            source_root=row["source_root"],
            source_root_identity=_identity_row(
                row["source_root_identity"],
                f"V2 guest mount {index} source-root identity",
            ),
            source=row["source"],
            source_identity=_identity_row(
                row["source_identity"],
                f"V2 guest mount {index} source identity",
            ),
            destination=row["destination"], mode=row["mode"],
            purpose=row["purpose"], kind=row["kind"],
            provider_mount_identity_sha256=row[
                "provider_mount_identity_sha256"
            ],
        ))
    result = tuple(rows)
    _validate_mount_roster_v2(
        result, target_lower, host_home, lower_binding_sha256,
    )
    return result


def _target_lower_row_v2(value: Any) -> HostOverlayLowerBindingV2:
    row = _exact_dict(value, _HOST_LOWER_KEYS_V2, "V2 target-lower binding")
    return HostOverlayLowerBindingV2(
        source_root=row["source_root"],
        source_root_identity=_identity_row(
            row["source_root_identity"], "V2 target-lower source-root identity",
        ),
        source=row["source"],
        source_identity=_identity_row(
            row["source_identity"], "V2 target-lower source identity",
        ),
        provider_mount_identity_sha256=row["provider_mount_identity_sha256"],
        purpose=row["purpose"], attachment=row["attachment"],
        mode=row["mode"], kind=row["kind"],
    )


def _execution_row_v2(value: Any) -> ExecutionAuthorityV2:
    row = _exact_dict(value, _EXECUTION_KEYS, "V2 guest process/network receipt")
    roster_fields = (
        "supplemental_groups", "capabilities_drop", "capabilities_add",
        "published_sockets", "host_devices", "masked_paths", "readonly_paths",
    )
    values = dict(row)
    for field in roster_fields:
        if type(values[field]) is not list:
            raise GuestAdmissionError("V2 guest process/network roster is invalid")
        values[field] = tuple(values[field])
    return ExecutionAuthorityV2(**values)


def admit_oci_guest_v2(
    _receipt_raw: bytes,
    _expectation: GuestAdmissionExpectationV2,
    *,
    replay_consumer: PersistentReplayConsumer,
    native_admission_authority: object,
    maximum_bytes: int = MAX_RECEIPT_BYTES,
) -> None:
    """Production V2 hard-stop pending a non-Python admission authority.

    The arguments intentionally describe the eventual integration surface, but
    neither their Python values nor any in-process registry can authorize a
    workload. Keep this fail-closed until a native/out-of-process receipt is
    authenticated and consumed without Python-mintable capability state.
    """
    raise GuestAdmissionError(
        "authenticated native/out-of-process V2 admission integration is unavailable"
    )


def _admit_oci_guest_v2_for_testing(
    receipt_raw: bytes,
    expectation: GuestAdmissionExpectationV2,
    *,
    replay_consumer: PersistentReplayConsumer,
    stopped_guest_authority: TestOnlyStoppedGuestAdmissionAuthorityV2,
    maximum_bytes: int = MAX_RECEIPT_BYTES,
) -> TestOnlySupervisorGuestAdmissionV2:
    """TEST_ONLY model of one exact already-created, stopped guest.

    Receipt parsing is side-effect free. Native stopped/layout observations
    surround the durable replay transition, and a third observation is required
    immediately before ``consume_for_start`` crosses the workload boundary.
    """
    if type(expectation) is not GuestAdmissionExpectationV2:
        raise GuestAdmissionError("typed V2 guest admission expectation is required")
    if replay_consumer is None or not _has_callable(replay_consumer, "consume"):
        raise GuestAdmissionError("a persistent atomic V2 replay consumer is required")
    if type(stopped_guest_authority) is not TestOnlyStoppedGuestAdmissionAuthorityV2:
        raise GuestAdmissionError("issued TEST_ONLY V2 stopped-guest authority is required")
    with _ISSUER_LOCK:
        if stopped_guest_authority not in _TEST_ONLY_STOPPED_AUTHORITY_REGISTRY_V2:
            raise GuestAdmissionError("issued TEST_ONLY V2 stopped-guest authority is required")

    receipt = _load_receipt(receipt_raw, maximum_bytes=maximum_bytes)
    _exact_dict(receipt, _TOP_KEYS_V2, "V2 guest receipt")
    if receipt["schema"] != TEST_ONLY_SCHEMA_V2:
        raise GuestAdmissionError("TEST_ONLY V2 guest receipt schema is unsupported")

    image = _exact_dict(receipt["image"], _IMAGE_KEYS_V2, "V2 guest image")
    platform = _exact_dict(image["platform"], _PLATFORM_KEYS, "V2 guest image platform")
    observed_image = _image_digest(
        image["manifest_digest"], "V2 guest image manifest digest",
    )
    observed_index = _image_digest(image["index_digest"], "V2 guest image index digest")
    observed_config = _image_digest(image["config_digest"], "V2 guest image config digest")
    apple_config = _plain_digest(image["apple_container_configuration_sha256"], "V2 guest Apple Container configuration sha256")
    reference = image["reference"]
    if type(reference) is not str or _OCI_REFERENCE.fullmatch(reference) is None or reference.rsplit("@", 1)[1] != observed_index:
        raise GuestAdmissionError("V2 guest image reference does not bind its index")
    if platform != {
        "os": expectation.platform_os,
        "architecture": expectation.platform_architecture,
    }:
        raise GuestAdmissionError("V2 guest image platform differs from launch authority")
    if (
        not _same_text(reference, expectation.image_reference)
        or not _same_text(observed_index, expectation.image_index_digest)
        or not _same_text(observed_image, expectation.image_manifest_digest)
        or not _same_text(observed_config, expectation.image_config_digest)
        or not _same_text(apple_config, expectation.apple_container_configuration_sha256)
    ):
        raise GuestAdmissionError("V2 guest image closure differs from launch authority")

    provider = _exact_dict(receipt["provider"], _PROVIDER_KEYS_V2, "V2 guest provider")
    provider_attempt = _attempt(
        provider["provider_attempt_id"], "V2 provider attempt ID",
    )
    provider_identity = _plain_digest(
        provider["identity_sha256"], "V2 provider identity sha256",
    )
    if (
        provider["kind"] != expectation.provider_kind
        or not _same_text(provider_identity, expectation.provider_identity_sha256)
        or not _same_text(provider_attempt, expectation.provider_attempt_id)
    ):
        raise GuestAdmissionError("V2 provider identity differs from launch authority")

    bindings = _exact_dict(receipt["bindings"], _BINDING_KEYS_V2, "V2 guest bindings")
    config = _plain_digest(bindings["config_sha256"], "V2 guest config sha256")
    envelope = _plain_digest(
        bindings["launch_envelope_sha256"], "V2 guest launch envelope sha256",
    )
    closure = _plain_digest(
        bindings["runtime_closure_sha256"], "V2 guest runtime closure sha256",
    )
    attempt = _attempt(bindings["provider_attempt_id"], "V2 guest provider attempt ID")
    helpers = _helper_rows(bindings["helpers"])
    materialization = _runtime_materialization_row_v2(bindings["runtime_materialization"])
    image_closure = _plain_digest(bindings["image_closure_sha256"], "V2 image closure sha256")
    backend_admission = _plain_digest(bindings["backend_admission_sha256"], "V2 backend admission sha256")
    if (
        not _same_text(config, expectation.config_sha256)
        or not _same_text(envelope, expectation.launch_envelope_sha256)
        or not _same_text(closure, expectation.runtime_closure_sha256)
        or not _same_text(attempt, expectation.provider_attempt_id)
        or helpers != expectation.helpers
        or materialization != expectation.runtime_materialization
        or not _same_text(image_closure, expectation.image_closure_sha256)
        or not _same_text(backend_admission, expectation.backend_admission_sha256)
    ):
        raise GuestAdmissionError("V2 guest bindings differ from launch authority")

    if _exact_dict(receipt["rootfs"], _ROOTFS_KEYS, "V2 guest rootfs")["readonly"] is not True:
        raise GuestAdmissionError("V2 guest rootfs is not read-only")
    overlay = _exact_dict(receipt["overlay"], _OVERLAY_KEYS_V2, "V2 guest overlay")
    target_lower = _target_lower_row_v2(overlay["target_lower"])
    lower_binding = _plain_digest(
        overlay["lower_binding_sha256"], "V2 lower binding sha256",
    )
    merged_provider_identity = _plain_digest(
        overlay["project_merged_provider_mount_identity_sha256"],
        "V2 project-merged provider mount identity sha256",
    )
    mounts = _mount_rows_v2(
        receipt["mounts"], expectation.host_home, target_lower, lower_binding,
    )
    if merged_provider_identity != mounts[0].provider_mount_identity_sha256:
        raise GuestAdmissionError("V2 overlay names a different project-merged mount")
    _validate_helpers_v2(helpers, mounts)
    if (
        mounts != expectation.mounts or target_lower != expectation.target_lower
        or not _same_text(lower_binding, expectation.lower_binding_sha256)
    ):
        raise GuestAdmissionError("V2 mount/overlay roster differs from launch authority")

    capabilities = _exact_dict(
        receipt["capabilities"], _CAPABILITY_KEYS, "V2 guest capabilities",
    )
    if _cgroup_row(capabilities["cgroup_v2"]) != expectation.cgroup:
        raise GuestAdmissionError("V2 cgroup-v2 authority differs from launch authority")
    if _landlock_row(capabilities["landlock"]) != expectation.landlock:
        raise GuestAdmissionError("V2 Landlock authority differs from launch authority")
    execution = _execution_row_v2(receipt["execution"])
    if execution != expectation.execution:
        raise GuestAdmissionError("V2 process/network authority differs from launch authority")

    lifecycle = _exact_dict(receipt["lifecycle"], _LIFECYCLE_KEYS_V2, "V2 guest lifecycle")
    initial_count = lifecycle["initial_process_count"]
    if (
        lifecycle["state"] != "CREATED_STOPPED"
        or lifecycle["create_stopped"] is not True
        or type(initial_count) is not int or isinstance(initial_count, bool)
        or initial_count != 0
        or lifecycle["workload_nonexecuting"] is not True
        or lifecycle["precreate_layout_sha256"]
        != expectation.precreate_layout_sha256
        or lifecycle["postcreate_layout_sha256"]
        != expectation.postcreate_layout_sha256
    ):
        raise GuestAdmissionError("V2 guest lifecycle is not created-stopped and stable")

    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    # Obtain the typed pre-admission observation before accepting it.  If it
    # proves that a workload already exists, durably poison the attempt before
    # validation can reject the observation; clearing the provider state must
    # never turn that attempt into a retryable admission.
    pre_admission = _read_stopped_guest_v2(
        stopped_guest_authority, expectation, "PRE_ADMISSION",
    )
    if pre_admission.workload_process_count != 0:
        try:
            poisoned = replay_consumer.consume(
                expectation.provider_attempt_id, receipt_sha256,
            )
        except BaseException:
            raise TestOnlyV2ProviderCleanupRequired(
                expectation.provider_attempt_id, "PRE_ADMISSION",
            ) from None
        if type(poisoned) is not bool:
            raise TestOnlyV2ProviderCleanupRequired(
                expectation.provider_attempt_id, "PRE_ADMISSION",
            )
        # True inserted the poison record; False proves that an attempt record
        # already exists.  Neither result permits admission or a retry.
        raise TestOnlyV2ProviderCleanupRequired(
            expectation.provider_attempt_id, "PRE_ADMISSION",
        )
    _validate_stopped_guest_observation_v2(
        pre_admission, expectation, "PRE_ADMISSION",
    )
    try:
        first = replay_consumer.consume(expectation.provider_attempt_id, receipt_sha256)
    except BaseException:
        raise GuestAdmissionError("persistent V2 replay consumption failed") from None
    if first is not True:
        raise GuestAdmissionError("V2 guest provider attempt receipt was already consumed")
    try:
        _observe_stopped_guest_v2(
            stopped_guest_authority, expectation, "POST_ADMISSION",
        )
    except BaseException:
        # The replay key is already durable, so this attempt is poisoned.  The
        # supervisor must now perform its provider-specific cleanup protocol.
        raise TestOnlyV2ProviderCleanupRequired(
            expectation.provider_attempt_id, "POST_ADMISSION",
        ) from None
    admission_sha256 = hashlib.sha256(_canonical_bytes({
        "schema": "plamen.oci_supervisor_admission.v2",
        "receipt_sha256": receipt_sha256,
        "provider_attempt_id": expectation.provider_attempt_id,
        "provider_identity_sha256": expectation.provider_identity_sha256,
        "precreate_layout_sha256": expectation.precreate_layout_sha256,
        "postcreate_layout_sha256": expectation.postcreate_layout_sha256,
        "lower_binding_sha256": expectation.lower_binding_sha256,
    })).hexdigest()
    capability = object.__new__(TestOnlySupervisorGuestAdmissionV2)
    with _ISSUER_LOCK:
        _TEST_ONLY_ADMISSION_REGISTRY_V2[capability] = _AdmissionStateV2(
            expectation, receipt_sha256, admission_sha256,
            stopped_guest_authority, False, threading.Lock(),
        )
    return capability


class CgroupTerminalEvidence:
    """Registry-backed non-authorizing proof issued only after kill/read."""
    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal evidence is issued by a termination capability")

    def _read(self, name: str) -> Any:
        if type(self) is not CgroupTerminalEvidence:
            raise GuestAdmissionError("issued terminal evidence is required")
        with _ISSUER_LOCK:
            fields = _TERMINAL_EVIDENCE_REGISTRY.get(self)
            if fields is None:
                raise GuestAdmissionError("issued terminal evidence is required")
            return fields[name]

    provider_attempt_id = property(lambda self: self._read("provider_attempt_id"))
    cgroup_path = property(lambda self: self._read("cgroup_path"))
    filesystem_device = property(lambda self: self._read("filesystem_device"))
    inode = property(lambda self: self._read("inode"))
    identity_sha256 = property(lambda self: self._read("identity_sha256"))
    termination_method = property(lambda self: self._read("termination_method"))
    populated = property(lambda self: self._read("populated"))
    cgroup_events_sha256 = property(lambda self: self._read("cgroup_events_sha256"))
    kill_generation = property(lambda self: self._read("kill_generation"))
    events_read_generation = property(lambda self: self._read("events_read_generation"))
    receipt_sha256 = property(lambda self: self._read("receipt_sha256"))

    def __copy__(self) -> "CgroupTerminalEvidence":
        raise TypeError("terminal evidence cannot be copied")

    def __deepcopy__(self, _memo: object) -> "CgroupTerminalEvidence":
        raise TypeError("terminal evidence cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("terminal evidence cannot be serialized")

    def __bool__(self) -> bool:
        raise TypeError("terminal evidence must be inspected through typed fields")


_TERMINAL_EVIDENCE_REGISTRY: weakref.WeakKeyDictionary[
    CgroupTerminalEvidence, Mapping[str, Any]
] = weakref.WeakKeyDictionary()


CGROUP_KILL_WRITE_SHA256 = hashlib.sha256(b"1\n").hexdigest()
_EMPTY_CGROUP_EVENTS = b"populated 0\nfrozen 0\n"


@dataclass(frozen=True, slots=True)
class CgroupTerminationObservation:
    provider_attempt_id: str
    cgroup_path: str
    filesystem_device: int
    inode: int
    identity_sha256: str
    kill_write_sha256: str
    kill_generation: int
    events_read_generation: int
    cgroup_events: bytes

    def __post_init__(self) -> None:
        _attempt(self.provider_attempt_id, "terminal provider attempt ID")
        _canonical_posix_path(self.cgroup_path, "terminal cgroup path")
        _domain_int(self.filesystem_device, "terminal cgroup filesystem device", positive=True)
        _domain_int(self.inode, "terminal cgroup inode", positive=True)
        _plain_digest(self.identity_sha256, "terminal cgroup identity sha256")
        _plain_digest(self.kill_write_sha256, "cgroup.kill write sha256")
        kill = _domain_int(self.kill_generation, "cgroup.kill generation", positive=True)
        read = _domain_int(self.events_read_generation, "cgroup.events read generation", positive=True)
        if read <= kill:
            raise GuestAdmissionError("cgroup.events was not observed after cgroup.kill")
        if type(self.cgroup_events) is not bytes or len(self.cgroup_events) > 4096:
            raise GuestAdmissionError("cgroup.events observation is invalid")


class CgroupTerminationObserver(Protocol):
    """Atomically writes cgroup.kill, then reads the same directory's events."""
    def kill_then_observe(self, cgroup: CgroupAuthority) -> CgroupTerminationObservation: ...


def _terminal_evidence_from_observation(
    cgroup: CgroupAuthority, observation: CgroupTerminationObservation
) -> CgroupTerminalEvidence:
    if type(observation) is not CgroupTerminationObservation:
        raise GuestAdmissionError("cgroup observer returned an invalid terminal observation")
    if (
        observation.provider_attempt_id != cgroup.provider_attempt_id
        or observation.cgroup_path != cgroup.path
        or observation.filesystem_device != cgroup.filesystem_device
        or observation.inode != cgroup.inode
        or not _same_text(observation.identity_sha256, cgroup.identity_sha256)
    ):
        raise GuestAdmissionError("terminal observation names a different cgroup attempt")
    if not _same_text(observation.kill_write_sha256, CGROUP_KILL_WRITE_SHA256):
        raise GuestAdmissionError("terminal observation did not prove the exact cgroup.kill write")
    if observation.cgroup_events != _EMPTY_CGROUP_EVENTS:
        raise GuestAdmissionError("terminal cgroup is not proven unpopulated")
    events_sha256 = hashlib.sha256(observation.cgroup_events).hexdigest()
    row = {
        "schema": TERMINAL_SCHEMA,
        "provider_attempt_id": cgroup.provider_attempt_id,
        "cgroup_path": cgroup.path,
        "filesystem_device": cgroup.filesystem_device,
        "inode": cgroup.inode,
        "identity_sha256": cgroup.identity_sha256,
        "termination_method": "CGROUP_KILL",
        "populated": 0,
        "cgroup_events_sha256": events_sha256,
        "kill_generation": observation.kill_generation,
        "events_read_generation": observation.events_read_generation,
    }
    receipt_sha256 = hashlib.sha256(canonical_receipt_bytes(row)).hexdigest()
    evidence = object.__new__(CgroupTerminalEvidence)
    with _ISSUER_LOCK:
        _TERMINAL_EVIDENCE_REGISTRY[evidence] = MappingProxyType({
            "provider_attempt_id": cgroup.provider_attempt_id,
            "cgroup_path": cgroup.path,
            "filesystem_device": cgroup.filesystem_device,
            "inode": cgroup.inode,
            "identity_sha256": cgroup.identity_sha256,
            "termination_method": "CGROUP_KILL",
            "populated": 0,
            "cgroup_events_sha256": events_sha256,
            "kill_generation": observation.kill_generation,
            "events_read_generation": observation.events_read_generation,
            "receipt_sha256": receipt_sha256,
        })
    return evidence


__all__ = [
    "CGROUP_KILL_WRITE_SHA256", "CgroupAuthority", "CgroupTerminalEvidence",
    "CgroupTerminationCapability", "CgroupTerminationObservation", "CgroupTerminationObserver",
    "CreatedMountReceipt", "DescriptorSnapshotSourceRevalidator",
    "DurableLaunchSupervisor",
    "ExecutionAuthority", "ExecutionAuthorityV2", "GuestAdmissionError",
    "GuestAdmissionExpectation", "GuestAdmissionExpectationV2",
    "GuestLaunchAdmission", "HelperBinding", "LANDLOCK_HANDLED_ACCESS_FS",
    "LANDLOCK_MAX_TESTED_ABI", "LANDLOCK_MIN_ABI", "LandlockAuthority",
    "HostOverlayLowerBindingV2", "LaunchedGuest", "MASKED_PATHS",
    "MAX_MOUNTS_V2", "MAX_RECEIPT_BYTES", "MountBinding", "OciGuestAdmission",
    "NativeMountProof", "PersistentReplayConsumer", "PinnedProviderMount", "PinnedSourceReference",
    "ProviderCreateReceipt", "ProviderCreateResult", "ProviderMountPinningAuthority",
    "READONLY_PATHS", "RevalidatedMount", "SCHEMA", "SOURCE_SNAPSHOT_FORMAT",
    "SCHEMA_V2", "RuntimeMaterializationBindingV2", "SourceIdentity", "SourceRevalidator",
    "SupervisorMountBindingV2", "TERMINAL_SCHEMA",
    "admit_oci_guest", "admit_oci_guest_v2",
    "bind_native_stopped_guest_authority_v2", "canonical_receipt_bytes",
    "snapshot_source_identity",
]
