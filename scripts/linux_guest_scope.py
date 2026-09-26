"""Typed provider for the compiled Linux/arm64 guest-scope helper.

The C helper owns cgroup, mount, capability, and Landlock syscalls.  Python
only validates retained descriptors, constructs a bounded scalar protocol,
authenticates receipts from a private pipe, and enforces lifecycle cleanup.
The confined entrypoint is a digest-pinned ELF Python interpreter plus a
separately pinned driver script at a fixed surviving procfd; scripts are never
passed directly to fexecve().
This module does not claim network isolation; OCI guest initialization must
establish that independently.  No shell or inherited environment is used.
Linux/x86_64 is recognized but rejected with a typed policy debt until its
seccomp and OCI admission profile is independently pinned and verified.
"""

from __future__ import annotations

from dataclasses import dataclass
try:
    import fcntl
except ImportError:  # Windows has no fcntl module.
    fcntl = None  # type: ignore[assignment]
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping, Sequence


RECEIPT_SCHEMA = "plamen.linux_guest_scope.v1"
MAX_RECEIPT_BYTES = 4096
MAX_ROOTS = 64
MAX_RUNTIME_ROOTS = 16
MAX_COMMAND_ARGS = 128
MAX_COMMAND_BYTES = 64 * 1024
MAX_HELPER_SOURCE_BYTES = 2 * 1024 * 1024
MAX_INTERPRETER_BYTES = 128 * 1024 * 1024
MAX_DRIVER_SCRIPT_BYTES = 16 * 1024 * 1024
MAX_TOPOLOGY_DEPTH = 256
MAX_RUNTIME_MANIFEST_DEPTH = 64
MAX_RUNTIME_ENTRIES = 100_000
MAX_RUNTIME_DIRECTORY_ENTRIES = 16_384
MAX_RUNTIME_FILE_BYTES = 512 * 1024 * 1024
MAX_RUNTIME_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
FS_IOC_GETFLAGS = 0x80086601
RUNTIME_SAFE_INODE_FLAGS = (
    0x00000010  # immutable
    | 0x00000040  # nodump
    | 0x00000080  # noatime
    | 0x00001000  # directory index
    | 0x00080000  # extents
    | 0x00100000  # fs-verity
)
MIN_LANDLOCK_ABI = 6
INTERPRETER_EXEC_FD = 197
DRIVER_SCRIPT_EXEC_FD = 198
INTERPRETER_ARGUMENT = f"/proc/self/fd/{INTERPRETER_EXEC_FD}"
DRIVER_SCRIPT_ARGUMENT = f"/proc/self/fd/{DRIVER_SCRIPT_EXEC_FD}"
INTERPRETER_FLAGS = ("-I", "-B", "-P")
READY_RECEIPT_FIELDS = (
    "schema", "phase", "attempt", "binding", "child", "cgroup_name",
    "cgroup_parent_device", "cgroup_parent_inode", "cgroup_device",
    "cgroup_inode", "pids_max", "memory_max", "cpu_quota", "cpu_period",
    "landlock_abi", "handled_fs", "handled_net", "uid", "gid",
    "caps_effective", "caps_permitted", "caps_inheritable", "caps_ambient",
    "no_new_privs", "mount_propagation", "procfs", "path_lookup",
    "direct_shebang_exec", "interpreter_exec_fd", "driver_script_fd",
    "surviving_fds", "interpreter_device", "interpreter_inode",
    "interpreter_mode", "interpreter_owner_uid", "interpreter_owner_gid",
    "interpreter_link_count", "interpreter_access_mode", "interpreter_size",
    "interpreter_sha256",
    "driver_device", "driver_inode", "driver_mode", "driver_owner_uid",
    "driver_owner_gid", "driver_link_count", "driver_access_mode",
    "driver_size", "driver_sha256",
    "runtime_count", "runtime_mounts_read_only", "runtime_roster_sha256",
    "argv_sha256", "overlay_storage_device", "overlay_storage_inode",
    "overlay_storage_mount", "lower_device", "lower_inode", "lower_mount",
    "upper_device", "upper_inode", "upper_mount", "work_device",
    "work_inode", "work_mount", "merged_device", "merged_inode",
    "merged_mount",
)
FINAL_RECEIPT_FIELDS = (
    "schema", "phase", "attempt", "binding", "interpreter_access_mode",
    "driver_access_mode", "wait_status", "timed_out", "exec_verified",
    "cleanup",
)
_HEX_256 = re.compile(r"[0-9a-f]{64}")
_FIELD = re.compile(r"[A-Za-z0-9_.:/+-]{1,256}")
_HELPER_SOURCE = Path(__file__).with_name("linux_guest_scope_helper.c")
_HELPER_DIRECTORY: tempfile.TemporaryDirectory[str] | None = None
_HELPER_PATH: Path | None = None
_HELPER_SOURCE_IDENTITY: dict[str, Any] | None = None
_HELPER_LOCK = threading.Lock()


class LinuxGuestScopeError(RuntimeError):
    """The guest scope could not be established or faithfully replayed."""

    def __init__(self, message: str, *, reason_code: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _is_hex256(value: object) -> bool:
    return isinstance(value, str) and _HEX_256.fullmatch(value) is not None


def _require_posix_fcntl() -> Any:
    """Return the real POSIX module or fail at the operation boundary.

    Keeping this check lazy lets Windows import the policy and use its pure
    validation types without inventing a Python stand-in for kernel authority.
    The explicit host test also prevents a spoofed ``sys.platform`` value from
    making a non-POSIX process look capable.
    """

    if (
        fcntl is None
        or os.name != "posix"
        or sys.platform not in {"darwin", "linux"}
    ):
        raise LinuxGuestScopeError(
            "POSIX descriptor controls are unavailable on this platform",
            reason_code="PLATFORM_UNSUPPORTED",
        )
    return fcntl


@dataclass(frozen=True)
class LinuxGuestLimits:
    pids_max: int
    memory_max: int
    cpu_quota: int
    cpu_period: int
    wall_time_ms: int

    def validate(self) -> None:
        values = (
            self.pids_max,
            self.memory_max,
            self.cpu_quota,
            self.cpu_period,
            self.wall_time_ms,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise LinuxGuestScopeError(
                "Linux guest limits must be exact integers",
                reason_code="LIMITS_INVALID",
            )
        if (
            not 1 <= self.pids_max <= 4096
            or not 16 * 1024 * 1024 <= self.memory_max <= 1024**4
            or not 1000 <= self.cpu_quota <= self.cpu_period
            or self.cpu_period > 1_000_000_000
            or not 100 <= self.wall_time_ms <= 86_400_000
        ):
            raise LinuxGuestScopeError(
                "Linux guest limits are outside the closed policy",
                reason_code="LIMITS_INVALID",
            )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise LinuxGuestScopeError(
            "Linux guest binding is not canonical JSON",
            reason_code="BINDING_INVALID",
        ) from None


def _exact_host_admission() -> dict[str, Any]:
    host = platform.uname()
    machine = host.machine.casefold()
    if (
        sys.platform == "linux"
        and host.system == "Linux"
        and machine in {"x86_64", "amd64"}
        and (8 * struct.calcsize("P")) == 64
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
    ):
        raise LinuxGuestScopeError(
            "Linux/x86_64 guest confinement has no pinned seccomp/OCI policy",
            reason_code="ARCHITECTURE_POLICY_UNAVAILABLE",
        )
    if (
        sys.platform != "linux"
        or host.system != "Linux"
        or machine not in {"aarch64", "arm64"}
        or (8 * struct.calcsize("P")) != 64
        or not hasattr(os, "geteuid")
        or os.geteuid() != 0
    ):
        raise LinuxGuestScopeError(
            "compiled guest confinement requires an exact root Linux/arm64 guest",
            reason_code="HOST_UNSUPPORTED",
        )
    return {
        "system": "Linux",
        "machine": machine,
        "release": host.release,
        "pointer_bits": 64,
        "effective_uid": 0,
    }


def _descriptor_identity(
    descriptor: int,
    *,
    directory: bool,
    executable: bool = False,
) -> dict[str, int]:
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 3:
        raise LinuxGuestScopeError(
            "guest-scope descriptor is malformed",
            reason_code="DESCRIPTOR_INVALID",
        )
    try:
        row = os.fstat(descriptor)
    except OSError:
        raise LinuxGuestScopeError(
            "guest-scope descriptor is unavailable",
            reason_code="DESCRIPTOR_UNAVAILABLE",
        ) from None
    if directory:
        valid = stat.S_ISDIR(row.st_mode) and int(row.st_nlink) >= 1
    else:
        valid = stat.S_ISREG(row.st_mode) and (
            not executable or bool(int(row.st_mode) & 0o111)
        )
    if not valid:
        raise LinuxGuestScopeError(
            "guest-scope descriptor has the wrong object type",
            reason_code="DESCRIPTOR_TYPE_INVALID",
        )
    return {
        "device": int(row.st_dev),
        "inode": int(row.st_ino),
        "mode": int(row.st_mode),
        "owner_uid": int(row.st_uid),
        "owner_gid": int(row.st_gid),
        "link_count": int(row.st_nlink),
        "size": int(row.st_size),
        "mtime_ns": int(row.st_mtime_ns),
        "ctime_ns": int(row.st_ctime_ns),
    }


def _file_identity(
    descriptor: int,
    *,
    maximum_bytes: int,
    executable: bool,
    require_elf: bool,
    require_root_owner: bool,
) -> dict[str, Any]:
    posix_fcntl = _require_posix_fcntl()
    base = _descriptor_identity(
        descriptor,
        directory=False,
        executable=executable,
    )
    try:
        before_flags = posix_fcntl.fcntl(descriptor, posix_fcntl.F_GETFL)
        if (before_flags & os.O_ACCMODE) != os.O_RDONLY:
            raise LinuxGuestScopeError(
                "pinned guest executable descriptor is not read-only",
                reason_code="EXECUTABLE_ACCESS_INVALID",
            )
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        prefix = b""
        offset = 0
        while offset <= maximum_bytes:
            chunk = os.pread(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - offset),
                offset,
            )
            if not chunk:
                break
            if offset == 0:
                prefix = chunk[:4]
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        after_flags = posix_fcntl.fcntl(descriptor, posix_fcntl.F_GETFL)
        if (
            (after_flags & os.O_ACCMODE) != os.O_RDONLY
            or (before_flags & os.O_ACCMODE)
            != (after_flags & os.O_ACCMODE)
        ):
            raise LinuxGuestScopeError(
                "pinned guest executable descriptor access changed during replay",
                reason_code="EXECUTABLE_ACCESS_INVALID",
            )
    except LinuxGuestScopeError:
        raise
    except OSError:
        raise LinuxGuestScopeError(
            "pinned guest executable material is unavailable",
            reason_code="EXECUTABLE_MATERIAL_UNAVAILABLE",
        ) from None
    before_identity = _stat_identity(before)
    after_identity = _stat_identity(after)
    if (
        offset <= 0
        or offset > maximum_bytes
        or offset != int(before.st_size)
        or before_identity != after_identity
        or int(before.st_nlink) != 1
        or int(before.st_mode) & 0o022
        or (require_root_owner and int(before.st_uid) != 0)
        or (require_elf and prefix != b"\x7fELF")
    ):
        raise LinuxGuestScopeError(
            "pinned guest executable material violates the closed policy",
            reason_code="EXECUTABLE_MATERIAL_INVALID",
        )
    result: dict[str, Any] = dict(base)
    result.update(
        {
            "size": offset,
            "mtime_ns": int(before.st_mtime_ns),
            "ctime_ns": int(before.st_ctime_ns),
            "sha256": digest.hexdigest(),
            "format": "ELF" if require_elf else "PYTHON_SOURCE",
            "access_mode": "O_RDONLY",
        }
    )
    return result


def _runtime_roster_identity(
    descriptors: Sequence[int],
    *,
    require_root_owner: bool,
    mount_observer: Callable[[int], Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, int]], str]:
    _require_posix_fcntl()
    if not 1 <= len(descriptors) <= MAX_RUNTIME_ROOTS:
        raise LinuxGuestScopeError(
            "runtime root roster is outside the closed policy",
            reason_code="RUNTIME_ROOTS_INVALID",
        )
    identities = [
        _descriptor_identity(descriptor, directory=True)
        for descriptor in descriptors
    ]
    for descriptor, identity in zip(descriptors, identities, strict=True):
        proof = _runtime_native_proof(descriptor, observer=mount_observer)
        identity["mount_id"] = int(proof["mount_id"])
        identity["mount_read_only"] = 1
        identity["inode_flags"] = int(proof["inode_flags"])
        identity["xattr_count"] = 0
    if any(
        identity["mode"] & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o022)
        or (require_root_owner and identity["owner_uid"] != 0)
        for identity in identities
    ):
        raise LinuxGuestScopeError(
            "runtime roots are not immutable to the dropped principal",
            reason_code="RUNTIME_ROOTS_INVALID",
        )
    manifest = hashlib.sha256()
    state: dict[str, Any] = {
        "entries": 0,
        "bytes": 0,
        "observer": mount_observer,
        "require_root_owner": require_root_owner,
    }
    for index, (descriptor, identity) in enumerate(
        zip(descriptors, identities, strict=True)
    ):
        state["root_mount_id"] = identity["mount_id"]
        _manifest_record(
            manifest,
            (
                b"R",
                str(index).encode("ascii"),
                *(str(identity[name]).encode("ascii") for name in (
                    "device", "inode", "mode", "owner_uid", "owner_gid",
                    "link_count", "size", "mtime_ns", "ctime_ns",
                    "inode_flags", "xattr_count",
                )),
            ),
        )
        _manifest_directory(
            descriptor,
            root_index=index,
            relative=b"",
            depth=0,
            digest=manifest,
            state=state,
        )
    return identities, manifest.hexdigest()


def _runtime_native_proof(
    descriptor: int,
    *,
    observer: Callable[[int], Mapping[str, Any]] | None,
) -> Mapping[str, Any]:
    _require_posix_fcntl()
    if observer is None:
        posix_fcntl = _require_posix_fcntl()
        try:
            filesystem = os.fstatvfs(descriptor)
            info_fd = os.open(
                f"/proc/self/fdinfo/{descriptor}",
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                captured = bytearray()
                while len(captured) <= 4096:
                    chunk = os.read(info_fd, 4097 - len(captured))
                    if not chunk:
                        break
                    captured.extend(chunk)
                raw = bytes(captured)
            finally:
                os.close(info_fd)
            match = re.search(rb"(?:^|\n)mnt_id:\s*([1-9][0-9]*)\n", raw)
            ioctl_result = posix_fcntl.ioctl(
                descriptor,
                FS_IOC_GETFLAGS,
                struct.pack("=I", 0),
            )
            proof: Mapping[str, Any] = {
                "mount_id": (
                    int(match.group(1))
                    if match is not None and len(raw) <= 4096
                    else 0
                ),
                "read_only": bool(
                    int(filesystem.f_flag) & int(getattr(os, "ST_RDONLY", 1))
                ),
                "xattrs_empty": len(os.listxattr(descriptor)) == 0,
                "inode_flags": struct.unpack("=I", ioctl_result[:4])[0],
            }
        except (OSError, TypeError, ValueError, struct.error):
            raise LinuxGuestScopeError(
                "runtime native metadata proof is unavailable",
                reason_code="RUNTIME_METADATA_UNAVAILABLE",
            ) from None
    else:
        try:
            proof = observer(descriptor)
        except BaseException:
            raise LinuxGuestScopeError(
                "runtime native metadata observer failed",
                reason_code="RUNTIME_METADATA_UNAVAILABLE",
            ) from None
    if (
        not isinstance(proof, Mapping)
        or set(proof)
        != {"mount_id", "read_only", "xattrs_empty", "inode_flags"}
        or isinstance(proof.get("mount_id"), bool)
        or not isinstance(proof.get("mount_id"), int)
        or int(proof["mount_id"]) <= 0
        or isinstance(proof.get("inode_flags"), bool)
        or not isinstance(proof.get("inode_flags"), int)
        or not 0 <= int(proof["inode_flags"]) <= 0xFFFFFFFF
    ):
        raise LinuxGuestScopeError(
            "runtime native metadata proof is malformed",
            reason_code="RUNTIME_METADATA_INVALID",
        )
    if proof.get("read_only") is not True:
        raise LinuxGuestScopeError(
            "runtime roots lack immutable read-only mount proof",
            reason_code="RUNTIME_MOUNT_PROOF_INVALID",
        )
    if (
        proof.get("xattrs_empty") is not True
        or int(proof["inode_flags"]) & ~RUNTIME_SAFE_INODE_FLAGS
    ):
        raise LinuxGuestScopeError(
            "runtime native metadata violates the closed policy",
            reason_code="RUNTIME_METADATA_INVALID",
        )
    return proof


def _manifest_record(digest: Any, fields: Sequence[bytes]) -> None:
    for field in fields:
        digest.update(str(len(field)).encode("ascii"))
        digest.update(b":")
        digest.update(field)
        digest.update(b";")


def _manifest_stat_fields(row: os.stat_result) -> tuple[bytes, ...]:
    return tuple(
        str(int(value)).encode("ascii")
        for value in (
            row.st_dev,
            row.st_ino,
            row.st_mode,
            row.st_uid,
            row.st_gid,
            row.st_nlink,
            row.st_size,
            row.st_mtime_ns,
            row.st_ctime_ns,
        )
    )


def _manifest_directory(
    descriptor: int,
    *,
    root_index: int,
    relative: bytes,
    depth: int,
    digest: Any,
    state: dict[str, Any],
) -> None:
    if depth >= MAX_RUNTIME_MANIFEST_DEPTH:
        raise LinuxGuestScopeError(
            "runtime manifest exceeds its depth policy",
            reason_code="RUNTIME_MANIFEST_INVALID",
        )
    try:
        before = os.fstat(descriptor)
        names = sorted(os.fsencode(name) for name in os.listdir(descriptor))
    except OSError:
        raise LinuxGuestScopeError(
            "runtime manifest is unavailable",
            reason_code="RUNTIME_MANIFEST_UNAVAILABLE",
        ) from None
    if len(names) > MAX_RUNTIME_DIRECTORY_ENTRIES:
        raise LinuxGuestScopeError(
            "runtime manifest exceeds its directory policy",
            reason_code="RUNTIME_MANIFEST_INVALID",
        )
    for name in names:
        state["entries"] += 1
        if state["entries"] > MAX_RUNTIME_ENTRIES or name in {b"", b".", b".."}:
            raise LinuxGuestScopeError(
                "runtime manifest exceeds its entry policy",
                reason_code="RUNTIME_MANIFEST_INVALID",
            )
        path = name if not relative else relative + b"/" + name
        try:
            row = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            raise LinuxGuestScopeError(
                "runtime manifest is unavailable",
                reason_code="RUNTIME_MANIFEST_UNAVAILABLE",
            ) from None
        if (
            int(row.st_mode) & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o022)
            or (state["require_root_owner"] and int(row.st_uid) != 0)
        ):
            raise LinuxGuestScopeError(
                "runtime manifest contains unsafe ownership or mode metadata",
                reason_code="RUNTIME_METADATA_INVALID",
            )
        child = -1
        inode_flags = 0
        if stat.S_ISDIR(row.st_mode):
            kind = b"D"
            content = b"-"
            try:
                child = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                if _stat_identity(os.fstat(child)) != _stat_identity(row):
                    raise OSError("runtime directory changed")
                proof = _runtime_native_proof(
                    child,
                    observer=state["observer"],
                )
                if int(proof["mount_id"]) != int(state["root_mount_id"]):
                    raise LinuxGuestScopeError(
                        "runtime manifest contains a nested or bind mount",
                        reason_code="RUNTIME_NESTED_MOUNT",
                    )
                inode_flags = int(proof["inode_flags"])
            except LinuxGuestScopeError:
                if child >= 0:
                    os.close(child)
                raise
            except OSError:
                if child >= 0:
                    os.close(child)
                raise LinuxGuestScopeError(
                    "runtime directory manifest drifted",
                    reason_code="RUNTIME_MANIFEST_UNAVAILABLE",
                ) from None
        elif stat.S_ISREG(row.st_mode):
            if int(row.st_nlink) != 1:
                raise LinuxGuestScopeError(
                    "runtime manifests reject hard-linked regular files",
                    reason_code="RUNTIME_HARDLINK_INVALID",
                )
            kind = b"F"
            content, inode_flags = _manifest_regular_file(
                descriptor,
                name,
                row,
                state,
            )
        elif stat.S_ISLNK(row.st_mode):
            raise LinuxGuestScopeError(
                "runtime manifests reject every symbolic link",
                reason_code="RUNTIME_SYMLINK_INVALID",
            )
        else:
            raise LinuxGuestScopeError(
                "runtime manifest contains an unsupported object",
                reason_code="RUNTIME_MANIFEST_INVALID",
            )
        if state["bytes"] > MAX_RUNTIME_TOTAL_BYTES:
            raise LinuxGuestScopeError(
                "runtime manifest exceeds its byte policy",
                reason_code="RUNTIME_MANIFEST_INVALID",
            )
        _manifest_record(
            digest,
            (
                b"E",
                str(root_index).encode("ascii"),
                path,
                kind,
                *_manifest_stat_fields(row),
                str(inode_flags).encode("ascii"),
                b"0",
                content,
            ),
        )
        if kind == b"D":
            try:
                _manifest_directory(
                    child,
                    root_index=root_index,
                    relative=path,
                    depth=depth + 1,
                    digest=digest,
                    state=state,
                )
            finally:
                if child >= 0:
                    os.close(child)
    try:
        after_directory = os.fstat(descriptor)
    except OSError:
        raise LinuxGuestScopeError(
            "runtime directory manifest replay failed",
            reason_code="RUNTIME_MANIFEST_UNAVAILABLE",
        ) from None
    if _stat_identity(before) != _stat_identity(after_directory):
        raise LinuxGuestScopeError(
            "runtime directory manifest drifted",
            reason_code="RUNTIME_MANIFEST_INVALID",
        )


def _manifest_regular_file(
    directory_fd: int,
    name: bytes,
    expected: os.stat_result,
    state: dict[str, Any],
) -> tuple[bytes, int]:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(descriptor)
        if int(before.st_nlink) != 1:
            raise LinuxGuestScopeError(
                "runtime manifests reject hard-linked regular files",
                reason_code="RUNTIME_HARDLINK_INVALID",
            )
        if (
            _stat_identity(before) != _stat_identity(expected)
            or int(before.st_size) < 0
            or int(before.st_size) > MAX_RUNTIME_FILE_BYTES
        ):
            raise OSError("runtime file changed")
        proof = _runtime_native_proof(
            descriptor,
            observer=state["observer"],
        )
        if int(proof["mount_id"]) != int(state["root_mount_id"]):
            raise LinuxGuestScopeError(
                "runtime manifest contains a nested or bind mount",
                reason_code="RUNTIME_NESTED_MOUNT",
            )
        file_digest = hashlib.sha256()
        offset = 0
        while offset < int(before.st_size):
            chunk = os.pread(
                descriptor,
                min(64 * 1024, int(before.st_size) - offset),
                offset,
            )
            if not chunk:
                raise OSError("runtime file read was short")
            file_digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise OSError("runtime file changed")
    except LinuxGuestScopeError:
        raise
    except OSError:
        raise LinuxGuestScopeError(
            "runtime file manifest drifted",
            reason_code="RUNTIME_MANIFEST_UNAVAILABLE",
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    state["bytes"] += offset
    return (
        file_digest.hexdigest().encode("ascii"),
        int(proof["inode_flags"]),
    )


def _directory_contains(ancestor_fd: int, descendant_fd: int) -> bool:
    ancestor = os.fstat(ancestor_fd)
    current = os.dup(descendant_fd)
    try:
        for _ in range(MAX_TOPOLOGY_DEPTH):
            row = os.fstat(current)
            if (row.st_dev, row.st_ino) == (ancestor.st_dev, ancestor.st_ino):
                return True
            parent = os.open(
                "..",
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            parent_row = os.fstat(parent)
            if (parent_row.st_dev, parent_row.st_ino) == (row.st_dev, row.st_ino):
                os.close(parent)
                return False
            os.close(current)
            current = parent
    except OSError:
        raise LinuxGuestScopeError(
            "guest root topology could not be replayed",
            reason_code="ROOT_TOPOLOGY_UNAVAILABLE",
        ) from None
    finally:
        os.close(current)
    raise LinuxGuestScopeError(
        "guest root topology exceeds its closed depth policy",
        reason_code="ROOT_TOPOLOGY_UNAVAILABLE",
    )


def _reject_root_overlap(descriptors: Sequence[int]) -> None:
    roots = tuple(descriptors)
    for index, left in enumerate(roots):
        for right in roots[index + 1 :]:
            if _directory_contains(left, right) or _directory_contains(right, left):
                raise LinuxGuestScopeError(
                    "guest roots overlap by ancestor topology",
                    reason_code="ROOT_TOPOLOGY_OVERLAP",
                )


def _stat_identity(row: os.stat_result) -> dict[str, int]:
    return {
        "size": int(row.st_size),
        "device": int(row.st_dev),
        "inode": int(row.st_ino),
        "mode": int(row.st_mode),
        "owner_uid": int(row.st_uid),
        "owner_gid": int(row.st_gid),
        "link_count": int(row.st_nlink),
        "mtime_ns": int(row.st_mtime_ns),
        "ctime_ns": int(row.st_ctime_ns),
    }


def _read_source_fd(descriptor: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        captured = bytearray()
        while len(captured) <= MAX_HELPER_SOURCE_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_HELPER_SOURCE_BYTES + 1 - len(captured)),
            )
            if not chunk:
                break
            captured.extend(chunk)
    except OSError:
        raise LinuxGuestScopeError(
            "Linux guest helper source is unavailable",
            reason_code="HELPER_SOURCE_UNAVAILABLE",
        ) from None
    if not captured or len(captured) > MAX_HELPER_SOURCE_BYTES:
        raise LinuxGuestScopeError(
            "Linux guest helper source exceeds its closed size policy",
            reason_code="HELPER_SOURCE_INVALID",
        )
    return bytes(captured)


def _open_source_snapshot() -> tuple[int, dict[str, Any]]:
    descriptor = -1
    try:
        descriptor = os.open(
            _HELPER_SOURCE,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        named = _HELPER_SOURCE.stat(follow_symlinks=False)
        raw = _read_source_fd(descriptor)
        after = os.fstat(descriptor)
        named_after = _HELPER_SOURCE.stat(follow_symlinks=False)
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        raise LinuxGuestScopeError(
            "Linux guest helper source is unavailable",
            reason_code="HELPER_SOURCE_UNAVAILABLE",
        ) from None
    except LinuxGuestScopeError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or int(before.st_nlink) != 1
        or _stat_identity(before) != _stat_identity(named)
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(before) != _stat_identity(named_after)
        or len(raw) != int(before.st_size)
    ):
        os.close(descriptor)
        raise LinuxGuestScopeError(
            "Linux guest helper source authority is invalid",
            reason_code="HELPER_SOURCE_INVALID",
        )
    identity: dict[str, Any] = _stat_identity(before)
    identity["sha256"] = hashlib.sha256(raw).hexdigest()
    return descriptor, identity


def _replay_source_snapshot(
    descriptor: int,
    expected: Mapping[str, Any],
) -> None:
    raw = _read_source_fd(descriptor)
    try:
        row = os.fstat(descriptor)
        named = _HELPER_SOURCE.stat(follow_symlinks=False)
    except OSError:
        raise LinuxGuestScopeError(
            "Linux guest helper source replay failed",
            reason_code="HELPER_SOURCE_DRIFT",
        ) from None
    identity: dict[str, Any] = _stat_identity(row)
    identity["sha256"] = hashlib.sha256(raw).hexdigest()
    if (
        identity != dict(expected)
        or _stat_identity(row) != _stat_identity(named)
        or stat.S_ISLNK(named.st_mode)
    ):
        raise LinuxGuestScopeError(
            "Linux guest helper source drifted during materialization",
            reason_code="HELPER_SOURCE_DRIFT",
        )


def _source_identity() -> dict[str, Any]:
    descriptor, identity = _open_source_snapshot()
    os.close(descriptor)
    return identity


def build_guest_binding(
    *,
    cgroup_parent_fd: int,
    overlay_storage_fd: int,
    interpreter_fd: int,
    driver_script_fd: int,
    runtime_root_fds: Sequence[int],
    expected_interpreter_sha256: str,
    expected_driver_script_sha256: str,
    expected_runtime_roster_sha256: str,
    read_only_root_fds: Sequence[int],
    writable_root_fds: Sequence[int],
    target_uid: int,
    target_gid: int,
    limits: LinuxGuestLimits,
    attempt_id: str,
    driver_argv: Sequence[str],
    admission: Mapping[str, Any] | None = None,
    runtime_mount_observer: Callable[[int], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create the canonical descriptor/host binding consumed by receipts."""

    _require_posix_fcntl()
    limits.validate()
    if not _is_hex256(attempt_id):
        raise LinuxGuestScopeError(
            "attempt identity must be lowercase sha256 text",
            reason_code="ATTEMPT_ID_INVALID",
        )
    if (
        isinstance(target_uid, bool)
        or not isinstance(target_uid, int)
        or not 1 <= target_uid < 2**32 - 1
        or isinstance(target_gid, bool)
        or not isinstance(target_gid, int)
        or not 1 <= target_gid < 2**32 - 1
    ):
        raise LinuxGuestScopeError(
            "target uid/gid must be non-root uint32 values",
            reason_code="PRINCIPAL_INVALID",
        )
    read_only = tuple(read_only_root_fds)
    writable = tuple(writable_root_fds)
    runtime = tuple(runtime_root_fds)
    if (
        not 1 <= len(read_only) <= MAX_ROOTS
        or not 1 <= len(writable) <= MAX_ROOTS
    ):
        raise LinuxGuestScopeError(
            "guest scope requires bounded read-only and writable roots",
            reason_code="ROOT_SET_INVALID",
        )
    command = _command_identity(driver_argv)
    all_fds = (
        cgroup_parent_fd,
        overlay_storage_fd,
        interpreter_fd,
        driver_script_fd,
        *runtime,
        *read_only,
        *writable,
    )
    if len(set(all_fds)) != len(all_fds):
        raise LinuxGuestScopeError(
            "guest-scope descriptors must be unique capabilities",
            reason_code="DESCRIPTOR_ALIAS",
        )
    if any(
        descriptor in {
            INTERPRETER_EXEC_FD - 1,
            INTERPRETER_EXEC_FD,
            DRIVER_SCRIPT_EXEC_FD,
        }
        for descriptor in all_fds
    ):
        raise LinuxGuestScopeError(
            "guest-scope descriptors collide with reserved execution slots",
            reason_code="DESCRIPTOR_INVALID",
        )
    host = dict(admission) if admission is not None else _exact_host_admission()
    require_root_owner = admission is None
    if admission is None and runtime_mount_observer is not None:
        raise LinuxGuestScopeError(
            "runtime mount proof overrides are restricted to injected tests",
            reason_code="TEST_OVERRIDE_FORBIDDEN",
        )
    cgroup_identity = _descriptor_identity(cgroup_parent_fd, directory=True)
    overlay_storage_identity = _descriptor_identity(
        overlay_storage_fd,
        directory=True,
    )
    interpreter_identity = _file_identity(
        interpreter_fd,
        maximum_bytes=MAX_INTERPRETER_BYTES,
        executable=True,
        require_elf=True,
        require_root_owner=require_root_owner,
    )
    driver_identity = _file_identity(
        driver_script_fd,
        maximum_bytes=MAX_DRIVER_SCRIPT_BYTES,
        executable=False,
        require_elf=False,
        require_root_owner=require_root_owner,
    )
    runtime_identities, runtime_digest = _runtime_roster_identity(
        runtime,
        require_root_owner=require_root_owner,
        mount_observer=runtime_mount_observer,
    )
    if (
        not _is_hex256(expected_interpreter_sha256)
        or interpreter_identity["sha256"] != expected_interpreter_sha256
    ):
        raise LinuxGuestScopeError(
            "pinned Python interpreter identity does not match the image lock",
            reason_code="INTERPRETER_SUBSTITUTION",
        )
    if (
        not _is_hex256(expected_driver_script_sha256)
        or driver_identity["sha256"] != expected_driver_script_sha256
    ):
        raise LinuxGuestScopeError(
            "pinned driver script identity does not match the image lock",
            reason_code="DRIVER_SCRIPT_MUTATION",
        )
    if (
        not _is_hex256(expected_runtime_roster_sha256)
        or runtime_digest != expected_runtime_roster_sha256
    ):
        raise LinuxGuestScopeError(
            "runtime root roster widens the pinned image policy",
            reason_code="RUNTIME_ROOTS_WIDENED",
        )
    read_only_identities = [
        _descriptor_identity(fd, directory=True) for fd in read_only
    ]
    writable_identities = [
        _descriptor_identity(fd, directory=True) for fd in writable
    ]
    object_identities = (
        cgroup_identity,
        overlay_storage_identity,
        interpreter_identity,
        driver_identity,
        *runtime_identities,
        *read_only_identities,
        *writable_identities,
    )
    object_keys = [
        (identity["device"], identity["inode"]) for identity in object_identities
    ]
    if len(set(object_keys)) != len(object_keys):
        raise LinuxGuestScopeError(
            "guest-scope descriptors alias the same kernel object",
            reason_code="DESCRIPTOR_ALIAS",
        )
    _reject_root_overlap((overlay_storage_fd, *runtime, *read_only, *writable))
    replayed_runtime, replayed_runtime_digest = _runtime_roster_identity(
        runtime,
        require_root_owner=require_root_owner,
        mount_observer=runtime_mount_observer,
    )
    replayed_read_only = [
        _descriptor_identity(fd, directory=True) for fd in read_only
    ]
    replayed_writable = [
        _descriptor_identity(fd, directory=True) for fd in writable
    ]
    if (
        _descriptor_identity(overlay_storage_fd, directory=True)
        != overlay_storage_identity
        or replayed_runtime != runtime_identities
        or replayed_runtime_digest != runtime_digest
        or replayed_read_only != read_only_identities
        or replayed_writable != writable_identities
    ):
        raise LinuxGuestScopeError(
            "guest root identity drifted during topology validation",
            reason_code="ROOT_TOPOLOGY_UNAVAILABLE",
        )
    binding = {
        "schema": RECEIPT_SCHEMA,
        "host": host,
        "helper_source": _source_identity(),
        "attempt_id": attempt_id,
        "target_uid": target_uid,
        "target_gid": target_gid,
        "invocation": command,
        "limits": {
            "pids_max": limits.pids_max,
            "memory_max": limits.memory_max,
            "cpu_quota": limits.cpu_quota,
            "cpu_period": limits.cpu_period,
            "wall_time_ms": limits.wall_time_ms,
        },
        "cgroup_parent": cgroup_identity,
        "overlay_storage": overlay_storage_identity,
        "interpreter": interpreter_identity,
        "driver_script": driver_identity,
        "runtime_roots": runtime_identities,
        "runtime_roster_sha256": runtime_digest,
        "image_lock": {
            "interpreter_sha256": expected_interpreter_sha256,
            "driver_script_sha256": expected_driver_script_sha256,
            "runtime_roster_sha256": expected_runtime_roster_sha256,
        },
        "read_only_roots": read_only_identities,
        "writable_roots": writable_identities,
        "overlay": {
            "lower_root_index": 0,
            "storage_capability": "DEDICATED_NOT_LANDLOCK_GRANTED",
            "host_target_write_policy": "READ_ONLY_BIND_LOWER",
            "merged_write_policy": "LANDLOCK_READ_ONLY",
        },
        "network_isolation_claimed": False,
        "shell_used": False,
    }
    return json.loads(_canonical_json(binding).decode("ascii"))


def binding_sha256(binding: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(binding)).hexdigest()


def _command_identity(command_argv: Sequence[str]) -> dict[str, Any]:
    if isinstance(command_argv, (str, bytes)):
        raise LinuxGuestScopeError(
            "guest command protocol is malformed",
            reason_code="COMMAND_INVALID",
        )
    try:
        driver_arguments = tuple(command_argv)
    except TypeError:
        raise LinuxGuestScopeError(
            "guest command protocol is malformed",
            reason_code="COMMAND_INVALID",
        ) from None
    command = (
        INTERPRETER_ARGUMENT,
        *INTERPRETER_FLAGS,
        DRIVER_SCRIPT_ARGUMENT,
        *driver_arguments,
    )
    try:
        encoded = tuple(item.encode("utf-8") for item in command)
    except (AttributeError, UnicodeEncodeError):
        raise LinuxGuestScopeError(
            "guest command protocol is malformed",
            reason_code="COMMAND_INVALID",
        ) from None
    if (
        not 1 <= len(command) <= MAX_COMMAND_ARGS
        or any(not item or "\x00" in item for item in command)
        or any(len(item) > 4096 for item in encoded)
        or sum(len(item) + 1 for item in encoded) > MAX_COMMAND_BYTES
    ):
        raise LinuxGuestScopeError(
            "guest command protocol is malformed",
            reason_code="COMMAND_INVALID",
        )
    canonical = b"".join(
        str(len(item)).encode("ascii") + b":" + item + b";"
        for item in encoded
    )
    return {
        "argc": len(command),
        "encoded_bytes": sum(len(item) + 1 for item in encoded),
        "argv_sha256": hashlib.sha256(canonical).hexdigest(),
        "interpreter_argv0": INTERPRETER_ARGUMENT,
        "driver_script_argv": DRIVER_SCRIPT_ARGUMENT,
        "fixed_interpreter_flags": list(INTERPRETER_FLAGS),
        "driver_argc": len(driver_arguments),
    }


def _helper_executable(
    *,
    expected_source: Mapping[str, Any] | None = None,
) -> Path:
    _require_posix_fcntl()
    global _HELPER_DIRECTORY, _HELPER_PATH, _HELPER_SOURCE_IDENTITY
    _exact_host_admission()
    with _HELPER_LOCK:
        source_fd, source_identity = _open_source_snapshot()
        if expected_source is not None and source_identity != dict(expected_source):
            os.close(source_fd)
            raise LinuxGuestScopeError(
                "Linux guest helper source binding drifted",
                reason_code="HELPER_SOURCE_DRIFT",
            )
        if _HELPER_PATH is not None:
            os.close(source_fd)
            if source_identity != _HELPER_SOURCE_IDENTITY:
                raise LinuxGuestScopeError(
                    "cached Linux guest helper no longer matches its source",
                    reason_code="HELPER_SOURCE_DRIFT",
                )
            return _HELPER_PATH
        compiler = Path("/usr/bin/cc")
        try:
            compiler_row = compiler.stat()
        except OSError:
            os.close(source_fd)
            raise LinuxGuestScopeError(
                "exact Linux C compiler is unavailable",
                reason_code="COMPILER_UNAVAILABLE",
            ) from None
        if (
            not stat.S_ISREG(compiler_row.st_mode)
            or int(compiler_row.st_uid) != 0
            or int(compiler_row.st_mode) & 0o022
        ):
            os.close(source_fd)
            raise LinuxGuestScopeError(
                "Linux C compiler authority is invalid",
                reason_code="COMPILER_INVALID",
            )
        try:
            directory = tempfile.TemporaryDirectory(prefix="plamen-linux-scope-")
        except OSError:
            os.close(source_fd)
            raise LinuxGuestScopeError(
                "private Linux helper build directory is unavailable",
                reason_code="HELPER_BUILD_FAILED",
            ) from None
        output = Path(directory.name) / "linux_guest_scope_helper"
        argv = (
            "/usr/bin/cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=3",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,now",
            "-o",
            os.fspath(output),
            "-x",
            "c",
            f"/proc/self/fd/{source_fd}",
        )
        try:
            result = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd="/",
                env={},
                shell=False,
                close_fds=True,
                pass_fds=(source_fd,),
                timeout=30.0,
                check=False,
            )
            _replay_source_snapshot(source_fd, source_identity)
        except (OSError, subprocess.TimeoutExpired):
            os.close(source_fd)
            directory.cleanup()
            raise LinuxGuestScopeError(
                "Linux guest helper compilation failed",
                reason_code="HELPER_BUILD_FAILED",
            ) from None
        except LinuxGuestScopeError:
            os.close(source_fd)
            directory.cleanup()
            raise
        os.close(source_fd)
        if result.returncode != 0:
            directory.cleanup()
            raise LinuxGuestScopeError(
                "Linux guest helper compilation failed",
                reason_code="HELPER_BUILD_FAILED",
            )
        output.chmod(0o500)
        row = output.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(row.st_mode)
            or int(row.st_uid) != os.geteuid()
            or stat.S_IMODE(row.st_mode) != 0o500
            or int(row.st_nlink) != 1
        ):
            directory.cleanup()
            raise LinuxGuestScopeError(
                "compiled Linux helper authority is invalid",
                reason_code="HELPER_BUILD_INVALID",
            )
        _HELPER_DIRECTORY = directory
        _HELPER_PATH = output
        _HELPER_SOURCE_IDENTITY = source_identity
        return output


def _parse_receipt(
    raw: bytes,
    *,
    authentication_key: bytes | bytearray,
    expected_attempt: str,
    expected_binding: str,
    expected_phase: str,
) -> dict[str, str]:
    if (
        not isinstance(raw, bytes)
        or len(raw) > MAX_RECEIPT_BYTES
        or not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
    ):
        raise LinuxGuestScopeError(
            "Linux guest receipt framing is invalid",
            reason_code="RECEIPT_INVALID",
        )
    try:
        text = raw[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise LinuxGuestScopeError(
            "Linux guest receipt encoding is invalid",
            reason_code="RECEIPT_INVALID",
        ) from None
    prefix = "PLAMEN_LINUX_SCOPE "
    if not text.startswith(prefix) or ";mac=" not in text:
        raise LinuxGuestScopeError(
            "Linux guest receipt framing is invalid",
            reason_code="RECEIPT_INVALID",
        )
    payload, mac = text[len(prefix) :].rsplit(";mac=", 1)
    if _HEX_256.fullmatch(mac) is None:
        raise LinuxGuestScopeError(
            "Linux guest receipt authenticator is invalid",
            reason_code="RECEIPT_INVALID",
        )
    expected_mac = hmac.new(
        authentication_key,
        payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(mac, expected_mac):
        raise LinuxGuestScopeError(
            "Linux guest receipt authentication failed",
            reason_code="RECEIPT_AUTHENTICATION_FAILED",
        )
    fields: dict[str, str] = {}
    ordered_names: list[str] = []
    for item in payload.split(";"):
        if item.count("=") != 1:
            raise LinuxGuestScopeError(
                "Linux guest receipt fields are invalid",
                reason_code="RECEIPT_INVALID",
            )
        name, value = item.split("=", 1)
        if (
            not name
            or name in fields
            or _FIELD.fullmatch(name) is None
            or _FIELD.fullmatch(value) is None
        ):
            raise LinuxGuestScopeError(
                "Linux guest receipt fields are invalid",
                reason_code="RECEIPT_INVALID",
            )
        fields[name] = value
        ordered_names.append(name)
    if expected_phase == "READY":
        expected_fields = READY_RECEIPT_FIELDS
    elif expected_phase == "FINAL":
        expected_fields = FINAL_RECEIPT_FIELDS
    else:
        raise LinuxGuestScopeError(
            "Linux guest receipt phase policy is invalid",
            reason_code="RECEIPT_INVALID",
        )
    if tuple(ordered_names) != expected_fields:
        raise LinuxGuestScopeError(
            "Linux guest receipt schema is not exact and canonical",
            reason_code="RECEIPT_INVALID",
        )
    if (
        fields.get("schema") != RECEIPT_SCHEMA
        or fields.get("phase") != expected_phase
        or fields.get("attempt") != expected_attempt
        or fields.get("binding") != expected_binding
    ):
        raise LinuxGuestScopeError(
            "Linux guest receipt binding drifted",
            reason_code="RECEIPT_BINDING_DRIFT",
        )
    return fields


def _validate_ready_receipt(
    fields: Mapping[str, str],
    *,
    limits: LinuxGuestLimits,
    target_uid: int,
    target_gid: int,
    attempt_id: str,
    binding: Mapping[str, Any] | None = None,
) -> None:
    expected = {
        "cgroup_name": f"plamen-{attempt_id}",
        "pids_max": str(limits.pids_max),
        "memory_max": str(limits.memory_max),
        "cpu_quota": str(limits.cpu_quota),
        "cpu_period": str(limits.cpu_period),
        "uid": str(target_uid),
        "gid": str(target_gid),
        "caps_effective": "0",
        "caps_permitted": "0",
        "caps_inheritable": "0",
        "caps_ambient": "0",
        "no_new_privs": "1",
        "mount_propagation": "PRIVATE",
        "interpreter_exec_fd": str(INTERPRETER_EXEC_FD),
        "driver_script_fd": str(DRIVER_SCRIPT_EXEC_FD),
        "surviving_fds": f"0:1:2:{INTERPRETER_EXEC_FD}:{DRIVER_SCRIPT_EXEC_FD}",
        "procfs": "VERIFIED",
        "path_lookup": "0",
        "direct_shebang_exec": "0",
        "runtime_mounts_read_only": "1",
        "interpreter_link_count": "1",
        "interpreter_access_mode": "O_RDONLY",
        "driver_link_count": "1",
        "driver_access_mode": "O_RDONLY",
    }
    if any(fields.get(name) != value for name, value in expected.items()):
        raise LinuxGuestScopeError(
            "Linux guest enforcement posture is incomplete",
            reason_code="ENFORCEMENT_INCOMPLETE",
        )
    positive = (
        "child",
        "cgroup_parent_device",
        "cgroup_parent_inode",
        "cgroup_device",
        "cgroup_inode",
        "landlock_abi",
        "handled_fs",
        "handled_net",
        "lower_device",
        "lower_inode",
        "lower_mount",
        "upper_device",
        "upper_inode",
        "upper_mount",
        "work_device",
        "work_inode",
        "work_mount",
        "merged_device",
        "merged_inode",
        "merged_mount",
        "interpreter_device",
        "interpreter_inode",
        "interpreter_mode",
        "interpreter_size",
        "driver_device",
        "driver_inode",
        "driver_mode",
        "driver_size",
        "runtime_count",
        "overlay_storage_device",
        "overlay_storage_inode",
        "overlay_storage_mount",
    )
    numeric_fields = tuple(
        name
        for name in READY_RECEIPT_FIELDS
        if name
        not in {
            "schema",
            "phase",
            "attempt",
            "binding",
            "cgroup_name",
            "mount_propagation",
            "procfs",
            "surviving_fds",
            "interpreter_sha256",
            "driver_sha256",
            "runtime_roster_sha256",
            "argv_sha256",
            "interpreter_access_mode",
            "driver_access_mode",
        }
    )
    try:
        if any(
            fields[name] != str(int(fields[name], 10))
            or int(fields[name], 10) < 0
            for name in numeric_fields
        ):
            raise ValueError
        values = {name: int(fields[name], 10) for name in positive}
    except (KeyError, ValueError):
        raise LinuxGuestScopeError(
            "Linux guest enforcement identities are malformed",
            reason_code="ENFORCEMENT_INCOMPLETE",
        ) from None
    if (
        any(value <= 0 for value in values.values())
        or values["landlock_abi"] < MIN_LANDLOCK_ABI
        or values["upper_inode"] == values["work_inode"]
    ):
        raise LinuxGuestScopeError(
            "Linux guest enforcement identities are incomplete",
            reason_code="ENFORCEMENT_INCOMPLETE",
        )
    for digest_field in (
        "interpreter_sha256",
        "driver_sha256",
        "runtime_roster_sha256",
        "argv_sha256",
    ):
        if _HEX_256.fullmatch(fields.get(digest_field, "")) is None:
            raise LinuxGuestScopeError(
                "Linux guest executable binding is incomplete",
                reason_code="ENFORCEMENT_INCOMPLETE",
            )
    try:
        owners = {
            name: int(fields[name], 10)
            for name in (
                "interpreter_owner_uid",
                "interpreter_owner_gid",
                "driver_owner_uid",
                "driver_owner_gid",
            )
        }
    except (KeyError, ValueError):
        raise LinuxGuestScopeError(
            "Linux guest executable ownership is malformed",
            reason_code="ENFORCEMENT_INCOMPLETE",
        ) from None
    if any(value < 0 for value in owners.values()):
        raise LinuxGuestScopeError(
            "Linux guest executable ownership is incomplete",
            reason_code="ENFORCEMENT_INCOMPLETE",
        )
    if binding is not None:
        try:
            parent = binding["cgroup_parent"]
            overlay_storage = binding["overlay_storage"]
            lower = binding["read_only_roots"][0]
            interpreter = binding["interpreter"]
            driver = binding["driver_script"]
            exact = (
                values["cgroup_parent_device"] == int(parent["device"])
                and values["cgroup_parent_inode"] == int(parent["inode"])
                and values["overlay_storage_device"]
                == int(overlay_storage["device"])
                and values["overlay_storage_inode"]
                == int(overlay_storage["inode"])
                and values["lower_device"] == int(lower["device"])
                and values["lower_inode"] == int(lower["inode"])
                and values["interpreter_device"] == int(interpreter["device"])
                and values["interpreter_inode"] == int(interpreter["inode"])
                and values["interpreter_mode"] == int(interpreter["mode"])
                and values["interpreter_size"] == int(interpreter["size"])
                and owners["interpreter_owner_uid"]
                == int(interpreter["owner_uid"])
                and owners["interpreter_owner_gid"]
                == int(interpreter["owner_gid"])
                and fields["interpreter_access_mode"]
                == interpreter["access_mode"]
                and fields["interpreter_sha256"] == interpreter["sha256"]
                and values["driver_device"] == int(driver["device"])
                and values["driver_inode"] == int(driver["inode"])
                and values["driver_mode"] == int(driver["mode"])
                and values["driver_size"] == int(driver["size"])
                and owners["driver_owner_uid"] == int(driver["owner_uid"])
                and owners["driver_owner_gid"] == int(driver["owner_gid"])
                and fields["driver_access_mode"] == driver["access_mode"]
                and fields["driver_sha256"] == driver["sha256"]
                and values["runtime_count"] == len(binding["runtime_roots"])
                and fields["runtime_roster_sha256"]
                == binding["runtime_roster_sha256"]
                and fields["argv_sha256"] == binding["invocation"]["argv_sha256"]
            )
        except (IndexError, KeyError, TypeError, ValueError):
            exact = False
        if not exact:
            raise LinuxGuestScopeError(
                "Linux guest retained-descriptor identities drifted",
                reason_code="ENFORCEMENT_IDENTITY_DRIFT",
            )


def _validate_final_receipt(fields: Mapping[str, str]) -> None:
    try:
        wait_status = int(fields["wait_status"], 10)
        canonical = fields["wait_status"] == str(wait_status)
    except (KeyError, ValueError):
        canonical = False
        wait_status = -1
    if (
        not canonical
        or wait_status < 0
        or wait_status > 2**31 - 1
        or fields.get("interpreter_access_mode") != "O_RDONLY"
        or fields.get("driver_access_mode") != "O_RDONLY"
        or fields.get("timed_out") not in {"0", "1"}
        or fields.get("exec_verified") != "1"
        or fields.get("cleanup") != "COMPLETE"
    ):
        raise LinuxGuestScopeError(
            "Linux guest scope requires descriptor-bound recovery",
            reason_code="RECOVERY_REQUIRED",
        )


def _read_line_bounded(descriptor: int, *, timeout_s: float) -> bytes:
    selector = selectors.DefaultSelector()
    captured = bytearray()
    try:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LinuxGuestScopeError(
                    "Linux guest receipt timed out",
                    reason_code="RECEIPT_TIMEOUT",
                )
            events = selector.select(remaining)
            if not events:
                raise LinuxGuestScopeError(
                    "Linux guest receipt timed out",
                    reason_code="RECEIPT_TIMEOUT",
                )
            chunk = os.read(descriptor, min(1024, MAX_RECEIPT_BYTES + 1 - len(captured)))
            if not chunk:
                raise LinuxGuestScopeError(
                    "Linux guest receipt channel closed",
                    reason_code="RECEIPT_UNAVAILABLE",
                )
            captured.extend(chunk)
            newline = captured.find(b"\n")
            if newline >= 0:
                if newline != len(captured) - 1:
                    raise LinuxGuestScopeError(
                        "Linux guest receipt contains trailing bytes",
                        reason_code="RECEIPT_INVALID",
                    )
                return bytes(captured)
            if len(captured) > MAX_RECEIPT_BYTES:
                raise LinuxGuestScopeError(
                    "Linux guest receipt exceeds its ceiling",
                    reason_code="RECEIPT_INVALID",
                )
    finally:
        selector.close()


def _build_helper_argv(
    helper: Path,
    *,
    auth_fd: int,
    status_fd: int,
    gate_fd: int,
    cgroup_parent_fd: int,
    overlay_storage_fd: int,
    interpreter_fd: int,
    driver_script_fd: int,
    runtime_root_fds: Sequence[int],
    expected_interpreter_sha256: str,
    expected_driver_script_sha256: str,
    expected_runtime_roster_sha256: str,
    read_only_root_fds: Sequence[int],
    writable_root_fds: Sequence[int],
    target_uid: int,
    target_gid: int,
    limits: LinuxGuestLimits,
    attempt_id: str,
    binding_digest: str,
    driver_argv: Sequence[str],
) -> tuple[str, ...]:
    command = tuple(driver_argv)
    _command_identity(command)
    if any(
        not _is_hex256(value)
        for value in (
            binding_digest,
            expected_interpreter_sha256,
            expected_driver_script_sha256,
            expected_runtime_roster_sha256,
        )
    ):
        raise LinuxGuestScopeError(
            "guest command protocol is malformed",
            reason_code="COMMAND_INVALID",
        )
    result = (
        os.fspath(helper),
        "--v1",
        str(auth_fd),
        str(status_fd),
        str(gate_fd),
        str(cgroup_parent_fd),
        str(overlay_storage_fd),
        str(interpreter_fd),
        str(driver_script_fd),
        str(target_uid),
        str(target_gid),
        str(limits.pids_max),
        str(limits.memory_max),
        str(limits.cpu_quota),
        str(limits.cpu_period),
        str(limits.wall_time_ms),
        attempt_id,
        binding_digest,
        expected_interpreter_sha256,
        expected_driver_script_sha256,
        expected_runtime_roster_sha256,
        str(len(runtime_root_fds)),
        *(str(fd) for fd in runtime_root_fds),
        str(len(read_only_root_fds)),
        *(str(fd) for fd in read_only_root_fds),
        str(len(writable_root_fds)),
        *(str(fd) for fd in writable_root_fds),
        "--",
        *command,
    )
    if len(result) > MAX_COMMAND_ARGS:
        raise LinuxGuestScopeError(
            "guest command protocol exceeds its argument ceiling",
            reason_code="COMMAND_INVALID",
        )
    return result


class LinuxGuestScopeProcess:
    """One gated helper invocation with authenticated READY/FINAL receipts."""

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        status_fd: int,
        gate_fd: int,
        key: bytearray,
        attempt_id: str,
        binding_digest: str,
        limits: LinuxGuestLimits,
        ready_receipt: Mapping[str, str],
    ) -> None:
        self._process = process
        self._status_fd = status_fd
        self._gate_fd = gate_fd
        self._key = key
        self._attempt_id = attempt_id
        self._binding_digest = binding_digest
        self._limits = limits
        self.ready_receipt = dict(ready_receipt)
        self._consumed = False

    def _erase(self) -> None:
        for index in range(len(self._key)):
            self._key[index] = 0

    def release_and_wait(self) -> dict[str, str]:
        if self._consumed:
            raise LinuxGuestScopeError(
                "Linux guest scope capability is no longer available",
                reason_code="CAPABILITY_CONSUMED",
            )
        self._consumed = True
        try:
            if os.write(self._gate_fd, b"1") != 1:
                raise OSError("short gate write")
            os.close(self._gate_fd)
            self._gate_fd = -1
            raw = _read_line_bounded(
                self._status_fd,
                timeout_s=self._limits.wall_time_ms / 1000.0 + 5.0,
            )
            fields = _parse_receipt(
                raw,
                authentication_key=self._key,
                expected_attempt=self._attempt_id,
                expected_binding=self._binding_digest,
                expected_phase="FINAL",
            )
            _validate_final_receipt(fields)
            self._process.wait(timeout=2.0)
            return fields
        except (OSError, subprocess.TimeoutExpired):
            self._terminate()
            raise LinuxGuestScopeError(
                "Linux guest scope completion failed",
                reason_code="RECOVERY_REQUIRED",
            ) from None
        except LinuxGuestScopeError:
            self._terminate()
            raise
        finally:
            if self._status_fd >= 0:
                os.close(self._status_fd)
                self._status_fd = -1
            self._erase()

    def _terminate(self) -> None:
        graceful = False
        try:
            self._process.terminate()
            self._process.wait(timeout=2.0)
            graceful = True
        except (OSError, subprocess.TimeoutExpired):
            pass
        if not graceful:
            try:
                os.killpg(self._process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                self._process.kill()
            except OSError:
                pass
            try:
                self._process.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if self._gate_fd >= 0:
            os.close(self._gate_fd)
            self._gate_fd = -1

    def discard(self) -> None:
        if self._consumed:
            return
        self._consumed = True
        self._terminate()
        if self._status_fd >= 0:
            os.close(self._status_fd)
            self._status_fd = -1
        self._erase()


def launch_linux_guest_scope(
    *,
    cgroup_parent_fd: int,
    overlay_storage_fd: int,
    interpreter_fd: int,
    driver_script_fd: int,
    runtime_root_fds: Sequence[int],
    expected_interpreter_sha256: str,
    expected_driver_script_sha256: str,
    expected_runtime_roster_sha256: str,
    read_only_root_fds: Sequence[int],
    writable_root_fds: Sequence[int],
    target_uid: int,
    target_gid: int,
    limits: LinuxGuestLimits,
    attempt_id: str,
    driver_argv: Sequence[str],
    helper_path: Path | None = None,
    popen_factory: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> LinuxGuestScopeProcess:
    """Launch the helper and return only after authenticating its READY receipt."""

    _require_posix_fcntl()
    if helper_path is not None and popen_factory is subprocess.Popen:
        raise LinuxGuestScopeError(
            "helper path overrides are restricted to injected fake runners",
            reason_code="TEST_OVERRIDE_FORBIDDEN",
        )
    binding = build_guest_binding(
        cgroup_parent_fd=cgroup_parent_fd,
        overlay_storage_fd=overlay_storage_fd,
        interpreter_fd=interpreter_fd,
        driver_script_fd=driver_script_fd,
        runtime_root_fds=runtime_root_fds,
        expected_interpreter_sha256=expected_interpreter_sha256,
        expected_driver_script_sha256=expected_driver_script_sha256,
        expected_runtime_roster_sha256=expected_runtime_roster_sha256,
        read_only_root_fds=read_only_root_fds,
        writable_root_fds=writable_root_fds,
        target_uid=target_uid,
        target_gid=target_gid,
        limits=limits,
        attempt_id=attempt_id,
        driver_argv=driver_argv,
    )
    digest = binding_sha256(binding)
    helper = (
        helper_path
        if helper_path is not None
        else _helper_executable(expected_source=binding["helper_source"])
    )
    key = bytearray(secrets.token_bytes(32))
    auth_read, auth_write = os.pipe()
    status_read, status_write = os.pipe()
    gate_read, gate_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    try:
        argv = _build_helper_argv(
            helper,
            auth_fd=auth_read,
            status_fd=status_write,
            gate_fd=gate_read,
            cgroup_parent_fd=cgroup_parent_fd,
            overlay_storage_fd=overlay_storage_fd,
            interpreter_fd=interpreter_fd,
            driver_script_fd=driver_script_fd,
            runtime_root_fds=runtime_root_fds,
            expected_interpreter_sha256=expected_interpreter_sha256,
            expected_driver_script_sha256=expected_driver_script_sha256,
            expected_runtime_roster_sha256=expected_runtime_roster_sha256,
            read_only_root_fds=read_only_root_fds,
            writable_root_fds=writable_root_fds,
            target_uid=target_uid,
            target_gid=target_gid,
            limits=limits,
            attempt_id=attempt_id,
            binding_digest=digest,
            driver_argv=driver_argv,
        )
        inherited = (
            auth_read,
            status_write,
            gate_read,
            cgroup_parent_fd,
            overlay_storage_fd,
            interpreter_fd,
            driver_script_fd,
            *runtime_root_fds,
            *read_only_root_fds,
            *writable_root_fds,
        )
        process = popen_factory(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env={},
            shell=False,
            close_fds=True,
            start_new_session=True,
            pass_fds=inherited,
        )
        os.close(auth_read)
        auth_read = -1
        os.close(status_write)
        status_write = -1
        os.close(gate_read)
        gate_read = -1
        if os.write(auth_write, memoryview(key)) != len(key):
            raise OSError("short authentication write")
        os.close(auth_write)
        auth_write = -1
        raw = _read_line_bounded(status_read, timeout_s=15.0)
        fields = _parse_receipt(
            raw,
            authentication_key=key,
            expected_attempt=attempt_id,
            expected_binding=digest,
            expected_phase="READY",
        )
        _validate_ready_receipt(
            fields,
            limits=limits,
            target_uid=target_uid,
            target_gid=target_gid,
            attempt_id=attempt_id,
            binding=binding,
        )
        return LinuxGuestScopeProcess(
            process=process,
            status_fd=status_read,
            gate_fd=gate_write,
            key=key,
            attempt_id=attempt_id,
            binding_digest=digest,
            limits=limits,
            ready_receipt=fields,
        )
    except BaseException:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for descriptor in (
            auth_read,
            auth_write,
            status_read,
            status_write,
            gate_read,
            gate_write,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for index in range(len(key)):
            key[index] = 0
        raise


def recover_guest_scope(
    *,
    cgroup_parent_fd: int,
    overlay_storage_fd: int,
    attempt_id: str,
    timeout_s: float = 2.0,
) -> dict[str, Any]:
    """Kill and retire one exact attempt cgroup and empty overlay staging tree."""

    _require_posix_fcntl()
    if not _is_hex256(attempt_id):
        raise LinuxGuestScopeError(
            "recovery attempt identity is malformed",
            reason_code="ATTEMPT_ID_INVALID",
        )
    if (
        isinstance(timeout_s, bool)
        or not isinstance(timeout_s, (int, float))
        or not 0.01 <= float(timeout_s) <= 30.0
    ):
        raise LinuxGuestScopeError(
            "recovery timeout is outside the closed policy",
            reason_code="RECOVERY_TIMEOUT_INVALID",
        )
    _descriptor_identity(cgroup_parent_fd, directory=True)
    _descriptor_identity(overlay_storage_fd, directory=True)
    cgroup_name = f"plamen-{attempt_id}"
    overlay_name = f"plamen-overlay-{attempt_id}"
    directory = -1
    events = -1
    killer = -1
    try:
        directory = os.open(
            cgroup_name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=cgroup_parent_fd,
        )
        killer = os.open(
            "cgroup.kill",
            os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        events = os.open(
            "cgroup.events",
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        if os.write(killer, b"1") != 1:
            raise OSError("short cgroup.kill write")
        deadline = time.monotonic() + timeout_s
        while True:
            os.lseek(events, 0, os.SEEK_SET)
            observed = os.read(events, 4097)
            if len(observed) > 4096:
                raise OSError("oversized cgroup.events")
            if b"populated 0" in observed.splitlines():
                break
            if time.monotonic() >= deadline:
                raise LinuxGuestScopeError(
                    "attempt cgroup remains populated",
                    reason_code="RECOVERY_REQUIRED",
                )
            time.sleep(0.01)
    except FileNotFoundError:
        pass
    except OSError:
        raise LinuxGuestScopeError(
            "attempt cgroup recovery failed",
            reason_code="RECOVERY_REQUIRED",
        ) from None
    finally:
        for descriptor in (killer, events, directory):
            if descriptor >= 0:
                os.close(descriptor)
    try:
        os.rmdir(cgroup_name, dir_fd=cgroup_parent_fd)
    except FileNotFoundError:
        pass
    except OSError:
        raise LinuxGuestScopeError(
            "attempt cgroup retirement failed",
            reason_code="RECOVERY_REQUIRED",
        ) from None

    overlay = -1
    try:
        overlay = os.open(
            overlay_name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=overlay_storage_fd,
        )
        for component in ("lower", "merged", "work", "upper"):
            try:
                os.rmdir(component, dir_fd=overlay)
            except FileNotFoundError:
                pass
        os.close(overlay)
        overlay = -1
        os.rmdir(overlay_name, dir_fd=overlay_storage_fd)
    except FileNotFoundError:
        pass
    except OSError:
        raise LinuxGuestScopeError(
            "attempt overlay recovery requires operator action",
            reason_code="RECOVERY_REQUIRED",
        ) from None
    finally:
        if overlay >= 0:
            os.close(overlay)
    return {
        "schema": RECEIPT_SCHEMA,
        "attempt": attempt_id,
        "cgroup_name": cgroup_name,
        "overlay_name": overlay_name,
        "cleanup": "COMPLETE",
    }
