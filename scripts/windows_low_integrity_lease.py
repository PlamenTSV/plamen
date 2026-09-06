"""Temporary global lease for Plamen's Windows low-integrity workers.

Windows mandatory-integrity control (MIC) prevents a low-integrity worker from
writing medium-integrity source and canonical state.  MIC does *not* distinguish
two low-integrity workers: without another boundary, either worker may write the
other's low-labeled stage.  This module supplies that deliberately narrow,
temporary boundary by allowing only one Plamen low-integrity lifetime at once.

The cross-process byte-range lock is released by Windows if the provider
process crashes.  A medium-integrity state record lists every root lowered by
the prior holder, so the next holder restores stale roots before lowering its
own.  This is sibling-stage isolation, not an AppContainer: unrelated
pre-existing low-integrity objects remain writable and capability reporting
must not call this exhaustive filesystem confinement.
"""
from __future__ import annotations

import hashlib
import json
import math
import msvcrt
import os
from pathlib import Path
import re
import stat
import time
from typing import Any
import uuid

from windows_private_execution_root import (
    WindowsPrivateExecutionRootAuthority,
    is_windows_private_execution_root_authority,
)


LEASE_PROTOCOL = "PLAMEN_WINDOWS_LOW_INTEGRITY_GLOBAL_LEASE_V1"
LEASE_SCHEMA_VERSION = 1
LEASE_DIRECTORY_ENV = "PLAMEN_WINDOWS_LOW_INTEGRITY_LEASE_DIR"
LEASE_TIMEOUT_ENV = "PLAMEN_WINDOWS_LOW_INTEGRITY_LEASE_TIMEOUT_SECONDS"
LEASE_TEST_OVERRIDE_ENV = "PLAMEN_TEST_ALLOW_WINDOWS_LEASE_OVERRIDE"
DEFAULT_LEASE_TIMEOUT_SECONDS = 12 * 60 * 60
DEFAULT_CALLER_LEASE_ACQUISITION_TIMEOUT_SECONDS = 30.0
_LOCK_FILE_NAME = "execution.lock"
_STATE_FILE_NAME = "state.json"
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(
    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
)
_QUARANTINED_LEASES: list["WindowsLowIntegrityExecutionLease"] = []


class WindowsLowIntegrityLeaseError(RuntimeError):
    """The temporary Windows sibling-stage boundary could not be proven."""


def _windows_extended_path(path: Path) -> Path:
    """Return a Win32 extended-length spelling for one absolute path.

    Python and several Win32 APIs still apply the legacy MAX_PATH boundary to
    ordinary ``D:\\...`` spellings. Forge artifact names can cross that
    boundary even when the lease root itself is short. The ``\\\\?\\`` form
    preserves object identity while disabling legacy path parsing.
    """

    raw = str(Path(path).absolute())
    if raw.startswith("\\\\?\\"):
        return Path(raw)
    if raw.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + raw[2:])
    return Path("\\\\?\\" + raw)


def _is_reparse(path: Path) -> bool:
    try:
        row = os.stat(
            _windows_extended_path(path),
            follow_symlinks=False,
        )
        return bool(row.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
    except AttributeError:
        return stat.S_ISLNK(row.st_mode)


def _validate_real_directory(path: Path, *, purpose: str) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        raise WindowsLowIntegrityLeaseError(f"{purpose} must be absolute")
    try:
        from rooted_path_io import RootedPathIOError, checked_directory

        resolved = checked_directory(
            raw,
            label=purpose,
        )
    except (OSError, RootedPathIOError) as exc:
        raise WindowsLowIntegrityLeaseError(f"{purpose} is unreadable") from exc
    if resolved.parent == resolved:
        raise WindowsLowIntegrityLeaseError(f"{purpose} cannot be a filesystem root")
    return resolved


def _windows_known_folder_local_app_data() -> Path:
    """Resolve LocalAppData from Windows authority, never mutable environment."""

    if os.name != "nt":
        raise WindowsLowIntegrityLeaseError(
            "Windows Known Folders are unavailable on this host"
        )
    from ctypes import wintypes
    import ctypes

    class _Guid(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_uint32),
            ("Data2", ctypes.c_uint16),
            ("Data3", ctypes.c_uint16),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    # FOLDERID_LocalAppData =
    # {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
    folder_id = _Guid(
        0xF1B32785,
        0x6FBA,
        0x4FCF,
        (ctypes.c_ubyte * 8)(
            0x9D,
            0x55,
            0x7B,
            0x8E,
            0x7F,
            0x15,
            0x70,
            0x91,
        ),
    )
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    shell32.SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(_Guid),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole32.CoTaskMemFree.restype = None
    rendered = ctypes.c_wchar_p()
    result = int(
        shell32.SHGetKnownFolderPath(
            ctypes.byref(folder_id),
            0,
            None,
            ctypes.byref(rendered),
        )
    )
    if result != 0 or not rendered.value:
        raise WindowsLowIntegrityLeaseError(
            f"SHGetKnownFolderPath(LocalAppData) failed: 0x{result & 0xFFFFFFFF:08x}"
        )
    try:
        return _validate_real_directory(
            Path(rendered.value),
            purpose="Windows LocalAppData known folder",
        )
    finally:
        ole32.CoTaskMemFree(ctypes.cast(rendered, ctypes.c_void_p))


def _create_validated_namespace(
    root: Path,
    *,
    components: tuple[str, ...],
) -> Path:
    """Create exact non-reparse descendants one component at a time."""

    current = _validate_real_directory(root, purpose="lease namespace root")
    for component in components:
        if (
            not component
            or component in {".", ".."}
            or "/" in component
            or "\\" in component
        ):
            raise WindowsLowIntegrityLeaseError(
                "lease namespace component is invalid"
            )
        candidate = current / component
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise WindowsLowIntegrityLeaseError(
                "cannot create the low-integrity lease namespace"
            ) from exc
        current = _validate_real_directory(
            candidate,
            purpose="lease namespace component",
        )
    return current


def _lease_directory() -> Path:
    configured = os.environ.get(LEASE_DIRECTORY_ENV)
    if configured:
        if os.environ.get(LEASE_TEST_OVERRIDE_ENV) != "1":
            raise WindowsLowIntegrityLeaseError(
                f"{LEASE_DIRECTORY_ENV} is test-only and requires "
                f"{LEASE_TEST_OVERRIDE_ENV}=1"
            )
        raw = Path(configured)
        if not raw.is_absolute() or "\x00" in configured:
            raise WindowsLowIntegrityLeaseError(
                f"{LEASE_DIRECTORY_ENV} must be an absolute path"
            )
        try:
            raw.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise WindowsLowIntegrityLeaseError(
                "cannot create the low-integrity lease directory"
            ) from exc
        return _validate_real_directory(raw, purpose="lease directory")
    return _create_validated_namespace(
        _windows_known_folder_local_app_data(),
        components=(
            "Plamen",
            "security",
            "low-integrity-lease-v1",
        )
    )


def _lease_timeout_seconds() -> float:
    raw = os.environ.get(
        LEASE_TIMEOUT_ENV, str(DEFAULT_LEASE_TIMEOUT_SECONDS)
    )
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise WindowsLowIntegrityLeaseError(
            f"{LEASE_TIMEOUT_ENV} must be a positive number"
        ) from exc
    if value <= 0 or value > DEFAULT_LEASE_TIMEOUT_SECONDS:
        raise WindowsLowIntegrityLeaseError(
            f"{LEASE_TIMEOUT_ENV} must be in (0, {DEFAULT_LEASE_TIMEOUT_SECONDS}]"
        )
    return value


def lease_capability_binding() -> dict[str, Any]:
    """Return stable protocol identity without acquiring the execution lease."""

    directory = _lease_directory()
    lock_path = directory / _LOCK_FILE_NAME
    state_path = directory / _STATE_FILE_NAME
    test_override = bool(os.environ.get(LEASE_DIRECTORY_ENV))
    identity_bytes = (
        f"{LEASE_PROTOCOL}\0{os.path.normcase(str(lock_path))}".encode("utf-8")
    )
    return {
        "protocol": LEASE_PROTOCOL,
        "lock_path": str(lock_path),
        "state_path": str(state_path),
        "identity_sha256": hashlib.sha256(identity_bytes).hexdigest(),
        "namespace_authority": (
            "TEST_ONLY_EXPLICIT_DIRECTORY_OVERRIDE"
            if test_override
            else "WINDOWS_KNOWN_FOLDER_LOCAL_APP_DATA"
        ),
        "namespace_limitation": (
            "TEST_OVERRIDE_NOT_PRODUCTION_AUTHORITY"
            if test_override
            else "SAME_USER_MEDIUM_INTEGRITY_MUTATION_OUT_OF_SCOPE"
        ),
        "scope": (
            "TEST_PROCESS_EXPLICIT_NAMESPACE_ONLY"
            if test_override
            else "ALL_PLAMEN_LOW_INTEGRITY_LIFETIMES_FOR_THIS_WINDOWS_USER_PROFILE"
        ),
        "crash_recovery": "OS_BYTE_RANGE_UNLOCK_PLUS_STALE_ROOT_RELABEL",
    }


def _cancellation_requested(token: Any) -> bool:
    if token is None:
        return False
    if callable(token):
        return bool(token())
    is_set = getattr(token, "is_set", None)
    if callable(is_set):
        return bool(is_set())
    raise WindowsLowIntegrityLeaseError(
        "lease cancellation token must be callable or Event-like"
    )


def _set_windows_integrity_label(
    path: Path,
    *,
    sid_alias: str,
    inheritable: bool,
) -> None:
    """Replace the mandatory label on one exact filesystem object."""

    if os.name != "nt":
        raise WindowsLowIntegrityLeaseError(
            "Windows integrity labels are unavailable on this host"
        )
    from ctypes import wintypes
    import ctypes

    target = _windows_extended_path(Path(path))
    try:
        if _is_reparse(target):
            raise WindowsLowIntegrityLeaseError(
                "integrity-label target must not be a reparse point"
            )
        target = target.resolve(strict=True)
    except OSError as exc:
        raise WindowsLowIntegrityLeaseError(
            "integrity-label target is unreadable"
        ) from exc

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    advapi32.GetSecurityDescriptorSacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorSacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD()
    flags = "OICI" if inheritable else ""
    sddl = f"S:(ML;{flags};NW;;;{sid_alias})"
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    ):
        raise WindowsLowIntegrityLeaseError(
            "cannot compile the Windows integrity descriptor: "
            f"{ctypes.get_last_error()}"
        )
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        sacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorSacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(sacl),
            ctypes.byref(defaulted),
        ) or not present.value or not sacl.value:
            raise WindowsLowIntegrityLeaseError(
                "compiled descriptor has no mandatory label"
            )
        result = advapi32.SetNamedSecurityInfoW(
            str(target),
            1,  # SE_FILE_OBJECT
            0x00000010,  # LABEL_SECURITY_INFORMATION
            None,
            None,
            None,
            sacl,
        )
        if result != 0:
            raise WindowsLowIntegrityLeaseError(
                f"SetNamedSecurityInfoW(integrity label) failed: {result}"
            )
    finally:
        kernel32.LocalFree(descriptor)


def set_windows_low_integrity_root(path: Path) -> None:
    """Lower one lease-owned root; children inherit the low MIC label."""

    root = _validate_real_directory(path, purpose="writable root")
    _set_windows_integrity_label(root, sid_alias="LW", inheritable=True)


def restore_windows_medium_integrity_tree(path: Path) -> None:
    """Restore one exact owned tree, rejecting aliases instead of following."""

    root = _validate_real_directory(path, purpose="stale writable root")
    members: list[tuple[Path, bool]] = []
    # Enumerate through an extended-length spelling so a short owned root may
    # safely contain Forge-style descendants at or beyond MAX_PATH.
    pending = [_windows_extended_path(root)]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    member = Path(entry.path)
                    if _is_reparse(member) or entry.is_symlink():
                        raise WindowsLowIntegrityLeaseError(
                            "owned writable root contains a reparse point"
                        )
                    if entry.is_dir(follow_symlinks=False):
                        members.append((member, True))
                        pending.append(member)
                    elif entry.is_file(follow_symlinks=False):
                        members.append((member, False))
                    else:
                        raise WindowsLowIntegrityLeaseError(
                            "owned writable root contains a non-file object"
                        )
        except OSError as exc:
            raise WindowsLowIntegrityLeaseError(
                "cannot enumerate an owned writable root"
            ) from exc

    # Relabel leaves first.  A low child cannot exploit a restored directory
    # while a low descendant remains writable through an already-open path.
    for member, is_directory in reversed(members):
        _set_windows_integrity_label(
            member,
            sid_alias="ME",
            inheritable=is_directory,
        )
    _set_windows_integrity_label(root, sid_alias="ME", inheritable=True)


def _restore_failed_activation_root(path: Path) -> None:
    """Restore a root when lease activation failed before any child launch.

    An activation failure occurs inside the lease constructor, so the caller
    cannot yet possess a lease and cannot launch a low-integrity process.  The
    root itself may already have received the inheritable low label, but no
    child could have been created under that authority.  Restoring the exact
    root is therefore sufficient and, unlike full-tree recovery, remains safe
    when a read-only project input already contained dependency junctions.
    """

    root = _validate_real_directory(path, purpose="failed-activation root")
    try:
        _set_windows_integrity_label(root, sid_alias="ME", inheritable=True)
        return
    except WindowsLowIntegrityLeaseError:
        # SetNamedSecurityInfo can be denied on a source tree whose owner has
        # modify/read authority but no WRITE_OWNER authority.  That same denial
        # may have been the activation failure: no low label was ever applied.
        # Native label-only inspection does not require SeSecurityPrivilege.
        sddl = _windows_integrity_label_sddl(root)
        if not sddl:
            return  # No explicit label means Windows' implicit medium level.
        if re.search(r";;;(?:ME|HI|SI|PP)\)", sddl):
            return
        numeric = re.search(r";;;S-1-16-(\d+)\)", sddl)
        if numeric is not None and int(numeric.group(1)) >= 8192:
            return
        # Unknown, untrusted, or low labels remain a hard recovery failure.
        raise


def _windows_integrity_label_sddl(path: Path) -> str:
    """Return the exact mandatory-label SDDL, or empty for implicit medium."""

    if os.name != "nt":
        raise WindowsLowIntegrityLeaseError(
            "Windows integrity labels are unavailable on this host"
        )
    from ctypes import wintypes
    import ctypes

    root = _validate_real_directory(path, purpose="integrity-label query root")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(root),
        1,  # SE_FILE_OBJECT
        0x00000010,  # LABEL_SECURITY_INFORMATION
        None,
        None,
        None,
        ctypes.byref(sacl),
        ctypes.byref(descriptor),
    )
    if result != 0 or not descriptor.value:
        raise WindowsLowIntegrityLeaseError(
            f"GetNamedSecurityInfoW(integrity label) failed: {result}"
        )
    rendered = wintypes.LPWSTR()
    rendered_size = wintypes.DWORD()
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            0x00000010,
            ctypes.byref(rendered),
            ctypes.byref(rendered_size),
        ):
            raise WindowsLowIntegrityLeaseError(
                "cannot render the Windows integrity descriptor: "
                f"{ctypes.get_last_error()}"
            )
        return str(rendered.value or "")
    finally:
        if rendered:
            kernel32.LocalFree(rendered)
        kernel32.LocalFree(descriptor)


def _canonical_roots(
    roots: tuple[Path, ...],
    *,
    lease_directory: Path,
) -> tuple[Path, ...]:
    canonical = tuple(
        _validate_real_directory(root, purpose="writable root") for root in roots
    )
    if len(set(canonical)) != len(canonical):
        raise WindowsLowIntegrityLeaseError("writable roots must be unique")
    for index, left in enumerate(canonical):
        if left == lease_directory or left in lease_directory.parents:
            raise WindowsLowIntegrityLeaseError(
                "writable root must not contain the lease authority"
            )
        if lease_directory in left.parents:
            raise WindowsLowIntegrityLeaseError(
                "writable root must not be inside the lease authority"
            )
        for right in canonical[index + 1 :]:
            if left in right.parents or right in left.parents:
                raise WindowsLowIntegrityLeaseError(
                    "writable roots must not overlap"
                )
    return canonical


def _recoverable_stale_roots(
    roots: tuple[Path, ...],
    *,
    lease_directory: Path,
) -> tuple[Path, ...]:
    """Validate still-present stale roots; absence is already non-writable."""

    present: list[Path] = []
    normalized_seen: set[str] = set()
    for raw in roots:
        path = Path(raw)
        if not path.is_absolute():
            raise WindowsLowIntegrityLeaseError(
                "stale writable root must be absolute"
            )
        normalized = os.path.normcase(os.path.normpath(str(path)))
        if normalized in normalized_seen:
            raise WindowsLowIntegrityLeaseError(
                "stale writable roots must be unique"
            )
        normalized_seen.add(normalized)
        if not os.path.lexists(path):
            continue
        present.append(
            _validate_real_directory(path, purpose="stale writable root")
        )
    return _canonical_roots(
        tuple(present),
        lease_directory=lease_directory,
    )


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_state(path: Path, payload: dict[str, Any]) -> str:
    raw = _json_bytes(payload)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}")
    try:
        with open(temporary, "xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise WindowsLowIntegrityLeaseError(
            "cannot persist the low-integrity lease state"
        ) from exc
    return hashlib.sha256(raw).hexdigest()


def _read_state(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not os.path.lexists(path):
        return None, None
    try:
        if _is_reparse(path) or not path.is_file():
            raise WindowsLowIntegrityLeaseError(
                "lease state is not a real regular file"
            )
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsLowIntegrityLeaseError(
            "lease state is unreadable or malformed"
        ) from exc
    if not isinstance(payload, dict):
        raise WindowsLowIntegrityLeaseError("lease state must be an object")
    return payload, hashlib.sha256(raw).hexdigest()


class WindowsLowIntegrityExecutionLease:
    """Own one cross-process serialized low-integrity stage lifetime."""

    def __init__(
        self,
        *,
        writable_roots: tuple[Path, ...],
        owner_identity: str,
        writable_root_authorities: tuple[
            WindowsPrivateExecutionRootAuthority, ...
        ] = (),
        acquisition_deadline_monotonic: float | None = None,
        cancel_token: Any = None,
    ) -> None:
        if os.name != "nt":
            raise WindowsLowIntegrityLeaseError(
                "Windows low-integrity lease is unavailable on this host"
            )
        if not owner_identity or not isinstance(owner_identity, str):
            raise WindowsLowIntegrityLeaseError("lease owner identity is invalid")
        now = time.monotonic()
        deadline = (
            now + DEFAULT_CALLER_LEASE_ACQUISITION_TIMEOUT_SECONDS
            if acquisition_deadline_monotonic is None
            else acquisition_deadline_monotonic
        )
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(float(deadline))
        ):
            raise WindowsLowIntegrityLeaseError(
                "lease acquisition deadline must be a finite monotonic timestamp"
            )
        self._acquisition_deadline_monotonic = float(deadline)
        self._cancel_token = cancel_token
        # Validate cancellation/deadline before creating or opening authority
        # objects.  An already-cancelled caller must have no lease side effect.
        if _cancellation_requested(self._cancel_token):
            raise WindowsLowIntegrityLeaseError(
                "cancelled before acquiring the global low-integrity "
                "execution lease"
            )
        if self._acquisition_deadline_monotonic <= now:
            raise WindowsLowIntegrityLeaseError(
                "caller deadline expired before acquiring the global "
                "low-integrity execution lease"
            )
        self._directory = _lease_directory()
        self._binding = lease_capability_binding()
        self._lock_path = Path(self._binding["lock_path"])
        self._state_path = Path(self._binding["state_path"])
        self._roots = _canonical_roots(
            tuple(Path(item) for item in writable_roots),
            lease_directory=self._directory,
        )
        if any(
            not is_windows_private_execution_root_authority(item)
            for item in writable_root_authorities
        ):
            raise WindowsLowIntegrityLeaseError(
                "private writable-root authority type is invalid"
            )
        authority_by_root: dict[str, WindowsPrivateExecutionRootAuthority] = {}
        for authority in writable_root_authorities:
            authority.replay()
            key = os.path.normcase(str(authority.path))
            if key in authority_by_root:
                raise WindowsLowIntegrityLeaseError(
                    "private writable-root authority is duplicated"
                )
            authority_by_root[key] = authority
        root_keys = {os.path.normcase(str(item)) for item in self._roots}
        if set(authority_by_root) - root_keys:
            raise WindowsLowIntegrityLeaseError(
                "private writable-root authority is outside the lease roots"
            )
        self._private_root_authorities = authority_by_root
        self._owner_identity = owner_identity
        self._lease_id = uuid.uuid4().hex
        self._lock_handle: Any | None = None
        self._state_sha256: str | None = None
        self._recovered_state_sha256: str | None = None
        self._active = False
        self._quarantined = False
        self._acquire_and_activate()

    def _acquire_lock(self) -> None:
        try:
            if os.path.lexists(self._lock_path) and (
                _is_reparse(self._lock_path) or not self._lock_path.is_file()
            ):
                raise WindowsLowIntegrityLeaseError(
                    "global low-integrity execution lock is not a real file"
                )
            handle = open(self._lock_path, "a+b", buffering=0)
            if _is_reparse(self._lock_path) or not self._lock_path.is_file():
                handle.close()
                raise WindowsLowIntegrityLeaseError(
                    "global low-integrity execution lock became aliased"
                )
            if self._lock_path.stat().st_size == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
        except OSError as exc:
            raise WindowsLowIntegrityLeaseError(
                "cannot open the global low-integrity execution lock"
            ) from exc
        deadline = min(
            self._acquisition_deadline_monotonic,
            time.monotonic() + _lease_timeout_seconds(),
        )
        acquired = False
        try:
            while True:
                if _cancellation_requested(self._cancel_token):
                    raise WindowsLowIntegrityLeaseError(
                        "cancelled while waiting for the global low-integrity "
                        "execution lease"
                    )
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    self._lock_handle = handle
                    acquired = True
                    return
                except OSError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise WindowsLowIntegrityLeaseError(
                            "caller deadline expired while waiting for the "
                            "global low-integrity execution lease"
                        )
                    time.sleep(min(0.025, remaining))
        finally:
            if not acquired:
                handle.close()

    def _recover_previous_state(self) -> None:
        previous, previous_sha = _read_state(self._state_path)
        if previous is None:
            return
        if (
            previous.get("schema_version") != LEASE_SCHEMA_VERSION
            or previous.get("protocol") != LEASE_PROTOCOL
            or previous.get("binding_identity_sha256")
            != self._binding["identity_sha256"]
            or not isinstance(previous.get("status"), str)
            or previous.get("status")
            not in {"PREPARING", "ACTIVE", "QUARANTINED", "IDLE"}
            or not isinstance(previous.get("writable_roots"), list)
            or any(
                not isinstance(item, str)
                for item in previous["writable_roots"]
            )
        ):
            raise WindowsLowIntegrityLeaseError(
                "stale lease state has an unsupported schema"
            )
        if previous["status"] == "IDLE":
            return
        stale_roots = _recoverable_stale_roots(
            tuple(Path(item) for item in previous["writable_roots"]),
            lease_directory=self._directory,
        )
        activation_never_launched = (
            previous["status"] == "QUARANTINED"
            and previous.get("quarantine_reason")
            == "ACTIVATION_RECOVERY_FAILED"
        )
        for root in stale_roots:
            if activation_never_launched:
                _restore_failed_activation_root(root)
            else:
                restore_windows_medium_integrity_tree(root)
        self._recovered_state_sha256 = previous_sha

    def _active_payload(self, status: str) -> dict[str, Any]:
        return {
            "schema_version": LEASE_SCHEMA_VERSION,
            "protocol": LEASE_PROTOCOL,
            "status": status,
            "lease_id": self._lease_id,
            "owner_identity": self._owner_identity,
            "owner_pid": os.getpid(),
            "writable_roots": [str(item) for item in self._roots],
            "binding_identity_sha256": self._binding["identity_sha256"],
            "recovered_state_sha256": self._recovered_state_sha256,
            "written_at_unix_ns": time.time_ns(),
        }

    def _acquire_and_activate(self) -> None:
        self._acquire_lock()
        try:
            self._recover_previous_state()
        except BaseException:
            # Never overwrite an unrecovered predecessor with an IDLE record
            # for the new request.  The predecessor is the only durable clue
            # capable of driving the next recovery attempt.
            self._unlock()
            raise
        try:
            # PREPARING is written first so a crash between any two label
            # operations remains mechanically recoverable.
            self._state_sha256 = _write_state(
                self._state_path,
                self._active_payload("PREPARING"),
            )
            for root in self._roots:
                authority = self._private_root_authorities.get(
                    os.path.normcase(str(root))
                )
                if authority is None:
                    set_windows_low_integrity_root(root)
                else:
                    authority.lower_to_low_integrity()
            self._state_sha256 = _write_state(
                self._state_path,
                self._active_payload("ACTIVE"),
            )
            self._active = True
        except BaseException:
            try:
                for root in self._roots:
                    authority = self._private_root_authorities.get(
                        os.path.normcase(str(root))
                    )
                    if authority is None:
                        restore_windows_medium_integrity_tree(root)
                    else:
                        authority.restore_medium_integrity_tree()
                _write_state(self._state_path, self._active_payload("IDLE"))
                self._unlock()
            except BaseException:
                self._quarantine("ACTIVATION_RECOVERY_FAILED")
            raise

    def _unlock(self) -> None:
        handle = self._lock_handle
        if handle is None:
            return
        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError as exc:
            raise WindowsLowIntegrityLeaseError(
                "cannot release the global low-integrity execution lease"
            ) from exc
        handle.close()
        self._lock_handle = None

    def _quarantine(self, reason: str) -> None:
        self._quarantined = True
        try:
            self._state_sha256 = _write_state(
                self._state_path,
                {
                    **self._active_payload("QUARANTINED"),
                    "quarantine_reason": reason,
                },
            )
        finally:
            if self not in _QUARANTINED_LEASES:
                _QUARANTINED_LEASES.append(self)

    def release_after_proven_closure(self) -> None:
        """Restore exact roots and release only after process population is zero."""

        if not self._active:
            return
        try:
            for root in self._roots:
                authority = self._private_root_authorities.get(
                    os.path.normcase(str(root))
                )
                if authority is None:
                    restore_windows_medium_integrity_tree(root)
                else:
                    authority.restore_medium_integrity_tree()
            self._active = False
            self._state_sha256 = _write_state(
                self._state_path,
                self._active_payload("IDLE"),
            )
            self._unlock()
        except BaseException:
            self._quarantine("ROOT_RESTORE_OR_RELEASE_FAILED")
            raise

    def quarantine_after_emergency_close(self) -> None:
        """Restore roots but retain the lease until provider-process death."""

        if not self._active:
            return
        try:
            for root in self._roots:
                authority = self._private_root_authorities.get(
                    os.path.normcase(str(root))
                )
                if authority is None:
                    restore_windows_medium_integrity_tree(root)
                else:
                    authority.restore_medium_integrity_tree()
        except BaseException:
            self._quarantine("EMERGENCY_ROOT_RESTORE_FAILED")
            raise
        self._quarantine("PROCESS_POPULATION_ZERO_NOT_PROVEN")
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    @property
    def binding(self) -> dict[str, Any]:
        return {
            **self._binding,
            "lease_id": self._lease_id,
            "owner_identity": self._owner_identity,
            "owner_pid": os.getpid(),
            "state_sha256": self._state_sha256,
            "recovered_state_sha256": self._recovered_state_sha256,
            "active": self._active,
            "quarantined": self._quarantined,
            "writable_roots_sha256": hashlib.sha256(
                _json_bytes({"roots": [str(item) for item in self._roots]})
            ).hexdigest(),
        }


__all__ = [
    "DEFAULT_CALLER_LEASE_ACQUISITION_TIMEOUT_SECONDS",
    "LEASE_DIRECTORY_ENV",
    "LEASE_PROTOCOL",
    "LEASE_TEST_OVERRIDE_ENV",
    "LEASE_TIMEOUT_ENV",
    "WindowsLowIntegrityExecutionLease",
    "WindowsLowIntegrityLeaseError",
    "lease_capability_binding",
    "restore_windows_medium_integrity_tree",
    "set_windows_low_integrity_root",
]
