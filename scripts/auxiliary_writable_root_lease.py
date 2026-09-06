"""Provider-owned, attempt-scoped auxiliary writable-root leases.

The caller reserves a logical lease but cannot nominate a filesystem path.
Only after the caller supplies the already-durable AttemptArm digest does the
provider atomically create and expose one unique, empty child of its stable
per-user runtime namespace.

Every arm first publishes a strict, write-through lifecycle intent in a
provider-owned registry outside the leased root. Bind and terminal revocation
are compare-and-replace journal transitions. Startup reconciliation is bounded
and destructive only after the recorded provider is provably dead; bound
leases additionally require persistent process-scope population-zero proof.

This module is intentionally independent from worker_execution_receipts.py.
It supplies a narrow integration primitive; it does not claim that Python path
checks provide kernel-enforced write confinement against an unrelated,
same-user process racing the runtime namespace.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import threading
import time
from types import MappingProxyType
from typing import Any, Iterator, Mapping
import uuid

import owned_directory_guard as _owned_directory
from windows_private_execution_root import (
    WindowsPrivateExecutionRootAuthority,
    WindowsPrivateExecutionRootError,
    create_windows_private_execution_root,
)


RESERVATION_SCHEMA = "plamen.auxiliary_writable_root_reservation.v1"
LEASE_SCHEMA = "plamen.auxiliary_writable_root_lease.v1"
REVOCATION_SCHEMA = "plamen.auxiliary_writable_root_revocation.v1"
JOURNAL_SCHEMA = "plamen.auxiliary_writable_root_journal.v1"
RECOVERY_TERMINAL_SCHEMA = (
    "plamen.auxiliary_writable_root_recovery_terminal.v1"
)
RECONCILIATION_SCHEMA = (
    "plamen.auxiliary_writable_root_reconciliation.v1"
)
PRELAUNCH_ABORT_CLAIM_SCHEMA = (
    "plamen.auxiliary_writable_root_prelaunch_abort_claim.v1"
)
REGISTRY_DIRECTORY_NAME = "registry-v1"
TERMINAL_ARCHIVE_DIRECTORY_NAME = "terminal-v1"
ABANDONED_TEMP_DIRECTORY_NAME = "abandoned-temporary-v1"
REGISTRY_LOCK_FILE_NAME = ".registry-mutation-v1.lock"
PROFILE_LIFECYCLE_DIRECTORY_NAME = "profile-lifecycle-v1"

MAX_SELECTION_ATTEMPTS = 64
MAX_NAMESPACE_ENTRIES = 100_000
MAX_REGISTRY_ENTRIES = 10_000
MAX_REGISTRY_RECOVERY_ENTRIES = 100_000
MAX_REGISTRY_RECOVERY_BYTES = 512 * 1024 * 1024
MAX_JOURNAL_BYTES = 1024 * 1024
MAX_CLEANUP_ENTRIES = 100_000
MAX_CLEANUP_BYTES = 2 * 1024 * 1024 * 1024
MAX_CLEANUP_DEPTH = 64
MAX_RECONCILIATION_DETAILS = 10_000
REGISTRY_LOCK_TIMEOUT_SECONDS = 15.0

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ROOT_NAME = re.compile(r"root-[0-9a-f]{32}")
_JOURNAL_NAME = re.compile(r"lease-[0-9a-f]{32}\.json")
_TEMP_JOURNAL_NAME = re.compile(
    r"\.tmp-lease-[0-9a-f]{32}-[0-9a-f]{32}",
)
_JOURNAL_STATES = frozenset(
    {"INTENT", "ARMED_UNBOUND", "ARMED_BOUND", "TERMINAL"}
)
_REPARSE_ATTRIBUTE = 0x400
_TOKEN_CAPABILITY = object()
_PRELAUNCH_ABORT_CLAIM_CAPABILITY = object()
_PROVIDER_INSTANCE_NONCE = uuid.uuid4().hex
_REGISTRY_LOCK_STATE = threading.local()


class AuxiliaryWritableRootLeaseError(RuntimeError):
    """The auxiliary-root lifecycle could not be proven safe."""


class AuxiliaryWritableRootLockTimeout(AuxiliaryWritableRootLeaseError):
    """The cooperative provider registry lock was not acquired in time."""


def _native_path(path: Path) -> str:
    """Return an extended-length Windows spelling for owned-root I/O."""

    value = os.path.abspath(os.fspath(path))
    if os.name != "nt" or value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root evidence is not canonical JSON"
        ) from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest_mapping(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_json(value))


def _clone_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(_canonical_json(dict(value)).decode("utf-8"))


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root journal contains duplicate JSON keys"
            )
        result[key] = value
    return result


def _strict_json_loads(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {value}")
            ),
        )
    except (
        AuxiliaryWritableRootLeaseError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal is not strict JSON"
        ) from exc
    if not isinstance(value, dict):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal root is not an object"
        )
    return value


def _is_alias_stat(row: os.stat_result) -> bool:
    return stat.S_ISLNK(row.st_mode) or bool(
        getattr(row, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return os.lstat(_native_path(path))
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(f"{label} is unavailable") from exc


def _path_identity(row: os.stat_result) -> dict[str, int]:
    # st_dev/st_ino are the strongest portable identity exposed by Python.
    # Windows' implementation maps these to volume/file identifiers on current
    # supported CPython versions; the attribute value additionally binds the
    # reparse status used by this module.
    return {
        "st_dev": int(row.st_dev),
        "st_ino": int(row.st_ino),
        "st_mode_type": int(stat.S_IFMT(row.st_mode)),
        "st_file_attributes": int(getattr(row, "st_file_attributes", 0)),
    }


def _same_identity(expected: Mapping[str, Any], row: os.stat_result) -> bool:
    return _path_identity(row) == dict(expected)


def _default_runtime_namespace() -> Path:
    """Return the provider-selected per-user namespace, never a worker input."""

    if os.name == "nt":
        base_raw = os.environ.get("LOCALAPPDATA")
        base = Path(base_raw) if base_raw else Path(tempfile.gettempdir())
    else:
        runtime_raw = os.environ.get("XDG_RUNTIME_DIR")
        base = Path(runtime_raw) if runtime_raw else Path.home() / ".cache"
    try:
        stable_base = base.expanduser().resolve(strict=True)
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "provider runtime base is unavailable"
        ) from exc
    return (
        stable_base
        / "Plamen"
        / "runtime"
        / "auxiliary-writable-roots"
        / "v1"
    )


def _assert_no_alias_ancestors(path: Path) -> None:
    current = path.absolute()
    while True:
        if os.path.lexists(current):
            row = _lstat(current, "provider runtime namespace ancestor")
            if _is_alias_stat(row):
                raise AuxiliaryWritableRootLeaseError(
                    "provider runtime namespace has an ancestor alias/reparse point"
                )
        parent = current.parent
        if parent == current:
            return
        current = parent


def _secure_namespace() -> Path:
    requested = Path(_default_runtime_namespace())
    _assert_no_alias_ancestors(requested)
    if os.path.lexists(requested):
        row = _lstat(requested, "provider runtime namespace")
        if _is_alias_stat(row):
            raise AuxiliaryWritableRootLeaseError(
                "provider runtime namespace is an alias/reparse point"
            )
        if not stat.S_ISDIR(row.st_mode):
            raise AuxiliaryWritableRootLeaseError(
                "provider runtime namespace is not a directory"
            )
        _assert_no_alias_ancestors(requested)
    else:
        try:
            requested.mkdir(mode=0o700, parents=True, exist_ok=False)
        except FileExistsError:
            # A concurrent provider may have created the same stable namespace.
            pass
        except OSError as exc:
            raise AuxiliaryWritableRootLeaseError(
                "provider runtime namespace creation failed"
            ) from exc
        row = _lstat(requested, "provider runtime namespace")
        if _is_alias_stat(row):
            raise AuxiliaryWritableRootLeaseError(
                "provider runtime namespace became an alias/reparse point"
            )
        if not stat.S_ISDIR(row.st_mode):
            raise AuxiliaryWritableRootLeaseError(
                "provider runtime namespace is not a directory"
            )
    try:
        requested.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "provider runtime namespace validation failed"
        ) from exc
    # Resolving to another spelling signals either an alias in the final
    # component or path/case canonicalization drift. The direct lstat above
    # rejects final-component aliases; case normalization remains platform
    # native and is also enforced for every selected child.
    if os.path.normcase(str(resolved)) != os.path.normcase(str(requested.absolute())):
        raise AuxiliaryWritableRootLeaseError(
            "provider runtime namespace has an ancestor alias"
        )
    return resolved


def _safe_direct_child(namespace: Path, child: Path) -> bool:
    try:
        common = os.path.commonpath(
            (
                os.path.normcase(str(namespace)),
                os.path.normcase(str(child)),
            )
        )
    except ValueError:
        return False
    return (
        os.path.normcase(common) == os.path.normcase(str(namespace))
        and child.parent == namespace
        and bool(_ROOT_NAME.fullmatch(child.name))
    )


def _casefold_entry_exists(namespace: Path, name: str) -> bool:
    wanted = name.casefold()
    observed = 0
    try:
        with os.scandir(namespace) as entries:
            for entry in entries:
                observed += 1
                if observed > MAX_NAMESPACE_ENTRIES:
                    raise AuxiliaryWritableRootLeaseError(
                        "provider runtime namespace exceeded its traversal bound"
                    )
                if entry.name.casefold() == wanted:
                    return True
            return False
    except AuxiliaryWritableRootLeaseError:
        raise
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "provider runtime namespace enumeration failed"
        ) from exc


def _assert_exact_casefold_entry(namespace: Path, name: str) -> None:
    wanted = name.casefold()
    observed = 0
    matches: list[str] = []
    try:
        with os.scandir(namespace) as entries:
            for entry in entries:
                observed += 1
                if observed > MAX_NAMESPACE_ENTRIES:
                    raise AuxiliaryWritableRootLeaseError(
                        "provider runtime namespace exceeded its traversal bound"
                    )
                if entry.name.casefold() == wanted:
                    matches.append(entry.name)
                    if len(matches) > 1:
                        break
    except AuxiliaryWritableRootLeaseError:
        raise
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "provider runtime namespace enumeration failed"
        ) from exc
    if matches != [name]:
        raise AuxiliaryWritableRootLeaseError(
            "provider-selected path has a casefold alias or spelling drift"
        )


def _select_unique_root(namespace: Path) -> Path:
    for _ in range(MAX_SELECTION_ATTEMPTS):
        name = f"root-{secrets.token_hex(16)}"
        if not _ROOT_NAME.fullmatch(name):
            raise AuxiliaryWritableRootLeaseError(
                "provider random root name is invalid"
            )
        if _casefold_entry_exists(namespace, name):
            continue
        candidate = namespace / name
        if not _safe_direct_child(namespace, candidate):
            raise AuxiliaryWritableRootLeaseError(
                "provider-selected root escaped its namespace"
            )
        return candidate
    raise AuxiliaryWritableRootLeaseError(
        "provider could not select a collision-free auxiliary root"
    )


@dataclass(frozen=True)
class _ReservedEmptyRoot:
    root: Path
    identity: dict[str, int]
    windows_authority: WindowsPrivateExecutionRootAuthority | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __iter__(self):
        # Preserve the historical two-value internal/test unpacking API.
        yield self.root
        yield self.identity


def _create_reserved_empty_root(
    namespace: Path,
    candidate: Path,
) -> _ReservedEmptyRoot:
    if not _safe_direct_child(namespace, candidate):
        raise AuxiliaryWritableRootLeaseError(
            "reserved auxiliary root escaped its namespace"
        )
    name = candidate.name
    if _casefold_entry_exists(namespace, name):
        raise AuxiliaryWritableRootLeaseError(
            "reserved auxiliary root collided before creation"
        )
    windows_authority: WindowsPrivateExecutionRootAuthority | None = None
    try:
        if os.name == "nt":
            windows_authority = create_windows_private_execution_root(
                candidate
            )
        else:
            candidate.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "reserved auxiliary root collided during creation"
        ) from exc
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "provider-selected root creation failed"
        ) from exc
    except WindowsPrivateExecutionRootError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "provider-selected private Windows root creation failed"
        ) from exc
    try:
        row = _lstat(candidate, "provider-selected root")
        if _is_alias_stat(row) or not stat.S_ISDIR(row.st_mode):
            raise AuxiliaryWritableRootLeaseError(
                "provider-selected root is an alias or not a directory"
            )
        if any(candidate.iterdir()):
            raise AuxiliaryWritableRootLeaseError(
                "provider-selected root was not created empty"
            )
        candidate.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        resolved = candidate.resolve(strict=True)
        if resolved.parent != namespace or resolved.name != name:
            raise AuxiliaryWritableRootLeaseError(
                "provider-selected root canonical path drifted"
            )
        _assert_exact_casefold_entry(namespace, name)
        if windows_authority is not None:
            windows_authority.replay()
        return _ReservedEmptyRoot(
            resolved,
            _path_identity(row),
            windows_authority,
        )
    except BaseException:
        if windows_authority is not None:
            try:
                windows_authority.close_after_medium_restore()
            except BaseException:
                pass
        try:
            if os.path.lexists(candidate):
                row = candidate.lstat()
                if _is_alias_stat(row):
                    os.unlink(candidate)
                elif stat.S_ISDIR(row.st_mode):
                    os.rmdir(candidate)
        except OSError:
            pass
        raise


def _create_unique_empty_root(namespace: Path) -> tuple[Path, dict[str, int]]:
    """Compatibility wrapper; durable arms use the two-stage API above."""

    result = _create_reserved_empty_root(
        namespace,
        _select_unique_root(namespace),
    )
    return result.root, result.identity


def _secure_registry(namespace: Path) -> Path:
    registry = namespace / REGISTRY_DIRECTORY_NAME
    if registry.parent != namespace:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry escaped its namespace"
        )
    if os.path.lexists(registry):
        row = _lstat(registry, "auxiliary-root registry")
        if _is_alias_stat(row) or not stat.S_ISDIR(row.st_mode):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root registry is aliased or not a directory"
            )
    else:
        try:
            registry.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError:
            pass
        except OSError as exc:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root registry creation failed"
            ) from exc
        row = _lstat(registry, "auxiliary-root registry")
        if _is_alias_stat(row) or not stat.S_ISDIR(row.st_mode):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root registry is aliased or not a directory"
            )
    try:
        registry.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        resolved = registry.resolve(strict=True)
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry validation failed"
        ) from exc
    if resolved.parent != namespace or resolved.name != REGISTRY_DIRECTORY_NAME:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry canonical path drifted"
        )
    return resolved


def _secure_named_directory(namespace: Path, name: str, label: str) -> Path:
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name)
    ):
        raise AuxiliaryWritableRootLeaseError(
            f"{label} directory name is invalid"
        )
    directory = namespace / name
    if directory.parent != namespace:
        raise AuxiliaryWritableRootLeaseError(
            f"{label} directory escaped its namespace"
        )
    if os.path.lexists(directory):
        row = _lstat(directory, label)
        if _is_alias_stat(row) or not stat.S_ISDIR(row.st_mode):
            raise AuxiliaryWritableRootLeaseError(
                f"{label} is aliased or not a directory"
            )
    else:
        try:
            directory.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError:
            pass
        except OSError as exc:
            raise AuxiliaryWritableRootLeaseError(
                f"{label} creation failed"
            ) from exc
        row = _lstat(directory, label)
        if _is_alias_stat(row) or not stat.S_ISDIR(row.st_mode):
            raise AuxiliaryWritableRootLeaseError(
                f"{label} is aliased or not a directory"
            )
    try:
        directory.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        resolved = directory.resolve(strict=True)
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            f"{label} validation failed"
        ) from exc
    if resolved.parent != namespace or resolved.name != name:
        raise AuxiliaryWritableRootLeaseError(
            f"{label} canonical path drifted"
        )
    _assert_exact_casefold_entry(namespace, name)
    return resolved


def _secure_terminal_archive(namespace: Path) -> Path:
    return _secure_named_directory(
        namespace,
        TERMINAL_ARCHIVE_DIRECTORY_NAME,
        "auxiliary-root terminal archive",
    )


def _secure_abandoned_temp_directory(namespace: Path) -> Path:
    return _secure_named_directory(
        namespace,
        ABANDONED_TEMP_DIRECTORY_NAME,
        "auxiliary-root abandoned-temporary archive",
    )


def _validate_existing_named_directory(
    namespace: Path,
    directory: Path,
    name: str,
    label: str,
) -> Path:
    if directory != namespace / name or directory.parent != namespace:
        raise AuxiliaryWritableRootLeaseError(
            f"{label} directory escaped its namespace"
        )
    _assert_no_alias_ancestors(namespace)
    namespace_row = _lstat(namespace, "provider runtime namespace")
    if _is_alias_stat(namespace_row) or not stat.S_ISDIR(
        namespace_row.st_mode
    ):
        raise AuxiliaryWritableRootLeaseError(
            "provider runtime namespace is aliased or not a directory"
        )
    row = _lstat(directory, label)
    if _is_alias_stat(row) or not stat.S_ISDIR(row.st_mode):
        raise AuxiliaryWritableRootLeaseError(
            f"{label} is aliased or not a directory"
        )
    resolved_namespace = namespace.resolve(strict=True)
    resolved = directory.resolve(strict=True)
    if (
        os.path.normcase(str(resolved_namespace))
        != os.path.normcase(str(namespace.absolute()))
        or resolved.parent != resolved_namespace
        or resolved.name != name
    ):
        raise AuxiliaryWritableRootLeaseError(
            f"{label} canonical path drifted"
        )
    _assert_exact_casefold_entry(resolved_namespace, name)
    return resolved


def _current_platform_identity() -> str:
    return "WINDOWS" if os.name == "nt" else sys.platform.upper()


def _open_registry_lock(namespace: Path) -> tuple[int, Path, dict[str, int]]:
    path = namespace / REGISTRY_LOCK_FILE_NAME
    if path.parent != namespace:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry lock escaped its namespace"
        )
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        row = os.fstat(descriptor)
        if (
            _is_alias_stat(row)
            or not stat.S_ISREG(row.st_mode)
            or int(getattr(row, "st_nlink", 1)) != 1
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root registry lock is aliased or not a file"
            )
        if int(row.st_size) == 0:
            if os.write(descriptor, b"0") != 1:
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root registry lock initialization was truncated"
                )
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        path_row = _lstat(path, "auxiliary-root registry lock")
        if (
            _is_alias_stat(path_row)
            or not stat.S_ISREG(path_row.st_mode)
            or _path_identity(path_row) != _path_identity(os.fstat(descriptor))
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root registry lock identity drifted"
            )
        _assert_exact_casefold_entry(namespace, REGISTRY_LOCK_FILE_NAME)
        return descriptor, path, _path_identity(path_row)
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _try_lock_descriptor(descriptor: int) -> bool:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (OSError, BlockingIOError):
        return False


def _unlock_descriptor(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def _registry_mutation_guard(
    namespace: Path,
    *,
    timeout_seconds: float | None = None,
) -> Iterator[dict[str, Any]]:
    """Serialize honest provider mutation/recovery across processes.

    This is a cooperative OS advisory lock. It closes accidental multi-driver
    races but deliberately does not claim protection from an unrelated
    same-user process that replaces the lock pathname.
    """

    stable_namespace = Path(namespace).resolve(strict=True)
    expected_namespace = _secure_namespace()
    if stable_namespace != expected_namespace:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry lock namespace mismatched"
        )
    timeout = (
        float(REGISTRY_LOCK_TIMEOUT_SECONDS)
        if timeout_seconds is None
        else float(timeout_seconds)
    )
    if not (0.0 < timeout <= 60.0):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry lock timeout is invalid"
        )
    lock_path = stable_namespace / REGISTRY_LOCK_FILE_NAME
    depth = int(getattr(_REGISTRY_LOCK_STATE, "depth", 0) or 0)
    if depth:
        if getattr(_REGISTRY_LOCK_STATE, "path", None) != str(lock_path):
            raise AuxiliaryWritableRootLeaseError(
                "nested auxiliary-root registry lock changed namespace"
            )
        _REGISTRY_LOCK_STATE.depth = depth + 1
        try:
            yield dict(getattr(_REGISTRY_LOCK_STATE, "evidence"))
        finally:
            _REGISTRY_LOCK_STATE.depth = depth
        return

    descriptor, opened_path, identity = _open_registry_lock(stable_namespace)
    acquired = False
    deadline = time.monotonic() + timeout
    try:
        while not acquired:
            acquired = _try_lock_descriptor(descriptor)
            if acquired:
                break
            if time.monotonic() >= deadline:
                raise AuxiliaryWritableRootLockTimeout(
                    "auxiliary-root registry lock timed out"
                )
            time.sleep(min(0.025, max(0.001, timeout / 20.0)))
        path_row = _lstat(opened_path, "auxiliary-root registry lock")
        if _path_identity(path_row) != identity:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root registry lock changed after acquisition"
            )
        evidence = {
            "protocol": "OS_ADVISORY_EXCLUSIVE_REGISTRY_MUTATION_V1",
            "path": str(opened_path),
            "timeout_seconds": timeout,
            "acquired": True,
            "cross_process_cooperative": True,
            "external_same_user_race_free": False,
        }
        _REGISTRY_LOCK_STATE.depth = 1
        _REGISTRY_LOCK_STATE.path = str(opened_path)
        _REGISTRY_LOCK_STATE.evidence = dict(evidence)
        yield dict(evidence)
    finally:
        _REGISTRY_LOCK_STATE.depth = 0
        _REGISTRY_LOCK_STATE.path = None
        _REGISTRY_LOCK_STATE.evidence = None
        if acquired:
            try:
                _unlock_descriptor(descriptor)
            except OSError:
                pass
        os.close(descriptor)


def _journal_path(registry: Path, lease_id: str) -> Path:
    if not isinstance(lease_id, str) or not re.fullmatch(r"[0-9a-f]{32}", lease_id):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal lease id is invalid"
        )
    path = registry / f"lease-{lease_id}.json"
    if path.parent != registry or not _JOURNAL_NAME.fullmatch(path.name):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal path escaped its registry"
        )
    return path


def _regular_file_identity(path: Path, label: str) -> dict[str, int]:
    row = _lstat(path, label)
    if (
        _is_alias_stat(row)
        or not stat.S_ISREG(row.st_mode)
        or int(getattr(row, "st_nlink", 1)) != 1
    ):
        raise AuxiliaryWritableRootLeaseError(f"{label} is aliased or not a file")
    return _path_identity(row)


def _read_regular_file_bounded(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    allow_empty: bool = False,
) -> bytes:
    expected_identity = _regular_file_identity(path, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if _is_alias_stat(before) or not stat.S_ISREG(before.st_mode):
            raise AuxiliaryWritableRootLeaseError(
                f"{label} is aliased or not a regular file"
            )
        if _path_identity(before) != expected_identity:
            raise AuxiliaryWritableRootLeaseError(
                f"{label} identity changed before no-follow open"
            )
        expected_size = int(before.st_size)
        if (
            expected_size < 0
            or (expected_size == 0 and not allow_empty)
            or expected_size > maximum_bytes
        ):
            raise AuxiliaryWritableRootLeaseError(f"{label} size is invalid")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - observed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise AuxiliaryWritableRootLeaseError(
                    f"{label} exceeded its byte bound"
                )
        after = os.fstat(descriptor)
        if (
            _path_identity(before) != _path_identity(after)
            or int(after.st_size) != expected_size
            or observed != expected_size
        ):
            raise AuxiliaryWritableRootLeaseError(
                f"{label} changed during no-follow read"
            )
        return b"".join(chunks)
    except AuxiliaryWritableRootLeaseError:
        raise
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(f"{label} read failed") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(descriptor, raw[offset:])
        except OSError as exc:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root journal write failed"
            ) from exc
        if written <= 0:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root journal write made no progress"
            )
        offset += written


def _publish_record_windows(source: Path, destination: Path, *, replace: bool) -> None:
    from ctypes import wintypes

    move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move.restype = wintypes.BOOL
    flags = 0x00000008  # MOVEFILE_WRITE_THROUGH
    if replace:
        flags |= 0x00000001  # MOVEFILE_REPLACE_EXISTING
    if not move(str(source), str(destination), flags):
        code = ctypes.get_last_error()
        raise AuxiliaryWritableRootLeaseError(
            f"auxiliary-root journal publish failed: {code}"
        )


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        # MoveFileExW(MOVEFILE_WRITE_THROUGH) above is the Windows durability
        # boundary. Opening directories for fsync is not supported by CPython.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry directory sync failed"
        ) from exc


def _publish_record(
    path: Path,
    record: Mapping[str, Any],
    *,
    replace: bool,
) -> None:
    raw = _canonical_json(record)
    if len(raw) > MAX_JOURNAL_BYTES:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal exceeded its byte bound"
        )
    registry = path.parent
    temporary = registry / f".tmp-{path.stem}-{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        _regular_file_identity(temporary, "auxiliary-root temporary journal")
        if os.name == "nt":
            _publish_record_windows(temporary, path, replace=replace)
        elif replace:
            os.replace(temporary, path)
        else:
            # link+unlink is an atomic no-replace publication on POSIX.
            os.link(temporary, path, follow_symlinks=False)
            os.unlink(temporary)
        _sync_directory(registry)
        final_identity = _regular_file_identity(
            path,
            "auxiliary-root durable journal",
        )
        if final_identity["st_mode_type"] != stat.S_IFREG:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root durable journal type drifted"
            )
        if _read_regular_file_bounded(
            path,
            label="auxiliary-root durable journal",
            maximum_bytes=MAX_JOURNAL_BYTES,
        ) != raw:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root durable journal readback mismatched"
            )
    except FileExistsError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal already exists"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if os.path.lexists(temporary):
            try:
                row = temporary.lstat()
                if not _is_alias_stat(row) and stat.S_ISREG(row.st_mode):
                    os.unlink(temporary)
            except OSError:
                pass


def _record_with_digest(core: Mapping[str, Any]) -> dict[str, Any]:
    row = _clone_mapping(core)
    return {**row, "record_sha256": _digest_mapping(row)}


def _write_new_journal_unlocked(
    path: Path,
    core: Mapping[str, Any],
) -> dict[str, Any]:
    if _casefold_entry_exists(path.parent, path.name):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal has a casefold collision"
        )
    record = _record_with_digest(core)
    _publish_record(path, record, replace=False)
    return record


def _write_new_journal(path: Path, core: Mapping[str, Any]) -> dict[str, Any]:
    namespace = path.parent.parent
    with _registry_mutation_guard(namespace):
        return _write_new_journal_unlocked(path, core)


def _read_journal(path: Path) -> dict[str, Any]:
    raw = _read_regular_file_bounded(
        path,
        label="auxiliary-root journal",
        maximum_bytes=MAX_JOURNAL_BYTES,
    )
    return _strict_json_loads(raw)


def _validate_journal_record(
    path: Path,
    record: Mapping[str, Any],
) -> dict[str, Any]:
    row = _clone_mapping(record)
    digest = row.pop("record_sha256", None)
    if not isinstance(digest, str) or digest != _digest_mapping(row):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal digest mismatched"
        )
    if (
        row.get("schema") != JOURNAL_SCHEMA
        or row.get("state") not in _JOURNAL_STATES
        or not isinstance(row.get("revision"), int)
        or isinstance(row.get("revision"), bool)
        or int(row["revision"]) < 1
        or not isinstance(row.get("owner"), dict)
    ):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal envelope is invalid"
        )
    revision = int(row["revision"])
    predecessor = row.get("previous_record_sha256")
    if (
        (revision == 1 and predecessor is not None)
        or (
            revision > 1
            and not _SHA256.fullmatch(str(predecessor or ""))
        )
        or not _SHA256.fullmatch(
            str(row.get("reservation_sha256", ""))
        )
        or not _SAFE_ID.fullmatch(str(row.get("attempt_id", "")))
        or not _SAFE_ID.fullmatch(str(row.get("purpose", "")))
    ):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal chain or reservation linkage is invalid"
        )
    owner = row["owner"]
    if (
        isinstance(owner.get("pid"), bool)
        or not isinstance(owner.get("pid"), int)
        or int(owner["pid"]) <= 0
        or not isinstance(owner.get("platform"), str)
        or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,64}",
            str(owner.get("platform")),
        )
        or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(owner.get("provider_instance_nonce", "")),
        )
        or (
            owner.get("process_start_marker") is not None
            and (
                not isinstance(owner.get("process_start_marker"), str)
                or len(str(owner["process_start_marker"])) > 256
            )
        )
    ):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal owner identity is invalid"
        )
    lease_id = row.get("lease_id")
    if path != _journal_path(path.parent, str(lease_id)):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal filename linkage mismatched"
        )
    namespace = Path(str(row.get("namespace", "")))
    root = Path(str(row.get("root", "")))
    if (
        namespace != path.parent.parent
        or not _safe_direct_child(namespace, root)
        or row.get("attempt_id") is None
        or row.get("purpose") is None
        or not _SHA256.fullmatch(str(row.get("attempt_arm_sha256", "")))
        or not _SAFE_ID.fullmatch(str(row.get("process_scope_identity", "")))
    ):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal immutable linkage is invalid"
        )
    state = str(row["state"])
    if state == "INTENT":
        if (
            revision != 1
            or "binding" in row
            or "root_identity" in row
            or row.get("root_visibility") != "NOT_EXPOSED"
            or row.get("scope_binding") != {"state": "UNBOUND"}
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root intent journal is invalid"
            )
    if state in {"ARMED_UNBOUND", "ARMED_BOUND", "TERMINAL"}:
        binding = row.get("binding")
        if not isinstance(binding, dict):
            # An INTENT can transition directly to TERMINAL during recovery.
            if not (
                state == "TERMINAL"
                and row.get("prior_state") == "INTENT"
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root journal binding is absent"
                )
        else:
            binding_row = dict(binding)
            binding_digest = binding_row.pop("binding_sha256", None)
            if binding_digest != _digest_mapping(binding_row):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root journal binding digest mismatched"
                )
            if (
                binding.get("schema") != LEASE_SCHEMA
                or binding.get("reservation_sha256")
                != row["reservation_sha256"]
                or binding.get("attempt_id") != row["attempt_id"]
                or binding.get("purpose") != row["purpose"]
                or binding.get("attempt_arm_sha256")
                != row["attempt_arm_sha256"]
                or binding.get("process_scope_identity")
                != row["process_scope_identity"]
                or binding.get("root") != str(root)
                or binding.get("namespace") != str(namespace)
                or binding.get("journal", {}).get("path") != str(path)
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root journal binding linkage mismatched"
                )
    if state == "ARMED_UNBOUND":
        scope_binding = row.get("scope_binding")
        unclaimed = scope_binding == {"state": "UNBOUND"}
        claimed = (
            isinstance(scope_binding, dict)
            and scope_binding.get("state")
            == "PRELAUNCH_ABORT_CLAIMED"
            and set(scope_binding) == {"state", "claim_sha256"}
        )
        if (
            (not unclaimed and not claimed)
            or row.get("root_visibility")
            != "EXPOSED_AFTER_DURABLE_ARM"
            or not isinstance(row.get("root_identity"), dict)
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root unbound arm journal is invalid"
            )
        claim_value = row.get("prelaunch_abort_claim")
        if claimed:
            try:
                claim = replay_auxiliary_prelaunch_abort_claim(
                    claim_value
                )
            except AuxiliaryWritableRootLeaseError as exc:
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root prelaunch-abort journal claim is invalid"
                ) from exc
            if (
                claim["claim_sha256"]
                != scope_binding["claim_sha256"]
                or claim["lease_binding_sha256"]
                != row["binding"]["binding_sha256"]
                or claim["attempt_arm_sha256"]
                != row["attempt_arm_sha256"]
                or claim["process_scope_identity"]
                != row["process_scope_identity"]
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root prelaunch-abort journal linkage drifted"
                )
        elif claim_value is not None:
            raise AuxiliaryWritableRootLeaseError(
                "unclaimed auxiliary-root journal carried an abort claim"
            )
    if state == "ARMED_BOUND" and row.get("scope_binding") != {
        "state": "BOUND",
        "process_scope_identity": row["process_scope_identity"],
    }:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal scope binding is invalid"
        )
    if state == "TERMINAL":
        if row.get("prior_state") not in {
            "INTENT",
            "ARMED_UNBOUND",
            "ARMED_BOUND",
        }:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root terminal predecessor state is invalid"
            )
        terminal = row.get("terminal")
        if not isinstance(terminal, dict):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root terminal evidence is absent"
            )
        terminal_row = dict(terminal)
        terminal_digest = terminal_row.pop("terminal_sha256", None)
        if terminal_digest != _digest_mapping(terminal_row):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root terminal evidence digest mismatched"
            )
        if terminal.get("root_absent_after") is not True:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root terminal absence proof is invalid"
            )
        mode = terminal.get("mode")
        if mode == "LEASE_REVOCATION_RECEIPT":
            receipt = terminal.get("receipt")
            if (
                not isinstance(receipt, dict)
                or terminal.get("receipt_sha256")
                != receipt.get("receipt_sha256")
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root terminal receipt linkage is invalid"
                )
            if receipt.get("revocation_mode") == "PRELAUNCH_ABORT":
                try:
                    claim = replay_auxiliary_prelaunch_abort_claim(
                        row.get("prelaunch_abort_claim")
                    )
                except AuxiliaryWritableRootLeaseError as exc:
                    raise AuxiliaryWritableRootLeaseError(
                        "prelaunch-abort terminal claim is invalid"
                    ) from exc
                if (
                    receipt.get("prelaunch_abort_claim_sha256")
                    != claim["claim_sha256"]
                    or claim["lease_binding_sha256"]
                    != row["binding"]["binding_sha256"]
                    or claim["attempt_arm_sha256"]
                    != row["attempt_arm_sha256"]
                    or claim["process_scope_identity"]
                    != row["process_scope_identity"]
                    or claim["reason_code"]
                    != receipt.get("reason_code")
                    or row.get("scope_binding")
                    != {
                        "state": "PRELAUNCH_ABORT_CLAIMED",
                        "claim_sha256": claim["claim_sha256"],
                    }
                ):
                    raise AuxiliaryWritableRootLeaseError(
                        "prelaunch-abort terminal claim linkage drifted"
                    )
        elif mode == "STARTUP_ORPHAN_RECOVERY":
            if (
                terminal.get("prior_record_sha256")
                != row.get("previous_record_sha256")
                or terminal.get("prior_state") != row.get("prior_state")
                or terminal.get("owner_status", {}).get("status")
                != "PROVEN_DEAD"
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root recovery terminal linkage is invalid"
                )
            scope_recovery = terminal.get("process_scope_recovery")
            if row.get("prior_state") == "ARMED_BOUND":
                if (
                    not isinstance(scope_recovery, dict)
                    or scope_recovery.get("population_zero") is not True
                    or scope_recovery.get("identity")
                    != row.get("process_scope_identity")
                ):
                    raise AuxiliaryWritableRootLeaseError(
                        "auxiliary-root recovery scope proof is invalid"
                    )
            elif scope_recovery is not None:
                raise AuxiliaryWritableRootLeaseError(
                    "unbound auxiliary-root recovery claimed a scope proof"
                )
        else:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root terminal mode is invalid"
            )
    return {**row, "record_sha256": digest}


def _load_journal_record(path: Path) -> dict[str, Any]:
    return _validate_journal_record(path, _read_journal(path))


def _transition_journal_unlocked(
    path: Path,
    expected_record_sha256: str,
    update: Mapping[str, Any],
) -> dict[str, Any]:
    current = _load_journal_record(path)
    if current["record_sha256"] != expected_record_sha256:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal transition lost its predecessor"
        )
    core = dict(current)
    previous = str(core.pop("record_sha256"))
    core.update(_clone_mapping(update))
    core["revision"] = int(current["revision"]) + 1
    core["previous_record_sha256"] = previous
    record = _record_with_digest(core)
    _publish_record(path, record, replace=True)
    replay = _validate_journal_record(path, _read_journal(path))
    if replay["record_sha256"] != record["record_sha256"]:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root journal transition readback lost ownership"
        )
    return replay


def _transition_journal(
    path: Path,
    expected_record_sha256: str,
    update: Mapping[str, Any],
) -> dict[str, Any]:
    namespace = path.parent.parent
    with _registry_mutation_guard(namespace):
        return _transition_journal_unlocked(
            path,
            expected_record_sha256,
            update,
        )


def _move_regular_file_no_replace(
    source: Path,
    destination: Path,
    *,
    label: str,
    allow_empty: bool = False,
) -> None:
    source_raw = _read_regular_file_bounded(
        source,
        label=f"{label} source",
        maximum_bytes=MAX_JOURNAL_BYTES,
        allow_empty=allow_empty,
    )
    if os.path.lexists(destination):
        destination_raw = _read_regular_file_bounded(
            destination,
            label=f"{label} destination",
            maximum_bytes=MAX_JOURNAL_BYTES,
            allow_empty=allow_empty,
        )
        if destination_raw != source_raw:
            raise AuxiliaryWritableRootLeaseError(
                f"{label} destination conflicts with source"
            )
        os.unlink(source)
        _sync_directory(source.parent)
        return
    try:
        if os.name == "nt":
            _publish_record_windows(source, destination, replace=False)
        else:
            os.link(source, destination, follow_symlinks=False)
            os.unlink(source)
        _sync_directory(destination.parent)
        if source.parent != destination.parent:
            _sync_directory(source.parent)
    except AuxiliaryWritableRootLeaseError:
        raise
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(f"{label} move failed") from exc
    if os.path.lexists(source):
        raise AuxiliaryWritableRootLeaseError(
            f"{label} source remained after move"
        )
    if (
        _read_regular_file_bounded(
            destination,
            label=f"{label} destination",
            maximum_bytes=MAX_JOURNAL_BYTES,
            allow_empty=allow_empty,
        )
        != source_raw
    ):
        raise AuxiliaryWritableRootLeaseError(
            f"{label} destination readback mismatched"
        )


def _load_archived_terminal_record(
    logical_journal_path: Path,
    archived_path: Path,
) -> dict[str, Any]:
    namespace = logical_journal_path.parent.parent
    expected_archive = _terminal_archive_path_for_logical(
        logical_journal_path
    )
    if archived_path != expected_archive:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root archived journal path mismatched"
        )
    _validate_existing_named_directory(
        namespace,
        archived_path.parent,
        TERMINAL_ARCHIVE_DIRECTORY_NAME,
        "auxiliary-root terminal archive",
    )
    raw = _read_regular_file_bounded(
        archived_path,
        label="auxiliary-root archived terminal journal",
        maximum_bytes=MAX_JOURNAL_BYTES,
    )
    record = _validate_journal_record(
        logical_journal_path,
        _strict_json_loads(raw),
    )
    if record["state"] != "TERMINAL":
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root archived journal is not terminal"
        )
    return record


def _terminal_archive_path_for_logical(
    logical_journal_path: Path,
) -> Path:
    namespace = logical_journal_path.parent.parent
    archive = namespace / TERMINAL_ARCHIVE_DIRECTORY_NAME
    path = archive / logical_journal_path.name
    if (
        archive.parent != namespace
        or path.parent != archive
        or not _JOURNAL_NAME.fullmatch(path.name)
    ):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root terminal archive path escaped"
        )
    return path


def _compact_terminal_journal(
    path: Path,
    record: Mapping[str, Any],
) -> Path:
    namespace = path.parent.parent
    with _registry_mutation_guard(namespace):
        expected_digest = str(record.get("record_sha256", ""))
        if not _SHA256.fullmatch(expected_digest):
            raise AuxiliaryWritableRootLeaseError(
                "terminal compaction record digest is invalid"
            )
        if os.path.lexists(path):
            current = _load_journal_record(path)
            if (
                current["state"] != "TERMINAL"
                or current["record_sha256"] != expected_digest
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "terminal compaction lost journal ownership"
                )
        archive = _secure_terminal_archive(namespace)
        destination = archive / path.name
        if os.path.lexists(path):
            _move_regular_file_no_replace(
                path,
                destination,
                label="auxiliary-root terminal compaction",
            )
        archived = _load_archived_terminal_record(path, destination)
        if archived["record_sha256"] != expected_digest:
            raise AuxiliaryWritableRootLeaseError(
                "terminal compaction archive digest mismatched"
            )
        return destination


def _quarantine_abandoned_temporary_journal(path: Path) -> Path:
    if not _TEMP_JOURNAL_NAME.fullmatch(path.name):
        raise AuxiliaryWritableRootLeaseError(
            "abandoned temporary journal name is invalid"
        )
    namespace = path.parent.parent
    with _registry_mutation_guard(namespace):
        archive = _secure_abandoned_temp_directory(namespace)
        destination = archive / path.name
        _move_regular_file_no_replace(
            path,
            destination,
            label="auxiliary-root abandoned temporary journal",
            allow_empty=True,
        )
        return destination


def _linux_process_start_marker(pid: int) -> str | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        close = raw.rfind(")")
        if close < 0:
            return None
        fields = raw[close + 2 :].split()
        start_ticks = fields[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
        if not boot or not start_ticks.isdigit():
            return None
        return f"{boot}:{start_ticks}"
    except (OSError, IndexError, UnicodeError):
        return None


def _windows_process_probe(pid: int) -> tuple[str, str | None]:
    from ctypes import wintypes

    process = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = process.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    handle = open_process(0x100000 | 0x1000, False, pid)
    if not handle:
        code = ctypes.get_last_error()
        if code in {87, 1168}:  # invalid parameter / not found
            return "DEAD", None
        return "UNCERTAIN", None
    try:
        exit_code = wintypes.DWORD()
        get_exit = process.GetExitCodeProcess
        get_exit.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_exit.restype = wintypes.BOOL
        if not get_exit(handle, ctypes.byref(exit_code)):
            return "UNCERTAIN", None
        if int(exit_code.value) != 259:  # STILL_ACTIVE
            return "DEAD", None
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        get_times = process.GetProcessTimes
        get_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        get_times.restype = wintypes.BOOL
        if not get_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return "UNCERTAIN", None
        marker = (
            (int(creation.dwHighDateTime) << 32)
            | int(creation.dwLowDateTime)
        )
        return "LIVE", str(marker)
    finally:
        process.CloseHandle(handle)


def _process_start_marker(pid: int) -> tuple[str, str | None]:
    if os.name == "nt":
        return _windows_process_probe(pid)
    if sys.platform.startswith("linux"):
        marker = _linux_process_start_marker(pid)
        if marker is not None:
            return "LIVE", marker
        if not os.path.exists(f"/proc/{pid}"):
            return "DEAD", None
        return "UNCERTAIN", None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "DEAD", None
    except (PermissionError, OSError):
        return "UNCERTAIN", None
    return "LIVE", None


def _provider_owner_identity() -> dict[str, Any]:
    pid = os.getpid()
    status, marker = _process_start_marker(pid)
    if status != "LIVE":
        raise AuxiliaryWritableRootLeaseError(
            "provider process start identity is unavailable"
        )
    return {
        "pid": pid,
        "platform": _current_platform_identity(),
        "process_start_marker": marker,
        "provider_instance_nonce": _PROVIDER_INSTANCE_NONCE,
    }


def _provider_owner_status(owner: Mapping[str, Any]) -> dict[str, str]:
    try:
        pid = owner["pid"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            return {"status": "UNCERTAIN", "reason": "OWNER_PID_INVALID"}
        if owner.get("platform") != _current_platform_identity():
            return {
                "status": "UNCERTAIN",
                "reason": "OWNER_PLATFORM_MISMATCH",
            }
        expected_marker = owner.get("process_start_marker")
        if (
            pid == os.getpid()
            and owner.get("provider_instance_nonce") == _PROVIDER_INSTANCE_NONCE
        ):
            current = _provider_owner_identity()
            if current.get("process_start_marker") == expected_marker:
                return {
                    "status": "EXACT_LIVE",
                    "reason": "CURRENT_PROVIDER_IDENTITY_MATCH",
                }
        status, marker = _process_start_marker(pid)
        if status == "DEAD":
            return {"status": "PROVEN_DEAD", "reason": "PROCESS_ABSENT"}
        if status != "LIVE":
            return {
                "status": "UNCERTAIN",
                "reason": "PROCESS_LIVENESS_UNPROVEN",
            }
        if expected_marker is None or marker is None:
            return {
                "status": "UNCERTAIN",
                "reason": "PROCESS_START_IDENTITY_UNAVAILABLE",
            }
        if str(marker) == str(expected_marker):
            return {
                "status": "EXACT_LIVE",
                "reason": "PID_AND_START_IDENTITY_MATCH",
            }
        return {
            "status": "PROVEN_DEAD",
            "reason": "PID_REUSED_START_IDENTITY_MISMATCH",
        }
    except (KeyError, TypeError, ValueError):
        return {"status": "UNCERTAIN", "reason": "OWNER_IDENTITY_INVALID"}


def _recover_persisted_scope(process_scope_identity: str) -> dict[str, Any]:
    from owned_process_scope import recover_persisted_process_scope

    return recover_persisted_process_scope(process_scope_identity)


@dataclass(frozen=True)
class _CleanupRow:
    path: Path
    depth: int
    mode: int
    aliased: bool
    identity: Mapping[str, int]
    nominal_bytes: int


def _scan_cleanup_tree(root: Path) -> tuple[list[_CleanupRow], dict[str, int]]:
    rows: list[_CleanupRow] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    total_bytes = 0
    aliases = 0
    while stack:
        directory, depth = stack.pop()
        if depth > MAX_CLEANUP_DEPTH:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root cleanup exceeded its depth bound"
            )
        try:
            with os.scandir(_native_path(directory)) as entries:
                for entry in entries:
                    if len(rows) >= MAX_CLEANUP_ENTRIES:
                        raise AuxiliaryWritableRootLeaseError(
                            "auxiliary-root cleanup exceeded its entry bound"
                        )
                    child = Path(entry.path)
                    try:
                        # Use the same Path.lstat API at scan and removal time.
                        # On Windows, DirEntry.stat may expose a different
                        # st_ino/st_dev quality than Path.lstat.
                        row = os.lstat(_native_path(child))
                    except OSError as exc:
                        raise AuxiliaryWritableRootLeaseError(
                            "auxiliary-root cleanup stat failed"
                        ) from exc
                    aliased = entry.is_symlink() or _is_alias_stat(row)
                    nominal_bytes = (
                        0
                        if aliased or stat.S_ISDIR(row.st_mode)
                        else max(0, int(row.st_size))
                    )
                    total_bytes += nominal_bytes
                    if total_bytes > MAX_CLEANUP_BYTES:
                        raise AuxiliaryWritableRootLeaseError(
                            "auxiliary-root cleanup exceeded its byte bound"
                        )
                    rows.append(
                        _CleanupRow(
                            path=child,
                            depth=depth + 1,
                            mode=int(row.st_mode),
                            aliased=aliased,
                            identity=_path_identity(row),
                            nominal_bytes=nominal_bytes,
                        )
                    )
                    if aliased:
                        aliases += 1
                    elif stat.S_ISDIR(row.st_mode):
                        stack.append((child, depth + 1))
        except AuxiliaryWritableRootLeaseError:
            raise
        except OSError as exc:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root cleanup enumeration failed"
            ) from exc
    return rows, {
        "entries": len(rows),
        "nominal_bytes": total_bytes,
        "aliases": aliases,
        "max_depth": max((row.depth for row in rows), default=0),
    }


def _unlink_alias(path: Path, mode: int) -> None:
    operations = (os.rmdir, os.unlink) if stat.S_ISDIR(mode) else (os.unlink, os.rmdir)
    last_error: OSError | None = None
    for operation in operations:
        try:
            operation(_native_path(path))
            return
        except FileNotFoundError:
            return
        except OSError as exc:
            last_error = exc
    raise AuxiliaryWritableRootLeaseError(
        "auxiliary-root alias cleanup failed"
    ) from last_error


def _remove_scanned_tree(
    root: Path,
    root_identity: Mapping[str, Any],
    rows: list[_CleanupRow],
) -> None:
    current_root = _lstat(root, "auxiliary-root cleanup root")
    if (
        _is_alias_stat(current_root)
        or not stat.S_ISDIR(current_root.st_mode)
        or not _same_identity(root_identity, current_root)
    ):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root root identity drifted before cleanup"
        )
    for planned in sorted(rows, key=lambda item: item.depth, reverse=True):
        try:
            current = os.lstat(_native_path(planned.path))
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root cleanup replay stat failed"
            ) from exc
        current_alias = _is_alias_stat(current)
        if current_alias:
            _unlink_alias(planned.path, current.st_mode)
            continue
        if not _same_identity(planned.identity, current):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root descendant identity drifted before cleanup"
            )
        try:
            if stat.S_ISDIR(current.st_mode):
                os.rmdir(_native_path(planned.path))
            else:
                os.unlink(_native_path(planned.path))
        except FileNotFoundError:
            continue
        except PermissionError:
            try:
                os.chmod(
                    _native_path(planned.path),
                    stat.S_IRUSR | stat.S_IWUSR | (
                        stat.S_IXUSR if stat.S_ISDIR(current.st_mode) else 0
                    ),
                    follow_symlinks=False,
                )
                if stat.S_ISDIR(current.st_mode):
                    os.rmdir(_native_path(planned.path))
                else:
                    os.unlink(_native_path(planned.path))
            except OSError as exc:
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root cleanup permission repair failed"
                ) from exc
        except OSError as exc:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root cleanup unlink failed"
            ) from exc
    final_root = _lstat(root, "auxiliary-root cleanup root")
    if (
        _is_alias_stat(final_root)
        or not stat.S_ISDIR(final_root.st_mode)
        or not _same_identity(root_identity, final_root)
    ):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root root identity drifted before final removal"
        )
    try:
        os.rmdir(_native_path(root))
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root final removal failed"
        ) from exc


def _zero_cleanup_scan() -> dict[str, int]:
    return {
        "entries": 0,
        "nominal_bytes": 0,
        "aliases": 0,
        "max_depth": 0,
    }


def _terminal_evidence_for_receipt(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": RECOVERY_TERMINAL_SCHEMA,
        "mode": "LEASE_REVOCATION_RECEIPT",
        "receipt_sha256": receipt["receipt_sha256"],
        "receipt": _clone_mapping(receipt),
        "root_absent_after": True,
    }
    return {**core, "terminal_sha256": _digest_mapping(core)}


def _persist_lease_terminal(
    lease: Any,
    receipt: Mapping[str, Any],
) -> None:
    terminal = _terminal_evidence_for_receipt(receipt)
    namespace = lease._journal_path.parent.parent
    with _registry_mutation_guard(namespace):
        if os.path.lexists(lease._journal_path):
            current = _load_journal_record(lease._journal_path)
        else:
            archived_path = _terminal_archive_path_for_logical(
                lease._journal_path
            )
            current = _load_archived_terminal_record(
                lease._journal_path,
                archived_path,
            )
        if current["state"] == "TERMINAL":
            if current.get("terminal") != terminal:
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root terminal journal conflicts with the receipt"
                )
            lease._journal_sha256 = str(current["record_sha256"])
            _compact_terminal_journal(lease._journal_path, current)
            return
        if current["record_sha256"] != lease._journal_sha256:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root terminal transition lost journal ownership"
            )
        transitioned = _transition_journal(
            lease._journal_path,
            lease._journal_sha256,
            {
                "state": "TERMINAL",
                "prior_state": current["state"],
                "terminal": terminal,
            },
        )
        lease._journal_sha256 = str(transitioned["record_sha256"])
        _compact_terminal_journal(lease._journal_path, transitioned)


class ScopeClosureToken:
    """Opaque evidence minted only after an exact owned process scope closes."""

    __slots__ = (
        "_capability",
        "_lease_sha256",
        "_scope_identity",
        "_evidence_sha256",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        lease_sha256: str,
        scope_identity: str,
        evidence_sha256: str,
    ) -> ScopeClosureToken:
        if _capability is not _TOKEN_CAPABILITY:
            raise TypeError("ScopeClosureToken is opaque")
        instance = super().__new__(cls)
        object.__setattr__(instance, "_capability", _capability)
        object.__setattr__(instance, "_lease_sha256", lease_sha256)
        object.__setattr__(instance, "_scope_identity", scope_identity)
        object.__setattr__(instance, "_evidence_sha256", evidence_sha256)
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("ScopeClosureToken is immutable")

    def __reduce__(self) -> object:
        raise TypeError("ScopeClosureToken cannot be serialized")

    def __repr__(self) -> str:
        return "<ScopeClosureToken opaque>"


def _owned_process_scope_type() -> type[Any]:
    from owned_process_scope import OwnedProcessScope

    return OwnedProcessScope


def replay_auxiliary_prelaunch_abort_claim(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a durable, non-completion prelaunch-abort claim binding."""

    if not isinstance(value, Mapping):
        raise AuxiliaryWritableRootLeaseError(
            "prelaunch-abort claim must be an object"
        )
    clone = _clone_mapping(value)
    expected_fields = {
        "schema",
        "lease_binding_sha256",
        "attempt_arm_sha256",
        "process_scope_identity",
        "reason_code",
        "completion_authority",
        "claim_sha256",
    }
    if set(clone) != expected_fields:
        raise AuxiliaryWritableRootLeaseError(
            "prelaunch-abort claim fields drifted"
        )
    core = dict(clone)
    digest = core.pop("claim_sha256", None)
    if (
        core.get("schema") != PRELAUNCH_ABORT_CLAIM_SCHEMA
        or not isinstance(core.get("lease_binding_sha256"), str)
        or _SHA256.fullmatch(core["lease_binding_sha256"]) is None
        or not isinstance(core.get("attempt_arm_sha256"), str)
        or _SHA256.fullmatch(core["attempt_arm_sha256"]) is None
        or not isinstance(core.get("process_scope_identity"), str)
        or _SAFE_ID.fullmatch(core["process_scope_identity"]) is None
        or not isinstance(core.get("reason_code"), str)
        or _SAFE_ID.fullmatch(core["reason_code"]) is None
        or core.get("completion_authority") is not False
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or digest != _digest_mapping(core)
    ):
        raise AuxiliaryWritableRootLeaseError(
            "prelaunch-abort claim does not replay"
        )
    return {**core, "claim_sha256": digest}


class AuxiliaryPrelaunchAbortClaim:
    """Opaque live claim that serializes prelaunch abort against scope bind."""

    __slots__ = (
        "_binding",
        "_capability",
        "_lease_nonce",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        binding: Mapping[str, Any],
        lease_nonce: object,
    ) -> "AuxiliaryPrelaunchAbortClaim":
        if _capability is not _PRELAUNCH_ABORT_CLAIM_CAPABILITY:
            raise TypeError("AuxiliaryPrelaunchAbortClaim is opaque")
        instance = super().__new__(cls)
        object.__setattr__(instance, "_capability", _capability)
        object.__setattr__(
            instance,
            "_binding",
            MappingProxyType(
                replay_auxiliary_prelaunch_abort_claim(binding)
            ),
        )
        object.__setattr__(instance, "_lease_nonce", lease_nonce)
        return instance

    @property
    def binding(self) -> dict[str, Any]:
        return _clone_mapping(self._binding)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError(
            "AuxiliaryPrelaunchAbortClaim is immutable"
        )

    def __reduce__(self) -> None:
        raise TypeError(
            "AuxiliaryPrelaunchAbortClaim cannot be serialized"
        )

    def __repr__(self) -> str:
        return "<AuxiliaryPrelaunchAbortClaim opaque>"


@dataclass
class AuxiliaryWritableRootLease:
    """An armed lease. The path did not become visible before this object."""

    root: Path
    _binding: Mapping[str, Any]
    _root_identity: Mapping[str, Any]
    _journal_path: Path
    _journal_sha256: str
    _windows_private_root_authority: (
        WindowsPrivateExecutionRootAuthority | None
    ) = field(default=None, repr=False)
    _receipt: Mapping[str, Any] | None = None
    _scope_started: bool = False
    _lifecycle_lock: Any = field(
        default_factory=threading.RLock,
        repr=False,
    )
    _prelaunch_abort_claim: AuxiliaryPrelaunchAbortClaim | None = field(
        default=None,
        repr=False,
    )
    _prelaunch_abort_claim_nonce: object = field(
        default_factory=object,
        repr=False,
    )

    @property
    def roots(self) -> tuple[Path, ...]:
        return (self.root,)

    @property
    def windows_private_execution_root_authority(
        self,
    ) -> WindowsPrivateExecutionRootAuthority | None:
        """Return the opaque authority WER must pass into the Windows scope."""

        authority = self._windows_private_root_authority
        if authority is not None:
            authority.replay()
        return authority

    def _close_windows_private_root_for_cleanup(self) -> None:
        authority = self._windows_private_root_authority
        if authority is None:
            return
        authority.close_after_medium_restore()
        self._windows_private_root_authority = None

    @property
    def binding(self) -> dict[str, Any]:
        return _clone_mapping(self._binding)

    @property
    def journal_path(self) -> Path:
        return self._journal_path

    @property
    def process_scope_bound(self) -> bool:
        with self._lifecycle_lock:
            return self._scope_started

    @property
    def prelaunch_abort_claimed(self) -> bool:
        with self._lifecycle_lock:
            return self._prelaunch_abort_claim is not None

    def _validate_prelaunch_abort_authority(
        self,
        *,
        attempt_arm_sha256: str,
        process_scope_identity: str,
        reason_code: str,
    ) -> None:
        if (
            attempt_arm_sha256
            != self._binding["attempt_arm_sha256"]
            or process_scope_identity
            != self._binding["process_scope_identity"]
            or not isinstance(reason_code, str)
            or not _SAFE_ID.fullmatch(reason_code)
        ):
            raise AuxiliaryWritableRootLeaseError(
                "prelaunch abort authority does not match the armed lease"
            )

    def claim_prelaunch_abort(
        self,
        *,
        attempt_arm_sha256: str,
        process_scope_identity: str,
        reason_code: str,
    ) -> AuxiliaryPrelaunchAbortClaim:
        """Atomically make future process-scope binding impossible."""

        with self._lifecycle_lock:
            self._validate_prelaunch_abort_authority(
                attempt_arm_sha256=attempt_arm_sha256,
                process_scope_identity=process_scope_identity,
                reason_code=reason_code,
            )
            if self._scope_started:
                raise AuxiliaryWritableRootLeaseError(
                    "prelaunch abort is forbidden after process scope "
                    "lifecycle began"
                )
            if self._receipt is not None:
                if (
                    self._receipt.get("revocation_mode")
                    != "PRELAUNCH_ABORT"
                    or self._receipt.get("reason_code") != reason_code
                    or self._prelaunch_abort_claim is None
                ):
                    raise AuxiliaryWritableRootLeaseError(
                        "revoked auxiliary root has no matching abort claim"
                    )
                return self._prelaunch_abort_claim
            if self._prelaunch_abort_claim is not None:
                existing = self._prelaunch_abort_claim.binding
                if (
                    existing["attempt_arm_sha256"]
                    != attempt_arm_sha256
                    or existing["process_scope_identity"]
                    != process_scope_identity
                    or existing["reason_code"] != reason_code
                ):
                    raise AuxiliaryWritableRootLeaseError(
                        "a different prelaunch abort was already claimed"
                    )
                return self._prelaunch_abort_claim
            core = {
                "schema": PRELAUNCH_ABORT_CLAIM_SCHEMA,
                "lease_binding_sha256": self._binding[
                    "binding_sha256"
                ],
                "attempt_arm_sha256": attempt_arm_sha256,
                "process_scope_identity": process_scope_identity,
                "reason_code": reason_code,
                "completion_authority": False,
            }
            binding = {
                **core,
                "claim_sha256": _digest_mapping(core),
            }
            claim = AuxiliaryPrelaunchAbortClaim(
                _capability=_PRELAUNCH_ABORT_CLAIM_CAPABILITY,
                binding=binding,
                lease_nonce=self._prelaunch_abort_claim_nonce,
            )
            journal = _transition_journal(
                self._journal_path,
                self._journal_sha256,
                {
                    "state": "ARMED_UNBOUND",
                    "scope_binding": {
                        "state": "PRELAUNCH_ABORT_CLAIMED",
                        "claim_sha256": binding["claim_sha256"],
                    },
                    "prelaunch_abort_claim": binding,
                },
            )
            self._journal_sha256 = str(journal["record_sha256"])
            self._prelaunch_abort_claim = claim
            return claim

    def _require_live_prelaunch_abort_claim(
        self,
        claim: AuxiliaryPrelaunchAbortClaim,
    ) -> dict[str, Any]:
        if (
            type(claim) is not AuxiliaryPrelaunchAbortClaim
            or claim._capability
            is not _PRELAUNCH_ABORT_CLAIM_CAPABILITY
            or claim._lease_nonce
            is not self._prelaunch_abort_claim_nonce
            or claim is not self._prelaunch_abort_claim
        ):
            raise AuxiliaryWritableRootLeaseError(
                "prelaunch abort claim is not live for this lease"
            )
        binding = replay_auxiliary_prelaunch_abort_claim(
            claim.binding
        )
        if binding["lease_binding_sha256"] != self._binding[
            "binding_sha256"
        ]:
            raise AuxiliaryWritableRootLeaseError(
                "prelaunch abort claim lease binding drifted"
            )
        return binding

    def bind_process_scope(self, scope: object) -> None:
        """Make the prelaunch-abort path unavailable for this lease."""

        with self._lifecycle_lock:
            if self._receipt is not None:
                raise AuxiliaryWritableRootLeaseError(
                    "revoked auxiliary root cannot bind a process scope"
                )
            if self._prelaunch_abort_claim is not None:
                raise AuxiliaryWritableRootLeaseError(
                    "prelaunch abort was already claimed; process scope "
                    "binding is forbidden"
                )
            expected_type = _owned_process_scope_type()
            if type(scope) is not expected_type:
                raise AuxiliaryWritableRootLeaseError(
                    "process scope type is not the trusted OwnedProcessScope"
                )
            if getattr(scope, "persistent_identity", None) != self._binding[
                "process_scope_identity"
            ]:
                raise AuxiliaryWritableRootLeaseError(
                    "process scope identity does not match the "
                    "auxiliary-root lease"
                )
            if self._scope_started:
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root process scope is already bound"
                )
            journal = _transition_journal(
                self._journal_path,
                self._journal_sha256,
                {
                    "state": "ARMED_BOUND",
                    "scope_binding": {
                        "state": "BOUND",
                        "process_scope_identity": self._binding[
                            "process_scope_identity"
                        ],
                    },
                },
            )
            self._journal_sha256 = str(journal["record_sha256"])
            self._scope_started = True

    def abort_before_process_scope(
        self,
        *,
        attempt_arm_sha256: str,
        process_scope_identity: str,
        reason_code: str,
        claim: AuxiliaryPrelaunchAbortClaim | None = None,
    ) -> dict[str, Any]:
        """Revoke a root when the trusted coordinator launched no process scope."""

        with self._lifecycle_lock:
            self._validate_prelaunch_abort_authority(
                attempt_arm_sha256=attempt_arm_sha256,
                process_scope_identity=process_scope_identity,
                reason_code=reason_code,
            )
            if self._scope_started:
                raise AuxiliaryWritableRootLeaseError(
                    "prelaunch abort is forbidden after process scope "
                    "lifecycle began"
                )
            if self._receipt is not None and claim is None:
                if (
                    self._receipt.get("revocation_mode")
                    != "PRELAUNCH_ABORT"
                    or self._prelaunch_abort_claim is None
                ):
                    raise AuxiliaryWritableRootLeaseError(
                        "revoked auxiliary root has no completed "
                        "prelaunch abort"
                    )
                # A wrapper may make a best-effort abort call after an inner
                # layer already completed the exact claimed abort.  This is a
                # terminal receipt observation only: it creates no claim,
                # performs no cleanup, and grants no completion authority.
                # Explicit-claim replay below remains exact.
                return _clone_mapping(self._receipt)
            active_claim = (
                self.claim_prelaunch_abort(
                    attempt_arm_sha256=attempt_arm_sha256,
                    process_scope_identity=process_scope_identity,
                    reason_code=reason_code,
                )
                if claim is None
                else claim
            )
            claim_binding = self._require_live_prelaunch_abort_claim(
                active_claim
            )
            if (
                claim_binding["attempt_arm_sha256"]
                != attempt_arm_sha256
                or claim_binding["process_scope_identity"]
                != process_scope_identity
                or claim_binding["reason_code"] != reason_code
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "prelaunch abort claim authority drifted"
                )
            if self._receipt is not None:
                if (
                    self._receipt.get("revocation_mode")
                    != "PRELAUNCH_ABORT"
                    or self._receipt.get(
                        "prelaunch_abort_claim_sha256"
                    )
                    != claim_binding["claim_sha256"]
                    or self._receipt.get("reason_code")
                    != reason_code
                ):
                    raise AuxiliaryWritableRootLeaseError(
                        "completed abort differs from the live claim"
                    )
                return _clone_mapping(self._receipt)
            if os.path.lexists(self.root):
                replay = replay_auxiliary_writable_root_binding(
                    self._binding
                )
                if replay["valid"] is not True:
                    raise AuxiliaryWritableRootLeaseError(
                        "auxiliary-root root identity drifted before "
                        "prelaunch abort"
                    )
                rows, scan = _scan_cleanup_tree(self.root)
                self._close_windows_private_root_for_cleanup()
                _remove_scanned_tree(
                    self.root,
                    self._root_identity,
                    rows,
                )
            else:
                scan = _zero_cleanup_scan()
            if os.path.lexists(self.root):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root remained after prelaunch abort"
                )
            abort_evidence = {
                "lease_binding_sha256": self._binding[
                    "binding_sha256"
                ],
                "prelaunch_abort_claim_sha256": claim_binding[
                    "claim_sha256"
                ],
                "attempt_arm_sha256": attempt_arm_sha256,
                "process_scope_identity": process_scope_identity,
                "process_scope_created": False,
                "reason_code": reason_code,
            }
            receipt_core: dict[str, Any] = {
                "schema": REVOCATION_SCHEMA,
                "lease_binding_sha256": self._binding[
                    "binding_sha256"
                ],
                "revocation_mode": "PRELAUNCH_ABORT",
                "prelaunch_abort_claim_sha256": claim_binding[
                    "claim_sha256"
                ],
                "prelaunch_abort_evidence_sha256": _digest_mapping(
                    abort_evidence
                ),
                "process_scope_identity": process_scope_identity,
                "reason_code": reason_code,
                "revoked": True,
                "root_absent_after": True,
                "entries_removed": scan["entries"],
                "nominal_bytes_removed": scan["nominal_bytes"],
                "aliases_unlinked": scan["aliases"],
                "max_depth_observed": scan["max_depth"],
                "cleanup_authority": {
                    "protocol": (
                        "ATOMIC_CLAIM_THEN_BOUNDED_NO_FOLLOW_"
                        "PRELAUNCH_ABORT"
                    ),
                    "kernel_enforced_write_confinement": False,
                    "external_same_user_race_free": False,
                },
            }
            receipt = {
                **receipt_core,
                "receipt_sha256": _digest_mapping(receipt_core),
            }
            _persist_lease_terminal(self, receipt)
            self._receipt = MappingProxyType(
                _clone_mapping(receipt)
            )
            return _clone_mapping(receipt)

    def revoke(self, closure: ScopeClosureToken) -> dict[str, Any]:
        with self._lifecycle_lock:
            return self._revoke_locked(closure)

    def _revoke_locked(
        self,
        closure: ScopeClosureToken,
    ) -> dict[str, Any]:
        if self._receipt is not None:
            if (
                not isinstance(closure, ScopeClosureToken)
                or closure._capability is not _TOKEN_CAPABILITY
                or closure._lease_sha256 != self._binding["binding_sha256"]
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root closure token is invalid"
                )
            return _clone_mapping(self._receipt)
        if (
            not isinstance(closure, ScopeClosureToken)
            or closure._capability is not _TOKEN_CAPABILITY
            or closure._lease_sha256 != self._binding["binding_sha256"]
            or closure._scope_identity
            != self._binding["process_scope_identity"]
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root closure token is invalid"
            )
        if not self._scope_started:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root process scope was never bound"
            )
        if os.path.lexists(self.root):
            replay = replay_auxiliary_writable_root_binding(self._binding)
            if replay["valid"] is not True:
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root root identity drifted before cleanup"
                )
            rows, scan = _scan_cleanup_tree(self.root)
            self._close_windows_private_root_for_cleanup()
            _remove_scanned_tree(self.root, self._root_identity, rows)
        else:
            scan = _zero_cleanup_scan()
        if os.path.lexists(self.root):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root remained after cleanup"
            )
        receipt_core: dict[str, Any] = {
            "schema": REVOCATION_SCHEMA,
            "lease_binding_sha256": self._binding["binding_sha256"],
            "revocation_mode": "NORMAL_SCOPE_CLOSURE",
            "scope_closure_evidence_sha256": closure._evidence_sha256,
            "process_scope_identity": closure._scope_identity,
            "revoked": True,
            "root_absent_after": True,
            "entries_removed": scan["entries"],
            "nominal_bytes_removed": scan["nominal_bytes"],
            "aliases_unlinked": scan["aliases"],
            "max_depth_observed": scan["max_depth"],
            "cleanup_authority": {
                "protocol": "BOUNDED_NO_FOLLOW_IDENTITY_REPLAY",
                "kernel_enforced_write_confinement": False,
                "external_same_user_race_free": False,
            },
        }
        receipt = {
            **receipt_core,
            "receipt_sha256": _digest_mapping(receipt_core),
        }
        _persist_lease_terminal(self, receipt)
        self._receipt = MappingProxyType(_clone_mapping(receipt))
        return _clone_mapping(receipt)


@dataclass
class AuxiliaryWritableRootReservation:
    """Path-opaque reservation that can be armed exactly once."""

    _reservation_binding: Mapping[str, Any]
    _armed: bool = False

    @property
    def binding(self) -> dict[str, Any]:
        return _clone_mapping(self._reservation_binding)

    def arm(
        self,
        *,
        attempt_arm_sha256: str,
        process_scope_identity: str,
    ) -> AuxiliaryWritableRootLease:
        if self._armed:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reservation is already armed"
            )
        if (
            not isinstance(attempt_arm_sha256, str)
            or not _SHA256.fullmatch(attempt_arm_sha256)
        ):
            raise AuxiliaryWritableRootLeaseError(
                "AttemptArm digest is invalid"
            )
        if (
            not isinstance(process_scope_identity, str)
            or not _SAFE_ID.fullmatch(process_scope_identity)
        ):
            raise AuxiliaryWritableRootLeaseError(
                "process-scope identity is invalid"
            )
        namespace = _secure_namespace()
        registry = _secure_registry(namespace)
        candidate = _select_unique_root(namespace)
        journal_path = _journal_path(
            registry,
            str(self._reservation_binding["lease_id"]),
        )
        intent_core: dict[str, Any] = {
            "schema": JOURNAL_SCHEMA,
            "revision": 1,
            "previous_record_sha256": None,
            "state": "INTENT",
            "lease_id": self._reservation_binding["lease_id"],
            "reservation_sha256": self._reservation_binding[
                "reservation_sha256"
            ],
            "attempt_id": self._reservation_binding["attempt_id"],
            "purpose": self._reservation_binding["purpose"],
            "attempt_arm_sha256": attempt_arm_sha256,
            "process_scope_identity": process_scope_identity,
            "namespace": str(namespace),
            "root": str(candidate),
            "owner": _provider_owner_identity(),
            "root_visibility": "NOT_EXPOSED",
            "scope_binding": {"state": "UNBOUND"},
        }
        intent = _write_new_journal(journal_path, intent_core)
        # Once the intent is durable, this reservation is consumed even if a
        # crash occurs in mkdir or the ARMED transition. Startup reconciliation
        # owns that exact candidate from this point onward.
        self._armed = True
        created_root = _create_reserved_empty_root(namespace, candidate)
        root, identity = created_root
        binding_core: dict[str, Any] = {
            "schema": LEASE_SCHEMA,
            "reservation_sha256": self._reservation_binding[
                "reservation_sha256"
            ],
            "lease_id": self._reservation_binding["lease_id"],
            "attempt_id": self._reservation_binding["attempt_id"],
            "purpose": self._reservation_binding["purpose"],
            "attempt_arm_sha256": attempt_arm_sha256,
            "process_scope_identity": process_scope_identity,
            "namespace": str(namespace),
            "root": str(root),
            "root_identity": dict(identity),
            "journal": {
                "schema": JOURNAL_SCHEMA,
                "path": str(journal_path),
                "registry": str(registry),
            },
            "lifecycle": {
                "before": "ABSENT",
                "after": "CREATED_EMPTY",
            },
            "selection_authority": {
                "protocol": (
                    "PROVIDER_SELECTED_ATOMIC_UNIQUE_DIRECT_CHILD_MKDIR"
                ),
                "caller_supplied_path": False,
                "casefold_collision_checked": True,
                "alias_rejected": True,
                "portable_identity": "ST_DEV_ST_INO_MODE_ATTRIBUTES",
                "kernel_enforced_write_confinement": False,
                "external_same_user_race_free": False,
            },
        }
        binding = {
            **binding_core,
            "binding_sha256": _digest_mapping(binding_core),
        }
        armed = _transition_journal(
            journal_path,
            str(intent["record_sha256"]),
            {
                "state": "ARMED_UNBOUND",
                "root_visibility": "EXPOSED_AFTER_DURABLE_ARM",
                "root_identity": dict(identity),
                "binding": binding,
            },
        )
        return AuxiliaryWritableRootLease(
            root=root,
            _binding=MappingProxyType(dict(binding)),
            _root_identity=MappingProxyType(dict(identity)),
            _journal_path=journal_path,
            _journal_sha256=str(armed["record_sha256"]),
            _windows_private_root_authority=getattr(
                created_root,
                "windows_authority",
                None,
            ),
        )


def reserve_auxiliary_writable_root(
    *,
    attempt_id: str,
    purpose: str,
) -> AuxiliaryWritableRootReservation:
    """Reserve an opaque lease without accepting or exposing a root path."""

    if not isinstance(attempt_id, str) or not _SAFE_ID.fullmatch(attempt_id):
        raise AuxiliaryWritableRootLeaseError("attempt_id is invalid")
    if not isinstance(purpose, str) or not _SAFE_ID.fullmatch(purpose):
        raise AuxiliaryWritableRootLeaseError("purpose is invalid")
    core: dict[str, Any] = {
        "schema": RESERVATION_SCHEMA,
        "lease_id": uuid.uuid4().hex,
        "attempt_id": attempt_id,
        "purpose": purpose,
        "root_visibility": "WITHHELD_UNTIL_ARM",
        "caller_supplied_path": False,
    }
    binding = {
        **core,
        "reservation_sha256": _digest_mapping(core),
    }
    return AuxiliaryWritableRootReservation(
        _reservation_binding=MappingProxyType(binding)
    )


def prove_owned_process_scope_closed(
    lease: AuxiliaryWritableRootLease,
    scope: object,
) -> ScopeClosureToken:
    """Mint opaque closure evidence from the exact trusted scope type."""

    if not isinstance(lease, AuxiliaryWritableRootLease):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root lease is invalid"
        )
    expected_type = _owned_process_scope_type()
    if type(scope) is not expected_type:
        raise AuxiliaryWritableRootLeaseError(
            "process scope type is not the trusted OwnedProcessScope"
        )
    if getattr(scope, "persistent_identity", None) != lease._binding[
        "process_scope_identity"
    ]:
        raise AuxiliaryWritableRootLeaseError(
            "process scope identity does not match the auxiliary-root lease"
        )
    if lease._scope_started is not True:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root process scope was never bound"
        )
    if getattr(scope, "closed", None) is not True:
        raise AuxiliaryWritableRootLeaseError(
            "process scope closure is not proven"
        )
    if getattr(scope, "population_zero_proven", None) is not True:
        raise AuxiliaryWritableRootLeaseError(
            "process scope population-zero proof is absent"
        )
    evidence = {
        "lease_binding_sha256": lease._binding["binding_sha256"],
        "process_scope_identity": lease._binding["process_scope_identity"],
        "closed": True,
        "population_zero_proven": True,
        "emergency_closed": bool(getattr(scope, "emergency_closed", False)),
    }
    return ScopeClosureToken(
        _capability=_TOKEN_CAPABILITY,
        lease_sha256=str(lease._binding["binding_sha256"]),
        scope_identity=str(lease._binding["process_scope_identity"]),
        evidence_sha256=_digest_mapping(evidence),
    )


def replay_auxiliary_writable_root_binding(
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay an armed lease while its root remains live."""

    try:
        row = dict(binding)
        digest = row.pop("binding_sha256")
        if digest != _digest_mapping(row):
            return {"valid": False, "reason": "BINDING_DIGEST_MISMATCH"}
        if row.get("schema") != LEASE_SCHEMA:
            return {"valid": False, "reason": "SCHEMA_MISMATCH"}
        namespace = Path(str(row["namespace"]))
        root = Path(str(row["root"]))
        if not _safe_direct_child(namespace, root):
            return {"valid": False, "reason": "ROOT_PATH_UNSAFE"}
        namespace_row = namespace.lstat()
        root_row = root.lstat()
        if (
            _is_alias_stat(namespace_row)
            or not stat.S_ISDIR(namespace_row.st_mode)
        ):
            return {"valid": False, "reason": "NAMESPACE_ALIAS_OR_TYPE_DRIFT"}
        if _is_alias_stat(root_row) or not stat.S_ISDIR(root_row.st_mode):
            return {"valid": False, "reason": "ROOT_ALIAS_OR_TYPE_DRIFT"}
        if not _same_identity(row["root_identity"], root_row):
            return {"valid": False, "reason": "ROOT_IDENTITY_DRIFT"}
        resolved_namespace = namespace.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
        if resolved_root.parent != resolved_namespace or resolved_root != root:
            return {"valid": False, "reason": "ROOT_CANONICAL_DRIFT"}
        journal_binding = row.get("journal")
        if not isinstance(journal_binding, dict):
            return {"valid": False, "reason": "JOURNAL_BINDING_ABSENT"}
        journal_path = Path(str(journal_binding.get("path", "")))
        if (
            journal_binding.get("schema") != JOURNAL_SCHEMA
            or journal_binding.get("registry") != str(journal_path.parent)
            or journal_path.parent.parent != resolved_namespace
        ):
            return {"valid": False, "reason": "JOURNAL_BINDING_UNSAFE"}
        journal = _load_journal_record(journal_path)
        if (
            journal.get("state") not in {"ARMED_UNBOUND", "ARMED_BOUND"}
            or journal.get("binding") != binding
        ):
            return {"valid": False, "reason": "JOURNAL_STATE_MISMATCH"}
        return {
            "valid": True,
            "reason": "LIVE_ROOT_IDENTITY_REPLAYED",
            "binding_sha256": digest,
        }
    except (
        AuxiliaryWritableRootLeaseError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ):
        return {"valid": False, "reason": "BINDING_REPLAY_FAILED"}


def replay_auxiliary_writable_root_revocation(
    binding: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a completed revocation without requiring the deleted root."""

    try:
        binding_row = dict(binding)
        binding_digest = binding_row.pop("binding_sha256")
        if binding_digest != _digest_mapping(binding_row):
            return {"valid": False, "reason": "BINDING_DIGEST_MISMATCH"}
        receipt_row = dict(receipt)
        receipt_digest = receipt_row.pop("receipt_sha256")
        if receipt_digest != _digest_mapping(receipt_row):
            return {"valid": False, "reason": "RECEIPT_DIGEST_MISMATCH"}
        if (
            receipt_row.get("schema") != REVOCATION_SCHEMA
            or receipt_row.get("lease_binding_sha256") != binding_digest
            or receipt_row.get("revoked") is not True
            or receipt_row.get("root_absent_after") is not True
            or receipt_row.get("revocation_mode")
            not in {"NORMAL_SCOPE_CLOSURE", "PRELAUNCH_ABORT"}
        ):
            return {"valid": False, "reason": "RECEIPT_LINKAGE_MISMATCH"}
        if (
            receipt_row.get("revocation_mode") == "NORMAL_SCOPE_CLOSURE"
            and not _SHA256.fullmatch(
                str(receipt_row.get("scope_closure_evidence_sha256", ""))
            )
        ):
            return {"valid": False, "reason": "CLOSURE_EVIDENCE_MALFORMED"}
        if (
            receipt_row.get("revocation_mode") == "PRELAUNCH_ABORT"
            and (
                not _SHA256.fullmatch(
                    str(
                        receipt_row.get(
                            "prelaunch_abort_claim_sha256",
                            "",
                        )
                    )
                )
                or not _SHA256.fullmatch(
                    str(
                        receipt_row.get(
                            "prelaunch_abort_evidence_sha256",
                            "",
                        )
                    )
                )
                or receipt_row.get("process_scope_identity")
                != binding_row.get("process_scope_identity")
                or not isinstance(receipt_row.get("reason_code"), str)
                or _SAFE_ID.fullmatch(receipt_row["reason_code"]) is None
                or receipt_row.get("prelaunch_abort_evidence_sha256")
                != _digest_mapping({
                    "lease_binding_sha256": binding_digest,
                    "prelaunch_abort_claim_sha256": receipt_row[
                        "prelaunch_abort_claim_sha256"
                    ],
                    "attempt_arm_sha256": binding_row[
                        "attempt_arm_sha256"
                    ],
                    "process_scope_identity": binding_row[
                        "process_scope_identity"
                    ],
                    "process_scope_created": False,
                    "reason_code": receipt_row["reason_code"],
                })
            )
        ):
            return {"valid": False, "reason": "PRELAUNCH_EVIDENCE_MALFORMED"}
        root = Path(str(binding_row["root"]))
        if os.path.lexists(root):
            return {"valid": False, "reason": "ROOT_REAPPEARED"}
        return {
            "valid": True,
            "reason": "REVOCATION_REPLAYED",
            "binding_sha256": binding_digest,
            "receipt_sha256": receipt_digest,
        }
    except (KeyError, TypeError, ValueError):
        return {"valid": False, "reason": "REVOCATION_REPLAY_FAILED"}


def replay_auxiliary_writable_root_journal(
    journal_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Replay one durable lifecycle journal without authorizing recovery."""

    try:
        path = Path(journal_path).absolute()
        if os.path.lexists(path):
            record = _load_journal_record(path)
        else:
            archived_path = _terminal_archive_path_for_logical(path)
            record = _load_archived_terminal_record(path, archived_path)
        state = str(record["state"])
        result: dict[str, Any] = {
            "valid": True,
            "reason": "JOURNAL_REPLAYED",
            "state": state,
            "record_sha256": record["record_sha256"],
            "root": record["root"],
            "process_scope_identity": record["process_scope_identity"],
        }
        binding = record.get("binding")
        if isinstance(binding, dict):
            result["binding_sha256"] = binding["binding_sha256"]
        if state == "TERMINAL":
            terminal = record["terminal"]
            if os.path.lexists(Path(str(record["root"]))):
                return {
                    "valid": False,
                    "reason": "TERMINAL_ROOT_REAPPEARED",
                }
            if terminal.get("mode") == "LEASE_REVOCATION_RECEIPT":
                if not isinstance(binding, dict) or not isinstance(
                    terminal.get("receipt"), dict
                ):
                    return {
                        "valid": False,
                        "reason": "TERMINAL_RECEIPT_LINKAGE_INVALID",
                    }
                replay = replay_auxiliary_writable_root_revocation(
                    binding,
                    terminal["receipt"],
                )
                if replay["valid"] is not True:
                    return {
                        "valid": False,
                        "reason": "TERMINAL_RECEIPT_REPLAY_FAILED",
                    }
                result["receipt_sha256"] = terminal["receipt_sha256"]
            elif terminal.get("mode") != "STARTUP_ORPHAN_RECOVERY":
                return {
                    "valid": False,
                    "reason": "TERMINAL_MODE_INVALID",
                }
            result["prior_state"] = record.get("prior_state")
        return result
    except (
        AuxiliaryWritableRootLeaseError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ):
        return {"valid": False, "reason": "JOURNAL_REPLAY_FAILED"}


def _cleanup_orphaned_journal_root(
    record: Mapping[str, Any],
) -> dict[str, int]:
    namespace = Path(str(record["namespace"]))
    root = Path(str(record["root"]))
    if not _safe_direct_child(namespace, root):
        raise AuxiliaryWritableRootLeaseError(
            "orphaned auxiliary root path is unsafe"
        )
    namespace_row = _lstat(namespace, "orphaned auxiliary-root namespace")
    if _is_alias_stat(namespace_row) or not stat.S_ISDIR(namespace_row.st_mode):
        raise AuxiliaryWritableRootLeaseError(
            "orphaned auxiliary-root namespace drifted"
        )
    if not os.path.lexists(root):
        return _zero_cleanup_scan()
    root_row = _lstat(root, "orphaned auxiliary root")
    if _is_alias_stat(root_row) or not stat.S_ISDIR(root_row.st_mode):
        raise AuxiliaryWritableRootLeaseError(
            "orphaned auxiliary root is aliased or not a directory"
        )
    if record["state"] != "INTENT":
        expected = record.get("root_identity")
        if not isinstance(expected, dict) or not _same_identity(
            expected,
            root_row,
        ):
            raise AuxiliaryWritableRootLeaseError(
                "orphaned auxiliary root identity drifted"
            )
    observed_identity = _path_identity(root_row)
    rows, scan = _scan_cleanup_tree(root)
    _remove_scanned_tree(root, observed_identity, rows)
    if os.path.lexists(root):
        raise AuxiliaryWritableRootLeaseError(
            "orphaned auxiliary root remained after recovery"
        )
    return scan


def _startup_recovery_terminal(
    record: Mapping[str, Any],
    *,
    owner_status: Mapping[str, Any],
    process_scope_recovery: Mapping[str, Any] | None,
    scan: Mapping[str, Any],
) -> dict[str, Any]:
    evidence_core: dict[str, Any] = {
        "schema": RECOVERY_TERMINAL_SCHEMA,
        "mode": "STARTUP_ORPHAN_RECOVERY",
        "prior_record_sha256": record["record_sha256"],
        "prior_state": record["state"],
        "owner_status": _clone_mapping(owner_status),
        "process_scope_recovery": (
            None
            if process_scope_recovery is None
            else _clone_mapping(process_scope_recovery)
        ),
        "root_absent_after": True,
        "entries_removed": int(scan["entries"]),
        "nominal_bytes_removed": int(scan["nominal_bytes"]),
        "aliases_unlinked": int(scan["aliases"]),
        "max_depth_observed": int(scan["max_depth"]),
        "cleanup_authority": {
            "protocol": (
                "PROVEN_DEAD_OWNER_THEN_SCOPE_ZERO_THEN_BOUNDED_NO_FOLLOW"
            ),
            "live_or_uncertain_owner_cleanup": False,
            "kernel_enforced_write_confinement": False,
            "external_same_user_race_free": False,
        },
    }
    return {
        **evidence_core,
        "terminal_sha256": _digest_mapping(evidence_core),
    }


def _bounded_registry_entries(
    registry: Path,
    *,
    maximum_entries: int,
) -> tuple[list[Path], bool]:
    if (
        isinstance(maximum_entries, bool)
        or not isinstance(maximum_entries, int)
        or maximum_entries < 0
    ):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry bound is invalid"
        )
    paths: list[Path] = []
    try:
        with os.scandir(registry) as entries:
            for entry in entries:
                paths.append(Path(entry.path))
                if len(paths) > maximum_entries:
                    return [], False
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root registry enumeration failed"
        ) from exc
    return sorted(paths, key=lambda path: path.name), True


def _bounded_namespace_root_entries(
    namespace: Path,
) -> tuple[list[Path], bool]:
    roots: list[Path] = []
    observed = 0
    try:
        with os.scandir(namespace) as entries:
            for entry in entries:
                observed += 1
                if observed > MAX_NAMESPACE_ENTRIES:
                    return [], False
                if re.fullmatch(
                    r"root-[0-9a-f]{32}",
                    entry.name,
                    flags=re.IGNORECASE,
                ):
                    roots.append(Path(entry.path))
    except OSError as exc:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root namespace inventory failed"
        ) from exc
    return sorted(roots, key=lambda path: path.name.casefold()), True


def _finalize_reconciliation_report(
    report: Mapping[str, Any],
) -> dict[str, Any]:
    core = _clone_mapping(report)
    return {**core, "report_sha256": _digest_mapping(core)}


def _append_reconciliation_detail(
    report: dict[str, Any],
    detail: Mapping[str, Any],
) -> None:
    if len(report["details"]) < MAX_RECONCILIATION_DETAILS:
        report["details"].append(_clone_mapping(detail))
    else:
        report["details_truncated"] = int(
            report.get("details_truncated", 0)
        ) + 1


def _set_reconciliation_disposition(
    report: dict[str, Any],
    *,
    disposition: str,
    debt_category: str | None,
    debt_reason: str | None,
) -> None:
    if disposition not in {
        "ALLOW_NEW_LEASES",
        "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT",
        "DENY_NEW_LEASES",
    }:
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root allocation disposition is invalid"
        )
    required = disposition != "ALLOW_NEW_LEASES"
    if required != (debt_category is not None and debt_reason is not None):
        raise AuxiliaryWritableRootLeaseError(
            "auxiliary-root reconciliation debt linkage is invalid"
        )
    report["allocation_disposition"] = disposition
    report["runtime_debt"] = {
        "required": required,
        "category": debt_category,
        "reason": debt_reason,
    }


def replay_auxiliary_writable_root_reconciliation(
    reconciliation: Mapping[str, Any],
) -> dict[str, Any]:
    """Strictly replay one driver-bindable startup reconciliation report."""

    try:
        row = _clone_mapping(reconciliation)
        expected_keys = {
            "schema",
            "namespace",
            "registry",
            "complete",
            "reason",
            "allocation_disposition",
            "runtime_debt",
            "registry_lock",
            "scanned",
            "recovered",
            "terminal",
            "terminal_compacted",
            "temporary_quarantined",
            "registry_scan_nominal_bytes",
            "active_registry_entries",
            "live",
            "quarantined",
            "legacy_unjournaled",
            "details",
            "details_truncated",
            "report_sha256",
        }
        if set(row) != expected_keys:
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation fields are invalid"
            )
        digest = row.pop("report_sha256")
        if not isinstance(digest, str) or digest != _digest_mapping(row):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation digest mismatched"
            )
        if (
            row.get("schema") != RECONCILIATION_SCHEMA
            or not isinstance(row.get("namespace"), str)
            or not row["namespace"]
            or not isinstance(row.get("registry"), str)
            or not row["registry"]
            or not isinstance(row.get("complete"), bool)
            or not isinstance(row.get("reason"), str)
            or not row["reason"]
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation envelope is invalid"
            )
        namespace_path = Path(row["namespace"])
        if (
            not namespace_path.is_absolute()
            or Path(row["registry"])
            != namespace_path / REGISTRY_DIRECTORY_NAME
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation path linkage is invalid"
            )
        counters = (
            "scanned",
            "recovered",
            "terminal",
            "terminal_compacted",
            "temporary_quarantined",
            "registry_scan_nominal_bytes",
            "active_registry_entries",
            "live",
            "quarantined",
            "legacy_unjournaled",
            "details_truncated",
        )
        if any(
            isinstance(row.get(name), bool)
            or not isinstance(row.get(name), int)
            or int(row[name]) < 0
            for name in counters
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation counters are invalid"
            )
        details = row.get("details")
        if (
            not isinstance(details, list)
            or len(details) > MAX_RECONCILIATION_DETAILS
            or any(
                not isinstance(detail, dict)
                or not isinstance(detail.get("path"), str)
                or not isinstance(detail.get("disposition"), str)
                or not isinstance(detail.get("reason"), str)
                for detail in details
            )
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation details are invalid"
            )
        disposition = row.get("allocation_disposition")
        debt = row.get("runtime_debt")
        if (
            disposition
            not in {
                "ALLOW_NEW_LEASES",
                "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT",
                "DENY_NEW_LEASES",
            }
            or not isinstance(debt, dict)
            or set(debt) != {"required", "category", "reason"}
            or not isinstance(debt.get("required"), bool)
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation disposition is invalid"
            )
        requires_debt = disposition != "ALLOW_NEW_LEASES"
        if (
            debt["required"] is not requires_debt
            or (
                requires_debt
                and (
                    not isinstance(debt.get("category"), str)
                    or not debt["category"]
                    or not isinstance(debt.get("reason"), str)
                    or not debt["reason"]
                )
            )
            or (
                not requires_debt
                and (
                    debt.get("category") is not None
                    or debt.get("reason") is not None
                )
            )
            or (row["complete"] is True and requires_debt)
            or (
                row["complete"] is False
                and disposition == "ALLOW_NEW_LEASES"
            )
            or (
                disposition == "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT"
                and row["reason"]
                != "RECONCILIATION_COMPLETE_WITH_QUARANTINE"
            )
            or (
                disposition == "DENY_NEW_LEASES"
                and row["reason"]
                == "RECONCILIATION_COMPLETE_WITH_QUARANTINE"
            )
            or (
                row["complete"] is True
                and (
                    row["reason"] != "RECONCILIATION_COMPLETE"
                    or row["quarantined"] != 0
                )
            )
            or (
                row["complete"] is False
                and row["reason"] == "RECONCILIATION_COMPLETE"
            )
            or row["terminal_compacted"]
            > row["terminal"] + row["recovered"]
            or row["temporary_quarantined"] > row["scanned"]
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation debt is inconsistent"
            )
        lock = row.get("registry_lock")
        if (
            not isinstance(lock, dict)
            or set(lock)
            != {
                "protocol",
                "path",
                "timeout_seconds",
                "acquired",
                "cross_process_cooperative",
                "external_same_user_race_free",
            }
            or lock.get("protocol")
            != "OS_ADVISORY_EXCLUSIVE_REGISTRY_MUTATION_V1"
            or not isinstance(lock.get("path"), str)
            or not lock["path"]
            or Path(lock["path"])
            != namespace_path / REGISTRY_LOCK_FILE_NAME
            or isinstance(lock.get("timeout_seconds"), bool)
            or not isinstance(lock.get("timeout_seconds"), (int, float))
            or not (0.0 < float(lock["timeout_seconds"]) <= 60.0)
            or not isinstance(lock.get("acquired"), bool)
            or lock.get("cross_process_cooperative") is not True
            or lock.get("external_same_user_race_free") is not False
            or (
                (lock["acquired"] is False)
                != (row["reason"] == "REGISTRY_LOCK_TIMEOUT")
            )
        ):
            raise AuxiliaryWritableRootLeaseError(
                "auxiliary-root reconciliation lock evidence is invalid"
            )
        return {
            "valid": True,
            "reason": "RECONCILIATION_REPLAYED",
            "report_sha256": digest,
            "complete": row["complete"],
            "allocation_disposition": disposition,
            "runtime_debt": _clone_mapping(debt),
        }
    except (
        AuxiliaryWritableRootLeaseError,
        KeyError,
        TypeError,
        ValueError,
    ):
        return {
            "valid": False,
            "reason": "RECONCILIATION_REPLAY_FAILED",
        }


def reconcile_auxiliary_writable_root_leases() -> dict[str, Any]:
    """Conservatively recover journals whose provider owner is provably dead.

    This is a startup primitive. Callers must invoke it before arming new
    leases. It never removes a root owned by a live or ambiguously identified
    provider, and it requires process-scope population-zero recovery for every
    journal that durably reached ARMED_BOUND.
    """

    namespace = _secure_namespace()
    registry_path = namespace / REGISTRY_DIRECTORY_NAME
    report: dict[str, Any] = {
        "schema": RECONCILIATION_SCHEMA,
        "namespace": str(namespace),
        "registry": str(registry_path),
        "complete": True,
        "reason": "RECONCILIATION_COMPLETE",
        "allocation_disposition": "ALLOW_NEW_LEASES",
        "runtime_debt": {
            "required": False,
            "category": None,
            "reason": None,
        },
        "registry_lock": {
            "protocol": "OS_ADVISORY_EXCLUSIVE_REGISTRY_MUTATION_V1",
            "path": str(namespace / REGISTRY_LOCK_FILE_NAME),
            "timeout_seconds": float(REGISTRY_LOCK_TIMEOUT_SECONDS),
            "acquired": False,
            "cross_process_cooperative": True,
            "external_same_user_race_free": False,
        },
        "scanned": 0,
        "recovered": 0,
        "terminal": 0,
        "terminal_compacted": 0,
        "temporary_quarantined": 0,
        "registry_scan_nominal_bytes": 0,
        "active_registry_entries": 0,
        "live": 0,
        "quarantined": 0,
        "legacy_unjournaled": 0,
        "details": [],
        "details_truncated": 0,
    }
    try:
        with _registry_mutation_guard(namespace) as lock_evidence:
            report["registry_lock"] = lock_evidence
            registry = _secure_registry(namespace)
            profile_lifecycle_directory = (
                namespace / PROFILE_LIFECYCLE_DIRECTORY_NAME
            )
            try:
                profile_reconciliation = (
                    _owned_directory
                    .reconcile_owned_directory_cleanup_ledgers(
                        profile_lifecycle_directory
                    )
                )
                if (
                    profile_reconciliation.get("complete") is not True
                    or profile_reconciliation.get(
                        "completion_authority"
                    )
                    is not False
                ):
                    raise AuxiliaryWritableRootLeaseError(
                        "profile lifecycle reconciliation did not replay"
                    )
                if profile_reconciliation.get(
                    "directory_present"
                ) is True:
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(profile_lifecycle_directory),
                            "disposition": (
                                "PROFILE_LIFECYCLE_REPLAYED"
                            ),
                            "reason": str(
                                profile_reconciliation["reason"]
                            ),
                            "receipt_sha256": str(
                                profile_reconciliation[
                                    "receipt_sha256"
                                ]
                            ),
                            "scanned": int(
                                profile_reconciliation["scanned"]
                            ),
                            "recovered": int(
                                profile_reconciliation["recovered"]
                            ),
                            "terminal": int(
                                profile_reconciliation["terminal"]
                            ),
                            "completion_authority": False,
                        },
                    )
            except (
                _owned_directory.OwnedDirectoryGuardError,
                AuxiliaryWritableRootLeaseError,
                OSError,
            ) as exc:
                # Outer-root cleanup would erase the only remaining profile
                # recovery target. Fail closed before inventorying or
                # disposing any orphaned outer lease root.
                report["complete"] = False
                report["reason"] = (
                    "PROFILE_LIFECYCLE_RECOVERY_UNPROVEN"
                )
                # Preserve a bounded typed cause, never arbitrary exception text.
                profile_failure_code = getattr(exc, "code", None)
                profile_failure_detail = (
                    {"cause_code": profile_failure_code}
                    if isinstance(exc, _owned_directory.OwnedDirectoryGuardError)
                    and isinstance(profile_failure_code, str)
                    and re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", profile_failure_code)
                    else {}
                )
                _append_reconciliation_detail(
                    report,
                    {
                        "path": str(profile_lifecycle_directory),
                        "disposition": "QUARANTINED",
                        "reason": (
                            "PROFILE_LIFECYCLE_RECOVERY_UNPROVEN:"
                            f"{type(exc).__name__}"
                        ),
                        **profile_failure_detail,
                    },
                )
                _set_reconciliation_disposition(
                    report,
                    disposition="DENY_NEW_LEASES",
                    debt_category=(
                        "AUXILIARY_ROOT_PROFILE_LIFECYCLE_RECOVERY"
                    ),
                    debt_reason=report["reason"],
                )
                return _finalize_reconciliation_report(report)
            namespace_roots, namespace_within_bound = (
                _bounded_namespace_root_entries(namespace)
            )
            if not namespace_within_bound:
                report["complete"] = False
                report["reason"] = "NAMESPACE_BOUND_EXCEEDED"
                _set_reconciliation_disposition(
                    report,
                    disposition="DENY_NEW_LEASES",
                    debt_category=(
                        "AUXILIARY_ROOT_RECONCILIATION_NAMESPACE_BOUND"
                    ),
                    debt_reason=report["reason"],
                )
                return _finalize_reconciliation_report(report)
            entries, within_recovery_bound = _bounded_registry_entries(
                registry,
                maximum_entries=MAX_REGISTRY_RECOVERY_ENTRIES,
            )
            if not within_recovery_bound:
                report["complete"] = False
                report["reason"] = "REGISTRY_RECOVERY_BOUND_EXCEEDED"
                _set_reconciliation_disposition(
                    report,
                    disposition="DENY_NEW_LEASES",
                    debt_category=(
                        "AUXILIARY_ROOT_RECONCILIATION_REGISTRY_BOUND"
                    ),
                    debt_reason=report["reason"],
                )
                return _finalize_reconciliation_report(report)
            report["scanned"] = len(entries)
            if (
                isinstance(MAX_REGISTRY_RECOVERY_BYTES, bool)
                or not isinstance(MAX_REGISTRY_RECOVERY_BYTES, int)
                or MAX_REGISTRY_RECOVERY_BYTES < 0
            ):
                raise AuxiliaryWritableRootLeaseError(
                    "auxiliary-root registry recovery byte bound is invalid"
                )
            try:
                nominal_bytes = 0
                for path in entries:
                    inventory_row = path.lstat()
                    if stat.S_ISREG(inventory_row.st_mode):
                        nominal_bytes += max(
                            0,
                            int(inventory_row.st_size),
                        )
            except OSError:
                report["complete"] = False
                report["reason"] = "REGISTRY_RECOVERY_INVENTORY_UNPROVEN"
                _set_reconciliation_disposition(
                    report,
                    disposition="DENY_NEW_LEASES",
                    debt_category=(
                        "AUXILIARY_ROOT_RECONCILIATION_REGISTRY_INVENTORY"
                    ),
                    debt_reason=report["reason"],
                )
                return _finalize_reconciliation_report(report)
            report["registry_scan_nominal_bytes"] = nominal_bytes
            if nominal_bytes > MAX_REGISTRY_RECOVERY_BYTES:
                report["complete"] = False
                report["reason"] = "REGISTRY_RECOVERY_BYTE_BOUND_EXCEEDED"
                _set_reconciliation_disposition(
                    report,
                    disposition="DENY_NEW_LEASES",
                    debt_category=(
                        "AUXILIARY_ROOT_RECONCILIATION_REGISTRY_BOUND"
                    ),
                    debt_reason=report["reason"],
                )
                return _finalize_reconciliation_report(report)

            journal_entries: list[Path] = []
            for path in entries:
                if not _TEMP_JOURNAL_NAME.fullmatch(path.name):
                    journal_entries.append(path)
                    continue
                try:
                    path_row = _lstat(
                        path,
                        "auxiliary-root temporary registry entry",
                    )
                    if _is_alias_stat(path_row) or not stat.S_ISREG(
                        path_row.st_mode
                    ):
                        raise AuxiliaryWritableRootLeaseError(
                            "temporary registry entry is aliased or not a file"
                        )
                    destination = _quarantine_abandoned_temporary_journal(path)
                    report["temporary_quarantined"] += 1
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(path),
                            "archive_path": str(destination),
                            "disposition": "TEMPORARY_QUARANTINED",
                            "reason": "ABANDONED_NONAUTHORITATIVE_TEMPORARY",
                        },
                    )
                except (AuxiliaryWritableRootLeaseError, OSError) as exc:
                    report["quarantined"] += 1
                    report["complete"] = False
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(path),
                            "disposition": "QUARANTINED",
                            "reason": (
                                "TEMPORARY_RECOVERY_UNPROVEN:"
                                f"{type(exc).__name__}"
                            ),
                        },
                    )

            recorded_roots: set[str] = set()
            for path in journal_entries:
                if not _JOURNAL_NAME.fullmatch(path.name):
                    report["quarantined"] += 1
                    report["complete"] = False
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(path),
                            "disposition": "QUARANTINED",
                            "reason": "UNEXPECTED_REGISTRY_ENTRY",
                        },
                    )
                    continue
                try:
                    path_row = _lstat(path, "auxiliary-root registry entry")
                    if _is_alias_stat(path_row) or not stat.S_ISREG(
                        path_row.st_mode
                    ):
                        raise AuxiliaryWritableRootLeaseError(
                            "auxiliary-root registry entry is aliased or not a file"
                        )
                    record = _load_journal_record(path)
                    recorded_roots.add(
                        os.path.normcase(
                            os.path.abspath(str(record["root"]))
                        )
                    )
                except (AuxiliaryWritableRootLeaseError, OSError) as exc:
                    report["quarantined"] += 1
                    report["complete"] = False
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(path),
                            "disposition": "QUARANTINED",
                            "reason": (
                                f"JOURNAL_INVALID:{type(exc).__name__}"
                            ),
                        },
                    )
                    continue

                if record["state"] == "TERMINAL":
                    replay = replay_auxiliary_writable_root_journal(path)
                    if replay["valid"] is True:
                        try:
                            archive_path = _compact_terminal_journal(
                                path,
                                record,
                            )
                            report["terminal"] += 1
                            report["terminal_compacted"] += 1
                            _append_reconciliation_detail(
                                report,
                                {
                                    "path": str(path),
                                    "archive_path": str(archive_path),
                                    "disposition": "TERMINAL_COMPACTED",
                                    "reason": replay["reason"],
                                },
                            )
                        except (
                            AuxiliaryWritableRootLeaseError,
                            OSError,
                        ) as exc:
                            report["quarantined"] += 1
                            report["complete"] = False
                            _append_reconciliation_detail(
                                report,
                                {
                                    "path": str(path),
                                    "disposition": "QUARANTINED",
                                    "reason": (
                                        "TERMINAL_COMPACTION_UNPROVEN:"
                                        f"{type(exc).__name__}"
                                    ),
                                },
                            )
                    else:
                        report["quarantined"] += 1
                        report["complete"] = False
                        _append_reconciliation_detail(
                            report,
                            {
                                "path": str(path),
                                "disposition": "QUARANTINED",
                                "reason": replay["reason"],
                            },
                        )
                    continue

                owner_status = _provider_owner_status(record["owner"])
                if owner_status.get("status") == "EXACT_LIVE":
                    report["live"] += 1
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(path),
                            "disposition": "LIVE_UNTOUCHED",
                            "reason": owner_status.get("reason"),
                        },
                    )
                    continue
                if owner_status.get("status") != "PROVEN_DEAD":
                    report["quarantined"] += 1
                    report["complete"] = False
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(path),
                            "disposition": "QUARANTINED",
                            "reason": owner_status.get(
                                "reason",
                                "OWNER_UNCERTAIN",
                            ),
                        },
                    )
                    continue

                try:
                    process_scope_recovery: Mapping[str, Any] | None = None
                    if record["state"] == "ARMED_BOUND":
                        recovered_scope = _recover_persisted_scope(
                            str(record["process_scope_identity"])
                        )
                        if (
                            not isinstance(recovered_scope, dict)
                            or recovered_scope.get("population_zero") is not True
                            or recovered_scope.get("identity")
                            != record["process_scope_identity"]
                        ):
                            raise AuxiliaryWritableRootLeaseError(
                                "persisted process scope population zero was not proven"
                            )
                        process_scope_recovery = recovered_scope
                    scan = _cleanup_orphaned_journal_root(record)
                    terminal = _startup_recovery_terminal(
                        record,
                        owner_status=owner_status,
                        process_scope_recovery=process_scope_recovery,
                        scan=scan,
                    )
                    transitioned = _transition_journal(
                        path,
                        str(record["record_sha256"]),
                        {
                            "state": "TERMINAL",
                            "prior_state": record["state"],
                            "terminal": terminal,
                        },
                    )
                    archive_path = _compact_terminal_journal(
                        path,
                        transitioned,
                    )
                    replay = replay_auxiliary_writable_root_journal(path)
                    if (
                        replay["valid"] is not True
                        or transitioned["state"] != "TERMINAL"
                    ):
                        raise AuxiliaryWritableRootLeaseError(
                            "startup recovery terminal replay failed"
                        )
                    report["recovered"] += 1
                    report["terminal_compacted"] += 1
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(path),
                            "archive_path": str(archive_path),
                            "disposition": "RECOVERED",
                            "reason": "PROVEN_ORPHAN_REVOKED",
                        },
                    )
                except Exception as exc:
                    # Recovery is haltless across independent records, but every
                    # unproven row remains present for operator review.
                    report["quarantined"] += 1
                    report["complete"] = False
                    _append_reconciliation_detail(
                        report,
                        {
                            "path": str(path),
                            "disposition": "QUARANTINED",
                            "reason": (
                                f"RECOVERY_UNPROVEN:{type(exc).__name__}"
                            ),
                        },
                    )

            for root in namespace_roots:
                root_key = os.path.normcase(os.path.abspath(str(root)))
                if root_key in recorded_roots:
                    continue
                report["legacy_unjournaled"] += 1
                report["quarantined"] += 1
                report["complete"] = False
                _append_reconciliation_detail(
                    report,
                    {
                        "path": str(root),
                        "disposition": "QUARANTINED",
                        "reason": "LEGACY_OR_UNJOURNALED_ROOT",
                    },
                )

            active_entries, active_within_recovery_bound = (
                _bounded_registry_entries(
                    registry,
                    maximum_entries=MAX_REGISTRY_RECOVERY_ENTRIES,
                )
            )
            if not active_within_recovery_bound:
                report["complete"] = False
                report["reason"] = "REGISTRY_RECOVERY_BOUND_EXCEEDED"
                _set_reconciliation_disposition(
                    report,
                    disposition="DENY_NEW_LEASES",
                    debt_category=(
                        "AUXILIARY_ROOT_RECONCILIATION_REGISTRY_BOUND"
                    ),
                    debt_reason=report["reason"],
                )
                return _finalize_reconciliation_report(report)
            report["active_registry_entries"] = len(active_entries)
            if len(active_entries) > MAX_REGISTRY_ENTRIES:
                report["complete"] = False
                report["reason"] = "ACTIVE_REGISTRY_BOUND_EXCEEDED"
                _set_reconciliation_disposition(
                    report,
                    disposition="DENY_NEW_LEASES",
                    debt_category=(
                        "AUXILIARY_ROOT_RECONCILIATION_REGISTRY_BOUND"
                    ),
                    debt_reason=report["reason"],
                )
                return _finalize_reconciliation_report(report)
            if report["quarantined"]:
                report["complete"] = False
                report["reason"] = (
                    "RECONCILIATION_COMPLETE_WITH_QUARANTINE"
                )
                _set_reconciliation_disposition(
                    report,
                    disposition="ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT",
                    debt_category=(
                        "AUXILIARY_ROOT_RECONCILIATION_QUARANTINE"
                    ),
                    debt_reason=report["reason"],
                )
            else:
                _set_reconciliation_disposition(
                    report,
                    disposition="ALLOW_NEW_LEASES",
                    debt_category=None,
                    debt_reason=None,
                )
            return _finalize_reconciliation_report(report)
    except AuxiliaryWritableRootLockTimeout:
        report["complete"] = False
        report["reason"] = "REGISTRY_LOCK_TIMEOUT"
        _set_reconciliation_disposition(
            report,
            disposition="DENY_NEW_LEASES",
            debt_category=(
                "AUXILIARY_ROOT_RECONCILIATION_LOCK_TIMEOUT"
            ),
            debt_reason=report["reason"],
        )
        return _finalize_reconciliation_report(report)


__all__ = [
    "ABANDONED_TEMP_DIRECTORY_NAME",
    "AuxiliaryPrelaunchAbortClaim",
    "AuxiliaryWritableRootLease",
    "AuxiliaryWritableRootLeaseError",
    "AuxiliaryWritableRootLockTimeout",
    "AuxiliaryWritableRootReservation",
    "JOURNAL_SCHEMA",
    "LEASE_SCHEMA",
    "MAX_CLEANUP_BYTES",
    "MAX_CLEANUP_DEPTH",
    "MAX_CLEANUP_ENTRIES",
    "MAX_REGISTRY_ENTRIES",
    "MAX_REGISTRY_RECOVERY_BYTES",
    "MAX_REGISTRY_RECOVERY_ENTRIES",
    "PRELAUNCH_ABORT_CLAIM_SCHEMA",
    "RECONCILIATION_SCHEMA",
    "RECOVERY_TERMINAL_SCHEMA",
    "REGISTRY_DIRECTORY_NAME",
    "REGISTRY_LOCK_TIMEOUT_SECONDS",
    "RESERVATION_SCHEMA",
    "REVOCATION_SCHEMA",
    "ScopeClosureToken",
    "TERMINAL_ARCHIVE_DIRECTORY_NAME",
    "prove_owned_process_scope_closed",
    "reconcile_auxiliary_writable_root_leases",
    "replay_auxiliary_writable_root_binding",
    "replay_auxiliary_prelaunch_abort_claim",
    "replay_auxiliary_writable_root_journal",
    "replay_auxiliary_writable_root_reconciliation",
    "replay_auxiliary_writable_root_revocation",
    "reserve_auxiliary_writable_root",
]
