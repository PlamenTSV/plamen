"""Byte-only durable materialization for validated DRIVER successors.

This module grants no transition authority.  Callers must validate and begin
the exact successor step before invoking it, then validate/complete the step.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
from typing import Callable

import rooted_path_io as rooted_io


_DARWIN_SYSTEM_DIRECTORY_ALIASES = (
    (Path("/var"), Path("/private/var")),
    (Path("/tmp"), Path("/private/tmp")),
)


def canonicalize_trusted_driver_temporary_directory(path: Path) -> Path:
    """Return an alias-free directory for driver-owned temporary writes.

    Rooted I/O intentionally rejects every symlinked ancestor.  Darwin,
    however, exposes its system temporary tree through the fixed aliases
    ``/var -> /private/var`` and ``/tmp -> /private/tmp``.  Admit only those
    exact OS aliases, rewrite only their first component, and then perform the
    normal no-link validation on the entire canonical path.  No user-created
    or deeper symlink is resolved or accepted.
    """

    absolute = rooted_io.absolute_path(path)
    try:
        return rooted_io.checked_directory(
            absolute,
            label="driver successor temporary directory",
        )
    except rooted_io.RootedPathIOError as exc:
        lexical_error = exc
        if sys.platform != "darwin":
            raise

    for alias, canonical_alias in _DARWIN_SYSTEM_DIRECTORY_ALIASES:
        try:
            relative = absolute.relative_to(alias)
        except ValueError:
            continue
        try:
            alias_before = rooted_io.lstat(alias)
            link_before = os.readlink(rooted_io.native_path(alias))
            if not stat.S_ISLNK(alias_before.st_mode):
                raise rooted_io.RootedPathIOError(
                    f"trusted Darwin temporary alias is not a symlink: {alias}"
                )
            if Path(os.path.realpath(rooted_io.native_path(alias))) != canonical_alias:
                raise rooted_io.RootedPathIOError(
                    f"trusted Darwin temporary alias target differs: {alias}"
                )

            canonical = canonical_alias.joinpath(*relative.parts)
            rooted_io.checked_directory(
                canonical,
                label="driver successor canonical temporary directory",
            )
            followed = os.stat(rooted_io.native_path(absolute))
            named = rooted_io.lstat(canonical)
            alias_after = rooted_io.lstat(alias)
            link_after = os.readlink(rooted_io.native_path(alias))
            if (
                int(followed.st_dev) != int(named.st_dev)
                or int(followed.st_ino) != int(named.st_ino)
                or not stat.S_ISDIR(followed.st_mode)
                or not stat.S_ISDIR(named.st_mode)
                or int(alias_before.st_dev) != int(alias_after.st_dev)
                or int(alias_before.st_ino) != int(alias_after.st_ino)
                or link_before != link_after
            ):
                raise rooted_io.RootedPathIOError(
                    "trusted Darwin temporary alias changed while validated"
                )
            return canonical
        except (OSError, rooted_io.RootedPathIOError):
            raise lexical_error
    raise lexical_error


def _atomic_bytes(path: Path, data: bytes) -> None:
    target = Path(path)
    rooted_io.ensure_directory(
        target.parent,
        parents=True,
        label="driver successor parent",
    )
    fd, temporary = rooted_io.exclusive_temp_file(
        target.parent,
        prefix="_.p.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        rooted_io.durable_replace(temporary, target)
    finally:
        if fd >= 0:
            os.close(fd)
        if rooted_io.lexists(temporary):
            rooted_io.unlink(temporary)


def materialize_driver_successor_transition(
    path: Path,
    data: bytes,
    *,
    byte_publisher: Callable[[Path, bytes], None] | None = None,
) -> bool:
    """Publish one postimage while preserving an exact safe no-op preimage."""

    target = Path(path)
    try:
        metadata = rooted_io.lstat(target)
        reparse = bool(getattr(metadata, "st_file_attributes", 0) & 0x400)
        if (
            stat.S_ISREG(metadata.st_mode)
            and not reparse
            and int(getattr(metadata, "st_nlink", 1) or 1) == 1
            and rooted_io.read_bytes(
                target,
                label="driver successor output",
                require_single_link=True,
            )
            == data
        ):
            confirmed = rooted_io.lstat(target)
            if (
                int(getattr(confirmed, "st_dev", 0))
                == int(getattr(metadata, "st_dev", 0))
                and int(getattr(confirmed, "st_ino", 0))
                == int(getattr(metadata, "st_ino", 0))
                and int(confirmed.st_size) == int(metadata.st_size)
                and int(confirmed.st_mtime_ns) == int(metadata.st_mtime_ns)
                and int(getattr(confirmed, "st_nlink", 1) or 1) == 1
                and stat.S_ISREG(confirmed.st_mode)
                and not bool(
                    getattr(confirmed, "st_file_attributes", 0) & 0x400
                )
            ):
                return False
    except (FileNotFoundError, OSError):
        pass
    (byte_publisher or _atomic_bytes)(target, data)
    return True


__all__ = [
    "canonicalize_trusted_driver_temporary_directory",
    "materialize_driver_successor_transition",
]
