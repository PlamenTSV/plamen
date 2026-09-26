"""Deterministic OCI archive transformation, NOT a verification authority.

The native source-bootstrap runner must authenticate this helper's complete
executable closure, retain/admit its inputs and outputs, and verify completion.
Python callers can invoke this transformation but cannot obtain a native receipt
or authorize publication with its return value. No source pathname is opened.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat
import tarfile
from typing import Sequence

try:
    import fcntl
except ImportError:  # Import-safe; Windows needs its native handle transport.
    fcntl = None


MAX_FILES = 4096
MAX_BYTES = 8 * 1024**3
# USTAR's size field is eleven octal digits plus its terminator.
MAX_MEMBER_BYTES = (1 << 33) - 1
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class ArchiveTransformError(RuntimeError):
    pass


@dataclass(frozen=True)
class ArchiveInput:
    """Untrusted transformation parameters; this is not a capability."""

    path: str
    descriptor: int
    size: int
    sha256: str


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _access(fd: int) -> int:
    if fcntl is None:
        raise ArchiveTransformError("POSIX retained descriptors required")
    if type(fd) is not int or fd < 0:
        raise ArchiveTransformError("invalid descriptor")
    return fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE


def _path(path: str) -> bool:
    return type(path) is str and (
        path in {"index.json", "oci-layout"}
        or (path.startswith("blobs/sha256/")
            and _HEX.fullmatch(path[len("blobs/sha256/"):]) is not None)
    )


class _Reader:
    def __init__(self, row: ArchiveInput, fd: int, identity: tuple[int, ...]):
        self.row, self.fd, self.identity = row, fd, identity
        self.offset = 0
        self.digest = hashlib.sha256()

    def read(self, count: int) -> bytes:
        count = min(count, self.row.size - self.offset)
        raw = os.pread(self.fd, count, self.offset)
        if len(raw) != count:
            raise ArchiveTransformError("input truncated during transformation")
        self.digest.update(raw)
        self.offset += len(raw)
        return raw

    def finish(self) -> None:
        if (self.offset != self.row.size or os.pread(self.fd, 1, self.row.size)
                or _identity(os.fstat(self.fd)) != self.identity
                or self.digest.hexdigest() != self.row.sha256):
            raise ArchiveTransformError("retained input commitment differs")


def write_retained_oci_archive(
    inputs: Sequence[ArchiveInput], output_descriptor: int,
) -> None:
    """Write raw canonical USTAR to an empty private retained output.

    Does not close caller FDs, publish a pathname, authenticate an OCI graph,
    issue a receipt, or clean up partial output after failure. The native caller
    owns those responsibilities. Source offsets remain unchanged. Exact content
    commitments are checked during consumption, not by reopening source paths.
    """
    if type(inputs) not in (tuple, list) or not 3 <= len(inputs) <= MAX_FILES:
        raise ArchiveTransformError("input roster outside bounds")
    if any(type(row) is not ArchiveInput for row in inputs):
        raise ArchiveTransformError("invalid transformation input row")
    names = [row.path for row in inputs]
    if (any(not _path(name) for name in names)
            or names != sorted(set(names))
            or "index.json" not in names or "oci-layout" not in names):
        raise ArchiveTransformError("layout member roster is not canonical")
    total = 0
    for row in inputs:
        if (type(row.size) is not int or not 0 <= row.size <= MAX_MEMBER_BYTES
                or type(row.sha256) is not str or not _HEX.fullmatch(row.sha256)):
            raise ArchiveTransformError("invalid content commitment")
        if row.path.startswith("blobs/") and row.path.rsplit("/", 1)[1] != row.sha256:
            raise ArchiveTransformError("blob name differs from commitment")
        total += row.size
    if total > MAX_BYTES:
        raise ArchiveTransformError("aggregate input bytes outside bounds")
    if _access(output_descriptor) != os.O_RDWR:
        raise ArchiveTransformError("output is not read-write")
    if fcntl.fcntl(output_descriptor, fcntl.F_GETFL) & os.O_APPEND:
        raise ArchiveTransformError("append output is forbidden")
    output = os.fstat(output_descriptor)
    if (not stat.S_ISREG(output.st_mode) or output.st_nlink != 1
            or output.st_uid != os.getuid() or output.st_size != 0
            or stat.S_IMODE(output.st_mode) != 0o600):
        raise ArchiveTransformError("output is not empty and owner-private")
    seen = {(output.st_dev, output.st_ino)}
    readers: list[_Reader] = []
    output_copy = -1
    try:
        for row in inputs:
            if _access(row.descriptor) != os.O_RDONLY:
                raise ArchiveTransformError("input descriptor is not read-only")
            fd = os.dup(row.descriptor)
            try:
                info = os.fstat(fd)
                key = (info.st_dev, info.st_ino)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.getuid() or info.st_size != row.size
                        or stat.S_IMODE(info.st_mode) != 0o444 or key in seen):
                    raise ArchiveTransformError("input identity or topology differs")
                seen.add(key)
                readers.append(_Reader(row, fd, _identity(info)))
                fd = -1
            finally:
                if fd >= 0:
                    os.close(fd)
        output_copy = os.dup(output_descriptor)
        os.lseek(output_copy, 0, os.SEEK_SET)
        with os.fdopen(output_copy, "wb", buffering=0) as destination:
            output_copy = -1
            with tarfile.open(fileobj=destination, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for directory in ("blobs/", "blobs/sha256/"):
                    entry = tarfile.TarInfo(directory)
                    entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                    archive.addfile(entry)
                for reader in readers:
                    entry = tarfile.TarInfo(reader.row.path)
                    entry.mode, entry.size = 0o444, reader.row.size
                    archive.addfile(entry, reader)
                    reader.finish()
            os.fsync(destination.fileno())
        for reader in readers:
            reader.finish()
    finally:
        if output_copy >= 0:
            os.close(output_copy)
        for reader in readers:
            os.close(reader.fd)
