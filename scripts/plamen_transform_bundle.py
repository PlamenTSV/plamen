"""Retained helper transformations; never issues authority or publishes paths.

The signed native helper admits its sandbox before calling ``run``. Its native
parent owns source authentication, input custody, completion, and receipts.
This module only consumes the exact PLMRHG1 grouped bytes and writes outputs.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
import struct
import tarfile

import oci_retained_archive_transform as archive_transform


HEADER_SIZE = ROW_SIZE = 256
MAX_INPUTS = 4096
MAX_BYTES = 8 * 1024**3


class TransformError(RuntimeError):
    pass


@dataclass(frozen=True)
class GroupRow:
    path: str
    size: int
    offset: int
    sha256: bytes


def _read(fd: int, size: int, offset: int) -> bytes:
    parts = []
    while size:
        raw = os.pread(fd, min(size, 65536), offset)
        if not raw:
            raise TransformError("truncated grouped input")
        parts.append(raw)
        size -= len(raw)
        offset += len(raw)
    return b"".join(parts)


class GroupedInputs:
    """A bounded reader, not a native capability. Caller retains the original FD."""

    def __init__(self, descriptor: int, operation: int):
        self.fd = -1
        if type(operation) is not int or operation not in (1, 2, 3, 4):
            raise TransformError("unknown operation")
        if archive_transform._access(descriptor) != os.O_RDONLY:
            raise TransformError("group descriptor is not read-only")
        self.fd = os.dup(descriptor)
        try:
            info = os.fstat(self.fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 0 or stat.S_IMODE(info.st_mode) != 0o400
                    or not HEADER_SIZE <= info.st_size <= MAX_BYTES + HEADER_SIZE + MAX_INPUTS * ROW_SIZE):
                raise TransformError("group identity or bounds differ")
            self.identity = archive_transform._identity(info)
            header = _read(self.fd, HEADER_SIZE, 0)
            version, header_size, observed_op, count, row_size, data_start, total = struct.unpack_from(
                ">HHIIIQQ", header, 8,
            )
            if (header[:8] != b"PLMRHG1\0" or version != 1
                    or header_size != HEADER_SIZE or observed_op != operation
                    or not 1 <= count <= MAX_INPUTS or row_size != ROW_SIZE
                    or data_start != HEADER_SIZE + count * ROW_SIZE
                    or total > MAX_BYTES or info.st_size != data_start + total
                    or not any(header[40:72]) or any(header[104:])):
                raise TransformError("group header differs")
            roster = _read(self.fd, count * ROW_SIZE, HEADER_SIZE)
            if hashlib.sha256(roster).digest() != header[72:104]:
                raise TransformError("group row roster commitment differs")
            rows = []
            seen = set()
            cursor = data_start
            for index in range(count):
                raw = roster[index * ROW_SIZE:(index + 1) * ROW_SIZE]
                length = struct.unpack_from(">H", raw)[0]
                size, offset = struct.unpack_from(">QQ", raw, 8)
                if (not 1 <= length <= 191 or any(raw[2:8])
                        or any(raw[56 + length:]) or offset != cursor
                        or size > info.st_size - cursor):
                    raise TransformError("group row bounds or padding differ")
                name_raw = raw[56:56 + length]
                if any(byte < 0x21 or byte > 0x7e for byte in name_raw):
                    raise TransformError("group path is not canonical ASCII")
                name = name_raw.decode("ascii")
                if (any(part in ("", ".", "..") for part in name.split("/"))
                        or name.lower() in seen):
                    raise TransformError("group path topology differs")
                seen.add(name.lower())
                rows.append(GroupRow(name, size, offset, raw[24:56]))
                cursor += size
            if cursor != info.st_size:
                raise TransformError("group payload coverage differs")
            self.rows = tuple(rows)
            self.request_sha256 = header[40:72]
            self.rejoin()
        except BaseException:
            self.close()
            raise

    def rejoin(self) -> None:
        if archive_transform._identity(os.fstat(self.fd)) != self.identity:
            raise TransformError("group identity changed during consumption")

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


class _SliceReader:
    def __init__(self, group: GroupedInputs, row: GroupRow):
        self.group, self.row = group, row
        self.offset = 0
        self.digest = hashlib.sha256()

    def read(self, count: int) -> bytes:
        if type(count) is not int or count < 0:
            raise TransformError("bounded read required")
        raw = _read(self.group.fd, min(count, self.row.size - self.offset), self.row.offset + self.offset)
        self.offset += len(raw)
        self.digest.update(raw)
        return raw

    def finish(self) -> None:
        if self.offset != self.row.size or self.digest.digest() != self.row.sha256:
            raise TransformError("consumed group slice commitment differs")
        self.group.rejoin()


def _archive(group: GroupedInputs, output: int) -> None:
    names = [row.path for row in group.rows]
    if (len(names) < 3 or names != sorted(names)
            or "index.json" not in names or "oci-layout" not in names
            or any(not archive_transform._path(name) for name in names)):
        raise TransformError("OCI member roster differs")
    for row in group.rows:
        if (row.size > archive_transform.MAX_MEMBER_BYTES
                or (row.path.startswith("blobs/") and row.path.rsplit("/", 1)[1] != row.sha256.hex())):
            raise TransformError("OCI member commitment differs")
    if archive_transform._access(output) != os.O_RDWR:
        raise TransformError("output is not read-write")
    if archive_transform.fcntl.fcntl(output, archive_transform.fcntl.F_GETFL) & os.O_APPEND:
        raise TransformError("append output is forbidden")
    info = os.fstat(output)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != 0 or (info.st_dev, info.st_ino) == group.identity[:2]):
        raise TransformError("output is not an empty private distinct file")
    readers = [_SliceReader(group, row) for row in group.rows]
    with os.fdopen(os.dup(output), "wb", buffering=0) as destination:
        destination.seek(0)
        with tarfile.open(fileobj=destination, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            for name in ("blobs/", "blobs/sha256/"):
                entry = tarfile.TarInfo(name)
                entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(entry)
            for reader in readers:
                entry = tarfile.TarInfo(reader.row.path)
                entry.mode, entry.size = 0o444, reader.row.size
                archive.addfile(entry, reader)
                reader.finish()
        os.fsync(destination.fileno())
    group.rejoin()


def run(operation: int, group_fd: int, output_fds: tuple[int, ...], scratch_fds: tuple[int, ...]) -> None:
    """Native helper entry. No key, receipt, ambient input path, or publication."""
    if type(operation) is int and operation == 1:
        from plamen_oci_context_transform import verify
        return verify(group_fd, output_fds, scratch_fds)
    if type(operation) is int and operation == 2:
        from plamen_oci_build_transform import build
        return build(group_fd, output_fds, scratch_fds)
    if type(operation) is int and operation == 4:
        from native_runtime_grouped_transform import run as materialize
        return materialize(operation, group_fd, output_fds, scratch_fds)
    if type(operation) is not int or operation != 3:
        raise TransformError("operation has no installed transform")
    if type(output_fds) is not tuple or len(output_fds) != 1:
        raise TransformError("archive requires exactly one output")
    if type(scratch_fds) is not tuple or scratch_fds:
        raise TransformError("archive has no scratch descriptors")
    with GroupedInputs(group_fd, operation) as group:
        _archive(group, output_fds[0])
