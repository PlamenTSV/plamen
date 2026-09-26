from __future__ import annotations

from dataclasses import replace
import hashlib
import io
import os
from pathlib import Path
import tarfile

import pytest

import oci_retained_archive_transform as T


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX FD transform")


@pytest.fixture
def layout(tmp_path):
    blob = b"retained blob bytes\n"
    payloads = {
        "blobs/sha256/" + hashlib.sha256(blob).hexdigest(): blob,
        "index.json": b'{"manifests":[],"schemaVersion":2}\n',
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}\n',
    }
    rows = []
    descriptors = []
    for name, raw in sorted(payloads.items()):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o444)
        fd = os.open(path, os.O_RDONLY)
        descriptors.append(fd)
        rows.append(T.ArchiveInput(name, fd, len(raw), hashlib.sha256(raw).hexdigest()))
    output_path = tmp_path / "output.tar"
    output = os.open(output_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    descriptors.append(output)
    try:
        yield tmp_path, rows, payloads, output, output_path
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _reference(payloads):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("blobs/", "blobs/sha256/", *sorted(payloads)):
            entry = tarfile.TarInfo(name)
            entry.uid = entry.gid = entry.mtime = 0
            entry.uname = entry.gname = ""
            if name.endswith("/"):
                entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(entry)
            else:
                entry.type, entry.mode = tarfile.REGTYPE, 0o444
                entry.size = len(payloads[name])
                archive.addfile(entry, io.BytesIO(payloads[name]))
    return stream.getvalue()


def test_exact_ustar_uses_retained_bytes_after_source_path_substitution(layout):
    root, rows, payloads, output, output_path = layout
    for row in rows:
        source = root / row.path
        source.rename(source.with_name(source.name + ".retained"))
        source.write_bytes(b"substituted pathname\n")
        os.lseek(row.descriptor, 2, os.SEEK_SET)
    assert T.write_retained_oci_archive(rows, output) is None
    assert output_path.read_bytes() == _reference(payloads)
    assert all(os.lseek(row.descriptor, 0, os.SEEK_CUR) == 2 for row in rows)
    with tarfile.open(output_path) as archive:
        assert archive.getnames() == ["blobs", "blobs/sha256", *sorted(payloads)]
        for name, raw in payloads.items():
            assert archive.extractfile(name).read() == raw


def test_transform_matches_existing_canonical_layout_archive_bytes(layout):
    import deterministic_oci_layout as existing

    root, rows, payloads, output, path = layout
    reference = io.BytesIO()
    existing._write_canonical_oci_archive_from_directory(
        reference, root, tuple(sorted(payloads)),
    )
    T.write_retained_oci_archive(rows, output)
    assert path.read_bytes() == reference.getvalue()


@pytest.mark.parametrize("case", ["unsorted", "duplicate", "path", "blob", "size", "ustar_size", "boolsize"])
def test_invalid_roster_rejected_before_output(layout, case):
    _, original, _, output, path = layout
    rows = list(original)
    if case == "unsorted":
        rows.reverse()
    elif case == "duplicate":
        rows[2] = rows[1]
    elif case == "path":
        rows[0] = replace(rows[0], path="../escape")
    elif case == "blob":
        rows[0] = replace(rows[0], sha256="0" * 64)
    elif case == "size":
        rows[0] = replace(rows[0], size=T.MAX_BYTES + 1)
    elif case == "ustar_size":
        rows[0] = replace(rows[0], size=T.MAX_MEMBER_BYTES + 1)
    else:
        rows[0] = replace(rows[0], size=True)
    with pytest.raises(T.ArchiveTransformError):
        T.write_retained_oci_archive(rows, output)
    assert path.read_bytes() == b""


def test_wrong_consumed_digest_fails_and_preserves_partial_output(layout):
    _, rows, _, output, path = layout
    rows[1] = replace(rows[1], sha256="0" * 64)
    with pytest.raises(T.ArchiveTransformError, match="commitment"):
        T.write_retained_oci_archive(rows, output)
    assert path.stat().st_size > 0
    # Partial output is owned by the native transaction, not silently repaired.
    before = path.read_bytes()
    with pytest.raises(T.ArchiveTransformError, match="empty"):
        T.write_retained_oci_archive(rows, output)
    assert path.read_bytes() == before


def test_nonempty_output_is_never_truncated(layout):
    _, rows, _, output, path = layout
    os.write(output, b"existing output")
    with pytest.raises(T.ArchiveTransformError, match="empty"):
        T.write_retained_oci_archive(rows, output)
    assert path.read_bytes() == b"existing output"


def test_writable_source_descriptor_rejected(layout):
    root, rows, _, output, path = layout
    source = root / rows[0].path
    source.chmod(0o600)
    writable = os.open(source, os.O_RDWR)
    source.chmod(0o444)
    try:
        rows[0] = replace(rows[0], descriptor=writable)
        with pytest.raises(T.ArchiveTransformError, match="read-only"):
            T.write_retained_oci_archive(rows, output)
        assert path.read_bytes() == b""
    finally:
        os.close(writable)


def test_aliased_input_roster_rejected(layout):
    _, rows, _, output, path = layout
    rows[2] = replace(rows[1], path="oci-layout")
    with pytest.raises(T.ArchiveTransformError, match="topology"):
        T.write_retained_oci_archive(rows, output)
    assert path.read_bytes() == b""


def test_append_output_rejected_without_writes(layout):
    _, rows, _, _, path = layout
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND)
    try:
        with pytest.raises(T.ArchiveTransformError, match="append"):
            T.write_retained_oci_archive(rows, descriptor)
        assert path.read_bytes() == b""
    finally:
        os.close(descriptor)
