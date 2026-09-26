import hashlib
import io
import os
import struct
import tarfile

import pytest

import plamen_transform_bundle as T


def encode(payloads, operation=3):
    rows = bytearray()
    data = bytearray()
    start = 256 + 256 * len(payloads)
    for name, payload in payloads.items():
        row = bytearray(256)
        raw_name = name.encode("ascii")
        struct.pack_into(">H", row, 0, len(raw_name))
        struct.pack_into(">QQ", row, 8, len(payload), start + len(data))
        row[24:56] = hashlib.sha256(payload).digest()
        row[56:56 + len(raw_name)] = raw_name
        rows.extend(row)
        data.extend(payload)
    header = bytearray(256)
    header[:8] = b"PLMRHG1\0"
    struct.pack_into(">HHIIIQQ", header, 8, 1, 256, operation, len(payloads), 256, start, len(data))
    header[40:72] = hashlib.sha256(b"native request").digest()
    header[72:104] = hashlib.sha256(rows).digest()
    return header + rows + data


@pytest.fixture
def fixture(tmp_path):
    blob = b"retained image blob\n"
    payloads = dict(sorted({
        "blobs/sha256/" + hashlib.sha256(blob).hexdigest(): blob,
        "index.json": b'{"manifests":[],"schemaVersion":2}\n',
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}\n',
    }.items()))
    descriptors = []
    serial = 0

    def group(raw, writable=False, linked=False):
        nonlocal serial
        serial += 1
        path = tmp_path / str(serial)
        path.write_bytes(raw)
        writer = os.open(path, os.O_RDWR)
        path.chmod(0o400)
        fd = writer if writable else os.open(path, os.O_RDONLY)
        if not writable:
            os.close(writer)
        if not linked:
            path.unlink()
        descriptors.append(fd)
        return fd

    output_path = tmp_path / "output.tar"
    output = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    descriptors.append(output)
    yield payloads, group, output, output_path
    for fd in descriptors:
        os.close(fd)


def reference(payloads):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("blobs/", "blobs/sha256/", *payloads):
            entry = tarfile.TarInfo(name)
            if name.endswith("/"):
                entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(entry)
            else:
                entry.mode, entry.size = 0o444, len(payloads[name])
                archive.addfile(entry, io.BytesIO(payloads[name]))
    return stream.getvalue()


def test_actual_retained_group_writes_identical_archive_and_keeps_offset(fixture):
    payloads, group, output, path = fixture
    fd = group(encode(payloads))
    os.lseek(fd, 31, os.SEEK_SET)
    assert T.run(3, fd, (output,), ()) is None
    assert path.read_bytes() == reference(payloads)
    assert os.lseek(fd, 0, os.SEEK_CUR) == 31
    # Native helper, not Python transform, owns the subsequent seal.
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("case", [
    "magic", "version", "operation", "count_zero", "count_large", "row_size",
    "data_start", "total", "request_zero", "header_padding", "roster_hash",
    "row_padding", "row_tail", "offset_overlap", "length", "size", "truncated", "trailer",
])
def test_malformed_group_rejects_without_output(fixture, case):
    payloads, group, output, path = fixture
    raw = encode(payloads)
    if case == "magic": raw[0] ^= 1
    elif case == "version": raw[9] = 2
    elif case == "operation": raw[15] = 4
    elif case == "count_zero": raw[16:20] = bytes(4)
    elif case == "count_large": struct.pack_into(">I", raw, 16, 4097)
    elif case == "row_size": struct.pack_into(">I", raw, 20, 255)
    elif case == "data_start": raw[31] ^= 1
    elif case == "total": raw[39] ^= 1
    elif case == "request_zero": raw[40:72] = bytes(32)
    elif case == "header_padding": raw[255] = 1
    elif case == "roster_hash": raw[72] ^= 1
    elif case == "row_padding": raw[258] = 1
    elif case == "row_tail": raw[511] = 1
    elif case == "offset_overlap": struct.pack_into(">Q", raw, 256 + 16, 0)
    elif case == "length": struct.pack_into(">H", raw, 256, 192)
    elif case == "size": struct.pack_into(">Q", raw, 256 + 8, 2**63)
    elif case == "truncated": raw.pop()
    elif case == "trailer": raw.append(0)
    if case in {"row_padding", "row_tail", "offset_overlap", "length", "size"}:
        raw[72:104] = hashlib.sha256(raw[256:1024]).digest()
    with pytest.raises(T.TransformError):
        T.run(3, group(raw), (output,), ())
    assert path.read_bytes() == b""


@pytest.mark.parametrize("payloads", [
    {"../outside": b"a"}, {"a/./b": b"b"}, {"a//b": b"b"},
    {"/absolute": b"b"}, {"Case": b"a", "case": b"b"}, {"space name": b"a"},
])
def test_group_path_topology_rejected(fixture, payloads):
    _, group, _, _ = fixture
    with pytest.raises(T.TransformError):
        with T.GroupedInputs(group(encode(payloads)), 3):
            pass


@pytest.mark.parametrize("case", ["writable", "linked", "append", "nonempty", "outputs", "operation"])
def test_invalid_transport_rejects_without_replacing_output(fixture, case):
    payloads, group, output, path = fixture
    fd = group(encode(payloads), writable=case == "writable", linked=case == "linked")
    if case == "nonempty": os.write(output, b"preserved")
    if case == "append":
        T.archive_transform.fcntl.fcntl(output, T.archive_transform.fcntl.F_SETFL, os.O_APPEND)
    before = path.read_bytes()
    with pytest.raises(T.TransformError):
        T.run(5 if case == "operation" else 3, fd, (output, output) if case == "outputs" else (output,), ())
    assert path.read_bytes() == before


def test_bad_consumed_slice_preserves_partial_output(fixture):
    payloads, group, output, path = fixture
    raw = encode(payloads)
    raw[-1] ^= 1
    fd = group(raw)
    with pytest.raises(T.TransformError, match="consumed group slice"):
        T.run(3, fd, (output,), ())
    assert path.stat().st_size > 0
    before = path.read_bytes()
    with pytest.raises(T.TransformError, match="empty"):
        T.run(3, fd, (output,), ())
    assert path.read_bytes() == before


def test_slice_reader_cannot_cross_member_boundary(fixture):
    payloads, group, _, _ = fixture
    with T.GroupedInputs(group(encode(payloads)), 3) as retained:
        reader = T._SliceReader(retained, retained.rows[0])
        assert reader.read(10**6) == next(iter(payloads.values()))
        assert reader.read(1) == b""
        reader.finish()


def test_maximum_row_count_uses_one_descriptor(fixture):
    _, group, _, _ = fixture
    payloads = {f"member-{i:04d}": b"" for i in range(4096)}
    with T.GroupedInputs(group(encode(payloads)), 3) as retained:
        assert len(retained.rows) == 4096
        assert all(row.size == 0 for row in retained.rows)
