from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import urllib.error
from email.message import Message

import pytest

import native_fixed_role_acquisition as A


class _HTTPSResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size=-1):
        return b""


def _retained(path: Path, raw: bytes) -> int:
    path.write_bytes(raw)
    path.chmod(0o400)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


def _writer_pair(path: Path) -> tuple[int, int]:
    writer = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    reader = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    return writer, reader


def _tar(rows: list[tuple[str, bytes, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, raw, mode in rows:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def test_foundry_transform_emits_exact_sorted_normalized_ustar(tmp_path: Path) -> None:
    source = _tar([
        (name, (name + "\n").encode(), 0o700 if index & 1 else 0o600)
        for index, name in enumerate(("solar", "forge", "chisel", "cast", "anvil"))
    ])
    source_fd = _retained(tmp_path / "foundry.tar.gz", source)
    writer, reader = _writer_pair(tmp_path / "projection.tar")
    try:
        A._canonical_ustar(source_fd, writer, role=7)
        os.fsync(writer)
        raw = os.pread(reader, os.fstat(reader).st_size, 0)
        assert len(raw) % tarfile.RECORDSIZE == 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            rows = archive.getmembers()
            assert [row.name for row in rows] == [
                "bin/anvil", "bin/cast", "bin/chisel", "bin/forge", "bin/solar",
            ]
            assert all(row.uid == row.gid == row.mtime == 0 for row in rows)
            assert all(row.uname == row.gname == "" for row in rows)
            assert [row.mode for row in rows] == [0o444, 0o555, 0o444, 0o555, 0o444]
    finally:
        for descriptor in (reader, writer, source_fd):
            os.close(descriptor)


def test_debian_package_state_derivation_is_exact_and_rejects_ambiguity(
    tmp_path: Path,
) -> None:
    status = (
        b"Package: zlib1g\nStatus: install ok installed\n"
        b"Architecture: arm64\nVersion: 1:1.2.13.dfsg-1\n\n"
        b"Package: base-files\nStatus: install ok installed\n"
        b"Architecture: arm64\nVersion: 12.4+deb12u12\n"
    )
    source = _tar([("var/lib/dpkg/status", status, 0o644)])
    descriptor = _retained(tmp_path / "rootfs.tar.gz", source)
    try:
        raw = A._render_debian_package_state(descriptor)
        assert json.loads(raw) == {
            "packages": [
                {"architecture": "arm64", "name": "base-files",
                 "status": "install ok installed", "version": "12.4+deb12u12"},
                {"architecture": "arm64", "name": "zlib1g",
                 "status": "install ok installed", "version": "1:1.2.13.dfsg-1"},
            ],
            "schema_version": "plamen.debian_package_state.v1",
        }
        assert b"\n" not in raw
        assert b'": ' not in raw and b'", "' not in raw
    finally:
        os.close(descriptor)

    duplicate = _tar([(
        "var/lib/dpkg/status",
        b"Package: a\nPackage: b\nArchitecture: arm64\nVersion: 1\n"
        b"Status: install ok installed\n",
        0o644,
    )])
    descriptor = _retained(tmp_path / "duplicate.tar.gz", duplicate)
    try:
        with pytest.raises(A.NativeFixedRoleAcquisitionError):
            A._render_debian_package_state(descriptor)
    finally:
        os.close(descriptor)


def test_projection_materializer_consumes_only_manifest_and_ordered_fds(
    tmp_path: Path,
) -> None:
    raw_members = (b"driver\n", b"rules\n")
    rows = [
        {"mode": mode, "path": path, "sha256": hashlib.sha256(raw).hexdigest(),
         "size": len(raw)}
        for path, raw, mode in (
            ("scripts/plamen_driver.py", raw_members[0], 0o400),
            ("rules/example.md", raw_members[1], 0o400),
        )
    ]
    rows.sort(key=lambda row: row["path"].encode())
    ordered = tuple(raw_members[1:] + raw_members[:1])
    roster = hashlib.sha256()
    roster.update(b"PLAMEN-FIXED-ROLE-SOURCE-PROJECTION-V1\0")
    for row in rows:
        encoded = row["path"].encode()
        roster.update(len(encoded).to_bytes(4, "big")); roster.update(encoded)
        roster.update(row["mode"].to_bytes(4, "big"))
        roster.update(row["size"].to_bytes(8, "big"))
        roster.update(bytes.fromhex(row["sha256"]))
    manifest = json.dumps({
        "projection_authority": {
            "schema": "plamen.runtime-source-projection.v1",
            "sha256": "3" * 64, "size": 123,
        },
        "role": "plamen_package", "roster_sha256": roster.hexdigest(),
        "rows": rows, "schema": "plamen.fixed-role-source-projection.v1",
        "source_commit": "4" * 40,
    }, sort_keys=True, separators=(",", ":")).encode()

    class Source:
        def duplicate_projection_manifest(self, role):
            assert role == "plamen_package"
            return _retained(tmp_path / "projection.json", manifest)

        def duplicate_projection_member(self, role, index):
            assert role == "plamen_package"
            return _retained(tmp_path / f"member-{index}", ordered[index])

    writer, reader = _writer_pair(tmp_path / "payload.tar")
    try:
        evidence = A._projection_payload(Source(), "plamen_package", writer)
        assert evidence["source_commit"] == "4" * 40
        with tarfile.open(fileobj=io.BytesIO(
            os.pread(reader, os.fstat(reader).st_size, 0)
        ), mode="r:") as archive:
            assert [row.name for row in archive.getmembers()] == [
                "rules/example.md", "scripts/plamen_driver.py",
            ]
    finally:
        os.close(reader); os.close(writer)


def test_production_factory_rejects_nonretained_or_callback_projection_authority(
    tmp_path: Path,
) -> None:
    store = tmp_path / "store"; store.mkdir(mode=0o700)
    store_fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    class LegacyCallbackAuthority:
        _PLAMEN_RETAINED_FIXED_ROLE_SOURCE_V1 = True

        def duplicate_member(self, role):
            raise AssertionError(role)

        def materialize_projection(self, role, writer):
            raise AssertionError((role, writer))

    try:
        with pytest.raises(
            A.NativeFixedRoleAcquisitionError,
            match="source authority differs",
        ):
            A.acquire_production_fixed_role_materialized_inputs(
                source_authority=LegacyCallbackAuthority(),
                private_store=A.RetainedPrivateStoreFactory(store_fd),
            )
        assert list(store.iterdir()) == []
    finally:
        os.close(store_fd)


def test_docker_redirect_is_exact_and_strips_registry_authorization() -> None:
    fetcher = A.DefaultSetupHTTPSFetcher()
    requests = []
    target = (
        "production.cloudfront.docker.com",
        "/registry-v2/docker/registry/v2/blobs/sha256/75/" + "7" * 64 + "/data",
    )

    class Opener:
        def open(self, request, timeout):
            assert timeout == 60
            requests.append(request)
            if len(requests) == 1:
                headers = Message()
                headers["Location"] = "https://" + target[0] + target[1] + "?signed=1"
                raise urllib.error.HTTPError(
                    request.full_url, 307, "redirect", headers, None,
                )
            return _HTTPSResponse()

    fetcher._opener = Opener()
    response = fetcher._open(
        "https://registry-1.docker.io/v2/library/debian/blobs/sha256:" + "7" * 64,
        allowed_hosts=("registry-1.docker.io", target[0]),
        maximum_redirects=1, redirect_targets=(target,),
        authorization="Bearer secret",
    )
    response.close = lambda: None
    assert requests[0].get_header("Authorization") == "Bearer secret"
    assert requests[1].get_header("Authorization") is None


def test_docker_redirect_rejects_unreviewed_path() -> None:
    fetcher = A.DefaultSetupHTTPSFetcher()

    class Opener:
        def open(self, request, timeout):
            headers = Message()
            headers["Location"] = (
                "https://production.cloudfront.docker.com/unreviewed? signed=1"
            )
            raise urllib.error.HTTPError(
                request.full_url, 307, "redirect", headers, None,
            )

    fetcher._opener = Opener()
    with pytest.raises(A.NativeFixedRoleAcquisitionError):
        fetcher._open(
            "https://registry-1.docker.io/v2/library/debian/blobs/sha256:" + "7" * 64,
            allowed_hosts=(
                "registry-1.docker.io", "production.cloudfront.docker.com",
            ),
            maximum_redirects=1,
            redirect_targets=((
                "production.cloudfront.docker.com", "/reviewed",
            ),),
            authorization="Bearer secret",
        )
