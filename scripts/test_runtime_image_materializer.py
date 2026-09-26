"""Adversarial tests for the credential-free runtime content compositor."""

from __future__ import annotations

import copy
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile

import pytest

import runtime_image_materializer as R


def _canonical(value) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _tar(entries: list[tuple[str, bytes | None, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload, mode in entries:
            info = tarfile.TarInfo(name)
            info.uid = 123
            info.gid = 456
            info.uname = "builder"
            info.gname = "builder"
            info.mtime = 987654321
            info.mode = mode
            if payload is None:
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _backend_archive(member: str, executable: bytes) -> bytes:
    return gzip.compress(_tar([(member, executable, 0o755)]), mtime=0)


def _append_tar_file(raw: bytes, name: str, payload: bytes = b"attacker") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source:
        with tarfile.open(
            fileobj=output, mode="w", format=tarfile.USTAR_FORMAT
        ) as target:
            for member in source:
                stream = source.extractfile(member) if member.isfile() else None
                target.addfile(member, stream)
            malicious = tarfile.TarInfo(name)
            malicious.mode = 0o644
            malicious.size = len(payload)
            target.addfile(malicious, io.BytesIO(payload))
    return output.getvalue()


def _fixture_values() -> tuple[dict, dict[str, bytes], dict[str, bytes]]:
    backend_members = {
        "codex": "package/vendor/aarch64-unknown-linux-gnu/bin/codex",
        "claude": "package/claude",
    }
    backend_executables = {
        "codex": b"\x7fELFcodex\n",
        "claude": b"\x7fELFclaude\n",
    }
    payloads = {
        "base": _tar(
            [
                ("bin/sh", b"\x7fELFshell\n", 0o755),
                ("etc/passwd", b"plamen:x:65532:65532::/nonexistent:/sbin/nologin\n", 0o644),
                ("lib/aarch64-linux-gnu/libc.so.6", b"\x7fELFlibc\n", 0o755),
                ("lib/aarch64-linux-gnu/libdl.so.2", b"\x7fELFlibdl\n", 0o755),
                ("lib/aarch64-linux-gnu/libm.so.6", b"\x7fELFlibm\n", 0o755),
                ("lib/aarch64-linux-gnu/libpthread.so.0", b"\x7fELFlibpthread\n", 0o755),
                ("lib/aarch64-linux-gnu/librt.so.1", b"\x7fELFlibrt\n", 0o755),
                ("lib/ld-linux-aarch64.so.1", b"\x7fELFloader\n", 0o755),
                ("usr/bin/env", b"\x7fELFenv\n", 0o755),
                ("var/lib/dpkg/status", b"Package: base-files\nStatus: install ok installed\n", 0o644),
                ("var/lib/dpkg/info/base-files.postinst", b"#!/bin/sh\nexit 0\n", 0o755),
            ]
        ),
        "debian-state": _canonical(
            {
                "packages": [
                    {
                        "architecture": "arm64",
                        "name": "base-files",
                        "status": "install ok installed",
                        "version": "12.4+deb12u12",
                    }
                ],
                "schema_version": "plamen.debian_package_state.v1",
            }
        ),
        "plamen-guest": _tar(
            [
                (
                    "lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
                    b"\x7fELFnative-supervisor\n",
                    0o755,
                ),
                ("libexec/plamen-guest", b"\x7fELFplamen-guest\n", 0o755),
            ]
        ),
        "cpython": _tar([("bin/python3", b"\x7fELFpython\n", 0o755)]),
        "plamen": _tar(
            [
                ("scripts/plamen_driver.py", b"def main(): return 0\n", 0o644),
                ("plamen-1.dist-info/entry_points.txt", b"[console_scripts]\nplamen=plamen_driver:main\n", 0o644),
            ]
        ),
        "codex": _backend_archive(
            backend_members["codex"], backend_executables["codex"],
        ),
        "claude": _backend_archive(
            backend_members["claude"], backend_executables["claude"],
        ),
        "foundry": _tar(
            [
                ("bin/anvil", b"\x7fELFanvil\n", 0o755),
                ("bin/cast", b"\x7fELFcast\n", 0o755),
                ("bin/chisel", b"\x7fELFchisel\n", 0o755),
                ("bin/forge", b"\x7fELFforge\n", 0o755),
            ]
        ),
        "medusa": b"\x7fELFmedusa-amd64\n",
        "solc": b"\x7fELFsolc-amd64\n",
        "amd64-compat": _tar(
            [("lib64/ld-linux-x86-64.so.2", b"\x7fELFloader\n", 0o755)]
        ),
    }
    definitions = [
        (
            "base",
            "base_rootfs",
            "application/vnd.plamen.canonical-rootfs.tar",
            "/",
            [
                "/bin/sh",
                "/etc/passwd",
                "/lib/aarch64-linux-gnu/libc.so.6",
                "/lib/aarch64-linux-gnu/libdl.so.2",
                "/lib/aarch64-linux-gnu/libm.so.6",
                "/lib/aarch64-linux-gnu/libpthread.so.0",
                "/lib/aarch64-linux-gnu/librt.so.1",
                "/lib/ld-linux-aarch64.so.1",
                "/usr/bin/env",
                "/var/lib/dpkg/status",
            ],
            "linux/arm64",
        ),
        (
            "debian-state",
            "debian_package_state",
            "application/vnd.plamen.debian-package-state+json",
            "/usr/local/lib/plamen/attestations/debian-packages.json",
            ["/usr/local/lib/plamen/attestations/debian-packages.json"],
            "linux/arm64",
        ),
        (
            "plamen-guest",
            "plamen_guest",
            "application/vnd.plamen.preinstalled-tree.tar",
            "/usr/local",
            [
                "/usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
                "/usr/local/libexec/plamen-guest",
            ],
            "linux/arm64",
        ),
        (
            "cpython",
            "cpython",
            "application/vnd.plamen.preinstalled-tree.tar",
            "/usr",
            ["/usr/bin/python3"],
            "linux/arm64",
        ),
        (
            "plamen",
            "plamen_package",
            "application/vnd.plamen.preinstalled-tree.tar",
            "/opt/plamen",
            ["/opt/plamen/scripts/plamen_driver.py"],
            "linux/noarch",
        ),
        (
            "codex",
            "codex",
            "application/vnd.plamen.authenticated-tar-member",
            "/usr/local/lib/plamen/bin/codex",
            ["/usr/local/lib/plamen/bin/codex"],
            "linux/arm64",
        ),
        (
            "claude",
            "claude",
            "application/vnd.plamen.authenticated-tar-member",
            "/usr/local/lib/plamen/bin/claude",
            ["/usr/local/lib/plamen/bin/claude"],
            "linux/arm64",
        ),
        (
            "foundry",
            "foundry",
            "application/vnd.plamen.preinstalled-tree.tar",
            "/usr/local/lib/plamen/toolchains/foundry",
            [
                "/usr/local/lib/plamen/toolchains/foundry/bin/anvil",
                "/usr/local/lib/plamen/toolchains/foundry/bin/cast",
                "/usr/local/lib/plamen/toolchains/foundry/bin/chisel",
                "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
            ],
            "linux/arm64",
        ),
        (
            "medusa",
            "medusa",
            "application/vnd.plamen.executable",
            "/usr/local/lib/plamen/toolchains/medusa/bin/medusa",
            ["/usr/local/lib/plamen/toolchains/medusa/bin/medusa"],
            "linux/amd64",
        ),
        (
            "solc",
            "solc_amd64",
            "application/vnd.plamen.executable",
            "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
            ["/usr/local/lib/plamen/toolchains/solc-amd64/solc"],
            "linux/amd64",
        ),
        (
            "amd64-compat",
            "amd64_compat",
            "application/vnd.plamen.preinstalled-tree.tar",
            "/usr/local/lib/plamen/compat/amd64",
            ["/usr/local/lib/plamen/compat/amd64/lib64/ld-linux-x86-64.so.2"],
            "linux/amd64",
        ),
    ]
    source_manifests: dict[str, bytes] = {}
    sources = []
    for artifact, role, media, destination, required_paths, platform in definitions:
        required_paths.sort(key=lambda value: value.encode("utf-8"))
        source_manifest = {
            "artifact_id": artifact,
            "authentication_scope": "TEST_ONLY_EXACT_CONTENT",
            "media_type": media,
            "payload_sha256": _digest(payloads[artifact]),
            "payload_size": len(payloads[artifact]),
            "platform": platform,
            "required_paths": required_paths,
            "role": role,
            "schema_version": R.SOURCE_MANIFEST_SCHEMA_VERSION,
            "source_reference": "fixture://" + artifact,
            "version": "1.0.0",
        }
        if role in {"codex", "claude"}:
            roster = [backend_members[role]]
            source_manifest.update({
                "archive_member": backend_members[role],
                "archive_member_count": 1,
                "archive_member_roster_sha256": _digest(
                    json.dumps(
                        roster, sort_keys=True, separators=(",", ":"),
                    ).encode()
                ),
                "installed_sha256": _digest(backend_executables[role]),
                "installed_size": len(backend_executables[role]),
            })
        raw_manifest = _canonical(source_manifest)
        source_manifests[artifact] = raw_manifest
        sources.append(
            {
                "artifact_id": artifact,
                "destination": destination,
                "media_type": media,
                "payload_sha256": _digest(payloads[artifact]),
                "payload_size": len(payloads[artifact]),
                "required_paths": required_paths,
                "role": role,
                "source_manifest_sha256": _digest(raw_manifest),
                "source_manifest_size": len(raw_manifest),
            }
        )
    manifest = {
        "authentication_scope": "TEST_ONLY_EXACT_CONTENT",
        "environment_denials": {"exact_names": ["GLIBC_TUNABLES"], "prefixes": ["LD_"]},
        "installation_policy": {
            "ambient_caches": "DENY",
            "dpkg": "NETWORKLESS_LINUX_BUILDER_ONLY",
            "package_scripts": "AUTHENTICATED_AND_CENSUSED_IN_BUILD_GUEST",
            "pip": "NETWORKLESS_LINUX_BUILDER_ONLY",
            "triggers": "AUTHENTICATED_AND_CENSUSED_IN_BUILD_GUEST",
        },
        "limits": {
            "entries": 131_072,
            "expanded_bytes": 12 * 1024 * 1024 * 1024,
            "input_bytes": 8 * 1024 * 1024 * 1024,
        },
        "network": "DENY",
        "schema_version": R.SCHEMA_VERSION,
        "sources": sources,
        "target": "linux/arm64",
    }
    return manifest, payloads, source_manifests


def _replace_payload(
    manifest: dict,
    payloads: dict[str, bytes],
    source_manifests: dict[str, bytes],
    source_index: int,
    payload: bytes,
) -> None:
    source = manifest["sources"][source_index]
    artifact = source["artifact_id"]
    payloads[artifact] = payload
    source["payload_sha256"] = _digest(payload)
    source["payload_size"] = len(payload)
    value = json.loads(source_manifests[artifact])
    value["payload_sha256"] = source["payload_sha256"]
    value["payload_size"] = source["payload_size"]
    source_manifests[artifact] = _canonical(value)
    source["source_manifest_sha256"] = _digest(source_manifests[artifact])
    source["source_manifest_size"] = len(source_manifests[artifact])


def _write_inputs(
    tmp_path: Path,
    manifest: dict,
    payloads: dict[str, bytes],
    source_manifests: dict[str, bytes],
) -> tuple[R.RetainedRuntimeInput, ...]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    retained = []
    for index, source in enumerate(manifest["sources"]):
        artifact = source["artifact_id"]
        payload_path = tmp_path / f"{index:02d}.payload"
        manifest_path = tmp_path / f"{index:02d}.manifest"
        payload_path.write_bytes(payloads[artifact])
        manifest_path.write_bytes(source_manifests[artifact])
        payload_fd = os.open(payload_path, os.O_RDONLY | os.O_NOFOLLOW)
        manifest_fd = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW)
        retained.append(R.RetainedRuntimeInput(artifact, payload_fd, manifest_fd))
    return tuple(retained)


def _output_pair(tmp_path: Path, name: str = "runtime.tar") -> tuple[int, int, int]:
    path = tmp_path / name
    writer = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    reader = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    watcher = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    path.unlink()
    return writer, reader, watcher


def _compose(tmp_path: Path, *, mutate=None):
    manifest, payloads, source_manifests = _fixture_values()
    if mutate is not None:
        mutate(manifest, payloads, source_manifests)
    raw = _canonical(manifest)
    retained = _write_inputs(tmp_path, manifest, payloads, source_manifests)
    writer, reader, watcher = _output_pair(tmp_path)
    try:
        result = R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=retained,
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
        )
    except BaseException:
        os.close(watcher)
        raise
    return result, watcher, retained, raw


def test_production_entrypoint_is_a_literal_first_effect_hardstop(monkeypatch) -> None:
    touched = False

    def explode(*args, **kwargs):
        nonlocal touched
        touched = True
        raise AssertionError("inspected")

    monkeypatch.setattr(R.os, "fstat", explode)
    with pytest.raises(
        R.RuntimeMaterializationUnsupported,
        match="NATIVE_RETAINED_FD_BUILD_GUEST_AUTHORITY_REQUIRED",
    ):
        R.materialize_runtime_image(object(), payload=object())
    assert touched is False


def test_exact_runtime_composes_verifies_and_normalizes_every_entry(tmp_path: Path) -> None:
    result, watcher, retained, raw = _compose(tmp_path)
    try:
        for row in retained:
            with pytest.raises(OSError):
                os.fstat(row.payload_descriptor)
            with pytest.raises(OSError):
                os.fstat(row.source_manifest_descriptor)
        assert fcntl.fcntl(result.archive_descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        R._TEST_ONLY_verify_materialized_runtime(
            result.archive_descriptor,
            composition_manifest_bytes=raw,
            receipt_bytes=result.receipt_bytes,
            census_bytes=result.census_bytes,
            sbom_bytes=result.sbom_bytes,
            provenance_bytes=result.provenance_bytes,
            expected_manifest_sha256=_digest(raw),
        )
        receipt = json.loads(result.receipt_bytes)
        assert receipt["production_authority"] is False
        assert receipt["archive"]["diff_id"] == "sha256:" + receipt["archive"]["sha256"]
        assert receipt["package_execution"] == {
            "compositor_executed_scripts": False,
            "compositor_executed_triggers": False,
            "observed_installer_script_entries": 2,
            "observed_trigger_entries": 0,
        }
        with os.fdopen(os.dup(result.archive_descriptor), "rb") as stream:
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                members = archive.getmembers()
                extracted = {
                    member.name: archive.extractfile(member).read()
                    for member in members if member.isfile()
                }
        assert members
        assert all(member.uid == member.gid == member.mtime == 0 for member in members)
        assert all(member.uname == member.gname == "" for member in members)
        assert all(
            stat.S_IMODE(member.mode) in (0o444, 0o555, 0o755, 0o777)
            for member in members
        )
        assert extracted["usr/local/lib/plamen/bin/codex"] == b"\x7fELFcodex\n"
        assert extracted["usr/local/lib/plamen/bin/claude"] == b"\x7fELFclaude\n"
        assert extracted["usr/local/lib/plamen/bin/codex"] != _fixture_values()[1]["codex"]
        assert os.fstat(watcher).st_size == receipt["archive"]["size"]
    finally:
        os.close(result.archive_descriptor)
        os.close(watcher)


def test_output_is_byte_deterministic(tmp_path: Path) -> None:
    first, first_watcher, _, first_raw = _compose(tmp_path / "first")
    second, second_watcher, _, second_raw = _compose(tmp_path / "second")
    try:
        assert first_raw == second_raw
        assert first.receipt_bytes == second.receipt_bytes
        assert first.census_bytes == second.census_bytes
        assert first.sbom_bytes == second.sbom_bytes
        assert first.provenance_bytes == second.provenance_bytes
        assert os.pread(first.archive_descriptor, os.fstat(first.archive_descriptor).st_size, 0) == os.pread(
            second.archive_descriptor, os.fstat(second.archive_descriptor).st_size, 0
        )
    finally:
        for descriptor in (
            first.archive_descriptor,
            first_watcher,
            second.archive_descriptor,
            second_watcher,
        ):
            os.close(descriptor)


def test_backend_archive_member_and_census_are_exactly_bound(tmp_path: Path) -> None:
    def wrong_member(manifest, _payloads, source_manifests):
        source = manifest["sources"][5]
        value = json.loads(source_manifests["codex"])
        value["archive_member"] = "package/vendor/other/bin/codex"
        source_manifests["codex"] = _canonical(value)
        source["source_manifest_sha256"] = _digest(source_manifests["codex"])
        source["source_manifest_size"] = len(source_manifests["codex"])

    with pytest.raises(R.RuntimeMaterializationError, match="census differs"):
        _compose(tmp_path / "member", mutate=wrong_member)

    def wrong_digest(manifest, _payloads, source_manifests):
        source = manifest["sources"][5]
        value = json.loads(source_manifests["codex"])
        value["installed_sha256"] = "00" * 32
        source_manifests["codex"] = _canonical(value)
        source["source_manifest_sha256"] = _digest(source_manifests["codex"])
        source["source_manifest_size"] = len(source_manifests["codex"])

    with pytest.raises(R.RuntimeMaterializationError, match="member digest differs"):
        _compose(tmp_path / "digest", mutate=wrong_digest)

    def extra_member(manifest, payloads, source_manifests):
        payload = gzip.compress(_tar([
            ("package/vendor/aarch64-unknown-linux-gnu/bin/codex",
             b"\x7fELFcodex\n", 0o755),
            ("package/extra", b"untrusted", 0o644),
        ]), mtime=0)
        _replace_payload(manifest, payloads, source_manifests, 5, payload)

    with pytest.raises(R.RuntimeMaterializationError, match="census differs"):
        _compose(tmp_path / "roster", mutate=extra_member)


def test_native_backend_source_manifest_renderer_binds_archive_and_executable() -> None:
    member = "package/vendor/aarch64-unknown-linux-gnu/bin/codex"
    archive = _backend_archive(member, b"\x7fELFcodex\n")
    roster_sha256 = _digest(json.dumps(
        [member], sort_keys=True, separators=(",", ":"),
    ).encode())
    payload = {
        "source_url": "https://registry.npmjs.org/codex/-/codex.tgz",
        "size": len(archive), "sha256": _digest(archive),
        "sha512_sri": "sha512-fixture", "archive_format": "tar.gz",
        "member_count": 1, "member_roster_sha256": roster_sha256,
        "selected_member": member, "path_traversal_rejected": True,
    }
    installed = {
        "platform": "linux-arm64", "relative_path": "node_modules/codex",
        "executable_size": len(b"\x7fELFcodex\n"),
        "executable_sha256": _digest(b"\x7fELFcodex\n"),
        "closure_count": 1, "closure_bytes": 1,
        "closure_sha256": "11" * 32, "code_signature": {},
    }
    raw = R.render_backend_archive_source_manifest(
        selector="codex", resolved_version="0.154.0",
        payload=payload, installed=installed,
    )
    assert raw == _canonical(json.loads(raw))
    value = json.loads(raw)
    assert value["artifact_id"] == "codex-0.154.0-linux-arm64"
    assert value["payload_sha256"] == _digest(archive)
    assert value["installed_sha256"] == _digest(b"\x7fELFcodex\n")
    assert value["archive_member"] == member

    forged = dict(payload); forged["selected_member"] = "package/bin/codex"
    with pytest.raises(R.RuntimeMaterializationError, match="selected member"):
        R.render_backend_archive_source_manifest(
            selector="codex", resolved_version="0.154.0",
            payload=forged, installed=installed,
        )


def test_full_census_sbom_and_provenance_have_identical_file_projection(tmp_path: Path) -> None:
    result, watcher, _, _ = _compose(tmp_path)
    try:
        census = json.loads(result.census_bytes)
        sbom = json.loads(result.sbom_bytes)
        provenance = json.loads(result.provenance_bytes)
        census_paths = [row["path"] for row in census["entries"]]
        assert [row["path"] for row in provenance["outputs"]] == census_paths
        assert [row["fileName"][1:] for row in sbom["files"]] == [
            row["path"] for row in census["entries"] if row["kind"] == "file"
        ]
        assert len(sbom["packages"]) == len(R._REQUIRED_ROLES)
    finally:
        os.close(result.archive_descriptor)
        os.close(watcher)


@pytest.mark.parametrize("name", ["LD_PRELOAD", "LD_LIBRARY_PATH", "GLIBC_TUNABLES"])
def test_loader_environment_is_denied_before_output(name: str, tmp_path: Path) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    raw = _canonical(manifest)
    retained = _write_inputs(tmp_path, manifest, payloads, source_manifests)
    writer, reader, watcher = _output_pair(tmp_path)
    with pytest.raises(R.RuntimeMaterializationError, match="forbidden loader environment"):
        R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=retained,
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
            declared_environment={name: "attacker"},
        )
    try:
        assert os.fstat(watcher).st_size == 0
    finally:
        os.close(watcher)


def test_composition_manifest_must_be_canonical_and_digest_pinned(tmp_path: Path) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    raw = json.dumps(manifest, indent=2).encode()
    retained = _write_inputs(tmp_path, manifest, payloads, source_manifests)
    writer, reader, watcher = _output_pair(tmp_path)
    with pytest.raises(R.RuntimeMaterializationError, match="not canonical JSON"):
        R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=retained,
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
        )
    os.close(watcher)


def test_role_reorder_is_rejected(tmp_path: Path) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    manifest["sources"][0], manifest["sources"][1] = manifest["sources"][1], manifest["sources"][0]
    raw = _canonical(manifest)
    retained = _write_inputs(tmp_path, manifest, payloads, source_manifests)
    writer, reader, watcher = _output_pair(tmp_path)
    with pytest.raises(R.RuntimeMaterializationError, match="role roster/order"):
        R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=retained,
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
        )
    os.close(watcher)


def test_retained_roster_alias_and_writable_sources_are_rejected(tmp_path: Path) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    raw = _canonical(manifest)
    retained = list(_write_inputs(tmp_path, manifest, payloads, source_manifests))
    duplicate = os.dup(retained[0].payload_descriptor)
    os.close(retained[1].payload_descriptor)
    retained[1] = R.RetainedRuntimeInput(
        retained[1].artifact_id, duplicate, retained[1].source_manifest_descriptor
    )
    writer, reader, watcher = _output_pair(tmp_path)
    with pytest.raises(R.RuntimeMaterializationError, match="alias"):
        R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=tuple(retained),
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
        )
    os.close(watcher)


def test_casefold_collision_is_rejected(tmp_path: Path) -> None:
    def mutate(manifest, payloads, source_manifests):
        payloads["cpython"] = _tar(
            [("bin/python3", b"python", 0o755), ("bin/PYTHON3", b"attacker", 0o755)]
        )
        source = manifest["sources"][3]
        source["payload_sha256"] = _digest(payloads["cpython"])
        source["payload_size"] = len(payloads["cpython"])
        value = json.loads(source_manifests["cpython"])
        value["payload_sha256"] = source["payload_sha256"]
        value["payload_size"] = source["payload_size"]
        source_manifests["cpython"] = _canonical(value)
        source["source_manifest_sha256"] = _digest(source_manifests["cpython"])
        source["source_manifest_size"] = len(source_manifests["cpython"])

    with pytest.raises(R.RuntimeMaterializationError, match="case/NFC collision"):
        _compose(tmp_path, mutate=mutate)


def test_safe_links_are_detected_normalized_and_resolved(tmp_path: Path) -> None:
    def mutate(manifest, payloads, source_manifests):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            valid = tarfile.TarInfo("bin/python3.12")
            valid.mode = 0o755
            valid.size = 6
            archive.addfile(valid, io.BytesIO(b"python"))
            symlink = tarfile.TarInfo("bin/python3")
            symlink.type = tarfile.SYMTYPE
            symlink.mode = 0o777
            symlink.linkname = "python3.12"
            archive.addfile(symlink)
            hardlink = tarfile.TarInfo("bin/python-copy")
            hardlink.type = tarfile.LNKTYPE
            hardlink.mode = 0o755
            hardlink.linkname = "bin/python3.12"
            archive.addfile(hardlink)
        payloads["cpython"] = stream.getvalue()
        source = manifest["sources"][3]
        source["payload_sha256"] = _digest(payloads["cpython"])
        source["payload_size"] = len(payloads["cpython"])
        value = json.loads(source_manifests["cpython"])
        value["payload_sha256"] = source["payload_sha256"]
        value["payload_size"] = source["payload_size"]
        source_manifests["cpython"] = _canonical(value)
        source["source_manifest_sha256"] = _digest(source_manifests["cpython"])
        source["source_manifest_size"] = len(source_manifests["cpython"])

    result, watcher, _, _ = _compose(tmp_path, mutate=mutate)
    try:
        census = json.loads(result.census_bytes)
        by_path = {row["path"]: row for row in census["entries"]}
        assert by_path["usr/bin/python3"] == {
            "kind": "symlink",
            "linkname": "python3.12",
            "mode": "0777",
            "path": "usr/bin/python3",
            "sha256": _digest(b"symlink\0python3.12"),
            "size": 0,
        }
        assert by_path["usr/bin/python-copy"]["kind"] == "hardlink"
        assert by_path["usr/bin/python-copy"]["linkname"] == (
            "usr/bin/python3.12"
        )
    finally:
        os.close(result.archive_descriptor)
        os.close(watcher)


@pytest.mark.parametrize("entry_type", [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_devices_and_special_entries_are_rejected(entry_type: bytes, tmp_path: Path) -> None:
    def mutate(manifest, payloads, source_manifests):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            valid = tarfile.TarInfo("bin/python3")
            valid.mode = 0o755
            valid.size = 6
            archive.addfile(valid, io.BytesIO(b"python"))
            bad = tarfile.TarInfo("bad")
            bad.type = entry_type
            bad.devmajor = 1
            bad.devminor = 3
            archive.addfile(bad)
        payloads["cpython"] = stream.getvalue()
        source = manifest["sources"][3]
        source["payload_sha256"] = _digest(payloads["cpython"])
        source["payload_size"] = len(payloads["cpython"])
        value = json.loads(source_manifests["cpython"])
        value["payload_sha256"] = source["payload_sha256"]
        value["payload_size"] = source["payload_size"]
        source_manifests["cpython"] = _canonical(value)
        source["source_manifest_sha256"] = _digest(source_manifests["cpython"])
        source["source_manifest_size"] = len(source_manifests["cpython"])

    with pytest.raises(R.RuntimeMaterializationError, match="devices|special"):
        _compose(tmp_path, mutate=mutate)


def test_symlink_escape_and_missing_hardlink_fail_closed(tmp_path: Path) -> None:
    def malicious_payload(kind: bytes, target: str) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            link = tarfile.TarInfo("bin/python3")
            link.type = kind
            link.mode = 0o777
            link.linkname = target
            archive.addfile(link)
        return stream.getvalue()

    for index, (kind, target, message) in enumerate(
        (
            (tarfile.SYMTYPE, "../../../../escape", "escapes"),
            (tarfile.LNKTYPE, "bin/missing", "hardlink target"),
        )
    ):
        folder = tmp_path / str(index)

        def mutate(manifest, payloads, source_manifests, *, kind=kind, target=target):
            payloads["cpython"] = malicious_payload(kind, target)
            source = manifest["sources"][3]
            source["payload_sha256"] = _digest(payloads["cpython"])
            source["payload_size"] = len(payloads["cpython"])
            value = json.loads(source_manifests["cpython"])
            value["payload_sha256"] = source["payload_sha256"]
            value["payload_size"] = source["payload_size"]
            source_manifests["cpython"] = _canonical(value)
            source["source_manifest_sha256"] = _digest(source_manifests["cpython"])
            source["source_manifest_size"] = len(source_manifests["cpython"])

        with pytest.raises(R.RuntimeMaterializationError, match=message):
            _compose(folder, mutate=mutate)


def test_uninstalled_package_script_tree_is_rejected(tmp_path: Path) -> None:
    def mutate(manifest, payloads, source_manifests):
        payloads["plamen"] = _tar(
            [
                ("plamen_driver.py", b"pass\n", 0o644),
                ("DEBIAN/postinst", b"#!/bin/sh\n", 0o755),
            ]
        )
        source = manifest["sources"][4]
        source["payload_sha256"] = _digest(payloads["plamen"])
        source["payload_size"] = len(payloads["plamen"])
        value = json.loads(source_manifests["plamen"])
        value["payload_sha256"] = source["payload_sha256"]
        value["payload_size"] = source["payload_size"]
        source_manifests["plamen"] = _canonical(value)
        source["source_manifest_sha256"] = _digest(source_manifests["plamen"])
        source["source_manifest_size"] = len(source_manifests["plamen"])

    with pytest.raises(R.RuntimeMaterializationError, match="package scripts"):
        _compose(tmp_path, mutate=mutate)


@pytest.mark.parametrize(
    "media_type",
    ["application/vnd.debian.binary-package", "application/vnd.python.wheel"],
)
def test_package_install_media_returns_exact_typed_linux_builder_boundary(
    media_type: str, tmp_path: Path
) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    source = manifest["sources"][4]
    source["media_type"] = media_type
    value = json.loads(source_manifests["plamen"])
    value["media_type"] = media_type
    source_manifests["plamen"] = _canonical(value)
    source["source_manifest_sha256"] = _digest(source_manifests["plamen"])
    source["source_manifest_size"] = len(source_manifests["plamen"])
    raw = _canonical(manifest)
    retained = _write_inputs(tmp_path, manifest, payloads, source_manifests)
    writer, reader, watcher = _output_pair(tmp_path)
    with pytest.raises(R.NetworklessLinuxBuilderRequired) as stopped:
        R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=retained,
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
        )
    try:
        protocol = json.loads(stopped.value.protocol_bytes)
        assert stopped.value.artifact_ids == ("plamen",)
        assert protocol == R.NETWORKLESS_LINUX_BUILDER_PROTOCOL
        assert protocol["network"] == "DENY"
        assert protocol["authority"] == "NATIVE_RETAINED_FD_BUILD_GUEST_BROKER_REQUIRED"
        assert "same_fd_recursive_elf_and_shebang_closure" in protocol["required_evidence"]
        assert os.fstat(watcher).st_size == 0
    finally:
        os.close(watcher)


def test_output_must_be_unlinked_same_inode_read_write_read_only_pair(tmp_path: Path) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    raw = _canonical(manifest)
    retained = _write_inputs(tmp_path, manifest, payloads, source_manifests)
    writer_path = tmp_path / "writer"
    reader_path = tmp_path / "reader"
    writer = os.open(writer_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    reader = os.open(reader_path, os.O_CREAT | os.O_EXCL | os.O_RDONLY, 0o600)
    watcher = os.dup(reader)
    writer_path.unlink()
    reader_path.unlink()
    with pytest.raises(R.RuntimeMaterializationError, match="same object"):
        R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=retained,
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
        )
    os.close(watcher)


def test_verifier_rejects_receipt_and_evidence_substitution(tmp_path: Path) -> None:
    result, watcher, _, raw = _compose(tmp_path)
    try:
        receipt = json.loads(result.receipt_bytes)
        receipt["network"] = "ALLOW"
        with pytest.raises(R.RuntimeMaterializationError, match="policy binding"):
            R._TEST_ONLY_verify_materialized_runtime(
                result.archive_descriptor,
                composition_manifest_bytes=raw,
                receipt_bytes=_canonical(receipt),
                census_bytes=result.census_bytes,
                sbom_bytes=result.sbom_bytes,
                provenance_bytes=result.provenance_bytes,
                expected_manifest_sha256=_digest(raw),
            )
        census = json.loads(result.census_bytes)
        census["entries"][0]["mode"] = "0777"
        with pytest.raises(R.RuntimeMaterializationError, match="evidence digest"):
            R._TEST_ONLY_verify_materialized_runtime(
                result.archive_descriptor,
                composition_manifest_bytes=raw,
                receipt_bytes=result.receipt_bytes,
                census_bytes=_canonical(census),
                sbom_bytes=result.sbom_bytes,
                provenance_bytes=result.provenance_bytes,
                expected_manifest_sha256=_digest(raw),
            )
    finally:
        os.close(result.archive_descriptor)
        os.close(watcher)


def test_post_write_failure_rolls_unlinked_output_back_to_zero(monkeypatch, tmp_path: Path) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    raw = _canonical(manifest)
    retained = _write_inputs(tmp_path, manifest, payloads, source_manifests)
    writer, reader, watcher = _output_pair(tmp_path)
    original = R._hash_fd

    def reject_written_archive(descriptor, size, label):
        if label == "canonical runtime archive":
            raise R.RuntimeMaterializationError("forced post-write rejection")
        return original(descriptor, size, label)

    monkeypatch.setattr(R, "_hash_fd", reject_written_archive)
    with pytest.raises(R.RuntimeMaterializationError, match="forced post-write"):
        R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=retained,
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
        )
    try:
        assert os.fstat(watcher).st_size == 0
    finally:
        os.close(watcher)


@pytest.mark.parametrize("unsafe", ["writable", "inheritable"])
def test_source_descriptors_must_be_noninheritable_read_only(
    unsafe: str, tmp_path: Path
) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    raw = _canonical(manifest)
    retained = list(_write_inputs(tmp_path, manifest, payloads, source_manifests))
    if unsafe == "writable":
        os.close(retained[0].payload_descriptor)
        descriptor = os.open(tmp_path / "00.payload", os.O_RDWR | os.O_NOFOLLOW)
        retained[0] = R.RetainedRuntimeInput(
            retained[0].artifact_id,
            descriptor,
            retained[0].source_manifest_descriptor,
        )
        message = "read-only"
    else:
        os.set_inheritable(retained[0].payload_descriptor, True)
        message = "not be inheritable"
    writer, reader, watcher = _output_pair(tmp_path)
    with pytest.raises(R.RuntimeMaterializationError, match=message):
        R._TEST_ONLY_materialize_runtime_image(
            raw,
            expected_manifest_sha256=_digest(raw),
            retained_inputs=tuple(retained),
            output_writer_descriptor=writer,
            output_reader_descriptor=reader,
        )
    try:
        assert os.fstat(watcher).st_size == 0
    finally:
        os.close(watcher)


def test_pinned_debian_usrmerge_symlinks_are_preserved_and_resolve(tmp_path: Path) -> None:
    def mutate(manifest, payloads, source_manifests):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, target in (("bin", "usr/bin"), ("lib", "usr/lib")):
                link = tarfile.TarInfo(name)
                link.type = tarfile.SYMTYPE
                link.mode = 0o777
                link.linkname = target
                archive.addfile(link)
            files = [
                ("etc/passwd", b"plamen:x:65532:65532::/nonexistent:/sbin/nologin\n"),
                ("usr/bin/sh", b"\x7fELFshell\n"),
                ("usr/bin/env", b"\x7fELFenv\n"),
                ("usr/lib/ld-linux-aarch64.so.1", b"\x7fELFloader\n"),
                ("usr/lib/aarch64-linux-gnu/libc.so.6", b"\x7fELFlibc\n"),
                ("usr/lib/aarch64-linux-gnu/libdl.so.2", b"\x7fELFlibdl\n"),
                ("usr/lib/aarch64-linux-gnu/libm.so.6", b"\x7fELFlibm\n"),
                ("usr/lib/aarch64-linux-gnu/libpthread.so.0", b"\x7fELFlibpthread\n"),
                ("usr/lib/aarch64-linux-gnu/librt.so.1", b"\x7fELFlibrt\n"),
                ("var/lib/dpkg/status", b"Package: base-files\nStatus: install ok installed\n"),
            ]
            for name, content in files:
                info = tarfile.TarInfo(name)
                info.mode = 0o755 if name.startswith("usr/") else 0o644
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        _replace_payload(manifest, payloads, source_manifests, 0, stream.getvalue())

    result, watcher, _, _ = _compose(tmp_path, mutate=mutate)
    try:
        census = json.loads(result.census_bytes)
        by_path = {row["path"]: row for row in census["entries"]}
        assert by_path["bin"]["kind"] == "symlink"
        assert by_path["bin"]["linkname"] == "usr/bin"
        assert by_path["lib"]["kind"] == "symlink"
        assert by_path["lib"]["linkname"] == "usr/lib"
    finally:
        os.close(result.archive_descriptor)
        os.close(watcher)


def test_gzip_archive_is_accepted_but_concatenation_is_rejected(tmp_path: Path) -> None:
    manifest, payloads, source_manifests = _fixture_values()
    raw_tar = payloads["cpython"]
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as encoder:
        encoder.write(raw_tar)
    compressed = buffer.getvalue()

    def valid(manifest, payloads, source_manifests):
        _replace_payload(manifest, payloads, source_manifests, 3, compressed)

    result, watcher, _, _ = _compose(tmp_path / "valid", mutate=valid)
    os.close(result.archive_descriptor)
    os.close(watcher)

    def concatenated(manifest, payloads, source_manifests):
        _replace_payload(
            manifest,
            payloads,
            source_manifests,
            3,
            compressed + gzip.compress(b"hidden", mtime=0),
        )

    with pytest.raises(R.RuntimeMaterializationError, match="concatenated|trailing"):
        _compose(tmp_path / "invalid", mutate=concatenated)


def test_gzip_inflation_is_chunked_and_stops_at_the_exact_bound(
    monkeypatch, tmp_path: Path
) -> None:
    raw = gzip.compress(b"A" * 8192, mtime=0)
    path = tmp_path / "bomb.tar.gz"
    path.write_bytes(raw)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    monkeypatch.setattr(R, "MAX_EXPANDED_BYTES", 4096)
    try:
        with tempfile.TemporaryFile(mode="w+b") as spool:
            with pytest.raises(
                R.RuntimeMaterializationError, match="decompression exceeds"
            ):
                R._expand_archive(
                    descriptor,
                    {
                        "artifact_id": "bomb",
                        "destination": "/usr",
                        "payload_size": len(raw),
                        "role": "cpython",
                    },
                    {},
                    {},
                    spool,
                    [0],
                )
            assert spool.tell() <= 4096
    finally:
        os.close(descriptor)


def test_hidden_tar_records_and_reserved_base_namespace_are_rejected(tmp_path: Path) -> None:
    for index, (mutation, message) in enumerate(
        (
            (lambda raw: raw + b"hidden", "terminator"),
            (
                lambda _raw: _tar(
                    [
                        ("opt/plamen/attacker", b"owned", 0o755),
                        ("bin/sh", b"shell", 0o755),
                    ]
                ),
                "reserved Plamen namespace",
            ),
        )
    ):
        def mutate(manifest, payloads, source_manifests, *, mutation=mutation):
            _replace_payload(
                manifest,
                payloads,
                source_manifests,
                0,
                mutation(payloads["base"]),
            )

        with pytest.raises(R.RuntimeMaterializationError, match=message):
            _compose(tmp_path / str(index), mutate=mutate)


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("etc/ld.so.cache", "forbidden loader state"),
        ("etc/ld.so.preload", "forbidden loader state"),
        (
            "usr/lib/aarch64-linux-gnu/glibc-hwcaps/attacker",
            "forbidden hwcaps namespace",
        ),
        ("usr/lib/aarch64-linux-gnu/tls/attacker", "forbidden hwcaps namespace"),
        (".wh.attacker", "OCI whiteout"),
        ("usr/.wh..wh..opq", "OCI whiteout"),
    ],
)
def test_loader_state_hwcaps_and_whiteouts_are_rejected(
    path: str, message: str, tmp_path: Path
) -> None:
    def mutate(manifest, payloads, source_manifests):
        _replace_payload(
            manifest,
            payloads,
            source_manifests,
            0,
            _append_tar_file(payloads["base"], path),
        )

    with pytest.raises(R.RuntimeMaterializationError, match=message):
        _compose(tmp_path, mutate=mutate)


def test_entry_limit_is_enforced_during_parent_synthesis(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(R, "MAX_ENTRIES", 5)
    with pytest.raises(R.RuntimeMaterializationError, match="131072-entry"):
        _compose(tmp_path)


def test_receipt_extra_fields_and_source_roster_substitution_are_rejected(tmp_path: Path) -> None:
    result, watcher, _, raw = _compose(tmp_path)
    try:
        receipt = json.loads(result.receipt_bytes)
        receipt["ignored"] = True
        with pytest.raises(R.RuntimeMaterializationError, match="schema"):
            R._TEST_ONLY_verify_materialized_runtime(
                result.archive_descriptor,
                composition_manifest_bytes=raw,
                receipt_bytes=_canonical(receipt),
                census_bytes=result.census_bytes,
                sbom_bytes=result.sbom_bytes,
                provenance_bytes=result.provenance_bytes,
                expected_manifest_sha256=_digest(raw),
            )
        receipt.pop("ignored")
        receipt["source_roster_sha256"] = "0" * 64
        with pytest.raises(R.RuntimeMaterializationError, match="source roster binding"):
            R._TEST_ONLY_verify_materialized_runtime(
                result.archive_descriptor,
                composition_manifest_bytes=raw,
                receipt_bytes=_canonical(receipt),
                census_bytes=result.census_bytes,
                sbom_bytes=result.sbom_bytes,
                provenance_bytes=result.provenance_bytes,
                expected_manifest_sha256=_digest(raw),
            )
    finally:
        os.close(result.archive_descriptor)
        os.close(watcher)


def test_staged_input_schema_is_exact_canonical_and_exposes_all_limits() -> None:
    raw = R.staged_input_schema_bytes()
    assert raw == _canonical(json.loads(raw))
    value = json.loads(raw)
    assert value["limits"] == {
        "entries": 131_072,
        "expanded_bytes": 12 * 1024 * 1024 * 1024,
        "input_bytes": 8 * 1024 * 1024 * 1024,
    }
    assert value["composition_manifest"]["required_role_order"] == [
        "base_rootfs",
        "debian_package_state",
        "plamen_guest",
        "cpython",
        "plamen_package",
        "codex",
        "claude",
        "foundry",
        "medusa",
        "solc_amd64",
        "amd64_compat",
    ]
    assert R.NETWORKLESS_LINUX_BUILDER_PROTOCOL["package_inputs"]["amd64_compat"] == (
        "PINNED_EXTRACT_ONLY_NO_POSTINSTALL_REQUEST_BOUND_ROSETTA"
    )
