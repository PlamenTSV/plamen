"""Independent and adversarial tests for deterministic OCI image assembly."""

from __future__ import annotations

import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tarfile
import tempfile
import zlib

import pytest

import deterministic_oci_layout as L
import elf_loader_closure as E
import oci_image_lock as O
import runtime_image_materializer as runtime_materializer
import test_oci_image_lock as lock_tests


_GOLDEN_MANIFEST = (
    "sha256:0d186371fe547dc89e2f8c1649289da066c5efae565fb562190b241b5340b1db"
)


def _json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _deterministic_gzip(raw: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = compressor.compress(raw) + compressor.flush(zlib.Z_FINISH)
    return (
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
        + body
        + struct.pack("<II", zlib.crc32(raw), len(raw) & 0xFFFFFFFF)
    )


def _gnu_magic_variant(raw: bytes) -> bytes:
    changed = bytearray(raw)
    assert len(changed) >= 512
    changed[257:265] = b"ustar  \0"
    changed[148:156] = b"        "
    checksum = sum(changed[:512])
    changed[148:156] = f"{checksum:06o}".encode("ascii") + b"\0 "
    return bytes(changed)


def _aarch64_elf(label: bytes) -> bytes:
    size = 64 + 56 + len(label)
    identity = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        identity,
        3,
        183,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0, size, size, 4096)
    return header + program + label


def _dynamic_aarch64_elf(
    *,
    needed: tuple[str, ...] = (),
    interpreter: str | None = "/lib/ld-linux-aarch64.so.1",
    soname: str | None = None,
    rpath: str | None = None,
    runpath: str | None = None,
    nodeflib: bool = False,
) -> bytes:
    strings = bytearray(b"\0")

    def add(value: str) -> int:
        offset = len(strings)
        strings.extend(value.encode("utf-8") + b"\0")
        return offset

    needed_offsets = [add(value) for value in needed]
    soname_offset = add(soname) if soname is not None else None
    rpath_offset = add(rpath) if rpath is not None else None
    runpath_offset = add(runpath) if runpath is not None else None
    program_count = 3 if interpreter is not None else 2
    interpreter_raw = (
        interpreter.encode("utf-8") + b"\0" if interpreter is not None else b""
    )
    dynamic_count = 3 + len(needed_offsets)
    dynamic_count += soname_offset is not None
    dynamic_count += rpath_offset is not None
    dynamic_count += runpath_offset is not None
    dynamic_count += nodeflib
    header_bytes = 64 + 56 * program_count
    interpreter_offset = header_bytes
    dynamic_offset = (interpreter_offset + len(interpreter_raw) + 7) & ~7
    string_offset = dynamic_offset + 16 * dynamic_count
    virtual_base = 0x400000
    dynamic_rows = [
        (5, virtual_base + string_offset),
        (10, len(strings)),
        *((1, offset) for offset in needed_offsets),
    ]
    if soname_offset is not None:
        dynamic_rows.append((14, soname_offset))
    if rpath_offset is not None:
        dynamic_rows.append((15, rpath_offset))
    if runpath_offset is not None:
        dynamic_rows.append((29, runpath_offset))
    if nodeflib:
        dynamic_rows.append((0x6FFFFFFB, 0x00000800))
    dynamic_rows.append((0, 0))
    dynamic_raw = b"".join(
        struct.pack("<qQ", tag, value) for tag, value in dynamic_rows
    )
    total_size = string_offset + len(strings)
    identity = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        identity,
        3,
        183,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        program_count,
        0,
        0,
        0,
    )
    programs = [
        struct.pack(
            "<IIQQQQQQ",
            1,
            5,
            0,
            virtual_base,
            0,
            total_size,
            total_size,
            4096,
        ),
        struct.pack(
            "<IIQQQQQQ",
            2,
            4,
            dynamic_offset,
            virtual_base + dynamic_offset,
            0,
            len(dynamic_raw),
            len(dynamic_raw),
            8,
        ),
    ]
    if interpreter is not None:
        programs.append(
            struct.pack(
                "<IIQQQQQQ",
                3,
                4,
                interpreter_offset,
                virtual_base + interpreter_offset,
                0,
                len(interpreter_raw),
                len(interpreter_raw),
                1,
            )
        )
    padding = b"\0" * (dynamic_offset - header_bytes - len(interpreter_raw))
    return (
        header
        + b"".join(programs)
        + interpreter_raw
        + padding
        + dynamic_raw
        + bytes(strings)
    )


def _fragment(
    files: dict[str, tuple[int, bytes]],
    *,
    extra: tarfile.TarInfo | None = None,
    extra_payload: bytes = b"",
    archive_format: int = tarfile.USTAR_FORMAT,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=archive_format) as archive:
        for path, (mode, raw) in sorted(files.items()):
            member = tarfile.TarInfo(path)
            member.type = tarfile.REGTYPE
            member.mode = mode
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ""
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        if extra is not None:
            archive.addfile(extra, io.BytesIO(extra_payload) if extra.isreg() else None)
    return output.getvalue()


def _materialize_runtime_fixture(
    tmp_path: Path,
    installed: dict[str, tuple[int, bytes]],
) -> tuple[dict[str, bytes], dict[str, object], dict[str, tuple[int, bytes]]]:
    """Produce the exact separate materializer evidence consumed by OCI."""

    by_prefix = lambda prefix: {
        path.removeprefix(prefix): value
        for path, value in installed.items()
        if path.startswith(prefix)
    }
    runtime_system_paths = {
        "usr/bin/python3",
        "usr/local/libexec/plamen-guest",
        "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
    }
    runtime_system_prefixes = (
        "usr/lib/python3.12/",
        "usr/local/lib/plamen/",
        "usr/local/share/plamen/",
    )
    base = {
        path: value
        for path, value in installed.items()
        if path.startswith(("bin/", "etc/", "lib/", "usr/", "var/"))
        and path not in runtime_system_paths
        and not path.startswith(runtime_system_prefixes)
    }
    base.setdefault(
        "var/lib/dpkg/status",
        (0o444, b"Package: base-files\nStatus: install ok installed\n"),
    )
    plamen_tree = {
        path.removeprefix("opt/plamen/"): value
        for path, value in installed.items()
        if path.startswith("opt/plamen/")
    }
    guest_tree = {
        path.removeprefix("usr/local/"): value
        for path, value in installed.items()
        if path
        in {
            "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
            "usr/local/libexec/plamen-guest",
        }
    }
    python_tree = {
        path.removeprefix("usr/"): value
        for path, value in installed.items()
        if path == "usr/bin/python3" or path.startswith("usr/lib/python3.12/")
    }
    backend_members = {
        "codex": "package/vendor/aarch64-unknown-linux-gnu/bin/codex",
        "claude": "package/claude",
    }
    backend_executables = {
        "codex": installed["usr/local/lib/plamen/bin/codex"][1],
        "claude": installed["usr/local/lib/plamen/bin/claude"][1],
    }
    payloads = {
        "base": _fragment(base),
        "debian-state": _json(
            {
                "packages": [
                    {
                        "architecture": "arm64",
                        "name": "base-files",
                        "status": "install ok installed",
                        "version": "12.15",
                    }
                ],
                "schema_version": "plamen.debian_package_state.v1",
            }
        ),
        "plamen-guest": _fragment(guest_tree),
        "cpython": _fragment(python_tree),
        "plamen": _fragment(plamen_tree),
        "codex": gzip.compress(_fragment({
            backend_members["codex"]: (0o555, backend_executables["codex"]),
        }), mtime=0),
        "claude": gzip.compress(_fragment({
            backend_members["claude"]: (0o555, backend_executables["claude"]),
        }), mtime=0),
        "foundry": _fragment(
            by_prefix("usr/local/lib/plamen/toolchains/foundry/")
        ),
        "medusa": installed["usr/local/lib/plamen/toolchains/medusa/bin/medusa"][1],
        "solc": b"\x7fELF\x02\x01\x01" + b"\0" * 64,
        "amd64-compat": _fragment(
            {
                "lib64/ld-linux-x86-64.so.2": (
                    0o555,
                    b"\x7fELF\x02\x01\x01" + b"\0" * 64,
                )
            }
        ),
    }
    definitions = (
        (
            "base", "base_rootfs",
            "application/vnd.plamen.canonical-rootfs.tar", "/",
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
            "debian-state", "debian_package_state",
            "application/vnd.plamen.debian-package-state+json",
            "/usr/local/lib/plamen/attestations/debian-packages.json",
            ["/usr/local/lib/plamen/attestations/debian-packages.json"], "linux/arm64",
        ),
        (
            "plamen-guest", "plamen_guest",
            "application/vnd.plamen.preinstalled-tree.tar", "/usr/local",
            [
                "/usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
                "/usr/local/libexec/plamen-guest",
            ],
            "linux/arm64",
        ),
        (
            "cpython", "cpython",
            "application/vnd.plamen.preinstalled-tree.tar", "/usr",
            ["/usr/bin/python3"], "linux/arm64",
        ),
        (
            "plamen", "plamen_package",
            "application/vnd.plamen.preinstalled-tree.tar", "/opt/plamen",
            ["/opt/plamen/scripts/plamen_driver.py"], "linux/noarch",
        ),
        (
            "codex", "codex", "application/vnd.plamen.authenticated-tar-member",
            "/usr/local/lib/plamen/bin/codex", ["/usr/local/lib/plamen/bin/codex"], "linux/arm64",
        ),
        (
            "claude", "claude", "application/vnd.plamen.authenticated-tar-member",
            "/usr/local/lib/plamen/bin/claude", ["/usr/local/lib/plamen/bin/claude"], "linux/arm64",
        ),
        (
            "foundry", "foundry",
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
            "medusa", "medusa", "application/vnd.plamen.executable",
            "/usr/local/lib/plamen/toolchains/medusa/bin/medusa",
            ["/usr/local/lib/plamen/toolchains/medusa/bin/medusa"], "linux/amd64",
        ),
        (
            "solc", "solc_amd64", "application/vnd.plamen.executable",
            "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
            ["/usr/local/lib/plamen/toolchains/solc-amd64/solc"], "linux/amd64",
        ),
        (
            "amd64-compat", "amd64_compat",
            "application/vnd.plamen.preinstalled-tree.tar",
            "/usr/local/lib/plamen/compat/amd64",
            ["/usr/local/lib/plamen/compat/amd64/lib64/ld-linux-x86-64.so.2"],
            "linux/amd64",
        ),
    )
    sources: list[dict[str, object]] = []
    source_manifests: dict[str, bytes] = {}
    for artifact, role, media, destination, required, target in definitions:
        required = sorted(required, key=lambda value: value.encode("utf-8"))
        source_manifest = {
            "artifact_id": artifact,
            "authentication_scope": "TEST_ONLY_EXACT_CONTENT",
            "media_type": media,
            "payload_sha256": _digest(payloads[artifact]),
            "payload_size": len(payloads[artifact]),
            "platform": target,
            "required_paths": required,
            "role": role,
            "schema_version": runtime_materializer.SOURCE_MANIFEST_SCHEMA_VERSION,
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
        source_raw = _json(source_manifest)
        source_manifests[artifact] = source_raw
        sources.append(
            {
                "artifact_id": artifact,
                "destination": destination,
                "media_type": media,
                "payload_sha256": _digest(payloads[artifact]),
                "payload_size": len(payloads[artifact]),
                "required_paths": required,
                "role": role,
                "source_manifest_sha256": _digest(source_raw),
                "source_manifest_size": len(source_raw),
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
            "entries": runtime_materializer.MAX_ENTRIES,
            "expanded_bytes": runtime_materializer.MAX_EXPANDED_BYTES,
            "input_bytes": runtime_materializer.MAX_INPUT_BYTES,
        },
        "network": "DENY",
        "schema_version": runtime_materializer.SCHEMA_VERSION,
        "sources": sources,
        "target": "linux/arm64",
    }
    manifest_raw = _json(manifest)
    work = tmp_path / "runtime-materializer"
    work.mkdir(parents=True, exist_ok=True)
    retained = []
    for number, source in enumerate(sources):
        artifact = str(source["artifact_id"])
        payload_path = work / f"{number:02d}.payload"
        source_path = work / f"{number:02d}.manifest"
        payload_path.write_bytes(payloads[artifact])
        source_path.write_bytes(source_manifests[artifact])
        retained.append(
            runtime_materializer.RetainedRuntimeInput(
                artifact,
                os.open(payload_path, os.O_RDONLY | os.O_NOFOLLOW),
                os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW),
            )
        )
    archive_path = work / "runtime.tar"
    writer = os.open(archive_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    reader = os.open(archive_path, os.O_RDONLY | os.O_NOFOLLOW)
    archive_path.unlink()
    result = runtime_materializer._TEST_ONLY_materialize_runtime_image(
        manifest_raw,
        expected_manifest_sha256=_digest(manifest_raw),
        retained_inputs=tuple(retained),
        output_writer_descriptor=writer,
        output_reader_descriptor=reader,
    )
    try:
        archive_raw = os.pread(
            result.archive_descriptor,
            os.fstat(result.archive_descriptor).st_size,
            0,
        )
        evidence = {
            "materialization/composition-manifest.json": manifest_raw,
            "materialization/runtime.tar": archive_raw,
            "materialization/receipt.json": result.receipt_bytes,
            "materialization/census.json": result.census_bytes,
            "materialization/sbom.spdx.json": result.sbom_bytes,
            "materialization/provenance.json": result.provenance_bytes,
        }
        receipt = json.loads(result.receipt_bytes)
        binding: dict[str, object] = {
            "schema_version": O.RUNTIME_MATERIALIZATION_SCHEMA_VERSION,
            "required_roles": list(O.RUNTIME_MATERIALIZATION_REQUIRED_ROLES),
            "source_roster_sha256": receipt["source_roster_sha256"],
            "composition_manifest": {
                "schema_version": runtime_materializer.SCHEMA_VERSION,
                "path": "materialization/composition-manifest.json",
                "sha256": _digest(manifest_raw), "size": len(manifest_raw),
            },
            "archive": {
                "media_type": receipt["archive"]["media_type"],
                "path": "materialization/runtime.tar",
                "sha256": receipt["archive"]["sha256"],
                "size": receipt["archive"]["size"],
                "diff_id": receipt["archive"]["diff_id"],
            },
            "receipt": {
                "path": "materialization/receipt.json",
                "sha256": _digest(result.receipt_bytes),
                "size": len(result.receipt_bytes),
            },
            "census": {
                "schema_version": runtime_materializer.CENSUS_SCHEMA_VERSION,
                "path": "materialization/census.json",
                "sha256": _digest(result.census_bytes),
                "size": len(result.census_bytes),
                "entry_count": receipt["installed"]["entry_count"],
                "expanded_bytes": receipt["installed"]["expanded_bytes"],
            },
            "sbom": {
                "format": "spdx-json-2.3",
                "path": "materialization/sbom.spdx.json",
                "sha256": _digest(result.sbom_bytes),
                "size": len(result.sbom_bytes),
            },
            "provenance": {
                "schema_version": runtime_materializer.PROVENANCE_SCHEMA_VERSION,
                "path": "materialization/provenance.json",
                "sha256": _digest(result.provenance_bytes),
                "size": len(result.provenance_bytes),
            },
        }
        materialized_installed: dict[str, tuple[int, bytes]] = {}
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:") as archive:
            for member in archive:
                if member.isfile():
                    stream = archive.extractfile(member)
                    assert stream is not None
                    materialized_installed[member.name] = (
                        member.mode,
                        stream.read(),
                    )
        return evidence, binding, materialized_installed
    finally:
        os.close(result.archive_descriptor)


def _runtime_payloads() -> tuple[dict[str, bytes], dict[str, tuple[int, bytes]]]:
    installed: dict[str, tuple[int, bytes]] = {
        "etc/group": (0o444, b"plamen:x:65532:\n"),
        "etc/passwd": (0o444, b"plamen:x:65532:65532:Plamen:/nonexistent:/sbin/nologin\n"),
        "lib/ld-linux-aarch64.so.1": (0o555, _aarch64_elf(b"loader\n")),
        "lib/aarch64-linux-gnu/libc.so.6": (0o555, _aarch64_elf(b"libc\n")),
        "lib/aarch64-linux-gnu/libdl.so.2": (0o555, _aarch64_elf(b"libdl\n")),
        "lib/aarch64-linux-gnu/libm.so.6": (0o555, _aarch64_elf(b"libm\n")),
        "lib/aarch64-linux-gnu/libpthread.so.0": (
            0o555,
            _aarch64_elf(b"libpthread\n"),
        ),
        "lib/aarch64-linux-gnu/librt.so.1": (0o555, _aarch64_elf(b"librt\n")),
        "bin/sh": (0o555, _aarch64_elf(b"shell\n")),
        "usr/bin/env": (0o555, _aarch64_elf(b"env\n")),
        "usr/local/libexec/plamen-guest": (
            0o555,
            _aarch64_elf(b"native-guest-bootstrap\n"),
        ),
        "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so": (
            0o555,
            _aarch64_elf(b"native-supervisor-extension\n"),
        ),
        "opt/plamen/scripts/plamen_driver.py": (0o444, b"def main():\n    return 0\n"),
        "usr/bin/python3": (0o555, b"#!/bin/sh\nexit 0\n"),
        "usr/lib/python3.12/site.py": (0o444, b"# pinned stdlib\n"),
        "usr/local/lib/plamen/toolchains/foundry/bin/forge": (0o555, b"#!/bin/sh\nexit 0\n"),
        "usr/local/lib/plamen/toolchains/foundry/bin/cast": (0o555, b"#!/bin/sh\nexit 0\n"),
        "usr/local/lib/plamen/toolchains/foundry/bin/anvil": (0o555, b"#!/bin/sh\nexit 0\n"),
        "usr/local/lib/plamen/toolchains/foundry/bin/chisel": (0o555, b"#!/bin/sh\nexit 0\n"),
        "usr/local/lib/plamen/toolchains/medusa/bin/medusa": (
            0o555,
            b"\x7fELF\x02\x01\x01" + b"\0" * 64,
        ),
    }
    installed.update(
        {
            f"usr/share/plamen-rootfs/file-{index:03d}": (
                0o444,
                f"{index}\n".encode(),
            )
            for index in range(100)
        }
    )
    complete_rootfs_paths = {
        key: value
        for key, value in installed.items()
        if key.startswith(("bin/", "etc/", "lib/", "usr/"))
        and key not in {
            "usr/bin/python3",
            "usr/local/libexec/plamen-guest",
            "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
        }
        and not key.startswith(
            (
                "usr/lib/python3.12/",
                "usr/local/lib/plamen/",
                "usr/local/share/plamen/",
            )
        )
    }
    closure_paths = {
        key: value
        for key, value in installed.items()
        if key
        in {
            "opt/plamen/scripts/plamen_driver.py",
            "usr/local/libexec/plamen-guest",
            "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
        }
    }
    python_paths = {
        "python/" + key.removeprefix("usr/"): value
        for key, value in installed.items()
        if key == "usr/bin/python3" or key.startswith("usr/lib/python3.12/")
    }
    foundry_paths = {
        key.rsplit("/", 1)[1]: value
        for key, value in installed.items()
        if key.startswith("usr/local/lib/plamen/toolchains/foundry/bin/")
    }
    payloads = {
        "artifacts/python.tar": _fragment(python_paths),
        "backends/claude": _aarch64_elf(b"claude"),
        "backends/codex": _aarch64_elf(b"codex"),
        "runtime/closure.json": _fragment(closure_paths),
        "runtime/complete-rootfs.tar.gz": _fragment(complete_rootfs_paths),
        "toolchains/foundry.tar": _fragment(foundry_paths),
    }
    rootfs_raw = payloads["runtime/complete-rootfs.tar.gz"]
    base_config = _json(
        {
            "architecture": "arm64",
            "config": {
                "Cmd": ["bash"],
                "Entrypoint": [],
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ],
            },
            "created": "2026-08-24T00:00:00Z",
            "history": [
                {
                    "comment": "debuerreotype 0.17",
                    "created": "2026-08-24T00:00:00Z",
                    "created_by": (
                        "# debian.sh --arch 'arm64' out/ 'bookworm' '@1787529600'"
                    ),
                }
            ],
            "os": "linux",
            "rootfs": {
                "diff_ids": ["sha256:" + _digest(rootfs_raw)],
                "type": "layers",
            },
            "variant": "v8",
        }
    )
    payloads["runtime/complete-rootfs-config.json"] = base_config
    base_manifest = _json(
        {
            "config": {
                "data": base64.b64encode(base_config).decode("ascii"),
                "digest": "sha256:" + _digest(base_config),
                "mediaType": L.OCI_CONFIG_MEDIA_TYPE,
                "size": len(base_config),
            },
            "layers": [
                {
                    "digest": "sha256:" + _digest(rootfs_raw),
                    "mediaType": L.OCI_LAYER_MEDIA_TYPE,
                    "size": len(rootfs_raw),
                }
            ],
            "mediaType": L.OCI_MANIFEST_MEDIA_TYPE,
            "schemaVersion": 2,
        }
    )
    payloads["runtime/complete-rootfs-manifest.json"] = base_manifest
    revision = "f73bd086e8d0e5e1c8b838ccc442bf24eb3ea205"
    base_index = _json(
        {
            "manifests": [
                {
                    "annotations": {
                        "com.docker.official-images.bashbrew.arch": "arm64v8",
                        "org.opencontainers.image.base.name": "scratch",
                        "org.opencontainers.image.created": "2026-08-24T00:00:00Z",
                        "org.opencontainers.image.revision": revision,
                        "org.opencontainers.image.source": (
                            "https://github.com/debuerreotype/docker-debian-artifacts.git"
                        ),
                        "org.opencontainers.image.url": (
                            "https://hub.docker.com/_/debian"
                        ),
                        "org.opencontainers.image.version": "bookworm-slim",
                    },
                    "digest": "sha256:" + _digest(base_manifest),
                    "mediaType": L.OCI_MANIFEST_MEDIA_TYPE,
                    "platform": {
                        "architecture": "arm64",
                        "os": "linux",
                        "variant": "v8",
                    },
                    "size": len(base_manifest),
                }
            ],
            "mediaType": L.OCI_INDEX_MEDIA_TYPE,
            "schemaVersion": 2,
        }
    )
    payloads["runtime/complete-rootfs-index.json"] = base_index
    official_images = (
        "GitRepo: https://github.com/debuerreotype/docker-debian-artifacts.git\n"
        f"arm64v8-GitCommit: {revision}\n"
        "Tags: bookworm-slim, bookworm-20260824-slim, 12.15-slim, 12-slim\n"
        "Architectures: amd64, arm32v7, arm64v8, i386, ppc64le\n"
        "Builder: oci-import\n"
        "Directory: bookworm/slim/oci\n"
        "File: index.json\n"
    ).encode()
    payloads["runtime/complete-rootfs-official-images.txt"] = official_images
    payloads["runtime/complete-rootfs-provenance.json"] = _json(
        {
            "authentication_scope": "TEST_ONLY_NO_RELEASE_AUTHORITY",
            "config_digest": "sha256:" + _digest(base_config),
            "config_size": len(base_config),
            "index_digest": "sha256:" + _digest(base_index),
            "index_size": len(base_index),
            "layer_digest": "sha256:"
            + _digest(rootfs_raw),
            "layer_diff_id": "sha256:" + _digest(rootfs_raw),
            "layer_size": len(rootfs_raw),
            "manifest_digest": "sha256:" + _digest(base_manifest),
            "manifest_size": len(base_manifest),
            "official_images_commit": (
                "b9c995a1c91bf8b195b035893ebdf8e877e7f7fa"
            ),
            "official_images_sha256": _digest(official_images),
            "platform": "linux/arm64/v8",
            "schema_version": "plamen.complete_rootfs_provenance.v1",
            "source_reference": "docker.io/library/debian:bookworm-20260824-slim@sha256:"
            + _digest(base_index),
        }
    )
    installed["usr/local/lib/plamen/bin/claude"] = (0o555, payloads["backends/claude"])
    installed["usr/local/lib/plamen/bin/codex"] = (0o555, payloads["backends/codex"])
    return payloads, installed


def _runtime_bindings(lock: dict) -> list[dict]:
    runtime = lock["runtime"]
    result = [
        {
            "artifact_id": "cpython",
            "path": runtime["cpython"]["path"],
            "role": "cpython",
            "sha256": runtime["cpython"]["sha256"],
            "version": runtime["cpython"]["version"],
        }
    ]
    result.extend(
        {
            "artifact_id": row["backend"],
            "path": row["path"],
            "role": "backend_cli",
            "sha256": row["sha256"],
            "version": row["version"],
        }
        for row in runtime["backend_clis"]
    )
    result.extend(
        {
            "artifact_id": row["toolchain_id"],
            "path": row["path"],
            "role": "toolchain",
            "sha256": row["sha256"],
            "version": row["version"],
        }
        for row in runtime["toolchains"]
    )
    result.extend(
        {
            "artifact_id": row["asset_id"],
            "path": row["path"],
            "role": "asset",
            "sha256": row["sha256"],
            "version": None,
        }
        for row in runtime["assets"]
    )
    derivation = lock["rootfs_derivation"]
    result.append(
        {
            "artifact_id": "cache-free-rootfs-derivation",
            "path": "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json",
            "role": "generated_attestation",
            "sha256": derivation["manifest_sha256"],
            "version": derivation["recipe_version"],
        }
    )
    return sorted(result, key=lambda row: (row["role"], row["artifact_id"]))


def _refresh_attestations(unsigned: dict, payloads: dict[str, bytes]) -> None:
    bindings = _runtime_bindings(unsigned)
    payloads["attestations/sbom.spdx.json"] = _json(
        {
            "packages": [
                {
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": row["sha256"]}
                    ],
                    "name": f"{row['role']}:{row['artifact_id']}",
                    "versionInfo": row["version"] or "content-addressed",
                }
                for row in bindings
            ],
            "spdxVersion": "SPDX-2.3",
        }
    )
    payloads["attestations/census.json"] = _json(
        {"artifacts": bindings, "schema_version": O.RUNTIME_CENSUS_SCHEMA_VERSION}
    )
    unsigned["attestations"]["sbom"]["sha256"] = _digest(
        payloads["attestations/sbom.spdx.json"]
    )
    unsigned["attestations"]["census"]["sha256"] = _digest(
        payloads["attestations/census.json"]
    )


def _oracle_layer(installed: dict[str, tuple[int, bytes]]) -> tuple[bytes, str, str]:
    tar_raw = io.BytesIO()
    directories: set[str] = set()
    for path in installed:
        parts = path.split("/")
        directories.update("/".join(parts[:end]) for end in range(1, len(parts)))
    with tarfile.open(fileobj=tar_raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(directories, key=lambda item: (item.casefold(), item)):
            member = tarfile.TarInfo(path + "/")
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ""
            archive.addfile(member)
        for path, (mode, raw) in sorted(
            installed.items(), key=lambda item: (item[0].casefold(), item[0])
        ):
            member = tarfile.TarInfo(path)
            member.type = tarfile.REGTYPE
            member.mode = mode
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ""
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    uncompressed = tar_raw.getvalue()
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = compressor.compress(uncompressed) + compressor.flush(zlib.Z_FINISH)
    compressed = (
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
        + body
        + struct.pack("<II", zlib.crc32(uncompressed), len(uncompressed) & 0xFFFFFFFF)
    )
    return compressed, "sha256:" + _digest(compressed), "sha256:" + _digest(uncompressed)


def _oracle_image_digests(
    unsigned: dict, installed: dict[str, tuple[int, bytes]]
) -> tuple[str, str, str, str]:
    layer, layer_digest, diff_id = _oracle_layer(installed)
    input_census = _digest(_json(unsigned["build_inputs"]))
    runtime_rows = [
        {
            "kind": "file",
            "linkname": "",
            "mode": f"0{mode:03o}",
            "path": path,
            "sha256": _digest(raw),
            "size": len(raw),
        }
        for path, (mode, raw) in sorted(
            installed.items(), key=lambda item: (item[0].casefold(), item[0])
        )
    ]
    assets = {row["asset_id"]: row for row in unsigned["runtime"]["assets"]}
    dependency_edges = [
        {
            "from": "usr/bin/python3",
            "kind": "interpreter",
            "name": "/bin/sh",
            "resolved": "bin/sh",
        },
        *(
            {
                "from": f"usr/local/lib/plamen/toolchains/foundry/bin/{name}",
                "kind": "interpreter",
                "name": "/bin/sh",
                "resolved": "bin/sh",
            }
            for name in ("anvil", "cast", "chisel", "forge")
        ),
    ]
    dependency_census = _json(
        {
            "edges": sorted(
                dependency_edges,
                key=lambda row: (
                    row["from"],
                    row["kind"],
                    row["name"],
                    row["resolved"],
                ),
            ),
            "roots": [
                "usr/local/libexec/plamen-guest",
                "usr/bin/python3",
                "usr/local/lib/plamen/bin/claude",
                "usr/local/lib/plamen/bin/codex",
                "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
                "usr/local/lib/plamen/toolchains/foundry/bin/anvil",
                "usr/local/lib/plamen/toolchains/foundry/bin/cast",
                "usr/local/lib/plamen/toolchains/foundry/bin/chisel",
                "usr/local/lib/plamen/toolchains/foundry/bin/forge",
            ],
            "schema_version": "plamen.runtime_dependency_census.v1",
        }
    )
    labels = {
        "org.plamen.build-input-census.sha256": input_census,
        "org.plamen.complete-rootfs.provenance.sha256": assets[
            "complete-rootfs-provenance"
        ]["sha256"],
        "org.plamen.complete-rootfs.derivation-manifest.sha256": unsigned[
            "rootfs_derivation"
        ]["manifest_sha256"],
        "org.plamen.complete-rootfs.derived-census.sha256": unsigned[
            "rootfs_derivation"
        ]["derived_census_sha256"],
        "org.plamen.complete-rootfs.derived-diff-id": unsigned[
            "rootfs_derivation"
        ]["derived_diff_id"],
        "org.plamen.complete-rootfs.derived.sha256": unsigned[
            "rootfs_derivation"
        ]["derived_sha256"],
        "org.plamen.complete-rootfs.source.sha256": assets["complete-rootfs"][
            "sha256"
        ],
        "org.plamen.empty-root.lock-reference": unsigned["image"]["base_reference"],
        "org.plamen.runtime-census.sha256": unsigned["attestations"]["census"]["sha256"],
        "org.plamen.runtime-dependencies.sha256": _digest(dependency_census),
        "org.plamen.runtime-files.sha256": _digest(_json(runtime_rows)),
        "org.plamen.runtime-materialization.archive.diff-id": unsigned[
            "runtime_materialization"
        ]["archive"]["diff_id"],
        "org.plamen.runtime-materialization.archive.sha256": unsigned[
            "runtime_materialization"
        ]["archive"]["sha256"],
        "org.plamen.runtime-materialization.archive.size": str(
            unsigned["runtime_materialization"]["archive"]["size"]
        ),
        "org.plamen.runtime-materialization.composition-manifest.sha256": unsigned[
            "runtime_materialization"
        ]["composition_manifest"]["sha256"],
        "org.plamen.runtime-materialization.entry-count": str(
            unsigned["runtime_materialization"]["census"]["entry_count"]
        ),
        "org.plamen.runtime-materialization.expanded-bytes": str(
            unsigned["runtime_materialization"]["census"]["expanded_bytes"]
        ),
        "org.plamen.runtime-materialization.installed-census.sha256": unsigned[
            "runtime_materialization"
        ]["census"]["sha256"],
        "org.plamen.runtime-materialization.provenance.sha256": unsigned[
            "runtime_materialization"
        ]["provenance"]["sha256"],
        "org.plamen.runtime-materialization.receipt.sha256": unsigned[
            "runtime_materialization"
        ]["receipt"]["sha256"],
        "org.plamen.runtime-materialization.sbom.sha256": unsigned[
            "runtime_materialization"
        ]["sbom"]["sha256"],
        "org.plamen.runtime-materialization.source-roster.sha256": unsigned[
            "runtime_materialization"
        ]["source_roster_sha256"],
        "org.plamen.sbom.sha256": unsigned["attestations"]["sbom"]["sha256"],
    }
    config = {
        "architecture": "arm64",
        "config": {
            "Entrypoint": ["/usr/local/libexec/plamen-guest"],
            "Env": [
                "FOUNDRY_OFFLINE=true",
                "PATH=/usr/local/lib/plamen/bin:/usr/local/lib/plamen/toolchains/foundry/bin:/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONNOUSERSITE=1",
            ],
            "Labels": labels,
            "User": "65532:65532",
            "WorkingDir": "/workspace/project",
        },
        "created": "1970-01-01T00:00:00Z",
        "history": [
            {
                "comment": "complete scratch-root audit runtime from authenticated closure",
                "created": "1970-01-01T00:00:00Z",
                "created_by": "plamen deterministic offline runtime assembler v1",
                "empty_layer": False,
            }
        ],
        "os": "linux",
        "rootfs": {"diff_ids": [diff_id], "type": "layers"},
    }
    config_raw = _json(config)
    config_digest = "sha256:" + _digest(config_raw)
    manifest = {
        "config": {
            "digest": config_digest,
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(config_raw),
        },
        "layers": [
            {
                "digest": layer_digest,
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": len(layer),
            }
        ],
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
    }
    manifest_raw = _json(manifest)
    manifest_digest = "sha256:" + _digest(manifest_raw)
    index = {
        "manifests": [
            {
                "digest": manifest_digest,
                "mediaType": L.OCI_MANIFEST_MEDIA_TYPE,
                "platform": {"architecture": "arm64", "os": "linux"},
                "size": len(manifest_raw),
            }
        ],
        "mediaType": L.OCI_INDEX_MEDIA_TYPE,
        "schemaVersion": 2,
    }
    return (
        manifest_digest,
        "sha256:" + _digest(_json(index)),
        config_digest,
        _digest(config_raw[:-1]),
    )


def _oracle_manifest(unsigned: dict, installed: dict[str, tuple[int, bytes]]) -> str:
    return _oracle_image_digests(unsigned, installed)[0]


def _fixture(
    tmp_path: Path, *, base_registry: str = "scratch.plamen.invalid"
) -> tuple[Path, dict, dict[str, tuple[int, bytes]]]:
    root, original = lock_tests._fixture(tmp_path)
    unsigned = copy.deepcopy(original)
    unsigned.pop("lock_sha256")
    payloads, installed = _runtime_payloads()
    runtime = unsigned["runtime"]
    runtime["assets"].extend(
        [
            {
                "asset_id": "complete-rootfs",
                "path": "runtime/complete-rootfs.tar.gz",
                "sha256": _digest(payloads["runtime/complete-rootfs.tar.gz"]),
            },
            {
                "asset_id": "complete-rootfs-provenance",
                "path": "runtime/complete-rootfs-provenance.json",
                "sha256": _digest(
                    payloads["runtime/complete-rootfs-provenance.json"]
                ),
            },
            {
                "asset_id": "complete-rootfs-config",
                "path": "runtime/complete-rootfs-config.json",
                "sha256": _digest(payloads["runtime/complete-rootfs-config.json"]),
            },
            {
                "asset_id": "complete-rootfs-index",
                "path": "runtime/complete-rootfs-index.json",
                "sha256": _digest(payloads["runtime/complete-rootfs-index.json"]),
            },
            {
                "asset_id": "complete-rootfs-manifest",
                "path": "runtime/complete-rootfs-manifest.json",
                "sha256": _digest(payloads["runtime/complete-rootfs-manifest.json"]),
            },
            {
                "asset_id": "complete-rootfs-official-images",
                "path": "runtime/complete-rootfs-official-images.txt",
                "sha256": _digest(
                    payloads["runtime/complete-rootfs-official-images.txt"]
                ),
            },
        ]
    )
    runtime["assets"].sort(key=lambda row: row["asset_id"])
    source_rows = [
        runtime["cpython"],
        *runtime["backend_clis"],
        *runtime["toolchains"],
        *runtime["assets"],
    ]
    for row in source_rows:
        row["sha256"] = _digest(payloads[row["path"]])
    rootfs_raw = payloads["runtime/complete-rootfs.tar.gz"]
    rootfs_rows = [
        {
            "kind": "file",
            "linkname": "",
            "mode": f"0{mode:03o}",
            "path": path,
            "sha256": _digest(raw),
            "size": len(raw),
        }
        for path, (mode, raw) in sorted(
            (
                (path, value)
                for path, value in installed.items()
                if path.startswith(("bin/", "etc/", "lib/", "usr/"))
                and path
                not in {
                    "usr/bin/python3",
                    "usr/local/libexec/plamen-guest",
                    "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
                }
                and not path.startswith(
                    (
                        "usr/lib/python3.12/",
                        "usr/local/lib/plamen/",
                        "usr/local/share/plamen/",
                    )
                )
            ),
            key=lambda item: (item[0].casefold(), item[0]),
        )
    ]
    source_sha256 = _digest(rootfs_raw)
    derivation = {
        "schema_version": O.ROOTFS_DERIVATION_BINDING_SCHEMA_VERSION,
        "derivation_schema_version": (
            "plamen.cache_free_rootfs_derivation.test.v1"
        ),
        "recipe_version": O.TEST_ONLY_ROOTFS_DERIVATION_RECIPE,
        "authentication_scope": "TEST_ONLY_NO_RELEASE_AUTHORITY",
        "production_authority": False,
        "source_asset_id": "complete-rootfs",
        "source_reference": "TEST_ONLY_SYNTHETIC_CACHE_FREE_ROOT",
        "source_sha256": source_sha256,
        "source_size": len(rootfs_raw),
        "source_diff_id": "sha256:" + source_sha256,
        "derived_sha256": source_sha256,
        "derived_size": len(rootfs_raw),
        "derived_diff_id": "sha256:" + source_sha256,
        "derived_tar_size": len(rootfs_raw),
        "derived_census_sha256": _digest(_json(rootfs_rows)),
        "derived_entry_count": len(rootfs_rows),
        "manifest_sha256": "0" * 64,
        "removed_cache_path": "/etc/ld.so.cache",
        "removed_cache_sha256": "0" * 64,
        "removed_cache_size": 0,
        "forbidden_environment": {
            "exact_names": ["GLIBC_TUNABLES"],
            "prefixes": ["LD_"],
        },
    }
    derivation["manifest_sha256"] = _digest(
        O._TEST_ONLY_rootfs_derivation_manifest_bytes(derivation)
    )
    unsigned["rootfs_derivation"] = derivation
    _refresh_attestations(unsigned, payloads)
    for path, raw in payloads.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o644)
    unsigned["build_inputs"] = [
        {
            "mode": "0644",
            "path": path,
            "sha256": _digest(raw),
            "size": len(raw),
        }
        for path, raw in sorted(
            payloads.items(), key=lambda item: (item[0].casefold(), item[0])
        )
    ]
    installed["usr/local/lib/plamen/attestations/sbom.json"] = (
        0o444,
        payloads["attestations/sbom.spdx.json"],
    )
    installed["usr/local/lib/plamen/attestations/census.json"] = (
        0o444,
        payloads["attestations/census.json"],
    )
    installed["usr/local/lib/plamen/attestations/complete-rootfs-provenance.json"] = (
        0o444,
        payloads["runtime/complete-rootfs-provenance.json"],
    )
    installed[
        "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json"
    ] = (0o444, O._TEST_ONLY_rootfs_derivation_manifest_bytes(derivation))
    materialization_payloads, materialization_binding, installed = (
        _materialize_runtime_fixture(tmp_path, installed)
    )
    installed.update(
        {
            "usr/local/lib/plamen/attestations/sbom.json": (
                0o444,
                payloads["attestations/sbom.spdx.json"],
            ),
            "usr/local/lib/plamen/attestations/census.json": (
                0o444,
                payloads["attestations/census.json"],
            ),
            "usr/local/lib/plamen/attestations/complete-rootfs-provenance.json": (
                0o444,
                payloads["runtime/complete-rootfs-provenance.json"],
            ),
            "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json": (
                0o444,
                O._TEST_ONLY_rootfs_derivation_manifest_bytes(derivation),
            ),
        }
    )
    unsigned["runtime_materialization"] = materialization_binding
    payloads.update(materialization_payloads)
    for path, raw in materialization_payloads.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o644)
    unsigned["build_inputs"] = [
        {
            "mode": "0644",
            "path": path,
            "sha256": _digest(raw),
            "size": len(raw),
        }
        for path, raw in sorted(
            payloads.items(), key=lambda item: (item[0].casefold(), item[0])
        )
    ]
    unsigned["image"]["base_reference"] = (
        f"{base_registry}/empty-root@{L.EMPTY_ROOT_DIGEST}"
    )
    unsigned["image"]["base_manifest_digest"] = L.EMPTY_ROOT_DIGEST
    manifest, index, config, apple_configuration = _oracle_image_digests(
        unsigned, installed
    )
    unsigned["image"]["manifest_digest"] = manifest
    unsigned["image"]["index_digest"] = index
    unsigned["image"]["config_digest"] = config
    unsigned["image"][
        "apple_container_configuration_sha256"
    ] = apple_configuration
    unsigned["image"]["reference"] = f"ghcr.io/plamen/audit-runtime@{index}"
    return root, O.seal_image_lock(unsigned), installed


def _plan(root: Path, lock: dict, nonce: str = "c" * 64):
    return lock_tests._render(lock, root, nonce=nonce)


def _ack(receipt: bytes) -> bytes:
    return _json(
        {
            "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
            "schema_version": L.LAYOUT_ACK_SCHEMA_VERSION,
            "status": "ACCEPTED",
        }
    )


def _build(tmp_path: Path, leaf: str = "layout"):
    root, lock, installed = _fixture(tmp_path)
    output = tmp_path / leaf
    result = L._build_oci_layout_for_testing(
        _plan(root, lock),
        output.resolve(),
        authenticated_external_fake_acknowledger=_ack,
    )
    return root, lock, installed, output, result


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _rendered_image_digests(
    plan: O.OCIValidatedBuildPlan,
) -> tuple[str, str, str, str]:
    """Render through the retained-reader path without publishing a layout."""

    rows = L._validate_plan_shape(plan)

    def consume(readers) -> tuple[str, str]:
        entries = []
        payload_spool = None
        try:
            (
                entries,
                runtime_files_sha256,
                dependency_census_sha256,
                _derivation_evidence,
                payload_spool,
            ) = L._expand_runtime_closure(plan, rows, readers)
            with tempfile.TemporaryFile(mode="w+b") as output:
                layer = L._write_layer(output, entries)
            documents = L._image_documents(
                layer,
                plan,
                runtime_files_sha256,
                dependency_census_sha256,
            )
            return documents[4], documents[5], documents[3], documents[6]
        finally:
            for entry in entries:
                if entry.source is not None:
                    entry.source.close()
            if payload_spool is not None:
                payload_spool.close()

    return plan.consume_build_context_for_testing(consume)


def _snapshot(root: Path) -> dict[str, tuple[int, bytes]]:
    result: dict[str, tuple[int, bytes]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result[path.relative_to(root).as_posix()] = (
                stat.S_IMODE(path.stat().st_mode),
                path.read_bytes(),
            )
    return result


def test_independent_golden_vector_and_complete_runtime_config(tmp_path: Path) -> None:
    root, lock, installed, output, result = _build(tmp_path)
    unsigned = {key: value for key, value in lock.items() if key != "lock_sha256"}
    (
        oracle_manifest,
        oracle_index,
        oracle_config,
        oracle_apple_configuration,
    ) = _oracle_image_digests(unsigned, installed)
    assert oracle_manifest == _GOLDEN_MANIFEST
    assert result.manifest_digest == _GOLDEN_MANIFEST == lock["image"]["manifest_digest"]
    assert result.index_digest == oracle_index == lock["image"]["index_digest"]
    assert result.config_digest == oracle_config == lock["image"]["config_digest"]
    assert (
        result.apple_container_configuration_sha256
        == oracle_apple_configuration
        == lock["image"]["apple_container_configuration_sha256"]
    )
    assert lock["image"]["reference"].endswith("@" + oracle_index)
    receipt = json.loads(result.receipt)
    assert receipt["index_digest"] == result.index_digest
    assert receipt["manifest_digest"] == result.manifest_digest
    assert (
        receipt["apple_container_configuration_sha256"]
        == result.apple_container_configuration_sha256
    )
    materialization = lock["runtime_materialization"]
    assert result.runtime_materialization_archive_sha256 == materialization["archive"]["sha256"]
    assert result.runtime_materialization_archive_diff_id == materialization["archive"]["diff_id"]
    assert result.installed_runtime_census_sha256 == materialization["census"]["sha256"]
    assert result.runtime_materialization_sbom_sha256 == materialization["sbom"]["sha256"]
    assert result.runtime_materialization_provenance_sha256 == materialization["provenance"]["sha256"]
    assert receipt["runtime_materialization"]["installed_census_sha256"] == result.installed_runtime_census_sha256
    observed = L._verify_oci_layout_for_testing(
        output.resolve(),
        expected_index_digest=result.index_digest,
        expected_manifest_digest=result.manifest_digest,
        expected_config_digest=result.config_digest,
        expected_apple_container_configuration_sha256=(
            result.apple_container_configuration_sha256
        ),
        expected_layer_digest=result.layer_digest,
        expected_layer_diff_id=result.layer_diff_id,
        expected_runtime_files_sha256=result.runtime_files_sha256,
        expected_sbom_sha256=result.sbom_sha256,
        expected_runtime_census_sha256=result.runtime_census_sha256,
        expected_runtime_dependency_census_sha256=(
            result.runtime_dependency_census_sha256
        ),
        expected_empty_root_reference=result.empty_root_reference,
        expected_complete_rootfs_source_sha256=(
            result.complete_rootfs_source_sha256
        ),
        expected_complete_rootfs_provenance_sha256=(
            result.complete_rootfs_provenance_sha256
        ),
    )
    assert observed.manifest_digest == result.manifest_digest
    assert observed.index_digest == result.index_digest
    assert observed.runtime_files_sha256 == result.runtime_files_sha256
    with pytest.raises(L.DeterministicOCILayoutError, match="index digest"):
        L._verify_oci_layout_for_testing(
            output.resolve(),
            expected_index_digest="sha256:" + "d" * 64,
            expected_manifest_digest=result.manifest_digest,
        )
    layer = output / "blobs" / "sha256" / result.layer_digest.removeprefix("sha256:")
    with tarfile.open(layer, "r:gz") as archive:
        names = {member.name.rstrip("/") for member in archive}
    assert set(installed).issubset(names)
    assert "artifacts/python.tar" not in names
    assert "toolchains/foundry.tar" not in names
    assert "runtime/closure.json" not in names
    assert root.exists()


def test_reproducible_bytes_and_base_alias_changes_manifest(tmp_path: Path) -> None:
    first_root, first_lock, _installed = _fixture(tmp_path / "a")
    second_root, second_lock, _ = _fixture(tmp_path / "b")
    first = tmp_path / "first"
    second = tmp_path / "second"
    one = L._build_oci_layout_for_testing(
        _plan(first_root, first_lock, "a" * 64),
        first.resolve(),
        authenticated_external_fake_acknowledger=_ack,
    )
    two = L._build_oci_layout_for_testing(
        _plan(second_root, second_lock, "b" * 64),
        second.resolve(),
        authenticated_external_fake_acknowledger=_ack,
    )
    assert _snapshot(first) == _snapshot(second)
    assert one.index_digest == two.index_digest
    assert one.manifest_digest == two.manifest_digest

    alias_root, alias_lock, _ = _fixture(
        tmp_path / "alias", base_registry="mirror.plamen.invalid"
    )
    alias_output = tmp_path / "alias-layout"
    alias_result = L._build_oci_layout_for_testing(
        _plan(alias_root, alias_lock),
        alias_output.resolve(),
        authenticated_external_fake_acknowledger=_ack,
    )
    assert alias_result.index_digest != one.index_digest
    assert alias_result.manifest_digest != one.manifest_digest
    assert _snapshot(alias_output) != _snapshot(first)


@pytest.mark.parametrize(
    "reference",
    [
        "docker.io/library/debian@sha256:" + "b" * 64,
        "scratch.plamen.invalid/empty-root@sha256:" + "b" * 64,
    ],
)
def test_non_scratch_parent_or_changed_sentinel_digest_is_rejected(
    tmp_path: Path, reference: str
) -> None:
    root, lock, _ = _fixture(tmp_path)
    plan = dict(_plan(root, lock))
    plan["base_image_reference"] = reference
    body = dict(plan)
    body.pop("plan_sha256")
    plan["plan_sha256"] = _digest(_json(body))
    with pytest.raises(L.DeterministicOCILayoutError, match="empty-root sentinel"):
        L._validate_plan_shape(plan)


def test_build_plan_keeps_index_and_selected_manifest_authority_distinct(
    tmp_path: Path,
) -> None:
    root, lock, _ = _fixture(tmp_path)
    plan = dict(_plan(root, lock))
    plan["expected_manifest_digest"] = plan["expected_index_digest"]
    body = dict(plan)
    body.pop("plan_sha256")
    plan["plan_sha256"] = _digest(_json(body))
    with pytest.raises(L.DeterministicOCILayoutError, match="must be distinct"):
        L._validate_plan_shape(plan)


def test_missing_complete_rootfs_input_has_typed_hardstop(tmp_path: Path) -> None:
    root, lock, _ = _fixture(tmp_path)
    retained = _plan(root, lock)
    plan = copy.deepcopy(dict(retained))
    retained._authority.close()
    plan["runtime"]["assets"] = [
        row
        for row in plan["runtime"]["assets"]
        if row["asset_id"] != "complete-rootfs"
    ]
    with pytest.raises(
        L.DeterministicOCILayoutError,
        match="COMPLETE_ROOTFS_ARCHIVE_REQUIRED",
    ):
        L._runtime_input_roles(plan, ())


def test_rootfs_provenance_must_bind_exact_archive_and_test_scope(
    tmp_path: Path,
) -> None:
    root, lock, _ = _fixture(tmp_path)
    retained = _plan(root, lock)
    plan = copy.deepcopy(dict(retained))
    retained._authority.close()
    provenance = json.loads(
        (root / "runtime/complete-rootfs-provenance.json").read_bytes()
    )
    evidence = {
        asset_id: (root / path).read_bytes()
        for asset_id, path in {
            "complete-rootfs-config": "runtime/complete-rootfs-config.json",
            "complete-rootfs-index": "runtime/complete-rootfs-index.json",
            "complete-rootfs-manifest": "runtime/complete-rootfs-manifest.json",
            "complete-rootfs-official-images": (
                "runtime/complete-rootfs-official-images.txt"
            ),
        }.items()
    }
    diff_id = provenance["layer_diff_id"]

    wrong_layer = copy.deepcopy(provenance)
    wrong_layer["layer_digest"] = "sha256:" + "f" * 64
    with pytest.raises(L.DeterministicOCILayoutError, match="does not bind"):
        L._validate_complete_rootfs_provenance(
            _json(wrong_layer), plan, evidence, diff_id
        )

    wrong_scope = copy.deepcopy(provenance)
    wrong_scope["authentication_scope"] = "REGISTRY_TLS_EXACT_DIGESTS"
    with pytest.raises(L.DeterministicOCILayoutError, match="scope"):
        L._validate_complete_rootfs_provenance(
            _json(wrong_scope), plan, evidence, diff_id
        )

    forged_production_plan = copy.deepcopy(plan)
    forged_production_plan["authentication_scope"] = "EXACT_RELEASE_AUTHORITY"
    with pytest.raises(
        L.DeterministicOCILayoutError, match="exact locked Debian"
    ):
        L._validate_complete_rootfs_provenance(
            _json(wrong_scope), forged_production_plan, evidence, diff_id
        )

    ambiguous_evidence = dict(evidence)
    ambiguous_index = json.loads(ambiguous_evidence["complete-rootfs-index"])
    ambiguous_index["manifests"].append(copy.deepcopy(ambiguous_index["manifests"][0]))
    ambiguous_evidence["complete-rootfs-index"] = _json(ambiguous_index)
    ambiguous_plan = copy.deepcopy(plan)
    ambiguous_digest = _digest(ambiguous_evidence["complete-rootfs-index"])
    for row in ambiguous_plan["runtime"]["assets"]:
        if row["asset_id"] == "complete-rootfs-index":
            row["sha256"] = ambiguous_digest
            index_path = row["path"]
            break
    for row in ambiguous_plan["build_inputs"]:
        if row["path"] == index_path:
            row["sha256"] = ambiguous_digest
            row["size"] = len(ambiguous_evidence["complete-rootfs-index"])
            break
    ambiguous_provenance = copy.deepcopy(provenance)
    ambiguous_provenance["index_digest"] = "sha256:" + ambiguous_digest
    ambiguous_provenance["index_size"] = len(
        ambiguous_evidence["complete-rootfs-index"]
    )
    ambiguous_provenance["source_reference"] = (
        "docker.io/library/debian:bookworm-20260824-slim@sha256:"
        + ambiguous_digest
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="exactly one"):
        L._validate_complete_rootfs_provenance(
            _json(ambiguous_provenance),
            ambiguous_plan,
            ambiguous_evidence,
            diff_id,
        )


def test_real_staged_debian_oci_graph_when_available() -> None:
    staged = Path("/private/tmp/plamen-runtime-inputs")
    evidence_paths = {
        "complete-rootfs-config": staged / "debian-bookworm-slim-arm64-config.json",
        "complete-rootfs-index": staged / "debian-bookworm-slim-index.json",
        "complete-rootfs-manifest": (
            staged / "debian-bookworm-slim-arm64-manifest.json"
        ),
        "complete-rootfs-official-images": (
            staged / "docker-official-images-library-debian.txt"
        ),
    }
    layer_path = staged / "debian-bookworm-slim-arm64-layer.tar.gz"
    if not layer_path.is_file() or any(
        not path.is_file() for path in evidence_paths.values()
    ):
        pytest.skip("verified Debian OCI evidence is not staged")
    evidence = {
        asset_id: path.read_bytes() for asset_id, path in evidence_paths.items()
    }
    assets = [
        {
            "asset_id": asset_id,
            "path": f"runtime/{path.name}",
            "sha256": _digest(evidence[asset_id]),
        }
        for asset_id, path in evidence_paths.items()
    ]
    assets.append(
        {
            "asset_id": "complete-rootfs",
            "path": f"runtime/{layer_path.name}",
            "sha256": (
                "75782e20ea1f4a9d9259bc20a5ecbbea8d5943bf5370bf0f5727900728f1cc9a"
            ),
        }
    )
    config = json.loads(evidence["complete-rootfs-config"])
    diff_id = config["rootfs"]["diff_ids"][0]
    provenance = _json(
        {
            "authentication_scope": "TEST_ONLY_NO_RELEASE_AUTHORITY",
            "config_digest": "sha256:" + _digest(evidence["complete-rootfs-config"]),
            "config_size": len(evidence["complete-rootfs-config"]),
            "index_digest": "sha256:" + _digest(evidence["complete-rootfs-index"]),
            "index_size": len(evidence["complete-rootfs-index"]),
            "layer_digest": "sha256:" + assets[-1]["sha256"],
            "layer_diff_id": diff_id,
            "layer_size": layer_path.stat().st_size,
            "manifest_digest": "sha256:"
            + _digest(evidence["complete-rootfs-manifest"]),
            "manifest_size": len(evidence["complete-rootfs-manifest"]),
            "official_images_commit": (
                "b9c995a1c91bf8b195b035893ebdf8e877e7f7fa"
            ),
            "official_images_sha256": _digest(
                evidence["complete-rootfs-official-images"]
            ),
            "platform": "linux/arm64/v8",
            "schema_version": "plamen.complete_rootfs_provenance.v1",
            "source_reference": (
                "docker.io/library/debian:bookworm-20260824-slim@sha256:"
                + _digest(evidence["complete-rootfs-index"])
            ),
        }
    )
    assets.extend(
        [
            {
                "asset_id": "complete-rootfs-provenance",
                "path": "runtime/provenance.json",
                "sha256": _digest(provenance),
            },
            {
                "asset_id": "runtime-closure",
                "path": "runtime/closure.tar",
                "sha256": "0" * 64,
            },
        ]
    )
    build_inputs = [
        {
            "mode": "0444",
            "path": row["path"],
            "sha256": row["sha256"],
            "size": (
                layer_path.stat().st_size
                if row["asset_id"] == "complete-rootfs"
                else len(evidence[row["asset_id"]])
            ),
        }
        for row in assets
        if row["asset_id"] in evidence or row["asset_id"] == "complete-rootfs"
    ]
    plan = {
        "authentication_scope": "TEST_ONLY_NO_RELEASE_AUTHORITY",
        "build_inputs": build_inputs,
        "runtime": {"assets": assets},
    }
    L._validate_complete_rootfs_provenance(provenance, plan, evidence, diff_id)

    production_provenance = json.loads(provenance)
    production_provenance["authentication_scope"] = "REGISTRY_TLS_EXACT_DIGESTS"
    production_plan = copy.deepcopy(plan)
    production_plan["authentication_scope"] = "EXACT_RELEASE_AUTHORITY"
    L._validate_complete_rootfs_provenance(
        _json(production_provenance),
        production_plan,
        evidence,
        diff_id,
    )

    substituted = copy.deepcopy(production_provenance)
    substituted["official_images_sha256"] = "0" * 64
    with pytest.raises(L.DeterministicOCILayoutError, match="exact locked Debian"):
        L._validate_complete_rootfs_provenance(
            _json(substituted),
            production_plan,
            evidence,
            diff_id,
        )


def test_real_staged_cache_free_rootfs_cannot_bypass_materializer_binding(
    tmp_path: Path,
) -> None:
    staged = Path("/private/tmp/plamen-runtime-inputs")
    source_paths = {
        "complete-rootfs": staged / "debian-bookworm-slim-arm64-layer.tar.gz",
        "complete-rootfs-config": staged / "debian-bookworm-slim-arm64-config.json",
        "complete-rootfs-index": staged / "debian-bookworm-slim-index.json",
        "complete-rootfs-manifest": (
            staged / "debian-bookworm-slim-arm64-manifest.json"
        ),
        "complete-rootfs-official-images": (
            staged / "docker-official-images-library-debian.txt"
        ),
    }
    if any(not path.is_file() for path in source_paths.values()):
        pytest.skip("verified Debian OCI evidence is not staged")

    root, original, _installed = _fixture(tmp_path)
    unsigned = copy.deepcopy(original)
    unsigned.pop("lock_sha256")
    assets = {
        row["asset_id"]: row for row in unsigned["runtime"]["assets"]
    }
    for asset_id, source in source_paths.items():
        destination = root / assets[asset_id]["path"]
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
        assets[asset_id]["sha256"] = _file_digest(destination)

    provenance = json.loads(E.pinned_provenance_bytes())
    # This is an explicitly TEST_ONLY renderer exercise.  The accepted ELF
    # derivation authenticates the immutable source facts independently; this
    # document still binds the exact staged graph without claiming issuance.
    provenance["authentication_scope"] = "TEST_ONLY_NO_RELEASE_AUTHORITY"
    provenance_path = root / assets["complete-rootfs-provenance"]["path"]
    provenance_path.write_bytes(_json(provenance))
    provenance_path.chmod(0o644)
    assets["complete-rootfs-provenance"]["sha256"] = _file_digest(
        provenance_path
    )

    unsigned["rootfs_derivation"] = {
        "schema_version": O.ROOTFS_DERIVATION_BINDING_SCHEMA_VERSION,
        "derivation_schema_version": E.SCHEMA_VERSION,
        "recipe_version": E.RECIPE_VERSION,
        "authentication_scope": E.AUTHENTICATION_SCOPE,
        "production_authority": False,
        "source_asset_id": "complete-rootfs",
        "source_reference": E.SOURCE_REFERENCE,
        "source_sha256": E.SOURCE_LAYER_SHA256,
        "source_size": E.SOURCE_LAYER_SIZE,
        "source_diff_id": "sha256:" + E.SOURCE_DIFF_ID,
        "derived_sha256": E.DERIVED_LAYER_SHA256,
        "derived_size": E.DERIVED_LAYER_SIZE,
        "derived_diff_id": "sha256:" + E.DERIVED_DIFF_ID,
        "derived_tar_size": E.SOURCE_TAR_SIZE,
        "derived_census_sha256": O._PINNED_DERIVED_CENSUS_SHA256,
        "derived_entry_count": O._PINNED_DERIVED_ENTRY_COUNT,
        "manifest_sha256": E.DERIVATION_MANIFEST_SHA256,
        "removed_cache_path": "/etc/ld.so.cache",
        "removed_cache_sha256": O._PINNED_REMOVED_CACHE_SHA256,
        "removed_cache_size": O._PINNED_REMOVED_CACHE_SIZE,
        "forbidden_environment": {
            "exact_names": ["GLIBC_TUNABLES"],
            "prefixes": ["LD_"],
        },
    }
    attestation_payloads: dict[str, bytes] = {}
    _refresh_attestations(unsigned, attestation_payloads)
    for path, raw in attestation_payloads.items():
        destination = root / path
        destination.write_bytes(raw)
        destination.chmod(0o644)

    for row in unsigned["build_inputs"]:
        source = root / row["path"]
        row["sha256"] = _file_digest(source)
        row["size"] = source.stat().st_size

    manifest_placeholder = "sha256:" + "f" * 64
    index_placeholder = "sha256:" + "e" * 64
    unsigned["image"]["manifest_digest"] = manifest_placeholder
    unsigned["image"]["index_digest"] = index_placeholder
    unsigned["image"]["reference"] = (
        "ghcr.io/plamen/audit-runtime@" + index_placeholder
    )
    first_lock = O.seal_image_lock(unsigned)
    # The source graph was changed without re-materializing the runtime image.
    # Even exact authenticated Debian bytes must not bypass the independent
    # composition-manifest/source-roster binding by reaching the layout
    # renderer's former legacy assembler path.
    with pytest.raises(
        O.OCIImageLockError,
        match="test build-context consumption failed closed",
    ):
        _rendered_image_digests(_plan(root, first_lock, nonce="7" * 64))


def test_locked_dodo_entry_budget_exceeds_old_cap_but_remains_finite() -> None:
    assert L._MAX_LAYER_ENTRIES > L._LOCKED_DODO_EXPECTED_ENTRY_FLOOR
    assert L._LOCKED_DODO_EXPECTED_ENTRY_FLOOR > 32_768
    assert L._MAX_LAYER_ENTRIES == 131_072
    L._require_layer_entry_count(32_769, "test runtime")
    L._require_layer_entry_count(L._MAX_LAYER_ENTRIES, "test runtime")
    with pytest.raises(L.DeterministicOCILayoutError, match="exceeds its bound"):
        L._require_layer_entry_count(L._MAX_LAYER_ENTRIES + 1, "test runtime")


def test_layout_resource_budgets_match_runtime_materializer_contract() -> None:
    assert L._MAX_INPUT_BYTES == runtime_materializer.MAX_INPUT_BYTES
    assert L._MAX_EXPANDED_BYTES == runtime_materializer.MAX_EXPANDED_BYTES
    assert L._MAX_LAYER_ENTRIES == runtime_materializer.MAX_ENTRIES
    assert runtime_materializer.MAX_ENTRIES == 131_072
    assert runtime_materializer.MAX_EXPANDED_BYTES == 12 * 1024**3
    assert runtime_materializer.MAX_INPUT_BYTES == 8 * 1024**3


def test_installed_sbom_census_and_provenance_are_semantically_cross_bound(
    tmp_path: Path,
) -> None:
    root, lock, _ = _fixture(tmp_path)
    runtime_assets = {
        row["asset_id"]: row for row in lock["runtime"]["assets"]
    }
    labels = {
        "org.plamen.complete-rootfs.provenance.sha256": runtime_assets[
            "complete-rootfs-provenance"
        ]["sha256"],
        "org.plamen.complete-rootfs.derivation-manifest.sha256": lock[
            "rootfs_derivation"
        ]["manifest_sha256"],
        "org.plamen.complete-rootfs.derived-census.sha256": lock[
            "rootfs_derivation"
        ]["derived_census_sha256"],
        "org.plamen.complete-rootfs.derived-diff-id": lock[
            "rootfs_derivation"
        ]["derived_diff_id"],
        "org.plamen.complete-rootfs.derived.sha256": lock[
            "rootfs_derivation"
        ]["derived_sha256"],
        "org.plamen.complete-rootfs.source.sha256": runtime_assets[
            "complete-rootfs"
        ]["sha256"],
        "org.plamen.runtime-census.sha256": lock["attestations"]["census"][
            "sha256"
        ],
        "org.plamen.sbom.sha256": lock["attestations"]["sbom"]["sha256"],
    }
    payloads = {
        "usr/local/lib/plamen/attestations/census.json": (
            root / "attestations/census.json"
        ).read_bytes(),
        "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json": (
            O._TEST_ONLY_rootfs_derivation_manifest_bytes(
                lock["rootfs_derivation"]
            )
        ),
        "usr/local/lib/plamen/attestations/complete-rootfs-provenance.json": (
            root / "runtime/complete-rootfs-provenance.json"
        ).read_bytes(),
        "usr/local/lib/plamen/attestations/sbom.json": (
            root / "attestations/sbom.spdx.json"
        ).read_bytes(),
    }
    L._validate_installed_attestations(payloads, labels)

    tampered = dict(payloads)
    census = json.loads(tampered["usr/local/lib/plamen/attestations/census.json"])
    census["artifacts"][0]["sha256"] = "e" * 64
    tampered["usr/local/lib/plamen/attestations/census.json"] = _json(census)
    tampered_labels = dict(labels)
    tampered_labels["org.plamen.runtime-census.sha256"] = _digest(
        tampered["usr/local/lib/plamen/attestations/census.json"]
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="SBOM.*runtime census"):
        L._validate_installed_attestations(tampered, tampered_labels)


def test_authenticated_expected_manifest_mismatch_is_atomic(tmp_path: Path) -> None:
    root, lock, _ = _fixture(tmp_path)
    lock["image"]["manifest_digest"] = "sha256:" + "d" * 64
    lock = lock_tests._resign(lock)
    output = tmp_path / "mismatch"
    with pytest.raises(L.DeterministicOCILayoutError, match="failed closed"):
        L._build_oci_layout_for_testing(
            _plan(root, lock),
            output.resolve(),
            authenticated_external_fake_acknowledger=_ack,
        )
    assert not output.exists()
    assert not list(tmp_path.glob(".plamen-oci-layout-*"))


def test_authenticated_expected_index_mismatch_is_atomic(tmp_path: Path) -> None:
    root, lock, _ = _fixture(tmp_path)
    replacement = "sha256:" + "d" * 64
    lock["image"]["index_digest"] = replacement
    lock["image"]["reference"] = (
        "ghcr.io/plamen/audit-runtime@" + replacement
    )
    lock = lock_tests._resign(lock)
    output = tmp_path / "index-mismatch"
    with pytest.raises(L.DeterministicOCILayoutError, match="failed closed"):
        L._build_oci_layout_for_testing(
            _plan(root, lock),
            output,
            authenticated_external_fake_acknowledger=_ack,
        )
    assert not output.exists()
    assert not list(tmp_path.glob(".plamen-oci-layout-*"))


def test_production_authority_hardstops_remain(tmp_path: Path) -> None:
    root, lock, _ = _fixture(tmp_path)
    testing = _plan(root, lock)
    with pytest.raises(L.DeterministicOCILayoutError, match="exact production"):
        L.build_oci_layout(
            testing,
            (tmp_path / "forbidden").resolve(),
            authenticated_context_consumer=object(),
        )

    value = dict(testing)
    value["authentication_scope"] = "CALLER_FORGED_PRODUCTION"
    body = dict(value)
    body.pop("plan_sha256")
    value["plan_sha256"] = _digest(_json(body))
    forged = O.OCIValidatedBuildPlan(value, testing._authority)
    testing._authority = type("Closed", (), {"close": lambda self: None})()
    with pytest.raises(
        L.DeterministicOCILayoutError,
        match="AUTHENTICATED_CONTEXT_CONSUMER_REQUIRED",
    ):
        L.build_oci_layout(
            forged,
            (tmp_path / "forbidden").resolve(),
            authenticated_context_consumer=lambda _: True,
        )

    absent_layout = (tmp_path / "absent-layout").resolve()
    absent_archive = (tmp_path / "absent-archive.tar").resolve()
    expected = "sha256:" + "a" * 64
    for operation in (
        lambda: L.verify_oci_layout(
            absent_layout, expected_manifest_digest=expected
        ),
        lambda: L.export_oci_layout_archive(
            absent_layout,
            absent_archive,
            expected_manifest_digest=expected,
        ),
        lambda: L.verify_oci_layout_archive(
            absent_archive,
            expected_manifest_digest=expected,
            expected_archive_sha256="b" * 64,
        ),
    ):
        with pytest.raises(
            L.DeterministicOCILayoutError,
            match="AUTHENTICATED_CONTEXT_CONSUMER_REQUIRED",
        ):
            operation()
    assert not absent_layout.exists()
    assert not absent_archive.exists()


@pytest.mark.parametrize(
    "injected",
    ("LD_PRELOAD=/attacker.so", "GLIBC_TUNABLES=glibc.malloc.check=0"),
)
def test_rootfs_derivation_denies_loader_environment_before_output_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, injected: str
) -> None:
    root, lock, _installed = _fixture(tmp_path)
    output = tmp_path / "must-not-exist"
    monkeypatch.setattr(L, "RUNTIME_ENV", (*L.RUNTIME_ENV, injected))
    with pytest.raises(
        L.DeterministicOCILayoutError,
        match="execution environment violates",
    ):
        L._build_oci_layout_for_testing(
            _plan(root, lock),
            output,
            authenticated_external_fake_acknowledger=_ack,
        )
    assert not output.exists()


def test_source_replacement_after_admission_cannot_change_runtime(tmp_path: Path) -> None:
    root, lock, installed = _fixture(tmp_path)
    plan = _plan(root, lock)
    (root / "backends" / "codex").write_bytes(b"#!/bin/sh\necho replaced\n")
    output = tmp_path / "snapshot"
    result = L._build_oci_layout_for_testing(
        plan, output.resolve(), authenticated_external_fake_acknowledger=_ack
    )
    layer = output / "blobs" / "sha256" / result.layer_digest.removeprefix("sha256:")
    with tarfile.open(layer, "r:gz") as archive:
        payload = archive.extractfile("usr/local/lib/plamen/bin/codex")
        assert payload is not None
        assert payload.read() == installed["usr/local/lib/plamen/bin/codex"][1]


def test_real_distribution_shapes_are_remapped_and_safe_symlinks_survive() -> None:
    link = tarfile.TarInfo("python/bin/python3")
    link.type = tarfile.SYMTYPE
    link.mode = 0o777
    link.uid = link.gid = link.mtime = 0
    link.linkname = "python3.12"
    python_raw = _fragment(
        {"python/bin/python3.12": (0o555, b"\x7fELF-python\n")}, extra=link
    )
    python_row = L._InputMetadata(
        "artifacts/python.tar", _digest(python_raw), len(python_raw), 0o644
    )
    python_entries: list[L._ExpandedEntry] = []
    L._expand_archive(
        L._ReaderAdapter(L._BytesReader(python_raw), python_row),
        python_row,
        entries=python_entries,
        files=set(),
        directories=set(),
        aliases={},
        expanded_total=[0],
        install_kind="cpython_archive",
        identifier="cpython",
    )
    try:
        assert {entry.path for entry in python_entries} == {
            "usr/bin/python3",
            "usr/bin/python3.12",
        }
        L._validate_expanded_links(python_entries)
    finally:
        for entry in python_entries:
            if entry.source is not None:
                entry.source.close()

    foundry_raw = _fragment(
        {
            name: (0o555, b"\x7fELF-" + name.encode())
            for name in ("forge", "cast", "anvil", "chisel")
        }
    )
    foundry_row = L._InputMetadata(
        "toolchains/foundry.tar", _digest(foundry_raw), len(foundry_raw), 0o644
    )
    foundry_entries: list[L._ExpandedEntry] = []
    L._expand_archive(
        L._ReaderAdapter(L._BytesReader(foundry_raw), foundry_row),
        foundry_row,
        entries=foundry_entries,
        files=set(),
        directories=set(),
        aliases={},
        expanded_total=[0],
        install_kind="toolchain_archive",
        identifier="foundry",
    )
    try:
        assert {entry.path for entry in foundry_entries} == {
            f"usr/local/lib/plamen/toolchains/foundry/bin/{name}"
            for name in ("forge", "cast", "anvil", "chisel")
        }
    finally:
        for entry in foundry_entries:
            if entry.source is not None:
                entry.source.close()


@pytest.mark.parametrize(
    "kind",
    [tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE],
)
def test_runtime_archive_rejects_links_devices_and_fifos(kind: bytes) -> None:
    member = tarfile.TarInfo("opt/plamen/unsafe")
    member.type = kind
    member.mode = 0o444
    member.uid = member.gid = member.mtime = 0
    raw = _fragment({}, extra=member)
    row = L._InputMetadata("runtime/unsafe.tar", _digest(raw), len(raw), 0o644)
    with pytest.raises(L.DeterministicOCILayoutError, match="linked|special|unsafe"):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(raw), row),
            row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_runtime_archive_rejects_escaping_links(kind: bytes) -> None:
    member = tarfile.TarInfo("opt/plamen/unsafe")
    member.type = kind
    member.mode = 0o777 if kind == tarfile.SYMTYPE else 0o444
    member.uid = member.gid = member.mtime = 0
    member.linkname = "../../../../escape"
    raw = _fragment({}, extra=member)
    row = L._InputMetadata("runtime/unsafe.tar", _digest(raw), len(raw), 0o644)
    with pytest.raises(L.DeterministicOCILayoutError, match="escape|forbidden"):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(raw), row),
            row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "opt/../../escape", "dev/credential"]
)
def test_runtime_archive_rejects_path_escape_and_forbidden_roots(name: str) -> None:
    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.mode = 0o444
    member.uid = member.gid = member.mtime = 0
    member.size = 1
    raw = _fragment({}, extra=member, extra_payload=b"x")
    row = L._InputMetadata("runtime/unsafe.tar", _digest(raw), len(raw), 0o644)
    with pytest.raises(
        L.DeterministicOCILayoutError, match="escapes|forbidden|ephemeral"
    ):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(raw), row),
            row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )


@pytest.mark.parametrize(
    ("identifier", "member_name", "payload", "error"),
    [
        (
            "runtime-closure",
            "etc/ld.so.preload",
            b"/untrusted.so\n",
            "reserved Plamen namespace",
        ),
        (
            "complete-rootfs",
            "opt/plamen/bin/claimed-by-base",
            b"x",
            "reserved Plamen namespace",
        ),
    ],
)
def test_base_and_runtime_closure_namespaces_are_disjoint(
    identifier: str, member_name: str, payload: bytes, error: str
) -> None:
    raw = _fragment({member_name: (0o444, payload)})
    row = L._InputMetadata("runtime/namespace.tar", _digest(raw), len(raw), 0o644)
    with pytest.raises(L.DeterministicOCILayoutError, match=error):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(raw), row),
            row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
            install_kind="rootfs_archive",
            identifier=identifier,
        )


def test_unapproved_link_into_provider_namespace_is_rejected() -> None:
    link = tarfile.TarInfo("usr/lib/provider-alias")
    link.type = tarfile.SYMTYPE
    link.mode = 0o777
    link.uid = link.gid = link.mtime = 0
    link.linkname = "/dev/null"
    raw = _fragment({}, extra=link)
    row = L._InputMetadata("runtime/provider-link.tar", _digest(raw), len(raw), 0o644)
    with pytest.raises(L.DeterministicOCILayoutError, match="provider-owned"):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(raw), row),
            row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
            install_kind="rootfs_archive",
            identifier="complete-rootfs",
        )


def test_archive_rejects_pax_aliases_and_expansion_bomb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pax = tarfile.TarInfo("opt/plamen/pax")
    pax.type = tarfile.REGTYPE
    pax.mode = 0o444
    pax.uid = pax.gid = pax.mtime = 0
    pax.size = 1
    pax.pax_headers = {"SCHILY.xattr.user.attack": "value"}
    raw = _fragment(
        {}, extra=pax, extra_payload=b"x", archive_format=tarfile.PAX_FORMAT
    )
    row = L._InputMetadata("runtime/pax.tar", _digest(raw), len(raw), 0o644)
    with pytest.raises(L.DeterministicOCILayoutError, match="metadata"):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(raw), row),
            row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )

    duplicate_member = tarfile.TarInfo("opt/plamen/duplicate")
    duplicate_member.type = tarfile.REGTYPE
    duplicate_member.mode = 0o444
    duplicate_member.uid = duplicate_member.gid = duplicate_member.mtime = 0
    duplicate_member.size = 1
    duplicate = _fragment(
        {"opt/plamen/duplicate": (0o444, b"a")},
        extra=duplicate_member,
        extra_payload=b"b",
    )
    duplicate_row = L._InputMetadata(
        "runtime/duplicate.tar", _digest(duplicate), len(duplicate), 0o644
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="collide|duplicate"):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(duplicate), duplicate_row),
            duplicate_row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )

    duplicate_directories = io.BytesIO()
    with tarfile.open(
        fileobj=duplicate_directories, mode="w", format=tarfile.USTAR_FORMAT
    ) as archive:
        for _ in range(2):
            directory = tarfile.TarInfo("opt/plamen/duplicate-directory/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.uid = directory.gid = directory.mtime = 0
            directory.uname = directory.gname = ""
            archive.addfile(directory)
    duplicate_directory_raw = duplicate_directories.getvalue()
    duplicate_directory_row = L._InputMetadata(
        "runtime/duplicate-directory.tar",
        _digest(duplicate_directory_raw),
        len(duplicate_directory_raw),
        0o644,
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="duplicate"):
        L._expand_archive(
            L._ReaderAdapter(
                L._BytesReader(duplicate_directory_raw), duplicate_directory_row
            ),
            duplicate_directory_row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )

    bomb = gzip.compress(
        _fragment({"opt/plamen/bomb": (0o444, b"x" * 513)}), mtime=0
    )
    bomb_row = L._InputMetadata(
        "runtime/bomb.tar", _digest(bomb), len(bomb), 0o644
    )
    monkeypatch.setattr(L, "_MAX_EXPANDED_BYTES", 512)
    with pytest.raises(L.DeterministicOCILayoutError, match="decompression|size"):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(bomb), bomb_row),
            bomb_row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )


def test_runtime_archive_rejects_noncanonical_zero_trailer() -> None:
    raw = _fragment({"opt/plamen/file": (0o444, b"payload")}) + b"\0" * 10_240
    row = L._InputMetadata("runtime/trailer.tar", _digest(raw), len(raw), 0o644)
    with pytest.raises(L.DeterministicOCILayoutError, match="terminator"):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(raw), row),
            row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )


@pytest.mark.parametrize(
    "suffix",
    [b"trailer", gzip.compress(_fragment({"second": (0o444, b"archive")}), mtime=0)],
)
def test_runtime_archive_rejects_gzip_trailer_or_concatenation(suffix: bytes) -> None:
    compressed = gzip.compress(
        _fragment({"opt/plamen/file": (0o444, b"payload")}), mtime=0
    ) + suffix
    row = L._InputMetadata(
        "runtime/trailing.tar.gz", _digest(compressed), len(compressed), 0o644
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="concatenated|trailing"):
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(compressed), row),
            row,
            entries=[],
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
        )


def test_runnable_entrypoint_is_mandatory_and_magic_checked() -> None:
    entry = L._ExpandedEntry(
        "usr/local/libexec/plamen-guest",
        _digest(b"not executable"),
        14,
        0o555,
        io.BytesIO(b"not executable"),
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="omits"):
        L._require_runnable_runtime([entry])
    required = {
        "usr/local/libexec/plamen-guest": b"not executable",
        "usr/local/lib/plamen/bin/claude": b"#!/bin/sh\n",
        "usr/local/lib/plamen/bin/codex": b"#!/bin/sh\n",
        "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so": (
            b"\x7fELF" + b"x" * 32
        ),
        "usr/bin/python3": b"#!/bin/sh\n",
    }
    entries = [
        L._ExpandedEntry(path, _digest(raw), len(raw), 0o555, io.BytesIO(raw))
        for path, raw in required.items()
    ]
    with pytest.raises(L.DeterministicOCILayoutError, match="format"):
        L._require_runnable_runtime(entries)

    fake_elf = L._ExpandedEntry(
        "opt/plamen/bin/fake",
        _digest(b"\x7fELF" + b"x" * 32),
        36,
        0o555,
        io.BytesIO(b"\x7fELF" + b"x" * 32),
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="range|ELF"):
        L._parse_arm64_elf(fake_elf)


def test_shebang_interpreter_must_resolve_inside_runtime() -> None:
    _payloads, installed = _runtime_payloads()
    installed["usr/local/libexec/plamen-guest"] = (
        0o555,
        b"#!/missing/interpreter\n",
    )
    entries = [
        L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
        for path, (mode, raw) in sorted(installed.items())
    ]
    with pytest.raises(L.DeterministicOCILayoutError, match="target is absent"):
        L._validate_runtime_dependencies(entries)

    installed["usr/local/libexec/plamen-guest"] = (
        0o555,
        b"#!/usr/bin/env python3\n",
    )
    entries = [
        L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
        for path, (mode, raw) in sorted(installed.items())
    ]
    with pytest.raises(L.DeterministicOCILayoutError, match="closed interpreter"):
        L._validate_runtime_dependencies(entries)

    installed["usr/local/libexec/plamen-guest"] = (
        0o555,
        b"#!/bin/sh\r\n",
    )
    entries = [
        L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
        for path, (mode, raw) in sorted(installed.items())
    ]
    with pytest.raises(L.DeterministicOCILayoutError, match="shebang"):
        L._validate_runtime_dependencies(entries)

    oversized = b"#!/" + b"a" * L._LINUX_BINPRM_BUF_SIZE
    installed["usr/local/libexec/plamen-guest"] = (0o555, oversized)
    entries = [
        L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
        for path, (mode, raw) in sorted(installed.items())
    ]
    with pytest.raises(L.DeterministicOCILayoutError, match="Linux buffer"):
        L._validate_runtime_dependencies(entries)


def test_dynamic_elf_dependency_closure_fails_closed() -> None:
    _payloads, installed = _runtime_payloads()

    def entries_for(values: dict[str, tuple[int, bytes]]) -> list[L._ExpandedEntry]:
        return [
            L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
            for path, (mode, raw) in sorted(values.items())
        ]

    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(needed=("libmissing.so.1",)),
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="unresolved"):
        L._validate_runtime_dependencies(entries_for(installed))

    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(needed=("libc.so.6",), interpreter=None),
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="omits PT_INTERP"):
        L._validate_runtime_dependencies(entries_for(installed))

    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(needed=("libclaimed.so.1",)),
    )
    installed["lib/aarch64-linux-gnu/libclaimed.so.1"] = (
        0o555,
        _dynamic_aarch64_elf(interpreter=None, soname="libother.so.1"),
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="SONAME"):
        L._validate_runtime_dependencies(entries_for(installed))

    installed.pop("lib/aarch64-linux-gnu/libclaimed.so.1")
    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(
            needed=("libmissing.so.1",),
            runpath="/dev",
        ),
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="provider-owned"):
        L._validate_runtime_dependencies(entries_for(installed))


def test_elf_owner_directory_is_not_an_implicit_search_path() -> None:
    _payloads, installed = _runtime_payloads()
    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(needed=("liblocal.so.1",)),
    )
    installed["usr/local/lib/plamen/bin/liblocal.so.1"] = (
        0o555,
        _dynamic_aarch64_elf(interpreter=None, soname="liblocal.so.1"),
    )

    def entries() -> list[L._ExpandedEntry]:
        return [
            L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
            for path, (mode, raw) in sorted(installed.items())
        ]

    with pytest.raises(L.DeterministicOCILayoutError, match="unresolved"):
        L._validate_runtime_dependencies(entries())

    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(
            needed=("liblocal.so.1",), runpath="$ORIGIN"
        ),
    )
    _document, digest = L._validate_runtime_dependencies(entries())
    assert len(digest) == 64


def test_elf_rpath_is_transitive_but_runpath_is_not() -> None:
    def closure(search_kind: str) -> list[L._ExpandedEntry]:
        _payloads, installed = _runtime_payloads()
        search = {search_kind: "$ORIGIN/lib"}
        installed["usr/local/lib/plamen/bin/claude"] = (
            0o555,
            _dynamic_aarch64_elf(needed=("libparent.so.1",), **search),
        )
        installed["usr/local/lib/plamen/bin/lib/libparent.so.1"] = (
            0o555,
            _dynamic_aarch64_elf(
                needed=("libchild.so.1",),
                interpreter=None,
                soname="libparent.so.1",
            ),
        )
        installed["usr/local/lib/plamen/bin/lib/libchild.so.1"] = (
            0o555,
            _dynamic_aarch64_elf(
                interpreter=None, soname="libchild.so.1"
            ),
        )
        return [
            L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
            for path, (mode, raw) in sorted(installed.items())
        ]

    document, digest = L._validate_runtime_dependencies(closure("rpath"))
    assert b'"name":"libchild.so.1"' in document
    assert len(digest) == 64
    with pytest.raises(L.DeterministicOCILayoutError, match="unresolved"):
        L._validate_runtime_dependencies(closure("runpath"))


def test_elf_nodeflib_suppresses_default_library_directories() -> None:
    _payloads, installed = _runtime_payloads()

    def entries() -> list[L._ExpandedEntry]:
        return [
            L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
            for path, (mode, raw) in sorted(installed.items())
        ]

    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(needed=("libc.so.6",), nodeflib=True),
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="unresolved"):
        L._validate_runtime_dependencies(entries())

    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(
            needed=("libc.so.6",),
            runpath="/lib/aarch64-linux-gnu",
            nodeflib=True,
        ),
    )
    document, digest = L._validate_runtime_dependencies(entries())
    assert b'"name":"libc.so.6"' in document
    assert len(digest) == 64


def test_ld_so_cache_requires_an_authenticated_resolution_model() -> None:
    _payloads, installed = _runtime_payloads()

    def entries() -> list[L._ExpandedEntry]:
        return [
            L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
            for path, (mode, raw) in sorted(installed.items())
        ]

    # True absence is allowed and does not become a cache claim.
    document, digest = L._validate_runtime_dependencies(entries())
    assert b"ld.so.cache" not in document
    assert len(digest) == 64

    cache_raw = b"glibc-cache-placeholder"
    literal = entries()
    literal.append(
        L._ExpandedEntry(
            "etc/ld.so.cache",
            _digest(cache_raw),
            len(cache_raw),
            0o444,
            io.BytesIO(cache_raw),
        )
    )
    with pytest.raises(
        L.DeterministicOCILayoutError,
        match="authenticated ld.so.cache resolution is not implemented",
    ):
        L._validate_runtime_dependencies(literal)

    # Resolve the effective absolute pathname through an ancestor symlink;
    # checking only the literal archive member would miss this cache.
    for path in tuple(installed):
        if path.startswith("etc/"):
            installed.pop(path)
    expanded = entries()
    expanded.extend(
        (
            L._ExpandedEntry(
                "etc",
                _digest(b"symlink\0/usr/etc"),
                0,
                0o777,
                None,
                "symlink",
                "/usr/etc",
            ),
            L._ExpandedEntry(
                "usr/etc/ld.so.cache",
                _digest(cache_raw),
                len(cache_raw),
                0o444,
                io.BytesIO(cache_raw),
            ),
        )
    )
    with pytest.raises(
        L.DeterministicOCILayoutError,
        match="authenticated ld.so.cache resolution is not implemented",
    ):
        L._validate_runtime_dependencies(expanded)


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("/usr/missing-ld.so.cache", "alias target is absent"),
        ("/etc/ld.so.cache", "alias is malformed"),
        ("../../../outside", "alias escapes the rootfs"),
        ("/run/provider-cache", "alias escapes the rootfs"),
    ],
)
def test_ld_so_cache_alias_malformed_and_escape_are_not_absence(
    target: str, message: str,
) -> None:
    _payloads, installed = _runtime_payloads()
    expanded = [
        L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
        for path, (mode, raw) in sorted(installed.items())
    ]
    expanded.append(
        L._ExpandedEntry(
            "etc/ld.so.cache",
            _digest(("symlink\0" + target).encode()),
            0,
            0o777,
            None,
            "symlink",
            target,
        )
    )
    with pytest.raises(L.DeterministicOCILayoutError, match=message):
        L._validate_runtime_dependencies(expanded)


def test_required_dynamic_root_policy_cannot_be_deduplicated_by_shebang() -> None:
    _payloads, installed = _runtime_payloads()
    installed["usr/local/libexec/plamen-guest"] = (
        0o555,
        b"#!/usr/local/lib/plamen/bin/claude\n",
    )
    installed["usr/local/lib/plamen/bin/claude"] = (
        0o555,
        _dynamic_aarch64_elf(needed=("libc.so.6",), interpreter=None),
    )
    expanded = [
        L._ExpandedEntry(path, _digest(raw), len(raw), mode, io.BytesIO(raw))
        for path, (mode, raw) in sorted(installed.items())
    ]
    with pytest.raises(L.DeterministicOCILayoutError, match="omits PT_INTERP"):
        L._validate_runtime_dependencies(expanded)


def test_real_staged_backend_elf_metadata_when_available() -> None:
    staged = Path("/private/tmp/plamen-runtime-inputs")
    claude_path = staged / "claude-linux-arm64-2.1.263"
    codex_path = staged / "codex-aarch64-unknown-linux-musl-0.153.4"
    if not claude_path.is_file() or not codex_path.is_file():
        pytest.skip("verified release backend inputs are not staged")
    with claude_path.open("rb") as claude_source, codex_path.open("rb") as codex_source:
        claude = L._ExpandedEntry(
            "usr/local/lib/plamen/bin/claude",
            "7d25d7c8ae6c6e009cc7dae4e817f674179fd31fb7761bcd56fee4c2902b4c03",
            claude_path.stat().st_size,
            0o555,
            claude_source,
        )
        codex = L._ExpandedEntry(
            "usr/local/lib/plamen/bin/codex",
            "4d76e542c222ea8c75861d8c4ade60a1a332a63255ce1c60bdaebf7c2a2869e6",
            codex_path.stat().st_size,
            0o555,
            codex_source,
        )
        claude_metadata = L._parse_arm64_elf(claude)
        codex_metadata = L._parse_arm64_elf(codex)
    assert claude_metadata.interpreter == "/lib/ld-linux-aarch64.so.1"
    assert set(claude_metadata.needed) == {
        "ld-linux-aarch64.so.1",
        "libc.so.6",
        "libdl.so.2",
        "libm.so.6",
        "libpthread.so.0",
        "librt.so.1",
    }
    assert codex_metadata.interpreter is None
    assert codex_metadata.needed == ()


def test_verifier_rejects_root_user_even_when_descriptor_graph_is_rehashed(
    tmp_path: Path,
) -> None:
    _root, _lock, _installed, output, result = _build(tmp_path)
    blob_root = output / "blobs" / "sha256"
    config_path = blob_root / result.config_digest.removeprefix("sha256:")
    config = json.loads(config_path.read_bytes())
    config["config"]["User"] = "0:0"
    changed = _json(config)
    changed_digest = "sha256:" + _digest(changed)
    manifest_path = blob_root / result.manifest_digest.removeprefix("sha256:")
    manifest = json.loads(manifest_path.read_bytes())
    manifest["config"] = {
        "digest": changed_digest,
        "mediaType": L.OCI_CONFIG_MEDIA_TYPE,
        "size": len(changed),
    }
    changed_manifest = _json(manifest)
    changed_manifest_digest = "sha256:" + _digest(changed_manifest)
    index = json.loads((output / "index.json").read_bytes())
    index["manifests"][0]["digest"] = changed_manifest_digest
    index["manifests"][0]["size"] = len(changed_manifest)
    for directory in (output, output / "blobs", blob_root):
        directory.chmod(0o700)
    for path in (config_path, manifest_path, output / "index.json"):
        path.chmod(0o600)
    config_path.unlink()
    manifest_path.unlink()
    changed_config_path = blob_root / changed_digest.removeprefix("sha256:")
    changed_manifest_path = blob_root / changed_manifest_digest.removeprefix("sha256:")
    changed_config_path.write_bytes(changed)
    changed_manifest_path.write_bytes(changed_manifest)
    (output / "index.json").write_bytes(_json(index))
    for path in output.rglob("*"):
        path.chmod(0o555 if path.is_dir() else 0o444)
    output.chmod(0o555)
    with pytest.raises(L.DeterministicOCILayoutError, match="non-root runtime"):
        L._verify_oci_layout_for_testing(
            output.resolve(), expected_manifest_digest=changed_manifest_digest
        )


def test_deterministic_outer_archive_round_trip_and_tamper(tmp_path: Path) -> None:
    _root, _lock, _installed, layout, image = _build(tmp_path)
    first_path = tmp_path / "first.oci.tar"
    second_path = tmp_path / "second.oci.tar"
    first = L._export_oci_layout_archive_for_testing(
        layout.resolve(),
        first_path.resolve(),
        expected_index_digest=image.index_digest,
        expected_manifest_digest=image.manifest_digest,
        expected_config_digest=image.config_digest,
        expected_apple_container_configuration_sha256=(
            image.apple_container_configuration_sha256
        ),
    )
    second = L._export_oci_layout_archive_for_testing(
        layout.resolve(),
        second_path.resolve(),
        expected_index_digest=image.index_digest,
        expected_manifest_digest=image.manifest_digest,
        expected_config_digest=image.config_digest,
        expected_apple_container_configuration_sha256=(
            image.apple_container_configuration_sha256
        ),
    )
    assert first == second
    assert first.index_digest == image.index_digest
    assert first.manifest_digest == image.manifest_digest
    assert first.config_digest == image.config_digest
    assert (
        first.apple_container_configuration_sha256
        == image.apple_container_configuration_sha256
    )
    assert first_path.read_bytes() == second_path.read_bytes()
    assert (
        L._verify_oci_layout_archive_for_testing(
            first_path.resolve(),
            expected_index_digest=image.index_digest,
            expected_manifest_digest=image.manifest_digest,
            expected_config_digest=image.config_digest,
            expected_apple_container_configuration_sha256=(
                image.apple_container_configuration_sha256
            ),
            expected_archive_sha256=first.archive_sha256,
        )
        == first
    )
    with pytest.raises(L.DeterministicOCILayoutError, match="index digest"):
        L._verify_oci_layout_archive_for_testing(
            first_path.resolve(),
            expected_index_digest="sha256:" + "d" * 64,
            expected_manifest_digest=image.manifest_digest,
            expected_archive_sha256=first.archive_sha256,
        )
    with pytest.raises(
        L.DeterministicOCILayoutError,
        match="Apple Container configuration",
    ):
        L._verify_oci_layout_archive_for_testing(
            first_path.resolve(),
            expected_index_digest=image.index_digest,
            expected_manifest_digest=image.manifest_digest,
            expected_config_digest=image.config_digest,
            expected_apple_container_configuration_sha256="f" * 64,
            expected_archive_sha256=first.archive_sha256,
        )

    first_path.chmod(0o600)
    tampered = bytearray(first_path.read_bytes())
    tampered[len(tampered) // 2] ^= 1
    first_path.write_bytes(tampered)
    first_path.chmod(0o444)
    with pytest.raises(L.DeterministicOCILayoutError, match="digest mismatch"):
        L._verify_oci_layout_archive_for_testing(
            first_path.resolve(),
            expected_index_digest=image.index_digest,
            expected_manifest_digest=image.manifest_digest,
            expected_archive_sha256=first.archive_sha256,
        )

    second_path.chmod(0o600)
    second_path.write_bytes(second_path.read_bytes() + b"\0" * tarfile.RECORDSIZE)
    second_path.chmod(0o444)
    with pytest.raises(L.DeterministicOCILayoutError, match="terminator extent"):
        L._verify_oci_layout_archive_for_testing(
            second_path.resolve(),
            expected_index_digest=image.index_digest,
            expected_manifest_digest=image.manifest_digest,
            expected_archive_sha256=_digest(second_path.read_bytes()),
        )


def test_outer_and_inner_archives_reject_noncanonical_gnu_magic(
    tmp_path: Path,
) -> None:
    _root, _lock, _installed, layout, image = _build(tmp_path)
    archive_path = tmp_path / "canonical.oci.tar"
    exported = L._export_oci_layout_archive_for_testing(
        layout.resolve(),
        archive_path.resolve(),
        expected_index_digest=image.index_digest,
        expected_manifest_digest=image.manifest_digest,
    )
    assert exported.archive_sha256 == _digest(archive_path.read_bytes())

    outer_variant = tmp_path / "gnu-magic.oci.tar"
    outer_variant.write_bytes(_gnu_magic_variant(archive_path.read_bytes()))
    outer_variant.chmod(0o444)
    with pytest.raises(L.DeterministicOCILayoutError, match="raw USTAR"):
        L._verify_oci_layout_archive_for_testing(
            outer_variant.resolve(),
            expected_index_digest=image.index_digest,
            expected_manifest_digest=image.manifest_digest,
            expected_archive_sha256=_digest(outer_variant.read_bytes()),
        )

    layer_path = (
        layout
        / "blobs"
        / "sha256"
        / image.layer_digest.removeprefix("sha256:")
    )
    changed_tar = _gnu_magic_variant(gzip.decompress(layer_path.read_bytes()))
    changed_layer = _deterministic_gzip(changed_tar)
    changed_name = _digest(changed_layer)
    blob_directory = tmp_path / "variant-blobs"
    blob_directory.mkdir()
    (blob_directory / changed_name).write_bytes(changed_layer)
    (blob_directory / changed_name).chmod(0o444)
    descriptor = os.open(
        blob_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        with pytest.raises(L.DeterministicOCILayoutError, match="raw USTAR"):
            L._verify_layer_tar(
                descriptor,
                {
                    "digest": "sha256:" + changed_name,
                    "mediaType": L.OCI_LAYER_MEDIA_TYPE,
                    "size": len(changed_layer),
                },
                "sha256:" + _digest(changed_tar),
            )
    finally:
        os.close(descriptor)


def test_post_publication_layout_substitution_preserves_precious_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, lock, _ = _fixture(tmp_path)
    output = tmp_path / "published-layout"
    retained = tmp_path / "retained-layout"
    original = L._revalidate_retained_layout

    def substitute(stage: L._StagedLayout) -> None:
        output.rename(retained)
        output.mkdir()
        (output / "precious").write_bytes(b"must survive cleanup")
        original(stage)

    monkeypatch.setattr(L, "_revalidate_retained_layout", substitute)
    with pytest.raises(
        L.DeterministicOCILayoutError, match="identity changed|substituted"
    ):
        L._build_oci_layout_for_testing(
            _plan(root, lock),
            output.resolve(),
            authenticated_external_fake_acknowledger=_ack,
        )
    assert (output / "precious").read_bytes() == b"must survive cleanup"
    assert retained.is_dir()


def test_post_publication_archive_substitution_is_detected_and_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _root, _lock, _installed, layout, image = _build(tmp_path)
    output = tmp_path / "published.tar"
    retained = tmp_path / "retained.tar"
    original = L._revalidate_published_archive

    def substitute(
        parent: int,
        output_name: str,
        retained_descriptor: int,
        retained_identity: tuple[int, int, int],
        expected_size: int,
        expected_sha256: str,
    ) -> None:
        output.rename(retained)
        output.write_bytes(b"precious archive substitute")
        output.chmod(0o444)
        original(
            parent,
            output_name,
            retained_descriptor,
            retained_identity,
            expected_size,
            expected_sha256,
        )

    monkeypatch.setattr(L, "_revalidate_published_archive", substitute)
    with pytest.raises(L.DeterministicOCILayoutError, match="identity changed"):
        L._export_oci_layout_archive_for_testing(
            layout.resolve(),
            output.resolve(),
            expected_manifest_digest=image.manifest_digest,
        )
    assert output.read_bytes() == b"precious archive substitute"
    assert retained.is_file()


def test_layout_verifier_replays_output_leaf_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _root, _lock, _installed, output, image = _build(tmp_path)
    retained = tmp_path / "retained-verified-layout"
    original = L._validate_installed_attestations
    attacked = False

    def substitute(payloads: dict[str, bytes], labels: dict[str, object]) -> None:
        nonlocal attacked
        original(payloads, labels)
        if not attacked:
            attacked = True
            output.rename(retained)
            output.mkdir()
            (output / "precious").write_bytes(b"attacker layout")

    monkeypatch.setattr(L, "_validate_installed_attestations", substitute)
    with pytest.raises(L.DeterministicOCILayoutError, match="substituted"):
        L._verify_oci_layout_for_testing(
            output.resolve(), expected_manifest_digest=image.manifest_digest
        )
    assert (output / "precious").read_bytes() == b"attacker layout"
    assert retained.is_dir()


def test_archive_verifier_replays_full_parent_ancestry_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _root, _lock, _installed, layout, image = _build(tmp_path)
    visible = tmp_path / "visible-verify-parent"
    visible.mkdir()
    archive_path = visible / "image.oci.tar"
    exported = L._export_oci_layout_archive_for_testing(
        layout.resolve(),
        archive_path.resolve(),
        expected_manifest_digest=image.manifest_digest,
    )
    moved = tmp_path / "moved-verify-parent"
    original = L._verify_oci_layout_for_testing
    attacked = False

    def substitute(*args: object, **kwargs: object) -> L.OCIImageLayoutResult:
        nonlocal attacked
        result = original(*args, **kwargs)
        if not attacked:
            attacked = True
            visible.rename(moved)
            visible.mkdir()
            (visible / archive_path.name).write_bytes(b"attacker archive")
        return result

    monkeypatch.setattr(L, "_verify_oci_layout_for_testing", substitute)
    with pytest.raises(L.DeterministicOCILayoutError, match="ancestry changed"):
        L._verify_oci_layout_archive_for_testing(
            archive_path.resolve(),
            expected_manifest_digest=image.manifest_digest,
            expected_archive_sha256=exported.archive_sha256,
        )
    assert archive_path.read_bytes() == b"attacker archive"
    assert (moved / archive_path.name).is_file()


def test_archive_export_replays_caller_parent_after_final_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _root, _lock, _installed, layout, image = _build(tmp_path)
    visible = tmp_path / "visible-publish-parent"
    visible.mkdir()
    output = visible / "image.oci.tar"
    moved = tmp_path / "moved-publish-parent"
    original = L._revalidate_published_archive

    def substitute(*args: object, **kwargs: object) -> None:
        original(*args, **kwargs)
        visible.rename(moved)
        visible.mkdir()
        output.write_bytes(b"attacker archive")

    monkeypatch.setattr(L, "_revalidate_published_archive", substitute)
    with pytest.raises(L.DeterministicOCILayoutError, match="ancestry changed"):
        L._export_oci_layout_archive_for_testing(
            layout.resolve(),
            output.resolve(),
            expected_manifest_digest=image.manifest_digest,
        )
    assert output.read_bytes() == b"attacker archive"
    assert (moved / output.name).is_file()


def test_archive_and_layout_publication_have_one_winner(tmp_path: Path) -> None:
    root, lock, _ = _fixture(tmp_path)
    output = tmp_path / "contended"
    plans = [_plan(root, lock, "a" * 64), _plan(root, lock, "b" * 64)]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                L._build_oci_layout_for_testing,
                plan,
                output.resolve(),
                authenticated_external_fake_acknowledger=_ack,
            )
            for plan in plans
        ]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except L.DeterministicOCILayoutError as exc:
                outcomes.append(exc)
    assert sum(isinstance(item, L.OCIImageLayoutResult) for item in outcomes) == 1
    assert sum(isinstance(item, L.DeterministicOCILayoutError) for item in outcomes) == 1
    winner = next(item for item in outcomes if isinstance(item, L.OCIImageLayoutResult))

    archive_output = tmp_path / "contended.tar"
    with ThreadPoolExecutor(max_workers=2) as executor:
        archive_futures = [
            executor.submit(
                L._export_oci_layout_archive_for_testing,
                output.resolve(),
                archive_output.resolve(),
                expected_manifest_digest=winner.manifest_digest,
            )
            for _ in range(2)
        ]
        archive_outcomes = []
        for future in archive_futures:
            try:
                archive_outcomes.append(future.result())
            except L.DeterministicOCILayoutError as exc:
                archive_outcomes.append(exc)
    assert sum(isinstance(item, L.OCIImageArchiveResult) for item in archive_outcomes) == 1
    assert sum(isinstance(item, L.DeterministicOCILayoutError) for item in archive_outcomes) == 1
    assert not list(tmp_path.glob(".plamen-oci-archive-*"))


def test_stale_publication_recovery_is_scoped_to_recorded_stage(
    tmp_path: Path,
) -> None:
    root, lock, _ = _fixture(tmp_path)
    output = tmp_path / "recovered"
    scope = _digest(output.name.encode())[:32]
    stage_name = f".plamen-oci-layout-stage-{scope}-{'a' * 32}"
    lock_name = f".plamen-oci-layout-{scope}.lock"
    stale_stage = tmp_path / stage_name
    stale_stage.mkdir(mode=0o700)
    (stale_stage / "partial").write_bytes(b"partial")
    stale_lock = tmp_path / lock_name
    stale_lock.write_bytes(
        _json(
            {
                "kind": "layout",
                "pid": 999999,
                "schema_version": "plamen.oci_publication_lock.v1",
                "stage_name": stage_name,
            }
        )
    )
    stale_lock.chmod(0o600)
    result = L._build_oci_layout_for_testing(
        _plan(root, lock),
        output.resolve(),
        authenticated_external_fake_acknowledger=_ack,
    )
    assert output.is_dir()
    assert result.manifest_digest == lock["image"]["manifest_digest"]
    assert not stale_stage.exists()
    assert not stale_lock.exists()

    archive = tmp_path / "recovered.tar"
    archive_scope = _digest(archive.name.encode())[:32]
    archive_stage_name = (
        f".plamen-oci-archive-stage-{archive_scope}-{'b' * 32}"
    )
    archive_lock_name = f".plamen-oci-archive-{archive_scope}.lock"
    archive_stage = tmp_path / archive_stage_name
    archive_stage.write_bytes(b"partial")
    archive_lock = tmp_path / archive_lock_name
    archive_lock.write_bytes(
        _json(
            {
                "kind": "archive",
                "pid": 999999,
                "schema_version": "plamen.oci_publication_lock.v1",
                "stage_name": archive_stage_name,
            }
        )
    )
    archive_lock.chmod(0o600)
    L._export_oci_layout_archive_for_testing(
        output.resolve(),
        archive.resolve(),
        expected_manifest_digest=result.manifest_digest,
    )
    assert archive.is_file()
    assert not archive_stage.exists()
    assert not archive_lock.exists()


def test_stale_recovery_refuses_hardlinked_stage_files(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.write_bytes(b"must not be chmodded or unlinked")
    external.chmod(0o444)
    stage = tmp_path / ".plamen-oci-layout-stage-scope-dead"
    stage.mkdir(mode=0o700)
    os.link(external, stage / "linked")
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(L.DeterministicOCILayoutError, match="identity is unsafe"):
            L._remove_recovery_stage(parent, stage.name, directory=True)
    finally:
        os.close(parent)
    assert external.read_bytes() == b"must not be chmodded or unlinked"
    assert stat.S_IMODE(external.stat().st_mode) == 0o444
    assert stage.exists()


def test_native_no_replace_preserves_racing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, lock, _ = _fixture(tmp_path)
    output = tmp_path / "raced"
    original = L._rename_noreplace

    def inject_race(
        source_parent: int,
        source_name: str,
        destination_parent: int,
        destination_name: str,
    ) -> None:
        if destination_name == output.name:
            output.mkdir()
            (output / "belongs-to-racer").write_bytes(b"preserve")
        original(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
        )

    monkeypatch.setattr(L, "_rename_noreplace", inject_race)
    with pytest.raises(L.DeterministicOCILayoutError, match="already exists"):
        L._build_oci_layout_for_testing(
            _plan(root, lock),
            output.resolve(),
            authenticated_external_fake_acknowledger=_ack,
        )
    assert (output / "belongs-to-racer").read_bytes() == b"preserve"
    assert not list(tmp_path.glob(".plamen-oci-layout-stage-*"))


def test_injected_write_failure_is_atomic_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, lock, _ = _fixture(tmp_path)
    original = L._write_file_at
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("SENSITIVE_WRITE_FAILURE")
        return original(*args, **kwargs)

    monkeypatch.setattr(L, "_write_file_at", fail_once)
    failed_output = tmp_path / "failed"
    with pytest.raises(L.DeterministicOCILayoutError) as raised:
        L._build_oci_layout_for_testing(
            _plan(root, lock),
            failed_output.resolve(),
            authenticated_external_fake_acknowledger=_ack,
        )
    assert "SENSITIVE_WRITE_FAILURE" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert not failed_output.exists()
    assert not list(tmp_path.glob(".plamen-oci-layout-*"))


def test_reader_streams_more_than_24_mib_without_unbounded_request() -> None:
    total = 24 * 1024 * 1024 + 17

    class Reader:
        def __init__(self) -> None:
            self.remaining = total
            self.maximum = 0

        def read(self, size: int) -> bytes:
            self.maximum = max(self.maximum, size)
            if self.remaining == 0:
                return b""
            amount = min(size, self.remaining)
            self.remaining -= amount
            return b"x" * amount

    reader = Reader()
    spool, digest = L._copy_exact_to_spool(reader, total, label="large vector")
    try:
        assert reader.maximum <= L._READ_CHUNK
        streamed = hashlib.sha256()
        for _ in range(total // L._READ_CHUNK):
            streamed.update(b"x" * L._READ_CHUNK)
        streamed.update(b"x" * (total % L._READ_CHUNK))
        assert digest == streamed.hexdigest()
        assert spool.seek(0, os.SEEK_END) == total
    finally:
        spool.close()


@pytest.mark.parametrize(
    "acknowledger,pattern",
    [
        (lambda _receipt: b'{"schema_version":', "malformed"),
        (lambda _receipt: True, "canonical bytes"),
        (
            lambda receipt: (
                b'{"receipt_sha256":"'
                + hashlib.sha256(receipt).hexdigest().encode()
                + b'","schema_version":"plamen.oci_layout_read_ack.v1",'
                + b'"status":"ACCEPTED","status":"ACCEPTED"}\n'
            ),
            "duplicate JSON key",
        ),
    ],
)
def test_read_completion_ack_is_strict_and_atomic(
    tmp_path: Path, acknowledger, pattern: str
) -> None:
    root, lock, _ = _fixture(tmp_path)
    output = tmp_path / "bad-ack"
    with pytest.raises(L.DeterministicOCILayoutError, match=pattern):
        L._build_oci_layout_for_testing(
            _plan(root, lock),
            output.resolve(),
            authenticated_external_fake_acknowledger=acknowledger,
        )
    assert not output.exists()
    assert not list(tmp_path.glob(".plamen-oci-layout-*"))
