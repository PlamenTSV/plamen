from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_loader_closure as C
import deterministic_oci_layout as L


STAGED_LAYER = Path(
    "/private/tmp/plamen-runtime-inputs/debian-bookworm-slim-arm64-layer.tar.gz"
)
DERIVED_SHA256 = "70b69e00fbe608f857f0cc44b0b4b504423fe9008df287d260760ed2a84da7f0"
DERIVED_DIFF_ID = "819f5c7a0170514b424e5a272bafe78bb28d5c5a66cb04c624545bd7797553a9"
DERIVED_SIZE = 100_236_788
MANIFEST_SHA256 = "0960d7dd99bbd7acc6027579118eb1f8402400f888c35df095cebd949811edf3"


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.fixture(scope="session")
def exact_derivation(tmp_path_factory: pytest.TempPathFactory):
    if not STAGED_LAYER.is_file():
        pytest.skip("exact pinned Debian layer is not staged")
    folder = tmp_path_factory.mktemp("cache-free-rootfs")
    output = folder / "derived.tar.gz"
    source_before = _sha256_path(STAGED_LAYER)
    source_fd = os.open(STAGED_LAYER, os.O_RDONLY)
    output_fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        result = C.derive_cache_free_rootfs(
            source_fd,
            output_fd,
            authenticated_provenance=C.pinned_provenance_bytes(),
        )
    finally:
        os.close(output_fd)
        os.close(source_fd)
    assert source_before == _sha256_path(STAGED_LAYER) == C.SOURCE_LAYER_SHA256
    return output, result


def test_exact_pinned_layer_derives_golden_cache_free_archive(exact_derivation) -> None:
    output, result = exact_derivation
    assert C.DERIVED_LAYER_SHA256 == DERIVED_SHA256
    assert C.DERIVED_DIFF_ID == DERIVED_DIFF_ID
    assert C.DERIVED_LAYER_SIZE == DERIVED_SIZE
    assert C.DERIVATION_MANIFEST_SHA256 == MANIFEST_SHA256
    assert result.schema_version == C.SCHEMA_VERSION
    assert result.status == "CONTENT_DERIVED_PENDING_NATIVE_HANDOFF_AND_TRANSITIVE_ELF_PROOF"
    assert result.derived_sha256 == DERIVED_SHA256
    assert result.derived_diff_id == DERIVED_DIFF_ID
    assert result.derived_size == DERIVED_SIZE
    assert result.entry_count == 4_218
    assert result.removed_cache_sha256 == (
        "4f3163cd39f4dfd4669e9c79e71bc6f04a4c8275658211671ed2b740c0ec434f"
    )
    assert result.manifest_sha256 == MANIFEST_SHA256
    assert _sha256_path(output) == DERIVED_SHA256

    manifest = json.loads(result.manifest_bytes)
    assert manifest["production_authority"] is False
    assert manifest["closure_contract"]["hwcaps_directories"] == "FORBIDDEN"
    assert manifest["closure_contract"]["transitive_elf_status"] == (
        "REQUIRES_SAME_FD_DOWNSTREAM_PROOF"
    )
    assert manifest["closure_contract"]["generic_linux_inputs"] == (
        "REJECTED_UNLESS_EXACT_RECIPE_MATCHES"
    )
    assert manifest["closure_contract"]["required_environment_denials"] == {
        "exact_names": ["GLIBC_TUNABLES"],
        "prefixes": ["LD_"],
    }
    with tarfile.open(output, "r:gz") as archive:
        names = {item.name for item in archive}
    assert "etc/ld.so.cache" not in names
    assert "etc/ld.so.preload" not in names
    assert not any(C._is_forbidden_hwcaps_path(name) for name in names)


def test_independent_verifier_replays_exact_manifest(exact_derivation) -> None:
    output, result = exact_derivation
    descriptor = os.open(output, os.O_RDONLY)
    try:
        verified = C.verify_cache_free_rootfs(
            descriptor,
            manifest_bytes=result.manifest_bytes,
        )
    finally:
        os.close(descriptor)
    assert verified == result


def test_accepted_oci_parser_consumes_derivation_without_cache_blocker(exact_derivation) -> None:
    output, result = exact_derivation
    raw = output.read_bytes()
    row = L._InputMetadata(
        "runtime/complete-rootfs.tar.gz",
        hashlib.sha256(raw).hexdigest(),
        len(raw),
        0o444,
    )
    entries: list[L._ExpandedEntry] = []
    archive_diff_ids: dict[str, str] = {}
    shared_spool = tempfile.TemporaryFile(mode="w+b")
    try:
        L._expand_archive(
            L._ReaderAdapter(L._BytesReader(raw), row),
            row,
            entries=entries,
            files=set(),
            directories=set(),
            aliases={},
            expanded_total=[0],
            payload_spool=shared_spool,
            archive_diff_ids=archive_diff_ids,
            install_kind="rootfs_archive",
            identifier="complete-rootfs",
        )
        assert archive_diff_ids["complete-rootfs"] == "sha256:" + result.derived_diff_id
        assert "etc/ld.so.cache" not in {entry.path for entry in entries}
        with pytest.raises(
            L.DeterministicOCILayoutError,
            match="required runtime root",
        ) as stopped:
            L._validate_runtime_dependencies(entries)
        assert "ld.so.cache" not in str(stopped.value)
    finally:
        for entry in entries:
            if entry.source is not None:
                entry.source.close()
        shared_spool.close()


def test_recipe_is_byte_deterministic(exact_derivation, tmp_path: Path) -> None:
    first, first_result = exact_derivation
    second = tmp_path / "second.tar.gz"
    source_fd = os.open(STAGED_LAYER, os.O_RDONLY)
    output_fd = os.open(second, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        second_result = C.derive_cache_free_rootfs(
            source_fd,
            output_fd,
            authenticated_provenance=C.pinned_provenance_bytes(),
        )
    finally:
        os.close(output_fd)
        os.close(source_fd)
    assert second_result == first_result
    assert first.read_bytes() == second.read_bytes()


def test_post_write_permission_mutation_is_rejected(monkeypatch, tmp_path: Path) -> None:
    if not STAGED_LAYER.is_file():
        pytest.skip("exact pinned Debian layer is not staged")
    original = C._write_all_at

    def mutate_after_write(descriptor: int, data: bytes) -> None:
        original(descriptor, data)
        os.fchmod(descriptor, 0o666)

    monkeypatch.setattr(C, "_write_all_at", mutate_after_write)
    output = tmp_path / "mutated.tar.gz"
    source_fd = os.open(STAGED_LAYER, os.O_RDONLY)
    output_fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="identity changed"):
            C.derive_cache_free_rootfs(
                source_fd,
                output_fd,
                authenticated_provenance=C.pinned_provenance_bytes(),
            )
        assert stat.S_IMODE(os.fstat(output_fd).st_mode) == 0o666
    finally:
        os.fchmod(output_fd, 0o600)
        os.close(output_fd)
        os.close(source_fd)


def test_provenance_is_exact_canonical_and_generic_inputs_fail_prewrite(tmp_path: Path) -> None:
    value = json.loads(C.pinned_provenance_bytes())
    value["source_reference"] = value["source_reference"].replace(
        "bookworm-20260824-slim", "bookworm-slim"
    )
    forged = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    source = tmp_path / "source"
    source.write_bytes(b"not a pinned layer")
    output = tmp_path / "output"
    source_fd = os.open(source, os.O_RDONLY)
    output_fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="exact pinned Debian closure"):
            C.derive_cache_free_rootfs(
                source_fd,
                output_fd,
                authenticated_provenance=forged,
            )
        assert os.fstat(output_fd).st_size == 0
    finally:
        os.close(output_fd)
        os.close(source_fd)

    noncanonical = json.dumps(json.loads(C.pinned_provenance_bytes()), indent=2).encode()
    with pytest.raises(C.ELFLoaderClosureError, match="not canonical JSON"):
        C._strict_provenance(noncanonical)


def test_wrong_layer_and_output_constraints_fail_before_mutation(tmp_path: Path) -> None:
    wrong = tmp_path / "wrong"
    wrong.write_bytes(b"x" * C.SOURCE_LAYER_SIZE)
    output = tmp_path / "output"
    source_fd = os.open(wrong, os.O_RDONLY)
    output_fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="digest does not match"):
            C.derive_cache_free_rootfs(
                source_fd,
                output_fd,
                authenticated_provenance=C.pinned_provenance_bytes(),
            )
        assert os.fstat(output_fd).st_size == 0
    finally:
        os.close(output_fd)
        os.close(source_fd)

    output.write_bytes(b"occupied")
    source_fd = os.open(wrong, os.O_RDONLY)
    output_fd = os.open(output, os.O_RDWR)
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="initially empty"):
            C.derive_cache_free_rootfs(
                source_fd,
                output_fd,
                authenticated_provenance=C.pinned_provenance_bytes(),
            )
        assert os.pread(output_fd, 8, 0) == b"occupied"
    finally:
        os.close(output_fd)
        os.close(source_fd)


def test_source_must_be_read_only_and_descriptors_cannot_alias(tmp_path: Path) -> None:
    file = tmp_path / "file"
    file.write_bytes(b"anything")
    descriptor = os.open(file, os.O_RDWR)
    other = tmp_path / "other"
    output_fd = os.open(other, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="read-only"):
            C._require_descriptor_modes(descriptor, output_fd)
        with pytest.raises(C.ELFLoaderClosureError, match="alias"):
            C._require_descriptor_modes(descriptor, descriptor)
    finally:
        os.close(output_fd)
        os.close(descriptor)

    source_fd = os.open(file, os.O_RDONLY)
    public = tmp_path / "public"
    public_fd = os.open(public, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o644)
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="owner-private"):
            C._require_descriptor_modes(source_fd, public_fd)
    finally:
        os.close(public_fd)
        os.close(source_fd)

    source_fd = os.open(file, os.O_RDONLY)
    appended = tmp_path / "appended"
    appended_fd = os.open(
        appended,
        os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_APPEND,
        0o600,
    )
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="must not append"):
            C._require_descriptor_modes(source_fd, appended_fd)
    finally:
        os.close(appended_fd)
        os.close(source_fd)


def test_missing_posix_authority_hardstops_before_descriptor_inspection(monkeypatch) -> None:
    observed = []
    monkeypatch.setattr(C, "_fcntl", None)
    monkeypatch.setattr(C, "_fd_identity", lambda *_args: observed.append(True))
    with pytest.raises(C.ELFLoaderClosureError, match="POSIX descriptor authority"):
        C._require_descriptor_modes(-1, -1)
    assert observed == []


def _tar_bytes(entries: list[tuple[str, bytes | None, bytes, str]]) -> io.BytesIO:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload, kind, target in entries:
            item = tarfile.TarInfo(name)
            item.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            item.uid = item.gid = 0
            item.mtime = 0
            item.type = kind
            if kind == tarfile.REGTYPE:
                assert payload is not None
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            else:
                item.size = 0
                item.linkname = target
                archive.addfile(item)
    raw.seek(0)
    return raw


@pytest.mark.parametrize(
    "name",
    ["../escape", "/absolute", "a//b", "a/./b", "a/../b", "not-nfc-e\u0301"],
)
def test_member_name_traversal_and_ambiguity_rejected(name: str) -> None:
    raw = _tar_bytes([(name, b"x", tarfile.REGTYPE, "")])
    with pytest.raises(C.ELFLoaderClosureError):
        C._parse_members(raw)


def test_duplicate_casefold_names_and_special_members_rejected() -> None:
    duplicate = _tar_bytes(
        [
            ("usr/lib/Thing", b"a", tarfile.REGTYPE, ""),
            ("usr/lib/thing", b"b", tarfile.REGTYPE, ""),
        ]
    )
    with pytest.raises(C.ELFLoaderClosureError, match="duplicate or ambiguous"):
        C._parse_members(duplicate)

    special = _tar_bytes([("device", None, tarfile.CHRTYPE, "")])
    with pytest.raises(C.ELFLoaderClosureError, match="special or unsupported"):
        C._parse_members(special)

    whiteout = _tar_bytes([("etc/.wh.ld.so.cache", b"", tarfile.REGTYPE, "")])
    with pytest.raises(C.ELFLoaderClosureError, match="whiteouts"):
        C._parse_members(whiteout)


@pytest.mark.parametrize(
    ("member", "target"),
    [
        ("link", "../escape"),
        ("usr/lib/link", "../../../escape"),
        ("usr/lib/link", ""),
    ],
)
def test_escaping_and_malformed_links_rejected(member: str, target: str) -> None:
    raw = _tar_bytes([(member, None, tarfile.SYMTYPE, target)])
    with pytest.raises(C.ELFLoaderClosureError):
        C._parse_members(raw)


def test_hardlinks_are_archive_root_relative() -> None:
    raw = _tar_bytes(
        [
            ("usr/bin/tool", b"payload", tarfile.REGTYPE, ""),
            ("usr/bin/tool2", None, tarfile.LNKTYPE, "usr/bin/tool"),
        ]
    )
    archive, members = C._parse_members(raw)
    try:
        by_name = {member.name: member for member in members}
        resolved = C._resolve_member("usr/bin/tool2", by_name, require_file=True)
        assert resolved.name == "usr/bin/tool"
    finally:
        archive.close()


@pytest.mark.parametrize(
    "path",
    [
        "lib/aarch64-linux-gnu/glibc-hwcaps/aarch64-v9/libc.so.6",
        "usr/lib/aarch64-linux-gnu/tls/libc.so.6",
        "lib/atomics/libc.so.6",
    ],
)
def test_hwcaps_and_legacy_capability_directories_rejected(path: str) -> None:
    assert C._is_forbidden_hwcaps_path(path)
    assert not C._is_forbidden_hwcaps_path("opt/plamen/glibc-hwcaps/data")


def _elf(machine: int) -> bytes:
    value = bytearray(64)
    value[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", value, 18, machine)
    return bytes(value)


def test_arm64_elf_check_is_structural_and_never_uses_host_loader() -> None:
    C._require_arm64_elf(_elf(183), "fixture")
    with pytest.raises(C.ELFLoaderClosureError, match="not Linux arm64 ELF"):
        C._require_arm64_elf(_elf(62), "fixture")
    with pytest.raises(C.ELFLoaderClosureError, match="not ELF"):
        C._require_arm64_elf(b"#!/bin/sh\n", "fixture")


def test_glibc_status_requires_exact_unique_installed_arm64_package() -> None:
    valid = (
        "Package: libc6\nStatus: install ok installed\nArchitecture: arm64\n"
        f"Version: {C.GLIBC_PACKAGE_VERSION}\n\n"
    ).encode()
    C._require_glibc_status(valid)
    with pytest.raises(C.ELFLoaderClosureError, match="one libc6"):
        C._require_glibc_status(valid + valid)
    with pytest.raises(C.ELFLoaderClosureError, match="pinned arm64 glibc"):
        C._require_glibc_status(valid.replace(b"arm64", b"amd64"))


def test_canonical_gzip_uses_stored_blocks_and_stable_header() -> None:
    raw = io.BytesIO(b"a" * 70_000)
    first = C._canonical_gzip_stored(raw)
    second = C._canonical_gzip_stored(io.BytesIO(b"a" * 70_000))
    assert first == second
    assert first[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
    assert gzip.decompress(first) == b"a" * 70_000
    assert hashlib.sha256(first).hexdigest() == (
        "e4d017f3b3b264417d0f6c39264a95d044f6fb1fa9268357dbf19a765bcc5dfb"
    )


def test_manifest_and_archive_tampering_are_rejected(exact_derivation, tmp_path: Path) -> None:
    output, result = exact_derivation
    value = json.loads(result.manifest_bytes)
    value["production_authority"] = True
    forged_manifest = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    descriptor = os.open(output, os.O_RDONLY)
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="forbidden production authority"):
            C.verify_cache_free_rootfs(descriptor, manifest_bytes=forged_manifest)
    finally:
        os.close(descriptor)

    tampered = tmp_path / "tampered.tar.gz"
    data = bytearray(output.read_bytes())
    data[len(data) // 2] ^= 1
    tampered.write_bytes(data)
    descriptor = os.open(tampered, os.O_RDONLY)
    try:
        with pytest.raises(C.ELFLoaderClosureError, match="not bound by the manifest"):
            C.verify_cache_free_rootfs(descriptor, manifest_bytes=result.manifest_bytes)
    finally:
        os.close(descriptor)


def test_return_value_cannot_claim_production_authority(exact_derivation) -> None:
    _output, result = exact_derivation
    assert not hasattr(result, "production_authority")
    with pytest.raises((AttributeError, TypeError)):
        result.status = "PRODUCTION"
