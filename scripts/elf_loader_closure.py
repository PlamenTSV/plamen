"""Authenticated cache-free rootfs derivation for the pinned Debian guest.

This module removes exactly ``/etc/ld.so.cache`` from the authenticated
Docker Official Image layer used by Plamen and emits a deterministic gzip
USTAR archive plus a content manifest.  It deliberately does *not* mint a
release, pathname, or execution authority.  A production caller must retain
the returned output descriptor, bind the manifest in the release context,
and run the ordinary recursive ELF/shebang closure verifier over that same
descriptor before it can publish or execute the image.

The recipe is intentionally not generic.  Dynamic-loader cache and hardware
capability selection vary by loader, architecture, and glibc release.  Inputs
other than the exact pinned Debian arm64 layer and glibc package fail closed.
The recipe also rejects every hardware-capability directory so the subsequent
ELF closure proof has one deterministic, cache-free search namespace.

No host dynamic loader is invoked and no pathname is trusted.  All source and
destination I/O is descriptor-relative.  The function is a content
transformation only; production descriptor handoff remains a native-authority
integration requirement.
"""

from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import hmac
import io
import json
import os
import stat
import struct
import tarfile
import tempfile
from typing import Any, BinaryIO, Mapping
import unicodedata
import zlib

try:  # pragma: no cover - exercised by import simulation tests
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows production hard-stop
    _fcntl = None


SCHEMA_VERSION = "plamen.cache_free_rootfs_derivation.v1"
RECIPE_VERSION = "plamen.debian_arm64_cache_free.v1"
PROVENANCE_SCHEMA_VERSION = "plamen.complete_rootfs_provenance.v1"
AUTHENTICATION_SCOPE = "REGISTRY_TLS_EXACT_DIGESTS"

SOURCE_REFERENCE = (
    "docker.io/library/debian:bookworm-20260824-slim@"
    "sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
)
SOURCE_LAYER_SHA256 = "75782e20ea1f4a9d9259bc20a5ecbbea8d5943bf5370bf0f5727900728f1cc9a"
SOURCE_LAYER_SIZE = 28_117_289
SOURCE_DIFF_ID = "13a56b6535801be2adde694dabaf1c2df1d862a390661907dac821c42cd565cc"
SOURCE_TAR_SIZE = 100_229_120
GLIBC_PACKAGE_VERSION = "2.36-9+deb12u14"
GLIBC_SOURCE_REFERENCE = (
    "https://sources.debian.org/src/glibc/"
    "2.36-9%2Bdeb12u14/sysdeps/unix/sysv/linux/aarch64/dl-procinfo.h"
)

_PINNED_PROVENANCE: Mapping[str, Any] = {
    "authentication_scope": AUTHENTICATION_SCOPE,
    "config_digest": "sha256:32d322b19846336d25f755f73618a448e3621982d52c48064e95af8b3dcbc2d9",
    "config_size": 468,
    "index_digest": "sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",
    "index_size": 5_651,
    "layer_digest": "sha256:" + SOURCE_LAYER_SHA256,
    "layer_diff_id": "sha256:" + SOURCE_DIFF_ID,
    "layer_size": SOURCE_LAYER_SIZE,
    "manifest_digest": "sha256:6bd27d44e6c32a66bbd72d7cb2b76a8ae3497ec2e5274a81abd1b37f6013fa1f",
    "manifest_size": 1_041,
    "official_images_commit": "b9c995a1c91bf8b195b035893ebdf8e877e7f7fa",
    "official_images_sha256": "6d254035660febfa46162fc76a1a148f217387677ff740a5bf1ed3c35aabb443",
    "platform": "linux/arm64/v8",
    "schema_version": PROVENANCE_SCHEMA_VERSION,
    "source_reference": SOURCE_REFERENCE,
}

_DEFAULT_LIBRARY_DIRS = (
    "lib/aarch64-linux-gnu",
    "usr/lib/aarch64-linux-gnu",
    "lib",
    "usr/lib",
)
_FORBIDDEN_ENV_PREFIXES = ("LD_",)
_FORBIDDEN_ENV_NAMES = ("GLIBC_TUNABLES",)
_FORBIDDEN_HWCAP_COMPONENTS = frozenset({"glibc-hwcaps", "tls", "atomics"})
_MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
_MAX_ENTRIES = 8_192
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_PATH_BYTES = 4_096
_MAX_COMPONENT_BYTES = 255
_MAX_LINK_DEPTH = 40
_READ_CHUNK = 1024 * 1024
_CACHE_PATH = "etc/ld.so.cache"
_PRELOAD_PATH = "etc/ld.so.preload"
_LOADER_PATH = "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
_LIBC_PATH = "usr/lib/aarch64-linux-gnu/libc.so.6"
_DPKG_STATUS_PATH = "var/lib/dpkg/status"
_ELF_MACHINE_AARCH64 = 183
DERIVED_LAYER_SHA256 = "70b69e00fbe608f857f0cc44b0b4b504423fe9008df287d260760ed2a84da7f0"
DERIVED_LAYER_SIZE = 100_236_788
DERIVED_DIFF_ID = "819f5c7a0170514b424e5a272bafe78bb28d5c5a66cb04c624545bd7797553a9"
_DERIVED_TAR_SIZE = 100_229_120
_DERIVED_CENSUS_SHA256 = "3d90ba706639fde6be674a520875aff6bcbc8f3a82dca8e35bf47bb090242112"
_DERIVED_ENTRY_COUNT = 4_218
_REMOVED_CACHE_SHA256 = "4f3163cd39f4dfd4669e9c79e71bc6f04a4c8275658211671ed2b740c0ec434f"
_REMOVED_CACHE_SIZE = 4_587
_LOADER_SHA256 = "17538b8f9889a470c061f69a8fea8124da89627311cd16546c133a89f09056df"
_LIBC_SHA256 = "e4ac8ae1d81e4865e3aadedb962879cf9415903b3f2ba81ec75e9962b86ab8b0"
_DPKG_STATUS_SHA256 = "437c37c0391ace1b7376ad3ae9cae0ab55e81d111ccc72fca8f5d0f4226992c8"
DERIVATION_MANIFEST_SHA256 = "0960d7dd99bbd7acc6027579118eb1f8402400f888c35df095cebd949811edf3"


class ELFLoaderClosureError(RuntimeError):
    """The cache-free loader proof cannot be established."""


@dataclass(frozen=True, slots=True)
class CacheFreeRootfsDerivation:
    """Content facts only; this value is never a publication capability."""

    schema_version: str
    status: str
    source_sha256: str
    source_size: int
    source_diff_id: str
    source_tar_size: int
    derived_sha256: str
    derived_size: int
    derived_diff_id: str
    derived_tar_size: int
    census_sha256: str
    entry_count: int
    removed_cache_sha256: str
    removed_cache_size: int
    loader_sha256: str
    libc_sha256: str
    manifest_sha256: str
    manifest_bytes: bytes


@dataclass(frozen=True, slots=True)
class _FDIdentity:
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int
    nlink: int


@dataclass(frozen=True, slots=True)
class _Member:
    name: str
    kind: str
    mode: int
    uid: int
    gid: int
    size: int
    linkname: str
    source: tarfile.TarInfo


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fd_identity(fd: int, label: str) -> _FDIdentity:
    if type(fd) is not int or fd < 0:
        raise ELFLoaderClosureError(f"{label} descriptor is invalid")
    try:
        value = os.fstat(fd)
    except OSError as error:
        raise ELFLoaderClosureError(f"{label} descriptor cannot be inspected") from error
    if not stat.S_ISREG(value.st_mode):
        raise ELFLoaderClosureError(f"{label} descriptor is not a regular file")
    return _FDIdentity(
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_nlink,
    )


def _require_descriptor_modes(source_fd: int, output_fd: int) -> tuple[_FDIdentity, _FDIdentity]:
    if _fcntl is None or os.name != "posix":
        raise ELFLoaderClosureError("POSIX descriptor authority is unavailable")
    source = _fd_identity(source_fd, "source")
    output = _fd_identity(output_fd, "output")
    if (source.dev, source.ino) == (output.dev, output.ino):
        raise ELFLoaderClosureError("source and output descriptors alias")
    try:
        source_flags = _fcntl.fcntl(source_fd, _fcntl.F_GETFL)
        output_flags = _fcntl.fcntl(output_fd, _fcntl.F_GETFL)
    except OSError as error:
        raise ELFLoaderClosureError("descriptor access modes cannot be inspected") from error
    if source_flags & os.O_ACCMODE != os.O_RDONLY:
        raise ELFLoaderClosureError("source descriptor must be read-only")
    if output_flags & os.O_ACCMODE != os.O_RDWR:
        raise ELFLoaderClosureError("output descriptor must be read-write")
    if output_flags & getattr(os, "O_APPEND", 0):
        raise ELFLoaderClosureError("output descriptor must not append")
    if output.size != 0:
        raise ELFLoaderClosureError("output descriptor must be initially empty")
    if output.nlink > 1:
        raise ELFLoaderClosureError("output descriptor has multiple hard links")
    if output.uid != os.geteuid() or stat.S_IMODE(output.mode) != 0o600:
        raise ELFLoaderClosureError("output descriptor is not owner-private")
    return source, output


def _read_exact_fd(fd: int, expected_size: int, label: str) -> bytes:
    if expected_size > _MAX_ARCHIVE_BYTES:
        raise ELFLoaderClosureError(f"{label} exceeds the byte limit")
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        try:
            chunk = os.pread(fd, min(_READ_CHUNK, expected_size - offset), offset)
        except OSError as error:
            raise ELFLoaderClosureError(f"{label} cannot be read") from error
        if not chunk:
            raise ELFLoaderClosureError(f"{label} was truncated")
        chunks.append(chunk)
        offset += len(chunk)
    try:
        extra = os.pread(fd, 1, expected_size)
    except OSError as error:
        raise ELFLoaderClosureError(f"{label} cannot be read") from error
    if extra:
        raise ELFLoaderClosureError(f"{label} grew during observation")
    return b"".join(chunks)


def _strict_provenance(raw: bytes) -> Mapping[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
        raise ELFLoaderClosureError("authenticated provenance bytes are invalid")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ELFLoaderClosureError("authenticated provenance is malformed") from error
    if type(value) is not dict or value != _PINNED_PROVENANCE:
        raise ELFLoaderClosureError("provenance is not the exact pinned Debian closure")
    if not hmac.compare_digest(raw, _canonical_json(value)):
        raise ELFLoaderClosureError("authenticated provenance is not canonical JSON")
    return value


def pinned_provenance_bytes() -> bytes:
    """Return the sole provenance document accepted by this recipe."""

    return _canonical_json(_PINNED_PROVENANCE)


def _normalize_name(raw: str, *, allow_root: bool = False) -> str:
    if not isinstance(raw, str) or not raw or "\x00" in raw or "\\" in raw:
        raise ELFLoaderClosureError("archive member name is malformed")
    if raw == "." and allow_root:
        return "."
    if raw.startswith("/") or raw.endswith("/"):
        raise ELFLoaderClosureError("archive member name is not canonical")
    parts = raw.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ELFLoaderClosureError("archive member name traverses or is ambiguous")
    if len(raw.encode("utf-8")) > _MAX_PATH_BYTES:
        raise ELFLoaderClosureError("archive member path is too long")
    for part in parts:
        encoded = part.encode("utf-8")
        if len(encoded) > _MAX_COMPONENT_BYTES:
            raise ELFLoaderClosureError("archive member component is too long")
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise ELFLoaderClosureError("archive member name contains control bytes")
        if unicodedata.normalize("NFC", part) != part:
            raise ELFLoaderClosureError("archive member name is not NFC-normalized")
    return raw


def _resolved_link(
    member_name: str,
    raw_target: str,
    *,
    hardlink: bool = False,
) -> str:
    if not isinstance(raw_target, str) or not raw_target or "\x00" in raw_target:
        raise ELFLoaderClosureError("archive link target is malformed")
    if "\\" in raw_target or len(raw_target.encode("utf-8")) > _MAX_PATH_BYTES:
        raise ELFLoaderClosureError("archive link target is malformed")
    # POSIX tar hard-link names are archive-root-relative.  Symbolic-link
    # names retain filesystem semantics and are relative to the link's parent
    # unless they begin with '/'.
    candidate = (
        raw_target.lstrip("/")
        if raw_target.startswith("/") or hardlink
        else "/".join(member_name.split("/")[:-1] + [raw_target])
    )
    stack: list[str] = []
    for part in candidate.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise ELFLoaderClosureError("archive link target escapes the rootfs")
            stack.pop()
            continue
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise ELFLoaderClosureError("archive link target contains control bytes")
        stack.append(part)
    if not stack:
        raise ELFLoaderClosureError("archive link target resolves to the root")
    return "/".join(stack)


def _kind(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    raise ELFLoaderClosureError("archive contains a special or unsupported member")


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if member.size < 0 or member.size > _MAX_FILE_BYTES:
        raise ELFLoaderClosureError("archive member exceeds the byte limit")
    stream = archive.extractfile(member)
    if stream is None:
        raise ELFLoaderClosureError("regular archive member has no payload")
    data = stream.read(member.size + 1)
    if len(data) != member.size:
        raise ELFLoaderClosureError("archive member payload is truncated")
    if len(data) > member.size:
        raise ELFLoaderClosureError("archive member payload exceeds its header")
    return data


def _parse_members(raw_tar: BinaryIO) -> tuple[tarfile.TarFile, tuple[_Member, ...]]:
    try:
        archive = tarfile.open(fileobj=raw_tar, mode="r:")
    except (tarfile.TarError, OSError) as error:
        raise ELFLoaderClosureError("source layer is not a readable tar archive") from error
    members: list[_Member] = []
    exact_names: set[str] = set()
    ambiguous_names: set[str] = set()
    try:
        for index, item in enumerate(archive):
            if index >= _MAX_ENTRIES:
                raise ELFLoaderClosureError("source layer has too many members")
            name = _normalize_name(item.name, allow_root=True)
            if name == ".":
                if not item.isdir() or members:
                    raise ELFLoaderClosureError("root archive member is malformed")
                continue
            if any(part.startswith(".wh.") for part in name.split("/")):
                raise ELFLoaderClosureError("complete-root recipe forbids OCI whiteouts")
            folded = unicodedata.normalize("NFC", name).casefold()
            if name in exact_names or folded in ambiguous_names:
                raise ELFLoaderClosureError("source layer has duplicate or ambiguous names")
            exact_names.add(name)
            ambiguous_names.add(folded)
            if item.pax_headers or getattr(item, "sparse", None):
                raise ELFLoaderClosureError("source layer uses extended or sparse metadata")
            kind = _kind(item)
            if item.mode < 0 or item.mode > 0o7777:
                raise ELFLoaderClosureError("archive member mode is invalid")
            if item.uid < 0 or item.gid < 0 or item.uid > 2**31 - 1 or item.gid > 2**31 - 1:
                raise ELFLoaderClosureError("archive member ownership is invalid")
            if kind in ("symlink", "hardlink"):
                _resolved_link(name, item.linkname, hardlink=kind == "hardlink")
                if item.size != 0:
                    raise ELFLoaderClosureError("archive link carries a payload")
            elif kind != "file" and item.size != 0:
                raise ELFLoaderClosureError("archive directory carries a payload")
            members.append(
                _Member(
                    name=name,
                    kind=kind,
                    mode=item.mode,
                    uid=item.uid,
                    gid=item.gid,
                    size=item.size,
                    linkname=item.linkname,
                    source=item,
                )
            )
    except Exception:
        archive.close()
        raise
    if not members:
        archive.close()
        raise ELFLoaderClosureError("source layer is empty")
    names = {member.name for member in members}
    for member in members:
        if member.kind == "hardlink":
            resolved = _resolved_link(member.name, member.linkname, hardlink=True)
            if resolved not in names:
                archive.close()
                raise ELFLoaderClosureError("archive hardlink target is absent")
    return archive, tuple(members)


def _is_forbidden_hwcaps_path(path: str) -> bool:
    parts = path.split("/")
    for directory in _DEFAULT_LIBRARY_DIRS:
        prefix = directory.split("/")
        if parts[: len(prefix)] != prefix:
            continue
        suffix = parts[len(prefix) :]
        if suffix and suffix[0] in _FORBIDDEN_HWCAP_COMPONENTS:
            return True
    return False


def _resolve_member(
    path: str,
    by_name: Mapping[str, _Member],
    *,
    require_file: bool,
) -> _Member:
    current = path
    seen: set[str] = set()
    for _ in range(_MAX_LINK_DEPTH):
        if current in seen:
            raise ELFLoaderClosureError(f"{path} resolves through a link cycle")
        seen.add(current)
        member = by_name.get(current)
        if member is None:
            raise ELFLoaderClosureError(f"{path} is absent from the pinned rootfs")
        if member.kind in ("symlink", "hardlink"):
            current = _resolved_link(
                current,
                member.linkname,
                hardlink=member.kind == "hardlink",
            )
            continue
        if require_file and member.kind != "file":
            raise ELFLoaderClosureError(f"{path} does not resolve to a regular file")
        return member
    raise ELFLoaderClosureError(f"{path} exceeds the link-depth bound")


def _require_arm64_elf(data: bytes, label: str) -> None:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ELFLoaderClosureError(f"{label} is not ELF")
    elf_class, byte_order, version = data[4], data[5], data[6]
    if elf_class != 2 or byte_order != 1 or version != 1:
        raise ELFLoaderClosureError(f"{label} is not little-endian ELF64")
    if struct.unpack_from("<H", data, 18)[0] != _ELF_MACHINE_AARCH64:
        raise ELFLoaderClosureError(f"{label} is not Linux arm64 ELF")


def _require_glibc_status(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ELFLoaderClosureError("dpkg status is not UTF-8") from error
    matches = []
    for stanza in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in stanza.splitlines():
            if not line or line[0].isspace() or ": " not in line:
                continue
            key, value = line.split(": ", 1)
            fields[key] = value
        if fields.get("Package") == "libc6":
            matches.append(fields)
    if len(matches) != 1:
        raise ELFLoaderClosureError("dpkg status does not identify one libc6 package")
    libc = matches[0]
    if (
        libc.get("Architecture") != "arm64"
        or libc.get("Version") != GLIBC_PACKAGE_VERSION
        or libc.get("Status") != "install ok installed"
    ):
        raise ELFLoaderClosureError("dpkg status does not bind the pinned arm64 glibc")


def _census_row(member: _Member, payload: bytes | None) -> Mapping[str, Any]:
    row: dict[str, Any] = {
        "gid": member.gid,
        "kind": member.kind,
        "mode": member.mode,
        "path": member.name,
        "uid": member.uid,
    }
    if member.kind == "file":
        assert payload is not None
        row["sha256"] = _sha256(payload)
        row["size"] = len(payload)
    elif member.kind in ("symlink", "hardlink"):
        row["linkname"] = member.linkname
        row["resolved_target"] = _resolved_link(
            member.name,
            member.linkname,
            hardlink=member.kind == "hardlink",
        )
    return row


def _tar_info(member: _Member) -> tarfile.TarInfo:
    result = tarfile.TarInfo(member.name)
    result.mode = member.mode
    result.uid = member.uid
    result.gid = member.gid
    result.uname = ""
    result.gname = ""
    result.mtime = 0
    result.devmajor = 0
    result.devminor = 0
    if member.kind == "file":
        result.type = tarfile.REGTYPE
        result.size = member.size
    elif member.kind == "directory":
        result.type = tarfile.DIRTYPE
        result.size = 0
    elif member.kind == "symlink":
        result.type = tarfile.SYMTYPE
        result.linkname = member.linkname
        result.size = 0
    elif member.kind == "hardlink":
        result.type = tarfile.LNKTYPE
        result.linkname = member.linkname
        result.size = 0
    else:  # defensive: _kind admitted the finite roster
        raise ELFLoaderClosureError("unsupported canonical member kind")
    return result


def _write_all_at(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.pwrite(fd, data[offset : offset + _READ_CHUNK], offset)
        except OSError as error:
            raise ELFLoaderClosureError("derived archive cannot be written") from error
        if written <= 0:
            raise ELFLoaderClosureError("derived archive write made no progress")
        offset += written
    try:
        os.ftruncate(fd, len(data))
        os.fsync(fd)
    except OSError as error:
        raise ELFLoaderClosureError("derived archive cannot be durably finalized") from error


def _decompress_source(source: bytes) -> tuple[BinaryIO, str, int]:
    raw = tempfile.TemporaryFile(mode="w+b")
    digest = hashlib.sha256()
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(source), mode="rb") as compressed:
            while True:
                chunk = compressed.read(_READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_ARCHIVE_BYTES:
                    raise ELFLoaderClosureError("expanded source layer exceeds the byte limit")
                digest.update(chunk)
                raw.write(chunk)
    except (gzip.BadGzipFile, EOFError, OSError, zlib.error) as error:
        raw.close()
        raise ELFLoaderClosureError("source layer gzip stream is malformed") from error
    raw.flush()
    raw.seek(0)
    return raw, digest.hexdigest(), total


def _canonical_gzip_stored(raw: BinaryIO) -> bytes:
    """Encode an RFC 1952 stream using only RFC 1951 stored blocks.

    Relying on a platform zlib encoder would make the compressed OCI digest an
    implementation-version output.  Stored blocks are larger but have one
    trivial byte representation and therefore remain stable across hosts.
    """

    raw.seek(0)
    result = bytearray(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff")
    crc = 0
    size = 0
    current = raw.read(65_535)
    if not current:
        result.extend(b"\x01\x00\x00\xff\xff")
    while current:
        following = raw.read(65_535)
        final = not following
        length = len(current)
        result.append(1 if final else 0)
        result.extend(struct.pack("<HH", length, length ^ 0xFFFF))
        result.extend(current)
        crc = zlib.crc32(current, crc)
        size += length
        if size > _MAX_ARCHIVE_BYTES:
            raise ELFLoaderClosureError("derived layer exceeds the byte limit")
        current = following
    result.extend(struct.pack("<II", crc & 0xFFFFFFFF, size & 0xFFFFFFFF))
    return bytes(result)


def _render_cache_free(
    raw_source: BinaryIO,
) -> tuple[bytes, str, int, bytes, Mapping[str, Any]]:
    archive, members = _parse_members(raw_source)
    by_name = {member.name: member for member in members}
    cache = by_name.get(_CACHE_PATH)
    if cache is None or cache.kind != "file":
        archive.close()
        raise ELFLoaderClosureError("the pinned rootfs cache is absent or not a regular file")
    if _PRELOAD_PATH in by_name:
        archive.close()
        raise ELFLoaderClosureError("ld.so.preload is forbidden")
    forbidden = sorted(member.name for member in members if _is_forbidden_hwcaps_path(member.name))
    if forbidden:
        archive.close()
        raise ELFLoaderClosureError("hardware-capability library directories are forbidden")

    cache_bytes = _read_member(archive, cache.source)
    loader_member = _resolve_member(_LOADER_PATH, by_name, require_file=True)
    libc_member = _resolve_member(_LIBC_PATH, by_name, require_file=True)
    status_member = _resolve_member(_DPKG_STATUS_PATH, by_name, require_file=True)
    loader_bytes = _read_member(archive, loader_member.source)
    libc_bytes = _read_member(archive, libc_member.source)
    status_bytes = _read_member(archive, status_member.source)
    _require_arm64_elf(loader_bytes, "pinned dynamic loader")
    _require_arm64_elf(libc_bytes, "pinned libc")
    _require_glibc_status(status_bytes)

    canonical_raw = tempfile.TemporaryFile(mode="w+b")
    census: list[Mapping[str, Any]] = []
    try:
        with tarfile.open(fileobj=canonical_raw, mode="w:", format=tarfile.USTAR_FORMAT) as output:
            for member in sorted(members, key=lambda value: value.name.encode("utf-8")):
                if member.name == _CACHE_PATH:
                    continue
                payload = _read_member(archive, member.source) if member.kind == "file" else None
                census.append(_census_row(member, payload))
                output.addfile(_tar_info(member), io.BytesIO(payload) if payload is not None else None)
        archive.close()
        canonical_raw.flush()
        canonical_raw.seek(0)
        raw_digest = hashlib.sha256()
        raw_size = 0
        while True:
            chunk = canonical_raw.read(_READ_CHUNK)
            if not chunk:
                break
            raw_size += len(chunk)
            if raw_size > _MAX_ARCHIVE_BYTES:
                raise ELFLoaderClosureError("derived layer exceeds the byte limit")
            raw_digest.update(chunk)
        compressed_bytes = _canonical_gzip_stored(canonical_raw)
    finally:
        archive.close()
        canonical_raw.close()
    census_bytes = _canonical_json(census)
    evidence = {
        "cache": {"sha256": _sha256(cache_bytes), "size": len(cache_bytes)},
        "census_sha256": _sha256(census_bytes),
        "entry_count": len(census),
        "libc_sha256": _sha256(libc_bytes),
        "loader_sha256": _sha256(loader_bytes),
        "status_sha256": _sha256(status_bytes),
    }
    return compressed_bytes, raw_digest.hexdigest(), raw_size, census_bytes, evidence


def _manifest(
    *,
    derived: bytes,
    derived_diff_id: str,
    derived_tar_size: int,
    evidence: Mapping[str, Any],
) -> bytes:
    value = {
        "closure_contract": {
            "default_library_directories": list(_DEFAULT_LIBRARY_DIRS),
            "generic_linux_inputs": "REJECTED_UNLESS_EXACT_RECIPE_MATCHES",
            "glibc_aarch64_policy": "NO_ADDITIONAL_LEGACY_HWCAP_SEARCH_PATHS",
            "glibc_source_reference": GLIBC_SOURCE_REFERENCE,
            "hwcaps_directories": "FORBIDDEN",
            "required_environment_denials": {
                "exact_names": list(_FORBIDDEN_ENV_NAMES),
                "prefixes": list(_FORBIDDEN_ENV_PREFIXES),
            },
            "transitive_elf_status": "REQUIRES_SAME_FD_DOWNSTREAM_PROOF",
        },
        "derived": {
            "census_sha256": evidence["census_sha256"],
            "diff_id": "sha256:" + derived_diff_id,
            "entry_count": evidence["entry_count"],
            "sha256": "sha256:" + _sha256(derived),
            "size": len(derived),
            "tar_size": derived_tar_size,
        },
        "glibc": {
            "architecture": "arm64",
            "libc_path": "/" + _LIBC_PATH,
            "libc_sha256": evidence["libc_sha256"],
            "loader_path": "/" + _LOADER_PATH,
            "loader_sha256": evidence["loader_sha256"],
            "package": "libc6",
            "status_sha256": evidence["status_sha256"],
            "version": GLIBC_PACKAGE_VERSION,
        },
        "production_authority": False,
        "provenance_sha256": _sha256(pinned_provenance_bytes()),
        "recipe_version": RECIPE_VERSION,
        "removed": {
            "path": "/" + _CACHE_PATH,
            "sha256": evidence["cache"]["sha256"],
            "size": evidence["cache"]["size"],
        },
        "schema_version": SCHEMA_VERSION,
        "source": {
            "diff_id": "sha256:" + SOURCE_DIFF_ID,
            "reference": SOURCE_REFERENCE,
            "sha256": "sha256:" + SOURCE_LAYER_SHA256,
            "size": SOURCE_LAYER_SIZE,
            "tar_size": SOURCE_TAR_SIZE,
        },
        "status": "CONTENT_DERIVED_PENDING_NATIVE_HANDOFF_AND_TRANSITIVE_ELF_PROOF",
    }
    return _canonical_json(value)


def _require_manifest_shape(value: Any) -> Mapping[str, Any]:
    top_keys = {
        "closure_contract",
        "derived",
        "glibc",
        "production_authority",
        "provenance_sha256",
        "recipe_version",
        "removed",
        "schema_version",
        "source",
        "status",
    }
    if type(value) is not dict or set(value) != top_keys:
        raise ELFLoaderClosureError("derivation manifest shape is unsupported")
    nested = {
        "closure_contract": {
            "default_library_directories",
            "generic_linux_inputs",
            "glibc_aarch64_policy",
            "glibc_source_reference",
            "hwcaps_directories",
            "required_environment_denials",
            "transitive_elf_status",
        },
        "derived": {"census_sha256", "diff_id", "entry_count", "sha256", "size", "tar_size"},
        "glibc": {
            "architecture",
            "libc_path",
            "libc_sha256",
            "loader_path",
            "loader_sha256",
            "package",
            "status_sha256",
            "version",
        },
        "removed": {"path", "sha256", "size"},
        "source": {"diff_id", "reference", "sha256", "size", "tar_size"},
    }
    for key, keys in nested.items():
        row = value[key]
        if type(row) is not dict or set(row) != keys:
            raise ELFLoaderClosureError("derivation manifest shape is unsupported")
    return value


def _require_golden_derivation(
    *,
    derived: bytes,
    derived_diff_id: str,
    derived_tar_size: int,
    evidence: Mapping[str, Any],
) -> None:
    cache = evidence.get("cache")
    facts = (
        len(derived) == DERIVED_LAYER_SIZE,
        hmac.compare_digest(_sha256(derived), DERIVED_LAYER_SHA256),
        derived_tar_size == _DERIVED_TAR_SIZE,
        hmac.compare_digest(derived_diff_id, DERIVED_DIFF_ID),
        evidence.get("entry_count") == _DERIVED_ENTRY_COUNT,
        hmac.compare_digest(str(evidence.get("census_sha256")), _DERIVED_CENSUS_SHA256),
        type(cache) is dict,
        cache.get("size") == _REMOVED_CACHE_SIZE if type(cache) is dict else False,
        hmac.compare_digest(str(cache.get("sha256")), _REMOVED_CACHE_SHA256)
        if type(cache) is dict
        else False,
        hmac.compare_digest(str(evidence.get("loader_sha256")), _LOADER_SHA256),
        hmac.compare_digest(str(evidence.get("libc_sha256")), _LIBC_SHA256),
        hmac.compare_digest(str(evidence.get("status_sha256")), _DPKG_STATUS_SHA256),
    )
    if not all(facts):
        raise ELFLoaderClosureError("cache-free derivation does not match the independent golden vector")


def derive_cache_free_rootfs(
    source_fd: int,
    output_fd: int,
    *,
    authenticated_provenance: bytes,
) -> CacheFreeRootfsDerivation:
    """Derive deterministic cache-free rootfs bytes into an empty output FD.

    The caller must supply the exact authenticated provenance document already
    admitted by the release authority.  Equality to this document does not by
    itself authenticate its caller; the returned object therefore remains a
    non-authoritative content receipt.
    """

    _strict_provenance(authenticated_provenance)
    source_before, output_before = _require_descriptor_modes(source_fd, output_fd)
    if source_before.size != SOURCE_LAYER_SIZE:
        raise ELFLoaderClosureError("source layer size does not match the pin")
    source = _read_exact_fd(source_fd, source_before.size, "source layer")
    if not hmac.compare_digest(_sha256(source), SOURCE_LAYER_SHA256):
        raise ELFLoaderClosureError("source layer digest does not match the pin")
    if _fd_identity(source_fd, "source") != source_before:
        raise ELFLoaderClosureError("source layer changed during observation")
    if _fd_identity(output_fd, "output") != output_before:
        raise ELFLoaderClosureError("output descriptor changed before derivation")

    raw_source, source_diff_id, source_tar_size = _decompress_source(source)
    try:
        if source_tar_size != SOURCE_TAR_SIZE or not hmac.compare_digest(source_diff_id, SOURCE_DIFF_ID):
            raise ELFLoaderClosureError("expanded source layer does not match the pinned DiffID")
        derived, derived_diff_id, derived_tar_size, _census, evidence = _render_cache_free(raw_source)
    finally:
        raw_source.close()
    _require_golden_derivation(
        derived=derived,
        derived_diff_id=derived_diff_id,
        derived_tar_size=derived_tar_size,
        evidence=evidence,
    )
    manifest = _manifest(
        derived=derived,
        derived_diff_id=derived_diff_id,
        derived_tar_size=derived_tar_size,
        evidence=evidence,
    )
    if not hmac.compare_digest(_sha256(manifest), DERIVATION_MANIFEST_SHA256):
        raise ELFLoaderClosureError("cache-free manifest does not match the independent golden vector")

    _write_all_at(output_fd, derived)
    output_after = _fd_identity(output_fd, "output")
    if (
        (output_after.dev, output_after.ino) != (output_before.dev, output_before.ino)
        or output_after.uid != output_before.uid
        or output_after.gid != output_before.gid
        or stat.S_IMODE(output_after.mode) != 0o600
        or output_after.size != len(derived)
        or output_after.nlink != output_before.nlink
    ):
        raise ELFLoaderClosureError("output descriptor identity changed during derivation")
    observed = _read_exact_fd(output_fd, len(derived), "derived layer")
    if not hmac.compare_digest(_sha256(observed), _sha256(derived)):
        raise ELFLoaderClosureError("derived layer changed before completion")
    if _fd_identity(output_fd, "output") != output_after:
        raise ELFLoaderClosureError("output descriptor changed during final observation")

    return CacheFreeRootfsDerivation(
        schema_version=SCHEMA_VERSION,
        status="CONTENT_DERIVED_PENDING_NATIVE_HANDOFF_AND_TRANSITIVE_ELF_PROOF",
        source_sha256=SOURCE_LAYER_SHA256,
        source_size=SOURCE_LAYER_SIZE,
        source_diff_id=SOURCE_DIFF_ID,
        source_tar_size=SOURCE_TAR_SIZE,
        derived_sha256=_sha256(derived),
        derived_size=len(derived),
        derived_diff_id=derived_diff_id,
        derived_tar_size=derived_tar_size,
        census_sha256=evidence["census_sha256"],
        entry_count=evidence["entry_count"],
        removed_cache_sha256=evidence["cache"]["sha256"],
        removed_cache_size=evidence["cache"]["size"],
        loader_sha256=evidence["loader_sha256"],
        libc_sha256=evidence["libc_sha256"],
        manifest_sha256=_sha256(manifest),
        manifest_bytes=manifest,
    )


def verify_cache_free_rootfs(
    derived_fd: int,
    *,
    manifest_bytes: bytes,
) -> CacheFreeRootfsDerivation:
    """Independently rederive and compare a cache-free output descriptor.

    Verification replays the deterministic recipe from the authenticated
    source facts embedded in the manifest.  It is still a content check, not
    a native retained-descriptor handoff or release authority.
    """

    if _fcntl is None or os.name != "posix":
        raise ELFLoaderClosureError("POSIX descriptor authority is unavailable")
    identity = _fd_identity(derived_fd, "derived")
    try:
        flags = _fcntl.fcntl(derived_fd, _fcntl.F_GETFL)
    except OSError as error:
        raise ELFLoaderClosureError("derived descriptor mode cannot be inspected") from error
    if flags & os.O_ACCMODE not in (os.O_RDONLY, os.O_RDWR):
        raise ELFLoaderClosureError("derived descriptor is not readable")
    if identity.size <= 0 or identity.size > _MAX_ARCHIVE_BYTES:
        raise ELFLoaderClosureError("derived layer size is invalid")
    raw_manifest = manifest_bytes
    if type(raw_manifest) is not bytes or not raw_manifest or len(raw_manifest) > 64 * 1024:
        raise ELFLoaderClosureError("derivation manifest bytes are invalid")
    try:
        value = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ELFLoaderClosureError("derivation manifest is malformed") from error
    value = _require_manifest_shape(value)
    if not hmac.compare_digest(raw_manifest, _canonical_json(value)):
        raise ELFLoaderClosureError("derivation manifest is not canonical JSON")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("recipe_version") != RECIPE_VERSION:
        raise ELFLoaderClosureError("derivation manifest schema is unsupported")
    if value.get("production_authority") is not False:
        raise ELFLoaderClosureError("derivation manifest claims forbidden production authority")
    derived = _read_exact_fd(derived_fd, identity.size, "derived layer")
    if _fd_identity(derived_fd, "derived") != identity:
        raise ELFLoaderClosureError("derived layer changed during verification")
    expected = value["derived"]
    if expected.get("sha256") != "sha256:" + _sha256(derived) or expected.get("size") != len(derived):
        raise ELFLoaderClosureError("derived layer is not bound by the manifest")

    raw, diff_id, raw_size = _decompress_source(derived)
    try:
        archive, members = _parse_members(raw)
        by_name = {member.name: member for member in members}
        if _CACHE_PATH in by_name or _PRELOAD_PATH in by_name:
            raise ELFLoaderClosureError("derived layer retains loader policy files")
        if any(_is_forbidden_hwcaps_path(member.name) for member in members):
            raise ELFLoaderClosureError("derived layer retains hardware-capability directories")
        loader = _resolve_member(_LOADER_PATH, by_name, require_file=True)
        libc = _resolve_member(_LIBC_PATH, by_name, require_file=True)
        status = _resolve_member(_DPKG_STATUS_PATH, by_name, require_file=True)
        loader_bytes = _read_member(archive, loader.source)
        libc_bytes = _read_member(archive, libc.source)
        status_bytes = _read_member(archive, status.source)
        _require_arm64_elf(loader_bytes, "derived dynamic loader")
        _require_arm64_elf(libc_bytes, "derived libc")
        _require_glibc_status(status_bytes)
        census: list[Mapping[str, Any]] = []
        for member in sorted(members, key=lambda item: item.name.encode("utf-8")):
            payload = _read_member(archive, member.source) if member.kind == "file" else None
            census.append(_census_row(member, payload))
        archive.close()
    finally:
        raw.close()
    census_sha256 = _sha256(_canonical_json(census))
    evidence = {
        "cache": value.get("removed"),
        "census_sha256": census_sha256,
        "entry_count": len(census),
        "libc_sha256": _sha256(libc_bytes),
        "loader_sha256": _sha256(loader_bytes),
        "status_sha256": _sha256(status_bytes),
    }
    _require_golden_derivation(
        derived=derived,
        derived_diff_id=diff_id,
        derived_tar_size=raw_size,
        evidence=evidence,
    )
    if (
        expected.get("diff_id") != "sha256:" + diff_id
        or expected.get("tar_size") != raw_size
        or expected.get("census_sha256") != census_sha256
        or expected.get("entry_count") != len(census)
    ):
        raise ELFLoaderClosureError("derived census or DiffID is not bound by the manifest")
    canonical_manifest = _manifest(
        derived=derived,
        derived_diff_id=diff_id,
        derived_tar_size=raw_size,
        evidence=evidence,
    )
    if not hmac.compare_digest(raw_manifest, canonical_manifest):
        raise ELFLoaderClosureError("derivation manifest does not match the exact recipe")
    if not hmac.compare_digest(_sha256(raw_manifest), DERIVATION_MANIFEST_SHA256):
        raise ELFLoaderClosureError("derivation manifest does not match the independent golden vector")
    removed = value["removed"]
    return CacheFreeRootfsDerivation(
        schema_version=SCHEMA_VERSION,
        status=value["status"],
        source_sha256=SOURCE_LAYER_SHA256,
        source_size=SOURCE_LAYER_SIZE,
        source_diff_id=SOURCE_DIFF_ID,
        source_tar_size=SOURCE_TAR_SIZE,
        derived_sha256=_sha256(derived),
        derived_size=len(derived),
        derived_diff_id=diff_id,
        derived_tar_size=raw_size,
        census_sha256=census_sha256,
        entry_count=len(census),
        removed_cache_sha256=removed["sha256"],
        removed_cache_size=removed["size"],
        loader_sha256=_sha256(loader_bytes),
        libc_sha256=_sha256(libc_bytes),
        manifest_sha256=_sha256(raw_manifest),
        manifest_bytes=raw_manifest,
    )


__all__ = [
    "AUTHENTICATION_SCOPE",
    "CacheFreeRootfsDerivation",
    "DERIVATION_MANIFEST_SHA256",
    "DERIVED_DIFF_ID",
    "DERIVED_LAYER_SHA256",
    "DERIVED_LAYER_SIZE",
    "ELFLoaderClosureError",
    "GLIBC_PACKAGE_VERSION",
    "RECIPE_VERSION",
    "SCHEMA_VERSION",
    "SOURCE_DIFF_ID",
    "SOURCE_LAYER_SHA256",
    "SOURCE_LAYER_SIZE",
    "SOURCE_REFERENCE",
    "SOURCE_TAR_SIZE",
    "derive_cache_free_rootfs",
    "pinned_provenance_bytes",
    "verify_cache_free_rootfs",
]
