"""Descriptor-bound native runtime binding policy for release generation v2.

The policy is a byte authority, not a discovery mechanism.  A frozen policy
names every evidence object below a caller-owned source directory and pins its
identity (mode, size and SHA-256).  Loading reopens every path with no-follow
``openat`` traversal, checks the inode before and after the read, replays the
OCI document graph and materialization receipts, and only then returns the 14
external bindings consumed by the native runtime-package manifest.

No pathname outside ``source_root_fd`` and no ambient image/tool lookup is
accepted.  Candidate policies may record missing production authority, but
cannot be loaded or frozen.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
from pathlib import PurePosixPath
import re
import stat
import struct
import tarfile
from typing import Any, Mapping

from runtime_policy_artifacts import (
    RuntimePolicyArtifactError,
    validate_baked_image_member_closure,
    validate_linux_guest_seccomp_profile,
)


SCHEMA = "plamen.native-runtime-bindings.v2"
POLICY_PATH = "verification_policy/native_runtime_bindings.v2.json"
SCHEMA_V3 = "plamen.native-runtime-bindings.v3"
POLICY_V3_PATH = "verification_policy/native_runtime_bindings.v3.json"
PLATFORM = {"architecture": "arm64", "os": "linux"}
INIT_REFERENCE = "/usr/local/libexec/plamen-guest"
PRODUCTION_MATERIALIZATION_SCHEMA = "plamen.runtime_materialization_receipt.v2"
LAYOUT_RECEIPT_SCHEMA = "plamen.oci_layout_receipt.v5"
OCI_LOCK_SCHEMA = "plamen.oci_image_lock.v5"
INSTALLED_CENSUS_SCHEMA = "plamen.installed_runtime_census.v1"

MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

DIGEST_FIELDS = (
    "oci_index_digest",
    "image_manifest_digest",
    "oci_config_digest",
    "image_closure_sha256",
    "apple_container_configuration_sha256",
    "seccomp_profile_sha256",
    "baked_toolchain_closure_sha256",
    "oci_lock_sha256",
    "materialization_receipt_sha256",
    "rootfs_archive_sha256",
    "rootfs_diff_id_sha256",
    "closure_census_sha256",
    "sbom_sha256",
    "provenance_sha256",
)

EVIDENCE_ROLES = (
    "oci_lock",
    "layout_receipt",
    "oci_index",
    "oci_manifest",
    "oci_config",
    "rootfs_archive",
    "runtime_materialization_archive",
    "materialization_receipt",
    "native_build_guest_receipt",
    "closure_census",
    "sbom",
    "provenance",
    "seccomp_profile",
    "baked_toolchain_closure",
)
EVIDENCE_ROLES_V3 = EVIDENCE_ROLES + (
    "oci_layout_archive",
    "apple_image_admission",
)
_APPLE_IMAGE_ADMISSION_V4_KEYS = frozenset({
    "schema", "state", "image_reference", "index_digest",
    "manifest_digest", "configuration_sha256", "platform_os",
    "platform_architecture", "archive_identity_sha256",
    "archive_content_sha256", "archive_size", "layout_receipt_sha256",
    "image_closure_sha256", "admission_nonce",
    "provider_provenance_sha256", "postcondition_sha256",
})

# These are in-image paths.  They deliberately do not overlap the read-only
# /opt/plamen source mount.  Every row must be a regular census entry; a
# symlink (notably /usr/bin/python3) is not an executable authority.
IMAGE_MEMBER_PATHS = {
    "forge": "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
    "js_offline_materializer": "/usr/local/libexec/plamen-js-offline-materializer.py",
    "managed_provisioner": "/usr/local/libexec/plamen-managed-evm-provisioner.py",
    "managed_python": "/usr/local/lib/plamen/python/bin/python3.12",
    "medusa": "/usr/local/lib/plamen/toolchains/medusa/bin/medusa",
    "opengrep": "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep",
    "slither": "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither",
    "solc": "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
    "specialized_worker": "/opt/plamen/scripts/posix_specialized_tool_worker.py",
}

_TOP_KEYS = frozenset(
    {
        "schema",
        "state",
        "platform",
        "references",
        "digests",
        "image_members",
        "evidence",
        "missing_authorities",
        "policy_sha256",
    }
)
_ROW_KEYS = frozenset({"mode", "path", "sha256", "size"})
_MEMBER_KEYS = frozenset({"mode", "path", "sha256", "size"})

IMAGE_MEMBER_RECEIPT_MAGIC = b"PLIMGV2\0"
IMAGE_MEMBER_RECEIPT_VERSION = 2
IMAGE_MEMBER_RECEIPT_HEADER_SIZE = 256
IMAGE_MEMBER_RECEIPT_ROW_SIZE = 320
IMAGE_MEMBER_FLAG_EXECUTABLE = 1
IMAGE_MEMBER_FLAG_PYTHON_OR_JS = 2


class NativeRuntimeBindingsError(RuntimeError):
    """The frozen native runtime binding authority is absent or invalid."""


def _canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise NativeRuntimeBindingsError("runtime binding JSON is not canonicalizable") from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _plain_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None or value == "0" * 64:
        raise NativeRuntimeBindingsError(f"{label} is not a nonzero lowercase SHA-256")
    return value


def _image_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _OCI_DIGEST.fullmatch(value) is None or value == "sha256:" + "0" * 64:
        raise NativeRuntimeBindingsError(f"{label} is not a nonzero OCI SHA-256")
    return value


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise NativeRuntimeBindingsError(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise NativeRuntimeBindingsError(f"{label} is not a safe relative path")
    if len(path.parts) > 64 or len(value.encode("utf-8")) > 512:
        raise NativeRuntimeBindingsError(f"{label} exceeds its path bound")
    return value


def _fd_identity(row: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(row.st_dev),
        int(row.st_ino),
        stat.S_IFMT(row.st_mode),
        stat.S_IMODE(row.st_mode),
        int(row.st_size),
        int(row.st_nlink),
    )


def _open_beneath(root_fd: int, path: str) -> int:
    path = _relative_path(path, "evidence path")
    current = os.dup(root_fd)
    try:
        for component in PurePosixPath(path).parts[:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=current,
            )
            os.close(current)
            current = child
        result = os.open(
            PurePosixPath(path).parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=current,
        )
        return result
    except OSError as exc:
        raise NativeRuntimeBindingsError(f"evidence path is unavailable: {path}") from exc
    finally:
        os.close(current)


def _read_descriptor(descriptor: int, maximum: int, label: str) -> tuple[bytes, os.stat_result]:
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise NativeRuntimeBindingsError(f"{label} descriptor is invalid") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise NativeRuntimeBindingsError(f"{label} descriptor identity is unsafe")
    identity = _fd_identity(before)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = int(before.st_size)
    while remaining:
        chunk = os.read(descriptor, min(remaining, _READ_CHUNK))
        if not chunk:
            raise NativeRuntimeBindingsError(f"{label} was truncated while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise NativeRuntimeBindingsError(f"{label} grew while reading")
    after = os.fstat(descriptor)
    if _fd_identity(after) != identity:
        raise NativeRuntimeBindingsError(f"{label} changed while reading")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks), before


def _read_evidence(root_fd: int, row: Mapping[str, Any], label: str) -> bytes:
    if type(row) is not dict or frozenset(row) != _ROW_KEYS:
        raise NativeRuntimeBindingsError(f"{label} evidence row schema is not exact")
    path = _relative_path(row["path"], f"{label} path")
    expected_sha = _plain_digest(row["sha256"], f"{label} SHA-256")
    size = row["size"]
    mode = row["mode"]
    if type(size) is not int or not 1 <= size <= MAX_EVIDENCE_BYTES:
        raise NativeRuntimeBindingsError(f"{label} evidence size is invalid")
    if not isinstance(mode, str) or not re.fullmatch(r"0[0-7]{3}", mode):
        raise NativeRuntimeBindingsError(f"{label} evidence mode is invalid")
    descriptor = _open_beneath(root_fd, path)
    try:
        raw, observed = _read_descriptor(descriptor, MAX_EVIDENCE_BYTES, label)
        if (
            int(observed.st_size) != size
            or stat.S_IMODE(observed.st_mode) != int(mode, 8)
            or not hmac.compare_digest(_sha(raw), expected_sha)
        ):
            raise NativeRuntimeBindingsError(f"{label} evidence differs from frozen policy")
        return raw
    finally:
        os.close(descriptor)


def _json(raw: bytes, label: str, *, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    if len(raw) > maximum:
        raise NativeRuntimeBindingsError(f"{label} exceeds its JSON bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeRuntimeBindingsError(f"{label} is not valid JSON") from exc
    if type(value) is not dict or _canonical(value) != raw:
        raise NativeRuntimeBindingsError(f"{label} is not exact canonical JSON")
    return value


def _strip_oci(value: str) -> str:
    return _image_digest(value, "OCI digest")[7:]


def _validate_materialization(
    receipt: Mapping[str, Any],
    receipt_sha256: str,
    census_raw: bytes,
    sbom_raw: bytes,
    provenance_raw: bytes,
    archive_raw: bytes,
    native_build_guest_receipt_raw: bytes,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if frozenset(receipt) != {
        "archive",
        "composition_manifest_sha256",
        "environment_denials",
        "installed",
        "native_build_guest_receipt_sha256",
        "network",
        "package_execution",
        "production_authority",
        "schema_version",
        "solc_execution_policy",
        "source_roster_sha256",
        "status",
        "target",
    }:
        raise NativeRuntimeBindingsError("native materialization receipt schema is not exact")
    if receipt.get("schema_version") != PRODUCTION_MATERIALIZATION_SCHEMA:
        raise NativeRuntimeBindingsError(
            "production native runtime materialization receipt is unavailable"
        )
    if receipt.get("production_authority") is not True:
        raise NativeRuntimeBindingsError("test-only materialization cannot become release authority")
    if receipt.get("status") != "MATERIALIZED_BY_NATIVE_RETAINED_FD_BUILD_GUEST":
        raise NativeRuntimeBindingsError("native materialization did not reach its terminal state")
    if receipt.get("target") != "linux/arm64" or receipt.get("network") != "DENY":
        raise NativeRuntimeBindingsError("runtime materialization platform/network policy drifted")
    if receipt.get("native_build_guest_receipt_sha256") != _sha(native_build_guest_receipt_raw):
        raise NativeRuntimeBindingsError("native build-guest receipt binding is invalid")
    archive = receipt.get("archive")
    installed = receipt.get("installed")
    if type(archive) is not dict or frozenset(archive) != {
        "diff_id", "media_type", "sha256", "size"
    }:
        raise NativeRuntimeBindingsError("materialization archive receipt is malformed")
    archive_sha = _plain_digest(archive.get("sha256"), "materialization archive SHA-256")
    if (
        archive.get("media_type") != "application/vnd.oci.image.layer.v1.tar"
        or archive.get("diff_id") != "sha256:" + archive_sha
        or archive.get("size") != len(archive_raw)
        or _sha(archive_raw) != archive_sha
    ):
        raise NativeRuntimeBindingsError("materialization archive bytes differ from receipt")
    if type(installed) is not dict or frozenset(installed) != {
        "census_sha256", "entry_count", "expanded_bytes", "provenance_sha256", "sbom_sha256"
    }:
        raise NativeRuntimeBindingsError("materialization installed receipt is malformed")
    if (
        installed.get("census_sha256") != _sha(census_raw)
        or installed.get("sbom_sha256") != _sha(sbom_raw)
        or installed.get("provenance_sha256") != _sha(provenance_raw)
    ):
        raise NativeRuntimeBindingsError("materialization evidence digest binding is invalid")
    census = _json(census_raw, "installed runtime census")
    if frozenset(census) != {"entries", "schema_version"} or census.get("schema_version") != INSTALLED_CENSUS_SCHEMA:
        raise NativeRuntimeBindingsError("installed runtime census schema is unsupported")
    rows = census.get("entries")
    if type(rows) is not list or installed.get("entry_count") != len(rows) or not rows:
        raise NativeRuntimeBindingsError("installed runtime census count is invalid")
    by_path: dict[str, dict[str, Any]] = {}
    prior: bytes | None = None
    expanded = 0
    for row in rows:
        if type(row) is not dict or frozenset(row) != {
            "kind", "linkname", "mode", "path", "sha256", "size"
        }:
            raise NativeRuntimeBindingsError("installed runtime census row schema is not exact")
        path = _relative_path(row.get("path"), "installed runtime census path")
        encoded = path.encode("utf-8")
        if prior is not None and encoded <= prior:
            raise NativeRuntimeBindingsError("installed runtime census is not canonically ordered")
        prior = encoded
        if path in by_path:
            raise NativeRuntimeBindingsError("installed runtime census path is duplicated")
        if row.get("kind") == "file":
            _plain_digest(row.get("sha256"), "installed runtime member SHA-256")
            if type(row.get("size")) is not int or row["size"] < 0:
                raise NativeRuntimeBindingsError("installed runtime member size is invalid")
            expanded += row["size"]
        by_path[path] = row
    if installed.get("expanded_bytes") != expanded:
        raise NativeRuntimeBindingsError("installed runtime expanded bytes differ from census")
    observed_rows: list[dict[str, Any]] = []
    try:
        archive_file = tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:")
    except tarfile.TarError as exc:
        raise NativeRuntimeBindingsError("materialization archive is not canonical tar") from exc
    with archive_file:
        for member in archive_file:
            name = member.name[:-1] if member.name.endswith("/") else member.name
            path = _relative_path(name, "materialization archive member")
            if member.isdir():
                kind, linkname, size, digest = "directory", "", 0, _sha(b"directory\0")
            elif member.isfile():
                stream = archive_file.extractfile(member)
                if stream is None:
                    raise NativeRuntimeBindingsError("materialization archive member is unreadable")
                payload = stream.read()
                kind, linkname, size, digest = "file", "", len(payload), _sha(payload)
            elif member.issym() or member.islnk():
                kind = "symlink" if member.issym() else "hardlink"
                linkname, size = member.linkname, 0
                digest = _sha((kind + "\0" + linkname).encode("utf-8"))
            else:
                raise NativeRuntimeBindingsError("materialization archive contains a special member")
            if member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname:
                raise NativeRuntimeBindingsError("materialization archive metadata is not normalized")
            observed_rows.append(
                {
                    "kind": kind,
                    "linkname": linkname,
                    "mode": f"{member.mode:04o}",
                    "path": path,
                    "sha256": digest,
                    "size": size,
                }
            )
    observed_rows.sort(key=lambda row: row["path"].encode("utf-8"))
    if observed_rows != rows:
        raise NativeRuntimeBindingsError("materialization archive differs from installed census")
    _json(sbom_raw, "installed runtime SBOM")
    provenance = _json(provenance_raw, "installed runtime provenance")
    if provenance.get("schema_version") != "plamen.source_output_provenance.v1":
        raise NativeRuntimeBindingsError("installed runtime provenance schema is unsupported")
    _plain_digest(receipt_sha256, "materialization receipt SHA-256")
    return dict(installed), by_path


def _derive_bindings(policy: Mapping[str, Any], raw: Mapping[str, bytes]) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    try:
        import oci_image_lock
    except ImportError as exc:
        raise NativeRuntimeBindingsError("OCI image-lock validator is unavailable") from exc
    lock_raw = raw["oci_lock"]
    lock_value = _json(lock_raw, "OCI image lock", maximum=MAX_POLICY_BYTES)
    try:
        lock = oci_image_lock.validate_image_lock(lock_value)
    except Exception as exc:
        raise NativeRuntimeBindingsError("OCI image lock failed exact validation") from exc
    if lock.get("schema_version") != OCI_LOCK_SCHEMA:
        raise NativeRuntimeBindingsError("OCI image lock schema is unsupported")

    receipt = _json(raw["layout_receipt"], "OCI layout receipt", maximum=MAX_POLICY_BYTES)
    if receipt.get("schema_version") != LAYOUT_RECEIPT_SCHEMA:
        raise NativeRuntimeBindingsError("OCI layout receipt schema is unsupported")
    index = _json(raw["oci_index"], "OCI index", maximum=MAX_POLICY_BYTES)
    manifest = _json(raw["oci_manifest"], "OCI manifest", maximum=MAX_POLICY_BYTES)
    config = _json(raw["oci_config"], "OCI config", maximum=MAX_POLICY_BYTES)
    index_digest = "sha256:" + _sha(raw["oci_index"])
    manifest_digest = "sha256:" + _sha(raw["oci_manifest"])
    config_digest = "sha256:" + _sha(raw["oci_config"])
    if (
        lock["image"]["index_digest"] != index_digest
        or lock["image"]["manifest_digest"] != manifest_digest
        or lock["image"]["config_digest"] != config_digest
        or receipt.get("index_digest") != index_digest
        or receipt.get("manifest_digest") != manifest_digest
        or receipt.get("config_digest") != config_digest
    ):
        raise NativeRuntimeBindingsError("OCI document digests differ from lock/layout receipt")
    manifests = index.get("manifests")
    if type(manifests) is not list or len(manifests) != 1 or manifests[0].get("digest") != manifest_digest:
        raise NativeRuntimeBindingsError("OCI index manifest roster is not exact")
    if manifest.get("config", {}).get("digest") != config_digest:
        raise NativeRuntimeBindingsError("OCI manifest config binding is invalid")
    layers = manifest.get("layers")
    if type(layers) is not list or len(layers) != 1:
        raise NativeRuntimeBindingsError("OCI manifest rootfs layer roster is not exact")
    layer_digest = "sha256:" + _sha(raw["rootfs_archive"])
    if layers[0].get("digest") != layer_digest or receipt.get("layer_blob_digest") != layer_digest:
        raise NativeRuntimeBindingsError("rootfs archive differs from OCI manifest/layout receipt")
    diff_ids = config.get("rootfs", {}).get("diff_ids")
    if type(diff_ids) is not list or len(diff_ids) != 1:
        raise NativeRuntimeBindingsError("OCI rootfs DiffID roster is not exact")
    rootfs_diff_id = _image_digest(diff_ids[0], "rootfs DiffID")
    if receipt.get("layer_diff_id") != rootfs_diff_id:
        raise NativeRuntimeBindingsError("rootfs DiffID differs from layout receipt")
    apple_config = _sha(_canonical(config)[:-1])
    if (
        lock["image"]["apple_container_configuration_sha256"] != apple_config
        or receipt.get("apple_container_configuration_sha256") != apple_config
    ):
        raise NativeRuntimeBindingsError("Apple Container configuration binding is invalid")

    materialization_receipt_sha = _sha(raw["materialization_receipt"])
    materialization = _json(
        raw["materialization_receipt"], "native materialization receipt", maximum=MAX_POLICY_BYTES
    )
    installed, census = _validate_materialization(
        materialization,
        materialization_receipt_sha,
        raw["closure_census"],
        raw["sbom"],
        raw["provenance"],
        raw["runtime_materialization_archive"],
        raw["native_build_guest_receipt"],
    )
    lock_materialization = lock["runtime_materialization"]
    layout_materialization = receipt.get("runtime_materialization")
    if type(layout_materialization) is not dict:
        raise NativeRuntimeBindingsError("layout materialization binding is absent")
    checks = {
        "archive_sha256": lock_materialization["archive"]["sha256"],
        "archive_diff_id": lock_materialization["archive"]["diff_id"],
        "receipt_sha256": lock_materialization["receipt"]["sha256"],
        "installed_census_sha256": lock_materialization["census"]["sha256"],
        "sbom_sha256": lock_materialization["sbom"]["sha256"],
        "provenance_sha256": lock_materialization["provenance"]["sha256"],
    }
    observed = {
        "archive_sha256": materialization["archive"]["sha256"],
        "archive_diff_id": materialization["archive"]["diff_id"],
        "receipt_sha256": materialization_receipt_sha,
        "installed_census_sha256": installed["census_sha256"],
        "sbom_sha256": installed["sbom_sha256"],
        "provenance_sha256": installed["provenance_sha256"],
    }
    if checks != observed or any(layout_materialization.get(key) != value for key, value in observed.items()):
        raise NativeRuntimeBindingsError("runtime materialization evidence graph is not closed")

    references = policy.get("references")
    if type(references) is not dict or frozenset(references) != {"oci_image_reference", "oci_init_reference"}:
        raise NativeRuntimeBindingsError("runtime reference schema is not exact")
    image_reference = references["oci_image_reference"]
    if image_reference != lock["image"]["reference"] or not image_reference.endswith("@" + index_digest):
        raise NativeRuntimeBindingsError("OCI image reference does not bind the exact index")
    if references["oci_init_reference"] != INIT_REFERENCE:
        raise NativeRuntimeBindingsError("OCI init reference is not the fixed guest entrypoint")
    image_closure = _sha(
        _canonical(
            {
                "apple_container_configuration_sha256": apple_config,
                "config_digest": config_digest,
                "index_digest": index_digest,
                "manifest_digest": manifest_digest,
                "platform": PLATFORM,
                "reference": image_reference,
            }
        )
    )
    digests = {
        "oci_index_digest": _strip_oci(index_digest),
        "image_manifest_digest": _strip_oci(manifest_digest),
        "oci_config_digest": _strip_oci(config_digest),
        "image_closure_sha256": image_closure,
        "apple_container_configuration_sha256": apple_config,
        "seccomp_profile_sha256": _sha(raw["seccomp_profile"]),
        "baked_toolchain_closure_sha256": _sha(raw["baked_toolchain_closure"]),
        "oci_lock_sha256": _plain_digest(lock["lock_sha256"], "OCI lock SHA-256"),
        "materialization_receipt_sha256": materialization_receipt_sha,
        "rootfs_archive_sha256": _strip_oci(layer_digest),
        "rootfs_diff_id_sha256": _strip_oci(rootfs_diff_id),
        "closure_census_sha256": _sha(raw["closure_census"]),
        "sbom_sha256": _sha(raw["sbom"]),
        "provenance_sha256": _sha(raw["provenance"]),
    }
    for name in DIGEST_FIELDS:
        _plain_digest(digests.get(name), f"derived {name}")

    members: dict[str, dict[str, Any]] = {}
    non_executable_anchors = frozenset(
        {"js_offline_materializer", "managed_provisioner", "specialized_worker"}
    )
    for name, absolute in IMAGE_MEMBER_PATHS.items():
        row = census.get(absolute.removeprefix("/"))
        if (
            type(row) is not dict
            or row.get("kind") != "file"
            or row.get("linkname") != ""
            or not isinstance(row.get("mode"), str)
            or (name not in non_executable_anchors and int(row["mode"], 8) & 0o111 == 0)
        ):
            raise NativeRuntimeBindingsError(f"required in-image anchor is absent or non-executable: {name}")
        members[name] = {
            "mode": row["mode"],
            "path": absolute,
            "sha256": _plain_digest(row.get("sha256"), f"{name} image member SHA-256"),
            "size": row.get("size"),
        }
    return digests, members


def _policy_sha256(policy: Mapping[str, Any]) -> str:
    unsigned = dict(policy)
    unsigned.pop("policy_sha256", None)
    return _sha(_canonical(unsigned))


def encode_image_member_rows_v2(validated: Mapping[str, Any]) -> bytes:
    """Return the exact eight native-validated 320-byte member rows."""

    if type(validated) is not dict or validated.get("schema") != SCHEMA:
        raise NativeRuntimeBindingsError("validated runtime binding result is required")
    digests = validated.get("digests")
    members = validated.get("image_members")
    if type(digests) is not dict or type(members) is not dict or tuple(sorted(members)) != tuple(sorted(IMAGE_MEMBER_PATHS)):
        raise NativeRuntimeBindingsError("image member receipt roster is not exact")
    script_ids = frozenset(
        {"js_offline_materializer", "managed_provisioner", "specialized_worker"}
    )
    rows: list[bytes] = []
    for ordinal, member_id in enumerate(sorted(IMAGE_MEMBER_PATHS)):
        row = members[member_id]
        if type(row) is not dict or frozenset(row) != _MEMBER_KEYS:
            raise NativeRuntimeBindingsError("image member receipt row is malformed")
        identifier = member_id.encode("ascii")
        path = row["path"].encode("ascii")
        if len(identifier) > 32 or len(path) > 240 or row["path"] != IMAGE_MEMBER_PATHS[member_id]:
            raise NativeRuntimeBindingsError("image member receipt path is invalid")
        size = row["size"]
        if type(size) is not int or not 1 <= size <= MAX_EVIDENCE_BYTES:
            raise NativeRuntimeBindingsError("image member receipt size is invalid")
        digest = bytes.fromhex(_plain_digest(row["sha256"], "image member receipt SHA-256"))
        mode = row["mode"]
        if not isinstance(mode, str) or re.fullmatch(r"0[0-7]{3}", mode) is None:
            raise NativeRuntimeBindingsError("image member receipt mode is invalid")
        flags = (
            IMAGE_MEMBER_FLAG_PYTHON_OR_JS
            if member_id in script_ids
            else IMAGE_MEMBER_FLAG_EXECUTABLE
        )
        rows.append(
            struct.pack(">HHHBBQ", ordinal, flags, int(mode, 8), len(identifier), len(path), size)
            + digest
            + identifier.ljust(32, b"\0")
            + path.ljust(240, b"\0")
        )
    row_bytes = b"".join(rows)
    if len(row_bytes) != len(IMAGE_MEMBER_PATHS) * IMAGE_MEMBER_RECEIPT_ROW_SIZE:
        raise NativeRuntimeBindingsError("image member rowset ABI invariant failed")
    return row_bytes


def encode_image_member_receipt_v2(
    validated: Mapping[str, Any],
    *,
    runtime_package_manifest_sha256: str,
) -> bytes:
    """Encode the fixed C-consumable image-member authority."""

    if type(validated) is not dict or validated.get("schema") != SCHEMA:
        raise NativeRuntimeBindingsError("validated runtime binding result is required")
    digests = validated.get("digests")
    if type(digests) is not dict:
        raise NativeRuntimeBindingsError("image member receipt bindings are malformed")
    row_bytes = encode_image_member_rows_v2(validated)
    header = (
        IMAGE_MEMBER_RECEIPT_MAGIC
        + struct.pack(
            ">HHHH",
            IMAGE_MEMBER_RECEIPT_VERSION,
            IMAGE_MEMBER_RECEIPT_HEADER_SIZE,
            IMAGE_MEMBER_RECEIPT_ROW_SIZE,
            len(IMAGE_MEMBER_PATHS),
        )
        + bytes.fromhex(_plain_digest(digests.get("image_manifest_digest"), "member receipt OCI manifest"))
        + bytes.fromhex(_plain_digest(runtime_package_manifest_sha256, "member receipt runtime manifest"))
        + bytes.fromhex(_plain_digest(digests.get("image_closure_sha256"), "member receipt image closure"))
        + bytes.fromhex(_plain_digest(digests.get("closure_census_sha256"), "member receipt closure census"))
        + bytes.fromhex(_plain_digest(digests.get("materialization_receipt_sha256"), "member receipt materialization"))
        + hashlib.sha256(row_bytes).digest()
        + bytes.fromhex(
            _plain_digest(
                validated.get("evidence", {}).get("policy_sha256"),
                "member receipt policy",
            )
        )
        + b"\0" * 16
    )
    if len(header) != IMAGE_MEMBER_RECEIPT_HEADER_SIZE:
        raise NativeRuntimeBindingsError("image member receipt ABI invariant failed")
    return header + row_bytes


def validate_native_runtime_bindings_v2(
    policy_raw: bytes,
    source_root_fd: int,
    *,
    require_frozen: bool = True,
    expected_policy_sha256: str | None = None,
) -> dict[str, Any]:
    """Replay one candidate/frozen policy against a retained source root."""

    if type(source_root_fd) is not int or source_root_fd < 0 or not stat.S_ISDIR(os.fstat(source_root_fd).st_mode):
        raise NativeRuntimeBindingsError("source root descriptor is not a directory")
    if type(policy_raw) is not bytes or len(policy_raw) > MAX_POLICY_BYTES:
        raise NativeRuntimeBindingsError("runtime binding policy bytes are invalid")
    policy = _json(policy_raw, "native runtime binding policy", maximum=MAX_POLICY_BYTES)
    if frozenset(policy) != _TOP_KEYS or policy.get("schema") != SCHEMA or policy.get("platform") != PLATFORM:
        raise NativeRuntimeBindingsError("native runtime binding policy schema is unsupported")
    claimed_policy_sha = _plain_digest(policy.get("policy_sha256"), "runtime binding policy SHA-256")
    if claimed_policy_sha != _policy_sha256(policy):
        raise NativeRuntimeBindingsError("runtime binding policy self-digest mismatch")
    if expected_policy_sha256 is not None:
        _plain_digest(expected_policy_sha256, "expected runtime binding policy SHA-256")
        if not hmac.compare_digest(_sha(policy_raw), expected_policy_sha256):
            raise NativeRuntimeBindingsError("runtime binding policy bytes differ from expected digest")
    if policy.get("state") != "FROZEN":
        missing = policy.get("missing_authorities")
        debt = ",".join(missing) if isinstance(missing, list) else "UNKNOWN"
        if require_frozen:
            raise NativeRuntimeBindingsError(f"native runtime bindings are not frozen; missing authority: {debt}")
        return policy
    if policy.get("missing_authorities") != []:
        raise NativeRuntimeBindingsError("frozen runtime binding policy retains missing authority")
    evidence = policy.get("evidence")
    if type(evidence) is not dict or tuple(sorted(evidence)) != tuple(sorted(EVIDENCE_ROLES)):
        raise NativeRuntimeBindingsError("runtime binding evidence roster is not exact")
    raw = {name: _read_evidence(source_root_fd, evidence[name], name) for name in EVIDENCE_ROLES}
    derived, members = _derive_bindings(policy, raw)
    if policy.get("digests") != derived or policy.get("image_members") != members:
        raise NativeRuntimeBindingsError("frozen runtime binding claims differ from retained evidence")
    return {
        "schema": SCHEMA,
        "references": dict(policy["references"]),
        "digests": derived,
        "image_members": members,
        "evidence": {
            "artifact_rows": {
                name: dict(evidence[name]) for name in EVIDENCE_ROLES
            },
            "image_member_roster_sha256": _sha(_canonical(members)),
            "policy_sha256": claimed_policy_sha,
            "policy_bytes_sha256": _sha(policy_raw),
        },
    }


def load_native_runtime_bindings_v2(
    source_root_fd: int,
    *,
    expected_policy_sha256: str | None = None,
) -> dict[str, Any]:
    """Load the fixed frozen policy beneath ``source_root_fd``."""

    descriptor = _open_beneath(source_root_fd, POLICY_PATH)
    try:
        raw, _ = _read_descriptor(descriptor, MAX_POLICY_BYTES, "native runtime binding policy")
    finally:
        os.close(descriptor)
    return validate_native_runtime_bindings_v2(
        raw,
        source_root_fd,
        require_frozen=True,
        expected_policy_sha256=expected_policy_sha256,
    )


def _validate_apple_image_admission_v4(
    admission_raw: bytes,
    archive_raw: bytes,
    layout_receipt_raw: bytes,
    validated_v2: Mapping[str, Any],
) -> dict[str, Any]:
    admission = _json(
        admission_raw, "Apple image admission", maximum=MAX_POLICY_BYTES
    )
    if frozenset(admission) != _APPLE_IMAGE_ADMISSION_V4_KEYS:
        raise NativeRuntimeBindingsError("Apple image admission schema is not exact")
    if _canonical(admission) != admission_raw:
        raise NativeRuntimeBindingsError("Apple image admission bytes are not canonical")
    digests = validated_v2["digests"]
    references = validated_v2["references"]
    if (
        admission.get("schema") != "plamen.apple-container.image-admission.v4"
        or admission.get("state") != "TERMINAL"
        or admission.get("image_reference") != references["oci_image_reference"]
        or admission.get("index_digest") != "sha256:" + digests["oci_index_digest"]
        or admission.get("manifest_digest")
           != "sha256:" + digests["image_manifest_digest"]
        or admission.get("configuration_sha256")
           != digests["apple_container_configuration_sha256"]
        or admission.get("platform_os") != PLATFORM["os"]
        or admission.get("platform_architecture") != PLATFORM["architecture"]
        or admission.get("archive_content_sha256") != _sha(archive_raw)
        or type(admission.get("archive_size")) is not int
        or admission.get("archive_size") != len(archive_raw)
        or admission.get("layout_receipt_sha256") != _sha(layout_receipt_raw)
        or admission.get("image_closure_sha256") != digests["image_closure_sha256"]
    ):
        raise NativeRuntimeBindingsError(
            "Apple image admission differs from the retained OCI evidence graph"
        )
    for field in (
        "archive_identity_sha256", "archive_content_sha256",
        "layout_receipt_sha256", "image_closure_sha256",
        "provider_provenance_sha256", "postcondition_sha256",
    ):
        _plain_digest(admission.get(field), f"Apple image admission {field}")
    nonce = admission.get("admission_nonce")
    if (not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{32}", nonce) is None):
        raise NativeRuntimeBindingsError("Apple image admission nonce is malformed")
    return admission


def validate_native_runtime_bindings_v3(
    policy_raw: bytes,
    source_root_fd: int,
    *,
    require_frozen: bool = True,
    expected_policy_sha256: str | None = None,
) -> dict[str, Any]:
    """Replay the explicit provider-v4/native-bindings-v3 lane."""
    policy = _json(policy_raw, "native runtime binding policy", maximum=MAX_POLICY_BYTES)
    if (frozenset(policy) != _TOP_KEYS or policy.get("schema") != SCHEMA_V3
            or policy.get("platform") != PLATFORM):
        raise NativeRuntimeBindingsError("native runtime binding v3 schema is unsupported")
    claimed = _plain_digest(policy.get("policy_sha256"), "runtime binding policy SHA-256")
    if claimed != _policy_sha256(policy):
        raise NativeRuntimeBindingsError("runtime binding policy self-digest mismatch")
    if expected_policy_sha256 is not None and not hmac.compare_digest(
        _sha(policy_raw), _plain_digest(expected_policy_sha256, "expected policy SHA-256")
    ):
        raise NativeRuntimeBindingsError("runtime binding policy bytes differ from expected digest")
    if policy.get("state") != "FROZEN":
        if require_frozen:
            raise NativeRuntimeBindingsError("native runtime bindings v3 are not frozen")
        return policy
    evidence = policy.get("evidence")
    if type(evidence) is not dict or tuple(sorted(evidence)) != tuple(sorted(EVIDENCE_ROLES_V3)):
        raise NativeRuntimeBindingsError("runtime binding v3 evidence roster is not exact")
    v2_policy = dict(policy)
    v2_policy["schema"] = SCHEMA
    v2_policy["evidence"] = {name: evidence[name] for name in EVIDENCE_ROLES}
    v2_policy["policy_sha256"] = _policy_sha256(v2_policy)
    validated = validate_native_runtime_bindings_v2(
        _canonical(v2_policy), source_root_fd, require_frozen=True
    )
    archive_raw = _read_evidence(source_root_fd, evidence["oci_layout_archive"],
                                 "OCI layout archive")
    layout_raw = _read_evidence(source_root_fd, evidence["layout_receipt"],
                                "OCI layout receipt")
    admission_raw = _read_evidence(source_root_fd, evidence["apple_image_admission"],
                                   "Apple image admission")
    admission = _validate_apple_image_admission_v4(
        admission_raw, archive_raw, layout_raw, validated
    )
    try:
        census_raw = _read_evidence(source_root_fd, evidence["closure_census"],
                                    "installed runtime census")
        validate_baked_image_member_closure(
            _read_evidence(source_root_fd, evidence["baked_toolchain_closure"],
                           "baked image-member closure"),
            census_raw,
            required_paths=IMAGE_MEMBER_PATHS,
        )
        validate_linux_guest_seccomp_profile(
            _read_evidence(source_root_fd, evidence["seccomp_profile"],
                           "fixed Linux guest seccomp profile")
        )
    except RuntimePolicyArtifactError as exc:
        raise NativeRuntimeBindingsError(
            "native runtime v3 policy artifacts differ from deterministic producers"
        ) from exc
    result = dict(validated)
    result["schema"] = SCHEMA_V3
    result["evidence"] = {
        "artifact_rows": {name: dict(evidence[name]) for name in EVIDENCE_ROLES_V3},
        "image_member_roster_sha256": validated["evidence"]["image_member_roster_sha256"],
        "policy_sha256": claimed,
        "policy_bytes_sha256": _sha(policy_raw),
        "apple_image_admission_sha256": _sha(admission_raw),
    }
    result["apple_image_admission"] = admission
    return result


def load_native_runtime_bindings_v3(
    source_root_fd: int, *, expected_policy_sha256: str | None = None
) -> dict[str, Any]:
    descriptor = _open_beneath(source_root_fd, POLICY_V3_PATH)
    try:
        raw, _ = _read_descriptor(descriptor, MAX_POLICY_BYTES,
                                  "native runtime binding v3 policy")
    finally:
        os.close(descriptor)
    return validate_native_runtime_bindings_v3(
        raw, source_root_fd, expected_policy_sha256=expected_policy_sha256
    )


def generate_candidate_v3(
    source_root_fd: int, *, evidence_paths: Mapping[str, str],
    oci_image_reference: str,
) -> bytes:
    if (type(evidence_paths) is not dict
            or tuple(sorted(evidence_paths)) != tuple(sorted(EVIDENCE_ROLES_V3))):
        raise NativeRuntimeBindingsError("candidate v3 evidence path roster is not exact")
    v2_candidate = generate_candidate(
        source_root_fd,
        evidence_paths={name: evidence_paths[name] for name in EVIDENCE_ROLES},
        oci_image_reference=oci_image_reference,
    )
    v2_frozen = freeze_candidate(v2_candidate, source_root_fd)
    v2_validated = validate_native_runtime_bindings_v2(v2_frozen, source_root_fd)
    rows = dict(_json(v2_candidate, "v2 candidate", maximum=MAX_POLICY_BYTES)["evidence"])
    raw_added: dict[str, bytes] = {}
    for name in ("oci_layout_archive", "apple_image_admission"):
        path = _relative_path(evidence_paths[name], f"{name} path")
        descriptor = _open_beneath(source_root_fd, path)
        try:
            raw, observed = _read_descriptor(descriptor, MAX_EVIDENCE_BYTES, name)
        finally:
            os.close(descriptor)
        mode = stat.S_IMODE(observed.st_mode)
        if mode & 0o022:
            raise NativeRuntimeBindingsError(f"{name} evidence is group/world writable")
        rows[name] = {"mode": f"0{mode:03o}", "path": path,
                      "sha256": _sha(raw), "size": len(raw)}
        raw_added[name] = raw
    layout_raw = _read_evidence(source_root_fd, rows["layout_receipt"],
                                "OCI layout receipt")
    _validate_apple_image_admission_v4(
        raw_added["apple_image_admission"], raw_added["oci_layout_archive"],
        layout_raw, v2_validated,
    )
    base = _json(v2_candidate, "v2 candidate", maximum=MAX_POLICY_BYTES)
    base["schema"] = SCHEMA_V3
    base["evidence"] = rows
    base["policy_sha256"] = _policy_sha256(base)
    return _canonical(base)


def freeze_candidate_v3(candidate_raw: bytes, source_root_fd: int) -> bytes:
    candidate = _json(candidate_raw, "native runtime binding v3 candidate",
                      maximum=MAX_POLICY_BYTES)
    if candidate.get("schema") != SCHEMA_V3 or candidate.get("state") != "READY_CANDIDATE":
        raise NativeRuntimeBindingsError("only a ready v3 candidate can be frozen")
    trial = dict(candidate)
    trial["state"] = "FROZEN"
    trial["policy_sha256"] = _policy_sha256(trial)
    frozen = _canonical(trial)
    validate_native_runtime_bindings_v3(frozen, source_root_fd)
    return frozen


def generate_candidate(
    source_root_fd: int,
    *,
    evidence_paths: Mapping[str, str],
    oci_image_reference: str,
) -> bytes:
    """Capture retained evidence rows and derive a ready candidate.

    This is an offline release-coordinator operation.  It never publishes or
    imports an image.  Missing or test-only authority fails closed.
    """

    if type(evidence_paths) is not dict or tuple(sorted(evidence_paths)) != tuple(sorted(EVIDENCE_ROLES)):
        raise NativeRuntimeBindingsError("candidate evidence path roster is not exact")
    rows: dict[str, dict[str, Any]] = {}
    for name in EVIDENCE_ROLES:
        path = _relative_path(evidence_paths[name], f"{name} path")
        descriptor = _open_beneath(source_root_fd, path)
        try:
            raw, observed = _read_descriptor(descriptor, MAX_EVIDENCE_BYTES, name)
        finally:
            os.close(descriptor)
        mode = stat.S_IMODE(observed.st_mode)
        if mode & 0o022:
            raise NativeRuntimeBindingsError(f"{name} evidence is group/world writable")
        rows[name] = {
            "mode": f"0{mode:03o}",
            "path": path,
            "sha256": _sha(raw),
            "size": len(raw),
        }
    base: dict[str, Any] = {
        "schema": SCHEMA,
        "state": "FROZEN",
        "platform": PLATFORM,
        "references": {
            "oci_image_reference": oci_image_reference,
            "oci_init_reference": INIT_REFERENCE,
        },
        "digests": {},
        "image_members": {},
        "evidence": rows,
        "missing_authorities": [],
        "policy_sha256": "1" * 64,
    }
    raw_evidence = {name: _read_evidence(source_root_fd, rows[name], name) for name in EVIDENCE_ROLES}
    digests, members = _derive_bindings(base, raw_evidence)
    base["state"] = "READY_CANDIDATE"
    base["digests"] = digests
    base["image_members"] = members
    base["policy_sha256"] = _policy_sha256(base)
    return _canonical(base)


def freeze_candidate(candidate_raw: bytes, source_root_fd: int) -> bytes:
    """Revalidate a ready candidate and return exact frozen policy bytes."""

    candidate = _json(candidate_raw, "native runtime binding candidate", maximum=MAX_POLICY_BYTES)
    if candidate.get("state") != "READY_CANDIDATE":
        raise NativeRuntimeBindingsError("only a ready runtime binding candidate can be frozen")
    trial = dict(candidate)
    trial["state"] = "FROZEN"
    trial["policy_sha256"] = _policy_sha256(trial)
    frozen = _canonical(trial)
    validate_native_runtime_bindings_v2(frozen, source_root_fd, require_frozen=True)
    return frozen


def blocked_candidate(missing_authorities: list[str]) -> bytes:
    """Render an explicit non-authoritative candidate without fake digests."""

    if (
        type(missing_authorities) is not list
        or not missing_authorities
        or any(type(item) is not str or not item for item in missing_authorities)
        or missing_authorities != sorted(set(missing_authorities))
    ):
        raise NativeRuntimeBindingsError("missing authority roster is invalid")
    policy: dict[str, Any] = {
        "schema": SCHEMA,
        "state": "CANDIDATE_BLOCKED",
        "platform": PLATFORM,
        "references": {},
        "digests": {},
        "image_members": {},
        "evidence": {},
        "missing_authorities": missing_authorities,
        "policy_sha256": "1" * 64,
    }
    policy["policy_sha256"] = _policy_sha256(policy)
    return _canonical(policy)


__all__ = [
    "DIGEST_FIELDS",
    "EVIDENCE_ROLES",
    "EVIDENCE_ROLES_V3",
    "IMAGE_MEMBER_RECEIPT_HEADER_SIZE",
    "IMAGE_MEMBER_RECEIPT_MAGIC",
    "IMAGE_MEMBER_RECEIPT_ROW_SIZE",
    "IMAGE_MEMBER_PATHS",
    "INIT_REFERENCE",
    "NativeRuntimeBindingsError",
    "POLICY_PATH",
    "POLICY_V3_PATH",
    "SCHEMA_V3",
    "load_native_runtime_bindings_v3",
    "validate_native_runtime_bindings_v3",
    "generate_candidate_v3",
    "freeze_candidate_v3",
    "SCHEMA",
    "blocked_candidate",
    "encode_image_member_receipt_v2",
    "encode_image_member_rows_v2",
    "freeze_candidate",
    "generate_candidate",
    "load_native_runtime_bindings_v2",
    "validate_native_runtime_bindings_v2",
]
