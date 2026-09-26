"""Operation-4 runtime composition over an authenticated grouped input.

This module is a deterministic transformer, never a receipt issuer.  The
signed native retained-helper owns descriptor admission, the sandbox, child
custody, output re-census, and the authoritative receipt.  In particular this
code opens no pathname and receives no signing key.

The native helper supplies one scratch file per payload/source-manifest row,
plus two already-open, unlinked, owner-private work files.  The control
manifest is consumed directly; the penultimate scratch file is the expanded-
content spool and the last is the reusable decoded-archive scratch file.  They exist so
the established canonical compositor can continue to use seekable descriptors
without creating files after sandbox admission.
"""

from __future__ import annotations

import hashlib
import hmac
import os
if os.name == "posix":
    import fcntl
else:
    fcntl = None  # type: ignore[assignment]
import stat
from typing import Any

import runtime_image_materializer as compositor


OPERATION = 4
DOCUMENT_LIMIT = 64 * 1024 * 1024
ARCHIVE_LIMIT = 12 * 1024 * 1024 * 1024
GROUP_LIMIT = 8 * 1024 * 1024 * 1024
READ_CHUNK = 1024 * 1024

ROLES = (
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
)
ROW_PATHS = (
    "control/runtime-composition-manifest.json",
    *(
        path
        for ordinal, role in enumerate(ROLES)
        for path in (
            f"runtime-inputs/{ordinal:02d}-{role}.payload",
            f"runtime-inputs/{ordinal:02d}-{role}.source-manifest.json",
        )
    ),
)
OUTPUT_ROLES = (
    "runtime-archive",
    "materialization-observation",
    "installed-runtime-census",
    "runtime-sbom",
    "runtime-provenance",
)
OBSERVATION_SCHEMA_VERSION = "plamen.runtime_materialization_observation.v1"


class NativeRuntimeTransformError(RuntimeError):
    pass


def _require_posix() -> None:
    if fcntl is None:
        raise NativeRuntimeTransformError(
            "native runtime transformation requires POSIX descriptor APIs"
        )


def _access(descriptor: int) -> int:
    return fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE


def _identity(descriptor: int) -> tuple[int, int, int, int, int, int, int, int]:
    info = os.fstat(descriptor)
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _admit_file(
    descriptor: int,
    *,
    label: str,
    linked: bool,
    empty: bool,
) -> tuple[int, int, int, int, int, int, int, int]:
    if type(descriptor) is not int or descriptor < 0:
        raise NativeRuntimeTransformError(f"{label} descriptor is invalid")
    try:
        info = os.fstat(descriptor)
        access = _access(descriptor)
        inheritable = os.get_inheritable(descriptor)
    except OSError as error:
        raise NativeRuntimeTransformError(f"{label} cannot be inspected") from error
    expected_links = 1 if linked else 0
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != expected_links
        or access != os.O_RDWR
        or fcntl.fcntl(descriptor, fcntl.F_GETFL) & getattr(os, "O_APPEND", 0)
        or inheritable
        or (empty and info.st_size != 0)
    ):
        raise NativeRuntimeTransformError(f"{label} identity or access differs")
    return _identity(descriptor)


def _copy_row(group: Any, row: Any, destination: int) -> None:
    os.ftruncate(destination, 0)
    digest = hashlib.sha256()
    cursor = 0
    while cursor < row.size:
        raw = os.pread(group.fd, min(READ_CHUNK, row.size - cursor), row.offset + cursor)
        if not raw:
            raise NativeRuntimeTransformError("group row was truncated")
        written = 0
        while written < len(raw):
            count = os.pwrite(destination, raw[written:], cursor + written)
            if count <= 0:
                raise NativeRuntimeTransformError("scratch snapshot write made no progress")
            written += count
        digest.update(raw)
        cursor += len(raw)
    if cursor != row.size or not hmac.compare_digest(digest.digest(), row.sha256):
        raise NativeRuntimeTransformError("group row commitment differs")
    os.fsync(destination)
    if os.fstat(destination).st_size != row.size:
        raise NativeRuntimeTransformError("scratch snapshot size differs")
    group.rejoin()


def _read_row(group: Any, row: Any, maximum: int, label: str) -> bytes:
    if row.size > maximum:
        raise NativeRuntimeTransformError(f"{label} exceeds its bound")
    digest = hashlib.sha256()
    parts = []
    cursor = 0
    while cursor < row.size:
        raw = os.pread(group.fd, min(READ_CHUNK, row.size - cursor), row.offset + cursor)
        if not raw:
            raise NativeRuntimeTransformError(f"{label} was truncated")
        parts.append(raw)
        digest.update(raw)
        cursor += len(raw)
    if not hmac.compare_digest(digest.digest(), row.sha256):
        raise NativeRuntimeTransformError(f"{label} commitment differs")
    group.rejoin()
    return b"".join(parts)


class _DecodedScratchFactory:
    """One-shot tempfile-compatible view over native-owned scratch row 21."""

    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor

    def __call__(self):
        os.ftruncate(self.descriptor, 0)
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        return os.fdopen(os.dup(self.descriptor), "w+b")


def _expand_with_scratch(
    descriptor: int,
    source: Any,
    entries: Any,
    collision_keys: Any,
    spool: Any,
    expanded: list[int],
    decoded_descriptor: int,
) -> None:
    compositor._expand_archive(
        descriptor,
        source,
        entries,
        collision_keys,
        spool,
        expanded,
        decoded_factory=_DecodedScratchFactory(decoded_descriptor),
    )


def _write_document(descriptor: int, raw: bytes, label: str) -> None:
    if type(raw) is not bytes or not raw or len(raw) > DOCUMENT_LIMIT:
        raise NativeRuntimeTransformError(f"{label} exceeds its bound")
    os.ftruncate(descriptor, 0)
    cursor = 0
    while cursor < len(raw):
        count = os.pwrite(descriptor, raw[cursor:], cursor)
        if count <= 0:
            raise NativeRuntimeTransformError(f"{label} write made no progress")
        cursor += count
    os.fsync(descriptor)
    if os.fstat(descriptor).st_size != len(raw):
        raise NativeRuntimeTransformError(f"{label} output size differs")


def _observation(
    *,
    archive_sha256: str,
    archive_size: int,
    manifest_sha256: str,
    sources: Any,
    entries: Any,
    expanded_bytes: int,
    census: bytes,
    sbom: bytes,
    provenance: bytes,
) -> bytes:
    return compositor._canonical_json(
        {
            "schema_version": OBSERVATION_SCHEMA_VERSION,
            "status": "CONTENT_COMPOSED_PENDING_NATIVE_RUNNER_RECEIPT",
            "production_authority": False,
            "target": "linux/arm64",
            "archive": {
                "media_type": "application/vnd.oci.image.layer.v1.tar",
                "sha256": archive_sha256,
                "size": archive_size,
                "diff_id": "sha256:" + archive_sha256,
            },
            "composition_manifest_sha256": manifest_sha256,
            "source_roster_sha256": compositor._source_roster_sha256(sources),
            "installed": {
                "entry_count": len(entries),
                "expanded_bytes": expanded_bytes,
                "census_sha256": compositor._digest(census),
                "sbom_sha256": compositor._digest(sbom),
                "provenance_sha256": compositor._digest(provenance),
            },
            "environment_denials": compositor._ENVIRONMENT_DENIALS,
            "network": "DENY",
            "package_execution": {
                "compositor_executed_scripts": False,
                "compositor_executed_triggers": False,
                "observed_installer_script_entries": sum(
                    row.installer_script for row in entries.values()
                ),
                "observed_trigger_entries": sum(
                    row.trigger_metadata for row in entries.values()
                ),
            },
            "authority_boundary": "PLAMEN_NATIVE_RETAINED_HELPER_RECEIPT_V1_REQUIRED",
            "solc_execution_policy": compositor._SOLC_EXECUTION_POLICY,
        }
    )


def run_runtime_materialize(
    group: Any,
    output_fds: tuple[int, ...],
    scratch_fds: tuple[int, ...],
) -> None:
    """Consume exact operation-4 inputs and populate five native-owned outputs."""
    _require_posix()
    if tuple(row.path for row in group.rows) != ROW_PATHS:
        raise NativeRuntimeTransformError("runtime grouped roster differs")
    source_row_count = len(ROLES) * 2
    spool_index = source_row_count
    archive_scratch_index = source_row_count + 1
    if len(group.rows) != 1 + source_row_count or sum(row.size for row in group.rows) > GROUP_LIMIT:
        raise NativeRuntimeTransformError("runtime grouped input bounds differ")
    if not hmac.compare_digest(group.request_sha256, group.rows[0].sha256):
        raise NativeRuntimeTransformError("runtime request binding differs")
    if type(output_fds) is not tuple or len(output_fds) != len(OUTPUT_ROLES):
        raise NativeRuntimeTransformError("runtime output roster differs")
    if type(scratch_fds) is not tuple or len(scratch_fds) != source_row_count + 2:
        raise NativeRuntimeTransformError("runtime scratch roster differs")

    output_identities = [
        _admit_file(fd, label=role, linked=False, empty=True)
        for fd, role in zip(output_fds, OUTPUT_ROLES, strict=True)
    ]
    scratch_identities = [
        _admit_file(fd, label=f"scratch {index}", linked=False, empty=True)
        for index, fd in enumerate(scratch_fds)
    ]
    objects = [(group.identity[0], group.identity[1])]
    objects.extend((row[0], row[1]) for row in output_identities)
    objects.extend((row[0], row[1]) for row in scratch_identities)
    if len(objects) != len(set(objects)):
        raise NativeRuntimeTransformError("runtime descriptors alias")

    try:
        for row, destination in zip(
            group.rows[1:], scratch_fds[:source_row_count], strict=True
        ):
            _copy_row(group, row, destination)

        manifest_raw = _read_row(
            group,
            group.rows[0],
            compositor.MAX_COMPOSITION_MANIFEST_BYTES,
            "runtime composition manifest",
        )
        manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
        if not hmac.compare_digest(manifest_sha256, group.request_sha256.hex()):
            raise NativeRuntimeTransformError("runtime manifest digest differs")
        _, sources = compositor._validate_composition_manifest(
            manifest_raw,
            manifest_sha256,
            expected_schema_version=(
                compositor.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION
            ),
            expected_authentication_scope=(
                compositor.NATIVE_RETAINED_AUTHENTICATION_SCOPE
            ),
        )
        if len(sources) != len(ROLES) or tuple(row["role"] for row in sources) != ROLES:
            raise NativeRuntimeTransformError("runtime source role order differs")

        source_manifests = {}
        unsupported = []
        for index, source in enumerate(sources):
            payload_fd = scratch_fds[index * 2]
            manifest_fd = scratch_fds[index * 2 + 1]
            payload_size = os.fstat(payload_fd).st_size
            source_manifest_size = os.fstat(manifest_fd).st_size
            if (
                payload_size != source["payload_size"]
                or source_manifest_size != source["source_manifest_size"]
                or not hmac.compare_digest(
                    compositor._hash_fd(payload_fd, payload_size, "source payload"),
                    source["payload_sha256"],
                )
            ):
                raise NativeRuntimeTransformError("runtime retained source differs")
            raw_source_manifest = compositor._read_exact(
                manifest_fd, source_manifest_size, "source manifest"
            )
            if not hmac.compare_digest(
                compositor._digest(raw_source_manifest),
                source["source_manifest_sha256"],
            ):
                raise NativeRuntimeTransformError("runtime source manifest differs")
            source_manifests[source["artifact_id"]] = compositor._validate_source_manifest(
                raw_source_manifest,
                source,
                expected_schema_version=(
                    compositor.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION
                ),
                expected_authentication_scope=(
                    compositor.NATIVE_RETAINED_AUTHENTICATION_SCOPE
                ),
            )
            if source["media_type"] in compositor._UNSUPPORTED_INSTALL_MEDIA:
                unsupported.append(source["artifact_id"])
        if unsupported:
            raise compositor.NetworklessLinuxBuilderRequired(unsupported)

        entries = {}
        collision_keys = {}
        expanded = [0]
        os.ftruncate(scratch_fds[spool_index], 0)
        os.lseek(scratch_fds[spool_index], 0, os.SEEK_SET)
        with os.fdopen(os.dup(scratch_fds[spool_index]), "w+b") as spool:
            for index, source in enumerate(sources):
                payload_fd = scratch_fds[index * 2]
                if source["media_type"] in compositor._ARCHIVE_MEDIA:
                    _expand_with_scratch(
                        payload_fd,
                        source,
                        entries,
                        collision_keys,
                        spool,
                        expanded,
                        scratch_fds[archive_scratch_index],
                    )
                elif source["media_type"] in compositor._RAW_MEDIA:
                    compositor._add_raw(
                        payload_fd, source,
                        source_manifests[source["artifact_id"]],
                        entries, collision_keys, spool, expanded
                    )
                else:
                    raise NativeRuntimeTransformError("runtime media type has no compositor")
            compositor._validate_links(entries)
            for source in sources:
                for path in source["required_paths"]:
                    try:
                        resolved = compositor._resolve_output(entries, path)
                    except compositor.RuntimeMaterializationError as error:
                        raise NativeRuntimeTransformError(
                            f"required output for {source['artifact_id']!r} is absent"
                        ) from error
                    if resolved.kind != "file":
                        raise NativeRuntimeTransformError("required output is not a file")
                    if (
                        path in compositor._REQUIRED_EXECUTABLE_OUTPUTS
                        and resolved.mode & 0o111 == 0
                    ):
                        raise NativeRuntimeTransformError("required output is not executable")
            if len(entries) > compositor.MAX_ENTRIES or expanded[0] > ARCHIVE_LIMIT:
                raise NativeRuntimeTransformError("runtime expansion exceeds its bound")
            census = compositor._make_census(entries)
            provenance = compositor._make_provenance(entries, manifest_sha256)
            sbom = compositor._make_sbom(
                entries, sources, source_manifests, manifest_sha256
            )
            spool.flush()
            archive_sha256, archive_size = compositor._write_archive(
                output_fds[0], entries, spool
            )
        if archive_size > ARCHIVE_LIMIT:
            raise NativeRuntimeTransformError("runtime archive exceeds its bound")
        observation = _observation(
            archive_sha256=archive_sha256,
            archive_size=archive_size,
            manifest_sha256=manifest_sha256,
            sources=sources,
            entries=entries,
            expanded_bytes=expanded[0],
            census=census,
            sbom=sbom,
            provenance=provenance,
        )
        for descriptor, raw, label in zip(
            output_fds[1:],
            (observation, census, sbom, provenance),
            OUTPUT_ROLES[1:],
            strict=True,
        ):
            _write_document(descriptor, raw, label)
        group.rejoin()
        for index, (descriptor, before) in enumerate(
            zip(scratch_fds, scratch_identities, strict=True)
        ):
            after = _identity(descriptor)
            if after[:5] != before[:5]:
                raise NativeRuntimeTransformError(f"scratch {index} identity changed")
    except BaseException:
        # Partial output is deliberate invalid residue.  The native parent
        # records its exact census and never adopts or retries these inodes.
        raise


def run(
    operation: int,
    group_fd: int,
    output_fds: tuple[int, ...],
    scratch_fds: tuple[int, ...],
) -> None:
    """Fixed embedded-helper dispatch target."""
    _require_posix()
    if type(operation) is not int or operation != OPERATION:
        raise NativeRuntimeTransformError("operation has no runtime transform")
    # Importing the generic parser from the immutable source bundle does not
    # grant it authority; the native helper has already admitted group_fd.
    from plamen_transform_bundle import GroupedInputs

    with GroupedInputs(group_fd, operation) as group:
        run_runtime_materialize(group, output_fds, scratch_fds)
