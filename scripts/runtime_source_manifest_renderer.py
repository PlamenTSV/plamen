"""Render operation-4 runtime source manifests from retained artifacts.

This module is deliberately a deterministic, non-authoritative renderer.  It
does not open pathnames, discover inputs, install software, read credentials,
or issue a receipt.  A native source-bootstrap coordinator must retain and
rejoin every payload and producer-receipt descriptor, bind the separate
``NATIVE_ACQUISITION_ROSTER_V1`` described below, retain the rendered manifest
bytes, and only then invoke the signed operation-4 helper.

The separate acquisition roster is essential.  Source manifests describe the
payload; their JSON fields are not proof that an acquisition policy ran.  For
each role, the native coordinator must bind this exact tuple in its own signed
transaction receipt::

    (role, payload fd identity/sha256/size,
     producer receipt fd identity/sha256/size, policy sha256)

Python observes those values here only to reject incomplete or internally
inconsistent candidate inputs.  It never parses a producer receipt and never
receives the native coordinator's signing key.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
if os.name == "posix":
    import fcntl
else:
    fcntl = None  # type: ignore[assignment]
import re
import stat
from typing import Any

import runtime_image_materializer as compositor


NATIVE_ACQUISITION_ROSTER_V1 = "PLAMEN_NATIVE_RUNTIME_ACQUISITION_ROSTER_V1"
NEXT_REQUIRED_AUTHORITY = "PLAMEN_NATIVE_SOURCE_BOOTSTRAP_COORDINATOR_RECEIPT_V1"
MAX_PRODUCER_RECEIPT_BYTES = 1024 * 1024
READ_CHUNK = 1024 * 1024

ROLES = compositor._REQUIRED_ROLES
OP4_ROW_PATHS = (
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

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_PRINTABLE_ASCII = re.compile(r"[\x21-\x7e]+\Z")


class RuntimeSourceRenderError(RuntimeError):
    """A retained source or its semantic metadata is not exact."""


def _require_posix() -> None:
    if fcntl is None:
        raise RuntimeSourceRenderError(
            "runtime source rendering requires POSIX descriptor APIs"
        )


@dataclass(frozen=True, slots=True)
class RetainedFileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class RetainedRuntimeSource:
    role: str
    artifact_id: str
    version: str
    source_reference: str
    payload_descriptor: int
    payload_identity: RetainedFileIdentity
    producer_receipt_descriptor: int
    producer_receipt_identity: RetainedFileIdentity
    policy_sha256: str
    archive_member: str | None = None
    archive_member_count: int | None = None
    archive_member_roster_sha256: str | None = None
    installed_sha256: str | None = None
    installed_size: int | None = None


@dataclass(frozen=True, slots=True)
class RenderedSourceManifest:
    role: str
    artifact_id: str
    row_path: str
    raw: bytes
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class AcquisitionRosterCandidate:
    role: str
    payload_descriptor: int
    payload_identity: RetainedFileIdentity
    producer_receipt_descriptor: int
    producer_receipt_identity: RetainedFileIdentity
    policy_sha256: str


@dataclass(frozen=True, slots=True)
class RenderedRuntimeSourceInputs:
    composition_manifest: bytes
    composition_manifest_sha256: str
    source_manifests: tuple[RenderedSourceManifest, ...]
    acquisition_roster: tuple[AcquisitionRosterCandidate, ...]
    op4_row_paths: tuple[str, ...]
    production_authority: bool = False
    next_required_authority: str = NEXT_REQUIRED_AUTHORITY


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise RuntimeSourceRenderError(f"{label} is not an exact sha256")
    return value


def _semantic_ascii(value: Any, label: str, maximum: int) -> str:
    if (
        type(value) is not str
        or len(value.encode("utf-8")) > maximum
        or _PRINTABLE_ASCII.fullmatch(value) is None
    ):
        raise RuntimeSourceRenderError(f"{label} is not canonical printable ASCII")
    return value


def _observed_identity(descriptor: int) -> RetainedFileIdentity:
    info = os.fstat(descriptor)
    return RetainedFileIdentity(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        mode=int(info.st_mode),
        uid=int(info.st_uid),
        gid=int(info.st_gid),
        links=int(info.st_nlink),
        size=int(info.st_size),
        mtime_ns=int(info.st_mtime_ns),
        ctime_ns=int(info.st_ctime_ns),
        sha256="",
    )


def retained_file_identity(descriptor: int) -> RetainedFileIdentity:
    _require_posix()
    """Observe a candidate identity; the native parent must repeat admission."""
    before = _admit_descriptor(descriptor, label="retained file", maximum=None)
    digest = _hash_descriptor(descriptor, before.size, "retained file")
    _rejoin(descriptor, before, "retained file")
    return RetainedFileIdentity(
        device=before.device,
        inode=before.inode,
        mode=before.mode,
        uid=before.uid,
        gid=before.gid,
        links=before.links,
        size=before.size,
        mtime_ns=before.mtime_ns,
        ctime_ns=before.ctime_ns,
        sha256=digest,
    )


def _admit_descriptor(
    descriptor: int,
    *,
    label: str,
    maximum: int | None,
) -> RetainedFileIdentity:
    if type(descriptor) is not int or descriptor < 3:
        raise RuntimeSourceRenderError(f"{label} descriptor is invalid")
    try:
        access = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        info = os.fstat(descriptor)
    except OSError as error:
        raise RuntimeSourceRenderError(f"{label} descriptor is unavailable") from error
    if access != os.O_RDONLY or descriptor_flags & fcntl.FD_CLOEXEC == 0:
        raise RuntimeSourceRenderError(f"{label} descriptor custody is not exact")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink < 1:
        raise RuntimeSourceRenderError(f"{label} descriptor identity is invalid")
    if info.st_size < 0 or (maximum is not None and info.st_size > maximum):
        raise RuntimeSourceRenderError(f"{label} exceeds its byte bound")
    return _observed_identity(descriptor)


def _hash_descriptor(descriptor: int, size: int, label: str) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(READ_CHUNK, size - offset), offset)
        if not block:
            raise RuntimeSourceRenderError(f"{label} was truncated")
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def _rejoin(
    descriptor: int,
    expected: RetainedFileIdentity,
    label: str,
) -> None:
    try:
        observed = _observed_identity(descriptor)
    except OSError as error:
        raise RuntimeSourceRenderError(f"{label} descriptor was lost") from error
    if observed != expected:
        raise RuntimeSourceRenderError(f"{label} descriptor identity changed")


def _admit_expected(
    descriptor: int,
    expected: RetainedFileIdentity,
    *,
    label: str,
    maximum: int | None,
) -> RetainedFileIdentity:
    if type(expected) is not RetainedFileIdentity:
        raise RuntimeSourceRenderError(f"{label} expected identity is invalid")
    for name in (
        "device",
        "inode",
        "mode",
        "uid",
        "gid",
        "links",
        "size",
        "mtime_ns",
        "ctime_ns",
    ):
        value = getattr(expected, name)
        if type(value) is not int or value < 0:
            raise RuntimeSourceRenderError(f"{label} expected identity is invalid")
    _sha256(expected.sha256, f"{label} expected sha256")
    observed = _admit_descriptor(descriptor, label=label, maximum=maximum)
    if observed != RetainedFileIdentity(
        device=expected.device,
        inode=expected.inode,
        mode=expected.mode,
        uid=expected.uid,
        gid=expected.gid,
        links=expected.links,
        size=expected.size,
        mtime_ns=expected.mtime_ns,
        ctime_ns=expected.ctime_ns,
        sha256="",
    ):
        raise RuntimeSourceRenderError(f"{label} differs from its retained identity")
    actual_sha256 = _hash_descriptor(descriptor, observed.size, label)
    if not hmac.compare_digest(actual_sha256, expected.sha256):
        raise RuntimeSourceRenderError(f"{label} digest differs")
    _rejoin(descriptor, observed, label)
    return observed


def _source_semantics(source: RetainedRuntimeSource) -> tuple[str, str, list[str]]:
    if type(source.artifact_id) is not str or _ARTIFACT_ID.fullmatch(source.artifact_id) is None:
        raise RuntimeSourceRenderError("artifact_id is invalid")
    version = _semantic_ascii(source.version, "version", 256)
    reference = _semantic_ascii(source.source_reference, "source_reference", 4096)
    if reference.startswith(("fixture:", "test:")):
        raise RuntimeSourceRenderError("source_reference names a non-production fixture")
    del version, reference
    destination, accepted_media = compositor._ROLE_CONTRACT[source.role]
    if len(accepted_media) != 1:
        raise RuntimeSourceRenderError("role media contract is ambiguous")
    media_type = next(iter(accepted_media))
    required_paths = list(compositor._REQUIRED_OUTPUTS[source.role])
    return destination, media_type, required_paths


def render_native_retained_runtime_inputs(
    sources: tuple[RetainedRuntimeSource, ...],
) -> RenderedRuntimeSourceInputs:
    """Render exact op4 manifests; return no authority or receipt."""
    _require_posix()
    if type(sources) is not tuple or len(sources) != len(ROLES):
        raise RuntimeSourceRenderError("runtime source roster is not exact")
    if any(type(source) is not RetainedRuntimeSource for source in sources):
        raise RuntimeSourceRenderError("runtime source row type is invalid")
    if tuple(source.role for source in sources) != ROLES:
        raise RuntimeSourceRenderError("runtime source role order is not exact")
    artifact_ids = tuple(source.artifact_id for source in sources)
    if len(set(artifact_ids)) != len(artifact_ids):
        raise RuntimeSourceRenderError("runtime artifact ids are not unique")

    all_descriptors = tuple(
        descriptor
        for source in sources
        for descriptor in (
            source.payload_descriptor,
            source.producer_receipt_descriptor,
        )
    )
    if len(set(all_descriptors)) != len(all_descriptors):
        raise RuntimeSourceRenderError("runtime retained descriptors alias")

    admitted: list[tuple[int, RetainedFileIdentity, str]] = []
    admitted_objects: set[tuple[int, int]] = set()
    source_rows: list[dict[str, Any]] = []
    rendered_manifests: list[RenderedSourceManifest] = []
    acquisition_rows: list[AcquisitionRosterCandidate] = []
    payload_total = 0

    for ordinal, source in enumerate(sources):
        _sha256(source.policy_sha256, f"{source.role} policy sha256")
        payload_observed = _admit_expected(
            source.payload_descriptor,
            source.payload_identity,
            label=f"{source.role} payload",
            maximum=compositor.MAX_INPUT_BYTES,
        )
        receipt_observed = _admit_expected(
            source.producer_receipt_descriptor,
            source.producer_receipt_identity,
            label=f"{source.role} producer receipt",
            maximum=MAX_PRODUCER_RECEIPT_BYTES,
        )
        if receipt_observed.size == 0:
            raise RuntimeSourceRenderError(f"{source.role} producer receipt is empty")
        objects = {
            (payload_observed.device, payload_observed.inode),
            (receipt_observed.device, receipt_observed.inode),
        }
        if len(objects) != 2 or admitted_objects.intersection(objects):
            raise RuntimeSourceRenderError("runtime retained descriptor objects alias")
        admitted_objects.update(objects)
        admitted.extend(
            (
                (source.payload_descriptor, payload_observed, f"{source.role} payload"),
                (
                    source.producer_receipt_descriptor,
                    receipt_observed,
                    f"{source.role} producer receipt",
                ),
            )
        )
        destination, media_type, required_paths = _source_semantics(source)
        source_manifest_value = {
            "artifact_id": source.artifact_id,
            "authentication_scope": compositor.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
            "media_type": media_type,
            "payload_sha256": source.payload_identity.sha256,
            "payload_size": source.payload_identity.size,
            "platform": compositor._ROLE_PLATFORM[source.role],
            "required_paths": required_paths,
            "role": source.role,
            "schema_version": compositor.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
            "source_reference": source.source_reference,
            "version": source.version,
        }
        if source.role in {"codex", "claude"}:
            source_manifest_value.update(
                {
                    "archive_member": source.archive_member,
                    "archive_member_count": source.archive_member_count,
                    "archive_member_roster_sha256": (
                        source.archive_member_roster_sha256
                    ),
                    "installed_sha256": source.installed_sha256,
                    "installed_size": source.installed_size,
                }
            )
        elif any(
            value is not None
            for value in (
                source.archive_member,
                source.archive_member_count,
                source.archive_member_roster_sha256,
                source.installed_sha256,
                source.installed_size,
            )
        ):
            raise RuntimeSourceRenderError(
                f"{source.role} cannot carry backend archive metadata"
            )
        raw_source_manifest = compositor._canonical_json(source_manifest_value)
        source_manifest_sha256 = hashlib.sha256(raw_source_manifest).hexdigest()
        row = {
            "artifact_id": source.artifact_id,
            "destination": destination,
            "media_type": media_type,
            "payload_sha256": source.payload_identity.sha256,
            "payload_size": source.payload_identity.size,
            "required_paths": required_paths,
            "role": source.role,
            "source_manifest_sha256": source_manifest_sha256,
            "source_manifest_size": len(raw_source_manifest),
        }
        compositor._validate_source_manifest(
            raw_source_manifest,
            row,
            expected_schema_version=compositor.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
            expected_authentication_scope=compositor.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        )
        source_rows.append(row)
        rendered_manifests.append(
            RenderedSourceManifest(
                role=source.role,
                artifact_id=source.artifact_id,
                row_path=OP4_ROW_PATHS[2 + ordinal * 2],
                raw=raw_source_manifest,
                size=len(raw_source_manifest),
                sha256=source_manifest_sha256,
            )
        )
        acquisition_rows.append(
            AcquisitionRosterCandidate(
                role=source.role,
                payload_descriptor=source.payload_descriptor,
                payload_identity=source.payload_identity,
                producer_receipt_descriptor=source.producer_receipt_descriptor,
                producer_receipt_identity=source.producer_receipt_identity,
                policy_sha256=source.policy_sha256,
            )
        )
        payload_total += source.payload_identity.size

    composition_value = {
        "authentication_scope": compositor.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        "environment_denials": compositor._ENVIRONMENT_DENIALS,
        "installation_policy": compositor._INSTALLATION_POLICY,
        "limits": compositor._LIMITS,
        "network": "DENY",
        "schema_version": compositor.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION,
        "sources": source_rows,
        "target": "linux/arm64",
    }
    raw_composition = compositor._canonical_json(composition_value)
    composition_sha256 = hashlib.sha256(raw_composition).hexdigest()
    compositor._validate_composition_manifest(
        raw_composition,
        composition_sha256,
        expected_schema_version=compositor.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION,
        expected_authentication_scope=compositor.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
    )
    total = payload_total + len(raw_composition) + sum(
        manifest.size for manifest in rendered_manifests
    )
    if total > compositor.MAX_INPUT_BYTES:
        raise RuntimeSourceRenderError("rendered runtime inputs exceed the op4 bound")

    for descriptor, identity, label in admitted:
        _rejoin(descriptor, identity, label)

    return RenderedRuntimeSourceInputs(
        composition_manifest=raw_composition,
        composition_manifest_sha256=composition_sha256,
        source_manifests=tuple(rendered_manifests),
        acquisition_roster=tuple(acquisition_rows),
        op4_row_paths=OP4_ROW_PATHS,
    )
