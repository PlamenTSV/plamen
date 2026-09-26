"""Deterministic, fail-closed OCI image-layout construction.

The production entrypoint accepts only the *exact* production plan type from
``oci_image_lock`` and delegates ownership to that plan's authenticated
out-of-process consumer.  The current image-lock seam intentionally refuses
such consumption until the native verifier/consumer is integrated, so this
module cannot turn a Python callback, subclass, marker, or test plan into
production authority.

The private testing entrypoint exercises the byte renderer against the
image-lock module's distinct test-only retained-reader seam.  It stages the
entire layout below a no-follow, owner-private parent, obtains a strict
read-completion acknowledgement only after every retained reader reached
authenticated EOF, verifies the staged layout, and publishes it with one
same-directory rename.  Its pathname-returning build/verify/archive helpers
are explicitly test-only and confer no production identity authority.

The pinned Debian root contains ``/etc/ld.so.cache``.  Production rendering
therefore remains typed-blocked until the pinned glibc loader's authenticated
cache and hwcaps selection semantics are implemented; binding the cache bytes
alone is deliberately not treated as dependency-closure proof.

Security boundary: this module and ``oci_image_lock`` execute in one trusted
supervisor interpreter.  Python global/closure mutation by hostile code in
that interpreter is out of scope; untrusted audit/model code must remain in a
separate OS-enforced process or guest.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import base64
import ctypes
from dataclasses import dataclass
import errno
import functools
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import secrets
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
from typing import Any, BinaryIO
import unicodedata
import zlib

import elf_loader_closure as elf_closure
import oci_image_lock as image_lock


OCI_LAYOUT_VERSION = "1.0.0"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
LAYOUT_RECEIPT_SCHEMA_VERSION = "plamen.oci_layout_receipt.v5"
LAYOUT_ACK_SCHEMA_VERSION = "plamen.oci_layout_read_ack.v1"
OCI_ARCHIVE_RECEIPT_SCHEMA_VERSION = "plamen.oci_archive_receipt.v1"

# The renderer deliberately builds a complete scratch-root filesystem.  The
# digest names that architectural choice; it is not an OCI parent manifest.
# A lock may use a different registry/namespace spelling ending in
# ``/empty-root``, but it must bind this exact sentinel digest.  The full
# reference is retained in the image labels, so alias changes cannot produce
# byte-identical output.
EMPTY_ROOT_DIGEST = "sha256:" + hashlib.sha256(
    b"plamen complete scratch rootfs v1\n"
).hexdigest()
EMPTY_ROOT_REFERENCE = f"scratch.plamen.invalid/empty-root@{EMPTY_ROOT_DIGEST}"

RUNTIME_ENTRYPOINT = "/usr/local/libexec/plamen-guest"
RUNTIME_WORKDIR = "/workspace/project"
RUNTIME_USER = "65532:65532"
RUNTIME_DYNAMIC_LIBRARIES = (
    "lib/ld-linux-aarch64.so.1",
    "lib/aarch64-linux-gnu/libc.so.6",
    "lib/aarch64-linux-gnu/libdl.so.2",
    "lib/aarch64-linux-gnu/libm.so.6",
    "lib/aarch64-linux-gnu/libpthread.so.0",
    "lib/aarch64-linux-gnu/librt.so.1",
)
RUNTIME_ENV = (
    "FOUNDRY_OFFLINE=true",
    "PATH=/usr/local/lib/plamen/bin:/usr/local/lib/plamen/toolchains/foundry/bin:/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE=1",
    "PYTHONNOUSERSITE=1",
)
_CREATED = "1970-01-01T00:00:00Z"
_LAYER_CREATED_BY = "plamen deterministic offline runtime assembler v1"
_LAYER_COMMENT = "complete scratch-root audit runtime from authenticated closure"

_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 65_536
_MAX_STRING_BYTES = 65_536
_MAX_INPUTS = 4_096
_MAX_INPUT_BYTES = 8 * 1024 * 1024 * 1024
_MAX_EXPANDED_BYTES = 12 * 1024 * 1024 * 1024
# The locked DODO composition is currently expected to install roughly 56,637
# filesystem entries (Debian + CPython + the complete wheel closure).  Keep a
# power-of-two ceiling with more than 2x headroom for directories and links,
# while retaining a finite allocation/iteration bound against archive bombs.
_LOCKED_DODO_EXPECTED_ENTRY_FLOOR = 56_637
_MAX_LAYER_ENTRIES = 131_072
_MAX_PATH_COMPONENTS = 64
_MAX_PATH_BYTES = 4_096
_MAX_COMPONENT_BYTES = 255
_READ_CHUNK = 1024 * 1024
_ELF_IDENTITY_BYTES = 20
_LINUX_BINPRM_BUF_SIZE = 256
_ELF_DEFAULT_LIBRARY_PATHS = (
    "lib/aarch64-linux-gnu",
    "usr/lib/aarch64-linux-gnu",
    "lib",
    "usr/lib",
)
_SHA256_PREFIX = "sha256:"
_DIGEST_LENGTH = 71
_PRODUCTION_CONSUMER_REQUIRED = "AUTHENTICATED_CONTEXT_CONSUMER_REQUIRED"
_COMPLETE_ROOTFS_REQUIRED = "COMPLETE_ROOTFS_ARCHIVE_REQUIRED"
_TEST_AUTHENTICATION_SCOPE = "TEST_ONLY_NO_RELEASE_AUTHORITY"
_ROOTFS_PROVENANCE_SCHEMA_VERSION = "plamen.complete_rootfs_provenance.v1"
_DEBIAN_OFFICIAL_IMAGES_COMMIT = "b9c995a1c91bf8b195b035893ebdf8e877e7f7fa"
_DEBIAN_RELEASE_REFERENCE = (
    "docker.io/library/debian:bookworm-20260824-slim@"
    "sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
)
_DEBIAN_RELEASE_CLOSURE = {
    "config_digest": "sha256:32d322b19846336d25f755f73618a448e3621982d52c48064e95af8b3dcbc2d9",
    "config_size": 468,
    "index_digest": "sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",
    "index_size": 5_651,
    "layer_digest": "sha256:75782e20ea1f4a9d9259bc20a5ecbbea8d5943bf5370bf0f5727900728f1cc9a",
    "layer_diff_id": "sha256:13a56b6535801be2adde694dabaf1c2df1d862a390661907dac821c42cd565cc",
    "layer_size": 28_117_289,
    "manifest_digest": "sha256:6bd27d44e6c32a66bbd72d7cb2b76a8ae3497ec2e5274a81abd1b37f6013fa1f",
    "manifest_size": 1_041,
    "official_images_commit": _DEBIAN_OFFICIAL_IMAGES_COMMIT,
    "official_images_sha256": "6d254035660febfa46162fc76a1a148f217387677ff740a5bf1ed3c35aabb443",
    "platform": "linux/arm64/v8",
    "schema_version": _ROOTFS_PROVENANCE_SCHEMA_VERSION,
    "source_reference": _DEBIAN_RELEASE_REFERENCE,
}
_ROOTFS_PROVENANCE_KEYS = frozenset(
    {
        "authentication_scope",
        "config_digest",
        "config_size",
        "index_digest",
        "index_size",
        "layer_digest",
        "layer_diff_id",
        "layer_size",
        "manifest_digest",
        "manifest_size",
        "official_images_commit",
        "official_images_sha256",
        "platform",
        "schema_version",
        "source_reference",
    }
)
_ROOTFS_EVIDENCE_ASSET_IDS = frozenset(
    {
        "complete-rootfs-config",
        "complete-rootfs-index",
        "complete-rootfs-manifest",
        "complete-rootfs-official-images",
    }
)
_ROOTFS_ASSET_IDS = frozenset(
    {
        "complete-rootfs",
        "complete-rootfs-provenance",
        "runtime-closure",
        *_ROOTFS_EVIDENCE_ASSET_IDS,
    }
)
_PROVIDER_OWNED_ROOTS = frozenset({"dev", "proc", "run", "sys", "tmp", "workspace"})
_ROOTFS_PROVIDER_LINK_POLICY = frozenset(
    {("var/lock", "/run/lock"), ("var/run", "/run")}
)

_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "authentication_scope",
        "lock_sha256",
        "release_generation",
        "release_nonce",
        "host_platform",
        "target_platform",
        "base_image_reference",
        "expected_image_reference",
        "expected_index_digest",
        "expected_manifest_digest",
        "expected_config_digest",
        "expected_apple_container_configuration_sha256",
        "runtime",
        "rootfs_derivation",
        "attestations",
        "runtime_materialization",
        "network",
        "runtime_package_resolution",
        "build_input_admission",
        "build_context_authority",
        "observed_build_input_census_sha256",
        "build_inputs",
        "executor_requirements",
        "plan_sha256",
    }
)
_INPUT_KEYS = frozenset({"path", "sha256", "size", "mode"})
_DESCRIPTOR_KEYS = frozenset({"digest", "mediaType", "size"})
_PLATFORM_DESCRIPTOR_KEYS = frozenset(
    {"digest", "mediaType", "platform", "size"}
)
_CONFIG_KEYS = frozenset(
    {"architecture", "config", "created", "history", "os", "rootfs"}
)
_EXECUTION_CONFIG_KEYS = frozenset(
    {"Entrypoint", "Env", "Labels", "User", "WorkingDir"}
)
_LABEL_KEYS = frozenset(
    {
        "org.plamen.build-input-census.sha256",
        "org.plamen.complete-rootfs.provenance.sha256",
        "org.plamen.complete-rootfs.derivation-manifest.sha256",
        "org.plamen.complete-rootfs.derived-census.sha256",
        "org.plamen.complete-rootfs.derived-diff-id",
        "org.plamen.complete-rootfs.derived.sha256",
        "org.plamen.complete-rootfs.source.sha256",
        "org.plamen.empty-root.lock-reference",
        "org.plamen.runtime-census.sha256",
        "org.plamen.runtime-dependencies.sha256",
        "org.plamen.runtime-files.sha256",
        "org.plamen.runtime-materialization.archive.diff-id",
        "org.plamen.runtime-materialization.archive.sha256",
        "org.plamen.runtime-materialization.archive.size",
        "org.plamen.runtime-materialization.composition-manifest.sha256",
        "org.plamen.runtime-materialization.entry-count",
        "org.plamen.runtime-materialization.expanded-bytes",
        "org.plamen.runtime-materialization.installed-census.sha256",
        "org.plamen.runtime-materialization.provenance.sha256",
        "org.plamen.runtime-materialization.receipt.sha256",
        "org.plamen.runtime-materialization.sbom.sha256",
        "org.plamen.runtime-materialization.source-roster.sha256",
        "org.plamen.sbom.sha256",
    }
)
_INSTALLED_ATTESTATION_PATHS = frozenset(
    {
        "usr/local/lib/plamen/attestations/census.json",
        "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json",
        "usr/local/lib/plamen/attestations/complete-rootfs-provenance.json",
        "usr/local/lib/plamen/attestations/sbom.json",
    }
)
_ALLOWED_ROOT_COMPONENTS = frozenset(
    {
        "bin",
        "boot",
        "dev",
        "etc",
        "home",
        "lib",
        "lib64",
        "media",
        "mnt",
        "opt",
        "proc",
        "root",
        "run",
        "sbin",
        "srv",
        "sys",
        "tmp",
        "usr",
        "var",
    }
)


class DeterministicOCILayoutError(RuntimeError):
    """The requested layout could not be rendered or verified safely."""


def _require_layer_entry_count(count: int, label: str) -> None:
    if type(count) is not int or count < 0 or count > _MAX_LAYER_ENTRIES:
        raise DeterministicOCILayoutError(f"{label} entry count exceeds its bound")


def _public_boundary(label: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(function)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except DeterministicOCILayoutError as exc:
                message = str(exc)
            except Exception:
                message = f"{label} failed closed"
            error = DeterministicOCILayoutError(message)
            error.__cause__ = None
            error.__context__ = None
            raise error from None

        return guarded

    return decorate


@dataclass(frozen=True)
class OCIImageLayoutResult:
    """Authenticated-read result for a deterministically published layout."""

    index_digest: str
    manifest_digest: str
    config_digest: str
    apple_container_configuration_sha256: str
    layer_digest: str
    layer_diff_id: str
    receipt: bytes
    runtime_files_sha256: str
    sbom_sha256: str
    runtime_census_sha256: str
    runtime_dependency_census_sha256: str
    empty_root_reference: str
    complete_rootfs_source_sha256: str
    complete_rootfs_provenance_sha256: str
    complete_rootfs_derivation_manifest_sha256: str
    complete_rootfs_derived_sha256: str
    complete_rootfs_derived_diff_id: str
    complete_rootfs_derived_census_sha256: str
    runtime_materialization_source_roster_sha256: str
    runtime_materialization_composition_manifest_sha256: str
    runtime_materialization_archive_sha256: str
    runtime_materialization_archive_diff_id: str
    runtime_materialization_archive_size: int
    installed_runtime_census_sha256: str
    runtime_materialization_receipt_sha256: str
    runtime_materialization_sbom_sha256: str
    runtime_materialization_provenance_sha256: str
    installed_runtime_entry_count: int
    installed_runtime_expanded_bytes: int


@dataclass(frozen=True)
class OCIImageArchiveResult:
    """Exact deterministic outer archive used by provider import APIs."""

    archive_sha256: str
    archive_size: int
    index_digest: str
    manifest_digest: str
    config_digest: str
    apple_container_configuration_sha256: str


@dataclass
class _ExpandedEntry:
    path: str
    sha256: str
    size: int
    mode: int
    source: BinaryIO | None
    kind: str = "file"
    linkname: str = ""


@dataclass(frozen=True)
class _InputMetadata:
    path: str
    sha256: str
    size: int
    mode: int


@dataclass(frozen=True)
class _LayerResult:
    blob_digest: str
    blob_size: int
    diff_id: str
    uncompressed_size: int


@dataclass(frozen=True)
class _ELFMetadata:
    interpreter: str | None
    needed: tuple[str, ...]
    soname: str | None
    rpath: tuple[str, ...]
    runpath: tuple[str, ...]
    nodeflib: bool
    dynamic: bool


@dataclass
class _StagedLayout:
    parent_descriptor: int
    parent_identity: tuple[int, int, int]
    parent_relationships: tuple[tuple[int, str, int, tuple[int, int, int]], ...]
    staging_name: str
    output_name: str
    output_path: str
    lock_name: str
    index_digest: str
    manifest_digest: str
    config_digest: str
    apple_container_configuration_sha256: str
    layer_digest: str
    layer_diff_id: str
    runtime_files_sha256: str
    sbom_sha256: str
    runtime_census_sha256: str
    runtime_dependency_census_sha256: str
    empty_root_reference: str
    complete_rootfs_source_sha256: str
    complete_rootfs_provenance_sha256: str
    complete_rootfs_derivation_manifest_sha256: str
    complete_rootfs_derived_sha256: str
    complete_rootfs_derived_diff_id: str
    complete_rootfs_derived_census_sha256: str
    runtime_materialization_source_roster_sha256: str
    runtime_materialization_composition_manifest_sha256: str
    runtime_materialization_archive_sha256: str
    runtime_materialization_archive_diff_id: str
    runtime_materialization_archive_size: int
    installed_runtime_census_sha256: str
    runtime_materialization_receipt_sha256: str
    runtime_materialization_sbom_sha256: str
    runtime_materialization_provenance_sha256: str
    installed_runtime_entry_count: int
    installed_runtime_expanded_bytes: int
    receipt: bytes
    retained_root_descriptor: int
    retained_root_identity: tuple[int, ...]
    published: bool = False


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DeterministicOCILayoutError("OCI JSON is not canonical") from exc


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeterministicOCILayoutError("duplicate JSON key is forbidden")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise DeterministicOCILayoutError("non-finite JSON number is forbidden")


def _bounded_json_tree(value: Any, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise DeterministicOCILayoutError("OCI JSON exceeds its depth bound")
    if value is None or type(value) in {bool, int, float}:
        return 1
    if isinstance(value, str):
        try:
            rendered = value.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise DeterministicOCILayoutError("OCI JSON is not strict UTF-8") from exc
        if len(rendered) > _MAX_STRING_BYTES:
            raise DeterministicOCILayoutError("OCI JSON string exceeds its bound")
        return 1
    if isinstance(value, list):
        count = 1
        for item in value:
            count += _bounded_json_tree(item, depth + 1)
            if count > _MAX_JSON_NODES:
                raise DeterministicOCILayoutError("OCI JSON exceeds its node bound")
        return count
    if isinstance(value, dict):
        count = 1
        for key, item in value.items():
            count += _bounded_json_tree(key, depth + 1)
            count += _bounded_json_tree(item, depth + 1)
            if count > _MAX_JSON_NODES:
                raise DeterministicOCILayoutError("OCI JSON exceeds its node bound")
        return count
    raise DeterministicOCILayoutError("OCI JSON contains a non-JSON value")


def _parse_canonical_json(raw: bytes, label: str) -> Any:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_JSON_BYTES:
        raise DeterministicOCILayoutError(f"{label} size is outside its bound")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except DeterministicOCILayoutError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise DeterministicOCILayoutError(f"{label} is malformed") from exc
    _bounded_json_tree(value)
    if raw != _canonical_bytes(value):
        raise DeterministicOCILayoutError(f"{label} is not canonical")
    return value


def _parse_content_addressed_json(raw: bytes, label: str) -> Any:
    """Parse bounded registry JSON whose authenticated bytes need not be canonical."""

    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_JSON_BYTES:
        raise DeterministicOCILayoutError(f"{label} size is outside its bound")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except DeterministicOCILayoutError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise DeterministicOCILayoutError(f"{label} is malformed") from exc
    _bounded_json_tree(value)
    return value


def _sha256(raw: bytes) -> str:
    return _SHA256_PREFIX + hashlib.sha256(raw).hexdigest()


def _validate_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _DIGEST_LENGTH
        or not value.startswith(_SHA256_PREFIX)
    ):
        raise DeterministicOCILayoutError(f"{label} is malformed")
    encoded = value[len(_SHA256_PREFIX) :]
    if any(character not in "0123456789abcdef" for character in encoded):
        raise DeterministicOCILayoutError(f"{label} is malformed")
    return value


def _validate_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise DeterministicOCILayoutError(f"{label} is not canonical")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise DeterministicOCILayoutError(f"{label} is not strict UTF-8") from exc
    parsed = PurePosixPath(value)
    parts = parsed.parts
    if (
        len(raw) > _MAX_PATH_BYTES
        or "\\" in value
        or "\x00" in value
        or parsed.is_absolute()
        or not parts
        or len(parts) > _MAX_PATH_COMPONENTS
        or parsed.as_posix() != value
        or any(
            not part
            or part in {".", ".."}
            or unicodedata.normalize("NFC", part) != part
            or len(part.encode("utf-8", "strict")) > _MAX_COMPONENT_BYTES
            for part in parts
        )
    ):
        raise DeterministicOCILayoutError(f"{label} escapes or aliases the layer")
    return value


def _validate_plan_shape(plan: Mapping[str, Any]) -> tuple[_InputMetadata, ...]:
    if set(plan) != _PLAN_KEYS:
        raise DeterministicOCILayoutError("build plan has an unsupported schema")
    _bounded_json_tree(dict(plan))
    if len(_canonical_bytes(dict(plan))) > _MAX_JSON_BYTES:
        raise DeterministicOCILayoutError("build plan JSON exceeds its byte bound")
    if plan.get("schema_version") != image_lock.BUILD_PLAN_SCHEMA_VERSION:
        raise DeterministicOCILayoutError("build plan schema version is unsupported")
    if plan.get("host_platform") != image_lock.APPLE_HOST_PLATFORM:
        raise DeterministicOCILayoutError("build plan host platform is unsupported")
    if plan.get("target_platform") != image_lock.TARGET_PLATFORM:
        raise DeterministicOCILayoutError("build plan target platform is unsupported")
    runtime = plan.get("runtime")
    raw_inputs = plan.get("build_inputs")
    if not isinstance(runtime, dict) or not isinstance(raw_inputs, list):
        raise DeterministicOCILayoutError("build plan runtime derivation is malformed")
    try:
        image_lock._validate_rootfs_derivation(
            plan.get("rootfs_derivation"),
            assets=runtime.get("assets", ()),
            inputs={str(item.get("path")): item for item in raw_inputs if isinstance(item, dict)},
        )
    except image_lock.OCIImageLockError as exc:
        raise DeterministicOCILayoutError(
            "build plan rootfs derivation binding is invalid"
        ) from exc
    denials = plan["rootfs_derivation"]["forbidden_environment"]
    environment_names = [item.split("=", 1)[0] for item in RUNTIME_ENV]
    if any(
        name in denials["exact_names"]
        or any(name.startswith(prefix) for prefix in denials["prefixes"])
        for name in environment_names
    ):
        raise DeterministicOCILayoutError(
            "execution environment violates the rootfs derivation policy"
        )
    if (
        plan.get("network") != "DENY"
        or plan.get("runtime_package_resolution") != "DENY"
        or plan.get("build_input_admission") != "EXACT_ROSTER"
        or plan.get("build_context_authority")
        != "ONE_SHOT_RETAINED_INPUT_READERS"
    ):
        raise DeterministicOCILayoutError("build plan weakens executor policy")
    requirements = plan.get("executor_requirements")
    if requirements != [
        "CONSUME_RETAINED_BUILD_CONTEXT_AUTHORITY_ONCE",
        "ENFORCE_NETWORK_NONE",
        "VERIFY_OUTPUT_MANIFEST_DIGEST",
        "VERIFY_SBOM_AND_INSTALLED_RUNTIME_CENSUS",
    ]:
        raise DeterministicOCILayoutError("build plan executor requirements drifted")
    plan_digest = plan.get("plan_sha256")
    if (
        not isinstance(plan_digest, str)
        or len(plan_digest) != 64
        or any(character not in "0123456789abcdef" for character in plan_digest)
    ):
        raise DeterministicOCILayoutError("build plan digest is malformed")
    body = dict(plan)
    body.pop("plan_sha256", None)
    if not hmac.compare_digest(plan_digest, hashlib.sha256(_canonical_bytes(body)).hexdigest()):
        raise DeterministicOCILayoutError("build plan digest mismatch")
    for field in ("lock_sha256", "observed_build_input_census_sha256"):
        value = plan.get(field)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise DeterministicOCILayoutError(f"build plan {field} is malformed")
    generation = plan.get("release_generation")
    if type(generation) is not int or not 1 <= generation <= 2**63 - 1:
        raise DeterministicOCILayoutError("build plan release generation is invalid")
    nonce = plan.get("release_nonce")
    if (
        not isinstance(nonce, str)
        or not 32 <= len(nonce) <= 128
        or any(character not in "0123456789abcdef" for character in nonce)
    ):
        raise DeterministicOCILayoutError("build plan release nonce is malformed")
    for field in ("base_image_reference", "expected_image_reference"):
        reference = plan.get(field)
        if (
            not isinstance(reference, str)
            or reference != reference.strip()
            or len(reference.encode("utf-8", "strict")) > 512
            or reference.count("@") != 1
        ):
            raise DeterministicOCILayoutError(f"build plan {field} is malformed")
        _validate_digest(reference.rsplit("@", 1)[1], f"build plan {field} digest")
    expected_index = _validate_digest(
        plan.get("expected_index_digest"), "build plan expected index digest"
    )
    expected_manifest = _validate_digest(
        plan.get("expected_manifest_digest"),
        "build plan expected manifest digest",
    )
    if hmac.compare_digest(expected_index, expected_manifest):
        raise DeterministicOCILayoutError(
            "build plan index and selected manifest digests must be distinct"
        )
    _validate_digest(
        plan.get("expected_config_digest"),
        "build plan expected config digest",
    )
    apple_configuration_sha256 = plan.get(
        "expected_apple_container_configuration_sha256"
    )
    if (
        not isinstance(apple_configuration_sha256, str)
        or len(apple_configuration_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in apple_configuration_sha256
        )
    ):
        raise DeterministicOCILayoutError(
            "build plan Apple Container configuration digest is malformed"
        )
    if not hmac.compare_digest(
        str(plan["expected_image_reference"]).rsplit("@", 1)[1],
        expected_index,
    ):
        raise DeterministicOCILayoutError(
            "build plan image reference does not bind its expected index"
        )
    base_reference = str(plan["base_image_reference"])
    base_name, base_digest = base_reference.rsplit("@", 1)
    if (
        not base_name.endswith("/empty-root")
        or not hmac.compare_digest(base_digest, EMPTY_ROOT_DIGEST)
    ):
        raise DeterministicOCILayoutError(
            "build plan must bind the complete scratch empty-root sentinel"
        )
    rows = plan.get("build_inputs")
    if not isinstance(rows, list) or not rows or len(rows) > _MAX_INPUTS:
        raise DeterministicOCILayoutError("build-input count is outside its bound")
    result: list[_InputMetadata] = []
    total = 0
    prior_key: tuple[str, str] | None = None
    aliases: set[str] = set()
    files: set[str] = set()
    directories: set[str] = set()
    component_spellings: dict[tuple[tuple[str, ...], str], str] = {}
    kind_by_alias: dict[str, str] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != _INPUT_KEYS:
            raise DeterministicOCILayoutError("build-input row schema is unsupported")
        path = _validate_relative_path(row["path"], f"build-input path {index}")
        digest = row["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise DeterministicOCILayoutError("build-input digest is malformed")
        size = row["size"]
        if type(size) is not int or size < 0:
            raise DeterministicOCILayoutError("build-input size is invalid")
        total += size
        if total > _MAX_INPUT_BYTES:
            raise DeterministicOCILayoutError("build-input bytes exceed their bound")
        mode_text = row["mode"]
        if (
            not isinstance(mode_text, str)
            or len(mode_text) != 4
            or mode_text[0] != "0"
            or any(character not in "01234567" for character in mode_text[1:])
        ):
            raise DeterministicOCILayoutError("build-input mode is malformed")
        mode = int(mode_text, 8)
        if mode & 0o022 or mode & 0o400 == 0:
            raise DeterministicOCILayoutError("build-input mode is unsafe")
        key = (path.casefold(), path)
        if prior_key is not None and key <= prior_key:
            raise DeterministicOCILayoutError("build-input order is not canonical")
        prior_key = key
        alias = unicodedata.normalize("NFC", path).casefold()
        if alias in aliases:
            raise DeterministicOCILayoutError("build-input paths collide")
        aliases.add(alias)
        parts = PurePosixPath(path).parts
        parent_alias: tuple[str, ...] = ()
        for component in parts:
            component_key = (parent_alias, component.casefold())
            prior_spelling = component_spellings.get(component_key)
            if prior_spelling is not None and prior_spelling != component:
                raise DeterministicOCILayoutError(
                    "build-input path components collide"
                )
            component_spellings[component_key] = component
            parent_alias = (*parent_alias, component.casefold())
        for end in range(1, len(parts)):
            parent = PurePosixPath(*parts[:end]).as_posix()
            if parent in files:
                raise DeterministicOCILayoutError("build-input descends from a file")
            directories.add(parent)
            alias_parent = unicodedata.normalize("NFC", parent).casefold()
            if kind_by_alias.get(alias_parent) == "file":
                raise DeterministicOCILayoutError(
                    "build-input path aliases a file"
                )
            kind_by_alias[alias_parent] = "directory"
        if path in directories:
            raise DeterministicOCILayoutError("build-input aliases a directory")
        if kind_by_alias.get(alias) == "directory":
            raise DeterministicOCILayoutError("build-input aliases a directory")
        kind_by_alias[alias] = "file"
        files.add(path)
        result.append(_InputMetadata(path, digest, size, mode))
    _require_layer_entry_count(len(files) + len(directories), "layer")
    observed_census = hashlib.sha256(_canonical_bytes(rows)).hexdigest()
    if not hmac.compare_digest(
        observed_census,
        str(plan["observed_build_input_census_sha256"]),
    ):
        raise DeterministicOCILayoutError("build-input census digest mismatch")
    _runtime_input_roles(plan, tuple(result))
    return tuple(result)


def _runtime_input_roles(
    plan: Mapping[str, Any], rows: Sequence[_InputMetadata]
) -> dict[str, tuple[str, str]]:
    """Return exact input-path -> (kind, identifier) installation roles."""

    runtime = plan.get("runtime")
    attestations = plan.get("attestations")
    if not isinstance(runtime, dict) or set(runtime) != {
        "cpython",
        "backend_clis",
        "toolchains",
        "assets",
    }:
        raise DeterministicOCILayoutError("runtime closure schema is unsupported")
    if not isinstance(attestations, dict) or set(attestations) != {"sbom", "census"}:
        raise DeterministicOCILayoutError("attestation closure schema is unsupported")

    candidates: list[tuple[Mapping[str, Any], str, str]] = []
    cpython = runtime["cpython"]
    if not isinstance(cpython, dict) or set(cpython) != {"path", "sha256", "version"}:
        raise DeterministicOCILayoutError("CPython closure schema is unsupported")
    candidates.append((cpython, "cpython_archive", "cpython"))

    backends = runtime["backend_clis"]
    if not isinstance(backends, list) or [row.get("backend") for row in backends if isinstance(row, dict)] != ["claude", "codex"]:
        raise DeterministicOCILayoutError("backend runtime roster is unsupported")
    for row in backends:
        if not isinstance(row, dict) or set(row) != {"backend", "path", "sha256", "version"}:
            raise DeterministicOCILayoutError("backend closure schema is unsupported")
        candidates.append((row, "backend", str(row["backend"])))

    toolchains = runtime["toolchains"]
    if not isinstance(toolchains, list) or not toolchains:
        raise DeterministicOCILayoutError("toolchain runtime roster is empty")
    for row in toolchains:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "toolchain_id", "version"}:
            raise DeterministicOCILayoutError("toolchain closure schema is unsupported")
        candidates.append((row, "toolchain_archive", str(row["toolchain_id"])))

    assets = runtime["assets"]
    if not isinstance(assets, list) or not assets:
        raise DeterministicOCILayoutError("runtime asset roster is empty")
    asset_ids = {
        row.get("asset_id") for row in assets if isinstance(row, dict)
    }
    if asset_ids != _ROOTFS_ASSET_IDS:
        raise DeterministicOCILayoutError(_COMPLETE_ROOTFS_REQUIRED)
    for row in assets:
        if not isinstance(row, dict) or set(row) != {"asset_id", "path", "sha256"}:
            raise DeterministicOCILayoutError("runtime asset closure schema is unsupported")
        asset_id = str(row["asset_id"])
        if asset_id == "complete-rootfs-provenance":
            kind = "rootfs_provenance"
        elif asset_id in _ROOTFS_EVIDENCE_ASSET_IDS:
            kind = "rootfs_evidence"
        elif asset_id in {"complete-rootfs", "runtime-closure"}:
            kind = "rootfs_archive"
        else:
            raise DeterministicOCILayoutError("runtime asset role is unsupported")
        candidates.append((row, kind, asset_id))

    sbom = attestations["sbom"]
    census = attestations["census"]
    if not isinstance(sbom, dict) or set(sbom) != {"format", "path", "sha256"}:
        raise DeterministicOCILayoutError("SBOM closure schema is unsupported")
    if not isinstance(census, dict) or set(census) != {"path", "schema_version", "sha256"}:
        raise DeterministicOCILayoutError("runtime-census closure schema is unsupported")
    candidates.extend(((sbom, "attestation", "sbom"), (census, "attestation", "census")))

    materialization = plan.get("runtime_materialization")
    if (
        not isinstance(materialization, dict)
        or set(materialization)
        != {
            "schema_version",
            "required_roles",
            "source_roster_sha256",
            "composition_manifest",
            "archive",
            "receipt",
            "census",
            "sbom",
            "provenance",
        }
        or materialization.get("schema_version")
        != image_lock.RUNTIME_MATERIALIZATION_SCHEMA_VERSION
        or materialization.get("required_roles")
        != list(image_lock.RUNTIME_MATERIALIZATION_REQUIRED_ROLES)
    ):
        raise DeterministicOCILayoutError(
            "runtime materialization binding is unsupported"
        )
    for name in (
        "composition_manifest",
        "archive",
        "receipt",
        "census",
        "sbom",
        "provenance",
    ):
        value = materialization.get(name)
        if not isinstance(value, dict):
            raise DeterministicOCILayoutError(
                "runtime materialization descriptor is malformed"
            )
        candidates.append(
            (
                value,
                (
                    "materialized_runtime_archive"
                    if name == "archive"
                    else "materialization_evidence"
                ),
                name,
            )
        )

    by_path = {row.path: row for row in rows}
    roles: dict[str, tuple[str, str]] = {}
    for candidate, kind, identifier in candidates:
        path = candidate.get("path")
        digest = candidate.get("sha256")
        if not isinstance(path, str) or path in roles:
            raise DeterministicOCILayoutError("runtime closure paths are not exclusive")
        source = by_path.get(path)
        if source is None or not hmac.compare_digest(str(digest), source.sha256):
            raise DeterministicOCILayoutError("runtime closure is not bound to build inputs")
        if kind not in {
            "materialized_runtime_archive",
            "materialization_evidence",
        }:
            kind = "materialization_source_evidence"
        roles[path] = (kind, identifier)
    if set(roles) != set(by_path):
        raise DeterministicOCILayoutError("runtime closure is not the exact input roster")
    return roles


def _runtime_asset(plan: Mapping[str, Any], asset_id: str) -> Mapping[str, Any]:
    runtime = plan["runtime"]
    for row in runtime["assets"]:
        if row["asset_id"] == asset_id:
            return row
    raise DeterministicOCILayoutError(_COMPLETE_ROOTFS_REQUIRED)


def _validate_complete_rootfs_provenance(
    raw: bytes,
    plan: Mapping[str, Any],
    evidence: Mapping[str, bytes],
    layer_diff_id: str,
) -> None:
    value = _exact_object(
        _parse_canonical_json(raw, "complete-rootfs provenance"),
        _ROOTFS_PROVENANCE_KEYS,
        "complete-rootfs provenance",
    )
    if value["schema_version"] != _ROOTFS_PROVENANCE_SCHEMA_VERSION:
        raise DeterministicOCILayoutError("complete-rootfs provenance schema is unsupported")
    if value["platform"] != "linux/arm64/v8":
        raise DeterministicOCILayoutError("complete-rootfs provenance platform is unsupported")
    scope = value["authentication_scope"]
    plan_scope = plan.get("authentication_scope")
    if plan_scope == _TEST_AUTHENTICATION_SCOPE:
        if scope != _TEST_AUTHENTICATION_SCOPE:
            raise DeterministicOCILayoutError("test rootfs provenance scope is invalid")
    elif scope != "REGISTRY_TLS_EXACT_DIGESTS":
        raise DeterministicOCILayoutError("production rootfs provenance is unauthenticated")
    elif any(
        value[key] != expected
        for key, expected in _DEBIAN_RELEASE_CLOSURE.items()
    ):
        raise DeterministicOCILayoutError(
            "production rootfs provenance is not the exact locked Debian closure"
        )
    for key in (
        "index_digest",
        "manifest_digest",
        "config_digest",
        "layer_digest",
        "layer_diff_id",
    ):
        _validate_digest(value[key], f"complete-rootfs {key}")
    for key in ("index_size", "manifest_size", "config_size", "layer_size"):
        if type(value[key]) is not int or not 1 <= value[key] <= _MAX_INPUT_BYTES:
            raise DeterministicOCILayoutError("complete-rootfs provenance size is invalid")
    commit = value["official_images_commit"]
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
        or commit != _DEBIAN_OFFICIAL_IMAGES_COMMIT
    ):
        raise DeterministicOCILayoutError("complete-rootfs provenance commit is malformed")
    official_images_sha256 = value["official_images_sha256"]
    if (
        not isinstance(official_images_sha256, str)
        or len(official_images_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in official_images_sha256
        )
    ):
        raise DeterministicOCILayoutError(
            "complete-rootfs official-images digest is malformed"
        )
    source_reference = value["source_reference"]
    repository_and_tag = (
        source_reference.split("@", 1)[0]
        if isinstance(source_reference, str) and "@" in source_reference
        else ""
    )
    expected_tag = "docker.io/library/debian:bookworm-20260824-slim"
    if (
        not isinstance(source_reference, str)
        or source_reference.count("@") != 1
        or repository_and_tag != expected_tag
        or not hmac.compare_digest(source_reference.rsplit("@", 1)[1], value["index_digest"])
    ):
        raise DeterministicOCILayoutError("complete-rootfs source reference is not immutable")

    required_evidence = {
        "complete-rootfs-config",
        "complete-rootfs-index",
        "complete-rootfs-manifest",
        "complete-rootfs-official-images",
    }
    if set(evidence) != required_evidence:
        raise DeterministicOCILayoutError(
            "complete-rootfs OCI evidence roster is not exact"
        )
    input_by_path = {row["path"]: row for row in plan["build_inputs"]}
    bindings = {
        "complete-rootfs-index": ("index_digest", "index_size"),
        "complete-rootfs-manifest": ("manifest_digest", "manifest_size"),
        "complete-rootfs-config": ("config_digest", "config_size"),
    }
    for asset_id, (digest_key, size_key) in bindings.items():
        asset = _runtime_asset(plan, asset_id)
        payload = evidence[asset_id]
        if (
            not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), asset["sha256"])
            or not hmac.compare_digest(value[digest_key], _sha256(payload))
            or value[size_key] != len(payload)
            or input_by_path[asset["path"]]["size"] != len(payload)
        ):
            raise DeterministicOCILayoutError(
                "complete-rootfs OCI evidence does not match provenance"
            )
    official_asset = _runtime_asset(plan, "complete-rootfs-official-images")
    official_raw = evidence["complete-rootfs-official-images"]
    rootfs = _runtime_asset(plan, "complete-rootfs")
    if (
        not hmac.compare_digest(
            hashlib.sha256(official_raw).hexdigest(), official_asset["sha256"]
        )
        or not hmac.compare_digest(
            official_images_sha256, hashlib.sha256(official_raw).hexdigest()
        )
        or not hmac.compare_digest(
            value["layer_digest"], _SHA256_PREFIX + rootfs["sha256"]
        )
        or value["layer_size"] != input_by_path[rootfs["path"]]["size"]
        or not hmac.compare_digest(value["layer_diff_id"], layer_diff_id)
    ):
        raise DeterministicOCILayoutError(
            "complete-rootfs provenance does not bind its full closure"
        )

    index = _exact_object(
        _parse_content_addressed_json(evidence["complete-rootfs-index"], "base OCI index"),
        frozenset({"manifests", "mediaType", "schemaVersion"}),
        "base OCI index",
    )
    if index["mediaType"] != OCI_INDEX_MEDIA_TYPE or index["schemaVersion"] != 2:
        raise DeterministicOCILayoutError("base OCI index header is unsupported")
    manifests = index["manifests"]
    if not isinstance(manifests, list) or not manifests:
        raise DeterministicOCILayoutError("base OCI index manifest roster is invalid")
    arm64_descriptors: list[Mapping[str, Any]] = []
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            raise DeterministicOCILayoutError("base OCI index descriptor is malformed")
        platform = descriptor.get("platform")
        if platform == {"architecture": "arm64", "os": "linux", "variant": "v8"}:
            arm64_descriptors.append(descriptor)
    if len(arm64_descriptors) != 1:
        raise DeterministicOCILayoutError(
            "base OCI index does not select exactly one linux/arm64/v8 image"
        )
    selected = arm64_descriptors[0]
    if set(selected) != {"annotations", "digest", "mediaType", "platform", "size"}:
        raise DeterministicOCILayoutError("base OCI arm64 descriptor schema is unsupported")
    annotations = selected["annotations"]
    required_annotations = {
        "com.docker.official-images.bashbrew.arch": "arm64v8",
        "org.opencontainers.image.base.name": "scratch",
        "org.opencontainers.image.created": "2026-08-24T00:00:00Z",
        "org.opencontainers.image.revision": (
            "f73bd086e8d0e5e1c8b838ccc442bf24eb3ea205"
        ),
        "org.opencontainers.image.source": (
            "https://github.com/debuerreotype/docker-debian-artifacts.git"
        ),
        "org.opencontainers.image.url": "https://hub.docker.com/_/debian",
        "org.opencontainers.image.version": "bookworm-slim",
    }
    if (
        selected["mediaType"] != OCI_MANIFEST_MEDIA_TYPE
        or selected["digest"] != value["manifest_digest"]
        or selected["size"] != value["manifest_size"]
        or annotations != required_annotations
    ):
        raise DeterministicOCILayoutError(
            "base OCI arm64 descriptor is not the locked Debian image"
        )

    manifest = _exact_object(
        _parse_content_addressed_json(
            evidence["complete-rootfs-manifest"], "base OCI manifest"
        ),
        frozenset({"config", "layers", "mediaType", "schemaVersion"}),
        "base OCI manifest",
    )
    if manifest["mediaType"] != OCI_MANIFEST_MEDIA_TYPE or manifest["schemaVersion"] != 2:
        raise DeterministicOCILayoutError("base OCI manifest header is unsupported")
    config_descriptor = manifest["config"]
    if not isinstance(config_descriptor, dict) or set(config_descriptor) != {
        "data",
        "digest",
        "mediaType",
        "size",
    }:
        raise DeterministicOCILayoutError("base OCI config descriptor is unsupported")
    try:
        embedded_config = base64.b64decode(config_descriptor["data"], validate=True)
    except (TypeError, ValueError) as exc:
        raise DeterministicOCILayoutError("base OCI embedded config is malformed") from exc
    if (
        config_descriptor["mediaType"] != OCI_CONFIG_MEDIA_TYPE
        or config_descriptor["digest"] != value["config_digest"]
        or config_descriptor["size"] != value["config_size"]
        or embedded_config != evidence["complete-rootfs-config"]
    ):
        raise DeterministicOCILayoutError("base OCI config descriptor is not exact")
    layers = manifest["layers"]
    if not isinstance(layers, list) or len(layers) != 1:
        raise DeterministicOCILayoutError("base OCI layer roster is not exact")
    layer_descriptor = layers[0]
    if (
        not isinstance(layer_descriptor, dict)
        or set(layer_descriptor) != {"digest", "mediaType", "size"}
        or layer_descriptor
        != {
            "digest": value["layer_digest"],
            "mediaType": OCI_LAYER_MEDIA_TYPE,
            "size": value["layer_size"],
        }
    ):
        raise DeterministicOCILayoutError("base OCI layer descriptor is not exact")

    config = _parse_content_addressed_json(
        evidence["complete-rootfs-config"], "base OCI config"
    )
    if not isinstance(config, dict):
        raise DeterministicOCILayoutError("base OCI config is malformed")
    rootfs = config.get("rootfs")
    if (
        config.get("architecture") != "arm64"
        or config.get("os") != "linux"
        or config.get("variant") != "v8"
        or not isinstance(rootfs, dict)
        or rootfs != {"type": "layers", "diff_ids": [value["layer_diff_id"]]}
    ):
        raise DeterministicOCILayoutError(
            "base OCI config platform/rootfs closure is not exact"
        )

    try:
        official_text = official_raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise DeterministicOCILayoutError("official-images evidence is not UTF-8") from exc
    revision = annotations.get("org.opencontainers.image.revision")
    required_lines = {
        "GitRepo: https://github.com/debuerreotype/docker-debian-artifacts.git",
        f"arm64v8-GitCommit: {revision}",
        "Tags: bookworm-slim, bookworm-20260824-slim, 12.15-slim, 12-slim",
        "Architectures: amd64, arm32v7, arm64v8, i386, ppc64le",
        "Builder: oci-import",
        "Directory: bookworm/slim/oci",
        "File: index.json",
    }
    if not isinstance(revision, str) or not required_lines.issubset(
        set(official_text.splitlines())
    ):
        raise DeterministicOCILayoutError(
            "official-images evidence does not bind the selected Debian image"
        )


def _expected_manifest_digest(plan: Mapping[str, Any]) -> str:
    return _validate_digest(
        plan.get("expected_manifest_digest"), "expected manifest digest"
    )


def _expected_index_digest(plan: Mapping[str, Any]) -> str:
    expected = _validate_digest(
        plan.get("expected_index_digest"), "expected index digest"
    )
    reference = plan.get("expected_image_reference")
    if (
        not isinstance(reference, str)
        or "@" not in reference
        or not hmac.compare_digest(reference.rsplit("@", 1)[1], expected)
    ):
        raise DeterministicOCILayoutError(
            "expected image reference does not bind its index digest"
        )
    return expected


def _stable_identity(row: os.stat_result) -> tuple[int, int, int]:
    return (int(row.st_dev), int(row.st_ino), int(row.st_mode))


def _stable_file_identity(row: os.stat_result) -> tuple[int, ...]:
    return (
        int(row.st_dev),
        int(row.st_ino),
        int(row.st_mode),
        int(row.st_uid),
        int(row.st_gid),
        int(row.st_nlink),
        int(row.st_size),
        int(row.st_mtime_ns),
        int(row.st_ctime_ns),
    )


def _list_xattrs(descriptor: int) -> tuple[str | bytes, ...]:
    inspector = image_lock._default_metadata_inspector()
    if inspector is None:
        raise DeterministicOCILayoutError("extended-metadata inspection is unavailable")
    try:
        values = tuple(inspector(descriptor))
    except (OSError, TypeError) as exc:
        raise DeterministicOCILayoutError("extended-metadata inspection failed") from exc
    if len(values) > 1_024:
        raise DeterministicOCILayoutError("extended-metadata count exceeds its bound")
    return values


def _require_plain_owned_directory(row: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(row.st_mode) or stat.S_ISLNK(row.st_mode):
        raise DeterministicOCILayoutError(f"{label} is not a plain directory")
    if int(row.st_uid) != os.geteuid() or stat.S_IMODE(row.st_mode) & 0o022:
        raise DeterministicOCILayoutError(f"{label} is not owner-private")
    if _list_xattrs_for_path_stat(row, label) is False:
        raise DeterministicOCILayoutError(f"{label} metadata is unavailable")


def _list_xattrs_for_path_stat(_row: os.stat_result, _label: str) -> bool:
    # Descriptor inspection happens immediately after every open.  This helper
    # exists solely to keep the ownership/mode predicate explicit.
    return True


def _open_canonical_parent(output: str | Path) -> tuple[int, str, tuple[Any, ...]]:
    rendered = os.fspath(output)
    if not isinstance(rendered, str):
        raise DeterministicOCILayoutError("output path must be text")
    canonical = os.path.normpath(rendered)
    if (
        not os.path.isabs(rendered)
        or rendered != canonical
        or canonical == os.sep
        or canonical.startswith(os.sep * 2)
        or "\x00" in canonical
        or unicodedata.normalize("NFC", canonical) != canonical
    ):
        raise DeterministicOCILayoutError("output must be a canonical absolute path")
    output_name = os.path.basename(canonical)
    if output_name in {"", ".", ".."} or len(output_name.encode("utf-8")) > 255:
        raise DeterministicOCILayoutError("output leaf is invalid")
    parent_parts = [item for item in os.path.dirname(canonical).split(os.sep) if item]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    opened: list[int] = []
    relationships: list[tuple[int, str, int, tuple[int, int, int]]] = []
    try:
        descriptor = os.open(os.sep, flags)
        opened.append(descriptor)
        for component in parent_parts:
            named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
                raise DeterministicOCILayoutError("output parent contains an alias")
            child = os.open(component, flags, dir_fd=descriptor)
            opened.append(child)
            identity = _stable_identity(named)
            if _stable_identity(os.fstat(child)) != identity:
                raise DeterministicOCILayoutError("output parent changed while opening")
            relationships.append((descriptor, component, child, identity))
            descriptor = child
        parent_row = os.fstat(descriptor)
        _require_plain_owned_directory(parent_row, "output parent")
        if _list_xattrs(descriptor):
            raise DeterministicOCILayoutError("output parent has extended metadata")
        retained = os.dup(descriptor)
        retained_relationships = tuple(relationships)
        # Relationship descriptors must remain open for revalidation.  Keep
        # them all and close them together with the staged operation.
        return retained, output_name, (tuple(opened), retained_relationships)
    except BaseException:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _revalidate_parent(
    parent_descriptor: int,
    parent_identity: tuple[int, int, int],
    relationships: Sequence[tuple[int, str, int, tuple[int, int, int]]],
) -> None:
    if _stable_identity(os.fstat(parent_descriptor)) != parent_identity:
        raise DeterministicOCILayoutError("output parent identity changed")
    for parent, component, child, identity in relationships:
        named = os.stat(component, dir_fd=parent, follow_symlinks=False)
        if _stable_identity(named) != identity or _stable_identity(os.fstat(child)) != identity:
            raise DeterministicOCILayoutError("output parent ancestry changed")


def _safe_lstat(name: str, descriptor: int) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _mkdir_at(parent: int, name: str, mode: int) -> int:
    os.mkdir(name, mode, dir_fd=parent)
    return os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise DeterministicOCILayoutError("layout write made no progress")
        view = view[written:]


def _write_file_at(parent: int, name: str, raw: bytes, mode: int = 0o444) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=parent)
    try:
        _write_all(descriptor, raw)
        os.fchmod(descriptor, mode)
        if _list_xattrs(descriptor):
            raise DeterministicOCILayoutError("generated file has extended metadata")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
) -> None:
    """Use the host kernel's atomic no-replace rename primitive or fail closed."""

    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = getattr(library, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL from <sys/stdio.h>.
    elif sys.platform.startswith("linux"):
        function = getattr(library, "renameat2", None)
        flag = 0x00000001  # RENAME_NOREPLACE from <linux/fs.h>.
    else:
        function = None
        flag = 0
    if function is None:
        raise DeterministicOCILayoutError(
            "native atomic no-replace publication is unavailable"
        )
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    ctypes.set_errno(0)
    result = function(
        source_parent,
        source,
        destination_parent,
        destination,
        flag,
    )
    if result == 0:
        return
    observed_errno = ctypes.get_errno()
    if observed_errno == errno.EEXIST:
        raise DeterministicOCILayoutError(
            "publication destination already exists"
        )
    raise DeterministicOCILayoutError(
        "native atomic no-replace publication failed closed"
    )


def _process_is_live(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _list_xattrs_for_named_path(parent: int, name: str) -> tuple[str | bytes, ...]:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        return _list_xattrs(descriptor)
    finally:
        os.close(descriptor)


def _remove_recovery_stage(
    parent: int,
    stage_name: str,
    *,
    directory: bool,
    expected_identity: tuple[int, int, int] | None = None,
) -> None:
    row = _safe_lstat(stage_name, parent)
    if row is None:
        return
    if directory:
        if (
            not stat.S_ISDIR(row.st_mode)
            or stat.S_ISLNK(row.st_mode)
            or row.st_uid != os.geteuid()
            or _list_xattrs_for_named_path(parent, stage_name)
            or (
                expected_identity is not None
                and _stable_identity(row) != expected_identity
            )
        ):
            raise DeterministicOCILayoutError(
                "stale publication stage has an unsafe identity"
            )
        _make_tree_owner_writable_at(parent, stage_name)
        shutil.rmtree(stage_name, dir_fd=parent)
    else:
        if (
            not stat.S_ISREG(row.st_mode)
            or stat.S_ISLNK(row.st_mode)
            or row.st_uid != os.geteuid()
            or row.st_nlink != 1
            or _list_xattrs_for_named_path(parent, stage_name)
            or (
                expected_identity is not None
                and _stable_identity(row) != expected_identity
            )
        ):
            raise DeterministicOCILayoutError(
                "stale publication stage has an unsafe identity"
            )
        os.unlink(stage_name, dir_fd=parent)


def _acquire_publication_lock(
    parent: int,
    lock_name: str,
    stage_name: str,
    *,
    kind: str,
    directory_stage: bool,
) -> int:
    generic_prefix = f".plamen-oci-{kind}-stage-"
    expected_prefix = stage_name.rsplit("-", 1)[0] + "-"
    if (
        kind not in {"archive", "layout"}
        or not stage_name.startswith(generic_prefix)
        or "/" in stage_name
    ):
        raise DeterministicOCILayoutError("publication recovery scope is invalid")
    record = _canonical_bytes(
        {
            "kind": kind,
            "pid": os.getpid(),
            "schema_version": "plamen.oci_publication_lock.v1",
            "stage_name": stage_name,
        }
    )
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    for attempt in range(2):
        try:
            descriptor = os.open(lock_name, flags, 0o600, dir_fd=parent)
        except FileExistsError:
            if attempt:
                raise DeterministicOCILayoutError(
                    "publication lock remains contended"
                ) from None
            existing = os.open(
                lock_name,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
            try:
                row = os.fstat(existing)
                identity = _stable_file_identity(row)
                if (
                    not stat.S_ISREG(row.st_mode)
                    or row.st_uid != os.geteuid()
                    or row.st_nlink != 1
                    or stat.S_IMODE(row.st_mode) != 0o600
                    or row.st_size <= 0
                    or row.st_size > _MAX_JSON_BYTES
                    or _list_xattrs(existing)
                ):
                    raise DeterministicOCILayoutError(
                        "publication lock identity is unsafe"
                    )
                os.lseek(existing, 0, os.SEEK_SET)
                raw = os.read(existing, int(row.st_size))
                if len(raw) != row.st_size or os.read(existing, 1):
                    raise DeterministicOCILayoutError(
                        "publication lock was truncated or grew"
                    )
                stale = _exact_object(
                    _parse_canonical_json(raw, "publication lock"),
                    frozenset({"kind", "pid", "schema_version", "stage_name"}),
                    "publication lock",
                )
                pid = stale["pid"]
                stale_stage = stale["stage_name"]
                if (
                    stale["schema_version"] != "plamen.oci_publication_lock.v1"
                    or stale["kind"] != kind
                    or type(pid) is not int
                    or pid <= 0
                    or not isinstance(stale_stage, str)
                    or not stale_stage.startswith(expected_prefix)
                    or "/" in stale_stage
                ):
                    raise DeterministicOCILayoutError(
                        "publication lock recovery record is invalid"
                    )
                if _process_is_live(pid):
                    raise DeterministicOCILayoutError(
                        "publication output is actively locked"
                    )
                named = os.stat(lock_name, dir_fd=parent, follow_symlinks=False)
                if _stable_file_identity(named) != identity:
                    raise DeterministicOCILayoutError(
                        "publication lock changed during recovery"
                    )
                _remove_recovery_stage(
                    parent, stale_stage, directory=directory_stage
                )
                os.unlink(lock_name, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(existing)
            continue
        try:
            _write_all(descriptor, record)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(parent)
            return descriptor
        except BaseException:
            os.close(descriptor)
            try:
                os.unlink(lock_name, dir_fd=parent)
                os.fsync(parent)
            except OSError:
                pass
            raise
    raise DeterministicOCILayoutError("publication lock acquisition failed closed")


class _DeterministicGzipWriter:
    """Write a deterministic RFC 1952 member while hashing both byte forms."""

    def __init__(self, destination: BinaryIO) -> None:
        self._destination = destination
        self._compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        self._diff = hashlib.sha256()
        self._blob = hashlib.sha256()
        self._crc = 0
        self._uncompressed_size = 0
        self._blob_size = 0
        self._closed = False
        # ID1 ID2 CM FLG MTIME(0) XFL(max compression) OS(unknown).
        self._emit(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff")

    def _emit(self, raw: bytes) -> None:
        view = memoryview(raw)
        while view:
            written = self._destination.write(view)
            if written is None or written <= 0:
                raise DeterministicOCILayoutError("compressed layer write made no progress")
            emitted = bytes(view[:written])
            self._blob.update(emitted)
            self._blob_size += written
            view = view[written:]

    def write(self, raw: bytes | bytearray | memoryview) -> int:
        if self._closed:
            raise ValueError("write to closed deterministic gzip stream")
        data = bytes(raw)
        self._diff.update(data)
        self._crc = zlib.crc32(data, self._crc)
        self._uncompressed_size += len(data)
        if self._uncompressed_size > _MAX_INPUT_BYTES + _MAX_LAYER_ENTRIES * 2048:
            raise DeterministicOCILayoutError("uncompressed layer exceeds its bound")
        self._emit(self._compressor.compress(data))
        return len(data)

    def tell(self) -> int:
        return self._uncompressed_size

    def flush(self) -> None:
        self._destination.flush()

    def finish(self) -> _LayerResult:
        if self._closed:
            raise DeterministicOCILayoutError("gzip stream was already finalized")
        self._closed = True
        self._emit(self._compressor.flush(zlib.Z_FINISH))
        self._emit(struct.pack("<II", self._crc & 0xFFFFFFFF, self._uncompressed_size & 0xFFFFFFFF))
        self._destination.flush()
        return _LayerResult(
            blob_digest=_SHA256_PREFIX + self._blob.hexdigest(),
            blob_size=self._blob_size,
            diff_id=_SHA256_PREFIX + self._diff.hexdigest(),
            uncompressed_size=self._uncompressed_size,
        )


class _ReaderAdapter(io.RawIOBase):
    def __init__(self, reader: Any, expected: _InputMetadata) -> None:
        self._reader = reader
        self._expected = expected
        self._observed = 0
        self._digest = hashlib.sha256()

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        remaining = self._expected.size - self._observed
        if size is None or size < 0:
            requested = remaining
        else:
            requested = min(size, remaining)
        chunks: list[bytes] = []
        needed = requested
        while needed:
            chunk = self._reader.read(min(needed, _READ_CHUNK))
            if not isinstance(chunk, bytes) or not chunk:
                raise DeterministicOCILayoutError("retained input was truncated")
            if len(chunk) > needed:
                raise DeterministicOCILayoutError("retained input exceeded its read bound")
            chunks.append(chunk)
            self._digest.update(chunk)
            self._observed += len(chunk)
            needed -= len(chunk)
        return b"".join(chunks)

    def authenticate_eof(self) -> None:
        if self._observed != self._expected.size:
            raise DeterministicOCILayoutError("retained input was not consumed completely")
        extra = self._reader.read(1)
        if extra != b"":
            raise DeterministicOCILayoutError("retained input grew during consumption")
        if not hmac.compare_digest(self._digest.hexdigest(), self._expected.sha256):
            raise DeterministicOCILayoutError("retained input digest mismatch")


class _SpoolSlice(io.RawIOBase):
    """Bounded pread view into one shared closure spool (no per-file FD)."""

    def __init__(self, owner: BinaryIO, offset: int, size: int) -> None:
        self._owner = owner
        self._offset = offset
        self._size = size
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError("unsupported seek mode")
        if position < 0 or position > self._size:
            raise ValueError("spool slice seek escapes its bound")
        self._position = position
        return position

    def read(self, size: int = -1) -> bytes:
        remaining = self._size - self._position
        requested = remaining if size is None or size < 0 else min(size, remaining)
        if requested == 0:
            return b""
        raw = os.pread(self._owner.fileno(), requested, self._offset + self._position)
        if len(raw) != requested:
            raise DeterministicOCILayoutError("shared closure spool was truncated")
        self._position += len(raw)
        return raw


def _append_exact_to_shared_spool(
    source: BinaryIO,
    size: int,
    owner: BinaryIO,
    *,
    label: str,
) -> tuple[_SpoolSlice, str]:
    if type(size) is not int or size < 0 or size > _MAX_EXPANDED_BYTES:
        raise DeterministicOCILayoutError(f"{label} size is outside its bound")
    owner.seek(0, os.SEEK_END)
    offset = owner.tell()
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = source.read(min(remaining, _READ_CHUNK))
        if not isinstance(chunk, bytes) or not chunk:
            raise DeterministicOCILayoutError(f"{label} was truncated")
        if len(chunk) > remaining:
            raise DeterministicOCILayoutError(f"{label} exceeds its declared size")
        owner.write(chunk)
        digest.update(chunk)
        remaining -= len(chunk)
    owner.flush()
    return _SpoolSlice(owner, offset, size), digest.hexdigest()


def _directory_entries(rows: Sequence[_InputMetadata]) -> tuple[str, ...]:
    result: set[str] = set()
    for row in rows:
        parts = PurePosixPath(row.path).parts
        for end in range(1, len(parts)):
            result.add(PurePosixPath(*parts[:end]).as_posix())
    return tuple(sorted(result, key=lambda item: (item.casefold(), item)))


def _tar_info(name: str, *, mode: int, size: int, directory: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name + "/" if directory else name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = 0 if directory else size
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    return info


def _write_layer(
    destination: BinaryIO,
    entries: Sequence[_ExpandedEntry],
) -> _LayerResult:
    gzip_writer = _DeterministicGzipWriter(destination)
    try:
        _write_canonical_rootfs_tar(gzip_writer, entries)
        return gzip_writer.finish()
    except BaseException:
        raise


def _write_canonical_rootfs_tar(
    destination: BinaryIO,
    entries: Sequence[_ExpandedEntry],
) -> None:
    """Encode the one accepted raw USTAR representation of a rootfs."""

    with tarfile.open(
        fileobj=destination,
        mode="w|",
        format=tarfile.USTAR_FORMAT,
        dereference=False,
    ) as archive:
        directory_rows = tuple(
            _InputMetadata(entry.path, entry.sha256, entry.size, entry.mode)
            for entry in entries
        )
        for directory in _directory_entries(directory_rows):
            archive.addfile(
                _tar_info(directory, mode=0o755, size=0, directory=True)
            )
        for index, entry in enumerate(entries):
            try:
                if entry.kind == "file":
                    if entry.source is None:
                        raise DeterministicOCILayoutError(
                            "runtime file payload is unavailable"
                        )
                    entry.source.seek(0)
                    archive.addfile(
                        _tar_info(
                            entry.path,
                            mode=entry.mode,
                            size=entry.size,
                            directory=False,
                        ),
                        entry.source,
                    )
                else:
                    info = _tar_info(
                        entry.path,
                        mode=entry.mode,
                        size=0,
                        directory=False,
                    )
                    info.type = (
                        tarfile.SYMTYPE
                        if entry.kind == "symlink"
                        else tarfile.LNKTYPE
                    )
                    info.linkname = entry.linkname
                    archive.addfile(info)
            except (ValueError, tarfile.TarError, OSError) as exc:
                raise DeterministicOCILayoutError(
                    f"layer entry {index} cannot be represented as deterministic ustar"
                ) from exc


def _compare_open_files_exact(
    left: int,
    right: int,
    *,
    label: str,
) -> None:
    """Byte-compare two retained regular files without path re-opening."""

    left_row = os.fstat(left)
    right_row = os.fstat(right)
    if left_row.st_size != right_row.st_size:
        raise DeterministicOCILayoutError(f"{label} size is not canonical")
    offset = 0
    size = int(left_row.st_size)
    while offset < size:
        width = min(_READ_CHUNK, size - offset)
        if os.pread(left, width, offset) != os.pread(right, width, offset):
            raise DeterministicOCILayoutError(
                f"{label} raw USTAR representation is not canonical"
            )
        offset += width


def _copy_exact_to_spool(
    source: BinaryIO,
    size: int,
    *,
    label: str,
    spool_factory: Callable[[], BinaryIO] | None = None,
) -> tuple[BinaryIO, str]:
    if type(size) is not int or size < 0 or size > _MAX_EXPANDED_BYTES:
        raise DeterministicOCILayoutError(f"{label} size is outside its bound")
    spool = spool_factory() if spool_factory is not None else tempfile.TemporaryFile(mode="w+b")
    digest = hashlib.sha256()
    remaining = size
    try:
        while remaining:
            chunk = source.read(min(remaining, _READ_CHUNK))
            if not isinstance(chunk, bytes) or not chunk:
                raise DeterministicOCILayoutError(f"{label} was truncated")
            if len(chunk) > remaining:
                raise DeterministicOCILayoutError(f"{label} exceeds its declared size")
            spool.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        spool.flush()
        spool.seek(0)
        return spool, digest.hexdigest()
    except BaseException:
        spool.close()
        raise


def _map_archive_path(path: str, install_kind: str, identifier: str, label: str) -> str:
    source = _validate_relative_path(path, label)
    parts = PurePosixPath(source).parts
    if install_kind == "cpython_archive":
        if parts[0] != "python":
            raise DeterministicOCILayoutError("CPython archive is not rooted at python/")
        suffix = parts[1:]
        mapped = PurePosixPath("usr", *suffix).as_posix()
    elif install_kind == "toolchain_archive":
        if identifier == "foundry":
            if len(parts) != 1 or parts[0] not in {"forge", "cast", "anvil", "chisel"}:
                raise DeterministicOCILayoutError("Foundry archive roster is unsupported")
            mapped = PurePosixPath(
                "usr", "local", "lib", "plamen", "toolchains", "foundry", "bin", parts[0]
            ).as_posix()
        else:
            mapped = PurePosixPath(
                "usr", "local", "lib", "plamen", "toolchains", identifier, *parts
            ).as_posix()
    elif install_kind == "rootfs_archive":
        mapped = source
    else:
        raise DeterministicOCILayoutError("runtime archive installation role is unsupported")
    mapped_parts = PurePosixPath(mapped).parts
    if mapped_parts[0] not in _ALLOWED_ROOT_COMPONENTS or any(
        component == ".wh..wh..opq" or component.startswith(".wh.")
        for component in mapped_parts
    ):
        raise DeterministicOCILayoutError(f"{label} targets a forbidden rootfs namespace")
    if identifier == "complete-rootfs" and (
        mapped == "opt/plamen"
        or mapped.startswith("opt/plamen/")
        or mapped == "usr/local/lib/plamen"
        or mapped.startswith("usr/local/lib/plamen/")
        or mapped == RUNTIME_ENTRYPOINT.removeprefix("/")
    ):
        raise DeterministicOCILayoutError(
            "complete-rootfs archive occupies the reserved Plamen namespace"
        )
    if identifier == "runtime-closure" and not (
        mapped == "opt/plamen"
        or mapped.startswith("opt/plamen/")
        or mapped == "usr/bin/python3"
        or mapped == "usr/local/lib/plamen"
        or mapped.startswith("usr/local/lib/plamen/")
        or mapped == "usr/local/libexec"
        or mapped == RUNTIME_ENTRYPOINT.removeprefix("/")
        or mapped == "usr/local/share/plamen"
        or mapped.startswith("usr/local/share/plamen/")
    ):
        raise DeterministicOCILayoutError(
            "runtime closure escapes its reserved Plamen namespace"
        )
    return mapped


def _normalized_archive_name(
    member: tarfile.TarInfo,
    label: str,
    install_kind: str,
    identifier: str,
) -> str:
    name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
    return _map_archive_path(name, install_kind, identifier, label)


def _mapped_link_target(
    member: tarfile.TarInfo,
    *,
    mapped_name: str,
    install_kind: str,
    identifier: str,
) -> str:
    target = member.linkname
    if (
        not isinstance(target, str)
        or not target
        or "\\" in target
        or "\x00" in target
        or target != target.strip()
        or unicodedata.normalize("NFC", target) != target
        or len(target.encode("utf-8", "strict")) > _MAX_PATH_BYTES
    ):
        raise DeterministicOCILayoutError("runtime archive link target is malformed")
    source_name = member.name.rstrip("/")
    if member.issym() and not target.startswith("/"):
        resolved_source = posixpath.normpath(posixpath.join(posixpath.dirname(source_name), target))
    else:
        resolved_source = posixpath.normpath(target.lstrip("/"))
    if resolved_source in {"", ".", ".."} or resolved_source.startswith("../"):
        raise DeterministicOCILayoutError("runtime archive link target escapes the rootfs")
    mapped_target = _map_archive_path(
        resolved_source, install_kind, identifier, "runtime archive link target"
    )
    target_root = PurePosixPath(mapped_target).parts[0]
    rendered_target = (
        "/" + mapped_target
        if target.startswith("/")
        else posixpath.relpath(mapped_target, posixpath.dirname(mapped_name))
    )
    if target_root in _PROVIDER_OWNED_ROOTS and (
        identifier not in {"complete-rootfs", "verified-layer"}
        or (mapped_name, rendered_target) not in _ROOTFS_PROVIDER_LINK_POLICY
    ):
        raise DeterministicOCILayoutError(
            "runtime archive link enters a provider-owned namespace"
        )
    if member.islnk():
        return mapped_target
    return rendered_target


def _register_expanded_path(
    path: str,
    *,
    is_file: bool,
    files: set[str],
    directories: set[str],
    aliases: dict[str, str],
) -> None:
    # OCI rootfs paths execute on Linux, where case-distinct names are not
    # aliases.  NFC is already mandatory, so only exact names collide here.
    alias = path
    prior = aliases.get(alias)
    if prior is not None and prior != path:
        raise DeterministicOCILayoutError("expanded runtime paths collide")
    aliases[alias] = path
    parts = PurePosixPath(path).parts
    for end in range(1, len(parts)):
        parent = PurePosixPath(*parts[:end]).as_posix()
        parent_alias = parent
        prior_parent = aliases.get(parent_alias)
        if prior_parent is not None and prior_parent != parent:
            raise DeterministicOCILayoutError("expanded runtime path components collide")
        aliases[parent_alias] = parent
        if parent in files:
            raise DeterministicOCILayoutError("expanded runtime descends from a file")
        directories.add(parent)
    if is_file:
        if path in files or path in directories:
            raise DeterministicOCILayoutError("expanded runtime contains a duplicate path")
        files.add(path)
    elif path in files:
        raise DeterministicOCILayoutError("expanded runtime directory aliases a file")
    else:
        directories.add(path)


def _expand_archive(
    adapter: _ReaderAdapter,
    row: _InputMetadata,
    *,
    entries: list[_ExpandedEntry],
    files: set[str],
    directories: set[str],
    aliases: dict[str, str],
    expanded_total: list[int],
    payload_spool: BinaryIO | None = None,
    archive_diff_ids: dict[str, str] | None = None,
    install_kind: str = "rootfs_archive",
    identifier: str = "runtime-closure",
    spool_factory: Callable[[], BinaryIO] | None = None,
) -> None:
    initial_entry_count = len(entries)
    per_archive = max(64 * 1024 * 1024, row.size * 200)
    per_archive = min(per_archive, _MAX_EXPANDED_BYTES)
    observed = 0
    raw_spool: BinaryIO | None = None
    tar_spool: BinaryIO | None = None
    source_member_names: list[str] = []
    seen_source_member_names: set[str] = set()
    try:
        raw_spool, raw_digest = _copy_exact_to_spool(
            adapter, row.size, label=f"runtime archive {row.path!r}",
            spool_factory=spool_factory,
        )
        adapter.authenticate_eof()
        if not hmac.compare_digest(raw_digest, row.sha256):
            raise DeterministicOCILayoutError("runtime archive digest mismatch")
        tar_spool = spool_factory() if spool_factory is not None else tempfile.TemporaryFile(mode="w+b")
        raw_spool.seek(0)
        signature = raw_spool.read(2)
        raw_spool.seek(0)
        if signature == b"\x1f\x8b":
            decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
            decoded_size = 0
            while chunk := raw_spool.read(_READ_CHUNK):
                decoded = decoder.decompress(chunk)
                decoded_size += len(decoded)
                if decoded_size > per_archive:
                    raise DeterministicOCILayoutError("runtime archive decompression exceeds its bound")
                tar_spool.write(decoded)
                if decoder.unused_data or decoder.unconsumed_tail:
                    raise DeterministicOCILayoutError("runtime archive has concatenated or trailing gzip data")
            decoded = decoder.flush()
            decoded_size += len(decoded)
            if decoded_size > per_archive:
                raise DeterministicOCILayoutError("runtime archive decompression exceeds its bound")
            tar_spool.write(decoded)
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise DeterministicOCILayoutError("runtime archive gzip member is incomplete")
        else:
            while chunk := raw_spool.read(_READ_CHUNK):
                tar_spool.write(chunk)
        tar_spool.flush()
        tar_size = tar_spool.seek(0, os.SEEK_END)
        if tar_size <= 0 or tar_size > per_archive:
            raise DeterministicOCILayoutError("runtime archive tar size is outside its bound")
        if archive_diff_ids is not None:
            tar_spool.seek(0)
            tar_digest = hashlib.sha256()
            while chunk := tar_spool.read(_READ_CHUNK):
                tar_digest.update(chunk)
            archive_diff_ids[identifier] = _SHA256_PREFIX + tar_digest.hexdigest()
        tar_spool.seek(0)
        expected_tar_payload = 0
        with tarfile.open(fileobj=tar_spool, mode="r:") as archive:
            for member_index, member in enumerate(archive):
                _require_layer_entry_count(
                    len(files) + len(directories) + 1, "expanded runtime"
                )
                source_name = member.name.rstrip("/")
                if source_name in seen_source_member_names:
                    raise DeterministicOCILayoutError(
                        "runtime archive contains a duplicate member name"
                    )
                seen_source_member_names.add(source_name)
                if (
                    install_kind == "rootfs_archive"
                    and member.name in {".", "./"}
                    and member.isdir()
                ):
                    source_member_names.append(".")
                    expected_tar_payload += 512
                    continue
                name = _normalized_archive_name(
                    member,
                    f"runtime archive {row.path!r} entry {member_index}",
                    install_kind,
                    identifier,
                )
                source_member_names.append(member.name.rstrip("/"))
                if (
                    PurePosixPath(name).parts[0] in {"dev", "proc", "sys", "run", "tmp"}
                    and not member.isdir()
                ):
                    raise DeterministicOCILayoutError(
                        "runtime archive populates a provider-owned ephemeral namespace"
                    )
                if (
                    member.pax_headers
                    or member.type
                    not in {
                        tarfile.REGTYPE,
                        tarfile.AREGTYPE,
                        tarfile.DIRTYPE,
                        tarfile.SYMTYPE,
                        tarfile.LNKTYPE,
                    }
                    or member.uid < 0
                    or member.gid < 0
                    or member.uid > 2**31 - 1
                    or member.gid > 2**31 - 1
                ):
                    raise DeterministicOCILayoutError(
                        "runtime archive contains special or unsafe metadata"
                    )
                mode = stat.S_IMODE(member.mode)
                expected_tar_payload += 512
                if (
                    mode & ~0o7777
                    or member.mode < 0
                    or member.mode > 0o7777
                ):
                    raise DeterministicOCILayoutError("runtime archive mode is unsafe")
                canonical_mode = (
                    0o777
                    if member.issym()
                    else (0o555 if mode & 0o111 else 0o444)
                )
                if member.isdir():
                    if member.size != 0:
                        raise DeterministicOCILayoutError("runtime archive directory has a payload")
                    _register_expanded_path(
                        name,
                        is_file=False,
                        files=files,
                        directories=directories,
                        aliases=aliases,
                    )
                    continue
                if member.issym() or member.islnk():
                    if member.size != 0:
                        raise DeterministicOCILayoutError("runtime archive link has a payload")
                    _register_expanded_path(
                        name,
                        is_file=True,
                        files=files,
                        directories=directories,
                        aliases=aliases,
                    )
                    linkname = _mapped_link_target(
                        member,
                        mapped_name=name,
                        install_kind=install_kind,
                        identifier=identifier,
                    )
                    kind = "symlink" if member.issym() else "hardlink"
                    link_digest = hashlib.sha256(
                        (kind + "\0" + linkname).encode("utf-8", "strict")
                    ).hexdigest()
                    entries.append(
                        _ExpandedEntry(
                            name,
                            link_digest,
                            0,
                            0o777 if kind == "symlink" else canonical_mode,
                            None,
                            kind,
                            linkname,
                        )
                    )
                    continue
                if not member.isreg() or member.size < 0:
                    raise DeterministicOCILayoutError("runtime archive contains a special entry")
                expected_tar_payload += ((member.size + 511) // 512) * 512
                observed += member.size
                expanded_total[0] += member.size
                if observed > per_archive or expanded_total[0] > _MAX_EXPANDED_BYTES:
                    raise DeterministicOCILayoutError("runtime archive expansion exceeds its bound")
                _register_expanded_path(
                    name,
                    is_file=True,
                    files=files,
                    directories=directories,
                    aliases=aliases,
                )
                payload = archive.extractfile(member)
                if payload is None:
                    raise DeterministicOCILayoutError("runtime archive payload is unavailable")
                if payload_spool is None:
                    spool, digest = _copy_exact_to_spool(
                        payload, member.size, label=f"runtime archive entry {name!r}",
                        spool_factory=spool_factory,
                    )
                else:
                    spool, digest = _append_exact_to_shared_spool(
                        payload,
                        member.size,
                        payload_spool,
                        label=f"runtime archive entry {name!r}",
                    )
                if payload.read(1):
                    spool.close()
                    raise DeterministicOCILayoutError("runtime archive payload exceeds its header")
                entries.append(
                    _ExpandedEntry(name, digest, member.size, canonical_mode, spool)
                )
        if install_kind == "toolchain_archive" and identifier == "foundry" and (
            len(source_member_names) != 4
            or set(source_member_names) != {"forge", "cast", "anvil", "chisel"}
        ):
            raise DeterministicOCILayoutError("Foundry archive roster is not exact")
        minimal_tar_size = expected_tar_payload + 1024
        blocked_tar_size = (
            (expected_tar_payload + 1024 + tarfile.RECORDSIZE - 1)
            // tarfile.RECORDSIZE
            * tarfile.RECORDSIZE
        )
        # Both POSIX's minimal two-zero-block EOF and tar's conventional
        # blocking-factor padding are deterministic representations.  Refuse
        # every other zero extent, including appended empty archives.
        if tar_size not in {minimal_tar_size, blocked_tar_size}:
            raise DeterministicOCILayoutError("runtime archive terminator is not canonical")
        tar_spool.seek(expected_tar_payload)
        trailing = tar_size - expected_tar_payload
        while trailing:
            chunk = tar_spool.read(min(trailing, _READ_CHUNK))
            if not chunk or any(chunk):
                raise DeterministicOCILayoutError("runtime archive has hidden or trailing records")
            trailing -= len(chunk)
        if install_kind == "rootfs_archive" and identifier == "complete-rootfs":
            _require_complete_rootfs(entries[initial_entry_count:])
    except DeterministicOCILayoutError:
        raise
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise DeterministicOCILayoutError("runtime artifact is not a bounded tar archive") from exc
    finally:
        for spool in (tar_spool, raw_spool):
            if spool is not None:
                try:
                    spool.close()
                except Exception:
                    pass


def _require_complete_rootfs(entries: Sequence[_ExpandedEntry]) -> None:
    if len(entries) < 100:
        raise DeterministicOCILayoutError("complete-rootfs archive is not a complete system root")
    by_path = {entry.path: entry for entry in entries}
    required = (*RUNTIME_DYNAMIC_LIBRARIES, "bin/sh", "usr/bin/env", "etc/passwd")
    for path in required:
        resolved = _resolve_rootfs_entry(path, by_path, label="complete-rootfs requirement")
        if resolved.source is None or resolved.size <= 0:
            raise DeterministicOCILayoutError("complete-rootfs required file is invalid")
        if path != "etc/passwd":
            resolved.source.seek(0)
            magic = resolved.source.read(_ELF_IDENTITY_BYTES)
            resolved.source.seek(0)
            if path in RUNTIME_DYNAMIC_LIBRARIES and not _is_arm64_elf(magic):
                raise DeterministicOCILayoutError(
                    "complete-rootfs library platform is invalid"
                )
            if path in {"bin/sh", "usr/bin/env"} and (
                resolved.mode & 0o111 == 0
                or not _is_supported_linux_executable(magic)
            ):
                raise DeterministicOCILayoutError("complete-rootfs executable mode is invalid")


def _runtime_files_sha256(entries: Sequence[_ExpandedEntry]) -> str:
    rows = [
        {
            "mode": f"0{entry.mode:03o}",
            "kind": entry.kind,
            "linkname": entry.linkname,
            "path": entry.path,
            "sha256": entry.sha256,
            "size": entry.size,
        }
        for entry in entries
    ]
    return hashlib.sha256(_canonical_bytes(rows)).hexdigest()


def _is_arm64_elf(prefix: bytes) -> bool:
    return (
        len(prefix) >= _ELF_IDENTITY_BYTES
        and prefix[:7] == b"\x7fELF\x02\x01\x01"
        and prefix[18:20] == b"\xb7\x00"
    )


def _is_supported_linux_executable(prefix: bytes) -> bool:
    return prefix.startswith(b"#!") or _is_arm64_elf(prefix)


def _read_entry_range(entry: _ExpandedEntry, offset: int, size: int) -> bytes:
    if (
        entry.source is None
        or type(offset) is not int
        or type(size) is not int
        or offset < 0
        or size < 0
        or offset > entry.size
        or size > entry.size - offset
    ):
        raise DeterministicOCILayoutError("runtime executable range is invalid")
    entry.source.seek(offset)
    raw = entry.source.read(size)
    entry.source.seek(0)
    if not isinstance(raw, bytes) or len(raw) != size:
        raise DeterministicOCILayoutError("runtime executable was truncated")
    return raw


def _elf_string(table: bytes, offset: int, label: str) -> str:
    if type(offset) is not int or not 0 <= offset < len(table):
        raise DeterministicOCILayoutError(f"ELF {label} offset is invalid")
    end = table.find(b"\0", offset)
    if end < 0:
        raise DeterministicOCILayoutError(f"ELF {label} is unterminated")
    try:
        value = table[offset:end].decode("utf-8", "strict")
    except UnicodeError as exc:
        raise DeterministicOCILayoutError(f"ELF {label} is not UTF-8") from exc
    if not value or len(value.encode()) > _MAX_PATH_BYTES or "\0" in value:
        raise DeterministicOCILayoutError(f"ELF {label} is malformed")
    return value


def _parse_arm64_elf(entry: _ExpandedEntry) -> _ELFMetadata:
    header = _read_entry_range(entry, 0, 64)
    try:
        (
            identity,
            elf_type,
            machine,
            version,
            _entrypoint,
            program_offset,
            _section_offset,
            _flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _section_names,
        ) = struct.unpack("<16sHHIQQQIHHHHHH", header)
    except struct.error as exc:
        raise DeterministicOCILayoutError("ELF header is malformed") from exc
    if (
        identity[:7] != b"\x7fELF\x02\x01\x01"
        or machine != 183
        or version != 1
        or elf_type not in {2, 3}
        or header_size != 64
        or program_entry_size != 56
        or not 1 <= program_count <= 4096
        or program_offset < 64
        or program_offset > entry.size
        or program_entry_size * program_count > entry.size - program_offset
    ):
        raise DeterministicOCILayoutError("ELF is not a bounded linux/arm64 executable")
    program_raw = _read_entry_range(
        entry, program_offset, program_entry_size * program_count
    )
    load_segments: list[tuple[int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    interpreter_range: tuple[int, int] | None = None
    for index in range(program_count):
        fields = struct.unpack_from("<IIQQQQQQ", program_raw, index * 56)
        kind, _segment_flags, offset, virtual, _physical, file_size, memory_size, _align = fields
        if file_size > memory_size or offset > entry.size or file_size > entry.size - offset:
            raise DeterministicOCILayoutError("ELF program segment escapes the file")
        if kind == 1:
            load_segments.append((virtual, file_size, offset))
        elif kind == 2:
            if dynamic is not None or file_size == 0 or file_size > 16 * 1024 * 1024:
                raise DeterministicOCILayoutError("ELF dynamic segment is ambiguous")
            dynamic = (offset, file_size)
        elif kind == 3:
            if (
                interpreter_range is not None
                or file_size < 2
                or file_size > _MAX_PATH_BYTES
            ):
                raise DeterministicOCILayoutError("ELF interpreter segment is invalid")
            interpreter_range = (offset, file_size)
    if not load_segments:
        raise DeterministicOCILayoutError("ELF has no loadable segment")

    interpreter: str | None = None
    if interpreter_range is not None:
        interpreter_raw = _read_entry_range(entry, *interpreter_range)
        if interpreter_raw[-1:] != b"\0" or b"\0" in interpreter_raw[:-1]:
            raise DeterministicOCILayoutError("ELF interpreter is not canonical")
        try:
            interpreter = interpreter_raw[:-1].decode("utf-8", "strict")
        except UnicodeError as exc:
            raise DeterministicOCILayoutError("ELF interpreter is not UTF-8") from exc
        if not interpreter.startswith("/"):
            raise DeterministicOCILayoutError("ELF interpreter is not absolute")
        _validate_relative_path(
            interpreter.removeprefix("/"), "ELF interpreter"
        )

    if dynamic is None:
        return _ELFMetadata(interpreter, (), None, (), (), False, False)
    dynamic_raw = _read_entry_range(entry, *dynamic)
    if len(dynamic_raw) % 16:
        raise DeterministicOCILayoutError("ELF dynamic segment is misaligned")
    tags: dict[int, list[int]] = {}
    terminated = False
    for offset in range(0, len(dynamic_raw), 16):
        tag, value = struct.unpack_from("<qQ", dynamic_raw, offset)
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    if not terminated:
        raise DeterministicOCILayoutError("ELF dynamic segment is unterminated")
    if len(tags.get(5, ())) != 1 or len(tags.get(10, ())) != 1:
        raise DeterministicOCILayoutError("ELF dynamic string table is ambiguous")
    string_virtual = tags[5][0]
    string_size = tags[10][0]
    if string_size <= 0 or string_size > 16 * 1024 * 1024:
        raise DeterministicOCILayoutError("ELF dynamic string table is outside its bound")
    string_offset: int | None = None
    for virtual, file_size, offset in load_segments:
        if virtual <= string_virtual and string_size <= file_size - (string_virtual - virtual):
            candidate = offset + (string_virtual - virtual)
            if string_offset is not None and string_offset != candidate:
                raise DeterministicOCILayoutError("ELF virtual address mapping is ambiguous")
            string_offset = candidate
    if string_offset is None:
        raise DeterministicOCILayoutError("ELF dynamic string table is not file-backed")
    string_table = _read_entry_range(entry, string_offset, string_size)
    needed = tuple(_elf_string(string_table, offset, "DT_NEEDED") for offset in tags.get(1, ()))
    if len(set(needed)) != len(needed):
        raise DeterministicOCILayoutError("ELF repeats a DT_NEEDED entry")
    sonames = tags.get(14, ())
    if len(sonames) > 1:
        raise DeterministicOCILayoutError("ELF SONAME is ambiguous")
    soname = _elf_string(string_table, sonames[0], "SONAME") if sonames else None
    rpath_tags = tags.get(15, ())
    runpath_tags = tags.get(29, ())
    flags_1_tags = tags.get(0x6FFFFFFB, ())
    if (
        len(rpath_tags) > 1
        or len(runpath_tags) > 1
        or len(flags_1_tags) > 1
    ):
        raise DeterministicOCILayoutError("ELF RPATH/RUNPATH is ambiguous")

    def decode_search_path(values: Sequence[int], label: str) -> tuple[str, ...]:
        if not values:
            return ()
        rendered = _elf_string(string_table, values[0], label)
        result = tuple(rendered.split(":"))
        if not result or any(not value for value in result):
            raise DeterministicOCILayoutError(
                "ELF search path contains an unsafe empty entry"
            )
        return result

    return _ELFMetadata(
        interpreter,
        needed,
        soname,
        decode_search_path(rpath_tags, "RPATH"),
        decode_search_path(runpath_tags, "RUNPATH"),
        bool(flags_1_tags and flags_1_tags[0] & 0x00000800),
        True,
    )


def _guest_path(value: str, origin: str, label: str) -> str:
    expanded = value.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
    if "$" in expanded:
        raise DeterministicOCILayoutError(f"{label} uses an unsupported substitution")
    if not expanded.startswith("/"):
        expanded = "/" + posixpath.normpath(posixpath.join(origin, expanded))
    normalized = posixpath.normpath(expanded)
    relative = normalized.removeprefix("/")
    _validate_relative_path(relative, label)
    if PurePosixPath(relative).parts[0] in _PROVIDER_OWNED_ROOTS:
        raise DeterministicOCILayoutError(f"{label} enters a provider-owned namespace")
    return relative


def _elf_search_directory(value: str, origin: str, label: str) -> str:
    expanded = value.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
    if "$" in expanded:
        raise DeterministicOCILayoutError(
            f"{label} uses an unsupported substitution"
        )
    # ld.so interprets a non-absolute RPATH/RUNPATH component relative to the
    # process working directory.  It does not grant an implicit owner-dir
    # search; callers must use $ORIGIN to request that behavior explicitly.
    if not expanded.startswith("/"):
        expanded = posixpath.join(RUNTIME_WORKDIR, expanded)
    normalized = posixpath.normpath(expanded)
    relative = normalized.removeprefix("/")
    _validate_relative_path(relative, label)
    if PurePosixPath(relative).parts[0] in _PROVIDER_OWNED_ROOTS:
        raise DeterministicOCILayoutError(
            f"{label} enters a provider-owned namespace"
        )
    return relative


def _linux_shebang_interpreter(entry: _ExpandedEntry) -> str:
    """Parse the interpreter name using Linux ``binfmt_script`` delimiters.

    Linux trims only space and tab around the interpreter field.  In
    particular, carriage return is ordinary path data, so accepting CRLF as
    ``/bin/sh`` would certify a different path than the kernel executes.
    """

    window_size = min(entry.size, _LINUX_BINPRM_BUF_SIZE)
    raw = _read_entry_range(entry, 0, window_size)
    if not raw.startswith(b"#!"):
        raise DeterministicOCILayoutError("script shebang marker is absent")
    newline = raw.find(b"\n", 2)
    if newline < 0:
        line_end = len(raw)
        if entry.size >= _LINUX_BINPRM_BUF_SIZE:
            # binfmt_script reserves the final buffer byte as its boundary. A
            # truncated line is accepted only when the interpreter name (not
            # necessarily its optional argument) was space/tab terminated.
            line_end = _LINUX_BINPRM_BUF_SIZE - 1
            candidate = raw[2:line_end]
            start = 0
            while start < len(candidate) and candidate[start] in b" \t":
                start += 1
            separator = min(
                (
                    position
                    for position in (
                        candidate.find(b" ", start),
                        candidate.find(b"\t", start),
                    )
                    if position >= 0
                ),
                default=-1,
            )
            if start == len(candidate) or separator < 0:
                raise DeterministicOCILayoutError(
                    "script shebang interpreter exceeds the Linux buffer"
                )
        line = raw[2:line_end]
    else:
        line = raw[2:newline]
    line = line.rstrip(b" \t")
    line = line.lstrip(b" \t")
    if not line:
        raise DeterministicOCILayoutError("script shebang interpreter is absent")
    separator = len(line)
    for delimiter in (b" ", b"\t"):
        offset = line.find(delimiter)
        if offset >= 0:
            separator = min(separator, offset)
    interpreter_raw = line[:separator]
    argument_raw = line[separator:].lstrip(b" \t")
    if (
        not interpreter_raw.startswith(b"/")
        or b"\0" in line
        or b"\r" in line
        or any((value < 0x20 and value != 0x09) or value == 0x7F for value in line)
        or (argument_raw and len(argument_raw) > _MAX_PATH_BYTES)
    ):
        raise DeterministicOCILayoutError("script shebang is unsupported")
    try:
        interpreter = interpreter_raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise DeterministicOCILayoutError("script shebang is not UTF-8") from exc
    if interpreter == "/usr/bin/env":
        raise DeterministicOCILayoutError(
            "script shebang through env has no closed interpreter identity"
        )
    return interpreter


def _validate_runtime_dependencies(
    entries: Sequence[_ExpandedEntry],
) -> tuple[bytes, str]:
    by_path = {entry.path: entry for entry in entries}

    def resolve_effective_ld_so_cache() -> _ExpandedEntry | None:
        """Resolve the optional cache name exactly as a rootfs pathname.

        Absence of the literal name and all of its ancestors is acceptable.
        Once any symlink/hardlink redirects resolution, however, a missing,
        cycling, non-file, or escaping target is malformed rather than absent.
        """

        current_path = "etc/ld.so.cache"
        seen: set[str] = set()
        redirected_once = False
        for _hop in range(_MAX_PATH_COMPONENTS):
            if current_path in seen:
                raise DeterministicOCILayoutError(
                    "effective /etc/ld.so.cache alias is malformed (cycle)"
                )
            seen.add(current_path)
            parts = list(PurePosixPath(current_path).parts)
            redirected = False
            for end in range(1, len(parts) + 1):
                prefix = PurePosixPath(*parts[:end]).as_posix()
                entry = by_path.get(prefix)
                if entry is None:
                    continue
                rest = parts[end:]
                if entry.kind == "file":
                    if rest:
                        raise DeterministicOCILayoutError(
                            "effective /etc/ld.so.cache alias is malformed"
                        )
                    if entry.source is None or entry.size < 0:
                        raise DeterministicOCILayoutError(
                            "effective /etc/ld.so.cache is not a regular file"
                        )
                    return entry
                if entry.kind == "hardlink":
                    if rest:
                        raise DeterministicOCILayoutError(
                            "effective /etc/ld.so.cache alias is malformed"
                        )
                    target = entry.linkname
                elif entry.kind == "symlink":
                    target = (
                        entry.linkname.removeprefix("/")
                        if entry.linkname.startswith("/")
                        else posixpath.normpath(
                            posixpath.join(
                                posixpath.dirname(prefix), entry.linkname
                            )
                        )
                    )
                else:
                    raise DeterministicOCILayoutError(
                        "effective /etc/ld.so.cache alias is malformed"
                    )
                current_path = posixpath.normpath(
                    posixpath.join(target, *rest) if rest else target
                )
                if (
                    current_path in {"", ".", ".."}
                    or current_path.startswith("../")
                    or current_path.startswith("/")
                    or PurePosixPath(current_path).parts[0]
                    in _PROVIDER_OWNED_ROOTS
                ):
                    raise DeterministicOCILayoutError(
                        "effective /etc/ld.so.cache alias escapes the rootfs"
                    )
                redirected_once = True
                redirected = True
                break
            if not redirected:
                if redirected_once:
                    raise DeterministicOCILayoutError(
                        "effective /etc/ld.so.cache alias target is absent"
                    )
                return None
        raise DeterministicOCILayoutError(
            "effective /etc/ld.so.cache alias exceeds the link-depth bound"
        )

    if resolve_effective_ld_so_cache() is not None:
        # glibc's binary cache carries its own ordered ABI/hwcaps resolution
        # semantics between RUNPATH and the built-in defaults.  Merely binding
        # its bytes is not equivalent to replaying that selection.  Until the
        # pinned loader's cache format and hwcaps policy are implemented, an
        # image containing a cache cannot receive dependency-closure credit.
        raise DeterministicOCILayoutError(
            "authenticated ld.so.cache resolution is not implemented"
        )
    roots = [
        RUNTIME_ENTRYPOINT.removeprefix("/"),
        "usr/bin/python3",
        "usr/local/lib/plamen/bin/claude",
        "usr/local/lib/plamen/bin/codex",
        "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
        *(f"usr/local/lib/plamen/toolchains/foundry/bin/{name}" for name in ("anvil", "cast", "chisel", "forge")),
    ]
    edges: list[dict[str, str]] = []
    visited: set[tuple[str, tuple[str, ...]]] = set()
    active: set[str] = set()

    def resolve(path: str, label: str, *, executable: bool = True) -> _ExpandedEntry:
        entry = _resolve_rootfs_entry(path, by_path, label=label)
        requested = by_path.get(path)
        if executable and (
            entry.mode & 0o111 == 0
            or (requested is not None and requested.mode & 0o111 == 0)
        ):
            raise DeterministicOCILayoutError(f"{label} is not executable")
        return entry

    def resolve_library(
        owner: str,
        name: str,
        metadata: _ELFMetadata,
        inherited_rpaths: tuple[str, ...],
    ) -> _ExpandedEntry:
        if "/" in name:
            candidates = [
                _guest_path(name, RUNTIME_WORKDIR, "ELF dependency")
            ]
        else:
            _validate_relative_path(name, "ELF dependency name")
            origin = "/" + posixpath.dirname(owner)
            own_rpath = (
                tuple(
                    _elf_search_directory(value, origin, "ELF RPATH")
                    for value in metadata.rpath
                )
                if not metadata.runpath
                else ()
            )
            own_runpath = tuple(
                _elf_search_directory(value, origin, "ELF RUNPATH")
                for value in metadata.runpath
            )
            # ld.so applies old-style RPATH transitively, but RUNPATH only to
            # the object's direct DT_NEEDED edges.  No implicit owner-directory
            # lookup exists, and this offline image supplies no LD_LIBRARY_PATH
            # or authenticated ld.so.cache denominator.
            directories = [
                *own_rpath,
                *inherited_rpaths,
                *own_runpath,
                *(() if metadata.nodeflib else _ELF_DEFAULT_LIBRARY_PATHS),
            ]
            candidates = [posixpath.join(directory, name).lstrip("/") for directory in directories]
        for candidate in candidates:
            try:
                resolved = _resolve_rootfs_entry(
                    candidate, by_path, label=f"ELF dependency {name!r}"
                )
            except DeterministicOCILayoutError:
                continue
            return resolved
        raise DeterministicOCILayoutError(f"ELF dependency {name!r} is unresolved")

    def visit(
        requested_path: str,
        *,
        root: bool = False,
        executable: bool = True,
        inherited_rpaths: tuple[str, ...] = (),
    ) -> None:
        resolved = resolve(
            requested_path, "runtime dependency", executable=executable
        )
        path = resolved.path
        visit_identity = (path, inherited_rpaths)
        if visit_identity in visited:
            return
        if path in active:
            raise DeterministicOCILayoutError("runtime dependency graph contains a cycle")
        if len(active) >= _MAX_PATH_COMPONENTS:
            raise DeterministicOCILayoutError(
                "runtime dependency graph exceeds its depth bound"
            )
        active.add(path)
        prefix = _read_entry_range(
            resolved, 0, min(resolved.size, _LINUX_BINPRM_BUF_SIZE)
        )
        if prefix.startswith(b"#!"):
            interpreter_name = _linux_shebang_interpreter(resolved)
            interpreter_path = _guest_path(
                interpreter_name,
                "/" + posixpath.dirname(path),
                "script interpreter",
            )
            interpreter = resolve(interpreter_path, "script interpreter")
            edges.append(
                {
                    "from": path,
                    "kind": "interpreter",
                    "name": interpreter_name,
                    "resolved": interpreter.path,
                }
            )
            visit(interpreter_path, inherited_rpaths=())
        elif prefix.startswith(b"\x7fELF"):
            metadata = _parse_arm64_elf(resolved)
            if root and metadata.dynamic and metadata.interpreter is None:
                raise DeterministicOCILayoutError(
                    "dynamic runtime executable omits PT_INTERP"
                )
            if metadata.interpreter is not None:
                interpreter_path = _guest_path(
                    metadata.interpreter,
                    "/" + posixpath.dirname(path),
                    "ELF interpreter",
                )
                interpreter = resolve(interpreter_path, "ELF interpreter")
                edges.append(
                    {
                        "from": path,
                        "kind": "interpreter",
                        "name": metadata.interpreter,
                        "resolved": interpreter.path,
                    }
                )
                visit(interpreter_path, inherited_rpaths=())
            origin = "/" + posixpath.dirname(path)
            next_inherited_rpaths = (
                tuple(
                    _elf_search_directory(value, origin, "ELF RPATH")
                    for value in metadata.rpath
                )
                + inherited_rpaths
                if not metadata.runpath
                else inherited_rpaths
            )
            for name in metadata.needed:
                dependency = resolve_library(
                    path, name, metadata, inherited_rpaths
                )
                dependency_metadata = _parse_arm64_elf(dependency)
                if dependency_metadata.soname is not None and dependency_metadata.soname != name:
                    raise DeterministicOCILayoutError(
                        "ELF dependency SONAME does not match DT_NEEDED"
                    )
                edges.append(
                    {
                        "from": path,
                        "kind": "needed",
                        "name": name,
                        "resolved": dependency.path,
                    }
                )
                visit(
                    dependency.path,
                    executable=False,
                    inherited_rpaths=next_inherited_rpaths,
                )
        else:
            raise DeterministicOCILayoutError(
                "runtime dependency is neither a script nor an ELF executable"
            )
        active.remove(path)
        visited.add(visit_identity)

    # Validate the policy unique to every required root before graph
    # deduplication.  A shebang traversal may otherwise visit (and memoize) a
    # later required root under the weaker interpreter policy first.
    for path in roots:
        resolved_root = resolve(
            path, "required runtime root", executable=True
        )
        root_prefix = _read_entry_range(
            resolved_root,
            0,
            min(resolved_root.size, _LINUX_BINPRM_BUF_SIZE),
        )
        if root_prefix.startswith(b"\x7fELF"):
            root_metadata = _parse_arm64_elf(resolved_root)
            if root_metadata.dynamic and root_metadata.interpreter is None:
                raise DeterministicOCILayoutError(
                    "dynamic runtime executable omits PT_INTERP"
                )

    for path in roots:
        visit(path, root=True)
    document = _canonical_bytes(
        {
            "edges": sorted(
                edges,
                key=lambda row: (
                    row["from"],
                    row["kind"],
                    row["name"],
                    row["resolved"],
                ),
            ),
            "roots": roots,
            "schema_version": "plamen.runtime_dependency_census.v1",
        }
    )
    return document, hashlib.sha256(document).hexdigest()


def _resolve_rootfs_entry(
    path: str,
    by_path: Mapping[str, _ExpandedEntry],
    *,
    label: str,
) -> _ExpandedEntry:
    current_path = _validate_relative_path(path, label)
    seen: set[str] = set()
    for _hop in range(_MAX_PATH_COMPONENTS):
        if current_path in seen:
            raise DeterministicOCILayoutError(f"{label} contains a link cycle")
        seen.add(current_path)
        parts = list(PurePosixPath(current_path).parts)
        redirected = False
        for end in range(1, len(parts) + 1):
            prefix = PurePosixPath(*parts[:end]).as_posix()
            entry = by_path.get(prefix)
            if entry is None:
                continue
            rest = parts[end:]
            if entry.kind == "file":
                if rest:
                    raise DeterministicOCILayoutError(f"{label} descends through a file")
                return entry
            if entry.kind == "hardlink":
                if rest:
                    raise DeterministicOCILayoutError(f"{label} descends through a hardlink")
                target = entry.linkname
            elif entry.linkname.startswith("/"):
                target = entry.linkname.removeprefix("/")
            else:
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(prefix), entry.linkname)
                )
            current_path = posixpath.normpath(
                posixpath.join(target, *rest) if rest else target
            )
            if current_path in {"", ".", ".."} or current_path.startswith("../"):
                raise DeterministicOCILayoutError(f"{label} escapes the rootfs")
            redirected = True
            break
        if not redirected:
            raise DeterministicOCILayoutError(f"{label} target is absent")
    raise DeterministicOCILayoutError(f"{label} exceeds the link-depth bound")


def _require_runnable_runtime(entries: Sequence[_ExpandedEntry]) -> None:
    by_path = {entry.path: entry for entry in entries}

    required_files = {
        RUNTIME_ENTRYPOINT.removeprefix("/"),
        "usr/bin/python3",
        "usr/local/lib/plamen/bin/claude",
        "usr/local/lib/plamen/bin/codex",
        "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
    }
    executable_paths = required_files
    if not required_files.issubset(by_path):
        raise DeterministicOCILayoutError("runtime closure omits a required runtime file")
    for path in required_files:
        requested = by_path[path]
        entry = _resolve_rootfs_entry(path, by_path, label="runtime file")
        if entry.source is None or entry.size < 4:
            raise DeterministicOCILayoutError("runtime closure file metadata is invalid")
        if path not in executable_paths:
            if requested.mode & 0o222 or entry.mode & 0o222:
                raise DeterministicOCILayoutError("runtime authority file is writable")
            continue
        if requested.mode & 0o111 == 0 or entry.mode & 0o111 == 0:
            raise DeterministicOCILayoutError("runtime closure executable metadata is invalid")
        entry.source.seek(0)
        magic = entry.source.read(_ELF_IDENTITY_BYTES)
        entry.source.seek(0)
        if not _is_supported_linux_executable(magic):
            raise DeterministicOCILayoutError("runtime closure executable format is unsupported")
    for path in RUNTIME_DYNAMIC_LIBRARIES:
        resolved = _resolve_rootfs_entry(
            path, by_path, label="Claude dynamic-loader dependency"
        )
        if resolved.source is None or resolved.size < 4:
            raise DeterministicOCILayoutError("runtime dynamic library is invalid")
        resolved.source.seek(0)
        magic = resolved.source.read(_ELF_IDENTITY_BYTES)
        resolved.source.seek(0)
        if not _is_arm64_elf(magic):
            raise DeterministicOCILayoutError(
                "runtime dynamic library platform is invalid"
            )


def _validate_expanded_links(entries: Sequence[_ExpandedEntry]) -> None:
    by_path = {entry.path: entry for entry in entries}
    for entry in entries:
        if entry.kind == "file":
            continue
        if entry.kind == "hardlink":
            target_path = entry.linkname
        elif entry.linkname.startswith("/"):
            target_path = entry.linkname.removeprefix("/")
        else:
            target_path = posixpath.normpath(
                posixpath.join(posixpath.dirname(entry.path), entry.linkname)
            )
        if entry.kind == "symlink" and any(
            path.startswith(target_path.rstrip("/") + "/") for path in by_path
        ):
            # Directory symlinks (for example Debian's /lib -> /usr/lib) do
            # not have a standalone directory row in the file census.
            continue
        if entry.kind == "symlink" and target_path not in by_path:
            # A contained dangling symlink is data, not an escape.  Required
            # executables and dynamic libraries are resolved separately and
            # therefore cannot rely on a dangling target.
            continue
        _resolve_rootfs_entry(entry.path, by_path, label="runtime archive link")


def _rootfs_derivation_evidence(
    plan: Mapping[str, Any],
    result: elf_closure.CacheFreeRootfsDerivation | None,
) -> tuple[bytes, dict[str, str]]:
    binding = plan["rootfs_derivation"]
    if binding["authentication_scope"] == elf_closure.AUTHENTICATION_SCOPE:
        if result is None:
            raise DeterministicOCILayoutError(
                "pinned rootfs derivation did not produce retained evidence"
            )
        observed: dict[str, Any] = {
            "schema_version": result.schema_version,
            "source_sha256": result.source_sha256,
            "source_size": result.source_size,
            "source_diff_id": _SHA256_PREFIX + result.source_diff_id,
            "derived_sha256": result.derived_sha256,
            "derived_size": result.derived_size,
            "derived_diff_id": _SHA256_PREFIX + result.derived_diff_id,
            "derived_tar_size": result.derived_tar_size,
            "derived_census_sha256": result.census_sha256,
            "derived_entry_count": result.entry_count,
            "manifest_sha256": result.manifest_sha256,
            "removed_cache_sha256": result.removed_cache_sha256,
            "removed_cache_size": result.removed_cache_size,
        }
        expected = {
            key: binding[key]
            for key in observed
            if key != "schema_version"
        }
        expected["schema_version"] = binding["derivation_schema_version"]
        if observed != expected:
            raise DeterministicOCILayoutError(
                "retained rootfs derivation evidence differs from the image lock"
            )
        manifest = result.manifest_bytes
    else:
        if result is not None:
            raise DeterministicOCILayoutError(
                "TEST_ONLY rootfs unexpectedly acquired pinned derivation evidence"
            )
        manifest = image_lock._TEST_ONLY_rootfs_derivation_manifest_bytes(binding)
    if not hmac.compare_digest(
        hashlib.sha256(manifest).hexdigest(), binding["manifest_sha256"]
    ):
        raise DeterministicOCILayoutError(
            "rootfs derivation manifest differs from the image lock"
        )
    return manifest, {
        "manifest_sha256": binding["manifest_sha256"],
        "derived_sha256": binding["derived_sha256"],
        "derived_diff_id": binding["derived_diff_id"],
        "derived_census_sha256": binding["derived_census_sha256"],
    }


def _consume_reader_exactly(adapter: _ReaderAdapter, size: int) -> None:
    remaining = size
    while remaining:
        chunk = adapter.read(min(remaining, _READ_CHUNK))
        if not chunk:
            raise DeterministicOCILayoutError("retained input was truncated")
        remaining -= len(chunk)
    adapter.authenticate_eof()


def _parse_materializer_json(raw: bytes, label: str) -> Any:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 64 * 1024 * 1024:
        raise DeterministicOCILayoutError(f"{label} is outside its byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except DeterministicOCILayoutError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise DeterministicOCILayoutError(f"{label} is malformed JSON") from exc
    if raw != _canonical_bytes(value):
        raise DeterministicOCILayoutError(f"{label} is not canonical JSON")
    return value


def _validate_materialized_runtime_census(
    raw: bytes,
    entries: Sequence[_ExpandedEntry],
    directories: set[str],
    binding: Mapping[str, Any],
) -> None:
    value = _parse_materializer_json(raw, "installed runtime census")
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "entries"}
        or value.get("schema_version")
        != image_lock.INSTALLED_RUNTIME_CENSUS_SCHEMA_VERSION
        or not isinstance(value.get("entries"), list)
    ):
        raise DeterministicOCILayoutError(
            "installed runtime census schema is unsupported"
        )
    rows = value["entries"]
    if (
        len(rows) != binding["entry_count"]
        or len(rows) > _MAX_LAYER_ENTRIES
    ):
        raise DeterministicOCILayoutError(
            "installed runtime census count differs from its binding"
        )
    observed: list[dict[str, Any]] = [
        {
            "kind": "directory",
            "linkname": "",
            "mode": "0755",
            "path": path,
            "sha256": None,
            "size": 0,
        }
        for path in directories
    ]
    observed.extend(
        {
            "kind": entry.kind,
            "linkname": entry.linkname,
            "mode": f"0{entry.mode:03o}",
            "path": entry.path,
            "sha256": entry.sha256,
            "size": entry.size,
        }
        for entry in entries
    )
    observed.sort(key=lambda row: row["path"].encode("utf-8", "strict"))
    prior: bytes | None = None
    for number, row in enumerate(rows):
        if (
            not isinstance(row, dict)
            or set(row)
            != {"kind", "linkname", "mode", "path", "sha256", "size"}
        ):
            raise DeterministicOCILayoutError(
                f"installed runtime census row {number} schema is not exact"
            )
        path = _validate_relative_path(
            row["path"], f"installed runtime census row {number} path"
        )
        encoded = path.encode("utf-8", "strict")
        if prior is not None and encoded <= prior:
            raise DeterministicOCILayoutError(
                "installed runtime census is not strictly ordered"
            )
        prior = encoded
        if row["kind"] not in {"file", "directory", "symlink", "hardlink"}:
            raise DeterministicOCILayoutError(
                "installed runtime census entry kind is unsupported"
            )
    if rows != observed:
        raise DeterministicOCILayoutError(
            "installed runtime census differs from the expanded archive"
        )
    if sum(row["size"] for row in rows if row["kind"] == "file") != binding[
        "expanded_bytes"
    ]:
        raise DeterministicOCILayoutError(
            "installed runtime expanded bytes differ from the census binding"
        )


def _expand_runtime_closure(
    plan: Mapping[str, Any],
    rows: Sequence[_InputMetadata],
    readers: Sequence[Any],
    *,
    spool_factory: Callable[[], BinaryIO] | None = None,
) -> tuple[list[_ExpandedEntry], str, str, dict[str, str], BinaryIO]:
    if len(rows) != len(readers):
        raise DeterministicOCILayoutError("retained-reader roster mismatch")
    roles = _runtime_input_roles(plan, rows)
    if spool_factory is not None and any(
        kind not in {"materialization_source_evidence", "materialization_evidence", "materialized_runtime_archive"}
        for kind, _identifier in roles.values()
    ):
        raise DeterministicOCILayoutError("retained transform requires the materialized runtime input lane")
    entries: list[_ExpandedEntry] = []
    files: set[str] = set()
    directories: set[str] = set()
    aliases: dict[str, str] = {}
    expanded_total = [0]
    archive_diff_ids: dict[str, str] = {}
    rootfs_evidence: dict[str, bytes] = {}
    rootfs_provenance_raw: bytes | None = None
    rootfs_source_diff_id: str | None = None
    derivation_result: elf_closure.CacheFreeRootfsDerivation | None = None
    derived_descriptor_owner: BinaryIO | None = None
    materialization_payloads: dict[str, bytes] = {}
    installed_attestation_sources: dict[
        str, tuple[_SpoolSlice, str, int]
    ] = {}
    materialized_archive_seen = False
    payload_spool = spool_factory() if spool_factory is not None else tempfile.TemporaryFile(mode="w+b")
    try:
        for row, reader in zip(rows, readers, strict=True):
            if type(reader) is image_lock._BuildInputReader:
                observed_metadata = (reader.path, reader.sha256, reader.size, reader.mode)
                expected_metadata = (row.path, row.sha256, row.size, f"0{row.mode:03o}")
                if observed_metadata != expected_metadata:
                    raise DeterministicOCILayoutError("retained-reader metadata mismatch")
            elif type(reader) is _RetainedTransformReader:
                if spool_factory is None or reader.metadata != row:
                    raise DeterministicOCILayoutError("retained transform reader binding differs")
            elif type(reader) is not _BytesReader:
                raise DeterministicOCILayoutError("retained-reader type is not authoritative")
            adapter = _ReaderAdapter(reader, row)
            kind, identifier = roles[row.path]
            if kind == "materialization_source_evidence":
                if identifier in {"sbom", "census", "complete-rootfs-provenance"}:
                    spool, digest = _append_exact_to_shared_spool(
                        adapter,
                        row.size,
                        payload_spool,
                        label=f"installed attestation source {identifier!r}",
                    )
                    adapter.authenticate_eof()
                    if not hmac.compare_digest(digest, row.sha256):
                        raise DeterministicOCILayoutError(
                            "installed attestation source digest mismatch"
                        )
                    installed_attestation_sources[identifier] = (
                        spool,
                        digest,
                        row.size,
                    )
                else:
                    _consume_reader_exactly(adapter, row.size)
                continue
            if kind == "materialization_evidence":
                spool, digest = _append_exact_to_shared_spool(
                    adapter,
                    row.size,
                    payload_spool,
                    label=f"runtime materialization {identifier!r}",
                )
                adapter.authenticate_eof()
                if not hmac.compare_digest(digest, row.sha256):
                    spool.close()
                    raise DeterministicOCILayoutError(
                        "runtime materialization evidence digest mismatch"
                    )
                spool.seek(0)
                materialization_payloads[identifier] = spool.read(row.size)
                spool.close()
                continue
            if kind == "materialized_runtime_archive":
                if materialized_archive_seen:
                    raise DeterministicOCILayoutError(
                        "materialized runtime archive is duplicated"
                    )
                materialized_archive_seen = True
                _expand_archive(
                    adapter,
                    row,
                    entries=entries,
                    files=files,
                    directories=directories,
                    aliases=aliases,
                    expanded_total=expanded_total,
                    payload_spool=payload_spool,
                    archive_diff_ids=archive_diff_ids,
                    install_kind="rootfs_archive",
                    identifier="materialized-runtime",
                    spool_factory=spool_factory,
                )
                continue
            if kind.endswith("_archive"):
                if kind == "rootfs_archive" and identifier == "complete-rootfs":
                    binding = plan["rootfs_derivation"]
                    rootfs_start = len(entries)
                    if binding["authentication_scope"] == elf_closure.AUTHENTICATION_SCOPE:
                        if type(reader) is not image_lock._BuildInputReader:
                            raise DeterministicOCILayoutError(
                                "pinned derivation requires an admitted retained reader"
                            )
                        source_descriptor = image_lock._TEST_ONLY_borrow_reader_descriptor(
                            reader
                        )
                        try:
                            source_identity = _stable_file_identity(
                                os.fstat(source_descriptor)
                            )
                            derived_descriptor_owner = tempfile.TemporaryFile(mode="w+b")
                            os.fchmod(derived_descriptor_owner.fileno(), 0o600)
                            derivation_result = elf_closure.derive_cache_free_rootfs(
                                source_descriptor,
                                derived_descriptor_owner.fileno(),
                                authenticated_provenance=(
                                    elf_closure.pinned_provenance_bytes()
                                ),
                            )
                            elf_closure.verify_cache_free_rootfs(
                                derived_descriptor_owner.fileno(),
                                manifest_bytes=derivation_result.manifest_bytes,
                            )
                            if _stable_file_identity(os.fstat(source_descriptor)) != source_identity:
                                raise DeterministicOCILayoutError(
                                    "retained rootfs source changed during derivation"
                                )
                        except elf_closure.ELFLoaderClosureError as exc:
                            raise DeterministicOCILayoutError(
                                "cache-free rootfs derivation failed closed"
                            ) from exc
                        finally:
                            os.close(source_descriptor)
                        _consume_reader_exactly(adapter, row.size)
                        rootfs_source_diff_id = _SHA256_PREFIX + derivation_result.source_diff_id
                        derived_identity = _stable_file_identity(
                            os.fstat(derived_descriptor_owner.fileno())
                        )
                        derived_descriptor_owner.seek(0)
                        derived_row = _InputMetadata(
                            path=row.path,
                            sha256=derivation_result.derived_sha256,
                            size=derivation_result.derived_size,
                            mode=0o600,
                        )
                        _expand_archive(
                            _ReaderAdapter(derived_descriptor_owner, derived_row),
                            derived_row,
                            entries=entries,
                            files=files,
                            directories=directories,
                            aliases=aliases,
                            expanded_total=expanded_total,
                            payload_spool=payload_spool,
                            archive_diff_ids=archive_diff_ids,
                            install_kind=kind,
                            identifier=identifier,
                        )
                        if _stable_file_identity(
                            os.fstat(derived_descriptor_owner.fileno())
                        ) != derived_identity:
                            raise DeterministicOCILayoutError(
                                "retained derived rootfs changed during expansion"
                            )
                    else:
                        _expand_archive(
                            adapter,
                            row,
                            entries=entries,
                            files=files,
                            directories=directories,
                            aliases=aliases,
                            expanded_total=expanded_total,
                            payload_spool=payload_spool,
                            archive_diff_ids=archive_diff_ids,
                            install_kind=kind,
                            identifier=identifier,
                        )
                        rootfs_source_diff_id = archive_diff_ids.get(identifier)
                        rootfs_entries = entries[rootfs_start:]
                        if (
                            binding["derived_sha256"] != row.sha256
                            or binding["derived_size"] != row.size
                            or binding["derived_diff_id"] != rootfs_source_diff_id
                            or binding["derived_entry_count"] != len(rootfs_entries)
                            or binding["derived_census_sha256"]
                            != _runtime_files_sha256(rootfs_entries)
                        ):
                            raise DeterministicOCILayoutError(
                                "TEST_ONLY pre-derived rootfs evidence is inconsistent"
                            )
                    continue
                _expand_archive(
                    adapter,
                    row,
                    entries=entries,
                    files=files,
                    directories=directories,
                    aliases=aliases,
                    expanded_total=expanded_total,
                    payload_spool=payload_spool,
                    archive_diff_ids=archive_diff_ids,
                    install_kind=kind,
                    identifier=identifier,
                )
                continue
            spool, digest = _append_exact_to_shared_spool(
                adapter,
                row.size,
                payload_spool,
                label=f"runtime input {row.path!r}",
            )
            adapter.authenticate_eof()
            if not hmac.compare_digest(digest, row.sha256):
                spool.close()
                raise DeterministicOCILayoutError("runtime input digest mismatch")
            if kind == "rootfs_evidence":
                spool.seek(0)
                rootfs_evidence[identifier] = spool.read(row.size)
                spool.close()
                continue
            if kind == "rootfs_provenance":
                spool.seek(0)
                rootfs_provenance_raw = spool.read(row.size)
                spool.seek(0)
            destination = (
                f"usr/local/lib/plamen/bin/{identifier}"
                if kind == "backend"
                else f"usr/local/lib/plamen/attestations/{identifier}.json"
            )
            _register_expanded_path(
                destination,
                is_file=True,
                files=files,
                directories=directories,
                aliases=aliases,
            )
            expanded_total[0] += row.size
            mode = 0o555 if kind == "backend" else 0o444
            entries.append(_ExpandedEntry(destination, digest, row.size, mode, spool))
        if materialized_archive_seen:
            expected_evidence = {
                "composition_manifest",
                "receipt",
                "census",
                "sbom",
                "provenance",
            }
            if set(materialization_payloads) != expected_evidence:
                raise DeterministicOCILayoutError(
                    "runtime materialization evidence roster is incomplete"
                )
            materialization = plan["runtime_materialization"]
            archive_binding = materialization["archive"]
            if (
                archive_diff_ids.get("materialized-runtime")
                != archive_binding["diff_id"]
            ):
                raise DeterministicOCILayoutError(
                    "materialized runtime archive DiffID changed"
                )
            _validate_materialized_runtime_census(
                materialization_payloads["census"],
                entries,
                directories,
                materialization["census"],
            )
            _require_complete_rootfs(entries)
            if set(installed_attestation_sources) != {
                "sbom",
                "census",
                "complete-rootfs-provenance",
            }:
                raise DeterministicOCILayoutError(
                    "retained installed attestation source roster is incomplete"
                )
            derivation_manifest, derivation_evidence = _rootfs_derivation_evidence(
                plan, derivation_result
            )
            derivation_spool, derivation_digest = _append_exact_to_shared_spool(
                io.BytesIO(derivation_manifest),
                len(derivation_manifest),
                payload_spool,
                label="installed rootfs derivation attestation",
            )
            installed_documents = {
                "usr/local/lib/plamen/attestations/sbom.json": (
                    *installed_attestation_sources["sbom"],
                ),
                "usr/local/lib/plamen/attestations/census.json": (
                    *installed_attestation_sources["census"],
                ),
                "usr/local/lib/plamen/attestations/complete-rootfs-provenance.json": (
                    *installed_attestation_sources["complete-rootfs-provenance"],
                ),
                "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json": (
                    derivation_spool,
                    derivation_digest,
                    len(derivation_manifest),
                ),
            }
            expected_document_digests = {
                "usr/local/lib/plamen/attestations/sbom.json": plan["attestations"]
                ["sbom"]["sha256"],
                "usr/local/lib/plamen/attestations/census.json": plan["attestations"]
                ["census"]["sha256"],
                "usr/local/lib/plamen/attestations/complete-rootfs-provenance.json": (
                    _runtime_asset(plan, "complete-rootfs-provenance")["sha256"]
                ),
                "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json": (
                    plan["rootfs_derivation"]["manifest_sha256"]
                ),
            }
            for path, (spool, digest, size) in installed_documents.items():
                if not hmac.compare_digest(digest, expected_document_digests[path]):
                    raise DeterministicOCILayoutError(
                        "retained installed attestation differs from its authority"
                    )
                _register_expanded_path(
                    path,
                    is_file=True,
                    files=files,
                    directories=directories,
                    aliases=aliases,
                )
                entries.append(_ExpandedEntry(path, digest, size, 0o444, spool))
                expanded_total[0] += size
                if expanded_total[0] > _MAX_EXPANDED_BYTES:
                    raise DeterministicOCILayoutError(
                        "expanded runtime exceeds its byte bound"
                    )
        else:
            raise DeterministicOCILayoutError(
                "authenticated materialized runtime archive is required"
            )
        if rootfs_provenance_raw is not None or derivation_result is not None:
            raise DeterministicOCILayoutError(
                "legacy runtime assembly cannot be mixed with materialized runtime"
            )
        entries.sort(key=lambda entry: (entry.path.casefold(), entry.path))
        if not entries:
            raise DeterministicOCILayoutError("expanded runtime roster is outside its bound")
        _require_layer_entry_count(
            len(entries) + len(directories), "expanded runtime"
        )
        _validate_expanded_links(entries)
        _require_runnable_runtime(entries)
        _dependency_document, dependency_census_sha256 = (
            _validate_runtime_dependencies(entries)
        )
        if derived_descriptor_owner is not None:
            try:
                elf_closure.verify_cache_free_rootfs(
                    derived_descriptor_owner.fileno(),
                    manifest_bytes=derivation_result.manifest_bytes,
                )
            except elf_closure.ELFLoaderClosureError as exc:
                raise DeterministicOCILayoutError(
                    "retained derived rootfs changed before dependency proof completed"
                ) from exc
        return (
            entries,
            _runtime_files_sha256(entries),
            dependency_census_sha256,
            derivation_evidence,
            payload_spool,
        )
    except BaseException:
        for entry in entries:
            try:
                if entry.source is not None:
                    entry.source.close()
            except Exception:
                pass
        payload_spool.close()
        raise
    finally:
        if derived_descriptor_owner is not None:
            derived_descriptor_owner.close()


def _descriptor(media_type: str, digest: str, size: int) -> dict[str, Any]:
    return {"digest": digest, "mediaType": media_type, "size": size}


def _image_documents(
    layer: _LayerResult,
    plan: Mapping[str, Any],
    runtime_files_sha256: str,
    runtime_dependency_census_sha256: str,
) -> tuple[bytes, bytes, bytes, str, str, str, str]:
    attestations = plan["attestations"]
    complete_rootfs = _runtime_asset(plan, "complete-rootfs")
    rootfs_provenance = _runtime_asset(plan, "complete-rootfs-provenance")
    derivation = plan["rootfs_derivation"]
    materialization = plan["runtime_materialization"]
    labels = {
        "org.plamen.build-input-census.sha256": plan["observed_build_input_census_sha256"],
        "org.plamen.complete-rootfs.provenance.sha256": rootfs_provenance["sha256"],
        "org.plamen.complete-rootfs.derivation-manifest.sha256": derivation[
            "manifest_sha256"
        ],
        "org.plamen.complete-rootfs.derived-census.sha256": derivation[
            "derived_census_sha256"
        ],
        "org.plamen.complete-rootfs.derived-diff-id": derivation[
            "derived_diff_id"
        ],
        "org.plamen.complete-rootfs.derived.sha256": derivation["derived_sha256"],
        "org.plamen.complete-rootfs.source.sha256": complete_rootfs["sha256"],
        "org.plamen.empty-root.lock-reference": plan["base_image_reference"],
        "org.plamen.runtime-census.sha256": attestations["census"]["sha256"],
        "org.plamen.runtime-dependencies.sha256": runtime_dependency_census_sha256,
        "org.plamen.runtime-files.sha256": runtime_files_sha256,
        "org.plamen.runtime-materialization.archive.diff-id": materialization[
            "archive"
        ]["diff_id"],
        "org.plamen.runtime-materialization.archive.sha256": materialization[
            "archive"
        ]["sha256"],
        "org.plamen.runtime-materialization.archive.size": str(
            materialization["archive"]["size"]
        ),
        "org.plamen.runtime-materialization.composition-manifest.sha256": (
            materialization["composition_manifest"]["sha256"]
        ),
        "org.plamen.runtime-materialization.entry-count": str(
            materialization["census"]["entry_count"]
        ),
        "org.plamen.runtime-materialization.expanded-bytes": str(
            materialization["census"]["expanded_bytes"]
        ),
        "org.plamen.runtime-materialization.installed-census.sha256": (
            materialization["census"]["sha256"]
        ),
        "org.plamen.runtime-materialization.provenance.sha256": materialization[
            "provenance"
        ]["sha256"],
        "org.plamen.runtime-materialization.receipt.sha256": materialization[
            "receipt"
        ]["sha256"],
        "org.plamen.runtime-materialization.sbom.sha256": materialization["sbom"][
            "sha256"
        ],
        "org.plamen.runtime-materialization.source-roster.sha256": materialization[
            "source_roster_sha256"
        ],
        "org.plamen.sbom.sha256": attestations["sbom"]["sha256"],
    }
    config = {
        "architecture": "arm64",
        "config": {
            "Entrypoint": [RUNTIME_ENTRYPOINT],
            "Env": list(RUNTIME_ENV),
            "Labels": labels,
            "User": RUNTIME_USER,
            "WorkingDir": RUNTIME_WORKDIR,
        },
        "created": _CREATED,
        "history": [
            {
                "comment": _LAYER_COMMENT,
                "created": _CREATED,
                "created_by": _LAYER_CREATED_BY,
                "empty_layer": False,
            }
        ],
        "os": "linux",
        "rootfs": {"diff_ids": [layer.diff_id], "type": "layers"},
    }
    config_raw = _canonical_bytes(config)
    config_digest = _sha256(config_raw)
    # Apple Container reports the canonical JSON object digest, without the
    # OCI blob's trailing canonical newline.  Bind both identities: the OCI
    # descriptor digest authenticates bytes, while this digest authenticates
    # the exact value returned in `container image inspect` variants[].config.
    apple_container_configuration_sha256 = hashlib.sha256(
        config_raw[:-1]
    ).hexdigest()
    manifest = {
        "config": _descriptor(OCI_CONFIG_MEDIA_TYPE, config_digest, len(config_raw)),
        "layers": [
            _descriptor(OCI_LAYER_MEDIA_TYPE, layer.blob_digest, layer.blob_size)
        ],
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "schemaVersion": 2,
    }
    manifest_raw = _canonical_bytes(manifest)
    manifest_digest = _sha256(manifest_raw)
    index = {
        "manifests": [
            {
                **_descriptor(
                    OCI_MANIFEST_MEDIA_TYPE,
                    manifest_digest,
                    len(manifest_raw),
                ),
                "platform": {"architecture": "arm64", "os": "linux"},
            }
        ],
        "mediaType": OCI_INDEX_MEDIA_TYPE,
        "schemaVersion": 2,
    }
    index_raw = _canonical_bytes(index)
    return (
        config_raw,
        manifest_raw,
        index_raw,
        config_digest,
        manifest_digest,
        _sha256(index_raw),
        apple_container_configuration_sha256,
    )


def _make_receipt(
    plan: Mapping[str, Any],
    rows: Sequence[_InputMetadata],
    layer: _LayerResult,
    *,
    config_digest: str,
    apple_container_configuration_sha256: str,
    index_digest: str,
    manifest_digest: str,
    runtime_files_sha256: str,
    runtime_dependency_census_sha256: str,
) -> bytes:
    input_rows = [
        {"mode": f"0{row.mode:03o}", "path": row.path, "sha256": row.sha256, "size": row.size}
        for row in rows
    ]
    materialization = plan["runtime_materialization"]
    receipt = {
        "build_input_bytes": sum(row.size for row in rows),
        "build_input_count": len(rows),
        "build_inputs_sha256": hashlib.sha256(_canonical_bytes(input_rows)).hexdigest(),
        "config_digest": config_digest,
        "apple_container_configuration_sha256": (
            apple_container_configuration_sha256
        ),
        "complete_rootfs_provenance_sha256": _runtime_asset(
            plan, "complete-rootfs-provenance"
        )["sha256"],
        "complete_rootfs_derivation_manifest_sha256": plan[
            "rootfs_derivation"
        ]["manifest_sha256"],
        "complete_rootfs_derived_sha256": plan["rootfs_derivation"][
            "derived_sha256"
        ],
        "complete_rootfs_derived_diff_id": plan["rootfs_derivation"][
            "derived_diff_id"
        ],
        "complete_rootfs_derived_census_sha256": plan["rootfs_derivation"][
            "derived_census_sha256"
        ],
        "complete_rootfs_source_sha256": _runtime_asset(
            plan, "complete-rootfs"
        )["sha256"],
        "empty_root_reference": plan["base_image_reference"],
        "layer_blob_digest": layer.blob_digest,
        "layer_diff_id": layer.diff_id,
        "lock_sha256": plan["lock_sha256"],
        "index_digest": index_digest,
        "manifest_digest": manifest_digest,
        "plan_sha256": plan["plan_sha256"],
        "read_completion": "ALL_RETAINED_READERS_AUTHENTICATED_EOF",
        "runtime_census_sha256": plan["attestations"]["census"]["sha256"],
        "runtime_dependency_census_sha256": runtime_dependency_census_sha256,
        "runtime_files_sha256": runtime_files_sha256,
        "runtime_materialization": {
            "archive_diff_id": materialization["archive"]["diff_id"],
            "archive_sha256": materialization["archive"]["sha256"],
            "archive_size": materialization["archive"]["size"],
            "composition_manifest_sha256": materialization[
                "composition_manifest"
            ]["sha256"],
            "entry_count": materialization["census"]["entry_count"],
            "expanded_bytes": materialization["census"]["expanded_bytes"],
            "installed_census_sha256": materialization["census"]["sha256"],
            "provenance_sha256": materialization["provenance"]["sha256"],
            "receipt_sha256": materialization["receipt"]["sha256"],
            "sbom_sha256": materialization["sbom"]["sha256"],
            "source_roster_sha256": materialization["source_roster_sha256"],
        },
        "schema_version": LAYOUT_RECEIPT_SCHEMA_VERSION,
        "sbom_sha256": plan["attestations"]["sbom"]["sha256"],
    }
    return _canonical_bytes(receipt)


def _stage_layout(
    plan: Mapping[str, Any],
    readers: Sequence[Any],
    output: str | Path,
) -> _StagedLayout:
    rows = _validate_plan_shape(plan)
    output_path = os.fspath(output)
    parent, output_name, ownership = _open_canonical_parent(output)
    opened, relationships = ownership
    parent_identity = _stable_identity(os.fstat(parent))
    publication_scope = hashlib.sha256(output_name.encode("utf-8")).hexdigest()[:32]
    lock_name = f".plamen-oci-layout-{publication_scope}.lock"
    lock_fd = -1
    staging_name = (
        f".plamen-oci-layout-stage-{publication_scope}-{secrets.token_hex(16)}"
    )
    staging_fd = blobs_fd = algorithm_fd = retained_root_fd = -1
    transferred = False
    try:
        if _safe_lstat(output_name, parent) is not None:
            raise DeterministicOCILayoutError("output already exists")
        lock_fd = _acquire_publication_lock(
            parent,
            lock_name,
            staging_name,
            kind="layout",
            directory_stage=True,
        )
        staging_fd = _mkdir_at(parent, staging_name, 0o700)
        os.fsync(parent)
        blobs_fd = _mkdir_at(staging_fd, "blobs", 0o700)
        algorithm_fd = _mkdir_at(blobs_fd, "sha256", 0o700)
        pending_fd = os.open(
            ".layer.pending",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=algorithm_fd,
        )
        entries: list[_ExpandedEntry] = []
        payload_spool: BinaryIO | None = None
        try:
            (
                entries,
                runtime_files_sha256,
                runtime_dependency_census_sha256,
                derivation_evidence,
                payload_spool,
            ) = _expand_runtime_closure(plan, rows, readers)
            expected_derivation = {
                "manifest_sha256": plan["rootfs_derivation"]["manifest_sha256"],
                "derived_sha256": plan["rootfs_derivation"]["derived_sha256"],
                "derived_diff_id": plan["rootfs_derivation"]["derived_diff_id"],
                "derived_census_sha256": plan["rootfs_derivation"][
                    "derived_census_sha256"
                ],
            }
            if derivation_evidence != expected_derivation:
                raise DeterministicOCILayoutError(
                    "rootfs derivation evidence changed before layer creation"
                )
            with os.fdopen(os.dup(pending_fd), "wb", buffering=0) as destination:
                layer = _write_layer(destination, entries)
            os.fsync(pending_fd)
            os.fchmod(pending_fd, 0o444)
            if _list_xattrs(pending_fd):
                raise DeterministicOCILayoutError("generated layer has extended metadata")
            os.fsync(pending_fd)
        finally:
            os.close(pending_fd)
            for entry in entries:
                try:
                    if entry.source is not None:
                        entry.source.close()
                except Exception:
                    pass
            if payload_spool is not None:
                payload_spool.close()
        layer_name = layer.blob_digest[len(_SHA256_PREFIX) :]
        _rename_noreplace(
            algorithm_fd, ".layer.pending", algorithm_fd, layer_name
        )
        (
            config_raw,
            manifest_raw,
            index_raw,
            config_digest,
            manifest_digest,
            index_digest,
            apple_container_configuration_sha256,
        ) = _image_documents(
            layer,
            plan,
            runtime_files_sha256,
            runtime_dependency_census_sha256,
        )
        if not hmac.compare_digest(manifest_digest, _expected_manifest_digest(plan)):
            raise DeterministicOCILayoutError("rendered manifest does not match the authenticated image lock")
        if not hmac.compare_digest(index_digest, _expected_index_digest(plan)):
            raise DeterministicOCILayoutError(
                "rendered index does not match the authenticated image lock"
            )
        if not hmac.compare_digest(
            config_digest,
            _validate_digest(
                plan["expected_config_digest"], "expected config digest"
            ),
        ):
            raise DeterministicOCILayoutError(
                "rendered config does not match the authenticated image lock"
            )
        if not hmac.compare_digest(
            apple_container_configuration_sha256,
            str(plan["expected_apple_container_configuration_sha256"]),
        ):
            raise DeterministicOCILayoutError(
                "rendered Apple Container configuration does not match the authenticated image lock"
            )
        _write_file_at(algorithm_fd, config_digest[len(_SHA256_PREFIX) :], config_raw)
        _write_file_at(algorithm_fd, manifest_digest[len(_SHA256_PREFIX) :], manifest_raw)
        _write_file_at(staging_fd, "oci-layout", _canonical_bytes({"imageLayoutVersion": OCI_LAYOUT_VERSION}))
        _write_file_at(staging_fd, "index.json", index_raw)
        for descriptor in (algorithm_fd, blobs_fd, staging_fd):
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o555)
            if _list_xattrs(descriptor):
                raise DeterministicOCILayoutError("generated directory has extended metadata")
            os.fsync(descriptor)
        receipt = _make_receipt(
            plan,
            rows,
            layer,
            config_digest=config_digest,
            apple_container_configuration_sha256=(
                apple_container_configuration_sha256
            ),
            index_digest=index_digest,
            manifest_digest=manifest_digest,
            runtime_files_sha256=runtime_files_sha256,
            runtime_dependency_census_sha256=runtime_dependency_census_sha256,
        )
        retained_root_fd = os.dup(staging_fd)
        retained_root_identity = _stable_identity(os.fstat(retained_root_fd))
        stage = _StagedLayout(
            parent_descriptor=parent,
            parent_identity=parent_identity,
            parent_relationships=relationships,
            staging_name=staging_name,
            output_name=output_name,
            output_path=output_path,
            lock_name=lock_name,
            index_digest=index_digest,
            manifest_digest=manifest_digest,
            config_digest=config_digest,
            apple_container_configuration_sha256=(
                apple_container_configuration_sha256
            ),
            layer_digest=layer.blob_digest,
            layer_diff_id=layer.diff_id,
            runtime_files_sha256=runtime_files_sha256,
            sbom_sha256=plan["attestations"]["sbom"]["sha256"],
            runtime_census_sha256=plan["attestations"]["census"]["sha256"],
            runtime_dependency_census_sha256=runtime_dependency_census_sha256,
            empty_root_reference=plan["base_image_reference"],
            complete_rootfs_source_sha256=_runtime_asset(
                plan, "complete-rootfs"
            )["sha256"],
            complete_rootfs_provenance_sha256=_runtime_asset(
                plan, "complete-rootfs-provenance"
            )["sha256"],
            complete_rootfs_derivation_manifest_sha256=plan[
                "rootfs_derivation"
            ]["manifest_sha256"],
            complete_rootfs_derived_sha256=plan["rootfs_derivation"][
                "derived_sha256"
            ],
            complete_rootfs_derived_diff_id=plan["rootfs_derivation"][
                "derived_diff_id"
            ],
            complete_rootfs_derived_census_sha256=plan["rootfs_derivation"][
                "derived_census_sha256"
            ],
            runtime_materialization_source_roster_sha256=plan[
                "runtime_materialization"
            ]["source_roster_sha256"],
            runtime_materialization_composition_manifest_sha256=plan[
                "runtime_materialization"
            ]["composition_manifest"]["sha256"],
            runtime_materialization_archive_sha256=plan[
                "runtime_materialization"
            ]["archive"]["sha256"],
            runtime_materialization_archive_diff_id=plan[
                "runtime_materialization"
            ]["archive"]["diff_id"],
            runtime_materialization_archive_size=plan["runtime_materialization"][
                "archive"
            ]["size"],
            installed_runtime_census_sha256=plan["runtime_materialization"][
                "census"
            ]["sha256"],
            runtime_materialization_receipt_sha256=plan[
                "runtime_materialization"
            ]["receipt"]["sha256"],
            runtime_materialization_sbom_sha256=plan["runtime_materialization"][
                "sbom"
            ]["sha256"],
            runtime_materialization_provenance_sha256=plan[
                "runtime_materialization"
            ]["provenance"]["sha256"],
            installed_runtime_entry_count=plan["runtime_materialization"][
                "census"
            ]["entry_count"],
            installed_runtime_expanded_bytes=plan["runtime_materialization"][
                "census"
            ]["expanded_bytes"],
            receipt=receipt,
            retained_root_descriptor=retained_root_fd,
            retained_root_identity=retained_root_identity,
        )
        retained_root_fd = -1
        transferred = True
        return stage
    except BaseException:
        stage_removed = _safe_lstat(staging_name, parent) is None
        if not stage_removed:
            try:
                _remove_recovery_stage(
                    parent,
                    staging_name,
                    directory=True,
                    expected_identity=(
                        _stable_identity(os.fstat(staging_fd))
                        if staging_fd >= 0
                        else None
                    ),
                )
                os.fsync(parent)
                stage_removed = True
            except Exception:
                pass
        if lock_fd >= 0 and stage_removed:
            try:
                os.unlink(lock_name, dir_fd=parent)
                os.fsync(parent)
            except OSError:
                pass
        try:
            os.close(parent)
        except OSError:
            pass
        raise
    finally:
        for descriptor in (
            algorithm_fd,
            blobs_fd,
            staging_fd,
            retained_root_fd,
            lock_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        # Keep ancestry descriptors alive in the returned staged object via
        # their integer values; close them only after publish/cleanup.
        if not transferred:
            for descriptor in reversed(opened):
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _close_stage_ancestry(stage: _StagedLayout) -> None:
    seen = {stage.parent_descriptor, stage.retained_root_descriptor}
    try:
        os.close(stage.retained_root_descriptor)
    except OSError:
        pass
    for parent, _component, child, _identity in reversed(stage.parent_relationships):
        for descriptor in (child, parent):
            if descriptor not in seen:
                seen.add(descriptor)
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    try:
        os.close(stage.parent_descriptor)
    except OSError:
        pass


def _make_tree_owner_writable_at(parent: int, name: str) -> None:
    """Restore deletion permissions without following a substituted symlink."""

    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            _stable_identity(opened) != _stable_identity(named)
            or not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or _list_xattrs(descriptor)
        ):
            raise DeterministicOCILayoutError(
                "staged layout directory identity is unsafe"
            )
        for entry in os.listdir(descriptor):
            row = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(row.st_mode) and not stat.S_ISLNK(row.st_mode):
                _make_tree_owner_writable_at(descriptor, entry)
            elif stat.S_ISREG(row.st_mode) and not stat.S_ISLNK(row.st_mode):
                if row.st_uid != os.geteuid() or row.st_nlink != 1:
                    raise DeterministicOCILayoutError(
                        "staged layout file identity is unsafe"
                    )
                child = os.open(
                    entry,
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=descriptor,
                )
                try:
                    opened_child = os.fstat(child)
                    if (
                        _stable_file_identity(opened_child)
                        != _stable_file_identity(row)
                        or _list_xattrs(child)
                    ):
                        raise DeterministicOCILayoutError(
                            "staged layout file changed during recovery"
                        )
                    os.fchmod(child, 0o600)
                    os.fsync(child)
                finally:
                    os.close(child)
            else:
                raise DeterministicOCILayoutError(
                    "staged layout contains an unexpected filesystem object"
                )
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_stage(stage: _StagedLayout) -> None:
    removed = False
    try:
        # A published name may have been replaced by another process after
        # publication.  There is no portable inode-conditioned recursive
        # unlink, so a failed post-publication verification must preserve the
        # named entry unconditionally.  The retained descriptor is enough to
        # prove failure without risking somebody else's directory tree.
        target = "" if stage.published else stage.staging_name
        if target and _safe_lstat(target, stage.parent_descriptor) is not None:
            _remove_recovery_stage(
                stage.parent_descriptor,
                target,
                directory=True,
                expected_identity=stage.retained_root_identity,
            )
            os.fsync(stage.parent_descriptor)
        removed = True
    finally:
        if removed:
            try:
                os.unlink(stage.lock_name, dir_fd=stage.parent_descriptor)
                os.fsync(stage.parent_descriptor)
            except OSError:
                pass
        _close_stage_ancestry(stage)


def _open_retained_layout_directory(parent: int, name: str, label: str) -> int:
    descriptor = os.open(
        name,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        row = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(row.st_mode)
            or stat.S_IMODE(row.st_mode) != 0o555
            or row.st_uid != os.geteuid()
            or _list_xattrs(descriptor)
        ):
            raise DeterministicOCILayoutError(
                f"retained {label} directory identity is invalid"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _revalidate_retained_layout(stage: _StagedLayout) -> None:
    """Prove the published name still denotes the exact retained layout.

    The pathname verifier closes semantic OCI edges.  This second pass uses
    the descriptor retained before publication, hashes all three exact blobs,
    and checks the named root again so a post-rename path substitution cannot
    be reported as a successful publication.
    """

    root = stage.retained_root_descriptor
    root_row = os.fstat(root)
    named = os.stat(
        stage.output_name,
        dir_fd=stage.parent_descriptor,
        follow_symlinks=False,
    )
    if (
        _stable_identity(root_row) != stage.retained_root_identity
        or _stable_identity(named) != stage.retained_root_identity
        or not stat.S_ISDIR(root_row.st_mode)
        or stat.S_IMODE(root_row.st_mode) != 0o555
        or root_row.st_uid != os.geteuid()
        or stat.S_ISLNK(named.st_mode)
        or _list_xattrs(root)
        or sorted(os.listdir(root)) != ["blobs", "index.json", "oci-layout"]
    ):
        raise DeterministicOCILayoutError("published layout identity changed")
    blobs = algorithm = layer_fd = -1
    try:
        blobs = _open_retained_layout_directory(root, "blobs", "blob")
        algorithm = _open_retained_layout_directory(
            blobs, "sha256", "digest algorithm"
        )
        if sorted(os.listdir(blobs)) != ["sha256"]:
            raise DeterministicOCILayoutError(
                "retained layout blob roster is not exact"
            )
        layout_raw = _read_bounded_file(
            root, "oci-layout", _MAX_JSON_BYTES, "retained oci-layout"
        )
        if layout_raw != _canonical_bytes(
            {"imageLayoutVersion": OCI_LAYOUT_VERSION}
        ):
            raise DeterministicOCILayoutError(
                "retained oci-layout bytes changed"
            )
        index_raw = _read_bounded_file(
            root, "index.json", _MAX_JSON_BYTES, "retained index"
        )
        if not hmac.compare_digest(_sha256(index_raw), stage.index_digest):
            raise DeterministicOCILayoutError("retained index digest changed")
        index = _parse_canonical_json(index_raw, "retained index")
        index = _exact_object(
            index,
            frozenset({"manifests", "mediaType", "schemaVersion"}),
            "retained index",
        )
        manifests = index["manifests"]
        if not isinstance(manifests, list) or len(manifests) != 1:
            raise DeterministicOCILayoutError(
                "retained index manifest roster changed"
            )
        manifest_descriptor = _exact_object(
            manifests[0], _PLATFORM_DESCRIPTOR_KEYS, "retained manifest descriptor"
        )
        platform = _exact_object(
            manifest_descriptor["platform"],
            frozenset({"architecture", "os"}),
            "retained manifest platform",
        )
        _validate_descriptor(
            {key: manifest_descriptor[key] for key in _DESCRIPTOR_KEYS},
            OCI_MANIFEST_MEDIA_TYPE,
            "retained manifest descriptor",
        )
        if (
            manifest_descriptor["digest"] != stage.manifest_digest
            or platform != {"architecture": "arm64", "os": "linux"}
        ):
            raise DeterministicOCILayoutError(
                "retained index manifest binding changed"
            )
        manifest_raw = _verify_layout_descriptor(
            algorithm, manifest_descriptor, "retained manifest"
        )
        expected_index = {
            "manifests": [
                {
                    **_descriptor(
                        OCI_MANIFEST_MEDIA_TYPE,
                        stage.manifest_digest,
                        len(manifest_raw),
                    ),
                    "platform": {"architecture": "arm64", "os": "linux"},
                }
            ],
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "schemaVersion": 2,
        }
        if index_raw != _canonical_bytes(expected_index):
            raise DeterministicOCILayoutError("retained index bytes changed")
        manifest = _parse_canonical_json(manifest_raw, "retained manifest")
        if not isinstance(manifest, dict):
            raise DeterministicOCILayoutError("retained manifest changed")
        config_descriptor = manifest.get("config")
        layers = manifest.get("layers")
        if (
            not isinstance(config_descriptor, dict)
            or config_descriptor.get("digest") != stage.config_digest
            or not isinstance(layers, list)
            or len(layers) != 1
            or not isinstance(layers[0], dict)
            or layers[0].get("digest") != stage.layer_digest
        ):
            raise DeterministicOCILayoutError(
                "retained manifest descriptor bindings changed"
            )
        retained_config_raw = _verify_layout_descriptor(
            algorithm, config_descriptor, "retained config"
        )
        retained_config = _parse_canonical_json(
            retained_config_raw, "retained config"
        )
        if not hmac.compare_digest(
            hashlib.sha256(_canonical_bytes(retained_config)[:-1]).hexdigest(),
            stage.apple_container_configuration_sha256,
        ):
            raise DeterministicOCILayoutError(
                "retained Apple Container configuration binding changed"
            )
        layer_fd, _compressed_size = _open_verified_layer_blob(
            algorithm, layers[0]
        )
        expected_blobs = sorted(
            digest.removeprefix(_SHA256_PREFIX)
            for digest in (
                stage.manifest_digest,
                stage.config_digest,
                stage.layer_digest,
            )
        )
        if sorted(os.listdir(algorithm)) != expected_blobs:
            raise DeterministicOCILayoutError(
                "retained layout digest roster changed"
            )
        named_after = os.stat(
            stage.output_name,
            dir_fd=stage.parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _stable_identity(named_after) != stage.retained_root_identity
            or _stable_identity(os.fstat(root)) != stage.retained_root_identity
        ):
            raise DeterministicOCILayoutError("published layout was substituted")
    finally:
        for descriptor in (layer_fd, algorithm, blobs):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _validate_acknowledgement(raw: Any, receipt: bytes) -> None:
    if not isinstance(raw, bytes):
        raise DeterministicOCILayoutError("read-completion acknowledgement must be canonical bytes")
    value = _parse_canonical_json(raw, "read-completion acknowledgement")
    expected = {
        "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
        "schema_version": LAYOUT_ACK_SCHEMA_VERSION,
        "status": "ACCEPTED",
    }
    if value != expected:
        raise DeterministicOCILayoutError("read-completion acknowledgement is invalid")


def _publish_stage(stage: _StagedLayout) -> None:
    _revalidate_parent(stage.parent_descriptor, stage.parent_identity, stage.parent_relationships)
    retained = os.fstat(stage.retained_root_descriptor)
    named_stage = os.stat(
        stage.staging_name,
        dir_fd=stage.parent_descriptor,
        follow_symlinks=False,
    )
    if (
        _stable_identity(retained) != stage.retained_root_identity
        or _stable_identity(named_stage) != stage.retained_root_identity
        or not stat.S_ISDIR(retained.st_mode)
        or stat.S_ISLNK(named_stage.st_mode)
    ):
        raise DeterministicOCILayoutError("staged layout identity changed")
    if _safe_lstat(stage.output_name, stage.parent_descriptor) is not None:
        raise DeterministicOCILayoutError("output appeared during publication")
    _rename_noreplace(
        stage.parent_descriptor,
        stage.staging_name,
        stage.parent_descriptor,
        stage.output_name,
    )
    stage.published = True
    published = os.stat(stage.output_name, dir_fd=stage.parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISDIR(published.st_mode)
        or stat.S_ISLNK(published.st_mode)
        or _stable_identity(published) != stage.retained_root_identity
        or _stable_identity(os.fstat(stage.retained_root_descriptor))
        != stage.retained_root_identity
    ):
        raise DeterministicOCILayoutError("published output is not a plain directory")
    os.fsync(stage.parent_descriptor)


def _finish_test_stage(
    stage: _StagedLayout,
    acknowledgement_consumer: Callable[[bytes], bytes],
) -> OCIImageLayoutResult:
    try:
        if not callable(acknowledgement_consumer):
            raise DeterministicOCILayoutError("read-completion acknowledger is unavailable")
        try:
            acknowledgement = acknowledgement_consumer(stage.receipt)
        except Exception:
            raise DeterministicOCILayoutError("read-completion acknowledgement failed closed") from None
        _validate_acknowledgement(acknowledgement, stage.receipt)
        _publish_stage(stage)
        _verify_oci_layout_for_testing(
            stage.output_path,
            expected_index_digest=stage.index_digest,
            expected_manifest_digest=stage.manifest_digest,
            expected_config_digest=stage.config_digest,
            expected_apple_container_configuration_sha256=(
                stage.apple_container_configuration_sha256
            ),
            expected_layer_digest=stage.layer_digest,
            expected_layer_diff_id=stage.layer_diff_id,
            expected_runtime_files_sha256=stage.runtime_files_sha256,
            expected_sbom_sha256=stage.sbom_sha256,
            expected_runtime_census_sha256=stage.runtime_census_sha256,
            expected_runtime_dependency_census_sha256=(
                stage.runtime_dependency_census_sha256
            ),
            expected_empty_root_reference=stage.empty_root_reference,
            expected_complete_rootfs_source_sha256=stage.complete_rootfs_source_sha256,
            expected_complete_rootfs_provenance_sha256=stage.complete_rootfs_provenance_sha256,
            expected_complete_rootfs_derivation_manifest_sha256=(
                stage.complete_rootfs_derivation_manifest_sha256
            ),
            expected_complete_rootfs_derived_sha256=(
                stage.complete_rootfs_derived_sha256
            ),
            expected_complete_rootfs_derived_diff_id=(
                stage.complete_rootfs_derived_diff_id
            ),
            expected_complete_rootfs_derived_census_sha256=(
                stage.complete_rootfs_derived_census_sha256
            ),
        )
        result = OCIImageLayoutResult(
            index_digest=stage.index_digest,
            manifest_digest=stage.manifest_digest,
            config_digest=stage.config_digest,
            apple_container_configuration_sha256=(
                stage.apple_container_configuration_sha256
            ),
            layer_digest=stage.layer_digest,
            layer_diff_id=stage.layer_diff_id,
            receipt=stage.receipt,
            runtime_files_sha256=stage.runtime_files_sha256,
            sbom_sha256=stage.sbom_sha256,
            runtime_census_sha256=stage.runtime_census_sha256,
            runtime_dependency_census_sha256=(
                stage.runtime_dependency_census_sha256
            ),
            empty_root_reference=stage.empty_root_reference,
            complete_rootfs_source_sha256=stage.complete_rootfs_source_sha256,
            complete_rootfs_provenance_sha256=stage.complete_rootfs_provenance_sha256,
            complete_rootfs_derivation_manifest_sha256=(
                stage.complete_rootfs_derivation_manifest_sha256
            ),
            complete_rootfs_derived_sha256=stage.complete_rootfs_derived_sha256,
            complete_rootfs_derived_diff_id=stage.complete_rootfs_derived_diff_id,
            complete_rootfs_derived_census_sha256=(
                stage.complete_rootfs_derived_census_sha256
            ),
            runtime_materialization_source_roster_sha256=(
                stage.runtime_materialization_source_roster_sha256
            ),
            runtime_materialization_composition_manifest_sha256=(
                stage.runtime_materialization_composition_manifest_sha256
            ),
            runtime_materialization_archive_sha256=(
                stage.runtime_materialization_archive_sha256
            ),
            runtime_materialization_archive_diff_id=(
                stage.runtime_materialization_archive_diff_id
            ),
            runtime_materialization_archive_size=(
                stage.runtime_materialization_archive_size
            ),
            installed_runtime_census_sha256=(
                stage.installed_runtime_census_sha256
            ),
            runtime_materialization_receipt_sha256=(
                stage.runtime_materialization_receipt_sha256
            ),
            runtime_materialization_sbom_sha256=(
                stage.runtime_materialization_sbom_sha256
            ),
            runtime_materialization_provenance_sha256=(
                stage.runtime_materialization_provenance_sha256
            ),
            installed_runtime_entry_count=stage.installed_runtime_entry_count,
            installed_runtime_expanded_bytes=stage.installed_runtime_expanded_bytes,
        )
        os.unlink(stage.lock_name, dir_fd=stage.parent_descriptor)
        os.fsync(stage.parent_descriptor)
        _revalidate_retained_layout(stage)
        _close_stage_ancestry(stage)
        return result
    except BaseException:
        _cleanup_stage(stage)
        raise


@_public_boundary("production OCI layout construction")
def build_oci_layout(
    plan: image_lock.OCIValidatedBuildPlan,
    output: str | Path,
    *,
    authenticated_context_consumer: object,
) -> OCIImageLayoutResult:
    """Request production construction without accepting Python authority.

    An exact production plan is mandatory.  The image-lock implementation
    currently closes its retained descriptors and returns
    ``AUTHENTICATED_CONTEXT_CONSUMER_REQUIRED``; this wrapper deliberately does
    not expose an alternate Python construction route.
    """

    if type(plan) is not image_lock.OCIValidatedBuildPlan:
        raise DeterministicOCILayoutError("exact production OCI build plan is required")
    if plan.get("authentication_scope") == _TEST_AUTHENTICATION_SCOPE:
        raise DeterministicOCILayoutError("test-only build plan is not production authority")
    _validate_plan_shape(plan)
    del output
    try:
        return plan.consume_build_context(authenticated_context_consumer)
    except image_lock.OCIImageLockError as exc:
        if str(exc) == _PRODUCTION_CONSUMER_REQUIRED:
            raise DeterministicOCILayoutError(_PRODUCTION_CONSUMER_REQUIRED) from None
        raise DeterministicOCILayoutError("authenticated context consumption failed closed") from None


@_public_boundary("test-only OCI layout construction")
def _build_oci_layout_for_testing(
    plan: image_lock.OCIValidatedBuildPlan,
    output: str | Path,
    *,
    authenticated_external_fake_acknowledger: Callable[[bytes], bytes],
) -> OCIImageLayoutResult:
    """Exercise rendering using the explicitly non-production image-lock seam."""

    if type(plan) is not image_lock._TestingOCIValidatedBuildPlan:
        raise DeterministicOCILayoutError("exact test-only OCI build plan is required")
    if plan.get("authentication_scope") != _TEST_AUTHENTICATION_SCOPE:
        raise DeterministicOCILayoutError("test-only build plan scope is invalid")
    _validate_plan_shape(plan)
    stage = plan.consume_build_context_for_testing(
        lambda readers: _stage_layout(plan, readers, output)
    )
    if type(stage) is not _StagedLayout:
        raise DeterministicOCILayoutError("test build-context consumer returned an invalid stage")
    return _finish_test_stage(stage, authenticated_external_fake_acknowledger)


class _RetainedTransformReader:
    """Pure byte-transform reader, not a production capability or receipt.

    Used only inside the separately supervised helper with retained scratch.
    Public build/verify entrypoints still require native execution authority.
    """

    def __init__(self, descriptor: int, offset: int, metadata: _InputMetadata) -> None:
        if type(descriptor) is not int or descriptor < 0 or type(offset) is not int or offset < 0:
            raise DeterministicOCILayoutError("invalid transform slice")
        self.descriptor, self.start, self.metadata = descriptor, offset, metadata
        self.offset = 0

    def read(self, maximum_bytes: int) -> bytes:
        if type(maximum_bytes) is not int or maximum_bytes < 0:
            raise DeterministicOCILayoutError("transform read requires a finite bound")
        count = min(maximum_bytes, self.metadata.size - self.offset)
        raw = os.pread(self.descriptor, count, self.start + self.offset)
        if len(raw) != count:
            raise DeterministicOCILayoutError("transform slice was truncated")
        self.offset += len(raw)
        return raw


class _BytesReader:
    """Private byte reader for narrow parser unit tests; never authority."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw
        self._offset = 0

    def read(self, maximum_bytes: int) -> bytes:
        result = self._raw[self._offset : self._offset + maximum_bytes]
        self._offset += len(result)
        return result

def _read_bounded_file(parent: int, name: str, maximum: int, label: str) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        row = os.fstat(descriptor)
        identity = _stable_file_identity(row)
        if (
            not stat.S_ISREG(row.st_mode)
            or row.st_nlink != 1
            or stat.S_IMODE(row.st_mode) != 0o444
            or row.st_size < 0
            or row.st_size > maximum
        ):
            raise DeterministicOCILayoutError(f"{label} file identity is invalid")
        if _list_xattrs(descriptor):
            raise DeterministicOCILayoutError(f"{label} has extended metadata")
        chunks: list[bytes] = []
        remaining = int(row.st_size)
        while remaining:
            chunk = os.read(descriptor, min(remaining, _READ_CHUNK))
            if not chunk:
                raise DeterministicOCILayoutError(f"{label} was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise DeterministicOCILayoutError(f"{label} grew while reading")
        if _stable_file_identity(os.fstat(descriptor)) != identity:
            raise DeterministicOCILayoutError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _exact_object(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise DeterministicOCILayoutError(f"{label} schema is unsupported")
    return value


def _validate_binding_identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in value
        )
    ):
        raise DeterministicOCILayoutError(f"installed {label} is malformed")
    return value


def _validate_installed_attestations(
    payloads: Mapping[str, bytes],
    labels: Mapping[str, Any],
) -> None:
    """Parse and cross-bind the attestations embedded in the final rootfs."""

    if set(payloads) != _INSTALLED_ATTESTATION_PATHS:
        raise DeterministicOCILayoutError(
            "installed attestation document roster is not exact"
        )
    label_by_path = {
        "usr/local/lib/plamen/attestations/census.json": "org.plamen.runtime-census.sha256",
        "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json": (
            "org.plamen.complete-rootfs.derivation-manifest.sha256"
        ),
        "usr/local/lib/plamen/attestations/complete-rootfs-provenance.json": (
            "org.plamen.complete-rootfs.provenance.sha256"
        ),
        "usr/local/lib/plamen/attestations/sbom.json": "org.plamen.sbom.sha256",
    }
    for path, raw in payloads.items():
        if not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), str(labels[label_by_path[path]])
        ):
            raise DeterministicOCILayoutError(
                "installed attestation digest does not match its label"
            )

    census = _exact_object(
        _parse_canonical_json(
            payloads["usr/local/lib/plamen/attestations/census.json"], "runtime census"
        ),
        frozenset({"artifacts", "schema_version"}),
        "runtime census",
    )
    if census["schema_version"] != image_lock.RUNTIME_CENSUS_SCHEMA_VERSION:
        raise DeterministicOCILayoutError(
            "installed runtime census schema is unsupported"
        )
    artifacts = census["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= _MAX_INPUTS:
        raise DeterministicOCILayoutError(
            "installed runtime census artifact roster is invalid"
        )
    normalized: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    paths: set[str] = set()
    for index, raw_row in enumerate(artifacts):
        row = _exact_object(
            raw_row,
            frozenset({"artifact_id", "path", "role", "sha256", "version"}),
            f"runtime census artifact {index}",
        )
        artifact_id = _validate_binding_identifier(
            row["artifact_id"], "runtime census artifact id"
        )
        role = row["role"]
        if role not in {
            "asset",
            "backend_cli",
            "cpython",
            "generated_attestation",
            "toolchain",
        }:
            raise DeterministicOCILayoutError(
                "installed runtime census role is unsupported"
            )
        path = _validate_relative_path(row["path"], "runtime census artifact path")
        digest = row["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise DeterministicOCILayoutError(
                "installed runtime census digest is malformed"
            )
        version = row["version"]
        if version is not None and (
            not isinstance(version, str)
            or not 1 <= len(version.encode("utf-8", "strict")) <= _MAX_STRING_BYTES
        ):
            raise DeterministicOCILayoutError(
                "installed runtime census version is malformed"
            )
        identity = (role, artifact_id)
        if identity in identities or path in paths:
            raise DeterministicOCILayoutError(
                "installed runtime census contains an ambiguous binding"
            )
        identities.add(identity)
        paths.add(path)
        normalized.append(
            {
                "artifact_id": artifact_id,
                "path": path,
                "role": role,
                "sha256": digest,
                "version": version,
            }
        )
    if artifacts != sorted(
        normalized, key=lambda row: (row["role"], row["artifact_id"])
    ):
        raise DeterministicOCILayoutError(
            "installed runtime census order is not canonical"
        )

    expected_spdx = {
        "packages": [
            {
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": row["sha256"]}
                ],
                "name": f"{row['role']}:{row['artifact_id']}",
                "versionInfo": row["version"] or "content-addressed",
            }
            for row in normalized
        ],
        "spdxVersion": "SPDX-2.3",
    }
    expected_cyclonedx = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                "name": f"{row['role']}:{row['artifact_id']}",
                "version": row["version"] or "content-addressed",
            }
            for row in normalized
        ],
        "specVersion": "1.6",
    }
    sbom = _parse_canonical_json(
        payloads["usr/local/lib/plamen/attestations/sbom.json"], "SBOM"
    )
    if sbom not in (expected_spdx, expected_cyclonedx):
        raise DeterministicOCILayoutError(
            "installed SBOM does not exactly bind the runtime census"
        )

    derivation = _parse_canonical_json(
        payloads[
            "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json"
        ],
        "cache-free rootfs derivation",
    )
    if not isinstance(derivation, dict) or derivation.get("production_authority") is not False:
        raise DeterministicOCILayoutError(
            "installed rootfs derivation manifest claims authority"
        )
    if derivation.get("schema_version") == elf_closure.SCHEMA_VERSION:
        closure = derivation.get("closure_contract")
        derived = derivation.get("derived")
        source = derivation.get("source")
        removed = derivation.get("removed")
        if (
            derivation.get("recipe_version") != elf_closure.RECIPE_VERSION
            or derivation.get("status")
            != "CONTENT_DERIVED_PENDING_NATIVE_HANDOFF_AND_TRANSITIVE_ELF_PROOF"
            or not isinstance(closure, dict)
            or closure.get("required_environment_denials")
            != {"exact_names": ["GLIBC_TUNABLES"], "prefixes": ["LD_"]}
            or closure.get("hwcaps_directories") != "FORBIDDEN"
            or not isinstance(derived, dict)
            or derived.get("sha256")
            != _SHA256_PREFIX
            + str(labels["org.plamen.complete-rootfs.derived.sha256"])
            or derived.get("diff_id")
            != labels["org.plamen.complete-rootfs.derived-diff-id"]
            or derived.get("census_sha256")
            != labels["org.plamen.complete-rootfs.derived-census.sha256"]
            or not isinstance(source, dict)
            or source.get("sha256")
            != _SHA256_PREFIX
            + str(labels["org.plamen.complete-rootfs.source.sha256"])
            or not isinstance(removed, dict)
            or removed.get("path") != "/etc/ld.so.cache"
        ):
            raise DeterministicOCILayoutError(
                "installed pinned rootfs derivation manifest is not exact"
            )
    elif derivation.get("schema_version") == (
        "plamen.cache_free_rootfs_derivation_manifest.test.v1"
    ):
        binding = derivation.get("binding")
        if (
            derivation.get("status") != "TEST_ONLY_PRE_DERIVED_CACHE_FREE"
            or not isinstance(binding, dict)
            or binding.get("authentication_scope")
            != "TEST_ONLY_NO_RELEASE_AUTHORITY"
            or binding.get("recipe_version")
            != image_lock.TEST_ONLY_ROOTFS_DERIVATION_RECIPE
            or binding.get("derived_sha256")
            != labels["org.plamen.complete-rootfs.derived.sha256"]
            or binding.get("derived_diff_id")
            != labels["org.plamen.complete-rootfs.derived-diff-id"]
            or binding.get("derived_census_sha256")
            != labels["org.plamen.complete-rootfs.derived-census.sha256"]
            or binding.get("source_sha256")
            != labels["org.plamen.complete-rootfs.source.sha256"]
            or binding.get("forbidden_environment")
            != {"exact_names": ["GLIBC_TUNABLES"], "prefixes": ["LD_"]}
        ):
            raise DeterministicOCILayoutError(
                "installed TEST_ONLY rootfs derivation manifest is not exact"
            )
    else:
        raise DeterministicOCILayoutError(
            "installed rootfs derivation manifest schema is unsupported"
        )

    provenance = _exact_object(
        _parse_canonical_json(
            payloads["usr/local/lib/plamen/attestations/complete-rootfs-provenance.json"],
            "complete-rootfs provenance",
        ),
        _ROOTFS_PROVENANCE_KEYS,
        "complete-rootfs provenance",
    )
    if (
        provenance["schema_version"] != _ROOTFS_PROVENANCE_SCHEMA_VERSION
        or provenance["platform"] != "linux/arm64/v8"
        or provenance["authentication_scope"]
        not in {_TEST_AUTHENTICATION_SCOPE, "REGISTRY_TLS_EXACT_DIGESTS"}
    ):
        raise DeterministicOCILayoutError(
            "installed complete-rootfs provenance is unsupported"
        )
    for key in (
        "index_digest",
        "manifest_digest",
        "config_digest",
        "layer_digest",
        "layer_diff_id",
    ):
        _validate_digest(provenance[key], f"installed complete-rootfs {key}")
    for key in ("index_size", "manifest_size", "config_size", "layer_size"):
        if (
            type(provenance[key]) is not int
            or not 1 <= provenance[key] <= _MAX_INPUT_BYTES
        ):
            raise DeterministicOCILayoutError(
                "installed complete-rootfs provenance size is invalid"
            )
    commit = provenance["official_images_commit"]
    official_images_sha256 = provenance["official_images_sha256"]
    source_reference = provenance["source_reference"]
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
        or commit != _DEBIAN_OFFICIAL_IMAGES_COMMIT
        or not isinstance(official_images_sha256, str)
        or len(official_images_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in official_images_sha256
        )
        or not isinstance(source_reference, str)
        or source_reference.count("@") != 1
        or source_reference.split("@", 1)[0]
        != "docker.io/library/debian:bookworm-20260824-slim"
        or not hmac.compare_digest(
            source_reference.rsplit("@", 1)[1], provenance["index_digest"]
        )
        or not hmac.compare_digest(
            provenance["layer_digest"],
            _SHA256_PREFIX
            + str(labels["org.plamen.complete-rootfs.source.sha256"]),
        )
    ):
        raise DeterministicOCILayoutError(
            "installed complete-rootfs provenance is not immutable and bound"
        )
    if provenance["authentication_scope"] == "REGISTRY_TLS_EXACT_DIGESTS" and any(
        provenance[key] != expected
        for key, expected in _DEBIAN_RELEASE_CLOSURE.items()
    ):
        raise DeterministicOCILayoutError(
            "installed production rootfs provenance is not the exact Debian closure"
        )
    census_by_identity = {
        (row["role"], row["artifact_id"]): row for row in normalized
    }
    for artifact_id, label_key in (
        ("complete-rootfs", "org.plamen.complete-rootfs.source.sha256"),
        (
            "complete-rootfs-provenance",
            "org.plamen.complete-rootfs.provenance.sha256",
        ),
    ):
        binding = census_by_identity.get(("asset", artifact_id))
        if binding is None or not hmac.compare_digest(
            binding["sha256"], str(labels[label_key])
        ):
            raise DeterministicOCILayoutError(
                "installed rootfs evidence is absent from the runtime census"
            )
    generated_derivation = census_by_identity.get(
        ("generated_attestation", "cache-free-rootfs-derivation")
    )
    if (
        generated_derivation is None
        or generated_derivation["path"]
        != "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json"
        or generated_derivation["sha256"]
        != labels["org.plamen.complete-rootfs.derivation-manifest.sha256"]
    ):
        raise DeterministicOCILayoutError(
            "rootfs derivation is absent from the runtime census"
        )
    evidence_digests = {
        "complete-rootfs-config": provenance["config_digest"].removeprefix(
            _SHA256_PREFIX
        ),
        "complete-rootfs-index": provenance["index_digest"].removeprefix(
            _SHA256_PREFIX
        ),
        "complete-rootfs-manifest": provenance["manifest_digest"].removeprefix(
            _SHA256_PREFIX
        ),
        "complete-rootfs-official-images": provenance["official_images_sha256"],
    }
    for artifact_id, expected_digest in evidence_digests.items():
        binding = census_by_identity.get(("asset", artifact_id))
        if binding is None or not hmac.compare_digest(
            binding["sha256"], expected_digest
        ):
            raise DeterministicOCILayoutError(
                "installed OCI source evidence is absent from the runtime census"
            )


def _validate_descriptor(value: Any, media_type: str, label: str) -> dict[str, Any]:
    row = _exact_object(value, _DESCRIPTOR_KEYS, label)
    if row["mediaType"] != media_type or type(row["size"]) is not int or row["size"] < 0:
        raise DeterministicOCILayoutError(f"{label} is malformed")
    _validate_digest(row["digest"], f"{label} digest")
    return row


def _verify_layout_descriptor(blob_directory: int, descriptor: Mapping[str, Any], label: str) -> bytes:
    digest = _validate_digest(descriptor["digest"], f"{label} digest")
    raw = _read_bounded_file(
        blob_directory,
        digest[len(_SHA256_PREFIX) :],
        _MAX_JSON_BYTES,
        label,
    )
    if len(raw) != descriptor["size"] or not hmac.compare_digest(_sha256(raw), digest):
        raise DeterministicOCILayoutError(f"{label} descriptor does not match its blob")
    return raw


def _open_verified_layer_blob(
    blob_directory: int,
    descriptor: Mapping[str, Any],
) -> tuple[int, int]:
    digest = _validate_digest(descriptor["digest"], "layer descriptor digest")
    expected_size = descriptor["size"]
    maximum = _MAX_INPUT_BYTES + _MAX_LAYER_ENTRIES * 2048
    if type(expected_size) is not int or not 0 < expected_size <= maximum:
        raise DeterministicOCILayoutError("layer blob size is outside its bound")
    descriptor_fd = os.open(
        digest[len(_SHA256_PREFIX) :],
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=blob_directory,
    )
    try:
        before = os.fstat(descriptor_fd)
        identity = _stable_file_identity(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_size != expected_size
            or _list_xattrs(descriptor_fd)
        ):
            raise DeterministicOCILayoutError("layer blob identity is invalid")
        observed = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor_fd, _READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                raise DeterministicOCILayoutError("layer blob grew while hashing")
            observed.update(chunk)
        if (
            total != expected_size
            or not hmac.compare_digest(_SHA256_PREFIX + observed.hexdigest(), digest)
            or _stable_file_identity(os.fstat(descriptor_fd)) != identity
        ):
            raise DeterministicOCILayoutError("layer descriptor does not match its blob")
        os.lseek(descriptor_fd, 0, os.SEEK_SET)
        header = os.read(descriptor_fd, 10)
        if header != b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff":
            raise DeterministicOCILayoutError("layer gzip header is not deterministic")
        os.lseek(descriptor_fd, 0, os.SEEK_SET)
        return descriptor_fd, expected_size
    except BaseException:
        os.close(descriptor_fd)
        raise


class _BoundedGzipReader:
    """Incrementally decode one exact gzip member and hash its tar bytes."""

    def __init__(
        self,
        descriptor: int,
        compressed_size: int,
        raw_tar_mirror: BinaryIO,
    ) -> None:
        self._descriptor = descriptor
        self._compressed_size = compressed_size
        self._raw_tar_mirror = raw_tar_mirror
        self._compressed_read = 0
        self._decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
        self._pending = bytearray()
        self._digest = hashlib.sha256()
        self._uncompressed_size = 0
        self._finished = False

    def _record(self, raw: bytes) -> None:
        if not raw:
            return
        self._uncompressed_size += len(raw)
        if self._uncompressed_size > _MAX_INPUT_BYTES + _MAX_LAYER_ENTRIES * 2048:
            raise DeterministicOCILayoutError("uncompressed layer exceeds its bound")
        self._raw_tar_mirror.write(raw)
        self._pending.extend(raw)

    def _fill(self, requested: int) -> None:
        while len(self._pending) < requested and not self._finished:
            chunk = os.read(self._descriptor, _READ_CHUNK)
            if not chunk:
                if not self._decoder.eof:
                    raise DeterministicOCILayoutError("layer gzip member is truncated")
                self._record(self._decoder.flush())
                self._finished = True
                break
            self._compressed_read += len(chunk)
            if self._compressed_read > self._compressed_size:
                raise DeterministicOCILayoutError("layer gzip member exceeds its bound")
            try:
                self._record(self._decoder.decompress(chunk))
            except zlib.error as exc:
                raise DeterministicOCILayoutError("layer gzip member is malformed") from exc
            if self._decoder.eof:
                if self._decoder.unused_data or self._compressed_read != self._compressed_size:
                    raise DeterministicOCILayoutError(
                        "layer gzip member has trailing or concatenated content"
                    )
                self._record(self._decoder.flush())
                self._finished = True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunks: list[bytes] = []
            while True:
                chunk = self.read(_READ_CHUNK)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        if size == 0:
            return b""
        self._fill(size)
        result = bytes(self._pending[:size])
        del self._pending[: len(result)]
        self._digest.update(result)
        return result

    def drain(self) -> None:
        while self.read(_READ_CHUNK):
            pass
        if not self._finished or self._pending or self._compressed_read != self._compressed_size:
            raise DeterministicOCILayoutError("layer gzip member did not terminate exactly")

    @property
    def diff_id(self) -> str:
        return _SHA256_PREFIX + self._digest.hexdigest()

    @property
    def uncompressed_size(self) -> int:
        return self._uncompressed_size


def _verify_layer_tar(
    blob_directory: int,
    descriptor: Mapping[str, Any],
    expected_diff_id: str,
) -> tuple[tuple[dict[str, Any], ...], dict[str, bytes], dict[str, bytes], str]:
    layer_fd, compressed_size = _open_verified_layer_blob(blob_directory, descriptor)
    raw_tar_spool = tempfile.TemporaryFile(mode="w+b")
    decoder = _BoundedGzipReader(layer_fd, compressed_size, raw_tar_spool)
    names: set[str] = set()
    directory_names: list[str] = []
    file_names: list[str] = []
    file_bytes = 0
    expected_tar_payload = 0
    saw_file = False
    file_records: list[dict[str, Any]] = []
    file_magic: dict[str, bytes] = {}
    attestation_payloads: dict[str, bytes] = {}
    file_sources: dict[str, _SpoolSlice] = {}
    payload_spool = tempfile.TemporaryFile(mode="w+b")
    aliases: dict[str, str] = {}
    registered_files: set[str] = set()
    registered_directories: set[str] = set()
    try:
        try:
            with tarfile.open(fileobj=decoder, mode="r|") as archive:
                for member in archive:
                    _require_layer_entry_count(len(names) + 1, "layer")
                    name = (
                        member.name[:-1]
                        if member.isdir() and member.name.endswith("/")
                        else member.name
                    )
                    _validate_relative_path(name, "layer entry path")
                    if PurePosixPath(name).parts[0] not in _ALLOWED_ROOT_COMPONENTS:
                        raise DeterministicOCILayoutError("layer targets a forbidden rootfs namespace")
                    if name in names:
                        raise DeterministicOCILayoutError("layer contains a duplicate path")
                    names.add(name)
                    if (
                        member.pax_headers
                        or member.uid != 0
                        or member.gid != 0
                        or member.uname != ""
                        or member.gname != ""
                        or member.mtime != 0
                    ):
                        raise DeterministicOCILayoutError(
                            "layer entry metadata is not deterministic"
                        )
                    expected_tar_payload += 512
                    if member.isdir():
                        if saw_file:
                            raise DeterministicOCILayoutError(
                                "layer directory order is not canonical"
                            )
                        if member.mode != 0o755 or member.size != 0:
                            raise DeterministicOCILayoutError(
                                "layer directory metadata is invalid"
                            )
                        directory_names.append(name)
                        _register_expanded_path(
                            name,
                            is_file=False,
                            files=registered_files,
                            directories=registered_directories,
                            aliases=aliases,
                        )
                    elif member.isreg():
                        saw_file = True
                        if member.mode & 0o022 or member.mode & 0o400 == 0 or member.size < 0:
                            raise DeterministicOCILayoutError("layer file metadata is unsafe")
                        file_bytes += member.size
                        if file_bytes > _MAX_EXPANDED_BYTES:
                            raise DeterministicOCILayoutError(
                                "layer file bytes exceed their bound"
                            )
                        expected_tar_payload += ((member.size + 511) // 512) * 512
                        source = archive.extractfile(member)
                        if source is None:
                            raise DeterministicOCILayoutError(
                                "layer file payload is unavailable"
                            )
                        remaining = member.size
                        digest = hashlib.sha256()
                        prefix = bytearray()
                        payload_spool.seek(0, os.SEEK_END)
                        payload_offset = payload_spool.tell()
                        capture = (
                            bytearray()
                            if name in _INSTALLED_ATTESTATION_PATHS
                            else None
                        )
                        if capture is not None and member.size > _MAX_JSON_BYTES:
                            raise DeterministicOCILayoutError(
                                "installed attestation exceeds its byte bound"
                            )
                        while remaining:
                            chunk = source.read(min(remaining, _READ_CHUNK))
                            if not chunk:
                                raise DeterministicOCILayoutError(
                                    "layer file payload is truncated"
                                )
                            remaining -= len(chunk)
                            digest.update(chunk)
                            payload_spool.write(chunk)
                            if capture is not None:
                                capture.extend(chunk)
                            if len(prefix) < _ELF_IDENTITY_BYTES:
                                prefix.extend(
                                    chunk[: _ELF_IDENTITY_BYTES - len(prefix)]
                                )
                        if source.read(1):
                            raise DeterministicOCILayoutError(
                                "layer file payload exceeds its header"
                            )
                        file_names.append(name)
                        _register_expanded_path(
                            name,
                            is_file=True,
                            files=registered_files,
                            directories=registered_directories,
                            aliases=aliases,
                        )
                        file_records.append(
                            {
                                "kind": "file",
                                "linkname": "",
                                "mode": f"0{member.mode:03o}",
                                "path": name,
                                "sha256": digest.hexdigest(),
                                "size": member.size,
                            }
                        )
                        file_magic[name] = bytes(prefix)
                        file_sources[name] = _SpoolSlice(
                            payload_spool, payload_offset, member.size
                        )
                        if capture is not None:
                            attestation_payloads[name] = bytes(capture)
                    elif member.issym() or member.islnk():
                        saw_file = True
                        kind = "symlink" if member.issym() else "hardlink"
                        expected_mode = 0o777 if kind == "symlink" else member.mode
                        if (
                            member.size != 0
                            or not member.linkname
                            or (kind == "symlink" and member.mode != 0o777)
                            or (kind == "hardlink" and (member.mode & 0o022 or member.mode & 0o400 == 0))
                        ):
                            raise DeterministicOCILayoutError("layer link metadata is unsafe")
                        # Reuse the source-archive resolver in rootfs mode.  It
                        # proves the link cannot resolve above the image root.
                        linkname = _mapped_link_target(
                            member,
                            mapped_name=name,
                            install_kind="rootfs_archive",
                            identifier="verified-layer",
                        )
                        if linkname != member.linkname:
                            raise DeterministicOCILayoutError("layer link target is not canonical")
                        _register_expanded_path(
                            name,
                            is_file=True,
                            files=registered_files,
                            directories=registered_directories,
                            aliases=aliases,
                        )
                        file_names.append(name)
                        link_digest = hashlib.sha256(
                            (kind + "\0" + linkname).encode("utf-8", "strict")
                        ).hexdigest()
                        file_records.append(
                            {
                                "kind": kind,
                                "linkname": linkname,
                                "mode": f"0{expected_mode:03o}",
                                "path": name,
                                "sha256": link_digest,
                                "size": 0,
                            }
                        )
                    else:
                        raise DeterministicOCILayoutError(
                            "layer contains a special or linked entry"
                        )
        except (tarfile.TarError, OSError) as exc:
            raise DeterministicOCILayoutError("layer tar stream is malformed") from exc
        decoder.drain()
        # _SpoolSlice uses descriptor-relative pread.  Flush the buffered
        # writer before structural ELF and shebang validation consume it.
        payload_spool.flush()
        if not names:
            raise DeterministicOCILayoutError("layer is empty")
        if directory_names != sorted(directory_names, key=lambda item: (item.casefold(), item)):
            raise DeterministicOCILayoutError("layer directory order is not canonical")
        if file_names != sorted(file_names, key=lambda item: (item.casefold(), item)):
            raise DeterministicOCILayoutError("layer file order is not canonical")
        required_directories: set[str] = set()
        for file_name in file_names:
            parts = PurePosixPath(file_name).parts
            for end in range(1, len(parts)):
                required_directories.add(PurePosixPath(*parts[:end]).as_posix())
        if directory_names != sorted(
            required_directories, key=lambda item: (item.casefold(), item)
        ):
            raise DeterministicOCILayoutError(
                "layer directory roster is not the exact file ancestry"
            )
        expected_tar_size = (
            (expected_tar_payload + 1024 + tarfile.RECORDSIZE - 1)
            // tarfile.RECORDSIZE
            * tarfile.RECORDSIZE
        )
        if decoder.uncompressed_size != expected_tar_size:
            raise DeterministicOCILayoutError("layer tar padding or trailing data is non-canonical")
        if not hmac.compare_digest(decoder.diff_id, expected_diff_id):
            raise DeterministicOCILayoutError(
                "layer DiffID does not match uncompressed tar"
            )
        link_entries = [
            _ExpandedEntry(
                row["path"],
                row["sha256"],
                row["size"],
                int(row["mode"], 8),
                file_sources.get(row["path"]),
                row["kind"],
                row["linkname"],
            )
            for row in file_records
        ]
        _validate_expanded_links(link_entries)
        raw_tar_spool.flush()
        with tempfile.TemporaryFile(mode="w+b") as canonical_tar:
            _write_canonical_rootfs_tar(canonical_tar, link_entries)
            canonical_tar.flush()
            _compare_open_files_exact(
                raw_tar_spool.fileno(),
                canonical_tar.fileno(),
                label="layer tar",
            )
        by_entry = {entry.path: entry for entry in link_entries}

        required = {
            RUNTIME_ENTRYPOINT.removeprefix("/"),
            "usr/bin/python3",
            "usr/local/lib/plamen/bin/claude",
            "usr/local/lib/plamen/bin/codex",
            "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
        }
        mode_by_path = {row["path"]: int(row["mode"], 8) for row in file_records}
        for path in required:
            resolved_entry = _resolve_rootfs_entry(
                path, by_entry, label="layer runtime executable"
            )
            magic = file_magic[resolved_entry.path]
            if mode_by_path[path] & 0o111 == 0 or resolved_entry.mode & 0o111 == 0 or (
                not _is_supported_linux_executable(magic)
            ):
                raise DeterministicOCILayoutError("layer runtime executable is invalid")
        for path in RUNTIME_DYNAMIC_LIBRARIES:
            resolved_entry = _resolve_rootfs_entry(
                path, by_entry, label="layer dynamic library"
            )
            if not _is_arm64_elf(file_magic[resolved_entry.path]):
                raise DeterministicOCILayoutError(
                    "layer dynamic library platform is invalid"
                )
        if set(attestation_payloads) != _INSTALLED_ATTESTATION_PATHS:
            raise DeterministicOCILayoutError(
                "layer omits an installed attestation document"
            )
        _dependency_document, dependency_census_sha256 = (
            _validate_runtime_dependencies(link_entries)
        )
        return (
            tuple(file_records),
            file_magic,
            attestation_payloads,
            dependency_census_sha256,
        )
    finally:
        os.close(layer_fd)
        raw_tar_spool.close()
        payload_spool.close()


@_public_boundary("production OCI layout verification")
def verify_oci_layout(
    output: str | Path,
    *,
    expected_manifest_digest: str,
    expected_index_digest: str | None = None,
    expected_config_digest: str | None = None,
    expected_apple_container_configuration_sha256: str | None = None,
    expected_layer_digest: str | None = None,
    expected_layer_diff_id: str | None = None,
    expected_runtime_files_sha256: str | None = None,
    expected_sbom_sha256: str | None = None,
    expected_runtime_census_sha256: str | None = None,
    expected_runtime_dependency_census_sha256: str | None = None,
    expected_empty_root_reference: str | None = None,
    expected_complete_rootfs_source_sha256: str | None = None,
    expected_complete_rootfs_provenance_sha256: str | None = None,
) -> OCIImageLayoutResult:
    """Refuse a pathname-only production verification result.

    Serial pathname checks cannot atomically transfer the verified inode to a
    native consumer.  Production must consume a retained descriptor/native
    handle lease; no Python object or registry token substitutes for it.
    """

    raise DeterministicOCILayoutError(_PRODUCTION_CONSUMER_REQUIRED)


@_public_boundary("test-only OCI layout verification")
def _verify_oci_layout_for_testing(
    output: str | Path,
    *,
    expected_manifest_digest: str,
    expected_index_digest: str | None = None,
    expected_config_digest: str | None = None,
    expected_apple_container_configuration_sha256: str | None = None,
    expected_layer_digest: str | None = None,
    expected_layer_diff_id: str | None = None,
    expected_runtime_files_sha256: str | None = None,
    expected_sbom_sha256: str | None = None,
    expected_runtime_census_sha256: str | None = None,
    expected_runtime_dependency_census_sha256: str | None = None,
    expected_empty_root_reference: str | None = None,
    expected_complete_rootfs_source_sha256: str | None = None,
    expected_complete_rootfs_provenance_sha256: str | None = None,
    expected_complete_rootfs_derivation_manifest_sha256: str | None = None,
    expected_complete_rootfs_derived_sha256: str | None = None,
    expected_complete_rootfs_derived_diff_id: str | None = None,
    expected_complete_rootfs_derived_census_sha256: str | None = None,
) -> OCIImageLayoutResult:
    """Verify canonical structure and all descriptor edges of one layout."""

    expected = _validate_digest(expected_manifest_digest, "expected manifest digest")
    expected_index = (
        _validate_digest(expected_index_digest, "expected index digest")
        if expected_index_digest is not None
        else None
    )
    parent, output_name, ownership = _open_canonical_parent(output)
    opened, relationships = ownership
    parent_identity = _stable_identity(os.fstat(parent))
    root = blobs = algorithm = -1
    try:
        root = os.open(
            output_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
        root_row = os.fstat(root)
        root_identity = _stable_file_identity(root_row)
        named_root = os.stat(output_name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(root_row.st_mode)
            or _stable_file_identity(named_root) != root_identity
            or stat.S_IMODE(root_row.st_mode) != 0o555
            or _list_xattrs(root)
        ):
            raise DeterministicOCILayoutError("layout root identity is invalid")
        if sorted(os.listdir(root)) != ["blobs", "index.json", "oci-layout"]:
            raise DeterministicOCILayoutError("layout root roster is not exact")
        blobs = os.open("blobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        algorithm = os.open("sha256", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=blobs)
        if (
            stat.S_IMODE(os.fstat(blobs).st_mode) != 0o555
            or stat.S_IMODE(os.fstat(algorithm).st_mode) != 0o555
            or _list_xattrs(blobs)
            or _list_xattrs(algorithm)
        ):
            raise DeterministicOCILayoutError("layout blob directory has extended metadata")
        layout_raw = _read_bounded_file(root, "oci-layout", _MAX_JSON_BYTES, "oci-layout")
        if _parse_canonical_json(layout_raw, "oci-layout") != {"imageLayoutVersion": OCI_LAYOUT_VERSION}:
            raise DeterministicOCILayoutError("oci-layout version is unsupported")
        index_raw = _read_bounded_file(root, "index.json", _MAX_JSON_BYTES, "index")
        index_digest = _sha256(index_raw)
        if expected_index is not None and not hmac.compare_digest(
            index_digest, expected_index
        ):
            raise DeterministicOCILayoutError(
                "index digest differs from the expected lock"
            )
        index = _exact_object(
            _parse_canonical_json(index_raw, "index"),
            frozenset({"manifests", "mediaType", "schemaVersion"}),
            "index",
        )
        if index["mediaType"] != OCI_INDEX_MEDIA_TYPE or index["schemaVersion"] != 2:
            raise DeterministicOCILayoutError("index header is unsupported")
        manifests = index["manifests"]
        if not isinstance(manifests, list) or len(manifests) != 1:
            raise DeterministicOCILayoutError("index manifest roster is not exact")
        manifest_descriptor = _exact_object(manifests[0], _PLATFORM_DESCRIPTOR_KEYS, "manifest descriptor")
        platform = _exact_object(
            manifest_descriptor["platform"], frozenset({"architecture", "os"}), "platform"
        )
        if platform != {"architecture": "arm64", "os": "linux"}:
            raise DeterministicOCILayoutError("manifest platform is unsupported")
        base_descriptor = {key: manifest_descriptor[key] for key in _DESCRIPTOR_KEYS}
        _validate_descriptor(base_descriptor, OCI_MANIFEST_MEDIA_TYPE, "manifest descriptor")
        if not hmac.compare_digest(manifest_descriptor["digest"], expected):
            raise DeterministicOCILayoutError("index does not reference the expected manifest")
        if hmac.compare_digest(index_digest, manifest_descriptor["digest"]):
            raise DeterministicOCILayoutError(
                "index and selected manifest digests must be distinct"
            )
        manifest_raw = _verify_layout_descriptor(algorithm, base_descriptor, "manifest")
        manifest = _exact_object(
            _parse_canonical_json(manifest_raw, "manifest"),
            frozenset({"config", "layers", "mediaType", "schemaVersion"}),
            "manifest",
        )
        if manifest["mediaType"] != OCI_MANIFEST_MEDIA_TYPE or manifest["schemaVersion"] != 2:
            raise DeterministicOCILayoutError("manifest header is unsupported")
        config_descriptor = _validate_descriptor(manifest["config"], OCI_CONFIG_MEDIA_TYPE, "config descriptor")
        if expected_config_digest is not None and not hmac.compare_digest(
            config_descriptor["digest"],
            _validate_digest(expected_config_digest, "expected config digest"),
        ):
            raise DeterministicOCILayoutError("config digest differs from the expected lock")
        layers = manifest["layers"]
        if not isinstance(layers, list) or len(layers) != 1:
            raise DeterministicOCILayoutError("layer roster is not exact")
        layer_descriptor = _validate_descriptor(layers[0], OCI_LAYER_MEDIA_TYPE, "layer descriptor")
        if expected_layer_digest is not None and not hmac.compare_digest(
            layer_descriptor["digest"],
            _validate_digest(expected_layer_digest, "expected layer digest"),
        ):
            raise DeterministicOCILayoutError("layer digest differs from the expected lock")
        config_raw = _verify_layout_descriptor(algorithm, config_descriptor, "config")
        config = _exact_object(
            _parse_canonical_json(config_raw, "config"),
            _CONFIG_KEYS,
            "config",
        )
        apple_container_configuration_sha256 = hashlib.sha256(
            _canonical_bytes(config)[:-1]
        ).hexdigest()
        if expected_apple_container_configuration_sha256 is not None:
            expected_apple_configuration = (
                expected_apple_container_configuration_sha256
            )
            if (
                not isinstance(expected_apple_configuration, str)
                or len(expected_apple_configuration) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in expected_apple_configuration
                )
            ):
                raise DeterministicOCILayoutError(
                    "expected Apple Container configuration digest is malformed"
                )
            if not hmac.compare_digest(
                apple_container_configuration_sha256,
                expected_apple_configuration,
            ):
                raise DeterministicOCILayoutError(
                    "Apple Container configuration differs from the expected lock"
                )
        rootfs = _exact_object(config["rootfs"], frozenset({"diff_ids", "type"}), "config rootfs")
        if (
            config["architecture"] != "arm64"
            or config["os"] != "linux"
            or rootfs["type"] != "layers"
            or config["created"] != _CREATED
        ):
            raise DeterministicOCILayoutError("config platform is unsupported")
        execution = _exact_object(config["config"], _EXECUTION_CONFIG_KEYS, "execution config")
        labels = _exact_object(execution["Labels"], _LABEL_KEYS, "execution labels")
        if (
            execution["Entrypoint"] != [RUNTIME_ENTRYPOINT]
            or execution["Env"] != list(RUNTIME_ENV)
            or execution["User"] != RUNTIME_USER
            or execution["WorkingDir"] != RUNTIME_WORKDIR
        ):
            raise DeterministicOCILayoutError("execution config is not the locked non-root runtime")
        history = config["history"]
        if history != [
            {
                "comment": _LAYER_COMMENT,
                "created": _CREATED,
                "created_by": _LAYER_CREATED_BY,
                "empty_layer": False,
            }
        ]:
            raise DeterministicOCILayoutError("config history is not canonical")
        for key in (
            "org.plamen.build-input-census.sha256",
            "org.plamen.complete-rootfs.provenance.sha256",
            "org.plamen.complete-rootfs.derivation-manifest.sha256",
            "org.plamen.complete-rootfs.derived-census.sha256",
            "org.plamen.complete-rootfs.derived.sha256",
            "org.plamen.complete-rootfs.source.sha256",
            "org.plamen.runtime-census.sha256",
            "org.plamen.runtime-dependencies.sha256",
            "org.plamen.runtime-files.sha256",
            "org.plamen.runtime-materialization.archive.sha256",
            "org.plamen.runtime-materialization.composition-manifest.sha256",
            "org.plamen.runtime-materialization.installed-census.sha256",
            "org.plamen.runtime-materialization.provenance.sha256",
            "org.plamen.runtime-materialization.receipt.sha256",
            "org.plamen.runtime-materialization.sbom.sha256",
            "org.plamen.runtime-materialization.source-roster.sha256",
            "org.plamen.sbom.sha256",
        ):
            value = labels[key]
            if not isinstance(value, str) or len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise DeterministicOCILayoutError("execution label digest is malformed")
        _validate_digest(
            labels["org.plamen.complete-rootfs.derived-diff-id"],
            "derived rootfs DiffID label",
        )
        _validate_digest(
            labels["org.plamen.runtime-materialization.archive.diff-id"],
            "runtime materialization archive DiffID label",
        )
        for key, maximum in (
            ("org.plamen.runtime-materialization.archive.size", _MAX_INPUT_BYTES),
            ("org.plamen.runtime-materialization.entry-count", _MAX_LAYER_ENTRIES),
            ("org.plamen.runtime-materialization.expanded-bytes", _MAX_EXPANDED_BYTES),
        ):
            rendered = labels[key]
            if (
                not isinstance(rendered, str)
                or not rendered.isascii()
                or not rendered.isdecimal()
                or (len(rendered) > 1 and rendered.startswith("0"))
            ):
                raise DeterministicOCILayoutError(
                    "runtime materialization numeric label is malformed"
                )
            number = int(rendered)
            if number < 1 or number > maximum:
                raise DeterministicOCILayoutError(
                    "runtime materialization numeric label exceeds its bound"
                )
        empty_root = labels["org.plamen.empty-root.lock-reference"]
        if not isinstance(empty_root, str) or "@" not in empty_root:
            raise DeterministicOCILayoutError("empty-root label is malformed")
        empty_name, empty_digest = empty_root.rsplit("@", 1)
        if not empty_name.endswith("/empty-root") or not hmac.compare_digest(
            empty_digest, EMPTY_ROOT_DIGEST
        ):
            raise DeterministicOCILayoutError("empty-root label is not the scratch sentinel")
        diff_ids = rootfs["diff_ids"]
        if not isinstance(diff_ids, list) or len(diff_ids) != 1:
            raise DeterministicOCILayoutError("config DiffID roster is not exact")
        diff_id = _validate_digest(diff_ids[0], "layer DiffID")
        if expected_layer_diff_id is not None and not hmac.compare_digest(
            diff_id,
            _validate_digest(expected_layer_diff_id, "expected layer DiffID"),
        ):
            raise DeterministicOCILayoutError("layer DiffID differs from the expected lock")
        (
            file_records,
            _executable_magic,
            attestation_payloads,
            runtime_dependency_census_sha256,
        ) = _verify_layer_tar(algorithm, layer_descriptor, diff_id)
        if not hmac.compare_digest(
            runtime_dependency_census_sha256,
            labels["org.plamen.runtime-dependencies.sha256"],
        ):
            raise DeterministicOCILayoutError(
                "runtime dependency census does not match its label"
            )
        runtime_files_sha256 = hashlib.sha256(
            _canonical_bytes(list(file_records))
        ).hexdigest()
        if not hmac.compare_digest(
            runtime_files_sha256, labels["org.plamen.runtime-files.sha256"]
        ):
            raise DeterministicOCILayoutError("runtime file census does not match its label")
        files_by_path = {row["path"]: row for row in file_records}
        for path, label_key in (
            ("usr/local/lib/plamen/attestations/sbom.json", "org.plamen.sbom.sha256"),
            ("usr/local/lib/plamen/attestations/census.json", "org.plamen.runtime-census.sha256"),
            (
                "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json",
                "org.plamen.complete-rootfs.derivation-manifest.sha256",
            ),
            (
                "usr/local/lib/plamen/attestations/complete-rootfs-provenance.json",
                "org.plamen.complete-rootfs.provenance.sha256",
            ),
        ):
            row = files_by_path.get(path)
            if row is None or not hmac.compare_digest(row["sha256"], labels[label_key]):
                raise DeterministicOCILayoutError("installed attestation digest is invalid")
        _validate_installed_attestations(attestation_payloads, labels)
        explicit_expectations = (
            (expected_runtime_files_sha256, labels["org.plamen.runtime-files.sha256"], "runtime-files"),
            (expected_sbom_sha256, labels["org.plamen.sbom.sha256"], "SBOM"),
            (expected_runtime_census_sha256, labels["org.plamen.runtime-census.sha256"], "runtime-census"),
            (
                expected_runtime_dependency_census_sha256,
                labels["org.plamen.runtime-dependencies.sha256"],
                "runtime-dependency-census",
            ),
            (expected_empty_root_reference, empty_root, "empty-root"),
            (
                expected_complete_rootfs_source_sha256,
                labels["org.plamen.complete-rootfs.source.sha256"],
                "complete-rootfs source",
            ),
            (
                expected_complete_rootfs_provenance_sha256,
                labels["org.plamen.complete-rootfs.provenance.sha256"],
                "complete-rootfs provenance",
            ),
            (
                expected_complete_rootfs_derivation_manifest_sha256,
                labels["org.plamen.complete-rootfs.derivation-manifest.sha256"],
                "complete-rootfs derivation manifest",
            ),
            (
                expected_complete_rootfs_derived_sha256,
                labels["org.plamen.complete-rootfs.derived.sha256"],
                "complete-rootfs derived archive",
            ),
            (
                expected_complete_rootfs_derived_diff_id,
                labels["org.plamen.complete-rootfs.derived-diff-id"],
                "complete-rootfs derived DiffID",
            ),
            (
                expected_complete_rootfs_derived_census_sha256,
                labels["org.plamen.complete-rootfs.derived-census.sha256"],
                "complete-rootfs derived census",
            ),
        )
        for expected_value, observed_value, label in explicit_expectations:
            if expected_value is not None and not hmac.compare_digest(
                expected_value, observed_value
            ):
                raise DeterministicOCILayoutError(f"{label} differs from the expected lock")
        expected_blobs = sorted(
            {
                expected[len(_SHA256_PREFIX) :],
                config_descriptor["digest"][len(_SHA256_PREFIX) :],
                layer_descriptor["digest"][len(_SHA256_PREFIX) :],
            }
        )
        if sorted(os.listdir(algorithm)) != expected_blobs or sorted(os.listdir(blobs)) != ["sha256"]:
            raise DeterministicOCILayoutError("layout blob roster is not exact")
        result = OCIImageLayoutResult(
            index_digest=index_digest,
            manifest_digest=expected,
            config_digest=config_descriptor["digest"],
            apple_container_configuration_sha256=(
                apple_container_configuration_sha256
            ),
            layer_digest=layer_descriptor["digest"],
            layer_diff_id=diff_id,
            receipt=b"",
            runtime_files_sha256=runtime_files_sha256,
            sbom_sha256=labels["org.plamen.sbom.sha256"],
            runtime_census_sha256=labels["org.plamen.runtime-census.sha256"],
            runtime_dependency_census_sha256=runtime_dependency_census_sha256,
            empty_root_reference=empty_root,
            complete_rootfs_source_sha256=labels[
                "org.plamen.complete-rootfs.source.sha256"
            ],
            complete_rootfs_provenance_sha256=labels[
                "org.plamen.complete-rootfs.provenance.sha256"
            ],
            complete_rootfs_derivation_manifest_sha256=labels[
                "org.plamen.complete-rootfs.derivation-manifest.sha256"
            ],
            complete_rootfs_derived_sha256=labels[
                "org.plamen.complete-rootfs.derived.sha256"
            ],
            complete_rootfs_derived_diff_id=labels[
                "org.plamen.complete-rootfs.derived-diff-id"
            ],
            complete_rootfs_derived_census_sha256=labels[
                "org.plamen.complete-rootfs.derived-census.sha256"
            ],
            runtime_materialization_source_roster_sha256=labels[
                "org.plamen.runtime-materialization.source-roster.sha256"
            ],
            runtime_materialization_composition_manifest_sha256=labels[
                "org.plamen.runtime-materialization.composition-manifest.sha256"
            ],
            runtime_materialization_archive_sha256=labels[
                "org.plamen.runtime-materialization.archive.sha256"
            ],
            runtime_materialization_archive_diff_id=labels[
                "org.plamen.runtime-materialization.archive.diff-id"
            ],
            runtime_materialization_archive_size=int(
                labels["org.plamen.runtime-materialization.archive.size"]
            ),
            installed_runtime_census_sha256=labels[
                "org.plamen.runtime-materialization.installed-census.sha256"
            ],
            runtime_materialization_receipt_sha256=labels[
                "org.plamen.runtime-materialization.receipt.sha256"
            ],
            runtime_materialization_sbom_sha256=labels[
                "org.plamen.runtime-materialization.sbom.sha256"
            ],
            runtime_materialization_provenance_sha256=labels[
                "org.plamen.runtime-materialization.provenance.sha256"
            ],
            installed_runtime_entry_count=int(
                labels["org.plamen.runtime-materialization.entry-count"]
            ),
            installed_runtime_expanded_bytes=int(
                labels["org.plamen.runtime-materialization.expanded-bytes"]
            ),
        )
        _revalidate_parent(parent, parent_identity, relationships)
        named_root_after = os.stat(
            output_name, dir_fd=parent, follow_symlinks=False
        )
        if (
            _stable_file_identity(os.fstat(root)) != root_identity
            or _stable_file_identity(named_root_after) != root_identity
        ):
            raise DeterministicOCILayoutError(
                "verified OCI layout path was substituted"
            )
        return result
    finally:
        for descriptor in (algorithm, blobs, root, parent):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _hash_open_file(descriptor: int, expected_size: int, label: str) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, _READ_CHUNK))
        if not chunk:
            raise DeterministicOCILayoutError(f"{label} was truncated")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise DeterministicOCILayoutError(f"{label} grew while hashing")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _layout_archive_file_paths(layout: Path) -> tuple[str, ...]:
    blob_root = layout / "blobs" / "sha256"
    names = sorted(path.name for path in blob_root.iterdir())
    if not names or any(
        len(name) != 64 or any(character not in "0123456789abcdef" for character in name)
        for name in names
    ):
        raise DeterministicOCILayoutError("layout blob roster cannot be archived")
    return tuple(
        sorted(
            ("index.json", "oci-layout", *(f"blobs/sha256/{name}" for name in names)),
            key=lambda item: (item.casefold(), item),
        )
    )


def _write_canonical_oci_archive_from_directory(
    destination: BinaryIO,
    layout: Path,
    files: Sequence[str],
) -> None:
    """Re-encode the sole accepted raw USTAR representation of an OCI layout.

    Callers use this only with either the retained, independently validated
    layout or a private verification extraction.  Byte comparison against
    this output rejects alternate GNU/PAX header dialects, checksum-preserving
    field encodings, extra EOF records, and concatenated archives.
    """

    with tarfile.open(
        fileobj=destination,
        mode="w|",
        format=tarfile.USTAR_FORMAT,
        dereference=False,
    ) as archive:
        for directory in ("blobs", "blobs/sha256"):
            archive.addfile(
                _tar_info(directory, mode=0o755, size=0, directory=True)
            )
        for relative in files:
            source_path = layout.joinpath(*PurePosixPath(relative).parts)
            row = source_path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(row.st_mode)
                or stat.S_IMODE(row.st_mode) != 0o444
                or row.st_nlink != 1
                or row.st_size < 0
                or row.st_size > _MAX_EXPANDED_BYTES
            ):
                raise DeterministicOCILayoutError(
                    "canonical OCI archive source is unsafe"
                )
            with source_path.open("rb", buffering=0) as source:
                archive.addfile(
                    _tar_info(
                        relative,
                        mode=0o444,
                        size=int(row.st_size),
                        directory=False,
                    ),
                    source,
                )


def _revalidate_published_archive(
    parent: int,
    output_name: str,
    retained_descriptor: int,
    retained_identity: tuple[int, int, int],
    expected_size: int,
    expected_sha256: str,
) -> None:
    named_descriptor = os.open(
        output_name,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        retained = os.fstat(retained_descriptor)
        named = os.fstat(named_descriptor)
        if (
            _stable_identity(retained) != retained_identity
            or _stable_identity(named) != retained_identity
            or not stat.S_ISREG(named.st_mode)
            or stat.S_IMODE(named.st_mode) != 0o444
            or named.st_uid != os.geteuid()
            or named.st_nlink != 1
            or named.st_size != expected_size
            or _list_xattrs(named_descriptor)
        ):
            raise DeterministicOCILayoutError(
                "published OCI archive identity changed"
            )
        if not hmac.compare_digest(
            _hash_open_file(
                retained_descriptor, expected_size, "retained OCI archive"
            ),
            expected_sha256,
        ) or not hmac.compare_digest(
            _hash_open_file(named_descriptor, expected_size, "published OCI archive"),
            expected_sha256,
        ):
            raise DeterministicOCILayoutError(
                "published OCI archive bytes changed"
            )
        _compare_open_files_exact(
            retained_descriptor,
            named_descriptor,
            label="published OCI archive",
        )
        named_after = os.stat(
            output_name, dir_fd=parent, follow_symlinks=False
        )
        if (
            _stable_identity(named_after) != retained_identity
            or _stable_identity(os.fstat(retained_descriptor))
            != retained_identity
        ):
            raise DeterministicOCILayoutError(
                "published OCI archive was substituted"
            )
    finally:
        os.close(named_descriptor)


@_public_boundary("production OCI archive export")
def export_oci_layout_archive(
    layout: str | Path,
    archive_output: str | Path,
    *,
    expected_manifest_digest: str,
    expected_index_digest: str | None = None,
    expected_config_digest: str | None = None,
    expected_apple_container_configuration_sha256: str | None = None,
) -> OCIImageArchiveResult:
    """Refuse pathname publication without an atomic native-handle consumer."""

    raise DeterministicOCILayoutError(_PRODUCTION_CONSUMER_REQUIRED)


@_public_boundary("test-only OCI archive export")
def _export_oci_layout_archive_for_testing(
    layout: str | Path,
    archive_output: str | Path,
    *,
    expected_manifest_digest: str,
    expected_index_digest: str | None = None,
    expected_config_digest: str | None = None,
    expected_apple_container_configuration_sha256: str | None = None,
) -> OCIImageArchiveResult:
    """Publish one deterministic, uncompressed OCI-layout import archive."""

    verified = _verify_oci_layout_for_testing(
        layout,
        expected_manifest_digest=expected_manifest_digest,
        expected_index_digest=expected_index_digest,
        expected_config_digest=expected_config_digest,
        expected_apple_container_configuration_sha256=(
            expected_apple_container_configuration_sha256
        ),
    )
    layout_path = Path(layout)
    files = _layout_archive_file_paths(layout_path)
    parent, output_name, ownership = _open_canonical_parent(archive_output)
    opened, relationships = ownership
    parent_identity = _stable_identity(os.fstat(parent))
    publication_scope = hashlib.sha256(output_name.encode("utf-8")).hexdigest()[:32]
    lock_name = f".plamen-oci-archive-{publication_scope}.lock"
    stage_name = (
        f".plamen-oci-archive-stage-{publication_scope}-{secrets.token_hex(16)}"
    )
    lock_fd = stage_fd = -1
    published = False
    stage_identity: tuple[int, int, int] | None = None
    try:
        if _safe_lstat(output_name, parent) is not None:
            raise DeterministicOCILayoutError("archive output already exists")
        lock_fd = _acquire_publication_lock(
            parent,
            lock_name,
            stage_name,
            kind="archive",
            directory_stage=False,
        )
        stage_fd = os.open(
            stage_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent,
        )
        stage_identity = _stable_identity(os.fstat(stage_fd))
        os.fsync(parent)
        with os.fdopen(os.dup(stage_fd), "wb", buffering=0) as destination:
            with tarfile.open(
                fileobj=destination,
                mode="w|",
                format=tarfile.USTAR_FORMAT,
                dereference=False,
            ) as archive:
                for directory in ("blobs", "blobs/sha256"):
                    archive.addfile(
                        _tar_info(directory, mode=0o755, size=0, directory=True)
                    )
                for relative in files:
                    source_path = layout_path.joinpath(*PurePosixPath(relative).parts)
                    source_fd = os.open(
                        source_path,
                        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    )
                    try:
                        before = os.fstat(source_fd)
                        identity = _stable_file_identity(before)
                        if (
                            not stat.S_ISREG(before.st_mode)
                            or before.st_nlink != 1
                            or stat.S_IMODE(before.st_mode) != 0o444
                            or before.st_size < 0
                            or before.st_size > _MAX_EXPANDED_BYTES
                            or _list_xattrs(source_fd)
                        ):
                            raise DeterministicOCILayoutError("layout archive input is unsafe")
                        with os.fdopen(os.dup(source_fd), "rb", buffering=0) as source:
                            archive.addfile(
                                _tar_info(
                                    relative,
                                    mode=0o444,
                                    size=int(before.st_size),
                                    directory=False,
                                ),
                                source,
                            )
                        if _stable_file_identity(os.fstat(source_fd)) != identity:
                            raise DeterministicOCILayoutError("layout changed during archive export")
                    finally:
                        os.close(source_fd)
        os.fsync(stage_fd)
        stage_row = os.fstat(stage_fd)
        if stage_row.st_size <= 0 or stage_row.st_size > _MAX_EXPANDED_BYTES + _MAX_JSON_BYTES * 4:
            raise DeterministicOCILayoutError("OCI archive size is outside its bound")
        archive_sha256 = _hash_open_file(stage_fd, int(stage_row.st_size), "OCI archive")
        os.fchmod(stage_fd, 0o444)
        stage_identity = _stable_identity(os.fstat(stage_fd))
        if _list_xattrs(stage_fd):
            raise DeterministicOCILayoutError("OCI archive has extended metadata")
        os.fsync(stage_fd)
        staged_result = _verify_oci_layout_archive_for_testing(
            Path(archive_output).with_name(stage_name),
            expected_index_digest=verified.index_digest,
            expected_manifest_digest=verified.manifest_digest,
            expected_config_digest=verified.config_digest,
            expected_apple_container_configuration_sha256=(
                verified.apple_container_configuration_sha256
            ),
            expected_archive_sha256=archive_sha256,
        )
        _revalidate_parent(parent, parent_identity, relationships)
        if _safe_lstat(output_name, parent) is not None:
            raise DeterministicOCILayoutError("archive output appeared during publication")
        named_stage = os.stat(stage_name, dir_fd=parent, follow_symlinks=False)
        if (
            stage_identity is None
            or _stable_identity(named_stage) != stage_identity
            or _stable_identity(os.fstat(stage_fd)) != stage_identity
        ):
            raise DeterministicOCILayoutError(
                "staged OCI archive identity changed"
            )
        _rename_noreplace(parent, stage_name, parent, output_name)
        published = True
        os.fsync(parent)
        os.unlink(lock_name, dir_fd=parent)
        os.fsync(parent)
        _revalidate_published_archive(
            parent,
            output_name,
            stage_fd,
            stage_identity,
            int(stage_row.st_size),
            archive_sha256,
        )
        # The retained parent can itself have been renamed out of the caller's
        # path after publication.  Replay every named ancestry edge and the
        # leaf as the final success predicate, after the byte revalidation.
        _revalidate_parent(parent, parent_identity, relationships)
        published_named = os.stat(
            output_name, dir_fd=parent, follow_symlinks=False
        )
        if (
            stage_identity is None
            or _stable_identity(published_named) != stage_identity
            or _stable_identity(os.fstat(stage_fd)) != stage_identity
        ):
            raise DeterministicOCILayoutError(
                "published OCI archive path was substituted"
            )
        return OCIImageArchiveResult(
            archive_sha256=staged_result.archive_sha256,
            archive_size=staged_result.archive_size,
            index_digest=staged_result.index_digest,
            manifest_digest=staged_result.manifest_digest,
            config_digest=staged_result.config_digest,
            apple_container_configuration_sha256=(
                staged_result.apple_container_configuration_sha256
            ),
        )
    except BaseException:
        stage_removed = False
        if not published:
            stage_removed = _safe_lstat(stage_name, parent) is None
            try:
                if not stage_removed:
                    _remove_recovery_stage(
                        parent,
                        stage_name,
                        directory=False,
                        expected_identity=stage_identity,
                    )
                    os.fsync(parent)
                    stage_removed = True
            except (OSError, DeterministicOCILayoutError):
                pass
        if lock_fd >= 0 and stage_removed:
            try:
                os.unlink(lock_name, dir_fd=parent)
                os.fsync(parent)
            except OSError:
                pass
        raise
    finally:
        for descriptor in (stage_fd, lock_fd, parent):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass


@_public_boundary("production OCI archive verification")
def verify_oci_layout_archive(
    archive_path: str | Path,
    *,
    expected_manifest_digest: str,
    expected_index_digest: str | None = None,
    expected_config_digest: str | None = None,
    expected_apple_container_configuration_sha256: str | None = None,
    expected_archive_sha256: str,
) -> OCIImageArchiveResult:
    """Refuse a pathname-only production archive verification result."""

    raise DeterministicOCILayoutError(_PRODUCTION_CONSUMER_REQUIRED)


@_public_boundary("test-only OCI archive verification")
def _verify_oci_layout_archive_for_testing(
    archive_path: str | Path,
    *,
    expected_manifest_digest: str,
    expected_index_digest: str | None = None,
    expected_config_digest: str | None = None,
    expected_apple_container_configuration_sha256: str | None = None,
    expected_archive_sha256: str,
) -> OCIImageArchiveResult:
    """Verify the exact import bytes, extract safely, then verify OCI edges."""

    if (
        not isinstance(expected_archive_sha256, str)
        or len(expected_archive_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_archive_sha256)
    ):
        raise DeterministicOCILayoutError("expected OCI archive digest is malformed")
    parent, name, ownership = _open_canonical_parent(archive_path)
    opened, relationships = ownership
    parent_identity = _stable_identity(os.fstat(parent))
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
        row = os.fstat(descriptor)
        identity = _stable_file_identity(row)
        named_row = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(row.st_mode)
            or _stable_file_identity(named_row) != identity
            or row.st_nlink != 1
            or stat.S_IMODE(row.st_mode) != 0o444
            or row.st_size <= 0
            or row.st_size > _MAX_EXPANDED_BYTES + _MAX_JSON_BYTES * 4
            or _list_xattrs(descriptor)
        ):
            raise DeterministicOCILayoutError("OCI archive identity is invalid")
        observed_digest = _hash_open_file(descriptor, int(row.st_size), "OCI archive")
        if not hmac.compare_digest(observed_digest, expected_archive_sha256):
            raise DeterministicOCILayoutError("OCI archive digest mismatch")
        with tempfile.TemporaryDirectory(prefix="plamen-oci-archive-verify-") as temporary:
            temporary_root = Path(temporary)
            layout = temporary_root / "layout"
            layout.mkdir(mode=0o700)
            (layout / "blobs").mkdir(mode=0o700)
            (layout / "blobs" / "sha256").mkdir(mode=0o700)
            seen: list[str] = []
            expected_tar_payload = 0
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(os.dup(descriptor), "rb", buffering=0) as source:
                with tarfile.open(fileobj=source, mode="r|") as archive:
                    for member in archive:
                        raw_name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                        relative = _validate_relative_path(raw_name, "OCI archive member")
                        if relative in seen:
                            raise DeterministicOCILayoutError("OCI archive contains a duplicate member")
                        seen.append(relative)
                        expected_tar_payload += 512
                        if (
                            member.pax_headers
                            or member.linkname
                            or member.uid != 0
                            or member.gid != 0
                            or member.uname != ""
                            or member.gname != ""
                            or member.mtime != 0
                        ):
                            raise DeterministicOCILayoutError("OCI archive metadata is not canonical")
                        if member.isdir():
                            if relative not in {"blobs", "blobs/sha256"} or member.mode != 0o755 or member.size != 0:
                                raise DeterministicOCILayoutError("OCI archive directory roster is invalid")
                            continue
                        if not member.isreg() or member.mode != 0o444:
                            raise DeterministicOCILayoutError("OCI archive contains a special member")
                        allowed_root_file = relative in {"index.json", "oci-layout"}
                        parts = PurePosixPath(relative).parts
                        allowed_blob = (
                            len(parts) == 3
                            and parts[:2] == ("blobs", "sha256")
                            and len(parts[2]) == 64
                            and all(character in "0123456789abcdef" for character in parts[2])
                        )
                        if not allowed_root_file and not allowed_blob:
                            raise DeterministicOCILayoutError("OCI archive member roster is invalid")
                        payload = archive.extractfile(member)
                        if payload is None:
                            raise DeterministicOCILayoutError("OCI archive payload is unavailable")
                        target = layout.joinpath(*parts)
                        with target.open("xb") as destination:
                            remaining = member.size
                            digest = hashlib.sha256()
                            while remaining:
                                chunk = payload.read(min(remaining, _READ_CHUNK))
                                if not chunk:
                                    raise DeterministicOCILayoutError("OCI archive member was truncated")
                                destination.write(chunk)
                                digest.update(chunk)
                                remaining -= len(chunk)
                            if payload.read(1):
                                raise DeterministicOCILayoutError("OCI archive member exceeds its header")
                        expected_tar_payload += ((member.size + 511) // 512) * 512
                        if allowed_blob and digest.hexdigest() != parts[2]:
                            raise DeterministicOCILayoutError("OCI archive blob name does not match content")
                        target.chmod(0o444)
            expected_order = [
                "blobs",
                "blobs/sha256",
                *sorted((item for item in seen if item not in {"blobs", "blobs/sha256"}), key=lambda item: (item.casefold(), item)),
            ]
            if seen != expected_order:
                raise DeterministicOCILayoutError("OCI archive member order is not canonical")
            expected_archive_size = (
                (expected_tar_payload + 1024 + tarfile.RECORDSIZE - 1)
                // tarfile.RECORDSIZE
                * tarfile.RECORDSIZE
            )
            if row.st_size != expected_archive_size:
                raise DeterministicOCILayoutError(
                    "OCI archive terminator extent is not canonical"
                )
            os.lseek(descriptor, expected_tar_payload, os.SEEK_SET)
            trailing = expected_archive_size - expected_tar_payload
            while trailing:
                chunk = os.read(descriptor, min(trailing, _READ_CHUNK))
                if not chunk or any(chunk):
                    raise DeterministicOCILayoutError(
                        "OCI archive has a concatenated or non-zero trailer"
                    )
                trailing -= len(chunk)
            if os.read(descriptor, 1):
                raise DeterministicOCILayoutError("OCI archive has trailing bytes")
            with tempfile.TemporaryFile(mode="w+b") as canonical_archive:
                _write_canonical_oci_archive_from_directory(
                    canonical_archive,
                    layout,
                    tuple(seen[2:]),
                )
                canonical_archive.flush()
                _compare_open_files_exact(
                    descriptor,
                    canonical_archive.fileno(),
                    label="OCI archive",
                )
            for directory in (layout / "blobs" / "sha256", layout / "blobs", layout):
                directory.chmod(0o555)
            verified = _verify_oci_layout_for_testing(
                layout.resolve(),
                expected_manifest_digest=expected_manifest_digest,
                expected_index_digest=expected_index_digest,
                expected_config_digest=expected_config_digest,
                expected_apple_container_configuration_sha256=(
                    expected_apple_container_configuration_sha256
                ),
            )
        if _stable_file_identity(os.fstat(descriptor)) != identity:
            raise DeterministicOCILayoutError("OCI archive changed during verification")
        result = OCIImageArchiveResult(
            archive_sha256=observed_digest,
            archive_size=int(row.st_size),
            index_digest=verified.index_digest,
            manifest_digest=verified.manifest_digest,
            config_digest=verified.config_digest,
            apple_container_configuration_sha256=(
                verified.apple_container_configuration_sha256
            ),
        )
        _revalidate_parent(parent, parent_identity, relationships)
        named_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _stable_file_identity(os.fstat(descriptor)) != identity
            or _stable_file_identity(named_after) != identity
        ):
            raise DeterministicOCILayoutError(
                "verified OCI archive path was substituted"
            )
        return result
    finally:
        for file_descriptor in (descriptor, parent):
            if file_descriptor >= 0:
                try:
                    os.close(file_descriptor)
                except OSError:
                    pass
        for file_descriptor in reversed(opened):
            try:
                os.close(file_descriptor)
            except OSError:
                pass


__all__ = [
    "DeterministicOCILayoutError",
    "EMPTY_ROOT_DIGEST",
    "EMPTY_ROOT_REFERENCE",
    "OCIImageArchiveResult",
    "OCIImageLayoutResult",
    "build_oci_layout",
    "export_oci_layout_archive",
    "verify_oci_layout",
    "verify_oci_layout_archive",
]
