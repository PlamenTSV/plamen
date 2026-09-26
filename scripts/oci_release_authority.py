"""Fail-closed release-authority protocol for deterministic OCI publication.

Production authentication deliberately has no Python-mintable capability or
receipt type.  The eventual implementation must be a descriptor-owning native
or separately authenticated service which supplies an opaque capability to a
native consumer.  Until that boundary exists every production entry point
fails before reading inputs or starting a process.

The ``TEST_ONLY_*`` API is intentionally type-separated.  It exercises the
canonical wire format, subprocess framing, and durable replay state machine;
it is not a production trust primitive and cannot enable the production API.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import base64
import functools
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import secrets
import stat
import subprocess
import tempfile
import threading
from typing import Any, NoReturn
import unicodedata

import elf_loader_closure as elf_closure

try:  # Import-safe on Windows; operational test seams still fail closed.
    import fcntl
except ImportError:  # pragma: no cover - Windows CI
    fcntl = None  # type: ignore[assignment]


REQUEST_SCHEMA = "plamen.oci_release_authority_request.v6"
RECEIPT_SCHEMA = "plamen.oci_release_authority_receipt.v6"
COMMITMENTS_SCHEMA = "plamen.oci_output_commitments.v6"
PROTOCOL = "NATIVE_OPAQUE_RELEASE_AUTHORITY_V6"
TEST_ONLY_PROTOCOL = "TEST_ONLY_OUT_OF_PROCESS_V6"
ROOTFS_DERIVATION_BINDING_SCHEMA = "plamen.oci_rootfs_derivation_binding.v1"
RUNTIME_MATERIALIZATION_SCHEMA = "plamen.runtime_materialization_binding.v1"
INSTALLED_RUNTIME_CENSUS_SCHEMA = "plamen.installed_runtime_census.v1"
RUNTIME_MATERIALIZATION_REQUIRED_ROLES = (
    "base_rootfs", "debian_package_state", "plamen_guest", "cpython",
    "plamen_package", "codex", "claude", "foundry", "medusa", "solc_amd64",
    "amd64_compat",
)

INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"

_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_ARTIFACTS = 131_072
_MAX_DIRECTORIES = 131_072
_MAX_LAYERS = 256
_MAX_TOTAL_EXPANDED = 12 * 1024 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
_MAX_JSON_DEPTH = 20
_MAX_JSON_NODES = 4_194_304
_MAX_STRING_BYTES = 65_536

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OCI_REFERENCE = re.compile(
    r"[a-z0-9](?:[a-z0-9._:-]{0,253})/"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}\Z"
)
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_NONCE = re.compile(r"[0-9a-f]{32,128}\Z")
_MODE = re.compile(r"0[0-7]{3}\Z")


class OCIReleaseAuthorityError(RuntimeError):
    """Release authentication could not be established safely."""


class AmbiguousReleaseAttemptError(OCIReleaseAuthorityError):
    """A helper may have acted, but no durable receipt exists."""


def _public_boundary(label: str):
    def decorate(function: Any) -> Any:
        @functools.wraps(function)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except OCIReleaseAuthorityError:
                raise
            except Exception:
                error = OCIReleaseAuthorityError(f"{label} failed closed")
                error.__cause__ = None
                error.__context__ = None
                raise error from None

        return guarded

    return decorate


def _require_posix() -> None:
    if os.name != "posix" or fcntl is None:
        raise OCIReleaseAuthorityError("TEST-ONLY descriptor protocol requires POSIX")


def _bounded_json_tree(value: Any, *, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise OCIReleaseAuthorityError("protocol JSON exceeds its depth bound")
    if value is None or type(value) in {bool, int}:
        return 1
    if isinstance(value, float):
        raise OCIReleaseAuthorityError("protocol JSON forbids floating-point values")
    if isinstance(value, str):
        if len(value.encode("utf-8", "strict")) > _MAX_STRING_BYTES:
            raise OCIReleaseAuthorityError("protocol JSON contains oversized text")
        return 1
    if isinstance(value, list):
        count = 1
        for item in value:
            count += _bounded_json_tree(item, depth=depth + 1)
            if count > _MAX_JSON_NODES:
                raise OCIReleaseAuthorityError("protocol JSON exceeds its node bound")
        return count
    if isinstance(value, dict):
        count = 1
        for key, item in value.items():
            if not isinstance(key, str):
                raise OCIReleaseAuthorityError("protocol JSON keys must be strings")
            count += _bounded_json_tree(key, depth=depth + 1)
            count += _bounded_json_tree(item, depth=depth + 1)
            if count > _MAX_JSON_NODES:
                raise OCIReleaseAuthorityError("protocol JSON exceeds its node bound")
        return count
    raise OCIReleaseAuthorityError("protocol JSON contains a non-JSON value")


def _canonical_bytes(value: Any) -> bytes:
    _bounded_json_tree(value)
    try:
        raw = (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise OCIReleaseAuthorityError("protocol value is not canonical JSON") from exc
    if not raw or len(raw) > _MAX_JSON_BYTES:
        raise OCIReleaseAuthorityError("protocol JSON exceeds its byte bound")
    return raw


def _parse_canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_JSON_BYTES:
        raise OCIReleaseAuthorityError(f"{label} size is outside its bound")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise OCIReleaseAuthorityError(f"{label} is malformed JSON") from exc
    _bounded_json_tree(value)
    if not isinstance(value, dict) or _canonical_bytes(value) != raw:
        raise OCIReleaseAuthorityError(f"{label} is not canonical JSON")
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OCIReleaseAuthorityError(f"{label} does not have the exact schema")
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or "\x00" in value
    ):
        raise OCIReleaseAuthorityError(f"{label} is not canonical text")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise OCIReleaseAuthorityError(f"{label} is malformed")
    return value


def _sha256(value: Any, label: str) -> str:
    return _text(value, label, _SHA256)


def _oci_digest(value: Any, label: str) -> str:
    return _text(value, label, _OCI_DIGEST)


def _positive(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise OCIReleaseAuthorityError(f"{label} is outside its bound")
    return value


def _nonnegative(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise OCIReleaseAuthorityError(f"{label} is outside its bound")
    return value


def _timeout(value: Any) -> int:
    # Whole seconds are the exact wire-independent timeout unit.  In
    # particular, bool, Decimal, float (including NaN/Inf), and subclasses do
    # not acquire surprising comparison/conversion semantics.
    if type(value) is not int or not 1 <= value <= 300:
        raise OCIReleaseAuthorityError("authority timeout must be an exact whole second")
    return value


def _relative_path(value: Any, label: str) -> str:
    rendered = _text(value, label)
    path = PurePosixPath(rendered)
    if (
        path.is_absolute()
        or rendered in {".", ".."}
        or "\\" in rendered
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != rendered
    ):
        raise OCIReleaseAuthorityError(f"{label} is not a canonical relative path")
    return rendered


def _descriptor(value: Any, label: str, media_type: str) -> dict[str, Any]:
    row = _exact(value, {"media_type", "digest", "size"}, label)
    if row["media_type"] != media_type:
        raise OCIReleaseAuthorityError(f"{label} media type is unsupported")
    return {
        "media_type": media_type,
        "digest": _oci_digest(row["digest"], f"{label} digest"),
        "size": _positive(row["size"], f"{label} size"),
    }


def _retained_file(value: Any, label: str, extra: set[str] | None = None) -> dict[str, Any]:
    keys = {"path", "sha256", "size"} | (extra or set())
    row = _exact(value, keys, label)
    result = {
        "path": _relative_path(row["path"], f"{label} path"),
        "sha256": _sha256(row["sha256"], f"{label} sha256"),
        "size": _positive(row["size"], f"{label} size", _MAX_TOTAL_EXPANDED),
    }
    for key in extra or set():
        result[key] = row[key]
    return result


def _validate_materialization(value: Any) -> dict[str, Any]:
    row = _exact(value, {
        "schema_version", "required_roles", "source_roster_sha256",
        "composition_manifest", "archive", "receipt", "census", "sbom",
        "provenance",
    }, "runtime materialization")
    if row["schema_version"] != RUNTIME_MATERIALIZATION_SCHEMA:
        raise OCIReleaseAuthorityError("runtime materialization schema is unsupported")
    if row["required_roles"] != list(RUNTIME_MATERIALIZATION_REQUIRED_ROLES):
        raise OCIReleaseAuthorityError("runtime materialization role roster is not exact")
    source = _sha256(row["source_roster_sha256"], "runtime source roster sha256")
    manifest = _retained_file(row["composition_manifest"], "composition manifest", {"schema_version"})
    archive = _retained_file(row["archive"], "materialized runtime archive", {"diff_id", "media_type"})
    receipt = _retained_file(row["receipt"], "materialization receipt")
    census = _retained_file(row["census"], "installed runtime census", {"schema_version", "entry_count", "expanded_bytes"})
    sbom = _retained_file(row["sbom"], "installed runtime SBOM", {"format"})
    provenance = _retained_file(row["provenance"], "installed runtime provenance", {"schema_version"})
    if archive["media_type"] != "application/vnd.oci.image.layer.v1.tar" or archive["diff_id"] != "sha256:" + archive["sha256"]:
        raise OCIReleaseAuthorityError("materialized runtime archive identity is invalid")
    _oci_digest(archive["diff_id"], "materialized runtime archive DiffID")
    if census["schema_version"] != INSTALLED_RUNTIME_CENSUS_SCHEMA:
        raise OCIReleaseAuthorityError("installed runtime census schema is unsupported")
    census["entry_count"] = _positive(census["entry_count"], "installed runtime entry count", _MAX_ARTIFACTS)
    census["expanded_bytes"] = _nonnegative(census["expanded_bytes"], "installed runtime expanded bytes", _MAX_TOTAL_EXPANDED)
    if sbom["format"] != "spdx-json-2.3":
        raise OCIReleaseAuthorityError("installed runtime SBOM format is unsupported")
    for item in (manifest, archive, receipt, census, sbom, provenance):
        if not item["path"].startswith("materialization/"):
            raise OCIReleaseAuthorityError("materialization evidence path is outside its namespace")
    if len({item["path"].casefold() for item in (manifest, archive, receipt, census, sbom, provenance)}) != 6:
        raise OCIReleaseAuthorityError("materialization evidence paths alias")
    return {
        "schema_version": RUNTIME_MATERIALIZATION_SCHEMA,
        "required_roles": list(RUNTIME_MATERIALIZATION_REQUIRED_ROLES),
        "source_roster_sha256": source,
        "composition_manifest": manifest, "archive": archive,
        "receipt": receipt, "census": census, "sbom": sbom,
        "provenance": provenance,
    }


def validate_output_commitments(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact OCI graph and the complete rootfs/layout census."""

    row = _exact(
        dict(value) if isinstance(value, Mapping) else value,
        {
            "schema_version", "image_reference",
            "apple_container_configuration_sha256", "platform", "index",
            "manifest", "config", "layers", "attestations", "artifacts",
            "directories", "rootfs_entries", "runtime_materialization",
            "layout_files", "rootfs_derivation",
        },
        "output commitments",
    )
    if row["schema_version"] != COMMITMENTS_SCHEMA:
        raise OCIReleaseAuthorityError("output commitments schema is unsupported")
    reference = _text(row["image_reference"], "image reference", _OCI_REFERENCE)
    platform_row = _exact(row["platform"], {"architecture", "os"}, "platform")
    platform_value = {
        "architecture": _text(platform_row["architecture"], "platform architecture"),
        "os": _text(platform_row["os"], "platform os"),
    }
    if platform_value["architecture"] not in {"amd64", "arm64"} or platform_value["os"] != "linux":
        raise OCIReleaseAuthorityError("platform is unsupported")

    index = _descriptor(row["index"], "index", INDEX_MEDIA_TYPE)
    manifest = _descriptor(row["manifest"], "manifest", MANIFEST_MEDIA_TYPE)
    config = _descriptor(row["config"], "config", CONFIG_MEDIA_TYPE)
    if reference.rsplit("@", 1)[1] != index["digest"]:
        raise OCIReleaseAuthorityError("image reference does not bind the index")
    if hmac.compare_digest(index["digest"], manifest["digest"]):
        raise OCIReleaseAuthorityError(
            "image index and selected manifest digests must be distinct"
        )
    apple_container_configuration_sha256 = _sha256(
        row["apple_container_configuration_sha256"],
        "Apple Container configuration sha256",
    )

    if not isinstance(row["layers"], list) or not 1 <= len(row["layers"]) <= _MAX_LAYERS:
        raise OCIReleaseAuthorityError("layer commitments are outside their bound")
    layers: list[dict[str, Any]] = []
    layer_digests: set[str] = set()
    diff_ids: set[str] = set()
    expanded_total = 0
    for number, value_row in enumerate(row["layers"]):
        layer = _exact(
            value_row,
            {"media_type", "digest", "size", "diff_id", "uncompressed_size"},
            f"layer {number}",
        )
        normalized = {
            **_descriptor(
                {key: layer[key] for key in ("media_type", "digest", "size")},
                f"layer {number}",
                LAYER_MEDIA_TYPE,
            ),
            "diff_id": _oci_digest(layer["diff_id"], f"layer {number} DiffID"),
            "uncompressed_size": _positive(
                layer["uncompressed_size"], f"layer {number} expanded size", _MAX_TOTAL_EXPANDED
            ),
        }
        if normalized["digest"] in layer_digests or normalized["diff_id"] in diff_ids:
            raise OCIReleaseAuthorityError("layer digest or DiffID is duplicated")
        layer_digests.add(normalized["digest"])
        diff_ids.add(normalized["diff_id"])
        expanded_total += normalized["uncompressed_size"]
        if expanded_total > _MAX_TOTAL_EXPANDED:
            raise OCIReleaseAuthorityError("expanded layers exceed their total bound")
        layers.append(normalized)

    if not isinstance(row["artifacts"], list) or not 1 <= len(row["artifacts"]) <= _MAX_ARTIFACTS:
        raise OCIReleaseAuthorityError("artifact commitments are outside their bound")
    artifacts: list[dict[str, Any]] = []
    ids: set[str] = set()
    paths: set[str] = set()
    for number, value_row in enumerate(row["artifacts"]):
        artifact = _exact(
            value_row,
            {"artifact_id", "role", "path", "sha256", "size", "mode"},
            f"artifact {number}",
        )
        normalized = {
            "artifact_id": _text(artifact["artifact_id"], f"artifact {number} id", _TOKEN),
            "role": _text(artifact["role"], f"artifact {number} role", _TOKEN),
            "path": _relative_path(artifact["path"], f"artifact {number} path"),
            "sha256": _sha256(artifact["sha256"], f"artifact {number} sha256"),
            "size": _nonnegative(artifact["size"], f"artifact {number} size"),
            "mode": _text(artifact["mode"], f"artifact {number} mode", _MODE),
        }
        folded = normalized["path"].casefold()
        if normalized["artifact_id"] in ids or folded in paths:
            raise OCIReleaseAuthorityError("artifact id or path is duplicated/aliased")
        ids.add(normalized["artifact_id"])
        paths.add(folded)
        artifacts.append(normalized)
    if artifacts != sorted(artifacts, key=lambda item: (item["path"], item["artifact_id"])):
        raise OCIReleaseAuthorityError("artifact commitments are not canonically ordered")

    if not isinstance(row["directories"], list) or len(row["directories"]) > _MAX_DIRECTORIES:
        raise OCIReleaseAuthorityError("directory commitments are outside their bound")
    directories: list[dict[str, Any]] = []
    directory_paths: set[str] = set()
    for number, value_row in enumerate(row["directories"]):
        directory = _exact(value_row, {"path", "mode"}, f"directory {number}")
        normalized = {
            "path": _relative_path(directory["path"], f"directory {number} path"),
            "mode": _text(directory["mode"], f"directory {number} mode", _MODE),
        }
        folded = normalized["path"].casefold()
        if folded in paths or folded in directory_paths:
            raise OCIReleaseAuthorityError("rootfs path is duplicated/aliased")
        directory_paths.add(folded)
        directories.append(normalized)
    if directories != sorted(directories, key=lambda item: item["path"]):
        raise OCIReleaseAuthorityError("directory commitments are not canonically ordered")
    all_rootfs = paths | directory_paths
    for path in [item["path"] for item in artifacts + directories]:
        parent = PurePosixPath(path).parent
        while parent.as_posix() != ".":
            if parent.as_posix().casefold() not in directory_paths:
                raise OCIReleaseAuthorityError("rootfs parent directory is not committed")
            parent = parent.parent

    materialization = _validate_materialization(row["runtime_materialization"])
    if not isinstance(row["rootfs_entries"], list) or not 1 <= len(row["rootfs_entries"]) <= _MAX_ARTIFACTS:
        raise OCIReleaseAuthorityError("installed runtime census is outside its bound")
    rootfs_entries: list[dict[str, Any]] = []
    rootfs_paths: set[str] = set()
    expanded_bytes = 0
    for number, value_row in enumerate(row["rootfs_entries"]):
        item = _exact(value_row, {"kind", "linkname", "mode", "path", "sha256", "size"}, f"rootfs entry {number}")
        kind = _text(item["kind"], f"rootfs entry {number} kind")
        if kind not in {"file", "directory", "symlink", "hardlink"}:
            raise OCIReleaseAuthorityError("rootfs entry kind is unsupported")
        path = _relative_path(item["path"], f"rootfs entry {number} path")
        linkname = item["linkname"]
        if not isinstance(linkname, str) or "\x00" in linkname:
            raise OCIReleaseAuthorityError("rootfs entry link target is malformed")
        size = _nonnegative(item["size"], f"rootfs entry {number} size", _MAX_TOTAL_EXPANDED)
        digest = item["sha256"]
        if kind == "directory":
            if linkname or size != 0 or digest is not None:
                raise OCIReleaseAuthorityError("directory census row is malformed")
        elif kind == "file":
            if linkname:
                raise OCIReleaseAuthorityError("file census row has a link target")
            digest = _sha256(digest, f"rootfs entry {number} sha256")
            expanded_bytes += size
        else:
            if not linkname or size != 0:
                raise OCIReleaseAuthorityError("link census row is malformed")
            digest = _sha256(digest, f"rootfs entry {number} sha256")
            if digest != hashlib.sha256((kind + "\0" + linkname).encode("utf-8")).hexdigest():
                raise OCIReleaseAuthorityError("link census digest is invalid")
        folded = path.casefold()
        if folded in rootfs_paths:
            raise OCIReleaseAuthorityError("installed runtime path is duplicated/aliased")
        rootfs_paths.add(folded)
        rootfs_entries.append({"kind": kind, "linkname": linkname, "mode": _text(item["mode"], f"rootfs entry {number} mode", _MODE), "path": path, "sha256": digest, "size": size})
    if rootfs_entries != sorted(rootfs_entries, key=lambda item: item["path"].encode("utf-8")):
        raise OCIReleaseAuthorityError("installed runtime census is not canonically ordered")
    by_rootfs_path = {item["path"]: item for item in rootfs_entries}
    for artifact in artifacts:
        installed = by_rootfs_path.get(artifact["path"])
        if (
            installed is None
            or installed["kind"] != "file"
            or any(
                installed[key] != artifact[key]
                for key in ("path", "sha256", "size", "mode")
            )
        ):
            raise OCIReleaseAuthorityError(
                "committed artifact is not the exact installed-runtime file"
            )
    allowed_provider_links = {("var/lock", "/run/lock"), ("var/run", "/run")}
    provider_roots = {"dev", "proc", "run", "sys", "tmp", "workspace"}
    for item in rootfs_entries:
        parent = PurePosixPath(item["path"]).parent
        while parent.as_posix() != ".":
            parent_row = by_rootfs_path.get(parent.as_posix())
            if parent_row is None or parent_row["kind"] != "directory":
                raise OCIReleaseAuthorityError(
                    "installed runtime parent directory is absent"
                )
            parent = parent.parent
        if item["kind"] == "hardlink":
            try:
                target = _relative_path(item["linkname"], "hardlink target")
            except OCIReleaseAuthorityError:
                raise OCIReleaseAuthorityError(
                    "hardlink target is not canonical"
                ) from None
            target_row = by_rootfs_path.get(target)
            if target_row is None or target_row["kind"] != "file":
                raise OCIReleaseAuthorityError(
                    "hardlink target is not a committed regular file"
                )
        elif item["kind"] == "symlink":
            linkname = item["linkname"]
            if "\\" in linkname or unicodedata.normalize("NFC", linkname) != linkname:
                raise OCIReleaseAuthorityError("symlink target is not canonical")
            resolved = posixpath.normpath(
                linkname.removeprefix("/")
                if linkname.startswith("/")
                else posixpath.join(posixpath.dirname(item["path"]), linkname)
            )
            if resolved in {"", ".", ".."} or resolved.startswith("../"):
                raise OCIReleaseAuthorityError("symlink target escapes the runtime root")
            first = PurePosixPath(resolved).parts[0]
            if (
                first in provider_roots
                and (item["path"], linkname) not in allowed_provider_links
            ):
                raise OCIReleaseAuthorityError(
                    "symlink target enters a provider-owned destination"
                )
    if len(rootfs_entries) != materialization["census"]["entry_count"] or expanded_bytes != materialization["census"]["expanded_bytes"]:
        raise OCIReleaseAuthorityError("installed runtime census totals differ from materialization")
    installed_census_raw = _canonical_bytes({
        "schema_version": INSTALLED_RUNTIME_CENSUS_SCHEMA,
        "entries": rootfs_entries,
    })
    if (
        hashlib.sha256(installed_census_raw).hexdigest()
        != materialization["census"]["sha256"]
        or len(installed_census_raw) != materialization["census"]["size"]
    ):
        raise OCIReleaseAuthorityError(
            "installed runtime census bytes differ from materialization"
        )
    if len(layers) != 1 or layers[0]["diff_id"] != materialization["archive"]["diff_id"] or layers[0]["uncompressed_size"] != materialization["archive"]["size"]:
        raise OCIReleaseAuthorityError("OCI layer is not the exact materialized runtime archive")

    attestation_row = _exact(
        row["attestations"], {"provenance", "runtime_census", "sbom"}, "attestations"
    )
    attestations: dict[str, dict[str, Any]] = {}
    required_roles = {
        "provenance": "provenance",
        "runtime_census": "runtime-census",
        "sbom": "sbom",
    }
    by_id = {item["artifact_id"]: item for item in artifacts}
    for name, role in required_roles.items():
        att = _exact(attestation_row[name], {"artifact_id", "path", "sha256", "size"}, name)
        normalized = {
            "artifact_id": _text(att["artifact_id"], f"{name} artifact id", _TOKEN),
            "path": _relative_path(att["path"], f"{name} path"),
            "sha256": _sha256(att["sha256"], f"{name} sha256"),
            "size": _nonnegative(att["size"], f"{name} size"),
        }
        artifact = by_id.get(normalized["artifact_id"])
        if artifact is None or artifact["role"] != role or any(
            artifact[key] != normalized[key] for key in ("path", "sha256", "size")
        ):
            raise OCIReleaseAuthorityError(f"{name} is not the exact committed artifact")
        attestations[name] = normalized

    derivation = _exact(
        row["rootfs_derivation"],
        {
            "schema_version", "derivation_schema_version", "recipe_version",
            "authentication_scope", "production_authority", "source_asset_id",
            "source_reference", "source_sha256", "source_size", "source_diff_id",
            "derived_sha256", "derived_size", "derived_diff_id",
            "derived_tar_size", "derived_census_sha256", "derived_entry_count",
            "manifest_sha256", "removed_cache_path", "removed_cache_sha256",
            "removed_cache_size", "forbidden_environment",
        },
        "rootfs derivation",
    )
    if (
        derivation["schema_version"] != ROOTFS_DERIVATION_BINDING_SCHEMA
        or derivation["production_authority"] is not False
        or derivation["source_asset_id"] != "complete-rootfs"
        or derivation["removed_cache_path"] != "/etc/ld.so.cache"
    ):
        raise OCIReleaseAuthorityError("rootfs derivation marker is invalid")
    for key in (
        "source_sha256", "derived_sha256", "derived_census_sha256",
        "manifest_sha256", "removed_cache_sha256",
    ):
        _sha256(derivation[key], f"rootfs derivation {key}")
    for key in ("source_diff_id", "derived_diff_id"):
        _oci_digest(derivation[key], f"rootfs derivation {key}")
    for key in (
        "source_size", "derived_size", "derived_tar_size",
        "derived_entry_count", "removed_cache_size",
    ):
        _nonnegative(derivation[key], f"rootfs derivation {key}")
    environment = _exact(
        derivation["forbidden_environment"],
        {"exact_names", "prefixes"},
        "rootfs derivation environment",
    )
    if environment != {"exact_names": ["GLIBC_TUNABLES"], "prefixes": ["LD_"]}:
        raise OCIReleaseAuthorityError("rootfs derivation environment denial is not exact")
    manifest_artifact = by_id.get("cache-free-rootfs-derivation")
    if (
        manifest_artifact is None
        or manifest_artifact["role"] != "generated-attestation"
        or manifest_artifact["path"]
        != "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json"
        or manifest_artifact["sha256"] != derivation["manifest_sha256"]
    ):
        raise OCIReleaseAuthorityError(
            "rootfs derivation manifest is not the exact committed artifact"
        )
    if derivation["authentication_scope"] == elf_closure.AUTHENTICATION_SCOPE:
        exact = {
            "derivation_schema_version": elf_closure.SCHEMA_VERSION,
            "recipe_version": elf_closure.RECIPE_VERSION,
            "source_reference": elf_closure.SOURCE_REFERENCE,
            "source_sha256": elf_closure.SOURCE_LAYER_SHA256,
            "source_size": elf_closure.SOURCE_LAYER_SIZE,
            "source_diff_id": "sha256:" + elf_closure.SOURCE_DIFF_ID,
            "derived_sha256": elf_closure.DERIVED_LAYER_SHA256,
            "derived_size": elf_closure.DERIVED_LAYER_SIZE,
            "derived_diff_id": "sha256:" + elf_closure.DERIVED_DIFF_ID,
            "derived_tar_size": elf_closure.SOURCE_TAR_SIZE,
            "derived_census_sha256": (
                "3d90ba706639fde6be674a520875aff6bcbc8f3a82dca8e35bf47bb090242112"
            ),
            "derived_entry_count": 4_218,
            "manifest_sha256": elf_closure.DERIVATION_MANIFEST_SHA256,
            "removed_cache_sha256": (
                "4f3163cd39f4dfd4669e9c79e71bc6f04a4c8275658211671ed2b740c0ec434f"
            ),
            "removed_cache_size": 4_587,
        }
        if any(derivation[key] != expected for key, expected in exact.items()):
            raise OCIReleaseAuthorityError("pinned rootfs derivation binding drifted")
    elif derivation["authentication_scope"] == "TEST_ONLY_NO_RELEASE_AUTHORITY":
        if (
            derivation["derivation_schema_version"]
            != "plamen.cache_free_rootfs_derivation.test.v1"
            or derivation["recipe_version"]
            != "TEST_ONLY_PRE_DERIVED_CACHE_FREE_V1"
            or derivation["source_reference"]
            != "TEST_ONLY_SYNTHETIC_CACHE_FREE_ROOT"
            or derivation["derived_sha256"] != derivation["source_sha256"]
            or derivation["derived_size"] != derivation["source_size"]
            or derivation["derived_diff_id"] != derivation["source_diff_id"]
            or derivation["derived_tar_size"] != derivation["source_size"]
            or derivation["source_size"] == 0
            or derivation["derived_size"] == 0
            or derivation["derived_tar_size"] == 0
            or derivation["derived_entry_count"] == 0
            or derivation["removed_cache_sha256"] != "0" * 64
            or derivation["removed_cache_size"] != 0
        ):
            raise OCIReleaseAuthorityError("TEST_ONLY rootfs derivation is invalid")
    else:
        raise OCIReleaseAuthorityError("rootfs derivation scope is unsupported")

    if not isinstance(row["layout_files"], list) or len(row["layout_files"]) != 4 + len(layers):
        raise OCIReleaseAuthorityError("layout file roster is not the exact OCI closure")
    layout_files: list[dict[str, Any]] = []
    layout_paths: set[str] = set()
    layout_roles: set[str] = set()
    for number, value_row in enumerate(row["layout_files"]):
        item = _exact(value_row, {"role", "path", "sha256", "size", "mode"}, f"layout file {number}")
        normalized = {
            "role": _text(item["role"], f"layout file {number} role", _TOKEN),
            "path": _relative_path(item["path"], f"layout file {number} path"),
            "sha256": _sha256(item["sha256"], f"layout file {number} sha256"),
            "size": _positive(item["size"], f"layout file {number} size"),
            "mode": _text(item["mode"], f"layout file {number} mode", _MODE),
        }
        if normalized["path"].casefold() in layout_paths or normalized["role"] in layout_roles:
            raise OCIReleaseAuthorityError("layout file path or role is duplicated/aliased")
        layout_paths.add(normalized["path"].casefold())
        layout_roles.add(normalized["role"])
        layout_files.append(normalized)
    if layout_files != sorted(layout_files, key=lambda item: (item["path"], item["role"])):
        raise OCIReleaseAuthorityError("layout files are not canonically ordered")

    expected_layout: dict[str, tuple[str, int]] = {
        "oci-layout": (hashlib.sha256(b'{"imageLayoutVersion":"1.0.0"}\n').hexdigest(), 31),
        "index.json": (index["digest"].split(":", 1)[1], index["size"]),
        f"blobs/sha256/{manifest['digest'].split(':', 1)[1]}": (manifest["digest"].split(":", 1)[1], manifest["size"]),
        f"blobs/sha256/{config['digest'].split(':', 1)[1]}": (config["digest"].split(":", 1)[1], config["size"]),
    }
    expected_roles = {
        "oci-layout": "oci-layout", "index.json": "index",
        f"blobs/sha256/{manifest['digest'].split(':', 1)[1]}": "manifest",
        f"blobs/sha256/{config['digest'].split(':', 1)[1]}": "config",
    }
    for number, layer in enumerate(layers):
        path = f"blobs/sha256/{layer['digest'].split(':', 1)[1]}"
        expected_layout[path] = (layer["digest"].split(":", 1)[1], layer["size"])
        expected_roles[path] = f"layer-{number}"
    actual_layout = {item["path"]: item for item in layout_files}
    if set(actual_layout) != set(expected_layout):
        raise OCIReleaseAuthorityError("layout file roster omits or adds OCI content")
    for path, (digest, size) in expected_layout.items():
        item = actual_layout[path]
        if (
            item["role"] != expected_roles[path]
            or item["sha256"] != digest
            or item["size"] != size
            or item["mode"] != "0444"
        ):
            raise OCIReleaseAuthorityError("layout file does not bind its OCI descriptor")

    normalized_commitments = {
        "schema_version": COMMITMENTS_SCHEMA,
        "image_reference": reference,
        "apple_container_configuration_sha256": (
            apple_container_configuration_sha256
        ),
        "platform": platform_value,
        "index": index,
        "manifest": manifest,
        "config": config,
        "layers": layers,
        "rootfs_derivation": json.loads(
            _canonical_bytes(derivation).decode("utf-8")
        ),
        "attestations": attestations,
        "artifacts": artifacts,
        "directories": directories,
        "rootfs_entries": rootfs_entries,
        "runtime_materialization": materialization,
        "layout_files": layout_files,
    }
    return json.loads(_canonical_bytes(normalized_commitments).decode("utf-8"))


def commitments_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(validate_output_commitments(value))).hexdigest()


def _stable_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev), "inode": int(info.st_ino),
        "mode": int(stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode)),
        "uid": int(info.st_uid), "gid": int(info.st_gid), "nlink": int(info.st_nlink),
    }


def _identity_tuple(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    row = _stable_identity(info)
    return tuple(row[key] for key in ("device", "inode", "mode", "uid", "gid", "nlink"))  # type: ignore[return-value]


def _file_sha256(descriptor: int, size: int) -> str:
    position = os.lseek(descriptor, 0, os.SEEK_CUR)
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        observed = 0
        while observed < size:
            chunk = os.read(descriptor, min(_READ_CHUNK, size - observed))
            if not chunk:
                raise OCIReleaseAuthorityError("descriptor was truncated while hashing")
            digest.update(chunk)
            observed += len(chunk)
        if os.read(descriptor, 1):
            raise OCIReleaseAuthorityError("descriptor grew while hashing")
        return digest.hexdigest()
    finally:
        os.lseek(descriptor, position, os.SEEK_SET)


def _dup_cloexec(descriptor: int) -> int:
    _require_posix()
    operation = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
    if operation is not None:
        return int(fcntl.fcntl(descriptor, operation, 64))
    duplicate = os.dup(descriptor)
    os.set_inheritable(duplicate, False)
    return duplicate


def _duplicate_readonly_file(descriptor: int, label: str, maximum: int) -> tuple[int, dict[str, Any]]:
    _require_posix()
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
        raise OCIReleaseAuthorityError(f"{label} descriptor is invalid")
    duplicate = -1
    try:
        duplicate = _dup_cloexec(descriptor)
        flags = int(fcntl.fcntl(duplicate, fcntl.F_GETFL))
        if flags & os.O_ACCMODE != os.O_RDONLY:
            raise OCIReleaseAuthorityError(f"{label} descriptor must be read-only")
        info = os.fstat(duplicate)
        if not stat.S_ISREG(info.st_mode) or int(info.st_nlink) != 1:
            raise OCIReleaseAuthorityError(f"{label} must be one ordinary unaliased file")
        size = _nonnegative(int(info.st_size), f"{label} size", maximum)
        digest = _file_sha256(duplicate, size)
        if _identity_tuple(os.fstat(duplicate)) != _identity_tuple(info):
            raise OCIReleaseAuthorityError(f"{label} changed during admission")
        os.lseek(duplicate, 0, os.SEEK_SET)
        return duplicate, {"sha256": digest, "size": size}
    except BaseException:
        if duplicate >= 0:
            os.close(duplicate)
        raise


# Production boundary.  There intentionally is no Python capability/receipt
# class, issuer singleton, registry, callback, or constructor to forge.
@_public_boundary("native executable admission")
def open_pinned_native_executable(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise OCIReleaseAuthorityError("NATIVE_RELEASE_AUTHORITY_INTEGRATION_REQUIRED")


@_public_boundary("release authentication")
def authenticate_release(
    *, native_authority_capability: object, **_request: Any
) -> NoReturn:
    del native_authority_capability
    raise OCIReleaseAuthorityError("NATIVE_RELEASE_AUTHORITY_INTEGRATION_REQUIRED")


class _TestOnlyExecutableRecord:
    __slots__ = ("descriptor", "argv_prefix", "sha256", "size", "identity")

    def __init__(self, descriptor: int, argv_prefix: tuple[str, ...], sha256: str, size: int, identity: tuple[int, ...]) -> None:
        self.descriptor = descriptor
        self.argv_prefix = argv_prefix
        self.sha256 = sha256
        self.size = size
        self.identity = identity


class _TestOnlyExecutable:
    """Explicitly non-production subprocess fixture."""

    __slots__ = ("_record", "_closed", "_lock")

    def __init__(self, record: _TestOnlyExecutableRecord) -> None:
        self._record = record
        self._closed = False
        self._lock = threading.Lock()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            os.close(self._record.descriptor)

    def __enter__(self) -> "_TestOnlyExecutable":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def TEST_ONLY_open_executable(argv: Sequence[str]) -> _TestOnlyExecutable:
    _require_posix()
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)) or not argv:
        raise OCIReleaseAuthorityError("TEST-ONLY argv is invalid")
    normalized = tuple(_text(item, "TEST-ONLY argv item") for item in argv)
    original = os.open(normalized[0], os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        descriptor, metadata = _duplicate_readonly_file(original, "TEST-ONLY executable", 2**31 - 1)
    finally:
        os.close(original)
    info = os.fstat(descriptor)
    return _TestOnlyExecutable(
        _TestOnlyExecutableRecord(
            descriptor, normalized, str(metadata["sha256"]), int(metadata["size"]), _identity_tuple(info)
        )
    )


def _test_executable_provenance(record: _TestOnlyExecutableRecord) -> dict[str, Any]:
    return {
        "sha256": record.sha256,
        "size": record.size,
        "kind": "TEST_ONLY_INTERPRETER",
        "identity": dict(zip(("device", "inode", "mode", "uid", "gid", "nlink"), record.identity, strict=True)),
    }


def _run_test_helper(
    executable: _TestOnlyExecutable,
    *, role: str,
    request: bytes,
    descriptors: Sequence[tuple[str, int]],
    timeout_seconds: Any,
) -> bytes:
    timeout = _timeout(timeout_seconds)
    record = executable._record
    with executable._lock:
        if executable._closed:
            raise OCIReleaseAuthorityError("TEST-ONLY executable is closed")
        if _identity_tuple(os.fstat(record.descriptor)) != record.identity or not hmac.compare_digest(
            _file_sha256(record.descriptor, record.size), record.sha256
        ):
            raise OCIReleaseAuthorityError("TEST-ONLY executable changed")
    with tempfile.TemporaryFile(prefix="plamen-test-request-") as request_file, tempfile.TemporaryFile(prefix="plamen-test-response-") as response_file:
        request_fd = request_file.fileno()
        response_fd = response_file.fileno()
        offset = 0
        while offset < len(request):
            offset += os.write(request_fd, request[offset:])
        os.fsync(request_fd)
        os.lseek(request_fd, 0, os.SEEK_SET)
        argv = list(record.argv_prefix) + [
            "--plamen-oci-protocol", TEST_ONLY_PROTOCOL,
            "--role", role, "--request-fd", str(request_fd),
            "--response-fd", str(response_fd),
        ]
        pass_fds = [record.descriptor, request_fd, response_fd]
        for descriptor_role, descriptor in descriptors:
            argv.extend(["--descriptor", f"{descriptor_role}={descriptor}"])
            pass_fds.append(descriptor)
        try:
            completed = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True,
                pass_fds=tuple(sorted(set(pass_fds))), check=False,
                timeout=timeout, cwd="/",
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            )
        except subprocess.TimeoutExpired as exc:
            raise OCIReleaseAuthorityError("TEST-ONLY helper timed out") from exc
        if completed.returncode != 0:
            raise OCIReleaseAuthorityError("TEST-ONLY helper failed closed")
        if os.lseek(request_fd, 0, os.SEEK_CUR) != len(request):
            raise OCIReleaseAuthorityError("TEST-ONLY helper did not consume request")
        os.lseek(response_fd, 0, os.SEEK_SET)
        response = os.read(response_fd, _MAX_RESPONSE_BYTES + 1)
        if len(response) > _MAX_RESPONSE_BYTES:
            raise OCIReleaseAuthorityError("TEST-ONLY helper response is oversized")
        return response


class _DurableAttempt:
    """Owner-private, locked, fsync-backed PREPARED/COMMITTED transaction."""

    def __init__(self, ledger: str | Path, kind: str, attempt: str, nonce: str) -> None:
        self._ledger_path = os.fspath(ledger)
        self._kind = kind
        self._attempt = attempt
        self._nonce = nonce
        self._directory_fd = -1
        self._lock_fd = -1
        self._fresh = False
        self._key = hashlib.sha256(f"{kind}\0{attempt}\0{nonce}".encode()).hexdigest()
        self._state_name = f"{self._key}.json"

    def __enter__(self) -> "_DurableAttempt":
        _require_posix()
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            resolved = os.path.realpath(os.path.abspath(self._ledger_path))
            current = os.open(os.path.sep, flags)
            try:
                for component in Path(resolved).parts[1:]:
                    child = os.open(component, flags, dir_fd=current)
                    os.close(current)
                    current = child
                self._directory_fd = current
                current = -1
            finally:
                if current >= 0:
                    os.close(current)
            info = os.fstat(self._directory_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise OCIReleaseAuthorityError("replay ledger directory is not owner-private")
            lock_name = f"{self._key}.lock"
            lock_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                self._lock_fd = os.open(lock_name, lock_flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self._directory_fd)
                os.fsync(self._directory_fd)
            except FileExistsError:
                self._lock_fd = os.open(lock_name, lock_flags, dir_fd=self._directory_fd)
            lock_info = os.fstat(self._lock_fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or lock_info.st_uid != os.geteuid() or stat.S_IMODE(lock_info.st_mode) != 0o600:
                raise OCIReleaseAuthorityError("replay ledger lock is unsafe")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            return self
        except BaseException:
            self.__exit__()
            raise

    def __exit__(self, *_args: object) -> None:
        if self._lock_fd >= 0:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = -1
        if self._directory_fd >= 0:
            os.close(self._directory_fd)
            self._directory_fd = -1

    def _read(self) -> dict[str, Any] | None:
        try:
            descriptor = os.open(self._state_name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=self._directory_fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_size > _MAX_JSON_BYTES:
                raise OCIReleaseAuthorityError("replay ledger record is unsafe")
            raw = b""
            while len(raw) < info.st_size:
                chunk = os.read(descriptor, info.st_size - len(raw))
                if not chunk:
                    raise OCIReleaseAuthorityError("replay ledger record was truncated")
                raw += chunk
            if os.read(descriptor, 1):
                raise OCIReleaseAuthorityError("replay ledger record grew")
            value = _parse_canonical_json(raw, "replay ledger record")
            digest = value.get("record_sha256")
            if not isinstance(digest, str):
                raise OCIReleaseAuthorityError("replay ledger record digest is absent")
            body = dict(value)
            del body["record_sha256"]
            if not hmac.compare_digest(digest, hashlib.sha256(_canonical_bytes(body)).hexdigest()):
                raise OCIReleaseAuthorityError("replay ledger record digest mismatch")
            return value
        finally:
            os.close(descriptor)

    def _write(self, value: Mapping[str, Any]) -> None:
        body = dict(value)
        body["record_sha256"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        raw = _canonical_bytes(body)
        temporary = f".{self._key}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        descriptor = -1
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=self._directory_fd)
            offset = 0
            while offset < len(raw):
                offset += os.write(descriptor, raw[offset:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self._state_name, src_dir_fd=self._directory_fd, dst_dir_fd=self._directory_fd)
            os.fsync(self._directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self._directory_fd)
            except FileNotFoundError:
                pass

    def admit(self, request_sha256: str) -> bytes | None:
        old = self._read()
        if old is None:
            self._write({
                "schema_version": "plamen.oci_authority_replay.v1", "state": "PREPARED",
                "kind": self._kind, "attempt_id": self._attempt, "nonce": self._nonce,
                "request_sha256": request_sha256, "receipt_b64": "",
            })
            self._fresh = True
            return None
        _exact(old, {"schema_version", "state", "kind", "attempt_id", "nonce", "request_sha256", "receipt_b64", "record_sha256"}, "replay ledger record")
        if old["schema_version"] != "plamen.oci_authority_replay.v1" or old["kind"] != self._kind or old["attempt_id"] != self._attempt or old["nonce"] != self._nonce or old["request_sha256"] != request_sha256:
            raise OCIReleaseAuthorityError("attempt key was replayed with different bytes")
        if old["state"] == "PREPARED" and old["receipt_b64"] == "":
            raise AmbiguousReleaseAttemptError("AMBIGUOUS_PRIOR_RELEASE_ATTEMPT")
        if old["state"] != "COMMITTED" or not isinstance(old["receipt_b64"], str):
            raise OCIReleaseAuthorityError("replay ledger state is invalid")
        try:
            return base64.b64decode(old["receipt_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise OCIReleaseAuthorityError("committed replay receipt is invalid") from exc

    def commit(self, request_sha256: str, receipt: bytes) -> None:
        if not self._fresh:
            raise OCIReleaseAuthorityError("only a fresh attempt can be committed")
        self._write({
            "schema_version": "plamen.oci_authority_replay.v1", "state": "COMMITTED",
            "kind": self._kind, "attempt_id": self._attempt, "nonce": self._nonce,
            "request_sha256": request_sha256,
            "receipt_b64": base64.b64encode(receipt).decode("ascii"),
        })
        self._fresh = False


_TEST_RECEIPT_KEYS = {
    "schema_version", "status", "protocol", "request_sha256", "attempt_id",
    "release_nonce", "release_generation", "lock_sha256", "commitments",
    "commitments_sha256", "authenticated_signer", "release_document_sha256",
    "signature_sha256", "test_executable_provenance",
}


class _TestOnlyVerifiedReleaseReceipt:
    """Forgeable by design and accepted only by exact TEST-ONLY consumers."""

    __slots__ = ("_bytes", "_recovered")

    def __init__(self, raw: bytes, recovered: bool = False) -> None:
        self._bytes = raw
        self._recovered = recovered

    @property
    def canonical_bytes(self) -> bytes:
        return self._bytes

    @property
    def value(self) -> dict[str, Any]:
        return json.loads(self._bytes.decode("utf-8"))

    @property
    def recovered(self) -> bool:
        return self._recovered


def _validate_test_release_receipt(raw: bytes, request: Mapping[str, Any] | None = None) -> dict[str, Any]:
    value = _parse_canonical_json(raw, "TEST-ONLY release receipt")
    _exact(value, _TEST_RECEIPT_KEYS, "TEST-ONLY release receipt")
    if value["schema_version"] != RECEIPT_SCHEMA or value["status"] != "TEST_ONLY_AUTHENTICATED" or value["protocol"] != TEST_ONLY_PROTOCOL:
        raise OCIReleaseAuthorityError("TEST-ONLY release receipt marker is invalid")
    _sha256(value["request_sha256"], "receipt request sha256")
    _text(value["attempt_id"], "receipt attempt id", _NONCE)
    _text(value["release_nonce"], "receipt release nonce", _NONCE)
    _positive(value["release_generation"], "receipt release generation")
    _sha256(value["lock_sha256"], "receipt lock sha256")
    commitments = validate_output_commitments(value["commitments"])
    if value["commitments"] != commitments or value["commitments_sha256"] != commitments_sha256(commitments):
        raise OCIReleaseAuthorityError("TEST-ONLY receipt commitments are invalid")
    _text(value["authenticated_signer"], "receipt signer")
    _sha256(value["release_document_sha256"], "receipt document sha256")
    _sha256(value["signature_sha256"], "receipt signature sha256")
    provenance = _exact(value["test_executable_provenance"], {"sha256", "size", "kind", "identity"}, "TEST-ONLY executable provenance")
    _sha256(provenance["sha256"], "TEST-ONLY executable sha256")
    _positive(provenance["size"], "TEST-ONLY executable size")
    if provenance["kind"] not in {"TEST_ONLY_INTERPRETER", "TEST_ONLY_NONE"}:
        raise OCIReleaseAuthorityError("TEST-ONLY executable kind is invalid")
    identity = _exact(provenance["identity"], {"device", "inode", "mode", "uid", "gid", "nlink"}, "TEST-ONLY executable identity")
    for key, item in identity.items():
        _nonnegative(item, f"TEST-ONLY executable {key}")
    if request is not None:
        expected = {
            "schema_version": RECEIPT_SCHEMA, "status": "TEST_ONLY_AUTHENTICATED",
            "protocol": TEST_ONLY_PROTOCOL,
            "request_sha256": hashlib.sha256(_canonical_bytes(dict(request))).hexdigest(),
            "attempt_id": request["attempt_id"], "release_nonce": request["release_nonce"],
            "release_generation": request["release_generation"], "lock_sha256": request["lock_sha256"],
            "commitments": request["commitments"], "commitments_sha256": request["commitments_sha256"],
            "authenticated_signer": request["expected_signer"],
            "release_document_sha256": request["release_document"]["sha256"],
            "signature_sha256": request["signature"]["sha256"],
            "test_executable_provenance": request["test_executable_provenance"],
        }
        if value != expected:
            raise OCIReleaseAuthorityError("TEST-ONLY release receipt does not bind the request")
    return value


def TEST_ONLY_issue_release_binding(
    *, attempt_id: str, release_nonce: str, release_generation: int,
    lock_sha256: str, commitments: Mapping[str, Any], authenticated_signer: str = "TEST_ONLY_NO_SIGNER_AUTHORITY",
) -> _TestOnlyVerifiedReleaseReceipt:
    normalized = validate_output_commitments(commitments)
    value = {
        "schema_version": RECEIPT_SCHEMA, "status": "TEST_ONLY_AUTHENTICATED",
        "protocol": TEST_ONLY_PROTOCOL, "request_sha256": "0" * 64,
        "attempt_id": _text(attempt_id, "attempt id", _NONCE),
        "release_nonce": _text(release_nonce, "release nonce", _NONCE),
        "release_generation": _positive(release_generation, "release generation"),
        "lock_sha256": _sha256(lock_sha256, "lock sha256"),
        "commitments": normalized, "commitments_sha256": commitments_sha256(normalized),
        "authenticated_signer": _text(authenticated_signer, "authenticated signer"),
        "release_document_sha256": "0" * 64, "signature_sha256": "0" * 64,
        "test_executable_provenance": {
            "sha256": "0" * 64, "size": 1, "kind": "TEST_ONLY_NONE",
            "identity": {"device": 0, "inode": 0, "mode": 0, "uid": 0, "gid": 0, "nlink": 0},
        },
    }
    raw = _canonical_bytes(value)
    _validate_test_release_receipt(raw)
    return _TestOnlyVerifiedReleaseReceipt(raw)


class _TestOnlyReleaseAuthority:
    __slots__ = ("_executable", "_ledger", "_lock", "_used")

    def __init__(self, executable: _TestOnlyExecutable, ledger: str | Path) -> None:
        self._executable = executable
        self._ledger = os.fspath(ledger)
        self._lock = threading.Lock()
        self._used = False

    def authenticate_for_testing(
        self, *, attempt_id: str, release_nonce: str, release_generation: int,
        lock_sha256: str, expected_signer: str, commitments: Mapping[str, Any],
        release_document_fd: int, signature_fd: int, timeout_seconds: Any,
    ) -> _TestOnlyVerifiedReleaseReceipt:
        with self._lock:
            if self._used:
                raise OCIReleaseAuthorityError("TEST-ONLY release authority is one-shot")
            self._used = True
        _timeout(timeout_seconds)
        attempt = _text(attempt_id, "attempt id", _NONCE)
        nonce = _text(release_nonce, "release nonce", _NONCE)
        normalized = validate_output_commitments(commitments)
        document = signature = -1
        try:
            document, document_meta = _duplicate_readonly_file(release_document_fd, "release document", _MAX_DOCUMENT_BYTES)
            signature, signature_meta = _duplicate_readonly_file(signature_fd, "release signature", _MAX_DOCUMENT_BYTES)
            if document_meta["size"] == 0 or signature_meta["size"] == 0:
                raise OCIReleaseAuthorityError("release document and signature must be non-empty")
            document_identity = _identity_tuple(os.fstat(document))
            signature_identity = _identity_tuple(os.fstat(signature))
            request = {
                "schema_version": REQUEST_SCHEMA, "protocol": TEST_ONLY_PROTOCOL,
                "attempt_id": attempt, "release_nonce": nonce,
                "release_generation": _positive(release_generation, "release generation"),
                "lock_sha256": _sha256(lock_sha256, "lock sha256"),
                "expected_signer": _text(expected_signer, "expected signer"),
                "release_document": document_meta, "signature": signature_meta,
                "commitments": normalized, "commitments_sha256": commitments_sha256(normalized),
                "test_executable_provenance": _test_executable_provenance(self._executable._record),
            }
            request_raw = _canonical_bytes(request)
            request_digest = hashlib.sha256(request_raw).hexdigest()
            with _DurableAttempt(self._ledger, "release-test-only", attempt, nonce) as journal:
                raw = journal.admit(request_digest)
                recovered = raw is not None
                if raw is None:
                    raw = _run_test_helper(
                        self._executable, role="release-authenticate-test-only",
                        request=request_raw,
                        descriptors=(("release-document", document), ("release-signature", signature)),
                        timeout_seconds=timeout_seconds,
                    )
                    if os.lseek(document, 0, os.SEEK_CUR) != document_meta["size"] or os.lseek(signature, 0, os.SEEK_CUR) != signature_meta["size"]:
                        raise OCIReleaseAuthorityError("TEST-ONLY helper did not consume release inputs")
                    if (
                        _identity_tuple(os.fstat(document)) != document_identity
                        or _identity_tuple(os.fstat(signature)) != signature_identity
                        or _file_sha256(document, document_meta["size"]) != document_meta["sha256"]
                        or _file_sha256(signature, signature_meta["size"]) != signature_meta["sha256"]
                    ):
                        raise OCIReleaseAuthorityError("TEST-ONLY release input changed during authentication")
                    _validate_test_release_receipt(raw, request)
                    journal.commit(request_digest, raw)
                else:
                    _validate_test_release_receipt(raw, request)
            return _TestOnlyVerifiedReleaseReceipt(raw, recovered)
        finally:
            if document >= 0:
                os.close(document)
            if signature >= 0:
                os.close(signature)


def TEST_ONLY_create_release_authority(executable: _TestOnlyExecutable, ledger_directory: str | Path) -> _TestOnlyReleaseAuthority:
    if type(executable) is not _TestOnlyExecutable:
        raise TypeError("TEST-ONLY authority requires exact TEST-ONLY executable")
    return _TestOnlyReleaseAuthority(executable, ledger_directory)


__all__ = [
    "AmbiguousReleaseAttemptError", "COMMITMENTS_SCHEMA", "OCIReleaseAuthorityError",
    "PROTOCOL", "RECEIPT_SCHEMA", "REQUEST_SCHEMA", "authenticate_release",
    "commitments_sha256", "open_pinned_native_executable", "validate_output_commitments",
]
