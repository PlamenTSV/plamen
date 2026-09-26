"""Deterministic, deny-by-default OCI image-lock build-plan renderer.

This module observes a local build-input tree and renders a declarative plan.
It never invokes a container engine, package manager, network client, or
credential provider.

Security boundary: Python module callers are inside one trusted interpreter
and can replace globals or inspect closures.  Consequently this module does
not issue release-authentication or build-completion capabilities in Python.
The production entrypoints fail closed until they are wired to a pinned
compiled/out-of-process verifier that authenticates the release receipt and
consumes every retained input before issuing a completion receipt.  The
explicit test-only seam exercises census and reader behavior, but its distinct
plan type is not production authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
import functools
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import tempfile
import threading
from typing import Any
import unicodedata

import elf_loader_closure as elf_closure
import runtime_image_materializer as runtime_materializer


SCHEMA_VERSION = "plamen.oci_image_lock.v5"
BUILD_PLAN_SCHEMA_VERSION = "plamen.oci_build_plan.v5"
APPLE_HOST_PLATFORM = "darwin/arm64"
TARGET_PLATFORM = "linux/arm64"
RUNTIME_CENSUS_SCHEMA_VERSION = "plamen.runtime_census.v1"
RUNTIME_MATERIALIZATION_SCHEMA_VERSION = (
    "plamen.runtime_materialization_binding.v1"
)
INSTALLED_RUNTIME_CENSUS_SCHEMA_VERSION = (
    runtime_materializer.CENSUS_SCHEMA_VERSION
)
RUNTIME_MATERIALIZATION_REQUIRED_ROLES = (
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

_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 65_536
_MAX_STRING_BYTES = 65_536
_MAX_BUILD_INPUTS = 4_096
_MAX_TOTAL_INPUT_BYTES = 8 * 1024 * 1024 * 1024
_MAX_PATH_COMPONENTS = 64
_MAX_ATTESTATION_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_VERSION = re.compile(
    r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?\Z"
)
_OCI_REFERENCE = re.compile(
    r"[a-z0-9](?:[a-z0-9._:-]{0,253})/"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}\Z"
)
_RELEASE_NONCE = re.compile(r"[0-9a-f]{32,128}\Z")
_SPDX_VERSION = "SPDX-2.3"
_CYCLONEDX_VERSION = "1.6"
_XATTR_SHOWCOMPRESSION = 0x0020

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "platform",
        "image",
        "runtime",
        "rootfs_derivation",
        "attestations",
        "runtime_materialization",
        "policies",
        "build_inputs",
        "lock_sha256",
    }
)
_PLATFORM_KEYS = frozenset({"host", "target"})
_IMAGE_KEYS = frozenset(
    {
        "reference",
        "index_digest",
        "manifest_digest",
        "config_digest",
        "apple_container_configuration_sha256",
        "base_reference",
        "base_manifest_digest",
    }
)
_RUNTIME_KEYS = frozenset(
    {"cpython", "backend_clis", "toolchains", "assets"}
)
_ROOTFS_DERIVATION_KEYS = frozenset(
    {
        "schema_version",
        "derivation_schema_version",
        "recipe_version",
        "authentication_scope",
        "production_authority",
        "source_asset_id",
        "source_reference",
        "source_sha256",
        "source_size",
        "source_diff_id",
        "derived_sha256",
        "derived_size",
        "derived_diff_id",
        "derived_tar_size",
        "derived_census_sha256",
        "derived_entry_count",
        "manifest_sha256",
        "removed_cache_path",
        "removed_cache_sha256",
        "removed_cache_size",
        "forbidden_environment",
    }
)
_ENVIRONMENT_DENIAL_KEYS = frozenset({"exact_names", "prefixes"})
ROOTFS_DERIVATION_BINDING_SCHEMA_VERSION = (
    "plamen.oci_rootfs_derivation_binding.v1"
)
TEST_ONLY_ROOTFS_DERIVATION_RECIPE = (
    "TEST_ONLY_PRE_DERIVED_CACHE_FREE_V1"
)
_PINNED_DERIVED_CENSUS_SHA256 = (
    "3d90ba706639fde6be674a520875aff6bcbc8f3a82dca8e35bf47bb090242112"
)
_PINNED_DERIVED_ENTRY_COUNT = 4_218
_PINNED_REMOVED_CACHE_SHA256 = (
    "4f3163cd39f4dfd4669e9c79e71bc6f04a4c8275658211671ed2b740c0ec434f"
)
_PINNED_REMOVED_CACHE_SIZE = 4_587
_TEST_ONLY_DERIVATION_SCHEMA_VERSION = (
    "plamen.cache_free_rootfs_derivation.test.v1"
)
_TEST_ONLY_DERIVATION_MANIFEST_SCHEMA_VERSION = (
    "plamen.cache_free_rootfs_derivation_manifest.test.v1"
)
_ARTIFACT_KEYS = frozenset({"version", "path", "sha256"})
_BACKEND_KEYS = frozenset({"backend", "version", "path", "sha256"})
_TOOLCHAIN_KEYS = frozenset({"toolchain_id", "version", "path", "sha256"})
_ASSET_KEYS = frozenset({"asset_id", "path", "sha256"})
_ATTESTATION_KEYS = frozenset({"sbom", "census"})
_SBOM_KEYS = frozenset({"format", "path", "sha256"})
_CENSUS_KEYS = frozenset({"schema_version", "path", "sha256"})
_MATERIALIZATION_KEYS = frozenset(
    {
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
)
_MATERIALIZATION_FILE_KEYS = frozenset({"path", "sha256", "size"})
_MATERIALIZATION_MANIFEST_KEYS = frozenset(
    {*_MATERIALIZATION_FILE_KEYS, "schema_version"}
)
_MATERIALIZATION_ARCHIVE_KEYS = frozenset(
    {*_MATERIALIZATION_FILE_KEYS, "diff_id", "media_type"}
)
_MATERIALIZATION_CENSUS_KEYS = frozenset(
    {
        *_MATERIALIZATION_FILE_KEYS,
        "schema_version",
        "entry_count",
        "expanded_bytes",
    }
)
_MATERIALIZATION_SBOM_KEYS = frozenset(
    {*_MATERIALIZATION_FILE_KEYS, "format"}
)
_MATERIALIZATION_PROVENANCE_KEYS = frozenset(
    {*_MATERIALIZATION_FILE_KEYS, "schema_version"}
)
_POLICY_KEYS = frozenset(
    {
        "network",
        "runtime_package_resolution",
        "build_input_admission",
        "symlinks",
        "hardlinks",
        "extended_attributes",
    }
)
_INPUT_KEYS = frozenset({"path", "sha256", "size", "mode"})
_REQUIRED_POLICIES = {
    "network": "DENY",
    "runtime_package_resolution": "DENY",
    "build_input_admission": "EXACT_ROSTER",
    "symlinks": "DENY",
    "hardlinks": "DENY",
    "extended_attributes": "DENY",
}


class OCIImageLockError(RuntimeError):
    """The image lock or observed build context is not authoritative."""


def _public_boundary(label: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Return public errors without retaining sensitive low-level exceptions."""

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(function)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except OCIImageLockError as exc:
                message = str(exc)
            except Exception:
                message = f"{label} failed closed"
            # This raise is deliberately outside the handler.  ``from None``
            # suppresses display chaining, and leaving the handler first means
            # neither __cause__ nor __context__ retains an attacker path.
            error = OCIImageLockError(message)
            error.__cause__ = None
            error.__context__ = None
            raise error from None

        return guarded

    return decorate


MetadataInspector = Callable[[int], Sequence[str | bytes]]


@dataclass(frozen=True)
class _RetainedInput:
    path: str
    sha256: str
    size: int
    mode: str
    descriptor: int
    identity: tuple[int, ...]


_READER_ISSUER = object()


class _BuildInputReader:
    """Read-only, non-seekable view of one retained admitted input."""

    __slots__ = ()

    def __new__(cls, issuer: object = None) -> "_BuildInputReader":
        if issuer is not _READER_ISSUER:
            raise TypeError("build-input readers can only be issued by the authority")
        return super().__new__(cls)

    @property
    def path(self) -> str:
        return str(_reader_attribute(self, "path"))

    @property
    def size(self) -> int:
        return int(_reader_attribute(self, "size"))

    @property
    def mode(self) -> str:
        return str(_reader_attribute(self, "mode"))

    @property
    def sha256(self) -> str:
        return str(_reader_attribute(self, "sha256"))

    @_public_boundary("build-input reading")
    def read(self, maximum_bytes: int = _READ_CHUNK) -> bytes:
        """Return the next bounded chunk and authenticate EOF exactly once."""

        if (
            isinstance(maximum_bytes, bool)
            or not isinstance(maximum_bytes, int)
            or maximum_bytes <= 0
        ):
            raise ValueError("build-input read size must be a positive integer")
        return _read_issued_reader(self, maximum_bytes)


def _make_reader_authority() -> tuple[Callable[..., Any], ...]:
    """Keep all mutable reader state in a closure owned by the issuer."""

    @dataclass
    class State:
        retained: _RetainedInput
        digest: Any = field(default_factory=hashlib.sha256)
        observed: int = 0
        complete: bool = False

    states: dict[_BuildInputReader, State] = {}
    state_lock = threading.RLock()

    def state_for(reader: _BuildInputReader) -> State:
        try:
            return states[reader]
        except KeyError:
            raise OCIImageLockError(
                "build-input reader is unavailable or revoked"
            ) from None

    def issue(retained: _RetainedInput) -> _BuildInputReader:
        reader = _BuildInputReader(_READER_ISSUER)
        with state_lock:
            states[reader] = State(retained=retained)
        return reader

    def attribute(reader: _BuildInputReader, name: str) -> str | int:
        if name not in {"path", "size", "mode", "sha256"}:
            raise OCIImageLockError("build-input reader attribute is unavailable")
        with state_lock:
            return getattr(state_for(reader).retained, name)

    def read(reader: _BuildInputReader, maximum_bytes: int) -> bytes:
        with state_lock:
            state = state_for(reader)
            if state.complete:
                return b""
            retained = state.retained
            remaining = retained.size - state.observed
            if remaining:
                chunk = os.read(
                    retained.descriptor,
                    min(maximum_bytes, _READ_CHUNK, remaining),
                )
                if not chunk:
                    raise OCIImageLockError(
                        f"retained build input {retained.path!r} was truncated"
                    )
                state.digest.update(chunk)
                state.observed += len(chunk)
                if state.observed < retained.size:
                    return chunk
            else:
                chunk = b""
            if os.read(retained.descriptor, 1):
                raise OCIImageLockError(
                    f"retained build input {retained.path!r} grew during consumption"
                )
            if state.digest.hexdigest() != retained.sha256:
                raise OCIImageLockError(
                    f"retained build input {retained.path!r} changed during consumption"
                )
            if _stable_identity(os.fstat(retained.descriptor)) != retained.identity:
                raise OCIImageLockError(
                    f"retained build input {retained.path!r} changed during consumption"
                )
            state.complete = True
            return chunk

    def require_complete(reader: _BuildInputReader) -> None:
        with state_lock:
            state = state_for(reader)
            if not state.complete:
                raise OCIImageLockError(
                    "executor did not consume retained build input "
                    f"{state.retained.path!r}"
                )

    def revoke(reader: _BuildInputReader) -> None:
        with state_lock:
            states.pop(reader, None)

    def borrow_descriptor_for_testing(reader: _BuildInputReader) -> int:
        """Duplicate one admitted snapshot descriptor for TEST_ONLY derivation.

        The reader state remains closure-owned and unforgeable through ordinary
        construction.  The duplicate is an O_RDONLY handle to the same
        unlinked snapshot; callers never receive or reopen a pathname.
        """

        with state_lock:
            retained = state_for(reader).retained
            descriptor = -1
            try:
                descriptor = os.dup(retained.descriptor)
                os.set_inheritable(descriptor, False)
                if _stable_identity(os.fstat(descriptor)) != retained.identity:
                    raise OCIImageLockError(
                        "borrowed build-input descriptor identity changed"
                    )
                return descriptor
            except BaseException:
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                raise

    return issue, attribute, read, require_complete, revoke, borrow_descriptor_for_testing


(
    _issue_reader,
    _reader_attribute,
    _read_issued_reader,
    _require_reader_complete,
    _revoke_reader,
    _TEST_ONLY_borrow_reader_descriptor,
) = _make_reader_authority()
del _make_reader_authority


DurableReplayConsumer = Callable[[int, str, str], bool]

_RELEASE_VERIFIER_REQUIRED = "AUTHENTICATED_RELEASE_RECEIPT_VERIFIER_REQUIRED"
_CONTEXT_CONSUMER_REQUIRED = "AUTHENTICATED_CONTEXT_CONSUMER_REQUIRED"


class _BuildContextAuthority:
    """One-shot ownership of the exact descriptors admitted by the census."""

    def __init__(
        self,
        retained: Sequence[_RetainedInput],
        *,
        metadata_inspector: MetadataInspector,
    ) -> None:
        self._retained = tuple(retained)
        self._metadata_inspector = metadata_inspector
        self._lock = threading.Lock()
        self._consumed = False
        self._closed = False

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            retained, self._retained = self._retained, ()
        for row in retained:
            try:
                os.close(row.descriptor)
            except OSError:
                pass

    def _revalidate(self) -> None:
        observed_total = 0
        for row in self._retained:
            before = os.fstat(row.descriptor)
            if _stable_identity(before) != row.identity:
                raise OCIImageLockError(
                    f"retained build input {row.path!r} changed before consumption"
                )
            if int(before.st_size) != row.size:
                raise OCIImageLockError(
                    f"retained build input {row.path!r} changed size"
                )
            observed_total += row.size
            if observed_total > _MAX_TOTAL_INPUT_BYTES:
                raise OCIImageLockError(
                    "retained build-input byte count exceeds its bound"
                )
            _assert_no_extended_metadata(
                row.descriptor,
                inspector=self._metadata_inspector,
                label=f"retained build input {row.path!r}",
            )
            observed_digest = _file_sha256(row.descriptor, row.size)
            after = os.fstat(row.descriptor)
            if (
                observed_digest != row.sha256
                or _stable_identity(after) != row.identity
            ):
                raise OCIImageLockError(
                    f"retained build input {row.path!r} changed before consumption"
                )

    def consume(self, consumer: Callable[[tuple[_BuildInputReader, ...]], Any]) -> Any:
        """Invoke one trusted executor with authenticated, non-path readers."""

        if not callable(consumer):
            raise TypeError("build-context consumer must be callable")
        with self._lock:
            if self._closed or self._consumed:
                raise OCIImageLockError(
                    "retained build-context authority is unavailable or consumed"
                )
            self._consumed = True
        # Capture issuer-owned operations before invoking caller code, so a
        # callback cannot swap module attributes to forge completion or skip
        # revocation during the synchronous handoff.
        issue = _issue_reader
        require_complete = _require_reader_complete
        revoke = _revoke_reader
        try:
            self._revalidate()
            readers: list[_BuildInputReader] = []
            try:
                for row in self._retained:
                    os.lseek(row.descriptor, 0, os.SEEK_SET)
                    readers.append(issue(row))
                result = consumer(tuple(readers))
                for reader in readers:
                    require_complete(reader)
                return result
            finally:
                for reader in readers:
                    revoke(reader)
        finally:
            self.close()


class OCIValidatedBuildPlan(dict[str, Any]):
    """Frozen plan whose production consumption requires a native authority.

    Instances of this exact type are reserved for the future authenticated
    integration.  A Python callback is deliberately insufficient evidence
    that an external executor consumed the complete retained context.
    """

    def __init__(
        self,
        value: Mapping[str, Any],
        authority: _BuildContextAuthority,
    ) -> None:
        dict.__init__(self, value)
        self._authority = authority

    @_public_boundary("build-context consumption")
    def consume_build_context(
        self,
        _authenticated_consumer: object,
    ) -> Any:
        """Fail closed until the native/out-of-process consumer is integrated."""

        self._authority.close()
        raise OCIImageLockError(_CONTEXT_CONSUMER_REQUIRED)

    def _consume_with_python_for_testing(
        self,
        consumer: Callable[[tuple[_BuildInputReader, ...]], Any],
    ) -> Any:
        expected = self.get("plan_sha256")
        body = dict(self)
        body.pop("plan_sha256", None)
        if (
            not isinstance(expected, str)
            or not hmac.compare_digest(
                expected,
                hashlib.sha256(_canonical_bytes(body)).hexdigest(),
            )
        ):
            self._authority.close()
            raise OCIImageLockError("build plan changed before context consumption")
        return self._authority.consume(consumer)

    def close(self) -> None:
        self._authority.close()

    def __enter__(self) -> "OCIValidatedBuildPlan":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        authority = getattr(self, "_authority", None)
        if authority is not None:
            authority.close()

    @staticmethod
    def _immutable(*_args: object, **_kwargs: object) -> None:
        raise TypeError("validated OCI build plans are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable


class _TestingOCIValidatedBuildPlan(OCIValidatedBuildPlan):
    """Non-production plan returned only by the explicit unit-test seam."""

    @_public_boundary("test build-context consumption")
    def consume_build_context_for_testing(
        self,
        consumer: Callable[[tuple[_BuildInputReader, ...]], Any],
    ) -> Any:
        return self._consume_with_python_for_testing(consumer)


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
        raise OCIImageLockError("image-lock value is not canonical JSON") from exc


def _enforce_json_bounds(value: Any) -> bytes:
    """Apply the same serialized/tree bounds to every public lock entrypoint."""

    _bounded_json_tree(value)
    encoded = _canonical_bytes(value)
    if not encoded or len(encoded) > _MAX_JSON_BYTES:
        raise OCIImageLockError("image-lock JSON size is outside its bound")
    return encoded


@_public_boundary("image-lock canonicalization")
def canonical_lock_sha256(payload: Mapping[str, Any]) -> str:
    """Digest the exact canonical lock body, excluding its digest field."""

    if not isinstance(payload, Mapping):
        raise OCIImageLockError("image lock must be a JSON object")
    body = dict(payload)
    body.pop("lock_sha256", None)
    return hashlib.sha256(_enforce_json_bounds(body)).hexdigest()


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Keys are attacker-controlled and can be both sensitive and very
            # large.  Never retain or echo one through a public error.
            raise OCIImageLockError("duplicate JSON key is forbidden")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise OCIImageLockError(f"non-finite JSON number {value!r} is forbidden")


def _bounded_json_tree(value: Any, *, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise OCIImageLockError("image lock exceeds JSON depth bound")
    if value is None or type(value) in {bool, int, float}:
        return 1
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise OCIImageLockError(
                "image lock contains non-UTF-8 text"
            ) from exc
        if len(encoded) > _MAX_STRING_BYTES:
            raise OCIImageLockError("image lock contains an oversized string")
        return 1
    if isinstance(value, list):
        count = 1
        for item in value:
            count += _bounded_json_tree(item, depth=depth + 1)
            if count > _MAX_JSON_NODES:
                raise OCIImageLockError("image lock exceeds JSON node bound")
        return count
    if isinstance(value, dict):
        count = 1
        for key, item in value.items():
            count += _bounded_json_tree(key, depth=depth + 1)
            count += _bounded_json_tree(item, depth=depth + 1)
            if count > _MAX_JSON_NODES:
                raise OCIImageLockError("image lock exceeds JSON node bound")
        return count
    raise OCIImageLockError("image lock contains a non-JSON value")


@_public_boundary("image-lock parsing")
def parse_image_lock(raw: bytes | str) -> dict[str, Any]:
    """Parse exact canonical UTF-8 JSON while rejecting aliases and excess."""

    try:
        encoded = raw.encode("utf-8", "strict") if isinstance(raw, str) else raw
    except UnicodeError as exc:
        raise OCIImageLockError("image lock is not strict UTF-8") from exc
    if not isinstance(encoded, bytes):
        raise OCIImageLockError("image lock must be bytes or text")
    if not encoded or len(encoded) > _MAX_JSON_BYTES:
        raise OCIImageLockError("image-lock JSON size is outside its bound")
    try:
        payload = json.loads(
            encoded.decode("utf-8", "strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except OCIImageLockError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise OCIImageLockError("image lock is malformed JSON") from exc
    _bounded_json_tree(payload)
    validated = validate_image_lock(payload)
    if encoded != _canonical_bytes(validated):
        raise OCIImageLockError("image-lock JSON is not in canonical wire form")
    return validated


def _exact_object(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OCIImageLockError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _text(value: Any, label: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise OCIImageLockError(f"{label} must be non-empty canonical text")
    if unicodedata.normalize("NFC", value) != value:
        raise OCIImageLockError(f"{label} must be NFC canonical")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise OCIImageLockError(f"{label} is malformed")
    return value


def _sha256(value: Any, label: str) -> str:
    return _text(value, label, pattern=_SHA256)


def _oci_digest(value: Any, label: str) -> str:
    return _text(value, label, pattern=_OCI_DIGEST)


def _version(value: Any, label: str) -> str:
    rendered = _text(value, label, pattern=_VERSION)
    if any(token in rendered.casefold() for token in ("latest", "snapshot", "nightly")):
        raise OCIImageLockError(f"{label} is mutable")
    return rendered


def _relative_path(value: Any, label: str) -> str:
    rendered = _text(value, label)
    if "\\" in rendered or len(rendered.encode("utf-8")) > 4096:
        raise OCIImageLockError(f"{label} is not a portable POSIX path")
    parsed = PurePosixPath(rendered)
    parts = parsed.parts
    if (
        parsed.is_absolute()
        or not parts
        or len(parts) > _MAX_PATH_COMPONENTS
        or rendered != parsed.as_posix()
        or any(part in {"", ".", ".."} for part in parts)
        or any(
            unicodedata.normalize("NFC", part) != part
            or part.casefold() in {".", ".."}
            for part in parts
        )
    ):
        raise OCIImageLockError(f"{label} escapes or aliases its build root")
    return rendered


def _immutable_reference(value: Any, digest: str, label: str) -> str:
    reference = _text(value, label, pattern=_OCI_REFERENCE)
    repository, observed_digest = reference.rsplit("@", 1)
    # Registry ports are allowed; a tag on the final repository segment is not.
    if ":" in repository.rsplit("/", 1)[-1]:
        raise OCIImageLockError(f"{label} contains a mutable tag")
    if observed_digest != digest:
        raise OCIImageLockError(f"{label} digest disagrees with its pinned digest")
    return reference


def _validate_artifact(
    value: Any,
    *,
    keys: frozenset[str],
    label: str,
    id_key: str | None = None,
) -> dict[str, Any]:
    row = _exact_object(value, keys, label)
    if id_key is not None:
        _text(row[id_key], f"{label} {id_key}", pattern=_IDENTIFIER)
    if "version" in row:
        _version(row["version"], f"{label} version")
    _relative_path(row["path"], f"{label} path")
    _sha256(row["sha256"], f"{label} sha256")
    return row


def _validate_sorted_unique_rows(
    rows: Any,
    *,
    label: str,
    id_key: str,
    keys: frozenset[str],
) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or not rows:
        raise OCIImageLockError(f"{label} must be a non-empty list")
    validated = [
        _validate_artifact(row, keys=keys, label=f"{label} row", id_key=id_key)
        for row in rows
    ]
    identities = [str(row[id_key]) for row in validated]
    if identities != sorted(identities, key=lambda item: (item.casefold(), item)):
        raise OCIImageLockError(f"{label} must be canonically sorted")
    if len({item.casefold() for item in identities}) != len(identities):
        raise OCIImageLockError(f"{label} contains a case-colliding identity")
    return validated


def _TEST_ONLY_rootfs_derivation_manifest_bytes(
    binding: Mapping[str, Any],
) -> bytes:
    """Render the explicit synthetic derivation evidence used by unit tests."""

    body = dict(binding)
    body.pop("manifest_sha256", None)
    return _canonical_bytes(
        {
            "binding": body,
            "production_authority": False,
            "schema_version": _TEST_ONLY_DERIVATION_MANIFEST_SCHEMA_VERSION,
            "status": "TEST_ONLY_PRE_DERIVED_CACHE_FREE",
        }
    )


def _validate_rootfs_derivation(
    value: Any,
    *,
    assets: Sequence[Mapping[str, Any]],
    inputs: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    row = _exact_object(value, _ROOTFS_DERIVATION_KEYS, "rootfs derivation")
    if row["schema_version"] != ROOTFS_DERIVATION_BINDING_SCHEMA_VERSION:
        raise OCIImageLockError("rootfs derivation binding schema is unsupported")
    if row["production_authority"] is not False:
        raise OCIImageLockError("rootfs derivation cannot claim production authority")
    source_asset_id = _text(
        row["source_asset_id"], "rootfs derivation source asset", pattern=_IDENTIFIER
    )
    asset = next(
        (candidate for candidate in assets if candidate["asset_id"] == source_asset_id),
        None,
    )
    if asset is None:
        raise OCIImageLockError("rootfs derivation source asset is absent")
    source_input = inputs.get(str(asset["path"]))
    if source_input is None:
        raise OCIImageLockError("rootfs derivation source input is absent")
    for key in (
        "source_sha256",
        "derived_sha256",
        "derived_census_sha256",
        "manifest_sha256",
        "removed_cache_sha256",
    ):
        _sha256(row[key], f"rootfs derivation {key}")
    for key in ("source_diff_id", "derived_diff_id"):
        _oci_digest(row[key], f"rootfs derivation {key}")
    for key in (
        "source_size",
        "derived_size",
        "derived_tar_size",
        "derived_entry_count",
        "removed_cache_size",
    ):
        number = row[key]
        if type(number) is not int or number < 0:
            raise OCIImageLockError(f"rootfs derivation {key} is invalid")
    if row["source_size"] == 0 or row["derived_size"] == 0:
        raise OCIImageLockError("rootfs derivation archives must be non-empty")
    if (
        row["source_sha256"] != asset["sha256"]
        or row["source_sha256"] != source_input["sha256"]
        or row["source_size"] != source_input["size"]
    ):
        raise OCIImageLockError("rootfs derivation does not bind its source input")
    denials = _exact_object(
        row["forbidden_environment"],
        _ENVIRONMENT_DENIAL_KEYS,
        "rootfs derivation environment denials",
    )
    if denials != {"exact_names": ["GLIBC_TUNABLES"], "prefixes": ["LD_"]}:
        raise OCIImageLockError("rootfs derivation environment denials are not exact")
    if row["removed_cache_path"] != "/etc/ld.so.cache":
        raise OCIImageLockError("rootfs derivation cache path is unsupported")

    scope = row["authentication_scope"]
    if scope == elf_closure.AUTHENTICATION_SCOPE:
        expected = {
            "schema_version": ROOTFS_DERIVATION_BINDING_SCHEMA_VERSION,
            "derivation_schema_version": elf_closure.SCHEMA_VERSION,
            "recipe_version": elf_closure.RECIPE_VERSION,
            "authentication_scope": elf_closure.AUTHENTICATION_SCOPE,
            "production_authority": False,
            "source_asset_id": "complete-rootfs",
            "source_reference": elf_closure.SOURCE_REFERENCE,
            "source_sha256": elf_closure.SOURCE_LAYER_SHA256,
            "source_size": elf_closure.SOURCE_LAYER_SIZE,
            "source_diff_id": "sha256:" + elf_closure.SOURCE_DIFF_ID,
            "derived_sha256": elf_closure.DERIVED_LAYER_SHA256,
            "derived_size": elf_closure.DERIVED_LAYER_SIZE,
            "derived_diff_id": "sha256:" + elf_closure.DERIVED_DIFF_ID,
            "derived_tar_size": elf_closure.SOURCE_TAR_SIZE,
            "derived_census_sha256": _PINNED_DERIVED_CENSUS_SHA256,
            "derived_entry_count": _PINNED_DERIVED_ENTRY_COUNT,
            "manifest_sha256": elf_closure.DERIVATION_MANIFEST_SHA256,
            "removed_cache_path": "/etc/ld.so.cache",
            "removed_cache_sha256": _PINNED_REMOVED_CACHE_SHA256,
            "removed_cache_size": _PINNED_REMOVED_CACHE_SIZE,
            "forbidden_environment": {
                "exact_names": ["GLIBC_TUNABLES"],
                "prefixes": ["LD_"],
            },
        }
        if row != expected:
            raise OCIImageLockError("pinned rootfs derivation binding drifted")
    elif scope == "TEST_ONLY_NO_RELEASE_AUTHORITY":
        if (
            row["derivation_schema_version"]
            != _TEST_ONLY_DERIVATION_SCHEMA_VERSION
            or row["recipe_version"] != TEST_ONLY_ROOTFS_DERIVATION_RECIPE
            or row["source_reference"] != "TEST_ONLY_SYNTHETIC_CACHE_FREE_ROOT"
            or row["derived_sha256"] != row["source_sha256"]
            or row["derived_size"] != row["source_size"]
            or row["derived_diff_id"] != row["source_diff_id"]
            or row["derived_tar_size"] != row["source_size"]
            or row["removed_cache_sha256"] != "0" * 64
            or row["removed_cache_size"] != 0
            or row["derived_entry_count"] == 0
        ):
            raise OCIImageLockError("TEST_ONLY rootfs derivation binding is invalid")
        expected_manifest_sha256 = hashlib.sha256(
            _TEST_ONLY_rootfs_derivation_manifest_bytes(row)
        ).hexdigest()
        if not hmac.compare_digest(row["manifest_sha256"], expected_manifest_sha256):
            raise OCIImageLockError("TEST_ONLY derivation manifest digest mismatch")
    else:
        raise OCIImageLockError("rootfs derivation authentication scope is unsupported")
    return row


def _validate_build_inputs(value: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > _MAX_BUILD_INPUTS
    ):
        raise OCIImageLockError("build_inputs count is outside its bound")
    rows: list[dict[str, Any]] = []
    total_size = 0
    for index, value_row in enumerate(value):
        row = _exact_object(value_row, _INPUT_KEYS, f"build input {index}")
        path = _relative_path(row["path"], f"build input {index} path")
        _sha256(row["sha256"], f"build input {index} sha256")
        size = row["size"]
        if type(size) is not int or size < 0:
            raise OCIImageLockError(f"build input {path} size is invalid")
        total_size += size
        if total_size > _MAX_TOTAL_INPUT_BYTES:
            raise OCIImageLockError("build-input byte count exceeds its bound")
        mode = _text(row["mode"], f"build input {path} mode")
        if re.fullmatch(r"0[0-7]{3}", mode) is None:
            raise OCIImageLockError(f"build input {path} mode is malformed")
        numeric_mode = int(mode, 8)
        if numeric_mode & 0o022 or numeric_mode & 0o400 == 0:
            raise OCIImageLockError(
                f"build input {path} mode is writable by others or unreadable"
            )
        rows.append(row)
    paths = [str(row["path"]) for row in rows]
    canonical = sorted(paths, key=lambda item: (item.casefold(), item))
    if paths != canonical:
        raise OCIImageLockError("build_inputs must be canonically sorted")
    if len(set(paths)) != len(paths):
        raise OCIImageLockError("build_inputs contains a duplicate path")
    aliases: dict[str, str] = {}
    for path in paths:
        key = unicodedata.normalize("NFC", path).casefold()
        prior = aliases.get(key)
        if prior is not None:
            raise OCIImageLockError(
                f"build_inputs contains a case/NFC collision: {prior!r}, {path!r}"
            )
        aliases[key] = path
    _expected_input_tree(rows)
    return rows


def _materialization_file(
    value: Any,
    keys: frozenset[str],
    label: str,
    *,
    maximum: int,
) -> dict[str, Any]:
    row = _exact_object(value, keys, label)
    normalized = dict(row)
    normalized["path"] = _relative_path(row["path"], f"{label} path")
    if PurePosixPath(normalized["path"]).parts[0] != "materialization":
        raise OCIImageLockError(
            f"{label} path must be inside the 'materialization' namespace"
        )
    normalized["sha256"] = _sha256(row["sha256"], f"{label} sha256")
    size = row["size"]
    if (
        type(size) is not int
        or isinstance(size, bool)
        or not 0 < size <= maximum
    ):
        raise OCIImageLockError(f"{label} size is outside its bound")
    normalized["size"] = size
    return normalized


def _validate_runtime_materialization(value: Any) -> dict[str, Any]:
    row = _exact_object(
        value, _MATERIALIZATION_KEYS, "runtime materialization"
    )
    if row["schema_version"] != RUNTIME_MATERIALIZATION_SCHEMA_VERSION:
        raise OCIImageLockError(
            "runtime materialization binding schema is unsupported"
        )
    if row["required_roles"] != list(RUNTIME_MATERIALIZATION_REQUIRED_ROLES):
        raise OCIImageLockError(
            "runtime materialization role roster is not exact"
        )
    source_roster_sha256 = _sha256(
        row["source_roster_sha256"],
        "runtime materialization source roster sha256",
    )
    manifest = _materialization_file(
        row["composition_manifest"],
        _MATERIALIZATION_MANIFEST_KEYS,
        "runtime composition manifest",
        maximum=runtime_materializer.MAX_INPUT_BYTES,
    )
    if manifest["schema_version"] != runtime_materializer.SCHEMA_VERSION:
        raise OCIImageLockError(
            "runtime composition manifest schema is unsupported"
        )
    archive = _materialization_file(
        row["archive"],
        _MATERIALIZATION_ARCHIVE_KEYS,
        "materialized runtime archive",
        maximum=runtime_materializer.MAX_INPUT_BYTES,
    )
    if (
        archive["media_type"] != "application/vnd.oci.image.layer.v1.tar"
        or archive["diff_id"] != "sha256:" + archive["sha256"]
    ):
        raise OCIImageLockError(
            "materialized runtime archive media/diffID binding is invalid"
        )
    receipt = _materialization_file(
        row["receipt"],
        _MATERIALIZATION_FILE_KEYS,
        "runtime materialization receipt",
        maximum=2 * 1024 * 1024,
    )
    census = _materialization_file(
        row["census"],
        _MATERIALIZATION_CENSUS_KEYS,
        "installed runtime census",
        maximum=_MAX_ATTESTATION_BYTES,
    )
    if census["schema_version"] != INSTALLED_RUNTIME_CENSUS_SCHEMA_VERSION:
        raise OCIImageLockError("installed runtime census schema is unsupported")
    if (
        type(census["entry_count"]) is not int
        or isinstance(census["entry_count"], bool)
        or not 1 <= census["entry_count"] <= runtime_materializer.MAX_ENTRIES
        or type(census["expanded_bytes"]) is not int
        or isinstance(census["expanded_bytes"], bool)
        or not 0 <= census["expanded_bytes"] <= runtime_materializer.MAX_EXPANDED_BYTES
    ):
        raise OCIImageLockError(
            "installed runtime census bounds are invalid"
        )
    sbom = _materialization_file(
        row["sbom"],
        _MATERIALIZATION_SBOM_KEYS,
        "installed runtime SBOM",
        maximum=_MAX_ATTESTATION_BYTES,
    )
    if sbom["format"] != "spdx-json-2.3":
        raise OCIImageLockError("installed runtime SBOM format is unsupported")
    provenance = _materialization_file(
        row["provenance"],
        _MATERIALIZATION_PROVENANCE_KEYS,
        "installed runtime provenance",
        maximum=_MAX_ATTESTATION_BYTES,
    )
    if provenance["schema_version"] != runtime_materializer.PROVENANCE_SCHEMA_VERSION:
        raise OCIImageLockError(
            "installed runtime provenance schema is unsupported"
        )
    paths = [
        item["path"]
        for item in (manifest, archive, receipt, census, sbom, provenance)
    ]
    if len(set(path.casefold() for path in paths)) != len(paths):
        raise OCIImageLockError(
            "runtime materialization inputs are duplicated or aliased"
        )
    return {
        "schema_version": RUNTIME_MATERIALIZATION_SCHEMA_VERSION,
        "required_roles": list(RUNTIME_MATERIALIZATION_REQUIRED_ROLES),
        "source_roster_sha256": source_roster_sha256,
        "composition_manifest": manifest,
        "archive": archive,
        "receipt": receipt,
        "census": census,
        "sbom": sbom,
        "provenance": provenance,
    }


@_public_boundary("image-lock validation")
def validate_image_lock(payload: Any) -> dict[str, Any]:
    """Validate and return a detached exact-schema lock object."""

    _enforce_json_bounds(payload)
    lock = _exact_object(payload, _TOP_LEVEL_KEYS, "image lock")
    if lock["schema_version"] != SCHEMA_VERSION:
        raise OCIImageLockError("image-lock schema version is unsupported")

    platform_row = _exact_object(lock["platform"], _PLATFORM_KEYS, "platform")
    if platform_row != {"host": APPLE_HOST_PLATFORM, "target": TARGET_PLATFORM}:
        raise OCIImageLockError(
            "image lock must bind the darwin/arm64 to linux/arm64 path"
        )

    image = _exact_object(lock["image"], _IMAGE_KEYS, "image")
    index = _oci_digest(image["index_digest"], "image index digest")
    manifest = _oci_digest(image["manifest_digest"], "image manifest digest")
    if hmac.compare_digest(index, manifest):
        raise OCIImageLockError(
            "image index and selected manifest digests must be distinct"
        )
    _oci_digest(image["config_digest"], "image config digest")
    _sha256(
        image["apple_container_configuration_sha256"],
        "Apple Container configuration digest",
    )
    base_manifest = _oci_digest(
        image["base_manifest_digest"], "base manifest digest"
    )
    _immutable_reference(image["reference"], index, "image reference")
    _immutable_reference(
        image["base_reference"], base_manifest, "base image reference"
    )

    runtime = _exact_object(lock["runtime"], _RUNTIME_KEYS, "runtime")
    cpython = _validate_artifact(
        runtime["cpython"], keys=_ARTIFACT_KEYS, label="CPython"
    )
    if re.fullmatch(r"3\.12\.[0-9]+", str(cpython["version"])) is None:
        raise OCIImageLockError("OCI runtime must pin an exact CPython 3.12 patch")
    backends = _validate_sorted_unique_rows(
        runtime["backend_clis"],
        label="backend_clis",
        id_key="backend",
        keys=_BACKEND_KEYS,
    )
    if {row["backend"] for row in backends} != {"claude", "codex"}:
        raise OCIImageLockError("backend_clis must pin exactly Claude and Codex")
    toolchains = _validate_sorted_unique_rows(
        runtime["toolchains"],
        label="toolchains",
        id_key="toolchain_id",
        keys=_TOOLCHAIN_KEYS,
    )
    assets = _validate_sorted_unique_rows(
        runtime["assets"],
        label="runtime assets",
        id_key="asset_id",
        keys=_ASSET_KEYS,
    )

    attestations = _exact_object(
        lock["attestations"], _ATTESTATION_KEYS, "attestations"
    )
    sbom = _exact_object(attestations["sbom"], _SBOM_KEYS, "SBOM")
    if sbom["format"] not in {"cyclonedx-json", "spdx-json"}:
        raise OCIImageLockError("SBOM format is unsupported")
    _relative_path(sbom["path"], "SBOM path")
    _sha256(sbom["sha256"], "SBOM sha256")
    census = _exact_object(attestations["census"], _CENSUS_KEYS, "census")
    if census["schema_version"] != RUNTIME_CENSUS_SCHEMA_VERSION:
        raise OCIImageLockError("runtime census schema version is unsupported")
    _relative_path(census["path"], "census path")
    _sha256(census["sha256"], "census sha256")
    if sbom["path"] == census["path"]:
        raise OCIImageLockError("SBOM and census must be distinct inputs")

    runtime_materialization = _validate_runtime_materialization(
        lock["runtime_materialization"]
    )

    policies = _exact_object(lock["policies"], _POLICY_KEYS, "policies")
    if policies != _REQUIRED_POLICIES:
        raise OCIImageLockError("OCI image policies must be exact deny-by-default")
    inputs = _validate_build_inputs(lock["build_inputs"])
    input_by_path = {str(row["path"]): row for row in inputs}
    referenced = [
        cpython,
        *backends,
        *toolchains,
        *assets,
        sbom,
        census,
        runtime_materialization["composition_manifest"],
        runtime_materialization["archive"],
        runtime_materialization["receipt"],
        runtime_materialization["census"],
        runtime_materialization["sbom"],
        runtime_materialization["provenance"],
    ]
    role_namespaces = [
        (cpython, "artifacts", "CPython"),
        *((row, "backends", f"backend {row['backend']}") for row in backends),
        *((row, "toolchains", f"toolchain {row['toolchain_id']}") for row in toolchains),
        *((row, "runtime", f"runtime asset {row['asset_id']}") for row in assets),
        (sbom, "attestations", "SBOM"),
        (census, "attestations", "runtime census"),
        (
            runtime_materialization["composition_manifest"],
            "materialization",
            "runtime composition manifest",
        ),
        (
            runtime_materialization["archive"],
            "materialization",
            "materialized runtime archive",
        ),
        (
            runtime_materialization["receipt"],
            "materialization",
            "runtime materialization receipt",
        ),
        (
            runtime_materialization["census"],
            "materialization",
            "installed runtime census",
        ),
        (
            runtime_materialization["sbom"],
            "materialization",
            "installed runtime SBOM",
        ),
        (
            runtime_materialization["provenance"],
            "materialization",
            "installed runtime provenance",
        ),
    ]
    for row, namespace, label in role_namespaces:
        if PurePosixPath(str(row["path"])).parts[0] != namespace:
            raise OCIImageLockError(
                f"{label} path must be inside the {namespace!r} namespace"
            )
    for row in referenced:
        path = str(row["path"])
        source = input_by_path.get(path)
        if source is None or source["sha256"] != row["sha256"]:
            raise OCIImageLockError(
                f"pinned artifact {path!r} is absent or disagrees with build_inputs"
            )
    referenced_paths = [str(row["path"]) for row in referenced]
    referenced_digests = [str(row["sha256"]) for row in referenced]
    if len(set(referenced_paths)) != len(referenced_paths):
        raise OCIImageLockError(
            "runtime, backend, toolchain, asset, and attestation paths must be exclusive"
        )
    if len(set(referenced_digests)) != len(referenced_digests):
        raise OCIImageLockError(
            "runtime, backend, toolchain, asset, and attestation digests must be exclusive"
        )
    if set(input_by_path) != set(referenced_paths):
        raise OCIImageLockError(
            "build_inputs must be the exact closed roster of pinned artifacts"
        )
    _validate_rootfs_derivation(
        lock["rootfs_derivation"], assets=assets, inputs=input_by_path
    )

    lock_digest = _sha256(lock["lock_sha256"], "lock sha256")
    expected_digest = canonical_lock_sha256(lock)
    if lock_digest != expected_digest:
        raise OCIImageLockError("image-lock canonical digest mismatch")
    # Canonical round-trip also detaches caller-owned dict/list identities.
    return json.loads(_canonical_bytes(lock).decode("utf-8"))


@_public_boundary("image-lock sealing")
def seal_image_lock(unsigned_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Attach the canonical digest to an otherwise complete lock body."""

    if not isinstance(unsigned_payload, Mapping) or "lock_sha256" in unsigned_payload:
        raise OCIImageLockError("unsigned image lock must omit lock_sha256")
    candidate = dict(unsigned_payload)
    candidate["lock_sha256"] = canonical_lock_sha256(candidate)
    return validate_image_lock(candidate)


def _default_metadata_inspector() -> MetadataInspector | None:
    if sys.platform == "darwin":
        # Always use Darwin's descriptor-native API directly.  Public Python
        # wrappers have no options parameter and can hide HFS compression
        # metadata unless XATTR_SHOWCOMPRESSION is requested explicitly.
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        libc.flistxattr.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        libc.flistxattr.restype = ctypes.c_ssize_t

        def inspect(descriptor: int) -> Sequence[str | bytes]:
            size = int(
                libc.flistxattr(
                    descriptor,
                    None,
                    0,
                    _XATTR_SHOWCOMPRESSION,
                )
            )
            if size < 0:
                raise OSError(
                    ctypes.get_errno(),
                    "descriptor-relative Darwin xattr inspection failed",
                )
            return () if size == 0 else (b"<extended-metadata-present>",)

        return inspect

    provider = getattr(os, "listxattr", None)
    supports_fd = getattr(os, "supports_fd", ())
    if provider is not None and provider in supports_fd:
        def inspect(descriptor: int) -> Sequence[str | bytes]:
            return provider(descriptor)

        return inspect
    return None


def _assert_no_extended_metadata(
    descriptor: int,
    *,
    inspector: MetadataInspector,
    label: str,
) -> None:
    try:
        values = iter(inspector(descriptor))
    except OSError as exc:
        raise OCIImageLockError(
            f"extended metadata for {label} cannot be inspected"
        ) from exc
    try:
        for index, _value in enumerate(values):
            if index >= 1_024:
                raise OCIImageLockError(
                    f"extended metadata for {label} exceeds its bound"
                )
            raise OCIImageLockError(
                f"extended metadata is forbidden for {label}"
            )
    except OSError as exc:
        raise OCIImageLockError(
            f"extended metadata for {label} cannot be inspected"
        ) from exc


def _file_sha256(descriptor: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    observed = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while observed < expected_size:
        chunk = os.read(descriptor, min(_READ_CHUNK, expected_size - observed))
        if not chunk:
            raise OCIImageLockError("build input was truncated during hashing")
        digest.update(chunk)
        observed += len(chunk)
    if os.read(descriptor, 1):
        raise OCIImageLockError("build input grew during hashing")
    return digest.hexdigest()


def _snapshot_file(descriptor: int, expected_size: int) -> tuple[int, str]:
    """Copy one admitted file into an unlinked O_RDONLY snapshot descriptor."""

    snapshot_descriptor, snapshot_path = tempfile.mkstemp(
        prefix=".plamen-build-input-snapshot-"
    )
    retained_descriptor = -1
    unlinked = False
    try:
        os.set_inheritable(snapshot_descriptor, False)
        os.fchmod(snapshot_descriptor, 0o400)
        digest = hashlib.sha256()
        observed = 0
        os.lseek(descriptor, 0, os.SEEK_SET)
        while observed < expected_size:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK, expected_size - observed),
            )
            if not chunk:
                raise OCIImageLockError(
                    "build input was truncated during snapshotting"
                )
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot_descriptor, view)
                if written <= 0:
                    raise OCIImageLockError(
                        "immutable build-input snapshot could not be written"
                    )
                view = view[written:]
            observed += len(chunk)
        if os.read(descriptor, 1):
            raise OCIImageLockError("build input grew during snapshotting")
        os.fsync(snapshot_descriptor)
        written_identity = _stable_identity(os.fstat(snapshot_descriptor))
        retained_descriptor = os.open(
            snapshot_path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        os.set_inheritable(retained_descriptor, False)
        if _stable_identity(os.fstat(retained_descriptor)) != written_identity:
            raise OCIImageLockError("build-input snapshot path was substituted")
        os.unlink(snapshot_path)
        unlinked = True
        os.lseek(retained_descriptor, 0, os.SEEK_SET)
        return retained_descriptor, digest.hexdigest()
    except BaseException:
        if retained_descriptor >= 0:
            os.close(retained_descriptor)
        raise
    finally:
        os.close(snapshot_descriptor)
        if not unlinked:
            try:
                os.unlink(snapshot_path)
            except OSError:
                pass


def _stable_identity(row: os.stat_result) -> tuple[int, ...]:
    return (
        int(row.st_dev),
        int(row.st_ino),
        stat.S_IFMT(row.st_mode),
        stat.S_IMODE(row.st_mode),
        int(row.st_uid),
        int(row.st_gid),
        int(row.st_size),
        int(row.st_nlink),
        int(row.st_mtime_ns),
        int(row.st_ctime_ns),
        int(getattr(row, "st_flags", 0)),
    )


def _namespace_identity(row: os.stat_result) -> tuple[int, int, int]:
    """Identity fields that do not drift on unrelated directory mutations."""

    return (int(row.st_dev), int(row.st_ino), stat.S_IFMT(row.st_mode))


def _host_platform() -> str:
    architecture = platform.machine().casefold()
    normalized_architecture = "arm64" if architecture in {"arm64", "aarch64"} else architecture
    host = "darwin" if sys.platform == "darwin" else sys.platform.casefold()
    return f"{host}/{normalized_architecture}"


@dataclass
class _ExpectedDirectory:
    directories: dict[str, "_ExpectedDirectory"]
    files: dict[str, dict[str, Any]]
    spellings: dict[str, str]


def _expected_input_tree(
    expected_rows: Sequence[dict[str, Any]],
) -> _ExpectedDirectory:
    root = _ExpectedDirectory({}, {}, {})
    for row in expected_rows:
        parts = PurePosixPath(str(row["path"])).parts
        node = root
        for component in parts[:-1]:
            folded = component.casefold()
            prior = node.spellings.get(folded)
            if prior is not None and prior != component:
                raise OCIImageLockError(
                    f"build path components case/NFC collide: {prior!r}, {component!r}"
                )
            node.spellings[folded] = component
            if component in node.files:
                raise OCIImageLockError(
                    f"build input {row['path']!r} descends from a file"
                )
            node = node.directories.setdefault(
                component,
                _ExpectedDirectory({}, {}, {}),
            )
        leaf = parts[-1]
        folded = leaf.casefold()
        prior = node.spellings.get(folded)
        if prior is not None and prior != leaf:
            raise OCIImageLockError(
                f"build path components case/NFC collide: {prior!r}, {leaf!r}"
            )
        node.spellings[folded] = leaf
        if leaf in node.directories:
            raise OCIImageLockError(
                f"build input {row['path']!r} aliases a directory"
            )
        node.files[leaf] = row
    return root


def _open_root_without_aliases(
    root: Path,
) -> tuple[list[int], list[tuple[int, str, int, tuple[int, int, int]]]]:
    """Open every absolute-root component without following a symlink."""

    required = (
        hasattr(os, "O_DIRECTORY"),
        hasattr(os, "O_NOFOLLOW"),
        os.open in os.supports_dir_fd,
        os.stat in os.supports_dir_fd,
        os.stat in os.supports_follow_symlinks,
    )
    rendered = os.fspath(root)
    canonical = os.path.normpath(rendered) if isinstance(rendered, str) else None
    if (
        not all(required)
        or not isinstance(canonical, str)
        or not os.path.isabs(rendered)
        or rendered != canonical
        or canonical == os.sep
        or canonical.startswith(os.sep * 2)
        or "\x00" in canonical
        or unicodedata.normalize("NFC", canonical) != canonical
    ):
        raise OCIImageLockError(
            "build root must be a canonical absolute no-follow path"
        )
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    opened: list[int] = []
    relationships: list[tuple[int, str, int, tuple[int, int, int]]] = []
    try:
        parent = os.open(os.sep, flags)
        opened.append(parent)
        for component in (item for item in canonical.split(os.sep) if item):
            try:
                named = os.stat(
                    component,
                    dir_fd=parent,
                    follow_symlinks=False,
                )
                if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
                    raise OCIImageLockError(
                        "build root contains an aliased or non-directory ancestor"
                    )
                child = os.open(component, flags, dir_fd=parent)
            except OCIImageLockError:
                raise
            except OSError as exc:
                raise OCIImageLockError(
                    "build root cannot be opened without following aliases"
                ) from exc
            identity = _namespace_identity(named)
            if _namespace_identity(os.fstat(child)) != identity:
                os.close(child)
                raise OCIImageLockError(
                    "build-root ancestor changed during admission"
                )
            opened.append(child)
            relationships.append((parent, component, child, identity))
            parent = child
        return opened, relationships
    except BaseException:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _revalidate_root_relationships(
    relationships: Sequence[tuple[int, str, int, tuple[int, int, int]]],
) -> None:
    for parent, component, child, identity in relationships:
        try:
            named = os.stat(
                component,
                dir_fd=parent,
                follow_symlinks=False,
            )
            opened = os.fstat(child)
        except OSError as exc:
            raise OCIImageLockError(
                "build-root ancestor changed during census"
            ) from exc
        if (
            _namespace_identity(named) != identity
            or _namespace_identity(opened) != identity
        ):
            raise OCIImageLockError("build-root ancestor changed during census")


def _runtime_binding_rows(lock: Mapping[str, Any]) -> list[dict[str, Any]]:
    runtime = lock["runtime"]
    rows = [
        {
            "artifact_id": "cpython",
            "path": runtime["cpython"]["path"],
            "role": "cpython",
            "sha256": runtime["cpython"]["sha256"],
            "version": runtime["cpython"]["version"],
        }
    ]
    rows.extend(
        {
            "artifact_id": row["backend"],
            "path": row["path"],
            "role": "backend_cli",
            "sha256": row["sha256"],
            "version": row["version"],
        }
        for row in runtime["backend_clis"]
    )
    rows.extend(
        {
            "artifact_id": row["toolchain_id"],
            "path": row["path"],
            "role": "toolchain",
            "sha256": row["sha256"],
            "version": row["version"],
        }
        for row in runtime["toolchains"]
    )
    rows.extend(
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
    rows.append(
        {
            "artifact_id": "cache-free-rootfs-derivation",
            "path": "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json",
            "role": "generated_attestation",
            "sha256": derivation["manifest_sha256"],
            "version": derivation["recipe_version"],
        }
    )
    return sorted(
        rows,
        key=lambda row: (str(row["role"]), str(row["artifact_id"])),
    )


def _read_retained_json(row: _RetainedInput, label: str) -> Any:
    if row.size > _MAX_ATTESTATION_BYTES:
        raise OCIImageLockError(f"{label} exceeds its byte bound")
    os.lseek(row.descriptor, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) < row.size:
        chunk = os.read(
            row.descriptor,
            min(_READ_CHUNK, row.size - len(raw)),
        )
        if not chunk:
            raise OCIImageLockError(f"{label} was truncated")
        raw.extend(chunk)
    if os.read(row.descriptor, 1):
        raise OCIImageLockError(f"{label} grew while being inspected")
    encoded = bytes(raw)
    try:
        value = json.loads(
            encoded.decode("utf-8", "strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except OCIImageLockError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise OCIImageLockError(f"{label} is malformed JSON") from exc
    _bounded_json_tree(value)
    if encoded != _canonical_bytes(value):
        raise OCIImageLockError(f"{label} is not canonical JSON")
    return value


def _read_retained_bytes(
    row: _RetainedInput,
    label: str,
    *,
    maximum: int,
) -> bytes:
    if row.size > maximum:
        raise OCIImageLockError(f"{label} exceeds its byte bound")
    os.lseek(row.descriptor, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) < row.size:
        chunk = os.read(
            row.descriptor,
            min(_READ_CHUNK, row.size - len(raw)),
        )
        if not chunk:
            raise OCIImageLockError(f"{label} was truncated")
        raw.extend(chunk)
    if os.read(row.descriptor, 1):
        raise OCIImageLockError(f"{label} grew while being inspected")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), row.sha256):
        raise OCIImageLockError(f"{label} digest changed")
    return bytes(raw)


def _validate_runtime_materialization_documents(
    lock: Mapping[str, Any],
    retained: Sequence[_RetainedInput],
) -> None:
    binding = lock["runtime_materialization"]
    by_path = {row.path: row for row in retained}
    manifest_row = by_path[binding["composition_manifest"]["path"]]
    archive_row = by_path[binding["archive"]["path"]]
    receipt_row = by_path[binding["receipt"]["path"]]
    census_row = by_path[binding["census"]["path"]]
    sbom_row = by_path[binding["sbom"]["path"]]
    provenance_row = by_path[binding["provenance"]["path"]]
    manifest_raw = _read_retained_bytes(
        manifest_row,
        "runtime composition manifest",
        maximum=runtime_materializer.MAX_INPUT_BYTES,
    )
    receipt_raw = _read_retained_bytes(
        receipt_row,
        "runtime materialization receipt",
        maximum=2 * 1024 * 1024,
    )
    census_raw = _read_retained_bytes(
        census_row,
        "installed runtime census",
        maximum=_MAX_ATTESTATION_BYTES,
    )
    sbom_raw = _read_retained_bytes(
        sbom_row,
        "installed runtime SBOM",
        maximum=_MAX_ATTESTATION_BYTES,
    )
    provenance_raw = _read_retained_bytes(
        provenance_row,
        "installed runtime provenance",
        maximum=_MAX_ATTESTATION_BYTES,
    )
    try:
        runtime_materializer._TEST_ONLY_verify_materialized_runtime(
            archive_row.descriptor,
            composition_manifest_bytes=manifest_raw,
            receipt_bytes=receipt_raw,
            census_bytes=census_raw,
            sbom_bytes=sbom_raw,
            provenance_bytes=provenance_raw,
            expected_manifest_sha256=binding["composition_manifest"]["sha256"],
        )
    except runtime_materializer.RuntimeMaterializationError as exc:
        raise OCIImageLockError(
            "retained runtime materialization evidence failed verification"
        ) from exc
    receipt = _read_retained_json(
        receipt_row, "runtime materialization receipt"
    )
    archive = receipt.get("archive") if isinstance(receipt, dict) else None
    installed = receipt.get("installed") if isinstance(receipt, dict) else None
    if (
        receipt.get("source_roster_sha256")
        != binding["source_roster_sha256"]
        or archive
        != {
            "diff_id": binding["archive"]["diff_id"],
            "media_type": binding["archive"]["media_type"],
            "sha256": binding["archive"]["sha256"],
            "size": binding["archive"]["size"],
        }
        or not isinstance(installed, dict)
        or installed.get("census_sha256") != binding["census"]["sha256"]
        or installed.get("sbom_sha256") != binding["sbom"]["sha256"]
        or installed.get("provenance_sha256")
        != binding["provenance"]["sha256"]
        or installed.get("entry_count") != binding["census"]["entry_count"]
        or installed.get("expanded_bytes")
        != binding["census"]["expanded_bytes"]
    ):
        raise OCIImageLockError(
            "runtime materialization receipt differs from its lock binding"
        )


def _validate_sbom_bindings(
    value: Mapping[str, Any],
    sbom_format: str,
    bindings: Sequence[dict[str, Any]],
) -> None:
    if sbom_format == "spdx-json":
        expected: Mapping[str, Any] = {
            "packages": [
                {
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": row["sha256"],
                        }
                    ],
                    "name": f"{row['role']}:{row['artifact_id']}",
                    "versionInfo": row["version"] or "content-addressed",
                }
                for row in bindings
            ],
            "spdxVersion": _SPDX_VERSION,
        }
    else:
        expected = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "hashes": [
                        {"alg": "SHA-256", "content": row["sha256"]}
                    ],
                    "name": f"{row['role']}:{row['artifact_id']}",
                    "version": row["version"] or "content-addressed",
                }
                for row in bindings
            ],
            "specVersion": _CYCLONEDX_VERSION,
        }
    if value != expected:
        raise OCIImageLockError(
            "SBOM must exactly equal the pinned package/component/checksum closure"
        )

def _validate_attestation_documents(
    lock: Mapping[str, Any],
    retained: Sequence[_RetainedInput],
) -> None:
    by_path = {row.path: row for row in retained}
    sbom_spec = lock["attestations"]["sbom"]
    census_spec = lock["attestations"]["census"]
    sbom = _read_retained_json(by_path[sbom_spec["path"]], "SBOM")
    if not isinstance(sbom, dict):
        raise OCIImageLockError("SBOM must be a JSON object")
    if sbom_spec["format"] == "spdx-json":
        if (
            sbom.get("spdxVersion") != _SPDX_VERSION
            or not isinstance(sbom.get("packages"), list)
            or any(not isinstance(row, dict) for row in sbom["packages"])
        ):
            raise OCIImageLockError("SBOM does not satisfy the SPDX JSON schema minimum")
    elif (
        sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != _CYCLONEDX_VERSION
        or not isinstance(sbom.get("components"), list)
        or any(not isinstance(row, dict) for row in sbom["components"])
    ):
        raise OCIImageLockError(
            "SBOM does not satisfy the CycloneDX JSON schema minimum"
        )
    bindings = _runtime_binding_rows(lock)
    _validate_sbom_bindings(sbom, str(sbom_spec["format"]), bindings)

    census = _read_retained_json(
        by_path[census_spec["path"]],
        "runtime census",
    )
    expected_census = {
        "artifacts": _runtime_binding_rows(lock),
        "schema_version": RUNTIME_CENSUS_SCHEMA_VERSION,
    }
    if census != expected_census:
        raise OCIImageLockError(
            "runtime census does not exactly bind the pinned runtime artifacts"
        )


def _observe_build_context(
    root: Path,
    lock: Mapping[str, Any],
    expected_rows: list[dict[str, Any]],
    *,
    metadata_inspector: MetadataInspector,
) -> tuple[list[dict[str, Any]], _BuildContextAuthority]:
    expected = {str(row["path"]): row for row in expected_rows}
    expected_tree = _expected_input_tree(expected_rows)
    attestation_paths = {
        str(lock["attestations"]["sbom"]["path"]),
        str(lock["attestations"]["census"]["path"]),
    }

    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    root_descriptors, root_relationships = _open_root_without_aliases(root)
    root_descriptor = root_descriptors[-1]
    observed: list[dict[str, Any]] = []
    retained: list[_RetainedInput] = []
    seen_spellings: dict[str, str] = {}
    observed_total = 0
    transferred = False
    try:
        opened_root = os.fstat(root_descriptor)
        _assert_no_extended_metadata(
            root_descriptor, inspector=metadata_inspector, label="build root"
        )

        def walk(
            directory_descriptor: int,
            prefix: PurePosixPath,
            expected_directory: _ExpectedDirectory,
        ) -> None:
            nonlocal observed_total
            maximum_entries = (
                len(expected_directory.directories)
                + len(expected_directory.files)
            )
            try:
                entries = []
                with os.scandir(directory_descriptor) as iterator:
                    for entry in iterator:
                        entries.append(entry)
                        if len(entries) > maximum_entries:
                            raise OCIImageLockError(
                                "build directory contains an unlisted entry"
                            )
                entries.sort(key=lambda row: row.name)
            except OCIImageLockError:
                raise
            except OSError as exc:
                raise OCIImageLockError("build directory cannot be enumerated") from exc
            for entry in entries:
                name = entry.name
                if (
                    not name
                    or name in {".", ".."}
                    or "/" in name
                    or "\\" in name
                    or unicodedata.normalize("NFC", name) != name
                ):
                    raise OCIImageLockError("physical build path is non-canonical")
                relative = (prefix / name).as_posix()
                folded = unicodedata.normalize("NFC", relative).casefold()
                prior = seen_spellings.get(folded)
                if prior is not None:
                    raise OCIImageLockError(
                        f"physical build paths case/NFC collide: {prior!r}, {relative!r}"
                    )
                seen_spellings[folded] = relative
                try:
                    initial = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise OCIImageLockError(
                        f"build input {relative!r} cannot be observed"
                    ) from exc
                if stat.S_ISLNK(initial.st_mode):
                    raise OCIImageLockError(f"build input {relative!r} is a symlink")
                if stat.S_ISDIR(initial.st_mode):
                    expected_child = expected_directory.directories.get(name)
                    if expected_child is None:
                        raise OCIImageLockError(
                            f"unlisted build directory {relative!r}"
                        )
                    try:
                        child = os.open(
                            name,
                            directory_flags,
                            dir_fd=directory_descriptor,
                        )
                    except OSError as exc:
                        raise OCIImageLockError(
                            f"build directory {relative!r} cannot be opened"
                        ) from exc
                    try:
                        if _stable_identity(os.fstat(child)) != _stable_identity(initial):
                            raise OCIImageLockError(
                                f"build directory {relative!r} changed during admission"
                            )
                        _assert_no_extended_metadata(
                            child,
                            inspector=metadata_inspector,
                            label=f"build directory {relative!r}",
                        )
                        walk(child, PurePosixPath(relative), expected_child)
                        if _stable_identity(os.fstat(child)) != _stable_identity(initial):
                            raise OCIImageLockError(
                                f"build directory {relative!r} changed during census"
                            )
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(initial.st_mode):
                    raise OCIImageLockError(
                        f"build input {relative!r} is not an ordinary file"
                    )
                expected_row = expected_directory.files.get(name)
                if expected_row is None:
                    raise OCIImageLockError(f"unlisted build input {relative!r}")
                try:
                    descriptor = os.open(
                        name,
                        file_flags,
                        dir_fd=directory_descriptor,
                    )
                except OSError as exc:
                    raise OCIImageLockError(
                        f"build input {relative!r} cannot be opened"
                    ) from exc
                try:
                    opened = os.fstat(descriptor)
                    if _stable_identity(opened) != _stable_identity(initial):
                        raise OCIImageLockError(
                            f"build input {relative!r} changed during admission"
                        )
                    if int(opened.st_nlink) != 1:
                        raise OCIImageLockError(
                            f"build input {relative!r} has a hardlink alias"
                        )
                    actual_size = int(opened.st_size)
                    actual_mode = f"0{stat.S_IMODE(opened.st_mode):03o}"
                    if (
                        actual_size != expected_row["size"]
                        or actual_mode != expected_row["mode"]
                    ):
                        raise OCIImageLockError(
                            f"build input {relative!r} drifted from its lock"
                        )
                    if (
                        relative in attestation_paths
                        and actual_size > _MAX_ATTESTATION_BYTES
                    ):
                        raise OCIImageLockError(
                            f"attestation {relative!r} exceeds its byte bound"
                        )
                    observed_total += actual_size
                    if observed_total > _MAX_TOTAL_INPUT_BYTES:
                        raise OCIImageLockError(
                            "observed build-input byte count exceeds its bound"
                        )
                    _assert_no_extended_metadata(
                        descriptor,
                        inspector=metadata_inspector,
                        label=f"build input {relative!r}",
                    )
                    snapshot_descriptor, digest = _snapshot_file(
                        descriptor,
                        actual_size,
                    )
                    after = os.fstat(descriptor)
                    if (
                        _stable_identity(after) != _stable_identity(opened)
                        or digest != expected_row["sha256"]
                    ):
                        os.close(snapshot_descriptor)
                        raise OCIImageLockError(
                            f"build input {relative!r} changed during snapshotting"
                        )
                    observed_row = {
                        "path": relative,
                        "sha256": digest,
                        "size": actual_size,
                        "mode": actual_mode,
                    }
                    if observed_row != expected_row:
                        os.close(snapshot_descriptor)
                        raise OCIImageLockError(
                            f"build input {relative!r} drifted from its lock"
                        )
                    try:
                        snapshot_identity = _stable_identity(
                            os.fstat(snapshot_descriptor)
                        )
                        _assert_no_extended_metadata(
                            snapshot_descriptor,
                            inspector=metadata_inspector,
                            label=f"immutable snapshot {relative!r}",
                        )
                        observed.append(observed_row)
                        retained.append(
                            _RetainedInput(
                                path=relative,
                                sha256=digest,
                                size=actual_size,
                                mode=actual_mode,
                                descriptor=snapshot_descriptor,
                                identity=snapshot_identity,
                            )
                        )
                    except BaseException:
                        os.close(snapshot_descriptor)
                        raise
                finally:
                    os.close(descriptor)

        walk(root_descriptor, PurePosixPath("."), expected_tree)
        missing = sorted(set(expected) - {str(row["path"]) for row in observed})
        if missing:
            raise OCIImageLockError(f"locked build inputs are missing: {missing}")
        if (
            _stable_identity(os.fstat(root_descriptor)) != _stable_identity(opened_root)
        ):
            raise OCIImageLockError("build-root identity changed during census")
        _revalidate_root_relationships(root_relationships)
        observed.sort(key=lambda row: (row["path"].casefold(), row["path"]))
        retained.sort(key=lambda row: (row.path.casefold(), row.path))
        _validate_attestation_documents(lock, retained)
        _validate_runtime_materialization_documents(lock, retained)
        authority = _BuildContextAuthority(
            retained,
            metadata_inspector=metadata_inspector,
        )
        transferred = True
        return observed, authority
    finally:
        for descriptor in reversed(root_descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if not transferred:
            for row in retained:
                try:
                    os.close(row.descriptor)
                except OSError:
                    pass


def _render_test_build_plan(
    lock: Mapping[str, Any],
    build_root: str | Path,
    *,
    release_generation: int,
    release_nonce: str,
) -> _TestingOCIValidatedBuildPlan:
    """Render a visibly non-production plan for bounded unit testing only."""

    if _host_platform() != APPLE_HOST_PLATFORM:
        raise OCIImageLockError(
            "OCI image lock platform mismatch: expected darwin/arm64 -> linux/arm64"
        )
    inspector = _default_metadata_inspector()
    if inspector is None:
        raise OCIImageLockError(
            "extended-metadata inspection is unavailable; build plan fails closed"
        )
    root = Path(build_root)
    observed, authority = _observe_build_context(
        root,
        lock,
        lock["build_inputs"],
        metadata_inspector=inspector,
    )
    try:
        observed_census_sha256 = hashlib.sha256(
            _canonical_bytes(observed)
        ).hexdigest()
        plan: dict[str, Any] = {
            "schema_version": BUILD_PLAN_SCHEMA_VERSION,
            "authentication_scope": "TEST_ONLY_NO_RELEASE_AUTHORITY",
            "lock_sha256": lock["lock_sha256"],
            "release_generation": release_generation,
            "release_nonce": release_nonce,
            "host_platform": APPLE_HOST_PLATFORM,
            "target_platform": TARGET_PLATFORM,
            "base_image_reference": lock["image"]["base_reference"],
            "expected_image_reference": lock["image"]["reference"],
            "expected_index_digest": lock["image"]["index_digest"],
            "expected_manifest_digest": lock["image"]["manifest_digest"],
            "expected_config_digest": lock["image"]["config_digest"],
            "expected_apple_container_configuration_sha256": lock["image"][
                "apple_container_configuration_sha256"
            ],
            "runtime": lock["runtime"],
            "rootfs_derivation": lock["rootfs_derivation"],
            "attestations": lock["attestations"],
            "runtime_materialization": lock["runtime_materialization"],
            "network": "DENY",
            "runtime_package_resolution": "DENY",
            "build_input_admission": "EXACT_ROSTER",
            "build_context_authority": "ONE_SHOT_RETAINED_INPUT_READERS",
            "observed_build_input_census_sha256": observed_census_sha256,
            "build_inputs": observed,
            "executor_requirements": [
                "CONSUME_RETAINED_BUILD_CONTEXT_AUTHORITY_ONCE",
                "ENFORCE_NETWORK_NONE",
                "VERIFY_OUTPUT_MANIFEST_DIGEST",
                "VERIFY_SBOM_AND_INSTALLED_RUNTIME_CENSUS",
            ],
        }
        plan["plan_sha256"] = hashlib.sha256(_canonical_bytes(plan)).hexdigest()
        return _TestingOCIValidatedBuildPlan(plan, authority)
    except BaseException:
        authority.close()
        raise


def _validate_testing_release_claim(
    *,
    observed_lock_sha256: str,
    expected_lock_sha256: str,
    release_generation: int,
    release_nonce: str,
    durable_replay_consumer: DurableReplayConsumer,
) -> None:
    """Validate synthetic release fields for tests without issuing authority."""

    expected = _sha256(expected_lock_sha256, "trusted lock sha256")
    if not hmac.compare_digest(expected, observed_lock_sha256):
        raise OCIImageLockError("image lock is not the authenticated release lock")
    if (
        isinstance(release_generation, bool)
        or not isinstance(release_generation, int)
        or not 1 <= release_generation <= (2**63 - 1)
    ):
        raise OCIImageLockError("release generation is outside its bound")
    if (
        not isinstance(release_nonce, str)
        or _RELEASE_NONCE.fullmatch(release_nonce) is None
    ):
        raise OCIImageLockError("release nonce is not canonical")
    if not callable(durable_replay_consumer):
        raise OCIImageLockError("durable replay consumer must be callable")
    try:
        accepted = durable_replay_consumer(
            release_generation,
            release_nonce,
            expected,
        )
    except Exception:
        raise OCIImageLockError(
            "durable release replay admission failed closed"
        ) from None
    if accepted is not True:
        raise OCIImageLockError(
            "release generation or nonce was already consumed"
        )


@_public_boundary("test OCI build-plan rendering")
def _render_build_plan_for_testing(
    lock_payload: Mapping[str, Any],
    build_root: str | Path,
    *,
    expected_lock_sha256: str,
    release_generation: int,
    release_nonce: str,
    durable_replay_consumer: DurableReplayConsumer,
) -> _TestingOCIValidatedBuildPlan:
    """Exercise plan mechanics without claiming production authentication.

    This seam is intentionally excluded from ``__all__`` and returns a
    distinct type.  Production consumers must reject subclasses and accept
    only an exact ``OCIValidatedBuildPlan`` after native receipt verification.
    """

    lock = validate_image_lock(lock_payload)
    _validate_testing_release_claim(
        observed_lock_sha256=str(lock["lock_sha256"]),
        expected_lock_sha256=expected_lock_sha256,
        release_generation=release_generation,
        release_nonce=release_nonce,
        durable_replay_consumer=durable_replay_consumer,
    )
    return _render_test_build_plan(
        lock,
        build_root,
        release_generation=release_generation,
        release_nonce=release_nonce,
    )


def _make_fail_closed_production_renderer() -> Callable[..., OCIValidatedBuildPlan]:
    """Capture an unavailable verifier so monkeypatching globals cannot enable it.

    The compiled/out-of-process integration must replace this factory output
    in a reviewed build.  There is deliberately no Python registration or
    issuer function: an ordinary module caller cannot mint a release receipt.
    A hostile caller able to mutate function closure cells/native memory is
    outside the declared trusted-interpreter boundary and must be isolated in
    another process.
    """

    def verify_release_receipt(
        _receipt: object,
        _observed_lock_sha256: str,
    ) -> tuple[int, str]:
        raise OCIImageLockError(_RELEASE_VERIFIER_REQUIRED)

    @_public_boundary("OCI build-plan rendering")
    def production_renderer(
        lock_payload: Mapping[str, Any],
        build_root: str | Path,
        *,
        authenticated_release_receipt: object,
    ) -> OCIValidatedBuildPlan:
        lock = validate_image_lock(lock_payload)
        generation, nonce = verify_release_receipt(
            authenticated_release_receipt,
            str(lock["lock_sha256"]),
        )
        # Unreachable in this frozen Python seam.  The reviewed native
        # integration must own both receipt verification and construction of
        # the exact production plan type; Python must not expose a constructor
        # helper that converts caller-supplied claims into production authority.
        del lock, build_root, generation, nonce
        raise OCIImageLockError(_RELEASE_VERIFIER_REQUIRED)

    return production_renderer


render_build_plan = _make_fail_closed_production_renderer()
render_build_plan.__name__ = "render_build_plan"
render_build_plan.__qualname__ = "render_build_plan"
del _make_fail_closed_production_renderer


__all__ = [
    "APPLE_HOST_PLATFORM",
    "BUILD_PLAN_SCHEMA_VERSION",
    "OCIValidatedBuildPlan",
    "OCIImageLockError",
    "RUNTIME_CENSUS_SCHEMA_VERSION",
    "ROOTFS_DERIVATION_BINDING_SCHEMA_VERSION",
    "SCHEMA_VERSION",
    "TARGET_PLATFORM",
    "TEST_ONLY_ROOTFS_DERIVATION_RECIPE",
    "canonical_lock_sha256",
    "parse_image_lock",
    "render_build_plan",
    "seal_image_lock",
    "validate_image_lock",
]
