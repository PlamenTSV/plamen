"""Deterministic, parent-bound source-manifest authority for Program Facts.

The builder deliberately consumes the existing audit-snapshot source selector.
There is no fallback filesystem walker: if that shared implementation is not
available, manifest authority fails closed.  The receipt-compatible
``source_manifest`` remains nested unchanged while this module's authority
envelope binds replay inputs, selection policy, parent snapshot identity,
compiled-denominator coverage, and typed debt.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import inspect
import os
from pathlib import Path
import re
import stat
import threading
from types import CodeType, FunctionType, MappingProxyType
from typing import Any, NoReturn
import unicodedata

import audit_snapshot as _audit_snapshot
import production_source_scope as _production_source_scope
from plamen_types import (
    ALL_AUDIT_SOURCE_SUFFIXES,
    L1_SOURCE_SUFFIXES,
    SOURCE_SUFFIXES_BY_ECOSYSTEM,
    normalize_scope_match_mode,
)
from program_facts_types import (
    CANONICALIZATION_VERSION,
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    derive_source_manifest_digest,
    derive_stable_id,
    strict_json_loads,
    validate_portable_path,
)
from production_source_scope import is_production_source_path


SOURCE_MANIFEST_AUTHORITY_SCHEMA = (
    "plamen.program-facts-source-manifest-authority.v1"
)
SOURCE_MANIFEST_POLICY_VERSION = "plamen.program_facts_source_scope.v1"
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_LINE_STARTS = 2_000_000
DEFAULT_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_COMPILED_SOURCE_PATHS = 20_000
DEFAULT_MAX_COMPILED_SOURCE_PATH_BYTES = 8 * 1024 * 1024

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_PFS_RE = re.compile(r"^PFS-[0-9a-f]{24}$", re.ASCII)
_PFD_RE = re.compile(r"^PFD-[0-9a-f]{24}$", re.ASCII)
_HOST_PATH_RE = re.compile(
    r"(?:^|[\s(])(?:[A-Za-z]:[\\/]|\\\\|/"
    r"(?:home|users|tmp|var|opt|root|mnt|private)/)",
    re.IGNORECASE,
)

_SOURCE_LANGUAGES = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".rs": "rust",
    ".go": "go",
    ".move": "move",
    ".daml": "daml",
    ".proto": "protobuf",
}
_SCOPE_CLASSES = frozenset(
    {"PRODUCTION", "EXPLICIT_SCOPE", "BOUND_DEPENDENCY", "GENERATED_BOUND"}
)
_COVERAGE_STATUSES = frozenset(
    {"FULL", "PARTIAL", "UNSUPPORTED", "UNKNOWN"}
)
_EXCLUSION_REASONS = frozenset(
    {
        "BOUND_DEPENDENCY_NOT_SELECTED",
        "GENERATED_SOURCE_NOT_BOUND",
        "NON_PRODUCTION_SOURCE",
        "SOURCE_SUFFIX_OUTSIDE_ECOSYSTEM_POLICY",
    }
)
_DEBT_CODES = frozenset(
    {
        "COMPILED_DENOMINATOR_UNAVAILABLE",
        "COMPILED_DENOMINATOR_UNTRUSTED",
        "ELIGIBLE_SOURCE_NOT_COMPILED",
        "COMPILED_SOURCE_OUTSIDE_ELIGIBLE_DENOMINATOR",
        "SOURCE_EXCLUDED",
        "UNSUPPORTED_ECOSYSTEM",
        "SOURCE_LANGUAGE_UNSUPPORTED",
        "SOURCE_LANGUAGE_COVERAGE_UNPROVEN",
        "EXPLICIT_SCOPE_PHYSICAL_SPELLING_UNAVAILABLE",
        "SNAPSHOT_SOURCE_SCOPE_LIMITED",
    }
)
_SUPPORTED_ECOSYSTEMS = frozenset(SOURCE_SUFFIXES_BY_ECOSYSTEM)
_POLICY_KEYS = frozenset(
    {
        "policy_version",
        "shared_selector",
        "selector_bridge_digest",
        "production_scope_predicate",
        "generated_verification_policy",
        "exclusion_inventory",
        "generated_source_exclusion_mode",
        "include_suffixes",
        "source_suffix_universe",
        "symlink_policy",
        "junction_reparse_policy",
        "hardlink_policy",
        "sparse_file_policy",
        "regular_file_policy",
        "policy_digest",
    }
)
_SOURCE_FILE_KEYS = frozenset(
    {
        "source_file_id",
        "path",
        "path_casefold_key",
        "source_sha256",
        "size_bytes",
        "language",
        "scope_class",
        "physical_identity_digest",
    }
)
_EXCLUDED_FILE_KEYS = frozenset({"identity", "reason", "source_sha256"})
_SOURCE_MANIFEST_KEYS = frozenset(
    {
        "policy_version",
        "eligible_files",
        "excluded_files",
        "file_count",
        "byte_count",
        "manifest_digest",
    }
)
_LINE_REPLAY_KEYS = frozenset(
    {"source_file_id", "line_start_byte_offsets"}
)
_DEBT_KEYS = frozenset(
    {"debt_id", "code", "affected_source_file_ids", "affected_paths"}
)
_DENOMINATOR_KEYS = frozenset(
    {
        "status",
        "eligible_source_file_ids",
        "compiled_source_file_ids",
        "uncompiled_source_file_ids",
        "unexpected_compiled_paths",
        "unresolved_debt_ids",
        "denominator_digest",
    }
)
_TREE_KEYS = frozenset({"pre_digest", "post_digest", "stable"})
_SNAPSHOT_REF_KEYS = frozenset(
    {"snapshot_digest", "source_scope_digest"}
)
_SELECTOR_AUTHORITY_KEYS = frozenset(
    {
        "pipeline",
        "ecosystem",
        "scope_match_mode",
        "scope_file_input",
        "allow_external_scope_targets",
        "build_root_input",
        "build_source_inputs",
        "dependency_root_inputs",
        "effective_dependency_roots",
        "source_config_inputs",
        "project_root_input_digest",
        "project_root_identity_digest",
        "selector_inputs_digest",
    }
)
_SOURCE_CONFIG_INPUT_KEYS = frozenset({"identity", "source_sha256"})
_PHYSICAL_INVENTORY_KEYS = frozenset(
    {"kind", "identity", "physical_identity_digest"}
)
_SOURCE_SUFFIX_BINDING_KEYS = frozenset({"source_file_id", "suffix"})
_AUTHORITY_KEYS = frozenset(
    {
        "schema_version",
        "canonicalization_version",
        "snapshot_ref",
        "selection_policy",
        "selector_authority",
        "source_manifest",
        "physical_identity_inventory",
        "source_suffix_bindings",
        "line_replay_inputs",
        "compiled_denominator",
        "debts",
        "tree_identity",
        "authority_digest",
    }
)

_FILE_ATTRIBUTE_SPARSE_FILE = 0x0200
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


class ProgramFactsSourceManifestError(ValueError):
    """The source denominator is unsafe, ambiguous, or not replayable."""


class SharedSourceSelectionUnavailable(RuntimeError):
    """The audit-snapshot selector bridge is absent; no fallback is legal."""


class SourceManifestCaptureCapability:
    """Opaque, one-shot proof that exact bytes came from this builder capture."""

    __slots__ = ("_opaque_nonce",)

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError(
            "SourceManifestCaptureCapability is builder-issued only"
        )

    def __setattr__(self, _name, _value):
        raise TypeError(
            "source-manifest capture capability is immutable"
        )

    def _consume(
        self,
        *,
        authority_digest: str,
        snapshot_digest: str,
        source_scope_digest: str,
        capture_digest: str,
    ) -> None:
        _consume_capture_capability(
            self,
            authority_digest=authority_digest,
            snapshot_digest=snapshot_digest,
            source_scope_digest=source_scope_digest,
            capture_digest=capture_digest,
        )

    def __copy__(self):
        raise TypeError(
            "source-manifest capture capability cannot be copied"
        )

    def __deepcopy__(self, _memo):
        raise TypeError(
            "source-manifest capture capability cannot be copied"
        )

    def __reduce__(self):
        raise TypeError(
            "source-manifest capture capability cannot be serialized"
        )


def _fail_from_type(exc: Exception) -> NoReturn:
    raise ProgramFactsSourceManifestError(str(exc)) from exc


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _fresh_json_mapping(value: Any, context: str) -> dict[str, Any]:
    """Capture one recursive JSON value and never reread caller containers."""

    if not isinstance(value, Mapping):
        raise ProgramFactsSourceManifestError(f"{context} must be an object")
    try:
        raw = canonical_json_bytes(value)
        parsed = strict_json_loads(
            raw,
            require_final_lf=False,
            require_canonical=True,
        )
    except ProgramFactsTypeError as exc:
        raise ProgramFactsSourceManifestError(
            f"{context} is not exact canonical JSON"
        ) from exc
    if type(parsed) is not dict:
        raise ProgramFactsSourceManifestError(f"{context} must be an object")
    return parsed


@dataclass(frozen=True, init=False)
class ProgramFactsAuditIdentity:
    """Complete digest identity of one canonical audit snapshot."""

    snapshot_digest: str
    source_scope_digest: str
    audit_config_digest: str
    methodology_digest: str
    toolchain_digest: str

    def __init__(
        self,
        *,
        snapshot_digest: str,
        source_scope_digest: str,
        audit_config_digest: str,
        methodology_digest: str,
        toolchain_digest: str,
    ) -> None:
        object.__setattr__(
            self,
            "snapshot_digest",
            _sha256(snapshot_digest, "audit snapshot digest"),
        )
        object.__setattr__(
            self,
            "source_scope_digest",
            _sha256(source_scope_digest, "source scope digest"),
        )
        object.__setattr__(
            self,
            "audit_config_digest",
            _sha256(audit_config_digest, "audit config digest"),
        )
        object.__setattr__(
            self,
            "methodology_digest",
            _sha256(methodology_digest, "methodology digest"),
        )
        object.__setattr__(
            self,
            "toolchain_digest",
            _sha256(toolchain_digest, "toolchain digest"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "snapshot_digest": self.snapshot_digest,
            "source_scope_digest": self.source_scope_digest,
            "audit_config_digest": self.audit_config_digest,
            "methodology_digest": self.methodology_digest,
            "toolchain_digest": self.toolchain_digest,
        }


@dataclass(frozen=True, init=False)
class ProgramFactsAuditSnapshotAuthority:
    """Opaque exact audit snapshot/config capture used as a trust root."""

    snapshot: Mapping[str, Any]
    config: Mapping[str, Any]
    snapshot_bytes: bytes
    config_bytes: bytes
    snapshot_digest: str
    source_scope_digest: str
    audit_config_digest: str
    methodology_digest: str
    toolchain_digest: str

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError(
            "ProgramFactsAuditSnapshotAuthority is validator-issued only"
        )

    @property
    def parent_authority_established(self) -> bool:
        return _audit_snapshot_authority_is_issued(self)

    @property
    def audit_identity(self) -> ProgramFactsAuditIdentity:
        return ProgramFactsAuditIdentity(
            snapshot_digest=self.snapshot_digest,
            source_scope_digest=self.source_scope_digest,
            audit_config_digest=self.audit_config_digest,
            methodology_digest=self.methodology_digest,
            toolchain_digest=self.toolchain_digest,
        )

    def __copy__(self):
        raise TypeError("audit-snapshot authority cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("audit-snapshot authority cannot be copied")

    def __reduce__(self):
        raise TypeError("audit-snapshot authority cannot be serialized")


@dataclass(frozen=True, init=False)
class ReplayedProgramFactsAuditSnapshotAuthority(
    ProgramFactsAuditSnapshotAuthority
):
    """Snapshot authority freshly replayed against the live source scope."""

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError(
            "ReplayedProgramFactsAuditSnapshotAuthority is validator-issued "
            "only"
        )


def _make_audit_snapshot_authority_registry(
    *,
    capture_code: Any,
    replay_code: Any,
):
    lock = threading.RLock()
    issued: dict[int, tuple[object, tuple[Any, ...]]] = {}

    def signature(value: object) -> tuple[Any, ...]:
        return (
            type(value),
            id(getattr(value, "snapshot", None)),
            id(getattr(value, "config", None)),
            getattr(value, "snapshot_bytes", None),
            getattr(value, "config_bytes", None),
            getattr(value, "snapshot_digest", None),
            getattr(value, "source_scope_digest", None),
            getattr(value, "audit_config_digest", None),
            getattr(value, "methodology_digest", None),
            getattr(value, "toolchain_digest", None),
        )

    def is_issued(value: object) -> bool:
        if type(value) not in {
            ProgramFactsAuditSnapshotAuthority,
            ReplayedProgramFactsAuditSnapshotAuthority,
        }:
            return False
        with lock:
            registered = issued.get(id(value))
            return bool(
                registered is not None
                and registered[0] is value
                and registered[1] == signature(value)
            )

    def issue(
        authority_type: type[ProgramFactsAuditSnapshotAuthority],
        *,
        snapshot: Mapping[str, Any],
        config: Mapping[str, Any],
        snapshot_bytes: bytes,
        config_bytes: bytes,
        snapshot_digest: str,
        source_scope_digest: str,
        audit_config_digest: str,
        methodology_digest: str,
        toolchain_digest: str,
    ) -> ProgramFactsAuditSnapshotAuthority:
        frame = inspect.currentframe()
        caller_code = (
            frame.f_back.f_code
            if frame is not None and frame.f_back is not None
            else None
        )
        del frame
        expected_caller = (
            capture_code
            if authority_type is ProgramFactsAuditSnapshotAuthority
            else replay_code
        )
        if caller_code is not expected_caller:
            raise TypeError(
                "audit-snapshot authority issuance is internal to its "
                "validated capture or replay operation"
            )
        if authority_type not in {
            ProgramFactsAuditSnapshotAuthority,
            ReplayedProgramFactsAuditSnapshotAuthority,
        }:
            raise TypeError("unsupported audit-snapshot authority type")
        value = object.__new__(authority_type)
        object.__setattr__(value, "snapshot", snapshot)
        object.__setattr__(value, "config", config)
        object.__setattr__(value, "snapshot_bytes", bytes(snapshot_bytes))
        object.__setattr__(value, "config_bytes", bytes(config_bytes))
        object.__setattr__(value, "snapshot_digest", snapshot_digest)
        object.__setattr__(
            value, "source_scope_digest", source_scope_digest
        )
        object.__setattr__(
            value, "audit_config_digest", audit_config_digest
        )
        object.__setattr__(value, "methodology_digest", methodology_digest)
        object.__setattr__(value, "toolchain_digest", toolchain_digest)
        with lock:
            issued[id(value)] = (value, signature(value))
        return value

    return is_issued, issue


@dataclass(frozen=True)
class ParsedProgramFactsSourceManifest(Mapping[str, Any]):
    """Immutable shape-valid record without parent or byte authority."""

    record: Mapping[str, Any]
    canonical_bytes: bytes
    authority_digest: str
    file_sha256: str

    @property
    def parent_authority_established(self) -> bool:
        return _manifest_authority_is_issued(self)

    @property
    def source_manifest(self) -> Mapping[str, Any]:
        return self.record["source_manifest"]

    @property
    def manifest_digest(self) -> str:
        return str(self.source_manifest["manifest_digest"])

    def __getitem__(self, key: str) -> Any:
        return self.record[key]

    def __iter__(self):
        return iter(self.record)

    def __len__(self) -> int:
        return len(self.record)


@dataclass(frozen=True, init=False)
class ProgramFactsSourceManifestAuthority(ParsedProgramFactsSourceManifest):
    """Builder result with captured source bytes and established parent binding."""

    source_bytes_by_id: Mapping[str, bytes]
    excluded_source_bytes_by_identity: Mapping[str, bytes]
    capture_capability: SourceManifestCaptureCapability

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError(
            "ProgramFactsSourceManifestAuthority is builder-issued only"
        )

    def __copy__(self):
        raise TypeError("source-manifest authority cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("source-manifest authority cannot be copied")

    def __reduce__(self):
        raise TypeError("source-manifest authority cannot be serialized")


@dataclass(frozen=True, init=False)
class ReplayedProgramFactsSourceManifest(ParsedProgramFactsSourceManifest):
    """Shape record whose parent bindings and exact raw bytes replayed."""

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError(
            "ReplayedProgramFactsSourceManifest is validator-issued only"
        )

    def __copy__(self):
        raise TypeError("replayed source-manifest authority cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("replayed source-manifest authority cannot be copied")

    def __reduce__(self):
        raise TypeError(
            "replayed source-manifest authority cannot be serialized"
        )


def _make_issuance_registry(
    *,
    builder_code: Any,
    replay_code: Any,
):
    """Keep issuance and consumption state outside attacker-mutable slots."""

    lock = threading.RLock()
    authorities: dict[int, tuple[object, tuple[Any, ...]]] = {}
    capabilities: dict[
        int,
        tuple[
            object,
            tuple[str, str, str, str],
            int,
            bool,
        ],
    ] = {}

    def authority_signature(value: object) -> tuple[Any, ...]:
        base = (
            type(value),
            id(getattr(value, "record", None)),
            getattr(value, "canonical_bytes", None),
            getattr(value, "authority_digest", None),
            getattr(value, "file_sha256", None),
        )
        if type(value) is ProgramFactsSourceManifestAuthority:
            return (
                *base,
                id(getattr(value, "source_bytes_by_id", None)),
                id(
                    getattr(
                        value,
                        "excluded_source_bytes_by_identity",
                        None,
                    )
                ),
                id(getattr(value, "capture_capability", None)),
            )
        return base

    def authority_is_issued(value: object) -> bool:
        if type(value) not in {
            ProgramFactsSourceManifestAuthority,
            ReplayedProgramFactsSourceManifest,
        }:
            return False
        with lock:
            registered = authorities.get(id(value))
            return (
                registered is not None
                and registered[0] is value
                and registered[1] == authority_signature(value)
            )

    def issue_authority(
        authority_type: type[ParsedProgramFactsSourceManifest],
        *,
        record: Mapping[str, Any],
        canonical_bytes: bytes,
        authority_digest: str,
        file_sha256: str,
        source_bytes_by_id: Mapping[str, bytes] | None = None,
        excluded_source_bytes_by_identity: Mapping[str, bytes] | None = None,
        capture_capability: SourceManifestCaptureCapability | None = None,
    ) -> ParsedProgramFactsSourceManifest:
        frame = inspect.currentframe()
        caller_code = (
            frame.f_back.f_code
            if frame is not None and frame.f_back is not None
            else None
        )
        del frame
        expected_caller = (
            builder_code
            if authority_type is ProgramFactsSourceManifestAuthority
            else replay_code
        )
        if caller_code is not expected_caller:
            raise TypeError(
                "source-manifest authority issuance is internal to its "
                "validated builder or replay operation"
            )
        if authority_type not in {
            ProgramFactsSourceManifestAuthority,
            ReplayedProgramFactsSourceManifest,
        }:
            raise TypeError("unsupported source-manifest authority type")
        value = object.__new__(authority_type)
        object.__setattr__(value, "record", record)
        object.__setattr__(value, "canonical_bytes", canonical_bytes)
        object.__setattr__(value, "authority_digest", authority_digest)
        object.__setattr__(value, "file_sha256", file_sha256)
        if authority_type is ProgramFactsSourceManifestAuthority:
            if (
                source_bytes_by_id is None
                or excluded_source_bytes_by_identity is None
                or capture_capability is None
            ):
                raise TypeError("builder authority capture is incomplete")
            object.__setattr__(
                value, "source_bytes_by_id", source_bytes_by_id
            )
            object.__setattr__(
                value,
                "excluded_source_bytes_by_identity",
                excluded_source_bytes_by_identity,
            )
            object.__setattr__(
                value, "capture_capability", capture_capability
            )
        with lock:
            authorities[id(value)] = (
                value,
                authority_signature(value),
            )
        return value

    def issue_capability(
        *,
        authority_digest: str,
        snapshot_digest: str,
        source_scope_digest: str,
        capture_digest: str,
    ) -> SourceManifestCaptureCapability:
        frame = inspect.currentframe()
        caller_code = (
            frame.f_back.f_code
            if frame is not None and frame.f_back is not None
            else None
        )
        del frame
        if caller_code is not builder_code:
            raise TypeError(
                "source-manifest capture capability issuance is internal "
                "to the validated builder"
            )
        value = object.__new__(SourceManifestCaptureCapability)
        object.__setattr__(value, "_opaque_nonce", object())
        binding = (
            authority_digest,
            snapshot_digest,
            source_scope_digest,
            capture_digest,
        )
        with lock:
            capabilities[id(value)] = (
                value,
                binding,
                os.getpid(),
                False,
            )
        return value

    def consume_capability(
        value: SourceManifestCaptureCapability,
        *,
        authority_digest: str,
        snapshot_digest: str,
        source_scope_digest: str,
        capture_digest: str,
    ) -> None:
        with lock:
            registered = capabilities.get(id(value))
            if registered is None or registered[0] is not value:
                raise ProgramFactsSourceManifestError(
                    "source-manifest capture capability was not issued"
                )
            issued_value, expected, issuer_pid, consumed = registered
            if os.getpid() != issuer_pid:
                raise ProgramFactsSourceManifestError(
                    "source-manifest capture capability is process-bound "
                    "and cannot be consumed after fork or transfer"
                )
            if consumed:
                raise ProgramFactsSourceManifestError(
                    "source-manifest capture capability is one-shot and consumed"
                )
            capabilities[id(value)] = (
                issued_value,
                expected,
                issuer_pid,
                True,
            )
            supplied = (
                authority_digest,
                snapshot_digest,
                source_scope_digest,
                capture_digest,
            )
            if supplied[:3] != expected[:3]:
                raise ProgramFactsSourceManifestError(
                    "source-manifest capture capability binding mismatch"
                )
            if supplied[3] != expected[3]:
                raise ProgramFactsSourceManifestError(
                    "source-manifest capture capability raw bytes "
                    "binding mismatch"
                )

    return (
        authority_is_issued,
        issue_authority,
        issue_capability,
        consume_capability,
    )


@dataclass(frozen=True)
class _Candidate:
    inspection_path: Path
    physical_path: Path
    portable_path: str
    scope_class: str


@dataclass(frozen=True)
class _StableRead:
    raw: bytes
    pre_fingerprint: Mapping[str, int]
    post_fingerprint: Mapping[str, int]
    physical_identity_digest: str


def _require_exact_keys(
    value: Any, expected: frozenset[str], context: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProgramFactsSourceManifestError(f"{context} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    reasons: list[str] = []
    if missing:
        reasons.append("missing fields: " + ", ".join(missing))
    if extra:
        reasons.append("unexpected fields: " + ", ".join(extra))
    if reasons:
        raise ProgramFactsSourceManifestError(
            f"{context} " + "; ".join(reasons)
        )
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        raise ProgramFactsSourceManifestError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _sha256_ref(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ProgramFactsSourceManifestError(
            f"{field} must be a sha256:<digest> reference"
        )
    _sha256(value[7:], field)
    return value


def _raw_digest(value: Any, field: str) -> str:
    if isinstance(value, str) and value.startswith("sha256:"):
        value = value[7:]
    return _sha256(value, field)


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProgramFactsSourceManifestError(
            f"{field} must be a non-negative integer"
        )
    return value


def _positive_int(value: Any, field: str) -> int:
    result = _nonnegative_int(value, field)
    if result == 0:
        raise ProgramFactsSourceManifestError(
            f"{field} must be greater than zero"
        )
    return result


def _portable_path(value: Any, field: str) -> str:
    try:
        result = validate_portable_path(value)
    except ProgramFactsTypeError as exc:
        _fail_from_type(exc)
    if unicodedata.normalize("NFC", result) != result:
        raise ProgramFactsSourceManifestError(
            f"{field} must be NFC-normalized"
        )
    return result


def _require_sorted_unique(
    values: Any, field: str, *, row_key: str | None = None
) -> list[Any]:
    if not isinstance(values, Sequence) or isinstance(
        values, (str, bytes, bytearray)
    ):
        raise ProgramFactsSourceManifestError(f"{field} must be an array")
    rows = list(values)
    if row_key is None:
        if any(not isinstance(item, str) for item in rows):
            raise ProgramFactsSourceManifestError(
                f"{field} must contain strings"
            )
        identities = rows
    else:
        identities = []
        for item in rows:
            if not isinstance(item, Mapping) or not isinstance(
                item.get(row_key), str
            ):
                raise ProgramFactsSourceManifestError(
                    f"{field} rows require {row_key}"
                )
            identities.append(item[row_key])
    if identities != sorted(identities):
        raise ProgramFactsSourceManifestError(f"{field} must be sorted")
    if len(identities) != len(set(identities)):
        raise ProgramFactsSourceManifestError(
            f"{field} contains a duplicate identity"
        )
    return rows


def _unsigned_digest(
    value: Mapping[str, Any], digest_field: str
) -> str:
    unsigned = dict(value)
    unsigned.pop(digest_field, None)
    try:
        return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    except ProgramFactsTypeError as exc:
        _fail_from_type(exc)


def _selector_source_digest() -> str:
    names = (
        "_casefold_production_source_files",
        "_snapshot_foundry_dependency_roots",
        "_scope_file_targets",
        "_is_generated_verification_source",
        "_project_context_files",
        "_assert_no_lexical_links",
        "_is_reparse_point",
    )
    sources: list[dict[str, str]] = []
    for name in names:
        function = getattr(_audit_snapshot, name, None)
        if function is None or not callable(function):
            raise SharedSourceSelectionUnavailable(
                f"audit_snapshot.{name} is unavailable"
            )
        try:
            source = inspect.getsource(function).replace("\r\n", "\n")
        except (OSError, TypeError) as exc:
            raise SharedSourceSelectionUnavailable(
                f"audit_snapshot.{name} cannot be identity-bound"
            ) from exc
        sources.append({"name": name, "source": source})
    try:
        predicate_source = inspect.getsource(
            is_production_source_path
        ).replace("\r\n", "\n")
    except (OSError, TypeError) as exc:
        raise SharedSourceSelectionUnavailable(
            "production source predicate cannot be identity-bound"
        ) from exc
    sources.append(
        {
            "name": "production_source_scope.is_production_source_path",
            "source": predicate_source,
        }
    )
    for name, module in (
        ("audit_snapshot.module", _audit_snapshot),
        ("production_source_scope.module", _production_source_scope),
    ):
        try:
            module_source = inspect.getsource(module).replace("\r\n", "\n")
        except (OSError, TypeError) as exc:
            raise SharedSourceSelectionUnavailable(
                f"{name} cannot be identity-bound"
            ) from exc
        sources.append(
            {
                "name": name,
                "source": hashlib.sha256(
                    module_source.encode("utf-8", errors="strict")
                ).hexdigest(),
            }
        )
    return hashlib.sha256(canonical_json_bytes(sources)).hexdigest()


def _shared_production_source_files(
    project_root: Path,
    suffixes: tuple[str, ...],
    *,
    dependency_roots: Sequence[Path],
) -> list[Path]:
    selector = getattr(
        _audit_snapshot, "_casefold_production_source_files", None
    )
    if selector is None or not callable(selector):
        raise SharedSourceSelectionUnavailable(
            "audit_snapshot production selector is unavailable"
        )
    return list(
        selector(
            project_root,
            suffixes,
            dependency_roots=dependency_roots,
        )
    )


def _shared_dependency_roots(
    config: Mapping[str, Any], project_root: Path
) -> tuple[Path, ...]:
    function = getattr(
        _audit_snapshot, "_snapshot_foundry_dependency_roots", None
    )
    if function is None or not callable(function):
        raise SharedSourceSelectionUnavailable(
            "audit_snapshot dependency-root selector is unavailable"
        )
    return tuple(function(config, project_root))


def _shared_scope_targets(
    config: Mapping[str, Any], project_root: Path
) -> list[Path]:
    function = getattr(_audit_snapshot, "_scope_file_targets", None)
    if function is None or not callable(function):
        raise SharedSourceSelectionUnavailable(
            "audit_snapshot explicit-scope selector is unavailable"
        )
    return list(function(config, project_root))


def _shared_project_context_files(project_root: Path) -> list[Path]:
    function = getattr(_audit_snapshot, "_project_context_files", None)
    if function is None or not callable(function):
        raise SharedSourceSelectionUnavailable(
            "audit_snapshot project-context selector is unavailable"
        )
    return list(function(project_root))


def _supplemental_source_exclusion_inventory(
    project_root: Path,
) -> list[Path]:
    """Inventory source-shaped exclusions omitted by snapshot context policy.

    The audit snapshot intentionally omits generated verification artifacts
    from its positive input set.  A source-denominator authority must still
    account for those files negatively, so this bounded walk is used only to
    produce exclusions; it never selects an eligible source.
    """

    skip = getattr(
        _audit_snapshot, "_is_project_context_skip_dir", None
    )
    if skip is None or not callable(skip):
        raise SharedSourceSelectionUnavailable(
            "audit_snapshot project-context directory policy is unavailable"
        )
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(
        project_root, followlinks=False
    ):
        retained: list[str] = []
        for name in sorted(dirnames):
            directory = Path(dirpath) / name
            # Generated source must be represented as explicit exclusion.
            # Other conventional caches/dependency outputs remain outside this
            # negative inventory, matching the snapshot boundary.
            should_skip = bool(skip(name, directory))
            if should_skip and name.casefold() != "generated":
                continue
            try:
                observed = directory.lstat()
            except OSError as exc:
                raise ProgramFactsSourceManifestError(
                    "source exclusion inventory has an unreadable directory"
                ) from exc
            if stat.S_ISLNK(observed.st_mode) or _is_reparse(observed):
                raise ProgramFactsSourceManifestError(
                    "source exclusion inventory traverses a symbolic link, "
                    "junction, or reparse point"
                )
            if not stat.S_ISDIR(observed.st_mode):
                raise ProgramFactsSourceManifestError(
                    "source exclusion inventory contains a non-directory"
                )
            retained.append(name)
        dirnames[:] = retained
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix.casefold() not in ALL_AUDIT_SOURCE_SUFFIXES:
                continue
            found.append(path)
            if len(found) > DEFAULT_MAX_FILES:
                raise ProgramFactsSourceManifestError(
                    "source exclusion inventory exceeds the bounded "
                    "file-count limit"
                )
    return found


def _shared_is_generated(path: Path, project_root: Path) -> bool:
    function = getattr(
        _audit_snapshot, "_is_generated_verification_source", None
    )
    if function is None or not callable(function):
        raise SharedSourceSelectionUnavailable(
            "audit_snapshot generated-source predicate is unavailable"
        )
    return bool(function(path, project_root))


def _is_manifest_generated(path: Path, project_root: Path) -> bool:
    if _shared_is_generated(path, project_root):
        return True
    try:
        relative = path.absolute().relative_to(project_root.absolute())
    except ValueError:
        relative = path
    return "generated" in {
        component.casefold() for component in relative.parts[:-1]
    }


def _is_reparse(stat_result: os.stat_result) -> bool:
    attributes = int(getattr(stat_result, "st_file_attributes", 0))
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _is_sparse(stat_result: os.stat_result) -> bool:
    attributes = int(getattr(stat_result, "st_file_attributes", 0))
    if attributes & _FILE_ATTRIBUTE_SPARSE_FILE:
        return True
    blocks = getattr(stat_result, "st_blocks", None)
    return (
        isinstance(blocks, int)
        and stat_result.st_size > 0
        and blocks * 512 < stat_result.st_size
    )


def _physical_fingerprint(stat_result: os.stat_result) -> dict[str, int]:
    return {
        "device": int(stat_result.st_dev),
        "inode": int(stat_result.st_ino),
        "mode": int(stat_result.st_mode),
        "size": int(stat_result.st_size),
        "link_count": int(stat_result.st_nlink),
        "mtime_ns": int(stat_result.st_mtime_ns),
        "file_attributes": int(
            getattr(stat_result, "st_file_attributes", 0)
        ),
    }


def _physical_identity(stat_result: os.stat_result) -> str:
    identity = {
        "device": int(stat_result.st_dev),
        "inode": int(stat_result.st_ino),
        "mode_type": int(stat.S_IFMT(stat_result.st_mode)),
        "file_attributes": int(
            getattr(stat_result, "st_file_attributes", 0)
        )
        & _FILE_ATTRIBUTE_REPARSE_POINT,
    }
    return hashlib.sha256(canonical_json_bytes(identity)).hexdigest()


def _check_regular_file(
    path: Path, stat_result: os.stat_result, *, context: str
) -> None:
    if stat.S_ISLNK(stat_result.st_mode):
        raise ProgramFactsSourceManifestError(
            f"{context} is a symbolic link; source policy rejects links"
        )
    if _is_reparse(stat_result):
        raise ProgramFactsSourceManifestError(
            f"{context} is a junction or reparse point"
        )
    if not stat.S_ISREG(stat_result.st_mode):
        raise ProgramFactsSourceManifestError(
            f"{context} is not a physical regular file"
        )
    if _is_sparse(stat_result):
        raise ProgramFactsSourceManifestError(
            f"{context} is sparse; source policy rejects sparse files"
        )


def _check_lexical_ancestors(
    path: Path, permitted_root: Path, *, context: str
) -> None:
    try:
        relative = path.absolute().relative_to(permitted_root.absolute())
    except ValueError:
        validator = getattr(
            _audit_snapshot, "_assert_no_lexical_links", None
        )
        if validator is None or not callable(validator):
            raise SharedSourceSelectionUnavailable(
                "audit_snapshot lexical-link validator is unavailable"
            )
        try:
            validator(path, label=context)
        except Exception as exc:
            raise ProgramFactsSourceManifestError(
                f"{context} traverses a symbolic link, junction, or reparse point"
            ) from exc
        return
    current = permitted_root.absolute()
    for part in relative.parts[:-1]:
        current = current / part
        try:
            observed = current.lstat()
        except OSError as exc:
            raise ProgramFactsSourceManifestError(
                f"{context} has an unreadable ancestor"
            ) from exc
        if stat.S_ISLNK(observed.st_mode) or _is_reparse(observed):
            raise ProgramFactsSourceManifestError(
                f"{context} traverses a symbolic link, junction, or reparse point"
            )


def _check_exact_disk_spelling(
    path: Path, permitted_root: Path, *, context: str
) -> None:
    """Reject case/Unicode aliases for each selected lexical component."""

    try:
        relative = path.absolute().relative_to(permitted_root.absolute())
    except ValueError:
        relative = None
    if relative is None:
        if not path.is_absolute() or not path.anchor:
            raise ProgramFactsSourceManifestError(
                f"{context} must be an absolute physical path"
            )
        if (
            os.name == "nt"
            and re.fullmatch(r"[A-Za-z]:", path.drive)
            and path.drive != path.drive.upper()
        ):
            raise ProgramFactsSourceManifestError(
                f"{context} drive spelling or case is not canonical"
            )
        components = path.parts[1:]
        current = Path(path.anchor)
    else:
        components = relative.parts
        current = permitted_root.absolute()
    for component in components:
        try:
            names = [entry.name for entry in os.scandir(current)]
        except OSError as exc:
            raise ProgramFactsSourceManifestError(
                f"{context} has an unreadable parent directory"
            ) from exc
        folded = unicodedata.normalize("NFC", component).casefold()
        aliases = [
            name
            for name in names
            if unicodedata.normalize("NFC", name).casefold() == folded
        ]
        if component not in names:
            raise ProgramFactsSourceManifestError(
                f"{context} spelling or case differs from the physical file"
            )
        if len(aliases) != 1:
            raise ProgramFactsSourceManifestError(
                f"{context} has a cross-platform case/Unicode collision"
            )
        current = current / component


def _read_regular_file_stably(
    path: Path,
    *,
    context: str,
    max_file_bytes: int,
) -> _StableRead:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProgramFactsSourceManifestError(
            f"{context} cannot be inspected"
        ) from exc
    _check_regular_file(path, before, context=context)
    if before.st_size > max_file_bytes:
        raise ProgramFactsSourceManifestError(
            f"{context} exceeds the bounded per-file byte limit"
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProgramFactsSourceManifestError(
            f"{context} cannot be opened as an immutable regular file"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        _check_regular_file(path, opened, context=context)
        if _physical_identity(opened) != _physical_identity(before):
            raise ProgramFactsSourceManifestError(
                f"{context} changed between inspection and open"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_file_bytes + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_file_bytes:
                raise ProgramFactsSourceManifestError(
                    f"{context} exceeds the bounded per-file byte limit"
                )
            chunks.append(chunk)
        after_open = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ProgramFactsSourceManifestError(
            f"{context} disappeared during stable read"
        ) from exc
    _check_regular_file(path, after, context=context)
    before_fingerprint = _physical_fingerprint(before)
    after_fingerprint = _physical_fingerprint(after)
    opened_fingerprint = _physical_fingerprint(opened)
    after_open_fingerprint = _physical_fingerprint(after_open)
    if (
        before_fingerprint != opened_fingerprint
        or before_fingerprint != after_open_fingerprint
        or before_fingerprint != after_fingerprint
    ):
        changed_fields = sorted(
            key
            for key in before_fingerprint
            if not (
                before_fingerprint[key]
                == opened_fingerprint[key]
                == after_open_fingerprint[key]
                == after_fingerprint[key]
            )
        )
        raise ProgramFactsSourceManifestError(
            f"{context} changed during stable read "
            f"({', '.join(changed_fields)})"
        )
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        raise ProgramFactsSourceManifestError(
            f"{context} size changed during stable read"
        )
    return _StableRead(
        raw=raw,
        pre_fingerprint=MappingProxyType(before_fingerprint),
        post_fingerprint=MappingProxyType(after_fingerprint),
        physical_identity_digest=_physical_identity(before),
    )


def _external_identity(path: Path) -> str:
    return hashlib.sha256(
        str(path.resolve()).encode("utf-8", errors="strict")
    ).hexdigest()


def _portable_candidate_path(
    physical_path: Path,
    project_root: Path,
    *,
    outside_prefix: str,
) -> str:
    try:
        return physical_path.relative_to(project_root).as_posix()
    except ValueError:
        suffix = physical_path.name
        if outside_prefix == "@outside":
            return f"@outside/{_external_identity(physical_path)}"
        return (
            f"@build_context/{_external_identity(physical_path)}/{suffix}"
        )


def _validate_project_root(project_root: Path) -> None:
    lexical = project_root.absolute()
    if not lexical.is_absolute() or not lexical.anchor:
        raise ProgramFactsSourceManifestError(
            "project_root must be an absolute physical directory"
        )
    if (
        os.name == "nt"
        and re.fullmatch(r"[A-Za-z]:", lexical.drive)
        and lexical.drive != lexical.drive.upper()
    ):
        raise ProgramFactsSourceManifestError(
            "project_root drive spelling or case is not canonical"
        )
    current = Path(lexical.anchor)
    for component in lexical.parts[1:]:
        try:
            names = [entry.name for entry in os.scandir(current)]
        except OSError as exc:
            raise ProgramFactsSourceManifestError(
                "project_root has an unreadable ancestor"
            ) from exc
        folded = unicodedata.normalize("NFC", component).casefold()
        aliases = [
            name
            for name in names
            if unicodedata.normalize("NFC", name).casefold() == folded
        ]
        if component not in names:
            raise ProgramFactsSourceManifestError(
                "project_root spelling or case differs from the physical directory"
            )
        if len(aliases) != 1:
            raise ProgramFactsSourceManifestError(
                "project_root has a cross-platform case/Unicode alias"
            )
        current = current / component
        try:
            observed = current.lstat()
        except OSError as exc:
            raise ProgramFactsSourceManifestError(
                "project_root is missing or unreadable"
            ) from exc
        if stat.S_ISLNK(observed.st_mode) or _is_reparse(observed):
            raise ProgramFactsSourceManifestError(
                "project_root traverses a symbolic link, junction, or reparse point"
            )
        if not stat.S_ISDIR(observed.st_mode):
            raise ProgramFactsSourceManifestError(
                "project_root ancestor is not a physical directory"
            )


def _project_root_identity(project_root: Path) -> str:
    _validate_project_root(project_root)
    try:
        observed = project_root.lstat()
    except OSError as exc:
        raise ProgramFactsSourceManifestError(
            "project_root is missing or unreadable"
        ) from exc
    return _physical_identity(observed)


def _suffixes_for(config: Mapping[str, Any]) -> tuple[str, ...]:
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    ecosystem = str(config.get("language") or "").strip().lower()
    if pipeline not in {"sc", "l1"}:
        raise ProgramFactsSourceManifestError(
            f"unsupported audit pipeline: {pipeline!r}"
        )
    if pipeline == "l1":
        return tuple(L1_SOURCE_SUFFIXES)
    return tuple(
        SOURCE_SUFFIXES_BY_ECOSYSTEM.get(
            ecosystem, ALL_AUDIT_SOURCE_SUFFIXES
        )
    )


def _candidate_key(path: Path) -> str:
    value = str(path.resolve())
    return value.casefold() if os.name == "nt" else value


def _collect_candidates(
    config: Mapping[str, Any],
    project_root: Path,
    suffixes: tuple[str, ...],
) -> tuple[
    list[_Candidate],
    list[_Candidate],
    Mapping[str, str],
    bool,
]:
    dependency_roots = _shared_dependency_roots(config, project_root)
    production = _shared_production_source_files(
        project_root,
        suffixes,
        dependency_roots=dependency_roots,
    )
    chosen: dict[str, _Candidate] = {}
    precedence = {
        "PRODUCTION": 0,
        "BOUND_DEPENDENCY": 1,
        "GENERATED_BOUND": 2,
        "EXPLICIT_SCOPE": 3,
    }

    def materialize(
        inspection_path: Path,
        *,
        scope_class: str,
        outside_prefix: str,
    ) -> _Candidate:
        try:
            lexical = inspection_path.absolute()
            physical = inspection_path.resolve(strict=True)
        except OSError as exc:
            raise ProgramFactsSourceManifestError(
                "selected source is missing or cannot be resolved"
            ) from exc
        _check_lexical_ancestors(
            lexical,
            project_root,
            context="selected source",
        )
        _check_exact_disk_spelling(
            lexical,
            project_root,
            context="selected source",
        )
        try:
            first = lexical.lstat()
        except OSError as exc:
            raise ProgramFactsSourceManifestError(
                "selected source cannot be inspected"
            ) from exc
        _check_regular_file(lexical, first, context="selected source")
        portable = _portable_candidate_path(
            physical,
            project_root,
            outside_prefix=outside_prefix,
        )
        _portable_path(portable, "selected source path")
        return _Candidate(
            inspection_path=lexical,
            physical_path=physical,
            portable_path=portable,
            scope_class=scope_class,
        )

    def add(
        inspection_path: Path,
        *,
        scope_class: str,
        outside_prefix: str,
    ) -> None:
        candidate = materialize(
            inspection_path,
            scope_class=scope_class,
            outside_prefix=outside_prefix,
        )
        key = _candidate_key(candidate.physical_path)
        current = chosen.get(key)
        if (
            current is None
            or precedence[candidate.scope_class] > precedence[current.scope_class]
        ):
            chosen[key] = candidate

    for path in production:
        if not _shared_is_generated(path, project_root):
            add(path, scope_class="PRODUCTION", outside_prefix="@outside")

    raw_build_sources = config.get("_resolved_build_source_files")
    if isinstance(raw_build_sources, (list, tuple)):
        wanted = {suffix.casefold() for suffix in suffixes}
        for value in raw_build_sources:
            original = Path(str(value)).expanduser()
            if not original.is_absolute():
                original = project_root / original
            if original.suffix.casefold() not in wanted:
                raise ProgramFactsSourceManifestError(
                    "resolved build source has a suffix outside the shared policy"
                )
            scope_class = (
                "GENERATED_BOUND"
                if _shared_is_generated(original, project_root)
                else "BOUND_DEPENDENCY"
            )
            add(
                original,
                scope_class=scope_class,
                outside_prefix="@build_context",
            )

    scope_file_present = bool(str(config.get("scope_file") or "").strip())
    for path in _shared_scope_targets(config, project_root):
        add(
            path,
            scope_class="EXPLICIT_SCOPE",
            outside_prefix="@outside",
        )

    eligible = sorted(
        chosen.values(),
        key=lambda item: (
            item.portable_path.casefold(),
            item.portable_path,
            item.scope_class,
        ),
    )
    selected_paths = {
        candidate.portable_path for candidate in eligible
    }
    wanted = {suffix.casefold() for suffix in suffixes}
    excluded: list[_Candidate] = []
    exclusion_reasons: dict[str, str] = {}
    inventory_by_lexical_path: dict[str, Path] = {}
    for path in [
        *_shared_project_context_files(project_root),
        *_supplemental_source_exclusion_inventory(project_root),
    ]:
        lexical = str(path.absolute())
        key = lexical.casefold() if os.name == "nt" else lexical
        inventory_by_lexical_path[key] = path
    for path in inventory_by_lexical_path.values():
        suffix = path.suffix.casefold()
        if suffix not in ALL_AUDIT_SOURCE_SUFFIXES:
            continue
        candidate = materialize(
            path,
            scope_class="EXCLUDED_PENDING",
            outside_prefix="@outside",
        )
        if candidate.portable_path in selected_paths:
            continue
        reason: str
        resolved = candidate.physical_path
        in_dependency = False
        for root in dependency_roots:
            try:
                resolved.relative_to(root.resolve())
                in_dependency = True
                break
            except ValueError:
                continue
        if in_dependency:
            reason = "BOUND_DEPENDENCY_NOT_SELECTED"
        elif _is_manifest_generated(path, project_root):
            reason = "GENERATED_SOURCE_NOT_BOUND"
        elif suffix not in wanted:
            reason = "SOURCE_SUFFIX_OUTSIDE_ECOSYSTEM_POLICY"
        elif not is_production_source_path(path, project_root):
            reason = "NON_PRODUCTION_SOURCE"
        else:
            raise ProgramFactsSourceManifestError(
                "shared source selectors disagree on an eligible source"
            )
        candidate = _Candidate(
            inspection_path=candidate.inspection_path,
            physical_path=candidate.physical_path,
            portable_path=candidate.portable_path,
            scope_class=f"EXCLUDED_{reason}",
        )
        excluded.append(candidate)
        exclusion_reasons[candidate.portable_path] = reason
    excluded.sort(
        key=lambda item: (
            item.portable_path.casefold(),
            item.portable_path,
        )
    )

    casefolds: dict[str, str] = {}
    for candidate in [*eligible, *excluded]:
        folded = candidate.portable_path.casefold()
        previous = casefolds.get(folded)
        if previous is not None and previous != candidate.portable_path:
            raise ProgramFactsSourceManifestError(
                "selected source paths have a case-fold collision"
            )
        casefolds[folded] = candidate.portable_path
    return (
        eligible,
        excluded,
        MappingProxyType(exclusion_reasons),
        scope_file_present,
    )


def _selection_policy(
    config: Mapping[str, Any], suffixes: tuple[str, ...]
) -> dict[str, Any]:
    del config
    try:
        selector_digest = _selector_source_digest()
    except SharedSourceSelectionUnavailable as exc:
        raise ProgramFactsSourceManifestError(
            f"shared source selection unavailable: {exc}"
        ) from exc
    policy: dict[str, Any] = {
        "policy_version": SOURCE_MANIFEST_POLICY_VERSION,
        "shared_selector": (
            "audit_snapshot._casefold_production_source_files"
        ),
        "selector_bridge_digest": selector_digest,
        "production_scope_predicate": (
            "production_source_scope.is_production_source_path"
        ),
        "generated_verification_policy": (
            "audit_snapshot._is_generated_verification_source"
        ),
        "exclusion_inventory": (
            "audit_snapshot._project_context_files"
            "+bounded_source_exclusion_walk"
        ),
        "generated_source_exclusion_mode": (
            "INVENTORY_GENERATED_SOURCE_AS_EXCLUDED_UNLESS_BOUND"
        ),
        "include_suffixes": sorted(
            {suffix.casefold() for suffix in suffixes}
        ),
        "source_suffix_universe": sorted(
            {suffix.casefold() for suffix in ALL_AUDIT_SOURCE_SUFFIXES}
        ),
        "symlink_policy": "REJECT_ALL",
        "junction_reparse_policy": "REJECT_ALL",
        "hardlink_policy": "REJECT_DUPLICATE_PHYSICAL_IDENTITY",
        "sparse_file_policy": "REJECT_ALL",
        "regular_file_policy": "PHYSICAL_REGULAR_FILES_ONLY",
    }
    policy["policy_digest"] = _unsigned_digest(policy, "policy_digest")
    return policy


def _normalized_selector_path(
    value: str | Path,
    project_root: Path,
    *,
    context: str,
    require_exists: bool,
    require_absolute: bool = False,
) -> tuple[str, Path]:
    path = Path(value).expanduser()
    if require_absolute and not path.is_absolute():
        raise ProgramFactsSourceManifestError(
            f"{context} must be an absolute resolved path"
        )
    if not path.is_absolute():
        path = project_root / path
    lexical = path.absolute()
    exists = lexical.exists()
    if require_exists and not exists:
        raise ProgramFactsSourceManifestError(
            f"{context} is missing or unreadable"
        )
    if exists:
        _check_lexical_ancestors(
            lexical,
            project_root,
            context=context,
        )
        _check_exact_disk_spelling(
            lexical,
            project_root,
            context=context,
        )
        try:
            observed = lexical.lstat()
        except OSError as exc:
            raise ProgramFactsSourceManifestError(
                f"{context} cannot be inspected"
            ) from exc
        if stat.S_ISLNK(observed.st_mode) or _is_reparse(observed):
            raise ProgramFactsSourceManifestError(
                f"{context} is a symbolic link, junction, or reparse point"
            )
    try:
        relative = lexical.relative_to(project_root.absolute())
    except ValueError:
        normalized = unicodedata.normalize("NFC", str(lexical))
        if os.name == "nt":
            normalized = normalized.casefold()
        opaque = hashlib.sha256(
            normalized.encode("utf-8", errors="strict")
        ).hexdigest()
        identity = f"@outside/{opaque}/{lexical.name}"
    else:
        identity = "." if not relative.parts else relative.as_posix()
    if identity != ".":
        _portable_path(identity, f"{context} normalized identity")
    return identity, lexical


def _selector_path_list(
    config: Mapping[str, Any],
    key: str,
    project_root: Path,
    *,
    context: str,
    require_exists: bool,
    require_absolute: bool,
) -> list[str]:
    raw = config.get(key)
    if raw is None:
        return []
    if not isinstance(raw, (list, tuple)):
        raise ProgramFactsSourceManifestError(
            f"{context} must be an array"
        )
    identities = [
        _normalized_selector_path(
            str(value),
            project_root,
            context=f"{context}[{index}]",
            require_exists=require_exists,
            require_absolute=require_absolute,
        )[0]
        for index, value in enumerate(raw)
    ]
    folded = [identity.casefold() for identity in identities]
    if len(folded) != len(set(folded)):
        raise ProgramFactsSourceManifestError(
            f"{context} contains a duplicate normalized path"
        )
    return sorted(identities)


def _effective_foundry_manifest(
    config: Mapping[str, Any], project_root: Path
) -> Path | None:
    raw_build_root = str(config.get("_resolved_build_root") or "").strip()
    if raw_build_root:
        root = Path(raw_build_root).expanduser()
        if not root.is_absolute():
            root = root.absolute()
        candidate = root / "foundry.toml"
        return candidate if candidate.is_file() else None
    for root in (project_root, *project_root.parents):
        candidate = root / "foundry.toml"
        if candidate.is_file():
            return candidate
    return None


def _source_config_input(
    path: Path,
    project_root: Path,
    *,
    context: str,
    max_file_bytes: int,
) -> dict[str, str]:
    identity, lexical = _normalized_selector_path(
        path,
        project_root,
        context=context,
        require_exists=True,
    )
    stable = _read_regular_file_stably(
        lexical,
        context=context,
        max_file_bytes=max_file_bytes,
    )
    return {
        "identity": identity,
        "source_sha256": hashlib.sha256(stable.raw).hexdigest(),
    }


def _selector_authority(
    config: Mapping[str, Any],
    project_root: Path,
    *,
    max_file_bytes: int,
) -> dict[str, Any]:
    raw_project_root = str(config.get("project_root") or "").strip()
    if not raw_project_root:
        raise ProgramFactsSourceManifestError(
            "selector authority config has no project_root"
        )
    configured_root = Path(raw_project_root).expanduser().absolute()
    _validate_project_root(configured_root)
    configured_spelling = unicodedata.normalize(
        "NFC", str(configured_root)
    )
    root_spelling = unicodedata.normalize("NFC", str(project_root.absolute()))
    if configured_spelling != root_spelling:
        raise ProgramFactsSourceManifestError(
            "selector authority project_root input differs from the capture root"
        )
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    ecosystem = str(config.get("language") or "").strip().lower()
    try:
        scope_match_mode = normalize_scope_match_mode(
            config.get("scope_match_mode", "legacy")
        )
    except ValueError as exc:
        raise ProgramFactsSourceManifestError(str(exc)) from exc

    raw_scope = str(config.get("scope_file") or "").strip()
    scope_path: Path | None = None
    if raw_scope:
        scope_file_input, scope_path = _normalized_selector_path(
            raw_scope,
            project_root,
            context="scope_file selector input",
            require_exists=True,
        )
    else:
        scope_file_input = None
    external_policy = config.get("allow_external_scope_targets", False)
    if type(external_policy) is not bool:
        raise ProgramFactsSourceManifestError(
            "allow_external_scope_targets must be an exact boolean"
        )

    raw_build_root = str(
        config.get("_resolved_build_root") or ""
    ).strip()
    if raw_build_root:
        build_root_input = _normalized_selector_path(
            raw_build_root,
            project_root,
            context="build_root selector input",
            require_exists=True,
            require_absolute=True,
        )[0]
    else:
        build_root_input = None

    build_sources = _selector_path_list(
        config,
        "_resolved_build_source_files",
        project_root,
        context="build source selector inputs",
        require_exists=True,
        require_absolute=True,
    )
    dependency_inputs = _selector_path_list(
        config,
        "_resolved_compiled_dependency_roots",
        project_root,
        context="dependency root selector inputs",
        require_exists=True,
        require_absolute=True,
    )
    try:
        effective_dependencies = [
            _normalized_selector_path(
                path,
                project_root,
                context="effective dependency root",
                require_exists=False,
                require_absolute=True,
            )[0]
            for path in _shared_dependency_roots(config, project_root)
        ]
    except SharedSourceSelectionUnavailable:
        raise
    except Exception as exc:
        raise ProgramFactsSourceManifestError(
            f"dependency selector inputs are invalid: {exc}"
        ) from exc
    effective_dependencies = sorted(set(effective_dependencies))

    source_configs: dict[str, dict[str, str]] = {}
    foundry_manifest = _effective_foundry_manifest(config, project_root)
    for context, path in (
        ("foundry source config", foundry_manifest),
        ("scope_file source config", scope_path),
    ):
        if path is None:
            continue
        row = _source_config_input(
            path,
            project_root,
            context=context,
            max_file_bytes=max_file_bytes,
        )
        source_configs[row["identity"]] = row

    authority: dict[str, Any] = {
        "pipeline": pipeline,
        "ecosystem": ecosystem,
        "scope_match_mode": scope_match_mode,
        "scope_file_input": scope_file_input,
        "allow_external_scope_targets": external_policy,
        "build_root_input": build_root_input,
        "build_source_inputs": build_sources,
        "dependency_root_inputs": dependency_inputs,
        "effective_dependency_roots": effective_dependencies,
        "source_config_inputs": [
            source_configs[key]
            for key in sorted(source_configs)
        ],
        "project_root_input_digest": hashlib.sha256(
            configured_spelling.encode("utf-8", errors="strict")
        ).hexdigest(),
        "project_root_identity_digest": _project_root_identity(
            project_root
        ),
    }
    authority["selector_inputs_digest"] = _unsigned_digest(
        authority, "selector_inputs_digest"
    )
    return authority


def _tree_digest(
    candidates: Sequence[_Candidate],
    fingerprints: Mapping[str, Mapping[str, int]],
) -> str:
    rows = [
        {
            "path": candidate.portable_path,
            "scope_class": candidate.scope_class,
            "fingerprint": dict(fingerprints[candidate.portable_path]),
        }
        for candidate in candidates
    ]
    return hashlib.sha256(canonical_json_bytes(rows)).hexdigest()


def _line_starts(
    raw: bytes, *, max_starts: int = DEFAULT_MAX_LINE_STARTS
) -> list[int]:
    starts = [0]
    for index, byte in enumerate(raw):
        if byte != 10:
            continue
        starts.append(index + 1)
        if len(starts) > max_starts:
            raise ProgramFactsSourceManifestError(
                "source exceeds the bounded line-replay input limit"
            )
    return starts


def _capture_bytes_digest(
    source_bytes_by_id: Mapping[str, bytes],
    excluded_source_bytes_by_identity: Mapping[str, bytes],
) -> str:
    rows = [
        {
            "kind": "ELIGIBLE",
            "identity": identity,
            "size_bytes": len(raw),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
        }
        for identity, raw in source_bytes_by_id.items()
    ]
    rows.extend(
        {
            "kind": "EXCLUDED",
            "identity": identity,
            "size_bytes": len(raw),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
        }
        for identity, raw in excluded_source_bytes_by_identity.items()
    )
    rows.sort(key=lambda row: (row["kind"], row["identity"]))
    return hashlib.sha256(canonical_json_bytes(rows)).hexdigest()


def _debt(
    code: str,
    *,
    source_file_ids: Sequence[str] = (),
    paths: Sequence[str] = (),
) -> dict[str, Any]:
    if code not in _DEBT_CODES:
        raise ProgramFactsSourceManifestError(
            f"unsupported manifest debt code: {code}"
        )
    binding = {
        "code": code,
        "affected_source_file_ids": sorted(set(source_file_ids)),
        "affected_paths": sorted(set(paths)),
    }
    return {
        "debt_id": derive_stable_id("PFD", binding),
        **binding,
    }


def digest_compiled_denominator(
    denominator: Mapping[str, Any],
) -> str:
    """Digest compiled-denominator semantics, omitting its own digest."""

    return _unsigned_digest(denominator, "denominator_digest")


def _freeze_compiled_source_paths(
    compiled_source_paths: Sequence[str] | None,
    *,
    max_paths: int,
    max_path_bytes: int,
) -> tuple[str, ...] | None:
    """Capture one bounded concrete observation before semantic work."""

    if compiled_source_paths is None:
        return None
    if type(compiled_source_paths) not in {list, tuple}:
        raise ProgramFactsSourceManifestError(
            "compiled_source_paths must be an exact list or tuple"
        )
    frozen = tuple(compiled_source_paths)
    if len(frozen) > max_paths:
        raise ProgramFactsSourceManifestError(
            "compiled_source_paths exceeds the bounded count limit"
        )
    total_bytes = 0
    for index, value in enumerate(frozen):
        if type(value) is not str:
            raise ProgramFactsSourceManifestError(
                "compiled_source_paths must contain exact strings"
            )
        try:
            total_bytes += len(value.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as exc:
            raise ProgramFactsSourceManifestError(
                f"compiled_source_paths[{index}] is not valid UTF-8 text"
            ) from exc
        if total_bytes > max_path_bytes:
            raise ProgramFactsSourceManifestError(
                "compiled_source_paths exceeds the bounded byte limit"
            )
    return frozen


def _reconcile_compiled_denominator(
    rows: Sequence[Mapping[str, Any]],
    compiled_source_paths: Sequence[str] | None,
    *,
    base_debts: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    eligible_by_path = {str(row["path"]): str(row["source_file_id"]) for row in rows}
    eligible_ids = sorted(eligible_by_path.values())
    debts = [dict(row) for row in base_debts]

    if compiled_source_paths is None:
        debts.append(
            _debt(
                "COMPILED_DENOMINATOR_UNAVAILABLE",
                source_file_ids=eligible_ids,
            )
        )
        compiled_ids: list[str] = []
        uncompiled_ids = list(eligible_ids)
        unexpected: list[str] = []
        status = "UNKNOWN"
    else:
        if isinstance(compiled_source_paths, (str, bytes, bytearray)):
            raise ProgramFactsSourceManifestError(
                "compiled_source_paths must be an array"
            )
        normalized: list[str] = []
        for index, value in enumerate(compiled_source_paths):
            normalized.append(
                _portable_path(
                    value, f"compiled_source_paths[{index}]"
                )
            )
        if len(normalized) != len(set(normalized)):
            raise ProgramFactsSourceManifestError(
                "compiled_source_paths contains a duplicate path"
            )
        compiled_casefolds = [path.casefold() for path in normalized]
        if len(compiled_casefolds) != len(set(compiled_casefolds)):
            raise ProgramFactsSourceManifestError(
                "compiled_source_paths has a case-fold collision"
            )
        # A raw path list is an observation, not build-plan authority.  Keep
        # validating it for ambiguity and diagnostics, but never let it mint
        # compiled source IDs or FULL coverage.
        compiled_ids = []
        uncompiled_ids = list(eligible_ids)
        unexpected = sorted(
            path for path in normalized if path not in eligible_by_path
        )
        debts.append(
            _debt(
                "COMPILED_DENOMINATOR_UNTRUSTED",
                source_file_ids=eligible_ids,
                paths=normalized,
            )
        )
        if unexpected:
            debts.append(
                _debt(
                    "COMPILED_SOURCE_OUTSIDE_ELIGIBLE_DENOMINATOR",
                    paths=unexpected,
                )
            )
        unsupported = any(
            row["code"]
            in {"UNSUPPORTED_ECOSYSTEM", "SOURCE_LANGUAGE_UNSUPPORTED"}
            for row in debts
        )
        if unsupported:
            status = "UNSUPPORTED"
        else:
            status = "UNKNOWN"

    debts.sort(key=lambda row: row["debt_id"])
    denominator: dict[str, Any] = {
        "status": status,
        "eligible_source_file_ids": eligible_ids,
        "compiled_source_file_ids": compiled_ids,
        "uncompiled_source_file_ids": uncompiled_ids,
        "unexpected_compiled_paths": unexpected,
        "unresolved_debt_ids": sorted(
            row["debt_id"] for row in debts
        ),
    }
    denominator["denominator_digest"] = digest_compiled_denominator(
        denominator
    )
    return denominator, debts


def _audit_identity_from_snapshot(
    snapshot: Mapping[str, Any],
) -> ProgramFactsAuditIdentity:
    components = snapshot.get("components")
    if not isinstance(components, Mapping):
        raise ProgramFactsSourceManifestError(
            "audit snapshot components are missing"
        )
    component_digests: dict[str, str] = {}
    for component_name, identity_name in (
        ("source_scope", "source scope"),
        ("audit_config", "audit config"),
        ("methodology", "methodology"),
        ("toolchain", "toolchain"),
    ):
        component = components.get(component_name)
        if not isinstance(component, Mapping):
            raise ProgramFactsSourceManifestError(
                f"audit snapshot {component_name} component is missing"
            )
        component_digests[component_name] = _sha256(
            component.get("digest"),
            f"{identity_name} digest",
        )
    return ProgramFactsAuditIdentity(
        snapshot_digest=_sha256(
            snapshot.get("snapshot_digest"),
            "audit snapshot digest",
        ),
        source_scope_digest=component_digests["source_scope"],
        audit_config_digest=component_digests["audit_config"],
        methodology_digest=component_digests["methodology"],
        toolchain_digest=component_digests["toolchain"],
    )


def _make_live_audit_identity_rebuilder(
    builder: Any,
):
    """Pin the installed canonical builder and its local semantic closure.

    Pinning only ``build_audit_snapshot`` is insufficient: Python functions
    resolve component builders and hashing helpers through their mutable module
    globals on every call.  Capture every audit-snapshot module binding reached
    by the builder's bytecode, recursively, so replacing a direct component or
    any local helper cannot mint a new self-consistent trust root.

    Mutable memoization/diagnostic dictionaries are identity-pinned but their
    contents are deliberately not frozen.  Their contents are runtime state,
    not snapshot semantics; replacing the dictionary object still fails
    closed.
    """

    if (
        not inspect.isfunction(builder)
        or builder.__module__ != _audit_snapshot.__name__
        or builder.__name__ != "build_audit_snapshot"
    ):
        raise RuntimeError("canonical audit snapshot builder provenance is invalid")
    def function_source_digest(function: Any) -> str:
        try:
            source = inspect.getsource(function).replace("\r\n", "\n")
        except (OSError, TypeError) as exc:
            raise RuntimeError(
                "canonical audit snapshot function source is unavailable"
            ) from exc
        return hashlib.sha256(
            source.encode("utf-8", errors="strict")
        ).hexdigest()

    builder_code = builder.__code__
    builder_source_digest = function_source_digest(builder)
    builder_globals = builder.__globals__
    missing = object()
    identity_only_mutable_names = frozenset(
        {
            "_FILE_HASH_CACHE",
            "_PYTHON_PACKAGE_CACHE",
            "_PYTHON_DISTRIBUTION_CLOSURE_CACHE",
            "_RETAINED_HARDLINK_APPROVALS",
            "_RETAINED_HARDLINK_APPROVAL_TAGS",
            "_RETAINED_HARDLINK_DENIAL_FDS",
            "_TOOL_FINGERPRINT_CACHE",
            "_TOOL_PROBE_DIAGNOSTICS",
        }
    )

    def provenance_value(value: Any) -> Any:
        value_type = type(value)
        if value is None or value_type in {bool, int, str, bytes}:
            return (value_type.__name__, value)
        if isinstance(value, Path):
            return ("path", str(value))
        if isinstance(value, re.Pattern):
            return ("pattern", value.pattern, value.flags)
        if value_type in {tuple, list}:
            return (
                value_type.__name__,
                tuple(provenance_value(item) for item in value),
            )
        if value_type in {set, frozenset}:
            items = [provenance_value(item) for item in value]
            return (
                value_type.__name__,
                tuple(sorted(items, key=repr)),
            )
        if value_type is dict:
            items = [
                (provenance_value(key), provenance_value(item))
                for key, item in value.items()
            ]
            return ("dict", tuple(sorted(items, key=repr)))
        return None

    def frozen_runtime_value(value: Any) -> Any:
        """Copy semantic containers without copying modules or callables."""

        value_type = type(value)
        if value_type is dict:
            return {
                frozen_runtime_value(key): frozen_runtime_value(item)
                for key, item in value.items()
            }
        if value_type is list:
            return [frozen_runtime_value(item) for item in value]
        if value_type is tuple:
            return tuple(frozen_runtime_value(item) for item in value)
        if value_type is set:
            return {frozen_runtime_value(item) for item in value}
        if value_type is frozenset:
            return frozenset(frozen_runtime_value(item) for item in value)
        return value

    def code_global_names(code: CodeType) -> set[str]:
        names = set(code.co_names)
        for constant in code.co_consts:
            if isinstance(constant, CodeType):
                names.update(code_global_names(constant))
        return names

    bindings: dict[
        str,
        tuple[Any, Any, Any, Any, Any, Any],
    ] = {}
    pending = [builder]
    visited_functions: set[int] = set()
    while pending:
        function = pending.pop()
        if id(function) in visited_functions:
            continue
        visited_functions.add(id(function))
        for name in code_global_names(function.__code__):
            value = builder_globals.get(name, missing)
            if value is missing:
                continue
            stable_value = (
                None
                if name in identity_only_mutable_names
                else provenance_value(value)
            )
            local_function = (
                inspect.isfunction(value)
                and value.__module__ == _audit_snapshot.__name__
            )
            if name not in bindings:
                bindings[name] = (
                    value,
                    stable_value,
                    (
                        value.__code__
                        if local_function
                        else None
                    ),
                    (
                        function_source_digest(value)
                        if local_function
                        else None
                    ),
                    (
                        provenance_value(value.__defaults__)
                        if local_function
                        else None
                    ),
                    (
                        provenance_value(value.__kwdefaults__)
                        if local_function
                        else None
                    ),
                )
            if local_function:
                pending.append(value)
    frozen_bindings = tuple(sorted(bindings.items()))
    frozen_globals = dict(builder_globals)
    for name, (
        expected_value,
        expected_stable_value,
        expected_code,
        _expected_source_digest,
        _expected_defaults,
        _expected_kwdefaults,
    ) in frozen_bindings:
        if name in identity_only_mutable_names:
            # Caches belong to the private semantic clone.  Live module cache
            # poisoning therefore cannot influence the rebuilt identity.
            frozen_globals[name] = {}
        elif expected_code is None and expected_stable_value is not None:
            frozen_globals[name] = frozen_runtime_value(expected_value)

    cloned_functions: dict[str, Any] = {}
    for name, (
        expected_value,
        _expected_stable_value,
        expected_code,
        _expected_source_digest,
        _expected_defaults,
        _expected_kwdefaults,
    ) in frozen_bindings:
        if expected_code is None:
            continue
        if expected_value.__closure__ is not None:
            raise RuntimeError(
                "canonical audit snapshot module function unexpectedly "
                f"captures a closure: {name}"
            )
        clone = FunctionType(
            expected_code,
            frozen_globals,
            name,
            frozen_runtime_value(expected_value.__defaults__),
        )
        clone.__kwdefaults__ = frozen_runtime_value(
            expected_value.__kwdefaults__
        )
        clone.__module__ = expected_value.__module__
        clone.__qualname__ = expected_value.__qualname__
        cloned_functions[name] = clone
    frozen_globals.update(cloned_functions)
    frozen_builder = FunctionType(
        builder_code,
        frozen_globals,
        builder.__name__,
        frozen_runtime_value(builder.__defaults__),
    )
    frozen_builder.__kwdefaults__ = frozen_runtime_value(
        builder.__kwdefaults__
    )
    frozen_builder.__module__ = builder.__module__
    frozen_builder.__qualname__ = builder.__qualname__

    def rebuild(
        config: Mapping[str, Any],
    ) -> ProgramFactsAuditIdentity:
        current_public_builder = getattr(
            _audit_snapshot,
            "build_audit_snapshot",
            None,
        )
        try:
            current_source_digest = function_source_digest(builder)
        except RuntimeError as exc:
            raise ProgramFactsSourceManifestError(
                "canonical audit snapshot builder provenance cannot replay"
            ) from exc
        if (
            current_public_builder is not builder
            or builder.__code__ is not builder_code
            or current_source_digest != builder_source_digest
        ):
            raise ProgramFactsSourceManifestError(
                "canonical audit snapshot builder was replaced or mutated"
            )
        for (
            name,
            (
                expected_value,
                expected_stable_value,
                expected_code,
                expected_source_digest,
                expected_defaults,
                expected_kwdefaults,
            ),
        ) in frozen_bindings:
            current_value = builder_globals.get(name, missing)
            if current_value is missing:
                raise ProgramFactsSourceManifestError(
                    "canonical audit snapshot builder dependency is missing"
                )
            if expected_code is not None:
                try:
                    current_dependency_source_digest = (
                        function_source_digest(current_value)
                    )
                except RuntimeError as exc:
                    raise ProgramFactsSourceManifestError(
                        "canonical audit snapshot builder dependency "
                        f"source cannot replay: {name}"
                    ) from exc
                if (
                    current_value is not expected_value
                    or not inspect.isfunction(current_value)
                    or current_value.__code__ is not expected_code
                    or current_dependency_source_digest
                    != expected_source_digest
                    or provenance_value(current_value.__defaults__)
                    != expected_defaults
                    or provenance_value(current_value.__kwdefaults__)
                    != expected_kwdefaults
                ):
                    raise ProgramFactsSourceManifestError(
                        "canonical audit snapshot builder dependency was "
                        f"replaced or mutated: {name}"
                    )
            elif expected_stable_value is not None:
                if provenance_value(current_value) != expected_stable_value:
                    raise ProgramFactsSourceManifestError(
                        "canonical audit snapshot builder constant changed: "
                        f"{name}"
                    )
            elif current_value is not expected_value:
                raise ProgramFactsSourceManifestError(
                    "canonical audit snapshot builder dependency changed: "
                    f"{name}"
                )
        try:
            implementation_root = (
                Path(__file__).resolve(strict=True).parent.parent
            )
            rebuilt = frozen_builder(config, implementation_root)
        except Exception as exc:
            raise ProgramFactsSourceManifestError(
                "canonical live audit identity cannot be rebuilt"
            ) from exc
        if not isinstance(rebuilt, Mapping):
            raise ProgramFactsSourceManifestError(
                "canonical audit snapshot builder returned malformed identity"
            )
        validator = getattr(_audit_snapshot, "_valid_snapshot", None)
        if (
            validator is None
            or not callable(validator)
            or not validator(dict(rebuilt))
        ):
            raise ProgramFactsSourceManifestError(
                "canonical live audit snapshot failed validation"
            )
        return _audit_identity_from_snapshot(rebuilt)

    return rebuild


_live_audit_identity = _make_live_audit_identity_rebuilder(
    _audit_snapshot.build_audit_snapshot
)
del _make_live_audit_identity_rebuilder


def _parent_digests(
    snapshot: Mapping[str, Any],
    config: Mapping[str, Any],
) -> tuple[str, str, tuple[str, ...]]:
    if not isinstance(snapshot, Mapping):
        raise ProgramFactsSourceManifestError(
            "audit_snapshot must be an object"
        )
    validator = getattr(_audit_snapshot, "_valid_snapshot", None)
    if validator is None or not callable(validator):
        raise ProgramFactsSourceManifestError(
            "shared audit snapshot validator is unavailable"
        )
    if not validator(dict(snapshot)):
        raise ProgramFactsSourceManifestError(
            "audit_snapshot is not an intact canonical snapshot"
        )
    audit_identity = _audit_identity_from_snapshot(snapshot)
    snapshot_digest = audit_identity.snapshot_digest
    components = snapshot.get("components")
    if not isinstance(components, Mapping):
        raise ProgramFactsSourceManifestError(
            "audit snapshot components are missing"
        )
    source_scope = components.get("source_scope")
    if not isinstance(source_scope, Mapping):
        raise ProgramFactsSourceManifestError(
            "audit snapshot source_scope component is missing"
        )
    source_scope_digest = audit_identity.source_scope_digest
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    ecosystem = str(config.get("language") or "").strip().lower()
    if source_scope.get("pipeline") != pipeline:
        raise ProgramFactsSourceManifestError(
            "audit snapshot pipeline does not match manifest config"
        )
    if source_scope.get("language") != ecosystem:
        raise ProgramFactsSourceManifestError(
            "audit snapshot language does not match manifest config"
        )
    raw_limitations = source_scope.get("coverage_limitations")
    if not isinstance(raw_limitations, list) or not all(
        isinstance(item, str) for item in raw_limitations
    ):
        raise ProgramFactsSourceManifestError(
            "audit snapshot source limitations are malformed"
        )
    limitation_digests = tuple(
        sorted(
            hashlib.sha256(
                item.encode("utf-8", errors="strict")
            ).hexdigest()
            for item in raw_limitations
        )
    )
    return snapshot_digest, source_scope_digest, limitation_digests


def _validate_current_snapshot_source_component(
    config: Mapping[str, Any],
    expected_source_scope_digest: str,
) -> None:
    """Replay the complete current source component against its parent."""

    builder = getattr(_audit_snapshot, "_source_component", None)
    if builder is None or not callable(builder):
        raise ProgramFactsSourceManifestError(
            "shared audit snapshot source component is unavailable"
        )
    try:
        current = builder(config)
    except Exception as exc:
        raise ProgramFactsSourceManifestError(
            "current audit snapshot source component cannot be replayed"
        ) from exc
    if not isinstance(current, Mapping):
        raise ProgramFactsSourceManifestError(
            "current audit snapshot source component is malformed"
        )
    current_digest = _sha256(
        current.get("digest"), "current source scope digest"
    )
    if current_digest != expected_source_scope_digest:
        raise ProgramFactsSourceManifestError(
            "audit snapshot source scope selection denominator or config "
            "input is stale relative to the current project inputs"
        )


def capture_program_facts_audit_snapshot_authority(
    audit_snapshot: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
) -> ProgramFactsAuditSnapshotAuthority:
    """Validate and freeze one exact snapshot/config trust root."""

    frozen_snapshot = _fresh_json_mapping(
        audit_snapshot, "audit_snapshot"
    )
    frozen_config = _fresh_json_mapping(config, "config")
    snapshot_digest, source_scope_digest, _limitations = _parent_digests(
        frozen_snapshot,
        frozen_config,
    )
    audit_identity = _audit_identity_from_snapshot(frozen_snapshot)
    if audit_identity != _live_audit_identity(frozen_config):
        raise ProgramFactsSourceManifestError(
            "audit snapshot identity differs from canonical live audit "
            "config, methodology, toolchain, or source authority"
        )
    _validate_current_snapshot_source_component(
        frozen_config,
        source_scope_digest,
    )
    return _issue_audit_snapshot_authority(
        ProgramFactsAuditSnapshotAuthority,
        snapshot=_freeze(frozen_snapshot),
        config=_freeze(frozen_config),
        snapshot_bytes=canonical_json_bytes(frozen_snapshot),
        config_bytes=canonical_json_bytes(frozen_config),
        snapshot_digest=snapshot_digest,
        source_scope_digest=source_scope_digest,
        audit_config_digest=audit_identity.audit_config_digest,
        methodology_digest=audit_identity.methodology_digest,
        toolchain_digest=audit_identity.toolchain_digest,
    )


def replay_program_facts_audit_snapshot_authority(
    authority: ProgramFactsAuditSnapshotAuthority,
    *,
    project_root: str | Path,
    config: Mapping[str, Any],
) -> ReplayedProgramFactsAuditSnapshotAuthority:
    """Replay a separately captured snapshot trust root at a sink."""

    if type(authority) not in {
        ProgramFactsAuditSnapshotAuthority,
        ReplayedProgramFactsAuditSnapshotAuthority,
    } or not _audit_snapshot_authority_is_issued(authority):
        raise ProgramFactsSourceManifestError(
            "production requires exact issued audit-snapshot authority"
        )
    frozen_config = _fresh_json_mapping(config, "config")
    try:
        frozen_snapshot = strict_json_loads(
            authority.snapshot_bytes,
            require_final_lf=False,
            require_canonical=True,
        )
    except ProgramFactsTypeError as exc:
        raise ProgramFactsSourceManifestError(
            "audit-snapshot authority bytes do not replay"
        ) from exc
    if type(frozen_snapshot) is not dict:
        raise ProgramFactsSourceManifestError(
            "audit-snapshot authority bytes are not an object"
        )
    if (
        canonical_json_bytes(frozen_snapshot) != authority.snapshot_bytes
        or canonical_json_bytes(frozen_config) != authority.config_bytes
        or canonical_json_bytes(authority.snapshot)
        != authority.snapshot_bytes
        or canonical_json_bytes(authority.config) != authority.config_bytes
    ):
        raise ProgramFactsSourceManifestError(
            "audit-snapshot authority capture or config was substituted"
        )
    snapshot_digest, source_scope_digest, _limitations = _parent_digests(
        frozen_snapshot,
        frozen_config,
    )
    audit_identity = _audit_identity_from_snapshot(frozen_snapshot)
    if audit_identity != _live_audit_identity(frozen_config):
        raise ProgramFactsSourceManifestError(
            "audit-snapshot authority differs from canonical live audit "
            "config, methodology, toolchain, or source authority"
        )
    if (
        snapshot_digest != authority.snapshot_digest
        or source_scope_digest != authority.source_scope_digest
        or audit_identity.audit_config_digest
        != authority.audit_config_digest
        or audit_identity.methodology_digest
        != authority.methodology_digest
        or audit_identity.toolchain_digest != authority.toolchain_digest
    ):
        raise ProgramFactsSourceManifestError(
            "audit-snapshot authority parent digest changed"
        )
    root = Path(project_root).expanduser().absolute()
    _validate_project_root(root)
    configured_root = Path(
        str(frozen_config.get("project_root") or "")
    ).expanduser().absolute()
    try:
        if configured_root.resolve(strict=True) != root.resolve(strict=True):
            raise ProgramFactsSourceManifestError(
                "audit-snapshot authority project root differs from config"
            )
    except OSError as exc:
        raise ProgramFactsSourceManifestError(
            "audit-snapshot authority project root cannot be resolved"
        ) from exc
    _validate_current_snapshot_source_component(
        frozen_config,
        source_scope_digest,
    )
    return _issue_audit_snapshot_authority(
        ReplayedProgramFactsAuditSnapshotAuthority,
        snapshot=_freeze(frozen_snapshot),
        config=_freeze(frozen_config),
        snapshot_bytes=authority.snapshot_bytes,
        config_bytes=authority.config_bytes,
        snapshot_digest=snapshot_digest,
        source_scope_digest=source_scope_digest,
        audit_config_digest=audit_identity.audit_config_digest,
        methodology_digest=audit_identity.methodology_digest,
        toolchain_digest=audit_identity.toolchain_digest,
    )


def _base_debts(
    config: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    *,
    excluded_paths: Sequence[str],
    explicit_scope_spelling_unavailable: bool,
    snapshot_limitation_digests: Sequence[str],
) -> list[dict[str, Any]]:
    ecosystem = str(config.get("language") or "").strip().lower()
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    all_ids = [str(row["source_file_id"]) for row in rows]
    debts: list[dict[str, Any]] = []
    if excluded_paths:
        debts.append(
            _debt("SOURCE_EXCLUDED", paths=excluded_paths)
        )
    if pipeline == "sc" and ecosystem not in _SUPPORTED_ECOSYSTEMS:
        debts.append(
            _debt("UNSUPPORTED_ECOSYSTEM", source_file_ids=all_ids)
        )
    unsupported_ids = [
        str(row["source_file_id"])
        for row in rows
        if row["language"] == "protobuf"
    ]
    if unsupported_ids:
        debts.append(
            _debt(
                "SOURCE_LANGUAGE_UNSUPPORTED",
                source_file_ids=unsupported_ids,
            )
        )
    vyper_ids = [
        str(row["source_file_id"])
        for row in rows
        if row["language"] == "vyper"
    ]
    if vyper_ids:
        debts.append(
            _debt(
                "SOURCE_LANGUAGE_COVERAGE_UNPROVEN",
                source_file_ids=vyper_ids,
            )
        )
    if explicit_scope_spelling_unavailable:
        debts.append(
            _debt(
                "EXPLICIT_SCOPE_PHYSICAL_SPELLING_UNAVAILABLE",
                source_file_ids=[
                    str(row["source_file_id"])
                    for row in rows
                    if row["scope_class"] == "EXPLICIT_SCOPE"
                ],
            )
        )
    if snapshot_limitation_digests:
        debts.append(
            _debt(
                "SNAPSHOT_SOURCE_SCOPE_LIMITED",
                source_file_ids=all_ids,
                paths=[
                    f"@limitation/{digest}"
                    for digest in snapshot_limitation_digests
                ],
            )
        )
    return debts


def build_program_facts_source_manifest(
    config: Mapping[str, Any],
    audit_snapshot: Mapping[str, Any],
    *,
    compiled_source_paths: Sequence[str] | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_line_starts: int = DEFAULT_MAX_LINE_STARTS,
    max_manifest_bytes: int = DEFAULT_MAX_MANIFEST_BYTES,
    max_compiled_source_paths: int = (
        DEFAULT_MAX_COMPILED_SOURCE_PATHS
    ),
    max_compiled_source_path_bytes: int = (
        DEFAULT_MAX_COMPILED_SOURCE_PATH_BYTES
    ),
) -> ProgramFactsSourceManifestAuthority:
    """Capture an exact immutable source denominator bound to its parent.

    ``compiled_source_paths`` is an untrusted project-relative observation.
    It is validated and recorded as typed debt, but cannot mint compiled IDs
    or full coverage without a separate build-plan authority.
    """

    if not isinstance(config, Mapping):
        raise ProgramFactsSourceManifestError("config must be an object")
    config = _fresh_json_mapping(config, "config")
    audit_snapshot = _fresh_json_mapping(
        audit_snapshot, "audit_snapshot"
    )
    max_files = _nonnegative_int(max_files, "max_files")
    max_file_bytes = _positive_int(max_file_bytes, "max_file_bytes")
    max_total_bytes = _positive_int(max_total_bytes, "max_total_bytes")
    max_line_starts = _positive_int(max_line_starts, "max_line_starts")
    max_manifest_bytes = _positive_int(
        max_manifest_bytes, "max_manifest_bytes"
    )
    max_compiled_source_paths = _nonnegative_int(
        max_compiled_source_paths,
        "max_compiled_source_paths",
    )
    max_compiled_source_path_bytes = _positive_int(
        max_compiled_source_path_bytes,
        "max_compiled_source_path_bytes",
    )
    frozen_compiled_source_paths = _freeze_compiled_source_paths(
        compiled_source_paths,
        max_paths=max_compiled_source_paths,
        max_path_bytes=max_compiled_source_path_bytes,
    )
    (
        snapshot_digest,
        source_scope_digest,
        snapshot_limitation_digests,
    ) = _parent_digests(audit_snapshot, config)
    _validate_current_snapshot_source_component(
        config, source_scope_digest
    )
    raw_root = str(config.get("project_root") or "").strip()
    if not raw_root:
        raise ProgramFactsSourceManifestError("project_root is required")
    project_root = Path(raw_root).expanduser().absolute()
    _validate_project_root(project_root)
    suffixes = _suffixes_for(config)
    policy = _selection_policy(config, suffixes)
    selector_authority = _selector_authority(
        config,
        project_root,
        max_file_bytes=max_file_bytes,
    )

    try:
        (
            candidates,
            excluded_candidates,
            exclusion_reasons,
            explicit_scope_spelling_unavailable,
        ) = _collect_candidates(config, project_root, suffixes)
    except SharedSourceSelectionUnavailable as exc:
        raise ProgramFactsSourceManifestError(
            f"shared source selection unavailable: {exc}"
        ) from exc
    all_candidates = [*candidates, *excluded_candidates]
    if len(all_candidates) > max_files:
        raise ProgramFactsSourceManifestError(
            "source denominator exceeds the bounded file-count limit"
        )
    if not candidates:
        raise ProgramFactsSourceManifestError(
            "shared source selection found no auditable source"
        )

    reads: dict[str, _StableRead] = {}
    pre_fingerprints: dict[str, Mapping[str, int]] = {}
    physical_ids: dict[str, str] = {}
    total_capture_bytes = 0
    for candidate in all_candidates:
        stable = _read_regular_file_stably(
            candidate.inspection_path,
            context=f"source {candidate.portable_path}",
            max_file_bytes=max_file_bytes,
        )
        previous = physical_ids.get(stable.physical_identity_digest)
        if previous is not None and previous != candidate.portable_path:
            raise ProgramFactsSourceManifestError(
                "source denominator has a physical-identity alias collision"
            )
        physical_ids[stable.physical_identity_digest] = (
            candidate.portable_path
        )
        total_capture_bytes += len(stable.raw)
        if total_capture_bytes > max_total_bytes:
            raise ProgramFactsSourceManifestError(
                "source denominator exceeds the bounded total byte limit"
            )
        reads[candidate.portable_path] = stable
        pre_fingerprints[candidate.portable_path] = stable.pre_fingerprint

    try:
        (
            post_candidates,
            post_excluded_candidates,
            post_exclusion_reasons,
            _post_scope_gap,
        ) = _collect_candidates(config, project_root, suffixes)
    except SharedSourceSelectionUnavailable as exc:
        raise ProgramFactsSourceManifestError(
            f"shared source selection unavailable: {exc}"
        ) from exc
    post_all_candidates = [
        *post_candidates,
        *post_excluded_candidates,
    ]
    pre_selection = [
        (row.portable_path, row.scope_class) for row in all_candidates
    ]
    post_selection = [
        (row.portable_path, row.scope_class)
        for row in post_all_candidates
    ]
    if (
        pre_selection != post_selection
        or dict(exclusion_reasons) != dict(post_exclusion_reasons)
    ):
        raise ProgramFactsSourceManifestError(
            "source tree changed during manifest capture"
        )
    post_selector_authority = _selector_authority(
        config,
        project_root,
        max_file_bytes=max_file_bytes,
    )
    if post_selector_authority != selector_authority:
        raise ProgramFactsSourceManifestError(
            "selector inputs changed during manifest capture"
        )

    post_fingerprints: dict[str, Mapping[str, int]] = {}
    for candidate in post_all_candidates:
        replay_read = _read_regular_file_stably(
            candidate.inspection_path,
            context=f"source {candidate.portable_path}",
            max_file_bytes=max_file_bytes,
        )
        fingerprint = replay_read.post_fingerprint
        post_fingerprints[candidate.portable_path] = fingerprint
        if fingerprint != dict(
            pre_fingerprints[candidate.portable_path]
        ):
            raise ProgramFactsSourceManifestError(
                "source tree changed during manifest capture"
            )
        if replay_read.raw != reads[candidate.portable_path].raw:
            raise ProgramFactsSourceManifestError(
                "source bytes changed during manifest capture"
            )

    source_rows: list[dict[str, Any]] = []
    excluded_rows: list[dict[str, Any]] = []
    line_rows: list[dict[str, Any]] = []
    source_bytes: dict[str, bytes] = {}
    excluded_source_bytes: dict[str, bytes] = {}
    physical_inventory: list[dict[str, str]] = []
    source_suffix_bindings: list[dict[str, str]] = []
    eligible_total_bytes = 0
    for candidate in candidates:
        stable = reads[candidate.portable_path]
        eligible_total_bytes += len(stable.raw)
        source_sha256 = hashlib.sha256(stable.raw).hexdigest()
        language = _SOURCE_LANGUAGES.get(
            candidate.physical_path.suffix.casefold()
        )
        if language is None:
            raise ProgramFactsSourceManifestError(
                "shared selector emitted an unclassified source suffix"
            )
        binding = {
            "source_scope_digest": source_scope_digest,
            "path": candidate.portable_path,
            "source_sha256": source_sha256,
            "scope_class": candidate.scope_class,
        }
        row = {
            "source_file_id": derive_stable_id("PFS", binding),
            "path": candidate.portable_path,
            "path_casefold_key": candidate.portable_path.casefold(),
            "source_sha256": source_sha256,
            "size_bytes": len(stable.raw),
            "language": language,
            "scope_class": candidate.scope_class,
            "physical_identity_digest": (
                stable.physical_identity_digest
            ),
        }
        source_rows.append(row)
        physical_inventory.append(
            {
                "kind": "ELIGIBLE",
                "identity": row["source_file_id"],
                "physical_identity_digest": (
                    stable.physical_identity_digest
                ),
            }
        )
        source_suffix_bindings.append(
            {
                "source_file_id": row["source_file_id"],
                "suffix": candidate.physical_path.suffix.casefold(),
            }
        )
        line_rows.append(
            {
                "source_file_id": row["source_file_id"],
                "line_start_byte_offsets": _line_starts(
                    stable.raw, max_starts=max_line_starts
                ),
            }
        )
        source_bytes[row["source_file_id"]] = stable.raw

    for candidate in excluded_candidates:
        stable = reads[candidate.portable_path]
        excluded_rows.append(
            {
                "identity": candidate.portable_path,
                "reason": exclusion_reasons[candidate.portable_path],
                "source_sha256": hashlib.sha256(stable.raw).hexdigest(),
            }
        )
        physical_inventory.append(
            {
                "kind": "EXCLUDED",
                "identity": candidate.portable_path,
                "physical_identity_digest": (
                    stable.physical_identity_digest
                ),
            }
        )
        excluded_source_bytes[candidate.portable_path] = stable.raw
    source_rows.sort(key=lambda row: row["source_file_id"])
    excluded_rows.sort(key=lambda row: row["identity"])
    line_rows.sort(key=lambda row: row["source_file_id"])
    physical_inventory.sort(
        key=lambda row: (row["kind"], row["identity"])
    )
    source_suffix_bindings.sort(
        key=lambda row: row["source_file_id"]
    )
    source_manifest: dict[str, Any] = {
        "policy_version": "plamen.program_facts_source_scope.v1",
        "eligible_files": source_rows,
        "excluded_files": excluded_rows,
        "file_count": len(source_rows),
        "byte_count": eligible_total_bytes,
    }
    source_manifest["manifest_digest"] = derive_source_manifest_digest(
        source_manifest
    )
    base_debts = _base_debts(
        config,
        source_rows,
        excluded_paths=[
            str(row["identity"]) for row in excluded_rows
        ],
        explicit_scope_spelling_unavailable=(
            explicit_scope_spelling_unavailable
        ),
        snapshot_limitation_digests=snapshot_limitation_digests,
    )
    denominator, debts = _reconcile_compiled_denominator(
        source_rows,
        frozen_compiled_source_paths,
        base_debts=base_debts,
    )
    pre_tree = _tree_digest(all_candidates, pre_fingerprints)
    post_tree = _tree_digest(post_all_candidates, post_fingerprints)
    if pre_tree != post_tree:
        raise ProgramFactsSourceManifestError(
            "source tree identity changed during manifest capture"
        )
    _validate_current_snapshot_source_component(
        config, source_scope_digest
    )

    record: dict[str, Any] = {
        "schema_version": SOURCE_MANIFEST_AUTHORITY_SCHEMA,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "snapshot_ref": {
            "snapshot_digest": f"sha256:{snapshot_digest}",
            "source_scope_digest": f"sha256:{source_scope_digest}",
        },
        "selection_policy": policy,
        "selector_authority": selector_authority,
        "source_manifest": source_manifest,
        "physical_identity_inventory": physical_inventory,
        "source_suffix_bindings": source_suffix_bindings,
        "line_replay_inputs": line_rows,
        "compiled_denominator": denominator,
        "debts": debts,
        "tree_identity": {
            "pre_digest": pre_tree,
            "post_digest": post_tree,
            "stable": True,
        },
    }
    record["authority_digest"] = _unsigned_digest(
        record, "authority_digest"
    )
    raw = canonical_file_bytes(record)
    if len(raw) > max_manifest_bytes:
        raise ProgramFactsSourceManifestError(
            "source manifest exceeds the bounded canonical-byte limit"
        )
    parsed = parse_program_facts_source_manifest_shape(
        raw, max_bytes=max_manifest_bytes
    )
    capture_capability = _issue_capture_capability(
        authority_digest=record["authority_digest"],
        snapshot_digest=snapshot_digest,
        source_scope_digest=source_scope_digest,
        capture_digest=_capture_bytes_digest(
            source_bytes,
            excluded_source_bytes,
        ),
    )
    authority = _issue_manifest_authority(
        ProgramFactsSourceManifestAuthority,
        record=parsed.record,
        canonical_bytes=raw,
        authority_digest=record["authority_digest"],
        file_sha256=parsed.file_sha256,
        source_bytes_by_id=MappingProxyType(dict(source_bytes)),
        excluded_source_bytes_by_identity=MappingProxyType(
            dict(excluded_source_bytes)
        ),
        capture_capability=capture_capability,
    )
    assert isinstance(authority, ProgramFactsSourceManifestAuthority)
    return authority


def _validate_selection_policy(value: Any) -> None:
    policy = _require_exact_keys(value, _POLICY_KEYS, "selection_policy")
    if policy["policy_version"] != SOURCE_MANIFEST_POLICY_VERSION:
        raise ProgramFactsSourceManifestError(
            "selection_policy.policy_version is unsupported"
        )
    if policy["shared_selector"] != (
        "audit_snapshot._casefold_production_source_files"
    ):
        raise ProgramFactsSourceManifestError(
            "selection_policy.shared_selector is unsupported"
        )
    if policy["production_scope_predicate"] != (
        "production_source_scope.is_production_source_path"
    ):
        raise ProgramFactsSourceManifestError(
            "selection_policy production predicate is unsupported"
        )
    if policy["generated_verification_policy"] != (
        "audit_snapshot._is_generated_verification_source"
    ):
        raise ProgramFactsSourceManifestError(
            "selection_policy generated policy is unsupported"
        )
    if policy["exclusion_inventory"] != (
        "audit_snapshot._project_context_files"
        "+bounded_source_exclusion_walk"
    ):
        raise ProgramFactsSourceManifestError(
            "selection_policy exclusion inventory is unsupported"
        )
    if policy["generated_source_exclusion_mode"] != (
        "INVENTORY_GENERATED_SOURCE_AS_EXCLUDED_UNLESS_BOUND"
    ):
        raise ProgramFactsSourceManifestError(
            "selection_policy generated exclusion mode is unsupported"
        )
    _sha256(
        policy["selector_bridge_digest"],
        "selection_policy.selector_bridge_digest",
    )
    suffixes = _require_sorted_unique(
        policy["include_suffixes"], "selection_policy.include_suffixes"
    )
    if any(
        item not in ALL_AUDIT_SOURCE_SUFFIXES for item in suffixes
    ):
        raise ProgramFactsSourceManifestError(
            "selection_policy has an unsupported source suffix"
        )
    universe = _require_sorted_unique(
        policy["source_suffix_universe"],
        "selection_policy.source_suffix_universe",
    )
    if universe != sorted(set(ALL_AUDIT_SOURCE_SUFFIXES)):
        raise ProgramFactsSourceManifestError(
            "selection_policy source suffix universe mismatch"
        )
    expected_literals = {
        "symlink_policy": "REJECT_ALL",
        "junction_reparse_policy": "REJECT_ALL",
        "hardlink_policy": "REJECT_DUPLICATE_PHYSICAL_IDENTITY",
        "sparse_file_policy": "REJECT_ALL",
        "regular_file_policy": "PHYSICAL_REGULAR_FILES_ONLY",
    }
    for field, expected in expected_literals.items():
        if policy[field] != expected:
            raise ProgramFactsSourceManifestError(
                f"selection_policy.{field} is unsupported"
            )
    claimed = _sha256(
        policy["policy_digest"], "selection_policy.policy_digest"
    )
    if claimed != _unsigned_digest(policy, "policy_digest"):
        raise ProgramFactsSourceManifestError(
            "selection_policy policy digest mismatch"
        )


def _selector_identity(value: Any, field: str, *, sentinels: set[str]) -> str:
    if not isinstance(value, str) or not value:
        raise ProgramFactsSourceManifestError(
            f"{field} must be a nonempty normalized identity"
        )
    if value in sentinels or value == ".":
        return value
    return _portable_path(value, field)


def _validate_selector_authority(value: Any) -> None:
    authority = _require_exact_keys(
        value, _SELECTOR_AUTHORITY_KEYS, "selector_authority"
    )
    if authority["pipeline"] not in {"sc", "l1"}:
        raise ProgramFactsSourceManifestError(
            "selector_authority.pipeline is unsupported"
        )
    ecosystem = authority["ecosystem"]
    if (
        not isinstance(ecosystem, str)
        or ecosystem != ecosystem.strip().lower()
        or ecosystem != unicodedata.normalize("NFC", ecosystem)
        or any(ord(char) < 32 or ord(char) == 127 for char in ecosystem)
    ):
        raise ProgramFactsSourceManifestError(
            "selector_authority.ecosystem must be normalized text"
        )
    try:
        normalized_scope = normalize_scope_match_mode(
            authority["scope_match_mode"]
        )
    except ValueError as exc:
        raise ProgramFactsSourceManifestError(str(exc)) from exc
    if normalized_scope != authority["scope_match_mode"]:
        raise ProgramFactsSourceManifestError(
            "selector_authority.scope_match_mode is not normalized"
        )
    if authority["scope_file_input"] is not None:
        _selector_identity(
            authority["scope_file_input"],
            "selector_authority.scope_file_input",
            sentinels=set(),
        )
    if not isinstance(authority["allow_external_scope_targets"], bool):
        raise ProgramFactsSourceManifestError(
            "selector_authority.allow_external_scope_targets must be boolean"
        )
    if authority["build_root_input"] is not None:
        _selector_identity(
            authority["build_root_input"],
            "selector_authority.build_root_input",
            sentinels=set(),
        )
    for field in (
        "build_source_inputs",
        "dependency_root_inputs",
        "effective_dependency_roots",
    ):
        rows = _require_sorted_unique(
            authority[field], f"selector_authority.{field}"
        )
        folded = [str(identity).casefold() for identity in rows]
        if len(folded) != len(set(folded)):
            raise ProgramFactsSourceManifestError(
                f"selector_authority.{field} has a case-fold collision"
            )
        for index, identity in enumerate(rows):
            _selector_identity(
                identity,
                f"selector_authority.{field}[{index}]",
                sentinels=set(),
            )
    config_rows = _require_sorted_unique(
        authority["source_config_inputs"],
        "selector_authority.source_config_inputs",
        row_key="identity",
    )
    config_folded = [
        str(row["identity"]).casefold() for row in config_rows
    ]
    if len(config_folded) != len(set(config_folded)):
        raise ProgramFactsSourceManifestError(
            "selector_authority.source_config_inputs has a case-fold collision"
        )
    for index, raw_row in enumerate(config_rows):
        row = _require_exact_keys(
            raw_row,
            _SOURCE_CONFIG_INPUT_KEYS,
            f"selector_authority.source_config_inputs[{index}]",
        )
        _selector_identity(
            row["identity"],
            f"selector_authority.source_config_inputs[{index}].identity",
            sentinels=set(),
        )
        _sha256(
            row["source_sha256"],
            f"selector_authority.source_config_inputs[{index}].source_sha256",
        )
    _sha256(
        authority["project_root_input_digest"],
        "selector_authority.project_root_input_digest",
    )
    _sha256(
        authority["project_root_identity_digest"],
        "selector_authority.project_root_identity_digest",
    )
    claimed = _sha256(
        authority["selector_inputs_digest"],
        "selector_authority.selector_inputs_digest",
    )
    if claimed != _unsigned_digest(authority, "selector_inputs_digest"):
        raise ProgramFactsSourceManifestError(
            "selector_authority selector input digest mismatch"
        )


def _validate_source_suffix_bindings(
    value: Any,
    eligible: Sequence[Mapping[str, Any]],
) -> Mapping[str, str]:
    rows = _require_sorted_unique(
        value,
        "source_suffix_bindings",
        row_key="source_file_id",
    )
    by_id: dict[str, str] = {}
    eligible_by_id = {
        str(row["source_file_id"]): row for row in eligible
    }
    for index, raw_row in enumerate(rows):
        row = _require_exact_keys(
            raw_row,
            _SOURCE_SUFFIX_BINDING_KEYS,
            f"source_suffix_bindings[{index}]",
        )
        source_id = row["source_file_id"]
        if source_id not in eligible_by_id:
            raise ProgramFactsSourceManifestError(
                "source suffix binding references an unknown source_file_id"
            )
        suffix = row["suffix"]
        if (
            not isinstance(suffix, str)
            or suffix != suffix.casefold()
            or suffix not in _SOURCE_LANGUAGES
        ):
            raise ProgramFactsSourceManifestError(
                "source suffix binding is outside the closed suffix policy"
            )
        source = eligible_by_id[source_id]
        expected_language = _SOURCE_LANGUAGES[suffix]
        if source["language"] != expected_language:
            raise ProgramFactsSourceManifestError(
                "source language does not match its closed suffix binding"
            )
        path = str(source["path"])
        if (
            not path.startswith("@outside/")
            and Path(path).suffix.casefold() != suffix
        ):
            raise ProgramFactsSourceManifestError(
                "source suffix binding does not match its portable path"
            )
        by_id[str(source_id)] = suffix
    if set(by_id) != set(eligible_by_id):
        raise ProgramFactsSourceManifestError(
            "source suffix bindings do not cover the exact source denominator"
        )
    return MappingProxyType(by_id)


def _validate_physical_identity_inventory(
    value: Any,
    eligible: Sequence[Mapping[str, Any]],
    excluded: Sequence[Mapping[str, Any]],
) -> Mapping[tuple[str, str], str]:
    if not isinstance(value, list):
        raise ProgramFactsSourceManifestError(
            "physical_identity_inventory must be an array"
        )
    rows: list[Mapping[str, Any]] = []
    keys: list[tuple[str, str]] = []
    physical_ids: set[str] = set()
    for index, raw_row in enumerate(value):
        row = _require_exact_keys(
            raw_row,
            _PHYSICAL_INVENTORY_KEYS,
            f"physical_identity_inventory[{index}]",
        )
        kind = row["kind"]
        if kind not in {"ELIGIBLE", "EXCLUDED"}:
            raise ProgramFactsSourceManifestError(
                "physical identity kind is outside the closed policy"
            )
        identity = row["identity"]
        if not isinstance(identity, str) or not identity:
            raise ProgramFactsSourceManifestError(
                "physical identity inventory identity must be nonempty text"
            )
        key = (str(kind), identity)
        keys.append(key)
        digest = _sha256(
            row["physical_identity_digest"],
            "physical identity inventory digest",
        )
        if digest in physical_ids:
            raise ProgramFactsSourceManifestError(
                "source denominator has a physical-identity alias collision"
            )
        physical_ids.add(digest)
        rows.append(row)
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ProgramFactsSourceManifestError(
            "physical identity inventory must be sorted and unique"
        )
    expected_keys = {
        ("ELIGIBLE", str(row["source_file_id"])) for row in eligible
    } | {
        ("EXCLUDED", str(row["identity"])) for row in excluded
    }
    if set(keys) != expected_keys:
        raise ProgramFactsSourceManifestError(
            "physical identity inventory does not cover the exact denominator"
        )
    by_key = {
        (str(row["kind"]), str(row["identity"])): str(
            row["physical_identity_digest"]
        )
        for row in rows
    }
    for row in eligible:
        key = ("ELIGIBLE", str(row["source_file_id"]))
        if by_key[key] != row["physical_identity_digest"]:
            raise ProgramFactsSourceManifestError(
                "eligible physical identity inventory mismatch"
            )
    return MappingProxyType(by_key)


def _validate_source_manifest_shape(
    value: Any, source_scope_digest: str
) -> tuple[
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    dict[str, int],
]:
    manifest = _require_exact_keys(
        value, _SOURCE_MANIFEST_KEYS, "source_manifest"
    )
    if (
        manifest["policy_version"]
        != "plamen.program_facts_source_scope.v1"
    ):
        raise ProgramFactsSourceManifestError(
            "source_manifest policy version is unsupported"
        )
    eligible = _require_sorted_unique(
        manifest["eligible_files"],
        "source_manifest.eligible_files",
        row_key="source_file_id",
    )
    excluded = _require_sorted_unique(
        manifest["excluded_files"],
        "source_manifest.excluded_files",
        row_key="identity",
    )
    casefolds: set[str] = set()
    physical_ids: set[str] = set()
    sizes: dict[str, int] = {}
    for index, raw_row in enumerate(eligible):
        row = _require_exact_keys(
            raw_row,
            _SOURCE_FILE_KEYS,
            f"source_manifest.eligible_files[{index}]",
        )
        source_id = row["source_file_id"]
        if not isinstance(source_id, str) or _PFS_RE.fullmatch(source_id) is None:
            raise ProgramFactsSourceManifestError(
                "source_file_id must be PFS-<24 lowercase hex>"
            )
        path = _portable_path(row["path"], "source file path")
        if row["path_casefold_key"] != path.casefold():
            raise ProgramFactsSourceManifestError(
                "source file path_casefold_key mismatch"
            )
        if row["path_casefold_key"] in casefolds:
            raise ProgramFactsSourceManifestError(
                "source manifest has a case-fold collision"
            )
        casefolds.add(row["path_casefold_key"])
        source_sha256 = _sha256(
            row["source_sha256"], "source file content digest"
        )
        size = _nonnegative_int(row["size_bytes"], "source file size")
        language = row["language"]
        if language not in set(_SOURCE_LANGUAGES.values()):
            raise ProgramFactsSourceManifestError(
                "source file language is outside the closed policy"
            )
        classified = _SOURCE_LANGUAGES.get(Path(path).suffix.casefold())
        if (
            not path.startswith("@outside/")
            and classified is not None
            and language != classified
        ):
            raise ProgramFactsSourceManifestError(
                "source file language does not match its closed suffix policy"
            )
        if row["scope_class"] not in _SCOPE_CLASSES:
            raise ProgramFactsSourceManifestError(
                "source file scope_class is outside the closed policy"
            )
        physical = _sha256(
            row["physical_identity_digest"],
            "source physical identity digest",
        )
        if physical in physical_ids:
            raise ProgramFactsSourceManifestError(
                "source manifest has a physical-identity alias collision"
            )
        physical_ids.add(physical)
        expected_id = derive_stable_id(
            "PFS",
            {
                "source_scope_digest": source_scope_digest,
                "path": path,
                "source_sha256": source_sha256,
                "scope_class": row["scope_class"],
            },
        )
        if source_id != expected_id:
            raise ProgramFactsSourceManifestError(
                "source file ID does not replay"
            )
        sizes[source_id] = size
    for index, raw_row in enumerate(excluded):
        row = _require_exact_keys(
            raw_row,
            _EXCLUDED_FILE_KEYS,
            f"source_manifest.excluded_files[{index}]",
        )
        identity = row["identity"]
        if not isinstance(identity, str) or not identity:
            raise ProgramFactsSourceManifestError(
                "excluded source identity must be nonempty text"
            )
        if any(ord(char) < 32 or ord(char) == 127 for char in identity):
            raise ProgramFactsSourceManifestError(
                "excluded source identity contains a control character"
            )
        if (
            identity.startswith(("/", "\\"))
            or "\\" in identity
            or ":" in identity
        ):
            raise ProgramFactsSourceManifestError(
                "excluded source identity contains a host or alternate-stream path"
            )
        if "/" in identity:
            _portable_path(identity, "excluded source identity")
        reason = row["reason"]
        if not isinstance(reason, str) or not reason:
            raise ProgramFactsSourceManifestError(
                "excluded source reason must be nonempty text"
            )
        if reason not in _EXCLUSION_REASONS:
            raise ProgramFactsSourceManifestError(
                "excluded source reason is outside the closed policy"
            )
        if any(ord(char) < 32 or ord(char) == 127 for char in reason):
            raise ProgramFactsSourceManifestError(
                "excluded source reason contains a control character"
            )
        if _HOST_PATH_RE.search(reason):
            raise ProgramFactsSourceManifestError(
                "excluded source reason contains a host path"
            )
        digest = row["source_sha256"]
        if digest != "":
            _sha256(digest, "excluded source digest")
    excluded_casefolds = [str(row["identity"]).casefold() for row in excluded]
    if len(excluded_casefolds) != len(set(excluded_casefolds)):
        raise ProgramFactsSourceManifestError(
            "excluded source identities have a case-fold collision"
        )
    if set(excluded_casefolds) & casefolds:
        raise ProgramFactsSourceManifestError(
            "source manifest includes and excludes the same logical path"
        )
    if _nonnegative_int(manifest["file_count"], "source file_count") != len(
        eligible
    ):
        raise ProgramFactsSourceManifestError(
            "source manifest file_count mismatch"
        )
    if _nonnegative_int(
        manifest["byte_count"], "source byte_count"
    ) != sum(sizes.values()):
        raise ProgramFactsSourceManifestError(
            "source manifest byte_count mismatch"
        )
    claimed = _sha256(
        manifest["manifest_digest"], "source manifest digest"
    )
    try:
        expected = derive_source_manifest_digest(manifest)
    except ProgramFactsTypeError as exc:
        _fail_from_type(exc)
    if claimed != expected:
        raise ProgramFactsSourceManifestError(
            "source manifest digest mismatch"
        )
    return eligible, excluded, sizes


def _validate_line_replay(
    value: Any,
    sizes: Mapping[str, int],
) -> dict[str, tuple[int, ...]]:
    rows = _require_sorted_unique(
        value, "line_replay_inputs", row_key="source_file_id"
    )
    replay: dict[str, tuple[int, ...]] = {}
    for index, raw_row in enumerate(rows):
        row = _require_exact_keys(
            raw_row,
            _LINE_REPLAY_KEYS,
            f"line_replay_inputs[{index}]",
        )
        source_id = row["source_file_id"]
        if source_id not in sizes:
            raise ProgramFactsSourceManifestError(
                "line replay input has an unknown source_file_id"
            )
        offsets = row["line_start_byte_offsets"]
        if not isinstance(offsets, Sequence) or isinstance(
            offsets, (str, bytes, bytearray)
        ):
            raise ProgramFactsSourceManifestError(
                "line_start_byte_offsets must be an array"
            )
        normalized = [
            _nonnegative_int(item, "line replay byte offset")
            for item in offsets
        ]
        if not normalized or normalized[0] != 0:
            raise ProgramFactsSourceManifestError(
                "line replay offsets must begin at zero"
            )
        if normalized != sorted(set(normalized)):
            raise ProgramFactsSourceManifestError(
                "line replay offsets must be sorted and unique"
            )
        if normalized[-1] > sizes[source_id]:
            raise ProgramFactsSourceManifestError(
                "line replay offset exceeds source size"
            )
        replay[source_id] = tuple(normalized)
    if set(replay) != set(sizes):
        raise ProgramFactsSourceManifestError(
            "line replay inputs do not cover the exact source denominator"
        )
    return replay


def _validate_debts(value: Any, source_ids: set[str]) -> list[Mapping[str, Any]]:
    rows = _require_sorted_unique(value, "debts", row_key="debt_id")
    for index, raw_row in enumerate(rows):
        row = _require_exact_keys(
            raw_row, _DEBT_KEYS, f"debts[{index}]"
        )
        if (
            not isinstance(row["debt_id"], str)
            or _PFD_RE.fullmatch(row["debt_id"]) is None
        ):
            raise ProgramFactsSourceManifestError(
                "manifest debt_id must be PFD-<24 lowercase hex>"
            )
        if row["code"] not in _DEBT_CODES:
            raise ProgramFactsSourceManifestError(
                "manifest debt code is outside the closed policy"
            )
        ids = _require_sorted_unique(
            row["affected_source_file_ids"],
            "debt affected_source_file_ids",
        )
        if not set(ids).issubset(source_ids):
            raise ProgramFactsSourceManifestError(
                "manifest debt references an unknown source_file_id"
            )
        paths = _require_sorted_unique(
            row["affected_paths"], "debt affected_paths"
        )
        for path in paths:
            _portable_path(path, "debt affected path")
        binding = {
            "code": row["code"],
            "affected_source_file_ids": ids,
            "affected_paths": paths,
        }
        if row["debt_id"] != derive_stable_id("PFD", binding):
            raise ProgramFactsSourceManifestError(
                "manifest debt ID does not replay"
            )
    return rows


def _validate_denominator(
    value: Any,
    source_ids: set[str],
    debt_ids: set[str],
) -> None:
    denominator = _require_exact_keys(
        value, _DENOMINATOR_KEYS, "compiled_denominator"
    )
    if denominator["status"] not in _COVERAGE_STATUSES:
        raise ProgramFactsSourceManifestError(
            "compiled denominator status is outside the closed policy"
        )
    eligible = _require_sorted_unique(
        denominator["eligible_source_file_ids"],
        "compiled denominator eligible_source_file_ids",
    )
    compiled = _require_sorted_unique(
        denominator["compiled_source_file_ids"],
        "compiled denominator compiled_source_file_ids",
    )
    uncompiled = _require_sorted_unique(
        denominator["uncompiled_source_file_ids"],
        "compiled denominator uncompiled_source_file_ids",
    )
    unexpected = _require_sorted_unique(
        denominator["unexpected_compiled_paths"],
        "compiled denominator unexpected_compiled_paths",
    )
    unresolved = _require_sorted_unique(
        denominator["unresolved_debt_ids"],
        "compiled denominator unresolved_debt_ids",
    )
    for path in unexpected:
        _portable_path(path, "unexpected compiled path")
    if set(eligible) != source_ids:
        raise ProgramFactsSourceManifestError(
            "compiled denominator eligible set mismatch"
        )
    if not set(compiled).issubset(source_ids):
        raise ProgramFactsSourceManifestError(
            "compiled denominator compiled set escapes eligible set"
        )
    if set(uncompiled) != source_ids - set(compiled):
        raise ProgramFactsSourceManifestError(
            "compiled denominator uncompiled set mismatch"
        )
    if set(unresolved) != debt_ids:
        raise ProgramFactsSourceManifestError(
            "compiled denominator debt set mismatch"
        )
    claimed = _sha256(
        denominator["denominator_digest"],
        "compiled denominator digest",
    )
    if claimed != digest_compiled_denominator(denominator):
        raise ProgramFactsSourceManifestError(
            "compiled denominator digest mismatch"
        )
    status = denominator["status"]
    if status == "FULL" and (
        compiled != eligible or unexpected or unresolved
    ):
        raise ProgramFactsSourceManifestError(
            "FULL compiled coverage requires exact debt-free equality"
        )
    if status == "UNKNOWN" and not any(
        row.startswith("PFD-") for row in unresolved
    ):
        raise ProgramFactsSourceManifestError(
            "UNKNOWN compiled coverage requires typed debt"
        )


def _validate_denominator_evidence_policy(
    denominator: Mapping[str, Any],
    debts: Sequence[Mapping[str, Any]],
    source_ids: set[str],
    excluded_paths: set[str],
) -> None:
    """Enforce v1 relationships that a self-signed shape cannot choose."""

    debt_by_code: dict[str, list[Mapping[str, Any]]] = {}
    for row in debts:
        debt_by_code.setdefault(str(row["code"]), []).append(row)

    exclusion_debts = debt_by_code.get("SOURCE_EXCLUDED", [])
    if excluded_paths:
        if len(exclusion_debts) != 1:
            raise ProgramFactsSourceManifestError(
                "excluded source denominator requires one total "
                "SOURCE_EXCLUDED debt"
            )
        exclusion_debt = exclusion_debts[0]
        if (
            set(exclusion_debt["affected_paths"]) != excluded_paths
            or exclusion_debt["affected_source_file_ids"]
        ):
            raise ProgramFactsSourceManifestError(
                "SOURCE_EXCLUDED debt does not cover the exact excluded "
                "source denominator"
            )
    elif exclusion_debts:
        raise ProgramFactsSourceManifestError(
            "SOURCE_EXCLUDED debt exists without excluded source"
        )

    unavailable = debt_by_code.get(
        "COMPILED_DENOMINATOR_UNAVAILABLE", []
    )
    untrusted = debt_by_code.get(
        "COMPILED_DENOMINATOR_UNTRUSTED", []
    )
    if len(unavailable) + len(untrusted) != 1:
        raise ProgramFactsSourceManifestError(
            "compiled denominator requires exactly one unavailable or "
            "untrusted evidence debt"
        )
    evidence = (unavailable or untrusted)[0]
    if (
        set(evidence["affected_source_file_ids"]) != source_ids
        or denominator["compiled_source_file_ids"]
        or set(denominator["uncompiled_source_file_ids"]) != source_ids
    ):
        raise ProgramFactsSourceManifestError(
            "compiled denominator v1 has no authority to substantiate "
            "compiled source IDs"
        )
    if denominator["status"] not in {"UNKNOWN", "UNSUPPORTED"}:
        raise ProgramFactsSourceManifestError(
            "compiled denominator v1 cannot substantiate FULL or PARTIAL "
            "coverage"
        )
    unexpected = set(denominator["unexpected_compiled_paths"])
    if unavailable:
        if unexpected or evidence["affected_paths"]:
            raise ProgramFactsSourceManifestError(
                "unavailable compiled denominator cannot name observed paths"
            )
    elif not unexpected.issubset(set(evidence["affected_paths"])):
        raise ProgramFactsSourceManifestError(
            "unexpected compiled paths escape the untrusted observation debt"
        )


def _validate_tree(value: Any) -> None:
    tree = _require_exact_keys(value, _TREE_KEYS, "tree_identity")
    pre = _sha256(tree["pre_digest"], "tree_identity.pre_digest")
    post = _sha256(tree["post_digest"], "tree_identity.post_digest")
    if tree["stable"] is not True or pre != post:
        raise ProgramFactsSourceManifestError(
            "tree identity is not a stable pre/post capture"
        )


def parse_program_facts_source_manifest_shape(
    raw: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_MANIFEST_BYTES,
) -> ParsedProgramFactsSourceManifest:
    """Validate canonical shape and internal digests without parent authority."""

    try:
        value = strict_json_loads(
            raw,
            require_final_lf=True,
            require_canonical=True,
            max_bytes=max_bytes,
        )
    except ProgramFactsTypeError as exc:
        _fail_from_type(exc)
    record = _require_exact_keys(
        value, _AUTHORITY_KEYS, "source manifest authority"
    )
    if record["schema_version"] != SOURCE_MANIFEST_AUTHORITY_SCHEMA:
        raise ProgramFactsSourceManifestError(
            "source manifest authority schema is unsupported"
        )
    if record["canonicalization_version"] != CANONICALIZATION_VERSION:
        raise ProgramFactsSourceManifestError(
            "source manifest canonicalization version is unsupported"
        )
    snapshot_ref = _require_exact_keys(
        record["snapshot_ref"], _SNAPSHOT_REF_KEYS, "snapshot_ref"
    )
    source_scope_digest = _sha256_ref(
        snapshot_ref["source_scope_digest"],
        "snapshot_ref.source_scope_digest",
    )[7:]
    _sha256_ref(
        snapshot_ref["snapshot_digest"],
        "snapshot_ref.snapshot_digest",
    )
    _validate_selection_policy(record["selection_policy"])
    _validate_selector_authority(record["selector_authority"])
    eligible, excluded, sizes = _validate_source_manifest_shape(
        record["source_manifest"], source_scope_digest
    )
    _validate_physical_identity_inventory(
        record["physical_identity_inventory"],
        eligible,
        excluded,
    )
    _validate_source_suffix_bindings(
        record["source_suffix_bindings"], eligible
    )
    _validate_line_replay(record["line_replay_inputs"], sizes)
    source_ids = {
        str(row["source_file_id"]) for row in eligible
    }
    debts = _validate_debts(record["debts"], source_ids)
    denominator = record["compiled_denominator"]
    _validate_denominator(
        denominator,
        source_ids,
        {str(row["debt_id"]) for row in debts},
    )
    _validate_denominator_evidence_policy(
        denominator,
        debts,
        source_ids,
        {
            str(row["identity"])
            for row in excluded
        },
    )
    _validate_tree(record["tree_identity"])
    claimed = _sha256(
        record["authority_digest"], "source manifest authority digest"
    )
    if claimed != _unsigned_digest(record, "authority_digest"):
        raise ProgramFactsSourceManifestError(
            "source manifest authority digest mismatch"
        )
    return ParsedProgramFactsSourceManifest(
        record=_freeze(record),
        canonical_bytes=bytes(raw),
        authority_digest=claimed,
        file_sha256=hashlib.sha256(raw).hexdigest(),
    )


def replay_program_facts_source_manifest(
    value: bytes | ParsedProgramFactsSourceManifest,
    *,
    expected_snapshot_digest: str,
    expected_source_scope_digest: str,
    source_bytes_by_id: Mapping[str, bytes] | None = None,
    excluded_source_bytes_by_identity: Mapping[str, bytes] | None = None,
    capture_capability: SourceManifestCaptureCapability | None = None,
    project_root: str | Path | None = None,
    config: Mapping[str, Any] | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_line_starts: int = DEFAULT_MAX_LINE_STARTS,
) -> ReplayedProgramFactsSourceManifest:
    """Establish parent and exact-byte authority for a shape-valid manifest."""

    if config is not None:
        config = _fresh_json_mapping(config, "config")
    if isinstance(value, bytes):
        parsed = parse_program_facts_source_manifest_shape(value)
    elif type(value) in {
        ParsedProgramFactsSourceManifest,
        ProgramFactsSourceManifestAuthority,
        ReplayedProgramFactsSourceManifest,
    }:
        reparsed = parse_program_facts_source_manifest_shape(
            value.canonical_bytes
        )
        if (
            value.record != reparsed.record
            or value.authority_digest != reparsed.authority_digest
            or value.file_sha256 != reparsed.file_sha256
        ):
            raise ProgramFactsSourceManifestError(
                "parsed manifest replay input differs from its canonical bytes"
            )
        parsed = reparsed
    else:
        raise ProgramFactsSourceManifestError(
            "manifest replay input must be canonical bytes or parsed shape"
        )
    expected_snapshot = _raw_digest(
        expected_snapshot_digest, "expected snapshot digest"
    )
    expected_scope = _raw_digest(
        expected_source_scope_digest, "expected source scope digest"
    )
    snapshot_ref = parsed.record["snapshot_ref"]
    if snapshot_ref["snapshot_digest"] != f"sha256:{expected_snapshot}":
        raise ProgramFactsSourceManifestError(
            "source manifest snapshot parent mismatch"
        )
    if snapshot_ref["source_scope_digest"] != f"sha256:{expected_scope}":
        raise ProgramFactsSourceManifestError(
            "source manifest source scope parent mismatch"
        )
    try:
        current_selector_digest = _selector_source_digest()
    except SharedSourceSelectionUnavailable as exc:
        raise ProgramFactsSourceManifestError(
            f"shared source selection unavailable during replay: {exc}"
        ) from exc
    if (
        parsed.record["selection_policy"]["selector_bridge_digest"]
        != current_selector_digest
    ):
        raise ProgramFactsSourceManifestError(
            "source manifest shared selector identity mismatch"
        )

    rows = parsed.record["source_manifest"]["eligible_files"]
    physical_by_key = {
        (str(row["kind"]), str(row["identity"])): str(
            row["physical_identity_digest"]
        )
        for row in parsed.record["physical_identity_inventory"]
    }
    suffix_by_id = {
        str(row["source_file_id"]): str(row["suffix"])
        for row in parsed.record["source_suffix_bindings"]
    }
    if source_bytes_by_id is not None and (
        project_root is not None or config is not None
    ):
        raise ProgramFactsSourceManifestError(
            "replay accepts one exact-byte source, not two"
        )
    if source_bytes_by_id is None and project_root is None:
        raise ProgramFactsSourceManifestError(
            "strict replay requires source_bytes_by_id or project_root"
        )
    if source_bytes_by_id is not None and capture_capability is None:
        raise ProgramFactsSourceManifestError(
            "raw mapping replay cannot establish parent authority without "
            "an opaque one-shot capture capability or project-tree replay"
        )
    if source_bytes_by_id is None and capture_capability is not None:
        raise ProgramFactsSourceManifestError(
            "project-tree replay does not accept a capture capability"
        )
    if capture_capability is not None and type(
        capture_capability
    ) is not SourceManifestCaptureCapability:
        raise ProgramFactsSourceManifestError(
            "capture capability has an unsupported authority type"
        )
    if project_root is not None and not isinstance(config, Mapping):
        raise ProgramFactsSourceManifestError(
            "project_root replay requires the shared selector config"
        )
    max_file_bytes = _positive_int(max_file_bytes, "max_file_bytes")
    max_total_bytes = _positive_int(max_total_bytes, "max_total_bytes")
    max_line_starts = _positive_int(
        max_line_starts, "max_line_starts"
    )
    supplied: dict[str, bytes] = {}
    supplied_excluded: dict[str, bytes] = {}
    total_bytes = 0
    if source_bytes_by_id is not None:
        if not isinstance(source_bytes_by_id, Mapping):
            raise ProgramFactsSourceManifestError(
                "source_bytes_by_id must be an object"
            )
        for source_id, raw in source_bytes_by_id.items():
            if not isinstance(source_id, str) or not isinstance(raw, bytes):
                raise ProgramFactsSourceManifestError(
                    "source_bytes_by_id must map IDs to exact bytes"
                )
            if len(raw) > max_file_bytes:
                raise ProgramFactsSourceManifestError(
                    "replay source exceeds the bounded per-file byte limit"
                )
            total_bytes += len(raw)
            if total_bytes > max_total_bytes:
                raise ProgramFactsSourceManifestError(
                    "replay sources exceed the bounded total byte limit"
                )
            supplied[source_id] = raw
        raw_excluded = excluded_source_bytes_by_identity
        if raw_excluded is None:
            raw_excluded = {}
        if not isinstance(raw_excluded, Mapping):
            raise ProgramFactsSourceManifestError(
                "excluded_source_bytes_by_identity must be an object"
            )
        for identity, raw in raw_excluded.items():
            if not isinstance(identity, str) or not isinstance(raw, bytes):
                raise ProgramFactsSourceManifestError(
                    "excluded source replay must map identities to exact bytes"
                )
            if len(raw) > max_file_bytes:
                raise ProgramFactsSourceManifestError(
                    "excluded replay source exceeds the bounded per-file byte limit"
                )
            total_bytes += len(raw)
            if total_bytes > max_total_bytes:
                raise ProgramFactsSourceManifestError(
                    "replay sources exceed the bounded total byte limit"
                )
            supplied_excluded[identity] = raw
    else:
        if excluded_source_bytes_by_identity is not None:
            raise ProgramFactsSourceManifestError(
                "project_root replay does not accept supplied excluded bytes"
            )
        root = Path(project_root).expanduser().absolute()
        _validate_project_root(root)
        assert isinstance(config, Mapping)
        raw_configured_root = str(config.get("project_root") or "").strip()
        if not raw_configured_root:
            raise ProgramFactsSourceManifestError(
                "project_root replay config has no project_root"
            )
        configured_root = Path(raw_configured_root).expanduser().absolute()
        try:
            if configured_root.resolve(strict=True) != root.resolve(
                strict=True
            ):
                raise ProgramFactsSourceManifestError(
                    "project_root replay differs from shared selector config"
                )
        except OSError as exc:
            raise ProgramFactsSourceManifestError(
                "project_root replay config cannot be resolved"
            ) from exc
        _validate_current_snapshot_source_component(
            config, expected_scope
        )
        current_selector_authority = _selector_authority(
            config,
            root,
            max_file_bytes=max_file_bytes,
        )
        if current_selector_authority["selector_inputs_digest"] != (
            parsed.record["selector_authority"][
                "selector_inputs_digest"
            ]
        ):
            raise ProgramFactsSourceManifestError(
                "project-tree replay selector authority or config input drifted"
            )
        policy_suffixes = tuple(
            str(value)
            for value in parsed.record["selection_policy"][
                "include_suffixes"
            ]
        )
        if tuple(
            sorted({suffix.casefold() for suffix in _suffixes_for(config)})
        ) != policy_suffixes:
            raise ProgramFactsSourceManifestError(
                "project_root replay ecosystem selection policy drifted"
            )

        def current_selection() -> tuple[
            list[_Candidate],
            list[_Candidate],
        ]:
            try:
                (
                    eligible_now,
                    excluded_now,
                    reasons_now,
                    _scope_gap,
                ) = _collect_candidates(config, root, policy_suffixes)
            except SharedSourceSelectionUnavailable as exc:
                raise ProgramFactsSourceManifestError(
                    "shared source selection unavailable during tree replay: "
                    f"{exc}"
                ) from exc
            expected_eligible = sorted(
                (
                    str(row["path"]),
                    str(row["scope_class"]),
                )
                for row in rows
            )
            actual_eligible = sorted(
                (
                    candidate.portable_path,
                    candidate.scope_class,
                )
                for candidate in eligible_now
            )
            expected_excluded_selection = sorted(
                (
                    str(row["identity"]),
                    str(row["reason"]),
                )
                for row in parsed.record["source_manifest"][
                    "excluded_files"
                ]
            )
            actual_excluded_selection = sorted(
                (
                    candidate.portable_path,
                    str(reasons_now[candidate.portable_path]),
                )
                for candidate in excluded_now
            )
            if (
                expected_eligible != actual_eligible
                or expected_excluded_selection
                != actual_excluded_selection
            ):
                raise ProgramFactsSourceManifestError(
                    "current source selection differs from frozen denominator"
                )
            return eligible_now, excluded_now

        selected, selected_excluded = current_selection()
        selected_by_path = {
            candidate.portable_path: candidate for candidate in selected
        }
        selected_excluded_by_path = {
            candidate.portable_path: candidate
            for candidate in selected_excluded
        }
        observed_physical: dict[str, tuple[str, str]] = {}

        def register_physical(
            *,
            kind: str,
            identity: str,
            digest: str,
        ) -> None:
            previous = observed_physical.get(digest)
            current = (kind, identity)
            if previous is not None and previous != current:
                raise ProgramFactsSourceManifestError(
                    "project-tree replay found a physical-identity alias "
                    "across the eligible/excluded denominator"
                )
            observed_physical[digest] = current

        for row in rows:
            path = str(row["path"])
            candidate = selected_by_path[path]
            stable = _read_regular_file_stably(
                candidate.inspection_path,
                context=f"replay source {path}",
                max_file_bytes=max_file_bytes,
            )
            if (
                stable.physical_identity_digest
                != physical_by_key[
                    ("ELIGIBLE", str(row["source_file_id"]))
                ]
            ):
                raise ProgramFactsSourceManifestError(
                    f"replay source {path} physical identity mismatch"
                )
            if (
                candidate.physical_path.suffix.casefold()
                != suffix_by_id[str(row["source_file_id"])]
            ):
                raise ProgramFactsSourceManifestError(
                    f"replay source {path} suffix/language authority mismatch"
                )
            register_physical(
                kind="ELIGIBLE",
                identity=str(row["source_file_id"]),
                digest=stable.physical_identity_digest,
            )
            total_bytes += len(stable.raw)
            if total_bytes > max_total_bytes:
                raise ProgramFactsSourceManifestError(
                    "replay sources exceed the bounded total byte limit"
                )
            supplied[str(row["source_file_id"])] = stable.raw
        for row in parsed.record["source_manifest"]["excluded_files"]:
            identity = str(row["identity"])
            candidate = selected_excluded_by_path[identity]
            stable = _read_regular_file_stably(
                candidate.inspection_path,
                context=f"replay excluded source {identity}",
                max_file_bytes=max_file_bytes,
            )
            if (
                stable.physical_identity_digest
                != physical_by_key[("EXCLUDED", identity)]
            ):
                raise ProgramFactsSourceManifestError(
                    f"replay excluded source {identity} physical identity mismatch"
                )
            register_physical(
                kind="EXCLUDED",
                identity=identity,
                digest=stable.physical_identity_digest,
            )
            total_bytes += len(stable.raw)
            if total_bytes > max_total_bytes:
                raise ProgramFactsSourceManifestError(
                    "replay sources exceed the bounded total byte limit"
                )
            supplied_excluded[identity] = stable.raw
        # Prove the denominator both before and after exact-byte capture.
        # Otherwise an added source can be silently ignored while every old
        # recorded path remains readable.
        current_selection()
        _validate_current_snapshot_source_component(
            config, expected_scope
        )

    expected_ids = {str(row["source_file_id"]) for row in rows}
    if set(supplied) != expected_ids:
        raise ProgramFactsSourceManifestError(
            "strict replay raw bytes do not cover the exact source denominator"
        )
    excluded_rows = parsed.record["source_manifest"]["excluded_files"]
    expected_excluded = {
        str(row["identity"]) for row in excluded_rows
    }
    if set(supplied_excluded) != expected_excluded:
        raise ProgramFactsSourceManifestError(
            "strict replay bytes do not cover the exact excluded source set"
        )
    if capture_capability is not None:
        capture_capability._consume(
            authority_digest=parsed.authority_digest,
            snapshot_digest=expected_snapshot,
            source_scope_digest=expected_scope,
            capture_digest=_capture_bytes_digest(
                supplied, supplied_excluded
            ),
        )
    line_rows = {
        str(row["source_file_id"]): tuple(
            row["line_start_byte_offsets"]
        )
        for row in parsed.record["line_replay_inputs"]
    }
    for row in rows:
        source_id = str(row["source_file_id"])
        raw = supplied[source_id]
        if (
            len(raw) != row["size_bytes"]
            or hashlib.sha256(raw).hexdigest() != row["source_sha256"]
        ):
            raise ProgramFactsSourceManifestError(
                f"source {source_id} raw bytes do not replay"
            )
        if tuple(
            _line_starts(
                raw, max_starts=max_line_starts
            )
        ) != line_rows[source_id]:
            raise ProgramFactsSourceManifestError(
                f"source {source_id} line replay inputs do not replay"
            )
    for row in excluded_rows:
        identity = str(row["identity"])
        raw = supplied_excluded[identity]
        if hashlib.sha256(raw).hexdigest() != row["source_sha256"]:
            raise ProgramFactsSourceManifestError(
                f"excluded source {identity} raw bytes do not replay"
            )
    replayed = _issue_manifest_authority(
        ReplayedProgramFactsSourceManifest,
        record=parsed.record,
        canonical_bytes=parsed.canonical_bytes,
        authority_digest=parsed.authority_digest,
        file_sha256=parsed.file_sha256,
    )
    assert isinstance(replayed, ReplayedProgramFactsSourceManifest)
    return replayed


def replay_program_facts_source_authority(
    authority: bytes | ParsedProgramFactsSourceManifest,
    *,
    expected_snapshot_digest: str,
    expected_source_scope_digest: str,
    project_root: str | Path,
    config: Mapping[str, Any],
    expected_ledger_binding: Mapping[str, Any] | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_line_starts: int = DEFAULT_MAX_LINE_STARTS,
) -> ReplayedProgramFactsSourceManifest:
    """Independently establish production authority from the live tree.

    ``parent_authority_established`` and the private issuance registry are
    anti-accident metadata only.  A production consumer must call this API at
    its semantic boundary and use the freshly returned authority.  The replay
    intentionally ignores any issuance state carried by ``authority`` and
    revalidates its canonical envelope, trusted parent digests, selector
    configuration, exact eligible/excluded denominator, stable bytes, and
    physical identities against ``project_root`` before and after capture.

    Raw byte mappings and in-process capture capabilities are deliberately not
    accepted here.  ``expected_ledger_binding`` reserves a future non-tree
    route, but fails closed until an external durable-ledger validator binds
    the same evidence.
    """

    if not isinstance(config, Mapping):
        raise ProgramFactsSourceManifestError(
            "production source replay requires selector config"
        )
    if project_root is None:
        raise ProgramFactsSourceManifestError(
            "production source replay requires project_root"
        )
    if expected_ledger_binding is not None:
        raise ProgramFactsSourceManifestError(
            "production source replay has no externally validated durable "
            "ledger binding implementation"
        )
    canonical = (
        authority
        if isinstance(authority, bytes)
        else authority.canonical_bytes
        if type(authority)
        in {
            ParsedProgramFactsSourceManifest,
            ProgramFactsSourceManifestAuthority,
            ReplayedProgramFactsSourceManifest,
        }
        else None
    )
    if canonical is None:
        raise ProgramFactsSourceManifestError(
            "production source replay requires canonical manifest bytes or "
            "an exact parsed source-manifest record"
        )
    return replay_program_facts_source_manifest(
        canonical,
        expected_snapshot_digest=expected_snapshot_digest,
        expected_source_scope_digest=expected_source_scope_digest,
        project_root=project_root,
        config=config,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        max_line_starts=max_line_starts,
    )


(
    _manifest_authority_is_issued,
    _issue_manifest_authority,
    _issue_capture_capability,
    _consume_capture_capability,
) = _make_issuance_registry(
    builder_code=build_program_facts_source_manifest.__code__,
    replay_code=replay_program_facts_source_manifest.__code__,
)
del _make_issuance_registry

(
    _audit_snapshot_authority_is_issued,
    _issue_audit_snapshot_authority,
) = _make_audit_snapshot_authority_registry(
    capture_code=capture_program_facts_audit_snapshot_authority.__code__,
    replay_code=replay_program_facts_audit_snapshot_authority.__code__,
)
del _make_audit_snapshot_authority_registry


__all__ = [
    "DEFAULT_MAX_COMPILED_SOURCE_PATH_BYTES",
    "DEFAULT_MAX_COMPILED_SOURCE_PATHS",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_LINE_STARTS",
    "DEFAULT_MAX_MANIFEST_BYTES",
    "DEFAULT_MAX_TOTAL_BYTES",
    "ParsedProgramFactsSourceManifest",
    "ProgramFactsAuditIdentity",
    "ProgramFactsAuditSnapshotAuthority",
    "ProgramFactsSourceManifestAuthority",
    "ProgramFactsSourceManifestError",
    "ReplayedProgramFactsSourceManifest",
    "ReplayedProgramFactsAuditSnapshotAuthority",
    "SOURCE_MANIFEST_AUTHORITY_SCHEMA",
    "SourceManifestCaptureCapability",
    "SharedSourceSelectionUnavailable",
    "build_program_facts_source_manifest",
    "capture_program_facts_audit_snapshot_authority",
    "digest_compiled_denominator",
    "parse_program_facts_source_manifest_shape",
    "replay_program_facts_source_manifest",
    "replay_program_facts_source_authority",
    "replay_program_facts_audit_snapshot_authority",
]
