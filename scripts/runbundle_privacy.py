"""Public structural exclusion, path, snapshot, and seal primitives for v2.

This module is deliberately independent from the synthetic-v1 evaluator.  It
does not import evaluator code and does not match, score, grade, or interpret
findings.  Its authority is limited to public-payload structural exclusions and
deterministic filesystem/content commitments.  A clean result does not prove
runner blinding or private/ground-truth corpus isolation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Callable, Iterable, Mapping, Sequence
import unicodedata


REAL_AUDIT_V2 = "REAL_AUDIT_V2"
BUNDLE_INDEX_SCHEMA = "plamen.real-audit-bundle-index.v2"
INPUT_SNAPSHOT_SCHEMA = "plamen.real-audit-export-input-snapshot.v1"

PAYLOAD_FILE_NAMES = frozenset(
    {
        "run_manifest.json",
        "phase_events.jsonl",
        "candidate_findings.json",
        "candidate_lineage.json",
        "raw_outputs.json",
        "report_projection.json",
        "harvest_receipt.json",
    }
)
GENERATED_FILE_NAMES = frozenset({"bundle_index.json", "SEALED.sha256"})
ROOT_ENTRY_NAMES = PAYLOAD_FILE_NAMES | GENERATED_FILE_NAMES | {"objects"}

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ABSOLUTE_PATH_HOME_RE = re.compile(
    r"(?:^|[\s\"'])(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)[\\/]",
    re.IGNORECASE,
)
_ABSOLUTE_PATH_DRIVE_RE = re.compile(r"(?:^|[\s\"'])[A-Za-z]:[\\/]")
_ABSOLUTE_PATH_UNC_RE = re.compile(
    r"(?:^|[\s\"'])\\\\[^\\/\s]+\\[^\\/\s]+"
)
_ABSOLUTE_PATH_NETWORK_RE = re.compile(r"(?<!:)//[^/\s]+/[^/\s]+")
_ABSOLUTE_PATH_POSIX_RE = re.compile(
    r"(?<![A-Za-z0-9:+._/~\\-])/(?!/)"
    r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*"
)
_ABSOLUTE_PATH_SENSITIVE_ROOT_RE = re.compile(
    r"(?<![A-Za-z0-9:+._-])/"
    r"(?:workspace|data|root|opt|srv|mnt|media|home|Users|private|"
    r"var|tmp|etc|usr|run|dev|proc|sys)"
    r"(?:/|$)",
    re.IGNORECASE,
)
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)
_WINDOWS_REPARSE_POINT = int(
    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
)
_WINDOWS_SPARSE_FILE = 0x200
_WINDOWS_ADS_INIT_ERROR: BaseException | None = None
_WINDOWS_FIND_STREAM_DATA: type[Any] | None = None
_WINDOWS_FIND_FIRST_STREAM: Any = None
_WINDOWS_FIND_NEXT_STREAM: Any = None
_WINDOWS_FIND_CLOSE: Any = None
_WINDOWS_CTYPES: Any = None
if os.name == "nt":
    try:
        import ctypes as _ctypes
        from ctypes import wintypes as _wintypes

        class _Win32FindStreamData(_ctypes.Structure):
            _fields_ = [
                ("StreamSize", _ctypes.c_longlong),
                ("cStreamName", _wintypes.WCHAR * 296),
            ]

        _kernel32 = _ctypes.WinDLL("kernel32", use_last_error=True)
        _WINDOWS_FIND_STREAM_DATA = _Win32FindStreamData
        _WINDOWS_FIND_FIRST_STREAM = _kernel32.FindFirstStreamW
        _WINDOWS_FIND_NEXT_STREAM = _kernel32.FindNextStreamW
        _WINDOWS_FIND_CLOSE = _kernel32.FindClose
        _WINDOWS_FIND_FIRST_STREAM.argtypes = [
            _wintypes.LPCWSTR,
            _wintypes.DWORD,
            _ctypes.POINTER(_Win32FindStreamData),
            _wintypes.DWORD,
        ]
        _WINDOWS_FIND_FIRST_STREAM.restype = _wintypes.HANDLE
        _WINDOWS_FIND_NEXT_STREAM.argtypes = [
            _wintypes.HANDLE,
            _ctypes.POINTER(_Win32FindStreamData),
        ]
        _WINDOWS_FIND_NEXT_STREAM.restype = _wintypes.BOOL
        _WINDOWS_FIND_CLOSE.argtypes = [_wintypes.HANDLE]
        _WINDOWS_FIND_CLOSE.restype = _wintypes.BOOL
        _WINDOWS_CTYPES = _ctypes
    except (AttributeError, ImportError, OSError) as _ads_exc:
        _WINDOWS_ADS_INIT_ERROR = _ads_exc
_BLINDING_FALSE_FIELDS = frozenset(
    {
        "ground_truth_available_to_runner",
        "prior_report_available_to_runner",
        "private_case_lock_available_to_runner",
        "grader_labels_available_to_runner",
    }
)
_PLAMEN_SCHEMA_MARKER_RE = re.compile(
    r"\bplamen\.[a-z0-9][a-z0-9._-]*",
    re.IGNORECASE,
)
_FORBIDDEN_PLAMEN_SCHEMA_FRAGMENTS = (
    "private",
    "score",
    "reference",
    "groundtruth",
    "gtlock",
    "gtissue",
    "gtroot",
    "gtannotation",
)
_PUBLIC_RELATIVE_PATH_FIELDS = frozenset(
    {"relative_path", "relative_source_path", "object_path"}
)
_FORBIDDEN_KEY_FRAGMENTS = (
    "groundtruth",
    "truthissue",
    "truthfinding",
    "truthroot",
    "truthdigest",
    "truthcount",
    "truthseverity",
    "answerkey",
    "privatecaselock",
    "expectedissue",
    "expectedfinding",
    "expectedcount",
    "expectedseverity",
    "gtissue",
    "gtfinding",
    "gtroot",
    "gtdigest",
    "gtcount",
    "gtseverity",
    "gtidentity",
    "referenceseverity",
    "referenceissue",
    "referencefinding",
    "referenceroot",
    "knownissue",
    "knownfinding",
    "knownroot",
    "correctseverity",
    "reviewerresult",
    "forbiddenpath",
    "forbiddenhash",
    "forbiddenidentity",
    "rootcause",
    "candidateissuebinding",
    "candidategtbinding",
    "experimentoutcome",
    "comparisonoutcome",
    "runoutcome",
    "winningcell",
    "winner",
    "postrunscore",
)
_FORBIDDEN_EXACT_KEYS = frozenset(
    {
        "gt",
        "truth",
        "severity",
        "match",
        "matches",
        "matching",
        "matchresult",
        "matchresults",
        "root",
        "rootid",
        "rootids",
        "rootroster",
        "outcome",
        "score",
        "scores",
        "scoring",
    }
)
# One immutable, versioned ASCII signature registry is compiled into both the
# decoded JSON/text scanner and the byte scanner.  Each vendor-shaped entry
# records the public evidence family that fixes its prefix/length grammar.
# The generic entries are deliberately labelled as conservative structural
# policy rather than being represented as vendor credential formats.
CREDENTIAL_SIGNATURE_REGISTRY_VERSION = "2026-07-28.1"
PUBLIC_STRUCTURAL_SCAN_POLICY_ID = (
    "plamen.runbundle-public-structural-exclusion-policy"
)
PUBLIC_STRUCTURAL_SCAN_POLICY_VERSION = "1"


@dataclass(frozen=True, slots=True)
class CredentialSignatureDefinition:
    signature_id: str
    ascii_pattern: str
    ignore_case: bool
    evidence_source: str


_CREDENTIAL_SIGNATURE_REGISTRY = (
    CredentialSignatureDefinition(
        "pem-private-key",
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
        True,
        "rfc7468-textual-encodings",
    ),
    CredentialSignatureDefinition(
        "authorization-header",
        r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+\S+",
        True,
        "rfc6750-bearer-and-rfc7617-basic",
    ),
    CredentialSignatureDefinition(
        "bearer-value",
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}",
        True,
        "rfc6750-bearer-token-usage",
    ),
    CredentialSignatureDefinition(
        "openai-api-key",
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        False,
        "github-secret-scanning-supported-patterns-openai",
    ),
    CredentialSignatureDefinition(
        "aws-access-key-id",
        r"\bAKIA[0-9A-Z]{16}\b",
        False,
        "aws-iam-access-key-id-format",
    ),
    CredentialSignatureDefinition(
        "github-legacy-token",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        False,
        "github-token-formats",
    ),
    CredentialSignatureDefinition(
        "github-fine-grained-token",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        False,
        "github-token-formats",
    ),
    CredentialSignatureDefinition(
        "generic-credential-assignment",
        (
            r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|"
            r"pass(?:word)?)\s*[:=]\s*[^\s,;]{8,}"
        ),
        True,
        "plamen-conservative-public-export-policy",
    ),
    CredentialSignatureDefinition(
        "slack-token",
        r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
        True,
        "slack-token-types",
    ),
    CredentialSignatureDefinition(
        "npm-access-token",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        False,
        "github-secret-scanning-supported-patterns-npm",
    ),
    CredentialSignatureDefinition(
        "google-api-key",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        False,
        "google-api-key-format",
    ),
    CredentialSignatureDefinition(
        "stripe-live-secret",
        r"\bsk_live_[0-9A-Za-z]{24,}\b",
        False,
        "stripe-api-key-types",
    ),
)
_SECRET_PATTERN_SPECS = tuple(
    (
        definition.ascii_pattern,
        re.IGNORECASE if definition.ignore_case else 0,
    )
    for definition in _CREDENTIAL_SIGNATURE_REGISTRY
)
_SECRET_PATTERNS = tuple(
    re.compile(pattern, flags) for pattern, flags in _SECRET_PATTERN_SPECS
)
_BINARY_SECRET_PATTERNS = tuple(
    re.compile(pattern.encode("ascii"), flags)
    for pattern, flags in _SECRET_PATTERN_SPECS
)

# Binary artifacts may legitimately be non-UTF-8, so invalid bytes alone are
# not a privacy failure.  They are not allowed to act as token separators,
# though: scan both a deletion and a single-space projection of every control,
# DEL, or high byte.  This deliberately conservative projection may reject a
# coincidental signature split by binary bytes; exporting a possible secret is
# worse than requiring the producer to omit or redact that object.
_BINARY_OBFUSCATING_BYTES_RE = re.compile(br"[\x00-\x20\x7f-\xff]+")
_BINARY_STRUCTURAL_OBFUSCATING_BYTES_RE = re.compile(
    br"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]+"
)
_CREDENTIAL_KEY_FRAGMENTS = frozenset(
    {
        "apikey",
        "apitoken",
        "authorization",
        "bearer",
        "clientsecret",
        "credential",
        "credentials",
        "key",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "secretkey",
        "token",
    }
)


def _is_credential_field(normalized_key: str) -> bool:
    if normalized_key in _CREDENTIAL_KEY_FRAGMENTS:
        return True
    return normalized_key.endswith(
        (
            "apikey",
            "apitoken",
            "authorization",
            "clientsecret",
            "credential",
            "credentials",
            "password",
            "passwd",
            "privatekey",
            "refreshtoken",
            "secretkey",
        )
    )


class RunBundlePrivacyError(ValueError):
    """A public RunBundle boundary could not be proven safe."""


@dataclass(frozen=True, slots=True)
class VerifiedBundleSnapshot:
    """Immutable, single-read capture of one exact sealed RunBundle tree."""

    directories: tuple[str, ...]
    files: tuple[tuple[str, bytes], ...]
    file_states: tuple[tuple[str, tuple[int, ...]], ...]
    directory_states: tuple[
        tuple[str, tuple[int, ...], tuple[str, ...]], ...
    ]
    bundle_index_bytes: bytes
    bundle_seal_sha256: str

    def bytes_for(self, relative_path: str) -> bytes:
        for path, raw in self.files:
            if path == relative_path:
                return raw
        raise RunBundlePrivacyError(
            f"verified bundle snapshot has no entry {relative_path!r}"
        )


@dataclass(frozen=True, slots=True)
class StableRegularFileSnapshot:
    """One exact regular-file generation plus its filesystem identity."""

    raw: bytes
    state: tuple[int, ...]
    sha256: str


@dataclass(frozen=True, slots=True)
class StableRegularTreeSnapshot:
    """Exact recursive bytes, identities, and directory memberships."""

    directories: tuple[str, ...]
    files: tuple[tuple[str, bytes], ...]
    file_states: tuple[tuple[str, tuple[int, ...]], ...]
    directory_states: tuple[
        tuple[str, tuple[int, ...], tuple[str, ...]], ...
    ]
    tree_sha256: str

    def bytes_for(self, relative_path: str) -> bytes:
        for path, raw in self.files:
            if path == relative_path:
                return raw
        raise RunBundlePrivacyError(
            f"stable tree snapshot has no entry {relative_path!r}"
        )


def _canonical_json_bytes(value: Any) -> bytes:
    # Lazy import prevents an import cycle: contracts uses the path validator.
    try:
        from runbundle_contracts import canonical_json_bytes
    except ImportError:  # pragma: no cover - package-style import fallback
        from .runbundle_contracts import canonical_json_bytes

    return canonical_json_bytes(value)


def _canonical_document_bytes(value: Any) -> bytes:
    try:
        from runbundle_contracts import canonical_document_bytes
    except ImportError:  # pragma: no cover - package-style import fallback
        from .runbundle_contracts import canonical_document_bytes

    return canonical_document_bytes(value)


def _strict_json_loads(raw: bytes, *, require_canonical: bool) -> Any:
    try:
        from runbundle_contracts import strict_json_loads
    except ImportError:  # pragma: no cover - package-style import fallback
        from .runbundle_contracts import strict_json_loads

    return strict_json_loads(raw, require_canonical=require_canonical)


def sha256_bytes(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise RunBundlePrivacyError("SHA-256 input must be bytes")
    return hashlib.sha256(raw).hexdigest()


def credential_signature_registry_preimage() -> dict[str, Any]:
    """Return the immutable public credential-signature policy preimage."""

    return {
        "registry_id": "plamen.public-credential-signature-registry",
        "registry_version": CREDENTIAL_SIGNATURE_REGISTRY_VERSION,
        "signatures": [
            {
                "signature_id": definition.signature_id,
                "ascii_pattern": definition.ascii_pattern,
                "ignore_case": definition.ignore_case,
                "evidence_source": definition.evidence_source,
            }
            for definition in _CREDENTIAL_SIGNATURE_REGISTRY
        ],
    }


def public_structural_scan_policy_preimage() -> dict[str, Any]:
    """Describe only the evaluator-owned public structural exclusion scan.

    Passing this policy proves that the supplied public bytes did not match
    these structural exclusions.  It does not prove runner blinding, private
    corpus isolation, or absence of every possible secret.
    """

    return {
        "policy_id": PUBLIC_STRUCTURAL_SCAN_POLICY_ID,
        "policy_version": PUBLIC_STRUCTURAL_SCAN_POLICY_VERSION,
        "claim_scope": "PUBLIC_STRUCTURAL_EXCLUSION_ONLY",
        "credential_signature_registry": (
            credential_signature_registry_preimage()
        ),
        "field_policy": {
            "forbidden_exact_keys": sorted(_FORBIDDEN_EXACT_KEYS),
            "forbidden_key_fragments": list(_FORBIDDEN_KEY_FRAGMENTS),
            "credential_key_fragments": sorted(_CREDENTIAL_KEY_FRAGMENTS),
            "relative_path_fields": sorted(_PUBLIC_RELATIVE_PATH_FIELDS),
        },
        "scalar_policy": {
            "unicode_form": "NFC",
            "reject_nul": True,
            "reject_absolute_paths": True,
            "reject_forbidden_plamen_schema_markers": True,
            "absolute_path_prefixes": ["\\\\?\\", "\\\\.\\"],
            "absolute_path_casefold_prefixes": ["file://"],
            "absolute_path_patterns": [
                {
                    "pattern": pattern.pattern,
                    "ignore_case": bool(pattern.flags & re.IGNORECASE),
                }
                for pattern in (
                    _ABSOLUTE_PATH_HOME_RE,
                    _ABSOLUTE_PATH_DRIVE_RE,
                    _ABSOLUTE_PATH_UNC_RE,
                    _ABSOLUTE_PATH_NETWORK_RE,
                    _ABSOLUTE_PATH_POSIX_RE,
                    _ABSOLUTE_PATH_SENSITIVE_ROOT_RE,
                )
            ],
            "plamen_schema_marker_pattern": (
                _PLAMEN_SCHEMA_MARKER_RE.pattern
            ),
            "forbidden_plamen_schema_fragments": list(
                _FORBIDDEN_PLAMEN_SCHEMA_FRAGMENTS
            ),
        },
        "binary_projection_policy": {
            "credential_projection": {
                "obfuscating_byte_ranges": ["00-20", "7f-ff"],
                "projections": ["RAW", "COMPACT", "SPACED"],
            },
            "structural_projection": {
                "obfuscating_byte_ranges": [
                    "00-08",
                    "0b-0c",
                    "0e-1f",
                    "7f-ff",
                ],
                "preserved_ascii_separators": [
                    "09",
                    "0a",
                    "0d",
                    "20",
                ],
                "projections": ["ASCII_COMPACT", "ASCII_SPACED"],
            },
            "scan_absolute_paths_before_invalid_utf8_return": True,
            "scan_forbidden_schema_before_invalid_utf8_return": True,
        },
    }


def public_structural_scan_policy_sha256() -> str:
    return sha256_bytes(
        _canonical_json_bytes(public_structural_scan_policy_preimage())
    )


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def is_forbidden_public_field(key: str) -> bool:
    """Return whether a key names evaluator-private or post-run material."""

    if not isinstance(key, str):
        return True
    if key in _BLINDING_FALSE_FIELDS:
        return False
    normalized = _normalized_key(key)
    return normalized in _FORBIDDEN_EXACT_KEYS or any(
        fragment in normalized for fragment in _FORBIDDEN_KEY_FRAGMENTS
    ) or "match" in normalized or "winner" in normalized or "score" in normalized


def assert_public_field_name(key: str) -> None:
    if is_forbidden_public_field(key):
        raise RunBundlePrivacyError(
            f"forbidden public field name at key {key!r}"
        )


def assert_safe_relative_path(value: str, *, label: str = "value") -> str:
    """Validate one normalized, portable, relative POSIX path.

    Colons are rejected everywhere, not merely after a drive letter, so a path
    cannot become a Windows alternate data stream after transfer.
    """

    if not isinstance(value, str) or not value:
        raise RunBundlePrivacyError(f"{label} is not a safe relative path")
    if unicodedata.normalize("NFC", value) != value:
        raise RunBundlePrivacyError(
            f"{label} relative path is not Unicode-normalized"
        )
    if (
        "\x00" in value
        or any(ord(char) < 0x20 for char in value)
        or "\\" in value
        or value.startswith("/")
        or value.startswith("//")
        or value.startswith("\\\\")
        or _WINDOWS_DRIVE_RE.match(value)
        or ":" in value
    ):
        raise RunBundlePrivacyError(f"{label} is not a safe relative path")
    candidate = PurePosixPath(value)
    parts = candidate.parts
    if (
        not parts
        or candidate.is_absolute()
        or candidate.as_posix() != value
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise RunBundlePrivacyError(f"{label} is not a safe relative path")
    for part in parts:
        if part.endswith((" ", ".")):
            raise RunBundlePrivacyError(f"{label} is not a safe relative path")
        device_stem = part.split(".", 1)[0].upper()
        if device_stem in _WINDOWS_DEVICE_NAMES:
            raise RunBundlePrivacyError(f"{label} is not a safe relative path")
    return value


def assert_no_casefold_collisions(paths: Iterable[str]) -> None:
    seen: dict[str, str] = {}
    for raw in paths:
        path = assert_safe_relative_path(raw, label="bundle entry")
        key = unicodedata.normalize("NFC", path).casefold()
        prior = seen.get(key)
        if prior is not None and prior != path:
            raise RunBundlePrivacyError(
                "bundle paths contain a casefold collision"
            )
        if prior is not None:
            raise RunBundlePrivacyError("bundle paths contain a duplicate entry")
        seen[key] = path


def _looks_absolute_path(value: str) -> bool:
    stripped = value.strip()
    return bool(
        stripped.startswith(("\\\\?\\", "\\\\.\\"))
        or stripped.casefold().startswith("file://")
        or _ABSOLUTE_PATH_HOME_RE.search(value)
        or _ABSOLUTE_PATH_DRIVE_RE.search(value)
        or _ABSOLUTE_PATH_UNC_RE.search(value)
        or _ABSOLUTE_PATH_NETWORK_RE.search(value)
        or _ABSOLUTE_PATH_POSIX_RE.search(value)
        or _ABSOLUTE_PATH_SENSITIVE_ROOT_RE.search(value)
    )


def _contains_forbidden_plamen_schema(value: str) -> bool:
    for marker in _PLAMEN_SCHEMA_MARKER_RE.findall(value):
        normalized = _normalized_key(marker)
        if any(
            fragment in normalized
            for fragment in _FORBIDDEN_PLAMEN_SCHEMA_FRAGMENTS
        ):
            return True
    return False


def _validate_public_scalar_string(
    value: str,
    *,
    forbidden_tokens: Sequence[str],
) -> None:
    if unicodedata.normalize("NFC", value) != value:
        raise RunBundlePrivacyError("public string is not Unicode-normalized")
    if "\x00" in value:
        raise RunBundlePrivacyError("public string contains NUL")
    if _contains_forbidden_plamen_schema(value):
        raise RunBundlePrivacyError(
            "public payload contains a forbidden private/reference/score schema"
        )
    if _looks_absolute_path(value):
        raise RunBundlePrivacyError("public payload contains an absolute user path")
    if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise RunBundlePrivacyError("public payload contains credential material")
    for token in forbidden_tokens:
        if token and token in value:
            # Do not echo the private token or publish a digest of it.
            raise RunBundlePrivacyError(
                "public payload contains evaluator-private corpus material"
            )


def validate_public_payload(
    value: Any,
    *,
    forbidden_tokens: Sequence[str] = (),
    forbidden_field_aliases: Sequence[str] = (),
) -> Any:
    """Reject private semantics, paths, secrets, and private token canaries.

    ``forbidden_tokens`` is intended for the evaluator-private import scan.
    Production exporters normally call this with an empty tuple because the
    tokens themselves must never enter the runner environment.
    """

    if not isinstance(forbidden_tokens, Sequence) or isinstance(
        forbidden_tokens, (str, bytes)
    ):
        raise RunBundlePrivacyError("forbidden token roster must be a sequence")
    if not isinstance(forbidden_field_aliases, Sequence) or isinstance(
        forbidden_field_aliases, (str, bytes)
    ):
        raise RunBundlePrivacyError(
            "forbidden field alias roster must be a sequence"
        )
    if any(not isinstance(token, str) or not token for token in forbidden_tokens):
        raise RunBundlePrivacyError("forbidden token roster contains invalid data")
    if any(
        not isinstance(alias, str) or not alias
        for alias in forbidden_field_aliases
    ):
        raise RunBundlePrivacyError(
            "forbidden field alias roster contains invalid data"
        )
    tokens = tuple(forbidden_tokens)
    configured_aliases = frozenset(
        _normalized_key(alias) for alias in forbidden_field_aliases
    )

    def scalar_is_nonempty(current: Any) -> bool:
        if current is None or current is False:
            return False
        if isinstance(current, str):
            return bool(current)
        if isinstance(current, (bool, int, float)):
            return True
        return False

    def descendant_scalars(current: Any) -> list[str]:
        if isinstance(current, Mapping):
            values: list[str] = []
            for child in current.values():
                values.extend(descendant_scalars(child))
            return values
        if isinstance(current, (list, tuple)):
            values = []
            for child in current:
                values.extend(descendant_scalars(child))
            return values
        if isinstance(current, str):
            return [current]
        if scalar_is_nonempty(current):
            return [str(current)]
        return []

    def reject_joined_secret_fragments(current: Any) -> None:
        strings = [part for part in descendant_scalars(current) if part]
        if len(strings) < 2:
            return
        for joined in ("".join(strings), " ".join(strings), ":".join(strings)):
            if any(pattern.search(joined) for pattern in _SECRET_PATTERNS):
                raise RunBundlePrivacyError(
                    "public payload contains split credential material"
                )

    def walk(
        current: Any,
        *,
        field_name: str | None = None,
        credential_context: bool = False,
    ) -> None:
        if isinstance(current, Mapping):
            seen: set[str] = set()
            for key, child in current.items():
                if not isinstance(key, str):
                    raise RunBundlePrivacyError(
                        "public JSON object keys must be strings"
                    )
                folded = unicodedata.normalize("NFC", key).casefold()
                if folded in seen:
                    raise RunBundlePrivacyError(
                        "public JSON object has a casefold key collision"
                    )
                seen.add(folded)
                assert_public_field_name(key)
                if _normalized_key(key) in configured_aliases:
                    raise RunBundlePrivacyError(
                        f"forbidden configured public field alias at key {key!r}"
                    )
                if key in _BLINDING_FALSE_FIELDS and child is not False:
                    raise RunBundlePrivacyError(
                        f"public blinding field {key!r} must be false"
                    )
                if key in _PUBLIC_RELATIVE_PATH_FIELDS and isinstance(child, str):
                    assert_safe_relative_path(
                        child, label=f"public field {key!r}"
                    )
                normalized_key = _normalized_key(key)
                child_credential_context = (
                    credential_context
                    or _is_credential_field(normalized_key)
                )
                if child_credential_context and descendant_scalars(child):
                    raise RunBundlePrivacyError(
                        "public payload contains credential material under "
                        "a credential-bearing field"
                    )
                walk(
                    child,
                    field_name=key,
                    credential_context=child_credential_context,
                )
            reject_joined_secret_fragments(current)
            return
        if isinstance(current, (list, tuple)):
            for child in current:
                walk(
                    child,
                    field_name=field_name,
                    credential_context=credential_context,
                )
            reject_joined_secret_fragments(current)
            return
        if isinstance(current, str):
            if credential_context and current:
                raise RunBundlePrivacyError(
                    "public payload contains credential material under "
                    "a credential-bearing field"
                )
            _validate_public_scalar_string(current, forbidden_tokens=tokens)
            return
        if current is None or isinstance(current, (bool, int)):
            return
        if isinstance(current, float) and math.isfinite(current):
            return
        raise RunBundlePrivacyError(
            f"public payload contains unsupported value type {type(current).__name__}"
        )

    walk(value)
    return value


def validate_public_object_bytes(
    raw: bytes,
    *,
    media_type: str,
    maximum_bytes: int = 64 << 20,
) -> None:
    """Scan referenced object content without assuming binary data is UTF-8."""

    if (
        not isinstance(raw, bytes)
        or not isinstance(media_type, str)
        or not media_type
        or not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 0
        or len(raw) > maximum_bytes
    ):
        raise RunBundlePrivacyError("public object scan input is invalid")
    compact = _BINARY_OBFUSCATING_BYTES_RE.sub(b"", raw)
    spaced = _BINARY_OBFUSCATING_BYTES_RE.sub(b" ", raw)
    if any(
        pattern.search(candidate)
        for candidate in (raw, compact, spaced)
        for pattern in _BINARY_SECRET_PATTERNS
    ):
        raise RunBundlePrivacyError(
            "public object contains a binary credential or secret signature"
        )
    structural_compact = _BINARY_STRUCTURAL_OBFUSCATING_BYTES_RE.sub(
        b"", raw
    )
    structural_spaced = _BINARY_STRUCTURAL_OBFUSCATING_BYTES_RE.sub(
        b" ", raw
    )
    for projection in (structural_compact, structural_spaced):
        # Both projections contain ASCII only because every high byte is
        # removed/replaced.  Scan them before the legitimate opaque-binary
        # invalid-UTF-8 return so invalid bytes cannot split a path or schema.
        text_projection = projection.decode("ascii", errors="strict")
        if _contains_forbidden_plamen_schema(text_projection):
            raise RunBundlePrivacyError(
                "public object contains a forbidden "
                "private/reference/score schema"
            )
        if _looks_absolute_path(text_projection):
            raise RunBundlePrivacyError(
                "public object contains an absolute user path"
            )
    normalized_media = media_type.casefold().split(";", 1)[0].strip()
    textual = normalized_media.startswith("text/") or any(
        marker in normalized_media
        for marker in (
            "json",
            "yaml",
            "xml",
            "markdown",
            "toml",
            "csv",
            "javascript",
        )
    )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        if not textual:
            return
        raise RunBundlePrivacyError(
            "textual public object is not valid UTF-8"
        ) from exc
    _validate_public_scalar_string(text, forbidden_tokens=())


def _lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _is_reparse_point(
    path: Path,
    row: os.stat_result | None = None,
) -> bool:
    info = row
    if info is None:
        try:
            info = _lstat(path)
        except OSError:
            return True
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    return bool(attributes & _WINDOWS_REPARSE_POINT)


def _enumerate_windows_streams(path: Path) -> tuple[str, ...]:
    """Enumerate every NTFS stream name or refuse if the primitive is unavailable."""

    if os.name != "nt":
        return ()
    if (
        _WINDOWS_ADS_INIT_ERROR is not None
        or _WINDOWS_CTYPES is None
        or _WINDOWS_FIND_STREAM_DATA is None
        or _WINDOWS_FIND_FIRST_STREAM is None
        or _WINDOWS_FIND_NEXT_STREAM is None
        or _WINDOWS_FIND_CLOSE is None
    ):
        raise NotImplementedError from _WINDOWS_ADS_INIT_ERROR
    data = _WINDOWS_FIND_STREAM_DATA()
    invalid = _WINDOWS_CTYPES.c_void_p(-1).value
    handle = _WINDOWS_FIND_FIRST_STREAM(
        str(Path(path).absolute()),
        0,
        _WINDOWS_CTYPES.byref(data),
        0,
    )
    if handle == invalid:
        error = _WINDOWS_CTYPES.get_last_error()
        if error == 38:  # ERROR_HANDLE_EOF: directories may have no streams.
            return ()
        raise OSError(error, "FindFirstStreamW failed")
    names: list[str] = []
    try:
        names.append(str(data.cStreamName))
        while True:
            _WINDOWS_CTYPES.set_last_error(0)
            if _WINDOWS_FIND_NEXT_STREAM(
                handle, _WINDOWS_CTYPES.byref(data)
            ):
                names.append(str(data.cStreamName))
                continue
            error = _WINDOWS_CTYPES.get_last_error()
            if error == 38:  # ERROR_HANDLE_EOF
                break
            raise OSError(error, "FindNextStreamW failed")
    finally:
        _WINDOWS_FIND_CLOSE(handle)
    return tuple(names)


def _assert_no_alternate_data_streams(path: Path) -> None:
    if os.name != "nt":
        return
    try:
        streams = _enumerate_windows_streams(path)
    except Exception as exc:
        raise RunBundlePrivacyError(
            "ADS_INSPECTION_UNAVAILABLE: refusing a false-clean tree inventory"
        ) from exc
    unexpected = [name for name in streams if name != "::$DATA"]
    if unexpected:
        raise RunBundlePrivacyError(
            "tree entry has an NTFS alternate data stream"
        )


def _is_sparse(row: os.stat_result) -> bool:
    attributes = int(getattr(row, "st_file_attributes", 0) or 0)
    if attributes & _WINDOWS_SPARSE_FILE:
        return True
    blocks = getattr(row, "st_blocks", None)
    return bool(
        isinstance(blocks, int)
        and row.st_size > 4096
        and blocks * 512 < row.st_size
    )


def _assert_plain_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        row = _lstat(path)
    except OSError as exc:
        raise RunBundlePrivacyError(f"{label} directory is unavailable") from exc
    if (
        stat.S_ISLNK(row.st_mode)
        or _is_reparse_point(path, row)
        or not stat.S_ISDIR(row.st_mode)
    ):
        raise RunBundlePrivacyError(
            f"{label} directory is a link/reparse point or not a directory"
        )
    return row


def _assert_plain_regular(
    path: Path,
    row: os.stat_result,
    *,
    label: str,
) -> None:
    if stat.S_ISLNK(row.st_mode) or _is_reparse_point(path, row):
        raise RunBundlePrivacyError(f"{label} is a link or reparse point")
    if not stat.S_ISREG(row.st_mode):
        raise RunBundlePrivacyError(f"{label} is not a regular file")
    if int(getattr(row, "st_nlink", 1)) != 1:
        raise RunBundlePrivacyError(f"{label} is a hardlink alias")
    if _is_sparse(row):
        raise RunBundlePrivacyError(f"{label} is a sparse file alias")


def _stable_fields(row: os.stat_result) -> tuple[int, ...]:
    return (
        int(getattr(row, "st_dev", 0)),
        int(getattr(row, "st_ino", 0)),
        int(row.st_size),
        int(getattr(row, "st_mtime_ns", 0)),
        int(getattr(row, "st_ctime_ns", 0)),
        int(getattr(row, "st_nlink", 1)),
        int(stat.S_IFMT(row.st_mode)),
    )


def read_stable_regular_bytes(
    path: Path,
    *,
    maximum_bytes: int = 1 << 30,
    label: str = "bundle file",
) -> bytes:
    """Read one non-link, single-link regular file with before/open/after checks."""

    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 0
    ):
        raise RunBundlePrivacyError("maximum byte bound is invalid")
    target = Path(path)
    try:
        before = _lstat(target)
    except OSError as exc:
        raise RunBundlePrivacyError(f"{label} is unavailable") from exc
    _assert_plain_regular(target, before, label=label)
    _assert_no_alternate_data_streams(target)
    if before.st_size > maximum_bytes:
        raise RunBundlePrivacyError(f"{label} exceeds its byte limit")

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise RunBundlePrivacyError(f"{label} could not be opened safely") from exc
    try:
        opened_before = os.fstat(descriptor)
        _assert_plain_regular(target, opened_before, label=label)
        if opened_before.st_size > maximum_bytes:
            raise RunBundlePrivacyError(f"{label} exceeds its byte limit")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = _lstat(target)
    except OSError as exc:
        raise RunBundlePrivacyError(f"{label} changed during read") from exc
    _assert_plain_regular(target, after, label=label)
    _assert_no_alternate_data_streams(target)
    if (
        len(raw) > maximum_bytes
        or len(raw) != after.st_size
        or _stable_fields(before)
        != _stable_fields(opened_before)
        != _stable_fields(opened_after)
        != _stable_fields(after)
    ):
        raise RunBundlePrivacyError(f"{label} changed during stable read")
    return raw


def read_stable_regular_file_snapshot(
    path: Path,
    *,
    maximum_bytes: int = 1 << 30,
    label: str = "source file",
) -> StableRegularFileSnapshot:
    """Capture bytes and identity across one outer stable-read window."""

    target = Path(path)
    try:
        before = _lstat(target)
    except OSError as exc:
        raise RunBundlePrivacyError(f"{label} is unavailable") from exc
    _assert_plain_regular(target, before, label=label)
    raw = read_stable_regular_bytes(
        target,
        maximum_bytes=maximum_bytes,
        label=label,
    )
    try:
        after = _lstat(target)
    except OSError as exc:
        raise RunBundlePrivacyError(f"{label} changed during capture") from exc
    _assert_plain_regular(target, after, label=label)
    _assert_no_alternate_data_streams(target)
    if _stable_fields(before) != _stable_fields(after):
        raise RunBundlePrivacyError(f"{label} changed during capture")
    return StableRegularFileSnapshot(
        raw=raw,
        state=_stable_fields(after),
        sha256=sha256_bytes(raw),
    )


def read_stable_regular_tree_snapshot(
    root: Path,
    *,
    maximum_files: int = 1_000_000,
    maximum_total_bytes: int = 8 << 30,
) -> StableRegularTreeSnapshot:
    """Capture one alias-free tree generation with exact identities and bytes."""

    if (
        not isinstance(maximum_files, int)
        or isinstance(maximum_files, bool)
        or maximum_files < 0
        or not isinstance(maximum_total_bytes, int)
        or isinstance(maximum_total_bytes, bool)
        or maximum_total_bytes < 0
    ):
        raise RunBundlePrivacyError("tree capture limits are invalid")
    base = Path(root)
    _assert_plain_directory(base, label="tree root")
    directories: list[str] = []
    files: list[tuple[str, bytes]] = []
    file_states: list[tuple[str, tuple[int, ...]]] = []
    directory_states: list[
        tuple[str, tuple[int, ...], tuple[str, ...]]
    ] = []
    all_entries: list[str] = []
    total = 0

    def visit(directory: Path, relative_parent: PurePosixPath | None) -> None:
        nonlocal total
        relative_directory = (
            "" if relative_parent is None else relative_parent.as_posix()
        )
        before = _assert_plain_directory(directory, label="tree directory")
        _assert_no_alternate_data_streams(directory)
        names = _sorted_entry_names(directory)
        _assert_no_alternate_data_streams(directory)
        for name in names:
            path = directory / name
            relative_path = (
                PurePosixPath(name)
                if relative_parent is None
                else relative_parent / name
            )
            relative = relative_path.as_posix()
            assert_safe_relative_path(relative, label="tree entry")
            all_entries.append(relative)
            try:
                row = _lstat(path)
            except OSError as exc:
                raise RunBundlePrivacyError(
                    "tree entry became unavailable"
                ) from exc
            if stat.S_ISLNK(row.st_mode) or _is_reparse_point(path, row):
                raise RunBundlePrivacyError(
                    "tree entry is a link or reparse point"
                )
            if stat.S_ISDIR(row.st_mode):
                directories.append(relative)
                visit(path, relative_path)
                continue
            _assert_plain_regular(path, row, label="tree entry")
            if len(files) >= maximum_files:
                raise RunBundlePrivacyError("tree exceeds its file-count limit")
            capture = read_stable_regular_file_snapshot(
                path,
                maximum_bytes=maximum_total_bytes - total,
                label="tree entry",
            )
            total += len(capture.raw)
            if total > maximum_total_bytes:
                raise RunBundlePrivacyError("tree exceeds its total byte limit")
            files.append((relative, capture.raw))
            file_states.append((relative, capture.state))
        after_names = _sorted_entry_names(directory)
        after = _assert_plain_directory(directory, label="tree directory")
        _assert_no_alternate_data_streams(directory)
        if names != after_names or _stable_fields(before) != _stable_fields(after):
            raise RunBundlePrivacyError(
                "tree directory changed during capture"
            )
        directory_states.append(
            (relative_directory, _stable_fields(after), tuple(names))
        )

    visit(base, None)
    assert_no_casefold_collisions(all_entries)
    sorted_directories = tuple(
        sorted(directories, key=lambda item: item.encode("utf-8"))
    )
    sorted_files = tuple(
        sorted(files, key=lambda item: item[0].encode("utf-8"))
    )
    sorted_file_states = tuple(
        sorted(file_states, key=lambda item: item[0].encode("utf-8"))
    )
    sorted_directory_states = tuple(
        sorted(directory_states, key=lambda item: item[0].encode("utf-8"))
    )
    preimage = {
        "directories": list(sorted_directories),
        "files": [
            {
                "relative_path": relative,
                "byte_length": len(raw),
                "sha256": sha256_bytes(raw),
            }
            for relative, raw in sorted_files
        ],
    }
    return StableRegularTreeSnapshot(
        directories=sorted_directories,
        files=sorted_files,
        file_states=sorted_file_states,
        directory_states=sorted_directory_states,
        tree_sha256=sha256_bytes(_canonical_document_bytes(preimage)),
    )


def assert_stable_regular_file_snapshot_unchanged(
    path: Path,
    snapshot: StableRegularFileSnapshot,
    *,
    maximum_bytes: int = 1 << 30,
    label: str = "source file",
) -> None:
    """Rehash one live file and require its exact captured identity."""

    if not isinstance(snapshot, StableRegularFileSnapshot):
        raise RunBundlePrivacyError("source file snapshot is invalid")
    current = read_stable_regular_file_snapshot(
        path,
        maximum_bytes=maximum_bytes,
        label=label,
    )
    if current != snapshot:
        raise RunBundlePrivacyError(f"{label} changed after capture")


def assert_stable_regular_tree_snapshot_unchanged(
    root: Path,
    snapshot: StableRegularTreeSnapshot,
    *,
    maximum_files: int = 1_000_000,
    maximum_total_bytes: int = 8 << 30,
) -> None:
    """Re-enumerate and rehash a live tree, including every identity."""

    if not isinstance(snapshot, StableRegularTreeSnapshot):
        raise RunBundlePrivacyError("source tree snapshot is invalid")
    current = read_stable_regular_tree_snapshot(
        root,
        maximum_files=maximum_files,
        maximum_total_bytes=maximum_total_bytes,
    )
    if current != snapshot:
        raise RunBundlePrivacyError("source tree changed after capture")


def _sorted_entry_names(path: Path) -> list[str]:
    try:
        names = [entry.name for entry in os.scandir(path)]
    except OSError as exc:
        raise RunBundlePrivacyError("bundle directory could not be enumerated") from exc
    return sorted(names, key=lambda item: item.encode("utf-8"))


def inspect_exact_tree(
    root: Path,
    *,
    maximum_files: int = 1_000_000,
    maximum_total_bytes: int = 8 << 30,
) -> dict[str, Any]:
    """Inventory every directory plus every safe regular file exactly once."""

    base = Path(root)
    _assert_plain_directory(base, label="tree root")
    if maximum_files < 0 or maximum_total_bytes < 0:
        raise RunBundlePrivacyError("tree inventory limits are invalid")
    all_relative_entries: list[str] = []
    rows: list[dict[str, Any]] = []
    directories: list[str] = []
    total = 0

    def visit(directory: Path, relative_parent: PurePosixPath | None) -> None:
        nonlocal total
        before_directory = _assert_plain_directory(
            directory, label="tree directory"
        )
        _assert_no_alternate_data_streams(directory)
        names = _sorted_entry_names(directory)
        _assert_no_alternate_data_streams(directory)
        for name in names:
            path = directory / name
            relative = (
                PurePosixPath(name)
                if relative_parent is None
                else relative_parent / name
            ).as_posix()
            assert_safe_relative_path(relative, label="tree entry")
            all_relative_entries.append(relative)
            try:
                row = _lstat(path)
            except OSError as exc:
                raise RunBundlePrivacyError("tree entry became unavailable") from exc
            if stat.S_ISLNK(row.st_mode) or _is_reparse_point(path, row):
                raise RunBundlePrivacyError(
                    "tree entry is a link or reparse point"
                )
            if stat.S_ISDIR(row.st_mode):
                directories.append(relative)
                visit(path, PurePosixPath(relative))
                continue
            _assert_plain_regular(path, row, label="tree entry")
            _assert_no_alternate_data_streams(path)
            if len(rows) >= maximum_files:
                raise RunBundlePrivacyError("tree exceeds its file-count limit")
            raw = read_stable_regular_bytes(
                path,
                maximum_bytes=maximum_total_bytes - total,
                label="tree entry",
            )
            total += len(raw)
            if total > maximum_total_bytes:
                raise RunBundlePrivacyError("tree exceeds its total byte limit")
            rows.append(
                {
                    "relative_path": relative,
                    "byte_length": len(raw),
                    "sha256": sha256_bytes(raw),
                }
            )
        after_names = _sorted_entry_names(directory)
        after_directory = _assert_plain_directory(
            directory, label="tree directory"
        )
        _assert_no_alternate_data_streams(directory)
        if (
            names != after_names
            or _stable_fields(before_directory)
            != _stable_fields(after_directory)
        ):
            raise RunBundlePrivacyError(
                "tree directory changed during enumeration"
            )

    visit(base, None)
    assert_no_casefold_collisions(all_relative_entries)
    return {
        "directories": sorted(
            directories, key=lambda item: item.encode("utf-8")
        ),
        "files": sorted(
            rows,
            key=lambda row: str(row["relative_path"]).encode("utf-8"),
        ),
    }


def inspect_regular_tree(
    root: Path,
    *,
    maximum_files: int = 1_000_000,
    maximum_total_bytes: int = 8 << 30,
) -> list[dict[str, Any]]:
    """Compatibility view of the exact inventory's regular-file rows."""

    return inspect_exact_tree(
        root,
        maximum_files=maximum_files,
        maximum_total_bytes=maximum_total_bytes,
    )["files"]


def _snapshot_tree_digest(inventory: Mapping[str, Any]) -> str:
    return sha256_bytes(_canonical_document_bytes(inventory))


def snapshot_export_inputs(
    root: Path,
    *,
    maximum_files: int = 1_000_000,
    maximum_total_bytes: int = 8 << 30,
) -> dict[str, Any]:
    inventory = inspect_exact_tree(
        root,
        maximum_files=maximum_files,
        maximum_total_bytes=maximum_total_bytes,
    )
    return {
        "schema_version": INPUT_SNAPSHOT_SCHEMA,
        "directories": inventory["directories"],
        "files": inventory["files"],
        "tree_sha256": _snapshot_tree_digest(inventory),
    }


def verify_export_inputs_unchanged(
    root: Path,
    expected: Mapping[str, Any],
    *,
    maximum_files: int = 1_000_000,
    maximum_total_bytes: int = 8 << 30,
) -> Mapping[str, Any]:
    if not isinstance(expected, Mapping) or set(expected) != {
        "schema_version",
        "directories",
        "files",
        "tree_sha256",
    }:
        raise RunBundlePrivacyError("input snapshot contract is invalid")
    if expected.get("schema_version") != INPUT_SNAPSHOT_SCHEMA:
        raise RunBundlePrivacyError("input snapshot schema is invalid")
    current = snapshot_export_inputs(
        root,
        maximum_files=maximum_files,
        maximum_total_bytes=maximum_total_bytes,
    )
    if _canonical_json_bytes(current) != _canonical_json_bytes(dict(expected)):
        raise RunBundlePrivacyError("export inputs changed during export")
    return expected


def assert_deterministic_exports(
    first: Path,
    second: Path,
) -> str:
    """Compare every byte of two independently materialized sealed bundles."""

    if isinstance(first, Mapping) or isinstance(second, Mapping):
        raise RunBundlePrivacyError(
            "determinism evidence requires two complete sealed RunBundle trees"
        )
    try:
        left_root = Path(first)
        right_root = Path(second)
    except TypeError as exc:
        raise RunBundlePrivacyError(
            "determinism evidence requires two complete sealed RunBundle trees"
        ) from exc
    left_index = verify_bundle_index(left_root)
    right_index = verify_bundle_index(right_root)
    left_inventory = inspect_exact_tree(left_root)
    right_inventory = inspect_exact_tree(right_root)
    if left_inventory != right_inventory:
        raise RunBundlePrivacyError(
            "double export produced nondeterministic tree bytes"
        )
    for row in left_inventory["files"]:
        relative = row["relative_path"]
        left_raw = read_stable_regular_bytes(
            left_root / PurePosixPath(relative),
            label="first deterministic export entry",
        )
        right_raw = read_stable_regular_bytes(
            right_root / PurePosixPath(relative),
            label="second deterministic export entry",
        )
        if left_raw != right_raw:
            raise RunBundlePrivacyError(
                "double export produced nondeterministic exact bytes"
            )
    left_seal = bundle_seal_sha256(left_index)
    if left_index != right_index or left_seal != bundle_seal_sha256(right_index):
        raise RunBundlePrivacyError(
            "double export produced nondeterministic index or seal bytes"
        )
    return left_seal


def prove_deterministic_double_export(
    materialize_and_seal: Callable[[Path], Any],
    first: Path,
    second: Path,
    *,
    exact_public_lock_bytes: bytes,
) -> str:
    """Materialize twice and verify both through the unified v2 boundary."""

    if not callable(materialize_and_seal):
        raise RunBundlePrivacyError("double-export materializer is not callable")
    if not isinstance(exact_public_lock_bytes, bytes):
        raise RunBundlePrivacyError(
            "double-export public case lock must be exact bytes"
        )
    first_root = Path(first).absolute()
    second_root = Path(second).absolute()
    first_text = os.path.normcase(str(first_root))
    second_text = os.path.normcase(str(second_root))
    if (
        first_text == second_text
        or first_text.startswith(second_text + os.sep)
        or second_text.startswith(first_text + os.sep)
    ):
        raise RunBundlePrivacyError(
            "double-export roots must be distinct and non-nested"
        )
    if os.path.lexists(first_root) or os.path.lexists(second_root):
        raise RunBundlePrivacyError(
            "double-export roots must be fresh and previously nonexistent"
        )
    try:
        import runbundle_contracts as contracts
    except ImportError:  # pragma: no cover - package-style import fallback
        from . import runbundle_contracts as contracts

    materialize_and_seal(first_root)
    left = contracts.verify_runbundle_v2(
        first_root, exact_public_lock_bytes
    )
    materialize_and_seal(second_root)
    right = contracts.verify_runbundle_v2(
        second_root, exact_public_lock_bytes
    )
    if (
        left.verified_files != right.verified_files
        or left.bundle_seal_sha256 != right.bundle_seal_sha256
        or left.verification_sha256 != right.verification_sha256
    ):
        raise RunBundlePrivacyError(
            "double export produced nondeterministic exact bytes"
        )
    return left.bundle_seal_sha256


def _root_shape(root: Path, *, require_generated_pair: bool) -> None:
    _assert_plain_directory(root, label="RunBundle root")
    names = _sorted_entry_names(root)
    assert_no_casefold_collisions(names)
    allowed = PAYLOAD_FILE_NAMES | {"objects"}
    allowed |= GENERATED_FILE_NAMES
    actual = set(names)
    if not PAYLOAD_FILE_NAMES.issubset(actual) or "objects" not in actual:
        raise RunBundlePrivacyError("RunBundle root entries are incomplete")
    if not actual.issubset(allowed):
        raise RunBundlePrivacyError("RunBundle has an unknown root entry")
    generated = actual & GENERATED_FILE_NAMES
    if require_generated_pair and generated != GENERATED_FILE_NAMES:
        raise RunBundlePrivacyError(
            "RunBundle generated seal entries are incomplete"
        )
    if not require_generated_pair and generated == {"SEALED.sha256"}:
        raise RunBundlePrivacyError(
            "RunBundle seal cannot exist without its bundle index"
        )
    objects = root / "objects"
    _assert_plain_directory(objects, label="object store")
    object_children = _sorted_entry_names(objects)
    if object_children != ["sha256"]:
        raise RunBundlePrivacyError("object store layout is invalid")
    _assert_plain_directory(objects / "sha256", label="SHA-256 object store")
    for payload in PAYLOAD_FILE_NAMES:
        try:
            row = _lstat(root / payload)
        except OSError as exc:
            raise RunBundlePrivacyError("RunBundle payload is unavailable") from exc
        _assert_plain_regular(root / payload, row, label="RunBundle payload")


def _validate_object_rows(rows: Sequence[Mapping[str, Any]]) -> None:
    prefix = "objects/sha256/"
    for row in rows:
        relative = str(row["relative_path"])
        if not relative.startswith("objects/"):
            continue
        if (
            not relative.startswith(prefix)
            or relative.count("/") != 2
            or not _DIGEST_RE.fullmatch(relative[len(prefix) :])
            or row["sha256"] != relative[len(prefix) :]
        ):
            raise RunBundlePrivacyError(
                "object path does not equal its content SHA-256"
            )


def build_bundle_index(root: Path) -> dict[str, Any]:
    """Build, but do not write, the canonical recursive v2 bundle index."""

    base = Path(root)
    _root_shape(base, require_generated_pair=False)
    inventory = inspect_exact_tree(base)
    if set(inventory["directories"]) != {"objects", "objects/sha256"}:
        raise RunBundlePrivacyError(
            "RunBundle contains an unexpected or missing directory"
        )
    entries = [
        row
        for row in inventory["files"]
        if row["relative_path"] not in GENERATED_FILE_NAMES
    ]
    if {row["relative_path"] for row in entries} & GENERATED_FILE_NAMES:
        raise RunBundlePrivacyError("generated files leaked into bundle index")
    _validate_object_rows(entries)
    return {
        "schema_version": BUNDLE_INDEX_SCHEMA,
        "bundle_profile": REAL_AUDIT_V2,
        "entries": entries,
    }


def _validate_index_contract(index: Any) -> dict[str, Any]:
    if not isinstance(index, dict) or set(index) != {
        "schema_version",
        "bundle_profile",
        "entries",
    }:
        raise RunBundlePrivacyError("bundle index contract is invalid")
    if index["schema_version"] != BUNDLE_INDEX_SCHEMA:
        raise RunBundlePrivacyError("bundle index schema is invalid")
    if index["bundle_profile"] != REAL_AUDIT_V2:
        raise RunBundlePrivacyError("bundle index profile is invalid")
    entries = index["entries"]
    if not isinstance(entries, list):
        raise RunBundlePrivacyError("bundle index entries are invalid")
    paths: list[str] = []
    for row in entries:
        if not isinstance(row, dict) or set(row) != {
            "relative_path",
            "byte_length",
            "sha256",
        }:
            raise RunBundlePrivacyError("bundle index entry contract is invalid")
        relative = assert_safe_relative_path(
            row["relative_path"], label="bundle index entry"
        )
        if relative in GENERATED_FILE_NAMES:
            raise RunBundlePrivacyError(
                "generated file cannot index itself or the seal"
            )
        if (
            not isinstance(row["byte_length"], int)
            or isinstance(row["byte_length"], bool)
            or row["byte_length"] < 0
        ):
            raise RunBundlePrivacyError("bundle index byte length is invalid")
        if (
            not isinstance(row["sha256"], str)
            or not _DIGEST_RE.fullmatch(row["sha256"])
        ):
            raise RunBundlePrivacyError("bundle index digest is invalid")
        paths.append(relative)
    assert_no_casefold_collisions(paths)
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
        raise RunBundlePrivacyError("bundle index entries are not canonical")
    _validate_object_rows(entries)
    return index


def bundle_index_bytes(index: Mapping[str, Any]) -> bytes:
    validated = _validate_index_contract(dict(index))
    return _canonical_json_bytes(validated) + b"\n"


def bundle_seal_sha256(index: Mapping[str, Any]) -> str:
    return sha256_bytes(bundle_index_bytes(index))


def read_verified_bundle_snapshot(
    root: Path,
    *,
    maximum_files: int = 1_000_000,
    maximum_total_bytes: int = 8 << 30,
) -> VerifiedBundleSnapshot:
    """Capture and verify one sealed tree while reading each file exactly once."""

    if (
        not isinstance(maximum_files, int)
        or isinstance(maximum_files, bool)
        or maximum_files < 0
        or not isinstance(maximum_total_bytes, int)
        or isinstance(maximum_total_bytes, bool)
        or maximum_total_bytes < 0
    ):
        raise RunBundlePrivacyError("bundle capture limits are invalid")
    base = Path(root)
    _assert_plain_directory(base, label="RunBundle root")
    directories: list[str] = []
    files: list[tuple[str, bytes]] = []
    file_states: list[tuple[str, tuple[int, ...]]] = []
    directory_states: list[
        tuple[str, tuple[int, ...], tuple[str, ...]]
    ] = []
    all_entries: list[str] = []
    total = 0

    def visit(directory: Path, relative_parent: PurePosixPath | None) -> None:
        nonlocal total
        relative_directory = (
            "" if relative_parent is None else relative_parent.as_posix()
        )
        before = _assert_plain_directory(directory, label="bundle directory")
        _assert_no_alternate_data_streams(directory)
        names = _sorted_entry_names(directory)
        _assert_no_alternate_data_streams(directory)
        for name in names:
            path = directory / name
            relative_path = (
                PurePosixPath(name)
                if relative_parent is None
                else relative_parent / name
            )
            relative = relative_path.as_posix()
            assert_safe_relative_path(relative, label="bundle entry")
            all_entries.append(relative)
            try:
                row = _lstat(path)
            except OSError as exc:
                raise RunBundlePrivacyError(
                    "bundle entry became unavailable"
                ) from exc
            if stat.S_ISLNK(row.st_mode) or _is_reparse_point(path, row):
                raise RunBundlePrivacyError(
                    "bundle entry is a link or reparse point"
                )
            if stat.S_ISDIR(row.st_mode):
                directories.append(relative)
                visit(path, relative_path)
                continue
            _assert_plain_regular(path, row, label="bundle entry")
            if len(files) >= maximum_files:
                raise RunBundlePrivacyError(
                    "bundle exceeds its file-count limit"
                )
            raw = read_stable_regular_bytes(
                path,
                maximum_bytes=maximum_total_bytes - total,
                label="bundle entry",
            )
            total += len(raw)
            if total > maximum_total_bytes:
                raise RunBundlePrivacyError(
                    "bundle exceeds its total byte limit"
                )
            after_file = _lstat(path)
            _assert_plain_regular(path, after_file, label="bundle entry")
            files.append((relative, raw))
            file_states.append((relative, _stable_fields(after_file)))
        after_names = _sorted_entry_names(directory)
        after = _assert_plain_directory(directory, label="bundle directory")
        _assert_no_alternate_data_streams(directory)
        if names != after_names or _stable_fields(before) != _stable_fields(after):
            raise RunBundlePrivacyError(
                "bundle directory changed during capture"
            )
        directory_states.append(
            (relative_directory, _stable_fields(after), tuple(names))
        )

    visit(base, None)
    assert_no_casefold_collisions(all_entries)
    sorted_directories = tuple(
        sorted(directories, key=lambda item: item.encode("utf-8"))
    )
    sorted_files = tuple(
        sorted(files, key=lambda item: item[0].encode("utf-8"))
    )
    sorted_file_states = tuple(
        sorted(file_states, key=lambda item: item[0].encode("utf-8"))
    )
    sorted_directory_states = tuple(
        sorted(directory_states, key=lambda item: item[0].encode("utf-8"))
    )
    if set(sorted_directories) != {"objects", "objects/sha256"}:
        raise RunBundlePrivacyError(
            "RunBundle contains an unexpected or missing directory"
        )
    captured = dict(sorted_files)
    required_files = PAYLOAD_FILE_NAMES | GENERATED_FILE_NAMES
    root_files = {
        path for path in captured if "/" not in path
    }
    if root_files != required_files:
        raise RunBundlePrivacyError(
            "RunBundle root payload/index/seal entries are incomplete or unknown"
        )
    if any(
        not path.startswith("objects/sha256/")
        for path in captured
        if "/" in path
    ):
        raise RunBundlePrivacyError("RunBundle object store layout is invalid")
    raw_index = captured["bundle_index.json"]
    try:
        parsed = _strict_json_loads(raw_index, require_canonical=True)
    except Exception as exc:
        if isinstance(exc, RunBundlePrivacyError):
            raise
        raise RunBundlePrivacyError("bundle index JSON is invalid") from exc
    index = _validate_index_contract(parsed)
    if raw_index != bundle_index_bytes(index):
        raise RunBundlePrivacyError("bundle index bytes are not canonical")
    expected_entries = [
        {
            "relative_path": relative,
            "byte_length": len(raw),
            "sha256": sha256_bytes(raw),
        }
        for relative, raw in sorted_files
        if relative not in GENERATED_FILE_NAMES
    ]
    _validate_object_rows(expected_entries)
    expected_index = {
        "schema_version": BUNDLE_INDEX_SCHEMA,
        "bundle_profile": REAL_AUDIT_V2,
        "entries": expected_entries,
    }
    if _canonical_json_bytes(index) != _canonical_json_bytes(expected_index):
        raise RunBundlePrivacyError(
            "bundle index does not match exact file digests and lengths"
        )
    seal_digest = bundle_seal_sha256(index)
    if captured["SEALED.sha256"] != seal_digest.encode("ascii") + b"\n":
        raise RunBundlePrivacyError("bundle seal digest is invalid")
    return VerifiedBundleSnapshot(
        directories=sorted_directories,
        files=sorted_files,
        file_states=sorted_file_states,
        directory_states=sorted_directory_states,
        bundle_index_bytes=raw_index,
        bundle_seal_sha256=seal_digest,
    )


def assert_verified_bundle_snapshot_unchanged(
    root: Path,
    snapshot: VerifiedBundleSnapshot,
) -> None:
    """Recheck identities, directory memberships, and every captured byte."""

    if not isinstance(snapshot, VerifiedBundleSnapshot):
        raise RunBundlePrivacyError("verified bundle snapshot is invalid")
    base = Path(root)
    for relative, expected_state, expected_names in snapshot.directory_states:
        directory = base if not relative else base / PurePosixPath(relative)
        before = _assert_plain_directory(directory, label="bundle directory")
        _assert_no_alternate_data_streams(directory)
        names = tuple(_sorted_entry_names(directory))
        _assert_no_alternate_data_streams(directory)
        after = _assert_plain_directory(directory, label="bundle directory")
        if (
            names != expected_names
            or _stable_fields(before) != expected_state
            or _stable_fields(after) != expected_state
        ):
            raise RunBundlePrivacyError(
                "verified bundle changed after its stable capture"
            )
    captured_bytes = dict(snapshot.files)
    for relative, expected_state in snapshot.file_states:
        path = base / PurePosixPath(relative)
        raw = read_stable_regular_bytes(
            path,
            maximum_bytes=max(len(captured_bytes[relative]), 1),
            label="verified bundle entry",
        )
        row = _lstat(path)
        if (
            _stable_fields(row) != expected_state
            or raw != captured_bytes[relative]
        ):
            raise RunBundlePrivacyError(
                "verified bundle changed after its stable capture"
            )


def verify_bundle_index(root: Path) -> dict[str, Any]:
    """Verify canonical index/seal bytes and exact recursive bundle contents."""

    snapshot = read_verified_bundle_snapshot(root)
    parsed = _strict_json_loads(
        snapshot.bundle_index_bytes, require_canonical=True
    )
    return _validate_index_contract(parsed)


__all__ = [
    "BUNDLE_INDEX_SCHEMA",
    "CREDENTIAL_SIGNATURE_REGISTRY_VERSION",
    "GENERATED_FILE_NAMES",
    "INPUT_SNAPSHOT_SCHEMA",
    "PAYLOAD_FILE_NAMES",
    "PUBLIC_STRUCTURAL_SCAN_POLICY_ID",
    "PUBLIC_STRUCTURAL_SCAN_POLICY_VERSION",
    "REAL_AUDIT_V2",
    "ROOT_ENTRY_NAMES",
    "RunBundlePrivacyError",
    "StableRegularFileSnapshot",
    "StableRegularTreeSnapshot",
    "VerifiedBundleSnapshot",
    "assert_stable_regular_file_snapshot_unchanged",
    "assert_stable_regular_tree_snapshot_unchanged",
    "assert_verified_bundle_snapshot_unchanged",
    "assert_deterministic_exports",
    "assert_no_casefold_collisions",
    "assert_public_field_name",
    "assert_safe_relative_path",
    "build_bundle_index",
    "bundle_index_bytes",
    "bundle_seal_sha256",
    "credential_signature_registry_preimage",
    "inspect_exact_tree",
    "inspect_regular_tree",
    "is_forbidden_public_field",
    "prove_deterministic_double_export",
    "public_structural_scan_policy_preimage",
    "public_structural_scan_policy_sha256",
    "read_stable_regular_bytes",
    "read_stable_regular_file_snapshot",
    "read_stable_regular_tree_snapshot",
    "read_verified_bundle_snapshot",
    "sha256_bytes",
    "snapshot_export_inputs",
    "validate_public_object_bytes",
    "validate_public_payload",
    "verify_bundle_index",
    "verify_export_inputs_unchanged",
]
