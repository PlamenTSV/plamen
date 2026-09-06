"""Closed, canonical, GT-blind contracts for real-audit RunBundle v2.

The synthetic-v1 contract is intentionally neither imported nor modified.
These validators normalize nothing: accepted values are returned unchanged,
and ambiguous/unknown data fails closed.  This module contains no matching,
grading, lifecycle inference, LLM invocation, or scoring behavior.
"""
from __future__ import annotations

import copy
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
import math
import re
import secrets
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence
import unicodedata

try:
    import runbundle_privacy as _privacy
except ImportError:  # pragma: no cover - package-style import fallback
    from . import runbundle_privacy as _privacy

try:
    import runbundle_phase_map as _phase_maps
except ImportError:  # pragma: no cover - package-style import fallback
    from . import runbundle_phase_map as _phase_maps


REAL_AUDIT_V2 = "REAL_AUDIT_V2"
LOCAL_TRUST_PROFILES = frozenset({"USER_RUN", "B0_LOCAL"})
B1_TRUST_PROFILES = frozenset({"B1_INCOMPLETE", "B1_COMPLETE"})
TRUST_PROFILES = LOCAL_TRUST_PROFILES | B1_TRUST_PROFILES
UNAUTHENTICATED_AUTHORITY = "UNAUTHENTICATED_PARSE"
PUBLIC_CASE_LOCK_SCHEMA = "plamen.public-case-lock.v2"
PRIVATE_CASE_LOCK_SCHEMA = "plamen.private-case-lock.v2"
RUN_MANIFEST_SCHEMA = "plamen.real-audit-run-manifest.v2"
PHASE_EVENT_SCHEMA = "plamen.real-audit-phase-event.v2"
CANDIDATE_SET_SCHEMA = "plamen.real-audit-candidate-set.v2"
CANDIDATE_LINEAGE_SCHEMA = "plamen.candidate-lineage.v1"
RAW_OUTPUT_INDEX_SCHEMA = "plamen.real-audit-raw-output-index.v2"
REPORT_PROJECTION_SCHEMA = "plamen.final-report-projection.v1"
HARVEST_RECEIPT_SCHEMA = "plamen.real-audit-harvest-receipt.v2"

PUBLIC_PAYLOAD_FILE_NAMES = frozenset(
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
PUBLIC_SCHEMA_VERSIONS = frozenset(
    {
        PUBLIC_CASE_LOCK_SCHEMA,
        RUN_MANIFEST_SCHEMA,
        PHASE_EVENT_SCHEMA,
        CANDIDATE_SET_SCHEMA,
        CANDIDATE_LINEAGE_SCHEMA,
        RAW_OUTPUT_INDEX_SCHEMA,
        REPORT_PROJECTION_SCHEMA,
        HARVEST_RECEIPT_SCHEMA,
    }
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_KINDS = frozenset(
    {"case", "run", "experiment", "cell", "parity", "nonce", "cluster", "alias"}
)
_RANDOM_ALLOCATION_KINDS = frozenset(
    {"case", "run", "experiment", "cell", "parity", "nonce"}
)
_OPAQUE_BODY_RE = re.compile(r"^[a-z2-7]{26}$")
_OPAQUE_CHECKSUM_RE = re.compile(r"^[a-z2-7]{8}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
_SEVERITIES = frozenset(
    {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNASSESSED"}
)
_MACRO_PHASES = frozenset(
    {
        "recon",
        "breadth",
        "inventory",
        "depth",
        "chain",
        "verify",
        "report",
        "bake",
        "graph",
        "composition",
        "CONTROL",
        "UNMAPPED",
    }
)
_AUTHORITY_TYPES = frozenset(
    {
        "RESOURCE_MEASUREMENT",
        "RESOURCE_MEASUREMENT_SUMMARY",
        "NEGATIVE_DISPOSITION",
        "NONFINDING_CLASSIFICATION",
        "CANDIDATE_EMISSION",
        "PHASE_OUTPUT",
        "REPORT_DISPOSITION",
        "REPORT_QUALITY",
        "SEVERITY_DECISION",
        "ALIAS_DECISION",
        "LINEAGE_DEBT",
        "RECORD_PARTITION",
        "RUN_CONTEXT",
    }
)

# One closed resource contract is shared by in-memory values, JSON, and JSONL.
# Raw artifacts belong in the content-addressed object store; public metadata
# documents must remain bounded enough to validate without relying on the
# interpreter recursion limit or exhausting process memory.
MAX_JSON_BYTES = 8 << 20
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 100_000
MAX_JSON_WIDTH = 10_000


class RunBundleContractError(ValueError):
    """A real-audit-v2 public document violated its frozen contract."""


_OPAQUE_ALLOCATION_AUTHORITY = object()
_VERIFICATION_RECEIPT_AUTHORITY = object()


@dataclass(frozen=True, slots=True, init=False)
class OpaqueIdAllocation:
    """Non-authoritative local opaque-ID allocation result.

    Its construction path requests bytes through :mod:`secrets`, but this
    Python object is not transferable proof of the OS entropy source, entropy
    quality, or freshness.  A governed evaluator must authenticate allocation
    provenance outside this process.
    """

    opaque_id: str
    kind: str
    authority_type: str
    entropy_bits: int
    nonce_commitment_sha256: str

    def __init__(
        self,
        *,
        opaque_id: str,
        kind: str,
        authority_type: str,
        entropy_bits: int,
        nonce_commitment_sha256: str,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _OPAQUE_ALLOCATION_AUTHORITY:
            raise RunBundleContractError(
                "opaque allocation requires the local allocation path"
            )
        object.__setattr__(self, "opaque_id", opaque_id)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "authority_type", authority_type)
        object.__setattr__(self, "entropy_bits", entropy_bits)
        object.__setattr__(
            self, "nonce_commitment_sha256", nonce_commitment_sha256
        )


@dataclass(frozen=True, slots=True, init=False)
class RunBundleVerificationReceipt:
    """Immutable, non-authoritative result from the physical v2 verifier.

    Python object identity and the private constructor token are not security
    boundaries.  Downstream trust decisions must re-run
    :func:`verify_runbundle_v2` over the exact sealed bytes and exact public
    lock; ``isinstance`` or possession of this object proves nothing.
    """

    bundle_profile: str
    run_id: str
    bundle_seal_sha256: str
    public_case_lock_sha256: str
    payload_digests: tuple[tuple[str, str], ...]
    object_digests: tuple[tuple[str, str], ...]
    verification_sha256: str
    verified_files: tuple[tuple[str, bytes], ...]

    def __init__(
        self,
        *,
        bundle_profile: str,
        run_id: str,
        bundle_seal_sha256: str,
        public_case_lock_sha256: str,
        payload_digests: tuple[tuple[str, str], ...],
        object_digests: tuple[tuple[str, str], ...],
        verification_sha256: str,
        verified_files: tuple[tuple[str, bytes], ...] = (),
        _authority: object | None = None,
    ) -> None:
        if _authority is not _VERIFICATION_RECEIPT_AUTHORITY:
            raise RunBundleContractError(
                "direct construction is unsupported; this local guard is not "
                "an authority boundary and downstream must revalidate sealed "
                "bytes with verify_runbundle_v2"
            )
        for field, value in (
            ("bundle_profile", bundle_profile),
            ("run_id", run_id),
            ("bundle_seal_sha256", bundle_seal_sha256),
            ("public_case_lock_sha256", public_case_lock_sha256),
            ("payload_digests", payload_digests),
            ("object_digests", object_digests),
            ("verification_sha256", verification_sha256),
            ("verified_files", verified_files),
        ):
            object.__setattr__(self, field, value)


def sha256_bytes(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise RunBundleContractError("SHA-256 input must be bytes")
    return hashlib.sha256(raw).hexdigest()


def _decode_canonical_urlsafe_b64(
    value: Any,
    *,
    context: str,
    maximum_text: int,
    expected_bytes: int | None = None,
) -> bytes:
    """Decode the one accepted unpadded URL-safe Base64 representation."""

    text = _text(value, context, maximum=maximum_text)
    assert isinstance(text, str)
    if (
        "=" in text
        or not re.fullmatch(r"[A-Za-z0-9_-]+", text)
        or len(text) % 4 == 1
    ):
        raise RunBundleContractError(f"{context} encoding is invalid")
    try:
        raw = base64.urlsafe_b64decode(text + ("=" * (-len(text) % 4)))
    except (ValueError, binascii.Error) as exc:
        raise RunBundleContractError(f"{context} encoding is invalid") from exc
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if not hmac.compare_digest(canonical, text):
        raise RunBundleContractError(
            f"canonical encoding is required for {context}"
        )
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise RunBundleContractError(f"{context} decoded length is invalid")
    return raw


class _JsonTraversalState:
    __slots__ = ("active_containers", "canonical_bytes", "nodes")

    def __init__(self) -> None:
        self.active_containers: set[int] = set()
        self.canonical_bytes = 0
        self.nodes = 0


def _charge_json_bytes(
    state: _JsonTraversalState,
    amount: int,
    *,
    context: str,
) -> None:
    state.canonical_bytes += amount
    if state.canonical_bytes > MAX_JSON_BYTES:
        raise RunBundleContractError(
            f"{context} exceeds the canonical JSON byte ceiling"
        )


def _canonical_string_size(value: str, *, context: str) -> int:
    if len(value) > MAX_JSON_BYTES:
        raise RunBundleContractError(f"{context} exceeds the JSON byte ceiling")
    try:
        utf8_size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise RunBundleContractError(f"{context} is not valid UTF-8") from exc
    escaped_extra = 0
    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}:
            escaped_extra += 1
        elif codepoint < 0x20:
            escaped_extra += 5
    return 2 + utf8_size + escaped_extra


def _copy_exact_json_value(
    value: Any,
    *,
    context: str = "$",
    _depth: int = 0,
    _state: _JsonTraversalState | None = None,
) -> Any:
    """Validate and copy one bounded JSON value using exact built-in types."""

    state = _JsonTraversalState() if _state is None else _state
    if _depth > MAX_JSON_DEPTH:
        raise RunBundleContractError(f"{context} exceeds the JSON depth ceiling")
    state.nodes += 1
    if state.nodes > MAX_JSON_NODES:
        raise RunBundleContractError(f"{context} exceeds the JSON node ceiling")

    if type(value) is dict:
        if len(value) > MAX_JSON_WIDTH:
            raise RunBundleContractError(
                f"{context} exceeds the JSON object width ceiling"
            )
        identity = id(value)
        if identity in state.active_containers:
            raise RunBundleContractError(f"{context} contains a JSON cycle")
        state.active_containers.add(identity)
        try:
            _charge_json_bytes(
                state,
                2 + max(len(value) - 1, 0),
                context=context,
            )
            seen: set[str] = set()
            result: dict[str, Any] = {}
            for key, child in value.items():
                if type(key) is not str:
                    raise RunBundleContractError(
                        f"{context} contains a non-exact built-in JSON object key"
                    )
                if unicodedata.normalize("NFC", key) != key:
                    raise RunBundleContractError(
                        f"{context} contains a non-normalized JSON key"
                    )
                folded = key.casefold()
                if folded in seen:
                    raise RunBundleContractError(
                        f"{context} contains a casefold JSON key collision"
                    )
                seen.add(folded)
                _charge_json_bytes(
                    state,
                    _canonical_string_size(key, context=context) + 1,
                    context=context,
                )
                result[key] = _copy_exact_json_value(
                    child,
                    context=f"{context}.{key}",
                    _depth=_depth + 1,
                    _state=state,
                )
            return result
        finally:
            state.active_containers.remove(identity)
    if isinstance(value, dict):
        raise RunBundleContractError(
            f"{context} must use an exact built-in JSON object"
        )
    if type(value) is list:
        if len(value) > MAX_JSON_WIDTH:
            raise RunBundleContractError(
                f"{context} exceeds the JSON array width ceiling"
            )
        identity = id(value)
        if identity in state.active_containers:
            raise RunBundleContractError(f"{context} contains a JSON cycle")
        state.active_containers.add(identity)
        try:
            _charge_json_bytes(
                state,
                2 + max(len(value) - 1, 0),
                context=context,
            )
            result_list: list[Any] = []
            for index, child in enumerate(value):
                result_list.append(
                    _copy_exact_json_value(
                        child,
                        context=f"{context}[{index}]",
                        _depth=_depth + 1,
                        _state=state,
                    )
                )
            return result_list
        finally:
            state.active_containers.remove(identity)
    if isinstance(value, list):
        raise RunBundleContractError(
            f"{context} must use an exact built-in JSON array"
        )
    if value is None:
        _charge_json_bytes(state, 4, context=context)
        return value
    if type(value) is bool:
        _charge_json_bytes(state, 4 if value else 5, context=context)
        return value
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise RunBundleContractError(
                f"{context} integer exceeds the signed 64-bit contract"
            )
        _charge_json_bytes(state, len(str(value)), context=context)
        return value
    if isinstance(value, int):
        raise RunBundleContractError(
            f"{context} must use an exact built-in JSON integer"
        )
    if type(value) is float:
        if not math.isfinite(value):
            raise RunBundleContractError(f"{context} contains a non-finite number")
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
        _charge_json_bytes(state, len(encoded), context=context)
        return value
    if isinstance(value, float):
        raise RunBundleContractError(
            f"{context} must use an exact built-in JSON number"
        )
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value:
            raise RunBundleContractError(
                f"{context} contains a non-normalized JSON string"
            )
        if "\x00" in value:
            raise RunBundleContractError(f"{context} contains NUL")
        _charge_json_bytes(
            state,
            _canonical_string_size(value, context=context),
            context=context,
        )
        return value
    if isinstance(value, str):
        raise RunBundleContractError(
            f"{context} must use exact built-in JSON text"
        )
    raise RunBundleContractError(
        f"{context} contains unsupported JSON type {type(value).__name__}"
    )


def _validate_json_value(value: Any, *, context: str = "$") -> None:
    _copy_exact_json_value(value, context=context)


def _exact_json_snapshot(value: Any, *, context: str = "$") -> Any:
    """Return an alias-free snapshot after exact recursive JSON validation."""

    return _copy_exact_json_value(value, context=context)


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic compact UTF-8 bytes without a terminal newline."""

    snapshot = _exact_json_snapshot(value)
    try:
        encoded = json.dumps(
            snapshot,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_JSON_BYTES:
            raise RunBundleContractError(
                "value exceeds the canonical JSON byte ceiling"
            )
        return encoded
    except RunBundleContractError:
        raise
    except RecursionError as exc:
        raise RunBundleContractError(
            "value exceeds the JSON depth ceiling"
        ) from exc
    except (TypeError, ValueError, OverflowError) as exc:
        raise RunBundleContractError("value is not canonicalizable JSON") from exc


def canonical_document_bytes(value: Any) -> bytes:
    """Return the one accepted on-disk JSON representation."""

    encoded = canonical_json_bytes(value) + b"\n"
    if len(encoded) > MAX_JSON_BYTES:
        raise RunBundleContractError(
            "document exceeds the canonical JSON byte ceiling"
        )
    return encoded


def document_sha256(value: Any) -> str:
    return sha256_bytes(canonical_document_bytes(value))


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    folded: set[str] = set()
    for key, value in pairs:
        if key in result:
            raise RunBundleContractError(f"duplicate JSON key {key!r}")
        case_key = unicodedata.normalize("NFC", key).casefold()
        if case_key in folded:
            raise RunBundleContractError(
                f"casefold-colliding JSON key {key!r}"
            )
        folded.add(case_key)
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    del token
    raise RunBundleContractError("JSON contains a non-finite constant")


def _bounded_int(token: str) -> int:
    if len(token.lstrip("-")) > 19:
        raise RunBundleContractError("JSON integer exceeds its token bound")
    try:
        value = int(token, 10)
    except ValueError as exc:
        raise RunBundleContractError("JSON integer is invalid") from exc
    if not -(2**63) <= value <= 2**63 - 1:
        raise RunBundleContractError("JSON integer exceeds signed 64-bit range")
    return value


def _bounded_float(token: str) -> float:
    if len(token) > 64:
        raise RunBundleContractError("JSON float exceeds its token bound")
    try:
        value = float(token)
    except ValueError as exc:
        raise RunBundleContractError("JSON float is invalid") from exc
    if not math.isfinite(value):
        raise RunBundleContractError("JSON contains a non-finite number")
    return value


def strict_json_loads(
    raw: str | bytes,
    *,
    require_canonical: bool = False,
    maximum_bytes: int = MAX_JSON_BYTES,
) -> Any:
    """Decode UTF-8 JSON while rejecting duplicate keys and extensions."""

    if type(maximum_bytes) is not int or maximum_bytes < 0:
        raise RunBundleContractError("JSON byte ceiling is invalid")
    if type(raw) is bytes:
        if len(raw) > maximum_bytes:
            raise RunBundleContractError("JSON exceeds its byte ceiling")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RunBundleContractError("JSON is not valid UTF-8") from exc
        source_bytes = raw
    elif type(raw) is str:
        if len(raw) > maximum_bytes:
            raise RunBundleContractError("JSON exceeds its byte ceiling")
        text = raw
        try:
            source_bytes = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise RunBundleContractError("JSON is not valid UTF-8") from exc
        if len(source_bytes) > maximum_bytes:
            raise RunBundleContractError("JSON exceeds its byte ceiling")
    else:
        raise RunBundleContractError(
            "JSON input must use exact built-in text or bytes"
        )
    if text.startswith("\ufeff"):
        raise RunBundleContractError("JSON UTF-8 BOM is not permitted")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_constant,
            parse_int=_bounded_int,
            parse_float=_bounded_float,
        )
    except RunBundleContractError:
        raise
    except RecursionError as exc:
        raise RunBundleContractError("JSON exceeds the depth ceiling") from exc
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RunBundleContractError("JSON syntax is invalid") from exc
    try:
        _validate_json_value(value)
    except RecursionError as exc:  # defensive if interpreter limits are lowered
        raise RunBundleContractError("JSON exceeds the depth ceiling") from exc
    if require_canonical and source_bytes != canonical_document_bytes(value):
        raise RunBundleContractError("JSON document bytes are not canonical")
    return value


def strict_json_load(
    path: Any,
    *,
    require_canonical: bool = False,
    maximum_bytes: int = MAX_JSON_BYTES,
) -> Any:
    raw = _privacy.read_stable_regular_bytes(
        path,
        maximum_bytes=maximum_bytes,
        label="RunBundle JSON document",
    )
    return strict_json_loads(
        raw,
        require_canonical=require_canonical,
        maximum_bytes=maximum_bytes,
    )


def canonical_jsonl_bytes(rows: Sequence[Any]) -> bytes:
    if type(rows) is not list:
        raise RunBundleContractError(
            "JSONL rows must use an exact built-in JSON array"
        )
    snapshot = _exact_json_snapshot(rows, context="JSONL rows")
    chunks: list[bytes] = []
    total = 0
    for row in snapshot:
        chunk = canonical_json_bytes(row) + b"\n"
        total += len(chunk)
        if total > MAX_JSON_BYTES:
            raise RunBundleContractError("JSONL exceeds its byte ceiling")
        chunks.append(chunk)
    return b"".join(chunks)


def strict_jsonl_loads(
    raw: str | bytes,
    *,
    require_canonical: bool = False,
    maximum_rows: int = 1_000_000,
    maximum_bytes: int = MAX_JSON_BYTES,
) -> list[Any]:
    """Decode duplicate-key rejecting UTF-8 JSONL with no blank rows."""

    if (
        not isinstance(maximum_rows, int)
        or isinstance(maximum_rows, bool)
        or maximum_rows < 0
    ):
        raise RunBundleContractError("JSONL row bound is invalid")
    if type(maximum_bytes) is not int or maximum_bytes < 0:
        raise RunBundleContractError("JSONL byte ceiling is invalid")
    if type(raw) is str:
        if len(raw) > maximum_bytes:
            raise RunBundleContractError("JSONL exceeds its byte ceiling")
        try:
            source = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise RunBundleContractError("JSONL is not valid UTF-8") from exc
        if len(source) > maximum_bytes:
            raise RunBundleContractError("JSONL exceeds its byte ceiling")
    elif type(raw) is bytes:
        if len(raw) > maximum_bytes:
            raise RunBundleContractError("JSONL exceeds its byte ceiling")
        source = raw
    else:
        raise RunBundleContractError(
            "JSONL input must use exact built-in text or bytes"
        )
    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RunBundleContractError("JSONL is not valid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise RunBundleContractError("JSONL UTF-8 BOM is not permitted")
    lines = text.splitlines()
    if len(lines) > maximum_rows:
        raise RunBundleContractError("JSONL exceeds its row-count bound")
    if len(lines) > MAX_JSON_WIDTH:
        raise RunBundleContractError("JSONL exceeds its row-width ceiling")
    if any(not line for line in lines):
        raise RunBundleContractError("JSONL contains a blank row")
    values = [
        strict_json_loads(line, maximum_bytes=maximum_bytes)
        for line in lines
    ]
    snapshot = _exact_json_snapshot(values, context="JSONL rows")
    if require_canonical and source != canonical_jsonl_bytes(snapshot):
        raise RunBundleContractError("JSONL document bytes are not canonical")
    return snapshot


def bind_embedded_sha256(
    value: Mapping[str, Any],
    field: str,
) -> dict[str, Any]:
    if type(value) is not dict or type(field) is not str or not field:
        raise RunBundleContractError("embedded digest input is invalid")
    result = _exact_json_snapshot(value, context="embedded digest document")
    result.pop(field, None)
    result[field] = document_sha256(result)
    return result


def verify_embedded_sha256(value: Mapping[str, Any], field: str) -> str:
    if type(value) is not dict or type(field) is not str or not field:
        raise RunBundleContractError("embedded digest document must be an object")
    snapshot = _exact_json_snapshot(value, context="embedded digest document")
    supplied = snapshot.get(field)
    _digest(supplied, field)
    unsigned = snapshot
    unsigned.pop(field, None)
    expected = document_sha256(unsigned)
    if supplied != expected:
        raise RunBundleContractError(f"{field} binding is invalid")
    return expected


def _closed(
    value: Any,
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    context: str,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise RunBundleContractError(
            f"{context} must use an exact built-in JSON object"
        )
    required_set = frozenset(required)
    optional_set = frozenset(optional)
    keys = set(value)
    missing = required_set - keys
    unknown = keys - required_set - optional_set
    if missing:
        raise RunBundleContractError(
            f"{context} is missing required fields: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise RunBundleContractError(
            f"{context} contains unknown fields: {', '.join(sorted(unknown))}"
        )
    return value


def _text(
    value: Any,
    context: str,
    *,
    nullable: bool = False,
    allow_empty: bool = False,
    maximum: int = 1_000_000,
) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise RunBundleContractError(f"{context} must be text")
    if (not value and not allow_empty) or len(value) > maximum:
        raise RunBundleContractError(f"{context} text length is invalid")
    return value


def _opaque_checksum(kind: str, body: str) -> str:
    digest = hashlib.sha256(
        b"plamen.real-audit.opaque-id.v2\0"
        + kind.encode("ascii")
        + b"\0"
        + body.encode("ascii")
    ).digest()
    return base64.b32encode(digest[:5]).decode("ascii").lower()


def _encode_opaque_id(kind: str, entropy: bytes) -> str:
    if kind not in _OPAQUE_KINDS:
        raise RunBundleContractError("opaque identifier kind is invalid")
    if not isinstance(entropy, bytes) or len(entropy) != 16:
        raise RunBundleContractError(
            "opaque identifier entropy must be exactly 128 bits"
        )
    body = base64.b32encode(entropy).decode("ascii").rstrip("=").lower()
    if len(body) != 26:  # defensive contract assertion
        raise RunBundleContractError("opaque identifier encoding failed")
    return f"{kind}-{body}-{_opaque_checksum(kind, body)}"


def opaque_id_from_entropy(kind: str, entropy: bytes) -> str:
    """Encode non-allocation identities from caller-supplied entropy.

    Case, cell, and nonce identities are allocation boundaries and therefore
    cannot accept public/caller-controlled bytes through this constructor.
    """

    if kind in _RANDOM_ALLOCATION_KINDS:
        raise RunBundleContractError(
            f"{kind} allocation requires the local allocation path"
        )
    return _encode_opaque_id(kind, entropy)


def allocate_opaque_id(kind: str) -> OpaqueIdAllocation:
    if kind not in _RANDOM_ALLOCATION_KINDS:
        raise RunBundleContractError(
            "typed allocation kind is invalid"
        )
    entropy = secrets.token_bytes(16)
    opaque_id = _encode_opaque_id(kind, entropy)
    commitment = sha256_bytes(
        b"plamen.real-audit.csp-random-allocation.v2\0"
        + kind.encode("ascii")
        + b"\0"
        + entropy
    )
    return OpaqueIdAllocation(
        opaque_id=opaque_id,
        kind=kind,
        authority_type="LOCAL_OS_RANDOM_ALLOCATION",
        entropy_bits=128,
        nonce_commitment_sha256=commitment,
        _authority=_OPAQUE_ALLOCATION_AUTHORITY,
    )


def generate_opaque_id(kind: str) -> str:
    if kind in _RANDOM_ALLOCATION_KINDS:
        raise RunBundleContractError(
            f"{kind} allocation requires allocate_opaque_id typed authority"
        )
    return _encode_opaque_id(kind, secrets.token_bytes(16))


def derive_opaque_id(kind: str, public_material: Any, *, domain: str) -> str:
    """Derive an opaque ID from explicitly public material and a public domain."""

    if kind in _RANDOM_ALLOCATION_KINDS:
        raise RunBundleContractError(
            f"{kind} allocation cannot use deterministic public derivation; "
            "the local allocation path is required"
        )
    domain_text = _text(domain, "opaque identifier domain", maximum=128)
    assert isinstance(domain_text, str)
    if any(char.isspace() for char in domain_text):
        raise RunBundleContractError("opaque identifier domain is invalid")
    try:
        _privacy.validate_public_payload(public_material)
    except _privacy.RunBundlePrivacyError as exc:
        raise RunBundleContractError(
            "opaque identifier derivation material is not public"
        ) from exc
    digest = hashlib.sha256(
        b"plamen.real-audit.opaque-derivation.v2\0"
        + domain_text.encode("utf-8")
        + b"\0"
        + canonical_document_bytes(public_material)
    ).digest()
    return _encode_opaque_id(kind, digest[:16])


def validate_opaque_id(value: Any, kind: str) -> str:
    if kind not in _OPAQUE_KINDS:
        raise RunBundleContractError("opaque identifier kind is invalid")
    text = _text(value, f"{kind} opaque identifier", maximum=64)
    assert isinstance(text, str)
    parts = text.split("-")
    if (
        len(parts) != 3
        or parts[0] != kind
        or not _OPAQUE_BODY_RE.fullmatch(parts[1])
        or not _OPAQUE_CHECKSUM_RE.fullmatch(parts[2])
    ):
        raise RunBundleContractError(
            f"{kind} value does not satisfy the opaque identifier format"
        )
    expected = _opaque_checksum(kind, parts[1])
    if not hmac.compare_digest(parts[2], expected):
        raise RunBundleContractError(f"{kind} opaque identifier checksum is invalid")
    return text


def _opaque_id(value: Any, context: str, kind: str) -> str:
    try:
        return validate_opaque_id(value, kind)
    except RunBundleContractError as exc:
        raise RunBundleContractError(
            f"{context} must be a valid {kind} opaque identifier: {exc}"
        ) from exc


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, maximum=256)
    assert isinstance(text, str)
    if any(char.isspace() for char in text) or "/" in text or "\\" in text:
        raise RunBundleContractError(f"{context} is not a safe identifier")
    return text


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        if isinstance(value, str) and _DIGEST_RE.fullmatch(value.casefold()):
            raise RunBundleContractError(
                f"{context} must be a lowercase SHA-256 digest"
            )
        raise RunBundleContractError(f"{context} must be a SHA-256 digest")
    return value


def _integer(
    value: Any,
    context: str,
    *,
    minimum: int = 0,
    maximum: int = 2**63 - 1,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise RunBundleContractError(f"{context} integer is invalid")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise RunBundleContractError(f"{context} must be boolean")
    return value


def _enum(value: Any, choices: Iterable[str], context: str) -> str:
    allowed = frozenset(choices)
    if not isinstance(value, str) or value not in allowed:
        raise RunBundleContractError(
            f"{context} must be one of {', '.join(sorted(allowed))}"
        )
    return value


def _list(value: Any, context: str) -> list[Any]:
    if type(value) is not list:
        raise RunBundleContractError(
            f"{context} must use an exact built-in JSON array"
        )
    return value


def _text_list(
    value: Any,
    context: str,
    *,
    unique: bool = False,
    allow_empty_text: bool = False,
) -> list[str]:
    rows = _list(value, context)
    result: list[str] = []
    for index, row in enumerate(rows):
        text = _text(
            row,
            f"{context}[{index}]",
            allow_empty=allow_empty_text,
        )
        assert isinstance(text, str)
        result.append(text)
    if unique and len(set(result)) != len(result):
        raise RunBundleContractError(f"{context} contains duplicate values")
    return result


def _id_list(value: Any, context: str) -> list[str]:
    rows = _list(value, context)
    result = [
        _identifier(row, f"{context}[{index}]")
        for index, row in enumerate(rows)
    ]
    if len(set(result)) != len(result):
        raise RunBundleContractError(f"{context} contains duplicate identifiers")
    if result != sorted(result, key=lambda item: item.encode("utf-8")):
        raise RunBundleContractError(
            f"{context} identifiers are not canonically sorted"
        )
    return result


def _validate_doc_start(value: Any, schema: str, context: str) -> dict[str, Any]:
    snapshot = _exact_json_snapshot(value, context=context)
    try:
        _privacy.validate_public_payload(snapshot)
    except _privacy.RunBundlePrivacyError as exc:
        raise RunBundleContractError(str(exc)) from exc
    if type(snapshot) is not dict:
        raise RunBundleContractError(f"{context} must be a JSON object")
    if snapshot.get("schema_version") != schema:
        raise RunBundleContractError(f"{context} schema_version is invalid")
    return snapshot


def _validate_public_document_row(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={"document_id", "title", "sha256", "relative_path"},
        context=context,
    )
    _identifier(row["document_id"], f"{context}.document_id")
    _text(row["title"], f"{context}.title")
    _digest(row["sha256"], f"{context}.sha256")
    try:
        _privacy.assert_safe_relative_path(
            row["relative_path"], label=f"{context}.relative_path"
        )
    except _privacy.RunBundlePrivacyError as exc:
        raise RunBundleContractError(str(exc)) from exc


def _validate_allocation_authority(
    value: Any,
    *,
    context: str,
) -> dict[str, str]:
    """Validate structural derivation from a public allocation reveal.

    This self-contained receipt proves only deterministic consistency with the
    supplied reveal.  It does not prove that the reveal was random, fresh, or
    generated by a CSPRNG.  Those are external public-lock governance
    premises.
    """

    row = _closed(
        value,
        required={
            "schema_version",
            "receipt_id",
            "authority_type",
            "algorithm",
            "reveal_bits",
            "allocation_reveal_b64",
            "reveal_commitment_sha256",
            "allocations",
            "receipt_sha256",
        },
        context=context,
    )
    _enum(
        row["schema_version"],
        {"plamen.structural-allocation-reveal.v1"},
        f"{context}.schema_version",
    )
    _identifier(row["receipt_id"], f"{context}.receipt_id")
    _enum(
        row["authority_type"],
        {"STRUCTURAL_ALLOCATION_REVEAL"},
        f"{context}.authority_type",
    )
    _enum(
        row["algorithm"],
        {"HMAC_SHA256_FROM_PUBLIC_REVEAL"},
        f"{context}.algorithm",
    )
    if (
        _integer(
            row["reveal_bits"],
            f"{context}.reveal_bits",
        )
        != 256
    ):
        raise RunBundleContractError(
            f"{context} must contain exactly 256 reveal bits"
        )
    commitment = _digest(
        row["reveal_commitment_sha256"],
        f"{context}.reveal_commitment_sha256",
    )
    reveal = _decode_canonical_urlsafe_b64(
        row["allocation_reveal_b64"],
        context=f"{context}.allocation_reveal_b64",
        maximum_text=64,
        expected_bytes=32,
    )
    expected_commitment = sha256_bytes(
        b"plamen.real-audit.csp-allocation-reveal.v2\0" + reveal
    )
    if not hmac.compare_digest(commitment, expected_commitment):
        raise RunBundleContractError(
            f"{context} allocation reveal commitment is invalid"
        )
    allocations = _list(row["allocations"], f"{context}.allocations")
    bound: dict[str, str] = {}
    indices: set[int] = set()
    for position, allocation in enumerate(allocations):
        allocation_row = _closed(
            allocation,
            required={"kind", "index", "opaque_id"},
            context=f"{context}.allocations[{position}]",
        )
        kind = _enum(
            allocation_row["kind"],
            _RANDOM_ALLOCATION_KINDS,
            f"{context}.allocations[{position}].kind",
        )
        index = _integer(
            allocation_row["index"],
            f"{context}.allocations[{position}].index",
        )
        if kind in bound or index in indices:
            raise RunBundleContractError(
                f"{context} allocation kind/index is duplicated"
            )
        indices.add(index)
        opaque_id = _opaque_id(
            allocation_row["opaque_id"],
            f"{context}.allocations[{position}].opaque_id",
            kind,
        )
        entropy = hmac.new(
            reveal,
            b"plamen.real-audit.csp-allocation.v2\0"
            + kind.encode("ascii")
            + b"\0"
            + str(index).encode("ascii"),
            hashlib.sha256,
        ).digest()[:16]
        if opaque_id != _encode_opaque_id(kind, entropy):
            raise RunBundleContractError(
                f"{context} allocation does not bind its public reveal"
            )
        bound[kind] = opaque_id
    if set(indices) != set(range(len(allocations))):
        raise RunBundleContractError(
            f"{context} allocation indices are not contiguous"
        )
    verify_embedded_sha256(row, "receipt_sha256")
    return bound


def _validate_audit_authority(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "key_id",
            "algorithm",
            "modulus_hex",
            "public_exponent",
        },
        context=context,
    )
    key_id = _digest(row["key_id"], f"{context}.key_id")
    _enum(
        row["algorithm"],
        {"RSA_PKCS1V15_SHA256"},
        f"{context}.algorithm",
    )
    modulus_hex = _text(
        row["modulus_hex"], f"{context}.modulus_hex", maximum=1024
    )
    assert isinstance(modulus_hex, str)
    if (
        not re.fullmatch(r"[0-9a-f]{512,}", modulus_hex)
        or len(modulus_hex) % 2
        or modulus_hex.startswith("0")
    ):
        raise RunBundleContractError(f"{context}.modulus_hex is invalid")
    modulus = bytes.fromhex(modulus_hex)
    modulus_integer = int.from_bytes(modulus, "big")
    if modulus_integer.bit_length() < 2048 or modulus_integer % 2 == 0:
        raise RunBundleContractError(f"{context}.modulus_hex is invalid")
    if sha256_bytes(modulus) != key_id:
        raise RunBundleContractError(f"{context}.key_id binding is invalid")
    if (
        _integer(
            row["public_exponent"],
            f"{context}.public_exponent",
            minimum=3,
        )
        != 65537
    ):
        raise RunBundleContractError(
            f"{context}.public_exponent is unsupported"
        )


def validate_public_case_lock(value: Any) -> dict[str, Any]:
    row = _validate_doc_start(value, PUBLIC_CASE_LOCK_SCHEMA, "public case lock")
    _closed(
        row,
        required={
            "schema_version",
            "case_id",
            "source_snapshot_sha256",
            "source_export_receipt_sha256",
            "language",
            "build_instructions",
            "test_instructions",
            "allowed_public_documentation",
            "capability_flags",
            "public_corpus_suite_id",
            "public_corpus_suite_version",
            "allocation_nonce",
            "allocation_authority",
            "audit_authority",
        },
        context="public case lock",
    )
    _opaque_id(row["case_id"], "public case lock.case_id", "case")
    _digest(
        row["source_snapshot_sha256"],
        "public case lock.source_snapshot_sha256",
    )
    _digest(
        row["source_export_receipt_sha256"],
        "public case lock.source_export_receipt_sha256",
    )
    _enum(
        row["language"],
        {"evm", "solana", "aptos", "sui", "soroban", "daml", "go", "rust"},
        "public case lock.language",
    )
    _text_list(row["build_instructions"], "public case lock.build_instructions")
    _text_list(row["test_instructions"], "public case lock.test_instructions")
    docs = _list(
        row["allowed_public_documentation"],
        "public case lock.allowed_public_documentation",
    )
    for index, document in enumerate(docs):
        _validate_public_document_row(
            document,
            f"public case lock.allowed_public_documentation[{index}]",
        )
    doc_ids = [str(document["document_id"]) for document in docs]
    if len(set(doc_ids)) != len(doc_ids):
        raise RunBundleContractError(
            "public case lock documentation IDs are duplicated"
        )
    capabilities = _closed(
        row["capability_flags"],
        required={
            "build_available",
            "tests_available",
            "network_required",
            "rag_allowed",
            "fuzz_allowed",
        },
        context="public case lock.capability_flags",
    )
    for key, enabled in capabilities.items():
        _boolean(enabled, f"public case lock.capability_flags.{key}")
    _identifier(
        row["public_corpus_suite_id"],
        "public case lock.public_corpus_suite_id",
    )
    _text(
        row["public_corpus_suite_version"],
        "public case lock.public_corpus_suite_version",
        maximum=64,
    )
    _opaque_id(
        row["allocation_nonce"], "public case lock.allocation_nonce", "nonce"
    )
    allocations = _validate_allocation_authority(
        row["allocation_authority"],
        context="public case lock.allocation_authority",
    )
    if (
        allocations.get("case") != row["case_id"]
        or allocations.get("nonce") != row["allocation_nonce"]
    ):
        raise RunBundleContractError(
            "public case lock allocation authority binding is invalid"
        )
    _validate_audit_authority(
        row["audit_authority"], "public case lock.audit_authority"
    )
    return row


def public_case_lock_sha256(value: Mapping[str, Any]) -> str:
    validated = validate_public_case_lock(value)
    return document_sha256(validated)


def load_public_case_lock(path: Any) -> dict[str, Any]:
    value = strict_json_load(
        path,
        require_canonical=True,
        maximum_bytes=8 << 20,
    )
    return validate_public_case_lock(value)


def public_case_lock_file_sha256(path: Any) -> str:
    raw = _privacy.read_stable_regular_bytes(
        path,
        maximum_bytes=8 << 20,
        label="public case lock",
    )
    value = strict_json_loads(raw, require_canonical=True)
    validate_public_case_lock(value)
    return sha256_bytes(raw)


def _validate_adapter(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "adapter_id",
            "adapter_version",
            "adapter_code_sha256",
            "output_contract",
        },
        context=context,
    )
    _identifier(row["adapter_id"], f"{context}.adapter_id")
    _text(row["adapter_version"], f"{context}.adapter_version", maximum=128)
    _digest(row["adapter_code_sha256"], f"{context}.adapter_code_sha256")
    _enum(
        row["output_contract"],
        {CANDIDATE_SET_SCHEMA},
        f"{context}.output_contract",
    )


def _validate_phase_map(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={"map_id", "map_version", "map_sha256", "pipeline_kind"},
        context=context,
    )
    map_id = _identifier(row["map_id"], f"{context}.map_id")
    map_version = _text(
        row["map_version"], f"{context}.map_version", maximum=64
    )
    map_sha256 = _digest(row["map_sha256"], f"{context}.map_sha256")
    pipeline_kind = _enum(
        row["pipeline_kind"],
        _phase_maps.PIPELINE_KINDS,
        f"{context}.pipeline_kind",
    )
    definition = _phase_maps.pinned_phase_map(pipeline_kind)
    preimage = _pinned_phase_map_preimage(pipeline_kind)
    if (
        map_id != definition.map_id
        or map_version != definition.map_version
        or map_sha256 != definition.map_sha256
        or map_sha256 != sha256_bytes(canonical_json_bytes(preimage))
    ):
        raise RunBundleContractError(
            f"{context} is not an evaluator-owned pinned phase map"
        )


def _pinned_phase_map_preimage(pipeline_kind: str) -> dict[str, Any]:
    try:
        return _phase_maps.phase_map_preimage(pipeline_kind)
    except _phase_maps.RunBundlePhaseMapError as exc:
        raise RunBundleContractError("unknown pinned pipeline kind") from exc


def _pinned_phase_order(phase_map: Mapping[str, Any]) -> dict[str, int]:
    definition = _phase_maps.pinned_phase_map(
        str(phase_map["pipeline_kind"])
    )
    return dict(definition.macro_order())


def _pinned_native_phase_order(
    phase_map: Mapping[str, Any],
) -> dict[str, int]:
    definition = _phase_maps.pinned_phase_map(
        str(phase_map["pipeline_kind"])
    )
    return dict(definition.native_order())


def _pinned_native_phase_macros(
    phase_map: Mapping[str, Any],
) -> dict[str, str]:
    definition = _phase_maps.pinned_phase_map(
        str(phase_map["pipeline_kind"])
    )
    return dict(definition.native_macros())


def _validate_model_backend(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "model_family",
            "model_revision",
            "provider_class",
            "backend_class",
            "context_window_tokens",
        },
        context=context,
    )
    for key in ("model_family", "model_revision", "provider_class", "backend_class"):
        _text(row[key], f"{context}.{key}", maximum=256)
    _integer(
        row["context_window_tokens"],
        f"{context}.context_window_tokens",
        minimum=1,
    )


def _validate_tool_policy(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "tool_set_sha256",
            "network_policy",
            "rag_policy",
            "mcp_policy",
        },
        context=context,
    )
    _digest(row["tool_set_sha256"], f"{context}.tool_set_sha256")
    for key in ("network_policy", "mcp_policy"):
        _text(row[key], f"{context}.{key}", maximum=128)
    _enum(
        row["rag_policy"],
        {"DISABLED", "PUBLIC_ONLY"},
        f"{context}.rag_policy",
    )


_RESOURCE_FIELDS = frozenset(
    {"token_count", "wall_time_ms", "tool_calls", "model_calls"}
)


def _validate_resources(value: Any, context: str) -> None:
    row = _closed(value, required=_RESOURCE_FIELDS, context=context)
    for key in _RESOURCE_FIELDS:
        _integer(row[key], f"{context}.{key}")


def _validate_budget(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "regime",
            "reserved_total",
            "reserved_channels",
            "measured_consumption",
            "measurement_receipt_refs",
            "measurement_summary_receipt_ref",
            "parity_group_id",
        },
        context=context,
    )
    _enum(
        row["regime"],
        {"MATCHED_TOTAL", "MATCHED_PER_CHANNEL"},
        f"{context}.regime",
    )
    _validate_resources(row["reserved_total"], f"{context}.reserved_total")
    channels = _closed(
        row["reserved_channels"],
        required={"discovery", "verification", "report"},
        optional={"rag", "fuzz"},
        context=f"{context}.reserved_channels",
    )
    for name, resources in channels.items():
        _validate_resources(resources, f"{context}.reserved_channels.{name}")
    _validate_resources(
        row["measured_consumption"],
        f"{context}.measured_consumption",
    )
    measurement_refs = _id_list(
        row["measurement_receipt_refs"],
        f"{context}.measurement_receipt_refs",
    )
    summary_ref = row["measurement_summary_receipt_ref"]
    if measurement_refs:
        _identifier(
            summary_ref,
            f"{context}.measurement_summary_receipt_ref",
        )
    elif summary_ref is not None:
        raise RunBundleContractError(
            f"{context}.measurement_summary_receipt_ref must be null when "
            "there are no authenticated measurement receipts"
        )
    _opaque_id(
        row["parity_group_id"], f"{context}.parity_group_id", "parity"
    )


def _validate_blinding(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "ground_truth_available_to_runner",
            "prior_report_available_to_runner",
            "private_case_lock_available_to_runner",
            "grader_labels_available_to_runner",
            "rag_exposure",
        },
        context=context,
    )
    for key in (
        "ground_truth_available_to_runner",
        "prior_report_available_to_runner",
        "private_case_lock_available_to_runner",
        "grader_labels_available_to_runner",
    ):
        if row[key] is not False:
            raise RunBundleContractError(f"{context}.{key} must be false")
    _enum(
        row["rag_exposure"],
        {"NONE", "PUBLIC_ONLY"},
        f"{context}.rag_exposure",
    )


def _validate_resume(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={"mode", "attempt", "parent_state_seal_sha256"},
        context=context,
    )
    mode = _enum(
        row["mode"],
        {"NEW", "SAME_RUN_RESUME", "RECOVERED_EXPORT"},
        f"{context}.mode",
    )
    attempt = _integer(row["attempt"], f"{context}.attempt", minimum=1)
    parent = row["parent_state_seal_sha256"]
    if mode == "NEW":
        if attempt != 1 or parent is not None:
            raise RunBundleContractError(
                f"{context} NEW mode requires attempt 1 and a null parent seal"
            )
    else:
        _digest(parent, f"{context}.parent_state_seal_sha256")
        if mode == "SAME_RUN_RESUME" and attempt < 2:
            raise RunBundleContractError(
                f"{context} SAME_RUN_RESUME requires attempt 2 or greater"
            )


def _validate_completion(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={"state", "checkpoint_state", "final_report_gate_state"},
        context=context,
    )
    _enum(
        row["state"],
        {"COMPLETE", "DEGRADED", "INCOMPLETE", "FAILED"},
        f"{context}.state",
    )
    _enum(
        row["checkpoint_state"],
        {"COMMITTED", "DEGRADED", "UNCOMMITTED", "FAILED", "UNKNOWN"},
        f"{context}.checkpoint_state",
    )
    _enum(
        row["final_report_gate_state"],
        {"PASSED", "DEGRADED", "FAILED", "NOT_REACHED", "UNKNOWN"},
        f"{context}.final_report_gate_state",
    )


def _validate_exporter(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "package",
            "version",
            "code_sha256",
            "schema_set_sha256",
            "invocation_policy_sha256",
        },
        context=context,
    )
    _identifier(row["package"], f"{context}.package")
    _text(row["version"], f"{context}.version", maximum=128)
    for key in ("code_sha256", "schema_set_sha256", "invocation_policy_sha256"):
        _digest(row[key], f"{context}.{key}")


def _budget_policy_preimage(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "regime": value["regime"],
        "reserved_total": copy.deepcopy(value["reserved_total"]),
        "reserved_channels": copy.deepcopy(value["reserved_channels"]),
        "measured_consumption": copy.deepcopy(value["measured_consumption"]),
        "measurement_receipt_refs": list(value["measurement_receipt_refs"]),
        "measurement_summary_receipt_ref": value[
            "measurement_summary_receipt_ref"
        ],
        "parity_group_id": value["parity_group_id"],
    }


def run_context_commitment_payload(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the exact evaluator-signed, arm-defining run context.

    The campaign schedule digest is committed here.  Verification of the
    external schedule bytes that produced that digest remains an evaluator
    responsibility and is intentionally not inferred by this bundle parser.
    """

    if type(manifest) is not dict:
        raise RunBundleContractError(
            "run context manifest must use an exact built-in JSON object"
        )
    manifest = _exact_json_snapshot(
        manifest,
        context="run context manifest",
    )
    try:
        context = {
            "trust_profile": manifest["trust_profile"],
            "run_id": manifest["run_id"],
            "case_id": manifest["case_id"],
            "experiment_id": manifest["experiment_id"],
            "cell_id": manifest["cell_id"],
            "repetition_index": manifest["repetition_index"],
            "seed": manifest["seed"],
            "audit_system": manifest["audit_system"],
            "source_snapshot_sha256": manifest["source_snapshot_sha256"],
            "adapter": copy.deepcopy(manifest["adapter"]),
            "phase_map": copy.deepcopy(manifest["phase_map"]),
            "model_backend": copy.deepcopy(manifest["model_backend"]),
            "tool_policy": copy.deepcopy(manifest["tool_policy"]),
            "budget_policy": _budget_policy_preimage(manifest["budget"]),
            "blinding": copy.deepcopy(manifest["blinding"]),
            "resume": copy.deepcopy(manifest["resume"]),
            "experiment_plan_sha256": manifest["experiment_plan_sha256"],
            "campaign_schedule_sha256": manifest[
                "campaign_schedule_sha256"
            ],
            "campaign_schedule_bytes_verification": (
                "REQUIRED_EVALUATOR_SIDE"
            ),
            "public_launch_receipt": manifest["public_launch_receipt"],
            "exporter": copy.deepcopy(manifest["exporter"]),
        }
    except (KeyError, TypeError) as exc:
        raise RunBundleContractError(
            "run context manifest is incomplete"
        ) from exc
    _validate_json_value(context, context="run context")
    return {"run_context": context}


def _measurement_receipt_decision_payload(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the exact structural claim each measurement receipt must sign.

    The signature authenticates this JSON and its resume lineage only.  It
    does not prove external metering truth, freshness, parent-state existence,
    or the trustworthiness of the configured signer.
    """

    return {
        "run_id": manifest["run_id"],
        "measurement_state": "MEASURED",
        "measured_consumption": copy.deepcopy(
            manifest["budget"]["measured_consumption"]
        ),
        "resume": copy.deepcopy(manifest["resume"]),
    }


def _measurement_summary_decision_payload(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the signed structural roster for run-level measurement claims."""

    return {
        "run_id": manifest["run_id"],
        "measurement_state": "MEASURED",
        "measurement_receipt_refs": list(
            manifest["budget"]["measurement_receipt_refs"]
        ),
        "measured_consumption": copy.deepcopy(
            manifest["budget"]["measured_consumption"]
        ),
        "resume": copy.deepcopy(manifest["resume"]),
    }


def _validate_run_context_authority_envelope(
    value: Any,
    context: str,
) -> None:
    row = _closed(
        value,
        required={
            "schema_version",
            "receipt_id",
            "authority_type",
            "subject_ids",
            "source_artifact_ids",
            "decision",
            "decision_payload",
            "payload_sha256",
            "signature_b64",
        },
        context=context,
    )
    _enum(
        row["schema_version"],
        {"plamen.public-authority-receipt.v1"},
        f"{context}.schema_version",
    )
    _identifier(row["receipt_id"], f"{context}.receipt_id")
    _enum(row["authority_type"], {"RUN_CONTEXT"}, f"{context}.authority_type")
    _id_list(row["subject_ids"], f"{context}.subject_ids")
    if _id_list(
        row["source_artifact_ids"], f"{context}.source_artifact_ids"
    ):
        raise RunBundleContractError(
            f"{context} RUN_CONTEXT must not claim runner-produced sources"
        )
    _enum(
        row["decision"],
        {"AUTHORIZED_RUN_CONTEXT"},
        f"{context}.decision",
    )
    payload = _closed(
        row["decision_payload"],
        required={"run_context"},
        context=f"{context}.decision_payload",
    )
    if not isinstance(payload["run_context"], dict):
        raise RunBundleContractError(
            f"{context}.decision_payload.run_context must be an object"
        )
    if _digest(
        row["payload_sha256"], f"{context}.payload_sha256"
    ) != sha256_bytes(canonical_json_bytes(row["decision_payload"])):
        raise RunBundleContractError(
            f"{context} RUN_CONTEXT payload digest binding is invalid"
        )
    _decode_canonical_urlsafe_b64(
        row["signature_b64"],
        context=f"{context}.signature_b64",
        maximum_text=2048,
    )


def validate_run_manifest(value: Any) -> dict[str, Any]:
    row = _validate_doc_start(value, RUN_MANIFEST_SCHEMA, "run manifest")
    _closed(
        row,
        required={
            "schema_version",
            "bundle_profile",
            "trust_profile",
            "run_id",
            "case_id",
            "experiment_id",
            "cell_id",
            "allocation_authority_ref",
            "repetition_index",
            "seed",
            "audit_system",
            "adapter",
            "public_case_lock_sha256",
            "experiment_plan_sha256",
            "campaign_schedule_sha256",
            "source_snapshot_sha256",
            "phase_map",
            "model_backend",
            "tool_policy",
            "budget",
            "blinding",
            "resume",
            "completion",
            "exporter",
            "public_launch_receipt",
            "run_context_authority",
        },
        context="run manifest",
    )
    _enum(row["bundle_profile"], {REAL_AUDIT_V2}, "run manifest.bundle_profile")
    trust_profile = _enum(
        row["trust_profile"], TRUST_PROFILES, "run manifest.trust_profile"
    )
    for field, kind in (
        ("run_id", "run"),
        ("case_id", "case"),
        ("experiment_id", "experiment"),
        ("cell_id", "cell"),
    ):
        _opaque_id(row[field], f"run manifest.{field}", kind)
    _identifier(
        row["allocation_authority_ref"],
        "run manifest.allocation_authority_ref",
    )
    _integer(row["repetition_index"], "run manifest.repetition_index")
    _integer(row["seed"], "run manifest.seed")
    _enum(row["audit_system"], {"PLAMEN", "EXTERNAL"}, "run manifest.audit_system")
    _validate_adapter(row["adapter"], "run manifest.adapter")
    for field in (
        "public_case_lock_sha256",
        "experiment_plan_sha256",
        "campaign_schedule_sha256",
        "source_snapshot_sha256",
    ):
        _digest(row[field], f"run manifest.{field}")
    _validate_phase_map(row["phase_map"], "run manifest.phase_map")
    _validate_model_backend(row["model_backend"], "run manifest.model_backend")
    _validate_tool_policy(row["tool_policy"], "run manifest.tool_policy")
    _validate_budget(row["budget"], "run manifest.budget")
    _validate_blinding(row["blinding"], "run manifest.blinding")
    _validate_resume(row["resume"], "run manifest.resume")
    _validate_completion(row["completion"], "run manifest.completion")
    _validate_exporter(row["exporter"], "run manifest.exporter")
    receipt = row["public_launch_receipt"]
    if receipt is not None:
        _digest(receipt, "run manifest.public_launch_receipt")
    run_context_authority = row["run_context_authority"]
    if trust_profile in B1_TRUST_PROFILES:
        _validate_run_context_authority_envelope(
            run_context_authority,
            "run manifest.run_context_authority",
        )
    elif run_context_authority is not None:
        raise RunBundleContractError(
            "USER_RUN/B0_LOCAL run context authority must be null; local "
            "integrity evidence cannot be relabeled authenticated"
        )
    return row


def validate_public_case_lock_binding(
    manifest: Mapping[str, Any],
    public_case_lock: Mapping[str, Any],
) -> str:
    valid_manifest = validate_run_manifest(manifest)
    valid_lock = validate_public_case_lock(public_case_lock)
    expected = public_case_lock_sha256(valid_lock)
    if valid_manifest["public_case_lock_sha256"] != expected:
        raise RunBundleContractError("public case lock binding is invalid")
    if valid_manifest["case_id"] != valid_lock["case_id"]:
        raise RunBundleContractError("public case lock case_id binding is invalid")
    if (
        valid_manifest["source_snapshot_sha256"]
        != valid_lock["source_snapshot_sha256"]
    ):
        raise RunBundleContractError(
            "public case lock source snapshot binding is invalid"
        )
    allocation_authority = valid_lock["allocation_authority"]
    if (
        valid_manifest["allocation_authority_ref"]
        != allocation_authority["receipt_id"]
    ):
        raise RunBundleContractError(
            "run manifest allocation authority reference is invalid"
        )
    allocations = _validate_allocation_authority(
        allocation_authority,
        context="public case lock.allocation_authority",
    )
    expected_allocations = {
        "case": valid_manifest["case_id"],
        "run": valid_manifest["run_id"],
        "experiment": valid_manifest["experiment_id"],
        "cell": valid_manifest["cell_id"],
        "parity": valid_manifest["budget"]["parity_group_id"],
        "nonce": valid_lock["allocation_nonce"],
    }
    if allocations != expected_allocations:
        raise RunBundleContractError(
            "run manifest identifiers do not bind the authenticated "
            "CSPRNG allocation receipt"
        )
    return expected


def derive_publication_ceiling(manifest: Mapping[str, Any]) -> str:
    """Return the strongest status public runner evidence may support.

    This is deliberately a ceiling, not a publication decision.  B1 status is
    evaluator-private and additionally requires isolation, corpus, reviewer,
    adjudication, parity, and publication-authority evidence.
    """

    row = validate_run_manifest(manifest)
    profile = row["trust_profile"]
    if profile == "USER_RUN":
        return "USER_RUN"
    if profile == "B0_LOCAL":
        return "B0_LOCAL"
    return "B1_INCOMPLETE"


def _validate_rfc3339(value: Any, context: str) -> None:
    text = _text(value, context, maximum=64)
    assert isinstance(text, str)
    if not _RFC3339_RE.fullmatch(text):
        raise RunBundleContractError(f"{context} must be RFC3339")
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RunBundleContractError(f"{context} must be RFC3339") from exc


def validate_phase_event(value: Any) -> dict[str, Any]:
    row = _validate_doc_start(value, PHASE_EVENT_SCHEMA, "phase event")
    _closed(
        row,
        required={
            "schema_version",
            "event_id",
            "run_id",
            "sequence",
            "attempt",
            "native_phase",
            "macro_phase",
            "work_unit_id",
            "event_type",
            "commit_state",
            "source_artifact_ids",
            "input_artifact_ids",
            "output_artifact_ids",
            "artifact_relations",
            "source_receipt_id",
            "observed_at",
            "evidence_quality",
        },
        context="phase event",
    )
    for field in ("event_id", "run_id", "work_unit_id", "source_receipt_id"):
        _identifier(row[field], f"phase event.{field}")
    _integer(row["sequence"], "phase event.sequence", minimum=1)
    _integer(row["attempt"], "phase event.attempt", minimum=1)
    _identifier(row["native_phase"], "phase event.native_phase")
    _enum(row["macro_phase"], _MACRO_PHASES, "phase event.macro_phase")
    _enum(
        row["event_type"],
        {
            "PLANNED",
            "STARTED",
            "INPUTS_BOUND",
            "OUTPUTS_WRITTEN",
            "OUTPUTS_COMMITTED",
            "DEGRADED",
            "FAILED",
            "INVALIDATED",
            "REEXECUTED",
            "RESUMED",
            "REPORT_FINALIZED",
        },
        "phase event.event_type",
    )
    _enum(
        row["commit_state"],
        {"CLEAN", "DEGRADED", "FAILED", "UNCOMMITTED", "UNKNOWN"},
        "phase event.commit_state",
    )
    for field in (
        "source_artifact_ids",
        "input_artifact_ids",
        "output_artifact_ids",
    ):
        _id_list(row[field], f"phase event.{field}")
    _validate_rfc3339(row["observed_at"], "phase event.observed_at")
    _enum(
        row["evidence_quality"],
        {"AUTHENTICATED", "TYPED", "PARSED", "UNAUTHENTICATED", "UNKNOWN"},
        "phase event.evidence_quality",
    )
    relations = _list(
        row["artifact_relations"], "phase event.artifact_relations"
    )
    by_relation: dict[str, list[str]] = {
        "SOURCE": [],
        "INPUT": [],
        "OUTPUT": [],
        "CONTROL": [],
    }
    relation_ids: list[str] = []
    for index, relation in enumerate(relations):
        relation_context = f"phase event.artifact_relations[{index}]"
        relation_row = _closed(
            relation,
            required={"artifact_id", "relation"},
            context=relation_context,
        )
        artifact_id = _identifier(
            relation_row["artifact_id"],
            f"{relation_context}.artifact_id",
        )
        relation_kind = _enum(
            relation_row["relation"],
            by_relation,
            f"{relation_context}.relation",
        )
        relation_ids.append(artifact_id)
        by_relation[relation_kind].append(artifact_id)
    if (
        len(relation_ids) != len(set(relation_ids))
        or relations
        != sorted(
            relations,
            key=lambda item: (
                str(item["artifact_id"]).encode("utf-8"),
                str(item["relation"]).encode("utf-8"),
            ),
        )
    ):
        raise RunBundleContractError(
            "phase event artifact relations are duplicated or not "
            "canonically ordered"
        )
    for relation_kind, field in (
        ("SOURCE", "source_artifact_ids"),
        ("INPUT", "input_artifact_ids"),
        ("OUTPUT", "output_artifact_ids"),
    ):
        if by_relation[relation_kind] != row[field]:
            raise RunBundleContractError(
                f"phase event {relation_kind} relation replay is not exact"
            )
    return row


def _validate_location(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "relative_path",
            "function",
            "line_start",
            "line_end",
            "location_state",
            "source_record_id",
        },
        context=context,
    )
    state = _enum(
        row["location_state"],
        {"EXACT", "APPROXIMATE", "UNRESOLVED"},
        f"{context}.location_state",
    )
    path = row["relative_path"]
    if path is None:
        if state != "UNRESOLVED":
            raise RunBundleContractError(
                f"{context}.relative_path may be null only when unresolved"
            )
    else:
        try:
            _privacy.assert_safe_relative_path(
                path, label=f"{context}.relative_path"
            )
        except _privacy.RunBundlePrivacyError as exc:
            raise RunBundleContractError(str(exc)) from exc
    _text(row["function"], f"{context}.function", nullable=True, maximum=512)
    start = row["line_start"]
    end = row["line_end"]
    if start is None or end is None:
        if state != "UNRESOLVED" or start is not None or end is not None:
            raise RunBundleContractError(
                f"{context} line range is inconsistent with location state"
            )
    else:
        start_value = _integer(start, f"{context}.line_start", minimum=1)
        end_value = _integer(end, f"{context}.line_end", minimum=start_value)
        if end_value < start_value:
            raise RunBundleContractError(f"{context} line range is inverted")
    _identifier(row["source_record_id"], f"{context}.source_record_id")


def _validate_candidate(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "candidate_id",
            "first_occurrence_id",
            "native_candidate_ids",
            "producer",
            "claim",
            "locations",
            "evidence_refs",
            "audit_severity",
            "quality",
            "audit_cluster_id",
        },
        context=context,
    )
    _identifier(row["candidate_id"], f"{context}.candidate_id")
    _identifier(row["first_occurrence_id"], f"{context}.first_occurrence_id")
    native_ids = _id_list(row["native_candidate_ids"], f"{context}.native_candidate_ids")
    if not native_ids:
        raise RunBundleContractError(f"{context}.native_candidate_ids is empty")
    producer = _closed(
        row["producer"],
        required={
            "adapter_id",
            "native_phase",
            "work_unit_id",
            "artifact_id",
            "record_id",
        },
        context=f"{context}.producer",
    )
    for key in producer:
        _identifier(producer[key], f"{context}.producer.{key}")
    claim = _closed(
        row["claim"],
        required={"title", "mechanism", "description", "impact", "preconditions"},
        context=f"{context}.claim",
    )
    claim_parts: list[str] = []
    for key in ("title", "mechanism", "description", "impact"):
        text = _text(
            claim[key],
            f"{context}.claim.{key}",
            nullable=True,
            maximum=1_000_000,
        )
        if text:
            claim_parts.append(text)
    preconditions = _text_list(
        claim["preconditions"], f"{context}.claim.preconditions"
    )
    claim_parts.extend(preconditions)
    if not claim_parts:
        raise RunBundleContractError(f"{context}.claim cannot be empty")
    locations = _list(row["locations"], f"{context}.locations")
    for index, location in enumerate(locations):
        _validate_location(location, f"{context}.locations[{index}]")
    _id_list(row["evidence_refs"], f"{context}.evidence_refs")
    severity = _closed(
        row["audit_severity"],
        required={"label", "authority_receipt_id"},
        context=f"{context}.audit_severity",
    )
    severity_label = _enum(
        severity["label"], _SEVERITIES, f"{context}.audit_severity.label"
    )
    authority = severity["authority_receipt_id"]
    if severity_label == "UNASSESSED":
        if authority is not None:
            raise RunBundleContractError(
                f"{context}.audit_severity unassessed authority must be null"
            )
    else:
        _identifier(authority, f"{context}.audit_severity.authority_receipt_id")
    quality = _closed(
        row["quality"],
        required={
            "parse_completeness",
            "location_quality",
            "evidence_quality",
            "debts",
        },
        context=f"{context}.quality",
    )
    _enum(
        quality["parse_completeness"],
        {"COMPLETE", "PARTIAL", "OPAQUE_RECORD"},
        f"{context}.quality.parse_completeness",
    )
    location_quality = _enum(
        quality["location_quality"],
        {"EXACT", "APPROXIMATE", "UNRESOLVED"},
        f"{context}.quality.location_quality",
    )
    _enum(
        quality["evidence_quality"],
        {"AUTHENTICATED", "TYPED", "PARSED", "UNAUTHENTICATED", "UNKNOWN"},
        f"{context}.quality.evidence_quality",
    )
    debts = _text_list(quality["debts"], f"{context}.quality.debts")
    if not locations and (location_quality != "UNRESOLVED" or not debts):
        raise RunBundleContractError(
            f"{context} empty locations require unresolved location debt"
        )
    if row["audit_cluster_id"] is not None:
        _opaque_id(
            row["audit_cluster_id"], f"{context}.audit_cluster_id", "cluster"
        )


def validate_candidate_set(value: Any) -> dict[str, Any]:
    row = _validate_doc_start(value, CANDIDATE_SET_SCHEMA, "candidate set")
    _closed(
        row,
        required={"schema_version", "run_id", "candidates"},
        context="candidate set",
    )
    _identifier(row["run_id"], "candidate set.run_id")
    candidates = _list(row["candidates"], "candidate set.candidates")
    ids: list[str] = []
    for index, candidate in enumerate(candidates):
        _validate_candidate(candidate, f"candidate set.candidates[{index}]")
        ids.append(candidate["candidate_id"])
    if len(ids) != len(set(ids)):
        raise RunBundleContractError("candidate set has duplicate candidate IDs")
    if ids != sorted(ids, key=lambda item: item.encode("utf-8")):
        raise RunBundleContractError("candidate set candidates are not sorted")
    return row


def _validate_occurrence(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "occurrence_id",
            "candidate_id",
            "native_phase",
            "macro_phase",
            "artifact_id",
            "record_id",
            "record_sha256",
            "byte_range",
            "role",
            "state",
            "asserted_severity",
            "location_snapshot",
            "evidence_refs",
            "authority_ref",
        },
        context=context,
    )
    for field in (
        "occurrence_id",
        "candidate_id",
        "native_phase",
        "artifact_id",
        "record_id",
        "authority_ref",
    ):
        _identifier(row[field], f"{context}.{field}")
    _enum(row["macro_phase"], _MACRO_PHASES, f"{context}.macro_phase")
    _digest(row["record_sha256"], f"{context}.record_sha256")
    byte_range = _closed(
        row["byte_range"],
        required={"start", "end"},
        context=f"{context}.byte_range",
    )
    start = _integer(byte_range["start"], f"{context}.byte_range.start")
    _integer(
        byte_range["end"],
        f"{context}.byte_range.end",
        minimum=start + 1,
    )
    _enum(
        row["role"],
        {
            "DISCOVERY",
            "RETAINED",
            "VERIFICATION_INPUT",
            "VERIFICATION_RESULT",
            "REPORT_INDEX",
            "REPORT_BODY",
            "FINAL_REPORT",
            "APPENDIX",
        },
        f"{context}.role",
    )
    _enum(
        row["state"],
        {"POSITIVE", "CONTESTED", "NEGATIVE", "DEFERRED", "UNKNOWN"},
        f"{context}.state",
    )
    _enum(row["asserted_severity"], _SEVERITIES, f"{context}.asserted_severity")
    locations = _list(row["location_snapshot"], f"{context}.location_snapshot")
    for index, location in enumerate(locations):
        _validate_location(location, f"{context}.location_snapshot[{index}]")
    _id_list(row["evidence_refs"], f"{context}.evidence_refs")


def _validate_lineage_edge(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "edge_id",
            "edge_type",
            "source_candidate_id",
            "target_candidate_id",
            "survivor_candidate_id",
            "authority_receipt_id",
            "effective",
        },
        context=context,
    )
    for field in ("edge_id", "source_candidate_id", "target_candidate_id"):
        _identifier(row[field], f"{context}.{field}")
    edge_type = _enum(
        row["edge_type"],
        {
            "SAME_CANDIDATE",
            "AUTHORIZED_ALIAS",
            "REOPENED_AS",
            "REFUTED_BY",
            "REPORTS_AS",
            "PROPOSED_ALIAS",
        },
        f"{context}.edge_type",
    )
    for field in ("survivor_candidate_id", "authority_receipt_id"):
        if row[field] is not None:
            _identifier(row[field], f"{context}.{field}")
    effective = _boolean(row["effective"], f"{context}.effective")
    if edge_type == "PROPOSED_ALIAS" and effective:
        raise RunBundleContractError(
            f"{context} proposed aliases can never be effective"
        )
    if edge_type == "AUTHORIZED_ALIAS" and (
        not effective
        or row["survivor_candidate_id"] is None
        or row["authority_receipt_id"] is None
    ):
        raise RunBundleContractError(
            f"{context} effective alias authority is incomplete"
        )


def _validate_alias_class(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={"alias_class_id", "survivor_candidate_id", "candidate_ids", "applied_edge_ids"},
        context=context,
    )
    _opaque_id(row["alias_class_id"], f"{context}.alias_class_id", "alias")
    survivor = _identifier(
        row["survivor_candidate_id"], f"{context}.survivor_candidate_id"
    )
    members = _id_list(row["candidate_ids"], f"{context}.candidate_ids")
    edges = _id_list(row["applied_edge_ids"], f"{context}.applied_edge_ids")
    if survivor not in members or not edges:
        raise RunBundleContractError(f"{context} alias class binding is invalid")


def _validate_negative_disposition(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "disposition_id",
            "kind",
            "candidate_id",
            "occurrence_id",
            "native_phase",
            "macro_phase",
            "authority_receipt_id",
            "premise",
            "evidence_refs",
            "terminal",
            "superseding_occurrence_id",
        },
        context=context,
    )
    for field in (
        "disposition_id",
        "candidate_id",
        "occurrence_id",
        "native_phase",
        "authority_receipt_id",
    ):
        _identifier(row[field], f"{context}.{field}")
    _enum(
        row["kind"],
        {
            "SAFE",
            "REFUTED",
            "OUT_OF_SCOPE",
            "ZERO_HARM",
            "NON_EXPLOITABLE",
            "DEFERRED",
            "CONTESTED",
            "OTHER",
        },
        f"{context}.kind",
    )
    _enum(row["macro_phase"], _MACRO_PHASES, f"{context}.macro_phase")
    _text(row["premise"], f"{context}.premise", maximum=1_000_000)
    _id_list(row["evidence_refs"], f"{context}.evidence_refs")
    _boolean(row["terminal"], f"{context}.terminal")
    if row["superseding_occurrence_id"] is not None:
        _identifier(
            row["superseding_occurrence_id"],
            f"{context}.superseding_occurrence_id",
        )


def _validate_lineage_debt(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "debt_id",
            "debt_code",
            "candidate_ids",
            "occurrence_ids",
            "authority_refs",
            "detail",
        },
        context=context,
    )
    _identifier(row["debt_id"], f"{context}.debt_id")
    _identifier(row["debt_code"], f"{context}.debt_code")
    for field in ("candidate_ids", "occurrence_ids", "authority_refs"):
        _id_list(row[field], f"{context}.{field}")
    _text(row["detail"], f"{context}.detail", maximum=1_000_000)


def validate_candidate_lineage(value: Any) -> dict[str, Any]:
    row = _validate_doc_start(
        value, CANDIDATE_LINEAGE_SCHEMA, "candidate lineage"
    )
    _closed(
        row,
        required={
            "schema_version",
            "run_id",
            "occurrences",
            "edges",
            "alias_classes",
            "negative_dispositions",
            "lineage_debts",
        },
        context="candidate lineage",
    )
    _identifier(row["run_id"], "candidate lineage.run_id")
    specifications: tuple[tuple[str, Callable[[Any, str], None], str], ...] = (
        ("occurrences", _validate_occurrence, "occurrence_id"),
        ("edges", _validate_lineage_edge, "edge_id"),
        ("alias_classes", _validate_alias_class, "alias_class_id"),
        ("negative_dispositions", _validate_negative_disposition, "disposition_id"),
        ("lineage_debts", _validate_lineage_debt, "debt_id"),
    )
    for field, validator, identity_field in specifications:
        values = _list(row[field], f"candidate lineage.{field}")
        identities: list[str] = []
        for index, item in enumerate(values):
            validator(item, f"candidate lineage.{field}[{index}]")
            identities.append(item[identity_field])
        if len(set(identities)) != len(identities):
            raise RunBundleContractError(
                f"candidate lineage.{field} contains duplicate IDs"
            )
        if identities != sorted(
            identities, key=lambda item: item.encode("utf-8")
        ):
            raise RunBundleContractError(
                f"candidate lineage.{field} is not canonically sorted"
            )
    return row


def _validate_redaction(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={"redaction_type", "field_path"},
        context=context,
    )
    _identifier(row["redaction_type"], f"{context}.redaction_type")
    field_path = _text(row["field_path"], f"{context}.field_path", maximum=1024)
    assert isinstance(field_path, str)
    if field_path.startswith(("/", "\\")) or ":" in field_path:
        raise RunBundleContractError(
            f"{context}.field_path must not expose an absolute path"
        )


def _validate_raw_artifact(value: Any, context: str) -> None:
    common = {
        "artifact_id",
        "relative_source_path",
        "native_phase",
        "macro_phase",
        "work_unit_id",
        "producer_kind",
        "media_type",
        "byte_length",
        "sha256",
        "storage",
        "record_ids",
        "source_contract_ref",
        "commit_state",
        "redactions",
    }
    row = _closed(
        value,
        required=common,
        optional={"content", "object_path"},
        context=context,
    )
    for field in ("artifact_id", "native_phase", "work_unit_id"):
        _identifier(row[field], f"{context}.{field}")
    try:
        _privacy.assert_safe_relative_path(
            row["relative_source_path"],
            label=f"{context}.relative_source_path",
        )
    except _privacy.RunBundlePrivacyError as exc:
        raise RunBundleContractError(str(exc)) from exc
    _enum(row["macro_phase"], _MACRO_PHASES, f"{context}.macro_phase")
    _identifier(row["producer_kind"], f"{context}.producer_kind")
    _text(row["media_type"], f"{context}.media_type", maximum=256)
    byte_length = _integer(row["byte_length"], f"{context}.byte_length")
    digest = _digest(row["sha256"], f"{context}.sha256")
    storage = _enum(
        row["storage"], {"INLINE_UTF8", "OBJECT"}, f"{context}.storage"
    )
    if storage == "INLINE_UTF8":
        if set(row) & {"object_path"} or "content" not in row:
            raise RunBundleContractError(
                f"{context} INLINE_UTF8 storage union is invalid"
            )
        content = _text(
            row["content"],
            f"{context}.content",
            allow_empty=True,
            maximum=64 << 20,
        )
        assert isinstance(content, str)
        raw = content.encode("utf-8")
        if len(raw) != byte_length or sha256_bytes(raw) != digest:
            raise RunBundleContractError(
                f"{context} inline storage digest/length binding is invalid"
            )
    else:
        if set(row) & {"content"} or "object_path" not in row:
            raise RunBundleContractError(
                f"{context} OBJECT storage union is invalid"
            )
        expected = f"objects/sha256/{digest}"
        try:
            object_path = _privacy.assert_safe_relative_path(
                row["object_path"], label=f"{context}.object_path"
            )
        except _privacy.RunBundlePrivacyError as exc:
            raise RunBundleContractError(str(exc)) from exc
        if object_path != expected:
            raise RunBundleContractError(
                f"{context} object path does not bind the content digest"
            )
    _id_list(row["record_ids"], f"{context}.record_ids")
    _text(row["source_contract_ref"], f"{context}.source_contract_ref", maximum=256)
    _enum(
        row["commit_state"],
        {"CLEAN", "DEGRADED", "FAILED", "UNCOMMITTED", "UNKNOWN"},
        f"{context}.commit_state",
    )
    redactions = _list(row["redactions"], f"{context}.redactions")
    for index, redaction in enumerate(redactions):
        _validate_redaction(redaction, f"{context}.redactions[{index}]")


def _validate_authority_receipt_binding(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "receipt_id",
            "artifact_id",
            "byte_range",
            "record_sha256",
        },
        context=context,
    )
    _identifier(row["receipt_id"], f"{context}.receipt_id")
    _identifier(row["artifact_id"], f"{context}.artifact_id")
    byte_range = _closed(
        row["byte_range"],
        required={"start", "end"},
        context=f"{context}.byte_range",
    )
    start = _integer(byte_range["start"], f"{context}.byte_range.start")
    _integer(
        byte_range["end"],
        f"{context}.byte_range.end",
        minimum=start + 1,
    )
    _digest(row["record_sha256"], f"{context}.record_sha256")


def _raw_artifact_bytes(
    artifact: Mapping[str, Any],
    object_bytes: Mapping[str, bytes] | None,
    *,
    context: str,
) -> bytes:
    if artifact["storage"] == "INLINE_UTF8":
        return artifact["content"].encode("utf-8")
    if object_bytes is None:
        raise RunBundleContractError(
            f"{context} requires exact physical object bytes"
        )
    try:
        return object_bytes[artifact["object_path"]]
    except KeyError as exc:
        raise RunBundleContractError(
            f"{context} object byte binding is missing"
        ) from exc


def _validate_physical_payload_row(
    value: Any,
    context: str,
    *,
    debt: bool = False,
    occurrence: bool = False,
) -> None:
    required = {
        "record_id",
        "artifact_id",
        "byte_range",
        "record_sha256",
        "producer_kind",
        "source_contract_ref",
    }
    if debt:
        required.add("debt_id")
    if occurrence:
        required.add("occurrence_ids")
    row = _closed(value, required=required, context=context)
    for field in ("record_id", "artifact_id"):
        _identifier(row[field], f"{context}.{field}")
    if debt:
        _identifier(row["debt_id"], f"{context}.debt_id")
    if occurrence:
        occurrence_ids = _id_list(
            row["occurrence_ids"], f"{context}.occurrence_ids"
        )
        if not occurrence_ids:
            raise RunBundleContractError(
                f"{context}.occurrence_ids must not be empty"
            )
    _digest(row["record_sha256"], f"{context}.record_sha256")
    _identifier(row["producer_kind"], f"{context}.producer_kind")
    _text(
        row["source_contract_ref"],
        f"{context}.source_contract_ref",
        maximum=256,
    )
    byte_range = _closed(
        row["byte_range"],
        required={"start", "end"},
        context=f"{context}.byte_range",
    )
    start = _integer(byte_range["start"], f"{context}.byte_range.start")
    _integer(
        byte_range["end"],
        f"{context}.byte_range.end",
        minimum=start + 1,
    )


_AUTHORITY_PAYLOAD_FIELDS = {
    "CANDIDATE_EMISSION": frozenset({"occurrences"}),
    "LINEAGE_DEBT": frozenset({"debts"}),
    "NEGATIVE_DISPOSITION": frozenset({"dispositions"}),
    "NONFINDING_CLASSIFICATION": frozenset(
        {"classification", "record_ids"}
    ),
    "REPORT_DISPOSITION": frozenset({"rows"}),
    "REPORT_QUALITY": frozenset(
        {
            "final_report_artifact_id",
            "report_integrity_state",
            "final_report_artifact",
            "report_entries",
            "unmapped_entries",
            "physical_occurrences",
        }
    ),
    "SEVERITY_DECISION": frozenset({"rows"}),
}

_AUTHORITY_PAYLOAD_ROW_FIELDS = {
    "CANDIDATE_EMISSION": ("occurrences",),
    "LINEAGE_DEBT": ("debts",),
    "NEGATIVE_DISPOSITION": ("dispositions",),
    "NONFINDING_CLASSIFICATION": ("record_ids",),
    "REPORT_DISPOSITION": ("rows",),
    "REPORT_QUALITY": (
        "report_entries",
        "unmapped_entries",
        "physical_occurrences",
    ),
    "SEVERITY_DECISION": ("rows",),
}


def _validate_unique_authority_payload_rows(
    authority_type: str,
    payload: Mapping[str, Any],
    *,
    context: str,
) -> None:
    required = _AUTHORITY_PAYLOAD_FIELDS.get(authority_type)
    if required is None:
        return
    row = _closed(payload, required=required, context=context)
    for field in _AUTHORITY_PAYLOAD_ROW_FIELDS[authority_type]:
        values = _list(row[field], f"{context}.{field}")
        if authority_type == "NONFINDING_CLASSIFICATION":
            _enum(
                row["classification"],
                {"PARTITIONED_NONFINDING"},
                f"{context}.classification",
            )
            _id_list(values, f"{context}.{field}")
            continue
        for index, value in enumerate(values):
            item_context = f"{context}.{field}[{index}]"
            if authority_type == "CANDIDATE_EMISSION":
                item = _closed(
                    value,
                    required={
                        "candidate_id",
                        "occurrence_id",
                        "state",
                        "artifact_id",
                        "record_id",
                        "byte_range",
                        "record_sha256",
                        "producer_kind",
                        "source_contract_ref",
                    },
                    context=item_context,
                )
                for name in (
                    "candidate_id",
                    "occurrence_id",
                    "artifact_id",
                    "record_id",
                    "producer_kind",
                ):
                    _identifier(item[name], f"{item_context}.{name}")
                _enum(item["state"], {"POSITIVE"}, f"{item_context}.state")
                _digest(
                    item["record_sha256"],
                    f"{item_context}.record_sha256",
                )
                _text(
                    item["source_contract_ref"],
                    f"{item_context}.source_contract_ref",
                    maximum=256,
                )
                byte_range = _closed(
                    item["byte_range"],
                    required={"start", "end"},
                    context=f"{item_context}.byte_range",
                )
                start = _integer(
                    byte_range["start"],
                    f"{item_context}.byte_range.start",
                )
                _integer(
                    byte_range["end"],
                    f"{item_context}.byte_range.end",
                    minimum=start + 1,
                )
            elif authority_type == "NEGATIVE_DISPOSITION":
                item = _closed(
                    value,
                    required={
                        "disposition_id",
                        "kind",
                        "candidate_id",
                        "occurrence_id",
                        "native_phase",
                        "macro_phase",
                        "terminal",
                        "superseding_occurrence_id",
                        "ordering_basis",
                    },
                    context=item_context,
                )
                for name in (
                    "disposition_id",
                    "candidate_id",
                    "occurrence_id",
                    "native_phase",
                ):
                    _identifier(item[name], f"{item_context}.{name}")
                _enum(
                    item["kind"],
                    {
                        "SAFE",
                        "REFUTED",
                        "OUT_OF_SCOPE",
                        "ZERO_HARM",
                        "NON_EXPLOITABLE",
                        "DEFERRED",
                        "CONTESTED",
                        "OTHER",
                    },
                    f"{item_context}.kind",
                )
                _enum(
                    item["macro_phase"],
                    _MACRO_PHASES,
                    f"{item_context}.macro_phase",
                )
                _boolean(item["terminal"], f"{item_context}.terminal")
                if item["superseding_occurrence_id"] is not None:
                    _identifier(
                        item["superseding_occurrence_id"],
                        f"{item_context}.superseding_occurrence_id",
                    )
                _enum(
                    item["ordering_basis"],
                    {"PINNED_NATIVE_PHASE_MAP"},
                    f"{item_context}.ordering_basis",
                )
            elif authority_type == "LINEAGE_DEBT":
                item = _closed(
                    value,
                    required={
                        "debt_id",
                        "debt_code",
                        "candidate_ids",
                        "occurrence_ids",
                    },
                    context=item_context,
                )
                _identifier(item["debt_id"], f"{item_context}.debt_id")
                _identifier(item["debt_code"], f"{item_context}.debt_code")
                for name in ("candidate_ids", "occurrence_ids"):
                    _id_list(item[name], f"{item_context}.{name}")
            elif authority_type == "REPORT_DISPOSITION":
                item = _closed(
                    value,
                    required={"candidate_id", "report_status"},
                    context=item_context,
                )
                _identifier(
                    item["candidate_id"],
                    f"{item_context}.candidate_id",
                )
                _enum(
                    item["report_status"],
                    {
                        "REPORTED",
                        "APPENDIX",
                        "OMITTED_WITH_AUTHORITY",
                        "DEBT",
                    },
                    f"{item_context}.report_status",
                )
            elif authority_type == "SEVERITY_DECISION":
                item = _closed(
                    value,
                    required={"candidate_id", "severity"},
                    context=item_context,
                )
                _identifier(
                    item["candidate_id"],
                    f"{item_context}.candidate_id",
                )
                _enum(
                    item["severity"],
                    _SEVERITIES,
                    f"{item_context}.severity",
                )
            elif authority_type == "REPORT_QUALITY":
                if field == "physical_occurrences":
                    _validate_physical_payload_row(value, item_context)
                else:
                    item = _closed(
                        value,
                        required={
                            "entry_id",
                            "byte_range",
                            "byte_range_sha256",
                            "candidate_ids",
                            "projection_kind",
                        },
                        context=item_context,
                    )
                    _identifier(
                        item["entry_id"],
                        f"{item_context}.entry_id",
                    )
                    byte_range = _closed(
                        item["byte_range"],
                        required={"start", "end"},
                        context=f"{item_context}.byte_range",
                    )
                    start = _integer(
                        byte_range["start"],
                        f"{item_context}.byte_range.start",
                    )
                    _integer(
                        byte_range["end"],
                        f"{item_context}.byte_range.end",
                        minimum=start + 1,
                    )
                    _digest(
                        item["byte_range_sha256"],
                        f"{item_context}.byte_range_sha256",
                    )
                    _id_list(
                        item["candidate_ids"],
                        f"{item_context}.candidate_ids",
                    )
                    _enum(
                        item["projection_kind"],
                        {"REPORT", "APPENDIX", "UNMAPPED"},
                        f"{item_context}.projection_kind",
                    )
        fingerprints = [canonical_json_bytes(value) for value in values]
        if len(fingerprints) != len(set(fingerprints)):
            raise RunBundleContractError(
                f"{context}.{field} contains duplicate signed payload rows"
            )
    if authority_type == "REPORT_QUALITY":
        _identifier(
            row["final_report_artifact_id"],
            f"{context}.final_report_artifact_id",
        )
        _enum(
            row["report_integrity_state"],
            {"SHIP", "NO_SHIP", "DEGRADED", "UNKNOWN"},
            f"{context}.report_integrity_state",
        )
        artifact = _closed(
            row["final_report_artifact"],
            required={
                "artifact_id",
                "byte_length",
                "sha256",
                "producer_kind",
                "source_contract_ref",
                "record_ids",
                "parser_completeness",
            },
            context=f"{context}.final_report_artifact",
        )
        _identifier(
            artifact["artifact_id"],
            f"{context}.final_report_artifact.artifact_id",
        )
        _integer(
            artifact["byte_length"],
            f"{context}.final_report_artifact.byte_length",
        )
        _digest(
            artifact["sha256"],
            f"{context}.final_report_artifact.sha256",
        )
        _identifier(
            artifact["producer_kind"],
            f"{context}.final_report_artifact.producer_kind",
        )
        _text(
            artifact["source_contract_ref"],
            f"{context}.final_report_artifact.source_contract_ref",
            maximum=256,
        )
        _id_list(
            artifact["record_ids"],
            f"{context}.final_report_artifact.record_ids",
        )
        _enum(
            artifact["parser_completeness"],
            {"COMPLETE_RECORD_ENUMERATION"},
            f"{context}.final_report_artifact.parser_completeness",
        )


def _validate_authority_payload_shape(
    authority_type: str,
    payload: Mapping[str, Any],
    *,
    context: str,
) -> None:
    _validate_unique_authority_payload_rows(
        authority_type,
        payload,
        context=context,
    )
    if authority_type == "RESOURCE_MEASUREMENT":
        row = _closed(
            payload,
            required={
                "run_id",
                "measurement_state",
                "measured_consumption",
                "resume",
            },
            context=context,
        )
        _identifier(row["run_id"], f"{context}.run_id")
        _enum(
            row["measurement_state"],
            {"MEASURED"},
            f"{context}.measurement_state",
        )
        _validate_resources(
            row["measured_consumption"],
            f"{context}.measured_consumption",
        )
        _validate_resume(row["resume"], f"{context}.resume")
    elif authority_type == "RESOURCE_MEASUREMENT_SUMMARY":
        row = _closed(
            payload,
            required={
                "run_id",
                "measurement_state",
                "measurement_receipt_refs",
                "measured_consumption",
                "resume",
            },
            context=context,
        )
        _identifier(row["run_id"], f"{context}.run_id")
        _enum(
            row["measurement_state"],
            {"MEASURED"},
            f"{context}.measurement_state",
        )
        refs = _id_list(
            row["measurement_receipt_refs"],
            f"{context}.measurement_receipt_refs",
        )
        if not refs:
            raise RunBundleContractError(
                f"{context}.measurement_receipt_refs must not be empty"
            )
        _validate_resources(
            row["measured_consumption"],
            f"{context}.measured_consumption",
        )
        _validate_resume(row["resume"], f"{context}.resume")
    elif authority_type == "RUN_CONTEXT":
        row = _closed(payload, required={"run_context"}, context=context)
        if not isinstance(row["run_context"], dict):
            raise RunBundleContractError(
                f"{context}.run_context must be a JSON object"
            )
    elif authority_type == "ALIAS_DECISION":
        row = _closed(payload, required={"edges"}, context=context)
        edges = _list(row["edges"], f"{context}.edges")
        edge_ids: list[str] = []
        for index, edge in enumerate(edges):
            edge_context = f"{context}.edges[{index}]"
            edge_row = _closed(
                edge,
                required={
                    "edge_id",
                    "edge_type",
                    "source_candidate_id",
                    "target_candidate_id",
                    "survivor_candidate_id",
                    "direction",
                    "effective",
                    "applied",
                },
                context=edge_context,
            )
            edge_ids.append(
                _identifier(edge_row["edge_id"], f"{edge_context}.edge_id")
            )
            _enum(
                edge_row["edge_type"],
                {
                    "SAME_CANDIDATE",
                    "AUTHORIZED_ALIAS",
                    "REOPENED_AS",
                    "REFUTED_BY",
                    "REPORTS_AS",
                    "PROPOSED_ALIAS",
                },
                f"{edge_context}.edge_type",
            )
            for field in ("source_candidate_id", "target_candidate_id"):
                _identifier(edge_row[field], f"{edge_context}.{field}")
            if edge_row["survivor_candidate_id"] is not None:
                _identifier(
                    edge_row["survivor_candidate_id"],
                    f"{edge_context}.survivor_candidate_id",
                )
            _enum(
                edge_row["direction"],
                {"SOURCE_TO_TARGET"},
                f"{edge_context}.direction",
            )
            _boolean(edge_row["effective"], f"{edge_context}.effective")
            _boolean(edge_row["applied"], f"{edge_context}.applied")
        if (
            len(edge_ids) != len(set(edge_ids))
            or edge_ids
            != sorted(edge_ids, key=lambda item: item.encode("utf-8"))
        ):
            raise RunBundleContractError(
                f"{context}.edges are duplicated or not canonically ordered"
            )
    elif authority_type == "PHASE_OUTPUT":
        row = _closed(
            payload,
            required={
                "event",
                "source_artifacts",
                "input_artifacts",
                "output_artifacts",
                "control_artifacts",
            },
            context=context,
        )
        event = _closed(
            row["event"],
            required=PUBLIC_FIELDS_BY_SCHEMA[PHASE_EVENT_SCHEMA]
            - {"source_receipt_id"},
            context=f"{context}.event",
        )
        for field in (
            "source_artifact_ids",
            "input_artifact_ids",
            "output_artifact_ids",
        ):
            _id_list(event[field], f"{context}.event.{field}")
        relation_rows = _list(
            event["artifact_relations"],
            f"{context}.event.artifact_relations",
        )
        control_ids = [
            relation["artifact_id"]
            for relation in relation_rows
            if relation.get("relation") == "CONTROL"
        ]
        for payload_field, event_field in (
            ("source_artifacts", "source_artifact_ids"),
            ("input_artifacts", "input_artifact_ids"),
            ("output_artifacts", "output_artifact_ids"),
            ("control_artifacts", None),
        ):
            replay_rows = _list(
                row[payload_field], f"{context}.{payload_field}"
            )
            replay_ids: list[str] = []
            for index, source in enumerate(replay_rows):
                source_context = f"{context}.{payload_field}[{index}]"
                source_row = _closed(
                    source,
                    required={
                        "artifact_id",
                        "native_phase",
                        "macro_phase",
                        "work_unit_id",
                        "commit_state",
                        "source_contract_ref",
                    },
                    context=source_context,
                )
                replay_ids.append(
                    _identifier(
                        source_row["artifact_id"],
                        f"{source_context}.artifact_id",
                    )
                )
            expected_ids = (
                control_ids if event_field is None else event[event_field]
            )
            if replay_ids != expected_ids:
                raise RunBundleContractError(
                    f"{context} {payload_field} replay is not exact"
                )
    elif authority_type == "RECORD_PARTITION":
        row = _closed(
            payload,
            required={
                "run_id",
                "artifacts",
                "occurrence_rows",
                "nonfinding_rows",
                "debt_rows",
            },
            context=context,
        )
        _identifier(row["run_id"], f"{context}.run_id")
        artifact_rows = _list(row["artifacts"], f"{context}.artifacts")
        artifact_ids: list[str] = []
        for index, item in enumerate(artifact_rows):
            item_context = f"{context}.artifacts[{index}]"
            artifact = _closed(
                item,
                required={
                    "artifact_id",
                    "byte_length",
                    "sha256",
                    "producer_kind",
                    "source_contract_ref",
                    "record_ids",
                    "parser_completeness",
                },
                context=item_context,
            )
            artifact_ids.append(
                _identifier(
                    artifact["artifact_id"], f"{item_context}.artifact_id"
                )
            )
            _integer(
                artifact["byte_length"], f"{item_context}.byte_length"
            )
            _digest(artifact["sha256"], f"{item_context}.sha256")
            _identifier(
                artifact["producer_kind"], f"{item_context}.producer_kind"
            )
            _text(
                artifact["source_contract_ref"],
                f"{item_context}.source_contract_ref",
                maximum=256,
            )
            _id_list(artifact["record_ids"], f"{item_context}.record_ids")
            _enum(
                artifact["parser_completeness"],
                {"COMPLETE_RECORD_ENUMERATION"},
                f"{item_context}.parser_completeness",
            )
        if (
            len(artifact_ids) != len(set(artifact_ids))
            or artifact_ids
            != sorted(artifact_ids, key=lambda item: item.encode("utf-8"))
        ):
            raise RunBundleContractError(
                f"{context}.artifacts are duplicated or not canonically ordered"
            )
        for field, debt, occurrence in (
            ("occurrence_rows", False, True),
            ("nonfinding_rows", False, False),
            ("debt_rows", True, False),
        ):
            rows = _list(row[field], f"{context}.{field}")
            record_ids: list[str] = []
            for index, item in enumerate(rows):
                _validate_physical_payload_row(
                    item,
                    f"{context}.{field}[{index}]",
                    debt=debt,
                    occurrence=occurrence,
                )
                record_ids.append(item["record_id"])
            if (
                len(record_ids) != len(set(record_ids))
                or record_ids
                != sorted(record_ids, key=lambda item: item.encode("utf-8"))
            ):
                raise RunBundleContractError(
                    f"{context}.{field} is duplicated or not canonically ordered"
                )


def _authority_payload_subject_ids(
    authority_type: str,
    payload: Mapping[str, Any],
    *,
    context: str,
) -> set[str]:
    """Derive the complete subject roster from the signed decision payload."""

    try:
        if authority_type == "RESOURCE_MEASUREMENT":
            values = [payload["run_id"]]
        elif authority_type == "RESOURCE_MEASUREMENT_SUMMARY":
            values = [
                payload["run_id"],
                *payload["measurement_receipt_refs"],
            ]
        elif authority_type == "RUN_CONTEXT":
            run_context = payload["run_context"]
            values = [
                run_context["run_id"],
                run_context["case_id"],
                run_context["experiment_id"],
                run_context["cell_id"],
            ]
        elif authority_type == "ALIAS_DECISION":
            values = []
            for edge in payload["edges"]:
                values.extend(
                    (
                        edge["edge_id"],
                        edge["source_candidate_id"],
                        edge["target_candidate_id"],
                    )
                )
                if edge["survivor_candidate_id"] is not None:
                    values.append(edge["survivor_candidate_id"])
        elif authority_type == "PHASE_OUTPUT":
            values = [
                payload["event"]["event_id"],
                payload["event"]["work_unit_id"],
            ]
        elif authority_type == "RECORD_PARTITION":
            values = [
                item["record_id"]
                for field in (
                    "occurrence_rows",
                    "nonfinding_rows",
                    "debt_rows",
                )
                for item in payload[field]
            ]
        elif authority_type == "CANDIDATE_EMISSION":
            values = [
                subject
                for occurrence in payload["occurrences"]
                for subject in (
                    occurrence["candidate_id"],
                    occurrence["occurrence_id"],
                    occurrence["artifact_id"],
                    occurrence["record_id"],
                )
            ]
        elif authority_type == "NEGATIVE_DISPOSITION":
            values = [
                subject
                for disposition in payload["dispositions"]
                for subject in (
                    disposition["candidate_id"],
                    disposition["occurrence_id"],
                    disposition["disposition_id"],
                )
            ]
        elif authority_type == "LINEAGE_DEBT":
            values = [
                subject
                for debt in payload["debts"]
                for subject in (
                    debt["debt_id"],
                    *debt["candidate_ids"],
                    *debt["occurrence_ids"],
                )
            ]
        elif authority_type in {
            "REPORT_DISPOSITION",
            "SEVERITY_DECISION",
        }:
            values = [
                item["candidate_id"]
                for item in payload["rows"]
            ]
        elif authority_type == "REPORT_QUALITY":
            values = [
                payload["final_report_artifact_id"],
                *(item["entry_id"] for item in payload["report_entries"]),
            ]
        elif authority_type == "NONFINDING_CLASSIFICATION":
            values = list(payload["record_ids"])
        else:  # pragma: no cover - guarded by the closed authority enum
            raise KeyError(authority_type)
    except (KeyError, TypeError) as exc:
        raise RunBundleContractError(
            f"{context} authority subject set is not exact: "
            "payload roster is invalid"
        ) from exc
    subjects: list[str] = []
    for index, value in enumerate(values):
        subjects.append(
            _identifier(value, f"{context}.subjects[{index}]")
        )
    return set(subjects)


def _validate_signed_authority_receipt(
    value: Any,
    audit_authority: Mapping[str, Any],
    *,
    context: str,
) -> dict[str, Any]:
    row = _closed(
        value,
        required={
            "schema_version",
            "receipt_id",
            "authority_type",
            "subject_ids",
            "source_artifact_ids",
            "decision",
            "decision_payload",
            "payload_sha256",
            "signature_b64",
        },
        context=context,
    )
    _enum(
        row["schema_version"],
        {"plamen.public-authority-receipt.v1"},
        f"{context}.schema_version",
    )
    _identifier(row["receipt_id"], f"{context}.receipt_id")
    _enum(row["authority_type"], _AUTHORITY_TYPES, f"{context}.authority_type")
    _id_list(row["subject_ids"], f"{context}.subject_ids")
    _id_list(row["source_artifact_ids"], f"{context}.source_artifact_ids")
    if row["decision"] is not None:
        _identifier(row["decision"], f"{context}.decision")
    if not isinstance(row["decision_payload"], dict):
        raise RunBundleContractError(
            f"{context}.decision_payload must be a JSON object"
        )
    payload_sha256 = _digest(
        row["payload_sha256"], f"{context}.payload_sha256"
    )
    if payload_sha256 != sha256_bytes(
        canonical_json_bytes(row["decision_payload"])
    ):
        raise RunBundleContractError(
            f"{context} decision payload digest binding is invalid"
        )
    _validate_authority_payload_shape(
        row["authority_type"],
        row["decision_payload"],
        context=f"{context}.decision_payload",
    )
    expected_subjects = _authority_payload_subject_ids(
        row["authority_type"],
        row["decision_payload"],
        context=context,
    )
    if set(row["subject_ids"]) != expected_subjects:
        authority_label = {
            "RESOURCE_MEASUREMENT": "measurement receipt",
            "RESOURCE_MEASUREMENT_SUMMARY": "measurement summary",
        }.get(row["authority_type"], "signed authority")
        raise RunBundleContractError(
            f"{context} {authority_label} subject roster is not exact"
        )
    signature = _decode_canonical_urlsafe_b64(
        row["signature_b64"],
        context=f"{context}.signature_b64",
        maximum_text=2048,
    )
    modulus = int(str(audit_authority["modulus_hex"]), 16)
    exponent = int(audit_authority["public_exponent"])
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        raise RunBundleContractError(f"{context} signature length is invalid")
    signature_integer = int.from_bytes(signature, "big")
    if signature_integer <= 0 or signature_integer >= modulus:
        raise RunBundleContractError(f"{context} signature range is invalid")
    body = {key: item for key, item in row.items() if key != "signature_b64"}
    digest = hashlib.sha256(canonical_document_bytes(body)).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    if size < len(digest_info) + 11:
        raise RunBundleContractError(f"{context} audit key is too small")
    expected = (
        b"\x00\x01"
        + (b"\xff" * (size - len(digest_info) - 3))
        + b"\x00"
        + digest_info
    )
    actual = pow(signature_integer, exponent, modulus).to_bytes(size, "big")
    if not hmac.compare_digest(actual, expected):
        raise RunBundleContractError(
            f"{context} signature does not bind the audit authority"
        )
    return row


def _load_authority_receipts(
    raw_outputs: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    records: Mapping[str, str],
    object_bytes: Mapping[str, bytes] | None,
    public_case_lock: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    receipts: dict[str, dict[str, Any]] = {}
    bound_by_artifact: dict[str, set[str]] = {}
    for index, binding in enumerate(raw_outputs["authority_receipts"]):
        receipt_id = binding["receipt_id"]
        artifact_id = binding["artifact_id"]
        artifact = artifacts.get(artifact_id)
        if artifact is None or records.get(receipt_id) != artifact_id:
            raise RunBundleContractError(
                "authority receipt artifact/record binding is invalid"
            )
        raw = _raw_artifact_bytes(
            artifact,
            object_bytes,
            context=f"authority receipt binding {receipt_id}",
        )
        start = binding["byte_range"]["start"]
        end = binding["byte_range"]["end"]
        if (
            end > len(raw)
            or sha256_bytes(raw[start:end]) != binding["record_sha256"]
        ):
            raise RunBundleContractError(
                "authority receipt byte-range digest binding is invalid"
            )
        try:
            parsed = strict_json_loads(raw[start:end], require_canonical=True)
        except RunBundleContractError as exc:
            raise RunBundleContractError(
                f"authority receipt binding {receipt_id} is not a canonical record"
            ) from exc
        receipt = _validate_signed_authority_receipt(
            parsed,
            public_case_lock["audit_authority"],
            context=f"authority receipt binding {index}",
        )
        if receipt["receipt_id"] != receipt_id:
            raise RunBundleContractError(
                "authority receipt identity does not bind its index row"
            )
        receipts[receipt_id] = receipt
        bound_by_artifact.setdefault(artifact_id, set()).add(receipt_id)
    for artifact_id, bound_ids in bound_by_artifact.items():
        if set(artifacts[artifact_id]["record_ids"]) != bound_ids:
            raise RunBundleContractError(
                "authority receipt index does not exactly cover its artifact records"
            )
    return receipts


_TYPED_IDENTITY_NAMESPACE_KINDS = (
    "run",
    "receipt",
    "artifact",
    "record",
    "event",
    "work-unit",
    "candidate",
    "occurrence",
    "edge",
    "alias-class",
    "negative-disposition",
    "lineage-debt",
    "report-entry",
)


def _validate_typed_identity_namespaces(
    namespaces: Mapping[str, Iterable[str]],
    *,
    indexed_authority_receipt_ids: Iterable[str],
) -> None:
    """Require pairwise-disjoint typed definition namespaces.

    The sole cross-role exception is the physical representation of an
    indexed authority receipt: its receipt ID is intentionally also the exact
    record ID bound by that authority-index row.
    """

    if set(namespaces) != set(_TYPED_IDENTITY_NAMESPACE_KINDS):
        raise RunBundleContractError(
            "typed identity namespace inventory is incomplete"
        )
    normalized: dict[str, set[str]] = {}
    for kind in _TYPED_IDENTITY_NAMESPACE_KINDS:
        values = list(namespaces[kind])
        if any(type(value) is not str for value in values):
            raise RunBundleContractError(
                f"typed identity namespace {kind} contains a non-text ID"
            )
        if len(values) != len(set(values)):
            raise RunBundleContractError(
                f"typed identity namespace contains duplicate {kind} "
                "definition IDs"
            )
        normalized[kind] = set(values)

    indexed = set(indexed_authority_receipt_ids)
    if not indexed.issubset(
        normalized["receipt"] & normalized["record"]
    ):
        raise RunBundleContractError(
            "indexed authority receipt-record namespace binding is invalid"
        )
    for left_index, left_kind in enumerate(_TYPED_IDENTITY_NAMESPACE_KINDS):
        for right_kind in _TYPED_IDENTITY_NAMESPACE_KINDS[left_index + 1 :]:
            collision = normalized[left_kind] & normalized[right_kind]
            if {left_kind, right_kind} == {"receipt", "record"}:
                collision -= indexed
            if collision:
                raise RunBundleContractError(
                    "typed identity namespace collides between "
                    f"{left_kind} and {right_kind}: "
                    f"{sorted(collision, key=lambda item: item.encode('utf-8'))[0]}"
                )


def _validate_receipt_identity_namespace(
    receipt_ids: Iterable[str],
    *,
    manifest: Mapping[str, Any],
    public_case_lock: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    candidates: Mapping[str, Any],
    lineage: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    records: Mapping[str, str],
    raw_authority_receipt_ids: Iterable[str],
    authority_receipts: Mapping[str, Mapping[str, Any]],
    report: Mapping[str, Any],
) -> None:
    """Validate every typed identity role through one global namespace map."""

    receipts = list(receipt_ids)
    if len(receipts) != len(set(receipts)):
        raise RunBundleContractError(
            "receipt identity namespace contains duplicate definition IDs"
        )
    indexed_authority_records = set(raw_authority_receipt_ids)
    namespaces: dict[str, Iterable[str]] = {
        "run": (
            manifest["run_id"],
            manifest["case_id"],
            manifest["experiment_id"],
            manifest["cell_id"],
            manifest["budget"]["parity_group_id"],
            public_case_lock["allocation_nonce"],
        ),
        "receipt": receipts,
        "artifact": tuple(artifacts),
        "record": tuple(records),
        "event": tuple(event["event_id"] for event in events),
        "work-unit": {
            *(event["work_unit_id"] for event in events),
            *(artifact["work_unit_id"] for artifact in artifacts.values()),
        },
        "candidate": tuple(
            candidate["candidate_id"] for candidate in candidates["candidates"]
        ),
        "occurrence": tuple(
            occurrence["occurrence_id"] for occurrence in lineage["occurrences"]
        ),
        "edge": tuple(edge["edge_id"] for edge in lineage["edges"]),
        "alias-class": tuple(
            alias_class["alias_class_id"]
            for alias_class in lineage["alias_classes"]
        ),
        "negative-disposition": tuple(
            disposition["disposition_id"]
            for disposition in lineage["negative_dispositions"]
        ),
        "lineage-debt": {
            *(debt["debt_id"] for debt in lineage["lineage_debts"]),
            *(
                debt["debt_id"]
                for authority in authority_receipts.values()
                if authority["authority_type"] == "LINEAGE_DEBT"
                for debt in authority["decision_payload"]["debts"]
            ),
        },
        "report-entry": tuple(
            entry.get("report_entry_id", entry.get("entry_id"))
            for field in (
                "report_entries",
                "appendix_entries",
                "unmapped_finding_sections",
            )
            for entry in report[field]
        ),
    }
    _validate_typed_identity_namespaces(
        namespaces,
        indexed_authority_receipt_ids=indexed_authority_records,
    )


def _validate_physical_authority_eligibility_coverage(
    raw_outputs: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    physical_rows: Sequence[Mapping[str, Any]],
    object_bytes: Mapping[str, bytes] | None,
    authority_receipts: Mapping[str, Mapping[str, Any]],
) -> None:
    """Enumerate authority-eligible physical records independent of the index."""

    eligible: dict[str, Mapping[str, Any]] = {}
    for physical in physical_rows:
        artifact = artifacts[physical["artifact_id"]]
        raw = _raw_artifact_bytes(
            artifact,
            object_bytes,
            context="physical authority eligibility scan",
        )
        start = physical["byte_range"]["start"]
        end = physical["byte_range"]["end"]
        segment = raw[start:end]
        parsed: Any = None
        try:
            parsed = strict_json_loads(segment, require_canonical=False)
        except RunBundleContractError:
            pass
        schema_authority = (
            isinstance(parsed, dict)
            and parsed.get("schema_version")
            == "plamen.public-authority-receipt.v1"
        )
        if not schema_authority:
            continue
        try:
            canonical = strict_json_loads(segment, require_canonical=True)
        except RunBundleContractError as exc:
            raise RunBundleContractError(
                "authority eligibility record is not canonical"
            ) from exc
        if (
            not isinstance(canonical, dict)
            or canonical.get("schema_version")
            != "plamen.public-authority-receipt.v1"
            or canonical.get("receipt_id") != physical["record_id"]
        ):
            raise RunBundleContractError(
                "authority eligibility record identity/schema binding is invalid"
            )
        receipt_id = canonical["receipt_id"]
        if receipt_id in eligible:
            raise RunBundleContractError(
                "authority eligibility coverage contains a duplicate receipt"
            )
        eligible[receipt_id] = physical

    bindings = {
        binding["receipt_id"]: binding
        for binding in raw_outputs["authority_receipts"]
    }
    if set(eligible) != set(bindings) or set(eligible) != set(authority_receipts):
        raise RunBundleContractError(
            "authority eligibility coverage does not exactly match the "
            "physical authority index"
        )
    for receipt_id, physical in eligible.items():
        binding = bindings[receipt_id]
        if (
            binding["artifact_id"] != physical["artifact_id"]
            or binding["byte_range"] != physical["byte_range"]
            or binding["record_sha256"] != physical["record_sha256"]
        ):
            raise RunBundleContractError(
                "authority eligibility binding does not match its physical record"
            )


def _require_typed_authority(
    receipts: Mapping[str, Mapping[str, Any]],
    receipt_id: str,
    authority_type: str,
    *,
    subjects: Iterable[str] = (),
    source_artifact_ids: Iterable[str] | None = None,
    decision: str | None = None,
    decision_payload: Mapping[str, Any] | None = None,
    payload_row: tuple[str, Mapping[str, Any]] | None = None,
    context: str,
) -> Mapping[str, Any]:
    receipt = receipts.get(receipt_id)
    required_subjects = set(subjects)
    if receipt is not None:
        exact_subjects = _authority_payload_subject_ids(
            receipt["authority_type"],
            receipt["decision_payload"],
            context=context,
        )
    else:
        exact_subjects = set()
    if (
        receipt is None
        or receipt["authority_type"] != authority_type
        or set(receipt["subject_ids"]) != exact_subjects
        or not required_subjects.issubset(exact_subjects)
        or (decision is not None and receipt["decision"] != decision)
    ):
        raise RunBundleContractError(
            f"{context} typed authority binding subject set is not exact"
        )
    if (
        source_artifact_ids is not None
        and set(receipt["source_artifact_ids"]) != set(source_artifact_ids)
    ):
        raise RunBundleContractError(
            f"{context} source artifact authority binding is invalid"
        )
    if (
        decision_payload is not None
        and receipt["decision_payload"] != decision_payload
    ):
        raise RunBundleContractError(
            f"{context} canonical decision payload binding is invalid"
        )
    if payload_row is not None:
        field, expected_row = payload_row
        supplied_rows = receipt["decision_payload"].get(field)
        if (
            not isinstance(supplied_rows, list)
            or expected_row not in supplied_rows
        ):
            raise RunBundleContractError(
                f"{context} canonical decision payload row is invalid"
            )
    return receipt


def validate_raw_output_index(value: Any) -> dict[str, Any]:
    row = _validate_doc_start(
        value, RAW_OUTPUT_INDEX_SCHEMA, "raw output index"
    )
    _closed(
        row,
        required={
            "schema_version",
            "run_id",
            "artifacts",
            "authority_receipts",
        },
        context="raw output index",
    )
    _identifier(row["run_id"], "raw output index.run_id")
    artifacts = _list(row["artifacts"], "raw output index.artifacts")
    ids: list[str] = []
    source_paths: list[str] = []
    for index, artifact in enumerate(artifacts):
        _validate_raw_artifact(
            artifact, f"raw output index.artifacts[{index}]"
        )
        ids.append(artifact["artifact_id"])
        source_paths.append(artifact["relative_source_path"])
    if len(ids) != len(set(ids)):
        raise RunBundleContractError("raw output index has duplicate artifact IDs")
    if ids != sorted(ids, key=lambda item: item.encode("utf-8")):
        raise RunBundleContractError("raw output artifacts are not sorted")
    try:
        _privacy.assert_no_casefold_collisions(source_paths)
    except _privacy.RunBundlePrivacyError as exc:
        raise RunBundleContractError(str(exc)) from exc
    bindings = _list(
        row["authority_receipts"],
        "raw output index.authority_receipts",
    )
    receipt_ids: list[str] = []
    for index, binding in enumerate(bindings):
        _validate_authority_receipt_binding(
            binding,
            f"raw output index.authority_receipts[{index}]",
        )
        receipt_ids.append(binding["receipt_id"])
    if (
        len(receipt_ids) != len(set(receipt_ids))
        or receipt_ids != sorted(receipt_ids, key=lambda item: item.encode("utf-8"))
    ):
        raise RunBundleContractError(
            "raw output authority receipt bindings are duplicated or unsorted"
        )
    return row


_REPORT_ENTRY_FIELDS = frozenset(
    {
        "report_entry_id",
        "section_locator",
        "byte_range",
        "byte_range_sha256",
        "candidate_ids",
        "audit_alias_class_id",
        "asserted_severity",
        "evidence_record_refs",
        "report_status",
    }
)


def _validate_report_entry(value: Any, context: str) -> None:
    row = _closed(value, required=_REPORT_ENTRY_FIELDS, context=context)
    _identifier(row["report_entry_id"], f"{context}.report_entry_id")
    _text(row["section_locator"], f"{context}.section_locator", maximum=1024)
    byte_range = _closed(
        row["byte_range"],
        required={"start", "end"},
        context=f"{context}.byte_range",
    )
    start = _integer(byte_range["start"], f"{context}.byte_range.start")
    _integer(
        byte_range["end"],
        f"{context}.byte_range.end",
        minimum=start + 1,
    )
    _digest(row["byte_range_sha256"], f"{context}.byte_range_sha256")
    candidates = _id_list(row["candidate_ids"], f"{context}.candidate_ids")
    if not candidates:
        raise RunBundleContractError(f"{context}.candidate_ids is empty")
    if row["audit_alias_class_id"] is not None:
        _opaque_id(
            row["audit_alias_class_id"],
            f"{context}.audit_alias_class_id",
            "alias",
        )
    _enum(row["asserted_severity"], _SEVERITIES, f"{context}.asserted_severity")
    _id_list(row["evidence_record_refs"], f"{context}.evidence_record_refs")
    _enum(
        row["report_status"],
        {"REPORTED", "APPENDIX", "WITHHELD_WITH_AUTHORITY", "PARSE_DEBT"},
        f"{context}.report_status",
    )


def _validate_unmapped_report_entry(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "entry_id",
            "section_locator",
            "byte_range",
            "byte_range_sha256",
            "promoted_candidate_id",
            "debt_code",
        },
        context=context,
    )
    for field in ("entry_id", "promoted_candidate_id", "debt_code"):
        _identifier(row[field], f"{context}.{field}")
    _text(row["section_locator"], f"{context}.section_locator", maximum=1024)
    byte_range = _closed(
        row["byte_range"],
        required={"start", "end"},
        context=f"{context}.byte_range",
    )
    start = _integer(byte_range["start"], f"{context}.byte_range.start")
    _integer(
        byte_range["end"],
        f"{context}.byte_range.end",
        minimum=start + 1,
    )
    _digest(row["byte_range_sha256"], f"{context}.byte_range_sha256")


def _validate_report_disposition(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "candidate_id",
            "report_status",
            "authority_receipt_id",
            "debt_code",
        },
        context=context,
    )
    _identifier(row["candidate_id"], f"{context}.candidate_id")
    _enum(
        row["report_status"],
        {"REPORTED", "APPENDIX", "OMITTED_WITH_AUTHORITY", "DEBT"},
        f"{context}.report_status",
    )
    _identifier(
        row["authority_receipt_id"], f"{context}.authority_receipt_id"
    )
    if row["debt_code"] is not None:
        _identifier(row["debt_code"], f"{context}.debt_code")


def validate_report_projection(value: Any) -> dict[str, Any]:
    row = _validate_doc_start(
        value, REPORT_PROJECTION_SCHEMA, "report projection"
    )
    _closed(
        row,
        required={
            "schema_version",
            "run_id",
            "final_report_artifact_id",
            "final_report_sha256",
            "final_report_byte_length",
            "delivery_state",
            "report_entries",
            "appendix_entries",
            "unmapped_finding_sections",
            "candidate_report_dispositions",
            "report_evidence_quality_receipt_ref",
            "report_integrity_state",
        },
        context="report projection",
    )
    for field in (
        "run_id",
        "final_report_artifact_id",
        "report_evidence_quality_receipt_ref",
    ):
        _identifier(row[field], f"report projection.{field}")
    _digest(row["final_report_sha256"], "report projection.final_report_sha256")
    _integer(
        row["final_report_byte_length"],
        "report projection.final_report_byte_length",
    )
    _enum(
        row["delivery_state"],
        {"DELIVERED", "DEGRADED", "NOT_DELIVERED"},
        "report projection.delivery_state",
    )
    entry_ids: list[str] = []
    for field in ("report_entries", "appendix_entries"):
        entries = _list(row[field], f"report projection.{field}")
        for index, entry in enumerate(entries):
            _validate_report_entry(
                entry, f"report projection.{field}[{index}]"
            )
            entry_ids.append(entry["report_entry_id"])
    unmapped = _list(
        row["unmapped_finding_sections"],
        "report projection.unmapped_finding_sections",
    )
    for index, entry in enumerate(unmapped):
        _validate_unmapped_report_entry(
            entry,
            f"report projection.unmapped_finding_sections[{index}]",
        )
        entry_ids.append(entry["entry_id"])
    if len(entry_ids) != len(set(entry_ids)):
        raise RunBundleContractError("report projection has duplicate entry IDs")
    projections = [
        (
            entry["byte_range"]["start"],
            entry["byte_range"]["end"],
            entry.get("report_entry_id", entry.get("entry_id")),
        )
        for field in ("report_entries", "appendix_entries")
        for entry in row[field]
    ] + [
        (
            entry["byte_range"]["start"],
            entry["byte_range"]["end"],
            entry["entry_id"],
        )
        for entry in unmapped
    ]
    projections.sort(key=lambda item: (item[0], item[1], item[2]))
    for prior, current in zip(projections, projections[1:]):
        if current[0] < prior[1]:
            raise RunBundleContractError(
                "report projections contain duplicate or overlapping byte ranges"
            )
    dispositions = _list(
        row["candidate_report_dispositions"],
        "report projection.candidate_report_dispositions",
    )
    candidate_ids: list[str] = []
    for index, disposition in enumerate(dispositions):
        _validate_report_disposition(
            disposition,
            f"report projection.candidate_report_dispositions[{index}]",
        )
        candidate_ids.append(disposition["candidate_id"])
    if len(candidate_ids) != len(set(candidate_ids)):
        raise RunBundleContractError(
            "report projection has duplicate candidate dispositions"
        )
    _enum(
        row["report_integrity_state"],
        {"SHIP", "NO_SHIP", "DEGRADED", "UNKNOWN"},
        "report projection.report_integrity_state",
    )
    return row


def _validate_roster(value: Any, context: str) -> None:
    row = _closed(value, required={"count", "ids"}, context=context)
    count = _integer(row["count"], f"{context}.count")
    ids = _id_list(row["ids"], f"{context}.ids")
    if count != len(ids):
        raise RunBundleContractError(f"{context} count does not bind its IDs")


def _validate_source_snapshot(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "source_snapshot_sha256",
            "before_sha256",
            "after_sha256",
            "stable",
        },
        context=context,
    )
    for field in ("source_snapshot_sha256", "before_sha256", "after_sha256"):
        _digest(row[field], f"{context}.{field}")
    stable = _boolean(row["stable"], f"{context}.stable")
    if stable and row["before_sha256"] != row["after_sha256"]:
        raise RunBundleContractError(f"{context} stable digests disagree")
    if stable and row["source_snapshot_sha256"] != row["before_sha256"]:
        raise RunBundleContractError(
            f"{context} snapshot digest does not bind stable inputs"
        )


def _validate_reconciliation(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "discovered_count",
            "emitted_occurrence_count",
            "nonfinding_count",
            "debt_count",
            "balanced",
            "occurrence_record_ids",
            "authenticated_nonfinding_records",
            "explicit_debt_records",
            "partition_authority",
        },
        context=context,
    )
    counts = {
        field: _integer(row[field], f"{context}.{field}")
        for field in (
            "discovered_count",
            "emitted_occurrence_count",
            "nonfinding_count",
            "debt_count",
        )
    }
    balanced = _boolean(row["balanced"], f"{context}.balanced")
    occurrence_record_ids = _id_list(
        row["occurrence_record_ids"],
        f"{context}.occurrence_record_ids",
    )
    nonfinding_rows = _list(
        row["authenticated_nonfinding_records"],
        f"{context}.authenticated_nonfinding_records",
    )
    nonfinding_record_ids: list[str] = []
    for index, item in enumerate(nonfinding_rows):
        item_context = f"{context}.authenticated_nonfinding_records[{index}]"
        item_row = _closed(
            item,
            required={
                "record_id",
                "artifact_id",
                "byte_range",
                "record_sha256",
                "producer_kind",
                "source_contract_ref",
                "authority_receipt_id",
            },
            context=item_context,
        )
        nonfinding_record_ids.append(
            _identifier(item_row["record_id"], f"{item_context}.record_id")
        )
        _identifier(
            item_row["authority_receipt_id"],
            f"{item_context}.authority_receipt_id",
        )
        _identifier(item_row["artifact_id"], f"{item_context}.artifact_id")
        _digest(item_row["record_sha256"], f"{item_context}.record_sha256")
        _identifier(
            item_row["producer_kind"], f"{item_context}.producer_kind"
        )
        _text(
            item_row["source_contract_ref"],
            f"{item_context}.source_contract_ref",
            maximum=256,
        )
        byte_range = _closed(
            item_row["byte_range"],
            required={"start", "end"},
            context=f"{item_context}.byte_range",
        )
        start = _integer(
            byte_range["start"], f"{item_context}.byte_range.start"
        )
        _integer(
            byte_range["end"],
            f"{item_context}.byte_range.end",
            minimum=start + 1,
        )
    if (
        len(nonfinding_record_ids) != len(set(nonfinding_record_ids))
        or nonfinding_record_ids
        != sorted(nonfinding_record_ids, key=lambda item: item.encode("utf-8"))
    ):
        raise RunBundleContractError(
            f"{context}.authenticated_nonfinding_records are duplicated or unsorted"
        )
    debt_rows = _list(
        row["explicit_debt_records"],
        f"{context}.explicit_debt_records",
    )
    debt_record_ids: list[str] = []
    for index, item in enumerate(debt_rows):
        item_context = f"{context}.explicit_debt_records[{index}]"
        item_row = _closed(
            item,
            required={
                "record_id",
                "artifact_id",
                "byte_range",
                "record_sha256",
                "producer_kind",
                "source_contract_ref",
                "debt_id",
                "authority_receipt_id",
            },
            context=item_context,
        )
        debt_record_ids.append(
            _identifier(item_row["record_id"], f"{item_context}.record_id")
        )
        for field in ("debt_id", "authority_receipt_id"):
            _identifier(item_row[field], f"{item_context}.{field}")
        _identifier(item_row["artifact_id"], f"{item_context}.artifact_id")
        _digest(item_row["record_sha256"], f"{item_context}.record_sha256")
        _identifier(
            item_row["producer_kind"], f"{item_context}.producer_kind"
        )
        _text(
            item_row["source_contract_ref"],
            f"{item_context}.source_contract_ref",
            maximum=256,
        )
        byte_range = _closed(
            item_row["byte_range"],
            required={"start", "end"},
            context=f"{item_context}.byte_range",
        )
        start = _integer(
            byte_range["start"], f"{item_context}.byte_range.start"
        )
        _integer(
            byte_range["end"],
            f"{item_context}.byte_range.end",
            minimum=start + 1,
        )
    if (
        len(debt_record_ids) != len(set(debt_record_ids))
        or debt_record_ids
        != sorted(debt_record_ids, key=lambda item: item.encode("utf-8"))
    ):
        raise RunBundleContractError(
            f"{context}.explicit_debt_records are duplicated or unsorted"
        )
    if (
        counts["emitted_occurrence_count"] != len(occurrence_record_ids)
        or counts["nonfinding_count"] != len(nonfinding_rows)
        or counts["debt_count"] != len(debt_rows)
    ):
        raise RunBundleContractError(
            f"{context} counts do not bind their explicit record partitions"
        )
    exact = counts["discovered_count"] == (
        counts["emitted_occurrence_count"]
        + counts["nonfinding_count"]
        + counts["debt_count"]
    )
    if not balanced or not exact:
        raise RunBundleContractError(
            f"{context} denominator conservation is not exact"
        )
    if row["partition_authority"] is not None and not isinstance(
        row["partition_authority"], dict
    ):
        raise RunBundleContractError(
            f"{context}.partition_authority must be a signed receipt object "
            "or null for an explicitly unauthenticated local profile"
        )


def _validate_redaction_summary(value: Any, context: str) -> None:
    row = _closed(value, required={"count", "entries"}, context=context)
    count = _integer(row["count"], f"{context}.count")
    entries = _list(row["entries"], f"{context}.entries")
    for index, entry in enumerate(entries):
        _validate_redaction(entry, f"{context}.entries[{index}]")
    if count != len(entries):
        raise RunBundleContractError(f"{context} count is invalid")


def _validate_privacy_scan(value: Any, context: str) -> None:
    row = _closed(
        value,
        required={
            "status",
            "issue_count",
            "policy_id",
            "policy_version",
            "claim_scope",
            "policy_sha256",
        },
        context=context,
    )
    _enum(row["status"], {"PASSED"}, f"{context}.status")
    if _integer(row["issue_count"], f"{context}.issue_count") != 0:
        raise RunBundleContractError(f"{context} cannot seal privacy issues")
    policy_id = _identifier(row["policy_id"], f"{context}.policy_id")
    policy_version = _text(
        row["policy_version"], f"{context}.policy_version", maximum=64
    )
    claim_scope = _enum(
        row["claim_scope"],
        {"PUBLIC_STRUCTURAL_EXCLUSION_ONLY"},
        f"{context}.claim_scope",
    )
    policy_sha256 = _digest(
        row["policy_sha256"], f"{context}.policy_sha256"
    )
    if (
        policy_id != _privacy.PUBLIC_STRUCTURAL_SCAN_POLICY_ID
        or policy_version != _privacy.PUBLIC_STRUCTURAL_SCAN_POLICY_VERSION
        or claim_scope != "PUBLIC_STRUCTURAL_EXCLUSION_ONLY"
        or policy_sha256 != _privacy.public_structural_scan_policy_sha256()
    ):
        raise RunBundleContractError(
            f"{context} does not bind the evaluator-owned public structural "
            "scan policy"
        )


def _validate_export_status(value: Any, context: str) -> None:
    row = _closed(value, required={"state", "debts"}, context=context)
    _enum(
        row["state"],
        {"COMPLETE", "DEGRADED", "INCOMPLETE", "FAILED"},
        f"{context}.state",
    )
    _text_list(row["debts"], f"{context}.debts")


def validate_harvest_receipt(value: Any) -> dict[str, Any]:
    row = _validate_doc_start(
        value, HARVEST_RECEIPT_SCHEMA, "harvest receipt"
    )
    _closed(
        row,
        required={
            "schema_version",
            "run_id",
            "source_snapshot",
            "artifact_roster",
            "record_reconciliation",
            "candidate_roster",
            "occurrence_roster",
            "edge_roster",
            "report_entry_roster",
            "redaction_summary",
            "privacy_scan",
            "export_status",
            "receipt_sha256",
        },
        context="harvest receipt",
    )
    _identifier(row["run_id"], "harvest receipt.run_id")
    _validate_source_snapshot(
        row["source_snapshot"], "harvest receipt.source_snapshot"
    )
    for field in (
        "artifact_roster",
        "candidate_roster",
        "occurrence_roster",
        "edge_roster",
        "report_entry_roster",
    ):
        _validate_roster(row[field], f"harvest receipt.{field}")
    _validate_reconciliation(
        row["record_reconciliation"],
        "harvest receipt.record_reconciliation",
    )
    _validate_redaction_summary(
        row["redaction_summary"], "harvest receipt.redaction_summary"
    )
    _validate_privacy_scan(
        row["privacy_scan"], "harvest receipt.privacy_scan"
    )
    _validate_export_status(
        row["export_status"], "harvest receipt.export_status"
    )
    verify_embedded_sha256(row, "receipt_sha256")
    return row


PUBLIC_FIELDS_BY_SCHEMA: Mapping[str, frozenset[str]] = {
    PUBLIC_CASE_LOCK_SCHEMA: frozenset(
        {
            "schema_version",
            "case_id",
            "source_snapshot_sha256",
            "source_export_receipt_sha256",
            "language",
            "build_instructions",
            "test_instructions",
            "allowed_public_documentation",
            "capability_flags",
            "public_corpus_suite_id",
            "public_corpus_suite_version",
            "allocation_nonce",
            "allocation_authority",
            "audit_authority",
        }
    ),
    RUN_MANIFEST_SCHEMA: frozenset(
        {
            "schema_version",
            "bundle_profile",
            "trust_profile",
            "run_id",
            "case_id",
            "experiment_id",
            "cell_id",
            "allocation_authority_ref",
            "repetition_index",
            "seed",
            "audit_system",
            "adapter",
            "public_case_lock_sha256",
            "experiment_plan_sha256",
            "campaign_schedule_sha256",
            "source_snapshot_sha256",
            "phase_map",
            "model_backend",
            "tool_policy",
            "budget",
            "blinding",
            "resume",
            "completion",
            "exporter",
            "public_launch_receipt",
            "run_context_authority",
        }
    ),
    PHASE_EVENT_SCHEMA: frozenset(
        {
            "schema_version",
            "event_id",
            "run_id",
            "sequence",
            "attempt",
            "native_phase",
            "macro_phase",
            "work_unit_id",
            "event_type",
            "commit_state",
            "source_artifact_ids",
            "input_artifact_ids",
            "output_artifact_ids",
            "artifact_relations",
            "source_receipt_id",
            "observed_at",
            "evidence_quality",
        }
    ),
    CANDIDATE_SET_SCHEMA: frozenset(
        {"schema_version", "run_id", "candidates"}
    ),
    CANDIDATE_LINEAGE_SCHEMA: frozenset(
        {
            "schema_version",
            "run_id",
            "occurrences",
            "edges",
            "alias_classes",
            "negative_dispositions",
            "lineage_debts",
        }
    ),
    RAW_OUTPUT_INDEX_SCHEMA: frozenset(
        {"schema_version", "run_id", "artifacts", "authority_receipts"}
    ),
    REPORT_PROJECTION_SCHEMA: frozenset(
        {
            "schema_version",
            "run_id",
            "final_report_artifact_id",
            "final_report_sha256",
            "final_report_byte_length",
            "delivery_state",
            "report_entries",
            "appendix_entries",
            "unmapped_finding_sections",
            "candidate_report_dispositions",
            "report_evidence_quality_receipt_ref",
            "report_integrity_state",
        }
    ),
    HARVEST_RECEIPT_SCHEMA: frozenset(
        {
            "schema_version",
            "run_id",
            "source_snapshot",
            "artifact_roster",
            "record_reconciliation",
            "candidate_roster",
            "occurrence_roster",
            "edge_roster",
            "report_entry_roster",
            "redaction_summary",
            "privacy_scan",
            "export_status",
            "receipt_sha256",
        }
    ),
}


def public_field_allowlist(schema_version: str) -> frozenset[str]:
    try:
        return PUBLIC_FIELDS_BY_SCHEMA[schema_version]
    except KeyError as exc:
        raise RunBundleContractError(
            "schema has no public field allowlist"
        ) from exc


_VALIDATORS: Mapping[str, Callable[[Any], dict[str, Any]]] = {
    PUBLIC_CASE_LOCK_SCHEMA: validate_public_case_lock,
    RUN_MANIFEST_SCHEMA: validate_run_manifest,
    PHASE_EVENT_SCHEMA: validate_phase_event,
    CANDIDATE_SET_SCHEMA: validate_candidate_set,
    CANDIDATE_LINEAGE_SCHEMA: validate_candidate_lineage,
    RAW_OUTPUT_INDEX_SCHEMA: validate_raw_output_index,
    REPORT_PROJECTION_SCHEMA: validate_report_projection,
    HARVEST_RECEIPT_SCHEMA: validate_harvest_receipt,
}


def validate_document(value: Any) -> dict[str, Any]:
    row = _exact_json_snapshot(value, context="RunBundle document")
    if type(row) is not dict:
        raise RunBundleContractError("RunBundle document must be a JSON object")
    schema = row.get("schema_version")
    if isinstance(schema, str) and (
        schema == PRIVATE_CASE_LOCK_SCHEMA
        or schema.startswith("plamen.private-")
    ):
        raise RunBundleContractError(
            "private contract cannot enter a public RunBundle"
        )
    validator = _VALIDATORS.get(schema)
    if validator is None:
        raise RunBundleContractError(
            "unknown or unsupported public RunBundle schema"
        )
    return validator(row)


def validate_phase_events(value: Any) -> list[dict[str, Any]]:
    rows = _list(
        _exact_json_snapshot(value, context="phase events"),
        "phase events",
    )
    validated: list[dict[str, Any]] = []
    identities: set[tuple[Any, ...]] = set()
    sequences: list[int] = []
    for index, event in enumerate(rows):
        row = validate_phase_event(event)
        identity = (
            row["run_id"],
            row["attempt"],
            row["work_unit_id"],
            row["event_type"],
            row["source_receipt_id"],
        )
        if identity in identities:
            raise RunBundleContractError(
                f"phase events contain a duplicate identity at row {index}"
            )
        identities.add(identity)
        sequences.append(row["sequence"])
        validated.append(row)
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        raise RunBundleContractError(
            "phase events must have unique ascending sequence values"
        )
    return validated


def _require_evidence_reference(
    reference: str,
    artifacts: Mapping[str, Mapping[str, Any]],
    records: Mapping[str, str],
    *,
    context: str,
) -> None:
    if reference.count("#") != 1:
        raise RunBundleContractError(
            f"{context} reference must be artifact_id#record_id"
        )
    artifact_id, record_id = reference.split("#", 1)
    if (
        artifact_id not in artifacts
        or records.get(record_id) != artifact_id
    ):
        raise RunBundleContractError(f"{context} reference binding is invalid")


def _validate_alias_replay(
    lineage: Mapping[str, Any],
    candidate_ids: set[str],
) -> set[str]:
    edges = lineage["edges"]
    edge_by_id = {edge["edge_id"]: edge for edge in edges}
    for edge in edges:
        endpoints = {
            edge["source_candidate_id"],
            edge["target_candidate_id"],
        }
        if not endpoints.issubset(candidate_ids):
            raise RunBundleContractError(
                "lineage edge candidate binding is invalid"
            )
        if len(endpoints) != 2:
            raise RunBundleContractError(
                "lineage edge endpoints must be distinct"
            )
        survivor = edge["survivor_candidate_id"]
        if survivor is not None and survivor not in endpoints:
            raise RunBundleContractError(
                "lineage edge survivor binding is invalid"
            )
        if edge["effective"] and edge["edge_type"] != "AUTHORIZED_ALIAS":
            raise RunBundleContractError(
                "only an authorized alias edge may be effective"
            )

    applied = {
        edge["edge_id"]: edge
        for edge in edges
        if edge["edge_type"] == "AUTHORIZED_ALIAS" and edge["effective"]
    }
    listed: list[str] = []
    class_ids: set[str] = set()
    next_candidate: dict[str, str] = {}
    class_by_member: dict[str, str] = {}
    for alias_class in lineage["alias_classes"]:
        class_id = alias_class["alias_class_id"]
        if class_id in class_ids:
            raise RunBundleContractError("alias class identity is duplicated")
        class_ids.add(class_id)
        members = set(alias_class["candidate_ids"])
        if not members.issubset(candidate_ids):
            raise RunBundleContractError(
                "alias class candidate binding is invalid"
            )
        survivor = alias_class["survivor_candidate_id"]
        if survivor not in members:
            raise RunBundleContractError(
                "alias class survivor binding is invalid"
            )
        edge_members: set[str] = set()
        for edge_id in alias_class["applied_edge_ids"]:
            edge = applied.get(edge_id)
            if edge is None:
                raise RunBundleContractError(
                    "alias class contains a non-applied edge"
                )
            listed.append(edge_id)
            endpoints = {
                edge["source_candidate_id"],
                edge["target_candidate_id"],
            }
            edge_members.update(endpoints)
            edge_survivor = edge["survivor_candidate_id"]
            assert isinstance(edge_survivor, str)
            eliminated = next(iter(endpoints - {edge_survivor}))
            prior = next_candidate.get(eliminated)
            if prior is not None and prior != edge_survivor:
                raise RunBundleContractError(
                    "applied alias edges assign conflicting survivors"
                )
            next_candidate[eliminated] = edge_survivor
        if edge_members != members:
            raise RunBundleContractError(
                "alias class members do not equal applied edge membership"
            )
        for member in members:
            prior_class = class_by_member.get(member)
            if prior_class is not None and prior_class != class_id:
                raise RunBundleContractError(
                    "candidate appears in multiple applied alias classes"
                )
            class_by_member[member] = class_id

    if len(listed) != len(set(listed)) or set(listed) != set(applied):
        raise RunBundleContractError(
            "applied alias edge membership is incomplete or duplicated"
        )

    visiting: set[str] = set()
    terminal_cache: dict[str, str] = {}

    def terminal(candidate_id: str) -> str:
        if candidate_id in terminal_cache:
            return terminal_cache[candidate_id]
        if candidate_id in visiting:
            raise RunBundleContractError("applied alias graph contains a cycle")
        visiting.add(candidate_id)
        successor = next_candidate.get(candidate_id)
        result = candidate_id if successor is None else terminal(successor)
        visiting.remove(candidate_id)
        terminal_cache[candidate_id] = result
        return result

    for alias_class in lineage["alias_classes"]:
        expected = alias_class["survivor_candidate_id"]
        for member in alias_class["candidate_ids"]:
            if terminal(member) != expected:
                raise RunBundleContractError(
                    "alias class survivor does not match applied edge replay"
                )
    return class_ids


def _physical_record_occurrence(
    *,
    record_id: str,
    artifact: Mapping[str, Any],
    byte_range: Mapping[str, Any],
    record_sha256: str,
    occurrence_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    row = {
        "record_id": record_id,
        "artifact_id": artifact["artifact_id"],
        "byte_range": {
            "start": byte_range["start"],
            "end": byte_range["end"],
        },
        "record_sha256": record_sha256,
        "producer_kind": artifact["producer_kind"],
        "source_contract_ref": artifact["source_contract_ref"],
    }
    if occurrence_ids is not None:
        row["occurrence_ids"] = sorted(
            set(occurrence_ids), key=lambda item: item.encode("utf-8")
        )
    return row


def _artifact_partition_binding(
    artifact: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "artifact_id": artifact["artifact_id"],
        "byte_length": artifact["byte_length"],
        "sha256": artifact["sha256"],
        "producer_kind": artifact["producer_kind"],
        "source_contract_ref": artifact["source_contract_ref"],
        "record_ids": list(artifact["record_ids"]),
        "parser_completeness": "COMPLETE_RECORD_ENUMERATION",
    }


def _verify_physical_record_occurrence(
    row: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    records: Mapping[str, str],
    object_bytes: Mapping[str, bytes] | None,
    *,
    context: str,
) -> dict[str, Any]:
    artifact_id = row["artifact_id"]
    artifact = artifacts.get(artifact_id)
    if (
        artifact is None
        or records.get(row["record_id"]) != artifact_id
        or row["producer_kind"] != artifact["producer_kind"]
        or row["source_contract_ref"] != artifact["source_contract_ref"]
    ):
        raise RunBundleContractError(
            f"{context} physical occurrence artifact/parser binding is invalid"
        )
    raw = _raw_artifact_bytes(
        artifact,
        object_bytes,
        context=f"{context} physical occurrence",
    )
    start = row["byte_range"]["start"]
    end = row["byte_range"]["end"]
    if end > len(raw) or sha256_bytes(raw[start:end]) != row["record_sha256"]:
        raise RunBundleContractError(
            f"{context} physical occurrence byte-range binding is invalid"
        )
    return _physical_record_occurrence(
        record_id=row["record_id"],
        artifact=artifact,
        byte_range=row["byte_range"],
        record_sha256=row["record_sha256"],
        occurrence_ids=row.get("occurrence_ids"),
    )


def _phase_output_payload(
    event: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    event_facts = {
        key: value for key, value in event.items() if key != "source_receipt_id"
    }
    payload: dict[str, Any] = {"event": event_facts}
    for payload_field, event_field in (
        ("source_artifacts", "source_artifact_ids"),
        ("input_artifacts", "input_artifact_ids"),
        ("output_artifacts", "output_artifact_ids"),
    ):
        payload[payload_field] = [
            {
                "artifact_id": artifact_id,
                "native_phase": artifacts[artifact_id]["native_phase"],
                "macro_phase": artifacts[artifact_id]["macro_phase"],
                "work_unit_id": artifacts[artifact_id]["work_unit_id"],
                "commit_state": artifacts[artifact_id]["commit_state"],
                "source_contract_ref": artifacts[artifact_id][
                    "source_contract_ref"
                ],
            }
            for artifact_id in event[event_field]
        ]
    control_ids = [
        relation["artifact_id"]
        for relation in event["artifact_relations"]
        if relation["relation"] == "CONTROL"
    ]
    payload["control_artifacts"] = [
        {
            "artifact_id": artifact_id,
            "native_phase": artifacts[artifact_id]["native_phase"],
            "macro_phase": artifacts[artifact_id]["macro_phase"],
            "work_unit_id": artifacts[artifact_id]["work_unit_id"],
            "commit_state": artifacts[artifact_id]["commit_state"],
            "source_contract_ref": artifacts[artifact_id][
                "source_contract_ref"
            ],
        }
        for artifact_id in control_ids
    ]
    return payload


def _report_projection_authority_row(
    entry: Mapping[str, Any],
    *,
    projection_kind: str,
) -> dict[str, Any]:
    return {
        "entry_id": entry.get("report_entry_id", entry.get("entry_id")),
        "byte_range": {
            "start": entry["byte_range"]["start"],
            "end": entry["byte_range"]["end"],
        },
        "byte_range_sha256": entry["byte_range_sha256"],
        "candidate_ids": (
            entry["candidate_ids"]
            if "candidate_ids" in entry
            else [entry["promoted_candidate_id"]]
        ),
        "projection_kind": projection_kind,
    }


def validate_bundle_object_bindings(
    raw_output_index: Mapping[str, Any],
    bundle_index: Mapping[str, Any],
) -> None:
    """Replay every OBJECT artifact against the exact recursive bundle index."""

    raw_outputs = validate_raw_output_index(raw_output_index)
    exact_bundle_index = _exact_json_snapshot(
        bundle_index,
        context="bundle object index",
    )
    try:
        _privacy.bundle_index_bytes(exact_bundle_index)
    except _privacy.RunBundlePrivacyError as exc:
        raise RunBundleContractError("bundle object index is invalid") from exc
    indexed_objects = {
        row["relative_path"]: row
        for row in exact_bundle_index["entries"]
        if row["relative_path"].startswith("objects/")
    }
    expected_objects: dict[str, tuple[int, str]] = {}
    for artifact in raw_outputs["artifacts"]:
        if artifact["storage"] != "OBJECT":
            continue
        path = artifact["object_path"]
        binding = (artifact["byte_length"], artifact["sha256"])
        prior = expected_objects.get(path)
        if prior is not None and prior != binding:
            raise RunBundleContractError(
                "raw artifacts conflict on one object binding"
            )
        expected_objects[path] = binding
    if set(indexed_objects) != set(expected_objects):
        raise RunBundleContractError(
            "bundle object binding has missing or unreferenced objects"
        )
    for path, (byte_length, digest) in expected_objects.items():
        row = indexed_objects[path]
        if row["byte_length"] != byte_length or row["sha256"] != digest:
            raise RunBundleContractError(
                "bundle object binding digest/length is invalid"
            )


def _validate_bundle_native_phase_bindings(
    manifest: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    candidates: Mapping[str, Any],
    lineage: Mapping[str, Any],
    raw_outputs: Mapping[str, Any],
) -> None:
    """Bind every phase-bearing row to the exact evaluator-owned native map."""

    phase_map = manifest["phase_map"]
    native_macros = _pinned_native_phase_macros(phase_map)
    complete = manifest["completion"]["state"] == "COMPLETE"

    def validate_native(
        native_phase: str,
        macro_phase: str | None,
        *,
        context: str,
    ) -> None:
        expected_macro = native_macros.get(native_phase)
        if expected_macro is None:
            if complete:
                raise RunBundleContractError(
                    f"{context} has an unknown native phase in a COMPLETE bundle"
                )
            if macro_phase is not None and macro_phase != "UNMAPPED":
                raise RunBundleContractError(
                    f"{context} unknown native phase must be explicitly "
                    "UNMAPPED in a degraded bundle"
                )
            return
        if macro_phase is not None and macro_phase != expected_macro:
            raise RunBundleContractError(
                f"{context} native phase does not bind its pinned macro phase"
            )

    for index, event in enumerate(events):
        validate_native(
            event["native_phase"],
            event["macro_phase"],
            context=f"phase event {index}",
        )
    for index, artifact in enumerate(raw_outputs["artifacts"]):
        validate_native(
            artifact["native_phase"],
            artifact["macro_phase"],
            context=f"raw artifact {index}",
        )
    for index, candidate in enumerate(candidates["candidates"]):
        native_phase = candidate["producer"]["native_phase"]
        validate_native(
            native_phase,
            None,
            context=f"candidate producer {index}",
        )
        if (
            native_phase in native_macros
            and not _phase_maps.native_phase_allows_semantic_output(
                str(phase_map["pipeline_kind"]),
                native_phase,
            )
        ):
            raise RunBundleContractError(
                f"candidate producer {index} cannot use a CONTROL native phase"
            )
    for index, occurrence in enumerate(lineage["occurrences"]):
        validate_native(
            occurrence["native_phase"],
            occurrence["macro_phase"],
            context=f"lineage occurrence {index}",
        )
        if occurrence["macro_phase"] == "CONTROL":
            raise RunBundleContractError(
                f"lineage occurrence {index} cannot use a CONTROL phase"
            )
    for index, disposition in enumerate(lineage["negative_dispositions"]):
        validate_native(
            disposition["native_phase"],
            disposition["macro_phase"],
            context=f"negative disposition {index}",
        )
        if disposition["macro_phase"] == "CONTROL":
            raise RunBundleContractError(
                f"negative disposition {index} cannot use a CONTROL phase"
            )


def _validate_phase_event_native_order(
    manifest: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> None:
    native_order = _pinned_native_phase_order(manifest["phase_map"])
    for index, event in enumerate(events):
        event_rank = native_order.get(event["native_phase"])
        if event_rank is None:
            continue
        for field in ("source_artifact_ids", "input_artifact_ids"):
            for artifact_id in event[field]:
                artifact = artifacts.get(artifact_id)
                if artifact is None:
                    continue
                artifact_rank = native_order.get(artifact["native_phase"])
                if artifact_rank is not None and artifact_rank > event_rank:
                    raise RunBundleContractError(
                        f"phase event {index} consumes a future artifact "
                        "against pinned native phase order"
                    )
        for artifact_id in event["output_artifact_ids"]:
            artifact = artifacts.get(artifact_id)
            if artifact is None:
                continue
            artifact_rank = native_order.get(artifact["native_phase"])
            if artifact_rank is not None and artifact_rank < event_rank:
                raise RunBundleContractError(
                    f"phase output {index} commits backward against pinned "
                    "native phase order"
                )


_CONTROL_ONLY_PRODUCER_KINDS = frozenset(
    {"PLAMEN_PLANNING_CONTROL", "PLAMEN_HANDOFF_CONTROL"}
)
_COMMITTED_EVENT_TYPES = frozenset(
    {"OUTPUTS_COMMITTED", "REPORT_FINALIZED"}
)
def _validate_semantic_event_coverage(
    manifest: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    candidates: Mapping[str, Any],
    lineage: Mapping[str, Any],
    raw_outputs: Mapping[str, Any],
    report: Mapping[str, Any],
) -> None:
    """Require exact committed-event provenance for semantic artifacts."""

    artifacts = {
        artifact["artifact_id"]: artifact
        for artifact in raw_outputs["artifacts"]
    }
    relation_uses: dict[str, list[tuple[Mapping[str, Any], str]]] = {}
    for event in events:
        for relation in event["artifact_relations"]:
            artifact_id = relation["artifact_id"]
            if artifact_id not in artifacts:
                raise RunBundleContractError(
                    "phase event artifact relation binding is invalid"
                )
            relation_uses.setdefault(artifact_id, []).append(
                (event, relation["relation"])
            )

    for artifact_id, artifact in artifacts.items():
        if artifact["producer_kind"] not in _CONTROL_ONLY_PRODUCER_KINDS:
            continue
        uses = relation_uses.get(artifact_id, [])
        if not uses or any(relation != "CONTROL" for _, relation in uses):
            raise RunBundleContractError(
                "planning/handoff artifact requires only explicit typed "
                "CONTROL relations"
            )

    semantic_artifact_ids: set[str] = {
        candidate["producer"]["artifact_id"]
        for candidate in candidates["candidates"]
    }
    for disposition in lineage["negative_dispositions"]:
        semantic_artifact_ids.update(
            reference.split("#", 1)[0]
            for reference in disposition["evidence_refs"]
            if isinstance(reference, str) and reference.count("#") == 1
        )
    semantic_artifact_ids.update(
        occurrence["artifact_id"] for occurrence in lineage["occurrences"]
    )
    semantic_artifact_ids.add(report["final_report_artifact_id"])
    semantic_artifact_ids.update(
        artifact_id
        for artifact_id, artifact in artifacts.items()
        if artifact["producer_kind"] == "FINAL_REPORT"
    )

    for artifact_id in semantic_artifact_ids:
        artifact = artifacts.get(artifact_id)
        if artifact is None:
            raise RunBundleContractError(
                "semantic artifact event coverage references an unknown artifact"
            )
        if artifact["macro_phase"] == "CONTROL":
            raise RunBundleContractError(
                "CONTROL phases cannot carry semantic artifacts"
            )
        committed_outputs = [
            event
            for event, relation in relation_uses.get(artifact_id, [])
            if relation == "OUTPUT"
            and event["event_type"] in _COMMITTED_EVENT_TYPES
        ]
        if len(committed_outputs) != 1:
            raise RunBundleContractError(
                "semantic artifact must be covered by exactly one committed "
                "phase event"
            )
        event = committed_outputs[0]
        if (
            event["run_id"] != manifest["run_id"]
            or event["attempt"] != manifest["resume"]["attempt"]
            or event["macro_phase"] == "CONTROL"
            or event["native_phase"] != artifact["native_phase"]
            or event["macro_phase"] != artifact["macro_phase"]
            or event["work_unit_id"] != artifact["work_unit_id"]
            or event["commit_state"] != artifact["commit_state"]
            or event["commit_state"] not in {"CLEAN", "DEGRADED"}
        ):
            raise RunBundleContractError(
                "semantic artifact event coverage has no matching "
                "run/attempt/phase/work-unit/commit provenance"
            )


def validate_bundle_payload_set(
    documents: Mapping[str, Any],
    public_case_lock: Mapping[str, Any],
    *,
    object_bytes: Mapping[str, bytes] | None = None,
) -> Mapping[str, Any]:
    """Validate all seven public payloads and their exact cross-bindings."""

    documents = _exact_json_snapshot(
        documents,
        context="RunBundle payload set",
    )
    if type(documents) is not dict:
        raise RunBundleContractError(
            "RunBundle payload set must use an exact built-in JSON object"
        )
    if set(documents) != PUBLIC_PAYLOAD_FILE_NAMES:
        raise RunBundleContractError(
            "RunBundle payload set has missing or unknown file names"
        )
    manifest = validate_run_manifest(documents["run_manifest.json"])
    public_case_lock = validate_public_case_lock(public_case_lock)
    validate_public_case_lock_binding(manifest, public_case_lock)
    rag_exposure = manifest["blinding"]["rag_exposure"]
    rag_policy = manifest["tool_policy"]["rag_policy"]
    rag_allowed = public_case_lock["capability_flags"]["rag_allowed"]
    if (
        rag_exposure == "NONE"
        and rag_policy != "DISABLED"
    ) or (
        rag_exposure == "PUBLIC_ONLY"
        and (rag_policy != "PUBLIC_ONLY" or rag_allowed is not True)
    ):
        raise RunBundleContractError(
            "RAG exposure contradicts signed tool policy or public case lock"
        )
    events = validate_phase_events(documents["phase_events.jsonl"])
    candidates = validate_candidate_set(documents["candidate_findings.json"])
    lineage = validate_candidate_lineage(documents["candidate_lineage.json"])
    raw_outputs = validate_raw_output_index(documents["raw_outputs.json"])
    report = validate_report_projection(documents["report_projection.json"])
    receipt = validate_harvest_receipt(documents["harvest_receipt.json"])
    documents = {
        "run_manifest.json": manifest,
        "phase_events.jsonl": events,
        "candidate_findings.json": candidates,
        "candidate_lineage.json": lineage,
        "raw_outputs.json": raw_outputs,
        "report_projection.json": report,
        "harvest_receipt.json": receipt,
    }

    run_id = manifest["run_id"]
    for context, row in (
        ("candidate set", candidates),
        ("candidate lineage", lineage),
        ("raw output index", raw_outputs),
        ("report projection", report),
        ("harvest receipt", receipt),
    ):
        if row["run_id"] != run_id:
            raise RunBundleContractError(f"{context} run_id binding is invalid")
    for event in events:
        if event["run_id"] != run_id:
            raise RunBundleContractError("phase event run_id binding is invalid")

    authenticated_profile = manifest["trust_profile"] in B1_TRUST_PROFILES
    if authenticated_profile:
        run_context_authority = _validate_signed_authority_receipt(
            manifest["run_context_authority"],
            public_case_lock["audit_authority"],
            context="embedded evaluator RUN_CONTEXT authority",
        )
        if (
            run_context_authority["authority_type"] != "RUN_CONTEXT"
            or run_context_authority["decision"] != "AUTHORIZED_RUN_CONTEXT"
            or set(run_context_authority["subject_ids"])
            != {
                manifest["run_id"],
                manifest["case_id"],
                manifest["experiment_id"],
                manifest["cell_id"],
            }
            or run_context_authority["source_artifact_ids"]
            or run_context_authority["decision_payload"]
            != run_context_commitment_payload(manifest)
        ):
            raise RunBundleContractError(
                "signed evaluator RUN_CONTEXT does not exactly bind the run context"
            )
    else:
        run_context_authority = None

    artifacts = {
        artifact["artifact_id"]: artifact
        for artifact in raw_outputs["artifacts"]
    }
    _validate_bundle_native_phase_bindings(
        manifest,
        events,
        candidates,
        lineage,
        raw_outputs,
    )
    _validate_semantic_event_coverage(
        manifest,
        events,
        candidates,
        lineage,
        raw_outputs,
        report,
    )
    if object_bytes is not None:
        if type(object_bytes) is not dict or any(
            type(path) is not str or type(raw) is not bytes
            for path, raw in object_bytes.items()
        ):
            raise RunBundleContractError(
                "physical object bytes mapping is invalid"
            )
        object_bytes = dict(object_bytes)
        expected_object_paths = {
            artifact["object_path"]
            for artifact in artifacts.values()
            if artifact["storage"] == "OBJECT"
        }
        if set(object_bytes) != expected_object_paths:
            raise RunBundleContractError(
                "physical object bytes do not exactly bind raw object rows"
            )
        for artifact in artifacts.values():
            if artifact["storage"] != "OBJECT":
                continue
            raw = object_bytes[artifact["object_path"]]
            if (
                len(raw) != artifact["byte_length"]
                or sha256_bytes(raw) != artifact["sha256"]
            ):
                raise RunBundleContractError(
                    "physical object digest/length binding is invalid"
                )
            try:
                _privacy.validate_public_object_bytes(
                    raw,
                    media_type=artifact["media_type"],
                )
            except _privacy.RunBundlePrivacyError as exc:
                raise RunBundleContractError(
                    "referenced public object privacy validation failed"
                ) from exc
    records: dict[str, str] = {}
    for artifact_id, artifact in artifacts.items():
        for record_id in artifact["record_ids"]:
            if record_id in records:
                raise RunBundleContractError(
                    "raw output record identity is duplicated across artifacts"
                )
            records[record_id] = artifact_id
    if authenticated_profile:
        authority_receipts = _load_authority_receipts(
            raw_outputs,
            artifacts,
            records,
            object_bytes,
            public_case_lock,
        )
    else:
        if raw_outputs["authority_receipts"]:
            raise RunBundleContractError(
                "USER_RUN/B0_LOCAL authority receipt index must be empty; "
                "unsigned integrity artifacts remain raw evidence only"
            )
        authority_receipts = {}
    raw_authority_receipt_ids = set(authority_receipts)
    receipt_definition_ids = [
        *raw_authority_receipt_ids,
        public_case_lock["allocation_authority"]["receipt_id"],
    ]
    if run_context_authority is not None:
        receipt_definition_ids.append(run_context_authority["receipt_id"])
    _validate_receipt_identity_namespace(
        receipt_definition_ids,
        manifest=manifest,
        public_case_lock=public_case_lock,
        events=events,
        candidates=candidates,
        lineage=lineage,
        artifacts=artifacts,
        records=records,
        raw_authority_receipt_ids=raw_authority_receipt_ids,
        authority_receipts=authority_receipts,
        report=report,
    )

    for event in events:
        for field in (
            "source_artifact_ids",
            "input_artifact_ids",
            "output_artifact_ids",
        ):
            if not set(event[field]).issubset(artifacts):
                raise RunBundleContractError(
                    f"phase event {field} artifact reference binding is invalid"
                )
        if authenticated_profile:
            _require_typed_authority(
                authority_receipts,
                event["source_receipt_id"],
                "PHASE_OUTPUT",
                subjects=(event["event_id"], event["work_unit_id"]),
                source_artifact_ids=event["source_artifact_ids"],
                decision=event["event_type"],
                decision_payload=_phase_output_payload(event, artifacts),
                context="phase event source receipt payload",
            )
        elif (
            event["source_receipt_id"] != UNAUTHENTICATED_AUTHORITY
            or event["evidence_quality"]
            not in {"UNAUTHENTICATED", "PARSED", "UNKNOWN"}
        ):
            raise RunBundleContractError(
                "USER_RUN/B0_LOCAL phase event must be explicitly "
                "UNAUTHENTICATED_PARSE and cannot claim authenticated evidence"
            )
    _validate_phase_event_native_order(manifest, events, artifacts)
    measurement_refs = manifest["budget"]["measurement_receipt_refs"]
    measurement_summary_ref = manifest["budget"][
        "measurement_summary_receipt_ref"
    ]
    observed_measurement_refs = {
        receipt_id
        for receipt_id, authority in authority_receipts.items()
        if authority["authority_type"] == "RESOURCE_MEASUREMENT"
    }
    observed_measurement_summaries = {
        receipt_id
        for receipt_id, authority in authority_receipts.items()
        if authority["authority_type"] == "RESOURCE_MEASUREMENT_SUMMARY"
    }
    if authenticated_profile:
        if (
            observed_measurement_refs != set(measurement_refs)
            or observed_measurement_summaries != {measurement_summary_ref}
            or not measurement_refs
            or measurement_summary_ref is None
        ):
            raise RunBundleContractError(
                "B1 measurement authority inventory does not exactly match "
                "the signed nonempty receipt roster and summary"
            )
        measurement_summary = _require_typed_authority(
            authority_receipts,
            measurement_summary_ref,
            "RESOURCE_MEASUREMENT_SUMMARY",
            subjects=(run_id, *measurement_refs),
            source_artifact_ids=(),
            decision="SUMMARIZED",
            decision_payload=_measurement_summary_decision_payload(manifest),
            context="measurement summary",
        )
        if set(measurement_summary["subject_ids"]) != {
            run_id,
            *measurement_refs,
        }:
            raise RunBundleContractError(
                "measurement summary subject roster is not exact"
            )
        for receipt_ref in measurement_refs:
            measurement_receipt = _require_typed_authority(
                authority_receipts,
                receipt_ref,
                "RESOURCE_MEASUREMENT",
                subjects=(run_id,),
                source_artifact_ids=(),
                decision="MEASURED",
                decision_payload=_measurement_receipt_decision_payload(manifest),
                context="budget measurement receipt",
            )
            if set(measurement_receipt["subject_ids"]) != {run_id}:
                raise RunBundleContractError(
                    "budget measurement receipt subject binding is not exact"
                )
    elif (
        measurement_refs
        or measurement_summary_ref is not None
        or observed_measurement_refs
        or observed_measurement_summaries
    ):
        raise RunBundleContractError(
            "USER_RUN/B0_LOCAL cannot claim authenticated measurement receipts"
        )

    candidate_ids = {
        candidate["candidate_id"] for candidate in candidates["candidates"]
    }
    candidate_by_id = {
        candidate["candidate_id"]: candidate
        for candidate in candidates["candidates"]
    }
    occurrence_ids = {
        occurrence["occurrence_id"] for occurrence in lineage["occurrences"]
    }
    occurrence_by_id = {
        occurrence["occurrence_id"]: occurrence
        for occurrence in lineage["occurrences"]
    }
    for candidate in candidates["candidates"]:
        first_occurrence = occurrence_by_id.get(candidate["first_occurrence_id"])
        if (
            first_occurrence is None
            or first_occurrence["candidate_id"] != candidate["candidate_id"]
        ):
            raise RunBundleContractError(
                "candidate first occurrence binding is invalid"
            )
        producer = candidate["producer"]
        producer_artifact = artifacts.get(producer["artifact_id"])
        if (
            producer_artifact is None
            or records.get(producer["record_id"]) != producer["artifact_id"]
        ):
            raise RunBundleContractError(
                "candidate producer artifact/record binding is invalid"
            )
        if (
            producer["native_phase"] != producer_artifact["native_phase"]
            or producer["work_unit_id"] != producer_artifact["work_unit_id"]
        ):
            raise RunBundleContractError(
                "candidate producer phase/work-unit binding is invalid"
            )
        if (
            first_occurrence["artifact_id"] != producer["artifact_id"]
            or first_occurrence["record_id"] != producer["record_id"]
            or first_occurrence["native_phase"] != producer["native_phase"]
        ):
            raise RunBundleContractError(
                "candidate first-occurrence/producer record binding is invalid"
            )
        if producer["adapter_id"] != manifest["adapter"]["adapter_id"]:
            raise RunBundleContractError(
                "candidate producer adapter binding is invalid"
            )
        for location in candidate["locations"]:
            if location["source_record_id"] not in records:
                raise RunBundleContractError(
                    "candidate location record reference binding is invalid"
                )
        for reference in candidate["evidence_refs"]:
            _require_evidence_reference(
                reference,
                artifacts,
                records,
                context="candidate evidence",
            )
        severity_authority = candidate["audit_severity"]["authority_receipt_id"]
        if severity_authority is not None:
            if authenticated_profile:
                _require_typed_authority(
                    authority_receipts,
                    severity_authority,
                    "SEVERITY_DECISION",
                    subjects=(candidate["candidate_id"],),
                    decision=candidate["audit_severity"]["label"],
                    payload_row=(
                        "rows",
                        {
                            "candidate_id": candidate["candidate_id"],
                            "severity": candidate["audit_severity"]["label"],
                        },
                    ),
                    context="candidate severity authority",
                )
            elif severity_authority != UNAUTHENTICATED_AUTHORITY:
                raise RunBundleContractError(
                    "USER_RUN/B0_LOCAL severity must be explicitly "
                    "UNAUTHENTICATED_PARSE"
                )
    for occurrence in lineage["occurrences"]:
        if occurrence["candidate_id"] not in candidate_ids:
            raise RunBundleContractError(
                "lineage occurrence candidate binding is invalid"
            )
        artifact = artifacts.get(occurrence["artifact_id"])
        if (
            artifact is None
            or records.get(occurrence["record_id"]) != occurrence["artifact_id"]
        ):
            raise RunBundleContractError(
                "lineage occurrence artifact/record binding is invalid"
            )
        if (
            occurrence["native_phase"] != artifact["native_phase"]
            or occurrence["macro_phase"] != artifact["macro_phase"]
        ):
            raise RunBundleContractError(
                "lineage occurrence phase binding is invalid"
            )
        if artifact["storage"] == "INLINE_UTF8":
            raw = artifact["content"].encode("utf-8")
        else:
            if object_bytes is None:
                raise RunBundleContractError(
                    "OBJECT occurrence requires exact physical object bytes"
                )
            raw = object_bytes[artifact["object_path"]]
        start = occurrence["byte_range"]["start"]
        end = occurrence["byte_range"]["end"]
        if end > len(raw) or sha256_bytes(raw[start:end]) != occurrence[
            "record_sha256"
        ]:
            raise RunBundleContractError(
                "lineage occurrence byte-range digest binding is invalid"
            )
        for location in occurrence["location_snapshot"]:
            if location["source_record_id"] not in records:
                raise RunBundleContractError(
                    "occurrence location record reference binding is invalid"
                )
        for reference in occurrence["evidence_refs"]:
            _require_evidence_reference(
                reference,
                artifacts,
                records,
                context="occurrence evidence",
            )
        if occurrence["authority_ref"] != UNAUTHENTICATED_AUTHORITY:
            if not authenticated_profile:
                raise RunBundleContractError(
                    "USER_RUN/B0_LOCAL occurrence authority must be "
                    "UNAUTHENTICATED_PARSE"
                )
            _require_typed_authority(
                authority_receipts,
                occurrence["authority_ref"],
                "CANDIDATE_EMISSION",
                subjects=(
                    occurrence["candidate_id"],
                    occurrence["occurrence_id"],
                    occurrence["artifact_id"],
                    occurrence["record_id"],
                ),
                source_artifact_ids=(occurrence["artifact_id"],),
                decision=occurrence["state"],
                payload_row=(
                    "occurrences",
                    {
                        "candidate_id": occurrence["candidate_id"],
                        "occurrence_id": occurrence["occurrence_id"],
                        "state": occurrence["state"],
                        "artifact_id": occurrence["artifact_id"],
                        "record_id": occurrence["record_id"],
                        "byte_range": {
                            "start": occurrence["byte_range"]["start"],
                            "end": occurrence["byte_range"]["end"],
                        },
                        "record_sha256": occurrence["record_sha256"],
                        "producer_kind": artifact["producer_kind"],
                        "source_contract_ref": artifact["source_contract_ref"],
                    },
                ),
                context="occurrence authority",
            )

    alias_class_ids = _validate_alias_replay(lineage, candidate_ids)
    applied_alias_edge_ids = {
        edge_id
        for alias_class in lineage["alias_classes"]
        for edge_id in alias_class["applied_edge_ids"]
    }
    for edge in lineage["edges"]:
        authority = edge["authority_receipt_id"]
        if authority is not None:
            if not authenticated_profile:
                raise RunBundleContractError(
                    "USER_RUN/B0_LOCAL cannot claim an authenticated effective "
                    "alias; preserve it as proposal/debt"
                )
            subjects = [
                edge["edge_id"],
                edge["source_candidate_id"],
                edge["target_candidate_id"],
            ]
            if edge["survivor_candidate_id"] is not None:
                subjects.append(edge["survivor_candidate_id"])
            _require_typed_authority(
                authority_receipts,
                authority,
                "ALIAS_DECISION",
                subjects=subjects,
                decision=edge["edge_type"],
                payload_row=(
                    "edges",
                    {
                        "edge_id": edge["edge_id"],
                        "edge_type": edge["edge_type"],
                        "source_candidate_id": edge["source_candidate_id"],
                        "target_candidate_id": edge["target_candidate_id"],
                        "survivor_candidate_id": edge["survivor_candidate_id"],
                        "direction": "SOURCE_TO_TARGET",
                        "effective": edge["effective"],
                        "applied": edge["edge_id"] in applied_alias_edge_ids,
                    },
                ),
                context="lineage alias direction payload authority",
            )
    terminal_safe_candidates: set[str] = set()
    native_phase_order = _pinned_native_phase_order(manifest["phase_map"])
    for disposition in lineage["negative_dispositions"]:
        candidate_id = disposition["candidate_id"]
        occurrence = occurrence_by_id.get(disposition["occurrence_id"])
        if (
            candidate_id not in candidate_ids
            or occurrence is None
            or occurrence["candidate_id"] != candidate_id
        ):
            raise RunBundleContractError(
                "negative disposition candidate/occurrence binding is invalid"
            )
        for reference in disposition["evidence_refs"]:
            _require_evidence_reference(
                reference,
                artifacts,
                records,
                context="negative disposition evidence",
            )
        superseding = disposition["superseding_occurrence_id"]
        if superseding is not None and (
            superseding not in occurrence_by_id
            or occurrence_by_id[superseding]["candidate_id"] != candidate_id
        ):
            raise RunBundleContractError(
                "negative disposition superseding occurrence binding is invalid"
            )
        ordering_basis = "PINNED_NATIVE_PHASE_MAP"
        if disposition["kind"] == "SAFE" and disposition["terminal"]:
            terminal_safe_candidates.add(candidate_id)
            superseding_occurrence = (
                occurrence_by_id.get(superseding)
                if superseding is not None
                else None
            )
            try:
                disposition_rank = native_phase_order[
                    disposition["native_phase"]
                ]
                positive_rows = [
                    item
                    for item in lineage["occurrences"]
                    if item["candidate_id"] == candidate_id
                    and item["state"] == "POSITIVE"
                ]
                later_positive = any(
                    native_phase_order[item["native_phase"]]
                    > disposition_rank
                    for item in positive_rows
                )
                same_native_positive = [
                    item
                    for item in positive_rows
                    if native_phase_order[item["native_phase"]]
                    == disposition_rank
                ]
            except KeyError as exc:
                raise RunBundleContractError(
                    "terminal SAFE native phase is absent from the pinned "
                    "phase map"
                ) from exc
            if (
                superseding_occurrence is not None
                and superseding_occurrence["state"] == "POSITIVE"
            ) or later_positive:
                raise RunBundleContractError(
                    "terminal SAFE disposition has an ordered superseding "
                    "POSITIVE contradiction"
                )
            if same_native_positive:
                ordering_debts = [
                    debt
                    for debt in lineage["lineage_debts"]
                    if debt["debt_code"] == "PHASE_ORDER_AMBIGUITY"
                    and candidate_id in debt["candidate_ids"]
                    and any(
                        item["occurrence_id"] in debt["occurrence_ids"]
                        for item in same_native_positive
                    )
                ]
                if len(ordering_debts) != 1:
                    raise RunBundleContractError(
                        "terminal SAFE in the same native phase requires one "
                        "typed ordering debt"
                    )
                ordering_basis = (
                    "EXPLICIT_DEBT:" + ordering_debts[0]["debt_id"]
                )
        if authenticated_profile:
            _require_typed_authority(
                authority_receipts,
                disposition["authority_receipt_id"],
                "NEGATIVE_DISPOSITION",
                subjects=(
                    candidate_id,
                    disposition["occurrence_id"],
                    disposition["disposition_id"],
                ),
                decision=disposition["kind"],
                payload_row=(
                    "dispositions",
                    {
                        "disposition_id": disposition["disposition_id"],
                        "kind": disposition["kind"],
                        "candidate_id": candidate_id,
                        "occurrence_id": disposition["occurrence_id"],
                        "native_phase": disposition["native_phase"],
                        "macro_phase": disposition["macro_phase"],
                        "terminal": disposition["terminal"],
                        "superseding_occurrence_id": superseding,
                        "ordering_basis": ordering_basis,
                    },
                ),
                context="terminal SAFE negative disposition ordering payload",
            )
        elif disposition["authority_receipt_id"] != UNAUTHENTICATED_AUTHORITY:
            raise RunBundleContractError(
                "USER_RUN/B0_LOCAL negative disposition must be explicitly "
                "UNAUTHENTICATED_PARSE and is never proof-grade wrong-safe"
            )
    for debt_row in lineage["lineage_debts"]:
        if (
            not set(debt_row["candidate_ids"]).issubset(candidate_ids)
            or not set(debt_row["occurrence_ids"]).issubset(occurrence_by_id)
        ):
            raise RunBundleContractError(
                "lineage debt reference binding is invalid"
            )
        for authority_ref in debt_row["authority_refs"]:
            if not authenticated_profile:
                if authority_ref != UNAUTHENTICATED_AUTHORITY:
                    raise RunBundleContractError(
                        "USER_RUN/B0_LOCAL lineage debt authority must be "
                        "UNAUTHENTICATED_PARSE"
                    )
                continue
            _require_typed_authority(
                authority_receipts,
                authority_ref,
                "LINEAGE_DEBT",
                subjects=(
                    debt_row["debt_id"],
                    *debt_row["candidate_ids"],
                    *debt_row["occurrence_ids"],
                ),
                decision=debt_row["debt_code"],
                payload_row=(
                    "debts",
                    {
                        "debt_id": debt_row["debt_id"],
                        "debt_code": debt_row["debt_code"],
                        "candidate_ids": debt_row["candidate_ids"],
                        "occurrence_ids": debt_row["occurrence_ids"],
                    },
                ),
                context="lineage debt authority",
            )

    final_artifact = artifacts.get(report["final_report_artifact_id"])
    if (
        final_artifact is None
        or final_artifact["sha256"] != report["final_report_sha256"]
        or final_artifact["byte_length"] != report["final_report_byte_length"]
    ):
        raise RunBundleContractError(
            "final report artifact digest/length binding is invalid"
        )
    if final_artifact["storage"] == "INLINE_UTF8":
        final_report_raw = final_artifact["content"].encode("utf-8")
    else:
        if object_bytes is None:
            raise RunBundleContractError(
                "OBJECT final report requires exact physical object bytes"
            )
        final_report_raw = object_bytes[final_artifact["object_path"]]
    for entry in report["report_entries"] + report["appendix_entries"]:
        if not set(entry["candidate_ids"]).issubset(candidate_ids):
            raise RunBundleContractError(
                "report entry candidate binding is invalid"
            )
        alias_class_id = entry["audit_alias_class_id"]
        if alias_class_id is not None and alias_class_id not in alias_class_ids:
            raise RunBundleContractError(
                "report entry alias class binding is invalid"
            )
        if not set(entry["evidence_record_refs"]).issubset(records):
            raise RunBundleContractError(
                "report entry evidence record reference binding is invalid"
            )
        start = entry["byte_range"]["start"]
        end = entry["byte_range"]["end"]
        if (
            end > len(final_report_raw)
            or sha256_bytes(final_report_raw[start:end])
            != entry["byte_range_sha256"]
        ):
            raise RunBundleContractError(
                "report entry byte-range digest binding is invalid"
            )
        for candidate_id in entry["candidate_ids"]:
            if (
                candidate_by_id[candidate_id]["audit_severity"]["label"]
                != entry["asserted_severity"]
            ):
                raise RunBundleContractError(
                    "report asserted severity does not bind candidate authority"
                )
    mapped_report_candidate_ids = {
        candidate_id
        for entry in report["report_entries"] + report["appendix_entries"]
        for candidate_id in entry["candidate_ids"]
    }
    unmapped_candidate_ids: set[str] = set()
    unmapped_first_occurrence_ids: set[str] = set()
    for entry in report["unmapped_finding_sections"]:
        promoted_candidate_id = entry["promoted_candidate_id"]
        promoted_candidate = candidate_by_id.get(promoted_candidate_id)
        if (
            promoted_candidate is None
            or promoted_candidate_id in mapped_report_candidate_ids
            or promoted_candidate_id in unmapped_candidate_ids
        ):
            raise RunBundleContractError(
                "unmapped report section must promote a unique unmapped candidate"
            )
        first_occurrence_id = promoted_candidate["first_occurrence_id"]
        first_occurrence = occurrence_by_id.get(first_occurrence_id)
        if (
            first_occurrence is None
            or first_occurrence_id in unmapped_first_occurrence_ids
            or first_occurrence["authority_ref"] != "UNAUTHENTICATED_PARSE"
            or first_occurrence["state"] != "UNKNOWN"
            or first_occurrence["role"] not in {"REPORT_BODY", "FINAL_REPORT"}
            or first_occurrence["artifact_id"]
            != report["final_report_artifact_id"]
            or first_occurrence["byte_range"] != entry["byte_range"]
            or first_occurrence["record_sha256"]
            != entry["byte_range_sha256"]
            or entry["debt_code"]
            not in promoted_candidate["quality"]["debts"]
            or promoted_candidate["quality"]["parse_completeness"] != "PARTIAL"
        ):
            raise RunBundleContractError(
                "unmapped report first occurrence lacks exact report-range "
                "UNAUTHENTICATED_PARSE debt"
            )
        matching_debts = [
            debt
            for debt in lineage["lineage_debts"]
            if debt["debt_code"] == entry["debt_code"]
            and promoted_candidate_id in debt["candidate_ids"]
            and first_occurrence_id in debt["occurrence_ids"]
        ]
        if len(matching_debts) != 1:
            raise RunBundleContractError(
                "unmapped report first occurrence parse debt is not unique"
            )
        unmapped_candidate_ids.add(promoted_candidate_id)
        unmapped_first_occurrence_ids.add(first_occurrence_id)
        start = entry["byte_range"]["start"]
        end = entry["byte_range"]["end"]
        if (
            end > len(final_report_raw)
            or sha256_bytes(final_report_raw[start:end])
            != entry["byte_range_sha256"]
        ):
            raise RunBundleContractError(
                "unmapped report byte-range digest binding is invalid"
            )
    dispositions = report["candidate_report_dispositions"]
    disposition_candidates = [
        disposition["candidate_id"] for disposition in dispositions
    ]
    if (
        len(disposition_candidates) != len(set(disposition_candidates))
        or set(disposition_candidates) != candidate_ids
    ):
        raise RunBundleContractError(
            "report disposition candidate binding is incomplete"
        )
    projected_statuses: dict[str, str] = {}
    for field, projected_entries in (
        ("report_entries", report["report_entries"]),
        ("appendix_entries", report["appendix_entries"]),
    ):
        for entry in projected_entries:
            raw_status = entry["report_status"]
            if field == "appendix_entries":
                expected_status = "APPENDIX"
                if raw_status != "APPENDIX":
                    raise RunBundleContractError(
                        "appendix entry status contradicts its projection"
                    )
            elif raw_status == "REPORTED":
                expected_status = "REPORTED"
            elif raw_status == "PARSE_DEBT":
                expected_status = "DEBT"
            elif raw_status == "WITHHELD_WITH_AUTHORITY":
                expected_status = "OMITTED_WITH_AUTHORITY"
            else:
                raise RunBundleContractError(
                    "report entry status contradicts its projection"
                )
            for candidate_id in entry["candidate_ids"]:
                prior = projected_statuses.get(candidate_id)
                if prior is not None and prior != expected_status:
                    raise RunBundleContractError(
                        "candidate has conflicting report projections"
                    )
                projected_statuses[candidate_id] = expected_status
    dispositions_by_candidate = {
        disposition["candidate_id"]: disposition["report_status"]
        for disposition in dispositions
    }
    for entry in report["unmapped_finding_sections"]:
        disposition = next(
            item
            for item in dispositions
            if item["candidate_id"] == entry["promoted_candidate_id"]
        )
        if (
            disposition["report_status"] != "DEBT"
            or disposition["debt_code"] != entry["debt_code"]
        ):
            raise RunBundleContractError(
                "unmapped report candidate lacks matching report parse debt"
            )
    for candidate_id, projected_status in projected_statuses.items():
        if dispositions_by_candidate[candidate_id] != projected_status:
            raise RunBundleContractError(
                "report disposition contradicts the actual projection"
            )
    for candidate_id, disposition_status in dispositions_by_candidate.items():
        if (
            candidate_id not in projected_statuses
            and disposition_status in {"REPORTED", "APPENDIX"}
        ):
            raise RunBundleContractError(
                "report disposition claims a projection that does not exist"
            )
        if (
            candidate_id in terminal_safe_candidates
            and disposition_status in {"REPORTED", "APPENDIX"}
        ):
            raise RunBundleContractError(
                "terminal SAFE disposition contradicts a REPORTED candidate"
            )
    for disposition in dispositions:
        if authenticated_profile:
            _require_typed_authority(
                authority_receipts,
                disposition["authority_receipt_id"],
                "REPORT_DISPOSITION",
                subjects=(disposition["candidate_id"],),
                decision=disposition["report_status"],
                payload_row=(
                    "rows",
                    {
                        "candidate_id": disposition["candidate_id"],
                        "report_status": disposition["report_status"],
                    },
                ),
                context="report disposition authority",
            )
        elif disposition["authority_receipt_id"] != UNAUTHENTICATED_AUTHORITY:
            raise RunBundleContractError(
                "USER_RUN/B0_LOCAL report disposition must be explicitly "
                "UNAUTHENTICATED_PARSE"
            )
    if authenticated_profile:
        report_quality_receipt = _require_typed_authority(
            authority_receipts,
            report["report_evidence_quality_receipt_ref"],
            "REPORT_QUALITY",
            subjects=(
                report["final_report_artifact_id"],
                *(
                    entry["report_entry_id"]
                    for entry in report["report_entries"] + report["appendix_entries"]
                ),
            ),
            source_artifact_ids=(report["final_report_artifact_id"],),
            decision=report["report_integrity_state"],
            context="report evidence quality SHIP receipt",
        )
        report_quality_payload = report_quality_receipt["decision_payload"]
        if (
            report_quality_payload.get("final_report_artifact_id")
            != report["final_report_artifact_id"]
            or report_quality_payload.get("report_integrity_state")
            != report["report_integrity_state"]
        ):
            raise RunBundleContractError(
                "report quality canonical payload header is invalid"
            )
        authorized_report_rows = report_quality_payload.get("report_entries")
        authorized_unmapped_rows = report_quality_payload.get("unmapped_entries")
        if not isinstance(authorized_report_rows, list) or not isinstance(
            authorized_unmapped_rows, list
        ):
            raise RunBundleContractError(
                "report quality canonical payload coverage is invalid"
            )
        for entry in report["report_entries"]:
            if (
                _report_projection_authority_row(
                    entry, projection_kind="REPORT"
                )
                not in authorized_report_rows
            ):
                raise RunBundleContractError(
                    "report quality payload does not cover a report entry"
                )
        for entry in report["appendix_entries"]:
            if (
                _report_projection_authority_row(
                    entry, projection_kind="APPENDIX"
                )
                not in authorized_report_rows
            ):
                raise RunBundleContractError(
                    "report quality payload does not cover an appendix entry"
                )
        for entry in report["unmapped_finding_sections"]:
            if (
                _report_projection_authority_row(
                    entry, projection_kind="UNMAPPED"
                )
                not in authorized_unmapped_rows
            ):
                raise RunBundleContractError(
                    "report quality payload does not cover an unmapped entry"
                )
    elif (
        report["report_evidence_quality_receipt_ref"]
        != UNAUTHENTICATED_AUTHORITY
    ):
        raise RunBundleContractError(
            "USER_RUN/B0_LOCAL report quality must be explicitly "
            "UNAUTHENTICATED_PARSE"
        )

    projected_alias_classes: dict[str, list[Mapping[str, Any]]] = {}
    projected_candidate_ids = {
        candidate_id
        for entry in report["report_entries"] + report["appendix_entries"]
        for candidate_id in entry["candidate_ids"]
    }
    for entry in report["report_entries"] + report["appendix_entries"]:
        alias_id = entry["audit_alias_class_id"]
        if alias_id is not None:
            projected_alias_classes.setdefault(alias_id, []).append(entry)
    for alias_class in lineage["alias_classes"]:
        alias_id = alias_class["alias_class_id"]
        survivor = alias_class["survivor_candidate_id"]
        eliminated = set(alias_class["candidate_ids"]) - {survivor}
        entries = projected_alias_classes.get(alias_id, [])
        if (
            len(entries) != 1
            or set(entries[0]["candidate_ids"]) != {survivor}
            or survivor not in projected_candidate_ids
            or eliminated & projected_candidate_ids
            or any(
                dispositions_by_candidate[candidate_id]
                != "OMITTED_WITH_AUTHORITY"
                for candidate_id in eliminated
            )
        ):
            raise RunBundleContractError(
                "applied alias identities are not conserved into report "
                "entries/dispositions"
            )
    if set(projected_alias_classes) != alias_class_ids:
        raise RunBundleContractError(
            "report alias class references are incomplete"
        )

    completion = manifest["completion"]
    export_state = receipt["export_status"]["state"]
    shipping = (
        report["delivery_state"] == "DELIVERED"
        and report["report_integrity_state"] == "SHIP"
    )
    if (
        export_state != completion["state"]
        or (
            completion["state"] == "COMPLETE"
            and (
                completion["checkpoint_state"] != "COMMITTED"
                or completion["final_report_gate_state"] != "PASSED"
                or not shipping
                or final_artifact["commit_state"] != "CLEAN"
            )
        )
        or (
            completion["final_report_gate_state"] == "PASSED"
            and not shipping
        )
        or (
            report["report_integrity_state"] == "SHIP"
            and (
                report["delivery_state"] != "DELIVERED"
                or completion["state"] != "COMPLETE"
            )
        )
    ):
        raise RunBundleContractError(
            "completion/delivery/SHIP/export states are inconsistent"
        )

    expected_rosters = {
        "candidate_roster": candidate_ids,
        "occurrence_roster": occurrence_ids,
        "edge_roster": {edge["edge_id"] for edge in lineage["edges"]},
        "report_entry_roster": {
            entry["report_entry_id"]
            for entry in report["report_entries"] + report["appendix_entries"]
        }
        | {
            entry["entry_id"]
            for entry in report["unmapped_finding_sections"]
        },
        "artifact_roster": {
            artifact["artifact_id"] for artifact in raw_outputs["artifacts"]
        },
    }
    for field, expected in expected_rosters.items():
        supplied = set(receipt[field]["ids"])
        if supplied != expected or receipt[field]["count"] != len(expected):
            raise RunBundleContractError(
                f"harvest receipt {field} binding is invalid"
            )
    if (
        receipt["source_snapshot"]["source_snapshot_sha256"]
        != manifest["source_snapshot_sha256"]
    ):
        raise RunBundleContractError(
            "harvest receipt source snapshot binding is invalid"
        )
    reconciliation = receipt["record_reconciliation"]
    occurrences_by_record: dict[str, list[Mapping[str, Any]]] = {}
    for occurrence in lineage["occurrences"]:
        occurrences_by_record.setdefault(
            occurrence["record_id"], []
        ).append(occurrence)
    occurrence_record_ids = set(occurrences_by_record)
    supplied_occurrence_record_ids = set(
        reconciliation["occurrence_record_ids"]
    )
    nonfinding_rows = reconciliation["authenticated_nonfinding_records"]
    nonfinding_record_ids = {item["record_id"] for item in nonfinding_rows}
    debt_rows = reconciliation["explicit_debt_records"]
    debt_record_ids = {item["record_id"] for item in debt_rows}
    partitions = (
        supplied_occurrence_record_ids,
        nonfinding_record_ids,
        debt_record_ids,
    )
    if (
        supplied_occurrence_record_ids != occurrence_record_ids
        or any(
            left & right
            for index, left in enumerate(partitions)
            for right in partitions[index + 1 :]
        )
        or set().union(*partitions) != set(records)
    ):
        raise RunBundleContractError(
            "harvest receipt record partition does not exactly replay every record"
        )
    ordered_nonfinding_ids = sorted(
        nonfinding_record_ids,
        key=lambda item: item.encode("utf-8"),
    )
    if authenticated_profile:
        nonfinding_authorities = [
            (receipt_id, authority)
            for receipt_id, authority in authority_receipts.items()
            if authority["authority_type"] == "NONFINDING_CLASSIFICATION"
        ]
        if len(nonfinding_authorities) != 1:
            raise RunBundleContractError(
                "NONFINDING authority inventory must contain exactly one "
                "partition classifier"
            )
        nonfinding_authority_id, _ = nonfinding_authorities[0]
        _require_typed_authority(
            authority_receipts,
            nonfinding_authority_id,
            "NONFINDING_CLASSIFICATION",
            subjects=ordered_nonfinding_ids,
            decision="NONFINDING",
            decision_payload={
                "classification": "PARTITIONED_NONFINDING",
                "record_ids": ordered_nonfinding_ids,
            },
            context="authenticated nonfinding record partition",
        )
    elif any(
        item["authority_receipt_id"] != UNAUTHENTICATED_AUTHORITY
        for item in nonfinding_rows + debt_rows
    ):
        raise RunBundleContractError(
            "USER_RUN/B0_LOCAL record partition rows must be explicitly "
            "UNAUTHENTICATED_PARSE"
        )
    occurrence_physical_rows: list[dict[str, Any]] = []
    for record_id, record_occurrences in occurrences_by_record.items():
        first = record_occurrences[0]
        physical_identity = (
            first["artifact_id"],
            first["byte_range"]["start"],
            first["byte_range"]["end"],
            first["record_sha256"],
        )
        if any(
            (
                occurrence["artifact_id"],
                occurrence["byte_range"]["start"],
                occurrence["byte_range"]["end"],
                occurrence["record_sha256"],
            )
            != physical_identity
            for occurrence in record_occurrences[1:]
        ):
            raise RunBundleContractError(
                "multi-claim record occurrences disagree on physical identity"
            )
        occurrence_physical_rows.append(
            _physical_record_occurrence(
                record_id=record_id,
                artifact=artifacts[first["artifact_id"]],
                byte_range=first["byte_range"],
                record_sha256=first["record_sha256"],
                occurrence_ids=(
                    occurrence["occurrence_id"]
                    for occurrence in record_occurrences
                ),
            )
        )
    occurrence_physical_rows.sort(
        key=lambda item: item["record_id"].encode("utf-8")
    )
    nonfinding_physical_rows: list[dict[str, Any]] = []
    for item in nonfinding_rows:
        nonfinding_physical_rows.append(
            _verify_physical_record_occurrence(
                item,
                artifacts,
                records,
                object_bytes,
                context="authenticated nonfinding partition",
            )
        )
    lineage_debt_ids = {item["debt_id"] for item in lineage["lineage_debts"]}
    debt_physical_rows: list[dict[str, Any]] = []
    for item in debt_rows:
        if item["record_id"] not in records or item["debt_id"] not in lineage_debt_ids:
            raise RunBundleContractError(
                "explicit debt record binding is invalid"
            )
        physical = _verify_physical_record_occurrence(
            item,
            artifacts,
            records,
            object_bytes,
            context="explicit debt partition",
        )
        debt_physical_rows.append({**physical, "debt_id": item["debt_id"]})
    nonfinding_physical_rows.sort(
        key=lambda item: item["record_id"].encode("utf-8")
    )
    debt_physical_rows.sort(key=lambda item: item["record_id"].encode("utf-8"))
    artifact_partition_rows = sorted(
        (
            _artifact_partition_binding(artifact)
            for artifact in artifacts.values()
        ),
        key=lambda item: item["artifact_id"].encode("utf-8"),
    )
    physical_rows = (
        occurrence_physical_rows
        + nonfinding_physical_rows
        + [
            {
                key: value
                for key, value in item.items()
                if key != "debt_id"
            }
            for item in debt_physical_rows
        ]
    )
    physical_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for item in physical_rows:
        physical_by_artifact.setdefault(item["artifact_id"], []).append(item)
    for artifact_id, artifact in artifacts.items():
        rows_for_artifact = sorted(
            physical_by_artifact.get(artifact_id, []),
            key=lambda item: (
                item["byte_range"]["start"],
                item["byte_range"]["end"],
                item["record_id"].encode("utf-8"),
            ),
        )
        if {item["record_id"] for item in rows_for_artifact} != set(
            artifact["record_ids"]
        ):
            raise RunBundleContractError(
                "physical partition does not bind the artifact record roster"
            )
        cursor = 0
        for item in rows_for_artifact:
            start = item["byte_range"]["start"]
            end = item["byte_range"]["end"]
            if start != cursor:
                failure = "overlap" if start < cursor else "coverage gap"
                raise RunBundleContractError(
                    f"physical partition has a duplicate/{failure}"
                )
            cursor = end
        if cursor != artifact["byte_length"]:
            raise RunBundleContractError(
                "physical partition does not completely cover artifact bytes"
            )
    if authenticated_profile:
        _validate_physical_authority_eligibility_coverage(
            raw_outputs,
            artifacts,
            physical_rows,
            object_bytes,
            authority_receipts,
        )
        partition_authority = _validate_signed_authority_receipt(
            reconciliation["partition_authority"],
            public_case_lock["audit_authority"],
            context="harvest record partition authority",
        )
        partition_authority_id = partition_authority["receipt_id"]
        _validate_receipt_identity_namespace(
            [*receipt_definition_ids, partition_authority_id],
            manifest=manifest,
            public_case_lock=public_case_lock,
            events=events,
            candidates=candidates,
            lineage=lineage,
            artifacts=artifacts,
            records=records,
            raw_authority_receipt_ids=raw_authority_receipt_ids,
            authority_receipts=authority_receipts,
            report=report,
        )
        if (
            partition_authority["authority_type"] != "RECORD_PARTITION"
            or partition_authority["decision"] != "EXACT_PARTITION"
            or set(partition_authority["subject_ids"]) != set(records)
            or any(
                item["authority_receipt_id"] != partition_authority_id
                for item in nonfinding_rows + debt_rows
            )
            or partition_authority["decision_payload"]
            != {
                "run_id": run_id,
                "artifacts": artifact_partition_rows,
                "occurrence_rows": occurrence_physical_rows,
                "nonfinding_rows": nonfinding_physical_rows,
                "debt_rows": debt_physical_rows,
            }
        ):
            raise RunBundleContractError(
                "harvest signed partition payload does not bind exact physical occurrences"
            )
        expected_report_physical_rows = sorted(
            [
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"occurrence_ids", "debt_id"}
                }
                for item in physical_rows
                if item["artifact_id"] == report["final_report_artifact_id"]
            ],
            key=lambda item: item["record_id"].encode("utf-8"),
        )
        supplied_report_physical_rows = report_quality_payload.get(
            "physical_occurrences"
        )
        if supplied_report_physical_rows != expected_report_physical_rows:
            raise RunBundleContractError(
                "report quality payload does not bind final-report physical occurrences"
            )
        if report_quality_payload.get(
            "final_report_artifact"
        ) != _artifact_partition_binding(final_artifact):
            raise RunBundleContractError(
                "report quality payload does not bind the full final-report artifact"
            )
    elif reconciliation["partition_authority"] is not None:
        raise RunBundleContractError(
            "USER_RUN/B0_LOCAL partition authority must be null"
        )
    expected_counts = {
        "discovered_count": len(records),
        "emitted_occurrence_count": len(supplied_occurrence_record_ids),
        "nonfinding_count": len(nonfinding_record_ids),
        "debt_count": len(debt_record_ids),
        "balanced": True,
    }
    supplied_counts = {
        key: reconciliation[key] for key in expected_counts
    }
    if supplied_counts != expected_counts:
        raise RunBundleContractError(
            "harvest receipt record counts do not match exact row replay"
        )
    actual_redactions = [
        redaction
        for artifact in raw_outputs["artifacts"]
        for redaction in artifact["redactions"]
    ]
    supplied_redactions = receipt["redaction_summary"]["entries"]
    canonical_sort = lambda item: canonical_json_bytes(item)
    if (
        receipt["redaction_summary"]["count"] != len(actual_redactions)
        or sorted(actual_redactions, key=canonical_sort)
        != sorted(supplied_redactions, key=canonical_sort)
    ):
        raise RunBundleContractError(
            "harvest receipt redaction count/content replay is invalid"
        )
    return documents


def verify_runbundle_v2(
    root: Path,
    exact_public_lock_bytes: bytes,
) -> RunBundleVerificationReceipt:
    """Verify one physical sealed v2 bundle from one immutable byte capture."""

    if not isinstance(exact_public_lock_bytes, bytes):
        raise RunBundleContractError(
            "public case lock must be supplied as exact canonical bytes"
        )
    public_case_lock = strict_json_loads(
        exact_public_lock_bytes, require_canonical=True
    )
    validate_public_case_lock(public_case_lock)
    try:
        _privacy.validate_public_payload(public_case_lock)
        snapshot = _privacy.read_verified_bundle_snapshot(Path(root))
    except _privacy.RunBundlePrivacyError as exc:
        raise RunBundleContractError(
            f"physical RunBundle verification failed: {exc}"
        ) from exc
    captured = dict(snapshot.files)
    if set(PUBLIC_PAYLOAD_FILE_NAMES) - set(captured):
        raise RunBundleContractError(
            "physical RunBundle is missing a required payload"
        )
    documents: dict[str, Any] = {}
    for relative in sorted(
        PUBLIC_PAYLOAD_FILE_NAMES, key=lambda item: item.encode("utf-8")
    ):
        raw = captured[relative]
        if relative == "phase_events.jsonl":
            document = strict_jsonl_loads(raw, require_canonical=True)
        else:
            document = strict_json_loads(raw, require_canonical=True)
        try:
            _privacy.validate_public_payload(document)
        except _privacy.RunBundlePrivacyError as exc:
            raise RunBundleContractError(
                f"public payload privacy validation failed for {relative}"
            ) from exc
        documents[relative] = document
    index = strict_json_loads(
        snapshot.bundle_index_bytes, require_canonical=True
    )
    raw_output_rows = [
        row
        for row in index["entries"]
        if row["relative_path"] == "raw_outputs.json"
    ]
    if len(raw_output_rows) != 1:
        raise RunBundleContractError(
            "bundle index must contain exactly one raw_outputs.json row"
        )
    object_bytes = {
        relative: raw
        for relative, raw in snapshot.files
        if relative.startswith("objects/sha256/")
    }
    validate_bundle_payload_set(
        documents,
        public_case_lock,
        object_bytes=object_bytes,
    )
    validate_bundle_object_bindings(
        documents["raw_outputs.json"],
        index,
    )
    try:
        _privacy.assert_verified_bundle_snapshot_unchanged(root, snapshot)
    except _privacy.RunBundlePrivacyError as exc:
        raise RunBundleContractError(
            "physical RunBundle changed during unified verification"
        ) from exc

    payload_digests = tuple(
        (
            relative,
            sha256_bytes(captured[relative]),
        )
        for relative in sorted(
            PUBLIC_PAYLOAD_FILE_NAMES, key=lambda item: item.encode("utf-8")
        )
    )
    object_digests = tuple(
        (relative, sha256_bytes(raw))
        for relative, raw in snapshot.files
        if relative.startswith("objects/sha256/")
    )
    manifest = documents["run_manifest.json"]
    receipt_body = {
        "bundle_profile": REAL_AUDIT_V2,
        "run_id": manifest["run_id"],
        "bundle_seal_sha256": snapshot.bundle_seal_sha256,
        "public_case_lock_sha256": sha256_bytes(exact_public_lock_bytes),
        "payload_digests": [
            {"relative_path": path, "sha256": digest}
            for path, digest in payload_digests
        ],
        "object_digests": [
            {"relative_path": path, "sha256": digest}
            for path, digest in object_digests
        ],
    }
    verification_sha256 = document_sha256(receipt_body)
    return RunBundleVerificationReceipt(
        bundle_profile=REAL_AUDIT_V2,
        run_id=manifest["run_id"],
        bundle_seal_sha256=snapshot.bundle_seal_sha256,
        public_case_lock_sha256=sha256_bytes(exact_public_lock_bytes),
        payload_digests=payload_digests,
        object_digests=object_digests,
        verification_sha256=verification_sha256,
        verified_files=snapshot.files,
        _authority=_VERIFICATION_RECEIPT_AUTHORITY,
    )


# Compatibility aliases for adjacent exporter slices.
canonical_bytes = canonical_json_bytes
load_strict_json = strict_json_load
validate_manifest = validate_run_manifest
validate_candidates = validate_candidate_set
validate_lineage = validate_candidate_lineage
validate_raw_outputs = validate_raw_output_index


__all__ = [
    "CANDIDATE_LINEAGE_SCHEMA",
    "CANDIDATE_SET_SCHEMA",
    "HARVEST_RECEIPT_SCHEMA",
    "MAX_JSON_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_NODES",
    "MAX_JSON_WIDTH",
    "B1_TRUST_PROFILES",
    "LOCAL_TRUST_PROFILES",
    "PRIVATE_CASE_LOCK_SCHEMA",
    "PUBLIC_CASE_LOCK_SCHEMA",
    "PUBLIC_FIELDS_BY_SCHEMA",
    "PUBLIC_PAYLOAD_FILE_NAMES",
    "PUBLIC_SCHEMA_VERSIONS",
    "PHASE_EVENT_SCHEMA",
    "RAW_OUTPUT_INDEX_SCHEMA",
    "REAL_AUDIT_V2",
    "TRUST_PROFILES",
    "UNAUTHENTICATED_AUTHORITY",
    "REPORT_PROJECTION_SCHEMA",
    "RUN_MANIFEST_SCHEMA",
    "OpaqueIdAllocation",
    "RunBundleContractError",
    "RunBundleVerificationReceipt",
    "allocate_opaque_id",
    "bind_embedded_sha256",
    "canonical_bytes",
    "canonical_document_bytes",
    "canonical_jsonl_bytes",
    "canonical_json_bytes",
    "document_sha256",
    "derive_opaque_id",
    "derive_publication_ceiling",
    "generate_opaque_id",
    "load_strict_json",
    "load_public_case_lock",
    "opaque_id_from_entropy",
    "public_case_lock_sha256",
    "public_case_lock_file_sha256",
    "public_field_allowlist",
    "run_context_commitment_payload",
    "sha256_bytes",
    "strict_json_load",
    "strict_jsonl_loads",
    "strict_json_loads",
    "validate_bundle_payload_set",
    "validate_bundle_object_bindings",
    "validate_candidate_lineage",
    "validate_candidate_set",
    "validate_candidates",
    "validate_document",
    "validate_harvest_receipt",
    "validate_lineage",
    "validate_manifest",
    "validate_opaque_id",
    "validate_phase_event",
    "validate_phase_events",
    "validate_public_case_lock",
    "validate_public_case_lock_binding",
    "validate_raw_output_index",
    "validate_raw_outputs",
    "validate_report_projection",
    "validate_run_manifest",
    "verify_runbundle_v2",
    "verify_embedded_sha256",
]
