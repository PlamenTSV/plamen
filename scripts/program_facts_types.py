"""Canonical, portable primitives for typed Program Facts artifacts.

This module intentionally contains no provider or graph semantics.  It is the
small Stage-1 foundation shared by later schemas, receipts, and validators.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
import unicodedata
from typing import Any

from jsonschema import Draft202012Validator


CANONICALIZATION_VERSION = "plamen.canonical_json.v1"
DEFAULT_MAX_JSON_BYTES = 8 * 1024 * 1024
STRUCTURAL_TEST_ONLY = "STRUCTURAL_TEST_ONLY"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_STABLE_PREFIX_RE = re.compile(r"^PF[A-Z]{1,3}$")
_CONTRIBUTION_ID_RE = re.compile(
    r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$"
)
_PROGRAM_FACTS_ID_RE = re.compile(
    r"^PF(?:S|B|N|O|F|C|D)-[0-9a-f]{24}$"
)
_WORK_UNIT_KEY_RE = re.compile(
    r"^[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*){5}$"
)
_SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "rules" / "schemas"
_SCHEMA_FILES = {
    "payload": "mechanical_program_facts.v1.schema.json",
    "receipt": "mechanical_program_facts_receipt.v1.schema.json",
    "debt": "mechanical_program_facts_debt.v1.schema.json",
    "registry": "program_facts_provider_registry.v1.schema.json",
    "slice": "program_facts_slice.v1.schema.json",
    "disagreement": "program_facts_disagreement.v1.schema.json",
}


class ProgramFactsTypeError(ValueError):
    """Raised when portable Program Facts data is ambiguous or noncanonical."""


def _validate_unicode(value: str, *, label: str) -> str:
    if unicodedata.normalize("NFC", value) != value:
        raise ProgramFactsTypeError(f"{label} must be NFC-normalized")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProgramFactsTypeError(f"{label} is not valid Unicode") from exc
    if "\x00" in value:
        raise ProgramFactsTypeError(f"{label} contains NUL")
    return value


def _json_value(value: Any, *, location: str = "$") -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ProgramFactsTypeError(f"{location}: float values are forbidden")
    if isinstance(value, str):
        return _validate_unicode(value, label=location)
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProgramFactsTypeError(
                    f"{location}: object keys must be strings"
                )
            key = _validate_unicode(key, label=f"{location} object key")
            if key in normalized:
                raise ProgramFactsTypeError(
                    f"{location}: duplicate normalized object key {key!r}"
                )
            normalized[key] = _json_value(item, location=f"{location}.{key}")
        return normalized
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        return [
            _json_value(item, location=f"{location}[{index}]")
            for index, item in enumerate(value)
        ]
    raise ProgramFactsTypeError(
        f"{location}: value of type {type(value).__name__} is not JSON data"
    )


def canonical_json_bytes(
    value: Mapping[str, Any] | Sequence[Any],
) -> bytes:
    """Return compact canonical JSON bytes used for semantic digests.

    The returned bytes deliberately have no trailing newline.  Artifact writers
    use :func:`canonical_file_bytes`; file-byte receipts bind that newline
    separately from the semantic document digest.
    """

    normalized = _json_value(value)
    try:
        text = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return text.encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProgramFactsTypeError("value is not canonical JSON data") from exc


def canonical_file_bytes(
    value: Mapping[str, Any] | Sequence[Any],
) -> bytes:
    """Return canonical artifact bytes with exactly one final LF."""

    return canonical_json_bytes(value) + b"\n"


def _reject_float(_raw: str) -> None:
    raise ProgramFactsTypeError("float values are forbidden")


def _reject_constant(raw: str) -> None:
    raise ProgramFactsTypeError(f"non-finite JSON number is forbidden: {raw}")


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProgramFactsTypeError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def strict_json_loads(
    raw: bytes,
    *,
    require_final_lf: bool = False,
    require_canonical: bool = True,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> Any:
    """Decode closed-input JSON without accepting parser ambiguities."""

    if not isinstance(raw, bytes):
        raise ProgramFactsTypeError("strict JSON input must be bytes")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ProgramFactsTypeError("max_bytes must be a positive integer")
    if len(raw) > max_bytes:
        raise ProgramFactsTypeError("JSON input exceeds the configured byte ceiling")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ProgramFactsTypeError("UTF-8 BOM is forbidden")
    if require_final_lf and not raw.endswith(b"\n"):
        raise ProgramFactsTypeError("canonical artifact is missing its final LF")
    if require_final_lf and raw.endswith(b"\n\n"):
        raise ProgramFactsTypeError("canonical artifact has more than one final LF")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProgramFactsTypeError("invalid UTF-8 JSON input") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            parse_int=int,
        )
    except ProgramFactsTypeError:
        raise
    except json.JSONDecodeError as exc:
        raise ProgramFactsTypeError(f"invalid JSON: {exc.msg}") from exc

    normalized = _json_value(value)
    if require_canonical:
        expected = (
            canonical_file_bytes(normalized)
            if require_final_lf
            else canonical_json_bytes(normalized)
        )
        if raw != expected:
            raise ProgramFactsTypeError("JSON bytes are not canonical")
    return normalized


def signed_payload(
    value: Mapping[str, Any],
    digest_field: str,
) -> dict[str, Any]:
    """Return a copy signed over all fields except ``digest_field``."""

    if not isinstance(digest_field, str) or not digest_field:
        raise ProgramFactsTypeError("digest_field must be a nonempty string")
    _validate_unicode(digest_field, label="digest_field")
    unsigned = dict(_json_value(value))
    unsigned.pop(digest_field, None)
    digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    return {**unsigned, digest_field: digest}


def validate_signed_payload(
    value: Mapping[str, Any],
    digest_field: str,
) -> None:
    """Validate a lowercase SHA-256 self-digest."""

    normalized = dict(_json_value(value))
    claimed = normalized.get(digest_field)
    if not isinstance(claimed, str) or _HEX64_RE.fullmatch(claimed) is None:
        raise ProgramFactsTypeError(
            f"{digest_field} must be a lowercase 64-hex digest"
        )
    unsigned = dict(normalized)
    unsigned.pop(digest_field, None)
    expected = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if claimed != expected:
        raise ProgramFactsTypeError(f"{digest_field} digest mismatch")


def validate_portable_path(path: str) -> str:
    """Validate a case-preserving, project-relative POSIX artifact path."""

    if not isinstance(path, str):
        raise ProgramFactsTypeError("portable path must be a string")
    _validate_unicode(path, label="portable path")
    if not path:
        raise ProgramFactsTypeError("portable path must not be empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ProgramFactsTypeError("portable path must not contain control characters")
    if path.startswith("/") or path.startswith("\\"):
        raise ProgramFactsTypeError("portable path must be project-relative")
    if "\\" in path:
        raise ProgramFactsTypeError("portable path must use POSIX separators")
    if ":" in path:
        raise ProgramFactsTypeError(
            "portable path must not contain drive or alternate-stream syntax"
        )
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ProgramFactsTypeError(
            "portable path contains an empty, dot, or parent segment"
        )
    return path


def derive_stable_id(prefix: str, binding: Mapping[str, Any]) -> str:
    """Derive ``PREFIX-<24 lowercase hex>`` from a canonical binding."""

    if not isinstance(prefix, str) or _STABLE_PREFIX_RE.fullmatch(prefix) is None:
        raise ProgramFactsTypeError("invalid Program Facts stable-ID prefix")
    digest = hashlib.sha256(canonical_json_bytes(binding)).hexdigest()
    return f"{prefix}-{digest[:24]}"


def validate_stable_id(value: str, expected_prefix: str) -> str:
    """Validate a typed Program Facts stable identifier."""

    if not isinstance(value, str):
        raise ProgramFactsTypeError("stable ID must be a string")
    if _STABLE_PREFIX_RE.fullmatch(expected_prefix) is None:
        raise ProgramFactsTypeError("invalid expected stable-ID prefix")
    pattern = re.compile(rf"^{re.escape(expected_prefix)}-[0-9a-f]{{24}}$")
    if pattern.fullmatch(value) is None:
        raise ProgramFactsTypeError(
            f"stable ID must match {expected_prefix}-<24 lowercase hex>"
        )
    return value


def _without(row: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    excluded = set(keys)
    return {key: value for key, value in row.items() if key not in excluded}


def derive_node_id(ecosystem: str, row: Mapping[str, Any]) -> str:
    """Derive a node identity from its portable semantic binding.

    Display-only attributes and any future provider-run identity are
    deliberately excluded.  The qualified signature and exact source binding
    are included, so moving or changing a declaration changes its identity.
    """

    binding: dict[str, Any] = {
        "ecosystem": ecosystem,
        "build_variant_id": row.get("build_variant_id"),
        "kind": row.get("kind"),
        "qualified_name": row.get("qualified_name"),
        "canonical_signature": (
            row.get("signature", {}).get("canonical")
            if isinstance(row.get("signature"), Mapping)
            else None
        ),
        "source_binding": row.get("source_binding"),
    }
    if row.get("kind") in {"EXTERNAL_SYMBOL", "UNKNOWN_TARGET"}:
        binding["reason"] = row.get("reason")
    return derive_stable_id("PFN", binding)


def derive_occurrence_id(row: Mapping[str, Any]) -> str:
    """Derive an occurrence identity without provider iteration state."""

    return derive_stable_id(
        "PFO",
        {
            "kind": row.get("kind"),
            "enclosing_node_id": row.get("enclosing_node_id"),
            "source_binding": row.get("source_binding"),
            "ir_binding": row.get("ir_binding"),
        },
    )


def derive_fact_id(row: Mapping[str, Any]) -> str:
    """Derive a portable fact identity.

    ``provider_run_id`` and ``attestations`` are provenance, not semantic
    identity.  All fields that can change the structural claim remain bound.
    """

    return derive_stable_id(
        "PFF",
        {
            key: value
            for key, value in row.items()
            if key not in {"fact_id", "provider_run_id", "attestations"}
        },
    )


def derive_debt_id(row: Mapping[str, Any]) -> str:
    """Derive a stable debt identity from its complete review obligation."""

    return derive_stable_id("PFD", _without(row, "debt_id", "explanation"))


def _source_manifest_semantic(
    source_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "policy_version": source_manifest.get("policy_version"),
        "eligible_files": source_manifest.get("eligible_files"),
        "excluded_files": source_manifest.get("excluded_files"),
    }


def derive_source_manifest_digest(
    source_manifest: Mapping[str, Any],
) -> str:
    """Digest the exact ordered source and exclusion rows plus policy."""

    return hashlib.sha256(
        canonical_json_bytes(_source_manifest_semantic(source_manifest))
    ).hexdigest()


def _freeze_json(value: Any) -> Any:
    """Deep-freeze validated JSON so wrappers cannot be mutated post-check."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


@lru_cache(maxsize=len(_SCHEMA_FILES))
def _schema_validator(kind: str) -> Draft202012Validator:
    name = _SCHEMA_FILES.get(kind)
    if name is None:
        raise ProgramFactsTypeError(f"unknown Program Facts schema kind: {kind}")
    path = _SCHEMA_ROOT / name
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProgramFactsTypeError(f"cannot read Program Facts schema: {name}") from exc
    try:
        schema = json.loads(raw.decode("utf-8", errors="strict"))
        Draft202012Validator.check_schema(schema)
    except (UnicodeDecodeError, json.JSONDecodeError, Exception) as exc:
        if isinstance(exc, ProgramFactsTypeError):
            raise
        raise ProgramFactsTypeError(f"invalid Program Facts schema: {name}") from exc
    return Draft202012Validator(schema)


def _validate_schema(kind: str, value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _json_value(value)
    if not isinstance(normalized, dict):
        raise ProgramFactsTypeError(f"{kind} document must be an object")
    errors = sorted(
        _schema_validator(kind).iter_errors(normalized),
        key=lambda error: tuple(str(item) for item in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "$"
        if first.absolute_path:
            location += "." + ".".join(str(item) for item in first.absolute_path)
        raise ProgramFactsTypeError(
            f"{kind} schema violation at {location}: {first.message}"
        )
    return normalized


def _require_sorted_unique(
    values: Sequence[Any],
    *,
    label: str,
    key: str | None = None,
) -> None:
    observed: list[str] = []
    for item in values:
        if key is None:
            if not isinstance(item, str):
                raise ProgramFactsTypeError(f"{label} must contain strings")
            observed.append(item)
        else:
            if not isinstance(item, Mapping) or not isinstance(item.get(key), str):
                raise ProgramFactsTypeError(f"{label} rows require {key}")
            observed.append(str(item[key]))
    if len(set(observed)) != len(observed):
        raise ProgramFactsTypeError(f"{label} contains a duplicate identity")
    if observed != sorted(observed):
        raise ProgramFactsTypeError(f"{label} must be sorted by {key or 'value'}")


_PORTABLE_FORBIDDEN_KEYS = {
    "pid",
    "process_id",
    "timestamp",
    "created_at",
    "username",
    "user_name",
    "executable_path",
    "temporary_path",
    "temp_path",
    "worker_transaction_attempt_id",
    "attempt_id",
}


def _looks_like_host_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    lowered = normalized.casefold()
    return bool(
        re.match(r"^[a-z]:", normalized, re.IGNORECASE)
        or value.startswith("\\\\")
        or lowered.startswith(("~", "/"))
        or "/appdata/local/temp/" in lowered
    )


def _field_contains_host_path(value: str) -> bool:
    """Inspect a path field and explicit, field-local RHS path tokens.

    This deliberately does not scan arbitrary prose.  It unwraps only
    assignment, quoting, path-list, include-flag, and ``file://`` forms used
    by argv, remapping, registry-source, exclusion, and debt-scope fields.
    """

    pending = [value.strip()]
    seen: set[str] = set()
    while pending:
        token = pending.pop()
        if not token or token in seen:
            continue
        seen.add(token)
        if _looks_like_host_path(token):
            return True
        if token.casefold().startswith("file://"):
            return True
        if (
            len(token) >= 2
            and token[0] == token[-1]
            and token[0] in {"'", '"'}
        ):
            pending.append(token[1:-1].strip())
        if "=" in token:
            pending.extend(
                part.strip()
                for part in token.split("=")[1:]
            )
        if "|" in token or ";" in token:
            pending.extend(
                part.strip()
                for part in re.split(r"[|;]", token)
            )
        include_match = re.fullmatch(r"-[IL](.+)", token)
        if include_match:
            pending.append(include_match.group(1).strip())
    return False


def _portable_payload_scan(
    value: Any,
    *,
    location: str = "$",
    field_name: str = "",
) -> None:
    """Reject environment leakage without treating every string as a path.

    Closed-schema path fields are validated separately with
    :func:`validate_portable_path`.  This traversal is deliberately
    field-aware: it rejects path-shaped values only in opaque/path-like fields
    and rejects environment-only keys everywhere, while leaving language
    signatures and semantic labels alone.
    """

    if isinstance(value, Mapping):
        for key, item in value.items():
            folded = key.casefold()
            if folded in _PORTABLE_FORBIDDEN_KEYS:
                raise ProgramFactsTypeError(
                    f"portable payload contains environment field at {location}.{key}"
                )
            _portable_payload_scan(
                item,
                location=f"{location}.{key}",
                field_name=folded,
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _portable_payload_scan(
                item,
                location=f"{location}[{index}]",
                field_name=field_name,
            )
        return
    if isinstance(value, str):
        path_sensitive = (
            field_name == "build_root_id"
            or field_name.endswith("_path")
            or field_name in {"path", "physical_identity_digest"}
        )
        if path_sensitive and _field_contains_host_path(value):
            raise ProgramFactsTypeError(
                f"portable payload {field_name} contains a host path at {location}"
            )


def _validate_opaque_root_id(value: str, *, label: str) -> None:
    _validate_unicode(value, label=label)
    if not value:
        raise ProgramFactsTypeError(f"{label} must not be empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ProgramFactsTypeError(f"{label} contains a control character")
    if _looks_like_host_path(value) or "/" in value or "\\" in value:
        raise ProgramFactsTypeError(f"{label} must be an opaque non-path identity")


def _validate_portable_opaque_identity(value: str, *, label: str) -> None:
    _validate_unicode(value, label=label)
    if not value:
        raise ProgramFactsTypeError(f"{label} must not be empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ProgramFactsTypeError(f"{label} contains a control character")
    if (
        _field_contains_host_path(value)
        or "/" in value
        or "\\" in value
    ):
        raise ProgramFactsTypeError(
            f"{label} must be a portable opaque identity, not a host path"
        )


def _variant_semantic(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in row.items()
        if key not in {"build_variant_id", "variant_digest"}
    }


def _coverage_semantic(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key != "coverage_id"}


def _validate_variant(row: Mapping[str, Any]) -> None:
    semantic = _variant_semantic(row)
    expected_digest = hashlib.sha256(canonical_json_bytes(semantic)).hexdigest()
    if row.get("variant_digest") != expected_digest:
        raise ProgramFactsTypeError("build variant digest mismatch")
    if row.get("build_variant_id") != f"PFB-{expected_digest[:24]}":
        raise ProgramFactsTypeError("build variant ID mismatch")
    for field in ("features", "tags", "remappings", "defines", "target_triples"):
        _require_sorted_unique(row[field], label=f"build_variants.{field}")
    manifests = row["manifest_digests"]
    _require_sorted_unique(
        manifests, label="build_variants.manifest_digests", key="path"
    )
    for manifest in manifests:
        validate_portable_path(manifest["path"])
    _validate_opaque_root_id(row["build_root_id"], label="build_root_id")
    for remapping in row["remappings"]:
        if _field_contains_host_path(remapping):
            raise ProgramFactsTypeError(
                "build variant remapping contains a host path"
            )


def _validate_source_file(
    row: Mapping[str, Any],
    *,
    source_scope_digest: str,
) -> None:
    path = validate_portable_path(row["path"])
    if row["path_casefold_key"] != path.casefold():
        raise ProgramFactsTypeError("source file path_casefold_key mismatch")
    binding = {
        "source_scope_digest": source_scope_digest,
        "path": path,
        "source_sha256": row["source_sha256"],
        "scope_class": row["scope_class"],
    }
    if row["source_file_id"] != derive_stable_id("PFS", binding):
        raise ProgramFactsTypeError("source file ID mismatch")


def _line_column(raw: bytes, offset: int) -> tuple[int, int]:
    prefix = raw[:offset]
    return prefix.count(b"\n") + 1, len(prefix.rsplit(b"\n", 1)[-1])


def _validate_source_binding(
    binding: Mapping[str, Any],
    *,
    source_rows: Mapping[str, Mapping[str, Any]],
    source_bytes_by_id: Mapping[str, bytes] | None,
    label: str,
) -> None:
    source_id = binding["source_file_id"]
    source_row = source_rows.get(source_id)
    if source_row is None:
        raise ProgramFactsTypeError(f"{label} has a dangling source reference")
    start = binding["start_byte"]
    end = binding["end_byte"]
    size = source_row["size_bytes"]
    if start > end or end > size:
        raise ProgramFactsTypeError(
            f"{label} source span is outside the bound source bytes"
        )
    if source_bytes_by_id is None:
        return
    raw = source_bytes_by_id[source_id]
    expected_statement = hashlib.sha256(raw[start:end]).hexdigest()
    if binding["statement_sha256"] != expected_statement:
        raise ProgramFactsTypeError(f"{label} statement digest mismatch")
    start_line, start_column = _line_column(raw, start)
    end_line, end_column = _line_column(raw, end)
    if (
        binding["start_line"],
        binding["start_column"],
        binding["end_line"],
        binding["end_column"],
    ) != (start_line, start_column, end_line, end_column):
        raise ProgramFactsTypeError(f"{label} line/column replay mismatch")


def _validate_source_bytes(
    sources: Sequence[Mapping[str, Any]],
    source_bytes_by_id: Mapping[str, bytes] | None,
) -> Mapping[str, bytes]:
    if source_bytes_by_id is None:
        raise ProgramFactsTypeError(
            "canonical Program Facts authority requires source_bytes_by_id"
        )
    if not isinstance(source_bytes_by_id, Mapping):
        raise ProgramFactsTypeError("source_bytes_by_id must be a mapping")
    expected_ids = {row["source_file_id"] for row in sources}
    actual_ids = set(source_bytes_by_id)
    if actual_ids != expected_ids:
        raise ProgramFactsTypeError(
            "source byte bindings must exactly match the source-file denominator"
        )
    normalized: dict[str, bytes] = {}
    for row in sources:
        source_id = row["source_file_id"]
        raw = source_bytes_by_id[source_id]
        if not isinstance(raw, bytes):
            raise ProgramFactsTypeError("source byte binding must contain bytes")
        if len(raw) != row["size_bytes"]:
            raise ProgramFactsTypeError("source byte size mismatch")
        if hashlib.sha256(raw).hexdigest() != row["source_sha256"]:
            raise ProgramFactsTypeError("source byte digest mismatch")
        normalized[source_id] = raw
    return normalized


def _validate_payload_cross_references(
    payload: Mapping[str, Any],
    *,
    source_bytes_by_id: Mapping[str, bytes] | None,
    require_source_bytes: bool = True,
) -> None:
    variants = payload["build_variants"]
    sources = payload["source_files"]
    nodes = payload["nodes"]
    occurrences = payload["occurrences"]
    facts = payload["facts"]
    coverage = payload["coverage"]

    _require_sorted_unique(variants, label="build_variants", key="build_variant_id")
    _require_sorted_unique(sources, label="source_files", key="source_file_id")
    _require_sorted_unique(nodes, label="nodes", key="node_id")
    _require_sorted_unique(occurrences, label="occurrences", key="occurrence_id")
    _require_sorted_unique(facts, label="facts", key="fact_id")
    _require_sorted_unique(coverage, label="coverage", key="coverage_id")
    _require_sorted_unique(
        payload["provider_capability_refs"],
        label="provider_capability_refs",
    )

    for row in variants:
        _validate_variant(row)
    variant_ecosystems = {row["ecosystem"] for row in variants}
    if payload["ecosystem"] != "mixed" and variant_ecosystems - {
        payload["ecosystem"]
    }:
        raise ProgramFactsTypeError(
            "build variant ecosystem does not match payload ecosystem"
        )
    if payload["ecosystem"] == "mixed" and "mixed" in variant_ecosystems:
        raise ProgramFactsTypeError(
            "mixed payload must retain concrete build-variant ecosystems"
        )
    for row in sources:
        _validate_source_file(
            row,
            source_scope_digest=payload["snapshot_ref"]["source_scope_digest"],
        )
    if require_source_bytes:
        source_bytes_by_id = _validate_source_bytes(sources, source_bytes_by_id)
    elif source_bytes_by_id is not None:
        source_bytes_by_id = _validate_source_bytes(sources, source_bytes_by_id)

    variant_ids = {row["build_variant_id"] for row in variants}
    source_ids = {row["source_file_id"] for row in sources}
    source_rows = {row["source_file_id"]: row for row in sources}
    node_ids = {row["node_id"] for row in nodes}
    node_rows = {row["node_id"]: row for row in nodes}
    occurrence_ids = {row["occurrence_id"] for row in occurrences}
    occurrence_rows = {
        row["occurrence_id"]: row for row in occurrences
    }
    capability_ids = set(payload["provider_capability_refs"])

    casefold_keys = [row["path_casefold_key"] for row in sources]
    if len(casefold_keys) != len(set(casefold_keys)):
        raise ProgramFactsTypeError("source file case-fold collision")
    physical_ids = [
        row["physical_identity_digest"]
        for row in sources
        if row["physical_identity_digest"]
    ]
    if len(physical_ids) != len(set(physical_ids)):
        raise ProgramFactsTypeError("source file physical-identity alias collision")

    for row in nodes:
        if row["build_variant_id"] not in variant_ids:
            raise ProgramFactsTypeError("node has a dangling build reference")
        binding = row.get("source_binding")
        if binding:
            _validate_source_binding(
                binding,
                source_rows=source_rows,
                source_bytes_by_id=source_bytes_by_id,
                label="node",
            )
        if row["node_id"] != derive_node_id(payload["ecosystem"], row):
            raise ProgramFactsTypeError("node ID mismatch")
        _require_sorted_unique(row["attributes"], label="node attributes")
    for row in occurrences:
        if row["enclosing_node_id"] not in node_ids:
            raise ProgramFactsTypeError(
                "occurrence has a dangling enclosing-node reference"
            )
        _validate_source_binding(
            row["source_binding"],
            source_rows=source_rows,
            source_bytes_by_id=source_bytes_by_id,
            label="occurrence",
        )
        enclosing_binding = node_rows[row["enclosing_node_id"]].get(
            "source_binding"
        )
        if enclosing_binding and (
            row["source_binding"]["source_file_id"]
            != enclosing_binding["source_file_id"]
        ):
            raise ProgramFactsTypeError(
                "occurrence source does not match its enclosing node"
            )
        if row["occurrence_id"] != derive_occurrence_id(row):
            raise ProgramFactsTypeError("occurrence ID mismatch")
    for row in facts:
        if row["subject_id"] not in node_ids or row["object_id"] not in node_ids:
            raise ProgramFactsTypeError("fact has a dangling node reference")
        if row["build_variant_id"] not in variant_ids:
            raise ProgramFactsTypeError("fact has a dangling build reference")
        if (
            node_rows[row["subject_id"]]["build_variant_id"]
            != row["build_variant_id"]
            or node_rows[row["object_id"]]["build_variant_id"]
            != row["build_variant_id"]
        ):
            raise ProgramFactsTypeError(
                "fact build variant does not match its subject/object nodes"
            )
        if row["capability_id"] not in capability_ids:
            raise ProgramFactsTypeError("fact has a dangling capability reference")
        for occurrence_id in row["occurrence_ids"]:
            if occurrence_id not in occurrence_ids:
                raise ProgramFactsTypeError("fact has a dangling occurrence reference")
        for predicate_id in row["context"]["dominating_predicates"]:
            if predicate_id not in occurrence_ids:
                raise ProgramFactsTypeError(
                    "fact has a dangling dominating-predicate reference"
                )
        for occurrence_id in (
            list(row["occurrence_ids"])
            + list(row["context"]["dominating_predicates"])
        ):
            enclosing_node = node_rows[
                occurrence_rows[occurrence_id]["enclosing_node_id"]
            ]
            if enclosing_node["build_variant_id"] != row["build_variant_id"]:
                raise ProgramFactsTypeError(
                    "fact occurrence build variant does not match the fact"
                )
        if _CONTRIBUTION_ID_RE.fullmatch(row["provider_run_id"]) is None:
            raise ProgramFactsTypeError(
                "portable fact provider_run_id must be deterministic"
            )
        _require_sorted_unique(
            row["occurrence_ids"], label=f"fact {row['fact_id']} occurrence_ids"
        )
        _require_sorted_unique(
            row["context"]["dominating_predicates"],
            label=f"fact {row['fact_id']} dominating_predicates",
        )
        _require_sorted_unique(
            row["attestations"], label=f"fact {row['fact_id']} attestations"
        )
        if row["provider_run_id"] not in row["attestations"]:
            raise ProgramFactsTypeError(
                "fact provider_run_id must appear in its attestations"
            )
        if row["fact_id"] != derive_fact_id(row):
            raise ProgramFactsTypeError("fact ID mismatch")
        if row["provenance_origin"] == "SOURCE_PARSE" and (
            row["precision"] not in {"HEURISTIC", "SYNTACTIC"}
            or row["structural_confidence"] != "SOURCE_FALLBACK"
        ):
            raise ProgramFactsTypeError(
                "source-fallback fact cannot assert exact provider precision"
            )
    fact_ids = {row["fact_id"] for row in facts}
    for row in nodes:
        signature_ref = row["signature"]["signature_fact_ref"]
        if signature_ref and signature_ref not in fact_ids:
            raise ProgramFactsTypeError(
                "node signature has a dangling fact reference"
            )
    for row in coverage:
        expected_id = derive_stable_id("PFC", _coverage_semantic(row))
        if row["coverage_id"] != expected_id:
            raise ProgramFactsTypeError("coverage ID mismatch")
        if row["build_variant_id"] not in variant_ids:
            raise ProgramFactsTypeError("coverage has a dangling build reference")
        if row["capability_id"] not in capability_ids:
            raise ProgramFactsTypeError("coverage has a dangling capability reference")
        for field in (
            "eligible_source_file_ids",
            "covered_source_file_ids",
            "excluded_source_file_ids",
            "unresolved_debt_ids",
        ):
            _require_sorted_unique(row[field], label=f"coverage.{field}")
        referenced_sources = (
            set(row["eligible_source_file_ids"])
            | set(row["covered_source_file_ids"])
            | set(row["excluded_source_file_ids"])
        )
        if not referenced_sources <= source_ids:
            raise ProgramFactsTypeError("coverage has a dangling source reference")
        eligible = set(row["eligible_source_file_ids"])
        if not set(row["covered_source_file_ids"]) <= eligible:
            raise ProgramFactsTypeError(
                "coverage covered sources must be inside the eligible denominator"
            )
        if not set(row["excluded_source_file_ids"]) <= eligible:
            raise ProgramFactsTypeError(
                "coverage excluded sources must be inside the eligible denominator"
            )
        if set(row["covered_source_file_ids"]) & set(
            row["excluded_source_file_ids"]
        ):
            raise ProgramFactsTypeError("coverage covered/excluded sets overlap")
        denominator = {
            "eligible_source_file_ids": row["eligible_source_file_ids"],
            "excluded_source_file_ids": row["excluded_source_file_ids"],
        }
        expected_denominator = hashlib.sha256(
            canonical_json_bytes(denominator)
        ).hexdigest()
        if row["denominator_digest"] != expected_denominator:
            raise ProgramFactsTypeError("coverage denominator digest mismatch")
        if row["status"] == "FULL" and (
            set(row["covered_source_file_ids"])
            != set(row["eligible_source_file_ids"])
            or row["unresolved_debt_ids"]
        ):
            raise ProgramFactsTypeError(
                "FULL coverage requires the exact denominator and zero unresolved debt"
            )
        if row["status"] in {"PARTIAL", "UNSUPPORTED", "UNKNOWN"} and not row[
            "unresolved_debt_ids"
        ]:
            raise ProgramFactsTypeError(
                f"{row['status']} coverage requires explicit unresolved debt"
            )
        if row["status"] in {"UNSUPPORTED", "UNKNOWN"} and row[
            "covered_source_file_ids"
        ]:
            raise ProgramFactsTypeError(
                f"{row['status']} coverage cannot claim covered source files"
            )

    fact_capabilities = {row["capability_id"] for row in facts}
    if not fact_capabilities <= capability_ids:
        raise ProgramFactsTypeError("fact capability is outside provider capabilities")
    covered_capabilities = {row["capability_id"] for row in coverage}
    if covered_capabilities != capability_ids:
        raise ProgramFactsTypeError(
            "provider capabilities and coverage accounting are not total"
        )
    coverage_pairs = [
        (row["capability_id"], row["build_variant_id"]) for row in coverage
    ]
    if len(coverage_pairs) != len(set(coverage_pairs)):
        raise ProgramFactsTypeError("duplicate capability/build coverage row")
    expected_coverage_pairs = {
        (capability_id, variant_id)
        for capability_id in capability_ids
        for variant_id in variant_ids
    }
    if set(coverage_pairs) != expected_coverage_pairs:
        raise ProgramFactsTypeError(
            "coverage must contain the total capability by build-variant matrix"
        )
    denominators_by_variant: dict[
        str, tuple[tuple[str, ...], tuple[str, ...]]
    ] = {}
    for row in coverage:
        denominator = (
            tuple(row["eligible_source_file_ids"]),
            tuple(row["excluded_source_file_ids"]),
        )
        prior = denominators_by_variant.setdefault(
            row["build_variant_id"],
            denominator,
        )
        if prior != denominator:
            raise ProgramFactsTypeError(
                "coverage denominator differs within one build variant"
            )
    for row in nodes:
        binding = row.get("source_binding")
        if binding and binding["source_file_id"] not in set(
            denominators_by_variant[row["build_variant_id"]][0]
        ):
            raise ProgramFactsTypeError(
                "node source is outside its build-variant denominator"
            )
    if sources and coverage:
        accounted_sources = {
            source_id
            for row in coverage
            for source_id in row["eligible_source_file_ids"]
        }
        if accounted_sources != source_ids:
            raise ProgramFactsTypeError(
                "coverage source denominator does not account for every source file"
            )


def validate_program_facts_payload(
    value: Mapping[str, Any],
    *,
    source_bytes_by_id: Mapping[str, bytes] | None,
) -> dict[str, Any]:
    payload = _validate_schema("payload", value)
    validate_signed_payload(payload, "payload_sha256")
    _portable_payload_scan(payload)
    _validate_payload_cross_references(
        payload,
        source_bytes_by_id=source_bytes_by_id,
    )
    return payload


def validate_program_facts_payload_shape(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate schema and internal shape without granting source authority.

    This helper is intentionally not accepted by :class:`ProgramFactsPayload`
    or :class:`ProgramFactsBundle`.  Canonical public payload authority always
    replays the exact source bytes.
    """

    payload = _validate_schema("payload", value)
    validate_signed_payload(payload, "payload_sha256")
    _portable_payload_scan(payload)
    _validate_payload_cross_references(
        payload,
        source_bytes_by_id=None,
        require_source_bytes=False,
    )
    return payload


_DEBT_REASONS_REQUIRING_PROVIDER = {
    "PROVIDER_UNAVAILABLE",
    "PROVIDER_UNSUPPORTED_ECOSYSTEM",
    "PROVIDER_IDENTITY_UNBOUND",
    "PROVIDER_VERSION_DRIFT",
    "EXECUTABLE_DIGEST_DRIFT",
    "PARSER_DIGEST_DRIFT",
    "UNSUPPORTED_CONSTRUCT",
    "UNRESOLVED_DYNAMIC_CALL",
    "UNRESOLVED_PROXY_DISPATCH",
    "UNRESOLVED_ASSEMBLY",
    "ANALYSIS_TIMEOUT",
    "OUTPUT_TRUNCATED",
    "RESOURCE_LIMIT",
    "RAW_OUTPUT_MALFORMED",
    "DANGLING_REFERENCE",
    "DUPLICATE_ID_CONFLICT",
    "CAPABILITY_PARTIAL",
    "OS_PROCESS_SCOPE_UNPROVEN",
    "WORKER_TRANSACTION_INCOMPLETE",
    "UNSUPPORTED_HOST_SEMANTICS",
    "LICENSE_OR_DISTRIBUTION_RESTRICTED",
}
_DEBT_REASONS_REQUIRING_CAPABILITY = (
    _DEBT_REASONS_REQUIRING_PROVIDER
    | {"PROVIDER_DISAGREEMENT"}
) - {
    "OS_PROCESS_SCOPE_UNPROVEN",
    "WORKER_TRANSACTION_INCOMPLETE",
}
_DEBT_REASONS_REQUIRING_BUILD = (
    _DEBT_REASONS_REQUIRING_CAPABILITY
    | {
        "BUILD_CONFIGURATION_UNRESOLVED",
        "BUILD_FAILED",
        "BUILD_PARTIAL",
        "DEPENDENCY_CLOSURE_UNRESOLVED",
        "GENERATED_SOURCE_UNBOUND",
    }
)
_DEBT_REASONS_REQUIRING_PROGRAM_FACTS_SCOPE = (
    _DEBT_REASONS_REQUIRING_BUILD
    | {"PROVIDER_DISAGREEMENT"}
)


def _validate_debt_scope_id(scope_id: str, *, reason: str) -> None:
    _validate_unicode(scope_id, label=f"{reason} debt scope")
    if (
        not scope_id
        or any(ord(char) < 32 or ord(char) == 127 for char in scope_id)
        or _field_contains_host_path(scope_id)
    ):
        raise ProgramFactsTypeError(
            f"{reason} debt scope is not a typed portable identity"
        )
    if (
        _PROGRAM_FACTS_ID_RE.fullmatch(scope_id)
        or re.fullmatch(r"^sha256:[0-9a-f]{64}$", scope_id)
        or _WORK_UNIT_KEY_RE.fullmatch(scope_id)
        or _CONTRIBUTION_ID_RE.fullmatch(scope_id)
    ):
        return
    if "/" in scope_id:
        validate_portable_path(scope_id)
        return
    raise ProgramFactsTypeError(
        f"{reason} debt scope is not a recognized typed identity"
    )


def validate_program_facts_debt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    debt = _validate_schema("debt", value)
    validate_signed_payload(debt, "debt_sha256")
    rows = debt["debts"]
    _require_sorted_unique(rows, label="debts", key="debt_id")
    reason_counts = Counter(row["reason"] for row in rows)
    expected_counts = {key: reason_counts[key] for key in sorted(reason_counts)}
    capabilities = sorted(
        {
            row["capability_id"]
            for row in rows
            if isinstance(row["capability_id"], str) and row["capability_id"]
        }
    )
    source_ids = sorted(
        {
            scope_id
            for row in rows
            for scope_id in row["scope_ids"]
            if isinstance(scope_id, str) and scope_id.startswith("PFS-")
        }
    )
    blocking = any(bool(row["blocks_reuse"]) for row in rows)
    summary = debt["summary"]
    if (
        summary["by_reason"] != expected_counts
        or summary["affected_capabilities"] != capabilities
        or summary["affected_source_file_ids"] != source_ids
        or summary["has_blocking_reuse_debt"] is not blocking
    ):
        raise ProgramFactsTypeError("debt summary does not exactly replay debt rows")
    for row in rows:
        _require_sorted_unique(
            row["scope_ids"], label=f"debt {row['debt_id']} scope_ids"
        )
        _require_sorted_unique(
            row["evidence_refs"], label=f"debt {row['debt_id']} evidence_refs"
        )
        if row["debt_id"] != derive_debt_id(row):
            raise ProgramFactsTypeError("debt ID mismatch")
        reason = row["reason"]
        if not row["scope_ids"]:
            raise ProgramFactsTypeError(
                f"{reason} debt requires at least one typed scope"
            )
        for scope_id in row["scope_ids"]:
            _validate_debt_scope_id(scope_id, reason=reason)
        if (
            reason in _DEBT_REASONS_REQUIRING_PROGRAM_FACTS_SCOPE
            and not any(
                _PROGRAM_FACTS_ID_RE.fullmatch(scope_id)
                for scope_id in row["scope_ids"]
            )
        ):
            raise ProgramFactsTypeError(
                f"{reason} debt requires a typed Program Facts scope"
            )
        if reason in _DEBT_REASONS_REQUIRING_PROVIDER and not row[
            "provider_id"
        ]:
            raise ProgramFactsTypeError(
                f"{reason} debt requires provider_id"
            )
        if reason in _DEBT_REASONS_REQUIRING_CAPABILITY and not row[
            "capability_id"
        ]:
            raise ProgramFactsTypeError(
                f"{reason} debt requires capability_id"
            )
        if reason in _DEBT_REASONS_REQUIRING_BUILD and not row[
            "build_variant_id"
        ]:
            raise ProgramFactsTypeError(
                f"{reason} debt requires build_variant_id"
            )
        if reason in {
            "STALE_SNAPSHOT",
            "PHASE_IO_INCORPORATION_FAILED",
        } and row["blocks_reuse"] is not True:
            raise ProgramFactsTypeError(
                f"{reason} debt must block reuse"
            )
    return debt


def validate_program_facts_provider_registry(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the reviewed provider/capability map beyond JSON Schema."""

    registry = _validate_schema("registry", value)
    providers = registry["providers"]
    _require_sorted_unique(providers, label="registry providers", key="provider_id")
    provider_ids = {row["provider_id"] for row in providers}
    providers_by_id = {row["provider_id"]: row for row in providers}

    for row in providers:
        _require_sorted_unique(
            row["supported_ecosystems"],
            label=f"provider {row['provider_id']} supported_ecosystems",
        )
        _require_sorted_unique(
            row["supported_languages"],
            label=f"provider {row['provider_id']} supported_languages",
        )
        _require_sorted_unique(
            row["toolchain_ranges"],
            label=f"provider {row['provider_id']} toolchain_ranges",
            key="toolchain",
        )
        _require_sorted_unique(
            row["capabilities"],
            label=f"provider {row['provider_id']} capabilities",
            key="capability_id",
        )
        _require_sorted_unique(
            row["supported_platforms"],
            label=f"provider {row['provider_id']} supported_platforms",
            key="os",
        )
        for platform in row["supported_platforms"]:
            _require_sorted_unique(
                platform["architectures"],
                label=f"provider {row['provider_id']} platform architectures",
            )
        policy = row["supply_chain_policy"]
        if policy["pinned"] is not True:
            raise ProgramFactsTypeError(
                f"provider {row['provider_id']} is not supply-chain pinned"
            )
        distribution = row["distribution"]
        if policy["checksum_required"] and not distribution["checksum"]:
            raise ProgramFactsTypeError(
                f"provider {row['provider_id']} requires a distribution checksum"
            )
        if not distribution["checksum"] and not distribution["module_source_digest"]:
            raise ProgramFactsTypeError(
                f"provider {row['provider_id']} has no bound distribution or module"
            )
        if _field_contains_host_path(
            row["installation_provenance"]["source"]
        ):
            raise ProgramFactsTypeError(
                f"provider {row['provider_id']} installation provenance leaks a host path"
            )
        if not row["expected_version_syntax"]:
            raise ProgramFactsTypeError(
                f"provider {row['provider_id']} lacks version syntax"
            )
        try:
            re.compile(row["expected_version_syntax"])
        except re.error as exc:
            raise ProgramFactsTypeError(
                f"provider {row['provider_id']} has invalid version syntax"
            ) from exc
        for toolchain_range in row["toolchain_ranges"]:
            _parse_version_range(toolchain_range["version_range"])
        fallback = row["fallback"]
        if fallback:
            fallback_id = fallback["provider_id"]
            if fallback_id == row["provider_id"]:
                raise ProgramFactsTypeError("provider fallback cannot reference itself")
            if fallback_id not in provider_ids:
                raise ProgramFactsTypeError("provider fallback reference is dangling")
            fallback_row = providers_by_id[fallback_id]
            if not set(row["supported_ecosystems"]) & set(
                fallback_row["supported_ecosystems"]
            ):
                raise ProgramFactsTypeError(
                    "provider fallback has no common supported ecosystem"
                )
            if not {
                item["capability_id"] for item in row["capabilities"]
            } & {
                item["capability_id"] for item in fallback_row["capabilities"]
            }:
                raise ProgramFactsTypeError(
                    "provider fallback has no common capability"
                )
            precision_rank = {
                "SYNTACTIC": 0,
                "HEURISTIC": 1,
                "MAY": 2,
                "EXACT": 3,
            }
            fallback_maxima = [
                precision_rank[item["maximum_precision"]]
                for item in providers_by_id[fallback_id]["capabilities"]
            ]
            if not fallback_maxima or precision_rank[
                fallback["maximum_precision"]
            ] > max(fallback_maxima):
                raise ProgramFactsTypeError(
                    "provider fallback precision exceeds fallback authority"
                )

    # Fallbacks are an ordered degradation lane, never a cycle.
    for provider_id in sorted(provider_ids):
        seen: set[str] = set()
        current = provider_id
        while current:
            if current in seen:
                raise ProgramFactsTypeError("provider fallback graph contains a cycle")
            seen.add(current)
            fallback = providers_by_id[current]["fallback"]
            current = fallback.get("provider_id", "") if fallback else ""
    return registry


def _numeric_version(value: str, *, label: str) -> tuple[int, ...]:
    if re.fullmatch(r"\d+(?:\.\d+)*", value) is None:
        raise ProgramFactsTypeError(
            f"{label} must be a dotted numeric version"
        )
    return tuple(int(part) for part in value.split("."))


def _compare_numeric_versions(
    left: tuple[int, ...],
    right: tuple[int, ...],
) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _parse_version_range(value: str) -> tuple[tuple[str, tuple[int, ...]], ...]:
    clauses: list[tuple[str, tuple[int, ...]]] = []
    for raw_clause in value.split(","):
        match = re.fullmatch(
            r"\s*(>=|<=|==|!=|>|<)\s*(\d+(?:\.\d+)*)\s*",
            raw_clause,
        )
        if match is None:
            raise ProgramFactsTypeError(
                f"toolchain version range is unsupported: {value!r}"
            )
        clauses.append(
            (
                match.group(1),
                _numeric_version(
                    match.group(2),
                    label="toolchain range version",
                ),
            )
        )
    if not clauses:
        raise ProgramFactsTypeError("toolchain version range is empty")
    return tuple(clauses)


def _version_satisfies(version: str, version_range: str) -> bool:
    candidate = _numeric_version(version, label="toolchain version")
    for operator, boundary in _parse_version_range(version_range):
        comparison = _compare_numeric_versions(candidate, boundary)
        if (
            (operator == ">=" and comparison < 0)
            or (operator == "<=" and comparison > 0)
            or (operator == ">" and comparison <= 0)
            or (operator == "<" and comparison >= 0)
            or (operator == "==" and comparison != 0)
            or (operator == "!=" and comparison == 0)
        ):
            return False
    return True


def _validate_source_manifest(
    source_manifest: Mapping[str, Any],
    *,
    source_scope_digest: str,
) -> None:
    eligible = source_manifest["eligible_files"]
    excluded = source_manifest["excluded_files"]
    _require_sorted_unique(
        eligible, label="source manifest eligible files", key="source_file_id"
    )
    _require_sorted_unique(
        excluded, label="source manifest excluded files", key="identity"
    )
    for row in eligible:
        _validate_source_file(row, source_scope_digest=source_scope_digest)
    casefold_keys = [row["path_casefold_key"] for row in eligible]
    if len(casefold_keys) != len(set(casefold_keys)):
        raise ProgramFactsTypeError("source manifest has a case-fold collision")
    physical_ids = [
        row["physical_identity_digest"]
        for row in eligible
        if row["physical_identity_digest"]
    ]
    if len(physical_ids) != len(set(physical_ids)):
        raise ProgramFactsTypeError(
            "source manifest has a physical-identity alias collision"
        )
    if source_manifest["file_count"] != len(eligible):
        raise ProgramFactsTypeError("source manifest file_count mismatch")
    if source_manifest["byte_count"] != sum(row["size_bytes"] for row in eligible):
        raise ProgramFactsTypeError("source manifest byte_count mismatch")
    if source_manifest["manifest_digest"] != derive_source_manifest_digest(
        source_manifest
    ):
        raise ProgramFactsTypeError("source manifest digest mismatch")
    identities: list[str] = []
    for row in excluded:
        identity = row["identity"]
        _validate_unicode(identity, label="excluded source identity")
        if any(ord(char) < 32 or ord(char) == 127 for char in identity):
            raise ProgramFactsTypeError(
                "source manifest excluded identity contains a control character"
            )
        if _field_contains_host_path(identity):
            raise ProgramFactsTypeError(
                "source manifest excluded identity contains a host path"
            )
        if "/" in identity:
            validate_portable_path(identity)
        identities.append(identity.casefold())
    if len(identities) != len(set(identities)):
        raise ProgramFactsTypeError("source manifest excluded identity collision")
    if set(identities) & set(casefold_keys):
        raise ProgramFactsTypeError(
            "source manifest includes and excludes the same logical path"
        )


def _validate_string_set_fields(
    row: Mapping[str, Any],
    fields: Sequence[str],
    *,
    label: str,
) -> None:
    for field in fields:
        _require_sorted_unique(row[field], label=f"{label}.{field}")


def _validate_receipt_semantics(
    receipt: Mapping[str, Any],
    *,
    provider_registry: Mapping[str, Any] | None,
) -> None:
    _validate_portable_opaque_identity(
        receipt["run_id"],
        label="receipt run_id",
    )
    _validate_source_manifest(
        receipt["source_manifest"],
        source_scope_digest=receipt["audit_snapshot"]["source_scope_digest"],
    )
    builds = receipt["build_attempts"]
    providers = receipt["provider_runs"]
    transactions = receipt["worker_transaction_refs"]
    _require_sorted_unique(builds, label="build attempts", key="build_variant_id")
    _require_sorted_unique(providers, label="provider runs", key="provider_run_id")
    _require_sorted_unique(
        transactions, label="worker transaction refs", key="ref_id"
    )

    manifest_source_ids = {
        row["source_file_id"] for row in receipt["source_manifest"]["eligible_files"]
    }
    for row in builds:
        _validate_opaque_root_id(row["build_root_id"], label="build_root_id")
        if row["build_root_path"]:
            validate_portable_path(row["build_root_path"])
        _require_sorted_unique(
            row["manifest_digests"],
            label="build manifest_digests",
            key="path",
        )
        _require_sorted_unique(
            row["lockfile_digests"],
            label="build lockfile_digests",
            key="path",
        )
        _require_sorted_unique(
            row["toolchain_identities"],
            label="build toolchain_identities",
            key="name",
        )
        for path_digest in row["manifest_digests"] + row["lockfile_digests"]:
            validate_portable_path(path_digest["path"])
        _validate_string_set_fields(
            row,
            (
                "target_triples",
                "features",
                "tags",
                "remappings",
                "defines",
                "package_selection",
                "eligible_source_file_ids",
                "compiled_source_file_ids",
                "excluded_source_file_ids",
                "failed_source_file_ids",
                "debt_ids",
            ),
            label="build attempt",
        )
        eligible = set(row["eligible_source_file_ids"])
        compiled = set(row["compiled_source_file_ids"])
        excluded = set(row["excluded_source_file_ids"])
        failed = set(row["failed_source_file_ids"])
        if not eligible <= manifest_source_ids:
            raise ProgramFactsTypeError(
                "build eligible denominator is outside the source manifest"
            )
        if (compiled | excluded | failed) != eligible:
            raise ProgramFactsTypeError(
                "build denominator is not totally accounted"
            )
        if compiled & excluded or compiled & failed or excluded & failed:
            raise ProgramFactsTypeError("build denominator partitions overlap")
        outcome = row["outcome"]
        degraded = bool(
            row["debt_ids"]
            or row["stdout_truncated"]
            or row["stderr_truncated"]
        )
        if outcome == "SUCCEEDED" and (
            compiled != eligible or excluded or failed or degraded
        ):
            raise ProgramFactsTypeError(
                "successful build must compile its exact denominator without debt"
            )
        if outcome == "SUCCEEDED" and (
            not row["stdout_cas_ref"] or not row["stderr_cas_ref"]
        ):
            raise ProgramFactsTypeError(
                "successful build requires bound stdout/stderr CAS references"
            )
        if outcome != "SUCCEEDED" and not row["debt_ids"]:
            raise ProgramFactsTypeError(
                "non-successful build requires explicit debt"
            )
        if (row["stdout_truncated"] or row["stderr_truncated"]) and not row[
            "debt_ids"
        ]:
            raise ProgramFactsTypeError("truncated build output requires debt")

    transaction_by_id = {row["ref_id"]: row for row in transactions}
    provider_by_id = {row["provider_run_id"]: row for row in providers}
    referenced_transactions: set[str] = set()
    registry_value: dict[str, Any] | None = None
    registry_digest = ""
    registry_by_id: dict[str, Mapping[str, Any]] = {}
    if provider_registry is not None:
        registry_value = validate_program_facts_provider_registry(provider_registry)
        registry_digest = hashlib.sha256(
            canonical_json_bytes(registry_value)
        ).hexdigest()
        registry_by_id = {
            row["provider_id"]: row for row in registry_value["providers"]
        }
    elif providers:
        raise ProgramFactsTypeError(
            "provider registry is required when provider runs are present"
        )

    for row in providers:
        provider_id = row["provider_id"]
        _validate_portable_opaque_identity(
            row["provider_run_id"],
            label="provider_run_id",
        )
        registry_row = registry_by_id.get(provider_id)
        if registry_row is None:
            raise ProgramFactsTypeError("provider run references an unknown provider")
        if row["provider_registry_digest"] != registry_digest:
            raise ProgramFactsTypeError("provider registry digest mismatch")
        if row["parser_callable"] != registry_row["raw_binding"]["parser_callable"]:
            raise ProgramFactsTypeError("provider parser callable mismatch")
        if (
            row["parser_source_digest"]
            != registry_row["raw_binding"]["parser_source_digest"]
            or row["raw_schema_digest"]
            != registry_row["raw_binding"]["raw_schema_digest"]
        ):
            raise ProgramFactsTypeError("provider parser/raw schema binding mismatch")
        distribution = registry_row["distribution"]
        expected_implementation_digest = (
            distribution["module_source_digest"]
            or registry_row["installation_provenance"]["digest"]
        )
        expected_executable_digest = (
            distribution["checksum"]
            or distribution["module_source_digest"]
        )
        if (
            not expected_implementation_digest
            or row["implementation_digest"]
            != expected_implementation_digest
        ):
            raise ProgramFactsTypeError(
                "provider implementation identity does not match registry authority"
            )
        if (
            not expected_executable_digest
            or row["executable_or_module_digest"]
            != expected_executable_digest
        ):
            raise ProgramFactsTypeError(
                "provider executable/module digest does not match registry authority"
            )
        version_output = row["version_output"]
        if row["version_output_digest"] != hashlib.sha256(
            version_output.encode("utf-8")
        ).hexdigest():
            raise ProgramFactsTypeError(
                "provider version output digest mismatch"
            )
        if re.fullmatch(
            registry_row["expected_version_syntax"],
            version_output,
        ) is None:
            raise ProgramFactsTypeError(
                "provider version output is outside registry syntax"
            )
        pinned_version = distribution["version"]
        if pinned_version and pinned_version not in version_output:
            raise ProgramFactsTypeError(
                "provider version output does not identify the pinned version"
            )
        limits = registry_row["limits"]
        if (
            row["input_ceiling_bytes"] > limits["input_bytes"]
            or row["output_ceiling_bytes"] > limits["output_bytes"]
            or row["timeout_seconds"] > limits["time_seconds"]
        ):
            raise ProgramFactsTypeError(
                "provider execution ceiling exceeds registry limit authority"
            )
        _validate_opaque_root_id(
            row["working_directory_root_id"],
            label="working_directory_root_id",
        )
        for argument in row["argv"]:
            _validate_unicode(argument, label="provider argv")
            if (
                any(ord(char) < 32 or ord(char) == 127 for char in argument)
                or _field_contains_host_path(argument)
            ):
                raise ProgramFactsTypeError(
                    "provider argv contains a non-portable host path"
                )
        _validate_string_set_fields(
            row,
            (
                "capabilities_requested",
                "capabilities_emitted",
                "capabilities_unavailable",
                "capabilities_partial",
                "build_variant_ids",
                "worker_transaction_ref_ids",
                "debt_ids",
            ),
            label=f"provider {row['provider_run_id']}",
        )
        _require_sorted_unique(
            row["allowed_environment"],
            label="provider allowed_environment",
            key="name",
        )
        _require_sorted_unique(
            row["platform"]["runtime_versions"],
            label="provider platform runtime_versions",
            key="name",
        )
        requested = set(row["capabilities_requested"])
        emitted = set(row["capabilities_emitted"])
        unavailable = set(row["capabilities_unavailable"])
        partial = set(row["capabilities_partial"])
        advertised = {
            item["capability_id"] for item in registry_row["capabilities"]
        }
        if not requested <= advertised:
            raise ProgramFactsTypeError(
                "provider requested an unregistered capability"
            )
        if emitted & unavailable or emitted & partial or unavailable & partial:
            raise ProgramFactsTypeError("provider capability dispositions overlap")
        if emitted | unavailable | partial != requested:
            raise ProgramFactsTypeError(
                "provider capability disposition is not total"
            )
        if (unavailable or partial or row["output_truncated"] or row["cancelled"]) and not row[
            "debt_ids"
        ]:
            raise ProgramFactsTypeError(
                "degraded provider disposition requires explicit debt"
            )
        if row["cancelled"] and emitted:
            raise ProgramFactsTypeError(
                "cancelled provider cannot mint emitted capabilities"
            )
        if row["output_truncated"] and emitted:
            raise ProgramFactsTypeError(
                "truncated provider output cannot mint complete capabilities"
            )
        for ref_id in row["worker_transaction_ref_ids"]:
            transaction = transaction_by_id.get(ref_id)
            if transaction is None:
                raise ProgramFactsTypeError(
                    "provider has a dangling worker transaction reference"
                )
            if transaction["provider_run_id"] != row["provider_run_id"]:
                raise ProgramFactsTypeError(
                    "worker transaction/provider reference mismatch"
                )
            referenced_transactions.add(ref_id)
        if emitted and not row["worker_transaction_ref_ids"]:
            raise ProgramFactsTypeError(
                "emitted provider capabilities require a worker transaction"
            )
        if emitted and any(
            transaction_by_id[ref_id]["status"] != "COMPLETED"
            for ref_id in row["worker_transaction_ref_ids"]
        ):
            raise ProgramFactsTypeError(
                "incomplete worker transaction cannot mint emitted capabilities"
            )
        if any(
            transaction_by_id[ref_id]["status"] != "COMPLETED"
            for ref_id in row["worker_transaction_ref_ids"]
        ) and not row["debt_ids"]:
            raise ProgramFactsTypeError(
                "non-completed worker transaction requires provider debt"
            )

    if referenced_transactions != set(transaction_by_id):
        raise ProgramFactsTypeError(
            "worker transaction denominator is not exactly referenced"
        )
    for row in transactions:
        _validate_portable_opaque_identity(
            row["ref_id"],
            label="worker ref_id",
        )
        _validate_portable_opaque_identity(
            row["provider_run_id"],
            label="worker provider_run_id",
        )
        if row["provider_run_id"] not in provider_by_id:
            raise ProgramFactsTypeError(
                "worker transaction has a dangling provider reference"
            )
        if row["process_scope_active_zero"] is not True:
            raise ProgramFactsTypeError(
                "worker transaction lacks process-scope-zero proof"
            )
        if row["status"] == "COMPLETED":
            if (
                not row["completion_digest"]
                or row["debt_digest"]
                or not row["cas_manifest_digest"]
                or not row["incorporation_digest"]
            ):
                raise ProgramFactsTypeError(
                    "completed worker transaction has invalid completion authority"
                )
        elif (
            not row["debt_digest"]
            or row["completion_digest"]
            or row["incorporation_digest"]
        ):
            raise ProgramFactsTypeError(
                "non-completed worker transaction requires exclusive debt authority"
            )
    work_unit_key = receipt["phase_io"]["work_unit_key"]
    work_unit_parts = work_unit_key.split("/")
    if (
        len(work_unit_parts) != 6
        or any(
            re.fullmatch(r"^[a-z0-9][a-z0-9_.-]*$", part) is None
            for part in work_unit_parts
        )
        or work_unit_parts[4:] != ["recon", "program_facts_bake"]
    ):
        raise ProgramFactsTypeError(
            "receipt PhaseIO work unit is not a canonical "
            "*/recon/program_facts_bake key"
        )


def validate_program_facts_receipt(
    value: Mapping[str, Any],
    *,
    provider_registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = _validate_schema("receipt", value)
    validate_signed_payload(receipt, "receipt_sha256")
    _validate_receipt_semantics(
        receipt,
        provider_registry=provider_registry,
    )
    return receipt


def derive_program_facts_reuse_key(
    *,
    payload: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> str:
    """Derive the Stage-1 exact-equivalence reuse key.

    Provider execution identity and policy are represented by stable digests,
    never version prose alone.  PhaseIO ledger ownership and CAS presence are
    validated by later loader/transaction packages and intentionally are not
    fabricated here.
    """

    provider_identity_digests = sorted(
        hashlib.sha256(
            canonical_json_bytes(
                {
                    "provider_id": row["provider_id"],
                    "provider_schema_version": row["provider_schema_version"],
                    "implementation_digest": row["implementation_digest"],
                    "executable_or_module_digest": row[
                        "executable_or_module_digest"
                    ],
                    "version_output_digest": row["version_output_digest"],
                }
            )
        ).hexdigest()
        for row in receipt["provider_runs"]
    )
    limits_and_policy_digest = hashlib.sha256(
        canonical_json_bytes(
            [
                {
                    "provider_run_id": row["provider_run_id"],
                    "provider_schema_version": row["provider_schema_version"],
                    "raw_schema_digest": row["raw_schema_digest"],
                    "provider_id": row["provider_id"],
                    "build_variant_ids": row["build_variant_ids"],
                    "capabilities_requested": row[
                        "capabilities_requested"
                    ],
                    "argv": row["argv"],
                    "working_directory_root_id": row[
                        "working_directory_root_id"
                    ],
                    "input_ceiling_bytes": row["input_ceiling_bytes"],
                    "output_ceiling_bytes": row["output_ceiling_bytes"],
                    "timeout_seconds": row["timeout_seconds"],
                    "allowed_environment": row["allowed_environment"],
                    "platform": row["platform"],
                }
                for row in receipt["provider_runs"]
            ]
        )
    ).hexdigest()
    build_attempt_plan_digests = sorted(
        hashlib.sha256(
            canonical_json_bytes(
                {
                    key: value
                    for key, value in row.items()
                    if key
                    not in {
                        "compiled_source_file_ids",
                        "failed_source_file_ids",
                        "stdout_cas_ref",
                        "stderr_cas_ref",
                        "stdout_truncated",
                        "stderr_truncated",
                        "outcome",
                        "debt_ids",
                    }
                }
            )
        ).hexdigest()
        for row in receipt["build_attempts"]
    )
    binding = {
        "source_authority_digest": receipt["source_authority_digest"],
        "audit_snapshot": {
            "snapshot_digest": receipt["audit_snapshot"]["snapshot_digest"],
            "source_scope_digest": receipt["audit_snapshot"][
                "source_scope_digest"
            ],
            "audit_config_digest": receipt["audit_snapshot"][
                "audit_config_digest"
            ],
            "methodology_digest": receipt["audit_snapshot"][
                "methodology_digest"
            ],
            "toolchain_digest": receipt["audit_snapshot"][
                "toolchain_digest"
            ],
        },
        "payload_snapshot_ref": payload["snapshot_ref"],
        "build_variant_digests": sorted(
            row["variant_digest"] for row in payload["build_variants"]
        ),
        "build_attempt_plan_digests": build_attempt_plan_digests,
        "provider_registry_digests": sorted(
            {row["provider_registry_digest"] for row in receipt["provider_runs"]}
        ),
        "provider_identity_digests": provider_identity_digests,
        "parser_digests": sorted(
            row["parser_source_digest"] for row in receipt["provider_runs"]
        ),
        "requested_capability_ids": sorted(
            set(payload["provider_capability_refs"])
            | {
                capability
                for row in receipt["provider_runs"]
                for capability in row["capabilities_requested"]
            }
        ),
        "provider_capability_assignments": [
            {
                "provider_run_id": row["provider_run_id"],
                "provider_id": row["provider_id"],
                "provider_registry_digest": row[
                    "provider_registry_digest"
                ],
                "provider_schema_version": row[
                    "provider_schema_version"
                ],
                "implementation_digest": row[
                    "implementation_digest"
                ],
                "executable_or_module_digest": row[
                    "executable_or_module_digest"
                ],
                "version_output_digest": row[
                    "version_output_digest"
                ],
                "parser_source_digest": row[
                    "parser_source_digest"
                ],
                "raw_schema_digest": row["raw_schema_digest"],
                "build_variant_ids": row["build_variant_ids"],
                "capabilities_requested": row["capabilities_requested"],
            }
            for row in receipt["provider_runs"]
        ],
        "limits_and_policy_digest": limits_and_policy_digest,
        "canonicalization_version": payload["canonicalization_version"],
        "payload_schema": payload["schema_version"],
        "receipt_schema": receipt["schema_version"],
        "debt_schema": "plamen.mechanical_program_facts_debt.v1",
    }
    return hashlib.sha256(canonical_json_bytes(binding)).hexdigest()


@dataclass(frozen=True, init=False)
class ProgramFactsPayload:
    value: Mapping[str, Any]

    def __init__(
        self,
        value: Mapping[str, Any],
        *,
        source_bytes_by_id: Mapping[str, bytes] | None,
    ) -> None:
        object.__setattr__(
            self,
            "value",
            _freeze_json(
                validate_program_facts_payload(
                    value,
                    source_bytes_by_id=source_bytes_by_id,
                )
            )
        )

    @classmethod
    def validate(
        cls,
        value: Mapping[str, Any],
        *,
        source_bytes_by_id: Mapping[str, bytes] | None,
    ) -> "ProgramFactsPayload":
        return cls(value, source_bytes_by_id=source_bytes_by_id)


@dataclass(frozen=True, init=False)
class ProgramFactsDebt:
    value: Mapping[str, Any]

    def __init__(self, value: Mapping[str, Any]) -> None:
        object.__setattr__(
            self,
            "value",
            _freeze_json(validate_program_facts_debt(value)),
        )

    @classmethod
    def validate(cls, value: Mapping[str, Any]) -> "ProgramFactsDebt":
        return cls(value)


@dataclass(frozen=True, init=False)
class ProgramFactsReceipt:
    value: Mapping[str, Any]

    def __init__(
        self,
        value: Mapping[str, Any],
        *,
        provider_registry: Mapping[str, Any] | None = None,
    ) -> None:
        object.__setattr__(
            self,
            "value",
            _freeze_json(
                validate_program_facts_receipt(
                    value,
                    provider_registry=provider_registry,
                )
            )
        )

    @classmethod
    def validate(
        cls,
        value: Mapping[str, Any],
        *,
        provider_registry: Mapping[str, Any] | None = None,
    ) -> "ProgramFactsReceipt":
        return cls(value, provider_registry=provider_registry)


@dataclass(frozen=True, init=False)
class ProgramFactsBundle:
    payload: ProgramFactsPayload
    debt: ProgramFactsDebt
    receipt: ProgramFactsReceipt

    def __init__(
        self,
        *,
        payload: Mapping[str, Any],
        debt: Mapping[str, Any],
        receipt: Mapping[str, Any] | None,
        payload_file_bytes: bytes,
        debt_file_bytes: bytes,
        receipt_file_bytes: bytes,
        source_bytes_by_id: Mapping[str, bytes] | None,
        source_manifest_authority: Any,
        audit_snapshot_authority: Any = None,
        source_project_root: str | Path | None = None,
        source_config: Mapping[str, Any] | None = None,
        expected_source_ledger_binding: Mapping[str, Any] | None = None,
        provider_registry: Mapping[str, Any] | None = None,
    ) -> None:
        if receipt is None:
            raise ProgramFactsTypeError(
                "canonical Program Facts bundle requires its receipt"
            )
        from program_facts_source_manifest import (
            ReplayedProgramFactsSourceManifest,
        )

        if type(source_manifest_authority) is not ReplayedProgramFactsSourceManifest:
            raise ProgramFactsTypeError(
                "production bundle requires exact replayed source authority"
            )
        if source_project_root is None or source_config is None:
            raise ProgramFactsTypeError(
                "production bundle requires live source project/config replay"
            )
        try:
            # Capture the caller-owned configuration exactly once at the
            # production ingress.  Both independent authority replays consume
            # this fresh built-in object, so a stateful Mapping cannot present
            # one project/scope to the snapshot authority and another to the
            # source authority.
            frozen_source_config = json.loads(canonical_json_bytes(source_config))
        except (TypeError, ValueError) as exc:
            raise ProgramFactsTypeError(
                "production bundle source config must be an exact JSON object"
            ) from exc
        if type(frozen_source_config) is not dict:
            raise ProgramFactsTypeError(
                "production bundle source config must be an exact JSON object"
            )
        trusted_audit_identity = _replayed_audit_snapshot_authority_binding(
            audit_snapshot_authority,
            project_root=source_project_root,
            config=frozen_source_config,
        )
        production_registry = _production_provider_registry_binding(
            provider_registry
        )
        receipt_parent = validate_program_facts_receipt(
            receipt,
            provider_registry=production_registry,
        )
        (
            source_authority_digest,
            authoritative_source_manifest,
            authoritative_snapshot_digest,
            authoritative_source_scope_digest,
        ) = _replayed_source_authority_binding(
            source_manifest_authority,
            expected_snapshot_digest=trusted_audit_identity.snapshot_digest,
            expected_source_scope_digest=(
                trusted_audit_identity.source_scope_digest
            ),
            project_root=source_project_root,
            config=frozen_source_config,
            expected_ledger_binding=expected_source_ledger_binding,
        )
        (
            payload_value,
            debt_value,
            receipt_value,
        ) = _validate_program_facts_bundle_values(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=payload_file_bytes,
            debt_file_bytes=debt_file_bytes,
            receipt_file_bytes=receipt_file_bytes,
            source_bytes_by_id=source_bytes_by_id,
            expected_source_authority_digest=source_authority_digest,
            authoritative_source_manifest=authoritative_source_manifest,
            authoritative_snapshot_digest=authoritative_snapshot_digest,
            authoritative_source_scope_digest=(
                authoritative_source_scope_digest
            ),
            authoritative_audit_identity=trusted_audit_identity.to_dict(),
            provider_registry=production_registry,
        )
        object.__setattr__(
            self,
            "payload",
            ProgramFactsPayload(
                payload_value,
                source_bytes_by_id=source_bytes_by_id,
            ),
        )
        object.__setattr__(self, "debt", ProgramFactsDebt(debt_value))
        object.__setattr__(
            self,
            "receipt",
            ProgramFactsReceipt(
                receipt_value,
                provider_registry=production_registry,
            ),
        )


def _production_provider_registry_binding(
    registry: Any,
) -> Mapping[str, Any] | None:
    """Return exact replayed production registry bytes as a plain mapping."""

    if registry is None:
        return None
    # Lazy import avoids the registry -> types import cycle.
    from program_facts_provider_registry import (
        LoadedProgramFactsProviderRegistry,
        ProgramFactsProviderRegistryError,
    )

    if type(registry) is not LoadedProgramFactsProviderRegistry:
        raise ProgramFactsTypeError(
            "production bundle provider registry requires exact loaded authority"
        )
    try:
        registry._assert_replayable()
    except ProgramFactsProviderRegistryError as exc:
        raise ProgramFactsTypeError(
            "production bundle provider registry failed authority replay"
        ) from exc
    if not registry.production_authority_established:
        raise ProgramFactsTypeError(
            "structural provider registry cannot authorize production bundle"
        )
    return registry.to_dict()


def _replayed_audit_snapshot_authority_binding(
    authority: Any,
    *,
    project_root: str | Path | None,
    config: Mapping[str, Any] | None,
) -> Any:
    from program_facts_source_manifest import (
        ProgramFactsAuditIdentity,
        ProgramFactsAuditSnapshotAuthority,
        ProgramFactsSourceManifestError,
        ReplayedProgramFactsAuditSnapshotAuthority,
        replay_program_facts_audit_snapshot_authority,
    )

    if type(authority) not in {
        ProgramFactsAuditSnapshotAuthority,
        ReplayedProgramFactsAuditSnapshotAuthority,
    }:
        raise ProgramFactsTypeError(
            "production bundle requires exact audit-snapshot authority"
        )
    if project_root is None or config is None:
        raise ProgramFactsTypeError(
            "production bundle requires live snapshot project/config replay"
        )
    try:
        frozen_config = json.loads(canonical_json_bytes(config))
        replayed = replay_program_facts_audit_snapshot_authority(
            authority,
            project_root=project_root,
            config=frozen_config,
        )
    except (ProgramFactsSourceManifestError, OSError, TypeError, ValueError) as exc:
        raise ProgramFactsTypeError(
            "production bundle audit-snapshot authority failed replay"
        ) from exc
    audit_identity = replayed.audit_identity
    if (
        type(audit_identity) is not ProgramFactsAuditIdentity
        or audit_identity.to_dict()
        != {
            "snapshot_digest": replayed.snapshot_digest,
            "source_scope_digest": replayed.source_scope_digest,
            "audit_config_digest": replayed.audit_config_digest,
            "methodology_digest": replayed.methodology_digest,
            "toolchain_digest": replayed.toolchain_digest,
        }
    ):
        raise ProgramFactsTypeError(
            "production bundle audit-snapshot identity failed replay"
        )
    return audit_identity


def _replayed_source_authority_binding(
    authority: Any,
    *,
    expected_snapshot_digest: str,
    expected_source_scope_digest: str,
    project_root: str | Path | None,
    config: Mapping[str, Any] | None,
    expected_ledger_binding: Mapping[str, Any] | None,
) -> tuple[str, Mapping[str, Any], str, str]:
    # This lazy import avoids a module cycle: source-manifest construction uses
    # the canonical primitives in this module.
    from program_facts_source_manifest import (
        ProgramFactsSourceManifestError,
        ReplayedProgramFactsSourceManifest,
        replay_program_facts_source_authority,
    )

    if type(authority) is not ReplayedProgramFactsSourceManifest:
        raise ProgramFactsTypeError(
            "production bundle requires exact replayed source authority"
        )
    if project_root is None or config is None:
        raise ProgramFactsTypeError(
            "production bundle requires live source project/config replay"
        )
    try:
        frozen_config = json.loads(canonical_json_bytes(config))
        if not isinstance(frozen_config, Mapping):
            raise ProgramFactsTypeError(
                "production bundle source config must be an exact JSON object"
            )
        replayed = replay_program_facts_source_authority(
            authority,
            expected_snapshot_digest=expected_snapshot_digest,
            expected_source_scope_digest=expected_source_scope_digest,
            project_root=project_root,
            config=frozen_config,
            expected_ledger_binding=expected_ledger_binding,
        )
    except (ProgramFactsSourceManifestError, OSError, TypeError, ValueError) as exc:
        raise ProgramFactsTypeError(
            "production bundle snapshot/source authority failed semantic replay"
        ) from exc
    record = replayed.record
    try:
        source_manifest = _json_value(record["source_manifest"])
        snapshot_ref = record["snapshot_ref"]
        authority_digest = replayed.authority_digest
        snapshot_digest = str(snapshot_ref["snapshot_digest"])
        source_scope_digest = str(snapshot_ref["source_scope_digest"])
    except (KeyError, TypeError) as exc:
        raise ProgramFactsTypeError(
            "replayed source authority public envelope is incomplete"
        ) from exc
    if snapshot_digest.startswith("sha256:"):
        snapshot_digest = snapshot_digest[7:]
    if source_scope_digest.startswith("sha256:"):
        source_scope_digest = source_scope_digest[7:]
    if (
        not isinstance(authority_digest, str)
        or _HEX64_RE.fullmatch(authority_digest) is None
        or _HEX64_RE.fullmatch(snapshot_digest) is None
        or _HEX64_RE.fullmatch(source_scope_digest) is None
        or not isinstance(source_manifest, Mapping)
    ):
        raise ProgramFactsTypeError(
            "replayed source authority public envelope is invalid"
        )
    if not replayed.parent_authority_established:
        raise ProgramFactsTypeError(
            "replayed source authority changed during bundle binding"
        )
    return (
        authority_digest,
        source_manifest,
        snapshot_digest,
        source_scope_digest,
    )


@dataclass(frozen=True, init=False)
class StructuralProgramFactsBundle:
    """Schema-only fixture result with no production or reuse authority."""

    payload: ProgramFactsPayload
    debt: ProgramFactsDebt
    receipt: ProgramFactsReceipt
    authority_state: str
    production_authority_established: bool
    completion_authority: str

    def __init__(
        self,
        *,
        payload: Mapping[str, Any],
        debt: Mapping[str, Any],
        receipt: Mapping[str, Any] | None,
        payload_file_bytes: bytes,
        debt_file_bytes: bytes,
        receipt_file_bytes: bytes,
        source_bytes_by_id: Mapping[str, bytes] | None,
        source_authority_digest: str,
        provider_registry: Mapping[str, Any] | None = None,
    ) -> None:
        payload_value, debt_value, receipt_value = (
            _validate_program_facts_bundle_values(
                payload=payload,
                debt=debt,
                receipt=receipt,
                payload_file_bytes=payload_file_bytes,
                debt_file_bytes=debt_file_bytes,
                receipt_file_bytes=receipt_file_bytes,
                source_bytes_by_id=source_bytes_by_id,
                expected_source_authority_digest=source_authority_digest,
                authoritative_source_manifest=None,
                authoritative_snapshot_digest="",
                authoritative_source_scope_digest="",
                authoritative_audit_identity=None,
                provider_registry=provider_registry,
            )
        )
        object.__setattr__(
            self,
            "payload",
            ProgramFactsPayload(
                payload_value,
                source_bytes_by_id=source_bytes_by_id,
            ),
        )
        object.__setattr__(self, "debt", ProgramFactsDebt(debt_value))
        object.__setattr__(
            self,
            "receipt",
            ProgramFactsReceipt(
                receipt_value,
                provider_registry=provider_registry,
            ),
        )
        object.__setattr__(self, "authority_state", STRUCTURAL_TEST_ONLY)
        object.__setattr__(
            self, "production_authority_established", False
        )
        object.__setattr__(
            self,
            "completion_authority",
            "PROVISIONAL_NO_PUBLICATION_AUTHORITY",
        )


def _validate_program_facts_bundle_values(
    *,
    payload: Mapping[str, Any],
    debt: Mapping[str, Any],
    receipt: Mapping[str, Any] | None,
    payload_file_bytes: bytes,
    debt_file_bytes: bytes,
    receipt_file_bytes: bytes,
    source_bytes_by_id: Mapping[str, bytes] | None,
    expected_source_authority_digest: str,
    authoritative_source_manifest: Mapping[str, Any] | None,
    authoritative_snapshot_digest: str,
    authoritative_source_scope_digest: str,
    authoritative_audit_identity: Mapping[str, str] | None,
    provider_registry: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if receipt is None:
        raise ProgramFactsTypeError(
            "canonical Program Facts bundle requires its receipt"
        )
    payload_value = validate_program_facts_payload(
        payload,
        source_bytes_by_id=source_bytes_by_id,
    )
    debt_value = validate_program_facts_debt(debt)
    receipt_value = validate_program_facts_receipt(
        receipt,
        provider_registry=provider_registry,
    )
    if (
        not isinstance(expected_source_authority_digest, str)
        or _HEX64_RE.fullmatch(expected_source_authority_digest) is None
    ):
        raise ProgramFactsTypeError(
            "bundle source authority digest must be lowercase 64-hex"
        )
    if (
        receipt_value["source_authority_digest"]
        != expected_source_authority_digest
    ):
        raise ProgramFactsTypeError("bundle source-authority digest mismatch")
    if authoritative_source_manifest is not None:
        if receipt_value["source_manifest"] != authoritative_source_manifest:
            raise ProgramFactsTypeError(
                "bundle source manifest differs from replayed source authority"
            )
        if (
            receipt_value["audit_snapshot"]["snapshot_digest"]
            != authoritative_snapshot_digest
            or receipt_value["audit_snapshot"]["source_scope_digest"]
            != authoritative_source_scope_digest
        ):
            raise ProgramFactsTypeError(
                "bundle snapshot differs from replayed source authority"
            )
    if authoritative_audit_identity is not None:
        if (
            type(authoritative_audit_identity) is not dict
            or receipt_value["audit_snapshot"]
            != authoritative_audit_identity
        ):
            raise ProgramFactsTypeError(
                "bundle audit identity differs from replayed audit-snapshot "
                "authority"
            )
    registry_value = (
        validate_program_facts_provider_registry(provider_registry)
        if provider_registry is not None
        else None
    )
    registry_by_id = (
        {row["provider_id"]: row for row in registry_value["providers"]}
        if registry_value is not None
        else {}
    )

    # Actual staged bytes are part of authority.  Re-canonicalizing a parsed
    # mapping is insufficient because it can hide whitespace/BOM/duplicate-key
    # differences in the file that PhaseIO will publish.
    parsed_payload = strict_json_loads(
        payload_file_bytes,
        require_final_lf=True,
        require_canonical=True,
    )
    parsed_debt = strict_json_loads(
        debt_file_bytes,
        require_final_lf=True,
        require_canonical=True,
    )
    parsed_receipt = strict_json_loads(
        receipt_file_bytes,
        require_final_lf=True,
        require_canonical=True,
    )
    if parsed_payload != payload_value:
        raise ProgramFactsTypeError(
            "facts artifact bytes do not equal the validated payload"
        )
    if parsed_debt != debt_value:
        raise ProgramFactsTypeError(
            "debt artifact bytes do not equal the validated debt"
        )
    if parsed_receipt != receipt_value:
        raise ProgramFactsTypeError(
            "receipt artifact bytes do not equal the validated receipt"
        )

    if payload_value["snapshot_ref"]["snapshot_digest"] != debt_value[
        "snapshot_digest"
    ]:
        raise ProgramFactsTypeError("bundle snapshot digest mismatch")
    if payload_value["snapshot_ref"]["source_manifest_digest"] != debt_value[
        "source_manifest_digest"
    ]:
        raise ProgramFactsTypeError("bundle source-manifest digest mismatch")
    if receipt_value["audit_snapshot"]["snapshot_digest"] != payload_value[
        "snapshot_ref"
    ]["snapshot_digest"]:
        raise ProgramFactsTypeError("receipt snapshot digest mismatch")
    if receipt_value["audit_snapshot"]["source_scope_digest"] != payload_value[
        "snapshot_ref"
    ]["source_scope_digest"]:
        raise ProgramFactsTypeError("receipt source-scope digest mismatch")
    if receipt_value["source_manifest"]["manifest_digest"] != payload_value[
        "snapshot_ref"
    ]["source_manifest_digest"]:
        raise ProgramFactsTypeError("receipt source-manifest digest mismatch")
    if receipt_value["source_manifest"]["eligible_files"] != payload_value[
        "source_files"
    ]:
        raise ProgramFactsTypeError(
            "receipt source manifest does not exactly match payload source rows"
        )

    artifact_inputs = {
        "facts": (
            payload_value["payload_sha256"],
            payload_file_bytes,
        ),
        "debt": (
            debt_value["debt_sha256"],
            debt_file_bytes,
        ),
    }
    for artifact_name, (document_digest, raw) in artifact_inputs.items():
        binding = receipt_value["artifacts"][artifact_name]
        if (
            binding["document_sha256"] != document_digest
            or binding["file_sha256"] != hashlib.sha256(raw).hexdigest()
            or binding["size"] != len(raw)
        ):
            raise ProgramFactsTypeError(
                f"{artifact_name} artifact binding mismatch"
            )

    debt_ids = {row["debt_id"] for row in debt_value["debts"]}
    debt_by_id = {row["debt_id"]: row for row in debt_value["debts"]}
    referenced_debt_ids: set[str] = set()
    for coverage in payload_value["coverage"]:
        if not set(coverage["unresolved_debt_ids"]) <= debt_ids:
            raise ProgramFactsTypeError("coverage has a dangling debt reference")
        for debt_id in coverage["unresolved_debt_ids"]:
            debt_row = debt_by_id[debt_id]
            if debt_row["capability_id"] and debt_row["capability_id"] != coverage[
                "capability_id"
            ]:
                raise ProgramFactsTypeError(
                    "coverage debt capability does not match its coverage row"
                )
            if debt_row["build_variant_id"] and debt_row[
                "build_variant_id"
            ] != coverage["build_variant_id"]:
                raise ProgramFactsTypeError(
                    "coverage debt build variant does not match its coverage row"
                )
        referenced_debt_ids.update(coverage["unresolved_debt_ids"])

    unsupported = [
        row for row in payload_value["coverage"] if row["status"] == "UNSUPPORTED"
    ]
    if payload_value["ecosystem"] == "daml" and not unsupported:
        raise ProgramFactsTypeError(
            "unsupported ecosystem requires explicit UNSUPPORTED coverage"
        )
    if not payload_value["coverage"]:
        raise ProgramFactsTypeError(
            "canonical bundle requires explicit coverage/debt accounting"
        )
    if unsupported and not debt_value["debts"]:
        raise ProgramFactsTypeError(
            "unsupported coverage requires at least one visible debt row"
        )

    variant_by_id = {
        row["build_variant_id"]: row for row in payload_value["build_variants"]
    }
    source_ids = {row["source_file_id"] for row in payload_value["source_files"]}
    capability_ids = set(payload_value["provider_capability_refs"])
    provider_runs = {
        row["provider_run_id"]: row for row in receipt_value["provider_runs"]
    }
    for build in receipt_value["build_attempts"]:
        variant = variant_by_id.get(build["build_variant_id"])
        if variant is None:
            raise ProgramFactsTypeError(
                "build attempt has a dangling build-variant reference"
            )
        if build["variant_digest"] != variant["variant_digest"]:
            raise ProgramFactsTypeError("build attempt variant digest mismatch")
        for field in (
            "build_root_id",
            "manifest_digests",
            "dependency_closure_digest",
            "target_triples",
            "profile",
            "features",
            "tags",
            "remappings",
            "defines",
            "generated_source_policy",
        ):
            if build[field] != variant[field]:
                raise ProgramFactsTypeError(
                    f"build attempt {field} does not match its payload variant"
                )
        if variant["compiler_identity_digest"] not in {
            item["identity_digest"] for item in build["toolchain_identities"]
        }:
            raise ProgramFactsTypeError(
                "build attempt does not bind the variant compiler identity"
            )
        referenced_debt_ids.update(build["debt_ids"])
        for debt_id in build["debt_ids"]:
            debt_row = debt_by_id.get(debt_id)
            if debt_row is None:
                raise ProgramFactsTypeError(
                    "build attempt has a dangling debt reference"
                )
            if debt_row["build_variant_id"] and debt_row[
                "build_variant_id"
            ] != build["build_variant_id"]:
                raise ProgramFactsTypeError(
                    "build debt does not match its build variant"
                )

    for provider in receipt_value["provider_runs"]:
        requested = set(provider["capabilities_requested"])
        if not requested <= capability_ids:
            raise ProgramFactsTypeError(
                "provider run capability is outside the payload capability set"
            )
        if not set(provider["build_variant_ids"]) <= set(variant_by_id):
            raise ProgramFactsTypeError(
                "provider run has a dangling build-variant target"
            )
        referenced_debt_ids.update(provider["debt_ids"])
        for debt_id in provider["debt_ids"]:
            debt_row = debt_by_id.get(debt_id)
            if debt_row is None:
                raise ProgramFactsTypeError(
                    "provider run has a dangling debt reference"
                )
            if debt_row["provider_id"] and debt_row["provider_id"] != provider[
                "provider_id"
            ]:
                raise ProgramFactsTypeError(
                    "provider debt does not match its provider run"
                )
            if debt_row["capability_id"] and debt_row[
                "capability_id"
            ] not in provider["capabilities_requested"]:
                raise ProgramFactsTypeError(
                    "provider debt capability was not requested"
                )
        registry_row = registry_by_id[provider["provider_id"]]
        supported_ecosystems = set(registry_row["supported_ecosystems"])
        payload_ecosystems = (
            {row["ecosystem"] for row in payload_value["build_variants"]}
            if payload_value["ecosystem"] == "mixed"
            else {payload_value["ecosystem"]}
        )
        if not supported_ecosystems & payload_ecosystems:
            raise ProgramFactsTypeError(
                "provider is not registered for the payload ecosystem"
            )
        supported_platforms = {
            (platform["os"], architecture)
            for platform in registry_row["supported_platforms"]
            for architecture in platform["architectures"]
        }
        platform_key = (
            provider["platform"]["os"],
            provider["platform"]["architecture"],
        )
        if platform_key not in supported_platforms:
            raise ProgramFactsTypeError(
                "provider execution platform is outside the registry"
            )
    if provider_runs and set(variant_by_id) != {
        row["build_variant_id"] for row in receipt_value["build_attempts"]
    }:
        raise ProgramFactsTypeError(
            "provider execution requires one exact build attempt per payload variant"
        )
    build_by_variant = {
        row["build_variant_id"]: row for row in receipt_value["build_attempts"]
    }
    source_language_by_id = {
        row["source_file_id"]: row["language"]
        for row in payload_value["source_files"]
    }
    coverage_by_pair = {
        (row["capability_id"], row["build_variant_id"]): row
        for row in payload_value["coverage"]
    }

    def provider_supports_languages(
        provider_run: Mapping[str, Any],
        eligible_source_file_ids: Sequence[str],
    ) -> bool:
        eligible_languages = {
            source_language_by_id[source_id]
            for source_id in eligible_source_file_ids
        }
        return eligible_languages <= set(
            registry_by_id[provider_run["provider_id"]][
                "supported_languages"
            ]
        )

    def provider_supports_toolchain(
        provider_run: Mapping[str, Any],
        build_variant_id: str,
    ) -> bool:
        build = build_by_variant.get(build_variant_id)
        toolchain_ranges = registry_by_id[provider_run["provider_id"]][
            "toolchain_ranges"
        ]
        if build is None:
            return not toolchain_ranges
        observed_tools = {
            item["name"]: item["version"]
            for item in build["toolchain_identities"]
        }
        return all(
            tool_range["toolchain"] in observed_tools
            and _version_satisfies(
                observed_tools[tool_range["toolchain"]],
                tool_range["version_range"],
            )
            for tool_range in toolchain_ranges
        )

    for coverage in payload_value["coverage"]:
        capability = coverage["capability_id"]
        capability_runs = [
            row
            for row in receipt_value["provider_runs"]
            if capability in row["capabilities_requested"]
        ]
        variant_runs = [
            row
            for row in capability_runs
            if coverage["build_variant_id"] in row["build_variant_ids"]
        ]
        if capability_runs and not variant_runs:
            raise ProgramFactsTypeError(
                "provider execution does not target the coverage build variant"
            )
        build = build_by_variant.get(coverage["build_variant_id"])
        if build is not None:
            if set(coverage["eligible_source_file_ids"]) != set(
                build["eligible_source_file_ids"]
            ):
                raise ProgramFactsTypeError(
                    "coverage denominator does not match the exact build denominator"
                )
            if set(coverage["excluded_source_file_ids"]) != set(
                build["excluded_source_file_ids"]
            ):
                raise ProgramFactsTypeError(
                    "coverage exclusions do not match the exact build denominator"
                )
            if not set(coverage["covered_source_file_ids"]) <= set(
                build["compiled_source_file_ids"]
            ):
                raise ProgramFactsTypeError(
                    "coverage claims sources outside the compiled build denominator"
                )
        elif set(coverage["eligible_source_file_ids"]) != source_ids:
            raise ProgramFactsTypeError(
                "coverage without a build must retain the exact source denominator"
            )

        language_compatible_runs = [
            row
            for row in variant_runs
            if provider_supports_languages(
                row,
                coverage["eligible_source_file_ids"],
            )
        ]
        if variant_runs and not language_compatible_runs:
            raise ProgramFactsTypeError(
                "provider language authority does not cover the coverage denominator"
            )

        authoritative_runs = [
            row
            for row in language_compatible_runs
            if provider_supports_toolchain(
                row,
                coverage["build_variant_id"],
            )
        ]
        if language_compatible_runs and not authoritative_runs:
            raise ProgramFactsTypeError(
                "provider toolchain version is outside registry authority"
            )
        if coverage["status"] == "FULL" and not any(
            capability in row["capabilities_emitted"]
            for row in authoritative_runs
        ):
            raise ProgramFactsTypeError(
                "FULL coverage lacks provider execution authority"
            )
        if coverage["status"] == "FULL" and (
            coverage["build_variant_id"] not in build_by_variant
            or build_by_variant[coverage["build_variant_id"]]["outcome"]
            != "SUCCEEDED"
        ):
            raise ProgramFactsTypeError(
                "FULL coverage lacks a successful exact build"
            )
        if coverage["status"] == "PARTIAL" and not any(
            capability in row["capabilities_partial"]
            or capability in row["capabilities_emitted"]
            for row in authoritative_runs
        ):
            raise ProgramFactsTypeError(
                "PARTIAL coverage lacks provider execution/debt authority"
            )

    for fact in payload_value["facts"]:
        provider = provider_runs.get(fact["provider_run_id"])
        if provider is None:
            raise ProgramFactsTypeError(
                "fact has a dangling receipt provider-run reference"
            )
        if (
            fact["build_variant_id"] not in build_by_variant
            or build_by_variant[fact["build_variant_id"]]["outcome"]
            != "SUCCEEDED"
        ):
            raise ProgramFactsTypeError(
                "fact cannot mint authority from a non-successful build"
            )
        fact_coverage = coverage_by_pair[
            (fact["capability_id"], fact["build_variant_id"])
        ]
        if fact["build_variant_id"] not in provider["build_variant_ids"]:
            raise ProgramFactsTypeError(
                "fact provider run does not target the fact build variant"
            )
        if not provider_supports_languages(
            provider,
            fact_coverage["eligible_source_file_ids"],
        ):
            raise ProgramFactsTypeError(
                "fact provider language authority does not cover its build variant"
            )
        if not provider_supports_toolchain(
            provider,
            fact["build_variant_id"],
        ):
            raise ProgramFactsTypeError(
                "fact provider toolchain authority does not cover its build variant"
            )
        provider_fact_capabilities = set(provider["capabilities_emitted"]) | set(
            provider["capabilities_partial"]
        )
        if fact["capability_id"] not in provider_fact_capabilities:
            raise ProgramFactsTypeError(
                "fact capability was not emitted or retained as partial "
                "proposal material by its provider run"
            )
        if fact["capability_id"] in provider["capabilities_partial"] and not any(
            coverage["capability_id"] == fact["capability_id"]
            and coverage["build_variant_id"] == fact["build_variant_id"]
            and coverage["status"] == "PARTIAL"
            for coverage in payload_value["coverage"]
        ):
            raise ProgramFactsTypeError(
                "partial provider fact lacks PARTIAL coverage/debt authority"
            )
        capability_row = next(
            row
            for row in registry_by_id[provider["provider_id"]]["capabilities"]
            if row["capability_id"] == fact["capability_id"]
        )
        precision_rank = {
            "SYNTACTIC": 0,
            "HEURISTIC": 1,
            "MAY": 2,
            "EXACT": 3,
        }
        if precision_rank[fact["precision"]] > precision_rank[
            capability_row["maximum_precision"]
        ]:
            raise ProgramFactsTypeError(
                "fact precision exceeds provider registry authority"
            )
        for attestation in fact["attestations"]:
            if attestation not in provider_runs:
                raise ProgramFactsTypeError(
                    "fact attestation has a dangling provider-run reference"
                )
            attestation_capabilities = set(
                provider_runs[attestation]["capabilities_emitted"]
            ) | set(provider_runs[attestation]["capabilities_partial"])
            if fact["capability_id"] not in attestation_capabilities:
                raise ProgramFactsTypeError(
                    "fact attestation did not emit or partially retain the "
                    "fact capability"
                )
            attestation_run = provider_runs[attestation]
            if fact["build_variant_id"] not in attestation_run[
                "build_variant_ids"
            ]:
                raise ProgramFactsTypeError(
                    "fact attestation does not target the fact build variant"
                )
            if not provider_supports_languages(
                attestation_run,
                fact_coverage["eligible_source_file_ids"],
            ):
                raise ProgramFactsTypeError(
                    "fact attestation language authority does not cover its build variant"
                )
            if not provider_supports_toolchain(
                attestation_run,
                fact["build_variant_id"],
            ):
                raise ProgramFactsTypeError(
                    "fact attestation toolchain authority does not cover its build variant"
                )
            attestation_registry_row = registry_by_id[
                attestation_run["provider_id"]
            ]
            attestation_capability = next(
                (
                    row
                    for row in attestation_registry_row["capabilities"]
                    if row["capability_id"] == fact["capability_id"]
                ),
                None,
            )
            if attestation_capability is None or precision_rank[
                fact["precision"]
            ] > precision_rank[attestation_capability["maximum_precision"]]:
                raise ProgramFactsTypeError(
                    "fact attestation exceeds provider registry authority"
                )

    typed_scopes = {
        "PFS-": source_ids,
        "PFB-": set(variant_by_id),
        "PFN-": {row["node_id"] for row in payload_value["nodes"]},
        "PFO-": {row["occurrence_id"] for row in payload_value["occurrences"]},
        "PFF-": {row["fact_id"] for row in payload_value["facts"]},
        "PFC-": {row["coverage_id"] for row in payload_value["coverage"]},
    }
    for excluded in receipt_value["source_manifest"]["excluded_files"]:
        matching_debt = [
            row
            for row in debt_value["debts"]
            if row["reason"] == "SOURCE_EXCLUDED"
            and excluded["identity"] in row["scope_ids"]
        ]
        if len(matching_debt) != 1:
            raise ProgramFactsTypeError(
                "source manifest exclusion requires exactly one SOURCE_EXCLUDED debt"
            )
        referenced_debt_ids.add(matching_debt[0]["debt_id"])
    for debt_row in debt_value["debts"]:
        if (
            debt_row["build_variant_id"]
            and debt_row["build_variant_id"] not in variant_by_id
        ):
            raise ProgramFactsTypeError("debt has a dangling build reference")
        if (
            debt_row["capability_id"]
            and debt_row["capability_id"] not in capability_ids
        ):
            raise ProgramFactsTypeError("debt has a dangling capability reference")
        if (
            provider_registry is not None
            and debt_row["provider_id"]
            and debt_row["provider_id"] not in registry_by_id
        ):
            raise ProgramFactsTypeError("debt has a dangling provider reference")
        for scope_id in debt_row["scope_ids"]:
            for prefix, identities in typed_scopes.items():
                if scope_id.startswith(prefix) and scope_id not in identities:
                    raise ProgramFactsTypeError(
                        f"debt has a dangling {prefix[:-1]} scope"
                    )
        if debt_row["capability_id"]:
            coverage_refs = [
                coverage
                for coverage in payload_value["coverage"]
                if debt_row["debt_id"] in coverage["unresolved_debt_ids"]
            ]
            if not coverage_refs:
                raise ProgramFactsTypeError(
                    "capability-scoped debt is absent from coverage accounting"
                )

    if referenced_debt_ids != debt_ids:
        missing = sorted(debt_ids - referenced_debt_ids)
        dangling = sorted(referenced_debt_ids - debt_ids)
        detail = missing or dangling
        raise ProgramFactsTypeError(
            f"debt accounting is not total: {detail}"
        )

    covered_variants = {
        row["build_variant_id"] for row in payload_value["coverage"]
    }
    if covered_variants != set(variant_by_id):
        raise ProgramFactsTypeError(
            "coverage accounting does not include every build variant"
        )

    receipt_status = receipt_value["status"]
    coverage_statuses = {row["status"] for row in payload_value["coverage"]}
    if receipt_status in {"WRITTEN", "REUSED"}:
        if coverage_statuses - {"FULL"}:
            raise ProgramFactsTypeError(
                "successful receipt cannot hide degraded coverage"
            )
        if debt_value["summary"]["has_blocking_reuse_debt"]:
            raise ProgramFactsTypeError(
                "successful receipt cannot carry blocking reuse debt"
            )
        if debt_ids:
            raise ProgramFactsTypeError(
                "successful receipt cannot hide unresolved debt"
            )
    elif receipt_status == "DEGRADED":
        if not debt_ids:
            raise ProgramFactsTypeError("DEGRADED receipt requires visible debt")
    elif receipt_status == "UNAVAILABLE":
        if (
            payload_value["nodes"]
            or payload_value["occurrences"]
            or payload_value["facts"]
            or not debt_ids
            or (
                coverage_statuses
                and not coverage_statuses <= {"UNSUPPORTED", "UNKNOWN"}
            )
        ):
            raise ProgramFactsTypeError(
                "UNAVAILABLE receipt must be a zero-structure unsupported/debt bundle"
            )
    elif receipt_status == "FAILED":
        if (
            payload_value["nodes"]
            or payload_value["occurrences"]
            or payload_value["facts"]
            or not debt_ids
        ):
            raise ProgramFactsTypeError(
                "FAILED receipt must retain zero structure and visible debt"
            )
    elif receipt_status == "STALE":
        stale_rows = [
            row
            for row in debt_value["debts"]
            if row["reason"] == "STALE_SNAPSHOT" and row["blocks_reuse"]
        ]
        if not stale_rows:
            raise ProgramFactsTypeError(
                "STALE receipt requires blocking stale-snapshot debt"
            )

    if receipt_value["reuse_key"] != derive_program_facts_reuse_key(
        payload=payload_value,
        receipt=receipt_value,
    ):
        raise ProgramFactsTypeError("receipt reuse key mismatch")

    return payload_value, debt_value, receipt_value


def validate_program_facts_bundle(
    *,
    payload: Mapping[str, Any],
    debt: Mapping[str, Any],
    receipt: Mapping[str, Any] | None,
    payload_file_bytes: bytes,
    debt_file_bytes: bytes,
    receipt_file_bytes: bytes,
    source_bytes_by_id: Mapping[str, bytes] | None,
    source_manifest_authority: Any,
    audit_snapshot_authority: Any = None,
    source_project_root: str | Path | None = None,
    source_config: Mapping[str, Any] | None = None,
    expected_source_ledger_binding: Mapping[str, Any] | None = None,
    provider_registry: Mapping[str, Any] | None = None,
) -> ProgramFactsBundle:
    """Construct a bundle only after replaying every cross-document binding."""

    return ProgramFactsBundle(
        payload=payload,
        debt=debt,
        receipt=receipt,
        payload_file_bytes=payload_file_bytes,
        debt_file_bytes=debt_file_bytes,
        receipt_file_bytes=receipt_file_bytes,
        source_bytes_by_id=source_bytes_by_id,
        source_manifest_authority=source_manifest_authority,
        audit_snapshot_authority=audit_snapshot_authority,
        source_project_root=source_project_root,
        source_config=source_config,
        expected_source_ledger_binding=expected_source_ledger_binding,
        provider_registry=provider_registry,
    )


def validate_program_facts_bundle_structural_test_only(
    *,
    authority_mode: str,
    payload: Mapping[str, Any],
    debt: Mapping[str, Any],
    receipt: Mapping[str, Any] | None,
    payload_file_bytes: bytes,
    debt_file_bytes: bytes,
    receipt_file_bytes: bytes,
    source_bytes_by_id: Mapping[str, bytes] | None,
    source_authority_digest: str,
    provider_registry: Mapping[str, Any] | None = None,
) -> StructuralProgramFactsBundle:
    """Validate synthetic schema fixtures without minting production authority."""

    if authority_mode != STRUCTURAL_TEST_ONLY:
        raise ProgramFactsTypeError(
            "structural bundle validation requires explicit "
            "STRUCTURAL_TEST_ONLY authority mode"
        )
    return StructuralProgramFactsBundle(
        payload=payload,
        debt=debt,
        receipt=receipt,
        payload_file_bytes=payload_file_bytes,
        debt_file_bytes=debt_file_bytes,
        receipt_file_bytes=receipt_file_bytes,
        source_bytes_by_id=source_bytes_by_id,
        source_authority_digest=source_authority_digest,
        provider_registry=provider_registry,
    )


__all__ = [
    "CANONICALIZATION_VERSION",
    "DEFAULT_MAX_JSON_BYTES",
    "ProgramFactsTypeError",
    "ProgramFactsBundle",
    "ProgramFactsDebt",
    "ProgramFactsPayload",
    "ProgramFactsReceipt",
    "StructuralProgramFactsBundle",
    "STRUCTURAL_TEST_ONLY",
    "canonical_file_bytes",
    "canonical_json_bytes",
    "derive_debt_id",
    "derive_fact_id",
    "derive_node_id",
    "derive_occurrence_id",
    "derive_program_facts_reuse_key",
    "derive_source_manifest_digest",
    "derive_stable_id",
    "signed_payload",
    "strict_json_loads",
    "validate_portable_path",
    "validate_program_facts_bundle",
    "validate_program_facts_bundle_structural_test_only",
    "validate_program_facts_debt",
    "validate_program_facts_payload",
    "validate_program_facts_payload_shape",
    "validate_program_facts_provider_registry",
    "validate_program_facts_receipt",
    "validate_signed_payload",
    "validate_stable_id",
]
