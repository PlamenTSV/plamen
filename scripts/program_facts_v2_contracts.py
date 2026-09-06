"""Shared pure validation helpers for Program Facts v2 control artifacts.

The helpers in this module deliberately perform no discovery and no writes.
Callers must supply the exact document and evidence bytes that are already in
their authority boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator

from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
    validate_portable_path,
    validate_signed_payload,
)


SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "rules" / "schemas"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


@lru_cache(maxsize=32)
def schema_validator(schema_name: str) -> Draft202012Validator:
    if (
        not isinstance(schema_name, str)
        or not schema_name.endswith(".schema.json")
        or "/" in schema_name
        or "\\" in schema_name
    ):
        raise ProgramFactsTypeError("invalid schema name")
    path = SCHEMA_ROOT / schema_name
    try:
        raw = path.read_bytes()
        schema = json.loads(raw.decode("utf-8", errors="strict"))
        Draft202012Validator.check_schema(schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProgramFactsTypeError(
            f"cannot load Program Facts schema {schema_name!r}"
        ) from exc
    return Draft202012Validator(schema)


def normalized_document(
    value: Mapping[str, Any],
    *,
    schema_name: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProgramFactsTypeError(f"{label} must be an object")
    normalized = strict_json_loads(
        canonical_json_bytes(value),
        require_canonical=True,
    )
    if not isinstance(normalized, dict):
        raise ProgramFactsTypeError(f"{label} must be an object")
    errors = sorted(
        schema_validator(schema_name).iter_errors(normalized),
        key=lambda error: tuple(str(item) for item in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "$"
        if first.absolute_path:
            location += "." + ".".join(str(item) for item in first.absolute_path)
        raise ProgramFactsTypeError(
            f"{label} schema violation at {location}: {first.message}"
        )
    return normalized


def require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
        raise ProgramFactsTypeError(f"{label} must be lowercase SHA-256")
    return value


def require_sorted_unique(
    values: Sequence[Any],
    *,
    label: str,
    key: str | None = None,
    casefold: bool = False,
) -> None:
    observed: list[str] = []
    for item in values:
        candidate: Any
        if key is None:
            candidate = item
        elif isinstance(item, Mapping):
            candidate = item.get(key)
        else:
            candidate = None
        if not isinstance(candidate, str):
            raise ProgramFactsTypeError(f"{label} contains a non-string identity")
        observed.append(candidate.casefold() if casefold else candidate)
    if observed != sorted(observed):
        raise ProgramFactsTypeError(f"{label} must be canonically sorted")
    if len(observed) != len(set(observed)):
        raise ProgramFactsTypeError(f"{label} contains duplicate identities")


def require_exact_keys(
    value: Mapping[str, Any],
    *,
    required: frozenset[str],
    label: str,
) -> None:
    keys = frozenset(value)
    if keys != required:
        missing = sorted(required - keys)
        extra = sorted(keys - required)
        raise ProgramFactsTypeError(
            f"{label} keys mismatch; missing={missing!r}, extra={extra!r}"
        )


def require_relative_file_path(path: Any, *, label: str) -> str:
    if not isinstance(path, str):
        raise ProgramFactsTypeError(f"{label} must be a string")
    validate_portable_path(path)
    name = path.rsplit("/", 1)[-1]
    if "*" in path or "?" in path or "[" in path or "]" in path:
        raise ProgramFactsTypeError(f"{label} must not contain glob syntax")
    if "." not in name or name.endswith("."):
        raise ProgramFactsTypeError(f"{label} must identify a file, not a directory")
    return path


def full_file_binding(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise ProgramFactsTypeError("bound file content must be bytes")
    return {
        "size": len(raw),
        "full_file_sha256": hashlib.sha256(raw).hexdigest(),
    }


__all__ = [
    "ProgramFactsTypeError",
    "canonical_file_bytes",
    "canonical_json_bytes",
    "full_file_binding",
    "normalized_document",
    "require_exact_keys",
    "require_relative_file_path",
    "require_sha256",
    "require_sorted_unique",
    "schema_validator",
    "validate_signed_payload",
]
