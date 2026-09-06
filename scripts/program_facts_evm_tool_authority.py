"""Pinned, model-free EVM Program Facts tool identity.

The manifest binds the checked-in helper, the parser implementation, the raw
schema, and exact Slither distribution artifacts.  It grants no launch,
execution, publication, or semantic authority.  Production analysis remains
disabled until the helper's semantic extractor and its cross-OS fixtures are
independently accepted.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping

from jsonschema import Draft202012Validator

import rooted_path_io
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_json_bytes,
    strict_json_loads,
    validate_portable_path,
)


EVM_TOOL_MANIFEST_SCHEMA = "plamen.program_facts_evm_tool_manifest.v1"
EVM_TOOL_MANIFEST_AUTHORITY = (
    "PINNED_TOOL_IDENTITY_NO_EXECUTION_AUTHORITY"
)
EVM_ANALYSIS_RELEASE_STATE = "DISABLED_PENDING_SEMANTIC_REVIEW"
STRUCTURAL_TEST_ONLY = "STRUCTURAL_TEST_ONLY"
INSTALLED_PINNED_AUTHORITY = "INSTALLED_PINNED_AUTHORITY"
DEFAULT_MAX_TOOL_AUTHORITY_BYTES = 16 * 1024 * 1024
PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "runtime-data",
        "mode": "file",
        "path": "rules/program-facts-evm-tool-manifest.v1.json",
    },
    {
        "kind": "runtime-data",
        "mode": "named-files",
        "root": "rules/schemas",
        "names": (
            "program_facts_evm_tool_manifest.v1.schema.json",
            "program_facts_evm_slither_raw.v1.schema.json",
        ),
    },
    {
        "kind": "runtime-data",
        "mode": "file",
        "path": "scripts/program_facts_evm_helper.py",
    },
)

_ROOT = Path(__file__).resolve().parents[1]
EVM_TOOL_MANIFEST_PATH = (
    _ROOT / "rules" / "program-facts-evm-tool-manifest.v1.json"
)
EVM_TOOL_MANIFEST_SCHEMA_PATH = (
    _ROOT
    / "rules"
    / "schemas"
    / "program_facts_evm_tool_manifest.v1.schema.json"
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class ProgramFactsEvmToolAuthorityError(ValueError):
    """The installed EVM tool identity failed exact replay."""


def _fail(message: str, exc: BaseException | None = None) -> None:
    if exc is None:
        raise ProgramFactsEvmToolAuthorityError(message)
    raise ProgramFactsEvmToolAuthorityError(message) from exc


def _read(path: Path, *, label: str, max_bytes: int) -> bytes:
    try:
        raw = rooted_path_io.read_bytes(
            path,
            label=label,
            require_single_link=False,
        )
    except (OSError, rooted_path_io.RootedPathIOError) as exc:
        _fail(f"{label} is unavailable or aliased", exc)
    if len(raw) > max_bytes:
        _fail(f"{label} exceeds the byte ceiling")
    return raw


def _load_schema(max_bytes: int) -> Mapping[str, Any]:
    raw = _read(
        EVM_TOOL_MANIFEST_SCHEMA_PATH,
        label="EVM tool-manifest schema",
        max_bytes=max_bytes,
    )
    try:
        value = strict_json_loads(
            raw,
            require_final_lf=True,
            require_canonical=False,
            max_bytes=max_bytes,
        )
    except ProgramFactsTypeError as exc:
        _fail("EVM tool-manifest schema is invalid JSON", exc)
    if (
        not isinstance(value, Mapping)
        or value.get("$schema")
        != "https://json-schema.org/draft/2020-12/schema"
        or value.get("additionalProperties") is not False
    ):
        _fail("EVM tool-manifest schema is not closed")
    try:
        Draft202012Validator.check_schema(value)
    except Exception as exc:
        _fail("EVM tool-manifest JSON Schema is invalid", exc)
    return value


def _parse_manifest(
    raw: bytes,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    try:
        value = strict_json_loads(
            raw,
            require_final_lf=True,
            require_canonical=True,
            max_bytes=max_bytes,
        )
    except ProgramFactsTypeError as exc:
        _fail("EVM tool manifest is not exact canonical JSON", exc)
    if not isinstance(value, Mapping):
        _fail("EVM tool manifest must be an object")
    schema = _load_schema(max_bytes)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda error: tuple(str(item) for item in error.absolute_path),
    )
    if errors:
        _fail(f"EVM tool manifest schema rejected: {errors[0].message}")
    normalized = dict(value)
    supplied = normalized.pop("manifest_sha256")
    if (
        not isinstance(supplied, str)
        or _HEX64_RE.fullmatch(supplied) is None
        or hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
        != supplied
    ):
        _fail("EVM tool manifest self-digest mismatch")
    return dict(value)


def _replay_sources(
    value: Mapping[str, Any],
    *,
    root: Path,
    max_bytes: int,
) -> None:
    for label in ("helper", "parser", "raw_schema"):
        row = value[label]
        identity = row["source_identity"]
        try:
            validate_portable_path(identity)
        except ProgramFactsTypeError as exc:
            _fail(f"{label} source identity is not portable", exc)
        source_path = root.joinpath(*identity.split("/"))
        raw = _read(
            source_path,
            label=f"EVM {label} source",
            max_bytes=max_bytes,
        )
        if len(raw) != row["size_bytes"]:
            _fail(f"{label} source size differs from the manifest")
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            _fail(f"{label} source digest differs from the manifest")


@dataclass(frozen=True)
class EvmToolAuthority:
    authority_state: str
    value: Mapping[str, Any]
    canonical_bytes: bytes
    manifest_file_sha256: str
    installed_root: Path
    max_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            MappingProxyType(dict(self.value)),
        )

    @property
    def production_ready(self) -> bool:
        # Deliberately derived from the reviewed release-state constant.  A
        # caller cannot relabel a structural or disabled manifest as ready.
        return False

    @property
    def analysis_release_state(self) -> str:
        return str(self.value["analysis_release_state"])

    @property
    def unavailable_reason(self) -> str:
        return "PROVIDER_UNAVAILABLE"

    @property
    def helper_name(self) -> str:
        return "plamen-evm-slither-helper"

    @property
    def helper_version(self) -> str:
        return "1.0.0"

    @property
    def slither_version(self) -> str:
        return str(self.value["slither_distribution"]["version"])

    @property
    def manifest_digest(self) -> str:
        return str(self.value["manifest_sha256"])

    def to_dict(self) -> dict[str, Any]:
        return {
            key: (
                dict(item)
                if isinstance(item, Mapping)
                else item
            )
            for key, item in self.value.items()
        }

    def replay(self) -> "EvmToolAuthority":
        if self.authority_state == INSTALLED_PINNED_AUTHORITY:
            replayed = load_installed_evm_tool_authority(
                max_bytes=self.max_bytes
            )
        elif self.authority_state == STRUCTURAL_TEST_ONLY:
            replayed = validate_evm_tool_manifest_bytes_structural_test_only(
                self.canonical_bytes,
                max_bytes=self.max_bytes,
            )
        else:
            _fail("EVM tool authority state is invalid")
        if (
            replayed.canonical_bytes != self.canonical_bytes
            or replayed.manifest_file_sha256
            != self.manifest_file_sha256
            or replayed.to_dict() != self.to_dict()
        ):
            _fail("EVM tool authority changed during replay")
        return replayed


def _load(
    raw: bytes,
    *,
    authority_state: str,
    root: Path,
    max_bytes: int,
) -> EvmToolAuthority:
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes <= 0
    ):
        _fail("EVM tool authority max_bytes must be positive")
    value = _parse_manifest(raw, max_bytes=max_bytes)
    if (
        value["schema_version"] != EVM_TOOL_MANIFEST_SCHEMA
        or value["authority"] != EVM_TOOL_MANIFEST_AUTHORITY
        or value["analysis_release_state"] != EVM_ANALYSIS_RELEASE_STATE
        or value["terminal_negative_authority"] is not False
    ):
        _fail("EVM tool manifest authority/release state drift")
    _replay_sources(value, root=root, max_bytes=max_bytes)
    return EvmToolAuthority(
        authority_state=authority_state,
        value=value,
        canonical_bytes=bytes(raw),
        manifest_file_sha256=hashlib.sha256(raw).hexdigest(),
        installed_root=root,
        max_bytes=max_bytes,
    )


def load_installed_evm_tool_authority(
    *,
    max_bytes: int = DEFAULT_MAX_TOOL_AUTHORITY_BYTES,
) -> EvmToolAuthority:
    """Load only the manifest anchored beside this installed module."""

    raw = _read(
        EVM_TOOL_MANIFEST_PATH,
        label="installed EVM tool manifest",
        max_bytes=max_bytes,
    )
    return _load(
        raw,
        authority_state=INSTALLED_PINNED_AUTHORITY,
        root=_ROOT,
        max_bytes=max_bytes,
    )


def validate_evm_tool_manifest_bytes_structural_test_only(
    raw: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_TOOL_AUTHORITY_BYTES,
) -> EvmToolAuthority:
    """Validate arbitrary fixture bytes without granting installed authority."""

    if type(raw) is not bytes:
        _fail("structural EVM tool manifest must be exact bytes")
    return _load(
        raw,
        authority_state=STRUCTURAL_TEST_ONLY,
        root=_ROOT,
        max_bytes=max_bytes,
    )


__all__ = [
    "DEFAULT_MAX_TOOL_AUTHORITY_BYTES",
    "EVM_ANALYSIS_RELEASE_STATE",
    "EVM_TOOL_MANIFEST_PATH",
    "EvmToolAuthority",
    "ProgramFactsEvmToolAuthorityError",
    "load_installed_evm_tool_authority",
    "validate_evm_tool_manifest_bytes_structural_test_only",
]
