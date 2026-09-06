"""Pure provider protocol and exact policy validation for Program Facts.

The API separates four things that must not be conflated:

* :class:`ProviderContext` is deterministic driver input.
* :class:`ProviderPlan` is reviewed intent, not permission to execute.
* :class:`ProviderResult` is provisional parsing output, never process success.
* :class:`FactContribution` is additive proposal material, never publication
  authority or a clean/negative conclusion.

There is intentionally no subprocess, network, import, environment read, host
inspection, model call, or executable resolution in this module.

Trust boundary
--------------
The Python orchestrator process, interpreter, loaded deterministic gate code,
code objects and closure cells, and the installed methodology files captured
by that gate form the trusted computing base (TCB).  Worker, provider, and
model execution occurs outside that boundary; their configuration, protocol,
and artifact bytes are untrusted until replayed here.

Arbitrary code execution in the orchestrator, or mutation of its loaded code
objects or closure cells, is a TCB compromise and is deliberately outside this
data-validation threat model.  No Python seal, private name, caller-code check,
or closure can withstand an attacker that can rewrite the validating program
itself.  That risk requires OS process isolation, code/package integrity, and
deployment controls.  Semantic replay remains mandatory for every untrusted
byte or object crossing into the intact TCB.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
import hashlib
import inspect
import json
from pathlib import Path
import re
import threading
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable
import weakref

from jsonschema import Draft202012Validator

from program_facts_provider_registry import (
    INSTALLED_PRODUCTION_AUTHORITY,
    LoadedProgramFactsProviderRegistry,
    ProviderPolicyDebt,
    ProviderPolicyDebtCode,
    STRUCTURAL_TEST_ONLY,
    _new_provider_policy_debt,
)
from program_facts_source_manifest import (
    ParsedProgramFactsSourceManifest,
    ProgramFactsAuditIdentity,
    ProgramFactsAuditSnapshotAuthority,
    ReplayedProgramFactsSourceManifest,
    ReplayedProgramFactsAuditSnapshotAuthority,
    parse_program_facts_source_manifest_shape,
    replay_program_facts_audit_snapshot_authority,
    replay_program_facts_source_authority,
)
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_json_bytes,
    derive_stable_id,
    strict_json_loads,
)


PROVIDER_CONTEXT_SCHEMA = "plamen.program_facts_provider_context.v1"
PROVIDER_PLAN_SCHEMA = "plamen.program_facts_provider_plan.v1"
PROVIDER_RESULT_SCHEMA = "plamen.program_facts_provider_result.v1"
PARSED_PROVIDER_OUTPUT_SCHEMA = "plamen.parsed_provider_output.v1"
PROVIDER_SOURCE_INPUT_SNAPSHOT_SCHEMA = (
    "plamen.provider_source_input_snapshot.v1"
)
ZERO_POSITIVE_ACCOUNTING_SCHEMA = "plamen.zero_positive_accounting.v1"
FACT_CONTRIBUTION_SCHEMA = "plamen.program_facts_fact_contribution.v1"
PROVISIONAL_AUTHORITY = "PROVISIONAL_NO_PUBLICATION_AUTHORITY"
TCB_CODE_MUTATION_DISPOSITION = (
    "OUT_OF_THREAT_MODEL_TCB_CODE_MUTATION_REQUIRES_OS_PROCESS_INTEGRITY"
)
PROGRAM_FACTS_TRUST_BOUNDARY = MappingProxyType(
    {
        "schema_version": "plamen.program_facts_trust_boundary.v1",
        "trusted_computing_base": (
            "python_orchestrator_process",
            "python_interpreter_and_loaded_dependencies",
            "loaded_code_objects_and_closure_cells",
            "installed_methodology_files_and_exact_capture",
            "deterministic_gate_and_semantic_replay_code",
        ),
        "untrusted_surfaces": (
            "worker_process_outputs",
            "provider_process_outputs",
            "model_outputs",
            "configuration_bytes",
            "artifact_and_protocol_bytes",
            "reflection_constructed_data_carriers",
        ),
        "out_of_threat_model": (
            "arbitrary_code_execution_inside_the_tcb",
            "loaded_code_or_closure_cell_mutation",
            "interpreter_or_gate_code_replacement",
        ),
        "required_external_controls": (
            "os_process_isolation",
            "code_and_package_integrity",
            "installed_methodology_access_control",
        ),
    }
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$", re.ASCII)
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", re.ASCII)
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$", re.ASCII)
_SECRET_NAME_RE = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|"
    r"CREDENTIAL|AUTH)",
    re.ASCII,
)
_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$", re.ASCII)
_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$", re.ASCII)
_PRECISION_RANK = {
    "SYNTACTIC": 0,
    "HEURISTIC": 1,
    "MAY": 2,
    "EXACT": 3,
}
_RESULT_STATES = frozenset(
    {
        "PROVISIONAL_PARSED",
        "PROVISIONAL_DEGRADED",
        "PROVISIONAL_UNAVAILABLE",
        "PROVISIONAL_FAILED",
    }
)
_AUTHORITY = {
    "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
    "terminal_negative_authority": False,
    "can_suppress": False,
    "can_demote": False,
    "can_refute": False,
    "can_mark_examined": False,
    "can_certify_clean": False,
}
_ZERO_POSITIVE_AUTHORITY = {
    "semantic_authority": "ACCOUNTING_ONLY",
    "terminal_negative_authority": False,
    "can_suppress": False,
    "can_demote": False,
    "can_refute": False,
    "can_mark_examined": False,
    "can_certify_clean": False,
}
_CONTEXT_KEYS = frozenset(
    {
        "schema_version",
        "audit_run_id",
        "methodology_authority_digest",
        "snapshot_digest",
        "source_scope_digest",
        "source_manifest_digest",
        "source_authority_digest",
        "ecosystem",
        "languages",
        "build_variant_ids",
        "capability_requests",
        "toolchains",
        "platform",
        "environment",
        "working_directory_root_id",
    }
)
_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "plan_id",
        "audit_run_id",
        "methodology_authority_digest",
        "snapshot_digest",
        "source_scope_digest",
        "source_manifest_digest",
        "source_authority_digest",
        "provider_id",
        "provider_run_id",
        "provider_schema_version",
        "registry_digest",
        "context_digest",
        "toolchains",
        "adapter",
        "raw_binding",
        "tool_identity",
        "distribution",
        "version_output",
        "version_output_digest",
        "license_classification",
        "platform",
        "build_variant_ids",
        "capability_requests",
        "argv",
        "configuration_inputs",
        "invocation_policy_digest",
        "environment",
        "working_directory_root_id",
        "resources",
        "fallback_from_provider_id",
        "install_binding",
        "network_during_bake",
        "authority",
        "completion_authority",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "result_digest",
        "audit_run_id",
        "methodology_authority_digest",
        "registry_digest",
        "context_digest",
        "source_manifest_digest",
        "source_authority_digest",
        "plan_id",
        "provider_id",
        "provider_run_id",
        "result_state",
        "raw_output_sha256",
        "raw_output_size",
        "raw_schema_digest",
        "parser_callable",
        "parser_source_digest",
        "capabilities_parsed",
        "capabilities_partial",
        "capabilities_unavailable",
        "capability_diagnostics",
        "authority",
        "completion_authority",
    }
)
_CONTRIBUTION_KEYS = frozenset(
    {
        "schema_version",
        "contribution_id",
        "audit_run_id",
        "methodology_authority_digest",
        "registry_digest",
        "context_digest",
        "source_manifest_digest",
        "source_authority_digest",
        "plan_id",
        "result_digest",
        "provider_id",
        "provider_run_id",
        "build_variant_ids",
        "capability_ids",
        "nodes",
        "occurrences",
        "facts",
        "debt_codes",
        "capability_accounting",
        "authority",
        "completion_authority",
    }
)
_PARSED_PROVIDER_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "carrier_digest",
        "result",
        "parsed_payload_schema",
        "parsed_payload_digest",
        "parsed_payload",
        "authority",
        "completion_authority",
    }
)
_ZERO_POSITIVE_ACCOUNTING_KEYS = frozenset(
    {
        "schema_version",
        "accounting_digest",
        "capability_id",
        "result_digest",
        "source_authority_digest",
        "denominators",
        "authority",
    }
)
_ZERO_POSITIVE_DENOMINATOR_BASE_KEYS = frozenset(
    {
        "build_variant_id",
        "denominator_kind",
        "denominator_ids",
    }
)
_ZERO_POSITIVE_DENOMINATOR_WIRE_KEYS = frozenset(
    {
        *_ZERO_POSITIVE_DENOMINATOR_BASE_KEYS,
        "denominator_precision",
        "denominator_count",
        "denominator_digest",
    }
)
_PLAN_DECISION_SEAL = object()
_DIAGNOSTIC_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$", re.ASCII)
_MECHANICAL_DEBT_CODES = frozenset(
    {
        "PROVIDER_UNAVAILABLE",
        "PROVIDER_UNSUPPORTED_ECOSYSTEM",
        "PROVIDER_IDENTITY_UNBOUND",
        "PROVIDER_VERSION_DRIFT",
        "EXECUTABLE_DIGEST_DRIFT",
        "PARSER_DIGEST_DRIFT",
        "BUILD_CONFIGURATION_UNRESOLVED",
        "BUILD_FAILED",
        "BUILD_PARTIAL",
        "DEPENDENCY_CLOSURE_UNRESOLVED",
        "GENERATED_SOURCE_UNBOUND",
        "SOURCE_EXCLUDED",
        "SOURCE_CHANGED_DURING_RUN",
        "SOURCE_CASE_COLLISION",
        "SOURCE_ESCAPE_REJECTED",
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
        "PROVIDER_DISAGREEMENT",
        "CAPABILITY_PARTIAL",
        "OS_PROCESS_SCOPE_UNPROVEN",
        "WORKER_TRANSACTION_INCOMPLETE",
        "PHASE_IO_INCORPORATION_FAILED",
        "STALE_SNAPSHOT",
        "UNSUPPORTED_HOST_SEMANTICS",
        "LICENSE_OR_DISTRIBUTION_RESTRICTED",
    }
)


class ProgramFactsProviderAPIError(ValueError):
    """A protocol value is malformed, noncanonical, or overclaims authority."""


def _fail(message: str, exc: Exception | None = None) -> None:
    if exc is None:
        raise ProgramFactsProviderAPIError(message)
    raise ProgramFactsProviderAPIError(message) from exc


def _exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        detail: list[str] = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unknown " + ", ".join(extra))
        _fail(f"{label} schema drift: {'; '.join(detail)}")


def _hex64(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        _fail(f"{label} must be lowercase 64-hex")
    return value


def _provider_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _fail(f"{label} must be a canonical provider/capability ID")
    return value


def _opaque_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        _fail(f"{label} must be a non-path opaque identity")
    return value


def _host_path_shaped(value: str) -> bool:
    return bool(
        value.startswith(("/", "\\", "~"))
        or re.match(r"^[A-Za-z]:[\\/]", value)
        or value.casefold().startswith("file://")
    )


def _sorted_unique_strings(
    values: Sequence[str], label: str, *, allow_empty: bool = True
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        _fail(f"{label} must be an array")
    result = tuple(values)
    if any(not isinstance(item, str) or not item for item in result):
        _fail(f"{label} must contain nonempty strings")
    if not allow_empty and not result:
        _fail(f"{label} must not be empty")
    if result != tuple(sorted(result)):
        _fail(f"{label} must be sorted")
    if len(result) != len(set(result)):
        _fail(f"{label} contains duplicate identities")
    return result


def _json_mapping_tuple(
    values: Sequence[Mapping[str, Any]], label: str
) -> tuple[Mapping[str, Any], ...]:
    if isinstance(values, (str, bytes, bytearray)):
        _fail(f"{label} must be an array")
    result: list[Mapping[str, Any]] = []
    for value in values:
        if not isinstance(value, Mapping):
            _fail(f"{label} must contain objects")
        try:
            # This validates the JSON data model, floats, Unicode, and keys.
            normalized = json.loads(canonical_json_bytes(value))
        except (ProgramFactsTypeError, UnicodeDecodeError) as exc:
            _fail(f"{label} contains noncanonical JSON", exc)
        result.append(normalized)
    return tuple(result)


def _strict_protocol_mapping(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(
            raw,
            require_final_lf=False,
            require_canonical=True,
        )
    except ProgramFactsTypeError as exc:
        _fail(f"{label} bytes are invalid: {exc}", exc)
    if not isinstance(value, Mapping):
        _fail(f"{label} bytes must encode an object")
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_json(item) for item in value]
    return value


def _snapshot_json_value_once(value: Any, label: str, path: str) -> Any:
    if isinstance(value, Mapping):
        try:
            items = tuple(value.items())
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            _fail(f"{label} changed while snapshotting {path}", exc)
        seen: set[str] = set()
        copied: dict[str, Any] = {}
        for key, item in items:
            if not isinstance(key, str):
                _fail(f"{label} contains a non-string key at {path}")
            if key in seen:
                _fail(f"{label} contains a duplicate key at {path}: {key}")
            seen.add(key)
            copied[key] = _snapshot_json_value_once(
                item,
                label,
                f"{path}.{key}",
            )
        frozen = MappingProxyType(
            {key: copied[key] for key in sorted(copied)}
        )
        return frozen
    if isinstance(value, (list, tuple)):
        try:
            items = tuple(value)
        except (RuntimeError, TypeError, ValueError) as exc:
            _fail(f"{label} changed while snapshotting {path}", exc)
        frozen_items = tuple(
            _snapshot_json_value_once(item, label, f"{path}[{index}]")
            for index, item in enumerate(items)
        )
        return frozen_items
    if value is None or type(value) in {bool, int, str}:
        return value
    _fail(f"{label} contains a non-JSON value at {path}")


def _snapshot_json_once(value: Any, label: str) -> Any:
    """Recursively copy an untrusted JSON view without revisiting it."""

    frozen = _snapshot_json_value_once(value, label, "$")
    try:
        canonical_json_bytes(frozen)
    except (ProgramFactsTypeError, TypeError, ValueError) as exc:
        _fail(f"{label} is not canonical JSON", exc)
    return frozen


def _snapshot_source_bytes_once(
    source_bytes_by_id: Mapping[str, bytes],
) -> Mapping[str, bytes]:
    if not isinstance(source_bytes_by_id, Mapping):
        _fail("provider source bytes must be a mapping")
    try:
        items = tuple(source_bytes_by_id.items())
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        _fail("provider source bytes changed while snapshotting", exc)
    copied: dict[str, bytes] = {}
    for source_file_id, raw in items:
        _opaque_id(source_file_id, "provider source-file ID")
        if source_file_id in copied:
            _fail(
                "provider source bytes contain a duplicate source-file ID: "
                f"{source_file_id}"
            )
        if type(raw) is not bytes:
            _fail("provider source-byte values must be exact bytes")
        copied[source_file_id] = memoryview(raw).tobytes()
    return MappingProxyType(
        {source_file_id: copied[source_file_id] for source_file_id in sorted(copied)}
    )


def _schema_references_are_local(value: Any) -> bool:
    if isinstance(value, Mapping):
        reference = value.get("$ref")
        if reference is not None and (
            not isinstance(reference, str) or not reference.startswith("#/")
        ):
            return False
        return all(
            _schema_references_are_local(item) for item in value.values()
        )
    if isinstance(value, list):
        return all(_schema_references_are_local(item) for item in value)
    return True


def _numeric_version(value: str, label: str) -> tuple[int, ...]:
    if re.fullmatch(r"\d+(?:\.\d+)*", value) is None:
        _fail(f"{label} must be a dotted numeric version")
    return tuple(int(part) for part in value.split("."))


def _version_satisfies(version: str, version_range: str) -> bool:
    candidate = _numeric_version(version, "toolchain version")
    for raw_clause in version_range.split(","):
        match = re.fullmatch(
            r"\s*(>=|<=|==|!=|>|<)\s*(\d+(?:\.\d+)*)\s*",
            raw_clause,
        )
        if match is None:
            _fail("registry toolchain range is unsupported")
        boundary = _numeric_version(match.group(2), "toolchain range")
        width = max(len(candidate), len(boundary))
        left = candidate + (0,) * (width - len(candidate))
        right = boundary + (0,) * (width - len(boundary))
        comparison = (left > right) - (left < right)
        operator = match.group(1)
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


@dataclass(frozen=True, order=True)
class CapabilityRequest:
    capability_id: str
    maximum_precision: str

    def __post_init__(self) -> None:
        _provider_id(self.capability_id, "capability_id")
        if self.maximum_precision not in _PRECISION_RANK:
            _fail("capability maximum_precision is invalid")

    def to_dict(self) -> dict[str, str]:
        return {
            "capability_id": self.capability_id,
            "maximum_precision": self.maximum_precision,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityRequest":
        _exact_keys(
            value,
            frozenset({"capability_id", "maximum_precision"}),
            "capability request",
        )
        return cls(
            capability_id=value["capability_id"],
            maximum_precision=value["maximum_precision"],
        )


@dataclass(frozen=True, order=True)
class ToolchainIdentity:
    name: str
    version: str
    identity_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            _fail("toolchain name must be nonempty")
        _numeric_version(self.version, "toolchain version")
        _hex64(self.identity_digest, "toolchain identity digest")

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "identity_digest": self.identity_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolchainIdentity":
        _exact_keys(
            value,
            frozenset({"name", "version", "identity_digest"}),
            "toolchain identity",
        )
        return cls(
            name=value["name"],
            version=value["version"],
            identity_digest=value["identity_digest"],
        )


@dataclass(frozen=True, order=True)
class EnvironmentBinding:
    name: str
    value_digest: str
    is_secret: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _ENV_NAME_RE.fullmatch(self.name) is None:
            _fail("environment name is invalid")
        _hex64(self.value_digest, "environment value digest")
        if not isinstance(self.is_secret, bool):
            _fail("environment is_secret must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value_digest": self.value_digest,
            "is_secret": self.is_secret,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EnvironmentBinding":
        _exact_keys(
            value,
            frozenset({"name", "value_digest", "is_secret"}),
            "environment binding",
        )
        return cls(
            name=value["name"],
            value_digest=value["value_digest"],
            is_secret=value["is_secret"],
        )


@dataclass(frozen=True)
class PlatformIdentity:
    os: str
    architecture: str

    def __post_init__(self) -> None:
        if self.os not in {"windows", "linux", "macos"}:
            _fail("platform OS spelling is unsupported")
        if self.architecture not in {"amd64", "arm64"}:
            _fail("platform architecture spelling is unsupported")

    def to_dict(self) -> dict[str, str]:
        return {"os": self.os, "architecture": self.architecture}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PlatformIdentity":
        _exact_keys(
            value, frozenset({"os", "architecture"}), "platform identity"
        )
        return cls(os=value["os"], architecture=value["architecture"])


@dataclass(frozen=True)
class ProviderResources:
    time_seconds: int
    memory_bytes: int
    input_bytes: int
    output_bytes: int

    def __post_init__(self) -> None:
        for field in (
            "time_seconds",
            "memory_bytes",
            "input_bytes",
            "output_bytes",
        ):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                _fail(f"provider resource {field} must be a positive integer")

    def to_dict(self) -> dict[str, int]:
        return {
            "time_seconds": self.time_seconds,
            "memory_bytes": self.memory_bytes,
            "input_bytes": self.input_bytes,
            "output_bytes": self.output_bytes,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProviderResources":
        _exact_keys(
            value,
            frozenset(
                {"time_seconds", "memory_bytes", "input_bytes", "output_bytes"}
            ),
            "provider resources",
        )
        return cls(**dict(value))


@dataclass(frozen=True)
class ProviderSourceInputSnapshot:
    """One-read immutable source/manifest/build trust-boundary snapshot."""

    source_bytes_by_id: Mapping[str, bytes]
    source_manifest: Mapping[str, Any]
    build_inputs: Mapping[str, Any]
    _source_byte_records: tuple[Mapping[str, Any], ...] = field(
        init=False,
        repr=False,
        compare=True,
    )
    _source_manifest_digest: str = field(
        init=False,
        repr=False,
        compare=True,
    )
    _build_inputs_digest: str = field(
        init=False,
        repr=False,
        compare=True,
    )
    _binding_digest: str = field(
        init=False,
        repr=False,
        compare=True,
    )

    def __post_init__(self) -> None:
        source_bytes = _snapshot_source_bytes_once(self.source_bytes_by_id)
        if not isinstance(self.source_manifest, Mapping):
            _fail("provider source manifest must be a mapping")
        if not isinstance(self.build_inputs, Mapping):
            _fail("provider build inputs must be a mapping")
        source_manifest = _snapshot_json_once(
            self.source_manifest,
            "provider source manifest",
        )
        build_inputs = _snapshot_json_once(
            self.build_inputs,
            "provider build inputs",
        )
        assert isinstance(source_manifest, Mapping)
        assert isinstance(build_inputs, Mapping)
        source_records = tuple(
            _freeze_json(
                {
                    "source_file_id": source_file_id,
                    "byte_count": len(source_bytes[source_file_id]),
                    "sha256": hashlib.sha256(
                        source_bytes[source_file_id]
                    ).hexdigest(),
                }
            )
            for source_file_id in source_bytes
        )
        source_manifest_digest = hashlib.sha256(
            canonical_json_bytes(_thaw_json(source_manifest))
        ).hexdigest()
        build_inputs_digest = hashlib.sha256(
            canonical_json_bytes(_thaw_json(build_inputs))
        ).hexdigest()
        binding = {
            "schema_version": PROVIDER_SOURCE_INPUT_SNAPSHOT_SCHEMA,
            "source_byte_records": [
                _thaw_json(row) for row in source_records
            ],
            "source_manifest_digest": source_manifest_digest,
            "build_inputs_digest": build_inputs_digest,
        }
        object.__setattr__(self, "source_bytes_by_id", source_bytes)
        object.__setattr__(self, "source_manifest", source_manifest)
        object.__setattr__(self, "build_inputs", build_inputs)
        object.__setattr__(self, "_source_byte_records", source_records)
        object.__setattr__(
            self,
            "_source_manifest_digest",
            source_manifest_digest,
        )
        object.__setattr__(self, "_build_inputs_digest", build_inputs_digest)
        object.__setattr__(
            self,
            "_binding_digest",
            hashlib.sha256(canonical_json_bytes(binding)).hexdigest(),
        )

    @property
    def source_byte_records(self) -> tuple[Mapping[str, Any], ...]:
        return self._source_byte_records

    @property
    def source_manifest_digest(self) -> str:
        return self._source_manifest_digest

    @property
    def build_inputs_digest(self) -> str:
        return self._build_inputs_digest

    @property
    def binding_digest(self) -> str:
        return self._binding_digest

    def binding_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROVIDER_SOURCE_INPUT_SNAPSHOT_SCHEMA,
            "binding_digest": self.binding_digest,
            "source_byte_records": [
                _thaw_json(row) for row in self.source_byte_records
            ],
            "source_manifest_digest": self.source_manifest_digest,
            "build_inputs_digest": self.build_inputs_digest,
        }

    def canonical_binding_bytes(self) -> bytes:
        return canonical_json_bytes(self.binding_dict())


def snapshot_provider_source_inputs(
    *,
    source_bytes_by_id: Mapping[str, bytes],
    source_manifest: Mapping[str, Any],
    build_inputs: Mapping[str, Any],
) -> ProviderSourceInputSnapshot:
    """Capture every caller-owned source input exactly once."""

    return ProviderSourceInputSnapshot(
        source_bytes_by_id=source_bytes_by_id,
        source_manifest=source_manifest,
        build_inputs=build_inputs,
    )


def replay_provider_source_input_snapshot(
    snapshot: ProviderSourceInputSnapshot,
) -> ProviderSourceInputSnapshot:
    """Recompute all keys, sizes, and digests from only frozen snapshot views."""

    if type(snapshot) is not ProviderSourceInputSnapshot:
        _fail("provider source input replay requires an exact snapshot")
    expected_binding = snapshot.binding_dict()
    replayed = ProviderSourceInputSnapshot(
        source_bytes_by_id=snapshot.source_bytes_by_id,
        source_manifest=snapshot.source_manifest,
        build_inputs=snapshot.build_inputs,
    )
    if replayed.binding_dict() != expected_binding:
        _fail("provider source input snapshot failed immutable replay")
    return replayed


@dataclass(frozen=True)
class ProviderContext:
    """Driver-supplied immutable context; never inferred from this host."""

    audit_run_id: str
    methodology_authority_digest: str
    snapshot_digest: str
    source_scope_digest: str
    source_manifest_digest: str
    source_authority_digest: str
    ecosystem: str
    languages: tuple[str, ...]
    build_variant_ids: tuple[str, ...]
    capability_requests: tuple[CapabilityRequest, ...]
    toolchains: tuple[ToolchainIdentity, ...]
    platform: PlatformIdentity
    environment: tuple[EnvironmentBinding, ...]
    working_directory_root_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "languages", tuple(self.languages))
        object.__setattr__(
            self, "build_variant_ids", tuple(self.build_variant_ids)
        )
        object.__setattr__(
            self, "capability_requests", tuple(self.capability_requests)
        )
        object.__setattr__(self, "toolchains", tuple(self.toolchains))
        object.__setattr__(self, "environment", tuple(self.environment))
        for field in (
            "methodology_authority_digest",
            "snapshot_digest",
            "source_scope_digest",
            "source_manifest_digest",
            "source_authority_digest",
        ):
            _hex64(getattr(self, field), field)
        _opaque_id(self.audit_run_id, "audit run ID")
        if not isinstance(self.platform, PlatformIdentity):
            _fail("provider context platform must be typed")
        if self.ecosystem not in {
            "evm",
            "go",
            "rust",
            "solana",
            "soroban",
            "aptos",
            "sui",
            "daml",
            "mixed",
        }:
            _fail("provider context ecosystem is unsupported")
        _sorted_unique_strings(self.languages, "context languages", allow_empty=False)
        _sorted_unique_strings(
            self.build_variant_ids,
            "context build variants",
            allow_empty=False,
        )
        if any(
            not isinstance(item, CapabilityRequest)
            for item in self.capability_requests
        ):
            _fail("context capability requests must be typed")
        if not self.capability_requests:
            _fail("context capability request denominator must not be empty")
        capability_ids = tuple(item.capability_id for item in self.capability_requests)
        if capability_ids != tuple(sorted(capability_ids)) or len(
            capability_ids
        ) != len(set(capability_ids)):
            _fail("context capability requests must be sorted and unique")
        if any(
            not isinstance(item, ToolchainIdentity) for item in self.toolchains
        ):
            _fail("context toolchains must be typed")
        toolchain_names = tuple(item.name for item in self.toolchains)
        if toolchain_names != tuple(sorted(toolchain_names)) or len(
            toolchain_names
        ) != len(set(toolchain_names)):
            _fail("context toolchains must be sorted and unique")
        if any(
            not isinstance(item, EnvironmentBinding)
            for item in self.environment
        ):
            _fail("context environment must be typed")
        environment_names = tuple(item.name for item in self.environment)
        if environment_names != tuple(sorted(environment_names)) or len(
            environment_names
        ) != len(set(environment_names)):
            _fail("context environment must be sorted and unique")
        _opaque_id(self.working_directory_root_id, "working directory root ID")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROVIDER_CONTEXT_SCHEMA,
            "audit_run_id": self.audit_run_id,
            "methodology_authority_digest": self.methodology_authority_digest,
            "snapshot_digest": self.snapshot_digest,
            "source_scope_digest": self.source_scope_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "source_authority_digest": self.source_authority_digest,
            "ecosystem": self.ecosystem,
            "languages": list(self.languages),
            "build_variant_ids": list(self.build_variant_ids),
            "capability_requests": [
                item.to_dict() for item in self.capability_requests
            ],
            "toolchains": [item.to_dict() for item in self.toolchains],
            "platform": self.platform.to_dict(),
            "environment": [item.to_dict() for item in self.environment],
            "working_directory_root_id": self.working_directory_root_id,
        }

    @property
    def context_digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProviderContext":
        _exact_keys(value, _CONTEXT_KEYS, "provider context")
        if value["schema_version"] != PROVIDER_CONTEXT_SCHEMA:
            _fail("provider context schema version drift")
        return cls(
            audit_run_id=value["audit_run_id"],
            methodology_authority_digest=value[
                "methodology_authority_digest"
            ],
            snapshot_digest=value["snapshot_digest"],
            source_scope_digest=value["source_scope_digest"],
            source_manifest_digest=value["source_manifest_digest"],
            source_authority_digest=value["source_authority_digest"],
            ecosystem=value["ecosystem"],
            languages=tuple(value["languages"]),
            build_variant_ids=tuple(value["build_variant_ids"]),
            capability_requests=tuple(
                CapabilityRequest.from_dict(item)
                for item in value["capability_requests"]
            ),
            toolchains=tuple(
                ToolchainIdentity.from_dict(item) for item in value["toolchains"]
            ),
            platform=PlatformIdentity.from_dict(value["platform"]),
            environment=tuple(
                EnvironmentBinding.from_dict(item)
                for item in value["environment"]
            ),
            working_directory_root_id=value["working_directory_root_id"],
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ProviderContext":
        return cls.from_dict(_strict_protocol_mapping(raw, "provider context"))


@dataclass(frozen=True)
class ObservedProviderIdentity:
    """Explicit observation supplied by trusted pre-arm preparation.

    Constructing this value does not prove the observation.  The later
    WorkerTransaction receipt remains execution authority; this value only
    allows a deterministic equality check against the reviewed registry.
    """

    registry_digest: str
    provider_schema_version: str
    adapter_module: str
    adapter_symbol: str
    parser_callable: str
    parser_source_digest: str
    raw_schema_digest: str
    tool_kind: str
    tool_name: str
    command: str
    module: str
    executable_sha256: str
    module_sha256: str
    distribution_kind: str
    distribution_name: str
    distribution_version: str
    distribution_checksum: str
    distribution_module_source_digest: str
    version_output: str
    license_classification: str
    platform: PlatformIdentity
    installation_mode: str
    installation_lock_identity: str
    installation_lock_digest: str

    def __post_init__(self) -> None:
        text_fields = (
            "registry_digest",
            "provider_schema_version",
            "adapter_module",
            "adapter_symbol",
            "parser_callable",
            "parser_source_digest",
            "raw_schema_digest",
            "tool_kind",
            "tool_name",
            "command",
            "module",
            "executable_sha256",
            "module_sha256",
            "distribution_kind",
            "distribution_name",
            "distribution_version",
            "distribution_checksum",
            "distribution_module_source_digest",
            "version_output",
            "license_classification",
            "installation_mode",
            "installation_lock_identity",
            "installation_lock_digest",
        )
        if any(not isinstance(getattr(self, name), str) for name in text_fields):
            _fail("observed provider identity fields must be exact text")
        if not isinstance(self.platform, PlatformIdentity):
            _fail("observed provider platform must be typed")
        for field in (
            "registry_digest",
            "parser_source_digest",
            "raw_schema_digest",
            "distribution_checksum",
            "installation_lock_digest",
        ):
            _hex64(getattr(self, field), field)
        for field in (
            "executable_sha256",
            "module_sha256",
            "distribution_module_source_digest",
        ):
            _hex64(getattr(self, field), field, allow_empty=True)
        if (
            not self.version_output
            or "\n" in self.version_output
            or "\r" in self.version_output
        ):
            _fail("version output must be one exact line")

    @property
    def version_output_digest(self) -> str:
        return hashlib.sha256(self.version_output.encode("utf-8")).hexdigest()


@dataclass(frozen=True, eq=False)
class ProviderPlan:
    """Exact provider intent.  This object carries no launch authority."""

    audit_run_id: str
    methodology_authority_digest: str
    snapshot_digest: str
    source_scope_digest: str
    source_manifest_digest: str
    source_authority_digest: str
    provider_id: str
    provider_run_id: str
    provider_schema_version: str
    registry_digest: str
    context_digest: str
    toolchains: tuple[ToolchainIdentity, ...]
    adapter: Mapping[str, str]
    raw_binding: Mapping[str, str]
    tool_identity: Mapping[str, str]
    distribution: Mapping[str, str]
    version_output: str
    version_output_digest: str
    license_classification: str
    platform: PlatformIdentity
    build_variant_ids: tuple[str, ...]
    capability_requests: tuple[CapabilityRequest, ...]
    argv: tuple[str, ...]
    configuration_inputs: tuple[Mapping[str, str], ...]
    invocation_policy_digest: str
    environment: tuple[EnvironmentBinding, ...]
    working_directory_root_id: str
    resources: ProviderResources
    fallback_from_provider_id: str
    install_binding: Mapping[str, Any]
    _validation_seal: object | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _validation_digest: str = field(
        default="", init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "adapter", _freeze_json(self.adapter))
        object.__setattr__(self, "raw_binding", _freeze_json(self.raw_binding))
        object.__setattr__(
            self, "tool_identity", _freeze_json(self.tool_identity)
        )
        object.__setattr__(self, "distribution", _freeze_json(self.distribution))
        object.__setattr__(
            self, "build_variant_ids", tuple(self.build_variant_ids)
        )
        object.__setattr__(self, "toolchains", tuple(self.toolchains))
        object.__setattr__(
            self, "capability_requests", tuple(self.capability_requests)
        )
        object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(
            self,
            "configuration_inputs",
            tuple(_freeze_json(row) for row in self.configuration_inputs),
        )
        object.__setattr__(self, "environment", tuple(self.environment))
        object.__setattr__(
            self, "install_binding", _freeze_json(self.install_binding)
        )
        _provider_id(self.provider_id, "plan provider_id")
        _provider_id(self.provider_run_id, "plan provider_run_id")
        _opaque_id(self.audit_run_id, "plan audit run ID")
        if (
            not isinstance(self.provider_schema_version, str)
            or not self.provider_schema_version.startswith(
                "plamen.program_facts_provider."
            )
        ):
            _fail("plan provider schema version is invalid")
        for value, label in (
            (self.methodology_authority_digest, "plan methodology authority"),
            (self.snapshot_digest, "plan snapshot"),
            (self.source_scope_digest, "plan source scope"),
            (self.source_manifest_digest, "plan source manifest"),
            (self.source_authority_digest, "plan source authority"),
            (self.registry_digest, "plan registry"),
            (self.context_digest, "plan context"),
            (self.invocation_policy_digest, "plan invocation policy"),
        ):
            _hex64(value, f"{label} digest")
        _hex64(self.version_output_digest, "plan version output digest")
        if self.version_output_digest != hashlib.sha256(
            self.version_output.encode("utf-8")
        ).hexdigest():
            _fail("plan version output digest mismatch")
        if "\n" in self.version_output or "\r" in self.version_output:
            _fail("plan version output must be one exact line")
        _exact_keys(
            self.adapter, frozenset({"module", "symbol"}), "plan adapter"
        )
        if (
            not isinstance(self.adapter["module"], str)
            or _MODULE_RE.fullmatch(self.adapter["module"]) is None
            or not isinstance(self.adapter["symbol"], str)
            or _SYMBOL_RE.fullmatch(self.adapter["symbol"]) is None
        ):
            _fail("plan adapter module/symbol is invalid")
        _exact_keys(
            self.raw_binding,
            frozenset(
                {
                    "raw_schema_digest",
                    "parser_callable",
                    "parser_source_digest",
                }
            ),
            "plan raw binding",
        )
        _hex64(
            self.raw_binding["raw_schema_digest"], "plan raw schema digest"
        )
        _hex64(
            self.raw_binding["parser_source_digest"],
            "plan parser source digest",
        )
        if (
            not isinstance(self.raw_binding["parser_callable"], str)
            or not self.raw_binding["parser_callable"]
        ):
            _fail("plan parser callable is invalid")
        _exact_keys(
            self.tool_identity,
            frozenset(
                {
                    "kind",
                    "name",
                    "command",
                    "module",
                    "executable_sha256",
                    "module_sha256",
                }
            ),
            "plan tool identity",
        )
        _hex64(
            self.tool_identity["executable_sha256"],
            "plan executable digest",
            allow_empty=True,
        )
        _hex64(
            self.tool_identity["module_sha256"],
            "plan module digest",
            allow_empty=True,
        )
        _exact_keys(
            self.distribution,
            frozenset(
                {
                    "kind",
                    "name",
                    "version",
                    "checksum",
                    "module_source_digest",
                }
            ),
            "plan distribution",
        )
        _hex64(self.distribution["checksum"], "plan distribution checksum")
        _hex64(
            self.distribution["module_source_digest"],
            "plan distribution module digest",
            allow_empty=True,
        )
        _exact_keys(
            self.install_binding,
            frozenset(
                {
                    "mode",
                    "lock_identity",
                    "lock_digest",
                    "network_allowed",
                    "mutable_reference_allowed",
                }
            ),
            "plan install binding",
        )
        _hex64(self.install_binding["lock_digest"], "plan install lock digest")
        if (
            self.install_binding["network_allowed"] is not False
            or self.install_binding["mutable_reference_allowed"] is not False
        ):
            _fail("plan installation binding is mutable or networked")
        if not isinstance(self.platform, PlatformIdentity):
            _fail("plan platform must be typed")
        if not isinstance(self.resources, ProviderResources):
            _fail("plan resources must be typed")
        if any(
            not isinstance(item, ToolchainIdentity)
            for item in self.toolchains
        ):
            _fail("plan toolchains must be typed")
        toolchain_names = tuple(item.name for item in self.toolchains)
        if toolchain_names != tuple(sorted(toolchain_names)) or len(
            toolchain_names
        ) != len(set(toolchain_names)):
            _fail("plan toolchains must be sorted and unique")
        _sorted_unique_strings(
            self.build_variant_ids, "plan build variants", allow_empty=False
        )
        if any(
            not isinstance(item, CapabilityRequest)
            for item in self.capability_requests
        ):
            _fail("plan capability requests must be typed")
        if not self.capability_requests:
            _fail("plan capability request denominator must not be empty")
        capability_ids = tuple(item.capability_id for item in self.capability_requests)
        if capability_ids != tuple(sorted(capability_ids)) or len(
            capability_ids
        ) != len(set(capability_ids)):
            _fail("plan capabilities must be sorted and unique")
        if not self.argv or any(
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or "\n" in item
            for item in self.argv
        ):
            _fail("plan argv must be a nonempty exact string array")
        if any(_host_path_shaped(item) for item in self.argv):
            _fail("plan argv contains an absolute host path")
        if self.argv[0] != self.tool_identity["command"]:
            _fail("plan argv[0] does not match the reviewed tool command")
        configuration_ids: list[str] = []
        for row in self.configuration_inputs:
            _exact_keys(
                row,
                frozenset({"identity", "sha256"}),
                "plan configuration input",
            )
            identity = row["identity"]
            if (
                not isinstance(identity, str)
                or not identity
                or _host_path_shaped(identity)
                or "\\" in identity
            ):
                _fail("plan configuration identity is not portable")
            _hex64(row["sha256"], "plan configuration digest")
            configuration_ids.append(identity)
        if configuration_ids != sorted(configuration_ids) or len(
            configuration_ids
        ) != len(set(configuration_ids)):
            _fail("plan configuration inputs must be sorted and unique")
        if any(
            not isinstance(item, EnvironmentBinding)
            for item in self.environment
        ):
            _fail("plan environment must be typed")
        environment_names = tuple(item.name for item in self.environment)
        if environment_names != tuple(sorted(environment_names)) or len(
            environment_names
        ) != len(set(environment_names)):
            _fail("plan environment must be sorted and unique")
        _opaque_id(self.working_directory_root_id, "plan working root ID")
        if self.fallback_from_provider_id:
            _provider_id(
                self.fallback_from_provider_id, "fallback_from_provider_id"
            )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROVIDER_PLAN_SCHEMA,
            "audit_run_id": self.audit_run_id,
            "methodology_authority_digest": (
                self.methodology_authority_digest
            ),
            "snapshot_digest": self.snapshot_digest,
            "source_scope_digest": self.source_scope_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "source_authority_digest": self.source_authority_digest,
            "provider_id": self.provider_id,
            "provider_run_id": self.provider_run_id,
            "provider_schema_version": self.provider_schema_version,
            "registry_digest": self.registry_digest,
            "context_digest": self.context_digest,
            "toolchains": [item.to_dict() for item in self.toolchains],
            "adapter": _thaw_json(self.adapter),
            "raw_binding": _thaw_json(self.raw_binding),
            "tool_identity": _thaw_json(self.tool_identity),
            "distribution": _thaw_json(self.distribution),
            "version_output": self.version_output,
            "version_output_digest": self.version_output_digest,
            "license_classification": self.license_classification,
            "platform": self.platform.to_dict(),
            "build_variant_ids": list(self.build_variant_ids),
            "capability_requests": [
                item.to_dict() for item in self.capability_requests
            ],
            "argv": list(self.argv),
            "configuration_inputs": [
                _thaw_json(row) for row in self.configuration_inputs
            ],
            "invocation_policy_digest": self.invocation_policy_digest,
            "environment": [item.to_dict() for item in self.environment],
            "working_directory_root_id": self.working_directory_root_id,
            "resources": self.resources.to_dict(),
            "fallback_from_provider_id": self.fallback_from_provider_id,
            "install_binding": _thaw_json(self.install_binding),
            "network_during_bake": False,
            "authority": dict(_AUTHORITY),
            "completion_authority": PROVISIONAL_AUTHORITY,
        }

    @property
    def plan_id(self) -> str:
        return derive_stable_id("PFP", self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        value = self._unsigned_dict()
        return {**value, "plan_id": self.plan_id}

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def _validation_intact(self, expected_authority_state: str) -> bool:
        del expected_authority_state
        try:
            return bool(
                type(self) is ProviderPlan
                and ProviderPlan.from_dict(self.to_dict()).to_dict()
                == self.to_dict()
            )
        except (AttributeError, ProgramFactsProviderAPIError, TypeError, ValueError):
            return False

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProviderPlan":
        _exact_keys(value, _PLAN_KEYS, "provider plan")
        if value["schema_version"] != PROVIDER_PLAN_SCHEMA:
            _fail("provider plan schema version drift")
        if value["network_during_bake"] is not False:
            _fail("provider plan cannot authorize network during bake")
        if value["authority"] != _AUTHORITY:
            _fail("provider plan has non-additive authority")
        if value["completion_authority"] != PROVISIONAL_AUTHORITY:
            _fail("provider plan attempts to mint completion authority")
        plan = cls(
            audit_run_id=value["audit_run_id"],
            methodology_authority_digest=value[
                "methodology_authority_digest"
            ],
            snapshot_digest=value["snapshot_digest"],
            source_scope_digest=value["source_scope_digest"],
            source_manifest_digest=value["source_manifest_digest"],
            source_authority_digest=value["source_authority_digest"],
            provider_id=value["provider_id"],
            provider_run_id=value["provider_run_id"],
            provider_schema_version=value["provider_schema_version"],
            registry_digest=value["registry_digest"],
            context_digest=value["context_digest"],
            toolchains=tuple(
                ToolchainIdentity.from_dict(item)
                for item in value["toolchains"]
            ),
            adapter=dict(value["adapter"]),
            raw_binding=dict(value["raw_binding"]),
            tool_identity=dict(value["tool_identity"]),
            distribution=dict(value["distribution"]),
            version_output=value["version_output"],
            version_output_digest=value["version_output_digest"],
            license_classification=value["license_classification"],
            platform=PlatformIdentity.from_dict(value["platform"]),
            build_variant_ids=tuple(value["build_variant_ids"]),
            capability_requests=tuple(
                CapabilityRequest.from_dict(item)
                for item in value["capability_requests"]
            ),
            argv=tuple(value["argv"]),
            configuration_inputs=tuple(value["configuration_inputs"]),
            invocation_policy_digest=value["invocation_policy_digest"],
            environment=tuple(
                EnvironmentBinding.from_dict(item)
                for item in value["environment"]
            ),
            working_directory_root_id=value["working_directory_root_id"],
            resources=ProviderResources.from_dict(value["resources"]),
            fallback_from_provider_id=value["fallback_from_provider_id"],
            install_binding=dict(value["install_binding"]),
        )
        if value["plan_id"] != plan.plan_id:
            _fail("provider plan ID mismatch")
        return plan

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ProviderPlan":
        return cls.from_dict(_strict_protocol_mapping(raw, "provider plan"))


@dataclass(frozen=True)
class _PlanReplayBinding:
    """Complete deterministic inputs used to replay one plan decision."""

    registry: LoadedProgramFactsProviderRegistry
    provider_id: str
    provider_run_id: str
    context: ProviderContext
    observed_identity: ObservedProviderIdentity
    argv: tuple[str, ...]
    resources: ProviderResources
    allowed_license_classifications: tuple[str, ...]
    source_manifest_authority: ReplayedProgramFactsSourceManifest | None
    audit_snapshot_authority: (
        ProgramFactsAuditSnapshotAuthority
        | ReplayedProgramFactsAuditSnapshotAuthority
        | None
    )
    source_project_root: str | Path | None
    source_config: Mapping[str, Any] | None
    expected_source_ledger_binding: Mapping[str, Any] | None
    observed_configuration_inputs: tuple[Mapping[str, str], ...]
    fallback_from_provider_id: str


@dataclass(frozen=True)
class _ProviderPlanSemanticReplay:
    """Pure compiler result used by the intact-TCB authority sink.

    This carrier and its closure are not security boundaries.  Assuming TCB
    code integrity, readiness accepts only the result returned by deterministic
    semantic replay over the complete untrusted-data binding.
    """

    plan: ProviderPlan | None
    debts: tuple[ProviderPolicyDebt, ...]
    authority_state: str | None


def _make_plan_issuance_registry():
    """Track copy/mutation accidents; never establish production readiness.

    ``ProviderPlanDecision.ready`` independently recompiles the plan from its
    exact registry, context, observed identity, and source parents.  These weak
    tables can therefore only remove authority on drift, never create it.
    """

    lock = threading.RLock()
    plans: weakref.WeakKeyDictionary[
        object, tuple[str, bytes]
    ] = weakref.WeakKeyDictionary()
    decisions: weakref.WeakKeyDictionary[
        object, tuple[bool, bytes]
    ] = weakref.WeakKeyDictionary()

    def record_compiled_plan(
        value: ProviderPlan,
        *,
        registry: LoadedProgramFactsProviderRegistry,
        structural_test_only: bool,
    ) -> None:
        frame = inspect.currentframe()
        caller_code = (
            frame.f_back.f_code
            if frame is not None and frame.f_back is not None
            else None
        )
        del frame
        if caller_code is not _compile_provider_plan_impl.__code__:
            raise TypeError(
                "provider plan issuance is internal to deterministic compilation"
            )
        if type(registry) is not LoadedProgramFactsProviderRegistry:
            _fail("provider plan issuance requires exact registry authority")
        registry._assert_replayable()
        authority_state = (
            STRUCTURAL_TEST_ONLY
            if structural_test_only
            else INSTALLED_PRODUCTION_AUTHORITY
        )
        if structural_test_only is registry.production_authority_established:
            _fail("provider plan authority differs from parent registry")
        with lock:
            if value in plans:
                _fail("provider plan authority cannot be reissued")
            plans[value] = (authority_state, value.canonical_bytes())

    def plan_preimage(
        value: object,
    ) -> tuple[str, bytes] | None:
        with lock:
            return plans.get(value)

    def new_decision(
        *,
        plan: ProviderPlan | None,
        debts_value: Sequence[ProviderPolicyDebt],
        replay_binding: _PlanReplayBinding | None = None,
        candidate_state: str | None = None,
    ) -> ProviderPlanDecision:
        for debt in debts_value:
            debt._assert_valid()
        if candidate_state not in {
            None,
            INSTALLED_PRODUCTION_AUTHORITY,
            STRUCTURAL_TEST_ONLY,
        }:
            _fail("provider plan candidate authority state is invalid")
        if plan is None and candidate_state is not None:
            _fail("provider plan candidate authority requires a plan")
        production_ready = (
            candidate_state == INSTALLED_PRODUCTION_AUTHORITY
        )
        decision = ProviderPlanDecision._create(
            seal=_PLAN_DECISION_SEAL,
            plan=plan,
            debts=debts_value,
            production_ready=production_ready,
            replay_binding=replay_binding,
        )
        preimage = canonical_json_bytes(
            {
                "plan": None if plan is None else plan.to_dict(),
                "debts": [debt.to_dict() for debt in debts_value],
            }
        )
        with lock:
            decisions[decision] = (production_ready, preimage)
        return decision

    def decision_preimage(
        value: object,
    ) -> tuple[bool, bytes] | None:
        with lock:
            return decisions.get(value)

    def plan_authority_state(value: object) -> str | None:
        with lock:
            issued = plans.get(value)
        if (
            type(value) is not ProviderPlan
            or issued is None
            or issued[0] not in {
                INSTALLED_PRODUCTION_AUTHORITY,
                STRUCTURAL_TEST_ONLY,
            }
        ):
            return None
        try:
            return (
                issued[0]
                if value.canonical_bytes() == issued[1]
                else None
            )
        except (AttributeError, ProgramFactsProviderAPIError, TypeError, ValueError):
            return None

    return (
        record_compiled_plan,
        plan_preimage,
        new_decision,
        decision_preimage,
        plan_authority_state,
    )


(
    _record_compiled_plan,
    _plan_issuance_preimage,
    _plan_decision,
    _plan_decision_issuance_preimage,
    _plan_authority_state,
) = _make_plan_issuance_registry()


class ProviderPlanDecision:
    __slots__ = (
        "_seal",
        "_production_ready",
        "_issuance_digest",
        "_replay_binding",
        "plan",
        "debts",
        "__weakref__",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("ProviderPlanDecision is validator-issued only")

    @classmethod
    def _create(
        cls,
        *,
        seal: object,
        plan: ProviderPlan | None,
        debts: Sequence[ProviderPolicyDebt],
        production_ready: bool,
        replay_binding: _PlanReplayBinding | None = None,
    ) -> "ProviderPlanDecision":
        if seal is not _PLAN_DECISION_SEAL:
            raise TypeError("ProviderPlanDecision is validator-issued only")
        if any(type(debt) is not ProviderPolicyDebt for debt in debts):
            _fail("provider plan decision contains forged debt")
        value = object.__new__(cls)
        object.__setattr__(value, "_seal", seal)
        object.__setattr__(value, "_production_ready", bool(production_ready))
        object.__setattr__(value, "_replay_binding", replay_binding)
        object.__setattr__(value, "plan", plan)
        object.__setattr__(value, "debts", tuple(debts))
        object.__setattr__(
            value,
            "_issuance_digest",
            value._current_issuance_digest(),
        )
        return value

    def _current_issuance_digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "production_ready": self._production_ready,
                    "plan": (
                        None if self.plan is None else self.plan.to_dict()
                    ),
                    "debts": [debt.to_dict() for debt in self.debts],
                }
            )
        ).hexdigest()

    def _issuance_valid(self) -> bool:
        try:
            issued = _plan_decision_issuance_preimage(self)
            for debt in self.debts:
                debt._assert_valid()
            return bool(
                type(self) is ProviderPlanDecision
                and self._seal is _PLAN_DECISION_SEAL
                and isinstance(self._production_ready, bool)
                and all(type(debt) is ProviderPolicyDebt for debt in self.debts)
                and issued is not None
                and issued
                == (
                    self._production_ready,
                    canonical_json_bytes(
                        {
                            "plan": (
                                None
                                if self.plan is None
                                else self.plan.to_dict()
                            ),
                            "debts": [
                                debt.to_dict() for debt in self.debts
                            ],
                        }
                    ),
                )
            )
        except (
            AttributeError,
            ProgramFactsProviderAPIError,
            TypeError,
            ValueError,
        ):
            return False

    def _compiled_candidate_state(self) -> str | None:
        """Return local compilation state; never use as sink authority."""

        if not (
            self._issuance_valid()
            and self.plan is not None
            and not any(
                debt.code is not ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY
                for debt in self.debts
            )
        ):
            return None
        expected = (
            INSTALLED_PRODUCTION_AUTHORITY
            if self._production_ready
            else STRUCTURAL_TEST_ONLY
        )
        return (
            expected
            if self.plan._validation_intact(expected)
            else None
        )


def _debt(
    code: ProviderPolicyDebtCode,
    provider_id: str,
    detail: str,
    *,
    capability_id: str = "",
) -> ProviderPolicyDebt:
    return _new_provider_policy_debt(
        code,
        provider_id,
        capability_id=capability_id,
        detail=detail,
    )


def _deduplicate_debts(
    debts: Sequence[ProviderPolicyDebt],
) -> tuple[ProviderPolicyDebt, ...]:
    by_id = {debt.debt_id: debt for debt in debts}
    return tuple(by_id[key] for key in sorted(by_id))


def maximum_effective_precision(
    registry_cap: str,
    request_cap: str,
    fallback_cap: str,
) -> str:
    """Return the narrowest reviewed/request/fallback precision ceiling."""

    values = [registry_cap, request_cap]
    if fallback_cap:
        values.append(fallback_cap)
    if any(value not in _PRECISION_RANK for value in values):
        _fail("precision cap is invalid")
    return min(values, key=lambda value: _PRECISION_RANK[value])


def _replay_context(context: ProviderContext) -> ProviderContext:
    if type(context) is not ProviderContext:
        _fail("provider context requires exact typed canonical bytes")
    return ProviderContext.from_bytes(context.canonical_bytes())


def _validate_source_manifest_parent(
    source_manifest_authority: ReplayedProgramFactsSourceManifest | None,
    *,
    context: ProviderContext,
    audit_snapshot_authority: (
        ProgramFactsAuditSnapshotAuthority
        | ReplayedProgramFactsAuditSnapshotAuthority
        | None
    ) = None,
    project_root: str | Path | None = None,
    config: Mapping[str, Any] | None = None,
    expected_ledger_binding: Mapping[str, Any] | None = None,
) -> bool:
    if type(source_manifest_authority) is not ReplayedProgramFactsSourceManifest:
        return False
    if project_root is None or config is None:
        return False
    try:
        frozen_config = json.loads(canonical_json_bytes(config))
        if not isinstance(frozen_config, Mapping):
            return False
        replayed_snapshot = replay_program_facts_audit_snapshot_authority(
            audit_snapshot_authority,
            project_root=project_root,
            config=frozen_config,
        )
        audit_identity = replayed_snapshot.audit_identity
        if (
            type(audit_identity) is not ProgramFactsAuditIdentity
            or audit_identity.to_dict()
            != {
                "snapshot_digest": replayed_snapshot.snapshot_digest,
                "source_scope_digest": (
                    replayed_snapshot.source_scope_digest
                ),
                "audit_config_digest": (
                    replayed_snapshot.audit_config_digest
                ),
                "methodology_digest": replayed_snapshot.methodology_digest,
                "toolchain_digest": replayed_snapshot.toolchain_digest,
            }
            or audit_identity.snapshot_digest != context.snapshot_digest
            or audit_identity.source_scope_digest
            != context.source_scope_digest
        ):
            return False
        replayed = replay_program_facts_source_authority(
            source_manifest_authority,
            expected_snapshot_digest=audit_identity.snapshot_digest,
            expected_source_scope_digest=(
                audit_identity.source_scope_digest
            ),
            project_root=project_root,
            config=frozen_config,
            expected_ledger_binding=expected_ledger_binding,
        )
        parsed = parse_program_facts_source_manifest_shape(
            replayed.canonical_bytes
        )
    except Exception:
        return False
    return bool(
        parsed.authority_digest
        == replayed.authority_digest
        and parsed.authority_digest == context.source_authority_digest
        and parsed.record == replayed.record
        and parsed.manifest_digest == context.source_manifest_digest
        and parsed.record["snapshot_ref"]["snapshot_digest"]
        == f"sha256:{context.snapshot_digest}"
        and parsed.record["snapshot_ref"]["source_scope_digest"]
        == f"sha256:{context.source_scope_digest}"
        and replayed.parent_authority_established
    )


def _render_reviewed_argv(
    invocation: Mapping[str, Any],
    *,
    context: ProviderContext,
    provider_run_id: str,
) -> tuple[str, ...]:
    sources = {
        "AUDIT_RUN_ID": context.audit_run_id,
        "PROVIDER_RUN_ID": provider_run_id,
        "SNAPSHOT_DIGEST": context.snapshot_digest,
        "SOURCE_SCOPE_DIGEST": context.source_scope_digest,
        "SOURCE_MANIFEST_DIGEST": context.source_manifest_digest,
        "WORKING_DIRECTORY_ROOT_ID": context.working_directory_root_id,
    }
    if len(context.build_variant_ids) == 1:
        sources["SINGLE_BUILD_VARIANT_ID"] = context.build_variant_ids[0]
    substitutions: dict[str, str] = {}
    for row in invocation["typed_substitutions"]:
        source = row["source"]
        if source not in sources:
            _fail(
                "reviewed argv requires a typed substitution unavailable "
                "from the frozen context"
            )
        substitutions[row["placeholder"]] = sources[source]
    rendered: list[str] = []
    for token in invocation["argv_template"]:
        value = str(token)
        for placeholder, replacement in substitutions.items():
            value = value.replace(placeholder, replacement)
        if re.search(r"\{[A-Z][A-Z0-9_]*\}", value):
            _fail("reviewed argv contains an unresolved typed substitution")
        rendered.append(value)
    return tuple(rendered)


def _invocation_policy_digest(invocation: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(invocation)).hexdigest()


def _compile_provider_plan_impl(
    *,
    registry: LoadedProgramFactsProviderRegistry,
    provider_id: str,
    provider_run_id: str,
    context: ProviderContext,
    observed_identity: ObservedProviderIdentity,
    argv: Sequence[str],
    resources: ProviderResources,
    allowed_license_classifications: Sequence[str],
    source_manifest_authority: ReplayedProgramFactsSourceManifest | None,
    audit_snapshot_authority: (
        ProgramFactsAuditSnapshotAuthority
        | ReplayedProgramFactsAuditSnapshotAuthority
        | None
    ) = None,
    source_project_root: str | Path | None = None,
    source_config: Mapping[str, Any] | None = None,
    expected_source_ledger_binding: Mapping[str, Any] | None = None,
    observed_configuration_inputs: Sequence[Mapping[str, str]] = (),
    fallback_from_provider_id: str = "",
    _attach_replay_binding: bool = True,
    _semantic_replay: bool = False,
    _source_parent_validator=None,
) -> ProviderPlanDecision | _ProviderPlanSemanticReplay:
    """Compare explicit observations with one reviewed row.

    Every mismatch becomes typed blocking debt.  The function never searches
    for another provider, broadens fallback fidelity, resolves a host command,
    reads environment values, or launches anything.
    """

    if type(registry) is not LoadedProgramFactsProviderRegistry:
        _fail("compile_provider_plan requires loaded registry authority")
    if type(observed_identity) is not ObservedProviderIdentity:
        _fail("compile_provider_plan requires exact observed tool identity")
    if type(resources) is not ProviderResources:
        _fail("compile_provider_plan requires exact provider resources")
    if isinstance(argv, (str, bytes, bytearray)):
        _fail("provider argv must be an exact string sequence")
    normalized_argv = tuple(argv)
    source_parent_validator = (
        _validate_source_manifest_parent
        if _source_parent_validator is None
        else _source_parent_validator
    )
    normalized_source_config: Mapping[str, Any] | None = None
    if source_config is not None:
        if not isinstance(source_config, Mapping):
            _fail("provider source config must be a JSON object")
        normalized_source_config = _snapshot_json_once(
            source_config,
            "provider source config",
        )
        assert isinstance(normalized_source_config, Mapping)
    normalized_source_ledger_binding: Mapping[str, Any] | None = None
    if expected_source_ledger_binding is not None:
        if not isinstance(expected_source_ledger_binding, Mapping):
            _fail("provider source-ledger binding must be a JSON object")
        normalized_source_ledger_binding = _snapshot_json_once(
            expected_source_ledger_binding,
            "provider source-ledger binding",
        )
        assert isinstance(normalized_source_ledger_binding, Mapping)
    _provider_id(provider_id, "provider plan provider ID")
    _provider_id(provider_run_id, "provider plan run ID")
    registry._assert_replayable()
    selection = registry.provider(provider_id)
    structural_test_only = bool(
        not selection.ready
        and selection.provider is not None
        and selection.debts
        and all(
            debt.code is ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY
            for debt in selection.debts
        )
    )
    if not selection.ready and not structural_test_only:
        if _semantic_replay:
            return _ProviderPlanSemanticReplay(
                plan=None,
                debts=tuple(selection.debts),
                authority_state=None,
            )
        return _plan_decision(
            plan=None,
            debts_value=selection.debts,
        )
    row = selection.provider
    assert row is not None
    debts: list[ProviderPolicyDebt] = (
        list(selection.debts) if structural_test_only else []
    )
    context = _replay_context(context)

    def mismatch(
        condition: bool,
        code: ProviderPolicyDebtCode,
        detail: str,
        capability_id: str = "",
    ) -> None:
        if condition:
            debts.append(
                _debt(
                    code,
                    provider_id,
                    detail,
                    capability_id=capability_id,
                )
            )

    if not structural_test_only:
        mismatch(
            not registry.production_authority_established,
            ProviderPolicyDebtCode.METHODOLOGY_AUTHORITY_DRIFT,
            "registry lacks installed-methodology production authority",
        )
        mismatch(
            context.methodology_authority_digest
            != registry.methodology_capture_digest,
            ProviderPolicyDebtCode.METHODOLOGY_AUTHORITY_DRIFT,
            "context methodology authority differs from installed capture",
        )
        mismatch(
            context.snapshot_digest != registry.snapshot_digest,
            ProviderPolicyDebtCode.CONTEXT_BINDING_DRIFT,
            "context snapshot differs from installed methodology capture",
        )
        mismatch(
            context.audit_run_id != registry.audit_run_id,
            ProviderPolicyDebtCode.CONTEXT_BINDING_DRIFT,
            "context audit run differs from checkpoint capture authority",
        )
        mismatch(
            context.source_scope_digest != registry.source_scope_digest,
            ProviderPolicyDebtCode.CONTEXT_BINDING_DRIFT,
            "context source scope differs from audit snapshot",
        )
        mismatch(
            not source_parent_validator(
                source_manifest_authority,
                context=context,
                audit_snapshot_authority=audit_snapshot_authority,
                project_root=source_project_root,
                config=normalized_source_config,
                expected_ledger_binding=normalized_source_ledger_binding,
            ),
            ProviderPolicyDebtCode.SOURCE_AUTHORITY_DRIFT,
            "context source manifest lacks exact replayed parent authority",
        )

    mismatch(
        observed_identity.registry_digest != registry.registry_digest,
        ProviderPolicyDebtCode.REGISTRY_DIGEST_MISMATCH,
        "observed registry digest differs from loaded registry authority",
    )
    mismatch(
        observed_identity.provider_schema_version
        != row["provider_schema_version"],
        ProviderPolicyDebtCode.PROVIDER_SCHEMA_DRIFT,
        "provider schema version differs from the reviewed row",
    )
    mismatch(
        (
            observed_identity.adapter_module != row["adapter"]["module"]
            or observed_identity.adapter_symbol != row["adapter"]["symbol"]
        ),
        ProviderPolicyDebtCode.ADAPTER_BINDING_DRIFT,
        "adapter module/symbol differs from the reviewed row",
    )
    mismatch(
        observed_identity.parser_callable
        != row["raw_binding"]["parser_callable"],
        ProviderPolicyDebtCode.PARSER_DIGEST_DRIFT,
        "parser callable differs from the reviewed row",
    )
    mismatch(
        observed_identity.parser_source_digest
        != row["raw_binding"]["parser_source_digest"],
        ProviderPolicyDebtCode.PARSER_DIGEST_DRIFT,
        "parser source digest differs from the reviewed row",
    )
    mismatch(
        observed_identity.raw_schema_digest
        != row["raw_binding"]["raw_schema_digest"],
        ProviderPolicyDebtCode.RAW_SCHEMA_DIGEST_DRIFT,
        "raw schema digest differs from the reviewed row",
    )
    tool = row["tool_identity"]
    mismatch(
        (
            observed_identity.tool_kind != tool["kind"]
            or observed_identity.tool_name != tool["name"]
            or observed_identity.command != tool["command"]
            or observed_identity.module != tool["module"]
        ),
        ProviderPolicyDebtCode.TOOL_IDENTITY_DRIFT,
        "tool kind/name/command/module differs from the reviewed row",
    )
    mismatch(
        observed_identity.executable_sha256 != tool["executable_sha256"],
        ProviderPolicyDebtCode.EXECUTABLE_DIGEST_DRIFT,
        "executable digest differs from the reviewed row",
    )
    mismatch(
        observed_identity.module_sha256 != tool["module_sha256"],
        ProviderPolicyDebtCode.MODULE_DIGEST_DRIFT,
        "module digest differs from the reviewed row",
    )
    distribution = row["distribution"]
    mismatch(
        (
            observed_identity.distribution_kind != distribution["kind"]
            or observed_identity.distribution_name != distribution["name"]
        ),
        ProviderPolicyDebtCode.DISTRIBUTION_UNPINNED,
        "distribution kind/name differs from the reviewed row",
    )
    mismatch(
        observed_identity.distribution_version != distribution["version"],
        ProviderPolicyDebtCode.PROVIDER_VERSION_DRIFT,
        "distribution version differs from the exact reviewed pin",
    )
    mismatch(
        observed_identity.distribution_checksum != distribution["checksum"],
        ProviderPolicyDebtCode.DISTRIBUTION_CHECKSUM_MISMATCH,
        "distribution checksum differs from the reviewed row",
    )
    mismatch(
        observed_identity.distribution_module_source_digest
        != distribution["module_source_digest"],
        ProviderPolicyDebtCode.MODULE_DIGEST_DRIFT,
        "distribution module-source digest differs from the reviewed row",
    )
    try:
        version_matches = (
            re.fullmatch(
                row["expected_version_syntax"],
                observed_identity.version_output,
            )
            is not None
            and distribution["version"] in observed_identity.version_output
        )
    except re.error:
        version_matches = False
    mismatch(
        not version_matches,
        ProviderPolicyDebtCode.PROVIDER_VERSION_DRIFT,
        "version output does not exactly match the reviewed syntax/pin",
    )
    allowed_licenses = _sorted_unique_strings(
        tuple(allowed_license_classifications),
        "allowed license classifications",
    )
    mismatch(
        (
            observed_identity.license_classification
            != row["license_classification"]
            or row["license_classification"] not in set(allowed_licenses)
        ),
        ProviderPolicyDebtCode.LICENSE_OR_DISTRIBUTION_RESTRICTED,
        "license classification is drifted or outside caller policy",
    )
    mismatch(
        observed_identity.platform != context.platform,
        ProviderPolicyDebtCode.TOOL_IDENTITY_DRIFT,
        "observed platform differs from the frozen provider context",
    )
    supported_platforms = {
        (platform["os"], architecture)
        for platform in row["supported_platforms"]
        for architecture in platform["architectures"]
    }
    mismatch(
        context.platform.os not in {
            item["os"] for item in row["supported_platforms"]
        },
        ProviderPolicyDebtCode.UNSUPPORTED_OS,
        "context OS is outside the reviewed registry row",
    )
    mismatch(
        (
            context.platform.os,
            context.platform.architecture,
        )
        not in supported_platforms,
        ProviderPolicyDebtCode.UNSUPPORTED_ARCHITECTURE,
        "context OS/architecture pair is outside the reviewed registry row",
    )
    mismatch(
        context.ecosystem not in set(row["supported_ecosystems"]),
        ProviderPolicyDebtCode.UNSUPPORTED_ECOSYSTEM,
        "context ecosystem is outside provider authority",
    )
    for language in context.languages:
        mismatch(
            language not in set(row["supported_languages"]),
            ProviderPolicyDebtCode.UNSUPPORTED_LANGUAGE,
            f"language {language} is outside provider authority",
        )
    observed_toolchains = {
        item.name: (item.version, item.identity_digest)
        for item in context.toolchains
    }
    reviewed_toolchain_names = {
        item["toolchain"] for item in row["toolchain_ranges"]
    }
    mismatch(
        set(observed_toolchains) != reviewed_toolchain_names,
        ProviderPolicyDebtCode.UNSUPPORTED_TOOLCHAIN,
        "toolchain denominator differs from the exact reviewed set",
    )
    for toolchain_range in row["toolchain_ranges"]:
        name = toolchain_range["toolchain"]
        observed = observed_toolchains.get(name, ("0", ""))
        identity_is_reviewed = (
            observed[1] == toolchain_range["identity_digest"]
            if "identity_digest" in toolchain_range
            else (
                toolchain_range.get("identity_policy")
                == "RECEIPT_EXACT_PER_RUN"
                and _HEX64_RE.fullmatch(observed[1]) is not None
            )
        )
        mismatch(
            name not in observed_toolchains
            or not _version_satisfies(
                observed[0],
                toolchain_range["version_range"],
            )
            or not identity_is_reviewed,
            ProviderPolicyDebtCode.UNSUPPORTED_TOOLCHAIN,
            f"toolchain {name} is absent, drifted, or outside its reviewed range",
        )

    capabilities = {
        item["capability_id"]: item for item in row["capabilities"]
    }
    for request in context.capability_requests:
        capability = capabilities.get(request.capability_id)
        mismatch(
            capability is None,
            ProviderPolicyDebtCode.UNSUPPORTED_CAPABILITY,
            "requested capability is outside the reviewed row",
            request.capability_id,
        )
        if capability is not None:
            mismatch(
                _PRECISION_RANK[request.maximum_precision]
                > _PRECISION_RANK[capability["maximum_precision"]],
                ProviderPolicyDebtCode.CAPABILITY_FIDELITY_OVERCLAIM,
                "requested precision exceeds reviewed capability fidelity",
                request.capability_id,
            )

    fallback = row["fallback"]
    if fallback_from_provider_id:
        source_selection = registry.provider(fallback_from_provider_id)
        source_structural = bool(
            structural_test_only
            and source_selection.provider is not None
            and source_selection.debts
            and all(
                debt.code is ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY
                for debt in source_selection.debts
            )
        )
        if not source_selection.ready and not source_structural:
            debts.extend(source_selection.debts)
        else:
            if source_structural:
                debts.extend(source_selection.debts)
            source = source_selection.provider
            assert source is not None
            source_fallback = source["fallback"]
            mismatch(
                (
                    not source_fallback
                    or source_fallback["provider_id"] != provider_id
                ),
                ProviderPolicyDebtCode.FALLBACK_POLICY_MISMATCH,
                "requested fallback edge is not reviewed",
            )
            if source_fallback:
                source_capabilities = {
                    item["capability_id"] for item in source["capabilities"]
                }
                for request in context.capability_requests:
                    mismatch(
                        request.capability_id not in source_capabilities,
                        ProviderPolicyDebtCode.FALLBACK_POLICY_MISMATCH,
                        "fallback request adds a capability absent from the "
                        "reviewed source provider",
                        request.capability_id,
                    )
                    mismatch(
                        _PRECISION_RANK[request.maximum_precision]
                        > _PRECISION_RANK[
                            source_fallback["maximum_precision"]
                        ],
                        ProviderPolicyDebtCode.FALLBACK_PRECISION_BROADENING,
                        "fallback request broadens the reviewed precision cap",
                        request.capability_id,
                    )
    elif fallback and provider_id == fallback.get("provider_id"):
        # Defensive only; the registry validator already rejects self-fallback.
        mismatch(
            True,
            ProviderPolicyDebtCode.FALLBACK_POLICY_MISMATCH,
            "provider fallback cannot select itself",
        )

    limits = row["limits"]
    for field in (
        "time_seconds",
        "memory_bytes",
        "input_bytes",
        "output_bytes",
    ):
        mismatch(
            getattr(resources, field) > limits[field],
            ProviderPolicyDebtCode.RESOURCE_POLICY_BROADENING,
            f"requested {field} exceeds reviewed provider limits",
        )

    environment_policy = row["environment_policy"]
    allowed_environment = set(environment_policy["allowed_names"])
    required_environment = set(environment_policy["required_names"])
    observed_environment = {item.name for item in context.environment}
    for binding in context.environment:
        mismatch(
            binding.is_secret or _SECRET_NAME_RE.search(binding.name) is not None,
            ProviderPolicyDebtCode.ENVIRONMENT_SECRET_FORBIDDEN,
            f"environment name {binding.name} is secret or secret-shaped",
        )
        mismatch(
            binding.name not in allowed_environment,
            ProviderPolicyDebtCode.ENVIRONMENT_POLICY_BROADENING,
            f"environment name {binding.name} is not reviewed",
        )
    mismatch(
        not required_environment <= observed_environment,
        ProviderPolicyDebtCode.ENVIRONMENT_POLICY_BROADENING,
        "required reviewed environment names are absent",
    )

    install = row["install_policy"]
    mismatch(
        (
            observed_identity.installation_mode != install["mode"]
            or observed_identity.installation_lock_identity
            != install["lock_identity"]
            or observed_identity.installation_lock_digest
            != install["lock_digest"]
        ),
        ProviderPolicyDebtCode.INSTALL_POLICY_DRIFT,
        "installation mode/lock identity differs from the reviewed row",
    )
    invocation = row["invocation_policy"]
    try:
        expected_argv = _render_reviewed_argv(
            invocation,
            context=context,
            provider_run_id=provider_run_id,
        )
    except ProgramFactsProviderAPIError:
        expected_argv = ()
    mismatch(
        normalized_argv != expected_argv,
        ProviderPolicyDebtCode.INVOCATION_POLICY_DRIFT,
        "provider argv differs from the exact reviewed adapter template",
    )
    observed_configs = _json_mapping_tuple(
        observed_configuration_inputs,
        "observed configuration inputs",
    )
    expected_configs = tuple(invocation["configuration_inputs"])
    mismatch(
        tuple(observed_configs) != expected_configs,
        ProviderPolicyDebtCode.CONFIGURATION_BINDING_DRIFT,
        "provider configuration input denominator/digest differs from review",
    )
    normalized_debts = _deduplicate_debts(debts)
    non_structural_debts = tuple(
        debt
        for debt in normalized_debts
        if debt.code is not ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY
    )
    if non_structural_debts:
        if _semantic_replay:
            return _ProviderPlanSemanticReplay(
                plan=None,
                debts=non_structural_debts,
                authority_state=None,
            )
        return _plan_decision(
            plan=None,
            debts_value=non_structural_debts,
        )

    plan = ProviderPlan(
        audit_run_id=context.audit_run_id,
        methodology_authority_digest=context.methodology_authority_digest,
        snapshot_digest=context.snapshot_digest,
        source_scope_digest=context.source_scope_digest,
        source_manifest_digest=context.source_manifest_digest,
        source_authority_digest=context.source_authority_digest,
        provider_id=provider_id,
        provider_run_id=provider_run_id,
        provider_schema_version=row["provider_schema_version"],
        registry_digest=registry.registry_digest,
        context_digest=context.context_digest,
        toolchains=context.toolchains,
        adapter=dict(row["adapter"]),
        raw_binding=dict(row["raw_binding"]),
        tool_identity=dict(row["tool_identity"]),
        distribution=dict(row["distribution"]),
        version_output=observed_identity.version_output,
        version_output_digest=observed_identity.version_output_digest,
        license_classification=row["license_classification"],
        platform=context.platform,
        build_variant_ids=context.build_variant_ids,
        capability_requests=context.capability_requests,
        argv=normalized_argv,
        configuration_inputs=expected_configs,
        invocation_policy_digest=_invocation_policy_digest(invocation),
        environment=context.environment,
        working_directory_root_id=context.working_directory_root_id,
        resources=resources,
        fallback_from_provider_id=fallback_from_provider_id,
        install_binding={
            "mode": install["mode"],
            "lock_identity": install["lock_identity"],
            "lock_digest": install["lock_digest"],
            "network_allowed": False,
            "mutable_reference_allowed": False,
        },
    )
    # Replay the public mapping to prove no constructor-only unchecked state.
    replayed = ProviderPlan.from_dict(plan.to_dict())
    authority_state = (
        STRUCTURAL_TEST_ONLY
        if structural_test_only
        else INSTALLED_PRODUCTION_AUTHORITY
    )
    if _semantic_replay:
        return _ProviderPlanSemanticReplay(
            plan=replayed,
            debts=tuple(normalized_debts),
            authority_state=authority_state,
        )
    _record_compiled_plan(
        replayed,
        registry=registry,
        structural_test_only=structural_test_only,
    )
    replay_binding = (
        _PlanReplayBinding(
            registry=registry,
            provider_id=provider_id,
            provider_run_id=provider_run_id,
            context=context,
            observed_identity=observed_identity,
            argv=normalized_argv,
            resources=resources,
            allowed_license_classifications=tuple(allowed_licenses),
            source_manifest_authority=source_manifest_authority,
            audit_snapshot_authority=audit_snapshot_authority,
            source_project_root=source_project_root,
            source_config=normalized_source_config,
            expected_source_ledger_binding=normalized_source_ledger_binding,
            observed_configuration_inputs=tuple(observed_configs),
            fallback_from_provider_id=fallback_from_provider_id,
        )
        if _attach_replay_binding
        else None
    )
    return _plan_decision(
        plan=replayed,
        debts_value=normalized_debts,
        replay_binding=replay_binding,
        candidate_state=authority_state,
    )


def compile_provider_plan(
    *,
    registry: LoadedProgramFactsProviderRegistry,
    provider_id: str,
    provider_run_id: str,
    context: ProviderContext,
    observed_identity: ObservedProviderIdentity,
    argv: Sequence[str],
    resources: ProviderResources,
    allowed_license_classifications: Sequence[str],
    source_manifest_authority: ReplayedProgramFactsSourceManifest | None,
    audit_snapshot_authority: (
        ProgramFactsAuditSnapshotAuthority
        | ReplayedProgramFactsAuditSnapshotAuthority
        | None
    ) = None,
    source_project_root: str | Path | None = None,
    source_config: Mapping[str, Any] | None = None,
    expected_source_ledger_binding: Mapping[str, Any] | None = None,
    observed_configuration_inputs: Sequence[Mapping[str, str]] = (),
    fallback_from_provider_id: str = "",
) -> ProviderPlanDecision:
    """Compile a plan candidate whose public authority is replay-derived."""

    return _compile_provider_plan_impl(
        registry=registry,
        provider_id=provider_id,
        provider_run_id=provider_run_id,
        context=context,
        observed_identity=observed_identity,
        argv=argv,
        resources=resources,
        allowed_license_classifications=allowed_license_classifications,
        source_manifest_authority=source_manifest_authority,
        audit_snapshot_authority=audit_snapshot_authority,
        source_project_root=source_project_root,
        source_config=source_config,
        expected_source_ledger_binding=expected_source_ledger_binding,
        observed_configuration_inputs=observed_configuration_inputs,
        fallback_from_provider_id=fallback_from_provider_id,
    )


def validate_provider_plan(
    plan: ProviderPlan | Mapping[str, Any],
    *,
    registry: LoadedProgramFactsProviderRegistry,
    context: ProviderContext,
    observed_identity: ObservedProviderIdentity,
    allowed_license_classifications: Sequence[str],
    source_manifest_authority: ReplayedProgramFactsSourceManifest | None,
    audit_snapshot_authority: (
        ProgramFactsAuditSnapshotAuthority
        | ReplayedProgramFactsAuditSnapshotAuthority
        | None
    ) = None,
    source_project_root: str | Path | None = None,
    source_config: Mapping[str, Any] | None = None,
    expected_source_ledger_binding: Mapping[str, Any] | None = None,
    observed_configuration_inputs: Sequence[Mapping[str, str]] = (),
) -> ProviderPlanDecision:
    """Replay a provider-supplied plan against context and registry authority."""

    value = (
        ProviderPlan.from_dict(plan.to_dict())
        if type(plan) is ProviderPlan
        else ProviderPlan.from_dict(plan)
    )
    compiled = _compile_provider_plan_impl(
        registry=registry,
        provider_id=value.provider_id,
        provider_run_id=value.provider_run_id,
        context=context,
        observed_identity=observed_identity,
        argv=value.argv,
        resources=value.resources,
        allowed_license_classifications=allowed_license_classifications,
        source_manifest_authority=source_manifest_authority,
        audit_snapshot_authority=audit_snapshot_authority,
        source_project_root=source_project_root,
        source_config=source_config,
        expected_source_ledger_binding=expected_source_ledger_binding,
        observed_configuration_inputs=observed_configuration_inputs,
        fallback_from_provider_id=value.fallback_from_provider_id,
    )
    if type(compiled) is not ProviderPlanDecision:
        _fail("provider plan compiler returned an invalid decision")
    if not (compiled.ready or compiled.structurally_valid):
        return compiled
    assert compiled.plan is not None
    if compiled.plan.to_dict() != value.to_dict():
        debt = _debt(
            ProviderPolicyDebtCode.PROVIDER_SCHEMA_DRIFT,
            value.provider_id,
            "provider plan differs from deterministic reviewed compilation",
        )
        return _plan_decision(
            plan=None,
            debts_value=(debt,),
        )
    return compiled


def _make_plan_decision_authority_replayer(
    semantic_compiler,
    *,
    semantic_replay_type,
    source_parent_validator,
    production_state: str,
    structural_state: str,
):
    """Stabilize the TCB compiler against accidental global rebinding.

    Lexical capture is defense in depth, not protection from arbitrary code
    execution or closure-cell mutation inside the orchestrator TCB.
    """

    def replay_plan_decision_authority(
        decision: ProviderPlanDecision,
    ) -> str | None:
        """Recompile all parents without consulting issuance record tables."""

        try:
            binding = decision._replay_binding
            if (
                type(decision) is not ProviderPlanDecision
                or type(binding) is not _PlanReplayBinding
                or type(decision.plan) is not ProviderPlan
            ):
                return None
            replayed = semantic_compiler(
                registry=binding.registry,
                provider_id=binding.provider_id,
                provider_run_id=binding.provider_run_id,
                context=binding.context,
                observed_identity=binding.observed_identity,
                argv=binding.argv,
                resources=binding.resources,
                allowed_license_classifications=(
                    binding.allowed_license_classifications
                ),
                source_manifest_authority=binding.source_manifest_authority,
                audit_snapshot_authority=binding.audit_snapshot_authority,
                source_project_root=binding.source_project_root,
                source_config=binding.source_config,
                expected_source_ledger_binding=(
                    binding.expected_source_ledger_binding
                ),
                observed_configuration_inputs=(
                    binding.observed_configuration_inputs
                ),
                fallback_from_provider_id=binding.fallback_from_provider_id,
                _attach_replay_binding=False,
                _semantic_replay=True,
                _source_parent_validator=source_parent_validator,
            )
            if (
                type(replayed) is not semantic_replay_type
                or replayed.authority_state
                not in {
                    production_state,
                    structural_state,
                }
                or replayed.plan is None
                or replayed.plan.to_dict() != decision.plan.to_dict()
                or tuple(debt.to_dict() for debt in replayed.debts)
                != tuple(debt.to_dict() for debt in decision.debts)
            ):
                return None
            return replayed.authority_state
        except (
            AttributeError,
            ProgramFactsProviderAPIError,
            ProgramFactsTypeError,
            TypeError,
            ValueError,
        ):
            return None

    return replay_plan_decision_authority


_replay_plan_decision_authority = _make_plan_decision_authority_replayer(
    _compile_provider_plan_impl,
    semantic_replay_type=_ProviderPlanSemanticReplay,
    source_parent_validator=_validate_source_manifest_parent,
    production_state=INSTALLED_PRODUCTION_AUTHORITY,
    structural_state=STRUCTURAL_TEST_ONLY,
)


def _bind_plan_decision_readiness(
    semantic_replayer,
    *,
    production_state: str,
    structural_state: str,
) -> None:
    """Bind readiness to intact-TCB semantic replay.

    The property binding avoids accidental monkeypatch drift.  It is not an
    authority boundary against code execution within the TCB.
    """

    def ready(decision: ProviderPlanDecision) -> bool:
        return bool(
            decision._issuance_valid()
            and decision._production_ready
            and decision.plan is not None
            and decision.plan._validation_intact(production_state)
            and not decision.debts
            and semantic_replayer(decision) == production_state
        )

    def structurally_valid(decision: ProviderPlanDecision) -> bool:
        return bool(
            decision._issuance_valid()
            and not decision._production_ready
            and decision.plan is not None
            and decision.plan._validation_intact(structural_state)
            and decision.debts
            and all(
                debt.code is ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY
                for debt in decision.debts
            )
            and semantic_replayer(decision) == structural_state
        )

    ProviderPlanDecision.ready = property(ready)
    ProviderPlanDecision.structurally_valid = property(structurally_valid)


_bind_plan_decision_readiness(
    _replay_plan_decision_authority,
    production_state=INSTALLED_PRODUCTION_AUTHORITY,
    structural_state=STRUCTURAL_TEST_ONLY,
)
del _bind_plan_decision_readiness
del _make_plan_decision_authority_replayer


@dataclass(frozen=True)
class ProviderResult:
    """Provisional raw parse result; it cannot represent execution success."""

    audit_run_id: str
    methodology_authority_digest: str
    registry_digest: str
    context_digest: str
    source_manifest_digest: str
    source_authority_digest: str
    plan_id: str
    provider_id: str
    provider_run_id: str
    result_state: str
    raw_output_sha256: str
    raw_output_size: int
    raw_schema_digest: str
    parser_callable: str
    parser_source_digest: str
    capabilities_parsed: tuple[str, ...]
    capabilities_partial: tuple[str, ...]
    capabilities_unavailable: tuple[str, ...]
    capability_diagnostics: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "capabilities_parsed", tuple(self.capabilities_parsed)
        )
        object.__setattr__(
            self, "capabilities_partial", tuple(self.capabilities_partial)
        )
        object.__setattr__(
            self,
            "capabilities_unavailable",
            tuple(self.capabilities_unavailable),
        )
        object.__setattr__(
            self,
            "capability_diagnostics",
            tuple(
                _freeze_json(row)
                for row in _json_mapping_tuple(
                    self.capability_diagnostics,
                    "result capability diagnostics",
                )
            ),
        )
        if self.result_state not in _RESULT_STATES:
            _fail(
                "provider result state is invalid; success/completed states are "
                "not caller-mintable"
            )
        _provider_id(self.provider_id, "result provider_id")
        _provider_id(self.provider_run_id, "result provider_run_id")
        _opaque_id(self.audit_run_id, "result audit run ID")
        for value, label in (
            (self.methodology_authority_digest, "result methodology authority"),
            (self.registry_digest, "result registry"),
            (self.context_digest, "result context"),
            (self.source_manifest_digest, "result source manifest"),
            (self.source_authority_digest, "result source authority"),
        ):
            _hex64(value, f"{label} digest")
        if not re.fullmatch(r"^PFP-[0-9a-f]{24}$", self.plan_id):
            _fail("result plan_id is invalid")
        _hex64(
            self.raw_output_sha256,
            "raw output digest",
            allow_empty=True,
        )
        if (
            isinstance(self.raw_output_size, bool)
            or not isinstance(self.raw_output_size, int)
            or self.raw_output_size < 0
        ):
            _fail("raw output size must be a nonnegative integer")
        _hex64(self.raw_schema_digest, "result raw schema digest")
        _hex64(self.parser_source_digest, "result parser source digest")
        dispositions = (
            self.capabilities_parsed,
            self.capabilities_partial,
            self.capabilities_unavailable,
        )
        for index, values in enumerate(dispositions):
            _sorted_unique_strings(values, f"result capability disposition {index}")
        disposition_sets = [set(values) for values in dispositions]
        if not any(disposition_sets):
            _fail("provider result capability disposition must not be empty")
        if any(
            disposition_sets[left] & disposition_sets[right]
            for left in range(3)
            for right in range(left + 1, 3)
        ):
            _fail("provider result capability dispositions overlap")
        diagnostic_capabilities: list[str] = []
        for row in self.capability_diagnostics:
            _exact_keys(
                row,
                frozenset(
                    {
                        "capability_id",
                        "disposition",
                        "diagnostic_codes",
                        "debt_codes",
                    }
                ),
                "result capability diagnostic",
            )
            capability_id = _provider_id(
                row["capability_id"],
                "result diagnostic capability ID",
            )
            disposition = row["disposition"]
            expected_disposition = (
                "PARTIAL"
                if capability_id in set(self.capabilities_partial)
                else "UNAVAILABLE"
                if capability_id in set(self.capabilities_unavailable)
                else ""
            )
            if disposition != expected_disposition:
                _fail(
                    "result capability diagnostic disposition is not "
                    "capability-bound"
                )
            diagnostics = _sorted_unique_strings(
                row["diagnostic_codes"],
                "result scoped diagnostic codes",
                allow_empty=False,
            )
            debts = _sorted_unique_strings(
                row["debt_codes"],
                "result scoped debt codes",
                allow_empty=False,
            )
            if any(
                _DIAGNOSTIC_CODE_RE.fullmatch(code) is None
                for code in diagnostics
            ):
                _fail("result diagnostic/debt code is not canonical")
            if any(code not in _MECHANICAL_DEBT_CODES for code in debts):
                _fail("result debt code is outside the mechanical vocabulary")
            diagnostic_capabilities.append(capability_id)
        expected_diagnostics = sorted(
            set(self.capabilities_partial)
            | set(self.capabilities_unavailable)
        )
        if diagnostic_capabilities != expected_diagnostics:
            _fail(
                "partial/unavailable result capabilities require exactly one "
                "scoped diagnostic/debt row"
            )
        if self.result_state in {
            "PROVISIONAL_UNAVAILABLE",
            "PROVISIONAL_FAILED",
        }:
            if (
                self.raw_output_sha256
                or self.raw_output_size
                or self.capabilities_parsed
                or self.capabilities_partial
            ):
                _fail(
                    "unavailable/failed provisional result cannot retain parsed "
                    "authority"
                )
        elif not self.raw_output_sha256:
            _fail("parsed/degraded result requires a bound raw output digest")
        if self.result_state == "PROVISIONAL_PARSED" and (
            self.capabilities_partial
            or self.capabilities_unavailable
            or self.capability_diagnostics
        ):
            _fail("parsed result cannot hide partial/unavailable capability debt")
        if self.result_state == "PROVISIONAL_DEGRADED" and not (
            self.capabilities_partial or self.capabilities_unavailable
        ):
            _fail("degraded result requires scoped partial/unavailable debt")
        if self.result_state in {
            "PROVISIONAL_UNAVAILABLE",
            "PROVISIONAL_FAILED",
        } and (
            not self.capabilities_unavailable
            or self.capabilities_partial
        ):
            _fail("unavailable/failed result must disposition all work unavailable")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROVIDER_RESULT_SCHEMA,
            "audit_run_id": self.audit_run_id,
            "methodology_authority_digest": (
                self.methodology_authority_digest
            ),
            "registry_digest": self.registry_digest,
            "context_digest": self.context_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "source_authority_digest": self.source_authority_digest,
            "plan_id": self.plan_id,
            "provider_id": self.provider_id,
            "provider_run_id": self.provider_run_id,
            "result_state": self.result_state,
            "raw_output_sha256": self.raw_output_sha256,
            "raw_output_size": self.raw_output_size,
            "raw_schema_digest": self.raw_schema_digest,
            "parser_callable": self.parser_callable,
            "parser_source_digest": self.parser_source_digest,
            "capabilities_parsed": list(self.capabilities_parsed),
            "capabilities_partial": list(self.capabilities_partial),
            "capabilities_unavailable": list(self.capabilities_unavailable),
            "capability_diagnostics": [
                _thaw_json(row) for row in self.capability_diagnostics
            ],
            "authority": dict(_AUTHORITY),
            "completion_authority": PROVISIONAL_AUTHORITY,
        }

    @property
    def result_digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self._unsigned_dict())
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "result_digest": self.result_digest}

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProviderResult":
        _exact_keys(value, _RESULT_KEYS, "provider result")
        if value["schema_version"] != PROVIDER_RESULT_SCHEMA:
            _fail("provider result schema version drift")
        if value["authority"] != _AUTHORITY:
            _fail("provider result has non-additive authority")
        if value["completion_authority"] != PROVISIONAL_AUTHORITY:
            _fail("provider result attempts to mint completion/success authority")
        result = cls(
            audit_run_id=value["audit_run_id"],
            methodology_authority_digest=value[
                "methodology_authority_digest"
            ],
            registry_digest=value["registry_digest"],
            context_digest=value["context_digest"],
            source_manifest_digest=value["source_manifest_digest"],
            source_authority_digest=value["source_authority_digest"],
            plan_id=value["plan_id"],
            provider_id=value["provider_id"],
            provider_run_id=value["provider_run_id"],
            result_state=value["result_state"],
            raw_output_sha256=value["raw_output_sha256"],
            raw_output_size=value["raw_output_size"],
            raw_schema_digest=value["raw_schema_digest"],
            parser_callable=value["parser_callable"],
            parser_source_digest=value["parser_source_digest"],
            capabilities_parsed=tuple(value["capabilities_parsed"]),
            capabilities_partial=tuple(value["capabilities_partial"]),
            capabilities_unavailable=tuple(value["capabilities_unavailable"]),
            capability_diagnostics=tuple(value["capability_diagnostics"]),
        )
        if value["result_digest"] != result.result_digest:
            _fail("provider result digest mismatch")
        return result

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ProviderResult":
        return cls.from_dict(_strict_protocol_mapping(raw, "provider result"))


@dataclass(frozen=True)
class ParsedProviderOutput:
    """Immutable stateless transport from parsing to normalization.

    ``ProviderResult`` remains the provisional protocol/status envelope.  This
    carrier adds only canonical parsed material and a content binding; it does
    not mint execution, publication, negative, or clean authority.  Exact raw
    bytes are replayed by :func:`validate_parsed_provider_output` rather than
    retained in an adapter cache or process-global side channel.
    """

    result: ProviderResult
    parsed_payload_schema: str
    parsed_payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        result = (
            ProviderResult.from_dict(self.result.to_dict())
            if type(self.result) is ProviderResult
            else ProviderResult.from_dict(self.result)
            if isinstance(self.result, Mapping)
            else _fail("parsed provider output result must be a ProviderResult")
        )
        object.__setattr__(self, "result", result)
        if result.result_state not in {
            "PROVISIONAL_PARSED",
            "PROVISIONAL_DEGRADED",
        }:
            _fail(
                "parsed provider output requires parsed or degraded "
                "provisional material"
            )
        _provider_id(
            self.parsed_payload_schema,
            "parsed provider output payload schema",
        )
        if not isinstance(self.parsed_payload, Mapping):
            _fail("parsed provider output payload must be an object")
        try:
            normalized_payload = json.loads(
                canonical_json_bytes(self.parsed_payload)
            )
        except (ProgramFactsTypeError, UnicodeDecodeError) as exc:
            _fail("parsed provider output payload is noncanonical", exc)
        if not isinstance(normalized_payload, Mapping):
            _fail("parsed provider output payload must be an object")
        object.__setattr__(
            self,
            "parsed_payload",
            _freeze_json(normalized_payload),
        )

    @property
    def parsed_payload_digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(_thaw_json(self.parsed_payload))
        ).hexdigest()

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PARSED_PROVIDER_OUTPUT_SCHEMA,
            "result": self.result.to_dict(),
            "parsed_payload_schema": self.parsed_payload_schema,
            "parsed_payload_digest": self.parsed_payload_digest,
            "parsed_payload": _thaw_json(self.parsed_payload),
            "authority": dict(_AUTHORITY),
            "completion_authority": PROVISIONAL_AUTHORITY,
        }

    @property
    def carrier_digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self._unsigned_dict())
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "carrier_digest": self.carrier_digest}

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ParsedProviderOutput":
        _exact_keys(
            value,
            _PARSED_PROVIDER_OUTPUT_KEYS,
            "parsed provider output",
        )
        if value["schema_version"] != PARSED_PROVIDER_OUTPUT_SCHEMA:
            _fail("parsed provider output schema version drift")
        if value["authority"] != _AUTHORITY:
            _fail("parsed provider output has non-additive authority")
        if value["completion_authority"] != PROVISIONAL_AUTHORITY:
            _fail("parsed provider output attempts to mint completion authority")
        _hex64(
            value["parsed_payload_digest"],
            "parsed provider output payload digest",
        )
        _hex64(value["carrier_digest"], "parsed provider output carrier digest")
        carrier = cls(
            result=ProviderResult.from_dict(value["result"]),
            parsed_payload_schema=value["parsed_payload_schema"],
            parsed_payload=value["parsed_payload"],
        )
        if value["parsed_payload_digest"] != carrier.parsed_payload_digest:
            _fail("parsed provider output payload digest mismatch")
        if value["carrier_digest"] != carrier.carrier_digest:
            _fail("parsed provider output carrier digest mismatch")
        return carrier

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ParsedProviderOutput":
        return cls.from_dict(
            _strict_protocol_mapping(raw, "parsed provider output")
        )


def validate_parsed_provider_output(
    output: ParsedProviderOutput | Mapping[str, Any],
    *,
    raw_output: bytes,
    plan: ProviderPlan,
    expected_result: ProviderResult | Mapping[str, Any] | None = None,
) -> ParsedProviderOutput:
    """Replay an exact raw/result/plan binding for stateless normalization.

    This is deliberately a pure content check.  Production registry, source
    snapshot, and process-completion authority remain with the existing plan,
    result, PhaseIO, and execution validators.
    """

    if not isinstance(raw_output, bytes):
        _fail("parsed provider output raw output must be exact bytes")
    value = (
        ParsedProviderOutput.from_dict(output.to_dict())
        if type(output) is ParsedProviderOutput
        else ParsedProviderOutput.from_dict(output)
    )
    bound_plan = (
        ProviderPlan.from_dict(plan.to_dict())
        if type(plan) is ProviderPlan
        else _fail("parsed provider output plan must be a ProviderPlan")
    )
    result = value.result
    if (
        result.raw_output_size > bound_plan.resources.output_bytes
        or len(raw_output) > bound_plan.resources.output_bytes
    ):
        _fail(
            "parsed provider output exceeds the signed plan resource ceiling"
        )
    if (
        hashlib.sha256(raw_output).hexdigest() != result.raw_output_sha256
        or len(raw_output) != result.raw_output_size
    ):
        _fail("parsed provider output raw output digest/size mismatch")
    if (
        result.audit_run_id != bound_plan.audit_run_id
        or result.methodology_authority_digest
        != bound_plan.methodology_authority_digest
        or result.registry_digest != bound_plan.registry_digest
        or result.context_digest != bound_plan.context_digest
        or result.source_manifest_digest != bound_plan.source_manifest_digest
        or result.source_authority_digest != bound_plan.source_authority_digest
        or result.plan_id != bound_plan.plan_id
        or result.provider_id != bound_plan.provider_id
        or result.provider_run_id != bound_plan.provider_run_id
    ):
        _fail("parsed provider output result has a plan/source binding mismatch")
    if (
        result.raw_schema_digest
        != bound_plan.raw_binding["raw_schema_digest"]
        or result.parser_callable
        != bound_plan.raw_binding["parser_callable"]
        or result.parser_source_digest
        != bound_plan.raw_binding["parser_source_digest"]
    ):
        _fail("parsed provider output parser/result plan binding mismatch")
    requested_capabilities = {
        request.capability_id for request in bound_plan.capability_requests
    }
    disposed_capabilities = (
        set(result.capabilities_parsed)
        | set(result.capabilities_partial)
        | set(result.capabilities_unavailable)
    )
    if disposed_capabilities != requested_capabilities:
        _fail(
            "parsed provider output capability disposition is not total "
            "for the bound plan"
        )
    if expected_result is not None:
        expected = (
            ProviderResult.from_dict(expected_result.to_dict())
            if type(expected_result) is ProviderResult
            else ProviderResult.from_dict(expected_result)
        )
        if (
            expected.result_digest != result.result_digest
            or expected.to_dict() != result.to_dict()
        ):
            _fail("parsed provider output expected result mismatch")
    return ParsedProviderOutput.from_dict(value.to_dict())


def validate_provider_result(
    result: ProviderResult | Mapping[str, Any],
    *,
    plan: ProviderPlan,
    raw_output: bytes | None,
    registry: LoadedProgramFactsProviderRegistry,
    context: ProviderContext,
    observed_identity: ObservedProviderIdentity,
    allowed_license_classifications: Sequence[str],
    source_manifest_authority: ReplayedProgramFactsSourceManifest | None,
    audit_snapshot_authority: (
        ProgramFactsAuditSnapshotAuthority
        | ReplayedProgramFactsAuditSnapshotAuthority
        | None
    ) = None,
    source_project_root: str | Path | None = None,
    source_config: Mapping[str, Any] | None = None,
    expected_source_ledger_binding: Mapping[str, Any] | None = None,
    observed_configuration_inputs: Sequence[Mapping[str, str]] = (),
) -> ProviderResult:
    """Replay parser/result bindings without certifying process completion."""

    plan_decision = validate_provider_plan(
        plan,
        registry=registry,
        context=context,
        observed_identity=observed_identity,
        allowed_license_classifications=allowed_license_classifications,
        source_manifest_authority=source_manifest_authority,
        audit_snapshot_authority=audit_snapshot_authority,
        source_project_root=source_project_root,
        source_config=source_config,
        expected_source_ledger_binding=expected_source_ledger_binding,
        observed_configuration_inputs=observed_configuration_inputs,
    )
    if not (
        plan_decision.ready or plan_decision.structurally_valid
    ) or plan_decision.plan is None:
        _fail("provider result parent plan lacks production replay authority")
    plan = plan_decision.plan
    value = (
        ProviderResult.from_dict(result.to_dict())
        if type(result) is ProviderResult
        else ProviderResult.from_dict(result)
    )
    if (
        value.audit_run_id != plan.audit_run_id
        or value.methodology_authority_digest
        != plan.methodology_authority_digest
        or value.registry_digest != plan.registry_digest
        or value.context_digest != plan.context_digest
        or value.source_manifest_digest != plan.source_manifest_digest
        or value.source_authority_digest != plan.source_authority_digest
        or value.plan_id != plan.plan_id
        or value.provider_id != plan.provider_id
        or value.provider_run_id != plan.provider_run_id
    ):
        _fail("provider result plan/provider binding mismatch")
    if (
        value.raw_schema_digest != plan.raw_binding["raw_schema_digest"]
        or value.parser_callable != plan.raw_binding["parser_callable"]
        or value.parser_source_digest
        != plan.raw_binding["parser_source_digest"]
    ):
        _fail("provider result parser/raw-schema binding mismatch")
    if value.raw_output_size > plan.resources.output_bytes:
        _fail("provider result exceeds the signed plan resource ceiling")
    requested = {item.capability_id for item in plan.capability_requests}
    disposed = (
        set(value.capabilities_parsed)
        | set(value.capabilities_partial)
        | set(value.capabilities_unavailable)
    )
    if disposed != requested:
        _fail("provider result capability disposition is not total")
    if raw_output is None:
        if value.raw_output_sha256 or value.raw_output_size:
            _fail("provider result claims raw output without replay bytes")
    else:
        if len(raw_output) > plan.resources.output_bytes:
            _fail("provider raw output exceeds the signed plan resource ceiling")
        if (
            hashlib.sha256(raw_output).hexdigest() != value.raw_output_sha256
            or len(raw_output) != value.raw_output_size
        ):
            _fail("provider result raw output digest/size mismatch")
    return ProviderResult.from_dict(value.to_dict())


_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "rules"
    / "schemas"
    / "mechanical_program_facts.v1.schema.json"
)


@lru_cache(maxsize=8)
def _row_validator(
    definition: str,
    schema_raw: bytes | None = None,
) -> Draft202012Validator:
    try:
        schema = json.loads(
            (
                _SCHEMA_PATH.read_bytes()
                if schema_raw is None
                else schema_raw
            )
        )
        Draft202012Validator.check_schema(schema)
        if (
            not isinstance(schema, Mapping)
            or schema.get("$schema")
            != "https://json-schema.org/draft/2020-12/schema"
            or schema.get("additionalProperties") is not False
            or not isinstance(schema.get("$defs"), Mapping)
            or not _schema_references_are_local(schema)
        ):
            _fail("canonical Program Facts row schema is not independently closed")
        for name in ("node", "occurrence", "fact"):
            row_schema = schema["$defs"].get(name)
            if (
                not isinstance(row_schema, Mapping)
                or row_schema.get("additionalProperties") is not False
            ):
                _fail(f"Program Facts {name} row schema is not closed")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, Exception) as exc:
        _fail("cannot load canonical Program Facts row schema", exc)
    wrapper = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"],
        "$ref": f"#/$defs/{definition}",
    }
    return Draft202012Validator(wrapper)


def _validate_rows(
    values: Sequence[Mapping[str, Any]],
    definition: str,
    id_field: str,
    *,
    schema_raw: bytes | None = None,
) -> tuple[Mapping[str, Any], ...]:
    rows = _json_mapping_tuple(values, f"contribution {definition} rows")
    validator = _row_validator(definition, schema_raw)
    identities: list[str] = []
    for row in rows:
        errors = sorted(
            validator.iter_errors(row),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if errors:
            _fail(
                f"contribution {definition} schema violation: "
                f"{errors[0].message}"
            )
        identities.append(str(row[id_field]))
    if identities != sorted(identities):
        _fail(f"contribution {definition} rows must be sorted by {id_field}")
    if len(identities) != len(set(identities)):
        _fail(f"contribution {definition} rows contain duplicate IDs")
    return rows


@dataclass(frozen=True)
class ZeroPositiveAccounting:
    """Exact denominator accounting for a parsed capability with no facts.

    The record reconciles provider output; it is not evidence that a security
    property holds and carries no finding, negative, suppression, demotion,
    refutation, examined, or clean authority.
    """

    capability_id: str
    result_digest: str
    source_authority_digest: str
    denominators: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        _provider_id(
            self.capability_id,
            "zero-positive accounting capability ID",
        )
        _hex64(
            self.result_digest,
            "zero-positive accounting result digest",
        )
        _hex64(
            self.source_authority_digest,
            "zero-positive accounting source authority digest",
        )
        if isinstance(self.denominators, (str, bytes, bytearray)):
            _fail("zero-positive denominators must be an array")
        normalized: list[Mapping[str, Any]] = []
        build_variant_ids: list[str] = []
        for raw_row in self.denominators:
            if not isinstance(raw_row, Mapping):
                _fail("zero-positive denominators must contain objects")
            actual = frozenset(raw_row)
            if actual not in {
                _ZERO_POSITIVE_DENOMINATOR_BASE_KEYS,
                _ZERO_POSITIVE_DENOMINATOR_WIRE_KEYS,
            }:
                _exact_keys(
                    raw_row,
                    _ZERO_POSITIVE_DENOMINATOR_WIRE_KEYS,
                    "zero-positive denominator",
                )
            build_variant_id = _opaque_id(
                raw_row["build_variant_id"],
                "zero-positive denominator build variant",
            )
            denominator_kind = _provider_id(
                raw_row["denominator_kind"],
                "zero-positive denominator kind",
            )
            denominator_ids = _sorted_unique_strings(
                raw_row["denominator_ids"],
                "zero-positive denominator IDs",
            )
            for identity in denominator_ids:
                _opaque_id(
                    identity,
                    "zero-positive denominator identity",
                )
            unsigned = {
                "schema_version": ZERO_POSITIVE_ACCOUNTING_SCHEMA,
                "capability_id": self.capability_id,
                "result_digest": self.result_digest,
                "source_authority_digest": self.source_authority_digest,
                "build_variant_id": build_variant_id,
                "denominator_kind": denominator_kind,
                "denominator_ids": list(denominator_ids),
                "denominator_precision": "EXACT",
            }
            denominator_digest = hashlib.sha256(
                canonical_json_bytes(unsigned)
            ).hexdigest()
            if actual == _ZERO_POSITIVE_DENOMINATOR_WIRE_KEYS:
                if raw_row["denominator_precision"] != "EXACT":
                    _fail(
                        "zero-positive denominator precision must be EXACT"
                    )
                count = raw_row["denominator_count"]
                if (
                    isinstance(count, bool)
                    or not isinstance(count, int)
                    or count < 0
                ):
                    _fail(
                        "zero-positive denominator count must be a "
                        "nonnegative integer"
                    )
                if count != len(denominator_ids):
                    _fail("zero-positive denominator count mismatch")
                _hex64(
                    raw_row["denominator_digest"],
                    "zero-positive denominator digest",
                )
                if raw_row["denominator_digest"] != denominator_digest:
                    _fail("zero-positive denominator digest mismatch")
            normalized.append(
                _freeze_json(
                    {
                        "build_variant_id": build_variant_id,
                        "denominator_kind": denominator_kind,
                        "denominator_ids": list(denominator_ids),
                        "denominator_precision": "EXACT",
                        "denominator_count": len(denominator_ids),
                        "denominator_digest": denominator_digest,
                    }
                )
            )
            build_variant_ids.append(build_variant_id)
        if not normalized:
            _fail("zero-positive denominators must not be empty")
        if build_variant_ids != sorted(build_variant_ids) or len(
            build_variant_ids
        ) != len(set(build_variant_ids)):
            _fail(
                "zero-positive denominator build variants must be sorted "
                "and unique"
            )
        object.__setattr__(self, "denominators", tuple(normalized))

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ZERO_POSITIVE_ACCOUNTING_SCHEMA,
            "capability_id": self.capability_id,
            "result_digest": self.result_digest,
            "source_authority_digest": self.source_authority_digest,
            "denominators": [
                _thaw_json(row) for row in self.denominators
            ],
            "authority": dict(_ZERO_POSITIVE_AUTHORITY),
        }

    @property
    def accounting_digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self._unsigned_dict())
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "accounting_digest": self.accounting_digest,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ZeroPositiveAccounting":
        _exact_keys(
            value,
            _ZERO_POSITIVE_ACCOUNTING_KEYS,
            "zero-positive accounting",
        )
        if value["schema_version"] != ZERO_POSITIVE_ACCOUNTING_SCHEMA:
            _fail("zero-positive accounting schema version drift")
        if value["authority"] != _ZERO_POSITIVE_AUTHORITY:
            _fail("zero-positive accounting authority mismatch")
        _hex64(
            value["accounting_digest"],
            "zero-positive accounting digest",
        )
        record = cls(
            capability_id=value["capability_id"],
            result_digest=value["result_digest"],
            source_authority_digest=value["source_authority_digest"],
            denominators=tuple(value["denominators"]),
        )
        if value["accounting_digest"] != record.accounting_digest:
            _fail("zero-positive accounting digest mismatch")
        return record

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ZeroPositiveAccounting":
        return cls.from_dict(
            _strict_protocol_mapping(raw, "zero-positive accounting")
        )


@dataclass(frozen=True)
class FactContribution:
    """Provider-normalized additive proposal with no publication authority."""

    audit_run_id: str
    methodology_authority_digest: str
    registry_digest: str
    context_digest: str
    source_manifest_digest: str
    source_authority_digest: str
    plan_id: str
    result_digest: str
    provider_id: str
    provider_run_id: str
    build_variant_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    nodes: tuple[Mapping[str, Any], ...]
    occurrences: tuple[Mapping[str, Any], ...]
    facts: tuple[Mapping[str, Any], ...]
    debt_codes: tuple[str, ...]
    capability_accounting: tuple[Mapping[str, Any], ...]
    _row_schema_bytes: bytes | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        row_schema_bytes = self._row_schema_bytes
        if row_schema_bytes is not None and type(row_schema_bytes) is not bytes:
            _fail("contribution row schema authority must be exact bytes")
        object.__setattr__(
            self, "build_variant_ids", tuple(self.build_variant_ids)
        )
        object.__setattr__(self, "capability_ids", tuple(self.capability_ids))
        object.__setattr__(
            self,
            "nodes",
            tuple(_freeze_json(row) for row in _validate_rows(
                self.nodes,
                "node",
                "node_id",
                schema_raw=row_schema_bytes,
            )),
        )
        object.__setattr__(
            self,
            "occurrences",
            tuple(_freeze_json(row) for row in _validate_rows(
                self.occurrences,
                "occurrence",
                "occurrence_id",
                schema_raw=row_schema_bytes,
            )),
        )
        object.__setattr__(
            self,
            "facts",
            tuple(_freeze_json(row) for row in _validate_rows(
                self.facts,
                "fact",
                "fact_id",
                schema_raw=row_schema_bytes,
            )),
        )
        object.__setattr__(self, "_row_schema_bytes", None)
        object.__setattr__(self, "debt_codes", tuple(self.debt_codes))
        object.__setattr__(
            self,
            "capability_accounting",
            tuple(
                _freeze_json(row)
                for row in _json_mapping_tuple(
                    self.capability_accounting,
                    "contribution capability accounting",
                )
            ),
        )
        if not re.fullmatch(r"^PFP-[0-9a-f]{24}$", self.plan_id):
            _fail("contribution plan ID is invalid")
        _hex64(self.result_digest, "contribution result digest")
        _provider_id(self.provider_id, "contribution provider ID")
        _provider_id(self.provider_run_id, "contribution provider run ID")
        _opaque_id(self.audit_run_id, "contribution audit run ID")
        for value, label in (
            (
                self.methodology_authority_digest,
                "contribution methodology authority",
            ),
            (self.registry_digest, "contribution registry"),
            (self.context_digest, "contribution context"),
            (self.source_manifest_digest, "contribution source manifest"),
            (self.source_authority_digest, "contribution source authority"),
        ):
            _hex64(value, f"{label} digest")
        _sorted_unique_strings(
            self.build_variant_ids,
            "contribution build variants",
            allow_empty=False,
        )
        _sorted_unique_strings(
            self.capability_ids,
            "contribution capabilities",
            allow_empty=False,
        )
        _sorted_unique_strings(self.debt_codes, "contribution debt codes")
        if any(code not in _MECHANICAL_DEBT_CODES for code in self.debt_codes):
            _fail(
                "contribution debt code is outside the mechanical vocabulary"
        )
        accounting_ids: list[str] = []
        for row in self.capability_accounting:
            base_accounting_keys = frozenset(
                {
                    "capability_id",
                    "disposition",
                    "emitted_fact_ids",
                    "debt_codes",
                }
            )
            actual_accounting_keys = frozenset(row)
            if actual_accounting_keys not in {
                base_accounting_keys,
                base_accounting_keys | {"zero_positive_accounting"},
            }:
                _exact_keys(
                    row,
                    base_accounting_keys,
                    "contribution capability accounting",
                )
            accounting_ids.append(
                _provider_id(
                    row["capability_id"],
                    "contribution accounting capability ID",
                )
            )
            if row["disposition"] not in {
                "PARSED",
                "PARTIAL",
                "UNAVAILABLE",
            }:
                _fail("contribution accounting disposition is invalid")
            _sorted_unique_strings(
                row["emitted_fact_ids"],
                "contribution accounting fact IDs",
            )
            codes = _sorted_unique_strings(
                row["debt_codes"],
                "contribution accounting debt codes",
            )
            if any(code not in _MECHANICAL_DEBT_CODES for code in codes):
                _fail(
                    "contribution accounting debt code is outside the "
                    "mechanical vocabulary"
                )
            if "zero_positive_accounting" in row:
                ZeroPositiveAccounting.from_dict(
                    row["zero_positive_accounting"]
                )
        if accounting_ids != sorted(accounting_ids) or len(
            accounting_ids
        ) != len(set(accounting_ids)):
            _fail(
                "contribution capability accounting must be sorted and unique"
            )
        if not accounting_ids:
            _fail("contribution capability accounting must not be empty")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": FACT_CONTRIBUTION_SCHEMA,
            "audit_run_id": self.audit_run_id,
            "methodology_authority_digest": (
                self.methodology_authority_digest
            ),
            "registry_digest": self.registry_digest,
            "context_digest": self.context_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "source_authority_digest": self.source_authority_digest,
            "plan_id": self.plan_id,
            "result_digest": self.result_digest,
            "provider_id": self.provider_id,
            "provider_run_id": self.provider_run_id,
            "build_variant_ids": list(self.build_variant_ids),
            "capability_ids": list(self.capability_ids),
            "nodes": [_thaw_json(row) for row in self.nodes],
            "occurrences": [_thaw_json(row) for row in self.occurrences],
            "facts": [_thaw_json(row) for row in self.facts],
            "debt_codes": list(self.debt_codes),
            "capability_accounting": [
                _thaw_json(row) for row in self.capability_accounting
            ],
            "authority": dict(_AUTHORITY),
            "completion_authority": PROVISIONAL_AUTHORITY,
        }

    @property
    def contribution_id(self) -> str:
        return derive_stable_id("PFCN", self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "contribution_id": self.contribution_id,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        row_schema_bytes: bytes | None = None,
    ) -> "FactContribution":
        _exact_keys(value, _CONTRIBUTION_KEYS, "fact contribution")
        if value["schema_version"] != FACT_CONTRIBUTION_SCHEMA:
            _fail("fact contribution schema version drift")
        if value["authority"] != _AUTHORITY:
            _fail("fact contribution has non-additive authority")
        if value["completion_authority"] != PROVISIONAL_AUTHORITY:
            _fail("fact contribution attempts to mint publication authority")
        contribution = cls(
            audit_run_id=value["audit_run_id"],
            methodology_authority_digest=value[
                "methodology_authority_digest"
            ],
            registry_digest=value["registry_digest"],
            context_digest=value["context_digest"],
            source_manifest_digest=value["source_manifest_digest"],
            source_authority_digest=value["source_authority_digest"],
            plan_id=value["plan_id"],
            result_digest=value["result_digest"],
            provider_id=value["provider_id"],
            provider_run_id=value["provider_run_id"],
            build_variant_ids=tuple(value["build_variant_ids"]),
            capability_ids=tuple(value["capability_ids"]),
            nodes=tuple(value["nodes"]),
            occurrences=_validate_rows(
                value["occurrences"],
                "occurrence",
                "occurrence_id",
                schema_raw=row_schema_bytes,
            ),
            facts=_validate_rows(
                value["facts"],
                "fact",
                "fact_id",
                schema_raw=row_schema_bytes,
            ),
            debt_codes=tuple(value["debt_codes"]),
            capability_accounting=tuple(value["capability_accounting"]),
            _row_schema_bytes=row_schema_bytes,
        )
        if value["contribution_id"] != contribution.contribution_id:
            _fail("fact contribution ID mismatch")
        return contribution

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        row_schema_bytes: bytes | None = None,
    ) -> "FactContribution":
        return cls.from_dict(
            _strict_protocol_mapping(raw, "fact contribution"),
            row_schema_bytes=row_schema_bytes,
        )


def validate_fact_contribution(
    contribution: FactContribution | Mapping[str, Any],
    *,
    plan: ProviderPlan,
    result: ProviderResult,
    registry: LoadedProgramFactsProviderRegistry,
    context: ProviderContext,
    observed_identity: ObservedProviderIdentity,
    raw_output: bytes | None,
    allowed_license_classifications: Sequence[str],
    source_manifest_authority: ReplayedProgramFactsSourceManifest | None,
    audit_snapshot_authority: (
        ProgramFactsAuditSnapshotAuthority
        | ReplayedProgramFactsAuditSnapshotAuthority
        | None
    ) = None,
    source_project_root: str | Path | None = None,
    source_config: Mapping[str, Any] | None = None,
    expected_source_ledger_binding: Mapping[str, Any] | None = None,
    observed_configuration_inputs: Sequence[Mapping[str, str]] = (),
) -> FactContribution:
    """Validate structure, local references, and capability fidelity exactly."""

    frozen_source_config: Mapping[str, Any] | None = None
    if source_config is not None:
        if not isinstance(source_config, Mapping):
            _fail("provider source config must be a JSON object")
        frozen_source_config = _snapshot_json_once(
            source_config,
            "provider source config",
        )
        assert isinstance(frozen_source_config, Mapping)
    frozen_source_ledger: Mapping[str, Any] | None = None
    if expected_source_ledger_binding is not None:
        if not isinstance(expected_source_ledger_binding, Mapping):
            _fail("provider source-ledger binding must be a JSON object")
        frozen_source_ledger = _snapshot_json_once(
            expected_source_ledger_binding,
            "provider source-ledger binding",
        )
        assert isinstance(frozen_source_ledger, Mapping)
    frozen_observed_configuration_inputs = _json_mapping_tuple(
        observed_configuration_inputs,
        "observed configuration inputs",
    )
    frozen_allowed_license_classifications = tuple(
        allowed_license_classifications
    )
    result = validate_provider_result(
        result,
        plan=plan,
        raw_output=raw_output,
        registry=registry,
        context=context,
        observed_identity=observed_identity,
        allowed_license_classifications=(
            frozen_allowed_license_classifications
        ),
        source_manifest_authority=source_manifest_authority,
        audit_snapshot_authority=audit_snapshot_authority,
        source_project_root=source_project_root,
        source_config=frozen_source_config,
        expected_source_ledger_binding=frozen_source_ledger,
        observed_configuration_inputs=(
            frozen_observed_configuration_inputs
        ),
    )
    plan_decision = validate_provider_plan(
        plan,
        registry=registry,
        context=context,
        observed_identity=observed_identity,
        allowed_license_classifications=(
            frozen_allowed_license_classifications
        ),
        source_manifest_authority=source_manifest_authority,
        audit_snapshot_authority=audit_snapshot_authority,
        source_project_root=source_project_root,
        source_config=frozen_source_config,
        expected_source_ledger_binding=frozen_source_ledger,
        observed_configuration_inputs=(
            frozen_observed_configuration_inputs
        ),
    )
    production_plan_ready = plan_decision.ready
    structural_plan_valid = plan_decision.structurally_valid
    if not (
        production_plan_ready or structural_plan_valid
    ) or plan_decision.plan is None:
        _fail("fact contribution parent plan lacks production replay authority")
    plan = plan_decision.plan
    registry._assert_replayable()
    row_schema_bytes = (
        registry.captured_schema_bytes(
            "mechanical_program_facts.v1.schema.json"
        )
        if registry.production_authority_established
        else None
    )
    value = (
        FactContribution.from_dict(
            contribution.to_dict(),
            row_schema_bytes=row_schema_bytes,
        )
        if type(contribution) is FactContribution
        else FactContribution.from_dict(
            contribution,
            row_schema_bytes=row_schema_bytes,
        )
    )
    if (
        value.audit_run_id != plan.audit_run_id
        or value.methodology_authority_digest
        != plan.methodology_authority_digest
        or value.registry_digest != plan.registry_digest
        or value.context_digest != plan.context_digest
        or value.source_manifest_digest != plan.source_manifest_digest
        or value.source_authority_digest != plan.source_authority_digest
        or value.plan_id != plan.plan_id
        or value.result_digest != result.result_digest
        or value.provider_id != plan.provider_id
        or value.provider_run_id != plan.provider_run_id
    ):
        _fail("fact contribution plan/result/provider binding mismatch")
    if set(value.build_variant_ids) != set(plan.build_variant_ids):
        _fail("fact contribution build-variant denominator mismatch")
    result_capabilities = (
        set(result.capabilities_parsed)
        | set(result.capabilities_partial)
        | set(result.capabilities_unavailable)
    )
    if set(value.capability_ids) != result_capabilities:
        _fail("fact contribution capability denominator is not total")

    selection = registry.provider(plan.provider_id)
    if not selection.ready and not (
        structural_plan_valid and selection.provider is not None
    ):
        _fail("fact contribution references a provider outside registry authority")
    provider = selection.provider
    assert provider is not None
    capability_rows = {
        item["capability_id"]: item for item in provider["capabilities"]
    }
    request_rows = {
        item.capability_id: item for item in plan.capability_requests
    }
    fallback_cap = ""
    if plan.fallback_from_provider_id:
        source = registry.provider(plan.fallback_from_provider_id)
        if (
            not source.ready
            and not structural_plan_valid
        ) or source.provider is None:
            _fail("fact contribution fallback parent authority is unavailable")
        fallback_cap = source.provider["fallback"]["maximum_precision"]

    node_ids = {str(row["node_id"]) for row in value.nodes}
    occurrence_ids = {str(row["occurrence_id"]) for row in value.occurrences}
    for node in value.nodes:
        if node["build_variant_id"] not in set(value.build_variant_ids):
            _fail("contribution node has an unplanned build variant")
    for occurrence in value.occurrences:
        if occurrence["enclosing_node_id"] not in node_ids:
            _fail("contribution occurrence has a dangling node reference")
    for fact in value.facts:
        capability_id = fact["capability_id"]
        if capability_id not in set(value.capability_ids):
            _fail("contribution fact overclaims an undeclared capability")
        capability = capability_rows.get(capability_id)
        if capability is None:
            _fail("contribution fact capability is outside registry authority")
        request = request_rows.get(capability_id)
        if request is None:
            _fail("contribution fact capability is outside request authority")
        effective_precision = maximum_effective_precision(
            capability["maximum_precision"],
            request.maximum_precision,
            fallback_cap,
        )
        if _PRECISION_RANK[fact["precision"]] > _PRECISION_RANK[
            effective_precision
        ]:
            _fail(
                "contribution fact precision exceeds registry/request/fallback "
                "fidelity"
            )
        if fact["provenance_origin"] not in set(
            capability["allowed_provenance_origins"]
        ):
            _fail("contribution fact provenance exceeds registry fidelity")
        if fact["relation_kind"] not in set(
            capability["allowed_relation_kinds"]
        ):
            _fail("contribution fact relation exceeds registry fidelity")
        if (
            fact["provider_run_id"] != plan.provider_run_id
            or tuple(fact["attestations"]) != (plan.provider_run_id,)
        ):
            _fail("contribution fact provenance is not exactly provider-bound")
        if (
            fact["subject_id"] not in node_ids
            or fact["object_id"] not in node_ids
            or not set(fact["occurrence_ids"]) <= occurrence_ids
            or not set(fact["context"]["dominating_predicates"])
            <= occurrence_ids
        ):
            _fail("contribution fact has a dangling local reference")
        if fact["build_variant_id"] not in set(value.build_variant_ids):
            _fail("contribution fact has an unplanned build variant")
        if fact["semantic_authority"] != "ADDITIVE_PROPOSAL_ONLY":
            _fail("contribution fact has non-additive semantic authority")

    disposition_by_capability = {
        capability_id: "PARSED"
        for capability_id in result.capabilities_parsed
    }
    disposition_by_capability.update(
        {
            capability_id: "PARTIAL"
            for capability_id in result.capabilities_partial
        }
    )
    disposition_by_capability.update(
        {
            capability_id: "UNAVAILABLE"
            for capability_id in result.capabilities_unavailable
        }
    )
    result_debts_by_capability = {
        str(row["capability_id"]): set(row["debt_codes"])
        for row in result.capability_diagnostics
    }
    fact_ids_by_capability: dict[str, list[str]] = {
        capability_id: [] for capability_id in result_capabilities
    }
    for fact in value.facts:
        fact_ids_by_capability[fact["capability_id"]].append(fact["fact_id"])
    observed_debts: set[str] = set()
    accounting_ids: list[str] = []
    for row in value.capability_accounting:
        capability_id = row["capability_id"]
        accounting_ids.append(capability_id)
        if (
            capability_id not in disposition_by_capability
            or row["disposition"]
            != disposition_by_capability[capability_id]
        ):
            _fail("contribution capability accounting disposition mismatch")
        expected_fact_ids = sorted(fact_ids_by_capability[capability_id])
        if list(row["emitted_fact_ids"]) != expected_fact_ids:
            _fail("contribution capability accounting fact reconciliation mismatch")
        debts = set(row["debt_codes"])
        observed_debts.update(debts)
        if debts != result_debts_by_capability.get(capability_id, set()):
            _fail(
                "contribution capability debt differs from the parent result"
            )
        if row["disposition"] in {"PARTIAL", "UNAVAILABLE"} and not debts:
            _fail("partial/unavailable capability lacks scoped contribution debt")
        zero_positive = (
            ZeroPositiveAccounting.from_dict(
                row["zero_positive_accounting"]
            )
            if "zero_positive_accounting" in row
            else None
        )
        if zero_positive is not None:
            if expected_fact_ids or debts or row["disposition"] != "PARSED":
                _fail(
                    "zero-positive accounting is valid only for a fully parsed "
                    "capability without emitted facts or scoped debt"
                )
            if zero_positive.capability_id != capability_id:
                _fail("zero-positive accounting capability mismatch")
            if zero_positive.result_digest != result.result_digest:
                _fail("zero-positive accounting result digest mismatch")
            if (
                zero_positive.source_authority_digest
                != result.source_authority_digest
                or zero_positive.source_authority_digest
                != value.source_authority_digest
            ):
                _fail("zero-positive accounting source authority mismatch")
            zero_build_variants = {
                row_value["build_variant_id"]
                for row_value in zero_positive.denominators
            }
            if zero_build_variants != set(value.build_variant_ids):
                _fail(
                    "zero-positive accounting build-variant denominator "
                    "is not total"
                )
        if not expected_fact_ids and not debts and zero_positive is None:
            _fail(
                "capability disappeared without emitted facts, scoped debt, "
                "or exact zero-positive accounting"
            )
        if row["disposition"] == "UNAVAILABLE" and expected_fact_ids:
            _fail("unavailable capability cannot emit facts")
    if set(accounting_ids) != result_capabilities:
        _fail("contribution capability accounting is not total")
    if observed_debts != set(value.debt_codes):
        _fail("contribution flat/scoped debt reconciliation mismatch")
    return FactContribution.from_dict(
        value.to_dict(),
        row_schema_bytes=row_schema_bytes,
    )


@runtime_checkable
class ProgramFactsProvider(Protocol):
    """Provider adapter protocol.  Methods remain deterministic and provisional."""

    def plan(self, context: ProviderContext) -> ProviderPlan:
        ...

    def parse_raw(
        self, raw: bytes, plan: ProviderPlan
    ) -> ProviderResult | ParsedProviderOutput:
        ...

    def normalize(
        self,
        result: ProviderResult | ParsedProviderOutput,
        plan: ProviderPlan,
    ) -> FactContribution:
        ...


__all__ = [
    "CapabilityRequest",
    "EnvironmentBinding",
    "FACT_CONTRIBUTION_SCHEMA",
    "FactContribution",
    "ObservedProviderIdentity",
    "PARSED_PROVIDER_OUTPUT_SCHEMA",
    "PROGRAM_FACTS_TRUST_BOUNDARY",
    "PROVIDER_CONTEXT_SCHEMA",
    "PROVIDER_PLAN_SCHEMA",
    "PROVIDER_RESULT_SCHEMA",
    "PROVIDER_SOURCE_INPUT_SNAPSHOT_SCHEMA",
    "PROVISIONAL_AUTHORITY",
    "ParsedProviderOutput",
    "PlatformIdentity",
    "ProgramFactsProvider",
    "ProgramFactsProviderAPIError",
    "ProviderContext",
    "ProviderPlan",
    "ProviderPlanDecision",
    "ProviderResources",
    "ProviderResult",
    "ProviderSourceInputSnapshot",
    "ToolchainIdentity",
    "TCB_CODE_MUTATION_DISPOSITION",
    "ZERO_POSITIVE_ACCOUNTING_SCHEMA",
    "ZeroPositiveAccounting",
    "compile_provider_plan",
    "replay_provider_source_input_snapshot",
    "snapshot_provider_source_inputs",
    "validate_fact_contribution",
    "validate_parsed_provider_output",
    "validate_provider_plan",
    "validate_provider_result",
]
