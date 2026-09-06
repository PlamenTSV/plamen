"""Closed, replayable provider-registry authority for typed Program Facts.

This module is deliberately policy-only.  It never imports an adapter, resolves
an executable, inspects the host, reads environment variables, launches a
process, downloads a distribution, or asks a model to choose a provider.
Callers supply observations explicitly and receive either an exact reviewed row
or typed debt.  Absence, drift, and policy mismatch are never represented as a
clean result.

The registry validator executes inside the Program Facts TCB: the isolated
Python orchestrator process, interpreter and loaded dependencies, code objects
and closure cells, installed methodology files, and deterministic gate code.
Worker/provider/model behavior and all configuration, registry, protocol, and
artifact bytes entering from outside that process are untrusted and require
exact replay.

Arbitrary execution or code/closure mutation inside the TCB defeats every
Python-level gate and is out of this data-validation threat model.  It must be
addressed by OS process isolation plus code, package, and installed-file
integrity; underscore names and caller-code checks are not security controls.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import hashlib
import inspect
import re
from pathlib import Path
import threading
from types import MappingProxyType
from typing import Any
import weakref

from jsonschema import Draft202012Validator

from program_facts_methodology_authority import (
    DEFAULT_MAX_AUTHORITY_BYTES,
    INSTALLED_METHODOLOGY_AUTHORITY,
    InstalledMethodologyAuthority,
    METHODOLOGY_PACKAGE_SCHEMA,
    PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS,
    ProgramFactsMethodologyAuthorityError,
    replay_installed_program_facts_methodology_capture,
)
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    derive_stable_id,
    strict_json_loads,
    validate_portable_path,
    validate_program_facts_provider_registry,
)


REGISTRY_SCHEMA_VERSION = "plamen.program_facts_provider_registry.v1"
NO_PROVIDER_AUTHORITY = "NO_PROVIDER_AUTHORITY"
REVIEWED_PROVIDER_AUTHORITY = "REVIEWED_PROVIDER_AUTHORITY"
STRUCTURAL_TEST_ONLY = "STRUCTURAL_TEST_ONLY"
INSTALLED_PRODUCTION_AUTHORITY = "INSTALLED_PRODUCTION_AUTHORITY"
DEFAULT_REGISTRY_PATH = (
    Path(__file__).resolve().parents[1]
    / "rules"
    / "program-facts-provider-registry.v1.json"
)
DEFAULT_MAX_REGISTRY_BYTES = 4 * 1024 * 1024
PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "runtime-data",
        "mode": "file",
        "path": "rules/program-facts-provider-registry.v1.json",
    },
    {
        "kind": "runtime-data",
        "mode": "named-files",
        "root": "rules/schemas",
        "names": (
            "mechanical_program_facts.v1.schema.json",
            "mechanical_program_facts_debt.v1.schema.json",
            "mechanical_program_facts_receipt.v1.schema.json",
            "program_facts_disagreement.v1.schema.json",
            "program_facts_provider_registry.v1.schema.json",
            "program_facts_slice.v1.schema.json",
        ),
    },
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$", re.ASCII)
_PROVIDER_SCHEMA_RE = re.compile(
    r"^plamen\.program_facts_provider\.[a-z0-9_.-]+\.v[0-9]+$",
    re.ASCII,
)
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$", re.ASCII)
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$", re.ASCII)
_MUTABLE_PIN_RE = re.compile(
    r"(?:^|[./_+-])(latest|main|master|head|stable|nightly|current|snapshot)"
    r"(?:$|[./_+-])",
    re.IGNORECASE | re.ASCII,
)
_SECRET_NAME_RE = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|"
    r"CREDENTIAL|AUTH)",
    re.ASCII,
)

_TOP_LEVEL_KEYS = frozenset({"schema_version", "release_state", "providers"})
_PROVIDER_KEYS = frozenset(
    {
        "provider_id",
        "provider_schema_version",
        "adapter",
        "supported_ecosystems",
        "supported_languages",
        "toolchain_ranges",
        "capabilities",
        "raw_binding",
        "tool_identity",
        "invocation_policy",
        "resolution_policy",
        "expected_version_syntax",
        "distribution",
        "license_classification",
        "limits",
        "supported_platforms",
        "fallback",
        "authority",
        "installation_provenance",
        "environment_policy",
        "install_policy",
        "supply_chain_policy",
    }
)
_RESOLUTION_POLICIES = frozenset(
    {
        "PINNED_DISTRIBUTION",
        "PINNED_MODULE_SOURCE",
        "BUILT_FROM_PINNED_SOURCE",
    }
)
_DISTRIBUTION_KINDS = frozenset(
    {"python-wheel", "native-binary", "checked-in-module", "source-build"}
)
_INSTALL_PROVENANCE_KINDS = frozenset(
    {"checked-lock", "checked-source", "vendored-binary", "offline-package"}
)
_INSTALL_MODES = frozenset(
    {
        "PREINSTALLED_VERIFIED",
        "OFFLINE_PINNED_PACKAGE",
        "CHECKED_IN_SOURCE_BUILD",
    }
)
_PLATFORM_OSES = frozenset({"windows", "linux", "macos"})
_PLATFORM_ARCHITECTURES = frozenset({"amd64", "arm64"})
_PRECISION_RANK = {
    "SYNTACTIC": 0,
    "HEURISTIC": 1,
    "MAY": 2,
    "EXACT": 3,
}
_TYPED_SUBSTITUTION_SOURCES = frozenset(
    {
        "AUDIT_RUN_ID",
        "PROVIDER_RUN_ID",
        "SNAPSHOT_DIGEST",
        "SOURCE_SCOPE_DIGEST",
        "SOURCE_MANIFEST_DIGEST",
        "WORKING_DIRECTORY_ROOT_ID",
        "SINGLE_BUILD_VARIANT_ID",
    }
)
_PLACEHOLDER_RE = re.compile(r"^\{[A-Z][A-Z0-9_]*\}$", re.ASCII)
_DEBT_SEAL = object()
_DECISION_SEAL = object()


class ProgramFactsProviderRegistryError(ValueError):
    """The reviewed registry bytes or their policy semantics are invalid."""


class ProviderPolicyDebtCode(str, Enum):
    UNKNOWN_PROVIDER = "UNKNOWN_PROVIDER"
    REGISTRY_DIGEST_MISMATCH = "REGISTRY_DIGEST_MISMATCH"
    PROVIDER_SCHEMA_DRIFT = "PROVIDER_SCHEMA_DRIFT"
    PROVIDER_VERSION_DRIFT = "PROVIDER_VERSION_DRIFT"
    ADAPTER_BINDING_DRIFT = "ADAPTER_BINDING_DRIFT"
    TOOL_IDENTITY_DRIFT = "TOOL_IDENTITY_DRIFT"
    EXECUTABLE_DIGEST_DRIFT = "EXECUTABLE_DIGEST_DRIFT"
    MODULE_DIGEST_DRIFT = "MODULE_DIGEST_DRIFT"
    DISTRIBUTION_UNPINNED = "DISTRIBUTION_UNPINNED"
    DISTRIBUTION_CHECKSUM_MISMATCH = "DISTRIBUTION_CHECKSUM_MISMATCH"
    PARSER_DIGEST_DRIFT = "PARSER_DIGEST_DRIFT"
    RAW_SCHEMA_DIGEST_DRIFT = "RAW_SCHEMA_DIGEST_DRIFT"
    LICENSE_OR_DISTRIBUTION_RESTRICTED = (
        "LICENSE_OR_DISTRIBUTION_RESTRICTED"
    )
    UNSUPPORTED_OS = "UNSUPPORTED_OS"
    UNSUPPORTED_ARCHITECTURE = "UNSUPPORTED_ARCHITECTURE"
    UNSUPPORTED_ECOSYSTEM = "UNSUPPORTED_ECOSYSTEM"
    UNSUPPORTED_LANGUAGE = "UNSUPPORTED_LANGUAGE"
    UNSUPPORTED_TOOLCHAIN = "UNSUPPORTED_TOOLCHAIN"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    CAPABILITY_FIDELITY_OVERCLAIM = "CAPABILITY_FIDELITY_OVERCLAIM"
    FALLBACK_POLICY_MISMATCH = "FALLBACK_POLICY_MISMATCH"
    FALLBACK_PRECISION_BROADENING = "FALLBACK_PRECISION_BROADENING"
    RESOURCE_POLICY_BROADENING = "RESOURCE_POLICY_BROADENING"
    ENVIRONMENT_SECRET_FORBIDDEN = "ENVIRONMENT_SECRET_FORBIDDEN"
    ENVIRONMENT_POLICY_BROADENING = "ENVIRONMENT_POLICY_BROADENING"
    INSTALL_POLICY_DRIFT = "INSTALL_POLICY_DRIFT"
    STRUCTURAL_TEST_ONLY = "STRUCTURAL_TEST_ONLY"
    INVOCATION_POLICY_DRIFT = "INVOCATION_POLICY_DRIFT"
    CONFIGURATION_BINDING_DRIFT = "CONFIGURATION_BINDING_DRIFT"
    CONTEXT_BINDING_DRIFT = "CONTEXT_BINDING_DRIFT"
    SOURCE_AUTHORITY_DRIFT = "SOURCE_AUTHORITY_DRIFT"
    METHODOLOGY_AUTHORITY_DRIFT = "METHODOLOGY_AUTHORITY_DRIFT"


_MECHANICAL_DEBT_REASON = {
    ProviderPolicyDebtCode.UNKNOWN_PROVIDER: "PROVIDER_UNAVAILABLE",
    ProviderPolicyDebtCode.REGISTRY_DIGEST_MISMATCH: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
    ProviderPolicyDebtCode.PROVIDER_SCHEMA_DRIFT: "PROVIDER_VERSION_DRIFT",
    ProviderPolicyDebtCode.PROVIDER_VERSION_DRIFT: "PROVIDER_VERSION_DRIFT",
    ProviderPolicyDebtCode.ADAPTER_BINDING_DRIFT: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
    ProviderPolicyDebtCode.TOOL_IDENTITY_DRIFT: "PROVIDER_IDENTITY_UNBOUND",
    ProviderPolicyDebtCode.EXECUTABLE_DIGEST_DRIFT: (
        "EXECUTABLE_DIGEST_DRIFT"
    ),
    ProviderPolicyDebtCode.MODULE_DIGEST_DRIFT: "EXECUTABLE_DIGEST_DRIFT",
    ProviderPolicyDebtCode.DISTRIBUTION_UNPINNED: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
    ProviderPolicyDebtCode.DISTRIBUTION_CHECKSUM_MISMATCH: (
        "EXECUTABLE_DIGEST_DRIFT"
    ),
    ProviderPolicyDebtCode.PARSER_DIGEST_DRIFT: "PARSER_DIGEST_DRIFT",
    ProviderPolicyDebtCode.RAW_SCHEMA_DIGEST_DRIFT: "PARSER_DIGEST_DRIFT",
    ProviderPolicyDebtCode.LICENSE_OR_DISTRIBUTION_RESTRICTED: (
        "LICENSE_OR_DISTRIBUTION_RESTRICTED"
    ),
    ProviderPolicyDebtCode.UNSUPPORTED_OS: "PROVIDER_UNAVAILABLE",
    ProviderPolicyDebtCode.UNSUPPORTED_ARCHITECTURE: "PROVIDER_UNAVAILABLE",
    ProviderPolicyDebtCode.UNSUPPORTED_ECOSYSTEM: (
        "PROVIDER_UNSUPPORTED_ECOSYSTEM"
    ),
    ProviderPolicyDebtCode.UNSUPPORTED_LANGUAGE: "CAPABILITY_PARTIAL",
    ProviderPolicyDebtCode.UNSUPPORTED_TOOLCHAIN: "CAPABILITY_PARTIAL",
    ProviderPolicyDebtCode.UNSUPPORTED_CAPABILITY: "CAPABILITY_PARTIAL",
    ProviderPolicyDebtCode.CAPABILITY_FIDELITY_OVERCLAIM: (
        "CAPABILITY_PARTIAL"
    ),
    ProviderPolicyDebtCode.FALLBACK_POLICY_MISMATCH: "CAPABILITY_PARTIAL",
    ProviderPolicyDebtCode.FALLBACK_PRECISION_BROADENING: (
        "CAPABILITY_PARTIAL"
    ),
    ProviderPolicyDebtCode.RESOURCE_POLICY_BROADENING: "RESOURCE_LIMIT",
    ProviderPolicyDebtCode.ENVIRONMENT_SECRET_FORBIDDEN: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
    ProviderPolicyDebtCode.ENVIRONMENT_POLICY_BROADENING: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
    ProviderPolicyDebtCode.INSTALL_POLICY_DRIFT: (
        "LICENSE_OR_DISTRIBUTION_RESTRICTED"
    ),
    ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
    ProviderPolicyDebtCode.INVOCATION_POLICY_DRIFT: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
    ProviderPolicyDebtCode.CONFIGURATION_BINDING_DRIFT: (
        "BUILD_CONFIGURATION_UNRESOLVED"
    ),
    ProviderPolicyDebtCode.CONTEXT_BINDING_DRIFT: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
    ProviderPolicyDebtCode.SOURCE_AUTHORITY_DRIFT: (
        "SOURCE_CHANGED_DURING_RUN"
    ),
    ProviderPolicyDebtCode.METHODOLOGY_AUTHORITY_DRIFT: (
        "PROVIDER_IDENTITY_UNBOUND"
    ),
}


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _fail(message: str, exc: Exception | None = None) -> None:
    if exc is None:
        raise ProgramFactsProviderRegistryError(message)
    raise ProgramFactsProviderRegistryError(message) from exc


def _exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unknown " + ", ".join(extra))
        _fail(f"{label} has schema drift: {'; '.join(details)}")


def _sorted_unique_strings(values: Any, label: str) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(
        values, (str, bytes, bytearray)
    ):
        _fail(f"{label} must be an array")
    result = tuple(values)
    if any(not isinstance(item, str) or not item for item in result):
        _fail(f"{label} must contain nonempty strings")
    if result != tuple(sorted(result)):
        _fail(f"{label} must be sorted")
    if len(result) != len(set(result)):
        _fail(f"{label} contains a duplicate identity")
    return result


def _hex64(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase 64-hex digest")
    return value


def _portable_identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be nonempty text")
    if "\\" in value or value.startswith(("/", "~")) or re.match(
        r"^[A-Za-z]:", value
    ):
        _fail(f"{label} must not be a host path")
    if "/" in value:
        try:
            validate_portable_path(value)
        except ProgramFactsTypeError as exc:
            _fail(f"{label} is not a portable identity", exc)
    return value


def _is_mutable_pin(value: str) -> bool:
    return (
        not value
        or value == "*"
        or _MUTABLE_PIN_RE.search(value) is not None
        or value.endswith(("@latest", ":latest"))
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


def _validate_authority(value: Mapping[str, Any], provider_id: str) -> None:
    expected = {
        "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
        "terminal_negative_authority": False,
        "can_suppress": False,
        "can_demote": False,
        "can_refute": False,
        "can_mark_examined": False,
        "can_certify_clean": False,
    }
    if dict(value) != expected:
        _fail(f"provider {provider_id} has non-additive authority")


def _validate_provider_row(row: Mapping[str, Any]) -> None:
    _exact_keys(row, _PROVIDER_KEYS, "provider row")
    provider_id = row["provider_id"]
    if not isinstance(provider_id, str) or _ID_RE.fullmatch(provider_id) is None:
        _fail("provider_id is invalid")
    if (
        not isinstance(row["provider_schema_version"], str)
        or _PROVIDER_SCHEMA_RE.fullmatch(row["provider_schema_version"]) is None
    ):
        _fail(f"provider {provider_id} has an invalid provider schema version")
    _validate_authority(row["authority"], provider_id)

    ecosystems = _sorted_unique_strings(
        row["supported_ecosystems"],
        f"provider {provider_id} supported ecosystems",
    )
    languages = _sorted_unique_strings(
        row["supported_languages"],
        f"provider {provider_id} supported languages",
    )
    if not ecosystems or not languages:
        _fail(f"provider {provider_id} has an empty ecosystem/language authority")

    adapter = row["adapter"]
    raw_binding = row["raw_binding"]
    tool = row["tool_identity"]
    distribution = row["distribution"]
    if not isinstance(adapter, Mapping) or not isinstance(raw_binding, Mapping):
        _fail(f"provider {provider_id} has malformed adapter/parser bindings")
    if not isinstance(tool, Mapping) or not isinstance(distribution, Mapping):
        _fail(f"provider {provider_id} has malformed tool/distribution bindings")
    executable_digest = _hex64(
        tool["executable_sha256"],
        f"provider {provider_id} executable digest",
        allow_empty=True,
    )
    module_digest = _hex64(
        tool["module_sha256"],
        f"provider {provider_id} module digest",
        allow_empty=True,
    )
    if not executable_digest and not module_digest:
        _fail(f"provider {provider_id} has no executable or module identity")
    if tool["kind"] == "EXECUTABLE" and not executable_digest:
        _fail(f"provider {provider_id} executable tool lacks an exact digest")
    if tool["kind"] in {"PYTHON_MODULE", "CHECKED_IN_HELPER"} and not module_digest:
        _fail(f"provider {provider_id} module tool lacks an exact digest")
    if tool["module"] and not module_digest:
        _fail(f"provider {provider_id} names an unbound tool module")

    resolution_policy = row["resolution_policy"]
    if resolution_policy not in _RESOLUTION_POLICIES:
        _fail(f"provider {provider_id} has an unsupported resolution policy")
    if distribution["kind"] not in _DISTRIBUTION_KINDS:
        _fail(f"provider {provider_id} has an unsupported distribution kind")
    version = distribution["version"]
    if (
        not isinstance(version, str)
        or _VERSION_RE.fullmatch(version) is None
        or _is_mutable_pin(version)
    ):
        _fail(f"provider {provider_id} distribution version is mutable/unpinned")
    checksum = _hex64(
        distribution["checksum"],
        f"provider {provider_id} distribution checksum",
        allow_empty=True,
    )
    source_digest = _hex64(
        distribution["module_source_digest"],
        f"provider {provider_id} distribution module digest",
        allow_empty=True,
    )
    supply = row["supply_chain_policy"]
    if (
        supply["pinned"] is not True
        or supply["network_during_bake"] is not False
    ):
        _fail(f"provider {provider_id} has mutable/networked bake policy")
    if supply["checksum_required"] is not True:
        _fail(f"provider {provider_id} must require a distribution checksum")
    if not checksum:
        _fail(f"provider {provider_id} has an unbound distribution checksum")
    if resolution_policy == "PINNED_MODULE_SOURCE" and not source_digest:
        _fail(f"provider {provider_id} pinned module lacks a source digest")
    if distribution["name"] != tool["name"]:
        _fail(f"provider {provider_id} tool/distribution name mismatch")

    try:
        version_pattern = re.compile(row["expected_version_syntax"])
    except re.error as exc:
        _fail(f"provider {provider_id} has invalid version syntax", exc)
    if version_pattern.fullmatch(version) is not None:
        _fail(
            f"provider {provider_id} version syntax must bind version output, "
            "not accept a bare mutable observation"
        )
    capabilities = row["capabilities"]
    capability_ids: list[str] = []
    if not capabilities:
        _fail(f"provider {provider_id} has no reviewed capabilities")
    for capability in capabilities:
        capability_id = capability["capability_id"]
        capability_ids.append(capability_id)
        provenance = _sorted_unique_strings(
            capability.get("allowed_provenance_origins"),
            f"capability {capability_id} provenance origins",
        )
        relations = _sorted_unique_strings(
            capability.get("allowed_relation_kinds"),
            f"capability {capability_id} relation kinds",
        )
        if not provenance or not relations:
            _fail(f"capability {capability_id} has empty fidelity authority")
        if capability.get("host_semantic_authority") is not False:
            _fail(f"capability {capability_id} claims host-semantic authority")
    if capability_ids != sorted(capability_ids):
        _fail(f"provider {provider_id} capabilities must be sorted")
    if len(capability_ids) != len(set(capability_ids)):
        _fail(f"provider {provider_id} contains duplicate capability IDs")

    toolchains = row["toolchain_ranges"]
    toolchain_ids = [item["toolchain"] for item in toolchains]
    if toolchain_ids != sorted(toolchain_ids) or len(toolchain_ids) != len(
        set(toolchain_ids)
    ):
        _fail(f"provider {provider_id} toolchain ranges are not sorted/unique")
    if not toolchains:
        _fail(f"provider {provider_id} has no exact toolchain authority")
    for toolchain in toolchains:
        has_fixed_identity = "identity_digest" in toolchain
        has_per_run_identity = (
            toolchain.get("identity_policy") == "RECEIPT_EXACT_PER_RUN"
        )
        if has_fixed_identity == has_per_run_identity:
            _fail(
                f"provider {provider_id} toolchain identity authority is "
                "ambiguous"
            )
        if has_fixed_identity:
            _hex64(
                toolchain["identity_digest"],
                f"provider {provider_id} toolchain identity digest",
            )

    invocation = row["invocation_policy"]
    argv_template = invocation["argv_template"]
    if (
        not isinstance(argv_template, Sequence)
        or isinstance(argv_template, (str, bytes, bytearray))
        or not argv_template
        or any(
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or "\n" in item
            or "\r" in item
            for item in argv_template
        )
    ):
        _fail(f"provider {provider_id} invocation argv template is invalid")
    if argv_template[0] != tool["command"]:
        _fail(f"provider {provider_id} invocation command is not tool-bound")
    substitutions = invocation["typed_substitutions"]
    if not isinstance(substitutions, Sequence) or isinstance(
        substitutions, (str, bytes, bytearray)
    ):
        _fail(f"provider {provider_id} typed substitutions must be an array")
    placeholders: list[str] = []
    for substitution in substitutions:
        placeholder = substitution["placeholder"]
        source = substitution["source"]
        if (
            not isinstance(placeholder, str)
            or _PLACEHOLDER_RE.fullmatch(placeholder) is None
            or source not in _TYPED_SUBSTITUTION_SOURCES
        ):
            _fail(f"provider {provider_id} has an invalid typed substitution")
        placeholders.append(placeholder)
    if placeholders != sorted(placeholders) or len(placeholders) != len(
        set(placeholders)
    ):
        _fail(
            f"provider {provider_id} typed substitutions are not sorted/unique"
        )
    template_placeholders = {
        match.group(0)
        for token in argv_template
        for match in re.finditer(r"\{[A-Z][A-Z0-9_]*\}", token)
    }
    if template_placeholders != set(placeholders):
        _fail(
            f"provider {provider_id} argv template/substitution denominator "
            "mismatch"
        )
    configurations = invocation["configuration_inputs"]
    if not isinstance(configurations, Sequence) or isinstance(
        configurations, (str, bytes, bytearray)
    ):
        _fail(f"provider {provider_id} configuration inputs must be an array")
    configuration_ids: list[str] = []
    for configuration in configurations:
        identity = _portable_identity(
            configuration["identity"],
            f"provider {provider_id} configuration identity",
        )
        _hex64(
            configuration["sha256"],
            f"provider {provider_id} configuration digest",
        )
        configuration_ids.append(identity)
    if configuration_ids != sorted(configuration_ids) or len(
        configuration_ids
    ) != len(set(configuration_ids)):
        _fail(
            f"provider {provider_id} configuration inputs are not "
            "sorted/unique"
        )

    platforms = row["supported_platforms"]
    platform_ids: list[str] = []
    if not platforms:
        _fail(f"provider {provider_id} has no reviewed OS/architecture authority")
    for platform in platforms:
        os_name = platform["os"]
        if os_name not in _PLATFORM_OSES:
            _fail(f"provider {provider_id} has unsupported OS spelling")
        architectures = _sorted_unique_strings(
            platform["architectures"],
            f"provider {provider_id} {os_name} architectures",
        )
        if not architectures or not set(architectures) <= _PLATFORM_ARCHITECTURES:
            _fail(f"provider {provider_id} has unsupported architecture spelling")
        platform_ids.append(os_name)
    if platform_ids != sorted(platform_ids) or len(platform_ids) != len(
        set(platform_ids)
    ):
        _fail(f"provider {provider_id} platforms are not sorted/unique")

    limits = row["limits"]
    for field in ("time_seconds", "memory_bytes", "input_bytes", "output_bytes"):
        value = limits[field]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            _fail(f"provider {provider_id} resource {field} must be positive")

    environment = row["environment_policy"]
    if (
        environment["inheritance"] != "DENY_BY_DEFAULT"
        or environment["allow_secret_values"] is not False
        or environment["value_digest_required"] is not True
    ):
        _fail(f"provider {provider_id} environment is not deny-by-default")
    allowed_names = _sorted_unique_strings(
        environment["allowed_names"],
        f"provider {provider_id} allowed environment",
    )
    required_names = _sorted_unique_strings(
        environment["required_names"],
        f"provider {provider_id} required environment",
    )
    forbidden_names = _sorted_unique_strings(
        environment["forbidden_secret_names"],
        f"provider {provider_id} forbidden environment",
    )
    if any(_ENV_NAME_RE.fullmatch(name) is None for name in allowed_names):
        _fail(f"provider {provider_id} has an invalid environment name")
    if not set(required_names) <= set(allowed_names):
        _fail(f"provider {provider_id} requires an environment name it does not allow")
    if set(allowed_names) & set(forbidden_names):
        _fail(f"provider {provider_id} allows a forbidden secret name")
    if any(_SECRET_NAME_RE.search(name) for name in allowed_names):
        _fail(f"provider {provider_id} allowlists a secret-shaped environment name")

    install = row["install_policy"]
    if (
        install["mode"] not in _INSTALL_MODES
        or install["network_allowed"] is not False
        or install["mutable_reference_allowed"] is not False
    ):
        _fail(f"provider {provider_id} installation policy is not immutable/offline")
    _portable_identity(
        install["lock_identity"],
        f"provider {provider_id} install lock identity",
    )
    _hex64(install["lock_digest"], f"provider {provider_id} install lock digest")
    provenance = row["installation_provenance"]
    if provenance["kind"] not in _INSTALL_PROVENANCE_KINDS:
        _fail(f"provider {provider_id} installation provenance kind is unsupported")
    _portable_identity(
        provenance["source"],
        f"provider {provider_id} installation provenance source",
    )
    provenance_digest = _hex64(
        provenance["digest"],
        f"provider {provider_id} installation provenance digest",
    )
    if (
        install["lock_identity"] != provenance["source"]
        or install["lock_digest"] != provenance_digest
    ):
        _fail(f"provider {provider_id} installation policy/provenance mismatch")
    license_classification = row["license_classification"]
    if (
        not isinstance(license_classification, str)
        or not license_classification
        or license_classification.casefold() in {"unknown", "unreviewed", "latest"}
    ):
        _fail(f"provider {provider_id} has an unreviewed license classification")


def _validate_fallbacks(providers: Sequence[Mapping[str, Any]]) -> None:
    by_id = {row["provider_id"]: row for row in providers}
    for row in providers:
        fallback = row["fallback"]
        if not fallback:
            continue
        provider_id = row["provider_id"]
        fallback_id = fallback["provider_id"]
        target = by_id.get(fallback_id)
        if target is None or fallback_id == provider_id:
            _fail(f"provider {provider_id} has an invalid fallback reference")
        common_ecosystems = set(row["supported_ecosystems"]) & set(
            target["supported_ecosystems"]
        )
        if not common_ecosystems:
            _fail(f"provider {provider_id} fallback has no common ecosystem")
        source_caps = {
            item["capability_id"]: item for item in row["capabilities"]
        }
        target_caps = {
            item["capability_id"]: item for item in target["capabilities"]
        }
        common_capabilities = sorted(set(source_caps) & set(target_caps))
        if not common_capabilities:
            _fail(f"provider {provider_id} fallback has no common capability")
        fallback_rank = _PRECISION_RANK[fallback["maximum_precision"]]
        for capability_id in common_capabilities:
            maximum = min(
                _PRECISION_RANK[source_caps[capability_id]["maximum_precision"]],
                _PRECISION_RANK[target_caps[capability_id]["maximum_precision"]],
            )
            if fallback_rank > maximum:
                _fail(
                    f"provider {provider_id} fallback precision broadens "
                    f"capability {capability_id}"
                )
def validate_closed_program_facts_provider_registry(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate exact Stage-1 registry semantics, not only JSON Schema."""

    if not isinstance(value, Mapping):
        _fail("provider registry must be an object")
    try:
        normalized = validate_program_facts_provider_registry(value)
    except ProgramFactsTypeError as exc:
        _fail(str(exc), exc)
    _exact_keys(normalized, _TOP_LEVEL_KEYS, "provider registry")
    if normalized["schema_version"] != REGISTRY_SCHEMA_VERSION:
        _fail("provider registry schema version drift")
    providers = normalized["providers"]
    if not isinstance(providers, list):
        _fail("provider registry providers must be an array")
    provider_ids = [row["provider_id"] for row in providers]
    if provider_ids != sorted(provider_ids):
        _fail("provider registry rows must be sorted by provider_id")
    if len(provider_ids) != len(set(provider_ids)):
        _fail("provider registry contains duplicate provider IDs")
    release_state = normalized["release_state"]
    expected_state = (
        REVIEWED_PROVIDER_AUTHORITY if providers else NO_PROVIDER_AUTHORITY
    )
    if release_state != expected_state:
        _fail(
            "provider registry release_state does not match its reviewed "
            "provider denominator"
        )
    for row in providers:
        _validate_provider_row(row)
    _validate_fallbacks(providers)
    return normalized


def _validate_installed_methodology_phase_inputs(
    phase_inputs: Mapping[str, bytes],
    *,
    registry_value: Mapping[str, Any],
    registry_bytes: bytes,
    registry_digest: str,
    snapshot_digest: str,
    audit_run_id: str,
) -> None:
    """Replay the exact package/registry/six-schema authority denominator."""

    if tuple(phase_inputs) != PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS:
        _fail("provider registry installed methodology input denominator drift")
    if any(
        type(raw) is not bytes or not raw.endswith(b"\n")
        for raw in phase_inputs.values()
    ):
        _fail("installed methodology inputs must be exact newline-terminated bytes")

    package_identity = PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS[0]
    try:
        package = strict_json_loads(
            phase_inputs[package_identity],
            require_final_lf=True,
            require_canonical=True,
            max_bytes=DEFAULT_MAX_AUTHORITY_BYTES,
        )
    except ProgramFactsTypeError as exc:
        _fail(f"installed methodology package is invalid: {exc}", exc)
    if not isinstance(package, Mapping):
        _fail("installed methodology package must be an object")
    _exact_keys(
        package,
        frozenset(
            {
                "schema_version",
                "authority",
                "audit_snapshot",
                "package_identity",
                "registry",
                "schemas",
                "implementation_sources",
                "terminal_negative_authority",
                "package_sha256",
            }
        ),
        "installed methodology package",
    )
    if (
        package["schema_version"] != METHODOLOGY_PACKAGE_SCHEMA
        or package["authority"] != INSTALLED_METHODOLOGY_AUTHORITY
        or package["terminal_negative_authority"] is not False
    ):
        _fail("installed methodology package authority is invalid")
    supplied_package_digest = _hex64(
        package["package_sha256"], "installed methodology package digest"
    )
    unsigned_package = dict(package)
    del unsigned_package["package_sha256"]
    if (
        hashlib.sha256(canonical_json_bytes(unsigned_package)).hexdigest()
        != supplied_package_digest
    ):
        _fail("installed methodology package self-digest mismatch")

    snapshot = package["audit_snapshot"]
    if not isinstance(snapshot, Mapping):
        _fail("installed methodology package snapshot binding is invalid")
    _exact_keys(
        snapshot,
        frozenset(
            {
                "audit_run_id",
                "snapshot_digest",
                "methodology_component",
                "toolchain_component_digest",
            }
        ),
        "installed methodology package snapshot",
    )
    if (
        snapshot["audit_run_id"] != audit_run_id
        or snapshot["snapshot_digest"] != snapshot_digest
    ):
        _fail("installed methodology package snapshot/run binding mismatch")
    _hex64(snapshot["snapshot_digest"], "installed package snapshot digest")
    _hex64(
        snapshot["toolchain_component_digest"],
        "installed package toolchain digest",
    )
    methodology_component = snapshot["methodology_component"]
    if not isinstance(methodology_component, Mapping):
        _fail("installed methodology component is invalid")
    _exact_keys(
        methodology_component,
        frozenset({"digest", "path_set_digest", "file_count", "byte_count"}),
        "installed methodology component",
    )
    _hex64(methodology_component["digest"], "installed methodology digest")
    _hex64(
        methodology_component["path_set_digest"],
        "installed methodology path-set digest",
    )

    registry_row = package["registry"]
    if not isinstance(registry_row, Mapping):
        _fail("installed methodology registry binding is invalid")
    _exact_keys(
        registry_row,
        frozenset(
            {
                "installed_identity",
                "phase_io_identity",
                "document_sha256",
                "file_sha256",
                "size_bytes",
                "release_state",
            }
        ),
        "installed methodology registry binding",
    )
    registry_phase_identity = PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS[1]
    if (
        registry_row["installed_identity"]
        != "rules/program-facts-provider-registry.v1.json"
        or registry_row["phase_io_identity"] != registry_phase_identity
        or registry_row["document_sha256"] != registry_digest
        or registry_row["file_sha256"]
        != hashlib.sha256(registry_bytes).hexdigest()
        or registry_row["size_bytes"] != len(registry_bytes)
        or registry_row["release_state"] != registry_value["release_state"]
        or phase_inputs[registry_phase_identity] != registry_bytes
    ):
        _fail("installed methodology registry byte binding mismatch")

    expected_schema_identities = PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS[2:]
    schema_rows = package["schemas"]
    if not isinstance(schema_rows, list) or len(schema_rows) != len(
        expected_schema_identities
    ):
        _fail("installed methodology schema denominator mismatch")
    observed_schema_identities: list[str] = []
    for row, phase_identity in zip(
        schema_rows, expected_schema_identities, strict=True
    ):
        if not isinstance(row, Mapping):
            _fail("installed methodology schema binding is not an object")
        _exact_keys(
            row,
            frozenset(
                {
                    "installed_identity",
                    "phase_io_identity",
                    "sha256",
                    "size_bytes",
                }
            ),
            "installed methodology schema binding",
        )
        raw = phase_inputs[phase_identity]
        expected_installed = phase_identity.replace(
            "_program_facts_methodology/schemas/",
            "rules/schemas/",
            1,
        )
        if (
            row["installed_identity"] != expected_installed
            or row["phase_io_identity"] != phase_identity
            or row["sha256"] != hashlib.sha256(raw).hexdigest()
            or row["size_bytes"] != len(raw)
        ):
            _fail("installed methodology schema byte binding mismatch")
        try:
            schema_value = strict_json_loads(
                raw,
                require_final_lf=True,
                require_canonical=False,
                max_bytes=DEFAULT_MAX_AUTHORITY_BYTES,
            )
            if (
                not isinstance(schema_value, Mapping)
                or schema_value.get("$schema")
                != "https://json-schema.org/draft/2020-12/schema"
                or schema_value.get("additionalProperties") is not False
                or not _schema_references_are_local(schema_value)
            ):
                _fail("installed methodology schema is not independently closed")
            Draft202012Validator.check_schema(schema_value)
        except ProgramFactsTypeError as exc:
            _fail(f"installed methodology schema is invalid: {exc}", exc)
        except Exception as exc:
            _fail("installed methodology schema is invalid", exc)
        observed_schema_identities.append(str(row["phase_io_identity"]))
    if tuple(observed_schema_identities) != expected_schema_identities:
        _fail("installed methodology schema order/identity drift")

    package_identity_row = package["package_identity"]
    if not isinstance(package_identity_row, Mapping):
        _fail("installed methodology package identity is invalid")
    _exact_keys(
        package_identity_row,
        frozenset(
            {
                "name",
                "version",
                "version_file_sha256",
                "revision_identity",
            }
        ),
        "installed methodology package identity",
    )
    if package_identity_row["name"] != "plamen":
        _fail("installed methodology package name is invalid")
    if (
        not isinstance(package_identity_row["version"], str)
        or not package_identity_row["version"]
        or "\n" in package_identity_row["version"]
        or "\r" in package_identity_row["version"]
    ):
        _fail("installed methodology package version is invalid")
    _hex64(
        package_identity_row["version_file_sha256"],
        "installed methodology version-file digest",
    )
    _hex64(
        package_identity_row["revision_identity"],
        "installed methodology revision identity",
    )

    sources = package["implementation_sources"]
    if not isinstance(sources, list) or not sources:
        _fail("installed methodology implementation source denominator is empty")
    source_keys: list[tuple[str, str]] = []
    for row in sources:
        if not isinstance(row, Mapping):
            _fail("installed methodology source binding is not an object")
        _exact_keys(
            row,
            frozenset({"role", "identity", "sha256", "size_bytes"}),
            "installed methodology source binding",
        )
        _hex64(row["sha256"], "installed methodology source digest")
        if (
            not isinstance(row["role"], str)
            or not row["role"]
            or not isinstance(row["identity"], str)
            or not row["identity"]
            or isinstance(row["size_bytes"], bool)
            or not isinstance(row["size_bytes"], int)
            or row["size_bytes"] <= 0
        ):
            _fail("installed methodology source binding is malformed")
        source_keys.append((row["role"], row["identity"]))
    if source_keys != sorted(source_keys) or len(source_keys) != len(
        set(source_keys)
    ):
        _fail("installed methodology implementation sources are not exact")
    revision_preimage = {
        "methodology_component_digest": methodology_component["digest"],
        "toolchain_component_digest": snapshot[
            "toolchain_component_digest"
        ],
        "registry_file_sha256": registry_row["file_sha256"],
        "sources": sources,
        "schemas": schema_rows,
        "version_file_sha256": package_identity_row[
            "version_file_sha256"
        ],
    }
    if (
        hashlib.sha256(canonical_json_bytes(revision_preimage)).hexdigest()
        != package_identity_row["revision_identity"]
    ):
        _fail("installed methodology revision identity mismatch")


@dataclass(frozen=True)
class _IssuedRegistry:
    authority_state: str
    snapshot_digest: str
    source_scope_digest: str
    audit_run_id: str
    methodology_capture_digest: str
    methodology_checkpoint_bytes: bytes
    phase_io_input_bytes: tuple[tuple[str, bytes], ...]
    canonical_value_bytes: bytes
    canonical_bytes: bytes
    registry_digest: str
    file_sha256: str
    source_identity: str
    production: bool


def _make_issuance_registry():
    """Issue typed debt/decision carriers, not registry authority.

    Production registry status is replayed from canonical checkpoint and
    installed-methodology bytes by ``LoadedProgramFactsProviderRegistry``.
    """

    lock = threading.RLock()
    debts: weakref.WeakKeyDictionary[object, bytes] = (
        weakref.WeakKeyDictionary()
    )
    decisions: weakref.WeakKeyDictionary[
        object, tuple[bool, bytes]
    ] = weakref.WeakKeyDictionary()
    def new_debt(
        code: ProviderPolicyDebtCode,
        provider_id: str,
        *,
        capability_id: str = "",
        detail: str = "",
    ) -> ProviderPolicyDebt:
        """Issue blocking debt; this closure has no negative-authority mode."""

        debt = ProviderPolicyDebt._create(
            seal=_DEBT_SEAL,
            code=code,
            provider_id=provider_id,
            capability_id=capability_id,
            detail=detail,
        )
        with lock:
            debts[debt] = canonical_json_bytes(debt._unvalidated_dict())
        return debt

    def debt_preimage(value: object) -> bytes | None:
        with lock:
            return debts.get(value)

    def new_decision(
        registry: LoadedProgramFactsProviderRegistry,
        *,
        provider: Mapping[str, Any] | None,
        debts_value: Sequence[ProviderPolicyDebt],
    ) -> ProviderRegistryDecision:
        """Derive readiness from the exact parent registry, never a flag."""

        if type(registry) is not LoadedProgramFactsProviderRegistry:
            _fail("provider decision requires exact loaded registry authority")
        registry._assert_replayable()
        for debt in debts_value:
            debt._assert_valid()
        provider_is_registry_row = bool(
            provider is not None
            and any(
                _thaw(provider) == _thaw(row)
                for row in registry.providers
            )
        )
        if provider is not None and not provider_is_registry_row:
            _fail("provider decision row is outside parent registry authority")
        production_ready = bool(
            registry.production_authority_established
            and provider_is_registry_row
            and not debts_value
        )
        decision = ProviderRegistryDecision._create(
            seal=_DECISION_SEAL,
            registry=registry,
            provider=provider,
            debts=debts_value,
            production_ready=production_ready,
        )
        preimage = canonical_json_bytes(
            {
                "provider": (
                    None if provider is None else _thaw(provider)
                ),
                "debts": [
                    debt._unvalidated_dict() for debt in debts_value
                ],
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

    return (
        new_debt,
        debt_preimage,
        new_decision,
        decision_preimage,
    )


(
    _new_provider_policy_debt,
    _debt_issuance_preimage,
    _registry_decision,
    _registry_decision_issuance_preimage,
) = _make_issuance_registry()


def _record_loaded_registry(
    _value: object,
    _preimage: _IssuedRegistry,
) -> None:
    """Compatibility tombstone: registry recording is never authority."""

    raise TypeError(
        "provider registry issuance is internal; registry recording is "
        "disabled and semantic replay is required"
    )


class ProviderPolicyDebt:
    """Typed non-clean result of a provider policy comparison."""

    __slots__ = (
        "_seal",
        "_issuance_digest",
        "code",
        "provider_id",
        "capability_id",
        "detail",
        "blocks_reuse",
        "terminal_negative_authority",
        "__weakref__",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("ProviderPolicyDebt is validator-issued only")

    @classmethod
    def _create(
        cls,
        *,
        seal: object,
        code: ProviderPolicyDebtCode,
        provider_id: str,
        capability_id: str = "",
        detail: str = "",
    ) -> "ProviderPolicyDebt":
        if seal is not _DEBT_SEAL:
            raise TypeError("ProviderPolicyDebt is validator-issued only")
        if not isinstance(code, ProviderPolicyDebtCode):
            _fail("provider policy debt code must be typed")
        if not isinstance(provider_id, str):
            _fail("provider policy debt provider ID must be text")
        if not isinstance(capability_id, str) or not isinstance(detail, str):
            _fail("provider policy debt fields must be text")
        value = object.__new__(cls)
        object.__setattr__(value, "_seal", seal)
        object.__setattr__(value, "code", code)
        object.__setattr__(value, "provider_id", provider_id)
        object.__setattr__(value, "capability_id", capability_id)
        object.__setattr__(value, "detail", detail)
        # Debt may never be caller-relabeled nonblocking or terminal-negative.
        object.__setattr__(value, "blocks_reuse", True)
        object.__setattr__(value, "terminal_negative_authority", False)
        object.__setattr__(
            value,
            "_issuance_digest",
            value._current_issuance_digest(),
        )
        return value

    def _current_issuance_digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self._unvalidated_dict())
        ).hexdigest()

    def _unvalidated_dict(self) -> dict[str, Any]:
        return {
            "code": (
                self.code.value
                if isinstance(self.code, ProviderPolicyDebtCode)
                else self.code
            ),
            "provider_id": self.provider_id,
            "capability_id": self.capability_id,
            "detail": self.detail,
            "blocks_reuse": self.blocks_reuse,
            "terminal_negative_authority": self.terminal_negative_authority,
        }

    def _assert_valid(self) -> None:
        try:
            issued = _debt_issuance_preimage(self)
            valid = bool(
                type(self) is ProviderPolicyDebt
                and self._seal is _DEBT_SEAL
                and self.blocks_reuse is True
                and self.terminal_negative_authority is False
                and isinstance(self.code, ProviderPolicyDebtCode)
                and isinstance(self.provider_id, str)
                and isinstance(self.capability_id, str)
                and isinstance(self.detail, str)
                and issued is not None
                and issued == canonical_json_bytes(self._unvalidated_dict())
            )
        except (AttributeError, ProgramFactsTypeError, TypeError, ValueError):
            valid = False
        if not valid:
            _fail("provider policy debt authority was forged or mutated")

    @property
    def mechanical_debt_reason(self) -> str:
        self._assert_valid()
        return _MECHANICAL_DEBT_REASON[self.code]

    @property
    def debt_id(self) -> str:
        self._assert_valid()
        return derive_stable_id(
            "PFD",
            {
                "code": self.code.value,
                "provider_id": self.provider_id,
                "capability_id": self.capability_id,
                "detail": self.detail,
                "blocks_reuse": self.blocks_reuse,
                "terminal_negative_authority": self.terminal_negative_authority,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        self._assert_valid()
        return {
            "debt_id": self.debt_id,
            "code": self.code.value,
            "mechanical_debt_reason": self.mechanical_debt_reason,
            "provider_id": self.provider_id,
            "capability_id": self.capability_id,
            "detail": self.detail,
            "blocks_reuse": self.blocks_reuse,
            "terminal_negative_authority": self.terminal_negative_authority,
        }


class ProviderRegistryDecision:
    """A provider row or typed debt; never an implicit clean fallback."""

    __slots__ = (
        "_seal",
        "_production_ready",
        "_issuance_digest",
        "_registry",
        "provider",
        "debts",
        "__weakref__",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("ProviderRegistryDecision is validator-issued only")

    @classmethod
    def _create(
        cls,
        *,
        seal: object,
        registry: LoadedProgramFactsProviderRegistry | None = None,
        provider: Mapping[str, Any] | None,
        debts: Sequence[ProviderPolicyDebt],
        production_ready: bool,
    ) -> "ProviderRegistryDecision":
        if seal is not _DECISION_SEAL:
            raise TypeError("ProviderRegistryDecision is validator-issued only")
        if any(type(debt) is not ProviderPolicyDebt for debt in debts):
            _fail("provider registry decision contains untyped debt")
        value = object.__new__(cls)
        object.__setattr__(value, "_seal", seal)
        object.__setattr__(value, "_production_ready", bool(production_ready))
        object.__setattr__(value, "_registry", registry)
        object.__setattr__(value, "provider", provider)
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
                    "provider": (
                        None
                        if self.provider is None
                        else _thaw(self.provider)
                    ),
                    "debts": [debt.to_dict() for debt in self.debts],
                }
            )
        ).hexdigest()

    def _issuance_valid(self) -> bool:
        try:
            issued = _registry_decision_issuance_preimage(self)
            return bool(
                type(self) is ProviderRegistryDecision
                and self._seal is _DECISION_SEAL
                and isinstance(self._production_ready, bool)
                and all(type(debt) is ProviderPolicyDebt for debt in self.debts)
                and all(
                    (
                        debt._assert_valid() is None
                    )
                    for debt in self.debts
                )
                and issued is not None
                and issued
                == (
                    self._production_ready,
                    canonical_json_bytes(
                        {
                            "provider": (
                                None
                                if self.provider is None
                                else _thaw(self.provider)
                            ),
                            "debts": [
                                debt._unvalidated_dict()
                                for debt in self.debts
                            ],
                        }
                    ),
                )
            )
        except (
            AttributeError,
            ProgramFactsProviderRegistryError,
            ProgramFactsTypeError,
            TypeError,
            ValueError,
        ):
            return False

    @property
    def ready(self) -> bool:
        if not (
            self._issuance_valid()
            and self._production_ready
            and self.provider is not None
            and not self.debts
            and type(self._registry) is LoadedProgramFactsProviderRegistry
        ):
            return False
        try:
            self._registry._assert_replayable()
            return bool(
                self._registry.production_authority_established
                and any(
                    _thaw(self.provider) == _thaw(row)
                    for row in self._registry.providers
                )
            )
        except (
            AttributeError,
            ProgramFactsProviderRegistryError,
            ProgramFactsTypeError,
            TypeError,
            ValueError,
        ):
            return False


class LoadedProgramFactsProviderRegistry(Mapping[str, Any]):
    """Immutable validated registry plus semantic/file byte identities."""

    __hash__ = object.__hash__
    __eq__ = object.__eq__

    __slots__ = (
        "_authority_state",
        "_snapshot_digest",
        "_source_scope_digest",
        "_audit_run_id",
        "_methodology_capture_digest",
        "_methodology_checkpoint_bytes",
        "_phase_io_input_bytes",
        "value",
        "canonical_bytes",
        "registry_digest",
        "file_sha256",
        "source_identity",
        "__weakref__",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError(
            "LoadedProgramFactsProviderRegistry is loader-issued only"
        )

    @classmethod
    def _create(
        cls,
        *,
        authority_state: str,
        snapshot_digest: str,
        source_scope_digest: str,
        audit_run_id: str,
        methodology_capture_digest: str,
        methodology_checkpoint_bytes: bytes,
        phase_io_input_bytes: Mapping[str, bytes],
        value: Mapping[str, Any],
        canonical_bytes: bytes,
        registry_digest: str,
        file_sha256: str,
        source_identity: str,
    ) -> "LoadedProgramFactsProviderRegistry":
        result = object.__new__(cls)
        object.__setattr__(result, "_authority_state", authority_state)
        object.__setattr__(result, "_snapshot_digest", snapshot_digest)
        object.__setattr__(
            result, "_source_scope_digest", source_scope_digest
        )
        object.__setattr__(result, "_audit_run_id", audit_run_id)
        object.__setattr__(
            result,
            "_methodology_capture_digest",
            methodology_capture_digest,
        )
        object.__setattr__(
            result,
            "_methodology_checkpoint_bytes",
            bytes(methodology_checkpoint_bytes),
        )
        object.__setattr__(
            result,
            "_phase_io_input_bytes",
            MappingProxyType(
                {
                    identity: bytes(raw)
                    for identity, raw in phase_io_input_bytes.items()
                }
            ),
        )
        object.__setattr__(result, "value", _freeze(value))
        object.__setattr__(result, "canonical_bytes", bytes(canonical_bytes))
        object.__setattr__(result, "registry_digest", registry_digest)
        object.__setattr__(result, "file_sha256", file_sha256)
        object.__setattr__(result, "source_identity", source_identity)
        return result

    def __getitem__(self, key: str) -> Any:
        return self.value[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.value)

    def __len__(self) -> int:
        return len(self.value)

    @property
    def providers(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.value["providers"])

    @property
    def release_state(self) -> str:
        return str(self.value["release_state"])

    @property
    def production_authority_established(self) -> bool:
        try:
            self._assert_replayable()
        except ProgramFactsProviderRegistryError:
            return False
        return self._authority_state == INSTALLED_PRODUCTION_AUTHORITY

    @property
    def snapshot_digest(self) -> str:
        return self._snapshot_digest

    @property
    def source_scope_digest(self) -> str:
        return self._source_scope_digest

    @property
    def audit_run_id(self) -> str:
        return self._audit_run_id

    @property
    def methodology_capture_digest(self) -> str:
        return self._methodology_capture_digest

    @property
    def phase_io_input_bytes(self) -> Mapping[str, bytes]:
        self._assert_replayable()
        return MappingProxyType(
            {
                identity: bytes(raw)
                for identity, raw in self._phase_io_input_bytes.items()
            }
        )

    def captured_schema_bytes(self, filename: str) -> bytes:
        """Return one production-captured schema, never a live-path reread."""

        self._assert_replayable()
        if self._authority_state != INSTALLED_PRODUCTION_AUTHORITY:
            _fail(
                "captured schema bytes require installed production authority"
            )
        identity = f"_program_facts_methodology/schemas/{filename}"
        if identity not in PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS[2:]:
            _fail("captured schema identity is outside the reviewed denominator")
        raw = self._phase_io_input_bytes.get(identity)
        if type(raw) is not bytes:
            _fail("captured schema bytes are unavailable")
        return bytes(raw)

    def _assert_replayable(self) -> None:
        if type(self) is not LoadedProgramFactsProviderRegistry:
            _fail("provider registry authority type is unsupported")
        try:
            normalized = validate_closed_program_facts_provider_registry(
                self.to_dict()
            )
            current_phase_inputs = MappingProxyType(
                {
                    identity: bytes(raw)
                    for identity, raw in self._phase_io_input_bytes.items()
                }
            )
        except Exception as exc:
            _fail("provider registry replay preimage is unavailable", exc)
        expected_raw = canonical_file_bytes(normalized)
        if (
            expected_raw != self.canonical_bytes
            or hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
            != self.registry_digest
            or hashlib.sha256(self.canonical_bytes).hexdigest()
            != self.file_sha256
        ):
            _fail("provider registry object was mutated after validation")
        _portable_identity(
            self.source_identity, "provider registry source identity"
        )
        if self._authority_state == INSTALLED_PRODUCTION_AUTHORITY:
            if (
                not _HEX64_RE.fullmatch(self._snapshot_digest)
                or not _HEX64_RE.fullmatch(self._source_scope_digest)
                or not isinstance(self._audit_run_id, str)
                or not self._audit_run_id
                or not _HEX64_RE.fullmatch(self._methodology_capture_digest)
                or type(self._methodology_checkpoint_bytes) is not bytes
                or not self._methodology_checkpoint_bytes
                or not isinstance(
                    self._phase_io_input_bytes, MappingProxyType
                )
                or tuple(self._phase_io_input_bytes)
                != PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS
            ):
                _fail("provider registry installed authority binding is invalid")
            registry_identity = (
                "_program_facts_methodology/"
                "program-facts-provider-registry.v1.json"
            )
            if (
                self._phase_io_input_bytes.get(registry_identity)
                != self.canonical_bytes
            ):
                _fail("provider registry PhaseIO bytes were substituted")
            _validate_installed_methodology_phase_inputs(
                current_phase_inputs,
                registry_value=normalized,
                registry_bytes=self.canonical_bytes,
                registry_digest=self.registry_digest,
                snapshot_digest=self._snapshot_digest,
                audit_run_id=self._audit_run_id,
            )
            try:
                (
                    replay_inputs,
                    replay_snapshot_digest,
                    replay_source_scope_digest,
                    replay_audit_run_id,
                    replay_capture_digest,
                ) = replay_installed_program_facts_methodology_capture(
                    self._methodology_checkpoint_bytes
                )
            except ProgramFactsMethodologyAuthorityError as exc:
                _fail("installed methodology parent replay failed", exc)
            if (
                tuple(replay_inputs) != tuple(current_phase_inputs)
                or any(
                    replay_inputs[identity]
                    != current_phase_inputs[identity]
                    for identity in replay_inputs
                )
                or replay_snapshot_digest != self._snapshot_digest
                or replay_source_scope_digest != self._source_scope_digest
                or replay_audit_run_id != self._audit_run_id
                or replay_capture_digest != self._methodology_capture_digest
            ):
                _fail("installed methodology parent capture drift")
            try:
                current = DEFAULT_REGISTRY_PATH.read_bytes()
            except OSError as exc:
                _fail("installed provider registry is unreadable", exc)
            if current != self.canonical_bytes:
                _fail("installed provider registry changed after capture")
        elif self._authority_state == STRUCTURAL_TEST_ONLY:
            if (
                self._snapshot_digest
                or self._source_scope_digest
                or self._audit_run_id
                or self._methodology_capture_digest
                or self._methodology_checkpoint_bytes
                or tuple(current_phase_inputs)
            ):
                _fail(
                    "structural provider registry carries production metadata"
                )
        else:
            _fail("provider registry authority state is unsupported")

    def provider(self, provider_id: str) -> ProviderRegistryDecision:
        self._assert_replayable()
        for row in self.providers:
            if row["provider_id"] == provider_id:
                if self.production_authority_established:
                    return _registry_decision(
                        self,
                        provider=row,
                        debts_value=(),
                    )
                debt = _new_provider_policy_debt(
                    ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY,
                    provider_id,
                    detail=(
                        "arbitrary registry bytes are STRUCTURAL_TEST_ONLY "
                        "and cannot authorize production planning"
                    ),
                )
                return _registry_decision(
                    self,
                    provider=row,
                    debts_value=(debt,),
                )
        debt = _new_provider_policy_debt(
            ProviderPolicyDebtCode.UNKNOWN_PROVIDER,
            provider_id=provider_id,
            detail="provider ID is outside the reviewed closed registry",
        )
        return _registry_decision(
            self,
            provider=None,
            debts_value=(debt,),
        )

    def to_dict(self) -> dict[str, Any]:
        return _thaw(self.value)


def _loaded_registry_issuance_preimage(
    value: object,
) -> _IssuedRegistry | None:
    """Return a computed replay summary, never stored issuance authority."""

    if type(value) is not LoadedProgramFactsProviderRegistry:
        return None
    try:
        value._assert_replayable()
        normalized = validate_closed_program_facts_provider_registry(
            value.to_dict()
        )
        phase_inputs = tuple(
            (identity, bytes(content))
            for identity, content in value._phase_io_input_bytes.items()
        )
        return _IssuedRegistry(
            authority_state=value._authority_state,
            snapshot_digest=value._snapshot_digest,
            source_scope_digest=value._source_scope_digest,
            audit_run_id=value._audit_run_id,
            methodology_capture_digest=value._methodology_capture_digest,
            methodology_checkpoint_bytes=bytes(
                value._methodology_checkpoint_bytes
            ),
            phase_io_input_bytes=phase_inputs,
            canonical_value_bytes=canonical_json_bytes(normalized),
            canonical_bytes=bytes(value.canonical_bytes),
            registry_digest=value.registry_digest,
            file_sha256=value.file_sha256,
            source_identity=value.source_identity,
            production=(
                value._authority_state == INSTALLED_PRODUCTION_AUTHORITY
            ),
        )
    except (
        AttributeError,
        ProgramFactsProviderRegistryError,
        ProgramFactsTypeError,
        TypeError,
        ValueError,
    ):
        return None


def load_program_facts_provider_registry(
    *,
    installed_authority: InstalledMethodologyAuthority,
    expected_registry_digest: str | None = None,
    max_bytes: int = DEFAULT_MAX_REGISTRY_BYTES,
) -> LoadedProgramFactsProviderRegistry:
    """Consume one installed-methodology capture and load its exact registry."""

    if type(installed_authority) is not InstalledMethodologyAuthority:
        _fail("production registry load requires installed methodology authority")
    try:
        (
            phase_inputs,
            snapshot_digest,
            source_scope_digest,
            audit_run_id,
            capture_digest,
            checkpoint_bytes,
        ) = installed_authority._consume_and_replay()
    except ProgramFactsMethodologyAuthorityError as exc:
        _fail(str(exc), exc)
    identity = (
        "_program_facts_methodology/"
        "program-facts-provider-registry.v1.json"
    )
    raw = phase_inputs.get(identity)
    if raw is None:
        _fail("installed methodology capture omitted the provider registry")
    return _load_registry_bytes(
        raw,
        expected_registry_digest=expected_registry_digest,
        max_bytes=max_bytes,
        source_identity="program-facts-provider-registry.v1.json",
        authority_state=INSTALLED_PRODUCTION_AUTHORITY,
        snapshot_digest=snapshot_digest,
        source_scope_digest=source_scope_digest,
        audit_run_id=audit_run_id,
        methodology_capture_digest=capture_digest,
        methodology_checkpoint_bytes=checkpoint_bytes,
        phase_io_input_bytes=phase_inputs,
    )


def load_program_facts_provider_registry_bytes(
    raw: bytes,
    *,
    authority_mode: str,
    expected_registry_digest: str | None = None,
    max_bytes: int = DEFAULT_MAX_REGISTRY_BYTES,
    source_identity: str = "provided-registry-bytes",
) -> LoadedProgramFactsProviderRegistry:
    """Validate fixture bytes with explicit STRUCTURAL_TEST_ONLY authority."""

    if authority_mode != STRUCTURAL_TEST_ONLY:
        _fail(
            "arbitrary registry bytes require explicit STRUCTURAL_TEST_ONLY "
            "authority mode"
        )
    return _load_registry_bytes(
        raw,
        expected_registry_digest=expected_registry_digest,
        max_bytes=max_bytes,
        source_identity=source_identity,
        authority_state=STRUCTURAL_TEST_ONLY,
        snapshot_digest="",
        source_scope_digest="",
        audit_run_id="",
        methodology_capture_digest="",
        methodology_checkpoint_bytes=b"",
        phase_io_input_bytes={},
    )


def _load_registry_bytes(
    raw: bytes,
    *,
    expected_registry_digest: str | None,
    max_bytes: int,
    source_identity: str,
    authority_state: str,
    snapshot_digest: str,
    source_scope_digest: str,
    audit_run_id: str,
    methodology_capture_digest: str,
    methodology_checkpoint_bytes: bytes = b"",
    phase_io_input_bytes: Mapping[str, bytes],
) -> LoadedProgramFactsProviderRegistry:
    """Common exact-byte parser bound to one exact public authority loader."""

    frame = inspect.currentframe()
    caller_code = (
        frame.f_back.f_code
        if frame is not None and frame.f_back is not None
        else None
    )
    del frame
    expected_caller = (
        load_program_facts_provider_registry.__code__
        if authority_state == INSTALLED_PRODUCTION_AUTHORITY
        else load_program_facts_provider_registry_bytes.__code__
        if authority_state == STRUCTURAL_TEST_ONLY
        else None
    )
    if caller_code is not expected_caller:
        _fail("provider registry loading is internal to its authority loader")
    try:
        value = strict_json_loads(
            raw,
            require_final_lf=True,
            require_canonical=True,
            max_bytes=max_bytes,
        )
    except ProgramFactsTypeError as exc:
        _fail(str(exc), exc)
    normalized = validate_closed_program_facts_provider_registry(value)
    registry_digest = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
    if expected_registry_digest is not None:
        expected = expected_registry_digest
        if expected.startswith("sha256:"):
            expected = expected[7:]
        _hex64(expected, "expected registry digest")
        if registry_digest != expected:
            _fail("provider registry digest mismatch")
    loaded = LoadedProgramFactsProviderRegistry._create(
        authority_state=authority_state,
        snapshot_digest=snapshot_digest,
        source_scope_digest=source_scope_digest,
        audit_run_id=audit_run_id,
        methodology_capture_digest=methodology_capture_digest,
        methodology_checkpoint_bytes=methodology_checkpoint_bytes,
        phase_io_input_bytes=phase_io_input_bytes,
        value=_freeze(normalized),
        canonical_bytes=bytes(raw),
        registry_digest=registry_digest,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        source_identity=_portable_identity(
            source_identity, "provider registry source identity"
        ),
    )
    loaded._assert_replayable()
    return loaded


def select_reviewed_provider(
    registry: LoadedProgramFactsProviderRegistry,
    provider_id: str,
) -> ProviderRegistryDecision:
    """Return a reviewed row or typed unknown-provider debt."""

    if type(registry) is not LoadedProgramFactsProviderRegistry:
        _fail("provider selection requires a loaded registry authority")
    registry._assert_replayable()
    return registry.provider(provider_id)


__all__ = [
    "DEFAULT_MAX_REGISTRY_BYTES",
    "DEFAULT_REGISTRY_PATH",
    "LoadedProgramFactsProviderRegistry",
    "NO_PROVIDER_AUTHORITY",
    "ProgramFactsProviderRegistryError",
    "ProviderPolicyDebt",
    "ProviderPolicyDebtCode",
    "ProviderRegistryDecision",
    "REGISTRY_SCHEMA_VERSION",
    "REVIEWED_PROVIDER_AUTHORITY",
    "STRUCTURAL_TEST_ONLY",
    "INSTALLED_PRODUCTION_AUTHORITY",
    "load_program_facts_provider_registry",
    "load_program_facts_provider_registry_bytes",
    "select_reviewed_provider",
    "validate_closed_program_facts_provider_registry",
]
