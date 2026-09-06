"""Pure semantic-v1 backend/model capability policy and preflight receipts.

No function in this module probes a provider, resolves an executable path, or
launches a model.  Callers supply already-observed, redacted facts.  A parsed
``BackendCapabilityReceipt`` is deliberately untrusted: only exact replay
against the frozen policy, launch intent, semantic/resource/tool parents, and
an independently replayed typed provider-observation authority promotes it
to ``BackendCapabilityAuthority``. Evaluation consumes only that authority.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import InitVar, dataclass, field
import hashlib
import re
import threading
from typing import Any, ClassVar, NoReturn
import weakref

from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)


MODEL_POLICY_REGISTRY_SCHEMA = "plamen.model-policy-registry.v1"
BACKEND_CAPABILITY_RECEIPT_SCHEMA = "plamen.backend-capability-receipt.v1"
CAPABILITY_PREFLIGHT_REQUEST_SCHEMA = (
    "plamen.capability-preflight-request.v1"
)
CAPABILITY_PREFLIGHT_DECISION_SCHEMA = (
    "plamen.capability-preflight-decision.v1"
)
BACKEND_LAUNCH_INTENT_SCHEMA = "plamen.backend-launch-intent.v1"
CAPABILITY_REQUEST_AUTHORITY_SCHEMA = (
    "plamen.capability-request-authority.v1"
)
BACKEND_CAPABILITY_AUTHORITY_SCHEMA = (
    "plamen.backend-capability-authority.v2"
)
PAIRED_CAPABILITY_COMPARISON_SCHEMA = (
    "plamen.paired-capability-comparison.v1"
)
PROVIDER_OBSERVATION_RECORD_SCHEMA = (
    "plamen.provider-observation-record.v2"
)
PROVIDER_OBSERVATION_AUTHORITY_SCHEMA = (
    "plamen.provider-observation-authority.v2"
)
CAPABILITY_REQUEST_COMPILER_VERSION = "capability-request-compiler-v1"

BACKENDS = frozenset({"claude", "codex", "native"})
SEMANTIC_MODEL_CAPABILITY_TIERS = frozenset(
    {
        "R3_FRONTIER_REASONING",
        "R2_STANDARD_REASONING",
        "R1_ECONOMY_STRUCTURED",
        "N0_NATIVE_DETERMINISTIC",
    }
)
# User policy caps configurable reasoning at xhigh.  "max" and "ultra" are
# intentionally absent.
REASONING_MODES = frozenset(
    {
        "provider_default_bound",
        "low",
        "medium",
        "high",
        "xhigh",
        "not_applicable",
    }
)
CAPABILITY_STATES = frozenset(
    {
        "SUPPORTED_AND_ENFORCED",
        "SUPPORTED_OBSERVED_ONLY",
        "UNSUPPORTED",
        "UNAVAILABLE_AT_PREFLIGHT",
        "UNKNOWN_BLOCKED",
    }
)
CAPABILITY_NAMES = frozenset(
    {
        "EXACT_MODEL_AVAILABILITY",
        "PROVIDER_PREPARATION_AUTHORITY",
        "CONTEXT_CEILING",
        "OUTPUT_CEILING",
        "REASONING_CONTROL",
        "TOOL_EVENT_OBSERVABILITY",
        "FILESYSTEM_ENFORCEMENT",
        "NETWORK_ENFORCEMENT",
        "MCP_PROVIDER_AVAILABILITY",
        "NATIVE_COMMAND_BROKER",
        "PTY_TRANSPORT",
        "HEADLESS_TRANSPORT",
        "STREAM_USAGE_TELEMETRY",
        "PROCESS_TREE_CONTAINMENT",
        "RESUME_SESSION",
    }
)
SEMANTIC_TOOL_CAPABILITIES = frozenset(
    {
        "SOURCE_READ",
        "SOURCE_SEARCH",
        "METHODOLOGY_READ",
        "ASSIGNED_OUTPUT_WRITE",
        "EXTERNAL_PRECEDENT_QUERY",
        "STATIC_ANALYZER_QUERY",
        "NATIVE_BUILD",
        "NATIVE_TEST",
        "NATIVE_FUZZ",
        "VERSION_PROBE",
    }
)
# Blueprint section 17 codes are retained verbatim.  Capability-specific
# arithmetic codes extend that stable global vocabulary without renaming it.
BLUEPRINT_DEBT_CODES = frozenset(
    {
        "CX_NESTED_CHILD_UNOWNED",
        "CX_MCP_NOT_LOADED",
        "CX_TOOL_POLICY_UNENFORCED",
        "CX_MODEL_DEFAULT_UNKNOWN",
        "CX_MODEL_FALLBACK_MUTATION",
        "CX_REASONING_CONTROL_UNKNOWN",
        "CX_TIMEOUT_MULTIPLIER",
        "CX_SERIAL_FANOUT_DRIFT",
        "CX_PROMPT_TRANSLATION_DRIFT",
        "CX_OUTPUT_PRECREATE_DRIFT",
        "CX_VALIDATOR_RELAXATION",
        "CX_PATH_REWRITE_DRIFT",
        "CX_GENERATED_ADAPTER_UNUSED",
        "MODEL_TIER_UNMATCHED",
        "MCP_PROVIDER_UNMATCHED",
        "NATIVE_TOOLCHAIN_UNMATCHED",
        "PTY_DESCENDANT_CLOSURE_UNPROVEN",
        "PROCESS_CONTAINMENT_PLATFORM_DEBT",
        "CROSS_BACKEND_MIXED_PROVENANCE",
        "LEGACY_IDENTITY_UNRESOLVED",
    }
)
CAPABILITY_SPECIFIC_DEBT_CODES = frozenset(
    {
        "MODEL_EXACT_UNAVAILABLE",
        "MODEL_ID_UNMATCHED",
        "CAPABILITY_UNSUPPORTED",
        "CAPABILITY_OBSERVED_ONLY",
        "CAPABILITY_UNKNOWN",
        "CONTEXT_LIMIT_INSUFFICIENT",
        "OUTPUT_LIMIT_INSUFFICIENT",
        "TOOL_LIMIT_INSUFFICIENT",
        "PROVIDER_ACCOUNT_MODE_UNMATCHED",
        "PROVIDER_PREPARATION_AUTHORITY_MISSING",
    }
)
DEBT_CODES = BLUEPRINT_DEBT_CODES | CAPABILITY_SPECIFIC_DEBT_CODES
OS_FAMILIES = frozenset(
    {"windows", "linux", "wsl2", "macos", "unsupported"}
)
ACCOUNT_MODES = frozenset(
    {
        "SUBSCRIPTION_OAUTH",
        "API_KEY",
        "CLOUD_PROVIDER",
        "CHATGPT_ENTITLEMENT",
        "NATIVE",
        "NONE",
        "UNKNOWN_BLOCKED",
    }
)
PROVIDER_OBSERVATION_SOURCE_CONTRACTS = frozenset(
    {
        "PROVIDER_PREPARATION_PUBLIC_V1",
        "GENERIC_OBSERVATION_AUTHORITY_V1",
    }
)
PROVIDER_PREPARATION_STATES = frozenset(
    {"READY", "NOT_READY", "UNKNOWN_BLOCKED", "NOT_APPLICABLE"}
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,191}$", re.ASCII)
_MODEL_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$", re.ASCII
)
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$", re.ASCII)
_MODEL_ALIASES = frozenset(
    {"auto", "default", "latest", "account-default", "provider-default"}
)
_SENSITIVE_IDENTITY_RE = re.compile(
    r"(?:\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{16,}\b"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=])",
    re.IGNORECASE | re.ASCII,
)
_AUTHORITY_PROMOTION_TOKEN = object()
_DERIVATION_TOKEN = object()
_PROVIDER_LAUNCH_GENERATION_TOKEN = object()
_PROVIDER_PREPARATION_TOKEN = object()
_PROVIDER_OBSERVATION_ROOT_TOKEN = object()
_STRUCTURAL_TEST_BACKEND_TOKEN = object()


class _IdentitySealRegistry:
    """External canonical seals keyed by exact live-object identity."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[
            int, tuple[weakref.ReferenceType[Any], bytes]
        ] = {}

    def issue(self, value: Any, canonical: bytes) -> None:
        if type(canonical) is not bytes:
            raise CapabilityRegistryError(
                "external authority seal must be canonical bytes"
            )
        identity = id(value)

        def retire(reference: weakref.ReferenceType[Any]) -> None:
            with self._lock:
                current = self._entries.get(identity)
                if current is not None and current[0] is reference:
                    self._entries.pop(identity, None)

        reference = weakref.ref(value, retire)
        with self._lock:
            self._entries[identity] = (reference, bytes(canonical))

    def require(
        self,
        value: Any,
        *,
        exact_type: type,
        canonical: bytes,
        label: str,
    ) -> bytes:
        if type(value) is not exact_type:
            raise CapabilityRegistryError(
                f"exact {label} runtime type is required"
            )
        with self._lock:
            current = self._entries.get(id(value))
            if current is None or current[0]() is not value:
                raise CapabilityRegistryError(
                    f"{label} external issuance seal is absent"
                )
            sealed = current[1]
        if type(canonical) is not bytes or canonical != sealed:
            raise CapabilityRegistryError(
                f"{label} external seal/replay drifted"
            )
        return bytes(sealed)


_LAUNCH_INTENT_SEALS = _IdentitySealRegistry()
_LAUNCH_GENERATION_SEALS = _IdentitySealRegistry()
_PREPARATION_AUTHORITY_SEALS = _IdentitySealRegistry()
_OBSERVATION_ROOT_AUTHORITY_SEALS = _IdentitySealRegistry()
_BACKEND_RECEIPT_SEALS = _IdentitySealRegistry()
_PREFLIGHT_REQUEST_SEALS = _IdentitySealRegistry()
_REQUEST_AUTHORITY_SEALS = _IdentitySealRegistry()
_PROVIDER_OBSERVATION_AUTHORITY_SEALS = _IdentitySealRegistry()
_BACKEND_CAPABILITY_AUTHORITY_SEALS = _IdentitySealRegistry()

# Promotion is closed over adapter identities that have an explicit reviewed
# integration contract.  This is capability selection, not an availability
# claim: provider preparation/root authorities must still independently prove
# readiness for the current launch generation.
REVIEWED_ADAPTER_IDENTITIES = frozenset(
    {
        ("codex", "codex-exec-v1", "1.0.0", "codex-cli"),
        ("claude", "claude-exec-v1", "1.0.0", "claude-cli"),
        ("native", "native-command-v1", "1.0.0", "native-runner"),
    }
)

_POLICY_ENTRY_KEYS = frozenset(
    {
        "policy_id",
        "backend",
        "semantic_model_capability_tier",
        "exact_model_id",
        "reasoning_mode",
    }
)
_POLICY_REGISTRY_KEYS = frozenset(
    {"schema", "entries", "registry_digest"}
)
_CAPABILITY_OBSERVATION_KEYS = frozenset(
    {"capability", "state", "evidence_digest", "debt_code"}
)
_TOOL_OBSERVATION_KEYS = frozenset(
    {
        "tool_capability",
        "state",
        "max_calls",
        "evidence_digest",
        "debt_code",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "backend",
        "adapter_id",
        "adapter_version",
        "semantic_model_capability_tier",
        "exact_model_id",
        "reasoning_mode",
        "provider_cli_name",
        "provider_cli_version",
        "executable_sha256",
        "executable_size_bytes",
        "observation_root_digest",
        "os_family",
        "account_mode",
        "context_window_tokens",
        "max_output_tokens",
        "max_tool_calls_total",
        "max_native_commands",
        "max_native_wall_time_seconds",
        "capabilities",
        "tool_capabilities",
        "receipt_digest",
    }
)
_TOOL_REQUIREMENT_KEYS = frozenset(
    {"tool_capability", "required_calls"}
)
_REQUEST_KEYS = frozenset(
    {
        "schema",
        "semantic_model_capability_tier",
        "exact_model_id",
        "reasoning_mode",
        "minimum_context_window_tokens",
        "minimum_output_tokens",
        "maximum_tool_calls_required",
        "minimum_native_commands",
        "minimum_native_wall_time_seconds",
        "required_capabilities",
        "required_tools",
        "request_digest",
    }
)
_LAUNCH_INTENT_KEYS = frozenset(
    {
        "schema",
        "backend",
        "adapter_id",
        "adapter_version",
        "provider_cli_name",
        "provider_cli_version",
        "executable_sha256",
        "executable_size_bytes",
        "os_family",
        "account_mode",
        "transport_capability",
        "launch_intent_digest",
    }
)
_REQUEST_AUTHORITY_KEYS = frozenset(
    {
        "schema",
        "request_digest",
        "model_policy_registry_digest",
        "policy_entry_digest",
        "launch_intent_digest",
        "semantic_requirement_digest",
        "resource_grant_digest",
        "tool_capability_manifest_digest",
        "compiler_version",
        "request_authority_digest",
    }
)
_CAPABILITY_AUTHORITY_KEYS = frozenset(
    {
        "schema",
        "request_digest",
        "request_authority_digest",
        "receipt_digest",
        "launch_intent_digest",
        "model_policy_registry_digest",
        "policy_entry_digest",
        "trusted_observation_root_digest",
        "provider_observation_authority_digest",
        "launch_generation_authority_digest",
        "observation_generation",
        "capability_authority_digest",
    }
)
_PROVIDER_OBSERVATION_RECORD_KEYS = frozenset(
    {
        "schema",
        "source_contract",
        "source_authority_digest",
        "provider_preparation_authority_digest",
        "provider_observation_root_authority_digest",
        "launch_intent_digest",
        "observation_generation",
        "valid_through_generation",
        "preparation_state",
        "context_window_tokens",
        "max_output_tokens",
        "max_tool_calls_total",
        "max_native_commands",
        "max_native_wall_time_seconds",
        "capabilities",
        "tool_capabilities",
        "record_digest",
    }
)
_PROVIDER_OBSERVATION_AUTHORITY_KEYS = frozenset(
    {
        "schema",
        "record_digest",
        "source_authority_digest",
        "provider_preparation_authority_digest",
        "provider_observation_root_authority_digest",
        "launch_intent_digest",
        "observation_generation",
        "valid_through_generation",
        "evaluation_generation",
        "preparation_state",
        "observation_root_digest",
        "provider_observation_authority_digest",
    }
)
_DEBT_KEYS = frozenset(
    {"debt_code", "subject", "observed_state", "evidence_digest"}
)
_DECISION_KEYS = frozenset(
    {
        "schema",
        "request_digest",
        "receipt_digest",
        "capability_authority_digest",
        "eligible",
        "debts",
        "decision_digest",
    }
)
_PAIRED_CAPABILITY_KEYS = frozenset(
    {
        "schema",
        "left_request_digest",
        "right_request_digest",
        "left_receipt_digest",
        "right_receipt_digest",
        "left_decision_digest",
        "right_decision_digest",
        "semantic_requirement_digest",
        "resource_grant_digest",
        "tool_capability_manifest_digest",
        "state",
        "mismatch_fields",
        "comparison_digest",
    }
)


class CapabilityRegistryError(ValueError):
    """Capability policy or observed evidence is open or inconsistent."""

    def __init__(self, message: str, *, debt: Any = None) -> None:
        super().__init__(message)
        self.debt = debt


def _raise_as_registry_error(exc: Exception) -> NoReturn:
    raise CapabilityRegistryError(str(exc)) from exc


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_json_bytes(value)
    except ProgramFactsTypeError as exc:
        _raise_as_registry_error(exc)


def _canonical_file(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_file_bytes(value)
    except ProgramFactsTypeError as exc:
        _raise_as_registry_error(exc)


def _decode_record(raw: bytes) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(raw, require_final_lf=True)
    except ProgramFactsTypeError as exc:
        _raise_as_registry_error(exc)
    if not isinstance(value, Mapping):
        raise CapabilityRegistryError("record must be a JSON object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    if not isinstance(value, Mapping):
        raise CapabilityRegistryError(f"{context} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    reasons: list[str] = []
    if missing:
        reasons.append("missing fields: " + ", ".join(missing))
    if extra:
        reasons.append("unexpected fields: " + ", ".join(extra))
    if reasons:
        raise CapabilityRegistryError(f"{context} " + "; ".join(reasons))


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        raise CapabilityRegistryError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise CapabilityRegistryError(
            f"{field} must be an ASCII identity token"
        )
    if value in {".", ".."}:
        raise CapabilityRegistryError(f"{field} cannot be a path segment")
    if _SENSITIVE_IDENTITY_RE.search(value):
        raise CapabilityRegistryError(
            f"{field} cannot contain credential-like identity material"
        )
    return value


def _model_id(value: Any, field: str = "exact_model_id") -> str:
    if not isinstance(value, str) or _MODEL_ID_RE.fullmatch(value) is None:
        raise CapabilityRegistryError(
            f"{field} must be a canonical exact model/provider identity"
        )
    identity_segments = tuple(
        segment.casefold()
        for namespace in value.split("/")
        for segment in re.split(r"[:@]", namespace)
        if segment
    )
    if value.casefold() in _MODEL_ALIASES or any(
        segment in _MODEL_ALIASES for segment in identity_segments
    ):
        raise CapabilityRegistryError(
            f"{field} cannot be an unresolved model alias"
        )
    if _SENSITIVE_IDENTITY_RE.search(value):
        raise CapabilityRegistryError(
            f"{field} cannot contain credential-like identity material"
        )
    if (
        value.startswith(("/", "."))
        or value.endswith("/")
        or "//" in value
        or any(segment in {".", ".."} for segment in value.split("/"))
    ):
        raise CapabilityRegistryError(
            f"{field} cannot contain path traversal or empty namespaces"
        )
    return value


def _version_token(value: Any, field: str) -> str:
    if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
        raise CapabilityRegistryError(
            f"{field} must be a display-safe canonical version token"
        )
    return value


def _closed(value: Any, allowed: frozenset[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise CapabilityRegistryError(
            f"{field} must be one of {', '.join(sorted(allowed))}"
        )
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise CapabilityRegistryError(f"{field} must be an integer")
    if value < 0:
        raise CapabilityRegistryError(f"{field} must be non-negative")
    return value


def _positive_int(value: Any, field: str) -> int:
    result = _nonnegative_int(value, field)
    if result == 0:
        raise CapabilityRegistryError(f"{field} must be greater than zero")
    return result


def _optional_debt(value: Any, field: str = "debt_code") -> str | None:
    if value is None:
        return None
    return _closed(value, DEBT_CODES, field)


def _validate_state_debt(
    state: str,
    debt_code: str | None,
    context: str,
    *,
    expected_non_enforced_code: str,
) -> None:
    if state == "SUPPORTED_AND_ENFORCED":
        if debt_code is not None:
            raise CapabilityRegistryError(
                f"{context}.debt_code must be null for enforced support"
            )
        return
    if debt_code is None:
        raise CapabilityRegistryError(
            f"{context}.debt_code is required outside enforced support"
        )
    expected = (
        "CAPABILITY_OBSERVED_ONLY"
        if state == "SUPPORTED_OBSERVED_ONLY"
        else (
            "CAPABILITY_UNKNOWN"
            if state == "UNKNOWN_BLOCKED"
            and expected_non_enforced_code
            not in {
                "CX_REASONING_CONTROL_UNKNOWN",
                "CX_TOOL_POLICY_UNENFORCED",
                "PROVIDER_PREPARATION_AUTHORITY_MISSING",
            }
            else expected_non_enforced_code
        )
    )
    if debt_code != expected:
        raise CapabilityRegistryError(
            f"{context}.debt_code must be {expected} for state {state}"
        )


def _capability_debt_code(capability: str) -> str:
    if capability == "EXACT_MODEL_AVAILABILITY":
        return "MODEL_EXACT_UNAVAILABLE"
    if capability == "PROVIDER_PREPARATION_AUTHORITY":
        return "PROVIDER_PREPARATION_AUTHORITY_MISSING"
    if capability == "REASONING_CONTROL":
        return "CX_REASONING_CONTROL_UNKNOWN"
    if capability in {
        "TOOL_EVENT_OBSERVABILITY",
        "FILESYSTEM_ENFORCEMENT",
        "NETWORK_ENFORCEMENT",
    }:
        return "CX_TOOL_POLICY_UNENFORCED"
    if capability == "MCP_PROVIDER_AVAILABILITY":
        return "CX_MCP_NOT_LOADED"
    if capability == "NATIVE_COMMAND_BROKER":
        return "NATIVE_TOOLCHAIN_UNMATCHED"
    if capability == "PROCESS_TREE_CONTAINMENT":
        return "PROCESS_CONTAINMENT_PLATFORM_DEBT"
    return "CAPABILITY_UNSUPPORTED"


def _mapping_array(value: Any, field: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise CapabilityRegistryError(f"{field} must be a JSON array")
    result = tuple(value)
    if not all(isinstance(item, Mapping) for item in result):
        raise CapabilityRegistryError(
            f"{field} entries must be JSON objects"
        )
    return result


@dataclass(frozen=True, slots=True)
class ModelPolicyEntry:
    """One configurable tier-to-exact-model mapping without availability."""

    policy_id: str
    backend: str
    semantic_model_capability_tier: str
    exact_model_id: str
    reasoning_mode: str

    def __post_init__(self) -> None:
        if type(self) is not ModelPolicyEntry:
            raise CapabilityRegistryError(
                "ModelPolicyEntry cannot be subclass-minted"
            )
        _safe_id(self.policy_id, "policy_id")
        backend = _closed(self.backend, BACKENDS, "backend")
        tier = _closed(
            self.semantic_model_capability_tier,
            SEMANTIC_MODEL_CAPABILITY_TIERS,
            "semantic_model_capability_tier",
        )
        _model_id(self.exact_model_id)
        reasoning = _closed(
            self.reasoning_mode, REASONING_MODES, "reasoning_mode"
        )
        if backend == "native":
            if tier != "N0_NATIVE_DETERMINISTIC":
                raise CapabilityRegistryError(
                    "native policy requires N0_NATIVE_DETERMINISTIC"
                )
            if reasoning != "not_applicable":
                raise CapabilityRegistryError(
                    "native policy reasoning_mode must be not_applicable"
                )
        elif tier == "N0_NATIVE_DETERMINISTIC":
            raise CapabilityRegistryError(
                "model backend cannot map N0_NATIVE_DETERMINISTIC"
            )
        elif reasoning == "not_applicable":
            raise CapabilityRegistryError(
                "model policy reasoning_mode cannot be not_applicable"
            )

    @property
    def policy_entry_digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "backend": self.backend,
            "semantic_model_capability_tier": (
                self.semantic_model_capability_tier
            ),
            "exact_model_id": self.exact_model_id,
            "reasoning_mode": self.reasoning_mode,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelPolicyEntry":
        if cls is not ModelPolicyEntry:
            raise CapabilityRegistryError(
                "ModelPolicyEntry replay requires exact base class"
            )
        _require_exact_keys(value, _POLICY_ENTRY_KEYS, "model policy entry")
        return ModelPolicyEntry(
            policy_id=value["policy_id"],
            backend=value["backend"],
            semantic_model_capability_tier=value[
                "semantic_model_capability_tier"
            ],
            exact_model_id=value["exact_model_id"],
            reasoning_mode=value["reasoning_mode"],
        )


@dataclass(frozen=True, slots=True)
class ModelPolicyRegistry:
    """Closed deterministic model mapping selected after semantic tier."""

    entries: tuple[ModelPolicyEntry, ...]

    schema: ClassVar[str] = MODEL_POLICY_REGISTRY_SCHEMA

    def __post_init__(self) -> None:
        if type(self) is not ModelPolicyRegistry:
            raise CapabilityRegistryError(
                "ModelPolicyRegistry cannot be subclass-minted"
            )
        entries = tuple(
            sorted(
                self.entries,
                key=lambda row: (
                    row.semantic_model_capability_tier,
                    row.backend,
                    row.policy_id,
                ),
            )
        )
        if not entries:
            raise CapabilityRegistryError(
                "model policy registry must contain entries"
            )
        if not all(type(row) is ModelPolicyEntry for row in entries):
            raise CapabilityRegistryError(
                "model policy entries must be ModelPolicyEntry records"
            )
        keys = tuple(
            (row.semantic_model_capability_tier, row.backend)
            for row in entries
        )
        if len(keys) != len(set(keys)):
            raise CapabilityRegistryError(
                "model policy registry has ambiguous tier/backend mappings"
            )
        policy_ids = tuple(row.policy_id for row in entries)
        if len(policy_ids) != len(set(policy_ids)):
            raise CapabilityRegistryError(
                "model policy registry has duplicate policy_id"
            )
        object.__setattr__(self, "entries", entries)

    @classmethod
    def create(
        cls, entries: Iterable[ModelPolicyEntry]
    ) -> "ModelPolicyRegistry":
        if cls is not ModelPolicyRegistry:
            raise CapabilityRegistryError(
                "ModelPolicyRegistry factory requires exact base class"
            )
        return ModelPolicyRegistry(tuple(entries))

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "entries": [row.to_dict() for row in self.entries],
        }

    @property
    def registry_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "registry_digest": self.registry_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelPolicyRegistry":
        if cls is not ModelPolicyRegistry:
            raise CapabilityRegistryError(
                "ModelPolicyRegistry replay requires exact base class"
            )
        _require_exact_keys(value, _POLICY_REGISTRY_KEYS, "model policy registry")
        if value["schema"] != MODEL_POLICY_REGISTRY_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported model policy registry schema"
            )
        claimed = _sha256(value["registry_digest"], "registry_digest")
        registry = ModelPolicyRegistry.create(
            ModelPolicyEntry.from_dict(row)
            for row in _mapping_array(value["entries"], "entries")
        )
        if claimed != registry.registry_digest:
            raise CapabilityRegistryError("registry_digest digest mismatch")
        return registry

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ModelPolicyRegistry":
        if cls is not ModelPolicyRegistry:
            raise CapabilityRegistryError(
                "ModelPolicyRegistry replay requires exact base class"
            )
        return ModelPolicyRegistry.from_dict(_decode_record(raw))

    def resolve(
        self,
        *,
        semantic_model_capability_tier: str,
        backend: str,
        required_exact_model_id: str | None = None,
    ) -> ModelPolicyEntry:
        tier = _closed(
            semantic_model_capability_tier,
            SEMANTIC_MODEL_CAPABILITY_TIERS,
            "semantic_model_capability_tier",
        )
        backend_n = _closed(backend, BACKENDS, "backend")
        matches = tuple(
            row
            for row in self.entries
            if row.semantic_model_capability_tier == tier
            and row.backend == backend_n
        )
        if len(matches) != 1:
            raise CapabilityRegistryError(
                "no exact model policy mapping for semantic tier/backend"
            )
        result = matches[0]
        if required_exact_model_id is not None:
            required = _model_id(
                required_exact_model_id, "required_exact_model_id"
            )
            if required != result.exact_model_id:
                raise CapabilityRegistryError(
                    "required exact model does not match configured policy; "
                    "silent aliases and fallbacks are forbidden"
                )
        return result


@dataclass(frozen=True, slots=True, weakref_slot=True)
class BackendLaunchIntent:
    """Trusted, frozen arm intent; contains no executable path or secret."""

    backend: str
    adapter_id: str
    adapter_version: str
    provider_cli_name: str
    provider_cli_version: str
    executable_sha256: str
    executable_size_bytes: int
    os_family: str
    account_mode: str
    transport_capability: str

    schema: ClassVar[str] = BACKEND_LAUNCH_INTENT_SCHEMA

    def __post_init__(self) -> None:
        if type(self) is not BackendLaunchIntent:
            raise CapabilityRegistryError(
                "BackendLaunchIntent cannot be subclass-minted"
            )
        backend = _closed(self.backend, BACKENDS, "backend")
        _safe_id(self.adapter_id, "adapter_id")
        _version_token(self.adapter_version, "adapter_version")
        _safe_id(self.provider_cli_name, "provider_cli_name")
        _version_token(self.provider_cli_version, "provider_cli_version")
        _sha256(self.executable_sha256, "executable_sha256")
        _positive_int(self.executable_size_bytes, "executable_size_bytes")
        _closed(self.os_family, OS_FAMILIES, "os_family")
        account = _closed(self.account_mode, ACCOUNT_MODES, "account_mode")
        transport = _closed(
            self.transport_capability,
            frozenset({"PTY_TRANSPORT", "HEADLESS_TRANSPORT"}),
            "transport_capability",
        )
        if backend == "native":
            if account != "NATIVE":
                raise CapabilityRegistryError(
                    "native launch intent requires NATIVE account mode"
                )
            if transport != "HEADLESS_TRANSPORT":
                raise CapabilityRegistryError(
                    "native launch intent requires headless transport"
                )
        elif account in {"NATIVE", "NONE", "UNKNOWN_BLOCKED"}:
            raise CapabilityRegistryError(
                "model launch intent requires an explicit provider account"
            )
        _LAUNCH_INTENT_SEALS.issue(self, self.to_bytes())

    def require_exact_replay(self) -> bytes:
        return _LAUNCH_INTENT_SEALS.require(
            self,
            exact_type=BackendLaunchIntent,
            canonical=self.to_bytes(),
            label="BackendLaunchIntent",
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "backend": self.backend,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_cli_name": self.provider_cli_name,
            "provider_cli_version": self.provider_cli_version,
            "executable_sha256": self.executable_sha256,
            "executable_size_bytes": self.executable_size_bytes,
            "os_family": self.os_family,
            "account_mode": self.account_mode,
            "transport_capability": self.transport_capability,
        }

    @property
    def launch_intent_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "launch_intent_digest": self.launch_intent_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BackendLaunchIntent":
        if cls is not BackendLaunchIntent:
            raise CapabilityRegistryError(
                "BackendLaunchIntent replay requires exact base class"
            )
        _require_exact_keys(value, _LAUNCH_INTENT_KEYS, "backend launch intent")
        if value["schema"] != BACKEND_LAUNCH_INTENT_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported backend launch intent schema"
            )
        claimed = _sha256(
            value["launch_intent_digest"], "launch_intent_digest"
        )
        intent = cls(
            backend=value["backend"],
            adapter_id=value["adapter_id"],
            adapter_version=value["adapter_version"],
            provider_cli_name=value["provider_cli_name"],
            provider_cli_version=value["provider_cli_version"],
            executable_sha256=value["executable_sha256"],
            executable_size_bytes=value["executable_size_bytes"],
            os_family=value["os_family"],
            account_mode=value["account_mode"],
            transport_capability=value["transport_capability"],
        )
        if claimed != intent.launch_intent_digest:
            raise CapabilityRegistryError("launch_intent_digest mismatch")
        return intent

    @classmethod
    def from_bytes(cls, raw: bytes) -> "BackendLaunchIntent":
        if cls is not BackendLaunchIntent:
            raise CapabilityRegistryError(
                "BackendLaunchIntent replay requires exact base class"
            )
        return cls.from_dict(_decode_record(raw))


@dataclass(frozen=True, slots=True)
class CapabilityObservation:
    """One exact platform/model/transport capability observation."""

    capability: str
    state: str
    evidence_digest: str
    debt_code: str | None

    def __post_init__(self) -> None:
        _closed(self.capability, CAPABILITY_NAMES, "capability")
        state = _closed(self.state, CAPABILITY_STATES, "state")
        _sha256(self.evidence_digest, "evidence_digest")
        debt = _optional_debt(self.debt_code)
        _validate_state_debt(
            state,
            debt,
            "capability observation",
            expected_non_enforced_code=_capability_debt_code(
                self.capability
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "state": self.state,
            "evidence_digest": self.evidence_digest,
            "debt_code": self.debt_code,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityObservation":
        _require_exact_keys(
            value, _CAPABILITY_OBSERVATION_KEYS, "capability observation"
        )
        return cls(
            capability=value["capability"],
            state=value["state"],
            evidence_digest=value["evidence_digest"],
            debt_code=value["debt_code"],
        )


@dataclass(frozen=True, slots=True)
class ToolCapabilityObservation:
    """One semantic tool capability and its observed call ceiling."""

    tool_capability: str
    state: str
    max_calls: int
    evidence_digest: str
    debt_code: str | None

    def __post_init__(self) -> None:
        _closed(
            self.tool_capability,
            SEMANTIC_TOOL_CAPABILITIES,
            "tool_capability",
        )
        state = _closed(self.state, CAPABILITY_STATES, "state")
        _nonnegative_int(self.max_calls, "max_calls")
        _sha256(self.evidence_digest, "evidence_digest")
        debt = _optional_debt(self.debt_code)
        _validate_state_debt(
            state,
            debt,
            "tool capability observation",
            expected_non_enforced_code="CX_TOOL_POLICY_UNENFORCED",
        )
        if state in {
            "UNSUPPORTED",
            "UNAVAILABLE_AT_PREFLIGHT",
            "UNKNOWN_BLOCKED",
        } and self.max_calls != 0:
            raise CapabilityRegistryError(
                "unsupported or unknown tool max_calls must be zero"
            )
        if state in {
            "SUPPORTED_AND_ENFORCED",
            "SUPPORTED_OBSERVED_ONLY",
        } and self.max_calls == 0:
            raise CapabilityRegistryError(
                "supported tool max_calls must be positive"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_capability": self.tool_capability,
            "state": self.state,
            "max_calls": self.max_calls,
            "evidence_digest": self.evidence_digest,
            "debt_code": self.debt_code,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "ToolCapabilityObservation":
        _require_exact_keys(
            value, _TOOL_OBSERVATION_KEYS, "tool capability observation"
        )
        return cls(
            tool_capability=value["tool_capability"],
            state=value["state"],
            max_calls=value["max_calls"],
            evidence_digest=value["evidence_digest"],
            debt_code=value["debt_code"],
        )


def _coerce_capabilities(
    values: Iterable[CapabilityObservation],
) -> tuple[CapabilityObservation, ...]:
    try:
        result = tuple(sorted(values, key=lambda row: row.capability))
    except (TypeError, AttributeError) as exc:
        raise CapabilityRegistryError(
            "capabilities must contain CapabilityObservation records"
        ) from exc
    if not all(type(row) is CapabilityObservation for row in result):
        raise CapabilityRegistryError(
            "capabilities must contain CapabilityObservation records"
        )
    names = tuple(row.capability for row in result)
    if len(names) != len(set(names)):
        raise CapabilityRegistryError("capabilities contains duplicates")
    if set(names) != CAPABILITY_NAMES:
        missing = sorted(CAPABILITY_NAMES - set(names))
        extra = sorted(set(names) - CAPABILITY_NAMES)
        raise CapabilityRegistryError(
            "capabilities must contain the exact observation denominator; "
            f"missing={missing}, extra={extra}"
        )
    return result


def _coerce_tools(
    values: Iterable[ToolCapabilityObservation],
) -> tuple[ToolCapabilityObservation, ...]:
    try:
        result = tuple(sorted(values, key=lambda row: row.tool_capability))
    except (TypeError, AttributeError) as exc:
        raise CapabilityRegistryError(
            "tool_capabilities must contain ToolCapabilityObservation records"
        ) from exc
    if not all(type(row) is ToolCapabilityObservation for row in result):
        raise CapabilityRegistryError(
            "tool_capabilities must contain ToolCapabilityObservation records"
        )
    names = tuple(row.tool_capability for row in result)
    if len(names) != len(set(names)):
        raise CapabilityRegistryError("tool_capabilities contains duplicates")
    return result


def _coerce_provider_observed_capabilities(
    values: Iterable[CapabilityObservation],
) -> tuple[CapabilityObservation, ...]:
    result = _coerce_capabilities(
        tuple(values)
        + (
            CapabilityObservation(
                capability="PROVIDER_PREPARATION_AUTHORITY",
                state="UNKNOWN_BLOCKED",
                evidence_digest="0" * 64,
                debt_code="PROVIDER_PREPARATION_AUTHORITY_MISSING",
            ),
        )
    )
    return tuple(
        row
        for row in result
        if row.capability != "PROVIDER_PREPARATION_AUTHORITY"
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ProviderLaunchGenerationAuthority:
    """Opaque run/generation root for one exact backend launch intent."""

    run_id: str
    semantic_work_unit_key: str
    semantic_generation: int
    global_reservation_digest: str
    launch_intent_digest: str
    resource_authority_class: str
    _promotion_token: InitVar[object] = None
    _seal: str = field(init=False, repr=False, compare=False)

    def __post_init__(self, _promotion_token: object) -> None:
        if type(self) is not ProviderLaunchGenerationAuthority:
            raise CapabilityRegistryError(
                "ProviderLaunchGenerationAuthority cannot be subclass-minted"
            )
        if _promotion_token is not _PROVIDER_LAUNCH_GENERATION_TOKEN:
            raise CapabilityRegistryError(
                "provider launch generation authority is opaque"
            )
        _safe_id(self.run_id, "run_id")
        _sha256(self.semantic_work_unit_key, "semantic_work_unit_key")
        _positive_int(self.semantic_generation, "semantic_generation")
        _sha256(
            self.global_reservation_digest,
            "global_reservation_digest",
        )
        _sha256(self.launch_intent_digest, "launch_intent_digest")
        _closed(
            self.resource_authority_class,
            frozenset(
                {
                    "PRODUCTION_RESOURCE_AUTHORIZED",
                    "STRUCTURAL_TEST_ONLY",
                }
            ),
            "resource_authority_class",
        )
        object.__setattr__(
            self,
            "_seal",
            self.launch_generation_authority_digest,
        )
        _LAUNCH_GENERATION_SEALS.issue(
            self,
            self.launch_generation_authority_digest.encode("ascii"),
        )

    @property
    def launch_generation_authority_digest(self) -> str:
        return _digest(
            {
                "schema": "plamen.provider-launch-generation-authority.v1",
                "run_id": self.run_id,
                "semantic_work_unit_key": self.semantic_work_unit_key,
                "semantic_generation": self.semantic_generation,
                "global_reservation_digest": (
                    self.global_reservation_digest
                ),
                "launch_intent_digest": self.launch_intent_digest,
                "resource_authority_class": self.resource_authority_class,
            }
        )

    def require_exact_replay(self) -> None:
        if self._seal != self.launch_generation_authority_digest:
            raise CapabilityRegistryError(
                "provider launch-generation authority seal drifted"
            )
        _LAUNCH_GENERATION_SEALS.require(
            self,
            exact_type=ProviderLaunchGenerationAuthority,
            canonical=self.launch_generation_authority_digest.encode("ascii"),
            label="provider launch-generation authority",
        )


def _bind_provider_launch_generation_authority(
    *,
    semantic_work_plan: Any,
    global_reservation: Any,
    launch_intent: BackendLaunchIntent,
    _structural_test_token: object = None,
) -> ProviderLaunchGenerationAuthority:
    """Bind a launch generation to exact semantic/reservation parents."""

    # Local imports avoid the resource-policy module's vocabulary import from
    # this module while preserving exact runtime type checks.
    from resource_policy_authority import GlobalResourceReservation
    from semantic_work_plan import SemanticWorkPlan

    if type(semantic_work_plan) is not SemanticWorkPlan:
        raise CapabilityRegistryError(
            "exact typed SemanticWorkPlan is required for launch generation"
        )
    if type(global_reservation) is not GlobalResourceReservation:
        raise CapabilityRegistryError(
            "exact typed global reservation is required for launch generation"
        )
    if type(launch_intent) is not BackendLaunchIntent:
        raise CapabilityRegistryError(
            "exact typed launch intent is required for launch generation"
        )
    try:
        replayed_plan = SemanticWorkPlan.from_bytes(
            semantic_work_plan.to_bytes()
        )
        if _structural_test_token is _STRUCTURAL_TEST_BACKEND_TOKEN:
            if global_reservation.reservation_budget_authority_class != (
                "STRUCTURAL_TEST_ONLY"
            ):
                raise ValueError(
                    "structural launch requires structural reservation"
                )
            resource_authority_class = "STRUCTURAL_TEST_ONLY"
        else:
            global_reservation.require_production_budget_authority()
            resource_authority_class = (
                "PRODUCTION_RESOURCE_AUTHORIZED"
            )
        replayed_reservation = global_reservation.replay()
        global_reservation.allocation_for(
            semantic_work_plan.semantic_work_unit_id
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise CapabilityRegistryError(
            "provider launch generation parents do not exactly replay",
            debt=getattr(exc, "debt", None),
        ) from exc
    if (
        replayed_plan != semantic_work_plan
        or replayed_reservation != global_reservation
        or semantic_work_plan.run_id != global_reservation.run_id
        or semantic_work_plan.semantic_generation
        != global_reservation.generation
    ):
        raise CapabilityRegistryError(
            "provider launch generation does not bind run/reservation"
        )
    return ProviderLaunchGenerationAuthority(
        run_id=semantic_work_plan.run_id,
        semantic_work_unit_key=semantic_work_plan.semantic_work_unit_key,
        semantic_generation=semantic_work_plan.semantic_generation,
        global_reservation_digest=global_reservation.reservation_digest,
        launch_intent_digest=launch_intent.launch_intent_digest,
        resource_authority_class=resource_authority_class,
        _promotion_token=_PROVIDER_LAUNCH_GENERATION_TOKEN,
    )


def bind_provider_launch_generation_authority(
    *,
    semantic_work_plan: Any,
    global_reservation: Any,
    launch_intent: BackendLaunchIntent,
) -> ProviderLaunchGenerationAuthority:
    """Production launch binding; structural reservation fails closed."""

    return _bind_provider_launch_generation_authority(
        semantic_work_plan=semantic_work_plan,
        global_reservation=global_reservation,
        launch_intent=launch_intent,
    )


def bind_structural_test_provider_launch_generation_authority(
    *,
    semantic_work_plan: Any,
    global_reservation: Any,
    launch_intent: BackendLaunchIntent,
) -> ProviderLaunchGenerationAuthority:
    """Explicit test-only launch binding for structural fixtures."""

    return _bind_provider_launch_generation_authority(
        semantic_work_plan=semantic_work_plan,
        global_reservation=global_reservation,
        launch_intent=launch_intent,
        _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ProviderPreparationAuthority:
    """Opaque readiness parent rooted in provider preparation and generation."""

    source_contract: str
    source_authority_digest: str
    launch_intent_digest: str
    launch_generation_authority_digest: str
    prepared_exact_model_id: str | None
    observation_generation: int
    valid_through_generation: int
    preparation_state: str
    _promotion_token: InitVar[object] = None
    _seal: str = field(init=False, repr=False, compare=False)

    def __post_init__(self, _promotion_token: object) -> None:
        if type(self) is not ProviderPreparationAuthority:
            raise CapabilityRegistryError(
                "ProviderPreparationAuthority cannot be subclass-minted"
            )
        if _promotion_token is not _PROVIDER_PREPARATION_TOKEN:
            raise CapabilityRegistryError(
                "provider preparation authority is opaque"
            )
        source_contract = _closed(
            self.source_contract,
            PROVIDER_OBSERVATION_SOURCE_CONTRACTS,
            "source_contract",
        )
        _sha256(self.source_authority_digest, "source_authority_digest")
        _sha256(self.launch_intent_digest, "launch_intent_digest")
        _sha256(
            self.launch_generation_authority_digest,
            "launch_generation_authority_digest",
        )
        generation = _positive_int(
            self.observation_generation, "observation_generation"
        )
        valid_through = _positive_int(
            self.valid_through_generation, "valid_through_generation"
        )
        if valid_through < generation:
            raise CapabilityRegistryError(
                "provider preparation validity precedes observation"
            )
        state = _closed(
            self.preparation_state,
            PROVIDER_PREPARATION_STATES,
            "preparation_state",
        )
        if self.prepared_exact_model_id is not None:
            _model_id(
                self.prepared_exact_model_id,
                "prepared_exact_model_id",
            )
        if state == "READY" and (
            source_contract != "PROVIDER_PREPARATION_PUBLIC_V1"
            or self.prepared_exact_model_id is None
        ):
            raise CapabilityRegistryError(
                "provider READY requires replayed preparation and exact model"
            )
        if source_contract == "GENERIC_OBSERVATION_AUTHORITY_V1" and (
            state not in {"UNKNOWN_BLOCKED", "NOT_APPLICABLE"}
            or self.prepared_exact_model_id is not None
        ):
            raise CapabilityRegistryError(
                "generic preparation authority cannot assert readiness"
            )
        object.__setattr__(
            self,
            "_seal",
            self.provider_preparation_authority_digest,
        )
        _PREPARATION_AUTHORITY_SEALS.issue(
            self,
            self.provider_preparation_authority_digest.encode("ascii"),
        )

    @property
    def provider_preparation_authority_digest(self) -> str:
        return _digest(
            {
                "schema": "plamen.provider-preparation-authority.v1",
                "source_contract": self.source_contract,
                "source_authority_digest": self.source_authority_digest,
                "launch_intent_digest": self.launch_intent_digest,
                "launch_generation_authority_digest": (
                    self.launch_generation_authority_digest
                ),
                "prepared_exact_model_id": self.prepared_exact_model_id,
                "observation_generation": self.observation_generation,
                "valid_through_generation": self.valid_through_generation,
                "preparation_state": self.preparation_state,
            }
        )

    def require_exact_replay(self) -> None:
        if (
            type(self) is not ProviderPreparationAuthority
            or self._seal != self.provider_preparation_authority_digest
        ):
            raise CapabilityRegistryError(
                "provider preparation authority seal drifted"
            )
        _PREPARATION_AUTHORITY_SEALS.require(
            self,
            exact_type=ProviderPreparationAuthority,
            canonical=(
                self.provider_preparation_authority_digest.encode("ascii")
            ),
            label="provider preparation authority",
        )


def bind_unavailable_provider_preparation_authority(
    *,
    launch_generation_authority: ProviderLaunchGenerationAuthority,
    launch_intent: BackendLaunchIntent,
    preparation_state: str,
) -> ProviderPreparationAuthority:
    """Create only fail-closed UNKNOWN/NA state for an unimplemented adapter."""

    if type(launch_generation_authority) is not (
        ProviderLaunchGenerationAuthority
    ):
        raise CapabilityRegistryError(
            "opaque provider launch-generation authority is required"
        )
    launch_generation_authority.require_exact_replay()
    if type(launch_intent) is not BackendLaunchIntent:
        raise CapabilityRegistryError("exact launch intent is required")
    state = _closed(
        preparation_state,
        frozenset({"UNKNOWN_BLOCKED", "NOT_APPLICABLE"}),
        "preparation_state",
    )
    if (
        launch_generation_authority.launch_intent_digest
        != launch_intent.launch_intent_digest
    ):
        raise CapabilityRegistryError(
            "launch-generation/intent authority mismatch"
        )
    root_digest = _digest(
        {
            "schema": "plamen.unavailable-provider-preparation-root.v1",
            "launch_generation_authority_digest": (
                launch_generation_authority
                .launch_generation_authority_digest
            ),
            "preparation_state": state,
        }
    )
    generation = launch_generation_authority.semantic_generation
    return ProviderPreparationAuthority(
        source_contract="GENERIC_OBSERVATION_AUTHORITY_V1",
        source_authority_digest=root_digest,
        launch_intent_digest=launch_intent.launch_intent_digest,
        launch_generation_authority_digest=(
            launch_generation_authority.launch_generation_authority_digest
        ),
        prepared_exact_model_id=None,
        observation_generation=generation,
        valid_through_generation=generation,
        preparation_state=state,
        _promotion_token=_PROVIDER_PREPARATION_TOKEN,
    )


def bind_claude_provider_preparation_authority(
    *,
    provider_preparation: Any,
    launch_generation_authority: ProviderLaunchGenerationAuthority,
    launch_intent: BackendLaunchIntent,
) -> ProviderPreparationAuthority:
    """Fail closed until current startup/source authority is launch-bound."""

    from claude_provider_preparation import ClaudeProviderPreparation

    if type(provider_preparation) is not ClaudeProviderPreparation:
        raise CapabilityRegistryError(
            "exact opaque Claude provider preparation is required"
        )
    if type(launch_generation_authority) is not (
        ProviderLaunchGenerationAuthority
    ):
        raise CapabilityRegistryError(
            "opaque provider launch-generation authority is required"
        )
    launch_generation_authority.require_exact_replay()
    if type(launch_intent) is not BackendLaunchIntent:
        raise CapabilityRegistryError("exact launch intent is required")
    if (
        launch_intent.backend != "claude"
        or launch_generation_authority.launch_intent_digest
        != launch_intent.launch_intent_digest
    ):
        raise CapabilityRegistryError(
            "Claude provider preparation launch authority mismatch"
        )
    raise CapabilityRegistryError(
        "current Claude startup/source launch-binding authority is "
        "unavailable; bind UNKNOWN_BLOCKED provider preparation instead"
    )


def _provider_observation_payload_digest(
    *,
    source_contract: str,
    source_authority_digest: str,
    provider_preparation_authority_digest: str,
    launch_intent_digest: str,
    observation_generation: int,
    valid_through_generation: int,
    preparation_state: str,
    context_window_tokens: int,
    max_output_tokens: int,
    max_tool_calls_total: int,
    max_native_commands: int,
    max_native_wall_time_seconds: int,
    capabilities: Iterable[CapabilityObservation],
    tool_capabilities: Iterable[ToolCapabilityObservation],
) -> str:
    """Canonical full-observation denominator used by the opaque root."""

    normalized_capabilities = _coerce_provider_observed_capabilities(
        capabilities
    )
    normalized_tools = _coerce_tools(tool_capabilities)
    return _digest(
        {
            "schema": "plamen.provider-observation-payload.v1",
            "source_contract": source_contract,
            "source_authority_digest": source_authority_digest,
            "provider_preparation_authority_digest": (
                provider_preparation_authority_digest
            ),
            "launch_intent_digest": launch_intent_digest,
            "observation_generation": observation_generation,
            "valid_through_generation": valid_through_generation,
            "preparation_state": preparation_state,
            "context_window_tokens": context_window_tokens,
            "max_output_tokens": max_output_tokens,
            "max_tool_calls_total": max_tool_calls_total,
            "max_native_commands": max_native_commands,
            "max_native_wall_time_seconds": (
                max_native_wall_time_seconds
            ),
            "capabilities": [
                row.to_dict() for row in normalized_capabilities
            ],
            "tool_capabilities": [
                row.to_dict() for row in normalized_tools
            ],
        }
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ProviderObservationRootAuthority:
    """Opaque independent root for the complete provider observation payload.

    No generic public factory exists.  A provider-specific reviewed adapter
    must be added before production can assert READY.  This intentionally
    keeps unsupported backends at UNKNOWN_BLOCKED instead of turning a caller
    record into proof.
    """

    provider_preparation_authority_digest: str
    launch_generation_authority_digest: str
    prepared_exact_model_id: str
    observation_generation: int
    observation_payload_digest: str
    _promotion_token: InitVar[object] = None
    _seal: str = field(init=False, repr=False, compare=False)

    def __post_init__(self, _promotion_token: object) -> None:
        if type(self) is not ProviderObservationRootAuthority:
            raise CapabilityRegistryError(
                "ProviderObservationRootAuthority cannot be subclass-minted"
            )
        if _promotion_token is not _PROVIDER_OBSERVATION_ROOT_TOKEN:
            raise CapabilityRegistryError(
                "provider observation root authority is opaque"
            )
        _sha256(
            self.provider_preparation_authority_digest,
            "provider_preparation_authority_digest",
        )
        _sha256(
            self.launch_generation_authority_digest,
            "launch_generation_authority_digest",
        )
        _model_id(
            self.prepared_exact_model_id,
            "prepared_exact_model_id",
        )
        _positive_int(
            self.observation_generation,
            "observation_generation",
        )
        _sha256(
            self.observation_payload_digest,
            "observation_payload_digest",
        )
        object.__setattr__(
            self,
            "_seal",
            self.provider_observation_root_authority_digest,
        )
        _OBSERVATION_ROOT_AUTHORITY_SEALS.issue(
            self,
            self.provider_observation_root_authority_digest.encode("ascii"),
        )

    @property
    def provider_observation_root_authority_digest(self) -> str:
        return _digest(
            {
                "schema": "plamen.provider-observation-root-authority.v1",
                "provider_preparation_authority_digest": (
                    self.provider_preparation_authority_digest
                ),
                "launch_generation_authority_digest": (
                    self.launch_generation_authority_digest
                ),
                "prepared_exact_model_id": self.prepared_exact_model_id,
                "observation_generation": self.observation_generation,
                "observation_payload_digest": (
                    self.observation_payload_digest
                ),
            }
        )

    def require_exact_replay(self) -> None:
        if (
            type(self) is not ProviderObservationRootAuthority
            or self._seal
            != self.provider_observation_root_authority_digest
        ):
            raise CapabilityRegistryError(
                "provider observation root authority seal drifted"
            )
        _OBSERVATION_ROOT_AUTHORITY_SEALS.require(
            self,
            exact_type=ProviderObservationRootAuthority,
            canonical=(
                self.provider_observation_root_authority_digest.encode("ascii")
            ),
            label="provider observation root authority",
        )


@dataclass(frozen=True, slots=True)
class ProviderObservationRecord:
    """Untrusted typed output of an independent preparation/observation lane."""

    source_contract: str
    source_authority_digest: str
    provider_preparation_authority_digest: str | None
    provider_observation_root_authority_digest: str | None
    launch_intent_digest: str
    observation_generation: int
    valid_through_generation: int
    preparation_state: str
    context_window_tokens: int
    max_output_tokens: int
    max_tool_calls_total: int
    max_native_commands: int
    max_native_wall_time_seconds: int
    capabilities: tuple[CapabilityObservation, ...]
    tool_capabilities: tuple[ToolCapabilityObservation, ...]
    preparation_authority: InitVar[ProviderPreparationAuthority | None] = None
    observation_root_authority: InitVar[
        ProviderObservationRootAuthority | None
    ] = None

    schema: ClassVar[str] = PROVIDER_OBSERVATION_RECORD_SCHEMA

    def __post_init__(
        self,
        preparation_authority: ProviderPreparationAuthority | None,
        observation_root_authority: ProviderObservationRootAuthority | None,
    ) -> None:
        source_contract = _closed(
            self.source_contract,
            PROVIDER_OBSERVATION_SOURCE_CONTRACTS,
            "source_contract",
        )
        _sha256(self.source_authority_digest, "source_authority_digest")
        if self.provider_preparation_authority_digest is not None:
            _sha256(
                self.provider_preparation_authority_digest,
                "provider_preparation_authority_digest",
            )
        if self.provider_observation_root_authority_digest is not None:
            _sha256(
                self.provider_observation_root_authority_digest,
                "provider_observation_root_authority_digest",
            )
        _sha256(self.launch_intent_digest, "launch_intent_digest")
        generation = _positive_int(
            self.observation_generation, "observation_generation"
        )
        valid_through = _positive_int(
            self.valid_through_generation, "valid_through_generation"
        )
        if valid_through < generation:
            raise CapabilityRegistryError(
                "valid_through_generation cannot precede observation_generation"
            )
        preparation_state = _closed(
            self.preparation_state,
            PROVIDER_PREPARATION_STATES,
            "preparation_state",
        )
        if (
            source_contract == "GENERIC_OBSERVATION_AUTHORITY_V1"
            and preparation_state not in {"UNKNOWN_BLOCKED", "NOT_APPLICABLE"}
        ):
            raise CapabilityRegistryError(
                "generic observation authority cannot assert provider "
                "preparation readiness"
            )
        if preparation_state == "READY":
            if type(preparation_authority) is not ProviderPreparationAuthority:
                raise CapabilityRegistryError(
                    "READY requires opaque typed provider preparation authority"
                )
            preparation_authority.require_exact_replay()
            expected_preparation = (
                preparation_authority.source_contract,
                preparation_authority.source_authority_digest,
                preparation_authority.launch_intent_digest,
                preparation_authority.observation_generation,
                preparation_authority.valid_through_generation,
                preparation_authority.preparation_state,
            )
            supplied_preparation = (
                self.source_contract,
                self.source_authority_digest,
                self.launch_intent_digest,
                self.observation_generation,
                self.valid_through_generation,
                self.preparation_state,
            )
            if supplied_preparation != expected_preparation:
                raise CapabilityRegistryError(
                    "provider observation/preparation authority mismatch"
                )
            if self.provider_preparation_authority_digest != (
                preparation_authority
                .provider_preparation_authority_digest
            ):
                raise CapabilityRegistryError(
                    "provider observation preparation-root digest mismatch"
                )
            if type(observation_root_authority) is not (
                ProviderObservationRootAuthority
            ):
                raise CapabilityRegistryError(
                    "READY requires opaque provider observation root authority"
                )
            observation_root_authority.require_exact_replay()
            if (
                self.provider_observation_root_authority_digest
                != observation_root_authority
                .provider_observation_root_authority_digest
                or observation_root_authority
                .provider_preparation_authority_digest
                != preparation_authority
                .provider_preparation_authority_digest
                or observation_root_authority
                .launch_generation_authority_digest
                != preparation_authority
                .launch_generation_authority_digest
                or observation_root_authority.prepared_exact_model_id
                != preparation_authority.prepared_exact_model_id
                or observation_root_authority.observation_generation
                != self.observation_generation
            ):
                raise CapabilityRegistryError(
                    "provider observation root/preparation authority mismatch"
                )
        elif preparation_authority is not None:
            if type(preparation_authority) is not ProviderPreparationAuthority:
                raise CapabilityRegistryError(
                    "provider preparation authority must be exact typed"
                )
            preparation_authority.require_exact_replay()
            if (
                preparation_authority.preparation_state
                != preparation_state
                or preparation_authority.source_contract != source_contract
                or preparation_authority.source_authority_digest
                != self.source_authority_digest
                or preparation_authority.launch_intent_digest
                != self.launch_intent_digest
                or preparation_authority.observation_generation
                != self.observation_generation
                or preparation_authority.valid_through_generation
                != self.valid_through_generation
            ):
                raise CapabilityRegistryError(
                    "provider observation/preparation authority mismatch"
                )
            if self.provider_preparation_authority_digest != (
                preparation_authority
                .provider_preparation_authority_digest
            ):
                raise CapabilityRegistryError(
                    "provider observation preparation-root digest mismatch"
                )
        elif self.provider_preparation_authority_digest is not None:
            raise CapabilityRegistryError(
                "provider preparation-root digest lacks opaque parent"
            )
        if preparation_state != "READY" and (
            observation_root_authority is not None
            or self.provider_observation_root_authority_digest is not None
        ):
            raise CapabilityRegistryError(
                "non-READY observation cannot carry a positive root authority"
            )
        _nonnegative_int(
            self.context_window_tokens, "context_window_tokens"
        )
        _nonnegative_int(self.max_output_tokens, "max_output_tokens")
        _nonnegative_int(
            self.max_tool_calls_total, "max_tool_calls_total"
        )
        _nonnegative_int(self.max_native_commands, "max_native_commands")
        _nonnegative_int(
            self.max_native_wall_time_seconds,
            "max_native_wall_time_seconds",
        )
        if (self.max_native_commands == 0) != (
            self.max_native_wall_time_seconds == 0
        ):
            raise CapabilityRegistryError(
                "provider observation native command/time ceilings must "
                "both be zero or both be positive"
            )
        capabilities = _coerce_provider_observed_capabilities(
            self.capabilities
        )
        tools = _coerce_tools(self.tool_capabilities)
        if sum(row.max_calls for row in tools) != self.max_tool_calls_total:
            raise CapabilityRegistryError(
                "provider observation tool denominator does not equal "
                "max_tool_calls_total"
            )
        if preparation_state == "READY":
            assert type(observation_root_authority) is (
                ProviderObservationRootAuthority
            )
            payload_digest = _provider_observation_payload_digest(
                source_contract=self.source_contract,
                source_authority_digest=self.source_authority_digest,
                provider_preparation_authority_digest=(
                    self.provider_preparation_authority_digest
                ),
                launch_intent_digest=self.launch_intent_digest,
                observation_generation=self.observation_generation,
                valid_through_generation=self.valid_through_generation,
                preparation_state=self.preparation_state,
                context_window_tokens=self.context_window_tokens,
                max_output_tokens=self.max_output_tokens,
                max_tool_calls_total=self.max_tool_calls_total,
                max_native_commands=self.max_native_commands,
                max_native_wall_time_seconds=(
                    self.max_native_wall_time_seconds
                ),
                capabilities=capabilities,
                tool_capabilities=tools,
            )
            if payload_digest != (
                observation_root_authority.observation_payload_digest
            ):
                raise CapabilityRegistryError(
                    "provider observation payload is not rooted by authority"
                )
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "tool_capabilities", tools)

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "source_contract": self.source_contract,
            "source_authority_digest": self.source_authority_digest,
            "provider_preparation_authority_digest": (
                self.provider_preparation_authority_digest
            ),
            "provider_observation_root_authority_digest": (
                self.provider_observation_root_authority_digest
            ),
            "launch_intent_digest": self.launch_intent_digest,
            "observation_generation": self.observation_generation,
            "valid_through_generation": self.valid_through_generation,
            "preparation_state": self.preparation_state,
            "context_window_tokens": self.context_window_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_tool_calls_total": self.max_tool_calls_total,
            "max_native_commands": self.max_native_commands,
            "max_native_wall_time_seconds": (
                self.max_native_wall_time_seconds
            ),
            "capabilities": [row.to_dict() for row in self.capabilities],
            "tool_capabilities": [
                row.to_dict() for row in self.tool_capabilities
            ],
        }

    @property
    def record_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "record_digest": self.record_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        preparation_authority: ProviderPreparationAuthority | None = None,
        observation_root_authority: (
            ProviderObservationRootAuthority | None
        ) = None,
    ) -> "ProviderObservationRecord":
        _require_exact_keys(
            value,
            _PROVIDER_OBSERVATION_RECORD_KEYS,
            "provider observation record",
        )
        if value["schema"] != PROVIDER_OBSERVATION_RECORD_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported provider observation record schema"
            )
        claimed = _sha256(value["record_digest"], "record_digest")
        record = cls(
            source_contract=value["source_contract"],
            source_authority_digest=value["source_authority_digest"],
            provider_preparation_authority_digest=value[
                "provider_preparation_authority_digest"
            ],
            provider_observation_root_authority_digest=value[
                "provider_observation_root_authority_digest"
            ],
            launch_intent_digest=value["launch_intent_digest"],
            observation_generation=value["observation_generation"],
            valid_through_generation=value["valid_through_generation"],
            preparation_state=value["preparation_state"],
            context_window_tokens=value["context_window_tokens"],
            max_output_tokens=value["max_output_tokens"],
            max_tool_calls_total=value["max_tool_calls_total"],
            max_native_commands=value["max_native_commands"],
            max_native_wall_time_seconds=value[
                "max_native_wall_time_seconds"
            ],
            capabilities=tuple(
                CapabilityObservation.from_dict(row)
                for row in _mapping_array(
                    value["capabilities"], "capabilities"
                )
            ),
            tool_capabilities=tuple(
                ToolCapabilityObservation.from_dict(row)
                for row in _mapping_array(
                    value["tool_capabilities"], "tool_capabilities"
                )
            ),
            preparation_authority=preparation_authority,
            observation_root_authority=observation_root_authority,
        )
        if claimed != record.record_digest:
            raise CapabilityRegistryError(
                "provider observation record_digest mismatch"
            )
        return record

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        preparation_authority: ProviderPreparationAuthority | None = None,
        observation_root_authority: (
            ProviderObservationRootAuthority | None
        ) = None,
    ) -> "ProviderObservationRecord":
        return cls.from_dict(
            _decode_record(raw),
            preparation_authority=preparation_authority,
            observation_root_authority=observation_root_authority,
        )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ProviderObservationAuthority:
    """Replay-authorized independent observation source for capability promotion."""

    record: ProviderObservationRecord
    evaluation_generation: int
    preparation_authority: ProviderPreparationAuthority | None = None
    observation_root_authority: (
        ProviderObservationRootAuthority | None
    ) = None
    _promotion_token: InitVar[object] = None
    _seal: str = field(init=False, repr=False, compare=False)

    schema: ClassVar[str] = PROVIDER_OBSERVATION_AUTHORITY_SCHEMA

    def __post_init__(self, _promotion_token: object) -> None:
        if _promotion_token is not _AUTHORITY_PROMOTION_TOKEN:
            raise CapabilityRegistryError(
                "provider observation authority requires trusted replay"
            )
        if type(self.record) is not ProviderObservationRecord:
            raise CapabilityRegistryError(
                "provider observation authority record is invalid"
            )
        if self.record.preparation_state == "READY":
            if type(self.preparation_authority) is not (
                ProviderPreparationAuthority
            ):
                raise CapabilityRegistryError(
                    "READY observation lacks opaque preparation authority"
                )
            self.preparation_authority.require_exact_replay()
            if (
                self.preparation_authority.source_authority_digest
                != self.record.source_authority_digest
                or self.record.provider_preparation_authority_digest
                != self.preparation_authority
                .provider_preparation_authority_digest
                or self.preparation_authority.launch_intent_digest
                != self.record.launch_intent_digest
                or self.preparation_authority.observation_generation
                != self.record.observation_generation
                or self.preparation_authority.valid_through_generation
                != self.record.valid_through_generation
                or self.preparation_authority.preparation_state != "READY"
            ):
                raise CapabilityRegistryError(
                    "provider observation/preparation authority does not close"
                )
            if type(self.observation_root_authority) is not (
                ProviderObservationRootAuthority
            ):
                raise CapabilityRegistryError(
                    "READY observation lacks opaque observation-root authority"
                )
            self.observation_root_authority.require_exact_replay()
            if (
                self.record.provider_observation_root_authority_digest
                != self.observation_root_authority
                .provider_observation_root_authority_digest
                or self.observation_root_authority
                .provider_preparation_authority_digest
                != self.preparation_authority
                .provider_preparation_authority_digest
            ):
                raise CapabilityRegistryError(
                    "provider observation root does not close"
                )
        elif self.preparation_authority is not None and type(
            self.preparation_authority
        ) is not ProviderPreparationAuthority:
            raise CapabilityRegistryError(
                "provider preparation authority must be exact typed"
            )
        elif self.preparation_authority is not None:
            self.preparation_authority.require_exact_replay()
        if self.record.preparation_state != "READY" and (
            self.observation_root_authority is not None
        ):
            raise CapabilityRegistryError(
                "non-READY observation carries a positive root authority"
            )
        generation = _positive_int(
            self.evaluation_generation, "evaluation_generation"
        )
        if not (
            self.record.observation_generation
            <= generation
            <= self.record.valid_through_generation
        ):
            raise CapabilityRegistryError(
                "provider observation authority is stale for evaluation generation"
            )
        object.__setattr__(
            self,
            "_seal",
            self.provider_observation_authority_digest,
        )
        _PROVIDER_OBSERVATION_AUTHORITY_SEALS.issue(
            self,
            self.to_bytes(),
        )

    def require_exact_replay(self) -> None:
        """Reject subclasses, mutation, and record/opaque-parent drift."""

        if type(self) is not ProviderObservationAuthority:
            raise CapabilityRegistryError(
                "exact ProviderObservationAuthority runtime type is required"
            )
        if (
            self._seal != self.provider_observation_authority_digest
        ):
            raise CapabilityRegistryError(
                "provider observation authority seal drifted"
            )
        _PROVIDER_OBSERVATION_AUTHORITY_SEALS.require(
            self,
            exact_type=ProviderObservationAuthority,
            canonical=self.to_bytes(),
            label="provider observation authority",
        )
        try:
            replayed_record = ProviderObservationRecord.from_bytes(
                self.record.to_bytes(),
                preparation_authority=self.preparation_authority,
                observation_root_authority=self.observation_root_authority,
            )
        except (AttributeError, CapabilityRegistryError, TypeError, ValueError) as exc:
            raise CapabilityRegistryError(
                "provider observation authority record replay failed"
            ) from exc
        if replayed_record.to_bytes() != self.record.to_bytes():
            raise CapabilityRegistryError(
                "provider observation authority record replay drifted"
            )
        if self.preparation_authority is not None:
            self.preparation_authority.require_exact_replay()
        if self.observation_root_authority is not None:
            self.observation_root_authority.require_exact_replay()

    @property
    def observation_root_digest(self) -> str:
        return _digest(
            {
                "schema": "plamen.provider-observation-root.v1",
                "record_digest": self.record.record_digest,
                "evaluation_generation": self.evaluation_generation,
            }
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "record_digest": self.record.record_digest,
            "source_authority_digest": self.record.source_authority_digest,
            "provider_preparation_authority_digest": (
                self.record.provider_preparation_authority_digest
            ),
            "provider_observation_root_authority_digest": (
                self.record.provider_observation_root_authority_digest
            ),
            "launch_intent_digest": self.record.launch_intent_digest,
            "observation_generation": self.record.observation_generation,
            "valid_through_generation": self.record.valid_through_generation,
            "evaluation_generation": self.evaluation_generation,
            "preparation_state": self.record.preparation_state,
            "observation_root_digest": self.observation_root_digest,
        }

    @property
    def provider_observation_authority_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "provider_observation_authority_digest": (
                self.provider_observation_authority_digest
            ),
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def derived_preparation_observation(self) -> CapabilityObservation:
        if self.record.preparation_state == "READY":
            state = "SUPPORTED_AND_ENFORCED"
            debt = None
        elif self.record.preparation_state == "NOT_APPLICABLE":
            state = "UNSUPPORTED"
            debt = "PROVIDER_PREPARATION_AUTHORITY_MISSING"
        else:
            state = "UNKNOWN_BLOCKED"
            debt = "PROVIDER_PREPARATION_AUTHORITY_MISSING"
        return CapabilityObservation(
            capability="PROVIDER_PREPARATION_AUTHORITY",
            state=state,
            evidence_digest=self.record.source_authority_digest,
            debt_code=debt,
        )

    def validate_receipt(
        self,
        receipt: "BackendCapabilityReceipt",
        *,
        launch_intent: BackendLaunchIntent,
    ) -> None:
        self.require_exact_replay()
        receipt = _require_exact_backend_capability_receipt(receipt)
        if type(launch_intent) is not BackendLaunchIntent:
            raise CapabilityRegistryError(
                "exact launch intent is required for receipt validation"
            )
        launch_intent = BackendLaunchIntent.from_bytes(
            launch_intent.require_exact_replay()
        )
        if (
            self.record.preparation_state == "READY"
            and (
                type(self.preparation_authority)
                is not ProviderPreparationAuthority
                or self.preparation_authority.prepared_exact_model_id
                != receipt.exact_model_id
            )
        ):
            raise CapabilityRegistryError(
                "provider preparation exact model differs from receipt"
            )
        if self.record.launch_intent_digest != launch_intent.launch_intent_digest:
            raise CapabilityRegistryError(
                "provider observation launch intent mismatch"
            )
        if receipt.observation_root_digest != self.observation_root_digest:
            raise CapabilityRegistryError(
                "receipt observation root is not independently replayed"
            )
        expected_capabilities = tuple(
            sorted(
                (
                    *self.record.capabilities,
                    self.derived_preparation_observation(),
                ),
                key=lambda row: row.capability,
            )
        )
        if receipt.capabilities != expected_capabilities:
            raise CapabilityRegistryError(
                "receipt capability denominator/states/evidence do not "
                "match independent observation authority"
            )
        if receipt.tool_capabilities != self.record.tool_capabilities:
            raise CapabilityRegistryError(
                "receipt tool denominator/states/evidence do not match "
                "independent observation authority"
            )
        observed_limits = (
            receipt.context_window_tokens,
            receipt.max_output_tokens,
            receipt.max_tool_calls_total,
            receipt.max_native_commands,
            receipt.max_native_wall_time_seconds,
        )
        authoritative_limits = (
            self.record.context_window_tokens,
            self.record.max_output_tokens,
            self.record.max_tool_calls_total,
            self.record.max_native_commands,
            self.record.max_native_wall_time_seconds,
        )
        if observed_limits != authoritative_limits:
            raise CapabilityRegistryError(
                "receipt capability ceilings do not match independent "
                "observation authority"
            )

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        record: ProviderObservationRecord,
        preparation_authority: ProviderPreparationAuthority | None,
        observation_root_authority: (
            ProviderObservationRootAuthority | None
        ),
        launch_intent: BackendLaunchIntent,
        evaluation_generation: int,
    ) -> "ProviderObservationAuthority":
        value = _decode_record(raw)
        _require_exact_keys(
            value,
            _PROVIDER_OBSERVATION_AUTHORITY_KEYS,
            "provider observation authority",
        )
        if value["schema"] != PROVIDER_OBSERVATION_AUTHORITY_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported provider observation authority schema"
            )
        authority = replay_provider_observation_authority(
            record=record,
            preparation_authority=preparation_authority,
            observation_root_authority=observation_root_authority,
            launch_intent=launch_intent,
            evaluation_generation=evaluation_generation,
        )
        if value != authority.to_dict():
            raise CapabilityRegistryError(
                "provider observation authority does not match replay"
            )
        return authority


def replay_provider_observation_authority(
    *,
    record: ProviderObservationRecord,
    preparation_authority: ProviderPreparationAuthority | None,
    observation_root_authority: ProviderObservationRootAuthority | None,
    launch_intent: BackendLaunchIntent,
    evaluation_generation: int,
) -> ProviderObservationAuthority:
    if type(record) is not ProviderObservationRecord:
        raise CapabilityRegistryError(
            "provider observation replay requires typed record"
        )
    if type(launch_intent) is not BackendLaunchIntent:
        raise CapabilityRegistryError(
            "provider observation replay requires launch intent"
        )
    if record.preparation_state == "READY" and type(
        preparation_authority
    ) is not ProviderPreparationAuthority:
        raise CapabilityRegistryError(
            "READY observation requires opaque provider preparation authority; "
            "caller digest comparison is not authority"
        )
    if preparation_authority is not None:
        if type(preparation_authority) is not ProviderPreparationAuthority:
            raise CapabilityRegistryError(
                "provider preparation authority must be exact typed"
            )
        preparation_authority.require_exact_replay()
    if record.preparation_state == "READY" and type(
        observation_root_authority
    ) is not ProviderObservationRootAuthority:
        raise CapabilityRegistryError(
            "READY observation requires opaque provider observation root"
        )
    if observation_root_authority is not None:
        if type(observation_root_authority) is not (
            ProviderObservationRootAuthority
        ):
            raise CapabilityRegistryError(
                "provider observation root must be exact typed"
            )
        observation_root_authority.require_exact_replay()
    try:
        replayed_record = ProviderObservationRecord.from_bytes(
            record.to_bytes(),
            preparation_authority=preparation_authority,
            observation_root_authority=observation_root_authority,
        )
    except (CapabilityRegistryError, TypeError, ValueError) as exc:
        raise CapabilityRegistryError(
            "provider observation record does not replay from preparation root"
        ) from exc
    if replayed_record.to_bytes() != record.to_bytes():
        raise CapabilityRegistryError(
            "provider observation record changed during exact replay"
        )
    if record.launch_intent_digest != launch_intent.launch_intent_digest:
        raise CapabilityRegistryError(
            "provider observation launch intent mismatch"
        )
    return ProviderObservationAuthority(
        record=record,
        evaluation_generation=evaluation_generation,
        preparation_authority=preparation_authority,
        observation_root_authority=observation_root_authority,
        _promotion_token=_AUTHORITY_PROMOTION_TOKEN,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class BackendCapabilityReceipt:
    """Observed exact backend/model/CLI capability facts, without secrets."""

    backend: str
    adapter_id: str
    adapter_version: str
    semantic_model_capability_tier: str
    exact_model_id: str
    reasoning_mode: str
    provider_cli_name: str
    provider_cli_version: str
    executable_sha256: str
    executable_size_bytes: int
    observation_root_digest: str
    os_family: str
    account_mode: str
    context_window_tokens: int
    max_output_tokens: int
    max_tool_calls_total: int
    max_native_commands: int
    max_native_wall_time_seconds: int
    capabilities: tuple[CapabilityObservation, ...]
    tool_capabilities: tuple[ToolCapabilityObservation, ...]

    schema: ClassVar[str] = BACKEND_CAPABILITY_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if type(self) is not BackendCapabilityReceipt:
            raise CapabilityRegistryError(
                "BackendCapabilityReceipt cannot be subclass-minted"
            )
        backend = _closed(self.backend, BACKENDS, "backend")
        _safe_id(self.adapter_id, "adapter_id")
        _safe_id(self.adapter_version, "adapter_version")
        tier = _closed(
            self.semantic_model_capability_tier,
            SEMANTIC_MODEL_CAPABILITY_TIERS,
            "semantic_model_capability_tier",
        )
        _model_id(self.exact_model_id)
        reasoning = _closed(
            self.reasoning_mode, REASONING_MODES, "reasoning_mode"
        )
        _safe_id(self.provider_cli_name, "provider_cli_name")
        _version_token(self.provider_cli_version, "provider_cli_version")
        _sha256(self.executable_sha256, "executable_sha256")
        _positive_int(self.executable_size_bytes, "executable_size_bytes")
        _sha256(self.observation_root_digest, "observation_root_digest")
        _closed(self.os_family, OS_FAMILIES, "os_family")
        account = _closed(self.account_mode, ACCOUNT_MODES, "account_mode")
        _nonnegative_int(
            self.context_window_tokens, "context_window_tokens"
        )
        _nonnegative_int(self.max_output_tokens, "max_output_tokens")
        _nonnegative_int(
            self.max_tool_calls_total, "max_tool_calls_total"
        )
        _nonnegative_int(self.max_native_commands, "max_native_commands")
        _nonnegative_int(
            self.max_native_wall_time_seconds,
            "max_native_wall_time_seconds",
        )
        if (self.max_native_commands == 0) != (
            self.max_native_wall_time_seconds == 0
        ):
            raise CapabilityRegistryError(
                "native command and wall-time capability ceilings must both "
                "be zero or both be positive"
            )
        capabilities = _coerce_capabilities(self.capabilities)
        tools = _coerce_tools(self.tool_capabilities)
        if self.os_family == "unsupported":
            containment = next(
                row
                for row in capabilities
                if row.capability == "PROCESS_TREE_CONTAINMENT"
            )
            if (
                containment.state == "SUPPORTED_AND_ENFORCED"
                or containment.debt_code
                != "PROCESS_CONTAINMENT_PLATFORM_DEBT"
            ):
                raise CapabilityRegistryError(
                    "unsupported os_family requires "
                    "PROCESS_CONTAINMENT_PLATFORM_DEBT debt"
                )
        if sum(row.max_calls for row in tools) != self.max_tool_calls_total:
            raise CapabilityRegistryError(
                "tool capability ceilings must exactly equal "
                "max_tool_calls_total"
            )
        by_capability = {row.capability: row for row in capabilities}
        context_state = by_capability["CONTEXT_CEILING"].state
        output_state = by_capability["OUTPUT_CEILING"].state
        if (self.context_window_tokens > 0) != (
            context_state
            in {"SUPPORTED_AND_ENFORCED", "SUPPORTED_OBSERVED_ONLY"}
        ):
            raise CapabilityRegistryError(
                "context_window_tokens must agree with CONTEXT_CEILING state"
            )
        if (self.max_output_tokens > 0) != (
            output_state
            in {"SUPPORTED_AND_ENFORCED", "SUPPORTED_OBSERVED_ONLY"}
        ):
            raise CapabilityRegistryError(
                "max_output_tokens must agree with OUTPUT_CEILING state"
            )
        if backend == "native":
            if tier != "N0_NATIVE_DETERMINISTIC":
                raise CapabilityRegistryError(
                    "native receipt requires N0_NATIVE_DETERMINISTIC"
                )
            if reasoning != "not_applicable" or account != "NATIVE":
                raise CapabilityRegistryError(
                    "native receipt has model reasoning/account mode"
                )
            if (
                self.context_window_tokens
                or self.max_output_tokens
                or self.max_tool_calls_total
                or tools
            ):
                raise CapabilityRegistryError(
                    "native receipt model/tool ceilings must be zero"
                )
        elif tier == "N0_NATIVE_DETERMINISTIC":
            raise CapabilityRegistryError(
                "model backend cannot claim N0_NATIVE_DETERMINISTIC"
            )
        else:
            if reasoning == "not_applicable":
                raise CapabilityRegistryError(
                    "model receipt reasoning_mode cannot be not_applicable"
                )
            if account in {"NATIVE", "NONE", "UNKNOWN_BLOCKED"}:
                raise CapabilityRegistryError(
                    "model receipt requires an explicit provider account mode"
                )
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "tool_capabilities", tools)
        _BACKEND_RECEIPT_SEALS.issue(self, self.to_bytes())

    def require_exact_replay(self) -> bytes:
        """Return the externally sealed canonical receipt snapshot."""

        if (
            type(self.capabilities) is not tuple
            or not all(
                type(row) is CapabilityObservation
                and type(row.capability) is str
                and type(row.state) is str
                and type(row.evidence_digest) is str
                and (
                    row.debt_code is None
                    or type(row.debt_code) is str
                )
                for row in self.capabilities
            )
            or type(self.tool_capabilities) is not tuple
            or not all(
                type(row) is ToolCapabilityObservation
                and type(row.tool_capability) is str
                and type(row.state) is str
                and type(row.max_calls) is int
                and type(row.evidence_digest) is str
                and (
                    row.debt_code is None
                    or type(row.debt_code) is str
                )
                for row in self.tool_capabilities
            )
        ):
            raise CapabilityRegistryError(
                "backend capability receipt nested runtime types drifted"
            )
        return _BACKEND_RECEIPT_SEALS.require(
            self,
            exact_type=BackendCapabilityReceipt,
            canonical=self.to_bytes(),
            label="backend capability receipt",
        )

    @classmethod
    def create(
        cls,
        *,
        backend: str,
        adapter_id: str,
        adapter_version: str,
        semantic_model_capability_tier: str,
        exact_model_id: str,
        reasoning_mode: str,
        provider_cli_name: str,
        provider_cli_version: str,
        executable_sha256: str,
        executable_size_bytes: int,
        observation_root_digest: str,
        os_family: str,
        account_mode: str,
        context_window_tokens: int,
        max_output_tokens: int,
        max_tool_calls_total: int,
        max_native_commands: int,
        max_native_wall_time_seconds: int,
        capabilities: Iterable[CapabilityObservation],
        tool_capabilities: Iterable[ToolCapabilityObservation],
    ) -> "BackendCapabilityReceipt":
        if cls is not BackendCapabilityReceipt:
            raise CapabilityRegistryError(
                "BackendCapabilityReceipt factory requires exact base class"
            )
        return BackendCapabilityReceipt(
            backend=backend,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            semantic_model_capability_tier=semantic_model_capability_tier,
            exact_model_id=exact_model_id,
            reasoning_mode=reasoning_mode,
            provider_cli_name=provider_cli_name,
            provider_cli_version=provider_cli_version,
            executable_sha256=executable_sha256,
            executable_size_bytes=executable_size_bytes,
            observation_root_digest=observation_root_digest,
            os_family=os_family,
            account_mode=account_mode,
            context_window_tokens=context_window_tokens,
            max_output_tokens=max_output_tokens,
            max_tool_calls_total=max_tool_calls_total,
            max_native_commands=max_native_commands,
            max_native_wall_time_seconds=max_native_wall_time_seconds,
            capabilities=tuple(capabilities),
            tool_capabilities=tuple(tool_capabilities),
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "backend": self.backend,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "semantic_model_capability_tier": (
                self.semantic_model_capability_tier
            ),
            "exact_model_id": self.exact_model_id,
            "reasoning_mode": self.reasoning_mode,
            "provider_cli_name": self.provider_cli_name,
            "provider_cli_version": self.provider_cli_version,
            "executable_sha256": self.executable_sha256,
            "executable_size_bytes": self.executable_size_bytes,
            "observation_root_digest": self.observation_root_digest,
            "os_family": self.os_family,
            "account_mode": self.account_mode,
            "context_window_tokens": self.context_window_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_tool_calls_total": self.max_tool_calls_total,
            "max_native_commands": self.max_native_commands,
            "max_native_wall_time_seconds": (
                self.max_native_wall_time_seconds
            ),
            "capabilities": [row.to_dict() for row in self.capabilities],
            "tool_capabilities": [
                row.to_dict() for row in self.tool_capabilities
            ],
        }

    @property
    def receipt_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "receipt_digest": self.receipt_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "BackendCapabilityReceipt":
        if cls is not BackendCapabilityReceipt:
            raise CapabilityRegistryError(
                "BackendCapabilityReceipt replay requires exact base class"
            )
        _require_exact_keys(value, _RECEIPT_KEYS, "backend capability receipt")
        if value["schema"] != BACKEND_CAPABILITY_RECEIPT_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported backend capability receipt schema"
            )
        claimed = _sha256(value["receipt_digest"], "receipt_digest")
        receipt = BackendCapabilityReceipt.create(
            backend=value["backend"],
            adapter_id=value["adapter_id"],
            adapter_version=value["adapter_version"],
            semantic_model_capability_tier=value[
                "semantic_model_capability_tier"
            ],
            exact_model_id=value["exact_model_id"],
            reasoning_mode=value["reasoning_mode"],
            provider_cli_name=value["provider_cli_name"],
            provider_cli_version=value["provider_cli_version"],
            executable_sha256=value["executable_sha256"],
            executable_size_bytes=value["executable_size_bytes"],
            observation_root_digest=value["observation_root_digest"],
            os_family=value["os_family"],
            account_mode=value["account_mode"],
            context_window_tokens=value["context_window_tokens"],
            max_output_tokens=value["max_output_tokens"],
            max_tool_calls_total=value["max_tool_calls_total"],
            max_native_commands=value["max_native_commands"],
            max_native_wall_time_seconds=value[
                "max_native_wall_time_seconds"
            ],
            capabilities=(
                CapabilityObservation.from_dict(row)
                for row in _mapping_array(
                    value["capabilities"], "capabilities"
                )
            ),
            tool_capabilities=(
                ToolCapabilityObservation.from_dict(row)
                for row in _mapping_array(
                    value["tool_capabilities"], "tool_capabilities"
                )
            ),
        )
        if claimed != receipt.receipt_digest:
            raise CapabilityRegistryError("receipt_digest digest mismatch")
        return receipt

    @classmethod
    def from_bytes(cls, raw: bytes) -> "BackendCapabilityReceipt":
        if cls is not BackendCapabilityReceipt:
            raise CapabilityRegistryError(
                "BackendCapabilityReceipt replay requires exact base class"
            )
        return BackendCapabilityReceipt.from_dict(_decode_record(raw))


def _require_exact_backend_capability_receipt(
    receipt: Any,
) -> BackendCapabilityReceipt:
    if type(receipt) is not BackendCapabilityReceipt:
        raise CapabilityRegistryError(
            "exact BackendCapabilityReceipt runtime type is required"
        )
    return BackendCapabilityReceipt.from_bytes(
        receipt.require_exact_replay()
    )


@dataclass(frozen=True, slots=True)
class ToolCapabilityRequirement:
    tool_capability: str
    required_calls: int

    def __post_init__(self) -> None:
        _closed(
            self.tool_capability,
            SEMANTIC_TOOL_CAPABILITIES,
            "tool_capability",
        )
        _positive_int(self.required_calls, "required_calls")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_capability": self.tool_capability,
            "required_calls": self.required_calls,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "ToolCapabilityRequirement":
        _require_exact_keys(
            value, _TOOL_REQUIREMENT_KEYS, "tool capability requirement"
        )
        return cls(
            tool_capability=value["tool_capability"],
            required_calls=value["required_calls"],
        )


def _coerce_required_capabilities(values: Iterable[Any]) -> tuple[str, ...]:
    try:
        result = tuple(
            sorted(
                _closed(value, CAPABILITY_NAMES, "required_capabilities")
                for value in values
            )
        )
    except TypeError as exc:
        raise CapabilityRegistryError(
            "required_capabilities must be an array"
        ) from exc
    if not result:
        raise CapabilityRegistryError(
            "required_capabilities must not be empty"
        )
    if len(result) != len(set(result)):
        raise CapabilityRegistryError(
            "required_capabilities contains duplicates"
        )
    return result


def _coerce_requirements(
    values: Iterable[ToolCapabilityRequirement],
) -> tuple[ToolCapabilityRequirement, ...]:
    try:
        result = tuple(sorted(values, key=lambda row: row.tool_capability))
    except (TypeError, AttributeError) as exc:
        raise CapabilityRegistryError(
            "required_tools must contain ToolCapabilityRequirement records"
        ) from exc
    if not all(type(row) is ToolCapabilityRequirement for row in result):
        raise CapabilityRegistryError(
            "required_tools must contain ToolCapabilityRequirement records"
        )
    names = tuple(row.tool_capability for row in result)
    if len(names) != len(set(names)):
        raise CapabilityRegistryError("required_tools contains duplicates")
    return result


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CapabilityPreflightRequest:
    """Semantic request evaluated against one exact backend receipt."""

    semantic_model_capability_tier: str
    exact_model_id: str
    reasoning_mode: str
    minimum_context_window_tokens: int
    minimum_output_tokens: int
    maximum_tool_calls_required: int
    minimum_native_commands: int
    minimum_native_wall_time_seconds: int
    required_capabilities: tuple[str, ...]
    required_tools: tuple[ToolCapabilityRequirement, ...]

    schema: ClassVar[str] = CAPABILITY_PREFLIGHT_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        if type(self) is not CapabilityPreflightRequest:
            raise CapabilityRegistryError(
                "CapabilityPreflightRequest cannot be subclass-minted"
            )
        _closed(
            self.semantic_model_capability_tier,
            SEMANTIC_MODEL_CAPABILITY_TIERS,
            "semantic_model_capability_tier",
        )
        _model_id(self.exact_model_id)
        reasoning = _closed(
            self.reasoning_mode, REASONING_MODES, "reasoning_mode"
        )
        tier = self.semantic_model_capability_tier
        _nonnegative_int(
            self.minimum_context_window_tokens,
            "minimum_context_window_tokens",
        )
        _nonnegative_int(self.minimum_output_tokens, "minimum_output_tokens")
        _nonnegative_int(
            self.maximum_tool_calls_required,
            "maximum_tool_calls_required",
        )
        _nonnegative_int(
            self.minimum_native_commands, "minimum_native_commands"
        )
        _nonnegative_int(
            self.minimum_native_wall_time_seconds,
            "minimum_native_wall_time_seconds",
        )
        if (self.minimum_native_commands == 0) != (
            self.minimum_native_wall_time_seconds == 0
        ):
            raise CapabilityRegistryError(
                "minimum native commands and wall time must both be zero "
                "or both be positive"
            )
        capabilities = _coerce_required_capabilities(
            self.required_capabilities
        )
        tools = _coerce_requirements(self.required_tools)
        if sum(row.required_calls for row in tools) != (
            self.maximum_tool_calls_required
        ):
            raise CapabilityRegistryError(
                "required tool calls must exactly equal "
                "maximum_tool_calls_required"
            )
        if tier == "N0_NATIVE_DETERMINISTIC":
            if (
                self.minimum_context_window_tokens
                or self.minimum_output_tokens
                or self.maximum_tool_calls_required
                or tools
                or reasoning != "not_applicable"
            ):
                raise CapabilityRegistryError(
                    "native request requires zero model/tool budgets and "
                    "not_applicable reasoning"
                )
            if self.minimum_native_commands == 0:
                raise CapabilityRegistryError(
                    "native request requires a native command budget"
                )
        else:
            if (
                self.minimum_context_window_tokens == 0
                or self.minimum_output_tokens == 0
            ):
                raise CapabilityRegistryError(
                    "model request requires positive context/output"
                )
            if reasoning == "not_applicable":
                raise CapabilityRegistryError(
                    "model request reasoning_mode cannot be not_applicable"
                )
        object.__setattr__(self, "required_capabilities", capabilities)
        object.__setattr__(self, "required_tools", tools)
        _PREFLIGHT_REQUEST_SEALS.issue(self, self.to_bytes())

    @classmethod
    def create(
        cls,
        *,
        semantic_model_capability_tier: str,
        exact_model_id: str,
        reasoning_mode: str,
        minimum_context_window_tokens: int,
        minimum_output_tokens: int,
        maximum_tool_calls_required: int,
        minimum_native_commands: int = 0,
        minimum_native_wall_time_seconds: int = 0,
        required_capabilities: Iterable[str],
        required_tools: Iterable[ToolCapabilityRequirement],
    ) -> "CapabilityPreflightRequest":
        if cls is not CapabilityPreflightRequest:
            raise CapabilityRegistryError(
                "CapabilityPreflightRequest factory requires exact base class"
            )
        return CapabilityPreflightRequest(
            semantic_model_capability_tier=semantic_model_capability_tier,
            exact_model_id=exact_model_id,
            reasoning_mode=reasoning_mode,
            minimum_context_window_tokens=minimum_context_window_tokens,
            minimum_output_tokens=minimum_output_tokens,
            maximum_tool_calls_required=maximum_tool_calls_required,
            minimum_native_commands=minimum_native_commands,
            minimum_native_wall_time_seconds=(
                minimum_native_wall_time_seconds
            ),
            required_capabilities=tuple(required_capabilities),
            required_tools=tuple(required_tools),
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "semantic_model_capability_tier": (
                self.semantic_model_capability_tier
            ),
            "exact_model_id": self.exact_model_id,
            "reasoning_mode": self.reasoning_mode,
            "minimum_context_window_tokens": (
                self.minimum_context_window_tokens
            ),
            "minimum_output_tokens": self.minimum_output_tokens,
            "maximum_tool_calls_required": (
                self.maximum_tool_calls_required
            ),
            "minimum_native_commands": self.minimum_native_commands,
            "minimum_native_wall_time_seconds": (
                self.minimum_native_wall_time_seconds
            ),
            "required_capabilities": list(self.required_capabilities),
            "required_tools": [row.to_dict() for row in self.required_tools],
        }

    @property
    def request_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "request_digest": self.request_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def require_exact_replay(self) -> bytes:
        """Reject request subclasses, nested spoofing, and non-canonical drift."""

        if type(self) is not CapabilityPreflightRequest:
            raise CapabilityRegistryError(
                "exact CapabilityPreflightRequest runtime type is required"
            )
        if (
            type(self.semantic_model_capability_tier) is not str
            or type(self.exact_model_id) is not str
            or type(self.reasoning_mode) is not str
            or type(self.minimum_context_window_tokens) is not int
            or type(self.minimum_output_tokens) is not int
            or type(self.maximum_tool_calls_required) is not int
            or type(self.minimum_native_commands) is not int
            or type(self.minimum_native_wall_time_seconds) is not int
            or type(self.required_capabilities) is not tuple
            or not all(
                type(name) is str for name in self.required_capabilities
            )
            or type(self.required_tools) is not tuple
            or not all(
                type(row) is ToolCapabilityRequirement
                and type(row.tool_capability) is str
                and type(row.required_calls) is int
                for row in self.required_tools
            )
        ):
            raise CapabilityRegistryError(
                "capability preflight request nested runtime types drifted"
            )
        return _PREFLIGHT_REQUEST_SEALS.require(
            self,
            exact_type=CapabilityPreflightRequest,
            canonical=self.to_bytes(),
            label="capability preflight request",
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "CapabilityPreflightRequest":
        if cls is not CapabilityPreflightRequest:
            raise CapabilityRegistryError(
                "CapabilityPreflightRequest replay requires exact base class"
            )
        _require_exact_keys(value, _REQUEST_KEYS, "capability preflight request")
        if value["schema"] != CAPABILITY_PREFLIGHT_REQUEST_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported capability preflight request schema"
            )
        claimed = _sha256(value["request_digest"], "request_digest")
        request = CapabilityPreflightRequest.create(
            semantic_model_capability_tier=value[
                "semantic_model_capability_tier"
            ],
            exact_model_id=value["exact_model_id"],
            reasoning_mode=value["reasoning_mode"],
            minimum_context_window_tokens=value[
                "minimum_context_window_tokens"
            ],
            minimum_output_tokens=value["minimum_output_tokens"],
            maximum_tool_calls_required=value[
                "maximum_tool_calls_required"
            ],
            minimum_native_commands=value["minimum_native_commands"],
            minimum_native_wall_time_seconds=value[
                "minimum_native_wall_time_seconds"
            ],
            required_capabilities=value["required_capabilities"],
            required_tools=(
                ToolCapabilityRequirement.from_dict(row)
                for row in _mapping_array(
                    value["required_tools"], "required_tools"
                )
            ),
        )
        if claimed != request.request_digest:
            raise CapabilityRegistryError("request_digest digest mismatch")
        return request

    @classmethod
    def from_bytes(cls, raw: bytes) -> "CapabilityPreflightRequest":
        if cls is not CapabilityPreflightRequest:
            raise CapabilityRegistryError(
                "CapabilityPreflightRequest replay requires exact base class"
            )
        return CapabilityPreflightRequest.from_dict(_decode_record(raw))


def _require_exact_capability_preflight_request(
    request: Any,
) -> CapabilityPreflightRequest:
    if type(request) is not CapabilityPreflightRequest:
        raise CapabilityRegistryError(
            "exact CapabilityPreflightRequest runtime type is required"
        )
    sealed = request.require_exact_replay()
    return CapabilityPreflightRequest.from_bytes(sealed)


def _required_platform_capabilities(
    *,
    tier: str,
    transport_capability: str,
    required_tools: tuple[ToolCapabilityRequirement, ...],
    minimum_native_commands: int,
    requires_resume_session: bool,
) -> tuple[str, ...]:
    required = {
        "FILESYSTEM_ENFORCEMENT",
        "NETWORK_ENFORCEMENT",
        "PROCESS_TREE_CONTAINMENT",
        "STREAM_USAGE_TELEMETRY",
        transport_capability,
    }
    if tier != "N0_NATIVE_DETERMINISTIC":
        required.update(
            {
                "EXACT_MODEL_AVAILABILITY",
                "PROVIDER_PREPARATION_AUTHORITY",
                "CONTEXT_CEILING",
                "OUTPUT_CEILING",
                "REASONING_CONTROL",
            }
        )
    if required_tools:
        required.add("TOOL_EVENT_OBSERVABILITY")
    tool_names = {row.tool_capability for row in required_tools}
    if "EXTERNAL_PRECEDENT_QUERY" in tool_names:
        required.add("MCP_PROVIDER_AVAILABILITY")
    if minimum_native_commands or tool_names & {
        "STATIC_ANALYZER_QUERY",
        "NATIVE_BUILD",
        "NATIVE_TEST",
        "NATIVE_FUZZ",
        "VERSION_PROBE",
    }:
        required.add("NATIVE_COMMAND_BROKER")
    if requires_resume_session:
        required.add("RESUME_SESSION")
    return tuple(sorted(required))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CapabilityRequestAuthority:
    """Replayable proof that a raw request was mechanically compiled."""

    request_digest: str
    model_policy_registry_digest: str
    policy_entry_digest: str
    launch_intent_digest: str
    semantic_requirement_digest: str
    resource_grant_digest: str
    tool_capability_manifest_digest: str
    compiler_version: str = CAPABILITY_REQUEST_COMPILER_VERSION
    _promotion_token: InitVar[object] = None

    schema: ClassVar[str] = CAPABILITY_REQUEST_AUTHORITY_SCHEMA

    def __post_init__(self, _promotion_token: object) -> None:
        if type(self) is not CapabilityRequestAuthority:
            raise CapabilityRegistryError(
                "CapabilityRequestAuthority cannot be subclass-minted"
            )
        if _promotion_token is not _AUTHORITY_PROMOTION_TOKEN:
            raise CapabilityRegistryError(
                "request authority requires trusted compiler promotion"
            )
        for field in (
            "request_digest",
            "model_policy_registry_digest",
            "policy_entry_digest",
            "launch_intent_digest",
            "semantic_requirement_digest",
            "resource_grant_digest",
            "tool_capability_manifest_digest",
        ):
            _sha256(getattr(self, field), field)
        if self.compiler_version != CAPABILITY_REQUEST_COMPILER_VERSION:
            raise CapabilityRegistryError(
                "unsupported capability request compiler version"
            )
        _REQUEST_AUTHORITY_SEALS.issue(self, self.to_bytes())

    def require_exact_replay(self) -> bytes:
        return _REQUEST_AUTHORITY_SEALS.require(
            self,
            exact_type=CapabilityRequestAuthority,
            canonical=self.to_bytes(),
            label="capability request authority",
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "request_digest": self.request_digest,
            "model_policy_registry_digest": (
                self.model_policy_registry_digest
            ),
            "policy_entry_digest": self.policy_entry_digest,
            "launch_intent_digest": self.launch_intent_digest,
            "semantic_requirement_digest": self.semantic_requirement_digest,
            "resource_grant_digest": self.resource_grant_digest,
            "tool_capability_manifest_digest": (
                self.tool_capability_manifest_digest
            ),
            "compiler_version": self.compiler_version,
        }

    @property
    def request_authority_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "request_authority_digest": self.request_authority_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def validate_against(
        self,
        *,
        request: CapabilityPreflightRequest,
        registry: ModelPolicyRegistry,
        policy_entry: ModelPolicyEntry,
        launch_intent: BackendLaunchIntent,
        expected_model_policy_registry_digest: str,
        expected_policy_entry_digest: str,
        expected_launch_intent_digest: str,
        expected_semantic_requirement_digest: str,
        expected_resource_grant_digest: str,
        expected_tool_capability_manifest_digest: str,
    ) -> None:
        self.require_exact_replay()
        request = _require_exact_capability_preflight_request(request)
        if (
            type(registry) is not ModelPolicyRegistry
            or type(registry.entries) is not tuple
            or not all(
                type(row) is ModelPolicyEntry for row in registry.entries
            )
        ):
            raise CapabilityRegistryError(
                "exact model policy registry parent is required"
            )
        if type(policy_entry) is not ModelPolicyEntry:
            raise CapabilityRegistryError(
                "exact model policy entry parent is required"
            )
        if type(launch_intent) is not BackendLaunchIntent:
            raise CapabilityRegistryError(
                "exact launch intent parent is required"
            )
        launch_intent.require_exact_replay()
        trusted_registry_digest = _sha256(
            expected_model_policy_registry_digest,
            "expected_model_policy_registry_digest",
        )
        trusted_policy_entry_digest = _sha256(
            expected_policy_entry_digest,
            "expected_policy_entry_digest",
        )
        trusted_launch_intent_digest = _sha256(
            expected_launch_intent_digest,
            "expected_launch_intent_digest",
        )
        if self.request_digest != request.request_digest:
            raise CapabilityRegistryError(
                "request authority request_digest mismatch"
            )
        if (
            self.model_policy_registry_digest
            != registry.registry_digest
            or self.model_policy_registry_digest != trusted_registry_digest
        ):
            raise CapabilityRegistryError(
                "request authority model policy registry mismatch"
            )
        if (
            self.policy_entry_digest != policy_entry.policy_entry_digest
            or self.policy_entry_digest != trusted_policy_entry_digest
        ):
            raise CapabilityRegistryError(
                "request authority policy entry mismatch"
            )
        if (
            self.launch_intent_digest != launch_intent.launch_intent_digest
            or self.launch_intent_digest != trusted_launch_intent_digest
        ):
            raise CapabilityRegistryError(
                "request authority launch intent mismatch"
            )
        expected = (
            (
                "semantic_requirement_digest",
                self.semantic_requirement_digest,
                expected_semantic_requirement_digest,
            ),
            (
                "resource_grant_digest",
                self.resource_grant_digest,
                expected_resource_grant_digest,
            ),
            (
                "tool_capability_manifest_digest",
                self.tool_capability_manifest_digest,
                expected_tool_capability_manifest_digest,
            ),
        )
        for field, actual, wanted in expected:
            if actual != _sha256(wanted, f"expected_{field}"):
                raise CapabilityRegistryError(
                    f"request authority {field} mismatch"
                )
        if (
            policy_entry.backend != launch_intent.backend
            or policy_entry.semantic_model_capability_tier
            != request.semantic_model_capability_tier
            or policy_entry.exact_model_id != request.exact_model_id
            or policy_entry.reasoning_mode != request.reasoning_mode
        ):
            raise CapabilityRegistryError(
                "request authority policy/launch/request mismatch"
            )
        expected_caps = _required_platform_capabilities(
            tier=request.semantic_model_capability_tier,
            transport_capability=launch_intent.transport_capability,
            required_tools=request.required_tools,
            minimum_native_commands=request.minimum_native_commands,
            requires_resume_session=(
                "RESUME_SESSION" in request.required_capabilities
            ),
        )
        if request.required_capabilities != expected_caps:
            raise CapabilityRegistryError(
                "request authority capability denominator is not exact"
            )

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        request: CapabilityPreflightRequest,
        registry: ModelPolicyRegistry,
        policy_entry: ModelPolicyEntry,
        launch_intent: BackendLaunchIntent,
        expected_model_policy_registry_digest: str,
        expected_policy_entry_digest: str,
        expected_launch_intent_digest: str,
        expected_semantic_requirement_digest: str,
        expected_resource_grant_digest: str,
        expected_tool_capability_manifest_digest: str,
    ) -> "CapabilityRequestAuthority":
        if cls is not CapabilityRequestAuthority:
            raise CapabilityRegistryError(
                "CapabilityRequestAuthority replay requires exact base class"
            )
        value = _decode_record(raw)
        _require_exact_keys(
            value, _REQUEST_AUTHORITY_KEYS, "capability request authority"
        )
        if value["schema"] != CAPABILITY_REQUEST_AUTHORITY_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported capability request authority schema"
            )
        claimed = _sha256(
            value["request_authority_digest"],
            "request_authority_digest",
        )
        authority = CapabilityRequestAuthority(
            request_digest=value["request_digest"],
            model_policy_registry_digest=value[
                "model_policy_registry_digest"
            ],
            policy_entry_digest=value["policy_entry_digest"],
            launch_intent_digest=value["launch_intent_digest"],
            semantic_requirement_digest=value[
                "semantic_requirement_digest"
            ],
            resource_grant_digest=value["resource_grant_digest"],
            tool_capability_manifest_digest=value[
                "tool_capability_manifest_digest"
            ],
            compiler_version=value["compiler_version"],
            _promotion_token=_AUTHORITY_PROMOTION_TOKEN,
        )
        if claimed != authority.request_authority_digest:
            raise CapabilityRegistryError(
                "request_authority_digest mismatch"
            )
        authority.validate_against(
            request=request,
            registry=registry,
            policy_entry=policy_entry,
            launch_intent=launch_intent,
            expected_model_policy_registry_digest=(
                expected_model_policy_registry_digest
            ),
            expected_policy_entry_digest=expected_policy_entry_digest,
            expected_launch_intent_digest=expected_launch_intent_digest,
            expected_semantic_requirement_digest=(
                expected_semantic_requirement_digest
            ),
            expected_resource_grant_digest=expected_resource_grant_digest,
            expected_tool_capability_manifest_digest=(
                expected_tool_capability_manifest_digest
            ),
        )
        return authority


def _compile_capability_preflight_request(
    *,
    registry: ModelPolicyRegistry,
    policy_entry: ModelPolicyEntry,
    launch_intent: BackendLaunchIntent,
    expected_model_policy_registry_digest: str,
    expected_policy_entry_digest: str,
    expected_launch_intent_digest: str,
    semantic_requirement_digest: str,
    resource_grant_digest: str,
    tool_capability_manifest_digest: str,
    minimum_context_window_tokens: int,
    minimum_output_tokens: int,
    required_tools: Iterable[ToolCapabilityRequirement],
    minimum_native_commands: int,
    minimum_native_wall_time_seconds: int,
    requires_resume_session: bool = False,
) -> tuple[CapabilityPreflightRequest, CapabilityRequestAuthority]:
    """Internal projection compiler.

    Production callers use
    ``resource_grant.compile_preflight_request_from_resource_grant`` so the
    numeric and tool denominator is replayed from exact grant bytes.
    """

    if type(registry) is not ModelPolicyRegistry:
        raise CapabilityRegistryError("registry must be ModelPolicyRegistry")
    if (
        type(registry.entries) is not tuple
        or not all(type(row) is ModelPolicyEntry for row in registry.entries)
    ):
        raise CapabilityRegistryError(
            "registry must contain exact ModelPolicyEntry records"
        )
    if type(policy_entry) is not ModelPolicyEntry:
        raise CapabilityRegistryError(
            "policy_entry must be ModelPolicyEntry"
        )
    if type(launch_intent) is not BackendLaunchIntent:
        raise CapabilityRegistryError(
            "launch_intent must be BackendLaunchIntent"
        )
    try:
        registry_snapshot = ModelPolicyRegistry.from_bytes(
            registry.to_bytes()
        )
        policy_entry_snapshot = ModelPolicyEntry.from_dict(
            policy_entry.to_dict()
        )
        launch_intent_snapshot = BackendLaunchIntent.from_bytes(
            launch_intent.require_exact_replay()
        )
    except (AttributeError, TypeError, CapabilityRegistryError) as exc:
        raise CapabilityRegistryError(
            "request compiler parents do not exactly replay"
        ) from exc
    registry = registry_snapshot
    policy_entry = policy_entry_snapshot
    launch_intent = launch_intent_snapshot
    resolved = registry.resolve(
        semantic_model_capability_tier=(
            policy_entry.semantic_model_capability_tier
        ),
        backend=policy_entry.backend,
        required_exact_model_id=policy_entry.exact_model_id,
    )
    if resolved != policy_entry:
        raise CapabilityRegistryError(
            "policy entry is not the exact registry entry"
        )
    if launch_intent.backend != policy_entry.backend:
        raise CapabilityRegistryError(
            "launch intent backend does not match policy entry"
        )
    if registry.registry_digest != _sha256(
        expected_model_policy_registry_digest,
        "expected_model_policy_registry_digest",
    ):
        raise CapabilityRegistryError(
            "model policy registry does not match trusted parent digest"
        )
    if policy_entry.policy_entry_digest != _sha256(
        expected_policy_entry_digest, "expected_policy_entry_digest"
    ):
        raise CapabilityRegistryError(
            "model policy entry does not match trusted parent digest"
        )
    if launch_intent.launch_intent_digest != _sha256(
        expected_launch_intent_digest, "expected_launch_intent_digest"
    ):
        raise CapabilityRegistryError(
            "launch intent does not match trusted parent digest"
        )
    tools = _coerce_requirements(tuple(required_tools))
    required_capabilities = _required_platform_capabilities(
        tier=policy_entry.semantic_model_capability_tier,
        transport_capability=launch_intent.transport_capability,
        required_tools=tools,
        minimum_native_commands=minimum_native_commands,
        requires_resume_session=requires_resume_session,
    )
    request = CapabilityPreflightRequest.create(
        semantic_model_capability_tier=(
            policy_entry.semantic_model_capability_tier
        ),
        exact_model_id=policy_entry.exact_model_id,
        reasoning_mode=policy_entry.reasoning_mode,
        minimum_context_window_tokens=minimum_context_window_tokens,
        minimum_output_tokens=minimum_output_tokens,
        maximum_tool_calls_required=sum(
            row.required_calls for row in tools
        ),
        minimum_native_commands=minimum_native_commands,
        minimum_native_wall_time_seconds=(
            minimum_native_wall_time_seconds
        ),
        required_capabilities=required_capabilities,
        required_tools=tools,
    )
    authority = CapabilityRequestAuthority(
        request_digest=request.request_digest,
        model_policy_registry_digest=registry.registry_digest,
        policy_entry_digest=policy_entry.policy_entry_digest,
        launch_intent_digest=launch_intent.launch_intent_digest,
        semantic_requirement_digest=_sha256(
            semantic_requirement_digest, "semantic_requirement_digest"
        ),
        resource_grant_digest=_sha256(
            resource_grant_digest, "resource_grant_digest"
        ),
        tool_capability_manifest_digest=_sha256(
            tool_capability_manifest_digest,
            "tool_capability_manifest_digest",
        ),
        _promotion_token=_AUTHORITY_PROMOTION_TOKEN,
    )
    return request, authority


def _require_reviewed_adapter_identity(
    launch_intent: BackendLaunchIntent,
) -> None:
    if type(launch_intent) is not BackendLaunchIntent:
        raise CapabilityRegistryError(
            "exact BackendLaunchIntent runtime type is required"
        )
    launch_intent.require_exact_replay()
    identity = (
        launch_intent.backend,
        launch_intent.adapter_id,
        launch_intent.adapter_version,
        launch_intent.provider_cli_name,
    )
    if identity not in REVIEWED_ADAPTER_IDENTITIES:
        raise CapabilityRegistryError(
            "adapter identity is absent from the closed reviewed registry"
        )


def _validate_current_launch_generation_parents(
    *,
    request: CapabilityPreflightRequest,
    request_authority: CapabilityRequestAuthority,
    observation_authority: ProviderObservationAuthority,
    semantic_work_plan: Any,
    global_reservation: Any,
    launch_intent: BackendLaunchIntent,
    launch_generation_authority: ProviderLaunchGenerationAuthority,
    _structural_test_token: object = None,
) -> None:
    """Close promotion over the current run, reservation, and generation."""

    from resource_policy_authority import GlobalResourceReservation
    from semantic_work_plan import SemanticWorkPlan

    request = _require_exact_capability_preflight_request(request)
    if type(request_authority) is not CapabilityRequestAuthority:
        raise CapabilityRegistryError(
            "exact capability request authority is required"
        )
    request_authority.require_exact_replay()
    if type(semantic_work_plan) is not SemanticWorkPlan:
        raise CapabilityRegistryError(
            "exact SemanticWorkPlan is required for capability promotion"
        )
    if type(global_reservation) is not GlobalResourceReservation:
        raise CapabilityRegistryError(
            "exact global reservation is required for capability promotion"
        )
    if type(launch_generation_authority) is not (
        ProviderLaunchGenerationAuthority
    ):
        raise CapabilityRegistryError(
            "exact provider launch-generation authority is required"
        )
    try:
        replayed_plan = SemanticWorkPlan.from_bytes(
            semantic_work_plan.to_bytes()
        )
        replayed_reservation = global_reservation.replay()
        launch_generation_authority.require_exact_replay()
        expected_launch_generation = (
            _bind_provider_launch_generation_authority(
                semantic_work_plan=semantic_work_plan,
                global_reservation=global_reservation,
                launch_intent=launch_intent,
                _structural_test_token=_structural_test_token,
            )
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise CapabilityRegistryError(
            "current production/structural launch-generation reservation "
            "parents do not exactly replay",
            debt=getattr(exc, "debt", None),
        ) from exc
    if (
        replayed_plan.to_bytes() != semantic_work_plan.to_bytes()
        or replayed_reservation.to_bytes() != global_reservation.to_bytes()
        or expected_launch_generation
        .launch_generation_authority_digest
        != launch_generation_authority
        .launch_generation_authority_digest
        or expected_launch_generation.resource_authority_class
        != launch_generation_authority.resource_authority_class
    ):
        raise CapabilityRegistryError(
            "current launch-generation authority does not bind its parents"
        )
    if (
        request_authority.resource_grant_digest
        != semantic_work_plan.resource_grant_digest
        or request_authority.tool_capability_manifest_digest
        != semantic_work_plan.tool_capability_manifest_digest
        or request.semantic_model_capability_tier
        != semantic_work_plan.model_capability_tier
        or semantic_work_plan.run_id != global_reservation.run_id
        or semantic_work_plan.semantic_generation
        != global_reservation.generation
        or observation_authority.evaluation_generation
        != semantic_work_plan.semantic_generation
    ):
        raise CapabilityRegistryError(
            "capability promotion run/generation/reservation binding drifted"
        )
    preparation = observation_authority.preparation_authority
    root = observation_authority.observation_root_authority
    if observation_authority.record.preparation_state == "READY":
        if _structural_test_token is not _STRUCTURAL_TEST_BACKEND_TOKEN:
            raise CapabilityRegistryError(
                "production provider preparation/root issuer is unavailable; "
                "module-private tokens are not readiness proof"
            )
        if (
            type(preparation) is not ProviderPreparationAuthority
            or type(root) is not ProviderObservationRootAuthority
            or preparation.launch_generation_authority_digest
            != launch_generation_authority
            .launch_generation_authority_digest
            or root.launch_generation_authority_digest
            != launch_generation_authority
            .launch_generation_authority_digest
        ):
            raise CapabilityRegistryError(
                "READY observation is not rooted in current launch generation"
            )


@dataclass(frozen=True, slots=True)
class BackendCapabilityPromotionParents:
    """Exact live parents retained for sink-side replay.

    This record is not authority by itself.  Production sinks replay every
    member and additionally require the production resource closure.
    """

    request: CapabilityPreflightRequest
    request_authority: CapabilityRequestAuthority
    receipt: BackendCapabilityReceipt
    registry: ModelPolicyRegistry
    policy_entry: ModelPolicyEntry
    launch_intent: BackendLaunchIntent
    expected_model_policy_registry_digest: str
    expected_policy_entry_digest: str
    expected_launch_intent_digest: str
    expected_semantic_requirement_digest: str
    expected_resource_grant_digest: str
    expected_tool_capability_manifest_digest: str
    observation_authority: ProviderObservationAuthority
    semantic_work_plan: Any
    global_reservation: Any
    launch_generation_authority: ProviderLaunchGenerationAuthority
    resource_grant: Any = None
    resource_policy_authority: Any = None

    def as_validation_kwargs(self) -> dict[str, Any]:
        return {
            "request": self.request,
            "request_authority": self.request_authority,
            "receipt": self.receipt,
            "registry": self.registry,
            "policy_entry": self.policy_entry,
            "launch_intent": self.launch_intent,
            "expected_model_policy_registry_digest": (
                self.expected_model_policy_registry_digest
            ),
            "expected_policy_entry_digest": (
                self.expected_policy_entry_digest
            ),
            "expected_launch_intent_digest": (
                self.expected_launch_intent_digest
            ),
            "expected_semantic_requirement_digest": (
                self.expected_semantic_requirement_digest
            ),
            "expected_resource_grant_digest": (
                self.expected_resource_grant_digest
            ),
            "expected_tool_capability_manifest_digest": (
                self.expected_tool_capability_manifest_digest
            ),
            "observation_authority": self.observation_authority,
            "semantic_work_plan": self.semantic_work_plan,
            "global_reservation": self.global_reservation,
            "launch_generation_authority": (
                self.launch_generation_authority
            ),
            "resource_grant": self.resource_grant,
            "resource_policy_authority": (
                self.resource_policy_authority
            ),
        }


@dataclass(frozen=True, slots=True, weakref_slot=True)
class BackendCapabilityAuthority:
    """Trusted promotion of one raw preflight receipt and its exact parents."""

    request_digest: str
    request_authority_digest: str
    receipt_digest: str
    launch_intent_digest: str
    model_policy_registry_digest: str
    policy_entry_digest: str
    trusted_observation_root_digest: str
    provider_observation_authority_digest: str
    launch_generation_authority_digest: str
    observation_generation: int
    _bound_parents: BackendCapabilityPromotionParents | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _promotion_token: InitVar[object] = None
    _seal: str = field(init=False, repr=False, compare=False)

    schema: ClassVar[str] = BACKEND_CAPABILITY_AUTHORITY_SCHEMA

    def __post_init__(self, _promotion_token: object) -> None:
        if _promotion_token is not _AUTHORITY_PROMOTION_TOKEN:
            raise CapabilityRegistryError(
                "capability authority requires trusted promotion"
            )
        if type(self._bound_parents) is not (
            BackendCapabilityPromotionParents
        ):
            raise CapabilityRegistryError(
                "capability authority requires exact replay parents"
            )
        for field in (
            "request_digest",
            "request_authority_digest",
            "receipt_digest",
            "launch_intent_digest",
            "model_policy_registry_digest",
            "policy_entry_digest",
            "trusted_observation_root_digest",
            "provider_observation_authority_digest",
            "launch_generation_authority_digest",
        ):
            _sha256(getattr(self, field), field)
        _positive_int(self.observation_generation, "observation_generation")
        object.__setattr__(
            self,
            "_seal",
            self.capability_authority_digest,
        )
        _BACKEND_CAPABILITY_AUTHORITY_SEALS.issue(
            self,
            self.to_bytes(),
        )

    def require_exact_replay(self) -> None:
        if (
            type(self) is not BackendCapabilityAuthority
            or self._seal != self.capability_authority_digest
        ):
            raise CapabilityRegistryError(
                "backend capability authority seal/replay drifted"
            )
        _BACKEND_CAPABILITY_AUTHORITY_SEALS.require(
            self,
            exact_type=BackendCapabilityAuthority,
            canonical=self.to_bytes(),
            label="backend capability authority",
        )
        if type(self._bound_parents) is not (
            BackendCapabilityPromotionParents
        ):
            raise CapabilityRegistryError(
                "backend capability authority replay parents are absent"
            )

    @property
    def resource_authority_class(self) -> str:
        self.require_exact_replay()
        return (
            self._bound_parents
            .launch_generation_authority
            .resource_authority_class
        )

    def _validate_bound_parents(
        self,
        *,
        _structural_test_token: object = None,
    ) -> None:
        self.require_exact_replay()
        assert type(self._bound_parents) is (
            BackendCapabilityPromotionParents
        )
        structural = (
            _structural_test_token is _STRUCTURAL_TEST_BACKEND_TOKEN
        )
        expected_class = (
            "STRUCTURAL_TEST_ONLY"
            if structural
            else "PRODUCTION_RESOURCE_AUTHORIZED"
        )
        if self.resource_authority_class != expected_class:
            raise CapabilityRegistryError(
                "capability authority resource class replay is not valid for "
                f"{'structural test' if structural else 'production'} sink"
            )
        self._validate_against(
            **self._bound_parents.as_validation_kwargs(),
            _structural_test_token=_structural_test_token,
        )

    def validate_bound_parents(self) -> None:
        """Production replay of every retained capability parent."""

        self._validate_bound_parents()

    def validate_structural_test_bound_parents(self) -> None:
        """Explicit test-only replay of structural capability parents."""

        self._validate_bound_parents(
            _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "request_digest": self.request_digest,
            "request_authority_digest": self.request_authority_digest,
            "receipt_digest": self.receipt_digest,
            "launch_intent_digest": self.launch_intent_digest,
            "model_policy_registry_digest": (
                self.model_policy_registry_digest
            ),
            "policy_entry_digest": self.policy_entry_digest,
            "trusted_observation_root_digest": (
                self.trusted_observation_root_digest
            ),
            "provider_observation_authority_digest": (
                self.provider_observation_authority_digest
            ),
            "launch_generation_authority_digest": (
                self.launch_generation_authority_digest
            ),
            "observation_generation": self.observation_generation,
        }

    @property
    def capability_authority_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "capability_authority_digest": (
                self.capability_authority_digest
            ),
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def _validate_against(
        self,
        *,
        request: CapabilityPreflightRequest,
        request_authority: CapabilityRequestAuthority,
        receipt: BackendCapabilityReceipt,
        registry: ModelPolicyRegistry,
        policy_entry: ModelPolicyEntry,
        launch_intent: BackendLaunchIntent,
        expected_model_policy_registry_digest: str,
        expected_policy_entry_digest: str,
        expected_launch_intent_digest: str,
        expected_semantic_requirement_digest: str,
        expected_resource_grant_digest: str,
        expected_tool_capability_manifest_digest: str,
        observation_authority: ProviderObservationAuthority,
        semantic_work_plan: Any,
        global_reservation: Any,
        launch_generation_authority: ProviderLaunchGenerationAuthority,
        resource_grant: Any = None,
        resource_policy_authority: Any = None,
        _structural_test_token: object = None,
    ) -> None:
        self.require_exact_replay()
        request = _require_exact_capability_preflight_request(request)
        if type(request_authority) is not CapabilityRequestAuthority:
            raise CapabilityRegistryError(
                "exact capability request authority is required"
            )
        request_authority.require_exact_replay()
        receipt = _require_exact_backend_capability_receipt(receipt)
        if type(launch_intent) is not BackendLaunchIntent:
            raise CapabilityRegistryError(
                "exact launch intent is required"
            )
        launch_intent.require_exact_replay()
        if type(observation_authority) is not ProviderObservationAuthority:
            raise CapabilityRegistryError(
                "independent provider observation authority is required"
            )
        observation_authority.require_exact_replay()
        structural = (
            _structural_test_token is _STRUCTURAL_TEST_BACKEND_TOKEN
        )
        if structural:
            if (
                resource_grant is not None
                or resource_policy_authority is not None
            ):
                raise CapabilityRegistryError(
                    "structural capability promotion cannot masquerade "
                    "as production resource replay"
                )
        else:
            from resource_grant import (
                ResourceGrant,
                validate_resource_grant_against_semantic_work_plan,
            )
            from resource_policy_authority import ResourcePolicyAuthority

            if type(resource_grant) is not ResourceGrant:
                raise CapabilityRegistryError(
                    "production capability promotion requires exact "
                    "ResourceGrant"
                )
            if type(resource_policy_authority) is not (
                ResourcePolicyAuthority
            ):
                raise CapabilityRegistryError(
                    "production capability promotion requires exact "
                    "ResourcePolicyAuthority"
                )
            try:
                validate_resource_grant_against_semantic_work_plan(
                    resource_grant,
                    semantic_work_plan,
                    policy_authority=resource_policy_authority,
                    global_reservation=global_reservation,
                )
            except ValueError as exc:
                raise CapabilityRegistryError(
                    "production capability resource closure failed",
                    debt=getattr(exc, "debt", None),
                ) from exc
            if (
                resource_grant.resource_grant_digest
                != expected_resource_grant_digest
            ):
                raise CapabilityRegistryError(
                    "production capability resource grant digest mismatch"
                )
        _validate_current_launch_generation_parents(
            request=request,
            request_authority=request_authority,
            observation_authority=observation_authority,
            semantic_work_plan=semantic_work_plan,
            global_reservation=global_reservation,
            launch_intent=launch_intent,
            launch_generation_authority=launch_generation_authority,
            _structural_test_token=_structural_test_token,
        )
        request_authority.validate_against(
            request=request,
            registry=registry,
            policy_entry=policy_entry,
            launch_intent=launch_intent,
            expected_model_policy_registry_digest=(
                expected_model_policy_registry_digest
            ),
            expected_policy_entry_digest=expected_policy_entry_digest,
            expected_launch_intent_digest=expected_launch_intent_digest,
            expected_semantic_requirement_digest=(
                expected_semantic_requirement_digest
            ),
            expected_resource_grant_digest=expected_resource_grant_digest,
            expected_tool_capability_manifest_digest=(
                expected_tool_capability_manifest_digest
            ),
        )
        expected_digests = (
            ("request_digest", self.request_digest, request.request_digest),
            (
                "request_authority_digest",
                self.request_authority_digest,
                request_authority.request_authority_digest,
            ),
            ("receipt_digest", self.receipt_digest, receipt.receipt_digest),
            (
                "launch_intent_digest",
                self.launch_intent_digest,
                launch_intent.launch_intent_digest,
            ),
            (
                "model_policy_registry_digest",
                self.model_policy_registry_digest,
                registry.registry_digest,
            ),
            (
                "policy_entry_digest",
                self.policy_entry_digest,
                policy_entry.policy_entry_digest,
            ),
            (
                "trusted_observation_root_digest",
                self.trusted_observation_root_digest,
                observation_authority.observation_root_digest,
            ),
            (
                "provider_observation_authority_digest",
                self.provider_observation_authority_digest,
                observation_authority.provider_observation_authority_digest,
            ),
            (
                "launch_generation_authority_digest",
                self.launch_generation_authority_digest,
                launch_generation_authority
                .launch_generation_authority_digest,
            ),
        )
        for field, actual, expected in expected_digests:
            if actual != expected:
                raise CapabilityRegistryError(
                    f"capability authority {field} mismatch"
                )
        if self.observation_generation != (
            observation_authority.evaluation_generation
        ):
            raise CapabilityRegistryError(
                "capability authority observation generation mismatch"
            )
        observation_authority.validate_receipt(
            receipt, launch_intent=launch_intent
        )
        receipt_intent = (
            receipt.backend,
            receipt.adapter_id,
            receipt.adapter_version,
            receipt.provider_cli_name,
            receipt.provider_cli_version,
            receipt.executable_sha256,
            receipt.executable_size_bytes,
            receipt.os_family,
            receipt.account_mode,
        )
        expected_intent = (
            launch_intent.backend,
            launch_intent.adapter_id,
            launch_intent.adapter_version,
            launch_intent.provider_cli_name,
            launch_intent.provider_cli_version,
            launch_intent.executable_sha256,
            launch_intent.executable_size_bytes,
            launch_intent.os_family,
            launch_intent.account_mode,
        )
        if receipt_intent != expected_intent:
            raise CapabilityRegistryError(
                "receipt does not match trusted launch intent"
            )
        if (
            receipt.semantic_model_capability_tier
            != policy_entry.semantic_model_capability_tier
            or receipt.exact_model_id != policy_entry.exact_model_id
            or receipt.reasoning_mode != policy_entry.reasoning_mode
        ):
            raise CapabilityRegistryError(
                "receipt does not match trusted model policy entry"
            )

    def validate_against(self, **parents: Any) -> None:
        """Production validation; structural replay is not an option."""

        if "_structural_test_token" in parents:
            raise CapabilityRegistryError(
                "production capability validation cannot accept a "
                "structural-test token"
            )
        self._validate_against(**parents)

    def validate_structural_test_against(
        self,
        **parents: Any,
    ) -> None:
        """Explicit test-only validation of structural promotion parents."""

        if "_structural_test_token" in parents:
            raise CapabilityRegistryError(
                "structural-test validation token is internally bound"
            )
        self._validate_against(
            **parents,
            _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
        )

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        **parents: Any,
    ) -> "BackendCapabilityAuthority":
        return cls._from_bytes(
            raw,
            parents=parents,
        )

    @classmethod
    def from_structural_test_bytes(
        cls,
        raw: bytes,
        **parents: Any,
    ) -> "BackendCapabilityAuthority":
        """Explicit test-only replay; output remains structural-only."""

        return cls._from_bytes(
            raw,
            parents=parents,
            _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
        )

    @classmethod
    def _from_bytes(
        cls,
        raw: bytes,
        *,
        parents: Mapping[str, Any],
        _structural_test_token: object = None,
    ) -> "BackendCapabilityAuthority":
        if cls is not BackendCapabilityAuthority:
            raise CapabilityRegistryError(
                "BackendCapabilityAuthority replay requires exact base class"
            )
        value = _decode_record(raw)
        _require_exact_keys(
            value,
            _CAPABILITY_AUTHORITY_KEYS,
            "backend capability authority",
        )
        if value["schema"] != BACKEND_CAPABILITY_AUTHORITY_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported backend capability authority schema"
            )
        claimed = _sha256(
            value["capability_authority_digest"],
            "capability_authority_digest",
        )
        try:
            bound_parents = BackendCapabilityPromotionParents(**parents)
        except TypeError as exc:
            raise CapabilityRegistryError(
                "backend capability replay parent denominator is not exact"
            ) from exc
        authority = cls(
            request_digest=value["request_digest"],
            request_authority_digest=value["request_authority_digest"],
            receipt_digest=value["receipt_digest"],
            launch_intent_digest=value["launch_intent_digest"],
            model_policy_registry_digest=value[
                "model_policy_registry_digest"
            ],
            policy_entry_digest=value["policy_entry_digest"],
            trusted_observation_root_digest=value[
                "trusted_observation_root_digest"
            ],
            provider_observation_authority_digest=value[
                "provider_observation_authority_digest"
            ],
            launch_generation_authority_digest=value[
                "launch_generation_authority_digest"
            ],
            observation_generation=value["observation_generation"],
            _bound_parents=bound_parents,
            _promotion_token=_AUTHORITY_PROMOTION_TOKEN,
        )
        if claimed != authority.capability_authority_digest:
            raise CapabilityRegistryError(
                "capability_authority_digest mismatch"
            )
        authority._validate_against(
            **parents,
            _structural_test_token=_structural_test_token,
        )
        return authority


def _promote_backend_capability_receipt(
    *,
    request: CapabilityPreflightRequest,
    request_authority: CapabilityRequestAuthority,
    receipt: BackendCapabilityReceipt,
    registry: ModelPolicyRegistry,
    policy_entry: ModelPolicyEntry,
    launch_intent: BackendLaunchIntent,
    expected_model_policy_registry_digest: str,
    expected_policy_entry_digest: str,
    expected_launch_intent_digest: str,
    expected_semantic_requirement_digest: str,
    expected_resource_grant_digest: str,
    expected_tool_capability_manifest_digest: str,
    observation_authority: ProviderObservationAuthority,
    semantic_work_plan: Any,
    global_reservation: Any,
    launch_generation_authority: ProviderLaunchGenerationAuthority,
    resource_grant: Any = None,
    resource_policy_authority: Any = None,
    _structural_test_token: object = None,
) -> BackendCapabilityAuthority:
    """Promote only after independent typed observation-authority replay."""

    request = _require_exact_capability_preflight_request(request)
    if type(request_authority) is not CapabilityRequestAuthority:
        raise CapabilityRegistryError(
            "exact capability request authority is required"
        )
    request_authority.require_exact_replay()
    receipt = _require_exact_backend_capability_receipt(receipt)
    if type(observation_authority) is not ProviderObservationAuthority:
        raise CapabilityRegistryError(
            "independent provider observation authority is required; "
            "a raw receipt/root cannot self-assert capability support"
        )
    observation_authority.require_exact_replay()
    _require_reviewed_adapter_identity(launch_intent)
    _validate_current_launch_generation_parents(
        request=request,
        request_authority=request_authority,
        observation_authority=observation_authority,
        semantic_work_plan=semantic_work_plan,
        global_reservation=global_reservation,
        launch_intent=launch_intent,
        launch_generation_authority=launch_generation_authority,
        _structural_test_token=_structural_test_token,
    )

    bound_parents = BackendCapabilityPromotionParents(
        request=request,
        request_authority=request_authority,
        receipt=receipt,
        registry=registry,
        policy_entry=policy_entry,
        launch_intent=launch_intent,
        expected_model_policy_registry_digest=(
            expected_model_policy_registry_digest
        ),
        expected_policy_entry_digest=expected_policy_entry_digest,
        expected_launch_intent_digest=expected_launch_intent_digest,
        expected_semantic_requirement_digest=(
            expected_semantic_requirement_digest
        ),
        expected_resource_grant_digest=expected_resource_grant_digest,
        expected_tool_capability_manifest_digest=(
            expected_tool_capability_manifest_digest
        ),
        observation_authority=observation_authority,
        semantic_work_plan=semantic_work_plan,
        global_reservation=global_reservation,
        launch_generation_authority=launch_generation_authority,
        resource_grant=resource_grant,
        resource_policy_authority=resource_policy_authority,
    )
    authority = BackendCapabilityAuthority(
        request_digest=request.request_digest,
        request_authority_digest=(
            request_authority.request_authority_digest
        ),
        receipt_digest=receipt.receipt_digest,
        launch_intent_digest=launch_intent.launch_intent_digest,
        model_policy_registry_digest=registry.registry_digest,
        policy_entry_digest=policy_entry.policy_entry_digest,
        trusted_observation_root_digest=(
            observation_authority.observation_root_digest
        ),
        provider_observation_authority_digest=(
            observation_authority.provider_observation_authority_digest
        ),
        launch_generation_authority_digest=(
            launch_generation_authority
            .launch_generation_authority_digest
        ),
        observation_generation=(
            observation_authority.evaluation_generation
        ),
        _bound_parents=bound_parents,
        _promotion_token=_AUTHORITY_PROMOTION_TOKEN,
    )
    authority._validate_against(
        request=request,
        request_authority=request_authority,
        receipt=receipt,
        registry=registry,
        policy_entry=policy_entry,
        launch_intent=launch_intent,
        expected_model_policy_registry_digest=(
            expected_model_policy_registry_digest
        ),
        expected_policy_entry_digest=expected_policy_entry_digest,
        expected_launch_intent_digest=expected_launch_intent_digest,
        expected_semantic_requirement_digest=(
            expected_semantic_requirement_digest
        ),
        expected_resource_grant_digest=expected_resource_grant_digest,
        expected_tool_capability_manifest_digest=(
            expected_tool_capability_manifest_digest
        ),
        observation_authority=observation_authority,
        semantic_work_plan=semantic_work_plan,
        global_reservation=global_reservation,
        launch_generation_authority=launch_generation_authority,
        resource_grant=resource_grant,
        resource_policy_authority=resource_policy_authority,
        _structural_test_token=_structural_test_token,
    )
    return authority


def promote_backend_capability_receipt(
    *,
    resource_grant: Any,
    resource_policy_authority: Any,
    **kwargs: Any,
) -> BackendCapabilityAuthority:
    """Production promotion; exact resource closure is mandatory."""

    return _promote_backend_capability_receipt(
        resource_grant=resource_grant,
        resource_policy_authority=resource_policy_authority,
        **kwargs,
    )


def promote_structural_test_backend_capability_receipt(
    **kwargs: Any,
) -> BackendCapabilityAuthority:
    """Explicit test-only promotion; never valid at production evaluators."""

    return _promote_backend_capability_receipt(
        **kwargs,
        _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
    )


@dataclass(frozen=True, slots=True)
class CapabilityDebt:
    debt_code: str
    subject: str
    observed_state: str
    evidence_digest: str

    def __post_init__(self) -> None:
        _closed(self.debt_code, DEBT_CODES, "debt_code")
        _safe_id(self.subject, "subject")
        _closed(self.observed_state, CAPABILITY_STATES, "observed_state")
        _sha256(self.evidence_digest, "evidence_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "debt_code": self.debt_code,
            "subject": self.subject,
            "observed_state": self.observed_state,
            "evidence_digest": self.evidence_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityDebt":
        _require_exact_keys(value, _DEBT_KEYS, "capability debt")
        return cls(
            debt_code=value["debt_code"],
            subject=value["subject"],
            observed_state=value["observed_state"],
            evidence_digest=value["evidence_digest"],
        )


@dataclass(frozen=True, slots=True)
class CapabilityPreflightDecision:
    request_digest: str
    receipt_digest: str
    capability_authority_digest: str
    eligible: bool
    debts: tuple[CapabilityDebt, ...]
    _derivation_token: InitVar[object] = None

    schema: ClassVar[str] = CAPABILITY_PREFLIGHT_DECISION_SCHEMA

    def __post_init__(self, _derivation_token: object) -> None:
        if _derivation_token is not _DERIVATION_TOKEN:
            raise CapabilityRegistryError(
                "preflight decision requires evaluator derivation"
            )
        _sha256(self.request_digest, "request_digest")
        _sha256(self.receipt_digest, "receipt_digest")
        _sha256(
            self.capability_authority_digest,
            "capability_authority_digest",
        )
        if type(self.eligible) is not bool:
            raise CapabilityRegistryError("eligible must be boolean")
        debts = tuple(
            sorted(self.debts, key=lambda row: (row.debt_code, row.subject))
        )
        if not all(isinstance(row, CapabilityDebt) for row in debts):
            raise CapabilityRegistryError(
                "debts must contain CapabilityDebt records"
            )
        if self.eligible != (not debts):
            raise CapabilityRegistryError(
                "eligible must equal an empty debt denominator"
            )
        object.__setattr__(self, "debts", debts)

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "request_digest": self.request_digest,
            "receipt_digest": self.receipt_digest,
            "capability_authority_digest": (
                self.capability_authority_digest
            ),
            "eligible": self.eligible,
            "debts": [row.to_dict() for row in self.debts],
        }

    @property
    def decision_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "decision_digest": self.decision_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        request: CapabilityPreflightRequest,
        receipt: BackendCapabilityReceipt,
        authority: BackendCapabilityAuthority,
    ) -> "CapabilityPreflightDecision":
        return cls._from_bytes(
            raw,
            request=request,
            receipt=receipt,
            authority=authority,
        )

    @classmethod
    def from_structural_test_bytes(
        cls,
        raw: bytes,
        *,
        request: CapabilityPreflightRequest,
        receipt: BackendCapabilityReceipt,
        authority: BackendCapabilityAuthority,
    ) -> "CapabilityPreflightDecision":
        return cls._from_bytes(
            raw,
            request=request,
            receipt=receipt,
            authority=authority,
            _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
        )

    @classmethod
    def _from_bytes(
        cls,
        raw: bytes,
        *,
        request: CapabilityPreflightRequest,
        receipt: BackendCapabilityReceipt,
        authority: BackendCapabilityAuthority,
        _structural_test_token: object = None,
    ) -> "CapabilityPreflightDecision":
        value = _decode_record(raw)
        _require_exact_keys(
            value, _DECISION_KEYS, "capability preflight decision"
        )
        if value["schema"] != CAPABILITY_PREFLIGHT_DECISION_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported capability preflight decision schema"
            )
        claimed = _sha256(
            value["decision_digest"], "decision_digest"
        )
        replayed = _evaluate_capability_preflight(
            request,
            receipt,
            authority=authority,
            _structural_test_token=_structural_test_token,
        )
        if claimed != replayed.decision_digest or value != replayed.to_dict():
            raise CapabilityRegistryError(
                "capability preflight decision does not match replay"
            )
        return replayed


def _synthetic_debt(
    code: str,
    subject: str,
    receipt: BackendCapabilityReceipt,
    *,
    state: str = "UNSUPPORTED",
) -> CapabilityDebt:
    return CapabilityDebt(
        debt_code=code,
        subject=subject,
        observed_state=state,
        evidence_digest=receipt.receipt_digest,
    )


def _evaluate_capability_preflight(
    request: CapabilityPreflightRequest,
    receipt: BackendCapabilityReceipt,
    *,
    authority: BackendCapabilityAuthority | None = None,
    _structural_test_token: object = None,
) -> CapabilityPreflightDecision:
    """Evaluate the strict capability intersection without fallback."""

    request = _require_exact_capability_preflight_request(request)
    receipt = _require_exact_backend_capability_receipt(receipt)
    if type(authority) is not BackendCapabilityAuthority:
        raise CapabilityRegistryError(
            "capability authority is required; a raw receipt cannot be "
            "evaluated as trusted preflight"
        )
    authority._validate_bound_parents(
        _structural_test_token=_structural_test_token,
    )
    if (
        authority.request_digest != request.request_digest
        or authority.receipt_digest != receipt.receipt_digest
    ):
        raise CapabilityRegistryError(
            "capability authority does not bind request and receipt"
        )
    debts: list[CapabilityDebt] = []
    if (
        request.semantic_model_capability_tier
        != receipt.semantic_model_capability_tier
    ):
        debts.append(
            _synthetic_debt(
                "MODEL_TIER_UNMATCHED",
                "semantic_model_capability_tier",
                receipt,
            )
        )
    if request.exact_model_id != receipt.exact_model_id:
        debts.append(
            _synthetic_debt(
                "MODEL_ID_UNMATCHED", "exact_model_id", receipt
            )
        )
    if request.reasoning_mode != receipt.reasoning_mode:
        debts.append(
            _synthetic_debt(
                "CX_REASONING_CONTROL_UNKNOWN",
                "reasoning_mode",
                receipt,
            )
        )
    if (
        receipt.context_window_tokens
        < request.minimum_context_window_tokens
    ):
        debts.append(
            _synthetic_debt(
                "CONTEXT_LIMIT_INSUFFICIENT",
                "context_window_tokens",
                receipt,
            )
        )
    if receipt.max_native_commands < request.minimum_native_commands:
        debts.append(
            _synthetic_debt(
                "NATIVE_TOOLCHAIN_UNMATCHED",
                "max_native_commands",
                receipt,
            )
        )
    if (
        receipt.max_native_wall_time_seconds
        < request.minimum_native_wall_time_seconds
    ):
        debts.append(
            _synthetic_debt(
                "NATIVE_TOOLCHAIN_UNMATCHED",
                "max_native_wall_time_seconds",
                receipt,
            )
        )
    if receipt.max_output_tokens < request.minimum_output_tokens:
        debts.append(
            _synthetic_debt(
                "OUTPUT_LIMIT_INSUFFICIENT", "max_output_tokens", receipt
            )
        )
    if (
        receipt.max_tool_calls_total
        < request.maximum_tool_calls_required
    ):
        debts.append(
            _synthetic_debt(
                "TOOL_LIMIT_INSUFFICIENT",
                "max_tool_calls_total",
                receipt,
            )
        )

    by_capability = {row.capability: row for row in receipt.capabilities}
    for name in request.required_capabilities:
        observed = by_capability[name]
        if observed.state != "SUPPORTED_AND_ENFORCED":
            debts.append(
                CapabilityDebt(
                    debt_code=observed.debt_code or "CAPABILITY_UNKNOWN",
                    subject=name,
                    observed_state=observed.state,
                    evidence_digest=observed.evidence_digest,
                )
            )

    by_tool = {
        row.tool_capability: row for row in receipt.tool_capabilities
    }
    for required in request.required_tools:
        observed = by_tool.get(required.tool_capability)
        if observed is None:
            debts.append(
                CapabilityDebt(
                    debt_code="CX_TOOL_POLICY_UNENFORCED",
                    subject=required.tool_capability,
                    observed_state="UNSUPPORTED",
                    evidence_digest=receipt.receipt_digest,
                )
            )
            continue
        if observed.state != "SUPPORTED_AND_ENFORCED":
            debts.append(
                CapabilityDebt(
                    debt_code=(
                        observed.debt_code
                        or "CX_TOOL_POLICY_UNENFORCED"
                    ),
                    subject=required.tool_capability,
                    observed_state=observed.state,
                    evidence_digest=observed.evidence_digest,
                )
            )
        elif observed.max_calls < required.required_calls:
            debts.append(
                CapabilityDebt(
                    debt_code="TOOL_LIMIT_INSUFFICIENT",
                    subject=required.tool_capability,
                    observed_state=observed.state,
                    evidence_digest=observed.evidence_digest,
                )
            )

    # A request may list the same semantic failure through two constraints
    # only when the subjects differ.  Exact duplicates are collapsed
    # deterministically; no debt is silently discarded by code alone.
    unique = {
        (
            row.debt_code,
            row.subject,
            row.observed_state,
            row.evidence_digest,
        ): row
        for row in debts
    }
    ordered = tuple(
        sorted(unique.values(), key=lambda row: (row.debt_code, row.subject))
    )
    return CapabilityPreflightDecision(
        request_digest=request.request_digest,
        receipt_digest=receipt.receipt_digest,
        capability_authority_digest=(
            authority.capability_authority_digest
        ),
        eligible=not ordered,
        debts=ordered,
        _derivation_token=_DERIVATION_TOKEN,
    )


def evaluate_capability_preflight(
    request: CapabilityPreflightRequest,
    receipt: BackendCapabilityReceipt,
    *,
    authority: BackendCapabilityAuthority | None = None,
) -> CapabilityPreflightDecision:
    """Production evaluator; structural authorities are rejected."""

    return _evaluate_capability_preflight(
        request,
        receipt,
        authority=authority,
    )


def evaluate_structural_test_capability_preflight(
    request: CapabilityPreflightRequest,
    receipt: BackendCapabilityReceipt,
    *,
    authority: BackendCapabilityAuthority | None = None,
) -> CapabilityPreflightDecision:
    """Explicit test-only evaluator for structural authority fixtures."""

    return _evaluate_capability_preflight(
        request,
        receipt,
        authority=authority,
        _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
    )


def _validate_capability_arm_parents(
    *,
    request: CapabilityPreflightRequest,
    request_authority: CapabilityRequestAuthority,
    receipt: BackendCapabilityReceipt,
    capability_authority: BackendCapabilityAuthority,
    expected_resource_authority_class: str,
) -> None:
    _require_exact_capability_preflight_request(request)
    if type(request_authority) is not CapabilityRequestAuthority:
        raise CapabilityRegistryError(
            "arm request authority is required"
        )
    request_authority.require_exact_replay()
    if type(receipt) is not BackendCapabilityReceipt:
        raise CapabilityRegistryError(
            "arm receipt must be BackendCapabilityReceipt"
        )
    receipt.require_exact_replay()
    if type(capability_authority) is not BackendCapabilityAuthority:
        raise CapabilityRegistryError(
            "arm capability authority is required"
        )
    if expected_resource_authority_class == (
        "PRODUCTION_RESOURCE_AUTHORIZED"
    ):
        capability_authority.validate_bound_parents()
    elif expected_resource_authority_class == "STRUCTURAL_TEST_ONLY":
        capability_authority.validate_structural_test_bound_parents()
    else:
        raise CapabilityRegistryError(
            "capability arm expected resource class is invalid"
        )
    if (
        capability_authority.resource_authority_class
        != expected_resource_authority_class
    ):
        raise CapabilityRegistryError(
            "capability arm resource class is not valid for "
            + (
                "production"
                if expected_resource_authority_class
                == "PRODUCTION_RESOURCE_AUTHORIZED"
                else "structural test"
            )
            + " replay"
        )
    if (
        request_authority.request_digest != request.request_digest
        or capability_authority.request_authority_digest
        != request_authority.request_authority_digest
        or capability_authority.request_digest
        != request.request_digest
        or capability_authority.receipt_digest
        != receipt.receipt_digest
    ):
        raise CapabilityRegistryError(
            "capability arm parent digests do not close"
        )


@dataclass(frozen=True, slots=True)
class CapabilityArm:
    """Production in-memory exact parents for one replayable paired arm."""

    request: CapabilityPreflightRequest
    request_authority: CapabilityRequestAuthority
    receipt: BackendCapabilityReceipt
    capability_authority: BackendCapabilityAuthority

    def __post_init__(self) -> None:
        _validate_capability_arm_parents(
            request=self.request,
            request_authority=self.request_authority,
            receipt=self.receipt,
            capability_authority=self.capability_authority,
            expected_resource_authority_class=(
                "PRODUCTION_RESOURCE_AUTHORIZED"
            ),
        )

    @property
    def decision(self) -> CapabilityPreflightDecision:
        return evaluate_capability_preflight(
            self.request,
            self.receipt,
            authority=self.capability_authority,
        )


@dataclass(frozen=True, slots=True)
class StructuralTestCapabilityArm:
    """Explicit structural-test arm; never accepted by production compare."""

    request: CapabilityPreflightRequest
    request_authority: CapabilityRequestAuthority
    receipt: BackendCapabilityReceipt
    capability_authority: BackendCapabilityAuthority

    def __post_init__(self) -> None:
        _validate_capability_arm_parents(
            request=self.request,
            request_authority=self.request_authority,
            receipt=self.receipt,
            capability_authority=self.capability_authority,
            expected_resource_authority_class="STRUCTURAL_TEST_ONLY",
        )

    @property
    def structural_test_decision(self) -> CapabilityPreflightDecision:
        return evaluate_structural_test_capability_preflight(
            self.request,
            self.receipt,
            authority=self.capability_authority,
        )


_PAIRED_CAPABILITY_FIELD_ORDER = (
    "model_policy_registry_digest",
    "semantic_requirement_digest",
    "resource_grant_digest",
    "tool_capability_manifest_digest",
    "semantic_model_capability_tier",
    "reasoning_mode",
    "minimum_context_window_tokens",
    "minimum_output_tokens",
    "maximum_tool_calls_required",
    "minimum_native_commands",
    "minimum_native_wall_time_seconds",
    "required_capabilities",
    "required_tools",
    "distinct_backend_arms",
    "left_eligible",
    "right_eligible",
)


@dataclass(frozen=True, slots=True)
class PairedCapabilityComparison:
    left_request_digest: str
    right_request_digest: str
    left_receipt_digest: str
    right_receipt_digest: str
    left_decision_digest: str
    right_decision_digest: str
    semantic_requirement_digest: str
    resource_grant_digest: str
    tool_capability_manifest_digest: str
    state: str
    mismatch_fields: tuple[str, ...]
    _derivation_token: InitVar[object] = None

    schema: ClassVar[str] = PAIRED_CAPABILITY_COMPARISON_SCHEMA

    def __post_init__(self, _derivation_token: object) -> None:
        if _derivation_token is not _DERIVATION_TOKEN:
            raise CapabilityRegistryError(
                "paired capability comparison requires replay derivation"
            )
        for field in (
            "left_request_digest",
            "right_request_digest",
            "left_receipt_digest",
            "right_receipt_digest",
            "left_decision_digest",
            "right_decision_digest",
            "semantic_requirement_digest",
            "resource_grant_digest",
            "tool_capability_manifest_digest",
        ):
            _sha256(getattr(self, field), field)
        _closed(
            self.state, frozenset({"MATCHED", "UNMATCHED"}), "state"
        )
        fields = tuple(self.mismatch_fields)
        if len(fields) != len(set(fields)) or any(
            field not in _PAIRED_CAPABILITY_FIELD_ORDER for field in fields
        ):
            raise CapabilityRegistryError(
                "paired capability mismatch_fields is invalid"
            )
        if (self.state == "MATCHED") != (not fields):
            raise CapabilityRegistryError(
                "paired capability state must match mismatch_fields"
            )
        object.__setattr__(self, "mismatch_fields", fields)

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "left_request_digest": self.left_request_digest,
            "right_request_digest": self.right_request_digest,
            "left_receipt_digest": self.left_receipt_digest,
            "right_receipt_digest": self.right_receipt_digest,
            "left_decision_digest": self.left_decision_digest,
            "right_decision_digest": self.right_decision_digest,
            "semantic_requirement_digest": (
                self.semantic_requirement_digest
            ),
            "resource_grant_digest": self.resource_grant_digest,
            "tool_capability_manifest_digest": (
                self.tool_capability_manifest_digest
            ),
            "state": self.state,
            "mismatch_fields": list(self.mismatch_fields),
        }

    @property
    def comparison_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "comparison_digest": self.comparison_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def require_matched(self) -> None:
        if self.state != "MATCHED":
            raise CapabilityRegistryError(
                "paired capabilities differ: "
                + ", ".join(self.mismatch_fields)
            )

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        left: CapabilityArm,
        right: CapabilityArm,
    ) -> "PairedCapabilityComparison":
        return cls._from_bytes(
            raw,
            left=left,
            right=right,
        )

    @classmethod
    def from_structural_test_bytes(
        cls,
        raw: bytes,
        *,
        left: CapabilityArm,
        right: CapabilityArm,
    ) -> "PairedCapabilityComparison":
        return cls._from_bytes(
            raw,
            left=left,
            right=right,
            _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
        )

    @classmethod
    def _from_bytes(
        cls,
        raw: bytes,
        *,
        left: CapabilityArm,
        right: CapabilityArm,
        _structural_test_token: object = None,
    ) -> "PairedCapabilityComparison":
        value = _decode_record(raw)
        _require_exact_keys(
            value, _PAIRED_CAPABILITY_KEYS, "paired capability comparison"
        )
        if value["schema"] != PAIRED_CAPABILITY_COMPARISON_SCHEMA:
            raise CapabilityRegistryError(
                "unsupported paired capability comparison schema"
            )
        replayed = _compare_paired_capability_arms(
            left,
            right,
            _structural_test_token=_structural_test_token,
        )
        if value != replayed.to_dict():
            raise CapabilityRegistryError(
                "paired capability comparison does not match replay"
            )
        return replayed


def _compare_paired_capability_arms(
    left: Any,
    right: Any,
    *,
    _structural_test_token: object = None,
) -> PairedCapabilityComparison:
    expected_arm_type = (
        StructuralTestCapabilityArm
        if _structural_test_token is _STRUCTURAL_TEST_BACKEND_TOKEN
        else CapabilityArm
    )
    if type(left) is not expected_arm_type or type(right) is not (
        expected_arm_type
    ):
        raise CapabilityRegistryError(
            "paired capability comparison requires two exact "
            f"{expected_arm_type.__name__} records"
        )
    if _structural_test_token is _STRUCTURAL_TEST_BACKEND_TOKEN:
        left_decision = left.structural_test_decision
        right_decision = right.structural_test_decision
    else:
        left_decision = left.decision
        right_decision = right.decision
    left_caps = tuple(
        cap
        for cap in left.request.required_capabilities
        if cap not in {"PTY_TRANSPORT", "HEADLESS_TRANSPORT"}
    )
    right_caps = tuple(
        cap
        for cap in right.request.required_capabilities
        if cap not in {"PTY_TRANSPORT", "HEADLESS_TRANSPORT"}
    )
    values = {
        "model_policy_registry_digest": (
            left.request_authority.model_policy_registry_digest,
            right.request_authority.model_policy_registry_digest,
        ),
        "semantic_requirement_digest": (
            left.request_authority.semantic_requirement_digest,
            right.request_authority.semantic_requirement_digest,
        ),
        "resource_grant_digest": (
            left.request_authority.resource_grant_digest,
            right.request_authority.resource_grant_digest,
        ),
        "tool_capability_manifest_digest": (
            left.request_authority.tool_capability_manifest_digest,
            right.request_authority.tool_capability_manifest_digest,
        ),
        "semantic_model_capability_tier": (
            left.request.semantic_model_capability_tier,
            right.request.semantic_model_capability_tier,
        ),
        "reasoning_mode": (
            left.request.reasoning_mode,
            right.request.reasoning_mode,
        ),
        "minimum_context_window_tokens": (
            left.request.minimum_context_window_tokens,
            right.request.minimum_context_window_tokens,
        ),
        "minimum_output_tokens": (
            left.request.minimum_output_tokens,
            right.request.minimum_output_tokens,
        ),
        "maximum_tool_calls_required": (
            left.request.maximum_tool_calls_required,
            right.request.maximum_tool_calls_required,
        ),
        "minimum_native_commands": (
            left.request.minimum_native_commands,
            right.request.minimum_native_commands,
        ),
        "minimum_native_wall_time_seconds": (
            left.request.minimum_native_wall_time_seconds,
            right.request.minimum_native_wall_time_seconds,
        ),
        "required_capabilities": (left_caps, right_caps),
        "required_tools": (
            left.request.required_tools,
            right.request.required_tools,
        ),
        "distinct_backend_arms": (
            left.receipt.backend != right.receipt.backend,
            True,
        ),
        "left_eligible": (left_decision.eligible, True),
        "right_eligible": (right_decision.eligible, True),
    }
    mismatches = tuple(
        field
        for field in _PAIRED_CAPABILITY_FIELD_ORDER
        if values[field][0] != values[field][1]
    )
    # These are common parents only when matched.  An unmatched receipt still
    # records the left authority value without inventing a synthetic identity.
    return PairedCapabilityComparison(
        left_request_digest=left.request.request_digest,
        right_request_digest=right.request.request_digest,
        left_receipt_digest=left.receipt.receipt_digest,
        right_receipt_digest=right.receipt.receipt_digest,
        left_decision_digest=left_decision.decision_digest,
        right_decision_digest=right_decision.decision_digest,
        semantic_requirement_digest=(
            left.request_authority.semantic_requirement_digest
        ),
        resource_grant_digest=(
            left.request_authority.resource_grant_digest
        ),
        tool_capability_manifest_digest=(
            left.request_authority.tool_capability_manifest_digest
        ),
        state="MATCHED" if not mismatches else "UNMATCHED",
        mismatch_fields=mismatches,
        _derivation_token=_DERIVATION_TOKEN,
    )


def compare_paired_capability_arms(
    left: CapabilityArm,
    right: CapabilityArm,
) -> PairedCapabilityComparison:
    """Production comparison; structural arms are rejected."""

    return _compare_paired_capability_arms(left, right)


def compare_structural_test_paired_capability_arms(
    left: StructuralTestCapabilityArm,
    right: StructuralTestCapabilityArm,
) -> PairedCapabilityComparison:
    """Explicit test-only paired comparison."""

    return _compare_paired_capability_arms(
        left,
        right,
        _structural_test_token=_STRUCTURAL_TEST_BACKEND_TOKEN,
    )


__all__ = [
    "ACCOUNT_MODES",
    "BACKENDS",
    "BACKEND_CAPABILITY_AUTHORITY_SCHEMA",
    "BACKEND_CAPABILITY_RECEIPT_SCHEMA",
    "BACKEND_LAUNCH_INTENT_SCHEMA",
    "BackendCapabilityAuthority",
    "BackendCapabilityPromotionParents",
    "BackendCapabilityReceipt",
    "BackendLaunchIntent",
    "BLUEPRINT_DEBT_CODES",
    "CAPABILITY_NAMES",
    "CAPABILITY_PREFLIGHT_DECISION_SCHEMA",
    "CAPABILITY_PREFLIGHT_REQUEST_SCHEMA",
    "CAPABILITY_STATES",
    "CAPABILITY_REQUEST_AUTHORITY_SCHEMA",
    "CAPABILITY_REQUEST_COMPILER_VERSION",
    "CAPABILITY_SPECIFIC_DEBT_CODES",
    "CapabilityArm",
    "CapabilityDebt",
    "CapabilityObservation",
    "CapabilityPreflightDecision",
    "CapabilityPreflightRequest",
    "CapabilityRequestAuthority",
    "CapabilityRegistryError",
    "DEBT_CODES",
    "MODEL_POLICY_REGISTRY_SCHEMA",
    "ModelPolicyEntry",
    "ModelPolicyRegistry",
    "OS_FAMILIES",
    "PAIRED_CAPABILITY_COMPARISON_SCHEMA",
    "PROVIDER_OBSERVATION_AUTHORITY_SCHEMA",
    "PROVIDER_OBSERVATION_RECORD_SCHEMA",
    "PROVIDER_OBSERVATION_SOURCE_CONTRACTS",
    "PROVIDER_PREPARATION_STATES",
    "PairedCapabilityComparison",
    "ProviderObservationAuthority",
    "ProviderObservationRecord",
    "ProviderObservationRootAuthority",
    "ProviderLaunchGenerationAuthority",
    "ProviderPreparationAuthority",
    "REASONING_MODES",
    "SEMANTIC_MODEL_CAPABILITY_TIERS",
    "SEMANTIC_TOOL_CAPABILITIES",
    "StructuralTestCapabilityArm",
    "ToolCapabilityObservation",
    "ToolCapabilityRequirement",
    "compare_paired_capability_arms",
    "compare_structural_test_paired_capability_arms",
    "bind_claude_provider_preparation_authority",
    "bind_provider_launch_generation_authority",
    "bind_structural_test_provider_launch_generation_authority",
    "bind_unavailable_provider_preparation_authority",
    "evaluate_capability_preflight",
    "evaluate_structural_test_capability_preflight",
    "promote_backend_capability_receipt",
    "promote_structural_test_backend_capability_receipt",
    "replay_provider_observation_authority",
]
