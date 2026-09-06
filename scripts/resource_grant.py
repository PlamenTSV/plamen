"""Closed backend-neutral semantic resource grants for ``semantic_v1``.

Semantic budgets and transport grace are separate records.  A grace record
can authorize bounded launch/drain/cleanup time only; its schema has no token,
tool, native-command, attempt, or semantic-timeout expansion fields.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import InitVar, dataclass, field
import hashlib
import re
import threading
from typing import Any, ClassVar, NoReturn
import weakref

from backend_capability_registry import (
    SEMANTIC_TOOL_CAPABILITIES,
    BackendLaunchIntent,
    CapabilityPreflightRequest,
    CapabilityRegistryError,
    CapabilityRequestAuthority,
    ModelPolicyEntry,
    ModelPolicyRegistry,
    ToolCapabilityRequirement,
    _compile_capability_preflight_request,
)
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)
from resource_policy_authority import (
    GlobalResourceReservation,
    ParityPolicyAuthority,
    ResourceAuthorityDebt,
    ResourcePolicyAuthority,
    ResourcePolicyError,
)
from semantic_work_plan import (
    BackendArmExecutionIdentity,
    ExecutionAttemptIdentity,
    RetryPolicy,
    SemanticAttemptBundle,
    SemanticExecutionBundle,
    SemanticWorkPlan,
)


RESOURCE_GRANT_SCHEMA = "plamen.resource-grant.v1"
TRANSPORT_GRACE_SCHEMA = "plamen.transport-grace.v1"
PAIRED_RESOURCE_COMPARISON_SCHEMA = (
    "plamen.paired-resource-comparison.v1"
)
TRANSPORT_PLAN_SCHEMA = "plamen.transport-plan.v1"
RESUME_REQUIREMENT_AUTHORITY_SCHEMA = (
    "plamen.resume-requirement-authority.v1"
)

RESOURCE_PROFILES = frozenset({"adaptive-au-v1"})
AUDIT_MODES = frozenset({"light", "core", "thorough"})
WORKLOAD_CLASSES = frozenset(
    {
        "STANDARD_ANALYSIS",
        "PROOF_CAPABLE",
        "REPORT_BODY",
        "NATIVE_DETERMINISTIC",
    }
)
SCHEDULER_CONCURRENCY_CLASSES = frozenset(
    {"SERIAL", "STRICT_PAIRED", "BOUNDED_POOL"}
)
CACHE_POLICIES = frozenset(
    {
        "COLD_REQUIRED",
        "WARM_RECORDED",
        "CACHE_DISABLED",
        "PROVIDER_DEFAULT_BOUND",
    }
)
PARITY_MODES = frozenset({"NON_PAIRED_OPERATIONAL", "STRICT_PAIRED"})
TRANSPORT_GRACE_REASONS = frozenset(
    {
        "PROCESS_STARTUP_ONLY",
        "PROCESS_DRAIN_ONLY",
        "STREAM_FLUSH_ONLY",
        "CANCELLATION_CLEANUP_ONLY",
    }
)

MIN_RUNNABLE_INPUT_TOKENS = 32_768
MIN_RUNNABLE_OUTPUT_TOKENS = 2_048

_CLASS_LIMITS: dict[str, tuple[int, int | None, int | None, int]] = {
    # analysis_units, input ceiling, output ceiling, aggregate tool ceiling
    "STANDARD_ANALYSIS": (1, 65_536, 8_192, 24),
    "PROOF_CAPABLE": (2, 131_072, 12_288, 48),
    # A report channel costs one AU, so it retains the one-AU token ceilings.
    "REPORT_BODY": (1, 65_536, 8_192, 12),
    "NATIVE_DETERMINISTIC": (0, 0, 0, 0),
}
_MAX_MODEL_ATTEMPTS = 2
_MAX_CONCURRENCY = 4
_NATIVE_COMMAND_TOOL_CAPABILITIES = frozenset(
    {
        "STATIC_ANALYZER_QUERY",
        "NATIVE_BUILD",
        "NATIVE_TEST",
        "NATIVE_FUZZ",
        "VERSION_PROBE",
    }
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,191}$", re.ASCII)
_SENSITIVE_RE = re.compile(
    r"(?:\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{16,}\b"
    r"|\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE | re.ASCII,
)
_DERIVATION_TOKEN = object()
_RESUME_REQUIREMENT_AUTHORITY_TOKEN = object()
_STRUCTURAL_TEST_RESOURCE_TOKEN = object()
_BUDGET_SCOPE = "PER_ATTEMPT_CEILINGS_WITH_WORST_CASE_TOTALS"

_TOOL_LIMIT_KEYS = frozenset({"tool_capability", "max_calls"})
_GRANT_KEYS = frozenset(
    {
        "schema",
        "profile",
        "audit_mode",
        "semantic_work_unit_id",
        "phase_semantic_id",
        "resource_policy_digest",
        "global_reservation_digest",
        "parity_policy_digest",
        "parity_mode",
        "workload_class",
        "analysis_units",
        "max_reserved_analysis_units",
        "max_input_tokens",
        "max_output_tokens",
        "tool_call_limits",
        "max_tool_calls",
        "max_native_commands",
        "max_native_wall_time_seconds",
        "max_model_attempts",
        "max_execution_attempts",
        "semantic_timeout_seconds",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "max_stream_line_bytes",
        "scheduler_concurrency_class",
        "max_concurrency",
        "cache_policy",
        "budget_scope",
        "worst_case_totals",
        "resource_grant_digest",
    }
)
_GRACE_KEYS = frozenset(
    {
        "schema",
        "resource_grant_digest",
        "parity_policy_digest",
        "semantic_work_unit_id",
        "attempt_number",
        "use_id",
        "authorized_max_grace_seconds",
        "parity_mode",
        "grace_seconds",
        "reason_code",
        "transport_grace_digest",
    }
)
_COMPARISON_KEYS = frozenset(
    {
        "schema",
        "left_resource_grant_digest",
        "right_resource_grant_digest",
        "state",
        "equal",
        "strict_paired_eligible",
        "eligibility_debts",
        "left_transport_plan_digest",
        "right_transport_plan_digest",
        "mismatch_fields",
        "comparison_digest",
    }
)
_RESOURCE_FIELD_ORDER = (
    "profile",
    "audit_mode",
    "semantic_work_unit_id",
    "phase_semantic_id",
    "resource_policy_digest",
    "global_reservation_digest",
    "parity_policy_digest",
    "parity_mode",
    "workload_class",
    "analysis_units",
    "max_reserved_analysis_units",
    "max_input_tokens",
    "max_output_tokens",
    "tool_call_limits",
    "max_tool_calls",
    "max_native_commands",
    "max_native_wall_time_seconds",
    "max_model_attempts",
    "max_execution_attempts",
    "semantic_timeout_seconds",
    "max_stdout_bytes",
    "max_stderr_bytes",
    "max_stream_line_bytes",
    "scheduler_concurrency_class",
    "max_concurrency",
    "cache_policy",
    "budget_scope",
    "worst_case_totals",
)
_WORST_CASE_TOTAL_KEYS = frozenset(
    {
        "reserved_analysis_units",
        "input_tokens",
        "output_tokens",
        "tool_calls",
        "native_commands",
        "native_wall_time_seconds",
        "semantic_timeout_seconds",
        "stdout_bytes",
        "stderr_bytes",
    }
)


class ResourceGrantError(ValueError):
    """A resource grant is open, noncanonical, or budget-inconsistent."""

    def __init__(
        self,
        message: str,
        *,
        debt: ResourceAuthorityDebt | None = None,
    ) -> None:
        super().__init__(message)
        self.debt = debt


class _ResourceGrantSealRegistry:
    """Canonical snapshots rooted in exact live-object identity."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[
            int, tuple[weakref.ReferenceType[Any], bytes]
        ] = {}

    def issue(self, value: Any, canonical: bytes) -> None:
        identity = id(value)

        def retire(reference: weakref.ReferenceType[Any]) -> None:
            with self._lock:
                current = self._entries.get(identity)
                if current is not None and current[0] is reference:
                    self._entries.pop(identity, None)

        reference = weakref.ref(value, retire)
        with self._lock:
            self._entries[identity] = (reference, bytes(canonical))

    def require(self, value: Any, canonical: bytes) -> bytes:
        if type(value) is not ResourceGrant:
            raise ResourceGrantError(
                "exact ResourceGrant runtime type is required"
            )
        with self._lock:
            current = self._entries.get(id(value))
            if current is None or current[0]() is not value:
                raise ResourceGrantError(
                    "resource grant external issuance seal is absent"
                )
            sealed = current[1]
        if type(canonical) is not bytes or canonical != sealed:
            raise ResourceGrantError("resource grant seal/replay drifted")
        return bytes(sealed)


_RESOURCE_GRANT_SEALS = _ResourceGrantSealRegistry()


class _ResumeAuthoritySealRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[
            int, tuple[weakref.ReferenceType[Any], bytes]
        ] = {}

    def issue(self, value: Any, canonical: bytes) -> None:
        identity = id(value)

        def retire(reference: weakref.ReferenceType[Any]) -> None:
            with self._lock:
                current = self._entries.get(identity)
                if current is not None and current[0] is reference:
                    self._entries.pop(identity, None)

        reference = weakref.ref(value, retire)
        with self._lock:
            self._entries[identity] = (reference, bytes(canonical))

    def require(self, value: Any, canonical: bytes) -> bytes:
        if type(value) is not ResumeRequirementAuthority:
            raise ResourceGrantError(
                "exact resume requirement authority is required"
            )
        with self._lock:
            current = self._entries.get(id(value))
            if current is None or current[0]() is not value:
                raise ResourceGrantError(
                    "resume requirement authority issuance seal is absent"
                )
            sealed = current[1]
        if canonical != sealed:
            raise ResourceGrantError(
                "resume requirement authority seal/replay drifted"
            )
        return bytes(sealed)


_RESUME_REQUIREMENT_AUTHORITY_SEALS = _ResumeAuthoritySealRegistry()


def _raise_as_resource_error(exc: Exception) -> NoReturn:
    raise ResourceGrantError(str(exc)) from exc


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_json_bytes(value)
    except ProgramFactsTypeError as exc:
        _raise_as_resource_error(exc)


def _canonical_file(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_file_bytes(value)
    except ProgramFactsTypeError as exc:
        _raise_as_resource_error(exc)


def _decode_record(raw: bytes) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(raw, require_final_lf=True)
    except ProgramFactsTypeError as exc:
        _raise_as_resource_error(exc)
    if not isinstance(value, Mapping):
        raise ResourceGrantError("record must be a JSON object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    if not isinstance(value, Mapping):
        raise ResourceGrantError(f"{context} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    reasons: list[str] = []
    if missing:
        reasons.append("missing fields: " + ", ".join(missing))
    if extra:
        reasons.append("unexpected fields: " + ", ".join(extra))
    if reasons:
        raise ResourceGrantError(f"{context} " + "; ".join(reasons))


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        raise ResourceGrantError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _safe_id(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or _ID_RE.fullmatch(value) is None
        or value in {".", ".."}
        or _SENSITIVE_RE.search(value)
    ):
        raise ResourceGrantError(
            f"{field} must be a privacy-safe ASCII identity"
        )
    return value


def _closed(value: Any, allowed: frozenset[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ResourceGrantError(
            f"{field} must be one of {', '.join(sorted(allowed))}"
        )
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise ResourceGrantError(f"{field} must be an integer")
    if value < 0:
        raise ResourceGrantError(f"{field} must be non-negative")
    return value


def _positive_int(value: Any, field: str) -> int:
    result = _nonnegative_int(value, field)
    if result == 0:
        raise ResourceGrantError(f"{field} must be greater than zero")
    return result


def _mapping_array(value: Any, field: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise ResourceGrantError(f"{field} must be a JSON array")
    result = tuple(value)
    if not all(isinstance(row, Mapping) for row in result):
        raise ResourceGrantError(
            f"{field} entries must be JSON objects"
        )
    return result


@dataclass(frozen=True, slots=True)
class ToolCallLimit:
    """Per-semantic-capability tool-call ceiling."""

    tool_capability: str
    max_calls: int

    def __post_init__(self) -> None:
        _closed(
            self.tool_capability,
            SEMANTIC_TOOL_CAPABILITIES,
            "tool_capability",
        )
        _positive_int(self.max_calls, "max_calls")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_capability": self.tool_capability,
            "max_calls": self.max_calls,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolCallLimit":
        if cls is not ToolCallLimit:
            raise ResourceGrantError(
                "ToolCallLimit replay requires exact base class"
            )
        _require_exact_keys(value, _TOOL_LIMIT_KEYS, "tool call limit")
        return ToolCallLimit(
            tool_capability=value["tool_capability"],
            max_calls=value["max_calls"],
        )


def _coerce_tool_limits(
    values: Iterable[ToolCallLimit],
) -> tuple[ToolCallLimit, ...]:
    try:
        result = tuple(sorted(values, key=lambda row: row.tool_capability))
    except (TypeError, AttributeError) as exc:
        raise ResourceGrantError(
            "tool_call_limits must contain ToolCallLimit records"
        ) from exc
    if not all(type(row) is ToolCallLimit for row in result):
        raise ResourceGrantError(
            "tool_call_limits must contain ToolCallLimit records"
        )
    names = tuple(row.tool_capability for row in result)
    if len(names) != len(set(names)):
        raise ResourceGrantError("tool_call_limits contains duplicates")
    return result


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResourceGrant:
    """All semantic resource ceilings for one immutable work unit."""

    profile: str
    audit_mode: str
    semantic_work_unit_id: str
    phase_semantic_id: str
    resource_policy_digest: str
    global_reservation_digest: str
    parity_policy_digest: str
    parity_mode: str
    workload_class: str
    analysis_units: int
    max_input_tokens: int
    max_output_tokens: int
    tool_call_limits: tuple[ToolCallLimit, ...]
    max_native_commands: int
    max_native_wall_time_seconds: int
    max_model_attempts: int
    semantic_timeout_seconds: int
    max_stdout_bytes: int
    max_stderr_bytes: int
    max_stream_line_bytes: int
    scheduler_concurrency_class: str
    max_concurrency: int
    cache_policy: str
    _seal: str = field(init=False, repr=False, compare=False)

    schema: ClassVar[str] = RESOURCE_GRANT_SCHEMA

    def __post_init__(self) -> None:
        if type(self) is not ResourceGrant:
            raise ResourceGrantError(
                "ResourceGrant cannot be subclass-minted"
            )
        _closed(self.profile, RESOURCE_PROFILES, "profile")
        mode = _closed(self.audit_mode, AUDIT_MODES, "audit_mode")
        _safe_id(self.semantic_work_unit_id, "semantic_work_unit_id")
        _safe_id(self.phase_semantic_id, "phase_semantic_id")
        _sha256(self.resource_policy_digest, "resource_policy_digest")
        _sha256(
            self.global_reservation_digest, "global_reservation_digest"
        )
        _sha256(self.parity_policy_digest, "parity_policy_digest")
        parity_mode = _closed(
            self.parity_mode, PARITY_MODES, "parity_mode"
        )
        workload = _closed(
            self.workload_class, WORKLOAD_CLASSES, "workload_class"
        )
        _nonnegative_int(self.analysis_units, "analysis_units")
        _nonnegative_int(self.max_input_tokens, "max_input_tokens")
        _nonnegative_int(self.max_output_tokens, "max_output_tokens")
        tools = _coerce_tool_limits(self.tool_call_limits)
        _nonnegative_int(self.max_native_commands, "max_native_commands")
        _nonnegative_int(
            self.max_native_wall_time_seconds,
            "max_native_wall_time_seconds",
        )
        if (self.max_native_commands == 0) != (
            self.max_native_wall_time_seconds == 0
        ):
            raise ResourceGrantError(
                "native command count and native wall-time ceilings must "
                "both be zero or both be positive"
            )
        _nonnegative_int(self.max_model_attempts, "max_model_attempts")
        _positive_int(
            self.semantic_timeout_seconds, "semantic_timeout_seconds"
        )
        _positive_int(self.max_stdout_bytes, "max_stdout_bytes")
        _positive_int(self.max_stderr_bytes, "max_stderr_bytes")
        _positive_int(
            self.max_stream_line_bytes, "max_stream_line_bytes"
        )
        _closed(
            self.scheduler_concurrency_class,
            SCHEDULER_CONCURRENCY_CLASSES,
            "scheduler_concurrency_class",
        )
        _positive_int(self.max_concurrency, "max_concurrency")
        mode_max_concurrency = 2 if mode == "light" else _MAX_CONCURRENCY
        if self.max_concurrency > mode_max_concurrency:
            raise ResourceGrantError(
                f"{mode} max_concurrency exceeds adaptive-au-v1 ceiling "
                f"{mode_max_concurrency}"
            )
        if (
            self.scheduler_concurrency_class == "SERIAL"
            and self.max_concurrency != 1
        ):
            raise ResourceGrantError(
                "SERIAL scheduler requires max_concurrency=1"
            )
        _closed(self.cache_policy, CACHE_POLICIES, "cache_policy")
        if parity_mode == "STRICT_PAIRED":
            if self.scheduler_concurrency_class != "STRICT_PAIRED":
                raise ResourceGrantError(
                    "strict parity requires STRICT_PAIRED scheduler"
                )
            if self.cache_policy == "PROVIDER_DEFAULT_BOUND":
                raise ResourceGrantError(
                    "strict paired cache policy cannot be provider-default"
                )
        elif self.scheduler_concurrency_class == "STRICT_PAIRED":
            raise ResourceGrantError(
                "STRICT_PAIRED scheduler requires typed strict parity policy"
            )

        expected_au, input_ceiling, output_ceiling, tool_ceiling = (
            _CLASS_LIMITS[workload]
        )
        if self.analysis_units != expected_au:
            raise ResourceGrantError(
                f"{workload} requires analysis_units={expected_au}"
            )
        total_tools = sum(row.max_calls for row in tools)
        if total_tools > tool_ceiling:
            raise ResourceGrantError(
                f"{workload} tool calls exceed ceiling {tool_ceiling}"
            )
        if input_ceiling is not None and self.max_input_tokens > input_ceiling:
            raise ResourceGrantError(
                f"{workload} max_input_tokens exceeds {input_ceiling}"
            )
        if output_ceiling is not None and self.max_output_tokens > output_ceiling:
            raise ResourceGrantError(
                f"{workload} max_output_tokens exceeds {output_ceiling}"
            )
        if workload == "NATIVE_DETERMINISTIC":
            if (
                self.max_input_tokens
                or self.max_output_tokens
                or total_tools
                or self.max_model_attempts
            ):
                raise ResourceGrantError(
                    "NATIVE_DETERMINISTIC cannot grant model resources"
                )
            if self.max_native_commands == 0:
                raise ResourceGrantError(
                    "NATIVE_DETERMINISTIC requires a native command grant"
                )
        else:
            if (
                self.max_input_tokens < MIN_RUNNABLE_INPUT_TOKENS
                or self.max_output_tokens < MIN_RUNNABLE_OUTPUT_TOKENS
            ):
                raise ResourceGrantError(
                    "model grant is below the minimum runnable channel"
                )
            if self.max_model_attempts < 1:
                raise ResourceGrantError(
                    "model grant requires at least one model attempt"
                )
            if self.max_model_attempts > _MAX_MODEL_ATTEMPTS:
                raise ResourceGrantError(
                    "model attempt ceiling exceeds adaptive-au-v1 maximum "
                    f"{_MAX_MODEL_ATTEMPTS}"
                )

        native_tool_calls = sum(
            row.max_calls
            for row in tools
            if row.tool_capability in _NATIVE_COMMAND_TOOL_CAPABILITIES
        )
        if workload != "NATIVE_DETERMINISTIC":
            if self.max_native_commands and native_tool_calls == 0:
                raise ResourceGrantError(
                    "native command budget requires a native command-bearing "
                    "tool capability"
                )
            if native_tool_calls and self.max_native_commands == 0:
                raise ResourceGrantError(
                    "native tool capability requires a native command budget"
                )
            if self.max_native_commands < native_tool_calls:
                raise ResourceGrantError(
                    "native command ceiling cannot be smaller than native "
                    "tool request ceilings"
                )
        if (
            self.max_native_wall_time_seconds
            > self.semantic_timeout_seconds
        ):
            raise ResourceGrantError(
                "native wall-time ceiling cannot exceed semantic timeout"
            )
        if self.max_stream_line_bytes > min(
            self.max_stdout_bytes, self.max_stderr_bytes
        ):
            raise ResourceGrantError(
                "max_stream_line_bytes cannot exceed either stream ceiling"
            )
        object.__setattr__(self, "tool_call_limits", tools)
        object.__setattr__(self, "_seal", self.resource_grant_digest)
        _RESOURCE_GRANT_SEALS.issue(self, self.to_bytes())

    def require_exact_replay(self) -> bytes:
        """Reject subclasses and post-construction grant mutation."""

        if (
            type(self) is not ResourceGrant
            or self._seal != self.resource_grant_digest
            or type(self.tool_call_limits) is not tuple
            or not all(
                type(row) is ToolCallLimit
                and type(row.tool_capability) is str
                and type(row.max_calls) is int
                for row in self.tool_call_limits
            )
        ):
            raise ResourceGrantError("resource grant seal/replay drifted")
        return _RESOURCE_GRANT_SEALS.require(self, self.to_bytes())

    @classmethod
    def create(
        cls,
        *,
        profile: str,
        audit_mode: str,
        semantic_work_unit_id: str,
        phase_semantic_id: str,
        resource_policy_digest: str,
        global_reservation_digest: str,
        parity_policy_digest: str,
        parity_mode: str,
        workload_class: str,
        analysis_units: int,
        max_input_tokens: int,
        max_output_tokens: int,
        tool_call_limits: Iterable[ToolCallLimit],
        max_native_commands: int,
        max_native_wall_time_seconds: int,
        max_model_attempts: int,
        semantic_timeout_seconds: int,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        max_stream_line_bytes: int,
        scheduler_concurrency_class: str,
        max_concurrency: int,
        cache_policy: str,
    ) -> "ResourceGrant":
        if cls is not ResourceGrant:
            raise ResourceGrantError(
                "ResourceGrant factory requires exact base class"
            )
        return ResourceGrant(
            profile=profile,
            audit_mode=audit_mode,
            semantic_work_unit_id=semantic_work_unit_id,
            phase_semantic_id=phase_semantic_id,
            resource_policy_digest=resource_policy_digest,
            global_reservation_digest=global_reservation_digest,
            parity_policy_digest=parity_policy_digest,
            parity_mode=parity_mode,
            workload_class=workload_class,
            analysis_units=analysis_units,
            max_input_tokens=max_input_tokens,
            max_output_tokens=max_output_tokens,
            tool_call_limits=tuple(tool_call_limits),
            max_native_commands=max_native_commands,
            max_native_wall_time_seconds=max_native_wall_time_seconds,
            max_model_attempts=max_model_attempts,
            semantic_timeout_seconds=semantic_timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            max_stream_line_bytes=max_stream_line_bytes,
            scheduler_concurrency_class=scheduler_concurrency_class,
            max_concurrency=max_concurrency,
            cache_policy=cache_policy,
        )

    @property
    def max_tool_calls(self) -> int:
        return sum(row.max_calls for row in self.tool_call_limits)

    @property
    def max_reserved_analysis_units(self) -> int:
        """Worst-case reservation after all authorized model attempts."""

        return self.analysis_units * self.max_model_attempts

    @property
    def max_execution_attempts(self) -> int:
        return (
            1
            if self.workload_class == "NATIVE_DETERMINISTIC"
            else self.max_model_attempts
        )

    @property
    def worst_case_totals(self) -> dict[str, int]:
        attempts = self.max_execution_attempts
        return {
            "reserved_analysis_units": self.max_reserved_analysis_units,
            "input_tokens": self.max_input_tokens * attempts,
            "output_tokens": self.max_output_tokens * attempts,
            "tool_calls": self.max_tool_calls * attempts,
            "native_commands": self.max_native_commands * attempts,
            "native_wall_time_seconds": (
                self.max_native_wall_time_seconds * attempts
            ),
            "semantic_timeout_seconds": (
                self.semantic_timeout_seconds * attempts
            ),
            "stdout_bytes": self.max_stdout_bytes * attempts,
            "stderr_bytes": self.max_stderr_bytes * attempts,
        }

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "profile": self.profile,
            "audit_mode": self.audit_mode,
            "semantic_work_unit_id": self.semantic_work_unit_id,
            "phase_semantic_id": self.phase_semantic_id,
            "resource_policy_digest": self.resource_policy_digest,
            "global_reservation_digest": self.global_reservation_digest,
            "parity_policy_digest": self.parity_policy_digest,
            "parity_mode": self.parity_mode,
            "workload_class": self.workload_class,
            "analysis_units": self.analysis_units,
            "max_reserved_analysis_units": self.max_reserved_analysis_units,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "tool_call_limits": [
                row.to_dict() for row in self.tool_call_limits
            ],
            "max_tool_calls": self.max_tool_calls,
            "max_native_commands": self.max_native_commands,
            "max_native_wall_time_seconds": (
                self.max_native_wall_time_seconds
            ),
            "max_model_attempts": self.max_model_attempts,
            "max_execution_attempts": self.max_execution_attempts,
            "semantic_timeout_seconds": self.semantic_timeout_seconds,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "max_stream_line_bytes": self.max_stream_line_bytes,
            "scheduler_concurrency_class": (
                self.scheduler_concurrency_class
            ),
            "max_concurrency": self.max_concurrency,
            "cache_policy": self.cache_policy,
            "budget_scope": _BUDGET_SCOPE,
            "worst_case_totals": self.worst_case_totals,
        }

    @property
    def resource_grant_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "resource_grant_digest": self.resource_grant_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResourceGrant":
        if cls is not ResourceGrant:
            raise ResourceGrantError(
                "ResourceGrant replay requires exact base class"
            )
        _require_exact_keys(value, _GRANT_KEYS, "resource grant")
        if value["schema"] != RESOURCE_GRANT_SCHEMA:
            raise ResourceGrantError("unsupported resource grant schema")
        claimed = _sha256(
            value["resource_grant_digest"], "resource_grant_digest"
        )
        tool_limits = tuple(
            ToolCallLimit.from_dict(row)
            for row in _mapping_array(
                value["tool_call_limits"], "tool_call_limits"
            )
        )
        grant = ResourceGrant.create(
            profile=value["profile"],
            audit_mode=value["audit_mode"],
            semantic_work_unit_id=value["semantic_work_unit_id"],
            phase_semantic_id=value["phase_semantic_id"],
            resource_policy_digest=value["resource_policy_digest"],
            global_reservation_digest=value["global_reservation_digest"],
            parity_policy_digest=value["parity_policy_digest"],
            parity_mode=value["parity_mode"],
            workload_class=value["workload_class"],
            analysis_units=value["analysis_units"],
            max_input_tokens=value["max_input_tokens"],
            max_output_tokens=value["max_output_tokens"],
            tool_call_limits=tool_limits,
            max_native_commands=value["max_native_commands"],
            max_native_wall_time_seconds=value[
                "max_native_wall_time_seconds"
            ],
            max_model_attempts=value["max_model_attempts"],
            semantic_timeout_seconds=value["semantic_timeout_seconds"],
            max_stdout_bytes=value["max_stdout_bytes"],
            max_stderr_bytes=value["max_stderr_bytes"],
            max_stream_line_bytes=value["max_stream_line_bytes"],
            scheduler_concurrency_class=value[
                "scheduler_concurrency_class"
            ],
            max_concurrency=value["max_concurrency"],
            cache_policy=value["cache_policy"],
        )
        if value["max_tool_calls"] != grant.max_tool_calls:
            raise ResourceGrantError("max_tool_calls mismatch")
        if value["max_execution_attempts"] != grant.max_execution_attempts:
            raise ResourceGrantError("max_execution_attempts mismatch")
        if (
            value["max_reserved_analysis_units"]
            != grant.max_reserved_analysis_units
        ):
            raise ResourceGrantError(
                "max_reserved_analysis_units mismatch"
            )
        if value["budget_scope"] != _BUDGET_SCOPE:
            raise ResourceGrantError("resource budget_scope is invalid")
        supplied_totals = value["worst_case_totals"]
        if not isinstance(supplied_totals, Mapping) or set(
            supplied_totals
        ) != _WORST_CASE_TOTAL_KEYS:
            raise ResourceGrantError(
                "worst_case_totals denominator is not exact"
            )
        if supplied_totals != grant.worst_case_totals:
            raise ResourceGrantError(
                "worst_case_totals do not replay from per-attempt ceilings"
            )
        if claimed != grant.resource_grant_digest:
            raise ResourceGrantError("resource_grant_digest digest mismatch")
        return grant

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ResourceGrant":
        if cls is not ResourceGrant:
            raise ResourceGrantError(
                "ResourceGrant replay requires exact base class"
            )
        return ResourceGrant.from_dict(_decode_record(raw))


def _replay_semantic_attempt_bundle(
    value: Any,
) -> SemanticAttemptBundle:
    if type(value) is not SemanticAttemptBundle:
        raise ResourceGrantError(
            "exact SemanticAttemptBundle is required"
        )
    try:
        source_execution_bundle = value.execution_bundle
        if type(source_execution_bundle) is not SemanticExecutionBundle:
            raise ResourceGrantError(
                "exact SemanticExecutionBundle is required"
            )
        if (
            type(source_execution_bundle.plan) is not SemanticWorkPlan
            or type(source_execution_bundle.execution)
            is not BackendArmExecutionIdentity
            or type(value.attempt) is not ExecutionAttemptIdentity
        ):
            raise ResourceGrantError(
                "attempt parents must use exact typed records"
            )
        plan = SemanticWorkPlan.from_bytes(
            source_execution_bundle.plan.to_bytes()
        )
        execution = BackendArmExecutionIdentity.from_bytes(
            source_execution_bundle.execution.to_bytes()
        )
        attempt = ExecutionAttemptIdentity.from_bytes(
            value.attempt.to_bytes()
        )
        replayed = SemanticAttemptBundle(
            execution_bundle=SemanticExecutionBundle(
                plan=plan,
                execution=execution,
            ),
            attempt=attempt,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ResourceGrantError(
            "semantic attempt parents do not exactly replay"
        ) from exc
    if (
        replayed.execution_bundle.plan.to_bytes()
        != source_execution_bundle.plan.to_bytes()
        or replayed.execution_bundle.execution.to_bytes()
        != source_execution_bundle.execution.to_bytes()
        or replayed.attempt.to_bytes() != value.attempt.to_bytes()
    ):
        raise ResourceGrantError(
            "semantic attempt parent replay drifted"
        )
    return replayed


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResumeRequirementAuthority:
    """Opaque derivation of resume capability from one exact typed attempt."""

    semantic_work_unit_key: str
    execution_work_unit_key: str
    attempt_key: str
    attempt_number: int
    resource_grant_digest: str
    tool_capability_manifest_digest: str
    backend: str
    model_capability_tier: str
    requires_resume_session: bool
    _semantic_attempt_bundle: SemanticAttemptBundle | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _promotion_token: InitVar[object] = None

    schema: ClassVar[str] = RESUME_REQUIREMENT_AUTHORITY_SCHEMA

    def __post_init__(self, _promotion_token: object) -> None:
        if type(self) is not ResumeRequirementAuthority:
            raise ResourceGrantError(
                "ResumeRequirementAuthority cannot be subclass-minted"
            )
        if _promotion_token is not _RESUME_REQUIREMENT_AUTHORITY_TOKEN:
            raise ResourceGrantError(
                "resume requirement authority is opaque"
            )
        replayed_attempt = _replay_semantic_attempt_bundle(
            self._semantic_attempt_bundle
        )
        for field_name in (
            "semantic_work_unit_key",
            "execution_work_unit_key",
            "attempt_key",
            "resource_grant_digest",
            "tool_capability_manifest_digest",
        ):
            _sha256(getattr(self, field_name), field_name)
        _positive_int(self.attempt_number, "attempt_number")
        _closed(self.backend, frozenset({"claude", "codex", "native"}), "backend")
        _closed(
            self.model_capability_tier,
            frozenset(
                {
                    "R3_FRONTIER_REASONING",
                    "R2_STANDARD_REASONING",
                    "R1_ECONOMY_STRUCTURED",
                    "N0_NATIVE_DETERMINISTIC",
                }
            ),
            "model_capability_tier",
        )
        if type(self.requires_resume_session) is not bool:
            raise ResourceGrantError(
                "requires_resume_session must be boolean"
            )
        if self.requires_resume_session != (self.attempt_number > 1):
            raise ResourceGrantError(
                "resume requirement must derive from typed attempt number"
            )
        expected_parent_fields = (
            replayed_attempt.execution_bundle.plan.semantic_work_unit_key,
            replayed_attempt.execution_bundle.execution.execution_work_unit_key,
            replayed_attempt.attempt.attempt_key,
            replayed_attempt.attempt.attempt_number,
            replayed_attempt.execution_bundle.plan.resource_grant_digest,
            replayed_attempt.execution_bundle.plan.tool_capability_manifest_digest,
            replayed_attempt.execution_bundle.execution.backend,
            replayed_attempt.execution_bundle.execution.model_capability_tier,
        )
        supplied_parent_fields = (
            self.semantic_work_unit_key,
            self.execution_work_unit_key,
            self.attempt_key,
            self.attempt_number,
            self.resource_grant_digest,
            self.tool_capability_manifest_digest,
            self.backend,
            self.model_capability_tier,
        )
        if supplied_parent_fields != expected_parent_fields:
            raise ResourceGrantError(
                "resume requirement does not bind its exact attempt parents"
            )
        object.__setattr__(
            self,
            "_semantic_attempt_bundle",
            replayed_attempt,
        )
        _RESUME_REQUIREMENT_AUTHORITY_SEALS.issue(self, self.to_bytes())

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "semantic_work_unit_key": self.semantic_work_unit_key,
            "execution_work_unit_key": self.execution_work_unit_key,
            "attempt_key": self.attempt_key,
            "attempt_number": self.attempt_number,
            "resource_grant_digest": self.resource_grant_digest,
            "tool_capability_manifest_digest": (
                self.tool_capability_manifest_digest
            ),
            "backend": self.backend,
            "model_capability_tier": self.model_capability_tier,
            "requires_resume_session": self.requires_resume_session,
        }

    @property
    def resume_requirement_authority_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "resume_requirement_authority_digest": (
                self.resume_requirement_authority_digest
            ),
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def require_exact_replay(self) -> bytes:
        sealed = _RESUME_REQUIREMENT_AUTHORITY_SEALS.require(
            self, self.to_bytes()
        )
        replayed = _replay_semantic_attempt_bundle(
            self._semantic_attempt_bundle
        )
        if (
            replayed.execution_bundle.plan.semantic_work_unit_key
            != self.semantic_work_unit_key
            or replayed.execution_bundle.execution.execution_work_unit_key
            != self.execution_work_unit_key
            or replayed.attempt.attempt_key != self.attempt_key
            or replayed.attempt.attempt_number != self.attempt_number
        ):
            raise ResourceGrantError(
                "resume requirement attempt-parent replay drifted"
            )
        return sealed

    @property
    def bound_semantic_attempt_bundle(self) -> SemanticAttemptBundle:
        return _replay_semantic_attempt_bundle(
            self._semantic_attempt_bundle
        )

    def validate_against(
        self,
        *,
        grant: ResourceGrant,
        policy_entry: ModelPolicyEntry,
        launch_intent: BackendLaunchIntent,
        tool_capability_manifest_digest: str,
        semantic_attempt_bundle: SemanticAttemptBundle,
        global_reservation: GlobalResourceReservation,
    ) -> None:
        self.require_exact_replay()
        sealed_grant = grant.require_exact_replay()
        grant_snapshot = ResourceGrant.from_bytes(sealed_grant)
        current_attempt = _replay_semantic_attempt_bundle(
            semantic_attempt_bundle
        )
        bound_attempt = self.bound_semantic_attempt_bundle
        if (
            current_attempt.execution_bundle.plan.to_bytes()
            != bound_attempt.execution_bundle.plan.to_bytes()
            or current_attempt.execution_bundle.execution.to_bytes()
            != bound_attempt.execution_bundle.execution.to_bytes()
            or current_attempt.attempt.to_bytes()
            != bound_attempt.attempt.to_bytes()
        ):
            raise ResourceGrantError(
                "resume requirement authority is substituted across "
                "run/execution/attempt identity"
            )
        if type(global_reservation) is not GlobalResourceReservation:
            raise ResourceGrantError(
                "resume requirement needs exact global reservation"
            )
        try:
            global_reservation.require_exact_replay()
        except ResourcePolicyError as exc:
            raise ResourceGrantError(
                "resume reservation exact replay failed",
                debt=exc.debt,
            ) from exc
        plan = current_attempt.execution_bundle.plan
        execution = current_attempt.execution_bundle.execution
        attempt = current_attempt.attempt
        if (
            plan.run_id != global_reservation.run_id
            or plan.semantic_generation != global_reservation.generation
            or plan.semantic_work_unit_id
            != grant_snapshot.semantic_work_unit_id
            or plan.resource_grant_digest
            != grant_snapshot.resource_grant_digest
            or plan.tool_capability_manifest_digest
            != self.tool_capability_manifest_digest
            or attempt.attempt_number > grant_snapshot.max_execution_attempts
        ):
            raise ResourceGrantError(
                "resume requirement run/generation/attempt does not bind "
                "grant and reservation"
            )
        expected = (
            grant_snapshot.resource_grant_digest,
            _sha256(
                tool_capability_manifest_digest,
                "tool_capability_manifest_digest",
            ),
            policy_entry.backend,
            policy_entry.semantic_model_capability_tier,
            launch_intent.backend,
            execution.backend,
            execution.model_capability_tier,
        )
        supplied = (
            self.resource_grant_digest,
            self.tool_capability_manifest_digest,
            self.backend,
            self.model_capability_tier,
            self.backend,
            self.backend,
            self.model_capability_tier,
        )
        if supplied != expected:
            raise ResourceGrantError(
                "resume requirement authority does not bind grant, tool "
                "manifest, policy entry, and launch intent"
            )


def compile_resume_requirement_authority(
    *,
    semantic_attempt_bundle: SemanticAttemptBundle,
    grant: ResourceGrant,
) -> ResumeRequirementAuthority:
    """Derive resume from an exact attempt; callers cannot choose a boolean."""

    if type(semantic_attempt_bundle) is not SemanticAttemptBundle:
        raise ResourceGrantError(
            "exact typed SemanticAttemptBundle is required for resume"
        )
    if type(grant) is not ResourceGrant:
        raise ResourceGrantError(
            "exact ResourceGrant is required for resume authority"
        )
    sealed_grant = grant.require_exact_replay()
    grant_snapshot = ResourceGrant.from_bytes(sealed_grant)
    replayed = _replay_semantic_attempt_bundle(
        semantic_attempt_bundle
    )
    if (
        replayed.execution_bundle.plan.resource_grant_digest
        != grant_snapshot.resource_grant_digest
        or replayed.execution_bundle.plan.semantic_work_unit_id
        != grant_snapshot.semantic_work_unit_id
    ):
        raise ResourceGrantError(
            "resume attempt plan does not bind the resource grant"
        )
    return ResumeRequirementAuthority(
        semantic_work_unit_key=(
            replayed.execution_bundle.plan.semantic_work_unit_key
        ),
        execution_work_unit_key=(
            replayed.execution_bundle.execution.execution_work_unit_key
        ),
        attempt_key=replayed.attempt.attempt_key,
        attempt_number=replayed.attempt.attempt_number,
        resource_grant_digest=grant_snapshot.resource_grant_digest,
        tool_capability_manifest_digest=(
            replayed.execution_bundle.plan
            .tool_capability_manifest_digest
        ),
        backend=replayed.execution_bundle.execution.backend,
        model_capability_tier=(
            replayed.execution_bundle.execution.model_capability_tier
        ),
        requires_resume_session=(replayed.attempt.attempt_number > 1),
        _semantic_attempt_bundle=replayed,
        _promotion_token=_RESUME_REQUIREMENT_AUTHORITY_TOKEN,
    )


def _compile_resource_grant_from_policy(
    *,
    policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
    semantic_work_unit_id: str,
    audit_mode: str,
    phase_semantic_id: str,
    workload_class: str,
    _structural_test_token: object = None,
) -> ResourceGrant:
    """Derive one exact grant from typed policy and reservation parents."""

    if type(policy_authority) is not ResourcePolicyAuthority:
        raise ResourceGrantError(
            "typed ResourcePolicyAuthority is required"
        )
    try:
        policy_authority.require_exact_replay()
    except ResourcePolicyError as exc:
        raise ResourceGrantError(str(exc)) from exc
    if type(global_reservation) is not GlobalResourceReservation:
        raise ResourceGrantError(
            "typed global reservation parent is required"
        )
    try:
        global_reservation.require_exact_replay()
        if _structural_test_token is _STRUCTURAL_TEST_RESOURCE_TOKEN:
            if global_reservation.reservation_budget_authority_class != (
                "STRUCTURAL_TEST_ONLY"
            ):
                raise ResourcePolicyError(
                    "structural-test grant requires structural-test "
                    "reservation authority"
                )
        else:
            global_reservation.require_production_budget_authority()
        replayed_reservation = global_reservation.replay()
    except (AttributeError, ResourcePolicyError, ValueError) as exc:
        raise ResourceGrantError(
            "global reservation exact replay failed",
            debt=(
                exc.debt
                if isinstance(exc, ResourcePolicyError)
                else None
            ),
        ) from exc
    if replayed_reservation.to_bytes() != global_reservation.to_bytes():
        raise ResourceGrantError("global reservation exact replay drifted")
    if policy_authority.global_reservation_digest != (
        global_reservation.reservation_digest
    ):
        raise ResourceGrantError(
            "resource policy/global reservation parent mismatch"
        )
    try:
        ceiling = policy_authority.ceiling_for(
            audit_mode=audit_mode,
            phase_semantic_id=phase_semantic_id,
            workload_class=workload_class,
        )
        reserved = global_reservation.allocation_for(
            semantic_work_unit_id
        )
    except ResourcePolicyError as exc:
        raise ResourceGrantError(str(exc)) from exc
    expected_reserved = (
        ceiling.analysis_units_per_attempt * ceiling.max_attempts
    )
    if reserved != expected_reserved:
        raise ResourceGrantError(
            "global reservation allocation does not equal worst-case "
            "policy analysis-unit reservation"
        )
    parity = policy_authority.parity_policy
    return ResourceGrant.create(
        profile=policy_authority.profile,
        audit_mode=ceiling.audit_mode,
        semantic_work_unit_id=semantic_work_unit_id,
        phase_semantic_id=ceiling.phase_semantic_id,
        resource_policy_digest=(
            policy_authority.resource_policy_authority_digest
        ),
        global_reservation_digest=global_reservation.reservation_digest,
        parity_policy_digest=parity.parity_policy_digest,
        parity_mode=parity.parity_mode,
        workload_class=ceiling.workload_class,
        analysis_units=ceiling.analysis_units_per_attempt,
        max_input_tokens=ceiling.max_input_tokens_per_attempt,
        max_output_tokens=ceiling.max_output_tokens_per_attempt,
        tool_call_limits=tuple(
            ToolCallLimit(
                row.tool_capability, row.max_calls_per_attempt
            )
            for row in ceiling.tool_limits
        ),
        max_native_commands=ceiling.max_native_commands_per_attempt,
        max_native_wall_time_seconds=(
            ceiling.max_native_wall_time_seconds_per_attempt
        ),
        max_model_attempts=(
            0
            if ceiling.workload_class == "NATIVE_DETERMINISTIC"
            else ceiling.max_attempts
        ),
        semantic_timeout_seconds=(
            ceiling.semantic_timeout_seconds_per_attempt
        ),
        max_stdout_bytes=ceiling.max_stdout_bytes_per_attempt,
        max_stderr_bytes=ceiling.max_stderr_bytes_per_attempt,
        max_stream_line_bytes=ceiling.max_stream_line_bytes,
        scheduler_concurrency_class=(
            parity.scheduler_concurrency_class
        ),
        max_concurrency=parity.max_concurrency,
        cache_policy=parity.cache_policy,
    )


def compile_resource_grant_from_policy(
    *,
    policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
    semantic_work_unit_id: str,
    audit_mode: str,
    phase_semantic_id: str,
    workload_class: str,
) -> ResourceGrant:
    """Production compiler; structural-test reservations fail closed."""

    return _compile_resource_grant_from_policy(
        policy_authority=policy_authority,
        global_reservation=global_reservation,
        semantic_work_unit_id=semantic_work_unit_id,
        audit_mode=audit_mode,
        phase_semantic_id=phase_semantic_id,
        workload_class=workload_class,
    )


def compile_structural_test_resource_grant_from_policy(
    *,
    policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
    semantic_work_unit_id: str,
    audit_mode: str,
    phase_semantic_id: str,
    workload_class: str,
) -> ResourceGrant:
    """Test-only compiler; its result is not production authorization."""

    return _compile_resource_grant_from_policy(
        policy_authority=policy_authority,
        global_reservation=global_reservation,
        semantic_work_unit_id=semantic_work_unit_id,
        audit_mode=audit_mode,
        phase_semantic_id=phase_semantic_id,
        workload_class=workload_class,
        _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
    )


def _require_resource_grant_parent_replay(
    grant: ResourceGrant,
    *,
    policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
    _structural_test_token: object = None,
) -> None:
    """Replay a grant from its policy/reservation roots without a work plan."""

    if type(grant) is not ResourceGrant:
        raise ResourceGrantError("grant must be ResourceGrant")
    sealed_grant = grant.require_exact_replay()
    expected = _compile_resource_grant_from_policy(
        policy_authority=policy_authority,
        global_reservation=global_reservation,
        semantic_work_unit_id=grant.semantic_work_unit_id,
        audit_mode=grant.audit_mode,
        phase_semantic_id=grant.phase_semantic_id,
        workload_class=grant.workload_class,
        _structural_test_token=_structural_test_token,
    )
    if sealed_grant != expected.to_bytes():
        raise ResourceGrantError(
            "resource grant does not replay from exact policy, parity, "
            "and reservation authorities"
        )


def _validate_resource_grant_against_semantic_work_plan(
    grant: ResourceGrant,
    semantic_work_plan: Any,
    *,
    policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
    _structural_test_token: object = None,
) -> None:
    """Replay grant, policy, parity, plan, and reservation as one closure."""

    if type(grant) is not ResourceGrant:
        raise ResourceGrantError("grant must be ResourceGrant")
    sealed_grant = grant.require_exact_replay()
    if type(policy_authority) is not ResourcePolicyAuthority:
        raise ResourceGrantError(
            "exact typed ResourcePolicyAuthority is required"
        )
    try:
        policy_authority.require_exact_replay()
    except ResourcePolicyError as exc:
        raise ResourceGrantError(
            "resource policy authority exact replay failed",
            debt=exc.debt,
        ) from exc
    if type(semantic_work_plan) is not SemanticWorkPlan:
        raise ResourceGrantError(
            "exact typed SemanticWorkPlan authority is required"
        )
    if type(global_reservation) is not GlobalResourceReservation:
        raise ResourceGrantError(
            "exact typed global reservation authority is required"
        )
    try:
        global_reservation.require_exact_replay()
        if _structural_test_token is _STRUCTURAL_TEST_RESOURCE_TOKEN:
            if global_reservation.reservation_budget_authority_class != (
                "STRUCTURAL_TEST_ONLY"
            ):
                raise ResourcePolicyError(
                    "structural-test validation requires structural "
                    "reservation authority"
                )
        else:
            global_reservation.require_production_budget_authority()
        replayed_plan = SemanticWorkPlan.from_bytes(
            semantic_work_plan.to_bytes()
        )
        replayed_reservation = global_reservation.replay()
    except (AttributeError, ResourcePolicyError, ValueError) as exc:
        raise ResourceGrantError(
            "SemanticWorkPlan/global reservation exact replay failed",
            debt=(
                exc.debt
                if isinstance(exc, ResourcePolicyError)
                else None
            ),
        ) from exc
    if (
        replayed_plan != semantic_work_plan
        or replayed_reservation != global_reservation
    ):
        raise ResourceGrantError(
            "SemanticWorkPlan/global reservation exact replay drifted"
        )
    if policy_authority.global_reservation_digest != (
        global_reservation.reservation_digest
    ):
        raise ResourceGrantError(
            "resource policy/global reservation parent mismatch"
        )
    try:
        expected_grant = _compile_resource_grant_from_policy(
            policy_authority=policy_authority,
            global_reservation=global_reservation,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            audit_mode=grant.audit_mode,
            phase_semantic_id=grant.phase_semantic_id,
            workload_class=grant.workload_class,
            _structural_test_token=_structural_test_token,
        )
    except ResourceGrantError:
        raise
    if sealed_grant != expected_grant.to_bytes():
        raise ResourceGrantError(
            "resource grant does not replay from exact policy, parity, "
            "and reservation authorities"
        )
    retry_policy = semantic_work_plan.retry_policy
    if type(retry_policy) is not RetryPolicy:
        raise ResourceGrantError(
            "exact typed SemanticWorkPlan RetryPolicy authority is required"
        )
    if (
        grant.global_reservation_digest
        != global_reservation.reservation_digest
        or semantic_work_plan.run_id != global_reservation.run_id
        or semantic_work_plan.semantic_generation
        != global_reservation.generation
    ):
        raise ResourceGrantError(
            "SemanticWorkPlan run/generation does not bind global reservation"
        )
    try:
        reserved = global_reservation.allocation_for(
            semantic_work_plan.semantic_work_unit_id
        )
    except ResourcePolicyError as exc:
        raise ResourceGrantError(
            "SemanticWorkPlan work unit is absent from reservation"
        ) from exc
    if reserved != grant.max_reserved_analysis_units:
        raise ResourceGrantError(
            "SemanticWorkPlan reservation allocation does not bind grant"
        )
    expected = (
        grant.resource_grant_digest,
        grant.audit_mode,
        grant.phase_semantic_id,
        grant.semantic_work_unit_id,
        grant.max_execution_attempts,
    )
    supplied = (
        getattr(semantic_work_plan, "resource_grant_digest", None),
        getattr(semantic_work_plan, "mode", None),
        getattr(semantic_work_plan, "phase_semantic_id", None),
        getattr(semantic_work_plan, "semantic_work_unit_id", None),
        getattr(retry_policy, "max_attempts", None),
    )
    if supplied != expected:
        raise ResourceGrantError(
            "resource grant does not exactly equal SemanticWorkPlan "
            "retry-policy authority"
        )
    if any(
        getattr(retry_policy, field, None) is not True
        for field in (
            "same_prompt",
            "same_model_capability_tier",
            "same_tools",
            "model_change_requires_new_generation",
        )
    ):
        raise ResourceGrantError(
            "SemanticWorkPlan retry policy is not identity preserving"
        )


def validate_resource_grant_against_semantic_work_plan(
    grant: ResourceGrant,
    semantic_work_plan: Any,
    *,
    policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
) -> None:
    """Production validator; structural reservations fail with typed debt."""

    _validate_resource_grant_against_semantic_work_plan(
        grant,
        semantic_work_plan,
        policy_authority=policy_authority,
        global_reservation=global_reservation,
    )


def validate_structural_test_resource_grant_against_semantic_work_plan(
    grant: ResourceGrant,
    semantic_work_plan: Any,
    *,
    policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
) -> None:
    """Explicit test-only validator over structural scheduler authority."""

    _validate_resource_grant_against_semantic_work_plan(
        grant,
        semantic_work_plan,
        policy_authority=policy_authority,
        global_reservation=global_reservation,
        _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
    )


def _replay_resource_grant_from_policy(
    raw: bytes,
    *,
    policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
    semantic_work_unit_id: str,
    audit_mode: str,
    phase_semantic_id: str,
    workload_class: str,
    semantic_work_plan: Any | None = None,
    _structural_test_token: object = None,
) -> ResourceGrant:
    expected = _compile_resource_grant_from_policy(
        policy_authority=policy_authority,
        global_reservation=global_reservation,
        semantic_work_unit_id=semantic_work_unit_id,
        audit_mode=audit_mode,
        phase_semantic_id=phase_semantic_id,
        workload_class=workload_class,
        _structural_test_token=_structural_test_token,
    )
    if raw != expected.to_bytes():
        raise ResourceGrantError(
            "resource grant does not replay from exact typed policy/"
            "reservation parents"
        )
    if semantic_work_plan is not None:
        _validate_resource_grant_against_semantic_work_plan(
            expected,
            semantic_work_plan,
            policy_authority=policy_authority,
            global_reservation=global_reservation,
            _structural_test_token=_structural_test_token,
        )
    return expected


def replay_resource_grant_from_policy(
    raw: bytes,
    **kwargs: Any,
) -> ResourceGrant:
    """Production replay; structural-test reservations fail closed."""

    return _replay_resource_grant_from_policy(raw, **kwargs)


def replay_structural_test_resource_grant_from_policy(
    raw: bytes,
    **kwargs: Any,
) -> ResourceGrant:
    """Test-only replay over a structural reservation authority."""

    return _replay_resource_grant_from_policy(
        raw,
        **kwargs,
        _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
    )


def _compile_preflight_request_from_resource_grant(
    *,
    grant: ResourceGrant,
    registry: ModelPolicyRegistry,
    policy_entry: ModelPolicyEntry,
    launch_intent: BackendLaunchIntent,
    expected_model_policy_registry_digest: str,
    expected_policy_entry_digest: str,
    expected_launch_intent_digest: str,
    resource_policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
    semantic_requirement_digest: str,
    tool_capability_manifest_digest: str,
    resume_requirement_authority: ResumeRequirementAuthority | None = None,
    semantic_attempt_bundle: SemanticAttemptBundle | None = None,
    requires_resume_session: bool | None = None,
    _structural_test_token: object = None,
) -> tuple[CapabilityPreflightRequest, CapabilityRequestAuthority]:
    """Compile exact capability/tool requirements from immutable grant bytes."""

    if requires_resume_session is not None:
        raise ResourceGrantError(
            "resume selection requires typed resume authority; a caller "
            "boolean is forbidden"
        )
    if type(resume_requirement_authority) is not ResumeRequirementAuthority:
        raise ResourceGrantError(
            "typed resume requirement authority is required"
        )
    if semantic_attempt_bundle is None:
        if _structural_test_token is _STRUCTURAL_TEST_RESOURCE_TOKEN:
            semantic_attempt_bundle = (
                resume_requirement_authority
                .bound_semantic_attempt_bundle
            )
        else:
            raise ResourceGrantError(
                "production preflight requires the exact current semantic "
                "attempt bundle"
            )
    if type(grant) is not ResourceGrant:
        raise ResourceGrantError("exact ResourceGrant runtime type is required")
    sealed_grant = grant.require_exact_replay()
    grant_snapshot = ResourceGrant.from_bytes(sealed_grant)
    expected_grant = _compile_resource_grant_from_policy(
        policy_authority=resource_policy_authority,
        global_reservation=global_reservation,
        semantic_work_unit_id=grant_snapshot.semantic_work_unit_id,
        audit_mode=grant_snapshot.audit_mode,
        phase_semantic_id=grant_snapshot.phase_semantic_id,
        workload_class=grant_snapshot.workload_class,
        _structural_test_token=_structural_test_token,
    )
    if sealed_grant != expected_grant.to_bytes():
        raise ResourceGrantError(
            "resource grant is not replay-authorized by typed policy/"
            "reservation parents"
        )
    resume_requirement_authority.validate_against(
        grant=grant_snapshot,
        policy_entry=policy_entry,
        launch_intent=launch_intent,
        tool_capability_manifest_digest=tool_capability_manifest_digest,
        semantic_attempt_bundle=semantic_attempt_bundle,
        global_reservation=global_reservation,
    )
    native_tier = (
        policy_entry.semantic_model_capability_tier
        == "N0_NATIVE_DETERMINISTIC"
    )
    native_workload = (
        grant_snapshot.workload_class == "NATIVE_DETERMINISTIC"
    )
    if native_tier != native_workload:
        raise ResourceGrantError(
            "native model tier and native workload class must agree"
        )
    tools = tuple(
        ToolCapabilityRequirement(
            tool_capability=row.tool_capability,
            required_calls=row.max_calls,
        )
        for row in grant_snapshot.tool_call_limits
    )
    try:
        return _compile_capability_preflight_request(
            registry=registry,
            policy_entry=policy_entry,
            launch_intent=launch_intent,
            expected_model_policy_registry_digest=(
                expected_model_policy_registry_digest
            ),
            expected_policy_entry_digest=expected_policy_entry_digest,
            expected_launch_intent_digest=expected_launch_intent_digest,
            semantic_requirement_digest=semantic_requirement_digest,
            resource_grant_digest=grant_snapshot.resource_grant_digest,
            tool_capability_manifest_digest=(
                tool_capability_manifest_digest
            ),
            minimum_context_window_tokens=grant_snapshot.max_input_tokens,
            minimum_output_tokens=grant_snapshot.max_output_tokens,
            required_tools=tools,
            minimum_native_commands=grant_snapshot.max_native_commands,
            minimum_native_wall_time_seconds=(
                grant_snapshot.max_native_wall_time_seconds
            ),
            requires_resume_session=(
                resume_requirement_authority.requires_resume_session
            ),
        )
    except CapabilityRegistryError as exc:
        raise ResourceGrantError(
            f"capability request compilation failed: {exc}"
        ) from exc


def compile_preflight_request_from_resource_grant(
    **kwargs: Any,
) -> tuple[CapabilityPreflightRequest, CapabilityRequestAuthority]:
    """Production preflight compiler; structural reservations fail closed."""

    return _compile_preflight_request_from_resource_grant(**kwargs)


def compile_structural_test_preflight_request_from_resource_grant(
    **kwargs: Any,
) -> tuple[CapabilityPreflightRequest, CapabilityRequestAuthority]:
    """Test-only preflight projection over a structural reservation."""

    return _compile_preflight_request_from_resource_grant(
        **kwargs,
        _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
    )


def _replay_preflight_request_authority_from_resource_grant(
    raw_authority: bytes,
    *,
    request: CapabilityPreflightRequest,
    grant: ResourceGrant,
    registry: ModelPolicyRegistry,
    policy_entry: ModelPolicyEntry,
    launch_intent: BackendLaunchIntent,
    expected_model_policy_registry_digest: str,
    expected_policy_entry_digest: str,
    expected_launch_intent_digest: str,
    resource_policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
    semantic_requirement_digest: str,
    tool_capability_manifest_digest: str,
    resume_requirement_authority: ResumeRequirementAuthority | None = None,
    semantic_attempt_bundle: SemanticAttemptBundle | None = None,
    requires_resume_session: bool | None = None,
    _structural_test_token: object = None,
) -> CapabilityRequestAuthority:
    """Replay persisted request authority from exact ResourceGrant bytes."""

    if type(request) is not CapabilityPreflightRequest:
        raise ResourceGrantError(
            "exact CapabilityPreflightRequest runtime type is required"
        )
    try:
        request.require_exact_replay()
    except CapabilityRegistryError as exc:
        raise ResourceGrantError(
            "capability request exact replay failed"
        ) from exc
    expected_request, expected_authority = (
        _compile_preflight_request_from_resource_grant(
            grant=grant,
            registry=registry,
            policy_entry=policy_entry,
            launch_intent=launch_intent,
            expected_model_policy_registry_digest=(
                expected_model_policy_registry_digest
            ),
            expected_policy_entry_digest=expected_policy_entry_digest,
            expected_launch_intent_digest=expected_launch_intent_digest,
            resource_policy_authority=resource_policy_authority,
            global_reservation=global_reservation,
            semantic_requirement_digest=semantic_requirement_digest,
            tool_capability_manifest_digest=(
                tool_capability_manifest_digest
            ),
            resume_requirement_authority=resume_requirement_authority,
            semantic_attempt_bundle=semantic_attempt_bundle,
            requires_resume_session=requires_resume_session,
            _structural_test_token=_structural_test_token,
        )
    )
    if request.to_bytes() != expected_request.to_bytes():
        raise ResourceGrantError(
            "capability request does not replay from exact resource grant"
        )
    if raw_authority != expected_authority.to_bytes():
        raise ResourceGrantError(
            "capability request authority does not replay from exact "
            "resource grant"
        )
    return expected_authority


def replay_preflight_request_authority_from_resource_grant(
    raw_authority: bytes,
    **kwargs: Any,
) -> CapabilityRequestAuthority:
    """Production request-authority replay."""

    return _replay_preflight_request_authority_from_resource_grant(
        raw_authority,
        **kwargs,
    )


def replay_structural_test_preflight_request_authority_from_resource_grant(
    raw_authority: bytes,
    **kwargs: Any,
) -> CapabilityRequestAuthority:
    """Test-only request-authority replay over structural reservation."""

    return _replay_preflight_request_authority_from_resource_grant(
        raw_authority,
        **kwargs,
        _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
    )


@dataclass(frozen=True, slots=True)
class PairedResourceComparison:
    """Strict exact-equality result for two semantic grants."""

    left_resource_grant_digest: str
    right_resource_grant_digest: str
    state: str
    equal: bool
    strict_paired_eligible: bool
    eligibility_debts: tuple[str, ...]
    left_transport_plan_digest: str | None
    right_transport_plan_digest: str | None
    mismatch_fields: tuple[str, ...]
    _derivation_token: InitVar[object] = None

    schema: ClassVar[str] = PAIRED_RESOURCE_COMPARISON_SCHEMA

    def __post_init__(self, _derivation_token: object) -> None:
        if _derivation_token is not _DERIVATION_TOKEN:
            raise ResourceGrantError(
                "paired resource comparison requires replay derivation"
            )
        _sha256(
            self.left_resource_grant_digest,
            "left_resource_grant_digest",
        )
        _sha256(
            self.right_resource_grant_digest,
            "right_resource_grant_digest",
        )
        _closed(self.state, frozenset({"MATCHED", "UNMATCHED"}), "state")
        if type(self.equal) is not bool or type(
            self.strict_paired_eligible
        ) is not bool:
            raise ResourceGrantError(
                "paired equality/eligibility flags must be booleans"
            )
        if self.equal != (self.state == "MATCHED"):
            raise ResourceGrantError(
                "paired equality must match comparison state"
            )
        allowed_debts = frozenset(
            {
                "RESOURCE_MISMATCH",
                "STRICT_PARITY_POLICY_REQUIRED",
                "STRICT_SCHEDULER_REQUIRED",
                "PROVIDER_DEFAULT_CACHE",
                "TRANSPORT_PLAN_MISSING",
                "TRANSPORT_PLAN_TYPE_REQUIRED",
                "TRANSPORT_PLAN_MISMATCH",
                "NONZERO_TRANSPORT_GRACE",
                "INSUFFICIENT_CONCURRENT_CAPACITY",
                "CONCURRENCY_LEASE_AUTHORITY_MISSING",
            }
        )
        debts = tuple(self.eligibility_debts)
        if (
            len(debts) != len(set(debts))
            or debts != tuple(sorted(debts))
            or any(debt not in allowed_debts for debt in debts)
        ):
            raise ResourceGrantError(
                "strict paired eligibility debts are invalid"
            )
        if self.strict_paired_eligible != (not debts):
            raise ResourceGrantError(
                "strict paired eligibility must match eligibility debts"
            )
        for field in (
            "left_transport_plan_digest",
            "right_transport_plan_digest",
        ):
            value = getattr(self, field)
            if value is not None:
                _sha256(value, field)
        fields = tuple(self.mismatch_fields)
        if any(field not in _RESOURCE_FIELD_ORDER for field in fields):
            raise ResourceGrantError("mismatch_fields contains unknown field")
        if len(fields) != len(set(fields)):
            raise ResourceGrantError("mismatch_fields contains duplicates")
        if (self.state == "MATCHED") != (not fields):
            raise ResourceGrantError(
                "comparison state must match mismatch_fields"
            )
        object.__setattr__(self, "mismatch_fields", fields)
        object.__setattr__(self, "eligibility_debts", debts)

    def require_equal(self) -> None:
        if self.state != "MATCHED":
            raise ResourceGrantError(
                "paired resource grants differ: "
                + ", ".join(self.mismatch_fields)
            )

    def require_strict_paired_eligible(self) -> None:
        if not self.strict_paired_eligible:
            raise ResourceGrantError(
                "paired resources are equal but not strict-paired eligible: "
                + ", ".join(self.eligibility_debts)
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "comparison_digest": self.comparison_digest,
        }

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "left_resource_grant_digest": (
                self.left_resource_grant_digest
            ),
            "right_resource_grant_digest": (
                self.right_resource_grant_digest
            ),
            "state": self.state,
            "equal": self.equal,
            "strict_paired_eligible": self.strict_paired_eligible,
            "eligibility_debts": list(self.eligibility_debts),
            "left_transport_plan_digest": self.left_transport_plan_digest,
            "right_transport_plan_digest": self.right_transport_plan_digest,
            "mismatch_fields": list(self.mismatch_fields),
        }

    @property
    def comparison_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        left: "ResourceGrant",
        right: "ResourceGrant",
        left_policy_authority: ResourcePolicyAuthority,
        left_global_reservation: GlobalResourceReservation,
        right_policy_authority: ResourcePolicyAuthority,
        right_global_reservation: GlobalResourceReservation,
        left_transport_plan: Any | None = None,
        right_transport_plan: Any | None = None,
    ) -> "PairedResourceComparison":
        """Production replay from both grants' exact resource parents."""

        return cls._from_bytes(
            raw,
            left=left,
            right=right,
            left_policy_authority=left_policy_authority,
            left_global_reservation=left_global_reservation,
            right_policy_authority=right_policy_authority,
            right_global_reservation=right_global_reservation,
            left_transport_plan=left_transport_plan,
            right_transport_plan=right_transport_plan,
        )

    @classmethod
    def from_structural_test_bytes(
        cls,
        raw: bytes,
        *,
        left: "ResourceGrant",
        right: "ResourceGrant",
        left_transport_plan: Any | None = None,
        right_transport_plan: Any | None = None,
    ) -> "PairedResourceComparison":
        """Test-only replay; never establishes production resource authority."""

        return cls._from_bytes(
            raw,
            left=left,
            right=right,
            left_transport_plan=left_transport_plan,
            right_transport_plan=right_transport_plan,
            _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
        )

    @classmethod
    def _from_bytes(
        cls,
        raw: bytes,
        *,
        left: "ResourceGrant",
        right: "ResourceGrant",
        left_policy_authority: ResourcePolicyAuthority | None = None,
        left_global_reservation: GlobalResourceReservation | None = None,
        right_policy_authority: ResourcePolicyAuthority | None = None,
        right_global_reservation: GlobalResourceReservation | None = None,
        left_transport_plan: Any | None = None,
        right_transport_plan: Any | None = None,
        _structural_test_token: object = None,
    ) -> "PairedResourceComparison":
        value = _decode_record(raw)
        _require_exact_keys(
            value, _COMPARISON_KEYS, "paired resource comparison"
        )
        if value["schema"] != PAIRED_RESOURCE_COMPARISON_SCHEMA:
            raise ResourceGrantError(
                "unsupported paired resource comparison schema"
            )
        claimed = _sha256(
            value["comparison_digest"], "comparison_digest"
        )
        replayed = _compare_paired_resource_grants(
            left,
            right,
            left_policy_authority=left_policy_authority,
            left_global_reservation=left_global_reservation,
            right_policy_authority=right_policy_authority,
            right_global_reservation=right_global_reservation,
            left_transport_plan=left_transport_plan,
            right_transport_plan=right_transport_plan,
            _structural_test_token=_structural_test_token,
        )
        if claimed != replayed.comparison_digest:
            raise ResourceGrantError(
                "paired resource comparison digest does not replay"
            )
        if value != replayed.to_dict():
            raise ResourceGrantError(
                "paired resource comparison does not match replay"
            )
        return replayed


def _compare_paired_resource_grants(
    left: ResourceGrant,
    right: ResourceGrant,
    *,
    left_policy_authority: ResourcePolicyAuthority | None = None,
    left_global_reservation: GlobalResourceReservation | None = None,
    right_policy_authority: ResourcePolicyAuthority | None = None,
    right_global_reservation: GlobalResourceReservation | None = None,
    left_transport_plan: Any | None = None,
    right_transport_plan: Any | None = None,
    _structural_test_token: object = None,
) -> PairedResourceComparison:
    if type(left) is not ResourceGrant or type(right) is not ResourceGrant:
        raise ResourceGrantError(
            "paired comparison requires two ResourceGrant records"
        )
    if _structural_test_token is _STRUCTURAL_TEST_RESOURCE_TOKEN:
        left.require_exact_replay()
        right.require_exact_replay()
    else:
        _require_resource_grant_parent_replay(
            left,
            policy_authority=left_policy_authority,
            global_reservation=left_global_reservation,
        )
        _require_resource_grant_parent_replay(
            right,
            policy_authority=right_policy_authority,
            global_reservation=right_global_reservation,
        )
    left_values = left._unsigned_dict()
    right_values = right._unsigned_dict()
    mismatches = tuple(
        field
        for field in _RESOURCE_FIELD_ORDER
        if left_values[field] != right_values[field]
    )
    debts: set[str] = set()
    if mismatches:
        debts.add("RESOURCE_MISMATCH")
    if (
        left.parity_mode != "STRICT_PAIRED"
        or right.parity_mode != "STRICT_PAIRED"
        or left.parity_policy_digest != right.parity_policy_digest
    ):
        debts.add("STRICT_PARITY_POLICY_REQUIRED")
    if (
        left.scheduler_concurrency_class != "STRICT_PAIRED"
        or right.scheduler_concurrency_class != "STRICT_PAIRED"
    ):
        debts.add("STRICT_SCHEDULER_REQUIRED")
    if min(left.max_concurrency, right.max_concurrency) < 2:
        debts.add("INSUFFICIENT_CONCURRENT_CAPACITY")
    # A configured ceiling is not a reservation.  Until a typed concurrency
    # lease authority is implemented and accepted here, strict-paired launch
    # eligibility must remain explicit debt.
    debts.add("CONCURRENCY_LEASE_AUTHORITY_MISSING")
    if (
        left.cache_policy == "PROVIDER_DEFAULT_BOUND"
        or right.cache_policy == "PROVIDER_DEFAULT_BOUND"
    ):
        debts.add("PROVIDER_DEFAULT_CACHE")
    plans = (left_transport_plan, right_transport_plan)
    if any(plan is None for plan in plans):
        debts.add("TRANSPORT_PLAN_MISSING")
    elif not all(type(plan) is TransportPlan for plan in plans):
        debts.add("TRANSPORT_PLAN_TYPE_REQUIRED")
    else:
        left_plan_valid = _transport_plan_replays_for_comparison(
            left_transport_plan, left
        )
        right_plan_valid = _transport_plan_replays_for_comparison(
            right_transport_plan, right
        )
        if (
            not left_plan_valid
            or not right_plan_valid
            or
            left_transport_plan.resource_grant_digest
            != left.resource_grant_digest
            or right_transport_plan.resource_grant_digest
            != right.resource_grant_digest
            or left_transport_plan.parity_policy_digest
            != left.parity_policy_digest
            or right_transport_plan.parity_policy_digest
            != right.parity_policy_digest
            or left_transport_plan.usage_signature
            != right_transport_plan.usage_signature
        ):
            debts.add("TRANSPORT_PLAN_MISMATCH")
        if (
            left_transport_plan.total_grace_seconds != 0
            or right_transport_plan.total_grace_seconds != 0
        ):
            debts.add("NONZERO_TRANSPORT_GRACE")
    ordered_debts = tuple(sorted(debts))
    return PairedResourceComparison(
        left_resource_grant_digest=left.resource_grant_digest,
        right_resource_grant_digest=right.resource_grant_digest,
        state="MATCHED" if not mismatches else "UNMATCHED",
        equal=not mismatches,
        strict_paired_eligible=not ordered_debts,
        eligibility_debts=ordered_debts,
        left_transport_plan_digest=(
            left_transport_plan.transport_plan_digest
            if type(left_transport_plan) is TransportPlan
            else None
        ),
        right_transport_plan_digest=(
            right_transport_plan.transport_plan_digest
            if type(right_transport_plan) is TransportPlan
            else None
        ),
        mismatch_fields=mismatches,
        _derivation_token=_DERIVATION_TOKEN,
    )


def compare_paired_resource_grants(
    left: ResourceGrant,
    right: ResourceGrant,
    *,
    left_policy_authority: ResourcePolicyAuthority,
    left_global_reservation: GlobalResourceReservation,
    right_policy_authority: ResourcePolicyAuthority,
    right_global_reservation: GlobalResourceReservation,
    left_transport_plan: Any | None = None,
    right_transport_plan: Any | None = None,
) -> PairedResourceComparison:
    """Production comparison rooted in both scheduler reservations."""

    return _compare_paired_resource_grants(
        left,
        right,
        left_policy_authority=left_policy_authority,
        left_global_reservation=left_global_reservation,
        right_policy_authority=right_policy_authority,
        right_global_reservation=right_global_reservation,
        left_transport_plan=left_transport_plan,
        right_transport_plan=right_transport_plan,
    )


def compare_structural_test_paired_resource_grants(
    left: ResourceGrant,
    right: ResourceGrant,
    *,
    left_transport_plan: Any | None = None,
    right_transport_plan: Any | None = None,
) -> PairedResourceComparison:
    """Test-only comparison; result is never production eligibility proof."""

    return _compare_paired_resource_grants(
        left,
        right,
        left_transport_plan=left_transport_plan,
        right_transport_plan=right_transport_plan,
        _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
    )


def _transport_plan_replays_for_comparison(
    plan: TransportPlan,
    grant: ResourceGrant,
) -> bool:
    """Replay a strict-paired plan from exact typed grant-bound rows."""

    if type(plan) is not TransportPlan or type(grant) is not ResourceGrant:
        return False
    if (
        plan.resource_grant_digest != grant.resource_grant_digest
        or plan.parity_policy_digest != grant.parity_policy_digest
        or plan.parity_mode != grant.parity_mode
        or plan.semantic_work_unit_id != grant.semantic_work_unit_id
        or plan.max_execution_attempts != grant.max_execution_attempts
        or type(plan.max_execution_attempts) is not int
    ):
        return False
    if type(plan.grace_uses) is not tuple or any(
        type(row) is not TransportGrace for row in plan.grace_uses
    ):
        return False
    replayed_uses: list[TransportGrace] = []
    for row in plan.grace_uses:
        if (
            row.resource_grant_digest != grant.resource_grant_digest
            or row.parity_policy_digest != grant.parity_policy_digest
            or row.parity_mode != grant.parity_mode
            or row.semantic_work_unit_id != grant.semantic_work_unit_id
            or row.attempt_number > grant.max_execution_attempts
            or type(row.attempt_number) is not int
        ):
            return False
        if grant.parity_mode == "STRICT_PAIRED" and (
            row.authorized_max_grace_seconds != 0
            or row.grace_seconds != 0
        ):
            return False
        try:
            replayed_row = TransportGrace(
                resource_grant_digest=row.resource_grant_digest,
                parity_policy_digest=row.parity_policy_digest,
                semantic_work_unit_id=row.semantic_work_unit_id,
                attempt_number=row.attempt_number,
                use_id=row.use_id,
                authorized_max_grace_seconds=(
                    row.authorized_max_grace_seconds
                ),
                parity_mode=row.parity_mode,
                grace_seconds=row.grace_seconds,
                reason_code=row.reason_code,
            )
        except (ResourceGrantError, TypeError, ValueError):
            return False
        if (
            replayed_row != row
            or replayed_row.to_bytes() != row.to_bytes()
            or replayed_row.transport_grace_digest
            != row.transport_grace_digest
        ):
            return False
        replayed_uses.append(replayed_row)
    try:
        replayed = TransportPlan(
            resource_grant_digest=grant.resource_grant_digest,
            parity_policy_digest=grant.parity_policy_digest,
            parity_mode=grant.parity_mode,
            semantic_work_unit_id=grant.semantic_work_unit_id,
            max_execution_attempts=grant.max_execution_attempts,
            grace_uses=tuple(replayed_uses),
            _derivation_token=_DERIVATION_TOKEN,
        )
    except (ResourceGrantError, TypeError, ValueError):
        return False
    return (
        replayed == plan
        and replayed.to_bytes() == plan.to_bytes()
        and replayed.transport_plan_digest == plan.transport_plan_digest
    )


@dataclass(frozen=True, slots=True)
class TransportGrace:
    """Transport-only wall-time grace; never a semantic budget expansion."""

    resource_grant_digest: str
    parity_policy_digest: str
    semantic_work_unit_id: str
    attempt_number: int
    use_id: str
    authorized_max_grace_seconds: int
    parity_mode: str
    grace_seconds: int
    reason_code: str

    schema: ClassVar[str] = TRANSPORT_GRACE_SCHEMA

    def __post_init__(self) -> None:
        _sha256(self.resource_grant_digest, "resource_grant_digest")
        _sha256(self.parity_policy_digest, "parity_policy_digest")
        _safe_id(self.semantic_work_unit_id, "semantic_work_unit_id")
        _positive_int(self.attempt_number, "attempt_number")
        _safe_id(self.use_id, "use_id")
        _nonnegative_int(
            self.authorized_max_grace_seconds,
            "authorized_max_grace_seconds",
        )
        _closed(self.parity_mode, PARITY_MODES, "parity_mode")
        _nonnegative_int(self.grace_seconds, "grace_seconds")
        _closed(
            self.reason_code,
            TRANSPORT_GRACE_REASONS,
            "reason_code",
        )
        if self.grace_seconds > self.authorized_max_grace_seconds:
            raise ResourceGrantError(
                "grace_seconds exceeds authorized maximum"
            )
        if self.parity_mode == "STRICT_PAIRED":
            if (
                self.authorized_max_grace_seconds != 0
                or self.grace_seconds != 0
            ):
                raise ResourceGrantError(
                    "strict paired transport requires strict policy plus "
                    "zero authorized/used grace"
                )

    @classmethod
    def create(
        cls,
        *,
        grant: ResourceGrant,
        parity_policy: ParityPolicyAuthority,
        semantic_work_unit_id: str,
        attempt_number: int,
        use_id: str,
        grace_seconds: int,
        reason_code: str,
    ) -> "TransportGrace":
        if type(grant) is not ResourceGrant:
            raise ResourceGrantError("grant must be ResourceGrant")
        if type(parity_policy) is not ParityPolicyAuthority:
            raise ResourceGrantError(
                "typed parity policy authority is required"
            )
        if (
            grant.parity_policy_digest
            != parity_policy.parity_policy_digest
            or grant.parity_mode != parity_policy.parity_mode
            or grant.scheduler_concurrency_class
            != parity_policy.scheduler_concurrency_class
            or grant.cache_policy != parity_policy.cache_policy
        ):
            raise ResourceGrantError(
                "transport grace parity policy does not bind grant"
            )
        if semantic_work_unit_id != grant.semantic_work_unit_id:
            raise ResourceGrantError(
                "transport grace work-unit/grant binding mismatch"
            )
        if attempt_number > grant.max_execution_attempts:
            raise ResourceGrantError(
                "transport grace attempt exceeds grant retry denominator"
            )
        return cls(
            resource_grant_digest=grant.resource_grant_digest,
            parity_policy_digest=parity_policy.parity_policy_digest,
            semantic_work_unit_id=semantic_work_unit_id,
            attempt_number=attempt_number,
            use_id=use_id,
            authorized_max_grace_seconds=(
                parity_policy.max_transport_grace_seconds_per_use
            ),
            parity_mode=parity_policy.parity_mode,
            grace_seconds=grace_seconds,
            reason_code=reason_code,
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "resource_grant_digest": self.resource_grant_digest,
            "parity_policy_digest": self.parity_policy_digest,
            "semantic_work_unit_id": self.semantic_work_unit_id,
            "attempt_number": self.attempt_number,
            "use_id": self.use_id,
            "authorized_max_grace_seconds": (
                self.authorized_max_grace_seconds
            ),
            "parity_mode": self.parity_mode,
            "grace_seconds": self.grace_seconds,
            "reason_code": self.reason_code,
        }

    @property
    def transport_grace_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "transport_grace_digest": self.transport_grace_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def validate_against(
        self,
        grant: ResourceGrant,
        *,
        parity_policy: ParityPolicyAuthority,
    ) -> None:
        if type(grant) is not ResourceGrant:
            raise ResourceGrantError("grant must be ResourceGrant")
        if self.resource_grant_digest != grant.resource_grant_digest:
            raise ResourceGrantError(
                "transport grace resource_grant_digest mismatch"
            )
        if type(parity_policy) is not ParityPolicyAuthority:
            raise ResourceGrantError(
                "typed parity policy authority is required"
            )
        if self.parity_policy_digest != parity_policy.parity_policy_digest:
            raise ResourceGrantError(
                "transport grace parity policy digest mismatch"
            )
        if self.semantic_work_unit_id != grant.semantic_work_unit_id:
            raise ResourceGrantError(
                "transport grace semantic work-unit mismatch"
            )
        if self.attempt_number > grant.max_execution_attempts:
            raise ResourceGrantError(
                "transport grace attempt exceeds grant retry denominator"
            )
        expected = TransportGrace.create(
            grant=grant,
            parity_policy=parity_policy,
            semantic_work_unit_id=self.semantic_work_unit_id,
            attempt_number=self.attempt_number,
            use_id=self.use_id,
            grace_seconds=self.grace_seconds,
            reason_code=self.reason_code,
        )
        if self != expected:
            raise ResourceGrantError(
                "transport grace does not exactly replay from grant/parity/"
                "attempt/use authority"
            )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransportGrace":
        _require_exact_keys(value, _GRACE_KEYS, "transport grace")
        if value["schema"] != TRANSPORT_GRACE_SCHEMA:
            raise ResourceGrantError("unsupported transport grace schema")
        claimed = _sha256(
            value["transport_grace_digest"], "transport_grace_digest"
        )
        grace = cls(
            resource_grant_digest=value["resource_grant_digest"],
            parity_policy_digest=value["parity_policy_digest"],
            semantic_work_unit_id=value["semantic_work_unit_id"],
            attempt_number=value["attempt_number"],
            use_id=value["use_id"],
            authorized_max_grace_seconds=value[
                "authorized_max_grace_seconds"
            ],
            parity_mode=value["parity_mode"],
            grace_seconds=value["grace_seconds"],
            reason_code=value["reason_code"],
        )
        if claimed != grace.transport_grace_digest:
            raise ResourceGrantError(
                "transport_grace_digest digest mismatch"
            )
        return grace

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        grant: ResourceGrant,
        parity_policy: ParityPolicyAuthority,
    ) -> "TransportGrace":
        grace = cls.from_dict(_decode_record(raw))
        grace.validate_against(
            grant,
            parity_policy=parity_policy,
        )
        return grace


@dataclass(frozen=True, slots=True)
class TransportPlan:
    """Aggregate, one-use transport-grace accounting for one work unit."""

    resource_grant_digest: str
    parity_policy_digest: str
    parity_mode: str
    semantic_work_unit_id: str
    max_execution_attempts: int
    grace_uses: tuple[TransportGrace, ...]
    _derivation_token: InitVar[object] = None

    schema: ClassVar[str] = TRANSPORT_PLAN_SCHEMA

    def __post_init__(self, _derivation_token: object) -> None:
        if _derivation_token is not _DERIVATION_TOKEN:
            raise ResourceGrantError(
                "transport plan requires deterministic compilation/replay"
            )
        _sha256(self.resource_grant_digest, "resource_grant_digest")
        _sha256(self.parity_policy_digest, "parity_policy_digest")
        parity_mode = _closed(
            self.parity_mode, PARITY_MODES, "parity_mode"
        )
        _safe_id(self.semantic_work_unit_id, "semantic_work_unit_id")
        _positive_int(
            self.max_execution_attempts, "max_execution_attempts"
        )
        uses = tuple(
            sorted(
                self.grace_uses,
                key=lambda row: (row.attempt_number, row.use_id),
            )
        )
        if not all(type(row) is TransportGrace for row in uses):
            raise ResourceGrantError(
                "transport plan uses must be TransportGrace records"
            )
        use_ids = tuple(row.use_id for row in uses)
        attempts = tuple(row.attempt_number for row in uses)
        if (
            len(use_ids) != len(set(use_ids))
            or len(attempts) != len(set(attempts))
        ):
            raise ResourceGrantError(
                "transport grace use/attempt may be accounted only once"
            )
        for row in uses:
            if (
                row.resource_grant_digest != self.resource_grant_digest
                or row.parity_policy_digest != self.parity_policy_digest
                or row.parity_mode != parity_mode
                or row.semantic_work_unit_id != self.semantic_work_unit_id
                or row.attempt_number > self.max_execution_attempts
            ):
                raise ResourceGrantError(
                    "transport grace use does not bind aggregate plan"
                )
        if parity_mode == "STRICT_PAIRED" and any(
            row.grace_seconds != 0
            or row.authorized_max_grace_seconds != 0
            for row in uses
        ):
            raise ResourceGrantError(
                "strict paired transport plan requires zero grace"
            )
        object.__setattr__(self, "grace_uses", uses)

    @property
    def total_grace_seconds(self) -> int:
        return sum(row.grace_seconds for row in self.grace_uses)

    @property
    def usage_signature(self) -> tuple[tuple[int, str, int], ...]:
        return tuple(
            (row.attempt_number, row.reason_code, row.grace_seconds)
            for row in self.grace_uses
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "resource_grant_digest": self.resource_grant_digest,
            "parity_policy_digest": self.parity_policy_digest,
            "parity_mode": self.parity_mode,
            "semantic_work_unit_id": self.semantic_work_unit_id,
            "max_execution_attempts": self.max_execution_attempts,
            "grace_uses": [row.to_dict() for row in self.grace_uses],
            "grace_use_count": len(self.grace_uses),
            "total_grace_seconds": self.total_grace_seconds,
        }

    @property
    def transport_plan_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "transport_plan_digest": self.transport_plan_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        grant: ResourceGrant,
        parity_policy: ParityPolicyAuthority,
        resource_policy_authority: ResourcePolicyAuthority,
        global_reservation: GlobalResourceReservation,
    ) -> "TransportPlan":
        """Production replay from the grant's exact scheduler parents."""

        return cls._from_bytes(
            raw,
            grant=grant,
            parity_policy=parity_policy,
            resource_policy_authority=resource_policy_authority,
            global_reservation=global_reservation,
        )

    @classmethod
    def from_structural_test_bytes(
        cls,
        raw: bytes,
        *,
        grant: ResourceGrant,
        parity_policy: ParityPolicyAuthority,
    ) -> "TransportPlan":
        """Test-only replay; never establishes production resource authority."""

        return cls._from_bytes(
            raw,
            grant=grant,
            parity_policy=parity_policy,
            _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
        )

    @classmethod
    def _from_bytes(
        cls,
        raw: bytes,
        *,
        grant: ResourceGrant,
        parity_policy: ParityPolicyAuthority,
        resource_policy_authority: ResourcePolicyAuthority | None = None,
        global_reservation: GlobalResourceReservation | None = None,
        _structural_test_token: object = None,
    ) -> "TransportPlan":
        value = _decode_record(raw)
        expected_keys = {
            "schema",
            "resource_grant_digest",
            "parity_policy_digest",
            "parity_mode",
            "semantic_work_unit_id",
            "max_execution_attempts",
            "grace_uses",
            "grace_use_count",
            "total_grace_seconds",
            "transport_plan_digest",
        }
        _require_exact_keys(value, frozenset(expected_keys), "transport plan")
        if not isinstance(value["grace_uses"], list):
            raise ResourceGrantError("transport plan grace_uses must be array")
        uses = tuple(
            TransportGrace.from_dict(row) for row in value["grace_uses"]
        )
        replayed = _compile_transport_plan(
            grant=grant,
            parity_policy=parity_policy,
            grace_uses=uses,
            resource_policy_authority=resource_policy_authority,
            global_reservation=global_reservation,
            _structural_test_token=_structural_test_token,
        )
        if value != replayed.to_dict():
            raise ResourceGrantError(
                "transport plan does not match aggregate one-use replay"
            )
        return replayed


def _compile_transport_plan(
    *,
    grant: ResourceGrant,
    parity_policy: ParityPolicyAuthority,
    grace_uses: Iterable[TransportGrace],
    resource_policy_authority: ResourcePolicyAuthority | None = None,
    global_reservation: GlobalResourceReservation | None = None,
    _structural_test_token: object = None,
) -> TransportPlan:
    if type(grant) is not ResourceGrant:
        raise ResourceGrantError("grant must be ResourceGrant")
    if _structural_test_token is _STRUCTURAL_TEST_RESOURCE_TOKEN:
        grant.require_exact_replay()
    else:
        _require_resource_grant_parent_replay(
            grant,
            policy_authority=resource_policy_authority,
            global_reservation=global_reservation,
        )
    if type(parity_policy) is not ParityPolicyAuthority:
        raise ResourceGrantError(
            "typed parity policy authority is required"
        )
    if _structural_test_token is not _STRUCTURAL_TEST_RESOURCE_TOKEN:
        if (
            type(resource_policy_authority) is not ResourcePolicyAuthority
            or parity_policy
            != resource_policy_authority.parity_policy
        ):
            raise ResourceGrantError(
                "transport parity policy does not replay from the exact "
                "resource policy authority"
            )
    if (
        grant.parity_policy_digest != parity_policy.parity_policy_digest
        or grant.parity_mode != parity_policy.parity_mode
    ):
        raise ResourceGrantError(
            "transport plan parity policy does not bind grant"
        )
    try:
        iterator = iter(grace_uses)
    except TypeError as exc:
        raise ResourceGrantError(
            "transport grace uses must be a bounded iterable"
        ) from exc
    bounded_uses: list[TransportGrace] = []
    for _index in range(grant.max_execution_attempts + 1):
        try:
            bounded_uses.append(next(iterator))
        except StopIteration:
            break
    if len(bounded_uses) > grant.max_execution_attempts:
        raise ResourceGrantError(
            "transport grace use denominator exceeds the grant attempt bound"
        )
    uses = tuple(bounded_uses)
    for use in uses:
        use.validate_against(grant, parity_policy=parity_policy)
    return TransportPlan(
        resource_grant_digest=grant.resource_grant_digest,
        parity_policy_digest=parity_policy.parity_policy_digest,
        parity_mode=parity_policy.parity_mode,
        semantic_work_unit_id=grant.semantic_work_unit_id,
        max_execution_attempts=grant.max_execution_attempts,
        grace_uses=uses,
        _derivation_token=_DERIVATION_TOKEN,
    )


def compile_transport_plan(
    *,
    grant: ResourceGrant,
    parity_policy: ParityPolicyAuthority,
    grace_uses: Iterable[TransportGrace],
    resource_policy_authority: ResourcePolicyAuthority,
    global_reservation: GlobalResourceReservation,
) -> TransportPlan:
    """Production compiler rooted in exact policy and scheduler parents."""

    return _compile_transport_plan(
        grant=grant,
        parity_policy=parity_policy,
        grace_uses=grace_uses,
        resource_policy_authority=resource_policy_authority,
        global_reservation=global_reservation,
    )


def compile_structural_test_transport_plan(
    *,
    grant: ResourceGrant,
    parity_policy: ParityPolicyAuthority,
    grace_uses: Iterable[TransportGrace],
) -> TransportPlan:
    """Test-only compiler; output is not production resource authority."""

    return _compile_transport_plan(
        grant=grant,
        parity_policy=parity_policy,
        grace_uses=grace_uses,
        _structural_test_token=_STRUCTURAL_TEST_RESOURCE_TOKEN,
    )


__all__ = [
    "AUDIT_MODES",
    "CACHE_POLICIES",
    "MIN_RUNNABLE_INPUT_TOKENS",
    "MIN_RUNNABLE_OUTPUT_TOKENS",
    "PARITY_MODES",
    "PAIRED_RESOURCE_COMPARISON_SCHEMA",
    "PairedResourceComparison",
    "RESOURCE_GRANT_SCHEMA",
    "RESOURCE_PROFILES",
    "ResourceGrant",
    "ResourceGrantError",
    "SCHEDULER_CONCURRENCY_CLASSES",
    "TRANSPORT_GRACE_REASONS",
    "TRANSPORT_GRACE_SCHEMA",
    "TRANSPORT_PLAN_SCHEMA",
    "ToolCallLimit",
    "TransportGrace",
    "TransportPlan",
    "WORKLOAD_CLASSES",
    "compare_paired_resource_grants",
    "compare_structural_test_paired_resource_grants",
    "compile_resource_grant_from_policy",
    "compile_structural_test_resource_grant_from_policy",
    "compile_structural_test_preflight_request_from_resource_grant",
    "compile_structural_test_transport_plan",
    "compile_transport_plan",
    "compile_preflight_request_from_resource_grant",
    "replay_resource_grant_from_policy",
    "replay_structural_test_resource_grant_from_policy",
    "replay_structural_test_preflight_request_authority_from_resource_grant",
    "replay_preflight_request_authority_from_resource_grant",
    "validate_resource_grant_against_semantic_work_plan",
    "validate_structural_test_resource_grant_against_semantic_work_plan",
]
