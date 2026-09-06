"""Typed, replayable resource-policy and global-reservation authority.

This module contains policy facts only.  It does not construct execution
commands, inspect providers, or mutate reservations.  A resource grant is
derived elsewhere from one exact policy ceiling and one exact allocation.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import InitVar, dataclass, field
import hashlib
import re
import threading
from types import MappingProxyType
from typing import Any, ClassVar
import weakref

from backend_capability_registry import SEMANTIC_TOOL_CAPABILITIES
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)


RESOURCE_POLICY_AUTHORITY_SCHEMA = "plamen.resource-policy-authority.v1"
GLOBAL_RESOURCE_RESERVATION_SCHEMA = "plamen.global-resource-reservation.v1"
PARITY_POLICY_AUTHORITY_SCHEMA = "plamen.parity-policy-authority.v1"
REVIEWED_RESOURCE_POLICY_SOURCE_SCHEMA = (
    "plamen.reviewed-resource-policy-source.v1"
)
RESOURCE_AUTHORITY_DEBT_SCHEMA = "plamen.resource-authority-debt.v1"

MAX_RESERVATION_ALLOCATIONS = 4_096
MAX_TOTAL_ANALYSIS_UNITS = 1_000_000
MAX_RESERVATION_CANONICAL_BYTES = 8 * 1024 * 1024

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
SCHEDULER_CLASSES = frozenset({"SERIAL", "STRICT_PAIRED", "BOUNDED_POOL"})
CACHE_POLICIES = frozenset(
    {
        "COLD_REQUIRED",
        "WARM_RECORDED",
        "CACHE_DISABLED",
        "PROVIDER_DEFAULT_BOUND",
    }
)
PARITY_MODES = frozenset({"NON_PAIRED_OPERATIONAL", "STRICT_PAIRED"})

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,191}$", re.ASCII)
_SENSITIVE_RE = re.compile(
    r"(?:\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{16,}\b"
    r"|\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE | re.ASCII,
)
_AUTHORITY_TOKEN = object()
_SOURCE_SNAPSHOT_TOKEN = object()
_RESERVATION_BUDGET_TOKEN = object()
_REVIEWED_RESOURCE_POLICY_SOURCES: Mapping[str, bytes]


class ResourcePolicyError(ValueError):
    """A resource policy or reservation is open or inconsistent."""

    def __init__(
        self,
        message: str,
        *,
        debt: "ResourceAuthorityDebt | None" = None,
    ) -> None:
        super().__init__(message)
        self.debt = debt


class _IdentitySealRegistry:
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

    def require(
        self,
        value: Any,
        *,
        exact_type: type,
        canonical: bytes,
        label: str,
    ) -> bytes:
        if type(value) is not exact_type:
            raise ResourcePolicyError(f"exact {label} type is required")
        with self._lock:
            current = self._entries.get(id(value))
            if current is None or current[0]() is not value:
                raise ResourcePolicyError(
                    f"{label} external issuance seal is absent"
                )
            sealed = current[1]
        if canonical != sealed:
            raise ResourcePolicyError(f"{label} seal/replay drifted")
        return bytes(sealed)


_RESERVATION_BUDGET_AUTHORITY_SEALS = _IdentitySealRegistry()
_RESOURCE_POLICY_AUTHORITY_SEALS = _IdentitySealRegistry()
_GLOBAL_RESOURCE_RESERVATION_SEALS = _IdentitySealRegistry()


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_json_bytes(value)
    except ProgramFactsTypeError as exc:
        raise ResourcePolicyError(str(exc)) from exc


def _canonical_file(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_file_bytes(value)
    except ProgramFactsTypeError as exc:
        raise ResourcePolicyError(str(exc)) from exc


def _decode(raw: bytes) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(raw, require_final_lf=True)
    except ProgramFactsTypeError as exc:
        raise ResourcePolicyError(str(exc)) from exc
    if not isinstance(value, Mapping):
        raise ResourcePolicyError("record must be a JSON object")
    return value


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ResourcePolicyError(f"{context} fields are not exact")


def _sha(value: Any, field: str) -> str:
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        raise ResourcePolicyError(f"{field} must be a lowercase SHA-256")
    return value


def _identifier(value: Any, field: str) -> str:
    if (
        type(value) is not str
        or _ID_RE.fullmatch(value) is None
        or value in {".", ".."}
        or _SENSITIVE_RE.search(value)
    ):
        raise ResourcePolicyError(
            f"{field} must be a privacy-safe ASCII identity"
        )
    return value


def _integer(value: Any, field: str, *, positive: bool = False) -> int:
    if type(value) is not int:
        raise ResourcePolicyError(f"{field} must be an integer")
    if value < (1 if positive else 0):
        raise ResourcePolicyError(
            f"{field} must be {'positive' if positive else 'non-negative'}"
        )
    return value


def _enum(value: Any, allowed: frozenset[str], field: str) -> str:
    if type(value) is not str or value not in allowed:
        raise ResourcePolicyError(f"{field} is not in the closed vocabulary")
    return value


@dataclass(frozen=True, slots=True)
class ResourceAuthorityDebt:
    """Canonical fail-closed reason for unavailable production authority."""

    reservation_id: str
    reservation_digest: str
    observed_authority_class: str
    phase_roster_digest: str
    scheduler_budget_digest: str
    debt_code: str = "PRODUCTION_SCHEDULER_AUTHORITY_UNAVAILABLE"

    schema: ClassVar[str] = RESOURCE_AUTHORITY_DEBT_SCHEMA

    def __post_init__(self) -> None:
        _identifier(self.reservation_id, "reservation_id")
        _sha(self.reservation_digest, "reservation_digest")
        _identifier(
            self.observed_authority_class,
            "observed_authority_class",
        )
        _sha(self.phase_roster_digest, "phase_roster_digest")
        _sha(self.scheduler_budget_digest, "scheduler_budget_digest")
        if self.debt_code != (
            "PRODUCTION_SCHEDULER_AUTHORITY_UNAVAILABLE"
        ):
            raise ResourcePolicyError(
                "resource authority debt code is not closed"
            )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "debt_code": self.debt_code,
            "reservation_id": self.reservation_id,
            "reservation_digest": self.reservation_digest,
            "observed_authority_class": self.observed_authority_class,
            "phase_roster_digest": self.phase_roster_digest,
            "scheduler_budget_digest": self.scheduler_budget_digest,
        }

    @property
    def debt_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "debt_digest": self.debt_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ResourceAuthorityDebt":
        if cls is not ResourceAuthorityDebt:
            raise ResourcePolicyError(
                "ResourceAuthorityDebt replay requires exact base class"
            )
        value = _decode(raw)
        _keys(
            value,
            {
                "schema",
                "debt_code",
                "reservation_id",
                "reservation_digest",
                "observed_authority_class",
                "phase_roster_digest",
                "scheduler_budget_digest",
                "debt_digest",
            },
            "resource authority debt",
        )
        if value["schema"] != RESOURCE_AUTHORITY_DEBT_SCHEMA:
            raise ResourcePolicyError(
                "unsupported resource authority debt schema"
            )
        debt = ResourceAuthorityDebt(
            reservation_id=value["reservation_id"],
            reservation_digest=value["reservation_digest"],
            observed_authority_class=value["observed_authority_class"],
            phase_roster_digest=value["phase_roster_digest"],
            scheduler_budget_digest=value["scheduler_budget_digest"],
            debt_code=value["debt_code"],
        )
        if value != debt.to_dict():
            raise ResourcePolicyError(
                "resource authority debt does not exactly replay"
            )
        return debt


class ResourcePolicySourceSnapshot:
    """Opaque identity of exact bytes from the closed reviewed source set."""

    __slots__ = ("__raw", "__sha256")

    def __new__(
        cls,
        *,
        _token: object,
        raw: bytes,
    ) -> "ResourcePolicySourceSnapshot":
        if _token is not _SOURCE_SNAPSHOT_TOKEN:
            raise TypeError("ResourcePolicySourceSnapshot is opaque")
        instance = super().__new__(cls)
        instance.__raw = raw
        instance.__sha256 = hashlib.sha256(raw).hexdigest()
        return instance

    def __repr__(self) -> str:
        return (
            "<ResourcePolicySourceSnapshot "
            f"sha256={self.__sha256}>"
        )

    def __reduce__(self) -> None:
        raise TypeError("ResourcePolicySourceSnapshot cannot be serialized")

    def __copy__(self) -> None:
        raise TypeError("ResourcePolicySourceSnapshot cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("ResourcePolicySourceSnapshot cannot be copied")

    @property
    def source_authority_digest(self) -> str:
        return self.__sha256

    def to_bytes(self) -> bytes:
        return bytes(self.__raw)

    def replay(self) -> "ResourcePolicySourceSnapshot":
        return capture_resource_policy_source_snapshot(self.__raw)


def capture_resource_policy_source_snapshot(
    raw: bytes,
) -> ResourcePolicySourceSnapshot:
    """Capture one exact source from the closed reviewed policy registry."""

    if type(raw) is not bytes or not raw or len(raw) > 4 * 1024 * 1024:
        raise ResourcePolicyError(
            "resource policy source bytes are missing or exceed the bound"
        )
    value = _decode(raw)
    if _canonical_file(value) != raw:
        raise ResourcePolicyError(
            "resource policy source bytes must be canonical JSON"
        )
    _reviewed_source_configuration(raw)
    return ResourcePolicySourceSnapshot(
        _token=_SOURCE_SNAPSHOT_TOKEN,
        raw=bytes(raw),
    )


@dataclass(frozen=True, slots=True)
class PolicyToolLimit:
    tool_capability: str
    max_calls_per_attempt: int

    def __post_init__(self) -> None:
        _enum(
            self.tool_capability,
            SEMANTIC_TOOL_CAPABILITIES,
            "tool_capability",
        )
        _integer(
            self.max_calls_per_attempt,
            "max_calls_per_attempt",
            positive=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_capability": self.tool_capability,
            "max_calls_per_attempt": self.max_calls_per_attempt,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PolicyToolLimit":
        _keys(
            value,
            {"tool_capability", "max_calls_per_attempt"},
            "policy tool limit",
        )
        return cls(
            tool_capability=value["tool_capability"],
            max_calls_per_attempt=value["max_calls_per_attempt"],
        )


def _tool_limits(
    values: Iterable[PolicyToolLimit],
) -> tuple[PolicyToolLimit, ...]:
    rows = tuple(sorted(values, key=lambda row: row.tool_capability))
    if not all(type(row) is PolicyToolLimit for row in rows):
        raise ResourcePolicyError(
            "tool limits must contain PolicyToolLimit records"
        )
    names = tuple(row.tool_capability for row in rows)
    if len(names) != len(set(names)):
        raise ResourcePolicyError("policy tool denominator has duplicates")
    return rows


@dataclass(frozen=True, slots=True)
class ResourceCeiling:
    audit_mode: str
    phase_semantic_id: str
    workload_class: str
    analysis_units_per_attempt: int
    max_attempts: int
    max_input_tokens_per_attempt: int
    max_output_tokens_per_attempt: int
    tool_limits: tuple[PolicyToolLimit, ...]
    max_native_commands_per_attempt: int
    max_native_wall_time_seconds_per_attempt: int
    semantic_timeout_seconds_per_attempt: int
    max_stdout_bytes_per_attempt: int
    max_stderr_bytes_per_attempt: int
    max_stream_line_bytes: int

    def __post_init__(self) -> None:
        _enum(self.audit_mode, AUDIT_MODES, "audit_mode")
        _identifier(self.phase_semantic_id, "phase_semantic_id")
        _enum(self.workload_class, WORKLOAD_CLASSES, "workload_class")
        for field in (
            "analysis_units_per_attempt",
            "max_input_tokens_per_attempt",
            "max_output_tokens_per_attempt",
            "max_native_commands_per_attempt",
            "max_native_wall_time_seconds_per_attempt",
        ):
            _integer(getattr(self, field), field)
        for field in (
            "max_attempts",
            "semantic_timeout_seconds_per_attempt",
            "max_stdout_bytes_per_attempt",
            "max_stderr_bytes_per_attempt",
            "max_stream_line_bytes",
        ):
            _integer(getattr(self, field), field, positive=True)
        if (self.max_native_commands_per_attempt == 0) != (
            self.max_native_wall_time_seconds_per_attempt == 0
        ):
            raise ResourcePolicyError(
                "native command/time policy ceilings must agree"
            )
        if self.max_stream_line_bytes > min(
            self.max_stdout_bytes_per_attempt,
            self.max_stderr_bytes_per_attempt,
        ):
            raise ResourcePolicyError(
                "stream line ceiling exceeds stream budgets"
            )
        object.__setattr__(self, "tool_limits", _tool_limits(self.tool_limits))

    @property
    def key(self) -> tuple[str, str, str]:
        return (
            self.audit_mode,
            self.phase_semantic_id,
            self.workload_class,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_mode": self.audit_mode,
            "phase_semantic_id": self.phase_semantic_id,
            "workload_class": self.workload_class,
            "analysis_units_per_attempt": self.analysis_units_per_attempt,
            "max_attempts": self.max_attempts,
            "max_input_tokens_per_attempt": (
                self.max_input_tokens_per_attempt
            ),
            "max_output_tokens_per_attempt": (
                self.max_output_tokens_per_attempt
            ),
            "tool_limits": [row.to_dict() for row in self.tool_limits],
            "max_native_commands_per_attempt": (
                self.max_native_commands_per_attempt
            ),
            "max_native_wall_time_seconds_per_attempt": (
                self.max_native_wall_time_seconds_per_attempt
            ),
            "semantic_timeout_seconds_per_attempt": (
                self.semantic_timeout_seconds_per_attempt
            ),
            "max_stdout_bytes_per_attempt": (
                self.max_stdout_bytes_per_attempt
            ),
            "max_stderr_bytes_per_attempt": (
                self.max_stderr_bytes_per_attempt
            ),
            "max_stream_line_bytes": self.max_stream_line_bytes,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResourceCeiling":
        expected = {
            "audit_mode",
            "phase_semantic_id",
            "workload_class",
            "analysis_units_per_attempt",
            "max_attempts",
            "max_input_tokens_per_attempt",
            "max_output_tokens_per_attempt",
            "tool_limits",
            "max_native_commands_per_attempt",
            "max_native_wall_time_seconds_per_attempt",
            "semantic_timeout_seconds_per_attempt",
            "max_stdout_bytes_per_attempt",
            "max_stderr_bytes_per_attempt",
            "max_stream_line_bytes",
        }
        _keys(value, expected, "resource ceiling")
        if not isinstance(value["tool_limits"], list):
            raise ResourcePolicyError("tool_limits must be an array")
        return cls(
            **{
                key: value[key]
                for key in expected
                if key != "tool_limits"
            },
            tool_limits=tuple(
                PolicyToolLimit.from_dict(row)
                for row in value["tool_limits"]
            ),
        )


@dataclass(frozen=True, slots=True)
class ParityPolicyAuthority:
    policy_id: str
    policy_generation: int
    parity_mode: str
    scheduler_concurrency_class: str
    max_concurrency: int
    cache_policy: str
    max_transport_grace_seconds_per_use: int
    source_authority_digest: str

    schema: ClassVar[str] = PARITY_POLICY_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        _identifier(self.policy_id, "parity policy_id")
        _integer(self.policy_generation, "policy_generation", positive=True)
        parity_mode = _enum(self.parity_mode, PARITY_MODES, "parity_mode")
        scheduler = _enum(
            self.scheduler_concurrency_class,
            SCHEDULER_CLASSES,
            "scheduler_concurrency_class",
        )
        _integer(self.max_concurrency, "max_concurrency", positive=True)
        cache = _enum(self.cache_policy, CACHE_POLICIES, "cache_policy")
        _integer(
            self.max_transport_grace_seconds_per_use,
            "max_transport_grace_seconds_per_use",
        )
        _sha(self.source_authority_digest, "source_authority_digest")
        if parity_mode == "STRICT_PAIRED":
            if scheduler != "STRICT_PAIRED":
                raise ResourcePolicyError(
                    "strict parity requires STRICT_PAIRED scheduler"
                )
            if cache == "PROVIDER_DEFAULT_BOUND":
                raise ResourcePolicyError(
                    "strict parity forbids provider-default cache"
                )
            if self.max_transport_grace_seconds_per_use != 0:
                raise ResourcePolicyError(
                    "strict parity requires zero transport grace"
                )
        elif scheduler == "STRICT_PAIRED":
            raise ResourcePolicyError(
                "STRICT_PAIRED scheduler requires strict parity policy"
            )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "policy_generation": self.policy_generation,
            "parity_mode": self.parity_mode,
            "scheduler_concurrency_class": (
                self.scheduler_concurrency_class
            ),
            "max_concurrency": self.max_concurrency,
            "cache_policy": self.cache_policy,
            "max_transport_grace_seconds_per_use": (
                self.max_transport_grace_seconds_per_use
            ),
            "source_authority_digest": self.source_authority_digest,
        }

    @property
    def parity_policy_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "parity_policy_digest": self.parity_policy_digest,
        }


def _reviewed_source_payload(
    *,
    source_id: str,
    parity_mode: str,
    scheduler_concurrency_class: str,
    max_concurrency: int,
    cache_policy: str,
    max_transport_grace_seconds_per_use: int,
    ceiling: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": REVIEWED_RESOURCE_POLICY_SOURCE_SCHEMA,
        "source_id": source_id,
        "policy_id": "resource-policy-001",
        "policy_generation": 1,
        "profile": "adaptive-au-v1",
        "parity_policy": {
            "policy_id": "parity-policy-001",
            "policy_generation": 1,
            "parity_mode": parity_mode,
            "scheduler_concurrency_class": scheduler_concurrency_class,
            "max_concurrency": max_concurrency,
            "cache_policy": cache_policy,
            "max_transport_grace_seconds_per_use": (
                max_transport_grace_seconds_per_use
            ),
        },
        "ceilings": [dict(ceiling)],
    }


def _standard_ceiling_payload() -> dict[str, Any]:
    return {
        "audit_mode": "thorough",
        "phase_semantic_id": "depth",
        "workload_class": "STANDARD_ANALYSIS",
        "analysis_units_per_attempt": 1,
        "max_attempts": 2,
        "max_input_tokens_per_attempt": 65_536,
        "max_output_tokens_per_attempt": 8_192,
        "tool_limits": [
            {
                "tool_capability": "ASSIGNED_OUTPUT_WRITE",
                "max_calls_per_attempt": 1,
            },
            {
                "tool_capability": "METHODOLOGY_READ",
                "max_calls_per_attempt": 3,
            },
            {
                "tool_capability": "SOURCE_READ",
                "max_calls_per_attempt": 12,
            },
            {
                "tool_capability": "SOURCE_SEARCH",
                "max_calls_per_attempt": 8,
            },
        ],
        "max_native_commands_per_attempt": 0,
        "max_native_wall_time_seconds_per_attempt": 0,
        "semantic_timeout_seconds_per_attempt": 3_600,
        "max_stdout_bytes_per_attempt": 2_000_000,
        "max_stderr_bytes_per_attempt": 1_000_000,
        "max_stream_line_bytes": 65_536,
    }


def _reviewed_source_payloads() -> tuple[dict[str, Any], ...]:
    standard = _standard_ceiling_payload()
    proof = {
        **standard,
        "workload_class": "PROOF_CAPABLE",
        "analysis_units_per_attempt": 2,
        "max_input_tokens_per_attempt": 131_072,
        "max_output_tokens_per_attempt": 12_288,
        "tool_limits": [
            {
                "tool_capability": "ASSIGNED_OUTPUT_WRITE",
                "max_calls_per_attempt": 2,
            },
            {
                "tool_capability": "METHODOLOGY_READ",
                "max_calls_per_attempt": 6,
            },
            {
                "tool_capability": "NATIVE_TEST",
                "max_calls_per_attempt": 4,
            },
            {
                "tool_capability": "SOURCE_READ",
                "max_calls_per_attempt": 24,
            },
            {
                "tool_capability": "SOURCE_SEARCH",
                "max_calls_per_attempt": 12,
            },
        ],
        "max_native_commands_per_attempt": 4,
        "max_native_wall_time_seconds_per_attempt": 1_200,
        "semantic_timeout_seconds_per_attempt": 7_200,
        "max_stdout_bytes_per_attempt": 4_000_000,
        "max_stderr_bytes_per_attempt": 2_000_000,
        "max_stream_line_bytes": 131_072,
    }
    native = {
        **standard,
        "workload_class": "NATIVE_DETERMINISTIC",
        "analysis_units_per_attempt": 0,
        "max_attempts": 1,
        "max_input_tokens_per_attempt": 0,
        "max_output_tokens_per_attempt": 0,
        "tool_limits": [],
        "max_native_commands_per_attempt": 1,
        "max_native_wall_time_seconds_per_attempt": 60,
        "semantic_timeout_seconds_per_attempt": 60,
        "max_stdout_bytes_per_attempt": 1_024,
        "max_stderr_bytes_per_attempt": 1_024,
        "max_stream_line_bytes": 1_024,
    }
    strict = {
        "parity_mode": "STRICT_PAIRED",
        "scheduler_concurrency_class": "STRICT_PAIRED",
        "cache_policy": "COLD_REQUIRED",
        "max_transport_grace_seconds_per_use": 0,
    }
    operational = {
        "parity_mode": "NON_PAIRED_OPERATIONAL",
        "scheduler_concurrency_class": "BOUNDED_POOL",
        "cache_policy": "COLD_REQUIRED",
        "max_transport_grace_seconds_per_use": 30,
    }
    return (
        _reviewed_source_payload(
            source_id="adaptive-au-v1-standard-strict-c2",
            max_concurrency=2,
            ceiling=standard,
            **strict,
        ),
        _reviewed_source_payload(
            source_id="adaptive-au-v1-standard-strict-c1",
            max_concurrency=1,
            ceiling=standard,
            **strict,
        ),
        _reviewed_source_payload(
            source_id="adaptive-au-v1-standard-operational-c2",
            max_concurrency=2,
            ceiling=standard,
            **operational,
        ),
        _reviewed_source_payload(
            source_id="adaptive-au-v1-proof-strict-c2",
            max_concurrency=2,
            ceiling=proof,
            **strict,
        ),
        _reviewed_source_payload(
            source_id="adaptive-au-v1-native-operational-c1",
            parity_mode="NON_PAIRED_OPERATIONAL",
            scheduler_concurrency_class="SERIAL",
            max_concurrency=1,
            cache_policy="CACHE_DISABLED",
            max_transport_grace_seconds_per_use=30,
            ceiling=native,
        ),
    )


def _reviewed_source_configuration(
    raw: bytes,
) -> tuple[
    str,
    int,
    str,
    ParityPolicyAuthority,
    tuple[ResourceCeiling, ...],
]:
    value = _decode(raw)
    if value.get("schema") != REVIEWED_RESOURCE_POLICY_SOURCE_SCHEMA:
        raise ResourcePolicyError(
            "resource policy source is unavailable from the reviewed registry"
        )
    _keys(
        value,
        {
            "schema",
            "source_id",
            "policy_id",
            "policy_generation",
            "profile",
            "parity_policy",
            "ceilings",
        },
        "reviewed resource policy source",
    )
    source_id = _identifier(value["source_id"], "source_id")
    if _REVIEWED_RESOURCE_POLICY_SOURCES.get(source_id) != raw:
        raise ResourcePolicyError(
            "resource policy source is absent from the closed reviewed registry"
        )
    policy_id = _identifier(value["policy_id"], "policy_id")
    policy_generation = _integer(
        value["policy_generation"],
        "policy_generation",
        positive=True,
    )
    profile = _enum(value["profile"], RESOURCE_PROFILES, "profile")
    raw_parity = value["parity_policy"]
    _keys(
        raw_parity,
        {
            "policy_id",
            "policy_generation",
            "parity_mode",
            "scheduler_concurrency_class",
            "max_concurrency",
            "cache_policy",
            "max_transport_grace_seconds_per_use",
        },
        "reviewed parity policy source",
    )
    source_digest = hashlib.sha256(raw).hexdigest()
    parity = ParityPolicyAuthority(
        policy_id=raw_parity["policy_id"],
        policy_generation=raw_parity["policy_generation"],
        parity_mode=raw_parity["parity_mode"],
        scheduler_concurrency_class=raw_parity[
            "scheduler_concurrency_class"
        ],
        max_concurrency=raw_parity["max_concurrency"],
        cache_policy=raw_parity["cache_policy"],
        max_transport_grace_seconds_per_use=raw_parity[
            "max_transport_grace_seconds_per_use"
        ],
        source_authority_digest=source_digest,
    )
    if not isinstance(value["ceilings"], list) or not value["ceilings"]:
        raise ResourcePolicyError(
            "reviewed resource policy source has no ceiling denominator"
        )
    ceilings = tuple(
        ResourceCeiling.from_dict(row) for row in value["ceilings"]
    )
    return policy_id, policy_generation, profile, parity, ceilings


def reviewed_resource_policy_source_bytes(source_id: str) -> bytes:
    """Return canonical bytes for one closed reviewed resource-policy source."""

    reviewed_id = _identifier(source_id, "source_id")
    raw = _REVIEWED_RESOURCE_POLICY_SOURCES.get(reviewed_id)
    if raw is None:
        raise ResourcePolicyError(
            "resource policy source is unavailable from the reviewed registry"
        )
    return bytes(raw)


_REVIEWED_RESOURCE_POLICY_SOURCES = MappingProxyType(
    {
        payload["source_id"]: _canonical_file(payload)
        for payload in _reviewed_source_payloads()
    }
)


@dataclass(frozen=True, slots=True)
class ReservationAllocation:
    semantic_work_unit_id: str
    reserved_analysis_units: int

    def __post_init__(self) -> None:
        _identifier(self.semantic_work_unit_id, "semantic_work_unit_id")
        _integer(
            self.reserved_analysis_units,
            "reserved_analysis_units",
        )
        if self.reserved_analysis_units > MAX_TOTAL_ANALYSIS_UNITS:
            raise ResourcePolicyError(
                "reserved_analysis_units exceeds aggregate analysis bound"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_work_unit_id": self.semantic_work_unit_id,
            "reserved_analysis_units": self.reserved_analysis_units,
        }


def _bounded_reservation_allocations(
    allocations: Iterable[ReservationAllocation],
) -> tuple[ReservationAllocation, ...]:
    if type(allocations) is tuple:
        if len(allocations) > MAX_RESERVATION_ALLOCATIONS:
            raise ResourcePolicyError(
                "reservation allocation denominator exceeds count bound"
            )
        rows = allocations
    else:
        rows_list: list[ReservationAllocation] = []
        for row in allocations:
            if len(rows_list) >= MAX_RESERVATION_ALLOCATIONS:
                raise ResourcePolicyError(
                    "reservation allocation denominator exceeds count bound"
                )
            rows_list.append(row)
        rows = tuple(rows_list)
    if not all(type(row) is ReservationAllocation for row in rows):
        raise ResourcePolicyError(
            "reservation allocations require exact typed records"
        )
    ordered = tuple(
        sorted(rows, key=lambda row: row.semantic_work_unit_id)
    )
    if sum(row.reserved_analysis_units for row in ordered) > (
        MAX_TOTAL_ANALYSIS_UNITS
    ):
        raise ResourcePolicyError(
            "reservation aggregate analysis units exceed bound"
        )
    payload = _canonical_file(
        {
            "schema": "plamen.reservation-allocation-denominator.v1",
            "allocations": [row.to_dict() for row in ordered],
        }
    )
    if len(payload) > MAX_RESERVATION_CANONICAL_BYTES:
        raise ResourcePolicyError(
            "reservation allocation denominator exceeds byte bound"
        )
    return ordered


def _reservation_allocations_digest(
    allocations: tuple[ReservationAllocation, ...],
) -> str:
    rows = _bounded_reservation_allocations(allocations)
    return _digest(
        {
            "schema": "plamen.reservation-allocation-denominator.v1",
            "allocations": [row.to_dict() for row in rows],
        }
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ReservationBudgetAuthority:
    """Opaque phase-roster/scheduler budget binding for one reservation."""

    reservation_id: str
    run_id: str
    generation: int
    total_analysis_units: int
    allocations_digest: str
    phase_roster_digest: str
    scheduler_budget_digest: str
    authority_class: str
    _promotion_token: InitVar[object] = None

    def __post_init__(self, _promotion_token: object) -> None:
        if type(self) is not ReservationBudgetAuthority:
            raise ResourcePolicyError(
                "ReservationBudgetAuthority cannot be subclass-minted"
            )
        if _promotion_token is not _RESERVATION_BUDGET_TOKEN:
            raise ResourcePolicyError(
                "reservation budget authority is opaque"
            )
        _identifier(self.reservation_id, "reservation_id")
        _identifier(self.run_id, "run_id")
        _integer(self.generation, "generation", positive=True)
        _integer(
            self.total_analysis_units,
            "total_analysis_units",
            positive=True,
        )
        if self.total_analysis_units > MAX_TOTAL_ANALYSIS_UNITS:
            raise ResourcePolicyError(
                "total_analysis_units exceeds aggregate analysis bound"
            )
        _sha(self.allocations_digest, "allocations_digest")
        _sha(self.phase_roster_digest, "phase_roster_digest")
        _sha(self.scheduler_budget_digest, "scheduler_budget_digest")
        if self.authority_class != "STRUCTURAL_TEST_ONLY":
            raise ResourcePolicyError(
                "production phase-roster/scheduler issuer is unavailable; "
                "module-private tokens are not production proof"
            )
        _RESERVATION_BUDGET_AUTHORITY_SEALS.issue(
            self, self.to_bytes()
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": "plamen.reservation-budget-authority.v1",
            "reservation_id": self.reservation_id,
            "run_id": self.run_id,
            "generation": self.generation,
            "total_analysis_units": self.total_analysis_units,
            "allocations_digest": self.allocations_digest,
            "phase_roster_digest": self.phase_roster_digest,
            "scheduler_budget_digest": self.scheduler_budget_digest,
            "authority_class": self.authority_class,
        }

    @property
    def reservation_budget_authority_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "reservation_budget_authority_digest": (
                self.reservation_budget_authority_digest
            ),
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def require_exact_replay(self) -> bytes:
        sealed = _RESERVATION_BUDGET_AUTHORITY_SEALS.require(
            self,
            exact_type=ReservationBudgetAuthority,
            canonical=self.to_bytes(),
            label="reservation budget authority",
        )
        if self.authority_class != "STRUCTURAL_TEST_ONLY":
            raise ResourcePolicyError(
                "production scheduler issuer is unavailable; mutable "
                "authority class/seal is not production proof"
            )
        return sealed

    def validate_reservation(
        self,
        *,
        reservation_id: str,
        run_id: str,
        generation: int,
        total_analysis_units: int,
        allocations: tuple[ReservationAllocation, ...],
    ) -> None:
        self.require_exact_replay()
        rows = _bounded_reservation_allocations(allocations)
        supplied = (
            reservation_id,
            run_id,
            generation,
            total_analysis_units,
            _reservation_allocations_digest(rows),
        )
        expected = (
            self.reservation_id,
            self.run_id,
            self.generation,
            self.total_analysis_units,
            self.allocations_digest,
        )
        if supplied != expected:
            raise ResourcePolicyError(
                "reservation does not bind phase-roster/scheduler budget "
                "authority"
            )


def compile_structural_test_reservation_budget_authority(
    *,
    reservation_id: str,
    run_id: str,
    generation: int,
    total_analysis_units: int,
    allocations: Iterable[ReservationAllocation],
    phase_roster_digest: str,
    scheduler_budget_digest: str,
) -> ReservationBudgetAuthority:
    """Test-only stand-in until the production roster/scheduler issuer lands."""

    rows = _bounded_reservation_allocations(allocations)
    if not rows:
        raise ResourcePolicyError(
            "structural reservation authority requires exact allocations"
        )
    total = _integer(
        total_analysis_units,
        "total_analysis_units",
        positive=True,
    )
    if total > MAX_TOTAL_ANALYSIS_UNITS:
        raise ResourcePolicyError(
            "total_analysis_units exceeds aggregate analysis bound"
        )
    if sum(row.reserved_analysis_units for row in rows) > total:
        raise ResourcePolicyError(
            "structural reservation is over-allocated"
        )
    return ReservationBudgetAuthority(
        reservation_id=reservation_id,
        run_id=run_id,
        generation=generation,
        total_analysis_units=total,
        allocations_digest=_reservation_allocations_digest(rows),
        phase_roster_digest=_sha(
            phase_roster_digest, "phase_roster_digest"
        ),
        scheduler_budget_digest=_sha(
            scheduler_budget_digest, "scheduler_budget_digest"
        ),
        authority_class="STRUCTURAL_TEST_ONLY",
        _promotion_token=_RESERVATION_BUDGET_TOKEN,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class GlobalResourceReservation:
    reservation_id: str
    run_id: str
    generation: int
    total_analysis_units: int
    allocations: tuple[ReservationAllocation, ...]
    budget_authority: InitVar[ReservationBudgetAuthority | None] = None
    _budget_authority: ReservationBudgetAuthority = field(
        init=False, repr=False, compare=False
    )
    _sealed_reservation_bytes: bytes = field(
        init=False, repr=False, compare=False
    )

    schema: ClassVar[str] = GLOBAL_RESOURCE_RESERVATION_SCHEMA

    def __post_init__(
        self,
        budget_authority: ReservationBudgetAuthority | None,
    ) -> None:
        if type(budget_authority) is not ReservationBudgetAuthority:
            raise ResourcePolicyError(
                "trusted phase-roster/scheduler budget authority is required"
            )
        _identifier(self.reservation_id, "reservation_id")
        _identifier(self.run_id, "run_id")
        _integer(self.generation, "generation", positive=True)
        _integer(
            self.total_analysis_units,
            "total_analysis_units",
            positive=True,
        )
        if self.total_analysis_units > MAX_TOTAL_ANALYSIS_UNITS:
            raise ResourcePolicyError(
                "total_analysis_units exceeds aggregate analysis bound"
            )
        rows = _bounded_reservation_allocations(self.allocations)
        ids = tuple(row.semantic_work_unit_id for row in rows)
        if len(ids) != len(set(ids)):
            raise ResourcePolicyError(
                "global reservation allocations contain duplicates"
            )
        if sum(row.reserved_analysis_units for row in rows) > (
            self.total_analysis_units
        ):
            raise ResourcePolicyError(
                "global reservation is over-allocated"
            )
        budget_authority.validate_reservation(
            reservation_id=self.reservation_id,
            run_id=self.run_id,
            generation=self.generation,
            total_analysis_units=self.total_analysis_units,
            allocations=rows,
        )
        object.__setattr__(self, "allocations", rows)
        object.__setattr__(
            self, "_budget_authority", budget_authority
        )
        sealed_bytes = self.to_bytes()
        object.__setattr__(
            self,
            "_sealed_reservation_bytes",
            sealed_bytes,
        )
        _GLOBAL_RESOURCE_RESERVATION_SEALS.issue(
            self,
            sealed_bytes,
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "reservation_id": self.reservation_id,
            "run_id": self.run_id,
            "generation": self.generation,
            "total_analysis_units": self.total_analysis_units,
            "allocations": [row.to_dict() for row in self.allocations],
            "reservation_budget_authority_digest": (
                self._budget_authority
                .reservation_budget_authority_digest
            ),
            "reservation_budget_authority_class": (
                self._budget_authority.authority_class
            ),
        }

    @property
    def reservation_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def require_exact_replay(self) -> None:
        """Reject runtime/nested type spoofing and post-construction drift."""

        if type(self) is not GlobalResourceReservation:
            raise ResourcePolicyError(
                "exact GlobalResourceReservation runtime type is required"
            )
        if type(self._budget_authority) is not ReservationBudgetAuthority:
            raise ResourcePolicyError(
                "global reservation budget authority is absent"
            )
        self._budget_authority.validate_reservation(
            reservation_id=self.reservation_id,
            run_id=self.run_id,
            generation=self.generation,
            total_analysis_units=self.total_analysis_units,
            allocations=self.allocations,
        )
        seal = _GLOBAL_RESOURCE_RESERVATION_SEALS.require(
            self,
            exact_type=GlobalResourceReservation,
            canonical=self.to_bytes(),
            label="global resource reservation",
        )
        if (
            type(self.reservation_id) is not str
            or type(self.run_id) is not str
            or type(self.generation) is not int
            or type(self.total_analysis_units) is not int
            or type(self.allocations) is not tuple
            or not all(
                type(row) is ReservationAllocation
                and type(row.semantic_work_unit_id) is str
                and type(row.reserved_analysis_units) is int
                for row in self.allocations
            )
        ):
            raise ResourcePolicyError(
                "global resource reservation exact nested runtime types drifted"
            )
        try:
            current_bytes = self.to_bytes()
            replayed = GlobalResourceReservation.from_bytes(
                seal,
                budget_authority=self._budget_authority,
            )
        except (
            AttributeError,
            TypeError,
            ResourcePolicyError,
            ValueError,
        ) as exc:
            raise ResourcePolicyError(
                "global resource reservation exact replay failed"
            ) from exc
        current_allocations = tuple(
            (
                row.semantic_work_unit_id,
                row.reserved_analysis_units,
            )
            for row in self.allocations
        )
        if (
            current_bytes != seal
            or current_bytes != self._sealed_reservation_bytes
            or replayed.to_bytes() != seal
        ):
            raise ResourcePolicyError(
                "global resource reservation seal/replay drifted"
            )

    @property
    def reservation_budget_authority_class(self) -> str:
        return self._budget_authority.authority_class

    def require_production_budget_authority(self) -> None:
        self.require_exact_replay()
        if self.reservation_budget_authority_class != (
            "PRODUCTION_PHASE_ROSTER_SCHEDULER_V1"
        ):
            debt = self.production_authority_debt()
            raise ResourcePolicyError(
                "production phase-roster/scheduler budget authority is "
                "unavailable; structural-test reservation cannot mint a "
                "production grant",
                debt=debt,
            )

    def production_authority_debt(self) -> ResourceAuthorityDebt:
        self.require_exact_replay()
        authority = self._budget_authority
        return ResourceAuthorityDebt(
            reservation_id=self.reservation_id,
            reservation_digest=self.reservation_digest,
            observed_authority_class=authority.authority_class,
            phase_roster_digest=authority.phase_roster_digest,
            scheduler_budget_digest=authority.scheduler_budget_digest,
        )

    def replay(self) -> "GlobalResourceReservation":
        self.require_exact_replay()
        return GlobalResourceReservation.from_bytes(
            self.to_bytes(),
            budget_authority=self._budget_authority,
        )

    def allocation_for(self, semantic_work_unit_id: str) -> int:
        work_unit = _identifier(
            semantic_work_unit_id, "semantic_work_unit_id"
        )
        self.require_exact_replay()
        rows = tuple(
            row.reserved_analysis_units
            for row in self.allocations
            if row.semantic_work_unit_id == work_unit
        )
        if len(rows) != 1:
            raise ResourcePolicyError(
                "global reservation lacks exact work-unit allocation"
            )
        return rows[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "reservation_digest": self.reservation_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        budget_authority: ReservationBudgetAuthority | None = None,
    ) -> "GlobalResourceReservation":
        if cls is not GlobalResourceReservation:
            raise ResourcePolicyError(
                "GlobalResourceReservation replay requires exact base class"
            )
        if (
            type(raw) is not bytes
            or len(raw) > MAX_RESERVATION_CANONICAL_BYTES
        ):
            raise ResourcePolicyError(
                "global reservation canonical byte size exceeds its bound"
            )
        if type(budget_authority) is not ReservationBudgetAuthority:
            raise ResourcePolicyError(
                "reservation replay requires trusted budget authority"
            )
        value = _decode(raw)
        _keys(
            value,
            {
                "schema",
                "reservation_id",
                "run_id",
                "generation",
                "total_analysis_units",
                "allocations",
                "reservation_budget_authority_digest",
                "reservation_budget_authority_class",
                "reservation_digest",
            },
            "global resource reservation",
        )
        if value["schema"] != GLOBAL_RESOURCE_RESERVATION_SCHEMA:
            raise ResourcePolicyError(
                "unsupported global resource reservation schema"
            )
        if not isinstance(value["allocations"], list):
            raise ResourcePolicyError("allocations must be an array")
        if len(value["allocations"]) > MAX_RESERVATION_ALLOCATIONS:
            raise ResourcePolicyError(
                "global reservation allocation denominator exceeds "
                f"{MAX_RESERVATION_ALLOCATIONS}"
            )
        rows: list[ReservationAllocation] = []
        for raw_row in value["allocations"]:
            _keys(
                raw_row,
                {"semantic_work_unit_id", "reserved_analysis_units"},
                "reservation allocation",
            )
            rows.append(
                ReservationAllocation(
                    semantic_work_unit_id=raw_row[
                        "semantic_work_unit_id"
                    ],
                    reserved_analysis_units=raw_row[
                        "reserved_analysis_units"
                    ],
                )
            )
        if (
            value["reservation_budget_authority_digest"]
            != budget_authority.reservation_budget_authority_digest
            or value["reservation_budget_authority_class"]
            != budget_authority.authority_class
        ):
            raise ResourcePolicyError(
                "reservation budget authority does not match replay"
            )
        replayed = GlobalResourceReservation(
            reservation_id=value["reservation_id"],
            run_id=value["run_id"],
            generation=value["generation"],
            total_analysis_units=value["total_analysis_units"],
            allocations=tuple(rows),
            budget_authority=budget_authority,
        )
        if value != replayed.to_dict():
            raise ResourcePolicyError(
                "global resource reservation does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResourcePolicyAuthority:
    policy_id: str
    policy_generation: int
    profile: str
    source_authority_digest: str
    global_reservation_digest: str
    parity_policy: ParityPolicyAuthority
    ceilings: tuple[ResourceCeiling, ...]
    _authority_token: InitVar[object] = None
    _source_snapshot: InitVar[ResourcePolicySourceSnapshot | None] = None
    _sealed_authority_bytes: bytes = field(
        init=False, repr=False, compare=False
    )
    _sealed_source_bytes: bytes = field(
        init=False, repr=False, compare=False
    )

    schema: ClassVar[str] = RESOURCE_POLICY_AUTHORITY_SCHEMA

    def __post_init__(
        self,
        _authority_token: object,
        _source_snapshot: ResourcePolicySourceSnapshot | None,
    ) -> None:
        if _authority_token is not _AUTHORITY_TOKEN:
            raise ResourcePolicyError(
                "resource policy authority requires trusted compilation/replay"
            )
        if type(_source_snapshot) is not ResourcePolicySourceSnapshot:
            raise ResourcePolicyError(
                "resource policy authority requires its exact source snapshot"
            )
        replayed_source = _source_snapshot.replay()
        if (
            replayed_source.to_bytes() != _source_snapshot.to_bytes()
            or replayed_source.source_authority_digest
            != self.source_authority_digest
        ):
            raise ResourcePolicyError(
                "resource policy authority source snapshot drifted"
            )
        (
            source_policy_id,
            source_generation,
            source_profile,
            source_parity,
            source_ceilings,
        ) = _reviewed_source_configuration(replayed_source.to_bytes())
        _identifier(self.policy_id, "policy_id")
        _integer(self.policy_generation, "policy_generation", positive=True)
        _enum(self.profile, RESOURCE_PROFILES, "profile")
        _sha(self.source_authority_digest, "source_authority_digest")
        _sha(self.global_reservation_digest, "global_reservation_digest")
        if type(self.parity_policy) is not ParityPolicyAuthority:
            raise ResourcePolicyError("typed parity policy is required")
        if self.parity_policy.policy_generation != self.policy_generation:
            raise ResourcePolicyError(
                "parity/resource policy generations do not match"
            )
        if (
            self.policy_id != source_policy_id
            or self.policy_generation != source_generation
            or self.profile != source_profile
            or self.parity_policy.to_dict() != source_parity.to_dict()
        ):
            raise ResourcePolicyError(
                "resource/parity policy does not derive from reviewed source"
            )
        rows = tuple(sorted(self.ceilings, key=lambda row: row.key))
        if not rows or not all(
            type(row) is ResourceCeiling for row in rows
        ):
            raise ResourcePolicyError(
                "resource ceilings require typed non-empty denominator"
            )
        if not all(
            type(row.tool_limits) is tuple
            and all(type(limit) is PolicyToolLimit for limit in row.tool_limits)
            for row in rows
        ):
            raise ResourcePolicyError(
                "resource ceilings contain non-exact nested runtime types"
            )
        keys = tuple(row.key for row in rows)
        if len(keys) != len(set(keys)):
            raise ResourcePolicyError(
                "resource policy ceiling keys are duplicated"
            )
        if [row.to_dict() for row in rows] != [
            row.to_dict()
            for row in sorted(source_ceilings, key=lambda row: row.key)
        ]:
            raise ResourcePolicyError(
                "resource ceilings do not derive from reviewed source"
            )
        object.__setattr__(self, "ceilings", rows)
        object.__setattr__(
            self,
            "_sealed_source_bytes",
            _source_snapshot.to_bytes(),
        )
        object.__setattr__(
            self,
            "_sealed_authority_bytes",
            self.to_bytes(),
        )
        _RESOURCE_POLICY_AUTHORITY_SEALS.issue(
            self,
            self.to_bytes()
            + b"\x00"
            + _source_snapshot.to_bytes(),
        )

    def require_exact_replay(self) -> None:
        """Reject subclasses and any post-compilation authority drift."""

        if type(self) is not ResourcePolicyAuthority:
            raise ResourcePolicyError(
                "exact ResourcePolicyAuthority runtime type is required"
            )
        try:
            replayed_source = capture_resource_policy_source_snapshot(
                self._sealed_source_bytes
            )
            _RESOURCE_POLICY_AUTHORITY_SEALS.require(
                self,
                exact_type=ResourcePolicyAuthority,
                canonical=(
                    self.to_bytes()
                    + b"\x00"
                    + self._sealed_source_bytes
                ),
                label="resource policy authority",
            )
        except (AttributeError, TypeError, ResourcePolicyError) as exc:
            raise ResourcePolicyError(
                "resource policy authority source seal is invalid"
            ) from exc
        if (
            replayed_source.source_authority_digest
            != self.source_authority_digest
            or self.to_bytes() != self._sealed_authority_bytes
            or type(self.parity_policy) is not ParityPolicyAuthority
            or type(self.ceilings) is not tuple
            or not all(
                type(row) is ResourceCeiling
                and type(row.tool_limits) is tuple
                and all(
                    type(limit) is PolicyToolLimit
                    for limit in row.tool_limits
                )
                for row in self.ceilings
            )
        ):
            raise ResourcePolicyError(
                "resource policy authority seal/replay drifted"
            )
        (
            source_policy_id,
            source_generation,
            source_profile,
            source_parity,
            source_ceilings,
        ) = _reviewed_source_configuration(self._sealed_source_bytes)
        if (
            self.policy_id != source_policy_id
            or self.policy_generation != source_generation
            or self.profile != source_profile
            or self.parity_policy.to_dict() != source_parity.to_dict()
            or [row.to_dict() for row in self.ceilings]
            != [
                row.to_dict()
                for row in sorted(source_ceilings, key=lambda row: row.key)
            ]
        ):
            raise ResourcePolicyError(
                "resource policy authority reviewed-source replay drifted"
            )

    def ceiling_for(
        self,
        *,
        audit_mode: str,
        phase_semantic_id: str,
        workload_class: str,
    ) -> ResourceCeiling:
        self.require_exact_replay()
        key = (
            _enum(audit_mode, AUDIT_MODES, "audit_mode"),
            _identifier(phase_semantic_id, "phase_semantic_id"),
            _enum(workload_class, WORKLOAD_CLASSES, "workload_class"),
        )
        rows = tuple(row for row in self.ceilings if row.key == key)
        if len(rows) != 1:
            raise ResourcePolicyError(
                "resource policy has no exact mode/phase/workload ceiling"
            )
        return rows[0]

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "policy_generation": self.policy_generation,
            "profile": self.profile,
            "source_authority_digest": self.source_authority_digest,
            "global_reservation_digest": self.global_reservation_digest,
            "parity_policy": self.parity_policy.to_dict(),
            "ceilings": [row.to_dict() for row in self.ceilings],
        }

    @property
    def resource_policy_authority_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "resource_policy_authority_digest": (
                self.resource_policy_authority_digest
            ),
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        source_snapshot: ResourcePolicySourceSnapshot,
        global_reservation: GlobalResourceReservation,
        parity_policy: ParityPolicyAuthority,
        ceilings: Iterable[ResourceCeiling],
    ) -> "ResourcePolicyAuthority":
        value = _decode(raw)
        replayed = compile_resource_policy_authority(
            policy_id=value.get("policy_id"),
            policy_generation=value.get("policy_generation"),
            profile=value.get("profile"),
            source_snapshot=source_snapshot,
            global_reservation=global_reservation,
            parity_policy=parity_policy,
            ceilings=ceilings,
        )
        if value != replayed.to_dict():
            raise ResourcePolicyError(
                "resource policy authority does not match typed replay"
            )
        return replayed


def compile_resource_policy_authority(
    *,
    policy_id: str,
    policy_generation: int,
    profile: str,
    source_snapshot: ResourcePolicySourceSnapshot,
    global_reservation: GlobalResourceReservation,
    parity_policy: ParityPolicyAuthority,
    ceilings: Iterable[ResourceCeiling],
) -> ResourcePolicyAuthority:
    if type(source_snapshot) is not ResourcePolicySourceSnapshot:
        raise ResourcePolicyError(
            "opaque typed resource policy source snapshot is required"
        )
    replayed_source = source_snapshot.replay()
    if (
        replayed_source.to_bytes() != source_snapshot.to_bytes()
        or replayed_source.source_authority_digest
        != source_snapshot.source_authority_digest
    ):
        raise ResourcePolicyError("resource policy source snapshot drifted")
    if type(global_reservation) is not GlobalResourceReservation:
        raise ResourcePolicyError(
            "typed global reservation parent is required"
        )
    global_reservation.require_exact_replay()
    replayed_reservation = global_reservation.replay()
    if replayed_reservation.to_bytes() != global_reservation.to_bytes():
        raise ResourcePolicyError(
            "global resource reservation does not exactly replay"
        )
    if type(parity_policy) is not ParityPolicyAuthority:
        raise ResourcePolicyError("typed parity policy parent is required")
    if policy_generation != global_reservation.generation:
        raise ResourcePolicyError(
            "resource policy/global reservation generations do not match"
        )
    (
        source_policy_id,
        source_generation,
        source_profile,
        source_parity,
        source_ceilings,
    ) = _reviewed_source_configuration(replayed_source.to_bytes())
    supplied_ceilings = tuple(ceilings)
    if (
        policy_id != source_policy_id
        or policy_generation != source_generation
        or profile != source_profile
    ):
        raise ResourcePolicyError(
            "resource policy identity does not derive from reviewed source"
        )
    if (
        type(parity_policy) is not ParityPolicyAuthority
        or parity_policy.to_dict() != source_parity.to_dict()
    ):
        raise ResourcePolicyError(
            "parity policy does not derive from reviewed source"
        )
    if (
        type(supplied_ceilings) is not tuple
        or not all(
            type(row) is ResourceCeiling
            and type(row.tool_limits) is tuple
            and all(
                type(limit) is PolicyToolLimit
                for limit in row.tool_limits
            )
            for row in supplied_ceilings
        )
        or [
            row.to_dict()
            for row in sorted(supplied_ceilings, key=lambda row: row.key)
        ]
        != [
            row.to_dict()
            for row in sorted(source_ceilings, key=lambda row: row.key)
        ]
    ):
        raise ResourcePolicyError(
            "resource ceilings do not derive from reviewed source"
        )
    return ResourcePolicyAuthority(
        policy_id=source_policy_id,
        policy_generation=source_generation,
        profile=source_profile,
        source_authority_digest=source_snapshot.source_authority_digest,
        global_reservation_digest=global_reservation.reservation_digest,
        parity_policy=source_parity,
        ceilings=source_ceilings,
        _authority_token=_AUTHORITY_TOKEN,
        _source_snapshot=source_snapshot,
    )


__all__ = [
    "AUDIT_MODES",
    "CACHE_POLICIES",
    "GLOBAL_RESOURCE_RESERVATION_SCHEMA",
    "GlobalResourceReservation",
    "PARITY_MODES",
    "PARITY_POLICY_AUTHORITY_SCHEMA",
    "ParityPolicyAuthority",
    "PolicyToolLimit",
    "RESOURCE_AUTHORITY_DEBT_SCHEMA",
    "RESOURCE_POLICY_AUTHORITY_SCHEMA",
    "RESOURCE_PROFILES",
    "REVIEWED_RESOURCE_POLICY_SOURCE_SCHEMA",
    "ReservationAllocation",
    "ResourceAuthorityDebt",
    "ResourceCeiling",
    "ResourcePolicyAuthority",
    "ResourcePolicyError",
    "ResourcePolicySourceSnapshot",
    "SCHEDULER_CLASSES",
    "WORKLOAD_CLASSES",
    "compile_structural_test_reservation_budget_authority",
    "compile_resource_policy_authority",
    "capture_resource_policy_source_snapshot",
    "reviewed_resource_policy_source_bytes",
]
