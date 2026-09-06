"""Closed, backend-neutral semantic work identities for ``semantic_v1``.

This module is deliberately pure.  It does not inspect the live phase
registry, select a backend, read the filesystem, or participate in driver
launch construction.  ``legacy_claude_v1`` therefore remains untouched.

The identity split is intentional:

* :class:`SemanticWorkPlan` owns backend-neutral work and grants.
* :class:`BackendArmExecutionIdentity` owns backend/model/generation identity.
* :class:`ExecutionAttemptIdentity` owns one exact attempt ordinal.

All persisted records use canonical UTF-8 JSON with a single final LF.  Their
authority digests contain no floats, timestamps, physical paths, or host data.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import re
from typing import Any, ClassVar

from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)


SEMANTIC_PROFILE = "semantic_v1"
LEGACY_PROFILE = "legacy_claude_v1"
SEMANTIC_WORK_PLAN_SCHEMA = "plamen.semantic-work-plan.v1"
SEMANTIC_ROSTER_SCHEMA = "plamen.semantic-roster.v1"
BACKEND_ARM_EXECUTION_SCHEMA = "plamen.backend-arm-execution-identity.v1"
EXECUTION_ATTEMPT_SCHEMA = "plamen.execution-attempt-identity.v1"
SEMANTIC_PLAN_GENERATION_TRANSITION_SCHEMA = (
    "plamen.semantic-plan-generation-transition.v1"
)
EXECUTION_GENERATION_TRANSITION_SCHEMA = (
    "plamen.execution-generation-transition.v1"
)

CHILD_POLICY = "DRIVER_ONLY_NO_MODEL_CHILDREN"

PIPELINES = frozenset({"sc", "l1"})
MODES = frozenset({"light", "core", "thorough"})
ECOSYSTEMS = frozenset(
    {"evm", "solana", "aptos", "sui", "soroban", "daml", "go", "rust"}
)
MODEL_CAPABILITY_TIERS = frozenset(
    {
        "R3_FRONTIER_REASONING",
        "R2_STANDARD_REASONING",
        "R1_ECONOMY_STRUCTURED",
        "N0_NATIVE_DETERMINISTIC",
    }
)
SEMANTIC_CAPABILITIES = frozenset(
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
BACKENDS = frozenset({"claude", "codex", "native"})
ANALYSIS_TEMPLATE_ID = "BOUND_METHODOLOGY_OBLIGATION_ANALYSIS_V1"
NATIVE_TEMPLATE_ID = "BOUND_NATIVE_CAPABILITY_EXECUTION_V1"
REPORT_TEMPLATE_ID = "BOUND_REPORT_PROJECTION_V1"
SEMANTIC_TEMPLATE_IDS = frozenset(
    {ANALYSIS_TEMPLATE_ID, NATIVE_TEMPLATE_ID, REPORT_TEMPLATE_ID}
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,191}$", re.ASCII)

_RETRY_KEYS = frozenset(
    {
        "max_attempts",
        "same_prompt",
        "same_model_capability_tier",
        "same_tools",
        "model_change_requires_new_generation",
    }
)
_COMPLETION_KEYS = frozenset(
    {
        "requires_process_scope_empty",
        "requires_stream_eof",
        "requires_parser_acceptance",
        "requires_exact_output_denominator",
        "requires_phase_io_incorporation",
    }
)
_PLAN_KEYS = frozenset(
    {
        "schema",
        "semantic_profile",
        "run_id",
        "pipeline",
        "mode",
        "ecosystem",
        "semantic_generation",
        "phase_semantic_id",
        "roster_id",
        "roster_position",
        "roster_denominator",
        "semantic_work_unit_id",
        "role_id",
        "assignment_id",
        "semantic_template_id",
        "source_snapshot_digest",
        "deterministic_fact_snapshot_digests",
        "semantic_input_manifest_digest",
        "semantic_prompt_snapshot_digest",
        "methodology_bundle_digest",
        "obligation_bundle_digest",
        "output_contract_digest",
        "tool_capability_manifest_digest",
        "resource_grant_digest",
        "model_capability_tier",
        "required_capabilities",
        "child_policy",
        "retry_policy",
        "completion_policy",
        "semantic_digest",
    }
)
_ROSTER_KEYS = frozenset(
    {
        "schema",
        "semantic_profile",
        "run_id",
        "pipeline",
        "mode",
        "ecosystem",
        "semantic_generation",
        "phase_semantic_id",
        "roster_id",
        "roster_denominator",
        "ordered_semantic_work_unit_ids",
        "ordered_semantic_digests",
        "roster_digest",
    }
)
_EXECUTION_KEYS = frozenset(
    {
        "schema",
        "semantic_work_unit_key",
        "semantic_digest",
        "backend_arm_id",
        "backend",
        "execution_generation",
        "exact_model_id",
        "model_capability_tier",
        "capability_receipt_digest",
        "execution_work_unit_key",
    }
)
_ATTEMPT_KEYS = frozenset(
    {
        "schema",
        "semantic_work_unit_key",
        "execution_work_unit_key",
        "attempt_number",
        "attempt_key",
    }
)
_SEMANTIC_TRANSITION_KEYS = frozenset(
    {
        "schema",
        "previous_semantic_digest",
        "successor_semantic_digest",
        "previous_semantic_work_unit_key",
        "successor_semantic_work_unit_key",
        "previous_generation",
        "successor_generation",
        "trigger_evidence_digest",
        "reason_code",
        "transition_digest",
    }
)
_EXECUTION_TRANSITION_KEYS = frozenset(
    {
        "schema",
        "previous_execution_work_unit_key",
        "successor_execution_work_unit_key",
        "previous_generation",
        "successor_generation",
        "trigger_evidence_digest",
        "reason_code",
        "transition_digest",
    }
)


class SemanticSchemaError(ValueError):
    """A semantic identity is ambiguous, open-ended, or digest-invalid."""


def _raise_as_schema_error(exc: Exception) -> "NoReturn":  # type: ignore[name-defined]
    raise SemanticSchemaError(str(exc)) from exc


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_json_bytes(value)
    except ProgramFactsTypeError as exc:
        _raise_as_schema_error(exc)


def _canonical_file(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_file_bytes(value)
    except ProgramFactsTypeError as exc:
        _raise_as_schema_error(exc)


def _decode_record(raw: bytes) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(raw, require_final_lf=True)
    except ProgramFactsTypeError as exc:
        _raise_as_schema_error(exc)
    if not isinstance(value, Mapping):
        raise SemanticSchemaError("record must be a JSON object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    if not isinstance(value, Mapping):
        raise SemanticSchemaError(f"{context} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    reasons: list[str] = []
    if missing:
        reasons.append("missing fields: " + ", ".join(missing))
    if extra:
        reasons.append("unexpected fields: " + ", ".join(extra))
    if reasons:
        raise SemanticSchemaError(f"{context} " + "; ".join(reasons))


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        raise SemanticSchemaError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise SemanticSchemaError(
            f"{field} must be an ASCII semantic identity token"
        )
    if value in {".", ".."}:
        raise SemanticSchemaError(f"{field} cannot be a path segment")
    return value


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SemanticSchemaError(f"{field} must be an integer")
    if value < 1:
        raise SemanticSchemaError(f"{field} must be at least 1")
    return value


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise SemanticSchemaError(f"{field} must be boolean")
    return value


def _closed_value(value: Any, allowed: frozenset[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise SemanticSchemaError(
            f"{field} must be one of {', '.join(sorted(allowed))}"
        )
    return value


def _digest_tuple(values: Iterable[Any], field: str) -> tuple[str, ...]:
    try:
        raw = tuple(values)
    except TypeError as exc:
        raise SemanticSchemaError(f"{field} must be an array") from exc
    result = tuple(sorted(_sha256(item, field) for item in raw))
    if len(result) != len(set(result)):
        raise SemanticSchemaError(f"{field} contains duplicate digests")
    return result


def _capability_tuple(values: Iterable[Any]) -> tuple[str, ...]:
    try:
        raw = tuple(values)
    except TypeError as exc:
        raise SemanticSchemaError("required_capabilities must be an array") from exc
    result = tuple(
        sorted(
            _closed_value(item, SEMANTIC_CAPABILITIES, "required_capabilities")
            for item in raw
        )
    )
    if len(result) != len(set(result)):
        raise SemanticSchemaError("required_capabilities contains duplicates")
    return result


def derive_semantic_template_id(
    *,
    phase_semantic_id: str,
    model_capability_tier: str,
) -> str:
    """Derive the sole template authorized by typed plan semantics."""

    phase = _safe_id(phase_semantic_id, "phase_semantic_id")
    tier = _closed_value(
        model_capability_tier,
        MODEL_CAPABILITY_TIERS,
        "model_capability_tier",
    )
    if phase == "report":
        if tier == "N0_NATIVE_DETERMINISTIC":
            raise SemanticSchemaError(
                "report semantic work cannot use the native execution tier"
            )
        return REPORT_TEMPLATE_ID
    if tier == "N0_NATIVE_DETERMINISTIC":
        return NATIVE_TEMPLATE_ID
    return ANALYSIS_TEMPLATE_ID


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Closed retry authority; there is no fallback-model field."""

    max_attempts: int
    same_prompt: bool
    same_model_capability_tier: bool
    same_tools: bool
    model_change_requires_new_generation: bool

    def __post_init__(self) -> None:
        _positive_int(self.max_attempts, "retry_policy.max_attempts")
        _bool(self.same_prompt, "retry_policy.same_prompt")
        _bool(
            self.same_model_capability_tier,
            "retry_policy.same_model_capability_tier",
        )
        _bool(self.same_tools, "retry_policy.same_tools")
        _bool(
            self.model_change_requires_new_generation,
            "retry_policy.model_change_requires_new_generation",
        )
        if not (
            self.same_prompt
            and self.same_model_capability_tier
            and self.same_tools
            and self.model_change_requires_new_generation
        ):
            raise SemanticSchemaError(
                "semantic_v1 retry policy must preserve prompt, model tier, "
                "and tools, and model changes must create a new generation"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_attempts": self.max_attempts,
            "same_prompt": self.same_prompt,
            "same_model_capability_tier": self.same_model_capability_tier,
            "same_tools": self.same_tools,
            "model_change_requires_new_generation": (
                self.model_change_requires_new_generation
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RetryPolicy":
        _require_exact_keys(value, _RETRY_KEYS, "retry_policy")
        return cls(
            max_attempts=_positive_int(
                value["max_attempts"], "retry_policy.max_attempts"
            ),
            same_prompt=_bool(value["same_prompt"], "retry_policy.same_prompt"),
            same_model_capability_tier=_bool(
                value["same_model_capability_tier"],
                "retry_policy.same_model_capability_tier",
            ),
            same_tools=_bool(value["same_tools"], "retry_policy.same_tools"),
            model_change_requires_new_generation=_bool(
                value["model_change_requires_new_generation"],
                "retry_policy.model_change_requires_new_generation",
            ),
        )


@dataclass(frozen=True, slots=True)
class CompletionPolicy:
    """Closed completion authority for a semantic work unit."""

    requires_process_scope_empty: bool
    requires_stream_eof: bool
    requires_parser_acceptance: bool
    requires_exact_output_denominator: bool
    requires_phase_io_incorporation: bool

    def __post_init__(self) -> None:
        for field in _COMPLETION_KEYS:
            if not _bool(getattr(self, field), f"completion_policy.{field}"):
                raise SemanticSchemaError(
                    f"completion_policy.{field} must be true in semantic_v1"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requires_process_scope_empty": self.requires_process_scope_empty,
            "requires_stream_eof": self.requires_stream_eof,
            "requires_parser_acceptance": self.requires_parser_acceptance,
            "requires_exact_output_denominator": (
                self.requires_exact_output_denominator
            ),
            "requires_phase_io_incorporation": (
                self.requires_phase_io_incorporation
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CompletionPolicy":
        _require_exact_keys(value, _COMPLETION_KEYS, "completion_policy")
        return cls(
            **{
                field: _bool(value[field], f"completion_policy.{field}")
                for field in _COMPLETION_KEYS
            }
        )


def _coerce_retry(value: RetryPolicy | Mapping[str, Any]) -> RetryPolicy:
    if isinstance(value, RetryPolicy):
        return value
    if isinstance(value, Mapping):
        return RetryPolicy.from_dict(value)
    raise SemanticSchemaError("retry_policy must be a RetryPolicy or object")


def _coerce_completion(
    value: CompletionPolicy | Mapping[str, Any],
) -> CompletionPolicy:
    if isinstance(value, CompletionPolicy):
        return value
    if isinstance(value, Mapping):
        return CompletionPolicy.from_dict(value)
    raise SemanticSchemaError(
        "completion_policy must be a CompletionPolicy or object"
    )


@dataclass(frozen=True, slots=True)
class SemanticWorkPlan:
    """One immutable backend-neutral semantic work unit."""

    run_id: str
    pipeline: str
    mode: str
    ecosystem: str
    semantic_generation: int
    phase_semantic_id: str
    roster_id: str
    roster_position: int
    roster_denominator: int
    semantic_work_unit_id: str
    role_id: str
    assignment_id: str
    semantic_template_id: str
    source_snapshot_digest: str
    deterministic_fact_snapshot_digests: tuple[str, ...]
    semantic_input_manifest_digest: str
    semantic_prompt_snapshot_digest: str
    methodology_bundle_digest: str
    obligation_bundle_digest: str
    output_contract_digest: str
    tool_capability_manifest_digest: str
    resource_grant_digest: str
    model_capability_tier: str
    required_capabilities: tuple[str, ...]
    retry_policy: RetryPolicy
    completion_policy: CompletionPolicy
    child_policy: str = CHILD_POLICY

    schema: ClassVar[str] = SEMANTIC_WORK_PLAN_SCHEMA
    semantic_profile: ClassVar[str] = SEMANTIC_PROFILE

    def __post_init__(self) -> None:
        _safe_id(self.run_id, "run_id")
        _closed_value(self.pipeline, PIPELINES, "pipeline")
        _closed_value(self.mode, MODES, "mode")
        _closed_value(self.ecosystem, ECOSYSTEMS, "ecosystem")
        _positive_int(self.semantic_generation, "semantic_generation")
        _safe_id(self.phase_semantic_id, "phase_semantic_id")
        _safe_id(self.roster_id, "roster_id")
        position = _positive_int(self.roster_position, "roster_position")
        denominator = _positive_int(self.roster_denominator, "roster_denominator")
        if position > denominator:
            raise SemanticSchemaError(
                "roster_position cannot exceed roster_denominator"
            )
        _safe_id(self.semantic_work_unit_id, "semantic_work_unit_id")
        _safe_id(self.role_id, "role_id")
        _safe_id(self.assignment_id, "assignment_id")
        expected_template = derive_semantic_template_id(
            phase_semantic_id=self.phase_semantic_id,
            model_capability_tier=self.model_capability_tier,
        )
        if self.semantic_template_id != expected_template:
            raise SemanticSchemaError(
                "semantic_template_id does not match typed plan semantics"
            )
        for field in (
            "source_snapshot_digest",
            "semantic_input_manifest_digest",
            "semantic_prompt_snapshot_digest",
            "methodology_bundle_digest",
            "obligation_bundle_digest",
            "output_contract_digest",
            "tool_capability_manifest_digest",
            "resource_grant_digest",
        ):
            _sha256(getattr(self, field), field)
        facts = _digest_tuple(
            self.deterministic_fact_snapshot_digests,
            "deterministic_fact_snapshot_digests",
        )
        capabilities = _capability_tuple(self.required_capabilities)
        _closed_value(
            self.model_capability_tier,
            MODEL_CAPABILITY_TIERS,
            "model_capability_tier",
        )
        if self.child_policy != CHILD_POLICY:
            raise SemanticSchemaError(
                f"child_policy must be {CHILD_POLICY} in semantic_v1"
            )
        if not isinstance(self.retry_policy, RetryPolicy):
            raise SemanticSchemaError("retry_policy must be RetryPolicy")
        if not isinstance(self.completion_policy, CompletionPolicy):
            raise SemanticSchemaError(
                "completion_policy must be CompletionPolicy"
            )
        object.__setattr__(self, "deterministic_fact_snapshot_digests", facts)
        object.__setattr__(self, "required_capabilities", capabilities)

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        pipeline: str,
        mode: str,
        ecosystem: str,
        semantic_generation: int,
        phase_semantic_id: str,
        roster_id: str,
        roster_position: int,
        roster_denominator: int,
        semantic_work_unit_id: str,
        role_id: str,
        assignment_id: str,
        semantic_template_id: str,
        source_snapshot_digest: str,
        deterministic_fact_snapshot_digests: Iterable[str],
        semantic_input_manifest_digest: str,
        semantic_prompt_snapshot_digest: str,
        methodology_bundle_digest: str,
        obligation_bundle_digest: str,
        output_contract_digest: str,
        tool_capability_manifest_digest: str,
        resource_grant_digest: str,
        model_capability_tier: str,
        required_capabilities: Iterable[str],
        retry_policy: RetryPolicy | Mapping[str, Any],
        completion_policy: CompletionPolicy | Mapping[str, Any],
        child_policy: str = CHILD_POLICY,
    ) -> "SemanticWorkPlan":
        return cls(
            run_id=run_id,
            pipeline=pipeline,
            mode=mode,
            ecosystem=ecosystem,
            semantic_generation=semantic_generation,
            phase_semantic_id=phase_semantic_id,
            roster_id=roster_id,
            roster_position=roster_position,
            roster_denominator=roster_denominator,
            semantic_work_unit_id=semantic_work_unit_id,
            role_id=role_id,
            assignment_id=assignment_id,
            semantic_template_id=semantic_template_id,
            source_snapshot_digest=source_snapshot_digest,
            deterministic_fact_snapshot_digests=tuple(
                deterministic_fact_snapshot_digests
            ),
            semantic_input_manifest_digest=semantic_input_manifest_digest,
            semantic_prompt_snapshot_digest=semantic_prompt_snapshot_digest,
            methodology_bundle_digest=methodology_bundle_digest,
            obligation_bundle_digest=obligation_bundle_digest,
            output_contract_digest=output_contract_digest,
            tool_capability_manifest_digest=tool_capability_manifest_digest,
            resource_grant_digest=resource_grant_digest,
            model_capability_tier=model_capability_tier,
            required_capabilities=tuple(required_capabilities),
            retry_policy=_coerce_retry(retry_policy),
            completion_policy=_coerce_completion(completion_policy),
            child_policy=child_policy,
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "semantic_profile": self.semantic_profile,
            "run_id": self.run_id,
            "pipeline": self.pipeline,
            "mode": self.mode,
            "ecosystem": self.ecosystem,
            "semantic_generation": self.semantic_generation,
            "phase_semantic_id": self.phase_semantic_id,
            "roster_id": self.roster_id,
            "roster_position": self.roster_position,
            "roster_denominator": self.roster_denominator,
            "semantic_work_unit_id": self.semantic_work_unit_id,
            "role_id": self.role_id,
            "assignment_id": self.assignment_id,
            "semantic_template_id": self.semantic_template_id,
            "source_snapshot_digest": self.source_snapshot_digest,
            "deterministic_fact_snapshot_digests": list(
                self.deterministic_fact_snapshot_digests
            ),
            "semantic_input_manifest_digest": self.semantic_input_manifest_digest,
            "semantic_prompt_snapshot_digest": (
                self.semantic_prompt_snapshot_digest
            ),
            "methodology_bundle_digest": self.methodology_bundle_digest,
            "obligation_bundle_digest": self.obligation_bundle_digest,
            "output_contract_digest": self.output_contract_digest,
            "tool_capability_manifest_digest": (
                self.tool_capability_manifest_digest
            ),
            "resource_grant_digest": self.resource_grant_digest,
            "model_capability_tier": self.model_capability_tier,
            "required_capabilities": list(self.required_capabilities),
            "child_policy": self.child_policy,
            "retry_policy": self.retry_policy.to_dict(),
            "completion_policy": self.completion_policy.to_dict(),
        }

    @property
    def semantic_digest(self) -> str:
        return _digest(self._unsigned_dict())

    @property
    def prompt_binding_digest(self) -> str:
        """Acyclic binding consumed by ``SemanticPromptSnapshot``.

        The final semantic plan binds the exact prompt snapshot digest.  The
        prompt snapshot therefore cannot also contain the final plan digest
        without creating an impossible hash cycle.  This preimage binding
        commits to every plan field except the snapshot digest; the enclosing
        bundle validator then proves the reverse edge from the final plan to
        the exact snapshot.
        """

        binding = self._unsigned_dict()
        del binding["semantic_prompt_snapshot_digest"]
        return _digest(
            {
                "schema": "plamen.semantic-plan-prompt-binding.v1",
                "plan": binding,
            }
        )

    @property
    def semantic_work_unit_key(self) -> str:
        """Backend-neutral key for this semantic unit and generation."""

        return _digest(
            {
                "schema": "plamen.semantic-work-unit-key.v1",
                "run_id": self.run_id,
                "pipeline": self.pipeline,
                "mode": self.mode,
                "ecosystem": self.ecosystem,
                "semantic_generation": self.semantic_generation,
                "phase_semantic_id": self.phase_semantic_id,
                "roster_id": self.roster_id,
                "semantic_work_unit_id": self.semantic_work_unit_id,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "semantic_digest": self.semantic_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SemanticWorkPlan":
        _require_exact_keys(value, _PLAN_KEYS, "semantic work plan")
        if value["schema"] != SEMANTIC_WORK_PLAN_SCHEMA:
            raise SemanticSchemaError("unsupported semantic work plan schema")
        if value["semantic_profile"] != SEMANTIC_PROFILE:
            raise SemanticSchemaError("semantic_profile must be semantic_v1")
        claimed = _sha256(value["semantic_digest"], "semantic_digest")
        plan = cls.create(
            run_id=value["run_id"],
            pipeline=value["pipeline"],
            mode=value["mode"],
            ecosystem=value["ecosystem"],
            semantic_generation=value["semantic_generation"],
            phase_semantic_id=value["phase_semantic_id"],
            roster_id=value["roster_id"],
            roster_position=value["roster_position"],
            roster_denominator=value["roster_denominator"],
            semantic_work_unit_id=value["semantic_work_unit_id"],
            role_id=value["role_id"],
            assignment_id=value["assignment_id"],
            semantic_template_id=value["semantic_template_id"],
            source_snapshot_digest=value["source_snapshot_digest"],
            deterministic_fact_snapshot_digests=(
                value["deterministic_fact_snapshot_digests"]
            ),
            semantic_input_manifest_digest=value["semantic_input_manifest_digest"],
            semantic_prompt_snapshot_digest=value[
                "semantic_prompt_snapshot_digest"
            ],
            methodology_bundle_digest=value["methodology_bundle_digest"],
            obligation_bundle_digest=value["obligation_bundle_digest"],
            output_contract_digest=value["output_contract_digest"],
            tool_capability_manifest_digest=value[
                "tool_capability_manifest_digest"
            ],
            resource_grant_digest=value["resource_grant_digest"],
            model_capability_tier=value["model_capability_tier"],
            required_capabilities=value["required_capabilities"],
            retry_policy=value["retry_policy"],
            completion_policy=value["completion_policy"],
            child_policy=value["child_policy"],
        )
        if claimed != plan.semantic_digest:
            raise SemanticSchemaError("semantic_digest digest mismatch")
        return plan

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SemanticWorkPlan":
        return cls.from_dict(_decode_record(raw))


@dataclass(frozen=True, slots=True)
class SemanticRoster:
    """Canonical ordered roster compiled without backend or scheduler input."""

    plans: tuple[SemanticWorkPlan, ...]

    schema: ClassVar[str] = SEMANTIC_ROSTER_SCHEMA
    semantic_profile: ClassVar[str] = SEMANTIC_PROFILE

    def __post_init__(self) -> None:
        plans = tuple(sorted(self.plans, key=lambda plan: plan.roster_position))
        if not plans:
            raise SemanticSchemaError("semantic roster must contain at least one plan")
        if not all(isinstance(plan, SemanticWorkPlan) for plan in plans):
            raise SemanticSchemaError(
                "semantic roster entries must be SemanticWorkPlan records"
            )
        first = plans[0]
        shared_fields = (
            "run_id",
            "pipeline",
            "mode",
            "ecosystem",
            "semantic_generation",
            "phase_semantic_id",
            "roster_id",
            "roster_denominator",
        )
        for plan in plans[1:]:
            for field in shared_fields:
                if getattr(plan, field) != getattr(first, field):
                    raise SemanticSchemaError(
                        f"semantic roster has inconsistent {field}"
                    )
        denominator = first.roster_denominator
        positions = tuple(plan.roster_position for plan in plans)
        expected = tuple(range(1, denominator + 1))
        if positions != expected:
            raise SemanticSchemaError(
                "roster_position must be contiguous from 1 through "
                "roster_denominator"
            )
        if len(plans) != denominator:
            raise SemanticSchemaError(
                "semantic roster size does not match roster_denominator"
            )
        unit_ids = tuple(plan.semantic_work_unit_id for plan in plans)
        if len(unit_ids) != len(set(unit_ids)):
            raise SemanticSchemaError(
                "semantic roster contains duplicate semantic_work_unit_id"
            )
        object.__setattr__(self, "plans", plans)

    @classmethod
    def create(cls, plans: Iterable[SemanticWorkPlan]) -> "SemanticRoster":
        return cls(tuple(plans))

    @property
    def ordered_semantic_work_unit_ids(self) -> tuple[str, ...]:
        return tuple(plan.semantic_work_unit_id for plan in self.plans)

    @property
    def ordered_semantic_digests(self) -> tuple[str, ...]:
        return tuple(plan.semantic_digest for plan in self.plans)

    def _unsigned_dict(self) -> dict[str, Any]:
        first = self.plans[0]
        return {
            "schema": self.schema,
            "semantic_profile": self.semantic_profile,
            "run_id": first.run_id,
            "pipeline": first.pipeline,
            "mode": first.mode,
            "ecosystem": first.ecosystem,
            "semantic_generation": first.semantic_generation,
            "phase_semantic_id": first.phase_semantic_id,
            "roster_id": first.roster_id,
            "roster_denominator": first.roster_denominator,
            "ordered_semantic_work_unit_ids": list(
                self.ordered_semantic_work_unit_ids
            ),
            "ordered_semantic_digests": list(self.ordered_semantic_digests),
        }

    @property
    def roster_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "roster_digest": self.roster_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        plans: Iterable[SemanticWorkPlan],
    ) -> "SemanticRoster":
        _require_exact_keys(value, _ROSTER_KEYS, "semantic roster")
        if value["schema"] != SEMANTIC_ROSTER_SCHEMA:
            raise SemanticSchemaError("unsupported semantic roster schema")
        if value["semantic_profile"] != SEMANTIC_PROFILE:
            raise SemanticSchemaError("semantic_profile must be semantic_v1")
        roster = cls.create(plans)
        if value != roster.to_dict():
            raise SemanticSchemaError(
                "semantic roster fields or roster_digest do not match plans"
            )
        return roster


@dataclass(frozen=True, slots=True)
class BackendArmExecutionIdentity:
    """Backend/model identity separated from the semantic work key."""

    semantic_work_unit_key: str
    semantic_digest: str
    backend_arm_id: str
    backend: str
    execution_generation: int
    exact_model_id: str
    model_capability_tier: str
    capability_receipt_digest: str

    schema: ClassVar[str] = BACKEND_ARM_EXECUTION_SCHEMA

    def __post_init__(self) -> None:
        _sha256(self.semantic_work_unit_key, "semantic_work_unit_key")
        _sha256(self.semantic_digest, "semantic_digest")
        _safe_id(self.backend_arm_id, "backend_arm_id")
        _closed_value(self.backend, BACKENDS, "backend")
        _positive_int(self.execution_generation, "execution_generation")
        _safe_id(self.exact_model_id, "exact_model_id")
        _closed_value(
            self.model_capability_tier,
            MODEL_CAPABILITY_TIERS,
            "model_capability_tier",
        )
        _sha256(
            self.capability_receipt_digest, "capability_receipt_digest"
        )
        if self.backend == "native" and (
            self.model_capability_tier != "N0_NATIVE_DETERMINISTIC"
        ):
            raise SemanticSchemaError(
                "native backend requires N0_NATIVE_DETERMINISTIC"
            )
        if self.backend != "native" and (
            self.model_capability_tier == "N0_NATIVE_DETERMINISTIC"
        ):
            raise SemanticSchemaError(
                "model backend cannot use N0_NATIVE_DETERMINISTIC"
            )

    @classmethod
    def bind(
        cls,
        plan: SemanticWorkPlan,
        *,
        backend_arm_id: str,
        backend: str,
        execution_generation: int,
        exact_model_id: str,
        model_capability_tier: str,
        capability_receipt_digest: str,
    ) -> "BackendArmExecutionIdentity":
        if not isinstance(plan, SemanticWorkPlan):
            raise SemanticSchemaError("plan must be SemanticWorkPlan")
        plan = SemanticWorkPlan.from_bytes(plan.to_bytes())
        if model_capability_tier != plan.model_capability_tier:
            raise SemanticSchemaError(
                "execution model_capability_tier must match semantic plan"
            )
        return cls(
            semantic_work_unit_key=plan.semantic_work_unit_key,
            semantic_digest=plan.semantic_digest,
            backend_arm_id=backend_arm_id,
            backend=backend,
            execution_generation=execution_generation,
            exact_model_id=exact_model_id,
            model_capability_tier=model_capability_tier,
            capability_receipt_digest=capability_receipt_digest,
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "semantic_work_unit_key": self.semantic_work_unit_key,
            "semantic_digest": self.semantic_digest,
            "backend_arm_id": self.backend_arm_id,
            "backend": self.backend,
            "execution_generation": self.execution_generation,
            "exact_model_id": self.exact_model_id,
            "model_capability_tier": self.model_capability_tier,
            "capability_receipt_digest": self.capability_receipt_digest,
        }

    @property
    def execution_work_unit_key(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "execution_work_unit_key": self.execution_work_unit_key,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    def is_exact_resume_of(self, other: object) -> bool:
        return (
            isinstance(other, BackendArmExecutionIdentity)
            and self.execution_work_unit_key == other.execution_work_unit_key
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "BackendArmExecutionIdentity":
        _require_exact_keys(value, _EXECUTION_KEYS, "backend arm execution")
        if value["schema"] != BACKEND_ARM_EXECUTION_SCHEMA:
            raise SemanticSchemaError("unsupported backend execution schema")
        claimed = _sha256(
            value["execution_work_unit_key"], "execution_work_unit_key"
        )
        result = cls(
            semantic_work_unit_key=value["semantic_work_unit_key"],
            semantic_digest=value["semantic_digest"],
            backend_arm_id=value["backend_arm_id"],
            backend=value["backend"],
            execution_generation=value["execution_generation"],
            exact_model_id=value["exact_model_id"],
            model_capability_tier=value["model_capability_tier"],
            capability_receipt_digest=value["capability_receipt_digest"],
        )
        if claimed != result.execution_work_unit_key:
            raise SemanticSchemaError("execution_work_unit_key digest mismatch")
        return result

    @classmethod
    def from_bytes(cls, raw: bytes) -> "BackendArmExecutionIdentity":
        return cls.from_dict(_decode_record(raw))


def fork_backend_generation(
    previous: BackendArmExecutionIdentity,
    *,
    backend_arm_id: str,
    backend: str,
    exact_model_id: str,
    capability_receipt_digest: str,
) -> BackendArmExecutionIdentity:
    """Create the mandatory new arm/generation for a backend switch."""

    if not isinstance(previous, BackendArmExecutionIdentity):
        raise SemanticSchemaError(
            "previous must be BackendArmExecutionIdentity"
        )
    if backend == previous.backend:
        raise SemanticSchemaError(
            "backend must change when forking a backend generation"
        )
    if backend_arm_id == previous.backend_arm_id:
        raise SemanticSchemaError("backend switch requires a new backend arm")
    return BackendArmExecutionIdentity(
        semantic_work_unit_key=previous.semantic_work_unit_key,
        semantic_digest=previous.semantic_digest,
        backend_arm_id=backend_arm_id,
        backend=backend,
        execution_generation=previous.execution_generation + 1,
        exact_model_id=exact_model_id,
        model_capability_tier=previous.model_capability_tier,
        capability_receipt_digest=capability_receipt_digest,
    )


def fork_execution_generation(
    previous: BackendArmExecutionIdentity,
    *,
    exact_model_id: str,
    capability_receipt_digest: str,
) -> BackendArmExecutionIdentity:
    """Fork a same-backend arm when model/capability authority changes."""

    if not isinstance(previous, BackendArmExecutionIdentity):
        raise SemanticSchemaError(
            "previous must be BackendArmExecutionIdentity"
        )
    previous = BackendArmExecutionIdentity.from_bytes(previous.to_bytes())
    if (
        exact_model_id == previous.exact_model_id
        and capability_receipt_digest == previous.capability_receipt_digest
    ):
        raise SemanticSchemaError(
            "execution generation fork requires a model or capability change"
        )
    return BackendArmExecutionIdentity(
        semantic_work_unit_key=previous.semantic_work_unit_key,
        semantic_digest=previous.semantic_digest,
        backend_arm_id=previous.backend_arm_id,
        backend=previous.backend,
        execution_generation=previous.execution_generation + 1,
        exact_model_id=exact_model_id,
        model_capability_tier=previous.model_capability_tier,
        capability_receipt_digest=capability_receipt_digest,
    )


@dataclass(frozen=True, slots=True)
class SemanticPlanGenerationTransition:
    """A transition claim; deserialized claims require parent replay."""

    previous_semantic_digest: str
    successor_semantic_digest: str
    previous_semantic_work_unit_key: str
    successor_semantic_work_unit_key: str
    previous_generation: int
    successor_generation: int
    trigger_evidence_digest: str
    reason_code: str

    schema: ClassVar[str] = SEMANTIC_PLAN_GENERATION_TRANSITION_SCHEMA

    def __post_init__(self) -> None:
        for field in (
            "previous_semantic_digest",
            "successor_semantic_digest",
            "previous_semantic_work_unit_key",
            "successor_semantic_work_unit_key",
            "trigger_evidence_digest",
        ):
            _sha256(getattr(self, field), field)
        previous = _positive_int(
            self.previous_generation, "previous_generation"
        )
        successor = _positive_int(
            self.successor_generation, "successor_generation"
        )
        if successor != previous + 1:
            raise SemanticSchemaError(
                "successor_generation must immediately follow previous_generation"
            )
        if self.previous_semantic_digest == self.successor_semantic_digest:
            raise SemanticSchemaError(
                "semantic transition digests must differ"
            )
        if (
            self.previous_semantic_work_unit_key
            == self.successor_semantic_work_unit_key
        ):
            raise SemanticSchemaError(
                "semantic transition work-unit keys must differ"
            )
        _safe_id(self.reason_code, "reason_code")

    @classmethod
    def bind(
        cls,
        previous: SemanticWorkPlan,
        successor: SemanticWorkPlan,
        *,
        trigger_evidence_digest: str,
        reason_code: str,
    ) -> "SemanticPlanGenerationTransition":
        if not isinstance(previous, SemanticWorkPlan) or not isinstance(
            successor, SemanticWorkPlan
        ):
            raise SemanticSchemaError(
                "semantic generation transition requires two plans"
            )
        previous = SemanticWorkPlan.from_bytes(previous.to_bytes())
        successor = SemanticWorkPlan.from_bytes(successor.to_bytes())
        stable_fields = (
            "run_id",
            "pipeline",
            "mode",
            "ecosystem",
            "phase_semantic_id",
            "semantic_work_unit_id",
        )
        for field in stable_fields:
            if getattr(previous, field) != getattr(successor, field):
                raise SemanticSchemaError(
                    f"semantic generation transition changed stable {field}"
                )
        if successor.semantic_generation != previous.semantic_generation + 1:
            raise SemanticSchemaError(
                "semantic mutation requires the next semantic_generation"
            )
        if successor.semantic_digest == previous.semantic_digest:
            raise SemanticSchemaError(
                "semantic generation transition must change semantic content"
            )
        return cls(
            previous_semantic_digest=previous.semantic_digest,
            successor_semantic_digest=successor.semantic_digest,
            previous_semantic_work_unit_key=previous.semantic_work_unit_key,
            successor_semantic_work_unit_key=successor.semantic_work_unit_key,
            previous_generation=previous.semantic_generation,
            successor_generation=successor.semantic_generation,
            trigger_evidence_digest=_sha256(
                trigger_evidence_digest, "trigger_evidence_digest"
            ),
            reason_code=_safe_id(reason_code, "reason_code"),
        )

    @property
    def transition_digest(self) -> str:
        return _digest(
            {
                "schema": self.schema,
                "previous_semantic_digest": self.previous_semantic_digest,
                "successor_semantic_digest": self.successor_semantic_digest,
                "previous_semantic_work_unit_key": (
                    self.previous_semantic_work_unit_key
                ),
                "successor_semantic_work_unit_key": (
                    self.successor_semantic_work_unit_key
                ),
                "previous_generation": self.previous_generation,
                "successor_generation": self.successor_generation,
                "trigger_evidence_digest": self.trigger_evidence_digest,
                "reason_code": self.reason_code,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "previous_semantic_digest": self.previous_semantic_digest,
            "successor_semantic_digest": self.successor_semantic_digest,
            "previous_semantic_work_unit_key": (
                self.previous_semantic_work_unit_key
            ),
            "successor_semantic_work_unit_key": (
                self.successor_semantic_work_unit_key
            ),
            "previous_generation": self.previous_generation,
            "successor_generation": self.successor_generation,
            "trigger_evidence_digest": self.trigger_evidence_digest,
            "reason_code": self.reason_code,
            "transition_digest": self.transition_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def parse_untrusted_dict(
        cls, value: Mapping[str, Any]
    ) -> "SemanticPlanGenerationTransition":
        _require_exact_keys(
            value,
            _SEMANTIC_TRANSITION_KEYS,
            "semantic plan generation transition",
        )
        if value["schema"] != SEMANTIC_PLAN_GENERATION_TRANSITION_SCHEMA:
            raise SemanticSchemaError(
                "unsupported semantic plan generation transition schema"
            )
        claimed = _sha256(value["transition_digest"], "transition_digest")
        transition = cls(
            previous_semantic_digest=value["previous_semantic_digest"],
            successor_semantic_digest=value["successor_semantic_digest"],
            previous_semantic_work_unit_key=value[
                "previous_semantic_work_unit_key"
            ],
            successor_semantic_work_unit_key=value[
                "successor_semantic_work_unit_key"
            ],
            previous_generation=value["previous_generation"],
            successor_generation=value["successor_generation"],
            trigger_evidence_digest=value["trigger_evidence_digest"],
            reason_code=value["reason_code"],
        )
        if claimed != transition.transition_digest:
            raise SemanticSchemaError("transition_digest mismatch")
        return transition

    @classmethod
    def parse_untrusted_bytes(
        cls, raw: bytes
    ) -> "SemanticPlanGenerationTransition":
        return cls.parse_untrusted_dict(_decode_record(raw))


@dataclass(frozen=True, slots=True)
class ExecutionGenerationTransition:
    """An execution transition claim; deserialization is non-authoritative."""

    previous_execution_work_unit_key: str
    successor_execution_work_unit_key: str
    previous_generation: int
    successor_generation: int
    trigger_evidence_digest: str
    reason_code: str

    schema: ClassVar[str] = EXECUTION_GENERATION_TRANSITION_SCHEMA

    def __post_init__(self) -> None:
        for field in (
            "previous_execution_work_unit_key",
            "successor_execution_work_unit_key",
            "trigger_evidence_digest",
        ):
            _sha256(getattr(self, field), field)
        previous = _positive_int(
            self.previous_generation, "previous_generation"
        )
        successor = _positive_int(
            self.successor_generation, "successor_generation"
        )
        if successor != previous + 1:
            raise SemanticSchemaError(
                "successor_generation must immediately follow previous_generation"
            )
        if (
            self.previous_execution_work_unit_key
            == self.successor_execution_work_unit_key
        ):
            raise SemanticSchemaError(
                "execution transition work-unit keys must differ"
            )
        _safe_id(self.reason_code, "reason_code")

    @classmethod
    def bind(
        cls,
        previous: "SemanticExecutionBundle",
        successor: "SemanticExecutionBundle",
        *,
        trigger_evidence_digest: str,
        reason_code: str,
    ) -> "ExecutionGenerationTransition":
        if not isinstance(previous, SemanticExecutionBundle) or not isinstance(
            successor, SemanticExecutionBundle
        ):
            raise SemanticSchemaError(
                "execution generation transition requires two "
                "SemanticExecutionBundle authorities"
            )
        previous = SemanticExecutionBundle(
            plan=previous.plan,
            execution=previous.execution,
        )
        successor = SemanticExecutionBundle(
            plan=successor.plan,
            execution=successor.execution,
        )
        if previous.plan.semantic_digest != successor.plan.semantic_digest:
            raise SemanticSchemaError(
                "execution generation transition plans do not match"
            )
        previous_execution = previous.execution
        successor_execution = successor.execution
        if (
            successor_execution.semantic_work_unit_key
            != previous_execution.semantic_work_unit_key
            or successor_execution.semantic_digest
            != previous_execution.semantic_digest
        ):
            raise SemanticSchemaError(
                "execution generation cannot change semantic authority"
            )
        if (
            successor_execution.model_capability_tier
            != previous_execution.model_capability_tier
        ):
            raise SemanticSchemaError(
                "execution generation cannot change semantic model tier"
            )
        if (
            successor_execution.execution_generation
            != previous_execution.execution_generation + 1
        ):
            raise SemanticSchemaError(
                "execution mutation requires the next execution_generation"
            )
        if successor_execution.backend != previous_execution.backend:
            if (
                successor_execution.backend_arm_id
                == previous_execution.backend_arm_id
            ):
                raise SemanticSchemaError(
                    "backend switch requires a new backend_arm_id"
                )
        elif (
            successor_execution.backend_arm_id
            != previous_execution.backend_arm_id
        ):
            raise SemanticSchemaError(
                "same-backend generation must retain backend_arm_id"
            )
        if (
            successor_execution.backend == previous_execution.backend
            and successor_execution.exact_model_id
            == previous_execution.exact_model_id
            and successor_execution.capability_receipt_digest
            == previous_execution.capability_receipt_digest
        ):
            raise SemanticSchemaError(
                "execution generation transition cannot be a no-op"
            )
        return cls(
            previous_execution_work_unit_key=(
                previous_execution.execution_work_unit_key
            ),
            successor_execution_work_unit_key=(
                successor_execution.execution_work_unit_key
            ),
            previous_generation=previous_execution.execution_generation,
            successor_generation=successor_execution.execution_generation,
            trigger_evidence_digest=_sha256(
                trigger_evidence_digest, "trigger_evidence_digest"
            ),
            reason_code=_safe_id(reason_code, "reason_code"),
        )

    @property
    def transition_digest(self) -> str:
        return _digest(
            {
                "schema": self.schema,
                "previous_execution_work_unit_key": (
                    self.previous_execution_work_unit_key
                ),
                "successor_execution_work_unit_key": (
                    self.successor_execution_work_unit_key
                ),
                "previous_generation": self.previous_generation,
                "successor_generation": self.successor_generation,
                "trigger_evidence_digest": self.trigger_evidence_digest,
                "reason_code": self.reason_code,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "previous_execution_work_unit_key": (
                self.previous_execution_work_unit_key
            ),
            "successor_execution_work_unit_key": (
                self.successor_execution_work_unit_key
            ),
            "previous_generation": self.previous_generation,
            "successor_generation": self.successor_generation,
            "trigger_evidence_digest": self.trigger_evidence_digest,
            "reason_code": self.reason_code,
            "transition_digest": self.transition_digest,
        }

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def parse_untrusted_dict(
        cls, value: Mapping[str, Any]
    ) -> "ExecutionGenerationTransition":
        _require_exact_keys(
            value,
            _EXECUTION_TRANSITION_KEYS,
            "execution generation transition",
        )
        if value["schema"] != EXECUTION_GENERATION_TRANSITION_SCHEMA:
            raise SemanticSchemaError(
                "unsupported execution generation transition schema"
            )
        claimed = _sha256(value["transition_digest"], "transition_digest")
        transition = cls(
            previous_execution_work_unit_key=value[
                "previous_execution_work_unit_key"
            ],
            successor_execution_work_unit_key=value[
                "successor_execution_work_unit_key"
            ],
            previous_generation=value["previous_generation"],
            successor_generation=value["successor_generation"],
            trigger_evidence_digest=value["trigger_evidence_digest"],
            reason_code=value["reason_code"],
        )
        if claimed != transition.transition_digest:
            raise SemanticSchemaError("transition_digest mismatch")
        return transition

    @classmethod
    def parse_untrusted_bytes(
        cls, raw: bytes
    ) -> "ExecutionGenerationTransition":
        return cls.parse_untrusted_dict(_decode_record(raw))


@dataclass(frozen=True, slots=True)
class SemanticPlanGenerationTransitionAuthority:
    """A transition replayed against the exact predecessor and successor."""

    previous: SemanticWorkPlan
    successor: SemanticWorkPlan
    transition: SemanticPlanGenerationTransition
    trusted_trigger_evidence_digest: str
    trusted_reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.previous, SemanticWorkPlan) or not isinstance(
            self.successor, SemanticWorkPlan
        ):
            raise SemanticSchemaError(
                "semantic transition authority requires two plans"
            )
        if not isinstance(
            self.transition, SemanticPlanGenerationTransition
        ):
            raise SemanticSchemaError(
                "semantic transition authority requires a transition claim"
            )
        previous = SemanticWorkPlan.from_bytes(self.previous.to_bytes())
        successor = SemanticWorkPlan.from_bytes(self.successor.to_bytes())
        trusted_trigger_evidence_digest = _sha256(
            self.trusted_trigger_evidence_digest,
            "trusted_trigger_evidence_digest",
        )
        trusted_reason_code = _safe_id(
            self.trusted_reason_code,
            "trusted_reason_code",
        )
        expected = SemanticPlanGenerationTransition.bind(
            previous,
            successor,
            trigger_evidence_digest=trusted_trigger_evidence_digest,
            reason_code=trusted_reason_code,
        )
        if self.transition != expected:
            raise SemanticSchemaError(
                "semantic transition claim does not match exact parents"
            )
        object.__setattr__(self, "previous", previous)
        object.__setattr__(self, "successor", successor)
        object.__setattr__(self, "transition", expected)
        object.__setattr__(
            self,
            "trusted_trigger_evidence_digest",
            trusted_trigger_evidence_digest,
        )
        object.__setattr__(self, "trusted_reason_code", trusted_reason_code)

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        previous: SemanticWorkPlan,
        successor: SemanticWorkPlan,
        expected_trigger_evidence_digest: str,
        expected_reason_code: str,
    ) -> "SemanticPlanGenerationTransitionAuthority":
        return cls(
            previous=previous,
            successor=successor,
            transition=(
                SemanticPlanGenerationTransition.parse_untrusted_bytes(raw)
            ),
            trusted_trigger_evidence_digest=expected_trigger_evidence_digest,
            trusted_reason_code=expected_reason_code,
        )


@dataclass(frozen=True, slots=True)
class ExecutionGenerationTransitionAuthority:
    """An execution transition replayed against exact execution bundles."""

    previous: "SemanticExecutionBundle"
    successor: "SemanticExecutionBundle"
    transition: ExecutionGenerationTransition
    trusted_trigger_evidence_digest: str
    trusted_reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.previous, SemanticExecutionBundle) or not isinstance(
            self.successor, SemanticExecutionBundle
        ):
            raise SemanticSchemaError(
                "execution transition authority requires two execution bundles"
            )
        if not isinstance(self.transition, ExecutionGenerationTransition):
            raise SemanticSchemaError(
                "execution transition authority requires a transition claim"
            )
        previous = SemanticExecutionBundle(
            plan=self.previous.plan,
            execution=self.previous.execution,
        )
        successor = SemanticExecutionBundle(
            plan=self.successor.plan,
            execution=self.successor.execution,
        )
        trusted_trigger_evidence_digest = _sha256(
            self.trusted_trigger_evidence_digest,
            "trusted_trigger_evidence_digest",
        )
        trusted_reason_code = _safe_id(
            self.trusted_reason_code,
            "trusted_reason_code",
        )
        expected = ExecutionGenerationTransition.bind(
            previous,
            successor,
            trigger_evidence_digest=trusted_trigger_evidence_digest,
            reason_code=trusted_reason_code,
        )
        if self.transition != expected:
            raise SemanticSchemaError(
                "execution transition claim does not match exact parents"
            )
        object.__setattr__(self, "previous", previous)
        object.__setattr__(self, "successor", successor)
        object.__setattr__(self, "transition", expected)
        object.__setattr__(
            self,
            "trusted_trigger_evidence_digest",
            trusted_trigger_evidence_digest,
        )
        object.__setattr__(self, "trusted_reason_code", trusted_reason_code)

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        previous: "SemanticExecutionBundle",
        successor: "SemanticExecutionBundle",
        expected_trigger_evidence_digest: str,
        expected_reason_code: str,
    ) -> "ExecutionGenerationTransitionAuthority":
        return cls(
            previous=previous,
            successor=successor,
            transition=(
                ExecutionGenerationTransition.parse_untrusted_bytes(raw)
            ),
            trusted_trigger_evidence_digest=expected_trigger_evidence_digest,
            trusted_reason_code=expected_reason_code,
        )


@dataclass(frozen=True, slots=True)
class ExecutionAttemptIdentity:
    """Identity of one attempt within an exact backend execution generation."""

    semantic_work_unit_key: str
    execution_work_unit_key: str
    attempt_number: int

    schema: ClassVar[str] = EXECUTION_ATTEMPT_SCHEMA

    def __post_init__(self) -> None:
        _sha256(self.semantic_work_unit_key, "semantic_work_unit_key")
        _sha256(self.execution_work_unit_key, "execution_work_unit_key")
        _positive_int(self.attempt_number, "attempt_number")

    @classmethod
    def bind(
        cls,
        execution: BackendArmExecutionIdentity,
        *,
        plan: SemanticWorkPlan,
        attempt_number: int,
    ) -> "ExecutionAttemptIdentity":
        if not isinstance(execution, BackendArmExecutionIdentity):
            raise SemanticSchemaError(
                "execution must be BackendArmExecutionIdentity"
            )
        if not isinstance(plan, SemanticWorkPlan):
            raise SemanticSchemaError("plan must be SemanticWorkPlan")
        plan = SemanticWorkPlan.from_bytes(plan.to_bytes())
        execution = BackendArmExecutionIdentity.from_bytes(
            execution.to_bytes()
        )
        if execution.semantic_work_unit_key != plan.semantic_work_unit_key:
            raise SemanticSchemaError(
                "execution semantic_work_unit_key does not match plan"
            )
        if execution.semantic_digest != plan.semantic_digest:
            raise SemanticSchemaError(
                "execution semantic_digest does not match plan"
            )
        number = _positive_int(attempt_number, "attempt_number")
        if number > plan.retry_policy.max_attempts:
            raise SemanticSchemaError(
                "attempt_number exceeds plan retry_policy.max_attempts"
            )
        return cls(
            semantic_work_unit_key=execution.semantic_work_unit_key,
            execution_work_unit_key=execution.execution_work_unit_key,
            attempt_number=number,
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "semantic_work_unit_key": self.semantic_work_unit_key,
            "execution_work_unit_key": self.execution_work_unit_key,
            "attempt_number": self.attempt_number,
        }

    @property
    def attempt_key(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "attempt_key": self.attempt_key}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionAttemptIdentity":
        _require_exact_keys(value, _ATTEMPT_KEYS, "execution attempt")
        if value["schema"] != EXECUTION_ATTEMPT_SCHEMA:
            raise SemanticSchemaError("unsupported execution attempt schema")
        claimed = _sha256(value["attempt_key"], "attempt_key")
        result = cls(
            semantic_work_unit_key=value["semantic_work_unit_key"],
            execution_work_unit_key=value["execution_work_unit_key"],
            attempt_number=value["attempt_number"],
        )
        if claimed != result.attempt_key:
            raise SemanticSchemaError("attempt_key digest mismatch")
        return result

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ExecutionAttemptIdentity":
        return cls.from_dict(_decode_record(raw))


@dataclass(frozen=True, slots=True)
class SemanticExecutionBundle:
    """Replayed plan and exact backend-arm execution authority."""

    plan: SemanticWorkPlan
    execution: BackendArmExecutionIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.plan, SemanticWorkPlan):
            raise SemanticSchemaError("plan must be SemanticWorkPlan")
        if not isinstance(self.execution, BackendArmExecutionIdentity):
            raise SemanticSchemaError(
                "execution must be BackendArmExecutionIdentity"
            )
        plan = SemanticWorkPlan.from_bytes(self.plan.to_bytes())
        execution = BackendArmExecutionIdentity.from_bytes(
            self.execution.to_bytes()
        )
        if execution.semantic_work_unit_key != plan.semantic_work_unit_key:
            raise SemanticSchemaError(
                "execution semantic_work_unit_key does not match plan"
            )
        if execution.semantic_digest != plan.semantic_digest:
            raise SemanticSchemaError(
                "execution semantic_digest does not match plan"
            )
        if execution.model_capability_tier != plan.model_capability_tier:
            raise SemanticSchemaError(
                "execution model_capability_tier does not match plan"
            )
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "execution", execution)


@dataclass(frozen=True, slots=True)
class SemanticAttemptBundle:
    """Replayed plan/execution/attempt with retry-ceiling authority."""

    execution_bundle: SemanticExecutionBundle
    attempt: ExecutionAttemptIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.execution_bundle, SemanticExecutionBundle):
            raise SemanticSchemaError(
                "execution_bundle must be SemanticExecutionBundle"
            )
        if not isinstance(self.attempt, ExecutionAttemptIdentity):
            raise SemanticSchemaError(
                "attempt must be ExecutionAttemptIdentity"
            )
        bundle = SemanticExecutionBundle(
            plan=self.execution_bundle.plan,
            execution=self.execution_bundle.execution,
        )
        attempt = ExecutionAttemptIdentity.from_bytes(self.attempt.to_bytes())
        if attempt.semantic_work_unit_key != bundle.plan.semantic_work_unit_key:
            raise SemanticSchemaError(
                "attempt semantic_work_unit_key does not match plan"
            )
        if (
            attempt.execution_work_unit_key
            != bundle.execution.execution_work_unit_key
        ):
            raise SemanticSchemaError(
                "attempt execution_work_unit_key does not match execution"
            )
        if attempt.attempt_number > bundle.plan.retry_policy.max_attempts:
            raise SemanticSchemaError(
                "attempt_number exceeds plan retry_policy.max_attempts"
            )
        object.__setattr__(self, "execution_bundle", bundle)
        object.__setattr__(self, "attempt", attempt)


__all__ = [
    "ANALYSIS_TEMPLATE_ID",
    "BACKEND_ARM_EXECUTION_SCHEMA",
    "BACKENDS",
    "CHILD_POLICY",
    "CompletionPolicy",
    "ECOSYSTEMS",
    "EXECUTION_GENERATION_TRANSITION_SCHEMA",
    "EXECUTION_ATTEMPT_SCHEMA",
    "ExecutionAttemptIdentity",
    "ExecutionGenerationTransition",
    "ExecutionGenerationTransitionAuthority",
    "LEGACY_PROFILE",
    "MODEL_CAPABILITY_TIERS",
    "MODES",
    "NATIVE_TEMPLATE_ID",
    "PIPELINES",
    "REPORT_TEMPLATE_ID",
    "RetryPolicy",
    "SEMANTIC_CAPABILITIES",
    "SEMANTIC_TEMPLATE_IDS",
    "SEMANTIC_PROFILE",
    "SEMANTIC_PLAN_GENERATION_TRANSITION_SCHEMA",
    "SEMANTIC_ROSTER_SCHEMA",
    "SEMANTIC_WORK_PLAN_SCHEMA",
    "SemanticAttemptBundle",
    "SemanticExecutionBundle",
    "SemanticPlanGenerationTransition",
    "SemanticPlanGenerationTransitionAuthority",
    "SemanticRoster",
    "SemanticSchemaError",
    "SemanticWorkPlan",
    "BackendArmExecutionIdentity",
    "fork_backend_generation",
    "fork_execution_generation",
    "derive_semantic_template_id",
]
