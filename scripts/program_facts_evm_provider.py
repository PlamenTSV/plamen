"""Typed, emit-only EVM Program Facts provider adapter.

This module deliberately does not discover, install, import, or execute Slither.
Execution belongs to the reviewed WorkerTransaction/NativeCommandAdapter path.
The adapter only:

* compiles a registry-bound provisional provider plan;
* parses exact helper JSON into a provisional :class:`ProviderResult`;
* reconciles authoritative source denominators and normalizes replay-bound
  positive rows into an immutable :class:`EvmNormalizationOutcome`; and
* emits a deterministic, reason-typed three-sidecar bundle when the provider
  cannot run.

No object returned here has negative, clean, finding, severity, publication, or
consumer authority.  Stage-3 driver composition remains responsible for binding
completed build/worker/PhaseIO receipts before a positive contribution can be
published as canonical sidecars.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from program_facts_provider_api import (
    FactContribution,
    ObservedProviderIdentity,
    ParsedProviderOutput,
    ProviderContext,
    ProviderPlan,
    ProviderPlanDecision,
    ProviderResources,
    ProviderResult,
    ProviderSourceInputSnapshot,
    ZeroPositiveAccounting,
    compile_provider_plan,
    replay_provider_source_input_snapshot,
    snapshot_provider_source_inputs,
    validate_fact_contribution,
    validate_parsed_provider_output,
)
from program_facts_provider_registry import LoadedProgramFactsProviderRegistry
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    derive_debt_id,
    derive_fact_id,
    derive_node_id,
    derive_occurrence_id,
    derive_program_facts_reuse_key,
    derive_source_manifest_digest,
    derive_stable_id,
    signed_payload,
    strict_json_loads,
    validate_portable_path,
    validate_program_facts_bundle_structural_test_only,
)


EVM_PROVIDER_ID = "evm.slither.typed"
EVM_RAW_SCHEMA_VERSION = "plamen.evm_slither_raw.v1"
EVM_CAPABILITY_IDS = (
    "evm.slither.calls.v1",
    "evm.slither.cfg.v1",
    "evm.slither.dependencies.v1",
    "evm.slither.sinks.v1",
    "evm.slither.state.v1",
    "evm.slither.structure.v1",
)

_PAYLOAD_PATH = "mechanical_program_facts.v1.json"
_RECEIPT_PATH = "mechanical_program_facts_receipt.v1.json"
_DEBT_PATH = "mechanical_program_facts_debt.v1.json"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_LOCAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_DEBT_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")

_TOP_KEYS = frozenset(
    {
        "schema_version",
        "plan_id",
        "provider_run_id",
        "source_manifest_digest",
        "build_variant_id",
        "tool",
        "compiled_source_file_ids",
        "capability_dispositions",
        "nodes",
        "occurrences",
        "facts",
        "debts",
        "zero_positive_denominators",
    }
)
_TOOL_KEYS = frozenset(
    {
        "name",
        "executable_or_module_digest",
        "distribution_name",
        "distribution_version",
        "distribution_checksum",
        "version_output",
        "parser_source_digest",
        "raw_schema_digest",
        "toolchains",
    }
)
_TOOLCHAIN_KEYS = frozenset({"name", "version", "identity_digest"})
_DISPOSITION_KEYS = frozenset(
    {"capability_id", "disposition", "diagnostic_codes", "debt_codes"}
)
_NODE_KEYS = frozenset(
    {
        "local_id",
        "kind",
        "qualified_name",
        "display_name",
        "canonical_signature",
        "attributes",
        "source",
        "reason",
    }
)
_SOURCE_KEYS = frozenset(
    {"source_file_id", "path", "start_byte", "end_byte"}
)
_SOURCE_FILE_KEYS = frozenset(
    {
        "source_file_id",
        "path",
        "path_casefold_key",
        "source_sha256",
        "size_bytes",
        "language",
        "scope_class",
        "physical_identity_digest",
    }
)
_EXCLUDED_FILE_KEYS = frozenset({"identity", "reason", "source_sha256"})
_OCCURRENCE_KEYS = frozenset(
    {"local_id", "kind", "enclosing_local_id", "source", "ir_binding"}
)
_FACT_KEYS = frozenset(
    {
        "capability_id",
        "relation_kind",
        "subject_local_id",
        "object_local_id",
        "occurrence_local_ids",
        "provenance_origin",
        "precision",
        "coverage_scope",
        "structural_confidence",
        "context",
    }
)
_CONTEXT_KEYS = frozenset(
    {
        "call_dispatch",
        "analysis_algorithm",
        "root_set_digest",
        "dominating_predicates",
        "host_semantic_kind",
    }
)
_RAW_DEBT_KEYS = frozenset(
    {
        "reason",
        "capability_id",
        "scope_local_ids",
        "explanation",
        "evidence_refs",
        "retryable",
        "blocks_reuse",
    }
)
_ZERO_POSITIVE_KEYS = frozenset(
    {
        "capability_id",
        "build_variant_id",
        "denominator_kind",
        "node_local_ids",
        "source_file_ids",
    }
)

_NODE_KINDS = frozenset(
    {
        "COMPILATION_UNIT",
        "PACKAGE",
        "MODULE",
        "CONTRACT",
        "INTERFACE",
        "LIBRARY",
        "TRAIT",
        "IMPL",
        "FUNCTION",
        "METHOD",
        "MODIFIER",
        "CONSTRUCTOR",
        "BASIC_BLOCK",
        "PARAMETER",
        "LOCAL",
        "STATE_SYMBOL",
        "TYPE",
        "RESOURCE",
        "OBJECT",
        "ACCOUNT_FIELD",
        "AUTH_SUBJECT",
        "STORAGE_KEY",
        "EXTERNAL_SYMBOL",
        "UNKNOWN_TARGET",
    }
)
_OCCURRENCE_KINDS = frozenset(
    {
        "CALL_SITE",
        "READ_SITE",
        "WRITE_SITE",
        "BRANCH_PREDICATE",
        "RETURN_SITE",
        "SINK_SITE",
        "AUTH_SITE",
        "TRANSFER_SITE",
        "CREATE_SITE",
    }
)
_RELATION_KINDS = frozenset(
    {
        "CONTAINS",
        "DECLARES",
        "INHERITS_OR_IMPLEMENTS",
        "EXACT_CFG_EDGE",
        "EXACT_CFG_DOMINATES",
        "EXACT_CFG_POST_DOMINATES",
        "MAY_DEPENDENCY_FUNCTION",
        "MAY_DEPENDENCY_CONTRACT",
        "RESOLVED_STATIC_CALL",
        "MAY_REACH_CHA",
        "MAY_REACH_RTA",
        "MAY_REACH_VTA",
        "UNRESOLVED_DYNAMIC_CALL",
        "READS_STATE",
        "WRITES_STATE",
        "READS_ACCOUNT_FIELD",
        "WRITES_ACCOUNT_FIELD",
        "SYNTACTIC_SINK",
        "HOST_SEMANTIC_SINK",
        "AUTH_CHECK_OCCURRENCE",
        "VALUE_TRANSFER_OCCURRENCE",
        "CREATE_OCCURRENCE",
        "RESOURCE_FLOW_OCCURRENCE",
        "OBJECT_FLOW_OCCURRENCE",
        "HOST_CONSTRAINT_OCCURRENCE",
    }
)
_PROVENANCE = frozenset(
    {"COMPILER_IR", "SSA", "AST", "BYTECODE", "SOURCE_PARSE", "INDEX_REFERENCE"}
)
_PRECISION = frozenset({"EXACT", "MAY", "HEURISTIC", "SYNTACTIC"})
_COVERAGE_SCOPE = frozenset(
    {"OCCURRENCE", "FUNCTION", "CONTRACT", "PACKAGE", "BUILD_VARIANT"}
)
_STRUCTURAL_CONFIDENCE = frozenset(
    {"PROVIDER_EXACT", "PROVIDER_MAY", "SOURCE_FALLBACK", "UNKNOWN"}
)
_CALL_DISPATCH = frozenset(
    {
        "INTERNAL",
        "LIBRARY",
        "INTERFACE",
        "HIGH_LEVEL",
        "LOW_LEVEL",
        "DELEGATE",
        "CREATE",
        "DYNAMIC",
        "UNKNOWN",
    }
)
_DEBT_REASONS = frozenset(
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

_FUNCTION_KINDS = frozenset(
    {"FUNCTION", "METHOD", "MODIFIER", "CONSTRUCTOR"}
)
_CONTRACT_KINDS = frozenset({"CONTRACT", "INTERFACE", "LIBRARY"})
_DECLARED_KINDS = frozenset(
    {
        "FUNCTION",
        "METHOD",
        "MODIFIER",
        "CONSTRUCTOR",
        "BASIC_BLOCK",
        "PARAMETER",
        "LOCAL",
        "STATE_SYMBOL",
        "TYPE",
    }
)
_STATE_TARGET_KINDS = frozenset({"STATE_SYMBOL"})
_DEPENDENCY_TARGET_KINDS = frozenset(
    {"STATE_SYMBOL", "LOCAL", "PARAMETER"}
)
_CALL_TARGET_KINDS = frozenset(
    {"FUNCTION", "METHOD", "MODIFIER", "CONSTRUCTOR", "EXTERNAL_SYMBOL"}
)
_SINK_TARGET_KINDS = frozenset(
    {
        "FUNCTION",
        "METHOD",
        "CONSTRUCTOR",
        "EXTERNAL_SYMBOL",
        "UNKNOWN_TARGET",
    }
)


@dataclass(frozen=True)
class _RelationSemanticRule:
    capability_id: str
    subject_kinds: frozenset[str]
    object_kinds: frozenset[str]
    occurrence_kinds: frozenset[str]
    minimum_occurrences: int
    provenance_origins: frozenset[str]
    precision_confidence: frozenset[tuple[str, str]]
    call_dispatch: frozenset[str]
    algorithm_policy: str
    root_set_policy: str
    dominating_predicates_allowed: bool


def _semantic_rule(
    capability_id: str,
    subject_kinds: frozenset[str],
    object_kinds: frozenset[str],
    occurrence_kinds: frozenset[str],
    minimum_occurrences: int,
    provenance_origins: frozenset[str],
    precision_confidence: frozenset[tuple[str, str]],
    call_dispatch: frozenset[str] = frozenset({"UNKNOWN"}),
    algorithm_policy: str = "FORBIDDEN",
    root_set_policy: str = "FORBIDDEN",
    dominating_predicates_allowed: bool = False,
) -> _RelationSemanticRule:
    return _RelationSemanticRule(
        capability_id=capability_id,
        subject_kinds=subject_kinds,
        object_kinds=object_kinds,
        occurrence_kinds=occurrence_kinds,
        minimum_occurrences=minimum_occurrences,
        provenance_origins=provenance_origins,
        precision_confidence=precision_confidence,
        call_dispatch=call_dispatch,
        algorithm_policy=algorithm_policy,
        root_set_policy=root_set_policy,
        dominating_predicates_allowed=dominating_predicates_allowed,
    )


_EXACT = frozenset({("EXACT", "PROVIDER_EXACT")})
_MAY = frozenset({("MAY", "PROVIDER_MAY")})
_SYNTACTIC = frozenset({("SYNTACTIC", "SOURCE_FALLBACK")})
_EXACT_OR_MAY = frozenset(
    {("EXACT", "PROVIDER_EXACT"), ("MAY", "PROVIDER_MAY")}
)
_CALL_DISPATCH_RESOLVED = frozenset(
    {"INTERNAL", "LIBRARY", "INTERFACE", "HIGH_LEVEL"}
)
_CALL_DISPATCH_UNRESOLVED = frozenset(
    {"LOW_LEVEL", "DELEGATE", "DYNAMIC", "UNKNOWN"}
)

_RELATION_SEMANTICS: Mapping[str, _RelationSemanticRule] = MappingProxyType(
    {
        "CONTAINS": _semantic_rule(
            "evm.slither.structure.v1",
            _CONTRACT_KINDS | _FUNCTION_KINDS,
            _DECLARED_KINDS,
            frozenset(),
            0,
            frozenset({"AST", "INDEX_REFERENCE"}),
            _EXACT,
        ),
        "DECLARES": _semantic_rule(
            "evm.slither.structure.v1",
            _CONTRACT_KINDS,
            _DECLARED_KINDS - {"BASIC_BLOCK", "LOCAL"},
            frozenset(),
            0,
            frozenset({"AST", "INDEX_REFERENCE"}),
            _EXACT,
        ),
        "INHERITS_OR_IMPLEMENTS": _semantic_rule(
            "evm.slither.structure.v1",
            _CONTRACT_KINDS,
            _CONTRACT_KINDS | {"EXTERNAL_SYMBOL"},
            frozenset(),
            0,
            frozenset({"AST", "INDEX_REFERENCE"}),
            _EXACT,
        ),
        "EXACT_CFG_EDGE": _semantic_rule(
            "evm.slither.cfg.v1",
            frozenset({"BASIC_BLOCK"}),
            frozenset({"BASIC_BLOCK"}),
            frozenset({"BRANCH_PREDICATE"}),
            0,
            frozenset({"COMPILER_IR", "SSA"}),
            _EXACT,
            algorithm_policy="REQUIRED",
        ),
        "EXACT_CFG_DOMINATES": _semantic_rule(
            "evm.slither.cfg.v1",
            frozenset({"BASIC_BLOCK"}),
            frozenset({"BASIC_BLOCK"}),
            frozenset(),
            0,
            frozenset({"COMPILER_IR", "SSA"}),
            _EXACT,
            algorithm_policy="REQUIRED",
        ),
        "EXACT_CFG_POST_DOMINATES": _semantic_rule(
            "evm.slither.cfg.v1",
            frozenset({"BASIC_BLOCK"}),
            frozenset({"BASIC_BLOCK"}),
            frozenset(),
            0,
            frozenset({"COMPILER_IR", "SSA"}),
            _EXACT,
            algorithm_policy="REQUIRED",
        ),
        "MAY_DEPENDENCY_FUNCTION": _semantic_rule(
            "evm.slither.dependencies.v1",
            _FUNCTION_KINDS,
            _DEPENDENCY_TARGET_KINDS,
            frozenset({"READ_SITE", "WRITE_SITE"}),
            1,
            frozenset({"AST", "COMPILER_IR", "SSA"}),
            _MAY,
            algorithm_policy="REQUIRED",
            dominating_predicates_allowed=True,
        ),
        "MAY_DEPENDENCY_CONTRACT": _semantic_rule(
            "evm.slither.dependencies.v1",
            _CONTRACT_KINDS,
            _DEPENDENCY_TARGET_KINDS,
            frozenset({"READ_SITE", "WRITE_SITE"}),
            1,
            frozenset({"AST", "COMPILER_IR", "SSA"}),
            _MAY,
            algorithm_policy="REQUIRED",
        ),
        "RESOLVED_STATIC_CALL": _semantic_rule(
            "evm.slither.calls.v1",
            _FUNCTION_KINDS,
            _CALL_TARGET_KINDS,
            frozenset({"CALL_SITE"}),
            1,
            frozenset({"AST", "BYTECODE", "COMPILER_IR"}),
            _EXACT,
            _CALL_DISPATCH_RESOLVED,
            dominating_predicates_allowed=True,
        ),
        "MAY_REACH_CHA": _semantic_rule(
            "evm.slither.calls.v1",
            _FUNCTION_KINDS,
            _CALL_TARGET_KINDS,
            frozenset({"CALL_SITE"}),
            1,
            frozenset({"AST", "BYTECODE", "COMPILER_IR"}),
            _MAY,
            _CALL_DISPATCH_RESOLVED,
            algorithm_policy="REQUIRED",
            root_set_policy="REQUIRED",
            dominating_predicates_allowed=True,
        ),
        "MAY_REACH_RTA": _semantic_rule(
            "evm.slither.calls.v1",
            _FUNCTION_KINDS,
            _CALL_TARGET_KINDS,
            frozenset({"CALL_SITE"}),
            1,
            frozenset({"AST", "BYTECODE", "COMPILER_IR"}),
            _MAY,
            _CALL_DISPATCH_RESOLVED,
            algorithm_policy="REQUIRED",
            root_set_policy="REQUIRED",
            dominating_predicates_allowed=True,
        ),
        "MAY_REACH_VTA": _semantic_rule(
            "evm.slither.calls.v1",
            _FUNCTION_KINDS,
            _CALL_TARGET_KINDS,
            frozenset({"CALL_SITE"}),
            1,
            frozenset({"AST", "BYTECODE", "COMPILER_IR"}),
            _MAY,
            _CALL_DISPATCH_RESOLVED,
            algorithm_policy="REQUIRED",
            root_set_policy="REQUIRED",
            dominating_predicates_allowed=True,
        ),
        "UNRESOLVED_DYNAMIC_CALL": _semantic_rule(
            "evm.slither.calls.v1",
            _FUNCTION_KINDS,
            frozenset({"UNKNOWN_TARGET"}),
            frozenset({"CALL_SITE"}),
            1,
            frozenset({"AST", "BYTECODE", "COMPILER_IR"}),
            _MAY,
            _CALL_DISPATCH_UNRESOLVED,
            algorithm_policy="REQUIRED",
            dominating_predicates_allowed=True,
        ),
        "READS_STATE": _semantic_rule(
            "evm.slither.state.v1",
            _FUNCTION_KINDS,
            _STATE_TARGET_KINDS,
            frozenset({"READ_SITE"}),
            1,
            frozenset({"AST", "COMPILER_IR", "SSA"}),
            _EXACT,
            dominating_predicates_allowed=True,
        ),
        "WRITES_STATE": _semantic_rule(
            "evm.slither.state.v1",
            _FUNCTION_KINDS,
            _STATE_TARGET_KINDS,
            frozenset({"WRITE_SITE"}),
            1,
            frozenset({"AST", "COMPILER_IR", "SSA"}),
            _EXACT,
            dominating_predicates_allowed=True,
        ),
        "SYNTACTIC_SINK": _semantic_rule(
            "evm.slither.sinks.v1",
            _FUNCTION_KINDS,
            _SINK_TARGET_KINDS,
            frozenset({"SINK_SITE"}),
            1,
            frozenset({"AST", "SOURCE_PARSE"}),
            _SYNTACTIC,
            frozenset(
                {
                    "HIGH_LEVEL",
                    "LOW_LEVEL",
                    "DELEGATE",
                    "DYNAMIC",
                    "UNKNOWN",
                }
            ),
            dominating_predicates_allowed=True,
        ),
        "AUTH_CHECK_OCCURRENCE": _semantic_rule(
            "evm.slither.sinks.v1",
            _FUNCTION_KINDS,
            frozenset(
                {
                    "AUTH_SUBJECT",
                    "STATE_SYMBOL",
                    "EXTERNAL_SYMBOL",
                    "UNKNOWN_TARGET",
                }
            ),
            frozenset({"AUTH_SITE"}),
            1,
            frozenset({"AST", "SOURCE_PARSE"}),
            _SYNTACTIC,
            dominating_predicates_allowed=True,
        ),
        "VALUE_TRANSFER_OCCURRENCE": _semantic_rule(
            "evm.slither.sinks.v1",
            _FUNCTION_KINDS,
            _SINK_TARGET_KINDS,
            frozenset({"TRANSFER_SITE"}),
            1,
            frozenset({"AST", "COMPILER_IR"}),
            _EXACT_OR_MAY,
            frozenset({"HIGH_LEVEL", "LOW_LEVEL", "DELEGATE", "UNKNOWN"}),
            dominating_predicates_allowed=True,
        ),
        "CREATE_OCCURRENCE": _semantic_rule(
            "evm.slither.sinks.v1",
            _FUNCTION_KINDS,
            _CONTRACT_KINDS | {"EXTERNAL_SYMBOL", "UNKNOWN_TARGET"},
            frozenset({"CREATE_SITE"}),
            1,
            frozenset({"AST", "COMPILER_IR"}),
            _EXACT_OR_MAY,
            frozenset({"CREATE"}),
            dominating_predicates_allowed=True,
        ),
    }
)


@dataclass(frozen=True)
class _UnavailableReasonPolicy:
    coverage_status: str
    receipt_status: str
    retryable: bool
    blocks_reuse: bool


def _unavailable_policy(
    coverage_status: str,
    receipt_status: str,
    retryable: bool,
    blocks_reuse: bool,
) -> _UnavailableReasonPolicy:
    return _UnavailableReasonPolicy(
        coverage_status,
        receipt_status,
        retryable,
        blocks_reuse,
    )


_UNAVAILABLE_REASON_POLICY: Mapping[str, _UnavailableReasonPolicy] = (
    MappingProxyType(
        {
            "PROVIDER_UNSUPPORTED_ECOSYSTEM": _unavailable_policy(
                "UNSUPPORTED", "UNAVAILABLE", False, False
            ),
            "UNSUPPORTED_HOST_SEMANTICS": _unavailable_policy(
                "UNSUPPORTED", "UNAVAILABLE", False, False
            ),
            "LICENSE_OR_DISTRIBUTION_RESTRICTED": _unavailable_policy(
                "UNSUPPORTED", "UNAVAILABLE", False, False
            ),
            "PROVIDER_UNAVAILABLE": _unavailable_policy(
                "UNKNOWN", "UNAVAILABLE", True, True
            ),
            "PROVIDER_IDENTITY_UNBOUND": _unavailable_policy(
                "UNKNOWN", "UNAVAILABLE", False, True
            ),
            "PROVIDER_VERSION_DRIFT": _unavailable_policy(
                "UNKNOWN", "UNAVAILABLE", False, True
            ),
            "EXECUTABLE_DIGEST_DRIFT": _unavailable_policy(
                "UNKNOWN", "UNAVAILABLE", False, True
            ),
            "PARSER_DIGEST_DRIFT": _unavailable_policy(
                "UNKNOWN", "UNAVAILABLE", False, True
            ),
            "STALE_SNAPSHOT": _unavailable_policy(
                "UNKNOWN", "STALE", True, True
            ),
            "SOURCE_CHANGED_DURING_RUN": _unavailable_policy(
                "UNKNOWN", "STALE", True, True
            ),
            "ANALYSIS_TIMEOUT": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "OUTPUT_TRUNCATED": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "RESOURCE_LIMIT": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "RAW_OUTPUT_MALFORMED": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "BUILD_CONFIGURATION_UNRESOLVED": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "BUILD_FAILED": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "BUILD_PARTIAL": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "WORKER_TRANSACTION_INCOMPLETE": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "PHASE_IO_INCORPORATION_FAILED": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
            "OS_PROCESS_SCOPE_UNPROVEN": _unavailable_policy(
                "UNKNOWN", "FAILED", True, True
            ),
        }
    )
)


class EvmProgramFactsProviderError(ValueError):
    """Closed failure for Stage-2 provider planning/parsing/normalization."""


@dataclass(frozen=True)
class EvmProviderLimits:
    """Parser-local ceilings, bounded again by the reviewed ProviderPlan."""

    max_raw_bytes: int = 16 * 1024 * 1024
    max_records: int = 250_000
    max_string_bytes: int = 1 * 1024 * 1024
    max_nesting: int = 64

    def __post_init__(self) -> None:
        for name in (
            "max_raw_bytes",
            "max_records",
            "max_string_bytes",
            "max_nesting",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise EvmProgramFactsProviderError(
                    f"{name} must be a positive integer"
                )


def _effective_limits(
    plan: ProviderPlan,
    requested: EvmProviderLimits | None,
) -> EvmProviderLimits:
    """Return reviewed parser ceilings; caller values may only narrow them."""

    if type(plan) is not ProviderPlan:
        _fail("EVM parser limits require an issued ProviderPlan")
    hard = EvmProviderLimits()
    plan_raw_cap = min(hard.max_raw_bytes, int(plan.resources.output_bytes))
    if plan_raw_cap <= 0:
        _fail("EVM provider plan has no positive parser output budget")
    if requested is None:
        return EvmProviderLimits(
            max_raw_bytes=plan_raw_cap,
            max_records=hard.max_records,
            max_string_bytes=min(hard.max_string_bytes, plan_raw_cap),
            max_nesting=hard.max_nesting,
        )
    if type(requested) is not EvmProviderLimits:
        _fail("custom EVM parser limits require exact EvmProviderLimits")
    widened = (
        requested.max_raw_bytes > plan_raw_cap
        or requested.max_records > hard.max_records
        or requested.max_string_bytes > hard.max_string_bytes
        or requested.max_nesting > hard.max_nesting
    )
    if widened:
        _fail(
            "custom EVM parser limits may narrow but cannot widen the "
            "reviewed plan or built-in ceilings"
        )
    return EvmProviderLimits(
        max_raw_bytes=requested.max_raw_bytes,
        max_records=requested.max_records,
        max_string_bytes=min(
            requested.max_string_bytes,
            requested.max_raw_bytes,
        ),
        max_nesting=requested.max_nesting,
    )


@dataclass(frozen=True)
class EvmProgramFactsEmission:
    """Canonical staged bytes with explicit non-production authority."""

    payload: Mapping[str, Any]
    receipt: Mapping[str, Any]
    debt: Mapping[str, Any]
    sidecars: Mapping[str, bytes]
    production_authority_established: bool = False
    consumer_activation: bool = False


_NORMALIZATION_OUTCOME_SCHEMA = "plamen.evm_normalization_outcome.v1"
_DENOMINATOR_DECISION_KEYS = frozenset(
    {
        "capability_id",
        "build_variant_id",
        "denominator_kind",
        "expected_source_file_ids",
        "expected_denominator_digest",
        "observed_compiled_source_file_ids",
        "observed_compiled_digest",
        "observed_zero_positive",
        "observed_zero_build_variant_id",
        "observed_zero_denominator_kind",
        "observed_zero_node_local_ids",
        "observed_zero_source_file_ids",
        "status",
        "reason_codes",
        "decision_digest",
    }
)
_PROPOSAL_AUTHORITY = {
    "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
    "terminal_negative_authority": False,
    "publication_authority": "NONE",
}
_DEBT_PROPOSAL_KEYS = frozenset(
    {
        "schema_version",
        "capability_id",
        "build_variant_id",
        "reason",
        "reason_codes",
        "scope_ids",
        "source_input_binding_digest",
        "semantic_authority",
        "terminal_negative_authority",
        "publication_authority",
        "proposal_digest",
    }
)
_COVERAGE_PROPOSAL_KEYS = frozenset(
    {
        "schema_version",
        "capability_id",
        "build_variant_id",
        "status",
        "eligible_source_file_ids",
        "covered_source_file_ids",
        "unresolved_debt_codes",
        "denominator_digest",
        "source_input_binding_digest",
        "semantic_authority",
        "terminal_negative_authority",
        "publication_authority",
        "proposal_digest",
    }
)
_OUTCOME_KEYS = frozenset(
    {
        "schema_version",
        "original_carrier",
        "source_input_binding_digest",
        "denominator_decisions",
        "effective_result",
        "contribution",
        "debt_proposals",
        "coverage_proposals",
        "authority",
        "completion_authority",
        "outcome_digest",
    }
)
_OUTCOME_AUTHORITY = {
    "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
    "terminal_negative_authority": False,
    "can_suppress": False,
    "can_demote": False,
    "can_refute": False,
    "can_mark_examined": False,
    "can_certify_clean": False,
    "publication_authority": "NONE",
}


def _proposal_digest(row: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in row.items() if key != "proposal_digest"}
        )
    ).hexdigest()


def _decision_digest(row: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in row.items() if key != "decision_digest"}
        )
    ).hexdigest()


@dataclass(frozen=True)
class EvmNormalizationOutcome:
    """Immutable proof of a monotonic provider-result degradation.

    The outcome binds the original parsed carrier, independently reconciled
    source denominators, an equal-or-weaker effective result, its contribution,
    and proposal-only scoped debt/coverage.  It cannot publish sidecars or mint
    completion/negative authority.
    """

    original_carrier: ParsedProviderOutput
    source_input_binding_digest: str
    denominator_decisions: tuple[Mapping[str, Any], ...]
    effective_result: ProviderResult
    contribution: FactContribution
    debt_proposals: tuple[Mapping[str, Any], ...] = ()
    coverage_proposals: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        carrier = (
            ParsedProviderOutput.from_dict(self.original_carrier.to_dict())
            if type(self.original_carrier) is ParsedProviderOutput
            else ParsedProviderOutput.from_dict(self.original_carrier)
            if isinstance(self.original_carrier, Mapping)
            else _fail("normalization outcome carrier is invalid")
        )
        effective = (
            ProviderResult.from_dict(self.effective_result.to_dict())
            if type(self.effective_result) is ProviderResult
            else ProviderResult.from_dict(self.effective_result)
            if isinstance(self.effective_result, Mapping)
            else _fail("normalization outcome effective result is invalid")
        )
        contribution = (
            FactContribution.from_dict(self.contribution.to_dict())
            if type(self.contribution) is FactContribution
            else FactContribution.from_dict(self.contribution)
            if isinstance(self.contribution, Mapping)
            else _fail("normalization outcome contribution is invalid")
        )
        _hex64(
            self.source_input_binding_digest,
            "normalization source-input binding",
        )
        decisions: list[Mapping[str, Any]] = []
        decision_pairs: list[tuple[str, str]] = []
        mismatched_capabilities: set[str] = set()
        for raw_row in self.denominator_decisions:
            row = _mapping(raw_row, "normalization denominator decision")
            _exact_keys(
                row,
                _DENOMINATOR_DECISION_KEYS,
                "normalization denominator decision",
            )
            capability_id = _text(
                row["capability_id"],
                "normalization decision capability",
            )
            build_variant_id = _text(
                row["build_variant_id"],
                "normalization decision build variant",
            )
            denominator_kind = _text(
                row["denominator_kind"],
                "normalization decision denominator kind",
            )
            expected_ids = _string_list(
                row["expected_source_file_ids"],
                "normalization expected source IDs",
                sorted_required=True,
            )
            observed_ids = _string_list(
                row["observed_compiled_source_file_ids"],
                "normalization observed compiled source IDs",
                sorted_required=True,
            )
            zero_sources = _string_list(
                row["observed_zero_source_file_ids"],
                "normalization observed zero-positive source IDs",
                sorted_required=True,
            )
            zero_nodes = _string_list(
                row["observed_zero_node_local_ids"],
                "normalization observed zero-positive node IDs",
                sorted_required=True,
            )
            _boolean(
                row["observed_zero_positive"],
                "normalization observed zero-positive flag",
            )
            for key in (
                "observed_zero_build_variant_id",
                "observed_zero_denominator_kind",
            ):
                _text(
                    row[key],
                    f"normalization {key}",
                    allow_empty=True,
                )
            status = _enum(
                row["status"],
                frozenset({"EXACT", "MISMATCH"}),
                "normalization denominator status",
            )
            reasons = _string_list(
                row["reason_codes"],
                "normalization denominator reason codes",
                sorted_required=True,
            )
            if (status == "EXACT") != (not reasons):
                _fail(
                    "normalization denominator status/reason accounting "
                    "is inconsistent"
                )
            if status == "MISMATCH":
                mismatched_capabilities.add(capability_id)
            expected_semantic = {
                "capability_id": capability_id,
                "build_variant_id": build_variant_id,
                "denominator_kind": denominator_kind,
                "source_file_ids": list(expected_ids),
                "source_input_binding_digest": (
                    self.source_input_binding_digest
                ),
            }
            if row["expected_denominator_digest"] != hashlib.sha256(
                canonical_json_bytes(expected_semantic)
            ).hexdigest():
                _fail("normalization expected denominator digest mismatch")
            observed_semantic = {
                "build_variant_id": build_variant_id,
                "compiled_source_file_ids": list(observed_ids),
                "carrier_digest": carrier.carrier_digest,
            }
            if row["observed_compiled_digest"] != hashlib.sha256(
                canonical_json_bytes(observed_semantic)
            ).hexdigest():
                _fail("normalization observed denominator digest mismatch")
            if row["decision_digest"] != _decision_digest(row):
                _fail("normalization denominator decision digest mismatch")
            decision_pairs.append((capability_id, build_variant_id))
            decisions.append(_freeze_json(dict(row)))
        if decision_pairs != sorted(decision_pairs) or len(
            decision_pairs
        ) != len(set(decision_pairs)):
            _fail(
                "normalization denominator decisions must be sorted and unique"
            )
        original = carrier.result
        original_parsed = set(original.capabilities_parsed)
        original_partial = set(original.capabilities_partial)
        original_unavailable = set(original.capabilities_unavailable)
        expected_pairs = sorted(
            (capability_id, build_variant_id)
            for capability_id in (
                original_parsed | original_partial | original_unavailable
            )
            for build_variant_id in contribution.build_variant_ids
        )
        if decision_pairs != expected_pairs:
            _fail("normalization denominator decision accounting is not total")
        expected_parsed = original_parsed - mismatched_capabilities
        expected_partial = original_partial | (
            original_parsed & mismatched_capabilities
        )
        if (
            set(effective.capabilities_parsed) != expected_parsed
            or set(effective.capabilities_partial) != expected_partial
            or set(effective.capabilities_unavailable)
            != original_unavailable
        ):
            _fail(
                "normalization effective result is not a monotonic "
                "original-to-effective degradation"
            )
        binding_fields = (
            "audit_run_id",
            "methodology_authority_digest",
            "registry_digest",
            "context_digest",
            "source_manifest_digest",
            "source_authority_digest",
            "plan_id",
            "provider_id",
            "provider_run_id",
            "raw_output_sha256",
            "raw_output_size",
            "raw_schema_digest",
            "parser_callable",
            "parser_source_digest",
        )
        if any(
            getattr(original, field) != getattr(effective, field)
            for field in binding_fields
        ):
            _fail("normalization effective result changed an immutable binding")
        if contribution.result_digest != effective.result_digest:
            _fail(
                "normalization contribution is not bound to the effective result"
            )
        contribution_bindings = {
            "audit_run_id": contribution.audit_run_id,
            "methodology_authority_digest": (
                contribution.methodology_authority_digest
            ),
            "registry_digest": contribution.registry_digest,
            "context_digest": contribution.context_digest,
            "source_manifest_digest": contribution.source_manifest_digest,
            "source_authority_digest": contribution.source_authority_digest,
            "plan_id": contribution.plan_id,
            "provider_id": contribution.provider_id,
            "provider_run_id": contribution.provider_run_id,
        }
        if any(
            contribution_bindings[field] != getattr(effective, field)
            for field in contribution_bindings
        ):
            _fail(
                "normalization contribution changed an effective-result "
                "plan/provider/source binding"
            )
        accounting = {
            str(row["capability_id"]): str(row["disposition"])
            for row in contribution.capability_accounting
        }
        expected_accounting = {
            **{item: "PARSED" for item in effective.capabilities_parsed},
            **{item: "PARTIAL" for item in effective.capabilities_partial},
            **{
                item: "UNAVAILABLE"
                for item in effective.capabilities_unavailable
            },
        }
        if accounting != expected_accounting:
            _fail(
                "normalization contribution disposition differs from "
                "the effective result"
            )
        effective_diagnostics = {
            str(row["capability_id"]): row
            for row in effective.capability_diagnostics
        }
        for capability_id in original_parsed & mismatched_capabilities:
            decision = next(
                row
                for row in decisions
                if row["capability_id"] == capability_id
            )
            diagnostic = effective_diagnostics.get(capability_id)
            if (
                diagnostic is None
                or diagnostic["disposition"] != "PARTIAL"
                or tuple(diagnostic["diagnostic_codes"])
                != tuple(decision["reason_codes"])
                or tuple(diagnostic["debt_codes"])
                != ("CAPABILITY_PARTIAL",)
            ):
                _fail(
                    "normalization effective diagnostic does not replay "
                    "from its denominator decision"
                )

        debt_proposals = self._validate_proposals(
            self.debt_proposals,
            _DEBT_PROPOSAL_KEYS,
            "debt",
        )
        coverage_proposals = self._validate_proposals(
            self.coverage_proposals,
            _COVERAGE_PROPOSAL_KEYS,
            "coverage",
        )
        degraded_from_parsed = original_parsed & mismatched_capabilities
        if {
            str(row["capability_id"]) for row in debt_proposals
        } != degraded_from_parsed or {
            str(row["capability_id"]) for row in coverage_proposals
        } != degraded_from_parsed:
            _fail(
                "normalization scoped proposal accounting differs from "
                "the degradation decisions"
            )
        decision_by_capability = {
            str(row["capability_id"]): row for row in decisions
        }
        accounting_by_capability = {
            str(row["capability_id"]): row
            for row in contribution.capability_accounting
        }
        for row in debt_proposals:
            capability_id = str(row["capability_id"])
            decision = decision_by_capability[capability_id]
            if (
                row["schema_version"]
                != "plamen.evm_debt_proposal.v1"
                or row["build_variant_id"]
                != decision["build_variant_id"]
                or row["reason"] != "CAPABILITY_PARTIAL"
                or tuple(row["reason_codes"])
                != tuple(decision["reason_codes"])
                or tuple(row["scope_ids"])
                != tuple(
                    sorted(
                        {
                            str(decision["build_variant_id"]),
                            *(
                                str(item)
                                for item in decision[
                                    "expected_source_file_ids"
                                ]
                            ),
                        }
                    )
                )
            ):
                _fail(
                    "normalization debt proposal does not replay from "
                    "its denominator decision"
                )
        for row in coverage_proposals:
            capability_id = str(row["capability_id"])
            decision = decision_by_capability[capability_id]
            expected_sources = tuple(
                str(item)
                for item in decision["expected_source_file_ids"]
            )
            observed_sources = tuple(
                str(item)
                for item in decision[
                    "observed_compiled_source_file_ids"
                ]
            )
            expected_covered = tuple(
                sorted(set(expected_sources) & set(observed_sources))
            )
            expected_status = (
                "PARTIAL"
                if accounting_by_capability[capability_id][
                    "emitted_fact_ids"
                ]
                else "UNKNOWN"
            )
            if (
                row["schema_version"]
                != "plamen.evm_coverage_proposal.v1"
                or row["build_variant_id"]
                != decision["build_variant_id"]
                or row["status"] != expected_status
                or tuple(row["eligible_source_file_ids"])
                != expected_sources
                or tuple(row["covered_source_file_ids"])
                != expected_covered
                or tuple(row["unresolved_debt_codes"])
                != ("CAPABILITY_PARTIAL",)
                or row["denominator_digest"]
                != decision["expected_denominator_digest"]
            ):
                _fail(
                    "normalization coverage proposal does not replay from "
                    "its denominator decision"
                )
        object.__setattr__(self, "original_carrier", carrier)
        object.__setattr__(self, "effective_result", effective)
        object.__setattr__(self, "contribution", contribution)
        object.__setattr__(self, "denominator_decisions", tuple(decisions))
        object.__setattr__(self, "debt_proposals", debt_proposals)
        object.__setattr__(self, "coverage_proposals", coverage_proposals)

    def _validate_proposals(
        self,
        raw_rows: Sequence[Mapping[str, Any]],
        expected_keys: frozenset[str],
        label: str,
    ) -> tuple[Mapping[str, Any], ...]:
        normalized: list[Mapping[str, Any]] = []
        identities: list[tuple[str, str]] = []
        for raw_row in raw_rows:
            row = _mapping(raw_row, f"normalization {label} proposal")
            _exact_keys(row, expected_keys, f"normalization {label} proposal")
            if (
                row["semantic_authority"]
                != _PROPOSAL_AUTHORITY["semantic_authority"]
                or row["terminal_negative_authority"]
                is not _PROPOSAL_AUTHORITY["terminal_negative_authority"]
                or row["publication_authority"]
                != _PROPOSAL_AUTHORITY["publication_authority"]
            ):
                _fail(f"normalization {label} proposal authority mismatch")
            if (
                row["source_input_binding_digest"]
                != self.source_input_binding_digest
            ):
                _fail(
                    f"normalization {label} proposal source binding mismatch"
                )
            if row["proposal_digest"] != _proposal_digest(row):
                _fail(f"normalization {label} proposal digest mismatch")
            identities.append(
                (
                    _text(
                        row["capability_id"],
                        f"normalization {label} proposal capability",
                    ),
                    _text(
                        row["build_variant_id"],
                        f"normalization {label} proposal build",
                    ),
                )
            )
            normalized.append(_freeze_json(dict(row)))
        if identities != sorted(identities) or len(identities) != len(
            set(identities)
        ):
            _fail(
                f"normalization {label} proposals must be sorted and unique"
            )
        return tuple(normalized)

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _NORMALIZATION_OUTCOME_SCHEMA,
            "original_carrier": self.original_carrier.to_dict(),
            "source_input_binding_digest": self.source_input_binding_digest,
            "denominator_decisions": [
                _thaw_json(row) for row in self.denominator_decisions
            ],
            "effective_result": self.effective_result.to_dict(),
            "contribution": self.contribution.to_dict(),
            "debt_proposals": [
                _thaw_json(row) for row in self.debt_proposals
            ],
            "coverage_proposals": [
                _thaw_json(row) for row in self.coverage_proposals
            ],
            "authority": dict(_OUTCOME_AUTHORITY),
            "completion_authority": "PROVISIONAL_NO_PUBLICATION_AUTHORITY",
        }

    @property
    def outcome_digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self._unsigned_dict())
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "outcome_digest": self.outcome_digest}

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvmNormalizationOutcome":
        _exact_keys(value, _OUTCOME_KEYS, "EVM normalization outcome")
        if value["schema_version"] != _NORMALIZATION_OUTCOME_SCHEMA:
            _fail("EVM normalization outcome schema version drift")
        if value["authority"] != _OUTCOME_AUTHORITY:
            _fail("EVM normalization outcome authority mismatch")
        if (
            value["completion_authority"]
            != "PROVISIONAL_NO_PUBLICATION_AUTHORITY"
        ):
            _fail("EVM normalization outcome mints completion authority")
        outcome = cls(
            original_carrier=ParsedProviderOutput.from_dict(
                value["original_carrier"]
            ),
            source_input_binding_digest=value[
                "source_input_binding_digest"
            ],
            denominator_decisions=tuple(value["denominator_decisions"]),
            effective_result=ProviderResult.from_dict(
                value["effective_result"]
            ),
            contribution=FactContribution.from_dict(value["contribution"]),
            debt_proposals=tuple(value["debt_proposals"]),
            coverage_proposals=tuple(value["coverage_proposals"]),
        )
        if value["outcome_digest"] != outcome.outcome_digest:
            _fail("EVM normalization outcome digest mismatch")
        return outcome

    @classmethod
    def from_bytes(cls, raw: bytes) -> "EvmNormalizationOutcome":
        if type(raw) is not bytes:
            _fail("EVM normalization outcome bytes must be exact bytes")
        try:
            value = strict_json_loads(
                raw,
                require_final_lf=False,
                require_canonical=True,
            )
        except ProgramFactsTypeError as exc:
            _fail("EVM normalization outcome bytes are invalid", exc)
        if not isinstance(value, Mapping):
            _fail("EVM normalization outcome bytes must encode an object")
        return cls.from_dict(value)


def _fail(message: str, exc: BaseException | None = None) -> None:
    if exc is None:
        raise EvmProgramFactsProviderError(message)
    raise EvmProgramFactsProviderError(message) from exc


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{label} must be an object")
    return value


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        _fail(f"{label} must be an array")
    return value


def _exact_keys(
    value: Mapping[str, Any],
    expected: frozenset[str],
    label: str,
) -> None:
    actual = frozenset(value)
    if actual != expected:
        unknown = sorted(actual - expected)
        missing = sorted(expected - actual)
        _fail(f"{label} has unknown or missing fields: {unknown or missing}")


def _text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        _fail(f"{label} must be exact text")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{label} must be a nonnegative integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be a boolean")
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                str(key): _freeze_json(item)
                for key, item in sorted(value.items())
            }
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


def _enum(value: Any, allowed: frozenset[str], label: str) -> str:
    text = _text(value, label)
    if text not in allowed:
        _fail(f"{label} is outside its closed enum")
    return text


def _string_list(
    value: Any,
    label: str,
    *,
    allow_empty: bool = True,
    sorted_required: bool = False,
) -> tuple[str, ...]:
    values = tuple(_text(item, label) for item in _sequence(value, label))
    if not values and not allow_empty:
        _fail(f"{label} must not be empty")
    if len(values) != len(set(values)):
        _fail(f"{label} contains duplicate values")
    if sorted_required and values != tuple(sorted(values)):
        _fail(f"{label} must be sorted")
    return values


def _local_id(value: Any, label: str) -> str:
    text = _text(value, label)
    if _LOCAL_ID_RE.fullmatch(text) is None:
        _fail(f"{label} is not a canonical provider-local ID")
    return text


def _hex64(value: Any, label: str, *, allow_empty: bool = False) -> str:
    text = _text(value, label, allow_empty=allow_empty)
    if text == "" and allow_empty:
        return text
    if _HEX64_RE.fullmatch(text) is None:
        _fail(f"{label} must be lowercase 64-hex")
    return text


def _walk_limits(root: Any, limits: EvmProviderLimits) -> None:
    stack: list[tuple[Any, int]] = [(root, 1)]
    records = 0
    while stack:
        value, depth = stack.pop()
        if depth > limits.max_nesting:
            _fail("raw provider result exceeds the nesting depth limit")
        if isinstance(value, str):
            if len(value.encode("utf-8")) > limits.max_string_bytes:
                _fail("raw provider string exceeds the byte limit")
        elif isinstance(value, Mapping):
            records += 1
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray, memoryview)
        ):
            records += len(value)
            stack.extend((item, depth + 1) for item in value)
        if records > limits.max_records:
            _fail("raw provider result exceeds the record limit")


def _tool_digest(plan: ProviderPlan) -> str:
    identity = plan.tool_identity
    return str(identity["executable_sha256"] or identity["module_sha256"])


def _validate_tool(row: Mapping[str, Any], plan: ProviderPlan) -> None:
    _exact_keys(row, _TOOL_KEYS, "raw tool provenance")
    exact = {
        "name": plan.tool_identity["name"],
        "executable_or_module_digest": _tool_digest(plan),
        "distribution_name": plan.distribution["name"],
        "distribution_version": plan.distribution["version"],
        "distribution_checksum": (
            plan.distribution["checksum"]
            or plan.distribution["module_source_digest"]
        ),
        "version_output": plan.version_output,
        "parser_source_digest": plan.raw_binding["parser_source_digest"],
        "raw_schema_digest": plan.raw_binding["raw_schema_digest"],
    }
    for key, expected in exact.items():
        if row[key] != expected:
            _fail(f"raw tool provenance {key} drift")
    observed_toolchains = _sequence(row["toolchains"], "raw toolchains")
    normalized: list[dict[str, str]] = []
    for item in observed_toolchains:
        item = _mapping(item, "raw toolchain")
        _exact_keys(item, _TOOLCHAIN_KEYS, "raw toolchain")
        normalized.append(
            {
                "name": _text(item["name"], "raw toolchain name"),
                "version": _text(item["version"], "raw toolchain version"),
                "identity_digest": _hex64(
                    item["identity_digest"],
                    "raw toolchain identity",
                ),
            }
        )
    if normalized != [item.to_dict() for item in plan.toolchains]:
        _fail("raw toolchain provenance differs from the plan")


def _validate_source_ref_shape(value: Any, label: str) -> Mapping[str, Any]:
    row = _mapping(value, label)
    _exact_keys(row, _SOURCE_KEYS, label)
    _text(row["source_file_id"], f"{label} source_file_id")
    try:
        validate_portable_path(_text(row["path"], f"{label} path"))
    except ProgramFactsTypeError as exc:
        _fail(f"{label} path is not portable", exc)
    _integer(row["start_byte"], f"{label} start_byte")
    _integer(row["end_byte"], f"{label} end_byte")
    return row


def _validate_relation_semantics(
    *,
    facts: Sequence[Mapping[str, Any]],
    node_kinds: Mapping[str, str],
    occurrence_kinds: Mapping[str, str],
    occurrence_enclosing: Mapping[str, str],
) -> None:
    """Validate the closed EVM relation/type matrix across raw fields."""

    if any(
        local_id not in node_kinds
        for local_id in occurrence_enclosing.values()
    ):
        _fail(
            "relation semantic validation found a dangling occurrence "
            "enclosing node"
        )
    block_parent: dict[str, str] = {}
    for row in facts:
        if (
            row["relation_kind"] in {"CONTAINS", "DECLARES"}
            and node_kinds.get(str(row["subject_local_id"]))
            in _FUNCTION_KINDS
            and node_kinds.get(str(row["object_local_id"]))
            == "BASIC_BLOCK"
        ):
            block_id = str(row["object_local_id"])
            parent_id = str(row["subject_local_id"])
            previous = block_parent.setdefault(block_id, parent_id)
            if previous != parent_id:
                _fail(
                    "relation semantic contradiction: basic block has "
                    "multiple enclosing functions"
                )

    def function_scope(local_id: str) -> str:
        kind = node_kinds.get(local_id, "")
        if kind in _FUNCTION_KINDS:
            return local_id
        if kind == "BASIC_BLOCK":
            return block_parent.get(local_id, "")
        return ""

    for row in facts:
        capability_id = str(row["capability_id"])
        relation_kind = str(row["relation_kind"])
        rule = _RELATION_SEMANTICS.get(relation_kind)
        if rule is None:
            _fail(
                "relation semantic table has no EVM authority for "
                f"{relation_kind}"
            )
        if capability_id != rule.capability_id:
            _fail("relation semantic capability/relation mismatch")
        subject_local_id = str(row["subject_local_id"])
        object_local_id = str(row["object_local_id"])
        subject_kind = node_kinds.get(subject_local_id)
        object_kind = node_kinds.get(object_local_id)
        if subject_kind is None or object_kind is None:
            _fail("relation semantic validation found a dangling node")
        if (
            subject_kind not in rule.subject_kinds
            or object_kind not in rule.object_kinds
        ):
            _fail(
                "relation semantic endpoint node kinds are contradictory"
            )
        if (
            relation_kind
            in {"CONTAINS", "DECLARES", "INHERITS_OR_IMPLEMENTS"}
            and subject_local_id == object_local_id
        ):
            _fail("relation semantic structure relation cannot be reflexive")
        occurrence_ids = tuple(
            str(item) for item in row["occurrence_local_ids"]
        )
        if len(occurrence_ids) != len(set(occurrence_ids)):
            _fail("relation semantic occurrence list contains duplicates")
        if len(occurrence_ids) < rule.minimum_occurrences:
            _fail("relation semantic occurrence denominator is incomplete")
        if any(
            occurrence_kinds.get(item) not in rule.occurrence_kinds
            for item in occurrence_ids
        ):
            _fail("relation semantic occurrence kind is contradictory")
        if str(row["provenance_origin"]) not in rule.provenance_origins:
            _fail("relation semantic provenance is contradictory")
        if (
            str(row["precision"]),
            str(row["structural_confidence"]),
        ) not in rule.precision_confidence:
            _fail(
                "relation semantic precision/confidence pair is contradictory"
            )
        context = row["context"]
        if str(context["call_dispatch"]) not in rule.call_dispatch:
            _fail("relation semantic call dispatch is contradictory")
        algorithm = str(context["analysis_algorithm"])
        if (
            rule.algorithm_policy == "REQUIRED" and not algorithm
        ) or (
            rule.algorithm_policy == "FORBIDDEN" and algorithm
        ):
            _fail("relation semantic analysis-algorithm binding is invalid")
        root_set_digest = str(context["root_set_digest"])
        if (
            rule.root_set_policy == "REQUIRED" and not root_set_digest
        ) or (
            rule.root_set_policy == "FORBIDDEN" and root_set_digest
        ):
            _fail("relation semantic root-set binding is invalid")
        subject_scope = function_scope(subject_local_id)
        if relation_kind.startswith("EXACT_CFG_"):
            object_scope = function_scope(object_local_id)
            if (
                not subject_scope
                or not object_scope
                or subject_scope != object_scope
            ):
                _fail(
                    "relation semantic CFG endpoints lack one exact "
                    "function scope"
                )
        if subject_scope and any(
            occurrence_enclosing.get(item) != subject_scope
            for item in occurrence_ids
        ):
            _fail(
                "relation semantic occurrence is outside the subject "
                "control-flow scope"
            )
        dominating = tuple(
            str(item) for item in context["dominating_predicates"]
        )
        if dominating and not rule.dominating_predicates_allowed:
            _fail(
                "relation semantic dominating predicates are not permitted"
            )
        if dominating and str(row["provenance_origin"]) not in {
            "COMPILER_IR",
            "SSA",
        }:
            _fail(
                "relation semantic dominating predicates require "
                "compiler-IR/SSA provenance"
            )
        if len(dominating) != len(set(dominating)):
            _fail(
                "relation semantic dominating predicate list has duplicates"
            )
        for local_id in dominating:
            if occurrence_kinds.get(local_id) != "BRANCH_PREDICATE":
                _fail(
                    "relation semantic dominating predicate is not a "
                    "branch-predicate occurrence"
                )
            if (
                not subject_scope
                or occurrence_enclosing.get(local_id) != subject_scope
            ):
                _fail(
                    "relation semantic dominating predicate is outside "
                    "the fact control-flow scope"
                )


def _validate_raw_shape(
    value: Any,
    plan: ProviderPlan,
    limits: EvmProviderLimits,
) -> Mapping[str, Any]:
    root = _mapping(value, "raw EVM provider result")
    _exact_keys(root, _TOP_KEYS, "raw EVM provider result")
    _walk_limits(root, limits)
    if root["schema_version"] != EVM_RAW_SCHEMA_VERSION:
        _fail("raw EVM provider schema version drift")
    if root["plan_id"] != plan.plan_id:
        _fail("raw EVM provider plan binding mismatch")
    if root["provider_run_id"] != plan.provider_run_id:
        _fail("raw EVM provider run binding mismatch")
    if root["source_manifest_digest"] != plan.source_manifest_digest:
        _fail("raw EVM provider source-manifest binding mismatch")
    if root["build_variant_id"] not in set(plan.build_variant_ids):
        _fail("raw EVM provider build variant is outside the plan")
    _validate_tool(_mapping(root["tool"], "raw tool provenance"), plan)

    compiled_ids = _string_list(
        root["compiled_source_file_ids"],
        "compiled source IDs",
        sorted_required=True,
    )
    if any(re.fullmatch(r"^PFS-[0-9a-f]{24}$", value) is None for value in compiled_ids):
        _fail("compiled source ID is not typed")

    requested = {item.capability_id for item in plan.capability_requests}
    disposed: dict[str, str] = {}
    for raw_disposition in _sequence(
        root["capability_dispositions"],
        "capability dispositions",
    ):
        row = _mapping(raw_disposition, "capability disposition")
        _exact_keys(row, _DISPOSITION_KEYS, "capability disposition")
        capability_id = _text(row["capability_id"], "capability ID")
        if capability_id in disposed:
            _fail("capability dispositions contain duplicate IDs")
        if capability_id not in requested:
            _fail("capability disposition is outside the request")
        disposition = _enum(
            row["disposition"],
            frozenset({"PARSED", "PARTIAL", "UNAVAILABLE"}),
            "capability disposition",
        )
        diagnostics = _string_list(
            row["diagnostic_codes"],
            "capability diagnostic codes",
        )
        debts = _string_list(row["debt_codes"], "capability debt codes")
        if any(_DEBT_CODE_RE.fullmatch(code) is None for code in diagnostics + debts):
            _fail("capability diagnostic/debt code is not canonical")
        if disposition == "PARSED" and (diagnostics or debts):
            _fail("parsed capability cannot hide diagnostic debt")
        if disposition != "PARSED" and (not diagnostics or not debts):
            _fail("partial/unavailable capability requires diagnostic debt")
        disposed[capability_id] = disposition
    if set(disposed) != requested:
        _fail("capability disposition denominator is not total")

    node_local_ids: set[str] = set()
    node_kinds: dict[str, str] = {}
    for raw_node in _sequence(root["nodes"], "raw nodes"):
        row = _mapping(raw_node, "raw node")
        _exact_keys(row, _NODE_KEYS, "raw node")
        local_id = _local_id(row["local_id"], "raw node local_id")
        if local_id in node_local_ids:
            _fail("raw nodes contain duplicate local IDs")
        node_local_ids.add(local_id)
        kind = _enum(row["kind"], _NODE_KINDS, "raw node kind")
        node_kinds[local_id] = kind
        _text(row["qualified_name"], "raw node qualified_name")
        _text(row["display_name"], "raw node display_name", allow_empty=True)
        _text(
            row["canonical_signature"],
            "raw node canonical_signature",
            allow_empty=True,
        )
        _string_list(row["attributes"], "raw node attributes")
        reason = _text(row["reason"], "raw node reason", allow_empty=True)
        if kind in {"EXTERNAL_SYMBOL", "UNKNOWN_TARGET"}:
            if row["source"] is not None or not reason:
                _fail("external/unknown raw node requires reason and no source")
        else:
            if row["source"] is None or reason:
                _fail("source node requires an exact source and no reason")
            _validate_source_ref_shape(row["source"], "raw node source")

    occurrence_local_ids: set[str] = set()
    occurrence_kinds: dict[str, str] = {}
    occurrence_enclosing: dict[str, str] = {}
    for raw_occurrence in _sequence(root["occurrences"], "raw occurrences"):
        row = _mapping(raw_occurrence, "raw occurrence")
        _exact_keys(row, _OCCURRENCE_KEYS, "raw occurrence")
        local_id = _local_id(row["local_id"], "raw occurrence local_id")
        if local_id in occurrence_local_ids:
            _fail("raw occurrences contain duplicate local IDs")
        occurrence_local_ids.add(local_id)
        occurrence_kinds[local_id] = _enum(
            row["kind"],
            _OCCURRENCE_KINDS,
            "raw occurrence kind",
        )
        enclosing_local_id = _local_id(
            row["enclosing_local_id"],
            "raw occurrence enclosing_local_id",
        )
        occurrence_enclosing[local_id] = enclosing_local_id
        _validate_source_ref_shape(row["source"], "raw occurrence source")
        ir_binding = _mapping(row["ir_binding"], "raw occurrence ir_binding")
        allowed_ir_keys = frozenset(
            {"block_id", "instruction_id", "opcode_kind", "ssa_value_ids"}
        )
        if ir_binding:
            _exact_keys(ir_binding, allowed_ir_keys, "raw occurrence ir_binding")
            _text(
                ir_binding["block_id"],
                "IR block ID",
                allow_empty=True,
            )
            _text(
                ir_binding["instruction_id"],
                "IR instruction ID",
                allow_empty=True,
            )
            _text(
                ir_binding["opcode_kind"],
                "IR opcode kind",
                allow_empty=True,
            )
            _string_list(ir_binding["ssa_value_ids"], "IR SSA value IDs")

    fact_rows: list[Mapping[str, Any]] = []
    for raw_fact in _sequence(root["facts"], "raw facts"):
        row = _mapping(raw_fact, "raw fact")
        fact_rows.append(row)
        _exact_keys(row, _FACT_KEYS, "raw fact")
        capability_id = _text(row["capability_id"], "raw fact capability")
        if capability_id not in requested:
            _fail("raw fact capability is outside the request")
        if disposed[capability_id] == "UNAVAILABLE":
            _fail("unavailable capability cannot emit raw facts")
        _enum(row["relation_kind"], _RELATION_KINDS, "raw fact relation")
        relation_kind = str(row["relation_kind"])
        if relation_kind == "HOST_SEMANTIC_SINK":
            _fail(
                "Stage-2 EVM provider cannot claim host-semantic sink authority"
            )
        _local_id(row["subject_local_id"], "raw fact subject")
        _local_id(row["object_local_id"], "raw fact object")
        tuple(
            _local_id(item, "raw fact occurrence")
            for item in _sequence(
                row["occurrence_local_ids"],
                "raw fact occurrences",
            )
        )
        _enum(row["provenance_origin"], _PROVENANCE, "raw fact provenance")
        _enum(row["precision"], _PRECISION, "raw fact precision")
        _enum(row["coverage_scope"], _COVERAGE_SCOPE, "raw fact coverage")
        _enum(
            row["structural_confidence"],
            _STRUCTURAL_CONFIDENCE,
            "raw fact structural confidence",
        )
        context = _mapping(row["context"], "raw fact context")
        _exact_keys(context, _CONTEXT_KEYS, "raw fact context")
        _enum(
            context["call_dispatch"],
            _CALL_DISPATCH,
            "raw fact call dispatch",
        )
        analysis_algorithm = _text(
            context["analysis_algorithm"],
            "raw fact analysis algorithm",
            allow_empty=True,
        )
        if relation_kind.startswith("MAY_") and not analysis_algorithm:
            _fail("MAY relation requires an explicit analysis algorithm label")
        root_digest = _text(
            context["root_set_digest"],
            "raw fact root-set digest",
            allow_empty=True,
        )
        if root_digest:
            _hex64(root_digest, "raw fact root-set digest")
        tuple(
            _local_id(item, "raw fact dominating predicate")
            for item in _sequence(
                context["dominating_predicates"],
                "raw fact dominating predicates",
            )
        )
        host_semantic_kind = _text(
            context["host_semantic_kind"],
            "raw fact host semantic kind",
            allow_empty=True,
        )
        if host_semantic_kind:
            _fail(
                "Stage-2 EVM provider cannot claim host-semantic authority"
            )
    _validate_relation_semantics(
        facts=fact_rows,
        node_kinds=node_kinds,
        occurrence_kinds=occurrence_kinds,
        occurrence_enclosing=occurrence_enclosing,
    )

    raw_debt_capabilities: set[str] = set()
    for raw_debt in _sequence(root["debts"], "raw debts"):
        row = _mapping(raw_debt, "raw debt")
        _exact_keys(row, _RAW_DEBT_KEYS, "raw debt")
        _enum(row["reason"], _DEBT_REASONS, "raw debt reason")
        capability_id = _text(row["capability_id"], "raw debt capability")
        if capability_id not in requested:
            _fail("raw debt capability is outside the request")
        raw_debt_capabilities.add(capability_id)
        tuple(
            _local_id(item, "raw debt scope")
            for item in _sequence(row["scope_local_ids"], "raw debt scopes")
        )
        _text(row["explanation"], "raw debt explanation")
        evidence_refs = _string_list(
            row["evidence_refs"],
            "raw debt evidence references",
        )
        if any(re.fullmatch(r"^sha256:[0-9a-f]{64}$", ref) is None for ref in evidence_refs):
            _fail("raw debt evidence reference is not a SHA-256 CAS reference")
        _boolean(row["retryable"], "raw debt retryable")
        _boolean(row["blocks_reuse"], "raw debt blocks_reuse")
    degraded = {
        capability_id
        for capability_id, disposition in disposed.items()
        if disposition != "PARSED"
    }
    if raw_debt_capabilities != degraded:
        _fail("raw capability/debt accounting is not total")

    facts_by_capability = Counter(
        str(row["capability_id"]) for row in root["facts"]
    )
    zero_positive_capabilities: set[str] = set()
    for raw_denominator in _sequence(
        root["zero_positive_denominators"],
        "raw zero-positive denominators",
    ):
        row = _mapping(raw_denominator, "raw zero-positive denominator")
        _exact_keys(
            row,
            _ZERO_POSITIVE_KEYS,
            "raw zero-positive denominator",
        )
        capability_id = _text(
            row["capability_id"],
            "zero-positive capability",
        )
        if capability_id in zero_positive_capabilities:
            _fail("zero-positive capability denominator is duplicated")
        if capability_id not in requested:
            _fail("zero-positive capability is outside the request")
        if disposed[capability_id] != "PARSED":
            _fail(
                "zero-positive accounting is only valid for a parsed capability"
            )
        if facts_by_capability[capability_id]:
            _fail(
                "zero-positive capability cannot also emit positive facts"
            )
        _text(
            row["build_variant_id"],
            "zero-positive build denominator",
        )
        _text(
            row["denominator_kind"],
            "zero-positive denominator kind",
        )
        _string_list(
            row["node_local_ids"],
            "zero-positive denominator node IDs",
            sorted_required=True,
        )
        denominator_sources = _string_list(
            row["source_file_ids"],
            "zero-positive denominator source IDs",
            sorted_required=True,
        )
        if any(
            re.fullmatch(r"^PFS-[0-9a-f]{24}$", item) is None
            for item in denominator_sources
        ):
            _fail("zero-positive denominator source ID is not typed")
        zero_positive_capabilities.add(capability_id)
    return root


def plan_evm_slither(
    *,
    registry: LoadedProgramFactsProviderRegistry,
    provider_run_id: str,
    context: ProviderContext,
    observed_identity: ObservedProviderIdentity,
    argv: Sequence[str],
    resources: ProviderResources,
    allowed_license_classifications: Sequence[str],
    source_manifest_authority: Any,
    audit_snapshot_authority: Any = None,
    source_project_root: Any = None,
    source_config: Mapping[str, Any] | None = None,
    expected_source_ledger_binding: Mapping[str, Any] | None = None,
    observed_configuration_inputs: Sequence[Mapping[str, str]] = (),
) -> ProviderPlanDecision:
    """Compile a registry-bound plan; never execute or discover a provider."""

    if context.ecosystem != "evm" or set(context.languages) - {"solidity"}:
        _fail("EVM Slither provider requires an EVM/Solidity context")
    if len(context.build_variant_ids) != 1:
        _fail(
            "EVM Slither provider requires exactly one build variant per plan"
        )
    return compile_provider_plan(
        registry=registry,
        provider_id=EVM_PROVIDER_ID,
        provider_run_id=provider_run_id,
        context=context,
        observed_identity=observed_identity,
        argv=tuple(argv),
        resources=resources,
        allowed_license_classifications=allowed_license_classifications,
        source_manifest_authority=source_manifest_authority,
        audit_snapshot_authority=audit_snapshot_authority,
        source_project_root=source_project_root,
        source_config=source_config,
        expected_source_ledger_binding=expected_source_ledger_binding,
        observed_configuration_inputs=observed_configuration_inputs,
    )


def parse_evm_slither_raw(
    raw: bytes,
    plan: ProviderPlan,
    *,
    limits: EvmProviderLimits | None = None,
) -> ParsedProviderOutput:
    """Parse exact helper JSON into a provisional, raw-byte-bound result."""

    if type(plan) is not ProviderPlan:
        _fail("EVM raw parser requires an issued ProviderPlan")
    limits = _effective_limits(plan, limits)
    if not isinstance(raw, bytes):
        _fail("raw EVM provider output must be bytes")
    if len(raw) > limits.max_raw_bytes:
        _fail("raw EVM provider output exceeds its byte limit")
    try:
        value = strict_json_loads(
            raw,
            require_canonical=False,
            max_bytes=limits.max_raw_bytes,
        )
        root = _validate_raw_shape(value, plan, limits)
    except (ProgramFactsTypeError, RecursionError, TypeError, ValueError) as exc:
        if isinstance(exc, EvmProgramFactsProviderError):
            raise
        _fail(f"raw EVM provider JSON/schema rejected: {exc}", exc)

    parsed: list[str] = []
    partial: list[str] = []
    unavailable: list[str] = []
    diagnostics: list[dict[str, Any]] = []
    for raw_row in root["capability_dispositions"]:
        row = dict(raw_row)
        capability_id = str(row["capability_id"])
        disposition = str(row["disposition"])
        if disposition == "PARSED":
            parsed.append(capability_id)
        elif disposition == "PARTIAL":
            partial.append(capability_id)
            diagnostics.append(
                {
                    "capability_id": capability_id,
                    "disposition": disposition,
                    "diagnostic_codes": sorted(row["diagnostic_codes"]),
                    "debt_codes": sorted(row["debt_codes"]),
                }
            )
        else:
            unavailable.append(capability_id)
            diagnostics.append(
                {
                    "capability_id": capability_id,
                    "disposition": disposition,
                    "diagnostic_codes": sorted(row["diagnostic_codes"]),
                    "debt_codes": sorted(row["debt_codes"]),
                }
            )
    state = (
        "PROVISIONAL_PARSED"
        if not partial and not unavailable
        else "PROVISIONAL_DEGRADED"
    )
    result = ProviderResult(
        audit_run_id=plan.audit_run_id,
        methodology_authority_digest=plan.methodology_authority_digest,
        registry_digest=plan.registry_digest,
        context_digest=plan.context_digest,
        source_manifest_digest=plan.source_manifest_digest,
        source_authority_digest=plan.source_authority_digest,
        plan_id=plan.plan_id,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        result_state=state,
        raw_output_sha256=hashlib.sha256(raw).hexdigest(),
        raw_output_size=len(raw),
        raw_schema_digest=str(plan.raw_binding["raw_schema_digest"]),
        parser_callable=str(plan.raw_binding["parser_callable"]),
        parser_source_digest=str(plan.raw_binding["parser_source_digest"]),
        capabilities_parsed=tuple(sorted(parsed)),
        capabilities_partial=tuple(sorted(partial)),
        capabilities_unavailable=tuple(sorted(unavailable)),
        capability_diagnostics=tuple(
            sorted(diagnostics, key=lambda row: row["capability_id"])
        ),
    )
    return ParsedProviderOutput(
        result=result,
        parsed_payload_schema=EVM_RAW_SCHEMA_VERSION,
        parsed_payload=root,
    )


def _source_rows(
    source_manifest: Mapping[str, Any],
    source_bytes_by_id: Mapping[str, bytes],
    *,
    expected_source_manifest_digest: str,
    source_scope_digest: str,
) -> dict[str, Mapping[str, Any]]:
    expected_keys = frozenset(
        {
            "policy_version",
            "eligible_files",
            "excluded_files",
            "file_count",
            "byte_count",
            "manifest_digest",
        }
    )
    _exact_keys(source_manifest, expected_keys, "source manifest")
    if source_manifest["manifest_digest"] != derive_source_manifest_digest(
        source_manifest
    ):
        _fail("source manifest digest does not replay")
    if source_manifest["manifest_digest"] != expected_source_manifest_digest:
        _fail("source manifest differs from the provider plan")
    rows: dict[str, Mapping[str, Any]] = {}
    paths: set[str] = set()
    casefolds: set[str] = set()
    physical_identities: set[str] = set()
    for raw_row in _sequence(
        source_manifest["eligible_files"],
        "source manifest eligible files",
    ):
        row = _mapping(raw_row, "source manifest source row")
        _exact_keys(row, _SOURCE_FILE_KEYS, "source manifest source row")
        source_id = _text(row.get("source_file_id"), "source_file_id")
        path = _text(row.get("path"), "source path")
        try:
            validate_portable_path(path)
        except ProgramFactsTypeError as exc:
            _fail("source manifest path is not portable", exc)
        if source_id in rows:
            _fail("source manifest contains duplicate source IDs")
        if path in paths or path.casefold() in casefolds:
            _fail("source manifest contains a path/case collision")
        if row["path_casefold_key"] != path.casefold():
            _fail("source manifest path case-fold key mismatch")
        source_sha256 = _hex64(row["source_sha256"], "source SHA-256")
        size_bytes = _integer(row["size_bytes"], "source byte size")
        _text(row["language"], "source language")
        if row["scope_class"] not in {
            "PRODUCTION",
            "EXPLICIT_SCOPE",
            "BOUND_DEPENDENCY",
            "GENERATED_BOUND",
        }:
            _fail("source scope class is outside its closed enum")
        physical = _hex64(
            row["physical_identity_digest"],
            "source physical identity",
            allow_empty=True,
        )
        if physical and physical in physical_identities:
            _fail(
                "source manifest contains a symlink/reparse/hardlink "
                "physical-identity alias"
            )
        expected_source_id = derive_stable_id(
            "PFS",
            {
                "source_scope_digest": source_scope_digest,
                "path": path,
                "source_sha256": source_sha256,
                "scope_class": row["scope_class"],
            },
        )
        if source_id != expected_source_id:
            _fail("source manifest source ID does not replay")
        raw = source_bytes_by_id.get(source_id)
        if not isinstance(raw, bytes):
            _fail("source byte denominator is incomplete")
        if len(raw) != size_bytes or hashlib.sha256(raw).hexdigest() != source_sha256:
            _fail("source bytes differ in size or digest from the manifest")
        rows[source_id] = row
        paths.add(path)
        casefolds.add(path.casefold())
        if physical:
            physical_identities.add(physical)
    excluded_identities: set[str] = set()
    for raw_row in _sequence(
        source_manifest["excluded_files"],
        "source manifest excluded files",
    ):
        row = _mapping(raw_row, "source manifest excluded row")
        _exact_keys(row, _EXCLUDED_FILE_KEYS, "source manifest excluded row")
        identity = _text(row["identity"], "excluded source identity")
        _text(row["reason"], "excluded source reason")
        _hex64(
            row["source_sha256"],
            "excluded source SHA-256",
            allow_empty=True,
        )
        if identity in excluded_identities:
            _fail("source manifest contains duplicate excluded identities")
        excluded_identities.add(identity)
    if set(source_bytes_by_id) != set(rows):
        _fail("source byte denominator differs from the source manifest")
    if source_manifest["file_count"] != len(rows):
        _fail("source manifest file count mismatch")
    if source_manifest["byte_count"] != sum(len(raw) for raw in source_bytes_by_id.values()):
        _fail("source manifest byte count mismatch")
    return rows


def _source_binding(
    source: Mapping[str, Any],
    source_rows: Mapping[str, Mapping[str, Any]],
    source_bytes_by_id: Mapping[str, bytes],
) -> dict[str, Any]:
    source_id = str(source["source_file_id"])
    row = source_rows.get(source_id)
    if row is None:
        _fail("raw source has a dangling source-file reference")
    path = str(source["path"])
    if path != row["path"]:
        _fail("raw source path/case does not match the manifest")
    start = int(source["start_byte"])
    end = int(source["end_byte"])
    raw = source_bytes_by_id[source_id]
    if start > end or end > len(raw):
        _fail("raw source span is outside the bound source bytes")

    def line_column(offset: int) -> tuple[int, int]:
        prefix = raw[:offset]
        return prefix.count(b"\n") + 1, len(prefix.rsplit(b"\n", 1)[-1])

    start_line, start_column = line_column(start)
    end_line, end_column = line_column(end)
    return {
        "source_file_id": source_id,
        "start_byte": start,
        "end_byte": end,
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
        "statement_sha256": hashlib.sha256(raw[start:end]).hexdigest(),
    }


def _normalized_ir_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    if not value:
        return {}
    canonical = canonical_json_bytes(value)
    return {
        "compilation_unit_digest": hashlib.sha256(
            canonical_json_bytes(
                {
                    "block_id": str(value["block_id"]),
                    "ssa_value_ids": sorted(
                        str(item) for item in value["ssa_value_ids"]
                    ),
                }
            )
        ).hexdigest(),
        "block_id": str(value["block_id"]),
        "instruction_id": str(value["instruction_id"]),
        "ir_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _expected_denominator_digest(
    *,
    capability_id: str,
    build_variant_id: str,
    denominator_kind: str,
    source_file_ids: Sequence[str],
    source_input_binding_digest: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "capability_id": capability_id,
                "build_variant_id": build_variant_id,
                "denominator_kind": denominator_kind,
                "source_file_ids": sorted(source_file_ids),
                "source_input_binding_digest": (
                    source_input_binding_digest
                ),
            }
        )
    ).hexdigest()


def _observed_compiled_digest(
    *,
    build_variant_id: str,
    source_file_ids: Sequence[str],
    carrier_digest: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "build_variant_id": build_variant_id,
                "compiled_source_file_ids": sorted(source_file_ids),
                "carrier_digest": carrier_digest,
            }
        )
    ).hexdigest()


def _make_proposal(
    value: Mapping[str, Any],
) -> Mapping[str, Any]:
    row = {**dict(value), **_PROPOSAL_AUTHORITY, "proposal_digest": ""}
    row["proposal_digest"] = _proposal_digest(row)
    return _freeze_json(row)


def _reconcile_denominators(
    *,
    root: Mapping[str, Any],
    carrier: ParsedProviderOutput,
    plan: ProviderPlan,
    source_snapshot: ProviderSourceInputSnapshot,
    source_rows: Mapping[str, Mapping[str, Any]],
) -> tuple[
    tuple[Mapping[str, Any], ...],
    ProviderResult,
    tuple[Mapping[str, Any], ...],
    tuple[Mapping[str, Any], ...],
]:
    """Derive exact eligible sets outside raw and degrade monotonically."""

    variant_id = str(root["build_variant_id"])
    if variant_id not in set(plan.build_variant_ids):
        _fail("denominator reconciliation build variant is outside the plan")
    expected_source_ids = tuple(sorted(source_rows))
    observed_compiled_ids = tuple(
        sorted(str(item) for item in root["compiled_source_file_ids"])
    )
    facts_by_capability = Counter(
        str(row["capability_id"]) for row in root["facts"]
    )
    zero_by_capability = {
        str(row["capability_id"]): row
        for row in root["zero_positive_denominators"]
    }
    original = carrier.result
    dispositions = {
        **{item: "PARSED" for item in original.capabilities_parsed},
        **{item: "PARTIAL" for item in original.capabilities_partial},
        **{item: "UNAVAILABLE" for item in original.capabilities_unavailable},
    }
    decisions: list[Mapping[str, Any]] = []
    mismatch_reasons: dict[str, tuple[str, ...]] = {}
    for capability_id in sorted(dispositions):
        denominator_kind = (
            f"{capability_id}.eligible-source-files.v1"
        )
        reasons: set[str] = set()
        if observed_compiled_ids != expected_source_ids:
            reasons.add("COMPILED_SOURCE_DENOMINATOR_MISMATCH")
        zero = zero_by_capability.get(capability_id)
        requires_zero = (
            dispositions[capability_id] == "PARSED"
            and not facts_by_capability[capability_id]
        )
        if requires_zero:
            if zero is None:
                reasons.add("ZERO_POSITIVE_DENOMINATOR_MISSING")
            else:
                if str(zero["build_variant_id"]) != variant_id:
                    reasons.add("ZERO_POSITIVE_BUILD_VARIANT_MISMATCH")
                if str(zero["denominator_kind"]) != denominator_kind:
                    reasons.add(
                        "ZERO_POSITIVE_DENOMINATOR_KIND_MISMATCH"
                    )
                if tuple(zero["source_file_ids"]) != expected_source_ids:
                    reasons.add(
                        "ZERO_POSITIVE_SOURCE_DENOMINATOR_MISMATCH"
                    )
                if tuple(zero["node_local_ids"]):
                    reasons.add(
                        "ZERO_POSITIVE_NODE_DENOMINATOR_NONEMPTY"
                    )
        zero_sources = (
            tuple(str(item) for item in zero["source_file_ids"])
            if zero is not None
            else ()
        )
        zero_nodes = (
            tuple(str(item) for item in zero["node_local_ids"])
            if zero is not None
            else ()
        )
        row: dict[str, Any] = {
            "capability_id": capability_id,
            "build_variant_id": variant_id,
            "denominator_kind": denominator_kind,
            "expected_source_file_ids": list(expected_source_ids),
            "expected_denominator_digest": _expected_denominator_digest(
                capability_id=capability_id,
                build_variant_id=variant_id,
                denominator_kind=denominator_kind,
                source_file_ids=expected_source_ids,
                source_input_binding_digest=source_snapshot.binding_digest,
            ),
            "observed_compiled_source_file_ids": list(
                observed_compiled_ids
            ),
            "observed_compiled_digest": _observed_compiled_digest(
                build_variant_id=variant_id,
                source_file_ids=observed_compiled_ids,
                carrier_digest=carrier.carrier_digest,
            ),
            "observed_zero_positive": zero is not None,
            "observed_zero_build_variant_id": (
                str(zero["build_variant_id"]) if zero is not None else ""
            ),
            "observed_zero_denominator_kind": (
                str(zero["denominator_kind"]) if zero is not None else ""
            ),
            "observed_zero_node_local_ids": list(zero_nodes),
            "observed_zero_source_file_ids": list(zero_sources),
            "status": "MISMATCH" if reasons else "EXACT",
            "reason_codes": sorted(reasons),
            "decision_digest": "",
        }
        row["decision_digest"] = _decision_digest(row)
        decisions.append(_freeze_json(row))
        if reasons:
            mismatch_reasons[capability_id] = tuple(sorted(reasons))

    newly_degraded = set(original.capabilities_parsed) & set(
        mismatch_reasons
    )
    if not newly_degraded:
        effective = original
    else:
        diagnostics = {
            str(row["capability_id"]): {
                "capability_id": str(row["capability_id"]),
                "disposition": str(row["disposition"]),
                "diagnostic_codes": sorted(
                    str(item) for item in row["diagnostic_codes"]
                ),
                "debt_codes": sorted(
                    str(item) for item in row["debt_codes"]
                ),
            }
            for row in original.capability_diagnostics
        }
        for capability_id in newly_degraded:
            diagnostics[capability_id] = {
                "capability_id": capability_id,
                "disposition": "PARTIAL",
                "diagnostic_codes": list(
                    mismatch_reasons[capability_id]
                ),
                "debt_codes": ["CAPABILITY_PARTIAL"],
            }
        effective = ProviderResult(
            audit_run_id=original.audit_run_id,
            methodology_authority_digest=(
                original.methodology_authority_digest
            ),
            registry_digest=original.registry_digest,
            context_digest=original.context_digest,
            source_manifest_digest=original.source_manifest_digest,
            source_authority_digest=original.source_authority_digest,
            plan_id=original.plan_id,
            provider_id=original.provider_id,
            provider_run_id=original.provider_run_id,
            result_state="PROVISIONAL_DEGRADED",
            raw_output_sha256=original.raw_output_sha256,
            raw_output_size=original.raw_output_size,
            raw_schema_digest=original.raw_schema_digest,
            parser_callable=original.parser_callable,
            parser_source_digest=original.parser_source_digest,
            capabilities_parsed=tuple(
                sorted(set(original.capabilities_parsed) - newly_degraded)
            ),
            capabilities_partial=tuple(
                sorted(set(original.capabilities_partial) | newly_degraded)
            ),
            capabilities_unavailable=original.capabilities_unavailable,
            capability_diagnostics=tuple(
                diagnostics[item] for item in sorted(diagnostics)
            ),
        )

    debt_proposals: list[Mapping[str, Any]] = []
    coverage_proposals: list[Mapping[str, Any]] = []
    observed_covered = sorted(
        set(observed_compiled_ids) & set(expected_source_ids)
    )
    for capability_id in sorted(newly_degraded):
        reasons = list(mismatch_reasons[capability_id])
        debt_proposals.append(
            _make_proposal(
                {
                    "schema_version": (
                        "plamen.evm_debt_proposal.v1"
                    ),
                    "capability_id": capability_id,
                    "build_variant_id": variant_id,
                    "reason": "CAPABILITY_PARTIAL",
                    "reason_codes": reasons,
                    "scope_ids": sorted(
                        {variant_id, *expected_source_ids}
                    ),
                    "source_input_binding_digest": (
                        source_snapshot.binding_digest
                    ),
                }
            )
        )
        coverage_proposals.append(
            _make_proposal(
                {
                    "schema_version": (
                        "plamen.evm_coverage_proposal.v1"
                    ),
                    "capability_id": capability_id,
                    "build_variant_id": variant_id,
                    "status": (
                        "PARTIAL"
                        if facts_by_capability[capability_id]
                        else "UNKNOWN"
                    ),
                    "eligible_source_file_ids": list(
                        expected_source_ids
                    ),
                    "covered_source_file_ids": observed_covered,
                    "unresolved_debt_codes": ["CAPABILITY_PARTIAL"],
                    "denominator_digest": _expected_denominator_digest(
                        capability_id=capability_id,
                        build_variant_id=variant_id,
                        denominator_kind=(
                            f"{capability_id}.eligible-source-files.v1"
                        ),
                        source_file_ids=expected_source_ids,
                        source_input_binding_digest=(
                            source_snapshot.binding_digest
                        ),
                    ),
                    "source_input_binding_digest": (
                        source_snapshot.binding_digest
                    ),
                }
            )
        )
    return (
        tuple(decisions),
        effective,
        tuple(debt_proposals),
        tuple(coverage_proposals),
    )


def normalize_evm_slither(
    parsed_output: ParsedProviderOutput,
    *,
    raw: bytes,
    plan: ProviderPlan,
    registry: LoadedProgramFactsProviderRegistry,
    context: ProviderContext,
    observed_identity: ObservedProviderIdentity,
    source_manifest: Mapping[str, Any],
    source_bytes_by_id: Mapping[str, bytes],
    allowed_license_classifications: Sequence[str],
    source_manifest_authority: Any,
    audit_snapshot_authority: Any = None,
    source_project_root: Any = None,
    source_config: Mapping[str, Any] | None = None,
    expected_source_ledger_binding: Mapping[str, Any] | None = None,
    observed_configuration_inputs: Sequence[Mapping[str, str]] = (),
    limits: EvmProviderLimits | None = None,
) -> EvmNormalizationOutcome:
    """Normalize by reparsing the exact result-bound raw bytes.

    Requiring ``raw`` is intentional: the immutable parsed carrier transports
    normalized material, while exact raw replay prevents a caller from
    substituting a newly self-digested carrier for different helper bytes.
    """

    source_snapshot = snapshot_provider_source_inputs(
        source_bytes_by_id=source_bytes_by_id,
        source_manifest=source_manifest,
        build_inputs={
            "source_config": source_config,
            "expected_source_ledger_binding": (
                expected_source_ledger_binding
            ),
            "observed_configuration_inputs": (
                observed_configuration_inputs
            ),
        },
    )
    source_snapshot = replay_provider_source_input_snapshot(source_snapshot)
    source_manifest = source_snapshot.source_manifest
    source_bytes_by_id = source_snapshot.source_bytes_by_id
    source_config = source_snapshot.build_inputs["source_config"]
    expected_source_ledger_binding = source_snapshot.build_inputs[
        "expected_source_ledger_binding"
    ]
    observed_configuration_inputs = source_snapshot.build_inputs[
        "observed_configuration_inputs"
    ]
    limits = _effective_limits(plan, limits)
    try:
        validated_output = validate_parsed_provider_output(
            parsed_output,
            raw_output=raw,
            plan=plan,
            expected_result=parsed_output.result,
        )
        replayed_output = parse_evm_slither_raw(raw, plan, limits=limits)
        if replayed_output.to_dict() != validated_output.to_dict():
            _fail(
                "parsed provider carrier does not replay from the supplied "
                "raw bytes"
            )
        root = _validate_raw_shape(
            validated_output.parsed_payload,
            plan,
            limits,
        )
        sources = _source_rows(
            source_manifest,
            source_bytes_by_id,
            expected_source_manifest_digest=plan.source_manifest_digest,
            source_scope_digest=plan.source_scope_digest,
        )
        (
            denominator_decisions,
            result,
            debt_proposals,
            coverage_proposals,
        ) = _reconcile_denominators(
            root=root,
            carrier=validated_output,
            plan=plan,
            source_snapshot=source_snapshot,
            source_rows=sources,
        )
    except (ProgramFactsTypeError, TypeError, ValueError) as exc:
        if isinstance(exc, EvmProgramFactsProviderError):
            raise
        _fail(f"EVM normalization input rejected: {exc}", exc)

    variant_id = str(root["build_variant_id"])
    local_to_node: dict[str, str] = {}
    nodes: list[dict[str, Any]] = []
    for raw_node in root["nodes"]:
        kind = str(raw_node["kind"])
        row: dict[str, Any] = {
            "node_id": "PFN-" + "0" * 24,
            "kind": kind,
            "qualified_name": str(raw_node["qualified_name"]),
            "display_name": str(raw_node["display_name"]),
            "build_variant_id": variant_id,
            "signature": {
                "canonical": str(raw_node["canonical_signature"]),
                "language_specific": {},
                "signature_fact_ref": "",
            },
            "attributes": sorted(str(item) for item in raw_node["attributes"]),
        }
        if kind in {"EXTERNAL_SYMBOL", "UNKNOWN_TARGET"}:
            row["reason"] = str(raw_node["reason"])
        else:
            row["source_binding"] = _source_binding(
                raw_node["source"],
                sources,
                source_bytes_by_id,
            )
        row["node_id"] = derive_node_id("evm", row)
        local_id = str(raw_node["local_id"])
        local_to_node[local_id] = str(row["node_id"])
        nodes.append(row)
    if len({row["node_id"] for row in nodes}) != len(nodes):
        _fail("normalized EVM nodes contain a stable-ID collision")
    nodes.sort(key=lambda row: row["node_id"])

    local_to_occurrence: dict[str, str] = {}
    occurrences: list[dict[str, Any]] = []
    for raw_occurrence in root["occurrences"]:
        enclosing = local_to_node.get(str(raw_occurrence["enclosing_local_id"]))
        if enclosing is None:
            _fail("raw occurrence has a dangling enclosing node")
        row = {
            "occurrence_id": "PFO-" + "0" * 24,
            "kind": str(raw_occurrence["kind"]),
            "enclosing_node_id": enclosing,
            "source_binding": _source_binding(
                raw_occurrence["source"],
                sources,
                source_bytes_by_id,
            ),
            "ir_binding": _normalized_ir_binding(raw_occurrence["ir_binding"]),
        }
        row["occurrence_id"] = derive_occurrence_id(row)
        local_id = str(raw_occurrence["local_id"])
        local_to_occurrence[local_id] = str(row["occurrence_id"])
        occurrences.append(row)
    if len({row["occurrence_id"] for row in occurrences}) != len(occurrences):
        _fail("normalized EVM occurrences contain a stable-ID collision")
    occurrences.sort(key=lambda row: row["occurrence_id"])

    facts: list[dict[str, Any]] = []
    for raw_fact in root["facts"]:
        subject_id = local_to_node.get(str(raw_fact["subject_local_id"]))
        object_id = local_to_node.get(str(raw_fact["object_local_id"]))
        if subject_id is None or object_id is None:
            _fail("raw fact has a dangling node reference")
        occurrence_ids: list[str] = []
        for local_id in raw_fact["occurrence_local_ids"]:
            occurrence_id = local_to_occurrence.get(str(local_id))
            if occurrence_id is None:
                _fail("raw fact has a dangling occurrence reference")
            occurrence_ids.append(occurrence_id)
        context_row = dict(raw_fact["context"])
        dominating: list[str] = []
        for local_id in context_row["dominating_predicates"]:
            occurrence_id = local_to_occurrence.get(str(local_id))
            if occurrence_id is None:
                _fail("raw fact has a dangling dominating predicate")
            dominating.append(occurrence_id)
        row = {
            "fact_id": "PFF-" + "0" * 24,
            "relation_kind": str(raw_fact["relation_kind"]),
            "subject_id": subject_id,
            "object_id": object_id,
            "occurrence_ids": sorted(occurrence_ids),
            "build_variant_id": variant_id,
            "provider_run_id": plan.provider_run_id,
            "capability_id": str(raw_fact["capability_id"]),
            "provenance_origin": str(raw_fact["provenance_origin"]),
            "precision": str(raw_fact["precision"]),
            "coverage_scope": str(raw_fact["coverage_scope"]),
            "structural_confidence": str(
                raw_fact["structural_confidence"]
            ),
            "context": {
                "call_dispatch": str(context_row["call_dispatch"]),
                "analysis_algorithm": str(context_row["analysis_algorithm"]),
                "root_set_digest": str(context_row["root_set_digest"]),
                "dominating_predicates": sorted(dominating),
                "host_semantic_kind": str(context_row["host_semantic_kind"]),
            },
            "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
            "attestations": [plan.provider_run_id],
        }
        row["fact_id"] = derive_fact_id(row)
        facts.append(row)
    if len({row["fact_id"] for row in facts}) != len(facts):
        _fail("normalized EVM facts contain a duplicate/stable-ID collision")
    facts.sort(key=lambda row: row["fact_id"])

    node_local_ids = set(local_to_node)
    for raw_debt in root["debts"]:
        if not set(raw_debt["scope_local_ids"]) <= node_local_ids:
            _fail("raw debt has a dangling local scope")

    dispositions = {
        **{item: "PARSED" for item in result.capabilities_parsed},
        **{item: "PARTIAL" for item in result.capabilities_partial},
        **{
            item: "UNAVAILABLE"
            for item in result.capabilities_unavailable
        },
    }
    result_debts = {
        str(row["capability_id"]): sorted(str(code) for code in row["debt_codes"])
        for row in result.capability_diagnostics
    }
    facts_by_capability: dict[str, list[str]] = {
        capability_id: [] for capability_id in dispositions
    }
    for fact in facts:
        facts_by_capability[str(fact["capability_id"])].append(
            str(fact["fact_id"])
        )
    accounting = []
    zero_positive_by_capability = {
        str(row["capability_id"]): row
        for row in root["zero_positive_denominators"]
    }
    denominator_decision_by_capability = {
        str(row["capability_id"]): row
        for row in denominator_decisions
    }
    for capability_id in sorted(dispositions):
        fact_ids = sorted(facts_by_capability[capability_id])
        debt_codes = result_debts.get(capability_id, [])
        accounting_row: dict[str, Any] = {
            "capability_id": capability_id,
            "disposition": dispositions[capability_id],
            "emitted_fact_ids": fact_ids,
            "debt_codes": debt_codes,
        }
        zero_row = zero_positive_by_capability.get(capability_id)
        denominator_decision = denominator_decision_by_capability[
            capability_id
        ]
        if (
            zero_row is not None
            and denominator_decision["status"] == "EXACT"
            and dispositions[capability_id] == "PARSED"
            and not fact_ids
        ):
            accounting_row["zero_positive_accounting"] = (
                ZeroPositiveAccounting(
                    capability_id=capability_id,
                    result_digest=result.result_digest,
                    source_authority_digest=result.source_authority_digest,
                    denominators=(
                        {
                            "build_variant_id": variant_id,
                            "denominator_kind": str(
                                denominator_decision["denominator_kind"]
                            ),
                            "denominator_ids": list(
                                denominator_decision[
                                    "expected_source_file_ids"
                                ]
                            ),
                        },
                    ),
                ).to_dict()
            )
        accounting.append(accounting_row)
    contribution = FactContribution(
        audit_run_id=plan.audit_run_id,
        methodology_authority_digest=plan.methodology_authority_digest,
        registry_digest=plan.registry_digest,
        context_digest=plan.context_digest,
        source_manifest_digest=plan.source_manifest_digest,
        source_authority_digest=plan.source_authority_digest,
        plan_id=plan.plan_id,
        result_digest=result.result_digest,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        build_variant_ids=tuple(sorted(plan.build_variant_ids)),
        capability_ids=tuple(sorted(dispositions)),
        nodes=tuple(nodes),
        occurrences=tuple(occurrences),
        facts=tuple(facts),
        debt_codes=tuple(
            sorted(
                {
                    code
                    for values in result_debts.values()
                    for code in values
                }
            )
        ),
        capability_accounting=tuple(accounting),
    )
    try:
        validated_contribution = validate_fact_contribution(
            contribution,
            plan=plan,
            result=result,
            registry=registry,
            context=context,
            observed_identity=observed_identity,
            raw_output=raw,
            allowed_license_classifications=allowed_license_classifications,
            source_manifest_authority=source_manifest_authority,
            audit_snapshot_authority=audit_snapshot_authority,
            source_project_root=source_project_root,
            source_config=source_config,
            expected_source_ledger_binding=expected_source_ledger_binding,
            observed_configuration_inputs=observed_configuration_inputs,
        )
        outcome = EvmNormalizationOutcome(
            original_carrier=validated_output,
            source_input_binding_digest=source_snapshot.binding_digest,
            denominator_decisions=denominator_decisions,
            effective_result=result,
            contribution=validated_contribution,
            debt_proposals=debt_proposals,
            coverage_proposals=coverage_proposals,
        )
        return validate_evm_normalization_outcome(
            outcome,
            parsed_output=validated_output,
            plan=plan,
            source_snapshot=source_snapshot,
        )
    except (ProgramFactsTypeError, TypeError, ValueError) as exc:
        _fail(f"normalized EVM contribution rejected: {exc}", exc)


def validate_evm_normalization_outcome(
    outcome: EvmNormalizationOutcome | Mapping[str, Any],
    *,
    parsed_output: ParsedProviderOutput,
    plan: ProviderPlan,
    source_snapshot: ProviderSourceInputSnapshot,
) -> EvmNormalizationOutcome:
    """Replay an outcome against the immutable external source denominator."""

    try:
        value = (
            EvmNormalizationOutcome.from_dict(outcome.to_dict())
            if type(outcome) is EvmNormalizationOutcome
            else EvmNormalizationOutcome.from_dict(outcome)
        )
        carrier = (
            ParsedProviderOutput.from_dict(parsed_output.to_dict())
            if type(parsed_output) is ParsedProviderOutput
            else _fail("outcome replay requires an exact parsed carrier")
        )
        snapshot = replay_provider_source_input_snapshot(source_snapshot)
        if (
            value.original_carrier.carrier_digest
            != carrier.carrier_digest
            or value.source_input_binding_digest != snapshot.binding_digest
        ):
            _fail("normalization outcome external binding mismatch")
        sources = _source_rows(
            snapshot.source_manifest,
            snapshot.source_bytes_by_id,
            expected_source_manifest_digest=plan.source_manifest_digest,
            source_scope_digest=plan.source_scope_digest,
        )
        (
            decisions,
            effective,
            debt_proposals,
            coverage_proposals,
        ) = _reconcile_denominators(
            root=carrier.parsed_payload,
            carrier=carrier,
            plan=plan,
            source_snapshot=snapshot,
            source_rows=sources,
        )
        if (
            [_thaw_json(row) for row in value.denominator_decisions]
            != [_thaw_json(row) for row in decisions]
            or value.effective_result.to_dict() != effective.to_dict()
            or [_thaw_json(row) for row in value.debt_proposals]
            != [_thaw_json(row) for row in debt_proposals]
            or [_thaw_json(row) for row in value.coverage_proposals]
            != [_thaw_json(row) for row in coverage_proposals]
        ):
            _fail(
                "normalization outcome does not replay from the authoritative "
                "source denominator"
            )
        return value
    except (ProgramFactsTypeError, TypeError, ValueError) as exc:
        if isinstance(exc, EvmProgramFactsProviderError):
            raise
        _fail(f"EVM normalization outcome rejected: {exc}", exc)


def _authority() -> dict[str, Any]:
    return {
        "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
        "terminal_negative_authority": False,
        "can_suppress": False,
        "can_demote": False,
        "can_refute": False,
        "can_mark_examined": False,
        "can_certify_clean": False,
    }


def _coverage_row(
    capability_id: str,
    variant_id: str,
    source_ids: Sequence[str],
    debt_ids: Sequence[str],
    *,
    status: str,
) -> dict[str, Any]:
    denominator = {
        "eligible_source_file_ids": sorted(source_ids),
        "excluded_source_file_ids": [],
    }
    semantic = {
        "capability_id": capability_id,
        "build_variant_id": variant_id,
        "status": status,
        "eligible_source_file_ids": sorted(source_ids),
        "covered_source_file_ids": [],
        "excluded_source_file_ids": [],
        "unresolved_debt_ids": sorted(debt_ids),
        "denominator_digest": hashlib.sha256(
            canonical_json_bytes(denominator)
        ).hexdigest(),
        "terminal_negative_authority": False,
    }
    return {"coverage_id": derive_stable_id("PFC", semantic), **semantic}


def _debt_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counts = Counter(str(row["reason"]) for row in rows)
    return {
        "by_reason": {reason: counts[reason] for reason in sorted(counts)},
        "affected_capabilities": sorted(
            {
                str(row["capability_id"])
                for row in rows
                if row["capability_id"]
            }
        ),
        "affected_source_file_ids": sorted(
            {
                str(scope_id)
                for row in rows
                for scope_id in row["scope_ids"]
                if str(scope_id).startswith("PFS-")
            }
        ),
        "has_blocking_reuse_debt": any(
            bool(row["blocks_reuse"]) for row in rows
        ),
    }


def emit_evm_unavailable_sidecars(
    *,
    context: ProviderContext,
    source_manifest: Mapping[str, Any],
    source_bytes_by_id: Mapping[str, bytes],
    build_variants: Sequence[Mapping[str, Any]],
    audit_snapshot: Mapping[str, Any],
    phase_io: Mapping[str, Any],
    reason: str,
    explanation: str,
) -> EvmProgramFactsEmission:
    """Emit the mandatory zero-fact bundle when the EVM provider is absent.

    This is a schema-validated staging result only.  It does not write files,
    activate a consumer, or establish installed production authority.
    """

    if context.ecosystem != "evm":
        _fail("unavailable EVM bundle requires an EVM context")
    policy = _UNAVAILABLE_REASON_POLICY.get(reason)
    if policy is None:
        _fail(
            "unavailable EVM bundle reason is outside the closed "
            "unavailable-reason policy"
        )
    _text(explanation, "unavailable EVM explanation")
    source_snapshot = snapshot_provider_source_inputs(
        source_bytes_by_id=source_bytes_by_id,
        source_manifest=source_manifest,
        build_inputs={
            "build_variants": build_variants,
            "audit_snapshot": audit_snapshot,
            "phase_io": phase_io,
        },
    )
    source_snapshot = replay_provider_source_input_snapshot(source_snapshot)
    source_manifest = source_snapshot.source_manifest
    source_bytes_by_id = source_snapshot.source_bytes_by_id
    build_variants = source_snapshot.build_inputs["build_variants"]
    audit_snapshot = source_snapshot.build_inputs["audit_snapshot"]
    phase_io = source_snapshot.build_inputs["phase_io"]
    requested = tuple(
        sorted(item.capability_id for item in context.capability_requests)
    )
    if requested != EVM_CAPABILITY_IDS:
        _fail("unavailable EVM bundle capability denominator is incomplete")
    variants = [dict(row) for row in build_variants]
    variant_ids = tuple(sorted(str(row.get("build_variant_id")) for row in variants))
    if variant_ids != tuple(sorted(context.build_variant_ids)):
        _fail("unavailable EVM bundle build denominator differs from context")
    if source_manifest.get("manifest_digest") != context.source_manifest_digest:
        _fail("unavailable EVM source manifest differs from context")
    if audit_snapshot.get("snapshot_digest") != context.snapshot_digest:
        _fail("unavailable EVM snapshot differs from context")
    if audit_snapshot.get("source_scope_digest") != context.source_scope_digest:
        _fail("unavailable EVM source scope differs from context")
    # ``ProviderContext.methodology_authority_digest`` binds the installed
    # methodology-capture package/registry, while the receipt's
    # ``audit_snapshot.methodology_digest`` binds the snapshot component.
    # They are deliberately distinct digests.  The production compositor
    # replays both parents and rejects substitution; equating them here made
    # every genuine installed-registry context impossible to publish.

    # Validate source identities and bytes before constructing signed artifacts.
    try:
        sources_by_id = _source_rows(
            source_manifest,
            source_bytes_by_id,
            expected_source_manifest_digest=context.source_manifest_digest,
            source_scope_digest=context.source_scope_digest,
        )
    except (ProgramFactsTypeError, TypeError, ValueError) as exc:
        if isinstance(exc, EvmProgramFactsProviderError):
            raise
        _fail(f"unavailable EVM source authority rejected: {exc}", exc)
    source_rows = sorted(
        (dict(row) for row in sources_by_id.values()),
        key=lambda row: row["source_file_id"],
    )
    source_ids = tuple(sorted(sources_by_id))

    debts: list[dict[str, Any]] = []
    debt_by_pair: dict[tuple[str, str], tuple[str, ...]] = {}
    for capability_id in requested:
        for variant_id in variant_ids:
            pair_debt_ids: list[str] = []
            pair_reasons = (
                (reason, "STALE_SNAPSHOT")
                if reason == "SOURCE_CHANGED_DURING_RUN"
                else (reason,)
            )
            for pair_reason in pair_reasons:
                pair_policy = _UNAVAILABLE_REASON_POLICY[pair_reason]
                row: dict[str, Any] = {
                    "debt_id": "PFD-" + "0" * 24,
                    "reason": pair_reason,
                    "scope_ids": sorted({variant_id, *source_ids}),
                    "provider_id": EVM_PROVIDER_ID,
                    "capability_id": capability_id,
                    "build_variant_id": variant_id,
                    "explanation": (
                        explanation
                        if pair_reason == reason
                        else (
                            "Source mutation invalidated the bound audit "
                            "snapshot."
                        )
                    ),
                    "evidence_refs": [],
                    "retryable": pair_policy.retryable,
                    "blocks_reuse": pair_policy.blocks_reuse,
                    "terminal_negative_authority": False,
                }
                row["debt_id"] = derive_debt_id(row)
                debts.append(row)
                pair_debt_ids.append(str(row["debt_id"]))
            debt_by_pair[(capability_id, variant_id)] = tuple(
                sorted(pair_debt_ids)
            )
    for excluded in source_manifest.get("excluded_files", []):
        row = {
            "debt_id": "PFD-" + "0" * 24,
            "reason": "SOURCE_EXCLUDED",
            "scope_ids": [str(excluded["identity"])],
            "provider_id": "",
            "capability_id": "",
            "build_variant_id": "",
            "explanation": str(excluded["reason"]),
            "evidence_refs": (
                ["sha256:" + str(excluded["source_sha256"])]
                if excluded["source_sha256"]
                else []
            ),
            "retryable": False,
            "blocks_reuse": False,
            "terminal_negative_authority": False,
        }
        row["debt_id"] = derive_debt_id(row)
        debts.append(row)
    debts.sort(key=lambda row: row["debt_id"])

    coverage = [
        _coverage_row(
            capability_id,
            variant_id,
            source_ids,
            debt_by_pair[(capability_id, variant_id)],
            status=policy.coverage_status,
        )
        for capability_id in requested
        for variant_id in variant_ids
    ]
    coverage.sort(key=lambda row: row["coverage_id"])
    payload = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts.v1",
            "canonicalization_version": "plamen.canonical_json.v1",
            "authority": _authority(),
            "snapshot_ref": {
                "snapshot_digest": context.snapshot_digest,
                "source_scope_digest": context.source_scope_digest,
                "source_manifest_digest": context.source_manifest_digest,
            },
            "ecosystem": "evm",
            "build_variants": sorted(
                variants, key=lambda row: row["build_variant_id"]
            ),
            "source_files": source_rows,
            "provider_capability_refs": list(requested),
            "nodes": [],
            "occurrences": [],
            "facts": [],
            "coverage": coverage,
        },
        "payload_sha256",
    )
    debt = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": context.snapshot_digest,
            "source_manifest_digest": context.source_manifest_digest,
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": debts,
            "summary": _debt_summary(debts),
        },
        "debt_sha256",
    )
    payload_bytes = canonical_file_bytes(payload)
    debt_bytes = canonical_file_bytes(debt)
    receipt_unsigned = {
        "schema_version": "plamen.mechanical_program_facts_receipt.v1",
        "run_id": context.audit_run_id,
        "status": policy.receipt_status,
        "audit_snapshot": dict(audit_snapshot),
        "source_authority_digest": context.source_authority_digest,
        "source_manifest": dict(source_manifest),
        "build_attempts": [],
        "provider_runs": [],
        "worker_transaction_refs": [],
        "phase_io": dict(phase_io),
        "artifacts": {
            "facts": {
                "path": _PAYLOAD_PATH,
                "document_sha256": payload["payload_sha256"],
                "file_sha256": hashlib.sha256(payload_bytes).hexdigest(),
                "size": len(payload_bytes),
            },
            "debt": {
                "path": _DEBT_PATH,
                "document_sha256": debt["debt_sha256"],
                "file_sha256": hashlib.sha256(debt_bytes).hexdigest(),
                "size": len(debt_bytes),
            },
        },
        "reuse_key": "0" * 64,
    }
    receipt_unsigned["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt_unsigned,
    )
    receipt = signed_payload(receipt_unsigned, "receipt_sha256")
    receipt_bytes = canonical_file_bytes(receipt)
    try:
        bundle = validate_program_facts_bundle_structural_test_only(
            authority_mode="STRUCTURAL_TEST_ONLY",
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=payload_bytes,
            debt_file_bytes=debt_bytes,
            receipt_file_bytes=receipt_bytes,
            source_bytes_by_id=source_bytes_by_id,
            source_authority_digest=context.source_authority_digest,
        )
    except (ProgramFactsTypeError, TypeError, ValueError) as exc:
        _fail(f"unavailable EVM sidecar bundle rejected: {exc}", exc)

    return EvmProgramFactsEmission(
        payload=bundle.payload.value,
        receipt=bundle.receipt.value,
        debt=bundle.debt.value,
        sidecars=MappingProxyType(
            {
                _PAYLOAD_PATH: payload_bytes,
                _RECEIPT_PATH: receipt_bytes,
                _DEBT_PATH: debt_bytes,
            }
        ),
    )


__all__ = [
    "EVM_CAPABILITY_IDS",
    "EVM_PROVIDER_ID",
    "EVM_RAW_SCHEMA_VERSION",
    "EvmNormalizationOutcome",
    "EvmProgramFactsEmission",
    "EvmProgramFactsProviderError",
    "EvmProviderLimits",
    "emit_evm_unavailable_sidecars",
    "normalize_evm_slither",
    "parse_evm_slither_raw",
    "plan_evm_slither",
    "validate_evm_normalization_outcome",
]
