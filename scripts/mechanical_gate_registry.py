"""Strict mechanical-gate registry v2 schema and migration authority.

Stage 1 establishes the canonical legacy inventory without changing production
behavior.  A ``LEGACY_NOT_MIGRATED`` activation is source-bound metadata for an
existing call path, not a literal governance wrapper or runtime capability.
That allowance is legal only for ``LEGACY_ACTIVE_UNGOVERNED`` records while
``migration.new_runtime_transitions_blocked`` is true.  It cannot carry
invented PhaseIO contracts, ownership, review, evidence, or seam ceilings.

The blueprint deliberately left several nested objects prose-specified.  This
slice makes them closed rather than adding an extension bag:

* ``activation_inventory`` binds one manifest, source tree, and generator;
* admission records the class-specific requirement names and one evidence
  receipt;
* review/sunset records one previous state, review authority, expiry, reason,
  and replacement set;
* release evidence is a recall-parity and system-owner approval tuple; and
* Part-0 has explicit empty channels for target names, finding IDs, target
  locations, and motivating answers.

Because JSON floats are forbidden, false-fire rates use integer parts per
million (``maximum_false_fire_rate_ppm``), never a binary float.

Changing any of those shapes is a schema revision, not a permissive parser
change.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from itertools import product
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence
import unicodedata

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError


MAX_REGISTRY_BYTES = 8 * 1024 * 1024
# Keep every semantic integer interoperable with exact JSON-number consumers.
# Python itself supports larger integers, but JavaScript and several registry
# inspection tools do not preserve them exactly.
MAX_SEMANTIC_INTEGER = (1 << 53) - 1
MAX_HUMAN_TEXT_CHARS = 4096
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
CANONICAL_REGISTRY_FILENAME = "mechanical-gate-registry.json"
CANONICAL_SCHEMA_FILENAME = "mechanical-gate-registry.schema.v2.json"
SCHEMA_VERSION = "plamen.mechanical_gate_registry.v2"
SOURCE_TREE_DIGEST_ALGORITHM = "sha256:plamen-source-tree-v1"
DECISION_CODE_DIGEST_ALGORITHM = (
    "sha256:plamen-python-decision-closure-ast-v1"
)
LEGACY_MODULE_CODE_DIGEST_ALGORITHM = (
    "sha256:plamen-python-module-bytes-v1"
)

SEAMS = (
    "STARTUP_RESUME",
    "PRE_DISCOVERY",
    "POST_DISCOVERY",
    "PRE_VERIFY",
    "POST_VERIFY",
    "REPORT_ASSEMBLY",
)
DECISION_CLASSES = (
    "RC_AGENT_MECHANIZABLE",
    "RECALL_GENERATOR",
    "PIPELINE_INTEGRITY",
    "PRECISION_DISCRIMINATOR",
    "TELEMETRY_ONLY",
)
DIRECTIONS = (
    "GENERATE_ADD_ONLY",
    "REOPEN_ADD_ONLY",
    "RECONCILE_LOSSLESS",
    "CAP_DESTRUCTIVE",
    "FLOOR_RECALL_OPEN",
    "FLAG_TELEMETRY",
    "ROUTE_RECALL_OPEN",
    "CONSOLIDATE_LOSSLESS",
    "BLOCK_EXECUTION",
    "EXECUTE_TARGET",
    "VETO_SHIP",
)
LIFECYCLE_STATES = (
    "PROPOSED",
    "FIXTURED",
    "SHADOW",
    "REPLAY",
    "LEGACY_ACTIVE_UNGOVERNED",
    "ACTIVE",
    "EXPIRED_BLOCKED",
    "CONSOLIDATED",
    "SUNSET",
)
RUNTIME_COUNTED_STATES = frozenset(
    {"SHADOW", "REPLAY", "LEGACY_ACTIVE_UNGOVERNED", "ACTIVE"}
)
NON_RUNTIME_STATES = frozenset(
    {"PROPOSED", "FIXTURED", "EXPIRED_BLOCKED", "CONSOLIDATED", "SUNSET"}
)
ACTIVATION_RUNTIME_STATES = (
    "RUNTIME",
    "LEGACY_NOT_MIGRATED",
    "NON_RUNTIME",
)

PHASES = (
    "STARTUP",
    "RECON",
    "BREADTH",
    "INVENTORY",
    "RESCAN",
    "PER_CONTRACT",
    "SEMANTIC_INVARIANTS",
    "DEPTH",
    "CHAIN",
    "VERIFY",
    "REPORT",
)
PIPELINES = ("SC", "L1")
MODES = ("LIGHT", "CORE", "THOROUGH")
ECOSYSTEMS = (
    "EVM",
    "SOLANA",
    "APTOS",
    "SUI",
    "SOROBAN",
    "DAML",
    "L1_GO",
    "L1_RUST",
)
PIPELINE_ECOSYSTEMS = MappingProxyType(
    {
        "SC": frozenset(
            {"EVM", "SOLANA", "APTOS", "SUI", "SOROBAN", "DAML"}
        ),
        "L1": frozenset({"L1_GO", "L1_RUST"}),
    }
)
BACKENDS = ("CLAUDE", "CODEX")

INCLUDED_AUTHORITIES = (
    "CANDIDATE_MEMBERSHIP",
    "OBLIGATION_LIFECYCLE",
    "DISPOSITION_OR_REPORT_TIER",
    "SEVERITY",
    "EVIDENCE_OR_SUCCESSOR_AUTHORITY",
    "TARGET_EXECUTION",
    "VERIFICATION_ROUTING",
    "SHIP_AUTHORITY",
)
EXCLUDED_CONTROL_FAMILIES = (
    "STRUCTURAL_SELF_VALIDATION",
    "TRANSACTION_MECHANICS",
    "PURE_DATA_UTILITIES",
    "UNCONSUMED_TOOL_OUTPUT",
    "MODEL_JUDGMENT",
    "NON_PRODUCTION_CODE",
    "POST_AUDIT_HUMAN_CLASSIFICATION",
)

FAILURE_ACTIONS = (
    "HARD_STOP_BEFORE_SIDE_EFFECT",
    "BLOCK_TARGET_EXECUTION",
    "RETAIN_UPSTREAM_AND_FLAG",
    "GENERATE_ADD_ONLY_WITH_DEBT",
    "SHADOW_ONLY_WITH_DEBT",
    "QUARANTINE_AND_RETRY",
    "UNKNOWN_DEBT_CONTINUE",
    "NOT_APPLICABLE",
)
FAILURE_CONDITIONS = (
    "absent",
    "malformed",
    "stale",
    "split",
    "duplicate",
    "contradictory",
    "provider_failure",
    "timeout",
    "budget_overflow",
    "receipt_failure",
    "input_mutation",
    "partial_resume",
)
BUDGET_MAXIMA = (
    "max_input_bytes",
    "max_input_files",
    "max_raw_rows",
    "max_unique_subjects",
    "max_eligible_subjects",
    "max_retained_or_fired",
    "max_emitted_candidates",
    "max_wall_clock_ms",
    "max_external_processes",
    "max_workers",
    "max_tokens",
)

_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._][a-z0-9]+)+$")
_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_FINDING_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:H|M|L|C|I)-0*[1-9][0-9]*(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_CAMEL_TARGET_RE = re.compile(
    r"\b[A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+\b"
)
_SNAKE_TARGET_RE = re.compile(
    r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b"
)
_TARGET_LOCATION_RE = re.compile(
    r"(?:^|[\s(])(?:contracts?|programs?|sources?|crates?)/"
    r"[^\s)]+\.(?:sol|rs|move|go)(?::[0-9]+)?",
    re.IGNORECASE,
)
_MOTIVATING_ANSWER_RE = re.compile(
    r"\b(?:expected|known|motivating|target-specific)\s+"
    r"(?:vulnerab(?:ility|le)|answer|finding|exploit)\b",
    re.IGNORECASE,
)
_ABSOLUTE_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\[^\\\s]+|/(?:home|Users|private|tmp|var)/)"
)
_WORK_UNIT_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_PRINCIPAL_RE = re.compile(r"^[a-z0-9][a-z0-9._:@/-]{0,191}$")
_ARTIFACT_ROOTS = frozenset({"scratchpad", "project"})
_ARTIFACT_CLASSES = frozenset(
    {"REQUIRED", "OPTIONAL", "CONDITIONAL", "DRIVER_GENERATED"}
)
_WRITERS = frozenset({"MODEL", "DRIVER"})
_WRITE_MODES = frozenset({"CREATE", "REPLACE", "APPEND", "MERGE"})
_FORBIDDEN_ARTIFACT_CHARS = frozenset('*?[\\<>:"|]')
_REPARSE_ATTRIBUTE = 0x400

_TOP_KEYS = frozenset(
    {
        "schema_version",
        "registry_revision",
        "registry_scope",
        "migration_status",
        "migration",
        "activation_inventory",
        "seam_taxonomy",
        "decision_class_taxonomy",
        "direction_taxonomy",
        "seam_budgets",
        "gate_records",
    }
)
_SCOPE_KEYS = frozenset(
    {
        "scope_version",
        "included_authorities",
        "excluded_control_families",
        "production_roots",
        "production_excludes",
        "scope_review_receipt_sha256",
    }
)
_MIGRATION_KEYS = frozenset(
    {
        "source_tree_digest",
        "source_tree_digest_algorithm",
        "baseline_gate_ids",
        "baseline_live_gate_count",
        "baseline_review_status",
        "baseline_reviewer",
        "baseline_reviewed_at",
        "baseline_review_receipt_sha256",
        "new_runtime_transitions_blocked",
    }
)
_ACTIVATION_INVENTORY_KEYS = frozenset(
    {
        "schema_version",
        "manifest_path",
        "manifest_sha256",
        "source_tree_digest_algorithm",
        "source_tree_digest",
        "generator_version",
        "generator_digest",
        "independent_review_receipt_sha256",
    }
)
_GATE_KEYS = frozenset(
    {
        "gate_id",
        "display_name",
        "lifecycle_state",
        "decision_class",
        "admission",
        "owning_seam",
        "execution_order",
        "activations",
        "purpose",
        "authority",
        "input_contracts",
        "output_contracts",
        "failure_contract",
        "runtime_budget",
        "release_evidence",
        "false_fire_budget",
        "overlap_and_consolidation",
        "ownership",
        "review_and_sunset",
        "part0",
    }
)
_ACTIVATION_KEYS = frozenset(
    {
        "activation_id",
        "module",
        "wrapper_symbol",
        "implementation_symbols",
        "hook_id",
        "phases",
        "pipelines",
        "modes",
        "ecosystems",
        "backends",
        "runtime_state",
        "code_digest_algorithm",
        "code_digest",
    }
)
_ADMISSION_KEYS = frozenset(
    {"status", "evidence_requirements", "evidence_receipt_sha256"}
)
_AUTHORITY_KEYS = frozenset(
    {
        "can_add",
        "can_remove",
        "can_lower_severity",
        "can_raise_severity",
        "can_block_execution",
        "can_execute_target",
        "can_clear_debt",
        "can_veto_ship",
        "direction",
        "subject_identity_schema",
        "join_rule",
        "monotonicity_claim",
        "invalid_authority_fallback",
    }
)
_INPUT_KEYS = frozenset(
    {
        "artifact_identity",
        "artifact_root",
        "schema_version",
        "authoritative_producer",
        "role",
        "subject_identity_schema",
        "join_rule",
        "freshness_rule",
        "absent_behavior",
        "malformed_behavior",
    }
)
_OUTPUT_KEYS = frozenset(
    {
        "artifact_identity",
        "artifact_root",
        "schema_version",
        "phase_io_work_unit_id",
        "artifact_class",
        "writer",
        "write_mode",
        "minimum_gate",
        "consumers",
        "condition_id",
        "external_preimage_validator",
        "authority_carried",
    }
)
_RUNTIME_BUDGET_KEYS = frozenset(
    {
        "denominator_must_be_exact",
        "stable_shard_ordering",
        "overflow_action",
        *BUDGET_MAXIMA,
    }
)
_RELEASE_EVIDENCE_KEYS = frozenset(
    {
        "status",
        "replacement_gate_ids",
        "recall_parity_receipt_sha256",
        "system_owner_approval_sha256",
    }
)
_FALSE_FIRE_KEYS = frozenset(
    {
        "status",
        "held_out_corpus_id",
        "held_out_corpus_sha256",
        "evaluator_principal",
        "gate_implementer_principal",
        "evaluator_build_sha256",
        "comparator_sha256",
        "observation_window_id",
        "minimum_adjudicated_denominator",
        "adjudicated_fire_count",
        "true_fire_count",
        "false_fire_count",
        "maximum_false_fire_count",
        "maximum_false_fire_rate_ppm",
        "current_evidence_receipt_sha256",
    }
)
_OVERLAP_KEYS = frozenset(
    {
        "overlapping_gate_ids",
        "shared_contract_ids",
        "unique_authority",
        "consolidation_status",
        "retirement_criteria",
        "recall_parity_receipt_sha256",
    }
)
_OWNERSHIP_KEYS = frozenset(
    {
        "component_owner",
        "system_owner",
        "implementer",
        "independent_reviewer",
        "assignment_status",
    }
)
_REVIEW_KEYS = frozenset(
    {
        "previous_lifecycle_state",
        "transition_review_status",
        "reviewed_at",
        "review_receipt_sha256",
        "expires_at",
        "sunset_reason",
        "superseded_by_gate_ids",
    }
)
_PART0_KEYS = frozenset(
    {
        "status",
        "generic_subject",
        "target_names",
        "finding_ids",
        "target_locations",
        "motivating_answers",
        "review_receipt_sha256",
    }
)
_SEAM_BUDGET_KEYS = frozenset(
    {
        "owning_seam",
        "approval_status",
        "gate_budget_ceiling",
        "approval_revision",
        "approver",
        "baseline_gate_ids",
        "addition_gate_ids",
        "release_gate_ids",
        "active_gate_count",
        "activated_or_shadow_additions",
        "approved_slot_releases",
        "post_change_gate_count",
        "exception",
    }
)
_EXCEPTION_KEYS = frozenset(
    {
        "exception_approver",
        "temporary_ceiling_delta",
        "exception_rationale_code",
        "held_out_evidence_receipt_sha256",
        "review_by",
        "expires_on",
    }
)

_CLASS_ADMISSION_REQUIREMENTS = {
    "RC_AGENT_MECHANIZABLE": frozenset(
        {"M1_RECURRING", "M2_DETERMINISTIC", "M3_GENERIC_PART0", "M4_VERIFY_FILTERED"}
    ),
    "RECALL_GENERATOR": frozenset(
        {
            "M1_RECURRING",
            "M2_DETERMINISTIC",
            "M3_GENERIC_PART0",
            "EXACT_OR_LOWER_BOUND_DENOMINATOR",
            "INDEPENDENT_DOWNSTREAM_VERIFICATION",
            "MEASURED_COST_NOISE",
            "NO_TERMINAL_FINDING_AUTHORITY",
        }
    ),
    "PIPELINE_INTEGRITY": frozenset(
        {
            "DETERMINISTIC_CORRECTNESS_SAFETY",
            "TYPED_INPUT_OUTPUT",
            "FAULT_RESUME_EVIDENCE",
            "RECALL_SAFE_FAILURE",
            "PART0_PASS",
        }
    ),
    "PRECISION_DISCRIMINATOR": frozenset(
        {
            "M2_DETERMINISTIC",
            "M3_GENERIC_PART0",
            "TYPED_DECISION_EVIDENCE",
            "INDEPENDENT_REVIEW",
            "RECALL_SAFE_FALLBACK",
            "NEUTRAL_HELD_OUT_PRECISION_RECALL",
        }
    ),
    "TELEMETRY_ONLY": frozenset(
        {
            "M2_DETERMINISTIC",
            "M3_GENERIC_PART0",
            "EXACT_OR_VISIBLE_LOWER_BOUND",
            "TYPED_DELIVERY",
            "PART0_PASS",
        }
    ),
}

_ALLOWED_TRANSITIONS = frozenset(
    {
        ("PROPOSED", "FIXTURED"),
        ("FIXTURED", "SHADOW"),
        ("FIXTURED", "REPLAY"),
        ("LEGACY_ACTIVE_UNGOVERNED", "SHADOW"),
        ("LEGACY_ACTIVE_UNGOVERNED", "REPLAY"),
        ("SHADOW", "ACTIVE"),
        ("REPLAY", "ACTIVE"),
        ("ACTIVE", "EXPIRED_BLOCKED"),
        ("SHADOW", "EXPIRED_BLOCKED"),
        ("REPLAY", "EXPIRED_BLOCKED"),
        ("ACTIVE", "CONSOLIDATED"),
        ("ACTIVE", "SUNSET"),
        ("SHADOW", "CONSOLIDATED"),
        ("SHADOW", "SUNSET"),
        ("REPLAY", "CONSOLIDATED"),
        ("REPLAY", "SUNSET"),
        ("LEGACY_ACTIVE_UNGOVERNED", "CONSOLIDATED"),
        ("LEGACY_ACTIVE_UNGOVERNED", "SUNSET"),
        ("EXPIRED_BLOCKED", "PROPOSED"),
    }
)


class MechanicalGateRegistryError(ValueError):
    """Registry bytes, schema, or semantic authority are invalid."""


@dataclass(frozen=True, slots=True)
class GateActivation:
    activation_id: str
    module: str
    wrapper_symbol: str
    implementation_symbols: tuple[str, ...]
    hook_id: str
    phases: tuple[str, ...]
    pipelines: tuple[str, ...]
    modes: tuple[str, ...]
    ecosystems: tuple[str, ...]
    backends: tuple[str, ...]
    runtime_state: str
    code_digest_algorithm: str
    code_digest: str


@dataclass(frozen=True, slots=True)
class GateRecord:
    gate_id: str
    display_name: str
    lifecycle_state: str
    decision_class: str
    admission: Mapping[str, Any]
    owning_seam: str
    execution_order: int
    activations: tuple[GateActivation, ...]
    purpose: str
    authority: Mapping[str, Any]
    input_contracts: tuple[Mapping[str, Any], ...]
    output_contracts: tuple[Mapping[str, Any], ...]
    failure_contract: Mapping[str, Any]
    runtime_budget: Mapping[str, Any]
    release_evidence: Mapping[str, Any]
    false_fire_budget: Mapping[str, Any]
    overlap_and_consolidation: Mapping[str, Any]
    ownership: Mapping[str, Any]
    review_and_sunset: Mapping[str, Any]
    part0: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class SeamBudget:
    owning_seam: str
    approval_status: str
    gate_budget_ceiling: int | None
    approval_revision: int | None
    approver: str | None
    baseline_gate_ids: tuple[str, ...]
    addition_gate_ids: tuple[str, ...]
    release_gate_ids: tuple[str, ...]
    active_gate_count: int
    activated_or_shadow_additions: int
    approved_slot_releases: int
    post_change_gate_count: int
    exception: Mapping[str, Any] | None


@dataclass(frozen=True, slots=True)
class MechanicalGateRegistry:
    schema_version: str
    registry_revision: int
    registry_scope: Mapping[str, Any]
    migration_status: str
    migration: Mapping[str, Any]
    activation_inventory: Mapping[str, Any]
    seam_taxonomy: tuple[str, ...]
    decision_class_taxonomy: tuple[str, ...]
    direction_taxonomy: tuple[str, ...]
    seam_budgets: tuple[SeamBudget, ...]
    gate_records: tuple[GateRecord, ...]


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MechanicalGateRegistryError(
                f"duplicate JSON object key: {key!r}"
            )
        result[key] = value
    return result


def _reject_float(_value: str) -> Any:
    raise MechanicalGateRegistryError("JSON floats are forbidden")


def _reject_constant(_value: str) -> Any:
    raise MechanicalGateRegistryError("non-finite JSON numbers are forbidden")


def _has_unicode_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_json_shape_and_unicode(value: Any) -> None:
    """Bound parsed traversal and reject non-scalar Unicode recursively."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise MechanicalGateRegistryError(
                "registry JSON exceeds the node bound"
            )
        if depth > MAX_JSON_DEPTH:
            raise MechanicalGateRegistryError(
                "registry JSON exceeds the nesting-depth bound"
            )
        if isinstance(current, str):
            if _has_unicode_surrogate(current):
                raise MechanicalGateRegistryError(
                    "registry JSON contains a lone Unicode surrogate"
                )
        elif isinstance(current, Mapping):
            for key, nested in current.items():
                stack.append((key, depth + 1))
                stack.append((nested, depth + 1))
        elif isinstance(current, list):
            stack.extend((nested, depth + 1) for nested in current)


def strict_json_loads(source: bytes | str) -> Any:
    """Decode one bounded strict-UTF-8, integer-only JSON value."""

    if isinstance(source, str):
        try:
            raw = source.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise MechanicalGateRegistryError(
                "registry text is not strict UTF-8"
            ) from exc
    elif isinstance(source, bytes):
        raw = source
    else:
        raise MechanicalGateRegistryError(
            "strict_json_loads requires bytes or str"
        )
    if len(raw) > MAX_REGISTRY_BYTES:
        raise MechanicalGateRegistryError("registry exceeds 8 MiB")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise MechanicalGateRegistryError("UTF-8 BOM is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        _validate_json_shape_and_unicode(parsed)
        return parsed
    except MechanicalGateRegistryError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise MechanicalGateRegistryError("registry JSON is invalid") from exc


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MechanicalGateRegistryError(f"{label} must be an object")
    return value


def _closed(
    value: Any,
    keys: frozenset[str],
    label: str,
) -> Mapping[str, Any]:
    row = _mapping(value, label)
    actual = frozenset(row)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        raise MechanicalGateRegistryError(
            f"{label} has a non-closed shape; missing={missing}, unknown={unknown}"
        )
    return row


def _text(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or _has_unicode_surrogate(value)
        or value != value.strip()
        or value != unicodedata.normalize("NFC", value)
        or len(value) > MAX_HUMAN_TEXT_CHARS
    ):
        raise MechanicalGateRegistryError(
            f"{label} must be a bounded, trimmed, NFC-normalized string"
        )
    return value


def _human_text(value: Any, label: str) -> str:
    parsed = _text(value, label)
    assert parsed is not None
    if (
        parsed != parsed.strip()
        or not parsed.strip()
        or parsed != unicodedata.normalize("NFC", parsed)
        or len(parsed) > MAX_HUMAN_TEXT_CHARS
    ):
        raise MechanicalGateRegistryError(
            f"{label} must be trimmed, NFC-normalized human text no longer "
            f"than {MAX_HUMAN_TEXT_CHARS} characters"
        )
    return parsed


def _integer(
    value: Any,
    label: str,
    *,
    nullable: bool = False,
    minimum: int = 0,
    maximum: int = MAX_SEMANTIC_INTEGER,
) -> int | None:
    if value is None and nullable:
        return None
    if type(value) is not int or value < minimum or value > maximum:
        raise MechanicalGateRegistryError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise MechanicalGateRegistryError(f"{label} must be a boolean")
    return value


def _sha(value: Any, label: str, *, nullable: bool = False) -> str | None:
    parsed = _text(value, label, nullable=nullable)
    if parsed is None:
        return None
    if not _SHA_RE.fullmatch(parsed):
        raise MechanicalGateRegistryError(
            f"{label} must be a lowercase SHA-256"
        )
    return parsed


def _identifier(value: Any, label: str) -> str:
    parsed = _text(value, label)
    assert parsed is not None
    if parsed != unicodedata.normalize("NFC", parsed):
        raise MechanicalGateRegistryError(f"{label} must be NFC normalized")
    if not _ID_RE.fullmatch(parsed):
        raise MechanicalGateRegistryError(
            f"{label} is not a stable mechanical-gate identifier"
        )
    return parsed


def _principal(
    value: Any,
    label: str,
    *,
    nullable: bool = False,
) -> str | None:
    parsed = _text(value, label, nullable=nullable)
    if parsed is None:
        return None
    if (
        parsed != unicodedata.normalize("NFC", parsed)
        or parsed != parsed.strip()
        or parsed != parsed.casefold()
        or _PRINCIPAL_RE.fullmatch(parsed) is None
    ):
        raise MechanicalGateRegistryError(
            f"{label} must be one canonical lowercase principal"
        )
    return parsed


def _symbol(value: Any, label: str) -> str:
    parsed = _text(value, label)
    assert parsed is not None
    if not _SYMBOL_RE.fullmatch(parsed):
        raise MechanicalGateRegistryError(f"{label} is not a symbol")
    return parsed


def _artifact_identity(
    value: Any,
    label: str,
) -> tuple[str, str, str]:
    parsed = _text(value, label)
    assert parsed is not None
    if parsed != unicodedata.normalize("NFC", parsed):
        raise MechanicalGateRegistryError(
            f"{label} must be NFC normalized"
        )
    if parsed.count(":") != 1:
        raise MechanicalGateRegistryError(
            f"{label} must be one canonical root:path identity"
        )
    root, path = parsed.split(":", 1)
    if root not in _ARTIFACT_ROOTS:
        raise MechanicalGateRegistryError(
            f"{label} has an unsupported PhaseIO root"
        )
    if (
        not path
        or path != path.strip()
        or any(character in path for character in _FORBIDDEN_ARTIFACT_CHARS)
        or re.match(r"^[A-Za-z]:", path)
        or path.startswith("/")
    ):
        raise MechanicalGateRegistryError(
            f"{label} has a noncanonical PhaseIO path"
        )
    candidate = PurePosixPath(path)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != path
        or "//" in path
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(part.endswith((" ", ".")) for part in candidate.parts)
    ):
        raise MechanicalGateRegistryError(
            f"{label} has a noncanonical PhaseIO path"
        )
    canonical = f"{root}:{path}"
    if canonical != parsed:
        raise MechanicalGateRegistryError(
            f"{label} is not canonical"
        )
    return canonical, root, path


def _work_unit_key(value: Any, label: str) -> str:
    parsed = _text(value, label)
    assert parsed is not None
    parts = parsed.split("/")
    if (
        len(parts) != 6
        or any(
            not _WORK_UNIT_COMPONENT_RE.fullmatch(part)
            for part in parts
        )
    ):
        raise MechanicalGateRegistryError(
            f"{label} must be an exact six-component PhaseIO work-unit key"
        )
    return parsed


def _module_path(value: Any, label: str) -> str:
    parsed = _text(value, label)
    assert parsed is not None
    if (
        parsed != unicodedata.normalize("NFC", parsed)
        or "\\" in parsed
        or ":" in parsed
        or parsed.startswith("/")
        or not parsed.endswith(".py")
    ):
        raise MechanicalGateRegistryError(
            f"{label} must be a canonical relative POSIX Python path"
        )
    pure = PurePosixPath(parsed)
    if (
        pure.as_posix() != parsed
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(part.endswith((" ", ".")) for part in pure.parts)
    ):
        raise MechanicalGateRegistryError(
            f"{label} must be a canonical relative POSIX Python path"
        )
    return parsed


def _string_array(
    value: Any,
    label: str,
    *,
    nonempty: bool = False,
    allowed: Iterable[str] | None = None,
    identifiers: bool = False,
    symbols: bool = False,
    require_sorted: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise MechanicalGateRegistryError(f"{label} must be an array")
    rows: list[str] = []
    for index, item in enumerate(value):
        if identifiers:
            row = _identifier(item, f"{label}[{index}]")
        elif symbols:
            row = _symbol(item, f"{label}[{index}]")
        else:
            parsed = _text(item, f"{label}[{index}]")
            assert parsed is not None
            row = parsed
        rows.append(row)
    if nonempty and not rows:
        raise MechanicalGateRegistryError(f"{label} cannot be empty")
    if len(rows) != len(set(rows)):
        raise MechanicalGateRegistryError(f"{label} contains duplicates")
    folded = [unicodedata.normalize("NFC", row).casefold() for row in rows]
    if len(folded) != len(set(folded)):
        raise MechanicalGateRegistryError(
            f"{label} contains a case-fold collision"
        )
    if require_sorted and rows != sorted(rows, key=lambda item: item.encode("utf-8")):
        raise MechanicalGateRegistryError(
            f"{label} must be sorted by UTF-8 byte order"
        )
    if allowed is not None:
        invalid = set(rows) - set(allowed)
        if invalid:
            raise MechanicalGateRegistryError(
                f"{label} contains values outside its taxonomy: {sorted(invalid)}"
            )
    return tuple(rows)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, MechanicalGateRegistry):
        return {
            "schema_version": value.schema_version,
            "registry_revision": value.registry_revision,
            "registry_scope": _plain(value.registry_scope),
            "migration_status": value.migration_status,
            "migration": _plain(value.migration),
            "activation_inventory": _plain(value.activation_inventory),
            "seam_taxonomy": list(value.seam_taxonomy),
            "decision_class_taxonomy": list(
                value.decision_class_taxonomy
            ),
            "direction_taxonomy": list(value.direction_taxonomy),
            "seam_budgets": [_plain(item) for item in value.seam_budgets],
            "gate_records": [_plain(item) for item in value.gate_records],
        }
    if isinstance(value, GateRecord):
        return {
            field: _plain(getattr(value, field))
            for field in _GATE_KEYS
        }
    if isinstance(value, GateActivation):
        return {
            field: _plain(getattr(value, field))
            for field in _ACTIVATION_KEYS
        }
    if isinstance(value, SeamBudget):
        return {
            field: _plain(getattr(value, field))
            for field in _SEAM_BUDGET_KEYS
        }
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _validate_scope(value: Any) -> Mapping[str, Any]:
    row = _closed(value, _SCOPE_KEYS, "registry_scope")
    if row["scope_version"] != "plamen.mechanical_gate_scope.v1":
        raise MechanicalGateRegistryError(
            "registry_scope.scope_version is invalid"
        )
    if tuple(row["included_authorities"]) != INCLUDED_AUTHORITIES:
        raise MechanicalGateRegistryError(
            "included authority taxonomy is not exact"
        )
    if tuple(row["excluded_control_families"]) != EXCLUDED_CONTROL_FAMILIES:
        raise MechanicalGateRegistryError(
            "excluded control-family taxonomy is not exact"
        )
    roots = _string_array(
        row["production_roots"],
        "registry_scope.production_roots",
        nonempty=True,
    )
    excludes = _string_array(
        row["production_excludes"],
        "registry_scope.production_excludes",
    )
    for label, paths in (("production_roots", roots), ("production_excludes", excludes)):
        for item in paths:
            pure = item.replace("\\", "/")
            if (
                pure.startswith("/")
                or re.match(r"^[A-Za-z]:", pure)
                or ":" in pure
                or ".." in pure.split("/")
            ):
                raise MechanicalGateRegistryError(
                    f"registry_scope.{label} contains a path escape"
                )
    _sha(
        row["scope_review_receipt_sha256"],
        "registry_scope.scope_review_receipt_sha256",
        nullable=True,
    )
    return _freeze(row)


def _validate_migration(value: Any) -> Mapping[str, Any]:
    row = _closed(value, _MIGRATION_KEYS, "migration")
    _sha(row["source_tree_digest"], "migration.source_tree_digest")
    if row["source_tree_digest_algorithm"] != SOURCE_TREE_DIGEST_ALGORITHM:
        raise MechanicalGateRegistryError(
            "migration source-tree digest algorithm is invalid"
        )
    _string_array(
        row["baseline_gate_ids"],
        "migration.baseline_gate_ids",
        identifiers=True,
    )
    _integer(
        row["baseline_live_gate_count"],
        "migration.baseline_live_gate_count",
    )
    if row["baseline_review_status"] not in {
        "UNREVIEWED",
        "UNREVIEWED_DIRTY_FIXTURE",
    }:
        raise MechanicalGateRegistryError(
            "migration.baseline_review_status is invalid"
        )
    _text(
        row["baseline_reviewer"],
        "migration.baseline_reviewer",
        nullable=True,
    )
    reviewed_at = _text(
        row["baseline_reviewed_at"],
        "migration.baseline_reviewed_at",
        nullable=True,
    )
    if reviewed_at is not None:
        _utc_instant(reviewed_at, "migration.baseline_reviewed_at")
    _sha(
        row["baseline_review_receipt_sha256"],
        "migration.baseline_review_receipt_sha256",
        nullable=True,
    )
    _boolean(
        row["new_runtime_transitions_blocked"],
        "migration.new_runtime_transitions_blocked",
    )
    return _freeze(row)


def _validate_activation_inventory(value: Any) -> Mapping[str, Any]:
    row = _closed(
        value, _ACTIVATION_INVENTORY_KEYS, "activation_inventory"
    )
    if (
        row["schema_version"]
        != "plamen.mechanical_gate_activation_inventory.v1"
    ):
        raise MechanicalGateRegistryError(
            "activation_inventory schema is invalid"
        )
    manifest = _text(
        row["manifest_path"], "activation_inventory.manifest_path"
    )
    assert manifest is not None
    normalized = manifest.replace("\\", "/")
    if (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or ":" in normalized
        or ".." in normalized.split("/")
    ):
        raise MechanicalGateRegistryError(
            "activation_inventory.manifest_path escapes the install root"
        )
    _sha(
        row["manifest_sha256"],
        "activation_inventory.manifest_sha256",
        nullable=True,
    )
    if row["source_tree_digest_algorithm"] != SOURCE_TREE_DIGEST_ALGORITHM:
        raise MechanicalGateRegistryError(
            "activation inventory source-tree algorithm is invalid"
        )
    _sha(
        row["source_tree_digest"],
        "activation_inventory.source_tree_digest",
    )
    _text(
        row["generator_version"],
        "activation_inventory.generator_version",
    )
    _sha(
        row["generator_digest"],
        "activation_inventory.generator_digest",
        nullable=True,
    )
    _sha(
        row["independent_review_receipt_sha256"],
        "activation_inventory.independent_review_receipt_sha256",
        nullable=True,
    )
    return _freeze(row)


def _validate_activation(value: Any, label: str) -> GateActivation:
    row = _closed(value, _ACTIVATION_KEYS, label)
    activation_id = _identifier(row["activation_id"], f"{label}.activation_id")
    module = _module_path(row["module"], f"{label}.module")
    wrapper = _symbol(row["wrapper_symbol"], f"{label}.wrapper_symbol")
    implementations = _string_array(
        row["implementation_symbols"],
        f"{label}.implementation_symbols",
        nonempty=True,
        symbols=True,
    )
    hook_id = _identifier(row["hook_id"], f"{label}.hook_id")
    phases = _string_array(
        row["phases"],
        f"{label}.phases",
        nonempty=True,
        allowed=PHASES,
    )
    pipelines = _string_array(
        row["pipelines"],
        f"{label}.pipelines",
        nonempty=True,
        allowed=PIPELINES,
    )
    modes = _string_array(
        row["modes"],
        f"{label}.modes",
        nonempty=True,
        allowed=MODES,
    )
    ecosystems = _string_array(
        row["ecosystems"],
        f"{label}.ecosystems",
        nonempty=True,
        allowed=ECOSYSTEMS,
    )
    if len(pipelines) != 1:
        raise MechanicalGateRegistryError(
            f"{label} selector product must bind exactly one pipeline"
        )
    if not set(ecosystems).issubset(PIPELINE_ECOSYSTEMS[pipelines[0]]):
        raise MechanicalGateRegistryError(
            f"{label} selector product crosses pipeline ecosystem domains"
        )
    backends = _string_array(
        row["backends"],
        f"{label}.backends",
        nonempty=True,
        allowed=BACKENDS,
    )
    runtime_state = row["runtime_state"]
    if runtime_state not in ACTIVATION_RUNTIME_STATES:
        raise MechanicalGateRegistryError(
            f"{label}.runtime_state is invalid"
        )
    allowed_digest_algorithms = {DECISION_CODE_DIGEST_ALGORITHM}
    if runtime_state == "LEGACY_NOT_MIGRATED":
        allowed_digest_algorithms.add(LEGACY_MODULE_CODE_DIGEST_ALGORITHM)
    if row["code_digest_algorithm"] not in allowed_digest_algorithms:
        raise MechanicalGateRegistryError(
            f"{label}.code_digest_algorithm is invalid"
        )
    code_digest = _sha(row["code_digest"], f"{label}.code_digest")
    assert code_digest is not None
    return GateActivation(
        activation_id=activation_id,
        module=module,
        wrapper_symbol=wrapper,
        implementation_symbols=implementations,
        hook_id=hook_id,
        phases=phases,
        pipelines=pipelines,
        modes=modes,
        ecosystems=ecosystems,
        backends=backends,
        runtime_state=runtime_state,
        code_digest_algorithm=row["code_digest_algorithm"],
        code_digest=code_digest,
    )


def _utc_instant(value: Any, label: str) -> datetime:
    parsed = _text(value, label)
    assert parsed is not None
    if not parsed.endswith("Z"):
        raise MechanicalGateRegistryError(
            f"{label} must be a UTC instant ending in Z"
        )
    try:
        result = datetime.fromisoformat(parsed[:-1] + "+00:00")
    except ValueError as exc:
        raise MechanicalGateRegistryError(
            f"{label} is not an ISO-8601 UTC instant"
        ) from exc
    if result.tzinfo is None or result.utcoffset() != timezone.utc.utcoffset(result):
        raise MechanicalGateRegistryError(f"{label} is not UTC")
    return result


def _validate_admission(
    value: Any,
    label: str,
    decision_class: str,
    lifecycle: str,
) -> Mapping[str, Any]:
    row = _closed(value, _ADMISSION_KEYS, label)
    status = row["status"]
    if status not in {
        "LEGACY_UNASSESSED",
        "PROPOSED_UNASSESSED",
        "EVIDENCE_COMPLETE",
    }:
        raise MechanicalGateRegistryError(f"{label}.status is invalid")
    requirements = _string_array(
        row["evidence_requirements"],
        f"{label}.evidence_requirements",
        nonempty=True,
    )
    if set(requirements) != _CLASS_ADMISSION_REQUIREMENTS[decision_class]:
        raise MechanicalGateRegistryError(
            f"{label}.evidence_requirements do not match {decision_class}"
        )
    receipt = _sha(
        row["evidence_receipt_sha256"],
        f"{label}.evidence_receipt_sha256",
        nullable=True,
    )
    if lifecycle == "LEGACY_ACTIVE_UNGOVERNED":
        if status != "LEGACY_UNASSESSED" or receipt is not None:
            raise MechanicalGateRegistryError(
                "legacy gates cannot fabricate admission evidence"
            )
    if status == "EVIDENCE_COMPLETE" and receipt is None:
        raise MechanicalGateRegistryError(
            "completed admission requires an evidence receipt"
        )
    if lifecycle in {"SHADOW", "REPLAY", "ACTIVE"} and status != "EVIDENCE_COMPLETE":
        raise MechanicalGateRegistryError(
            f"{lifecycle} requires completed admission evidence"
        )
    if lifecycle in {"PROPOSED", "FIXTURED"} and status == "LEGACY_UNASSESSED":
        raise MechanicalGateRegistryError(
            f"{lifecycle} cannot claim legacy-unassessed admission"
        )
    return _freeze(row)


def _validate_authority(
    value: Any,
    label: str,
    decision_class: str,
) -> Mapping[str, Any]:
    row = _closed(value, _AUTHORITY_KEYS, label)
    booleans = {
        key: _boolean(row[key], f"{label}.{key}")
        for key in _AUTHORITY_KEYS
        if key.startswith("can_")
    }
    direction = row["direction"]
    if direction not in DIRECTIONS:
        raise MechanicalGateRegistryError(f"{label}.direction is invalid")
    for key in (
        "subject_identity_schema",
        "join_rule",
        "monotonicity_claim",
    ):
        _text(row[key], f"{label}.{key}")
    fallback = row["invalid_authority_fallback"]
    if fallback not in FAILURE_ACTIONS:
        raise MechanicalGateRegistryError(
            f"{label}.invalid_authority_fallback is invalid"
        )

    true_flags = frozenset(
        key for key, enabled in booleans.items() if enabled
    )
    allowed_flags: dict[str, frozenset[frozenset[str]]] = {
        "GENERATE_ADD_ONLY": frozenset(
            {frozenset({"can_add"})}
        ),
        "REOPEN_ADD_ONLY": frozenset(
            {frozenset({"can_add"})}
        ),
        "RECONCILE_LOSSLESS": frozenset(
            {frozenset(), frozenset({"can_add"})}
        ),
        "CAP_DESTRUCTIVE": frozenset(
            {
                frozenset({"can_remove"}),
                frozenset({"can_lower_severity"}),
                frozenset({"can_remove", "can_lower_severity"}),
            }
        ),
        "FLOOR_RECALL_OPEN": frozenset(
            {frozenset({"can_raise_severity"})}
        ),
        "FLAG_TELEMETRY": frozenset({frozenset()}),
        "ROUTE_RECALL_OPEN": frozenset({frozenset()}),
        "CONSOLIDATE_LOSSLESS": frozenset(
            {frozenset({"can_remove"})}
        ),
        "BLOCK_EXECUTION": frozenset(
            {frozenset({"can_block_execution"})}
        ),
        "EXECUTE_TARGET": frozenset(
            {frozenset({"can_execute_target"})}
        ),
        "VETO_SHIP": frozenset(
            {frozenset({"can_veto_ship"})}
        ),
    }
    if true_flags not in allowed_flags[direction]:
        raise MechanicalGateRegistryError(
            f"{label} boolean authority is incompatible with {direction}"
        )
    if decision_class == "RECALL_GENERATOR":
        if direction not in {"GENERATE_ADD_ONLY", "REOPEN_ADD_ONLY"}:
            raise MechanicalGateRegistryError(
                "recall-generator authority is not add/reopen-only"
            )
    elif decision_class == "TELEMETRY_ONLY":
        if direction != "FLAG_TELEMETRY":
            raise MechanicalGateRegistryError(
                "telemetry authority cannot change pipeline state"
            )
    elif decision_class == "PRECISION_DISCRIMINATOR":
        if direction not in {
            "CAP_DESTRUCTIVE",
            "FLOOR_RECALL_OPEN",
            "ROUTE_RECALL_OPEN",
            "CONSOLIDATE_LOSSLESS",
        }:
            raise MechanicalGateRegistryError(
                "precision discriminator has an incompatible direction"
            )
        if fallback not in {
            "RETAIN_UPSTREAM_AND_FLAG",
            "SHADOW_ONLY_WITH_DEBT",
            "UNKNOWN_DEBT_CONTINUE",
        }:
            raise MechanicalGateRegistryError(
                "precision discriminator lacks a recall-safe fallback"
            )
    elif decision_class == "PIPELINE_INTEGRITY":
        if direction not in {
            "RECONCILE_LOSSLESS",
            "ROUTE_RECALL_OPEN",
            "CONSOLIDATE_LOSSLESS",
            "BLOCK_EXECUTION",
            "EXECUTE_TARGET",
            "VETO_SHIP",
        }:
            raise MechanicalGateRegistryError(
                "pipeline-integrity direction is incompatible"
            )
    elif decision_class == "RC_AGENT_MECHANIZABLE":
        if direction not in {
            "GENERATE_ADD_ONLY",
            "REOPEN_ADD_ONLY",
            "CAP_DESTRUCTIVE",
            "FLOOR_RECALL_OPEN",
            "ROUTE_RECALL_OPEN",
        }:
            raise MechanicalGateRegistryError(
                "mechanizable-RC direction is incompatible"
            )
    return _freeze(row)


def _validate_contracts(
    values: Any,
    *,
    output: bool,
    label: str,
    allow_empty_migration_debt: bool = False,
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(values, list):
        raise MechanicalGateRegistryError(f"{label} must be an array")
    if not values:
        if allow_empty_migration_debt:
            return ()
        raise MechanicalGateRegistryError(f"{label} cannot be empty")
    result: list[Mapping[str, Any]] = []
    identities: list[str] = []
    for index, value in enumerate(values):
        item_label = f"{label}[{index}]"
        keys = _OUTPUT_KEYS if output else _INPUT_KEYS
        row = _closed(value, keys, item_label)
        identity, identity_root, _identity_path = _artifact_identity(
            row["artifact_identity"],
            f"{item_label}.artifact_identity",
        )
        identities.append(identity)
        root = _text(row["artifact_root"], f"{item_label}.artifact_root")
        if root != identity_root:
            raise MechanicalGateRegistryError(
                f"{item_label}.artifact_root differs from artifact identity"
            )
        _text(row["schema_version"], f"{item_label}.schema_version")
        if output:
            work_unit = _work_unit_key(
                row["phase_io_work_unit_id"],
                f"{item_label}.phase_io_work_unit_id",
            )
            artifact_class = row["artifact_class"]
            writer = row["writer"]
            write_mode = row["write_mode"]
            if artifact_class not in _ARTIFACT_CLASSES:
                raise MechanicalGateRegistryError(
                    f"{item_label}.artifact_class is invalid"
                )
            if writer not in _WRITERS:
                raise MechanicalGateRegistryError(
                    f"{item_label}.writer is invalid"
                )
            if write_mode not in _WRITE_MODES:
                raise MechanicalGateRegistryError(
                    f"{item_label}.write_mode is invalid"
                )
            if write_mode == "MERGE" and writer != "DRIVER":
                raise MechanicalGateRegistryError(
                    f"{item_label} MERGE output is not driver-owned"
                )
            if artifact_class == "DRIVER_GENERATED" and writer != "DRIVER":
                raise MechanicalGateRegistryError(
                    f"{item_label} driver-generated output has a model writer"
                )
            condition = row["condition_id"]
            if not isinstance(condition, str) or "\x00" in condition:
                raise MechanicalGateRegistryError(
                    f"{item_label}.condition_id must be a string"
                )
            if artifact_class == "CONDITIONAL" and not condition:
                raise MechanicalGateRegistryError(
                    f"{item_label} conditional output lacks condition_id"
                )
            if artifact_class != "CONDITIONAL" and condition:
                raise MechanicalGateRegistryError(
                    f"{item_label} nonconditional output has condition_id"
                )
            external = row["external_preimage_validator"]
            if not isinstance(external, str) or "\x00" in external:
                raise MechanicalGateRegistryError(
                    f"{item_label}.external_preimage_validator must be a string"
                )
            if external and (
                writer != "DRIVER" or write_mode != "MERGE"
            ):
                raise MechanicalGateRegistryError(
                    f"{item_label} external validator lacks DRIVER/MERGE authority"
                )
            _text(row["minimum_gate"], f"{item_label}.minimum_gate")
            _string_array(
                row["consumers"],
                f"{item_label}.consumers",
                nonempty=True,
            )
            if row["authority_carried"] not in {
                "COMMON_RECEIPT",
                "GOVERNANCE_DEBT",
                "OVERFLOW_BACKLOG",
                "CANDIDATE",
                "OBLIGATION",
                "DISPOSITION",
                "SEVERITY",
                "EXECUTION_BLOCK",
                "SHIP_VETO",
                "TELEMETRY",
            }:
                raise MechanicalGateRegistryError(
                    f"{item_label}.authority_carried is invalid"
                )
            common_contracts = {
                "COMMON_RECEIPT": (
                    "REQUIRED",
                    "DRIVER",
                    "CREATE",
                    "",
                ),
                "GOVERNANCE_DEBT": (
                    "CONDITIONAL",
                    "DRIVER",
                    "CREATE",
                    "GOVERNANCE_DEBT_PRESENT",
                ),
                "OVERFLOW_BACKLOG": (
                    "CONDITIONAL",
                    "DRIVER",
                    "CREATE",
                    "OVERFLOW_PRESENT",
                ),
            }
            expected_common = common_contracts.get(
                row["authority_carried"]
            )
            if expected_common is not None:
                actual_common = (
                    artifact_class,
                    writer,
                    write_mode,
                    condition,
                )
                if actual_common != expected_common:
                    raise MechanicalGateRegistryError(
                        f"{item_label} common PhaseIO authority is not exact"
                    )
                if external or row["minimum_gate"] != "SCHEMA":
                    raise MechanicalGateRegistryError(
                        f"{item_label} common PhaseIO validation is not exact"
                    )
            if not work_unit:
                raise AssertionError("validated work unit is empty")
        else:
            for key in (
                "authoritative_producer",
                "subject_identity_schema",
                "join_rule",
                "freshness_rule",
            ):
                _text(row[key], f"{item_label}.{key}")
            if row["role"] not in {
                "EXACT",
                "BOUNDED_LOOKUP",
                "OPTIONAL_CAPABILITY",
            }:
                raise MechanicalGateRegistryError(
                    f"{item_label}.role is invalid"
                )
            for key in {"absent_behavior", "malformed_behavior"}:
                if row[key] not in FAILURE_ACTIONS:
                    raise MechanicalGateRegistryError(
                        f"{item_label}.{key} is invalid"
                    )
        result.append(_freeze(row))
    _casefold_unique(identities, label)
    return tuple(result)


def _casefold_unique(values: Sequence[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise MechanicalGateRegistryError(f"{label} contains duplicates")
    folded = [
        unicodedata.normalize("NFC", item).casefold()
        for item in values
    ]
    if len(folded) != len(set(folded)):
        raise MechanicalGateRegistryError(
            f"{label} contains a case-fold collision"
        )


def _validate_failure_contract(
    value: Any, label: str
) -> Mapping[str, Any]:
    row = _closed(value, frozenset(FAILURE_CONDITIONS), label)
    for key, action in row.items():
        if action not in FAILURE_ACTIONS:
            raise MechanicalGateRegistryError(
                f"{label}.{key} has an invalid action"
            )
    return _freeze(row)


def _validate_runtime_budget(
    value: Any, label: str
) -> Mapping[str, Any]:
    row = _closed(value, _RUNTIME_BUDGET_KEYS, label)
    _boolean(
        row["denominator_must_be_exact"],
        f"{label}.denominator_must_be_exact",
    )
    _text(row["stable_shard_ordering"], f"{label}.stable_shard_ordering")
    if row["overflow_action"] not in FAILURE_ACTIONS:
        raise MechanicalGateRegistryError(
            f"{label}.overflow_action is invalid"
        )
    for key in BUDGET_MAXIMA:
        _integer(row[key], f"{label}.{key}", nullable=True)
    return _freeze(row)


def _validate_release_evidence(
    value: Any, label: str
) -> Mapping[str, Any]:
    row = _closed(value, _RELEASE_EVIDENCE_KEYS, label)
    if row["status"] not in {
        "UNESTABLISHED",
        "RECALL_PARITY_ESTABLISHED",
        "EXPLICIT_RECALL_TRADEOFF",
    }:
        raise MechanicalGateRegistryError(f"{label}.status is invalid")
    _string_array(
        row["replacement_gate_ids"],
        f"{label}.replacement_gate_ids",
        identifiers=True,
    )
    parity = _sha(
        row["recall_parity_receipt_sha256"],
        f"{label}.recall_parity_receipt_sha256",
        nullable=True,
    )
    owner = _sha(
        row["system_owner_approval_sha256"],
        f"{label}.system_owner_approval_sha256",
        nullable=True,
    )
    if row["status"] != "UNESTABLISHED" and (parity is None or owner is None):
        raise MechanicalGateRegistryError(
            f"{label} established release lacks independent authority"
        )
    return _freeze(row)


def _validate_false_fire(value: Any, label: str) -> Mapping[str, Any]:
    row = _closed(value, _FALSE_FIRE_KEYS, label)
    if row["status"] not in {"UNESTABLISHED", "PASS", "FAIL", "UNKNOWN"}:
        raise MechanicalGateRegistryError(f"{label}.status is invalid")
    for key in ("held_out_corpus_id", "observation_window_id"):
        _text(row[key], f"{label}.{key}", nullable=True)
    for key in ("evaluator_principal", "gate_implementer_principal"):
        _principal(row[key], f"{label}.{key}", nullable=True)
    for key in (
        "held_out_corpus_sha256",
        "evaluator_build_sha256",
        "comparator_sha256",
        "current_evidence_receipt_sha256",
    ):
        _sha(row[key], f"{label}.{key}", nullable=True)
    for key in (
        "minimum_adjudicated_denominator",
        "adjudicated_fire_count",
        "true_fire_count",
        "false_fire_count",
        "maximum_false_fire_count",
        "maximum_false_fire_rate_ppm",
    ):
        parsed = _integer(
            row[key],
            f"{label}.{key}",
            nullable=True,
            maximum=(
                1_000_000
                if key == "maximum_false_fire_rate_ppm"
                else MAX_SEMANTIC_INTEGER
            ),
        )
    evidence_keys = _FALSE_FIRE_KEYS - {"status"}
    if row["status"] == "UNESTABLISHED" and any(
        row[key] is not None for key in evidence_keys
    ):
        raise MechanicalGateRegistryError(
            f"{label} unestablished evidence must be entirely null"
        )
    if row["status"] == "PASS":
        if any(row[key] is None for key in evidence_keys):
            raise MechanicalGateRegistryError(
                "false-fire PASS cannot be self-certified without neutral evidence"
            )
        evaluator = _principal(
            row["evaluator_principal"],
            f"{label}.evaluator_principal",
        )
        implementer = _principal(
            row["gate_implementer_principal"],
            f"{label}.gate_implementer_principal",
        )
        if evaluator == implementer:
            raise MechanicalGateRegistryError(
                "false-fire PASS evaluator must be independent"
            )
        denominator = int(row["adjudicated_fire_count"])
        true_count = int(row["true_fire_count"])
        false_count = int(row["false_fire_count"])
        minimum = int(row["minimum_adjudicated_denominator"])
        if denominator <= 0 or minimum <= 0:
            raise MechanicalGateRegistryError(
                "false-fire PASS requires a nonzero neutral denominator"
            )
        if denominator != true_count + false_count:
            raise MechanicalGateRegistryError(
                "false-fire adjudicated count is not exact"
            )
        if denominator < minimum:
            raise MechanicalGateRegistryError(
                "false-fire evidence is below its minimum denominator"
            )
        if false_count > int(row["maximum_false_fire_count"]):
            raise MechanicalGateRegistryError(
                "false-fire count exceeds the approved maximum"
            )
        # Compare the exact rational without rounding away a boundary fire.
        if (
            false_count * 1_000_000
            > int(row["maximum_false_fire_rate_ppm"]) * denominator
        ):
            raise MechanicalGateRegistryError(
                "false-fire rate exceeds the approved maximum"
            )
    return _freeze(row)


def _validate_overlap(value: Any, label: str) -> Mapping[str, Any]:
    row = _closed(value, _OVERLAP_KEYS, label)
    for key in ("overlapping_gate_ids",):
        _string_array(
            row[key], f"{label}.{key}", identifiers=True
        )
    _string_array(
        row["shared_contract_ids"],
        f"{label}.shared_contract_ids",
    )
    for key in (
        "unique_authority",
        "consolidation_status",
        "retirement_criteria",
    ):
        _text(row[key], f"{label}.{key}")
    _sha(
        row["recall_parity_receipt_sha256"],
        f"{label}.recall_parity_receipt_sha256",
        nullable=True,
    )
    return _freeze(row)


def _validate_ownership(
    value: Any, label: str, lifecycle: str
) -> Mapping[str, Any]:
    row = _closed(value, _OWNERSHIP_KEYS, label)
    identities = {
        key: _principal(row[key], f"{label}.{key}", nullable=True)
        for key in (
            "component_owner",
            "system_owner",
            "implementer",
            "independent_reviewer",
        )
    }
    if row["assignment_status"] not in {
        "UNASSIGNED_MIGRATION_DEBT",
        "ASSIGNED",
    }:
        raise MechanicalGateRegistryError(
            f"{label}.assignment_status is invalid"
        )
    if lifecycle in {"SHADOW", "REPLAY", "ACTIVE"}:
        if any(value is None for value in identities.values()):
            raise MechanicalGateRegistryError(
                "new runtime state requires complete ownership"
            )
        if identities["implementer"] == identities["independent_reviewer"]:
            raise MechanicalGateRegistryError(
                "implementer and independent reviewer must differ"
            )
        if row["assignment_status"] != "ASSIGNED":
            raise MechanicalGateRegistryError(
                "new runtime state requires assigned ownership"
            )
    if lifecycle == "LEGACY_ACTIVE_UNGOVERNED":
        if (
            any(value is not None for value in identities.values())
            or row["assignment_status"] != "UNASSIGNED_MIGRATION_DEBT"
        ):
            raise MechanicalGateRegistryError(
                "legacy-unassessed record cannot fabricate ownership"
            )
    return _freeze(row)


def _validate_review(
    value: Any,
    label: str,
    lifecycle: str,
    *,
    migration_blocked: bool,
) -> Mapping[str, Any]:
    row = _closed(value, _REVIEW_KEYS, label)
    previous = row["previous_lifecycle_state"]
    if previous is not None:
        if previous not in LIFECYCLE_STATES:
            raise MechanicalGateRegistryError(
                f"{label}.previous_lifecycle_state is invalid"
            )
        if (previous, lifecycle) not in _ALLOWED_TRANSITIONS:
            raise MechanicalGateRegistryError(
                f"invalid lifecycle transition {previous} -> {lifecycle}"
            )
    if row["transition_review_status"] not in {
        "LEGACY_UNREVIEWED",
        "MIGRATION_TOMBSTONE_UNASSESSED",
        "PENDING",
        "REVIEWED",
    }:
        raise MechanicalGateRegistryError(
            f"{label}.transition_review_status is invalid"
        )
    for key in ("reviewed_at", "expires_at", "sunset_reason"):
        _text(row[key], f"{label}.{key}", nullable=True)
    for key in ("reviewed_at", "expires_at"):
        if row[key] is not None:
            _utc_instant(row[key], f"{label}.{key}")
    _sha(
        row["review_receipt_sha256"],
        f"{label}.review_receipt_sha256",
        nullable=True,
    )
    _string_array(
        row["superseded_by_gate_ids"],
        f"{label}.superseded_by_gate_ids",
        identifiers=True,
    )
    migration_tombstone = (
        lifecycle in {"CONSOLIDATED", "SUNSET"}
        and migration_blocked
        and row["transition_review_status"]
        == "MIGRATION_TOMBSTONE_UNASSESSED"
    )
    independently_reviewed_states = {
        "SHADOW",
        "REPLAY",
        "ACTIVE",
        "EXPIRED_BLOCKED",
        "CONSOLIDATED",
        "SUNSET",
    }
    if lifecycle in independently_reviewed_states and not migration_tombstone:
        if previous is None:
            raise MechanicalGateRegistryError(
                "lifecycle transition requires an exact previous state"
            )
        if (
            row["transition_review_status"] != "REVIEWED"
            or row["reviewed_at"] is None
            or row["review_receipt_sha256"] is None
        ):
            raise MechanicalGateRegistryError(
                "lifecycle transition lacks independent review"
            )
    if migration_tombstone:
        if (
            previous is not None
            or row["reviewed_at"] is not None
            or row["review_receipt_sha256"] is not None
            or row["expires_at"] is not None
            or row["superseded_by_gate_ids"]
        ):
            raise MechanicalGateRegistryError(
                "migration tombstone cannot fabricate transition authority"
            )
    if lifecycle == "LEGACY_ACTIVE_UNGOVERNED":
        if (
            previous is not None
            or row["transition_review_status"] != "LEGACY_UNREVIEWED"
            or row["reviewed_at"] is not None
            or row["review_receipt_sha256"] is not None
            or row["expires_at"] is not None
            or row["sunset_reason"] is not None
            or row["superseded_by_gate_ids"]
        ):
            raise MechanicalGateRegistryError(
                "legacy-unassessed record cannot fabricate transition review"
            )
    if lifecycle == "EXPIRED_BLOCKED" and row["expires_at"] is None:
        raise MechanicalGateRegistryError(
            "expired state requires an expiry instant"
        )
    if lifecycle in {"CONSOLIDATED", "SUNSET"} and row["sunset_reason"] is None:
        raise MechanicalGateRegistryError(
            "non-runtime tombstone requires a reason"
        )
    return _freeze(row)


def _validate_part0(value: Any, label: str) -> Mapping[str, Any]:
    row = _closed(value, _PART0_KEYS, label)
    if row["status"] != "PASS":
        raise MechanicalGateRegistryError(f"{label}.status must be PASS")
    _human_text(row["generic_subject"], f"{label}.generic_subject")
    for key in (
        "target_names",
        "finding_ids",
        "target_locations",
        "motivating_answers",
    ):
        values = _string_array(
            row[key], f"{label}.{key}", require_sorted=True
        )
        if values:
            raise MechanicalGateRegistryError(
                f"{label}.{key} must remain empty under Part 0"
            )
    _sha(
        row["review_receipt_sha256"],
        f"{label}.review_receipt_sha256",
        nullable=True,
    )
    return _freeze(row)


def _validate_gate(
    value: Any,
    index: int,
    *,
    migration_blocked: bool,
) -> GateRecord:
    label = f"gate_records[{index}]"
    row = _closed(value, _GATE_KEYS, label)
    gate_id = _identifier(row["gate_id"], f"{label}.gate_id")
    display_name = _human_text(
        row["display_name"], f"{label}.display_name"
    )
    lifecycle = row["lifecycle_state"]
    if lifecycle not in LIFECYCLE_STATES:
        raise MechanicalGateRegistryError(
            f"{label}.lifecycle_state is invalid"
        )
    decision_class = row["decision_class"]
    if decision_class not in DECISION_CLASSES:
        raise MechanicalGateRegistryError(
            f"{label}.decision_class is invalid"
        )
    admission = _validate_admission(
        row["admission"], f"{label}.admission", decision_class, lifecycle
    )
    seam = row["owning_seam"]
    if seam not in SEAMS:
        raise MechanicalGateRegistryError(
            f"{label}.owning_seam is invalid"
        )
    execution_order = _integer(
        row["execution_order"], f"{label}.execution_order"
    )
    assert execution_order is not None
    if not isinstance(row["activations"], list):
        raise MechanicalGateRegistryError(
            f"{label}.activations must be an array"
        )
    activations = tuple(
        _validate_activation(item, f"{label}.activations[{activation_index}]")
        for activation_index, item in enumerate(row["activations"])
    )
    legacy_not_migrated = (
        lifecycle == "LEGACY_ACTIVE_UNGOVERNED"
        and migration_blocked
        and bool(activations)
        and all(
            item.runtime_state == "LEGACY_NOT_MIGRATED"
            for item in activations
        )
    )
    if lifecycle in RUNTIME_COUNTED_STATES:
        if not activations or (
            not legacy_not_migrated
            and any(item.runtime_state != "RUNTIME" for item in activations)
        ):
            raise MechanicalGateRegistryError(
                "runtime-counted gate requires runtime activations"
            )
    else:
        if any(item.runtime_state != "NON_RUNTIME" for item in activations):
            raise MechanicalGateRegistryError(
                "non-runtime gate cannot retain a runtime activation"
            )
    _casefold_unique(
        [item.activation_id for item in activations],
        f"{label}.activations",
    )
    purpose = _human_text(row["purpose"], f"{label}.purpose")
    authority = _validate_authority(
        row["authority"], f"{label}.authority", decision_class
    )
    inputs = _validate_contracts(
        row["input_contracts"],
        output=False,
        label=f"{label}.input_contracts",
        allow_empty_migration_debt=(
            legacy_not_migrated
            or lifecycle in {"CONSOLIDATED", "SUNSET"}
        ),
    )
    outputs = _validate_contracts(
        row["output_contracts"],
        output=True,
        label=f"{label}.output_contracts",
        allow_empty_migration_debt=(
            legacy_not_migrated
            or lifecycle in {"CONSOLIDATED", "SUNSET"}
        ),
    )
    if legacy_not_migrated and bool(inputs) != bool(outputs):
        raise MechanicalGateRegistryError(
            f"{label} legacy migration contracts are only legal as an "
            "exact empty debt pair"
        )
    if legacy_not_migrated and (inputs or outputs):
        raise MechanicalGateRegistryError(
            f"{label} legacy migration cannot invent PhaseIO contracts"
        )
    expected_selectors = {
        tuple(item.lower() for item in selector)
        for activation in activations
        if activation.runtime_state == "RUNTIME"
        for selector in product(
            activation.pipelines,
            activation.modes,
            activation.ecosystems,
            activation.backends,
            activation.phases,
        )
    }
    observed_selectors = {
        tuple(
            str(output["phase_io_work_unit_id"]).split("/")[:5]
        )
        for output in outputs
    }
    if expected_selectors and observed_selectors != expected_selectors:
        raise MechanicalGateRegistryError(
            f"{label} PhaseIO work units do not equal activation selectors"
        )
    if {
        str(item["artifact_identity"]).casefold() for item in inputs
    } & {
        str(item["artifact_identity"]).casefold() for item in outputs
    }:
        raise MechanicalGateRegistryError(
            f"{label} cannot read and write the same undeclared artifact"
        )
    if lifecycle in RUNTIME_COUNTED_STATES and not legacy_not_migrated:
        common = {
            item["authority_carried"]
            for item in outputs
            if item["authority_carried"]
            in {
                "COMMON_RECEIPT",
                "GOVERNANCE_DEBT",
                "OVERFLOW_BACKLOG",
            }
        }
        required_common = {
            "COMMON_RECEIPT",
            "GOVERNANCE_DEBT",
            "OVERFLOW_BACKLOG",
        }
        if common != required_common:
            raise MechanicalGateRegistryError(
                f"{label} lacks common receipt/debt/overflow PhaseIO outputs"
            )
    return GateRecord(
        gate_id=gate_id,
        display_name=display_name,
        lifecycle_state=lifecycle,
        decision_class=decision_class,
        admission=admission,
        owning_seam=seam,
        execution_order=execution_order,
        activations=activations,
        purpose=purpose,
        authority=authority,
        input_contracts=inputs,
        output_contracts=outputs,
        failure_contract=_validate_failure_contract(
            row["failure_contract"], f"{label}.failure_contract"
        ),
        runtime_budget=_validate_runtime_budget(
            row["runtime_budget"], f"{label}.runtime_budget"
        ),
        release_evidence=_validate_release_evidence(
            row["release_evidence"], f"{label}.release_evidence"
        ),
        false_fire_budget=_validate_false_fire(
            row["false_fire_budget"], f"{label}.false_fire_budget"
        ),
        overlap_and_consolidation=_validate_overlap(
            row["overlap_and_consolidation"],
            f"{label}.overlap_and_consolidation",
        ),
        ownership=_validate_ownership(
            row["ownership"], f"{label}.ownership", lifecycle
        ),
        review_and_sunset=_validate_review(
            row["review_and_sunset"],
            f"{label}.review_and_sunset",
            lifecycle,
            migration_blocked=migration_blocked,
        ),
        part0=_validate_part0(row["part0"], f"{label}.part0"),
    )


def _validate_exception(value: Any, label: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    row = _closed(value, _EXCEPTION_KEYS, label)
    _text(row["exception_approver"], f"{label}.exception_approver")
    delta = _integer(
        row["temporary_ceiling_delta"],
        f"{label}.temporary_ceiling_delta",
        minimum=1,
    )
    assert delta is not None
    _text(
        row["exception_rationale_code"],
        f"{label}.exception_rationale_code",
    )
    _sha(
        row["held_out_evidence_receipt_sha256"],
        f"{label}.held_out_evidence_receipt_sha256",
    )
    review_by = _text(row["review_by"], f"{label}.review_by")
    expires = _text(row["expires_on"], f"{label}.expires_on")
    assert review_by is not None and expires is not None
    review_instant = _utc_instant(review_by, f"{label}.review_by")
    expiry_instant = _utc_instant(expires, f"{label}.expires_on")
    if review_instant >= expiry_instant:
        raise MechanicalGateRegistryError(
            "exception review_by must precede expires_on"
        )
    if expiry_instant <= datetime.now(timezone.utc):
        raise MechanicalGateRegistryError(
            "active seam exception is already expired"
        )
    return _freeze(row)


def _validate_budget(value: Any, index: int) -> SeamBudget:
    label = f"seam_budgets[{index}]"
    row = _closed(value, _SEAM_BUDGET_KEYS, label)
    seam = row["owning_seam"]
    if seam not in SEAMS:
        raise MechanicalGateRegistryError(f"{label}.owning_seam is invalid")
    status = row["approval_status"]
    if status not in {"UNAPPROVED_BASELINE", "APPROVED"}:
        raise MechanicalGateRegistryError(
            f"{label}.approval_status is invalid"
        )
    ceiling = _integer(
        row["gate_budget_ceiling"],
        f"{label}.gate_budget_ceiling",
        nullable=True,
    )
    revision = _integer(
        row["approval_revision"],
        f"{label}.approval_revision",
        nullable=True,
        minimum=1,
    )
    approver = _text(
        row["approver"], f"{label}.approver", nullable=True
    )
    if status == "UNAPPROVED_BASELINE":
        if ceiling is not None or revision is not None or approver is not None:
            raise MechanicalGateRegistryError(
                "unapproved seam cannot carry approval authority"
            )
    else:
        if ceiling is None or revision is None or approver is None:
            raise MechanicalGateRegistryError(
                "approved seam lacks prior-revision authority"
            )
    baseline = _string_array(
        row["baseline_gate_ids"],
        f"{label}.baseline_gate_ids",
        identifiers=True,
    )
    additions = _string_array(
        row["addition_gate_ids"],
        f"{label}.addition_gate_ids",
        identifiers=True,
    )
    releases = _string_array(
        row["release_gate_ids"],
        f"{label}.release_gate_ids",
        identifiers=True,
    )
    if status == "UNAPPROVED_BASELINE" and (additions or releases):
        raise MechanicalGateRegistryError(
            "unapproved seam cannot add or release gate authority"
        )
    counts: dict[str, int] = {}
    for key in (
        "active_gate_count",
        "activated_or_shadow_additions",
        "approved_slot_releases",
        "post_change_gate_count",
    ):
        parsed = _integer(row[key], f"{label}.{key}")
        assert parsed is not None
        counts[key] = parsed
    exception = _validate_exception(row["exception"], f"{label}.exception")
    return SeamBudget(
        owning_seam=seam,
        approval_status=status,
        gate_budget_ceiling=ceiling,
        approval_revision=revision,
        approver=approver,
        baseline_gate_ids=baseline,
        addition_gate_ids=additions,
        release_gate_ids=releases,
        active_gate_count=counts["active_gate_count"],
        activated_or_shadow_additions=counts[
            "activated_or_shadow_additions"
        ],
        approved_slot_releases=counts["approved_slot_releases"],
        post_change_gate_count=counts["post_change_gate_count"],
        exception=exception,
    )


def validate_part0_metadata(
    registry: Mapping[str, Any] | MechanicalGateRegistry,
) -> None:
    """Reject target answers or locations from methodology metadata."""

    def prose_strings(candidate: Any) -> Iterable[str]:
        if isinstance(candidate, str):
            yield candidate
        elif isinstance(candidate, Mapping):
            for nested in candidate.values():
                yield from prose_strings(nested)
        elif isinstance(candidate, (list, tuple)):
            for nested in candidate:
                yield from prose_strings(nested)

    def free_text_strings(row: Mapping[str, Any]) -> Iterable[str]:
        for key in ("display_name", "purpose"):
            value = row.get(key)
            if isinstance(value, str):
                yield value
        containers = (
            ("authority", ("join_rule", "monotonicity_claim")),
            (
                "overlap_and_consolidation",
                ("unique_authority", "retirement_criteria"),
            ),
            ("part0", ("generic_subject",)),
            ("review_and_sunset", ("sunset_reason",)),
        )
        for container, keys in containers:
            nested = row.get(container)
            if not isinstance(nested, Mapping):
                continue
            for key in keys:
                value = nested.get(key)
                if isinstance(value, str):
                    yield value
        inputs = row.get("input_contracts")
        if isinstance(inputs, list):
            for contract in inputs:
                if not isinstance(contract, Mapping):
                    continue
                for key in ("join_rule", "freshness_rule"):
                    value = contract.get(key)
                    if isinstance(value, str):
                        yield value

    raw = _plain(registry)
    top = _closed(raw, _TOP_KEYS, "registry")
    gates = top["gate_records"]
    if not isinstance(gates, list):
        raise MechanicalGateRegistryError("gate_records must be an array")
    for index, candidate in enumerate(gates):
        row = _mapping(candidate, f"gate_records[{index}]")
        part0 = _validate_part0(
            row.get("part0"), f"gate_records[{index}].part0"
        )
        for text in prose_strings(row):
            if _FINDING_ID_RE.search(text):
                raise MechanicalGateRegistryError(
                    "Part-0 metadata contains a target finding identifier"
                )
            if _ABSOLUTE_PATH_RE.search(text):
                raise MechanicalGateRegistryError(
                    "Part-0 metadata contains a host or target location"
                )
            if _TARGET_LOCATION_RE.search(text):
                raise MechanicalGateRegistryError(
                    "Part-0 metadata contains a target source location"
                )
            if _MOTIVATING_ANSWER_RE.search(text):
                raise MechanicalGateRegistryError(
                    "Part-0 metadata contains a motivating answer"
                )
            if _CAMEL_TARGET_RE.search(text):
                raise MechanicalGateRegistryError(
                    "Part-0 metadata contains a target-specific name"
                )
        for text in free_text_strings(row):
            if _SNAKE_TARGET_RE.search(text):
                raise MechanicalGateRegistryError(
                    "Part-0 free-text metadata contains a source-style "
                    "target-specific name"
                )


def _validate_seam_budget_equations_unchecked(
    registry: MechanicalGateRegistry,
) -> None:
    known = {record.gate_id: record for record in registry.gate_records}
    baseline_all: set[str] = set()
    post_change_all: set[str] = set()
    for budget in registry.seam_budgets:
        baseline = set(budget.baseline_gate_ids)
        additions = set(budget.addition_gate_ids)
        releases = set(budget.release_gate_ids)
        if not releases <= baseline:
            raise MechanicalGateRegistryError(
                f"{budget.owning_seam}: releases are not a baseline subset"
            )
        if additions & baseline or additions & releases:
            raise MechanicalGateRegistryError(
                f"{budget.owning_seam}: additions overlap prior identity sets"
            )
        if budget.active_gate_count != len(baseline):
            raise MechanicalGateRegistryError(
                f"{budget.owning_seam}: active count is not baseline cardinality"
            )
        if budget.activated_or_shadow_additions != len(additions):
            raise MechanicalGateRegistryError(
                f"{budget.owning_seam}: addition count is incorrect"
            )
        if budget.approved_slot_releases != len(releases):
            raise MechanicalGateRegistryError(
                f"{budget.owning_seam}: release count is incorrect"
            )
        post = (baseline - releases) | additions
        if budget.post_change_gate_count != len(post):
            raise MechanicalGateRegistryError(
                f"{budget.owning_seam}: post-change count is incorrect"
            )
        if budget.gate_budget_ceiling is not None:
            delta = (
                int(budget.exception["temporary_ceiling_delta"])
                if budget.exception is not None
                else 0
            )
            if len(post) > budget.gate_budget_ceiling + delta:
                raise MechanicalGateRegistryError(
                    f"{budget.owning_seam}: approved ceiling is exceeded"
                )
        for gate_id in baseline | additions | releases:
            if gate_id not in known:
                raise MechanicalGateRegistryError(
                    f"{budget.owning_seam}: unknown gate ID {gate_id}"
                )
            if known[gate_id].owning_seam != budget.owning_seam:
                raise MechanicalGateRegistryError(
                    f"{budget.owning_seam}: gate belongs to another seam"
                )
        for gate_id in additions:
            if known[gate_id].lifecycle_state not in {
                "SHADOW",
                "REPLAY",
                "ACTIVE",
            }:
                raise MechanicalGateRegistryError(
                    f"{budget.owning_seam}: addition is not a reviewed runtime transition"
                )
        for gate_id in releases:
            record = known[gate_id]
            if record.lifecycle_state not in {"CONSOLIDATED", "SUNSET"}:
                raise MechanicalGateRegistryError(
                    f"{budget.owning_seam}: release is not retired"
                )
            evidence = record.release_evidence
            if evidence["status"] not in {
                "RECALL_PARITY_ESTABLISHED",
                "EXPLICIT_RECALL_TRADEOFF",
            }:
                raise MechanicalGateRegistryError(
                    f"{budget.owning_seam}: release lacks recall authority"
                )
            if (
                evidence["recall_parity_receipt_sha256"] is None
                or evidence["system_owner_approval_sha256"] is None
            ):
                raise MechanicalGateRegistryError(
                    f"{budget.owning_seam}: release lacks independent receipts"
                )
        if baseline_all & baseline:
            raise MechanicalGateRegistryError(
                "a baseline gate appears in more than one seam"
            )
        baseline_all |= baseline
        if post_change_all & post:
            raise MechanicalGateRegistryError(
                "a post-change gate appears in more than one seam"
            )
        post_change_all |= post
    runtime_ids = {
        record.gate_id
        for record in registry.gate_records
        if record.lifecycle_state in RUNTIME_COUNTED_STATES
    }
    if post_change_all != runtime_ids:
        raise MechanicalGateRegistryError(
            "seam post-change set does not equal runtime-counted gate records"
        )


def validate_seam_budget_equations(
    registry: MechanicalGateRegistry,
) -> None:
    """Revalidate typed input, then enforce exact seam-set equations."""

    validated = validate_mechanical_gate_registry(registry)
    _validate_seam_budget_equations_unchecked(validated)


def _validate_stage1_baseline_authority(
    registry: MechanicalGateRegistry,
) -> None:
    """Keep the canonical Stage-1 baseline descriptive, never authoritative."""

    migration = registry.migration
    if (
        registry.migration_status != "BASELINING_EXISTING_ACTIVATIONS"
        or migration["new_runtime_transitions_blocked"] is not True
        or migration["baseline_review_status"] != "UNREVIEWED"
    ):
        return

    if registry.registry_scope["scope_review_receipt_sha256"] is not None:
        raise MechanicalGateRegistryError(
            "Stage-1 scope cannot fabricate review authority"
        )
    if any(
        migration[key] is not None
        for key in (
            "baseline_reviewer",
            "baseline_reviewed_at",
            "baseline_review_receipt_sha256",
        )
    ):
        raise MechanicalGateRegistryError(
            "Stage-1 migration cannot fabricate baseline review authority"
        )
    if (
        registry.activation_inventory[
            "independent_review_receipt_sha256"
        ]
        is not None
    ):
        raise MechanicalGateRegistryError(
            "Stage-1 activation inventory cannot fabricate review authority"
        )

    for budget in registry.seam_budgets:
        if (
            budget.approval_status != "UNAPPROVED_BASELINE"
            or budget.gate_budget_ceiling is not None
            or budget.approval_revision is not None
            or budget.approver is not None
            or budget.addition_gate_ids
            or budget.release_gate_ids
            or budget.activated_or_shadow_additions != 0
            or budget.approved_slot_releases != 0
            or budget.active_gate_count != len(budget.baseline_gate_ids)
            or budget.post_change_gate_count
            != len(budget.baseline_gate_ids)
            or budget.exception is not None
        ):
            raise MechanicalGateRegistryError(
                "Stage-1 seam budget cannot carry approval or ceiling authority"
            )

    for record in registry.gate_records:
        if record.lifecycle_state not in {
            "LEGACY_ACTIVE_UNGOVERNED",
            "CONSOLIDATED",
            "SUNSET",
        }:
            raise MechanicalGateRegistryError(
                "Stage-1 records must be legacy live gates or migration tombstones"
            )
        if (
            record.admission["status"] != "LEGACY_UNASSESSED"
            or record.admission["evidence_receipt_sha256"] is not None
        ):
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot fabricate admission evidence"
            )
        if record.input_contracts or record.output_contracts:
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot invent PhaseIO contracts"
            )
        if record.lifecycle_state == "LEGACY_ACTIVE_UNGOVERNED":
            if not record.activations or any(
                item.runtime_state != "LEGACY_NOT_MIGRATED"
                for item in record.activations
            ):
                raise MechanicalGateRegistryError(
                    "Stage-1 live gates must remain legacy-not-migrated"
                )
        elif record.activations:
            raise MechanicalGateRegistryError(
                "Stage-1 migration tombstones cannot be runtime activations"
            )
        if any(
            record.runtime_budget[key] is not None
            for key in BUDGET_MAXIMA
        ):
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot fabricate runtime ceilings"
            )
        release = record.release_evidence
        if (
            release["status"] != "UNESTABLISHED"
            or release["replacement_gate_ids"]
            or release["recall_parity_receipt_sha256"] is not None
            or release["system_owner_approval_sha256"] is not None
        ):
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot fabricate release evidence"
            )
        false_fire = record.false_fire_budget
        if (
            false_fire["status"] != "UNESTABLISHED"
            or any(
                false_fire[key] is not None
                for key in _FALSE_FIRE_KEYS - {"status"}
            )
        ):
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot fabricate false-fire evidence"
            )
        overlap = record.overlap_and_consolidation
        if (
            overlap["overlapping_gate_ids"]
            or overlap["shared_contract_ids"]
            or overlap["consolidation_status"] != "NOT ASSESSED"
            or overlap["recall_parity_receipt_sha256"] is not None
        ):
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot fabricate consolidation evidence"
            )
        ownership = record.ownership
        if (
            ownership["assignment_status"] != "UNASSIGNED_MIGRATION_DEBT"
            or any(
                ownership[key] is not None
                for key in (
                    "component_owner",
                    "system_owner",
                    "implementer",
                    "independent_reviewer",
                )
            )
        ):
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot fabricate ownership"
            )
        review = record.review_and_sunset
        expected_review_status = (
            "LEGACY_UNREVIEWED"
            if record.lifecycle_state == "LEGACY_ACTIVE_UNGOVERNED"
            else "MIGRATION_TOMBSTONE_UNASSESSED"
        )
        if (
            review["previous_lifecycle_state"] is not None
            or review["transition_review_status"] != expected_review_status
            or review["reviewed_at"] is not None
            or review["review_receipt_sha256"] is not None
            or review["expires_at"] is not None
            or review["superseded_by_gate_ids"]
        ):
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot fabricate transition review"
            )
        if record.part0["review_receipt_sha256"] is not None:
            raise MechanicalGateRegistryError(
                "Stage-1 records cannot fabricate Part-0 review authority"
            )


def _validate_mechanical_gate_registry_impl(
    value: Mapping[str, Any] | MechanicalGateRegistry,
) -> MechanicalGateRegistry:
    """Validate and deeply freeze one fixture registry."""

    if isinstance(value, MechanicalGateRegistry):
        # Frozen dataclasses are transport conveniences, not capabilities.
        # ``dataclasses.replace`` and direct constructor calls remain public,
        # so every typed instance must cross the same closed-schema and
        # semantic boundary as untrusted JSON before it can be used again.
        value = _plain(value)
    top = _closed(value, _TOP_KEYS, "registry")
    if top["schema_version"] != SCHEMA_VERSION:
        raise MechanicalGateRegistryError("registry schema version is invalid")
    revision = _integer(
        top["registry_revision"], "registry.registry_revision", minimum=1
    )
    assert revision is not None
    if (
        top["migration_status"]
        != "BASELINING_EXISTING_ACTIVATIONS"
    ):
        raise MechanicalGateRegistryError(
            "fixture slice permits baselining migration state only"
        )
    if tuple(top["seam_taxonomy"]) != SEAMS:
        raise MechanicalGateRegistryError("seam taxonomy is not exact")
    if tuple(top["decision_class_taxonomy"]) != DECISION_CLASSES:
        raise MechanicalGateRegistryError(
            "decision-class taxonomy is not exact"
        )
    if tuple(top["direction_taxonomy"]) != DIRECTIONS:
        raise MechanicalGateRegistryError("direction taxonomy is not exact")

    scope = _validate_scope(top["registry_scope"])
    migration = _validate_migration(top["migration"])
    inventory = _validate_activation_inventory(
        top["activation_inventory"]
    )
    if migration["source_tree_digest"] != inventory["source_tree_digest"]:
        raise MechanicalGateRegistryError(
            "migration and activation-inventory source trees differ"
        )

    if not isinstance(top["gate_records"], list):
        raise MechanicalGateRegistryError("gate_records must be an array")
    migration_blocked = (
        migration["new_runtime_transitions_blocked"] is True
    )
    records = tuple(
        _validate_gate(
            item,
            index,
            migration_blocked=migration_blocked,
        )
        for index, item in enumerate(top["gate_records"])
    )
    _casefold_unique([record.gate_id for record in records], "gate_records")
    activations = [
        activation
        for record in records
        for activation in record.activations
    ]
    _casefold_unique(
        [activation.activation_id for activation in activations],
        "all activation IDs",
    )
    module_spellings: dict[str, str] = {}
    for activation in activations:
        folded = activation.module.casefold()
        previous = module_spellings.setdefault(folded, activation.module)
        if previous != activation.module:
            raise MechanicalGateRegistryError(
                "activation modules collide under filesystem case folding"
            )
    for record in records:
        for activation in record.activations:
            if not activation.activation_id.startswith(record.gate_id + "."):
                raise MechanicalGateRegistryError(
                    "activation ID is outside its gate namespace"
                )
    execution_keys = [
        (record.owning_seam, record.execution_order)
        for record in records
        if record.lifecycle_state in RUNTIME_COUNTED_STATES
    ]
    if len(execution_keys) != len(set(execution_keys)):
        raise MechanicalGateRegistryError(
            "runtime gates share a seam execution order"
        )
    output_writers: dict[str, str] = {}
    work_unit_owners: dict[str, str] = {}
    for record in records:
        for output in record.output_contracts:
            identity = str(output["artifact_identity"])
            previous = output_writers.setdefault(
                identity.casefold(), record.gate_id
            )
            if previous != record.gate_id:
                raise MechanicalGateRegistryError(
                    "multiple gates claim authority to write one artifact"
                )
            work_unit = str(output["phase_io_work_unit_id"])
            previous_owner = work_unit_owners.setdefault(
                work_unit.casefold(), record.gate_id
            )
            if previous_owner != record.gate_id:
                raise MechanicalGateRegistryError(
                    "multiple gates claim one PhaseIO work unit"
                )

    if not isinstance(top["seam_budgets"], list):
        raise MechanicalGateRegistryError("seam_budgets must be an array")
    budgets = tuple(
        _validate_budget(item, index)
        for index, item in enumerate(top["seam_budgets"])
    )
    if tuple(item.owning_seam for item in budgets) != SEAMS:
        raise MechanicalGateRegistryError(
            "seam budgets must occur exactly once in taxonomy order"
        )
    for budget in budgets:
        if (
            budget.approval_status == "APPROVED"
            and (
                budget.approval_revision is None
                or budget.approval_revision >= revision
            )
        ):
            raise MechanicalGateRegistryError(
                "seam approval must come from a prior registry revision"
            )

    result = MechanicalGateRegistry(
        schema_version=SCHEMA_VERSION,
        registry_revision=revision,
        registry_scope=scope,
        migration_status=top["migration_status"],
        migration=migration,
        activation_inventory=inventory,
        seam_taxonomy=SEAMS,
        decision_class_taxonomy=DECISION_CLASSES,
        direction_taxonomy=DIRECTIONS,
        seam_budgets=budgets,
        gate_records=records,
    )
    _validate_seam_budget_equations_unchecked(result)
    validate_part0_metadata(result)

    known_gate_ids = {record.gate_id for record in records}
    for record in records:
        references = {
            *record.release_evidence["replacement_gate_ids"],
            *record.overlap_and_consolidation["overlapping_gate_ids"],
            *record.review_and_sunset["superseded_by_gate_ids"],
        }
        unknown = references - known_gate_ids
        if unknown:
            raise MechanicalGateRegistryError(
                f"{record.gate_id} references unknown gate IDs: "
                f"{sorted(unknown)}"
            )
        if record.gate_id in references:
            raise MechanicalGateRegistryError(
                f"{record.gate_id} cannot reference itself"
            )
        expires_at = record.review_and_sunset["expires_at"]
        if (
            record.lifecycle_state in RUNTIME_COUNTED_STATES
            and expires_at is not None
            and _utc_instant(
                expires_at,
                f"{record.gate_id}.review_and_sunset.expires_at",
            )
            <= datetime.now(timezone.utc)
        ):
            raise MechanicalGateRegistryError(
                f"{record.gate_id} is runtime-active after expiry"
            )

    baseline = tuple(migration["baseline_gate_ids"])
    budget_baseline = tuple(
        sorted(
            (
                gate_id
                for budget in budgets
                for gate_id in budget.baseline_gate_ids
            ),
            key=lambda item: item.encode("utf-8"),
        )
    )
    runtime_ids = tuple(
        sorted(
            (
                record.gate_id
                for record in records
                if record.lifecycle_state in RUNTIME_COUNTED_STATES
            ),
            key=lambda item: item.encode("utf-8"),
        )
    )
    if baseline != budget_baseline:
        raise MechanicalGateRegistryError(
            "migration baseline IDs do not equal seam baseline records"
        )
    if migration["baseline_live_gate_count"] != len(budget_baseline):
        raise MechanicalGateRegistryError(
            "migration baseline live count is incorrect"
        )
    if migration["new_runtime_transitions_blocked"] is not True:
        raise MechanicalGateRegistryError(
            "fixture-only registry must block new runtime transitions"
        )
    if any(
        record.lifecycle_state in RUNTIME_COUNTED_STATES
        and record.lifecycle_state != "LEGACY_ACTIVE_UNGOVERNED"
        for record in records
    ):
        raise MechanicalGateRegistryError(
            "fixture migration blocks all new runtime transitions"
        )
    _validate_stage1_baseline_authority(result)
    return result


def validate_mechanical_gate_registry(
    value: Mapping[str, Any] | MechanicalGateRegistry,
) -> MechanicalGateRegistry:
    """Normalize hostile input failures into the registry domain."""

    try:
        return _validate_mechanical_gate_registry_impl(value)
    except MechanicalGateRegistryError:
        raise
    except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as exc:
        raise MechanicalGateRegistryError(
            "mechanical gate registry input is malformed"
        ) from exc


def mechanical_gate_registry_digest(
    registry: MechanicalGateRegistry | Mapping[str, Any],
) -> str:
    validated = validate_mechanical_gate_registry(registry)
    try:
        raw = json.dumps(
            _plain(validated),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise MechanicalGateRegistryError(
            "mechanical gate registry cannot be canonicalized"
        ) from exc
    return hashlib.sha256(raw).hexdigest()


def resolve_gate_record(
    registry: MechanicalGateRegistry,
    gate_id: str,
) -> GateRecord:
    registry = validate_mechanical_gate_registry(registry)
    normalized = _identifier(gate_id, "gate_id")
    matches = [
        record for record in registry.gate_records
        if record.gate_id == normalized
    ]
    if len(matches) != 1:
        raise MechanicalGateRegistryError(
            f"gate ID is not uniquely registered: {normalized}"
        )
    return matches[0]


def _reject_stream_syntax(path: Path, label: str) -> None:
    exempt = {path.anchor, path.drive, ""}
    if any(":" in component for component in path.parts if component not in exempt):
        raise MechanicalGateRegistryError(
            f"{label} contains alternate-stream syntax"
        )


def _reject_path_aliases(path: Path, root: Path) -> tuple[os.stat_result, Path]:
    lexical_root = Path(os.path.abspath(root))
    lexical_path = Path(os.path.abspath(path))
    try:
        lexical_relative = lexical_path.relative_to(lexical_root)
    except ValueError as exc:
        raise MechanicalGateRegistryError(
            "registry is outside the installed Plamen root"
        ) from exc
    lexical_cursor = lexical_root
    lexical_components = (Path("."), *(
        Path(*lexical_relative.parts[:index])
        for index in range(1, len(lexical_relative.parts) + 1)
    ))
    for relative_component in lexical_components:
        lexical_cursor = lexical_root / relative_component
        try:
            lexical_row = lexical_cursor.lstat()
        except OSError as exc:
            raise MechanicalGateRegistryError(
                "registry lexical path cannot be inspected"
            ) from exc
        if stat.S_ISLNK(lexical_row.st_mode) or bool(
            getattr(lexical_row, "st_file_attributes", 0)
            & _REPARSE_ATTRIBUTE
        ):
            raise MechanicalGateRegistryError(
                "registry lexical path contains a symlink or reparse point"
            )
    try:
        resolved_root = root.resolve(strict=True)
        candidate = path.resolve(strict=True)
    except OSError as exc:
        raise MechanicalGateRegistryError(
            "registry path cannot be resolved"
        ) from exc
    try:
        relative = candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise MechanicalGateRegistryError(
            "registry is outside the installed Plamen root"
        ) from exc
    cursor = resolved_root
    for component in relative.parts:
        cursor = cursor / component
        try:
            row = cursor.lstat()
        except OSError as exc:
            raise MechanicalGateRegistryError(
                "registry path component cannot be inspected"
            ) from exc
        if stat.S_ISLNK(row.st_mode) or bool(
            getattr(row, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
        ):
            raise MechanicalGateRegistryError(
                "registry path contains a symlink or reparse point"
            )
    try:
        row = path.lstat()
    except OSError as exc:
        raise MechanicalGateRegistryError(
            "registry path cannot be inspected"
        ) from exc
    if not stat.S_ISREG(row.st_mode):
        raise MechanicalGateRegistryError(
            "registry path is not a regular file"
        )
    return row, candidate


def _read_bound_regular_file(
    candidate: Path,
    *,
    root: Path,
    label: str,
) -> bytes:
    """Read one in-root regular file without following identity changes."""

    _reject_stream_syntax(candidate, "registry path")
    _reject_stream_syntax(root, "installed root")
    before, resolved = _reject_path_aliases(candidate, root)
    if before.st_size > MAX_REGISTRY_BYTES:
        raise MechanicalGateRegistryError(f"{label} exceeds 8 MiB")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise MechanicalGateRegistryError(f"{label} open failed") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise MechanicalGateRegistryError(
                f"{label} identity drifted during open"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(65536, MAX_REGISTRY_BYTES + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > MAX_REGISTRY_BYTES:
                raise MechanicalGateRegistryError(
                    f"{label} exceeds 8 MiB"
                )
        after = os.fstat(descriptor)
        if (
            after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or (after.st_dev, after.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise MechanicalGateRegistryError(
                f"{label} mutated while being read"
            )
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def load_mechanical_gate_registry(
    path: Path | str,
    *,
    installed_root: Path | str,
) -> MechanicalGateRegistry:
    """Open and validate one exact in-root registry.

    The canonical installed filename additionally requires the adjacent,
    closed Draft 2020-12 schema.  Fixture filenames continue to exercise the
    Python semantic validator directly.
    """

    candidate = Path(path)
    root = Path(installed_root)
    raw = _read_bound_regular_file(
        candidate,
        root=root,
        label="registry",
    )
    payload = strict_json_loads(raw)
    if candidate.name == CANONICAL_REGISTRY_FILENAME:
        schema_path = candidate.with_name(CANONICAL_SCHEMA_FILENAME)
        schema_raw = _read_bound_regular_file(
            schema_path,
            root=root,
            label="registry schema",
        )
        schema = strict_json_loads(schema_raw)
        try:
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(payload)
        except (SchemaError, ValidationError) as exc:
            raise MechanicalGateRegistryError(
                "canonical registry fails its closed v2 JSON Schema"
            ) from exc
    return validate_mechanical_gate_registry(payload)


__all__ = [
    "ACTIVATION_RUNTIME_STATES",
    "BACKENDS",
    "CANONICAL_REGISTRY_FILENAME",
    "CANONICAL_SCHEMA_FILENAME",
    "DECISION_CLASSES",
    "DECISION_CODE_DIGEST_ALGORITHM",
    "DIRECTIONS",
    "ECOSYSTEMS",
    "GateActivation",
    "GateRecord",
    "LIFECYCLE_STATES",
    "LEGACY_MODULE_CODE_DIGEST_ALGORITHM",
    "MAX_REGISTRY_BYTES",
    "MAX_SEMANTIC_INTEGER",
    "MODES",
    "MechanicalGateRegistry",
    "MechanicalGateRegistryError",
    "PHASES",
    "PIPELINES",
    "RUNTIME_COUNTED_STATES",
    "SCHEMA_VERSION",
    "SEAMS",
    "SOURCE_TREE_DIGEST_ALGORITHM",
    "SeamBudget",
    "load_mechanical_gate_registry",
    "mechanical_gate_registry_digest",
    "resolve_gate_record",
    "strict_json_loads",
    "validate_mechanical_gate_registry",
    "validate_part0_metadata",
    "validate_seam_budget_equations",
]
