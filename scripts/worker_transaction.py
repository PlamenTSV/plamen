"""Provider-owned worker transaction contracts.

This module is the backend-neutral control plane for P0-AM.  It deliberately
contains no model, transport, or subprocess authority: a phase roster freezes
the logical denominator, while recovery converts abandoned arms into durable
retry debt.  Execution, incorporation, and full OS-scope recovery are migrated
behind this boundary in later P0-AM stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import contextlib
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Collection, Iterator, Mapping, Sequence
import uuid

from worker_execution_receipts import (
    BoundInput,
    CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
    CompletedExecution,
    ExecutionBindings,
    ExpectedOutput,
    ParserDigest,
    PrincipalInvocation,
    STDOUT_ASSIGNED_OUTPUT,
    WORKER_FILE_OUTPUTS,
    WorkerExecutionIncomplete,
    environment_allowlist_sha256,
    run_observed_worker,
    validate_staged_execution,
)
from claude_stream_json_evidence import (
    ClaudeStreamJsonEvidenceError,
    normalize_expected_init_contract,
)
from claude_launch_security import (
    ClaudeLaunchSecurityError,
    replay_claude_launch_security,
    replay_claude_launch_security_request,
)
from claude_runtime_materialization import (
    ClaudeRuntimeMaterializationError,
    compile_claude_runtime_materialization_request,
)
from claude_provider_preparation import (
    BoundClaudeProviderRuntime,
    ClaudeProviderPreparation,
    ClaudeProviderPreparationError,
    claim_bound_claude_provider_runtime,
)
from auxiliary_writable_root_lease import (
    AuxiliaryWritableRootLease,
    AuxiliaryWritableRootLeaseError,
    reserve_auxiliary_writable_root,
)
from auxiliary_writable_root_startup import (
    STARTUP_BINDING_SCHEMA,
    STARTUP_RECEIPT_DIRECTORY_NAME,
)
from owned_process_scope import (
    OwnedProcessScopeError,
    process_tree_termination_capability,
    recover_persisted_process_scope,
)
from provider_command_authority import argv_authority_sha256
import rooted_path_io as _rooted_io


PHASE_WORK_ROSTER_SCHEMA = "plamen.phase_work_roster.v1"
WORKER_ATTEMPT_ARM_SCHEMA = "plamen.worker_attempt_arm.v1"
WORKER_ATTEMPT_ARM_SCHEMA_V2 = "plamen.worker_attempt_arm.v2"
WORKER_ATTEMPT_ARM_SCHEMA_V3 = "plamen.worker_attempt_arm.v3"
WORKER_ATTEMPT_DEBT_SCHEMA = "plamen.worker_attempt_debt.v1"
WORKER_WORK_PLAN_SCHEMA_V1 = "plamen.worker_work_plan.v1"
WORKER_WORK_PLAN_SCHEMA_V2 = "plamen.worker_work_plan.v2"
ALL_REQUIRED_INCORPORATED = "ALL_REQUIRED_INCORPORATED"

ATTEMPT_ID_PLACEHOLDER = "__PLAMEN_ATTEMPT_ID__"
ATTEMPT_RELATIVE_PATH_PLACEHOLDER = "__PLAMEN_ATTEMPT_RELATIVE_PATH__"
ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER = (
    "__PLAMEN_ATTEMPT_OUTPUT_RELATIVE_PATH__"
)
ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER = (
    "__PLAMEN_ATTEMPT_OUTPUT_DIRECTORY__"
)
CLAUDE_STREAM_STDOUT_POLICY_KEY = (
    "provider_stdout_evidence_configuration"
)
AUXILIARY_STARTUP_POLICY_KEY = (
    "auxiliary_writable_root_startup_permit"
)
CLAUDE_LAUNCH_SECURITY_POLICY_KEY = "claude_launch_security"
CLAUDE_PROVIDER_PREPARATION_POLICY_KEY = (
    "claude_provider_preparation_sha256"
)
CODEX_RUNTIME_AUTH_POLICY_KEY = "codex_runtime_auth"
CODEX_HOME_PLACEHOLDER = "__PLAMEN_CODEX_HOME__"

_HEX_RE = re.compile(r"[0-9a-f]{64}")
_STARTUP_EPOCH_RE = re.compile(r"[0-9a-f]{32}")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
StagedOutputValidator = Callable[
    [Mapping[str, bytes], Mapping[str, Any]],
    Sequence[str],
]


class WorkerTransactionError(RuntimeError):
    """A transaction contract or persisted transaction artifact is invalid."""


@dataclass(frozen=True)
class RecoveryStatus:
    """Exact post-recovery attempt and retry denominator."""

    active_attempt_ids: tuple[str, ...]
    retry_work_unit_ids: tuple[str, ...]
    terminal_attempt_ids: tuple[str, ...] = ()
    blocked_work_unit_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class NativeCommandAdapter:
    """Trusted inputs needed to execute one native WorkPlan."""

    scratchpad: Path
    cwd: Path
    input_relative_paths: Mapping[str, str]
    parser_digest: ParserDigest
    environment: Mapping[str, str]
    environment_allowlist: tuple[str, ...]
    output_source_mode: str = STDOUT_ASSIGNED_OUTPUT
    stdin_input_name: str | None = None
    phase_roster: Mapping[str, Any] | None = None
    attempt_id: str | None = None


@dataclass(frozen=True)
class HeadlessModelAdapter:
    """Trusted runtime inputs for one headless Claude/Codex WorkPlan.

    The model receives the prompt through stdin and may publish only the
    assignment members in its attempt-owned output directory.  Authentication
    and provider-home materialization remain launcher concerns and must be
    represented in the bound environment.
    """

    scratchpad: Path
    cwd: Path
    input_relative_paths: Mapping[str, str]
    parser_digest: ParserDigest
    environment: Mapping[str, str]
    environment_allowlist: tuple[str, ...]
    stdin_input_name: str = "prompt"
    phase_roster: Mapping[str, Any] | None = None
    attempt_id: str | None = None
    provider_stdout_evidence_configuration: (
        Mapping[str, Any] | None
    ) = None
    startup_authority_binding: Mapping[str, Any] | None = None
    claude_launch_security_request: Mapping[str, Any] | None = None
    claude_provider_preparation: ClaudeProviderPreparation | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    claude_provider_runtime: BoundClaudeProviderRuntime | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    codex_auth_bytes: bytes | None = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class ExecutionRef:
    """Opaque reference to one terminal, closed, staged execution."""

    run_id: str
    phase: str
    work_unit_id: str
    generation: int
    work_plan_digest: str
    attempt_id: str
    attempt_directory: Path
    attempt_completion_path: Path
    provider_execution: CompletedExecution


@dataclass(frozen=True)
class IncorporationRef:
    """Opaque reference to a completed PhaseIO projection."""

    incorporation_path: Path
    incorporation_digest: str
    execution_ref: ExecutionRef
    projected_paths: tuple[Path, ...]


@dataclass(frozen=True)
class PhaseExecutionStatus:
    """Mechanically reconciled phase work denominator."""

    clean: bool
    completed_with_debt: bool
    incorporated_work_unit_ids: tuple[str, ...]
    debt_work_unit_ids: tuple[str, ...]
    missing_work_unit_ids: tuple[str, ...]
    active_attempt_ids: tuple[str, ...]


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkerTransactionError("transaction JSON is not canonicalizable") from exc


def _json_value(value: Any, label: str) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise WorkerTransactionError(f"{label} must not contain floating-point values")
    if isinstance(value, str):
        if "\x00" in value:
            raise WorkerTransactionError(f"{label} contains NUL")
        return value
    if isinstance(value, (list, tuple)):
        return [_json_value(item, label) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or "\x00" in key:
                raise WorkerTransactionError(f"{label} has an invalid JSON key")
            if key in normalized:
                raise WorkerTransactionError(f"{label} has duplicate JSON keys")
            normalized[key] = _json_value(item, label)
        return {key: normalized[key] for key in sorted(normalized)}
    raise WorkerTransactionError(f"{label} contains a non-JSON value")


def _provider_stdout_evidence_configuration(
    value: Any,
    *,
    provider: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize the exact opt-in Claude stdout policy bound by a WorkPlan.

    This is deliberately not inferred from ``backend == "claude"``.  A caller
    that wants provider stream evidence must supply the complete configuration,
    and the same canonical object must survive plan replay and adapter launch.
    WER remains the final command-contract validator and derives the honest
    platform producer-exclusivity capability at arm time.
    """

    fields = {
        "schema",
        "expected_session_id",
        "expected_init_contract",
        "max_line_bytes",
        "max_stream_bytes",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkerTransactionError(
            "Claude stdout evidence policy has schema drift"
        )
    if value.get("schema") != CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA:
        raise WorkerTransactionError(
            "Claude stdout evidence policy schema is unsupported"
        )
    if (
        provider.get("backend") != "claude"
        or provider.get("transport") != "headless"
    ):
        raise WorkerTransactionError(
            "Claude stdout evidence policy requires a headless Claude provider"
        )

    session_id = value.get("expected_session_id")
    try:
        canonical_session_id = str(uuid.UUID(str(session_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise WorkerTransactionError(
            "Claude stdout evidence policy session ID is invalid"
        ) from exc
    if session_id != canonical_session_id:
        raise WorkerTransactionError(
            "Claude stdout evidence policy session ID is not canonical"
        )

    try:
        expected_init = normalize_expected_init_contract(
            value.get("expected_init_contract")
        )
    except ClaudeStreamJsonEvidenceError as exc:
        raise WorkerTransactionError(
            f"Claude stdout evidence init contract is invalid: {exc}"
        ) from exc

    max_line = value.get("max_line_bytes")
    max_stream = value.get("max_stream_bytes")
    stdout_limit = provider.get("stream_limits", {}).get("stdout_bytes")
    if (
        isinstance(max_line, bool)
        or not isinstance(max_line, int)
        or max_line <= 0
        or max_line > 16 * 1024 * 1024
        or isinstance(max_stream, bool)
        or not isinstance(max_stream, int)
        or max_stream <= max_line
        or max_stream > 64 * 1024 * 1024
        or max_stream != stdout_limit
    ):
        raise WorkerTransactionError(
            "Claude stdout evidence policy ceilings conflict with the "
            "provider stdout limit"
        )
    return {
        "schema": CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
        "expected_session_id": canonical_session_id,
        "expected_init_contract": expected_init,
        "max_line_bytes": max_line,
        "max_stream_bytes": max_stream,
    }


def _auxiliary_startup_permit_binding(
    value: Any,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Normalize the exact durable startup permit carried across transactions.

    This is a structural compiler, not a current-authority replay.  WER owns
    launch-time/current replay and later historical replay of the immutable
    pointer-plus-receipt evidence.  Keeping disk authority out of WorkPlan
    compilation makes plan digesting deterministic while still preventing a
    caller from substituting a different run, epoch, pointer, or receipt.
    """

    fields = {
        "schema",
        "run_id",
        "startup_epoch",
        "current_pointer_sha256",
        "receipt_relative_path",
        "receipt_sha256",
        "allocation_disposition",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkerTransactionError(
            "auxiliary startup permit binding has schema drift"
        )
    normalized = _json_value(
        value,
        "auxiliary startup permit binding",
    )
    if not isinstance(normalized, dict):
        raise WorkerTransactionError(
            "auxiliary startup permit binding must be an object"
        )
    epoch = normalized.get("startup_epoch")
    if (
        normalized.get("schema") != STARTUP_BINDING_SCHEMA
        or normalized.get("run_id") != run_id
        or not isinstance(epoch, str)
        or _STARTUP_EPOCH_RE.fullmatch(epoch) is None
        or normalized.get("allocation_disposition")
        not in {
            "ALLOW_NEW_LEASES",
            "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT",
        }
    ):
        raise WorkerTransactionError(
            "auxiliary startup permit binding is not a permit for this run"
        )
    pointer_digest = _sha256(
        normalized.get("current_pointer_sha256"),
        "auxiliary startup current-pointer digest",
    )
    receipt_digest = _sha256(
        normalized.get("receipt_sha256"),
        "auxiliary startup receipt digest",
    )
    expected_relative = (
        f"{STARTUP_RECEIPT_DIRECTORY_NAME}/"
        f"startup-{epoch}-{receipt_digest}.json"
    )
    if (
        _relative_path(
            normalized.get("receipt_relative_path"),
            "auxiliary startup receipt path",
        )
        != expected_relative
    ):
        raise WorkerTransactionError(
            "auxiliary startup permit receipt path differs from its epoch/digest"
        )
    return {
        "schema": STARTUP_BINDING_SCHEMA,
        "run_id": run_id,
        "startup_epoch": epoch,
        "current_pointer_sha256": pointer_digest,
        "receipt_relative_path": expected_relative,
        "receipt_sha256": receipt_digest,
        "allocation_disposition": normalized["allocation_disposition"],
    }


def _completion_policy_contract(
    value: Mapping[str, Any],
    *,
    run_id: str,
    provider: Mapping[str, Any],
    write_scope: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = _json_value(
        _attempt_independent_value(value, write_scope),
        "worker plan completion_policy",
    )
    if not isinstance(normalized, dict):
        raise WorkerTransactionError(
            "worker plan completion_policy must be an object"
        )
    staged_gate = normalized.get("staged_semantic_gate")
    if staged_gate is not None:
        expected_gate_fields = {
            "schema",
            "callable",
            "implementation_sha256",
            "context",
            "required_input_bindings",
            "binding_sha256",
        }
        if (
            not isinstance(staged_gate, dict)
            or set(staged_gate) != expected_gate_fields
            or staged_gate.get("schema")
            != "plamen.staged_output_semantic_gate.v1"
            or not isinstance(staged_gate.get("callable"), str)
            or not staged_gate["callable"]
            or not isinstance(staged_gate.get("context"), dict)
            or not isinstance(
                staged_gate.get("required_input_bindings"), dict
            )
        ):
            raise WorkerTransactionError(
                "staged semantic validator binding is malformed"
            )
        _sha256(
            staged_gate.get("implementation_sha256"),
            "staged semantic validator implementation digest",
        )
        claimed_gate_digest = _sha256(
            staged_gate.get("binding_sha256"),
            "staged semantic validator binding digest",
        )
        unsigned_gate = {
            key: item
            for key, item in staged_gate.items()
            if key != "binding_sha256"
        }
        if _digest(unsigned_gate) != claimed_gate_digest:
            raise WorkerTransactionError(
                "staged semantic validator binding digest mismatch"
            )
    if CLAUDE_STREAM_STDOUT_POLICY_KEY in normalized:
        normalized[CLAUDE_STREAM_STDOUT_POLICY_KEY] = (
            _provider_stdout_evidence_configuration(
                normalized[CLAUDE_STREAM_STDOUT_POLICY_KEY],
                provider=provider,
            )
        )
    if AUXILIARY_STARTUP_POLICY_KEY in normalized:
        if provider.get("backend") not in {"claude", "codex"}:
            raise WorkerTransactionError(
                "auxiliary startup permit policy requires a model provider"
            )
        normalized[AUXILIARY_STARTUP_POLICY_KEY] = (
            _auxiliary_startup_permit_binding(
                normalized[AUXILIARY_STARTUP_POLICY_KEY],
                run_id=run_id,
            )
        )
    if CLAUDE_LAUNCH_SECURITY_POLICY_KEY in normalized:
        if (
            provider.get("backend") != "claude"
            or provider.get("transport") != "headless"
        ):
            raise WorkerTransactionError(
                "Claude launch-security policy requires a headless Claude provider"
            )
        try:
            claude_security = (
                replay_claude_launch_security(
                    normalized[CLAUDE_LAUNCH_SECURITY_POLICY_KEY]
                )
            )
        except ClaudeLaunchSecurityError as exc:
            raise WorkerTransactionError(
                f"Claude launch-security policy is invalid: {exc}"
            ) from exc
        provider_model = provider.get("model")
        if provider_model not in claude_security["headless_profile"][
            "expected_init_contract"
        ]["accepted_models"]:
            raise WorkerTransactionError(
                "Claude provider model is outside the launch-security "
                "model denominator"
            )
        normalized[CLAUDE_LAUNCH_SECURITY_POLICY_KEY] = claude_security
        if CLAUDE_PROVIDER_PREPARATION_POLICY_KEY not in normalized:
            raise WorkerTransactionError(
                "Claude launch-security policy requires a provider "
                "preparation digest"
            )
    if CLAUDE_PROVIDER_PREPARATION_POLICY_KEY in normalized:
        if (
            provider.get("backend") != "claude"
            or provider.get("transport") != "headless"
            or CLAUDE_LAUNCH_SECURITY_POLICY_KEY not in normalized
        ):
            raise WorkerTransactionError(
                "Claude provider preparation digest requires a headless "
                "Claude launch-security policy"
            )
        normalized[CLAUDE_PROVIDER_PREPARATION_POLICY_KEY] = _sha256(
            normalized[CLAUDE_PROVIDER_PREPARATION_POLICY_KEY],
            "Claude provider preparation digest",
        )
    return {
        key: normalized[key]
        for key in sorted(normalized)
    }


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise WorkerTransactionError(f"{label} has an invalid identifier shape")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX_RE.fullmatch(value):
        raise WorkerTransactionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WorkerTransactionError("generation must be a positive integer")
    return value


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise WorkerTransactionError(f"{label} must be non-empty canonical text")
    text = value.replace("\\", "/")
    candidate = Path(text)
    parts = text.split("/")
    if (
        candidate.is_absolute()
        or text.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part for part in parts)
        or "\x00" in text
    ):
        raise WorkerTransactionError(f"{label} is not a safe relative path")
    return "/".join(parts)


def _id_denominator(values: Sequence[str], label: str) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise WorkerTransactionError(f"{label} must be an ordered ID sequence")
    normalized = [_identifier(item, f"{label} member") for item in values]
    if len({item.casefold() for item in normalized}) != len(normalized):
        raise WorkerTransactionError(f"{label} contains duplicate/case-colliding IDs")
    return sorted(normalized)


def compile_phase_work_roster_denominator(
    *,
    run_id: str,
    phase: str,
    generation: int,
    required_work_unit_ids: Sequence[str],
    optional_work_unit_ids: Sequence[str] = (),
    aggregation_predicate: str = ALL_REQUIRED_INCORPORATED,
) -> dict[str, Any]:
    """Freeze the non-cyclic logical roster before provider plans are compiled."""

    required = _id_denominator(required_work_unit_ids, "required_work_unit_ids")
    optional = _id_denominator(optional_work_unit_ids, "optional_work_unit_ids")
    if not required:
        raise WorkerTransactionError("a phase roster requires at least one required unit")
    overlap = {item.casefold() for item in required} & {
        item.casefold() for item in optional
    }
    if overlap:
        raise WorkerTransactionError("required and optional work-unit IDs overlap")
    if aggregation_predicate != ALL_REQUIRED_INCORPORATED:
        raise WorkerTransactionError("aggregation predicate is unsupported")
    payload: dict[str, Any] = {
        "schema": PHASE_WORK_ROSTER_SCHEMA,
        "run_id": _identifier(run_id, "run_id"),
        "phase": _identifier(phase, "phase"),
        "generation": _generation(generation),
        "required_work_unit_ids": required,
        "optional_work_unit_ids": optional,
        "aggregation_predicate": ALL_REQUIRED_INCORPORATED,
    }
    payload["roster_denominator_digest"] = _digest(payload)
    return payload


def compile_phase_work_roster(
    *,
    run_id: str,
    phase: str,
    generation: int,
    required_work_unit_ids: Sequence[str],
    optional_work_unit_ids: Sequence[str] = (),
    work_plan_digests: Mapping[str, str],
    aggregation_predicate: str = ALL_REQUIRED_INCORPORATED,
) -> dict[str, Any]:
    """Compile one strict, backend-neutral phase denominator.

    Work-plan digests may differ across provider plans.  Provider/model/transport
    fields are intentionally absent from the roster so Claude and Codex execute
    the same logical required/optional denominator.
    """

    denominator = compile_phase_work_roster_denominator(
        run_id=run_id,
        phase=phase,
        generation=generation,
        required_work_unit_ids=required_work_unit_ids,
        optional_work_unit_ids=optional_work_unit_ids,
        aggregation_predicate=aggregation_predicate,
    )
    required = list(denominator["required_work_unit_ids"])
    optional = list(denominator["optional_work_unit_ids"])
    if not isinstance(work_plan_digests, Mapping):
        raise WorkerTransactionError("work_plan_digests must be an exact mapping")

    expected = required + optional
    if set(work_plan_digests) != set(expected):
        raise WorkerTransactionError(
            "work_plan_digests keys do not equal the roster denominator"
        )
    plans = {
        unit: _sha256(work_plan_digests[unit], f"work plan digest for {unit}")
        for unit in sorted(expected)
    }
    payload = dict(denominator)
    # A WorkPlan cannot bind the final roster digest while the final roster
    # simultaneously binds that WorkPlan's digest.  Freeze and expose the
    # backend-neutral denominator digest first, then bind provider-specific plan
    # digests into the final roster digest.
    payload["work_plan_digests"] = plans
    payload["roster_digest"] = _digest(payload)
    return payload


def _validate_phase_roster(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema",
        "run_id",
        "phase",
        "generation",
        "required_work_unit_ids",
        "optional_work_unit_ids",
        "aggregation_predicate",
        "roster_denominator_digest",
        "work_plan_digests",
        "roster_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise WorkerTransactionError("phase work roster has schema drift")
    roster = _json_value(value, "phase work roster")
    claimed = _sha256(roster["roster_digest"], "roster digest")
    unsigned = {key: item for key, item in roster.items() if key != "roster_digest"}
    if _digest(unsigned) != claimed:
        raise WorkerTransactionError("phase work roster digest mismatch")
    denominator = compile_phase_work_roster_denominator(
        run_id=roster["run_id"],
        phase=roster["phase"],
        generation=roster["generation"],
        required_work_unit_ids=roster["required_work_unit_ids"],
        optional_work_unit_ids=roster["optional_work_unit_ids"],
        aggregation_predicate=roster["aggregation_predicate"],
    )
    if roster["roster_denominator_digest"] != denominator[
        "roster_denominator_digest"
    ]:
        raise WorkerTransactionError("phase roster denominator digest mismatch")
    expected_units = (
        roster["required_work_unit_ids"] + roster["optional_work_unit_ids"]
    )
    if (
        not isinstance(roster["work_plan_digests"], dict)
        or set(roster["work_plan_digests"]) != set(expected_units)
    ):
        raise WorkerTransactionError("phase roster plan denominator mismatch")
    for unit, digest in roster["work_plan_digests"].items():
        _identifier(unit, "roster work-unit ID")
        _sha256(digest, "roster work-plan digest")
    return roster


def _replace_attempt_scope_values(
    value: str,
    write_scope: Mapping[str, Any],
) -> str:
    """Replace concrete attempt identity/path fragments with stable tokens."""

    text = str(value)
    replacements = (
        (
            str(write_scope.get("output_relative_path") or ""),
            ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER,
        ),
        (
            str(write_scope.get("attempt_relative_path") or ""),
            ATTEMPT_RELATIVE_PATH_PLACEHOLDER,
        ),
        (
            str(write_scope.get("attempt_id") or ""),
            ATTEMPT_ID_PLACEHOLDER,
        ),
    )
    for concrete, placeholder in replacements:
        if concrete:
            text = text.replace(concrete.replace("\\", "/"), placeholder)
            text = text.replace(concrete.replace("/", "\\"), placeholder)
            text = text.replace(concrete, placeholder)
    return text


def _attempt_independent_value(
    value: Any,
    write_scope: Mapping[str, Any],
) -> Any:
    if isinstance(value, str):
        return _replace_attempt_scope_values(value, write_scope)
    if isinstance(value, list):
        return [
            _attempt_independent_value(item, write_scope)
            for item in value
        ]
    if isinstance(value, tuple):
        return [
            _attempt_independent_value(item, write_scope)
            for item in value
        ]
    if isinstance(value, Mapping):
        return {
            key: _attempt_independent_value(item, write_scope)
            for key, item in value.items()
        }
    return value


def _write_scope_template(
    value: Mapping[str, Any],
    *,
    run_id: str,
    phase: str,
    work_unit_id: str,
) -> dict[str, Any]:
    """Normalize an attempt scope to its attempt-independent v2 template."""

    if not isinstance(value, Mapping):
        raise WorkerTransactionError("worker plan write scope must be a mapping")
    canonical_template = compile_attempt_write_scope_template(
        run_id=run_id,
        phase=phase,
        work_unit_id=work_unit_id,
    )
    if dict(value) == canonical_template:
        return canonical_template
    if value.get("kind") != "ATTEMPT_OUTPUT_ONLY":
        normalized = _json_value(
            value, "worker plan transitional write scope"
        )
        if normalized != {
            "mode": "ATTEMPT_ONLY",
            "roots": ["output"],
        }:
            raise WorkerTransactionError(
                "worker plan write scope template is unsupported"
            )
        return canonical_template
    expected = compile_attempt_write_scope(
        run_id=run_id,
        phase=phase,
        work_unit_id=work_unit_id,
        attempt_id=str(value.get("attempt_id") or ""),
    )
    if dict(value) != expected:
        raise WorkerTransactionError(
            "worker plan attempt scope is internally inconsistent"
        )
    return canonical_template


def _provider_contract(
    value: Mapping[str, Any],
    *,
    schema: str = WORKER_WORK_PLAN_SCHEMA_V1,
    write_scope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkerTransactionError("provider must be an exact mapping")
    shared = {
        "backend",
        "model",
        "transport",
        "resolved_executable",
        "executable_sha256",
        "environment_allowlist_digest",
        "timeout_seconds",
        "stream_limits",
    }
    if schema == WORKER_WORK_PLAN_SCHEMA_V2:
        if set(value) == shared | {"argv"}:
            raw_argv = value["argv"]
        elif set(value) == shared | {"argv_template"}:
            raw_argv = value["argv_template"]
        else:
            raise WorkerTransactionError("provider contract has schema drift")
    else:
        expected = shared | {"argv"}
        if set(value) != expected:
            raise WorkerTransactionError("provider contract has schema drift")
        raw_argv = value["argv"]
    backend = value["backend"]
    transport = value["transport"]
    if backend not in {"claude", "codex", "native"}:
        raise WorkerTransactionError("provider backend is unsupported")
    allowed_transports = {
        "claude": {"pty", "headless"},
        "codex": {"exec", "headless"},
        "native": {"native"},
    }
    if transport not in allowed_transports[backend]:
        raise WorkerTransactionError("provider backend/transport pairing is unsupported")
    model = value["model"]
    if not isinstance(model, str) or not model or model != model.strip() or "\x00" in model:
        raise WorkerTransactionError("provider model is invalid")
    executable = value["resolved_executable"]
    if (
        not isinstance(executable, str)
        or not executable
        or "\x00" in executable
        or not (
            executable.startswith("/")
            or executable.startswith("\\\\")
            or re.match(r"^[A-Za-z]:[\\/]", executable)
        )
    ):
        raise WorkerTransactionError("provider executable must be an absolute path")
    argv = raw_argv
    if (
        not isinstance(argv, (list, tuple))
        or not argv
        or any(
            not isinstance(item, str) or not item or "\x00" in item
            for item in argv
        )
    ):
        raise WorkerTransactionError("provider argv must be a non-empty string vector")
    timeout = value["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise WorkerTransactionError("provider timeout_seconds must be a positive integer")
    limits = value["stream_limits"]
    if (
        not isinstance(limits, Mapping)
        or set(limits) != {"stdout_bytes", "stderr_bytes", "staged_member_bytes"}
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in limits.values()
        )
    ):
        raise WorkerTransactionError("provider stream limits are malformed")
    result = {
        "backend": backend,
        "model": model,
        "transport": transport,
        "resolved_executable": executable,
        "executable_sha256": _sha256(
            value["executable_sha256"], "provider executable digest"
        ),
        "environment_allowlist_digest": _sha256(
            value["environment_allowlist_digest"],
            "provider environment allowlist digest",
        ),
        "timeout_seconds": timeout,
        "stream_limits": {
            name: int(limits[name])
            for name in ("stdout_bytes", "stderr_bytes", "staged_member_bytes")
        },
    }
    if schema == WORKER_WORK_PLAN_SCHEMA_V2:
        if write_scope is None:
            raise WorkerTransactionError(
                "v2 provider requires a write-scope template source"
            )
        result["argv_template"] = [
            _replace_attempt_scope_values(item, write_scope)
            for item in argv
        ]
        serialized = json.dumps(
            result["argv_template"],
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        if re.search(r"attempt-[0-9a-f]{24}", serialized):
            raise WorkerTransactionError(
                "provider argv template retains a concrete attempt identity"
            )
    else:
        result["argv"] = list(argv)
    return result


def _assignment_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"assignment_id", "members"}:
        raise WorkerTransactionError("assignment contract has schema drift")
    members = value["members"]
    if not isinstance(members, (list, tuple)) or not members:
        raise WorkerTransactionError("assignment must contain at least one member")
    normalized: list[dict[str, Any]] = []
    expected_member_keys = {
        "staged_relative_path",
        "canonical_identity",
        "parser_binding",
        "projection_mode",
        "canonical_prestate",
    }
    for member in members:
        if not isinstance(member, Mapping) or set(member) != expected_member_keys:
            raise WorkerTransactionError("assignment member has schema drift")
        identity = member["canonical_identity"]
        if not isinstance(identity, str) or not identity.startswith("scratchpad:"):
            raise WorkerTransactionError(
                "assignment canonical identity must use scratchpad: authority"
            )
        identity_path = _relative_path(
            identity.removeprefix("scratchpad:"),
            "assignment canonical identity path",
        )
        parser = member["parser_binding"]
        if not isinstance(parser, Mapping) or not parser:
            raise WorkerTransactionError("assignment parser binding must be non-empty")
        prestate = member["canonical_prestate"]
        if not isinstance(prestate, Mapping) or not prestate:
            raise WorkerTransactionError("assignment canonical prestate must be non-empty")
        mode = member["projection_mode"]
        if mode not in {"CREATE_ABSENT", "REPLACE_EXACT_PRESTATE"}:
            raise WorkerTransactionError("assignment projection mode is unsupported")
        normalized.append(
            {
                "staged_relative_path": _relative_path(
                    member["staged_relative_path"],
                    "assignment staged path",
                ),
                "canonical_identity": f"scratchpad:{identity_path}",
                "parser_binding": _json_value(parser, "assignment parser binding"),
                "projection_mode": mode,
                "canonical_prestate": _json_value(
                    prestate, "assignment canonical prestate"
                ),
            }
        )
    staged = [row["staged_relative_path"].casefold() for row in normalized]
    canonical = [row["canonical_identity"].casefold() for row in normalized]
    if len(set(staged)) != len(staged) or len(set(canonical)) != len(canonical):
        raise WorkerTransactionError("assignment members collide by path or identity")
    normalized.sort(
        key=lambda row: (row["staged_relative_path"], row["canonical_identity"])
    )
    return {
        "assignment_id": _identifier(value["assignment_id"], "assignment_id"),
        "members": normalized,
    }


def compile_worker_plan(
    *,
    run_id: str,
    phase: str,
    work_unit_id: str,
    generation: int,
    phase_roster_denominator_digest: str,
    phase_io_contract_digest: str,
    phase_io_launch_digest: str,
    phase_io_input_set_digest: str,
    prompt_sha256: str | None = None,
    prompt_template_sha256: str | None = None,
    methodology_digests: Sequence[str],
    source_snapshot_digest: str,
    provider: Mapping[str, Any],
    assignment: Mapping[str, Any],
    write_scope: Mapping[str, Any],
    child_denominator: Mapping[str, Any],
    completion_policy: Mapping[str, Any],
    retry_policy: Mapping[str, Any],
    terminal_debt_policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Compile one attempt-independent provider plan for a logical work unit.

    ``prompt_sha256`` remains a source-compatible alias for callers whose
    prompt is already attempt independent.  New launchers should pass
    ``prompt_template_sha256`` explicitly.  The persisted v2 record contains
    only the template digest.
    """

    if isinstance(methodology_digests, (str, bytes)) or not isinstance(
        methodology_digests, Sequence
    ):
        raise WorkerTransactionError("methodology_digests must be a digest sequence")
    methods = sorted(
        _sha256(item, "methodology digest") for item in methodology_digests
    )
    if len(set(methods)) != len(methods):
        raise WorkerTransactionError("methodology_digests contains duplicates")
    if prompt_sha256 is not None and prompt_template_sha256 is not None:
        raise WorkerTransactionError(
            "supply prompt_template_sha256, not two prompt digest authorities"
        )
    prompt_template = (
        prompt_template_sha256
        if prompt_template_sha256 is not None
        else prompt_sha256
    )
    if prompt_template is None:
        raise WorkerTransactionError("prompt template digest is required")
    run = _identifier(run_id, "run_id")
    phase_id = _identifier(phase, "phase")
    unit = _identifier(work_unit_id, "work_unit_id")
    scope_template = _write_scope_template(
        write_scope,
        run_id=run,
        phase=phase_id,
        work_unit_id=unit,
    )
    policy_values = {
        "child_denominator": child_denominator,
        "completion_policy": completion_policy,
        "retry_policy": retry_policy,
        "terminal_debt_policy": terminal_debt_policy,
    }
    if any(not isinstance(value, Mapping) for value in policy_values.values()):
        raise WorkerTransactionError("worker plan policies must be mappings")
    provider_contract = _provider_contract(
        provider,
        schema=WORKER_WORK_PLAN_SCHEMA_V2,
        write_scope=write_scope,
    )
    normalized_policies = {
        name: (
            _completion_policy_contract(
                value,
                run_id=run,
                provider=provider_contract,
                write_scope=write_scope,
            )
            if name == "completion_policy"
            else _json_value(
                _attempt_independent_value(value, write_scope),
                f"worker plan {name}",
            )
        )
        for name, value in policy_values.items()
    }
    payload: dict[str, Any] = {
        "schema": WORKER_WORK_PLAN_SCHEMA_V2,
        "run_id": run,
        "phase": phase_id,
        "work_unit_id": unit,
        "generation": _generation(generation),
        "phase_roster_denominator_digest": _sha256(
            phase_roster_denominator_digest,
            "phase roster denominator digest",
        ),
        "phase_io_contract_digest": _sha256(
            phase_io_contract_digest, "PhaseIO contract digest"
        ),
        "phase_io_launch_digest": _sha256(
            phase_io_launch_digest, "PhaseIO launch digest"
        ),
        "phase_io_input_set_digest": _sha256(
            phase_io_input_set_digest, "PhaseIO input-set digest"
        ),
        "prompt_template_sha256": _sha256(
            prompt_template, "prompt template digest"
        ),
        "methodology_digests": methods,
        "source_snapshot_digest": _sha256(
            source_snapshot_digest, "source snapshot digest"
        ),
        "provider": provider_contract,
        "assignment": _assignment_contract(assignment),
        "write_scope_template": scope_template,
        **normalized_policies,
    }
    payload["work_plan_digest"] = _digest(payload)
    return payload


def compile_attempt_write_scope_template(
    *,
    run_id: str,
    phase: str,
    work_unit_id: str,
) -> dict[str, Any]:
    """Compile the stable v2 scope template shared by every retry."""

    run = _identifier(run_id, "run_id")
    phase_id = _identifier(phase, "phase")
    unit = _identifier(work_unit_id, "work_unit_id")
    relative = f"{phase_id}/{unit}/attempts/{ATTEMPT_ID_PLACEHOLDER}"
    return {
        "kind": "ATTEMPT_OUTPUT_ONLY",
        "run_id": run,
        "phase": phase_id,
        "work_unit_id": unit,
        "attempt_id": ATTEMPT_ID_PLACEHOLDER,
        "attempt_relative_path": relative,
        "output_relative_path": f"{relative}/output",
    }


def compile_attempt_write_scope(
    *,
    run_id: str,
    phase: str,
    work_unit_id: str,
    attempt_id: str | None = None,
) -> dict[str, Any]:
    """Compile the non-cyclic attempt path used while rendering a prompt.

    The path deliberately omits the WorkPlan digest: a model prompt must name
    its output lane before the prompt digest can be included in the WorkPlan.
    The final plan binds this exact scope, and execution refuses a collision.
    """

    run = _identifier(run_id, "run_id")
    phase_id = _identifier(phase, "phase")
    unit = _identifier(work_unit_id, "work_unit_id")
    identity = (
        attempt_id
        if attempt_id is not None
        else f"attempt-{uuid.uuid4().hex[:24]}"
    )
    if not isinstance(identity, str) or not re.fullmatch(
        r"attempt-[0-9a-f]{24}", identity
    ):
        raise WorkerTransactionError("attempt_id has an invalid shape")
    relative = f"{phase_id}/{unit}/attempts/{identity}"
    return {
        "kind": "ATTEMPT_OUTPUT_ONLY",
        "run_id": run,
        "phase": phase_id,
        "work_unit_id": unit,
        "attempt_id": identity,
        "attempt_relative_path": relative,
        "output_relative_path": f"{relative}/output",
    }


def prompt_template_sha256(raw: bytes) -> str:
    """Digest exact immutable prompt-template bytes."""

    if not isinstance(raw, bytes):
        raise WorkerTransactionError("prompt template must be exact bytes")
    return hashlib.sha256(raw).hexdigest()


def _materialize_template_text(
    value: str,
    *,
    scratchpad: Path,
    write_scope: Mapping[str, Any],
) -> str:
    output_path = (
        scratchpad
        / ".worker_transactions"
        / str(write_scope["output_relative_path"])
    )
    # This placeholder is used in physical provider argv (for example,
    # Codex's output-file switch). Preserve the prompt's separately-rendered
    # relative route, but give Windows providers the native extended-length
    # spelling so retry lanes are not capped by legacy MAX_PATH parsing.
    output_directory = (
        _native_rooted_path(output_path)
        if os.name == "nt"
        else output_path.as_posix()
    )
    replacements = {
        ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER: output_directory,
        ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER: str(
            write_scope["output_relative_path"]
        ),
        ATTEMPT_RELATIVE_PATH_PLACEHOLDER: str(
            write_scope["attempt_relative_path"]
        ),
        ATTEMPT_ID_PLACEHOLDER: str(write_scope["attempt_id"]),
    }
    materialized = str(value)
    for placeholder, actual in replacements.items():
        materialized = materialized.replace(placeholder, actual)
    if any(token in materialized for token in replacements):
        raise WorkerTransactionError(
            "attempt template retains an unresolved placeholder"
        )
    return materialized


def _argv_sha256(argv: Sequence[str]) -> str:
    return argv_authority_sha256(argv)


def attempt_output_directory(
    scratchpad: Path,
    write_scope: Mapping[str, Any],
) -> Path:
    """Resolve a compiled attempt lane without creating or trusting it."""

    if not isinstance(write_scope, Mapping) or set(write_scope) != {
        "kind",
        "run_id",
        "phase",
        "work_unit_id",
        "attempt_id",
        "attempt_relative_path",
        "output_relative_path",
    }:
        raise WorkerTransactionError("attempt write scope has schema drift")
    expected = compile_attempt_write_scope(
        run_id=str(write_scope["run_id"]),
        phase=str(write_scope["phase"]),
        work_unit_id=str(write_scope["work_unit_id"]),
        attempt_id=str(write_scope["attempt_id"]),
    )
    if dict(write_scope) != expected:
        raise WorkerTransactionError("attempt write scope is internally inconsistent")
    root = _checked_root_directory(
        scratchpad,
        label="adapter scratchpad",
    )
    relative = _relative_path(
        write_scope["output_relative_path"], "attempt output path"
    )
    return root / ".worker_transactions" / relative


def _is_reparse(path: Path) -> bool:
    return _rooted_io.is_reparse(path)


def _native_rooted_path(path: str | Path) -> str:
    try:
        return _rooted_io.native_path(path)
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerTransactionError(str(exc)) from exc


def _rooted_lstat(path: str | Path) -> os.stat_result:
    return _rooted_io.lstat(path)


def _rooted_lexists(path: str | Path) -> bool:
    return _rooted_io.lexists(path)


def _rooted_is_symlink(path: str | Path) -> bool:
    return _rooted_io.is_symlink(path)


def _rooted_is_file(path: str | Path) -> bool:
    return _rooted_io.is_file(path)


def _rooted_is_dir(path: str | Path) -> bool:
    return _rooted_io.is_dir(path)


def _read_rooted_bytes(path: str | Path) -> bytes:
    try:
        return _rooted_io.read_bytes(
            path,
            label="worker transaction file",
            verify_ancestors=False,
            verify_exact_name=False,
        )
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerTransactionError(str(exc)) from exc


def _unlink_rooted(path: str | Path) -> None:
    _rooted_io.unlink(path)


def _mkdir_rooted(path: str | Path) -> None:
    _rooted_io.mkdir(path)


def _checked_root_directory(path: str | Path, *, label: str) -> Path:
    try:
        return _rooted_io.checked_directory(
            path,
            label=label,
            verify_ancestors=False,
        )
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerTransactionError(str(exc)) from exc


def _safe_directory(path: Path, label: str) -> Path:
    try:
        return _rooted_io.checked_directory(
            path,
            label=label,
            verify_ancestors=False,
        )
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerTransactionError(str(exc)) from exc


def _safe_file(path: Path, label: str) -> Path:
    try:
        return _rooted_io.checked_file(
            path,
            label=label,
            require_single_link=True,
            verify_ancestors=False,
        )
    except _rooted_io.RootedPathIOError as exc:
        raise WorkerTransactionError(str(exc)) from exc


def staged_output_validator_binding(
    validator: StagedOutputValidator,
    *,
    context: Mapping[str, Any],
    required_input_bindings: Mapping[str, Mapping[str, Any]],
    write_scope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind one source-backed semantic gate and its exact input denominator."""

    if not callable(validator):
        raise WorkerTransactionError("staged output validator is not callable")
    module = str(getattr(validator, "__module__", "") or "")
    name = str(getattr(validator, "__qualname__", "") or "")
    if not module or not name or "<locals>" in name:
        raise WorkerTransactionError(
            "staged output validator must be a top-level source-backed callable"
        )
    try:
        source = Path(inspect.getsourcefile(validator) or "").resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkerTransactionError(
            "staged output validator source cannot be resolved"
        ) from exc
    _safe_file(source, "staged output validator source")
    normalized_context = _json_value(context, "staged output validator context")
    if not isinstance(normalized_context, dict):
        raise WorkerTransactionError(
            "staged output validator context must be a mapping"
        )
    if write_scope is not None:
        if not isinstance(write_scope, Mapping):
            raise WorkerTransactionError(
                "staged output validator write scope must be a mapping"
            )
        scope = dict(write_scope)
        try:
            if scope.get("attempt_id") == ATTEMPT_ID_PLACEHOLDER:
                expected_scope = compile_attempt_write_scope_template(
                    run_id=str(scope.get("run_id") or ""),
                    phase=str(scope.get("phase") or ""),
                    work_unit_id=str(scope.get("work_unit_id") or ""),
                )
            else:
                expected_scope = compile_attempt_write_scope(
                    run_id=str(scope.get("run_id") or ""),
                    phase=str(scope.get("phase") or ""),
                    work_unit_id=str(scope.get("work_unit_id") or ""),
                    attempt_id=str(scope.get("attempt_id") or ""),
                )
        except (TypeError, ValueError) as exc:
            raise WorkerTransactionError(
                "staged output validator write scope is malformed"
            ) from exc
        if scope != expected_scope:
            raise WorkerTransactionError(
                "staged output validator write scope is non-canonical"
            )
        normalized_context = _json_value(
            _attempt_independent_value(normalized_context, scope),
            "attempt-independent staged output validator context",
        )
        if re.search(
            r"attempt-[0-9a-f]{24}",
            json.dumps(
                normalized_context,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        ):
            raise WorkerTransactionError(
                "staged output validator context retains a concrete attempt identity"
            )
    if not isinstance(required_input_bindings, Mapping):
        raise WorkerTransactionError(
            "staged output validator input bindings must be a mapping"
        )
    normalized_inputs: dict[str, dict[str, Any]] = {}
    allowed_fields = {
        "identity",
        "status",
        "size",
        "sha256",
        "producer_work_unit_key",
        "producer_contract_digest",
    }
    for identity, raw in sorted(required_input_bindings.items()):
        if (
            not isinstance(identity, str)
            or not identity.startswith(("scratchpad:", "project:"))
            or not isinstance(raw, Mapping)
        ):
            raise WorkerTransactionError(
                "staged output validator input binding is malformed"
            )
        row = {
            field: raw.get(field)
            for field in allowed_fields
        }
        if (
            row["identity"] != identity
            or row["status"] != "ACTIVE"
            or not isinstance(row["size"], int)
            or row["size"] < 0
            or not isinstance(row["sha256"], str)
            or not _HEX_RE.fullmatch(row["sha256"])
            or not isinstance(row["producer_work_unit_key"], str)
            or not isinstance(row["producer_contract_digest"], str)
        ):
            raise WorkerTransactionError(
                "staged output validator input authority is not ACTIVE"
            )
        normalized_inputs[identity] = row
    binding: dict[str, Any] = {
        "schema": "plamen.staged_output_semantic_gate.v1",
        "callable": f"{module}:{name}",
        "implementation_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "context": normalized_context,
        "required_input_bindings": normalized_inputs,
    }
    binding["binding_sha256"] = hashlib.sha256(
        _canonical_bytes(binding)
    ).hexdigest()
    return binding


def _children(directory: Path) -> list[Path]:
    try:
        return sorted(
            (
                directory / entry.name
                for entry in os.scandir(_native_rooted_path(directory))
            ),
            key=lambda p: p.name,
        )
    except OSError as exc:
        raise WorkerTransactionError(f"cannot enumerate transaction directory {directory}") from exc


def _read_json(path: Path, label: str) -> dict[str, Any]:
    _safe_file(path, label)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise WorkerTransactionError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            _read_rooted_bytes(path).decode("utf-8"),
            object_pairs_hook=pairs,
        )
    except WorkerTransactionError:
        raise
    except Exception as exc:
        raise WorkerTransactionError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise WorkerTransactionError(f"{label} must be a JSON object")
    return parsed


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_absent_json(path: Path, payload: Mapping[str, Any]) -> None:
    raw = _canonical_bytes(payload) + b"\n"
    try:
        descriptor = os.open(
            _native_rooted_path(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError as exc:
        raise WorkerTransactionError(f"terminal transaction artifact already exists: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
    except BaseException:
        try:
            _unlink_rooted(path)
        except OSError:
            pass
        raise


def _make_safe_directory_tree(root: Path, relative: str) -> Path:
    current = _safe_directory(root, "directory root")
    for part in _relative_path(relative, "directory path").split("/"):
        child = current / part
        if _rooted_lexists(child):
            _safe_directory(child, "transaction directory")
        else:
            try:
                _mkdir_rooted(child)
                _fsync_directory(current)
            except FileExistsError:
                # Sibling worker attempts share phase/unit ancestors.  A
                # concurrent creator winning this race is valid only when
                # the resulting object is still a regular directory.
                pass
            _safe_directory(child, "transaction directory")
        current = child
    return current


def _safe_relative_file(root: Path, relative: str, label: str) -> Path:
    current = _safe_directory(root, "scratchpad")
    parts = _relative_path(relative, label).split("/")
    for index, part in enumerate(parts):
        child = current / part
        if index < len(parts) - 1:
            current = _safe_directory(child, label)
        else:
            return _safe_file(child, label)
    raise WorkerTransactionError(f"{label} is invalid")


def _validate_compiled_plan(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkerTransactionError("work plan must be a mapping")
    plan = _json_value(value, "work plan")
    if not isinstance(plan, dict) or plan.get("schema") not in {
        WORKER_WORK_PLAN_SCHEMA_V1,
        WORKER_WORK_PLAN_SCHEMA_V2,
    }:
        raise WorkerTransactionError("work plan schema is unsupported")
    schema = plan["schema"]
    if schema == WORKER_WORK_PLAN_SCHEMA_V2:
        expected = {
            "schema",
            "run_id",
            "phase",
            "work_unit_id",
            "generation",
            "phase_roster_denominator_digest",
            "phase_io_contract_digest",
            "phase_io_launch_digest",
            "phase_io_input_set_digest",
            "prompt_template_sha256",
            "methodology_digests",
            "source_snapshot_digest",
            "provider",
            "assignment",
            "write_scope_template",
            "child_denominator",
            "completion_policy",
            "retry_policy",
            "terminal_debt_policy",
            "work_plan_digest",
        }
        if set(plan) != expected:
            raise WorkerTransactionError("work plan v2 has schema drift")
    claimed = _sha256(plan.get("work_plan_digest"), "work plan digest")
    unsigned = {key: item for key, item in plan.items() if key != "work_plan_digest"}
    if _digest(unsigned) != claimed:
        raise WorkerTransactionError("work plan digest mismatch")
    _identifier(plan.get("run_id"), "work plan run_id")
    _identifier(plan.get("phase"), "work plan phase")
    _identifier(plan.get("work_unit_id"), "work plan work_unit_id")
    _generation(plan.get("generation"))
    # Re-run the nested strict validators; persisted JSON cannot bypass the
    # compiler merely by carrying a self-consistent digest.
    provider = _provider_contract(
        plan.get("provider"),
        schema=schema,
        write_scope=plan.get("write_scope_template"),
    )
    if provider != plan.get("provider"):
        raise WorkerTransactionError("work plan provider is non-canonical")
    if _assignment_contract(plan.get("assignment")) != plan.get("assignment"):
        raise WorkerTransactionError("work plan assignment is non-canonical")
    if schema == WORKER_WORK_PLAN_SCHEMA_V2:
        _sha256(
            plan.get("phase_roster_denominator_digest"),
            "phase roster denominator digest",
        )
        _sha256(
            plan.get("prompt_template_sha256"),
            "prompt template digest",
        )
        expected_scope = compile_attempt_write_scope_template(
            run_id=plan["run_id"],
            phase=plan["phase"],
            work_unit_id=plan["work_unit_id"],
        )
        raw_scope = plan.get("write_scope_template")
        if (
            isinstance(raw_scope, Mapping)
            and raw_scope.get("kind") == "ATTEMPT_OUTPUT_ONLY"
            and raw_scope != expected_scope
        ):
            raise WorkerTransactionError(
                "work plan write-scope template is non-canonical"
            )
        recompiled = compile_worker_plan(
            run_id=plan["run_id"],
            phase=plan["phase"],
            work_unit_id=plan["work_unit_id"],
            generation=plan["generation"],
            phase_roster_denominator_digest=plan[
                "phase_roster_denominator_digest"
            ],
            phase_io_contract_digest=plan["phase_io_contract_digest"],
            phase_io_launch_digest=plan["phase_io_launch_digest"],
            phase_io_input_set_digest=plan["phase_io_input_set_digest"],
            prompt_template_sha256=plan["prompt_template_sha256"],
            methodology_digests=plan["methodology_digests"],
            source_snapshot_digest=plan["source_snapshot_digest"],
            provider=plan["provider"],
            assignment=plan["assignment"],
            write_scope=plan["write_scope_template"],
            child_denominator=plan["child_denominator"],
            completion_policy=plan["completion_policy"],
            retry_policy=plan["retry_policy"],
            terminal_debt_policy=plan["terminal_debt_policy"],
        )
        if recompiled != plan:
            raise WorkerTransactionError("work plan v2 is non-canonical")
    return plan


def validate_work_plan_phase_roster(
    plan: Mapping[str, Any],
    roster: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate exact final-roster ownership for one immutable WorkPlan."""

    compiled = _validate_compiled_plan(plan)
    bound = _validate_phase_roster(roster)
    for field in ("run_id", "phase", "generation"):
        if compiled[field] != bound[field]:
            raise WorkerTransactionError(
                f"WorkPlan and phase roster {field} differ"
            )
    if (
        compiled.get("phase_roster_denominator_digest")
        != bound["roster_denominator_digest"]
    ):
        raise WorkerTransactionError(
            "WorkPlan and phase roster denominator differ"
        )
    unit = compiled["work_unit_id"]
    if unit not in bound["work_plan_digests"]:
        raise WorkerTransactionError(
            "WorkPlan is a foreign work unit for the final phase roster"
        )
    if bound["work_plan_digests"][unit] != compiled["work_plan_digest"]:
        raise WorkerTransactionError(
            "WorkPlan digest does not match the final phase roster"
        )
    return bound


def validate_phase_work_roster(
    roster: Mapping[str, Any],
) -> dict[str, Any]:
    """Public strict loader for a final phase roster."""

    return _validate_phase_roster(roster)


def _singleton_phase_roster_for_plan(
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Build only the one-unit roster whose denominator the plan already binds."""

    compiled = _validate_compiled_plan(plan)
    unit = compiled["work_unit_id"]
    denominator = compile_phase_work_roster_denominator(
        run_id=compiled["run_id"],
        phase=compiled["phase"],
        generation=compiled["generation"],
        required_work_unit_ids=(unit,),
    )
    if (
        denominator["roster_denominator_digest"]
        != compiled["phase_roster_denominator_digest"]
    ):
        raise WorkerTransactionError(
            "a final multi-unit phase roster is required before launch"
        )
    return compile_phase_work_roster(
        run_id=compiled["run_id"],
        phase=compiled["phase"],
        generation=compiled["generation"],
        required_work_unit_ids=(unit,),
        work_plan_digests={unit: compiled["work_plan_digest"]},
    )


def _cancel_requested(token: Any) -> bool:
    if token is None:
        return False
    if callable(token):
        return bool(token())
    is_set = getattr(token, "is_set", None)
    if callable(is_set):
        return bool(is_set())
    raise WorkerTransactionError("cancel_token must be callable or Event-like")


@contextlib.contextmanager
def _registry_lock(directory: Path, timeout_seconds: float = 10.0) -> Iterator[None]:
    lock = directory / "active_attempts.lock"
    handle = open(lock, "a+b")
    try:
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"0")
            handle.flush()
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise WorkerTransactionError("active-attempt registry lock timed out")
                time.sleep(0.01)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _active_registry(directory: Path) -> dict[str, Any]:
    path = directory / "active_attempts.json"
    if not _rooted_lexists(path):
        payload: dict[str, Any] = {
            "schema": "plamen.worker_active_attempts.v1",
            "attempts": {},
        }
        payload["registry_digest"] = _digest(payload)
        return payload
    value = _read_json(path, "active-attempt registry")
    if set(value) != {"schema", "attempts", "registry_digest"}:
        raise WorkerTransactionError("active-attempt registry has schema drift")
    if value["schema"] != "plamen.worker_active_attempts.v1":
        raise WorkerTransactionError("active-attempt registry schema is unsupported")
    claimed = _sha256(value["registry_digest"], "active registry digest")
    unsigned = {key: item for key, item in value.items() if key != "registry_digest"}
    if _digest(unsigned) != claimed or not isinstance(value["attempts"], dict):
        raise WorkerTransactionError("active-attempt registry digest is invalid")
    expected_row_v1 = {
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_relative_path",
        "arm_digest",
    }
    expected_row_v2 = expected_row_v1 | {"phase_roster_digest"}
    for attempt_id, row in value["attempts"].items():
        _identifier(attempt_id, "active attempt ID")
        if (
            not isinstance(row, dict)
            or frozenset(row)
            not in {frozenset(expected_row_v1), frozenset(expected_row_v2)}
        ):
            raise WorkerTransactionError(
                "active-attempt registry row has schema drift"
            )
        run_id = _identifier(row["run_id"], "active attempt run_id")
        phase = _identifier(row["phase"], "active attempt phase")
        unit = _identifier(row["work_unit_id"], "active attempt work unit")
        generation = _generation(row["generation"])
        plan_digest = _sha256(
            row["work_plan_digest"], "active attempt work-plan digest"
        )
        arm_digest = _sha256(row["arm_digest"], "active attempt arm digest")
        if "phase_roster_digest" in row:
            _sha256(
                row["phase_roster_digest"],
                "active attempt phase roster digest",
            )
        relative = _relative_path(
            row["attempt_relative_path"],
            "active attempt relative path",
        )
        parts = relative.split("/")
        if (
            len(parts) != 4
            or parts[0] != phase
            or parts[1] != unit
            or parts[2] not in {plan_digest, plan_digest[:32], "attempts"}
            or parts[3] != attempt_id
        ):
            raise WorkerTransactionError(
                "active-attempt registry row/path binding is invalid"
            )
        # Bind normalized values without silently accepting subclassed or
        # noncanonical JSON inputs.
        if (
            row["run_id"] != run_id
            or row["generation"] != generation
            or row["arm_digest"] != arm_digest
        ):
            raise WorkerTransactionError(
                "active-attempt registry row is noncanonical"
            )
    return value


def _replace_json(path: Path, payload: Mapping[str, Any]) -> None:
    raw = _canonical_bytes(payload) + b"\n"
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        _native_rooted_path(temporary),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            _native_rooted_path(temporary),
            _native_rooted_path(path),
        )
        _fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            _unlink_rooted(temporary)
        raise


def _set_active_attempt(
    transaction_root: Path,
    *,
    attempt_id: str,
    row: Mapping[str, Any] | None,
) -> None:
    with _registry_lock(transaction_root):
        registry = _active_registry(transaction_root)
        attempts = dict(registry["attempts"])
        if row is None:
            attempts.pop(attempt_id, None)
        else:
            if attempt_id in attempts:
                raise WorkerTransactionError("attempt is already active")
            attempts[attempt_id] = _json_value(row, "active attempt row")
        updated: dict[str, Any] = {
            "schema": "plamen.worker_active_attempts.v1",
            "attempts": {key: attempts[key] for key in sorted(attempts)},
        }
        updated["registry_digest"] = _digest(updated)
        _replace_json(transaction_root / "active_attempts.json", updated)


def _validate_arm(
    arm: Mapping[str, Any],
    *,
    run_id: str,
    phase_dir: Path,
    unit_dir: Path,
    plan_dir: Path,
    attempt_dir: Path,
) -> dict[str, Any]:
    v1_keys = {
        "schema",
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "process_scope",
        "arm_digest",
    }
    v2_keys = v1_keys | {
        AUXILIARY_STARTUP_POLICY_KEY,
        "phase_roster_digest",
        "phase_roster_denominator_digest",
        "materialized",
    }
    schema = arm.get("schema")
    expected_keys = (
        v2_keys
        if schema in {
            WORKER_ATTEMPT_ARM_SCHEMA_V2,
            WORKER_ATTEMPT_ARM_SCHEMA_V3,
        }
        else v1_keys
    )
    if set(arm) != expected_keys:
        raise WorkerTransactionError("worker attempt arm has schema drift")
    if schema not in {
        WORKER_ATTEMPT_ARM_SCHEMA,
        WORKER_ATTEMPT_ARM_SCHEMA_V2,
        WORKER_ATTEMPT_ARM_SCHEMA_V3,
    }:
        raise WorkerTransactionError("worker attempt arm schema is unsupported")
    if _identifier(arm["run_id"], "arm run_id") != run_id:
        raise WorkerTransactionError("foreign-run worker attempt found in scratchpad")
    if _identifier(arm["phase"], "arm phase") != phase_dir.name:
        raise WorkerTransactionError("worker attempt phase/path mismatch")
    if _identifier(arm["work_unit_id"], "arm work_unit_id") != unit_dir.name:
        raise WorkerTransactionError("worker attempt unit/path mismatch")
    plan_digest = _sha256(arm["work_plan_digest"], "arm work_plan_digest")
    if plan_dir.name not in {plan_digest, plan_digest[:32], "attempts"}:
        raise WorkerTransactionError("worker attempt plan/path mismatch")
    if _identifier(arm["attempt_id"], "arm attempt_id") != attempt_dir.name:
        raise WorkerTransactionError("worker attempt ID/path mismatch")
    _generation(arm["generation"])
    scope = arm["process_scope"]
    if (
        not isinstance(scope, dict)
        or set(scope) != {"state", "capability", "persistent_identity"}
        or scope["state"] != "ARMED"
    ):
        raise WorkerTransactionError("worker attempt process-scope binding is malformed")
    _identifier(scope["capability"], "process scope capability")
    _identifier(scope["persistent_identity"], "process scope persistent identity")
    if schema in {
        WORKER_ATTEMPT_ARM_SCHEMA_V2,
        WORKER_ATTEMPT_ARM_SCHEMA_V3,
    }:
        raw_startup_binding = arm[AUXILIARY_STARTUP_POLICY_KEY]
        if raw_startup_binding is not None:
            normalized_startup_binding = _auxiliary_startup_permit_binding(
                raw_startup_binding,
                run_id=arm["run_id"],
            )
            if raw_startup_binding != normalized_startup_binding:
                raise WorkerTransactionError(
                    "worker attempt startup permit binding is non-canonical"
                )
        _sha256(arm["phase_roster_digest"], "arm phase roster digest")
        _sha256(
            arm["phase_roster_denominator_digest"],
            "arm phase roster denominator digest",
        )
        materialized = arm["materialized"]
        expected_materialized = (
            {
                "base_argv",
                "base_argv_sha256",
                "final_argv_authority",
                "prompt_sha256",
                "write_scope",
            }
            if schema == WORKER_ATTEMPT_ARM_SCHEMA_V3
            else {
                "argv",
                "argv_sha256",
                "prompt_sha256",
                "write_scope",
            }
        )
        if (
            not isinstance(materialized, dict)
            or set(materialized) != expected_materialized
        ):
            raise WorkerTransactionError(
                "worker attempt materialization binding is malformed"
            )
        argv_field = (
            "base_argv"
            if schema == WORKER_ATTEMPT_ARM_SCHEMA_V3
            else "argv"
        )
        argv_digest_field = (
            "base_argv_sha256"
            if schema == WORKER_ATTEMPT_ARM_SCHEMA_V3
            else "argv_sha256"
        )
        argv = materialized[argv_field]
        if (
            not isinstance(argv, list)
            or not argv
            or any(
                not isinstance(item, str) or not item or "\x00" in item
                for item in argv
            )
            or _argv_sha256(argv) != _sha256(
                materialized[argv_digest_field],
                "arm materialized base argv digest",
            )
        ):
            raise WorkerTransactionError(
                "worker attempt materialized base argv binding is invalid"
            )
        if (
            schema == WORKER_ATTEMPT_ARM_SCHEMA_V3
            and materialized["final_argv_authority"]
            != "INNER_PROVIDER_ARM_AFTER_RUNTIME_MATERIALIZATION"
        ):
            raise WorkerTransactionError(
                "worker attempt final argv authority is invalid"
            )
        _sha256(
            materialized["prompt_sha256"],
            "arm materialized prompt digest",
        )
        expected_write_scope = compile_attempt_write_scope(
            run_id=arm["run_id"],
            phase=arm["phase"],
            work_unit_id=arm["work_unit_id"],
            attempt_id=arm["attempt_id"],
        )
        if materialized["write_scope"] != expected_write_scope:
            raise WorkerTransactionError(
                "worker attempt materialized write scope differs from identity"
            )
    claimed = _sha256(arm["arm_digest"], "arm digest")
    unsigned = {key: value for key, value in arm.items() if key != "arm_digest"}
    if _digest(unsigned) != claimed:
        raise WorkerTransactionError("worker attempt arm digest mismatch")
    return dict(arm)


def _validate_attempt_completion(
    path: Path,
    *,
    arm: Mapping[str, Any],
) -> dict[str, Any]:
    completion, _ = _read_digest_bound_json(
        path,
        digest_field="completion_digest",
        label="worker attempt completion",
    )
    expected = {
        "schema",
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "arm_digest",
        "provider_completion_relative_path",
        "provider_completion_digest",
        "canonical_projection_state",
        "completion_digest",
    }
    if set(completion) != expected:
        raise WorkerTransactionError(
            "worker attempt completion has schema drift"
        )
    if completion["schema"] != "plamen.worker_attempt_completion.v1":
        raise WorkerTransactionError(
            "worker attempt completion schema is unsupported"
        )
    for field in (
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "arm_digest",
    ):
        if completion[field] != arm[field]:
            raise WorkerTransactionError(
                f"worker attempt completion {field} differs from arm"
            )
    _relative_path(
        completion["provider_completion_relative_path"],
        "provider completion path",
    )
    _sha256(
        completion["provider_completion_digest"],
        "provider completion digest",
    )
    if completion["canonical_projection_state"] != "PENDING_PHASE_IO":
        raise WorkerTransactionError(
            "attempt completion claims canonical projection authority"
        )
    if arm["schema"] in {
        WORKER_ATTEMPT_ARM_SCHEMA_V2,
        WORKER_ATTEMPT_ARM_SCHEMA_V3,
    }:
        roster_path = path.parent / "view" / "phase_roster.json"
        roster = _validate_phase_roster(
            _read_json(roster_path, "attempt final phase roster")
        )
        if (
            roster["roster_digest"] != arm["phase_roster_digest"]
            or roster["roster_denominator_digest"]
            != arm["phase_roster_denominator_digest"]
            or roster["work_plan_digests"].get(arm["work_unit_id"])
            != arm["work_plan_digest"]
        ):
            raise WorkerTransactionError(
                "attempt final phase roster differs from its arm"
            )
    return completion


def _validate_attempt_debt(
    path: Path,
    *,
    arm: Mapping[str, Any],
) -> dict[str, Any]:
    debt, _ = _read_digest_bound_json(
        path,
        digest_field="debt_digest",
        label="worker attempt debt",
    )
    required = {
        "schema",
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "arm_digest",
        "reason_code",
        "detail",
        "completion_emitted",
        "retry_required",
        "debt_digest",
    }
    optional = {
        "provider_arm_relative_path",
        "provider_debt_relative_path",
    }
    if not required <= set(debt) or not set(debt) <= required | optional:
        raise WorkerTransactionError("worker attempt debt has schema drift")
    if debt["schema"] != WORKER_ATTEMPT_DEBT_SCHEMA:
        raise WorkerTransactionError("worker attempt debt schema is unsupported")
    for field in (
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "arm_digest",
    ):
        if debt[field] != arm[field]:
            raise WorkerTransactionError(
                f"worker attempt debt {field} differs from arm"
            )
    _identifier(debt["reason_code"], "worker attempt debt reason")
    if (
        not isinstance(debt["detail"], str)
        or "\x00" in debt["detail"]
        or len(debt["detail"]) > 4096
        or debt["completion_emitted"] is not False
        or type(debt["retry_required"]) is not bool
    ):
        raise WorkerTransactionError("worker attempt debt disposition is malformed")
    for field in optional:
        if field in debt and debt[field]:
            _relative_path(debt[field], field)
    if debt["reason_code"] == "PROVIDER_EXECUTION_DEBT":
        if not optional <= set(debt):
            raise WorkerTransactionError(
                "provider execution debt lacks provider evidence paths"
            )
    elif optional & set(debt):
        raise WorkerTransactionError(
            "non-provider debt carries provider evidence fields"
        )
    return debt


def execute_worker_transaction(
    plan: Mapping[str, Any],
    adapter: NativeCommandAdapter | HeadlessModelAdapter,
    cancel_token: Any = None,
) -> ExecutionRef:
    """Execute one native or headless-model plan into attempt-owned staging.

    It never projects canonical output; a separate PhaseIO incorporation
    transaction is required.
    """

    compiled = _validate_compiled_plan(plan)
    plan_is_v2 = compiled["schema"] == WORKER_WORK_PLAN_SCHEMA_V2
    if not isinstance(adapter, (NativeCommandAdapter, HeadlessModelAdapter)):
        raise WorkerTransactionError(
            "worker adapter type is unsupported"
        )
    provider = compiled["provider"]
    phase_roster: dict[str, Any] | None = None
    if plan_is_v2:
        raw_roster = adapter.phase_roster
        if raw_roster is None:
            raw_roster = _singleton_phase_roster_for_plan(compiled)
        phase_roster = validate_work_plan_phase_roster(
            compiled,
            raw_roster,
        )
    if isinstance(adapter, NativeCommandAdapter):
        if provider["backend"] != "native" or provider["transport"] != "native":
            raise WorkerTransactionError(
                "native adapter cannot execute a model provider plan"
            )
        output_source_mode = adapter.output_source_mode
    else:
        if provider["backend"] not in {"claude", "codex"} or provider[
            "transport"
        ] not in {"headless", "exec"}:
            raise WorkerTransactionError(
                "headless model adapter cannot execute this provider plan"
            )
        if not plan_is_v2:
            raise WorkerTransactionError(
                "headless model execution requires a v2 WorkPlan startup "
                "permit contract"
            )
        output_source_mode = WORKER_FILE_OUTPUTS
        if (
            provider["backend"] == "claude"
            and adapter.stdin_input_name != "prompt"
        ):
            raise WorkerTransactionError(
                "headless model execution requires exact prompt stdin"
            )
    provider_stdout_evidence_configuration: dict[str, Any] | None = None
    startup_authority_binding: dict[str, Any] | None = None
    claude_launch_security_request: dict[str, Any] | None = None
    claude_provider_preparation: ClaudeProviderPreparation | None = None
    claude_provider_runtime: BoundClaudeProviderRuntime | None = None
    codex_auth_bytes: bytes | None = None
    codex_auth_policy: dict[str, Any] | None = None
    if isinstance(adapter, HeadlessModelAdapter):
        plan_completion_policy = compiled.get("completion_policy")
        if not isinstance(plan_completion_policy, Mapping):
            raise WorkerTransactionError(
                "WorkPlan completion policy is malformed"
            )
        raw_plan_stdout_policy = plan_completion_policy.get(
            CLAUDE_STREAM_STDOUT_POLICY_KEY
        )
        raw_adapter_stdout_policy = (
            adapter.provider_stdout_evidence_configuration
        )
        try:
            normalized_adapter_stdout_policy = (
                None
                if raw_adapter_stdout_policy is None
                else _provider_stdout_evidence_configuration(
                    raw_adapter_stdout_policy,
                    provider=provider,
                )
            )
        except WorkerTransactionError as exc:
            raise WorkerTransactionError(
                "Claude stdout evidence policy cannot be dropped or "
                "substituted by the runtime adapter"
            ) from exc
        if raw_plan_stdout_policy != normalized_adapter_stdout_policy:
            raise WorkerTransactionError(
                "Claude stdout evidence policy cannot be dropped or "
                "substituted by the runtime adapter"
            )
        provider_stdout_evidence_configuration = (
            normalized_adapter_stdout_policy
        )
        raw_plan_startup_binding = plan_completion_policy.get(
            AUXILIARY_STARTUP_POLICY_KEY
        )
        raw_adapter_startup_binding = adapter.startup_authority_binding
        try:
            normalized_adapter_startup_binding = (
                None
                if raw_adapter_startup_binding is None
                else _auxiliary_startup_permit_binding(
                    raw_adapter_startup_binding,
                    run_id=compiled["run_id"],
                )
            )
        except WorkerTransactionError as exc:
            raise WorkerTransactionError(
                "auxiliary startup permit cannot be dropped or substituted "
                "by the runtime adapter"
            ) from exc
        if (
            raw_plan_startup_binding is None
            or normalized_adapter_startup_binding is None
            or raw_plan_startup_binding != normalized_adapter_startup_binding
        ):
            raise WorkerTransactionError(
                "auxiliary startup permit cannot be dropped or substituted "
                "by the runtime adapter"
            )
        startup_authority_binding = normalized_adapter_startup_binding
        raw_plan_claude_security = plan_completion_policy.get(
            CLAUDE_LAUNCH_SECURITY_POLICY_KEY
        )
        raw_adapter_claude_request = (
            adapter.claude_launch_security_request
        )
        raw_provider_preparation = (
            adapter.claude_provider_preparation
        )
        raw_provider_runtime = adapter.claude_provider_runtime
        if raw_plan_claude_security is None:
            if raw_adapter_claude_request is not None:
                raise WorkerTransactionError(
                    "Claude launch-security request has no WorkPlan policy"
                )
            if (
                raw_provider_preparation is not None
                or raw_provider_runtime is not None
            ):
                raise WorkerTransactionError(
                    "Claude provider parent cannot authorize another backend"
                )
        else:
            if provider.get("backend") != "claude":
                raise WorkerTransactionError(
                    "Claude launch-security policy cannot authorize another backend"
                )
            if (
                type(raw_provider_preparation)
                is not ClaudeProviderPreparation
                or type(raw_provider_runtime)
                is not BoundClaudeProviderRuntime
            ):
                raise WorkerTransactionError(
                    "Claude execution requires an exact prepared and bound "
                    "provider parent"
                )
            try:
                normalized_request = replay_claude_launch_security_request(
                    raw_adapter_claude_request
                )
            except (ClaudeLaunchSecurityError, TypeError) as exc:
                raise WorkerTransactionError(
                    "Claude launch-security request cannot be dropped or substituted"
                ) from exc
            if normalized_request["policy"] != raw_plan_claude_security:
                raise WorkerTransactionError(
                    "Claude launch-security request differs from the WorkPlan"
                )
            plan_preparation_sha256 = plan_completion_policy.get(
                CLAUDE_PROVIDER_PREPARATION_POLICY_KEY
            )
            try:
                raw_provider_preparation.validate_for_backend("claude")
                public_parent = (
                    raw_provider_preparation.public_headless_arguments()
                )
                if (
                    plan_preparation_sha256
                    != raw_provider_preparation.preparation_sha256
                    or raw_provider_runtime.preparation_sha256
                    != raw_provider_preparation.preparation_sha256
                    or raw_provider_runtime.runtime_host_policy_sha256
                    != public_parent[
                        "claude_runtime_host_policy_sha256"
                    ]
                    or public_parent["claude_launch_security"]
                    != raw_plan_claude_security
                    or public_parent[
                        "claude_launch_security_request"
                    ]
                    != normalized_request
                    or public_parent[
                        "provider_stdout_evidence_configuration"
                    ]
                    != provider_stdout_evidence_configuration
                    or tuple(public_parent["environment_allowlist"])
                    != tuple(adapter.environment_allowlist)
                ):
                    raise ClaudeProviderPreparationError(
                        "Claude provider parent differs from the WorkPlan"
                    )
            except (ClaudeProviderPreparationError, TypeError) as exc:
                raise WorkerTransactionError(
                    "Claude provider parent cannot be dropped or substituted"
                ) from exc
            claude_launch_security_request = normalized_request
            claude_provider_preparation = raw_provider_preparation
            claude_provider_runtime = raw_provider_runtime
        raw_codex_auth_policy = plan_completion_policy.get(
            CODEX_RUNTIME_AUTH_POLICY_KEY
        )
        raw_codex_auth_bytes = adapter.codex_auth_bytes
        if raw_codex_auth_policy is None:
            if raw_codex_auth_bytes is not None:
                raise WorkerTransactionError(
                    "Codex authentication material has no WorkPlan policy"
                )
        else:
            if provider.get("backend") != "codex":
                raise WorkerTransactionError(
                    "Codex runtime auth policy cannot authorize another backend"
                )
            if (
                not isinstance(raw_codex_auth_policy, Mapping)
                or set(raw_codex_auth_policy) != {"mode", "sha256", "size"}
                or raw_codex_auth_policy.get("mode")
                not in {"AUTH_JSON_COPY", "ENVIRONMENT_API_KEY"}
                or not isinstance(raw_codex_auth_policy.get("sha256"), str)
                or not _HEX_RE.fullmatch(str(raw_codex_auth_policy["sha256"]))
                or not isinstance(raw_codex_auth_policy.get("size"), int)
                or isinstance(raw_codex_auth_policy.get("size"), bool)
                or int(raw_codex_auth_policy["size"]) < 0
                or int(raw_codex_auth_policy["size"]) > 1024 * 1024
                or not isinstance(raw_codex_auth_bytes, bytes)
                or len(raw_codex_auth_bytes) != int(raw_codex_auth_policy["size"])
                or hashlib.sha256(raw_codex_auth_bytes).hexdigest()
                != raw_codex_auth_policy["sha256"]
                or adapter.environment.get("CODEX_HOME")
                != CODEX_HOME_PLACEHOLDER
                or "CODEX_HOME" not in adapter.environment_allowlist
            ):
                raise WorkerTransactionError(
                    "Codex runtime auth material differs from the WorkPlan"
                )
            if (
                raw_codex_auth_policy["mode"] == "AUTH_JSON_COPY"
                and not raw_codex_auth_bytes
            ) or (
                raw_codex_auth_policy["mode"] == "ENVIRONMENT_API_KEY"
                and (
                    raw_codex_auth_bytes
                    or not any(
                        str(adapter.environment.get(name) or "").strip()
                        for name in ("CODEX_API_KEY", "OPENAI_API_KEY")
                    )
                )
            ):
                raise WorkerTransactionError(
                    "Codex runtime auth mode is inconsistent"
                )
            codex_auth_bytes = bytes(raw_codex_auth_bytes)
            codex_auth_policy = dict(raw_codex_auth_policy)
    if output_source_mode not in {
        STDOUT_ASSIGNED_OUTPUT,
        WORKER_FILE_OUTPUTS,
    }:
        raise WorkerTransactionError("adapter output source mode is unsupported")
    members = compiled["assignment"]["members"]
    if output_source_mode == STDOUT_ASSIGNED_OUTPUT and len(members) != 1:
        raise WorkerTransactionError(
            "stdout-assigned native execution requires one assignment member"
        )

    scratchpad = _checked_root_directory(
        adapter.scratchpad,
        label="adapter scratchpad",
    )
    cwd = _checked_root_directory(
        adapter.cwd,
        label="adapter cwd",
    )
    if (
        provider_stdout_evidence_configuration is not None
        and provider_stdout_evidence_configuration[
            "expected_init_contract"
        ]["cwd"]
        != str(cwd)
    ):
        raise WorkerTransactionError(
            "Claude stdout evidence policy init cwd differs from the "
            "runtime adapter cwd"
        )

    executable = Path(provider["resolved_executable"]).resolve(strict=True)
    _safe_file(executable, "provider executable")
    if hashlib.sha256(_read_rooted_bytes(executable)).hexdigest() != provider[
        "executable_sha256"
    ]:
        raise WorkerTransactionError("provider executable bytes changed")
    if environment_allowlist_sha256(adapter.environment_allowlist) != provider[
        "environment_allowlist_digest"
    ]:
        raise WorkerTransactionError(
            "adapter environment allowlist disagrees with the WorkPlan"
        )

    required_inputs = {"manifest", "intent", "context", "prompt", "tool_policy"}
    if set(adapter.input_relative_paths) != required_inputs:
        raise WorkerTransactionError("native adapter input denominator is incomplete")
    input_raw: dict[str, bytes] = {}
    for name in sorted(required_inputs):
        source = _safe_relative_file(
            scratchpad,
            adapter.input_relative_paths[name],
            f"{name} input",
        )
        input_raw[name] = _read_rooted_bytes(source)
    if plan_is_v2:
        if (
            hashlib.sha256(input_raw["prompt"]).hexdigest()
            != compiled["prompt_template_sha256"]
        ):
            raise WorkerTransactionError(
                "prompt template bytes disagree with the WorkPlan"
            )
    elif (
        hashlib.sha256(input_raw["prompt"]).hexdigest()
        != compiled["prompt_sha256"]
    ):
        raise WorkerTransactionError("prompt bytes disagree with the WorkPlan")
    try:
        intent = json.loads(input_raw["intent"].decode("utf-8"))
    except Exception as exc:
        raise WorkerTransactionError("launch intent is not UTF-8 JSON") from exc
    if (
        not isinstance(intent, dict)
        or intent.get("effective_backend") != provider["backend"]
        or intent.get("effective_model") != provider["model"]
        or intent.get("environment_allowlist_sha256")
        != provider["environment_allowlist_digest"]
    ):
        raise WorkerTransactionError("launch intent disagrees with the WorkPlan")

    transaction_root = _make_safe_directory_tree(
        scratchpad, ".worker_transactions"
    )
    phase = compiled["phase"]
    unit = compiled["work_unit_id"]
    plan_digest = compiled["work_plan_digest"]
    explicit_scope = compiled.get(
        "write_scope_template" if plan_is_v2 else "write_scope"
    )
    if plan_is_v2:
        attempt_id = (
            str(adapter.attempt_id)
            if adapter.attempt_id is not None
            else f"attempt-{uuid.uuid4().hex[:24]}"
        )
        scope_template = compile_attempt_write_scope_template(
            run_id=compiled["run_id"],
            phase=phase,
            work_unit_id=unit,
        )
        if explicit_scope != scope_template:
            raise WorkerTransactionError(
                "WorkPlan write-scope template is unsupported"
            )
        materialized_scope = compile_attempt_write_scope(
            run_id=compiled["run_id"],
            phase=phase,
            work_unit_id=unit,
            attempt_id=attempt_id,
        )
        attempt_relative = str(materialized_scope["attempt_relative_path"])
        if _rooted_lexists(transaction_root / attempt_relative):
            raise WorkerTransactionError("worker attempt path already exists")
        materialized_argv = [
            _materialize_template_text(
                item,
                scratchpad=scratchpad,
                write_scope=materialized_scope,
            )
            for item in provider["argv_template"]
        ]
        materialized_inputs = {
            name: _materialize_template_text(
                raw.decode("utf-8", errors="strict"),
                scratchpad=scratchpad,
                write_scope=materialized_scope,
            ).encode("utf-8")
            for name, raw in input_raw.items()
        }
    elif (
        isinstance(explicit_scope, Mapping)
        and explicit_scope.get("kind") == "ATTEMPT_OUTPUT_ONLY"
    ):
        expected_scope = compile_attempt_write_scope(
            run_id=compiled["run_id"],
            phase=phase,
            work_unit_id=unit,
            attempt_id=str(explicit_scope.get("attempt_id") or ""),
        )
        if explicit_scope != expected_scope:
            raise WorkerTransactionError(
                "WorkPlan attempt write scope disagrees with its identity"
            )
        attempt_id = str(expected_scope["attempt_id"])
        attempt_relative = str(expected_scope["attempt_relative_path"])
        if _rooted_lexists(transaction_root / attempt_relative):
            raise WorkerTransactionError(
                "precompiled worker attempt path already exists"
            )
        materialized_scope = expected_scope
        materialized_argv = list(provider["argv"])
        materialized_inputs = input_raw
    else:
        # Transitional native plans compiled before P0-AM used a plan-digest
        # directory.  New model/native callers must use the exact scope above.
        attempt_id = f"attempt-{uuid.uuid4().hex[:24]}"
        plan_directory = plan_digest[:32]
        attempt_relative = f"{phase}/{unit}/{plan_directory}/{attempt_id}"
        materialized_scope = compile_attempt_write_scope(
            run_id=compiled["run_id"],
            phase=phase,
            work_unit_id=unit,
            attempt_id=attempt_id,
        )
        materialized_argv = list(provider["argv"])
        materialized_inputs = input_raw
    attempt_dir = _make_safe_directory_tree(transaction_root, attempt_relative)
    view_names = {
        "manifest": "manifest.json",
        "intent": "intent.json",
        "context": "context.md",
        "prompt": "prompt.md",
        "tool_policy": "tool_policy.json",
    }

    capability = process_tree_termination_capability()
    shard_id = f"wt-{plan_digest[:16]}-{attempt_id[-16:]}"
    arm: dict[str, Any] = {
        "schema": (
            WORKER_ATTEMPT_ARM_SCHEMA_V3
            if plan_is_v2
            else WORKER_ATTEMPT_ARM_SCHEMA
        ),
        "run_id": compiled["run_id"],
        "phase": phase,
        "work_unit_id": unit,
        "generation": compiled["generation"],
        "work_plan_digest": plan_digest,
        "attempt_id": attempt_id,
        "process_scope": {
            "state": "ARMED",
            "capability": _identifier(
                str(capability.get("platform", "UNSUPPORTED")),
                "process capability",
            ),
            "persistent_identity": shard_id,
        },
    }
    if plan_is_v2:
        assert phase_roster is not None
        arm.update(
            {
                "phase_roster_digest": phase_roster["roster_digest"],
                "phase_roster_denominator_digest": phase_roster[
                    "roster_denominator_digest"
                ],
                AUXILIARY_STARTUP_POLICY_KEY: startup_authority_binding,
                "materialized": {
                    "base_argv": materialized_argv,
                    "base_argv_sha256": _argv_sha256(materialized_argv),
                    "final_argv_authority": (
                        "INNER_PROVIDER_ARM_AFTER_RUNTIME_MATERIALIZATION"
                    ),
                    "prompt_sha256": hashlib.sha256(
                        materialized_inputs["prompt"]
                    ).hexdigest(),
                    "write_scope": materialized_scope,
                },
            }
        )
    arm["arm_digest"] = _digest(arm)
    _write_absent_json(attempt_dir / "arm.json", arm)
    active_row = {
        "run_id": compiled["run_id"],
        "phase": phase,
        "work_unit_id": unit,
        "generation": compiled["generation"],
        "work_plan_digest": plan_digest,
        "attempt_relative_path": (
            Path(attempt_relative).as_posix()
        ),
        "arm_digest": arm["arm_digest"],
    }
    if plan_is_v2:
        active_row["phase_roster_digest"] = arm["phase_roster_digest"]
    _set_active_attempt(
        transaction_root, attempt_id=attempt_id, row=active_row
    )
    active_attempt_registered = True

    def clear_active_attempt() -> None:
        nonlocal active_attempt_registered
        if active_attempt_registered:
            _set_active_attempt(
                transaction_root,
                attempt_id=attempt_id,
                row=None,
            )
            active_attempt_registered = False

    def terminal_debt(reason_code: str, detail: str, **extra: Any) -> Path:
        debt: dict[str, Any] = {
            "schema": WORKER_ATTEMPT_DEBT_SCHEMA,
            "run_id": compiled["run_id"],
            "phase": phase,
            "work_unit_id": unit,
            "generation": compiled["generation"],
            "work_plan_digest": plan_digest,
            "attempt_id": attempt_id,
            "arm_digest": arm["arm_digest"],
            "reason_code": _identifier(reason_code, "attempt debt reason"),
            "detail": str(detail)[:4096],
            "completion_emitted": False,
            "retry_required": True,
            **_json_value(extra, "attempt debt extension"),
        }
        debt["debt_digest"] = _digest(debt)
        path = attempt_dir / "debt.json"
        _write_absent_json(path, debt)
        return path

    claude_runtime_materialization_request = None
    codex_home_lease: AuxiliaryWritableRootLease | None = None
    execution_environment = dict(adapter.environment)
    execution_auxiliary_leases: tuple[AuxiliaryWritableRootLease, ...] = ()
    if provider["backend"] == "claude":
        if (
            claude_launch_security_request is None
            or claude_provider_preparation is None
            or claude_provider_runtime is None
            or startup_authority_binding is None
        ):
            try:
                terminal_debt(
                    "CLAUDE_RUNTIME_AUTHORITY_INCOMPLETE",
                    "Claude runtime materialization authority is incomplete",
                )
            finally:
                clear_active_attempt()
            raise WorkerTransactionError(
                "Claude runtime materialization authority is incomplete"
            )
        # The v3 outer AttemptArm was written through _write_absent_json,
        # which fsyncs both the file and its containing directory.  Only after
        # that durable recovery boundary may the fresh provider attachment be
        # claimed into the exact one-shot parent accepted by WER.
        try:
            claimed_provider_runtime = (
                claim_bound_claude_provider_runtime(
                    claude_provider_runtime,
                    provider_preparation=(
                        claude_provider_preparation
                    ),
                    expected_preparation_sha256=(
                        claude_provider_preparation.preparation_sha256
                    ),
                    expected_runtime_host_policy_sha256=(
                        claude_provider_runtime.runtime_host_policy_sha256
                    ),
                    expected_attachment_sha256=(
                        claude_provider_runtime.attachment_sha256
                    ),
                )
            )
            claude_runtime_materialization_request = (
                compile_claude_runtime_materialization_request(
                    launch_security_request=(
                        claude_launch_security_request
                    ),
                    provider_runtime=claimed_provider_runtime,
                    base_argv=materialized_argv,
                    scratchpad=scratchpad,
                    startup_permit_binding=startup_authority_binding,
                    run_id=compiled["run_id"],
                    outer_attempt_arm_sha256=arm["arm_digest"],
                    work_plan_sha256=hashlib.sha256(
                        _canonical_bytes(compiled) + b"\n"
                    ).hexdigest(),
                    attempt_id=attempt_id,
                    process_scope_identity=shard_id,
                )
            )
        except (
            ClaudeProviderPreparationError,
            ClaudeRuntimeMaterializationError,
        ) as exc:
            try:
                terminal_debt(
                    "CLAUDE_RUNTIME_REQUEST_REJECTED",
                    str(exc),
                )
            finally:
                clear_active_attempt()
            raise WorkerTransactionError(
                f"Claude runtime request was rejected: {exc}"
            ) from exc

    def abort_unbound_codex_home(reason_code: str) -> None:
        if codex_home_lease is None or codex_home_lease.process_scope_bound:
            return
        codex_home_lease.abort_before_process_scope(
            attempt_arm_sha256=arm["arm_digest"],
            process_scope_identity=shard_id,
            reason_code=reason_code,
        )

    try:
        if codex_auth_policy is not None:
            reservation = reserve_auxiliary_writable_root(
                attempt_id=attempt_id,
                purpose="codex-runtime-home",
            )
            codex_home_lease = reservation.arm(
                attempt_arm_sha256=arm["arm_digest"],
                process_scope_identity=shard_id,
            )
            if codex_auth_policy["mode"] == "AUTH_JSON_COPY":
                assert codex_auth_bytes is not None and codex_auth_bytes
                _immutable_bytes(
                    codex_home_lease.root / "auth.json",
                    codex_auth_bytes,
                )
            if execution_environment.get("CODEX_HOME") != CODEX_HOME_PLACEHOLDER:
                raise WorkerTransactionError(
                    "Codex runtime home placeholder changed before materialization"
                )
            execution_environment["CODEX_HOME"] = str(codex_home_lease.root)
            execution_auxiliary_leases = (codex_home_lease,)
        # Attempt-specific argv, prompt, intent, and write scope exist only as
        # in-memory values until their immutable v2 AttemptArm is durable.
        # Any crash while materializing the view is therefore recoverable debt,
        # never an unarmed attempt.
        view_dir = _make_safe_directory_tree(
            transaction_root, f"{attempt_relative}/view"
        )
        _write_absent_json(view_dir / "plan.json", compiled)
        if plan_is_v2:
            assert phase_roster is not None
            _write_absent_json(
                view_dir / "phase_roster.json",
                phase_roster,
            )
        for name, filename in view_names.items():
            path = view_dir / filename
            raw = materialized_inputs[name]
            descriptor = os.open(
                _native_rooted_path(path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o400,
            )
            try:
                with os.fdopen(
                    descriptor, "wb", closefd=True
                ) as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                with contextlib.suppress(OSError):
                    _unlink_rooted(path)
                raise
        _fsync_directory(view_dir)

        if _cancel_requested(cancel_token):
            terminal_debt(
                "CANCELLED_BEFORE_LAUNCH",
                "worker transaction was cancelled after arm and before launch",
            )
            raise WorkerTransactionError("worker transaction cancelled before launch")

        prefix = (
            attempt_dir.relative_to(scratchpad).as_posix()
        )
        bindings = ExecutionBindings(
            run_id=compiled["run_id"],
            shard_id=shard_id,
            plan=BoundInput(f"{prefix}/view/plan.json"),
            manifest=BoundInput(f"{prefix}/view/manifest.json"),
            intent=BoundInput(f"{prefix}/view/intent.json"),
            context=BoundInput(f"{prefix}/view/context.md"),
            prompt=BoundInput(f"{prefix}/view/prompt.md"),
            tool_policy=BoundInput(f"{prefix}/view/tool_policy.json"),
            worker=PrincipalInvocation(
                f"native-{unit}", attempt_id
            ),
            assessors=(),
            effective_backend=provider["backend"],
            effective_model=provider["model"],
        )
        expected_outputs: list[ExpectedOutput] = []
        assignment_id = compiled["assignment"]["assignment_id"]
        for index, member in enumerate(members):
            expected_outputs.append(
                ExpectedOutput(
                    (
                        assignment_id
                        if len(members) == 1
                        else f"{assignment_id}-m{index:03d}"
                    ),
                    member["staged_relative_path"],
                    member["canonical_identity"].removeprefix("scratchpad:"),
                )
            )
        stdin_input_name = adapter.stdin_input_name
        stdin = (
            BoundInput(f"{prefix}/view/{view_names[stdin_input_name]}")
            if stdin_input_name is not None
            and stdin_input_name in view_names
            else None
        )
        if stdin_input_name is not None and stdin is None:
            raise WorkerTransactionError("native adapter stdin input name is invalid")

        try:
            execution = run_observed_worker(
                scratchpad=scratchpad,
                bindings=bindings,
                argv=materialized_argv,
                cwd=cwd,
                output_scope_relative=f"{prefix}/output",
                expected_outputs=tuple(expected_outputs),
                parser_digest=adapter.parser_digest,
                environment=execution_environment,
                environment_allowlist=adapter.environment_allowlist,
                stdin_input=stdin,
                timeout_seconds=provider["timeout_seconds"],
                output_source_mode=output_source_mode,
                stdout_limit_bytes=provider["stream_limits"]["stdout_bytes"],
                stderr_limit_bytes=provider["stream_limits"]["stderr_bytes"],
                staged_output_limit_bytes=provider["stream_limits"][
                    "staged_member_bytes"
                ],
                publish_canonical=False,
                process_scope_identity=shard_id,
                cancel_token=cancel_token,
                auxiliary_root_leases=execution_auxiliary_leases,
                provider_stdout_evidence_configuration=(
                    provider_stdout_evidence_configuration
                ),
                startup_authority_binding=startup_authority_binding,
                claude_launch_security_request=(
                    claude_launch_security_request
                ),
                claude_runtime_materialization_request=(
                    claude_runtime_materialization_request
                ),
            )
        except WorkerExecutionIncomplete as exc:
            provider_debt = (
                exc.debt_path.relative_to(scratchpad).as_posix()
                if exc.debt_path is not None
                else ""
            )
            terminal_debt(
                "PROVIDER_EXECUTION_DEBT",
                str(exc),
                provider_arm_relative_path=exc.arm_path.relative_to(
                    scratchpad
                ).as_posix(),
                provider_debt_relative_path=provider_debt,
            )
            raise WorkerTransactionError(
                f"native provider execution remained debt: {exc}"
            ) from exc

        completion: dict[str, Any] = {
            "schema": "plamen.worker_attempt_completion.v1",
            "run_id": compiled["run_id"],
            "phase": phase,
            "work_unit_id": unit,
            "generation": compiled["generation"],
            "work_plan_digest": plan_digest,
            "attempt_id": attempt_id,
            "arm_digest": arm["arm_digest"],
            "provider_completion_relative_path": execution.receipt_path.relative_to(
                scratchpad
            ).as_posix(),
            "provider_completion_digest": execution.completion_sha256,
            "canonical_projection_state": "PENDING_PHASE_IO",
        }
        completion["completion_digest"] = _digest(completion)
        completion_path = attempt_dir / "completion.json"
        _write_absent_json(completion_path, completion)
        return ExecutionRef(
            run_id=compiled["run_id"],
            phase=phase,
            work_unit_id=unit,
            generation=compiled["generation"],
            work_plan_digest=plan_digest,
            attempt_id=attempt_id,
            attempt_directory=attempt_dir,
            attempt_completion_path=completion_path,
            provider_execution=execution,
        )
    except WorkerTransactionError:
        with contextlib.suppress(AuxiliaryWritableRootLeaseError):
            abort_unbound_codex_home("WORKER_TRANSACTION_FAILED_BEFORE_SCOPE")
        if claude_runtime_materialization_request is not None:
            with contextlib.suppress(ClaudeRuntimeMaterializationError):
                claude_runtime_materialization_request.discard()
        raise
    except BaseException as exc:
        with contextlib.suppress(AuxiliaryWritableRootLeaseError):
            abort_unbound_codex_home("WORKER_TRANSACTION_EXCEPTION")
        if claude_runtime_materialization_request is not None:
            with contextlib.suppress(ClaudeRuntimeMaterializationError):
                claude_runtime_materialization_request.discard()
        if not _rooted_lexists(
            attempt_dir / "completion.json"
        ) and not _rooted_lexists(attempt_dir / "debt.json"):
            terminal_debt(
                "EXECUTION_PROVIDER_FAILED",
                f"{type(exc).__name__}: {exc}",
            )
        raise WorkerTransactionError(
            f"worker transaction execution failed: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        clear_active_attempt()


def _immutable_bytes(path: Path, raw: bytes) -> None:
    try:
        descriptor = os.open(
            _native_rooted_path(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        if _read_rooted_bytes(
            _safe_file(path, "immutable projection artifact")
        ) != raw:
            raise WorkerTransactionError(
                f"immutable projection artifact collision: {path}"
            )
        return
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            _unlink_rooted(path)
        raise


def _artifact_state(path: Path) -> dict[str, Any]:
    if not _rooted_lexists(path):
        return {"status": "ABSENT", "sha256": "", "size": 0}
    _safe_file(path, "canonical projection destination")
    raw = _read_rooted_bytes(path)
    return {
        "status": "ACTIVE",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def _projection_destination(scratchpad: Path, identity: str) -> Path:
    if not isinstance(identity, str) or not identity.startswith("scratchpad:"):
        raise WorkerTransactionError("projection identity is not scratchpad-owned")
    relative = _relative_path(
        identity.removeprefix("scratchpad:"), "projection identity"
    )
    parts = relative.split("/")
    parent = scratchpad
    for part in parts[:-1]:
        child = parent / part
        if not _rooted_lexists(child):
            _mkdir_rooted(child)
            _fsync_directory(parent)
        parent = _safe_directory(child, "projection parent")
    destination = parent / parts[-1]
    if (
        os.path.normcase(
            os.path.abspath(os.fspath(destination.parent))
        )
        != os.path.normcase(os.path.abspath(os.fspath(parent)))
    ):
        raise WorkerTransactionError("projection destination escapes scratchpad")
    return destination


def _replace_exact_bytes(path: Path, raw: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.projection")
    _immutable_bytes(temporary, raw)
    try:
        os.replace(
            _native_rooted_path(temporary),
            _native_rooted_path(path),
        )
        _fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            _unlink_rooted(temporary)
        raise


def _read_digest_bound_json(
    path: Path,
    *,
    digest_field: str,
    label: str,
    canonical_newline: bool = False,
) -> tuple[dict[str, Any], str]:
    value = _read_json(path, label)
    claimed = _sha256(value.get(digest_field), f"{label} digest")
    unsigned = {key: item for key, item in value.items() if key != digest_field}
    calculated = (
        hashlib.sha256(_canonical_bytes(unsigned) + b"\n").hexdigest()
        if canonical_newline
        else _digest(unsigned)
    )
    if calculated != claimed:
        raise WorkerTransactionError(f"{label} digest mismatch")
    return value, claimed


def validate_worker_execution_authority(
    *,
    scratchpad: Path,
    authority: Mapping[str, Any],
    contract: Any,
    launch: Any,
    run_id: str,
) -> dict[str, Any]:
    """Replay the structural execution→incorporation chain for ArtifactLedger."""

    expected_keys = {
        "schema",
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "attempt_completion_relative_path",
        "attempt_completion_digest",
        "provider_completion_relative_path",
        "provider_completion_digest",
        "incorporation_relative_path",
        "incorporation_digest",
        "contract_digest",
        "launch_digest",
        "authority_digest",
    }
    if not isinstance(authority, Mapping) or set(authority) != expected_keys:
        raise WorkerTransactionError("execution authority has schema drift")
    normalized = _json_value(authority, "execution authority")
    if normalized["schema"] != "plamen.worker_execution_authority.v1":
        raise WorkerTransactionError("execution authority schema is unsupported")
    claimed = _sha256(normalized["authority_digest"], "execution authority digest")
    unsigned = {
        key: item for key, item in normalized.items() if key != "authority_digest"
    }
    if _digest(unsigned) != claimed:
        raise WorkerTransactionError("execution authority digest mismatch")
    if normalized["run_id"] != run_id:
        raise WorkerTransactionError("execution authority run mismatch")
    if normalized["phase"] != getattr(contract, "phase", None):
        raise WorkerTransactionError("execution authority phase mismatch")
    if normalized["work_unit_id"] != getattr(contract, "work_unit_id", None):
        raise WorkerTransactionError("execution authority work-unit mismatch")
    if normalized["contract_digest"] != getattr(contract, "digest", None):
        raise WorkerTransactionError("execution authority contract mismatch")
    if normalized["launch_digest"] != getattr(launch, "digest", None):
        raise WorkerTransactionError("execution authority launch mismatch")

    root = _checked_root_directory(
        scratchpad,
        label="scratchpad",
    )
    attempt_path = _safe_relative_file(
        root,
        normalized["attempt_completion_relative_path"],
        "attempt completion",
    )
    attempt, attempt_digest = _read_digest_bound_json(
        attempt_path,
        digest_field="completion_digest",
        label="attempt completion",
    )
    if attempt_digest != normalized["attempt_completion_digest"]:
        raise WorkerTransactionError("attempt completion authority mismatch")
    if (
        attempt.get("run_id") != normalized["run_id"]
        or attempt.get("phase") != normalized["phase"]
        or attempt.get("work_unit_id") != normalized["work_unit_id"]
        or attempt.get("generation") != normalized["generation"]
        or attempt.get("work_plan_digest") != normalized["work_plan_digest"]
        or attempt.get("attempt_id") != normalized["attempt_id"]
        or attempt.get("provider_completion_relative_path")
        != normalized["provider_completion_relative_path"]
        or attempt.get("provider_completion_digest")
        != normalized["provider_completion_digest"]
        or attempt.get("canonical_projection_state") != "PENDING_PHASE_IO"
    ):
        raise WorkerTransactionError("attempt completion chain is inconsistent")

    provider = _safe_relative_file(
        root,
        normalized["provider_completion_relative_path"],
        "provider completion",
    )
    provider_value, provider_digest = _read_digest_bound_json(
        provider,
        digest_field="completion_sha256",
        label="provider completion",
        canonical_newline=True,
    )
    if (
        provider_digest != normalized["provider_completion_digest"]
        or provider_value.get("output_source_mode") not in {
            STDOUT_ASSIGNED_OUTPUT,
            WORKER_FILE_OUTPUTS,
        }
    ):
        raise WorkerTransactionError("provider completion chain is inconsistent")

    incorporation_path = _safe_relative_file(
        root,
        normalized["incorporation_relative_path"],
        "worker incorporation",
    )
    incorporation, incorporation_digest = _read_digest_bound_json(
        incorporation_path,
        digest_field="incorporation_digest",
        label="worker incorporation",
    )
    if incorporation_digest != normalized["incorporation_digest"]:
        raise WorkerTransactionError("incorporation authority mismatch")
    if (
        incorporation.get("schema")
        != "plamen.worker_phaseio_incorporation.v1"
        or incorporation.get("run_id") != normalized["run_id"]
        or incorporation.get("phase") != normalized["phase"]
        or incorporation.get("work_unit_id") != normalized["work_unit_id"]
        or incorporation.get("generation") != normalized["generation"]
        or incorporation.get("work_plan_digest")
        != normalized["work_plan_digest"]
        or incorporation.get("attempt_id") != normalized["attempt_id"]
        or incorporation.get("provider_completion_digest")
        != normalized["provider_completion_digest"]
        or incorporation.get("contract_digest") != normalized["contract_digest"]
        or incorporation.get("launch_digest") != normalized["launch_digest"]
        or incorporation.get("projection_state") != "COMPLETE"
    ):
        raise WorkerTransactionError("incorporation chain is inconsistent")
    projected = incorporation.get("projected_members")
    expected_identities = sorted(
        item.identity for item in getattr(contract, "outputs", ())
    )
    if (
        not isinstance(projected, list)
        or sorted(
            row.get("canonical_identity")
            for row in projected
            if isinstance(row, dict)
        )
        != expected_identities
        or len(projected) != len(expected_identities)
    ):
        raise WorkerTransactionError("incorporation output denominator mismatch")
    for row in projected:
        if not isinstance(row, dict):
            raise WorkerTransactionError("incorporation member is malformed")
        destination = _projection_destination(root, row["canonical_identity"])
        state = _artifact_state(destination)
        if (
            state["status"] != "ACTIVE"
            or state["sha256"] != row.get("sha256")
            or state["size"] != row.get("size")
        ):
            raise WorkerTransactionError("incorporated canonical bytes changed")
    return normalized


def incorporate_worker_execution(
    execution_ref: ExecutionRef,
    phase_io_contract: Any,
    *,
    phase_io_launch: Any,
    work_plan: Mapping[str, Any],
    parser_digest: ParserDigest,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    staged_output_validator: StagedOutputValidator | None = None,
    staged_output_context: Mapping[str, Any] | None = None,
) -> IncorporationRef:
    """Project one staged execution through a durable PhaseIO transaction."""

    from artifact_ledger import (
        read_artifact_ledger,
        record_work_unit_artifacts,
    )
    from phase_io_contracts import (
        ConditionalOutputReceipt,
        LaunchSpec,
        PhaseIOContract,
    )

    if not isinstance(execution_ref, ExecutionRef):
        raise WorkerTransactionError("execution_ref must be an ExecutionRef")
    if not isinstance(phase_io_contract, PhaseIOContract):
        raise WorkerTransactionError("phase_io_contract must be a PhaseIOContract")
    if not isinstance(phase_io_launch, LaunchSpec):
        raise WorkerTransactionError("phase_io_launch must be a LaunchSpec")
    if (staged_output_validator is None) != (staged_output_context is None):
        raise WorkerTransactionError(
            "staged output validator and context must be supplied together"
        )
    plan = _validate_compiled_plan(work_plan)
    if (
        execution_ref.run_id != run_id
        or execution_ref.run_id != plan["run_id"]
        or execution_ref.phase != plan["phase"]
        or execution_ref.work_unit_id != plan["work_unit_id"]
        or execution_ref.generation != plan["generation"]
        or execution_ref.work_plan_digest != plan["work_plan_digest"]
    ):
        raise WorkerTransactionError("execution reference and WorkPlan differ")
    if (
        phase_io_contract.phase != plan["phase"]
        or phase_io_contract.work_unit_id != plan["work_unit_id"]
        or phase_io_contract.digest != plan["phase_io_contract_digest"]
        or phase_io_launch.work_unit_key != phase_io_contract.key
        or phase_io_launch.digest != plan["phase_io_launch_digest"]
    ):
        raise WorkerTransactionError("WorkPlan and PhaseIO authority differ")

    root = _checked_root_directory(
        scratchpad,
        label="scratchpad",
    )
    project = _checked_root_directory(
        project_root,
        label="project root",
    )
    attempt_arm = _validate_arm(
        _read_json(
            execution_ref.attempt_directory / "arm.json",
            "worker attempt arm",
        ),
        run_id=run_id,
        phase_dir=execution_ref.attempt_directory.parents[2],
        unit_dir=execution_ref.attempt_directory.parents[1],
        plan_dir=execution_ref.attempt_directory.parent,
        attempt_dir=execution_ref.attempt_directory,
    )
    plan_completion_policy = plan.get("completion_policy")
    if not isinstance(plan_completion_policy, Mapping):
        raise WorkerTransactionError("WorkPlan completion policy is malformed")
    raw_plan_startup_binding = plan_completion_policy.get(
        AUXILIARY_STARTUP_POLICY_KEY
    )
    if attempt_arm.get(AUXILIARY_STARTUP_POLICY_KEY) != (
        raw_plan_startup_binding
    ):
        raise WorkerTransactionError(
            "WorkPlan and AttemptArm startup permits differ"
        )
    _validate_attempt_completion(
        execution_ref.attempt_completion_path,
        arm=attempt_arm,
    )
    completion = validate_staged_execution(
        scratchpad=root,
        receipt_path=execution_ref.provider_execution.receipt_path,
        parser_digest=parser_digest,
        expected_completion_sha256=(
            execution_ref.provider_execution.completion_sha256
        ),
    )
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(phase_io_contract.key)
    if (
        not isinstance(prior, dict)
        or prior.get("run_id") != run_id
        or prior.get("contract_digest") != phase_io_contract.digest
        or prior.get("launch_digest") != phase_io_launch.digest
        or prior.get("semantic_status") not in {"INPUTS_BOUND", "ACTIVE"}
        or prior.get("input_set_digest") != plan["phase_io_input_set_digest"]
    ):
        raise WorkerTransactionError(
            "PhaseIO pre-execution input authority is absent or drifted"
        )
    output_prestates = prior.get("output_prestates")
    if not isinstance(output_prestates, dict):
        raise WorkerTransactionError("PhaseIO output prestates are malformed")
    completion_policy = plan_completion_policy
    staged_gate = completion_policy.get("staged_semantic_gate")
    if staged_output_validator is None:
        if staged_gate is not None:
            raise WorkerTransactionError(
                "WorkPlan requires a staged semantic validator"
            )
    else:
        if not isinstance(staged_gate, Mapping):
            raise WorkerTransactionError(
                "WorkPlan staged semantic validator binding is absent"
            )
        gate_inputs = staged_gate.get("required_input_bindings")
        prior_inputs = prior.get("input_bindings")
        if not isinstance(gate_inputs, Mapping) or not isinstance(
            prior_inputs, Mapping
        ):
            raise WorkerTransactionError(
                "staged semantic validator input denominator is malformed"
            )
        expected_gate = staged_output_validator_binding(
            staged_output_validator,
            context=staged_output_context,
            required_input_bindings={
                str(identity): prior_inputs.get(identity)
                for identity in gate_inputs
            },
            write_scope=(
                attempt_arm["materialized"]["write_scope"]
                if plan["schema"] == WORKER_WORK_PLAN_SCHEMA_V2
                else None
            ),
        )
        if dict(staged_gate) != expected_gate:
            raise WorkerTransactionError(
                "staged semantic validator authority drifted"
            )

    members = plan["assignment"]["members"]
    output_rows = completion.get("outputs")
    if not isinstance(output_rows, list) or len(output_rows) != len(members):
        raise WorkerTransactionError("execution/assignment denominator mismatch")
    contract_identities = sorted(item.identity for item in phase_io_contract.outputs)
    plan_identities = sorted(member["canonical_identity"] for member in members)
    if plan_identities != contract_identities:
        raise WorkerTransactionError("WorkPlan does not cover the PhaseIO output denominator")

    incorporation_dir = _make_safe_directory_tree(
        root,
        (
            execution_ref.attempt_directory.relative_to(root).as_posix()
            + "/incorporation"
        ),
    )
    projected_rows: list[dict[str, Any]] = []
    arm_members: list[dict[str, Any]] = []
    staged_raw: dict[str, bytes] = {}
    for member, output in zip(members, output_rows):
        if (
            not isinstance(output, dict)
            or output.get("relative_path") != member["staged_relative_path"]
            or output.get("publish_relative_path")
            != member["canonical_identity"].removeprefix("scratchpad:")
        ):
            raise WorkerTransactionError("execution output and assignment member differ")
        identity = member["canonical_identity"]
        ledger_prestate = output_prestates.get(identity)
        if not isinstance(ledger_prestate, dict):
            raise WorkerTransactionError("PhaseIO output prestate is missing")
        declared_prestate = member["canonical_prestate"]
        for field in ("status", "sha256", "size"):
            if declared_prestate.get(field) != ledger_prestate.get(field):
                raise WorkerTransactionError(
                    "WorkPlan canonical prestate disagrees with PhaseIO"
                )
        blob = output.get("cas_blob")
        if (
            not isinstance(blob, dict)
            or set(blob) != {"relative_path", "sha256", "size"}
        ):
            raise WorkerTransactionError("provider CAS binding is malformed")
        blob_path = _safe_relative_file(
            execution_ref.provider_execution.receipt_path.parent,
            blob["relative_path"],
            "provider output CAS",
        )
        raw = _read_rooted_bytes(blob_path)
        if (
            len(raw) != blob["size"]
            or hashlib.sha256(raw).hexdigest() != blob["sha256"]
            or blob["sha256"] != output.get("raw_sha256")
        ):
            raise WorkerTransactionError("provider output CAS bytes changed")
        staged_raw[identity] = raw
        arm_members.append(
            {
                "canonical_identity": identity,
                "projection_mode": member["projection_mode"],
                "canonical_prestate": declared_prestate,
                "source_sha256": blob["sha256"],
                "source_size": blob["size"],
            }
        )

    if staged_output_validator is not None:
        try:
            raw_issues = staged_output_validator(
                dict(staged_raw),
                dict(staged_output_context or {}),
            )
        except Exception as exc:
            raise WorkerTransactionError(
                "staged semantic validator raised: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if (
            isinstance(raw_issues, (str, bytes))
            or not isinstance(raw_issues, Sequence)
        ):
            raise WorkerTransactionError(
                "staged semantic validator returned a malformed issue set"
            )
        issues = [
            str(value).strip()
            for value in raw_issues
            if str(value).strip()
        ]
        if (
            len(issues) > 64
            or any(len(value) > 2048 or "\x00" in value for value in issues)
        ):
            raise WorkerTransactionError(
                "staged semantic validator issue set exceeds its bound"
            )
        if issues:
            raise WorkerTransactionError(
                "staged semantic validation failed: " + "; ".join(issues)
            )

    incorporation_arm: dict[str, Any] = {
        "schema": "plamen.worker_phaseio_incorporation_arm.v1",
        "run_id": run_id,
        "phase": plan["phase"],
        "work_unit_id": plan["work_unit_id"],
        "generation": plan["generation"],
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": execution_ref.attempt_id,
        "provider_completion_digest": (
            execution_ref.provider_execution.completion_sha256
        ),
        "contract_digest": phase_io_contract.digest,
        "launch_digest": phase_io_launch.digest,
        "input_set_digest": plan["phase_io_input_set_digest"],
        "members": arm_members,
    }
    incorporation_arm["arm_digest"] = _digest(incorporation_arm)
    arm_path = incorporation_dir / "arm.json"
    if _rooted_lexists(arm_path):
        existing, existing_digest = _read_digest_bound_json(
            arm_path,
            digest_field="arm_digest",
            label="incorporation arm",
        )
        if existing_digest != incorporation_arm["arm_digest"] or existing != incorporation_arm:
            raise WorkerTransactionError("incorporation arm drifted")
    else:
        _write_absent_json(arm_path, incorporation_arm)

    for index, (member, output) in enumerate(zip(members, output_rows)):
        identity = member["canonical_identity"]
        blob = output["cas_blob"]
        raw = staged_raw[identity]
        destination = _projection_destination(root, identity)
        progress_path = incorporation_dir / f"member-{index:04d}.json"
        if _rooted_lexists(progress_path):
            progress, _progress_digest = _read_digest_bound_json(
                progress_path,
                digest_field="member_digest",
                label="incorporation member",
            )
            state = _artifact_state(destination)
            if (
                progress.get("canonical_identity") != identity
                or progress.get("sha256") != state["sha256"]
                or progress.get("size") != state["size"]
            ):
                raise WorkerTransactionError("incorporation progress cannot replay")
            projected_rows.append(
                {
                    "canonical_identity": identity,
                    "sha256": state["sha256"],
                    "size": state["size"],
                }
            )
            continue

        current = _artifact_state(destination)
        declared = member["canonical_prestate"]
        write_mode = str(declared.get("write_mode") or "REPLACE")

        # PhaseIO uses semantic prestate labels while the rooted filesystem
        # observer deliberately has only ACTIVE/ABSENT physical states.  An
        # APPEND producer therefore arrives with ACTIVE_PREIMAGE even though
        # the unchanged destination is physically ACTIVE.  Comparing those
        # labels literally made every isolated APPEND transaction fail before
        # publication (notably Thorough semantic-invariant Pass 2).
        expected_physical_status = {
            "ACTIVE_PREIMAGE": "ACTIVE",
            "ACTIVE_REGISTERED_PREDECESSOR": "ACTIVE",
            "VALIDATED_EXTERNAL_EMPTY_PREIMAGE": "ABSENT",
        }.get(str(declared.get("status") or ""), declared.get("status"))

        projected_raw = raw
        already_projected = bool(
            current["status"] == "ACTIVE"
            and current["sha256"] == blob["sha256"]
            and current["size"] == blob["size"]
        )
        if write_mode == "APPEND":
            if current["status"] != "ACTIVE":
                raise WorkerTransactionError("APPEND destination is absent")
            current_raw = _read_rooted_bytes(destination)
            declared_size = int(declared.get("size") or 0)
            declared_sha256 = str(declared.get("sha256") or "")
            current_is_preimage = bool(
                current["status"] == expected_physical_status
                and current["size"] == declared_size
                and current["sha256"] == declared_sha256
            )
            if current_is_preimage:
                # Providers write into an attempt-owned output, so an APPEND
                # result may be either the append fragment (the normal routed
                # contract) or a complete prefix-preserving successor.  The
                # driver composes the former and accepts the latter without
                # duplicating the prefix.
                projected_raw = (
                    raw
                    if len(raw) > len(current_raw) and raw.startswith(current_raw)
                    else current_raw + raw
                )
                already_projected = False
            else:
                prefix_preserved = bool(
                    declared_size >= 0
                    and len(current_raw) >= declared_size
                    and hashlib.sha256(current_raw[:declared_size]).hexdigest()
                    == declared_sha256
                )
                staged_is_full_successor = bool(
                    len(raw) >= declared_size
                    and hashlib.sha256(raw[:declared_size]).hexdigest()
                    == declared_sha256
                    and current_raw == raw
                )
                staged_is_append_fragment = bool(
                    prefix_preserved
                    and current_raw[declared_size:] == raw
                )
                already_projected = (
                    staged_is_full_successor or staged_is_append_fragment
                )
                if not already_projected:
                    raise WorkerTransactionError(
                        "canonical projection prestate changed"
                    )
                projected_raw = current_raw
        if not already_projected:
            if any(
                current[field]
                != (
                    expected_physical_status
                    if field == "status"
                    else declared.get(field)
                )
                for field in ("status", "sha256", "size")
            ):
                raise WorkerTransactionError("canonical projection prestate changed")
            if member["projection_mode"] == "CREATE_ABSENT":
                if current["status"] != "ABSENT":
                    raise WorkerTransactionError(
                        "CREATE_ABSENT destination acquired bytes"
                    )
                _immutable_bytes(destination, raw)
            elif member["projection_mode"] == "REPLACE_EXACT_PRESTATE":
                if current["status"] != "ACTIVE":
                    raise WorkerTransactionError("replacement destination is absent")
                _replace_exact_bytes(destination, projected_raw)
            else:
                raise WorkerTransactionError("projection mode is unsupported")
        state = _artifact_state(destination)
        projected_sha256 = hashlib.sha256(projected_raw).hexdigest()
        if (
            state["sha256"] != projected_sha256
            or state["size"] != len(projected_raw)
        ):
            raise WorkerTransactionError("projected canonical bytes do not match CAS")
        progress: dict[str, Any] = {
            "schema": "plamen.worker_phaseio_member.v1",
            "arm_digest": incorporation_arm["arm_digest"],
            "index": index,
            "canonical_identity": identity,
            "sha256": state["sha256"],
            "size": state["size"],
        }
        progress["member_digest"] = _digest(progress)
        _write_absent_json(progress_path, progress)
        projected_rows.append(
            {
                "canonical_identity": identity,
                "sha256": state["sha256"],
                "size": state["size"],
            }
        )

    incorporation: dict[str, Any] = {
        "schema": "plamen.worker_phaseio_incorporation.v1",
        "run_id": run_id,
        "phase": plan["phase"],
        "work_unit_id": plan["work_unit_id"],
        "generation": plan["generation"],
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": execution_ref.attempt_id,
        "provider_completion_digest": (
            execution_ref.provider_execution.completion_sha256
        ),
        "contract_digest": phase_io_contract.digest,
        "launch_digest": phase_io_launch.digest,
        "input_set_digest": plan["phase_io_input_set_digest"],
        "arm_digest": incorporation_arm["arm_digest"],
        "projection_state": "COMPLETE",
        "projected_members": projected_rows,
    }
    incorporation["incorporation_digest"] = _digest(incorporation)
    incorporation_path = incorporation_dir / "incorporation.json"
    if _rooted_lexists(incorporation_path):
        existing, existing_digest = _read_digest_bound_json(
            incorporation_path,
            digest_field="incorporation_digest",
            label="worker incorporation",
        )
        if (
            existing_digest != incorporation["incorporation_digest"]
            or existing != incorporation
        ):
            raise WorkerTransactionError("worker incorporation drifted")
    else:
        _write_absent_json(incorporation_path, incorporation)

    attempt_completion, attempt_completion_digest = _read_digest_bound_json(
        execution_ref.attempt_completion_path,
        digest_field="completion_digest",
        label="attempt completion",
    )
    authority: dict[str, Any] = {
        "schema": "plamen.worker_execution_authority.v1",
        "run_id": run_id,
        "phase": plan["phase"],
        "work_unit_id": plan["work_unit_id"],
        "generation": plan["generation"],
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": execution_ref.attempt_id,
        "attempt_completion_relative_path": (
            execution_ref.attempt_completion_path.relative_to(root).as_posix()
        ),
        "attempt_completion_digest": attempt_completion_digest,
        "provider_completion_relative_path": attempt_completion[
            "provider_completion_relative_path"
        ],
        "provider_completion_digest": attempt_completion[
            "provider_completion_digest"
        ],
        "incorporation_relative_path": incorporation_path.relative_to(
            root
        ).as_posix(),
        "incorporation_digest": incorporation["incorporation_digest"],
        "contract_digest": phase_io_contract.digest,
        "launch_digest": phase_io_launch.digest,
    }
    authority["authority_digest"] = _digest(authority)
    normalized_authority = validate_worker_execution_authority(
        scratchpad=root,
        authority=authority,
        contract=phase_io_contract,
        launch=phase_io_launch,
        run_id=run_id,
    )
    conditional_receipts = {
        spec.identity: ConditionalOutputReceipt(
            work_unit_key=phase_io_contract.key,
            contract_digest=phase_io_contract.digest,
            artifact_identity=spec.identity,
            condition_id=spec.condition_id,
            state="PRODUCED",
            expected_denominator=1,
            produced_identities=(spec.identity,),
        )
        for spec in phase_io_contract.outputs
        if spec.artifact_class == "CONDITIONAL"
    }
    record_work_unit_artifacts(
        root,
        project,
        phase_io_contract,
        phase_io_launch,
        run_id=run_id,
        actor=("MODEL" if phase_io_contract.model_invoked else "DRIVER"),
        conditional_receipts=conditional_receipts,
        execution_authority=normalized_authority,
    )
    return IncorporationRef(
        incorporation_path=incorporation_path,
        incorporation_digest=incorporation["incorporation_digest"],
        execution_ref=execution_ref,
        projected_paths=tuple(
            _projection_destination(root, row["canonical_identity"])
            for row in projected_rows
        ),
    )


def recover_worker_transactions(
    *, run_id: str, scratchpad: str | Path
) -> RecoveryStatus:
    """Convert orphaned arms into durable retry debt without minting completion.

    This Stage-0 recovery provider classifies only attempts with no terminal
    artifact.  Full platform-specific population-zero recovery is added with
    ``OwnedProcessScope`` before production launcher cutover; until then an
    interrupted attempt can only be retried and can never authorize output.
    """

    bound_run_id = _identifier(run_id, "run_id")
    root = _checked_root_directory(
        scratchpad,
        label="scratchpad",
    )
    transaction_root = root / ".worker_transactions"
    if not _rooted_lexists(transaction_root):
        return RecoveryStatus((), ())
    _safe_directory(transaction_root, "worker transaction root")

    retry_units: set[str] = set()
    blocked_units: set[str] = set()
    terminal_attempts: set[str] = set()
    root_entries = _children(transaction_root)
    allowed_root_files = {"active_attempts.json", "active_attempts.lock"}
    for entry in root_entries:
        if entry.name in allowed_root_files:
            if entry.name == "active_attempts.json":
                _active_registry(transaction_root)
            elif (
                _rooted_is_symlink(entry)
                or _is_reparse(entry)
                or not _rooted_is_file(entry)
            ):
                raise WorkerTransactionError("active-attempt lock artifact is unsafe")
            continue
        phase_dir = entry
        _safe_directory(phase_dir, "worker transaction phase")
        _identifier(phase_dir.name, "phase directory")
        for unit_dir in _children(phase_dir):
            _safe_directory(unit_dir, "worker transaction unit")
            _identifier(unit_dir.name, "work-unit directory")
            for plan_dir in _children(unit_dir):
                _safe_directory(plan_dir, "worker transaction plan")
                if (
                    plan_dir.name != "attempts"
                    and not re.fullmatch(
                        r"[0-9a-f]{32}|[0-9a-f]{64}", plan_dir.name
                    )
                ):
                    raise WorkerTransactionError(
                        "work-plan directory has an invalid digest prefix"
                    )
                for attempt_dir in _children(plan_dir):
                    _safe_directory(attempt_dir, "worker transaction attempt")
                    _identifier(attempt_dir.name, "attempt directory")
                    allowed = {
                        "arm.json",
                        "completion.json",
                        "debt.json",
                        "view",
                        "output",
                        "incorporation",
                    }
                    names = {entry.name for entry in _children(attempt_dir)}
                    if not names <= allowed or "arm.json" not in names:
                        raise WorkerTransactionError(
                            f"worker attempt directory has an invalid denominator: {attempt_dir}"
                        )
                    arm = _validate_arm(
                        _read_json(attempt_dir / "arm.json", "worker attempt arm"),
                        run_id=bound_run_id,
                        phase_dir=phase_dir,
                        unit_dir=unit_dir,
                        plan_dir=plan_dir,
                        attempt_dir=attempt_dir,
                    )
                    has_completion = "completion.json" in names
                    has_debt = "debt.json" in names
                    for directory_name in ("view", "output", "incorporation"):
                        if directory_name in names:
                            _safe_directory(
                                attempt_dir / directory_name,
                                f"worker attempt {directory_name}",
                            )
                    if has_completion and has_debt:
                        raise WorkerTransactionError(
                            "worker attempt has both completion and debt"
                        )
                    if has_completion or has_debt:
                        if has_completion:
                            _validate_attempt_completion(
                                attempt_dir / "completion.json",
                                arm=arm,
                            )
                        else:
                            _validate_attempt_debt(
                                attempt_dir / "debt.json",
                                arm=arm,
                            )
                        terminal_attempts.add(arm["attempt_id"])
                        continue

                    cleanup_detail = ""
                    retry_required = True
                    reason_code = "INTERRUPTED_PROVIDER_CRASH"
                    try:
                        cleanup = recover_persisted_process_scope(
                            arm["process_scope"]["persistent_identity"]
                        )
                        cleanup_detail = (
                            f"; scope_cleanup={cleanup['cleanup']}"
                        )
                    except OwnedProcessScopeError as exc:
                        reason_code = "INTERRUPTED_SCOPE_CLEANUP_FAILED"
                        retry_required = False
                        blocked_units.add(arm["work_unit_id"])
                        cleanup_detail = (
                            f"; scope_cleanup_error={type(exc).__name__}: {exc}"
                        )
                    debt: dict[str, Any] = {
                        "schema": WORKER_ATTEMPT_DEBT_SCHEMA,
                        "run_id": arm["run_id"],
                        "phase": arm["phase"],
                        "work_unit_id": arm["work_unit_id"],
                        "generation": arm["generation"],
                        "work_plan_digest": arm["work_plan_digest"],
                        "attempt_id": arm["attempt_id"],
                        "arm_digest": arm["arm_digest"],
                        "reason_code": reason_code,
                        "detail": (
                            "attempt was armed without a durable terminal "
                            f"artifact during recovery{cleanup_detail}"
                        ),
                        "completion_emitted": False,
                        "retry_required": retry_required,
                    }
                    debt["debt_digest"] = _digest(debt)
                    _write_absent_json(attempt_dir / "debt.json", debt)
                    if retry_required:
                        retry_units.add(arm["work_unit_id"])
                    terminal_attempts.add(arm["attempt_id"])

    with _registry_lock(transaction_root):
        registry = _active_registry(transaction_root)
        if registry["attempts"]:
            cleared: dict[str, Any] = {
                "schema": "plamen.worker_active_attempts.v1",
                "attempts": {},
            }
            cleared["registry_digest"] = _digest(cleared)
            _replace_json(transaction_root / "active_attempts.json", cleared)

    return RecoveryStatus(
        active_attempt_ids=(),
        retry_work_unit_ids=tuple(sorted(retry_units)),
        terminal_attempt_ids=tuple(sorted(terminal_attempts)),
        blocked_work_unit_ids=tuple(sorted(blocked_units)),
    )


def reconcile_phase_work_roster(
    roster: Mapping[str, Any], *, scratchpad: str | Path
) -> PhaseExecutionStatus:
    """Reconcile exact roster parity, terminal attempts, and incorporations."""

    from artifact_ledger import read_artifact_ledger

    bound = _validate_phase_roster(roster)
    root = _checked_root_directory(
        scratchpad,
        label="scratchpad",
    )
    expected_units = set(bound["required_work_unit_ids"]) | set(
        bound["optional_work_unit_ids"]
    )
    transaction_root = root / ".worker_transactions"
    if not _rooted_lexists(transaction_root):
        return PhaseExecutionStatus(
            clean=False,
            completed_with_debt=False,
            incorporated_work_unit_ids=(),
            debt_work_unit_ids=(),
            missing_work_unit_ids=tuple(sorted(expected_units)),
            active_attempt_ids=(),
        )
    _safe_directory(transaction_root, "worker transaction root")
    registry = _active_registry(transaction_root)
    active_rows = registry["attempts"]

    phase_dir = transaction_root / bound["phase"]
    units_with_terminal: set[str] = set()
    debt_units: set[str] = set()
    unrostered_units: set[str] = set()
    active_attempt_set: set[str] = set()
    for attempt_id, row in active_rows.items():
        if row["run_id"] != bound["run_id"]:
            raise WorkerTransactionError(
                "foreign-run active attempt found in scratchpad"
            )
        if row["phase"] != bound["phase"]:
            continue
        unit = row["work_unit_id"]
        active_attempt_set.add(attempt_id)
        if unit not in expected_units:
            unrostered_units.add(unit)
        elif (
            row["generation"] != bound["generation"]
            or row["work_plan_digest"]
            != bound["work_plan_digests"][unit]
            or (
                "phase_roster_digest" in row
                and row["phase_roster_digest"] != bound["roster_digest"]
            )
        ):
            debt_units.add(unit)
    if _rooted_lexists(phase_dir):
        _safe_directory(phase_dir, "phase transaction directory")
        for unit_dir in _children(phase_dir):
            _safe_directory(unit_dir, "work-unit transaction directory")
            unit = _identifier(unit_dir.name, "work-unit directory")
            if unit not in expected_units:
                unrostered_units.add(unit)
            for plan_dir in _children(unit_dir):
                _safe_directory(plan_dir, "work-plan transaction directory")
                if (
                    plan_dir.name != "attempts"
                    and not re.fullmatch(
                        r"[0-9a-f]{32}|[0-9a-f]{64}", plan_dir.name
                    )
                ):
                    raise WorkerTransactionError(
                        "work-plan directory has an invalid digest prefix"
                    )
                for attempt_dir in _children(plan_dir):
                    _safe_directory(attempt_dir, "attempt transaction directory")
                    arm_path = attempt_dir / "arm.json"
                    arm = _validate_arm(
                        _read_json(arm_path, "worker attempt arm"),
                        run_id=bound["run_id"],
                        phase_dir=phase_dir,
                        unit_dir=unit_dir,
                        plan_dir=plan_dir,
                        attempt_dir=attempt_dir,
                    )
                    if arm["generation"] != bound["generation"]:
                        debt_units.add(unit)
                    if (
                        arm["work_plan_digest"]
                        != bound["work_plan_digests"].get(unit)
                    ):
                        debt_units.add(unit)
                    has_completion = _rooted_is_file(
                        attempt_dir / "completion.json"
                    )
                    has_debt = _rooted_is_file(
                        attempt_dir / "debt.json"
                    )
                    if has_completion and has_debt:
                        raise WorkerTransactionError(
                            "worker attempt has both completion and debt"
                        )
                    if has_completion:
                        _validate_attempt_completion(
                            attempt_dir / "completion.json",
                            arm=arm,
                        )
                        units_with_terminal.add(unit)
                    elif has_debt:
                        _validate_attempt_debt(
                            attempt_dir / "debt.json",
                            arm=arm,
                        )
                        units_with_terminal.add(unit)
                        debt_units.add(unit)
                    else:
                        active_attempt_set.add(arm["attempt_id"])

    ledger = read_artifact_ledger(root)
    incorporated: set[str] = set()
    for unit_record in ledger.get("work_units", {}).values():
        if not isinstance(unit_record, dict):
            continue
        authority = unit_record.get("execution_authority")
        if (
            unit_record.get("run_id") != bound["run_id"]
            or unit_record.get("semantic_status") != "ACTIVE"
            or not isinstance(authority, dict)
            or authority.get("phase") != bound["phase"]
            or authority.get("generation") != bound["generation"]
        ):
            continue
        unit = authority.get("work_unit_id")
        if unit not in expected_units:
            unrostered_units.add(str(unit))
            continue
        expected_plan = bound["work_plan_digests"][unit]
        if authority.get("work_plan_digest") != expected_plan:
            debt_units.add(unit)
            continue
        incorporation_path = _safe_relative_file(
            root,
            authority.get("incorporation_relative_path"),
            "roster incorporation",
        )
        incorporation, incorporation_digest = _read_digest_bound_json(
            incorporation_path,
            digest_field="incorporation_digest",
            label="roster incorporation",
        )
        if (
            incorporation_digest != authority.get("incorporation_digest")
            or incorporation.get("projection_state") != "COMPLETE"
            or incorporation.get("work_plan_digest") != expected_plan
        ):
            debt_units.add(unit)
            continue
        incorporated.add(unit)

    debt_units.update(unrostered_units)
    missing = {
        unit
        for unit in expected_units
        if unit not in incorporated and unit not in debt_units
    }
    # A terminal provider completion that was never incorporated is visible
    # debt, never implicit success.
    debt_units.update(units_with_terminal - incorporated)
    missing -= debt_units
    required = set(bound["required_work_unit_ids"])
    optional = set(bound["optional_work_unit_ids"])
    active_attempts = tuple(sorted(active_attempt_set))
    all_disposed = not missing and not active_attempts and (
        expected_units <= incorporated | debt_units
    )
    clean = bool(
        all_disposed
        and required <= incorporated
        and optional <= incorporated
        and not debt_units
    )
    completed_with_debt = bool(
        all_disposed and not clean and debt_units
    )
    return PhaseExecutionStatus(
        clean=clean,
        completed_with_debt=completed_with_debt,
        incorporated_work_unit_ids=tuple(sorted(incorporated)),
        debt_work_unit_ids=tuple(sorted(debt_units)),
        missing_work_unit_ids=tuple(sorted(missing)),
        active_attempt_ids=active_attempts,
    )


__all__ = [
    "ALL_REQUIRED_INCORPORATED",
    "ATTEMPT_ID_PLACEHOLDER",
    "ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER",
    "ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER",
    "ATTEMPT_RELATIVE_PATH_PLACEHOLDER",
    "AUXILIARY_STARTUP_POLICY_KEY",
    "CLAUDE_LAUNCH_SECURITY_POLICY_KEY",
    "CLAUDE_PROVIDER_PREPARATION_POLICY_KEY",
    "CLAUDE_STREAM_STDOUT_POLICY_KEY",
    "CODEX_HOME_PLACEHOLDER",
    "CODEX_RUNTIME_AUTH_POLICY_KEY",
    "ExecutionRef",
    "HeadlessModelAdapter",
    "IncorporationRef",
    "NativeCommandAdapter",
    "PHASE_WORK_ROSTER_SCHEMA",
    "PhaseExecutionStatus",
    "RecoveryStatus",
    "StagedOutputValidator",
    "WORKER_ATTEMPT_ARM_SCHEMA",
    "WORKER_ATTEMPT_ARM_SCHEMA_V2",
    "WORKER_ATTEMPT_ARM_SCHEMA_V3",
    "WORKER_ATTEMPT_DEBT_SCHEMA",
    "WorkerTransactionError",
    "attempt_output_directory",
    "compile_attempt_write_scope",
    "compile_attempt_write_scope_template",
    "compile_phase_work_roster",
    "compile_phase_work_roster_denominator",
    "compile_worker_plan",
    "execute_worker_transaction",
    "incorporate_worker_execution",
    "reconcile_phase_work_roster",
    "recover_worker_transactions",
    "prompt_template_sha256",
    "staged_output_validator_binding",
    "validate_worker_execution_authority",
    "validate_phase_work_roster",
    "validate_work_plan_phase_roster",
]
