"""Strict post-work reconciliation for MethodCard application claims.

The v1 API is deliberately a non-authoritative foundation: it reconciles
caller-supplied claim/review structures but cannot establish their authorship.
The v2 API consumes only provider-authored typed outputs replayed through
WorkerTransaction and PhaseIO.  Neither version can prove findings, negatives,
severity, report placement, or drops.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any, NoReturn

from method_card_catalog import (
    MethodCard,
    MethodCardCatalog,
    MethodCardCatalogError,
    load_method_card_catalog,
)
from method_card_runtime_authority import (
    ACTIVATED_AUTHORITY_SCHEMA,
    MethodCardRuntimeAuthorityError,
    _replayed_work_plan,
    validate_activated_method_card_runtime_authority,
    validate_method_card_runtime_authority,
)
from phase_io_contracts import LaunchSpec, PhaseIOContract
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
    validate_portable_path,
)
from worker_transaction import (
    WorkerTransactionError,
    validate_worker_execution_authority,
)
from typed_worker_output_authority import (
    METHOD_CARD_PRODUCER_TYPED_ROLE,
    METHOD_CARD_REVIEWER_TYPED_ROLE,
    STRICT_CANONICAL_JSON_PARSER_ID,
    TypedWorkerOutputAuthorityError,
    TypedWorkerOutputReplayWitness,
    ValidatedTypedWorkerOutput,
    canonical_typed_worker_output_authority_bytes,
    replay_typed_worker_output,
)


WORKER_ATTEMPT_SCHEMA = "plamen.method-card-worker-attempt-identity.v1"
PRODUCER_RECEIPT_SCHEMA = "plamen.method-card-producer-application-receipt.v1"
REVIEW_RECEIPT_SCHEMA = "plamen.method-card-independent-application-review.v1"
APPLICATION_AUTHORITY_SCHEMA = "plamen.method-card-application-authority.v1"
PRODUCER_TYPED_OUTPUT_SCHEMA = (
    "plamen.method-card-producer-application-typed-output.v2"
)
REVIEWER_TYPED_OUTPUT_SCHEMA = (
    "plamen.method-card-independent-application-review-typed-output.v2"
)
APPLICATION_AUTHORITY_V2_SCHEMA = (
    "plamen.method-card-application-authority.v2"
)
APPLICATION_AUTHORITY_V3_SCHEMA = (
    "plamen.method-card-application-authority.v3"
)

AUTHORITY_LIMITS = {
    "application_completion_authority": False,
    "drop_authority": False,
    "evidence_proof_authority": False,
    "finding_authority": False,
    "negative_authority": False,
    "report_authority": False,
    "semantic_authority": False,
    "severity_authority": False,
}

V2_AUTHORITY_LIMITS = {
    **AUTHORITY_LIMITS,
    "application_completion_authority": True,
}

V2_TYPED_OUTPUT_AUTHORSHIP = {
    "producer": True,
    "reviewer": True,
    "external_claim_input": False,
    "external_review_input": False,
}

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$", re.ASCII)
_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
_FINDING_HEADING_RE = re.compile(
    r"^ {0,3}#{2,6}[ \t]+Finding[ \t]+\["
    r"(?P<candidate>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\]"
    r"(?=$|[ \t:])",
    re.ASCII,
)
_FENCE_RE = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})")

_IDENTITY_KEYS = frozenset({"path", "sha256", "size_bytes"})
_ATTEMPT_KEYS = frozenset(
    {
        "schema",
        "runtime_authority_digest",
        "run_id",
        "phase",
        "work_unit_id",
        "work_plan_digest",
        "source_snapshot_digest",
        "producer_execution_authority_digest",
        "phase_io_contract_digest",
        "phase_io_launch_digest",
        "attempt_id",
        "output",
        "sources",
        "attempt_digest",
    }
)
_DENOMINATOR_KEYS = frozenset(
    {
        "runtime_denominator_digest",
        "coverage_kind",
        "unknown_remainder",
        "limitation_reason",
        "target_count",
        "relation_count",
        "step_count",
        "targets",
        "relations",
        "steps",
    }
)
_ACTIVATED_DENOMINATOR_KEYS = frozenset(
    {
        "runtime_denominator_digest",
        "coverage_kind",
        "unknown_remainder",
        "limitation_reason",
        "method_count",
        "target_count",
        "relation_count",
        "step_count",
        "methods",
    }
)
_ACTIVATED_METHOD_DENOMINATOR_KEYS = frozenset(
    {
        "method_id",
        "method_version",
        "coverage_kind",
        "unknown_remainder",
        "limitation_reason",
        "target_count",
        "relation_count",
        "step_count",
        "targets",
        "relations",
        "steps",
        "method_denominator_digest",
    }
)
_ACTIVATED_TARGET_KEYS = frozenset({"target_id", "source_files"})
_ACTIVATED_RELATION_KEYS = frozenset(
    {
        "relation_id",
        "selector",
        "source_target_id",
        "destination_target_id",
    }
)
_STEP_KEYS = frozenset({"method_id", "method_version", "step_id"})
_EVIDENCE_KEYS = frozenset({"path", "line_start", "line_end", "sha256"})
_OUTCOME_KEYS = frozenset({"kind", "candidate_ids", "detail"})
_CLAIM_INPUT_KEYS = frozenset(
    {
        "method_id",
        "method_version",
        "producer_claim_state",
        "status",
        "targets_examined",
        "relations_examined",
        "steps_completed",
        "evidence",
        "outcome",
        "unresolved_assumptions",
        "not_applicable_reason",
    }
)
_CLAIM_KEYS = _CLAIM_INPUT_KEYS | {"claim_digest"}
_PRODUCER_KEYS = frozenset(
    {
        "schema",
        "runtime_authority_digest",
        "worker_attempt_digest",
        "producer_execution_authority_digest",
        "output",
        "denominator",
        "claims",
        "receipt_digest",
    }
)
_REVIEW_INPUT_KEYS = frozenset(
    {"method_id", "method_version", "disposition", "evidence", "reason"}
)
_REVIEW_KEYS = _REVIEW_INPUT_KEYS | {"claim_digest", "review_digest"}
_REVIEW_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "runtime_authority_digest",
        "worker_attempt_digest",
        "producer_receipt_digest",
        "producer_execution_authority_digest",
        "reviewer_execution_authority_digest",
        "denominator",
        "reviews",
        "receipt_digest",
    }
)
_PRODUCER_TYPED_PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "role",
        "runtime_authority_digest",
        "source_snapshot_digest",
        "runtime_input_identity",
        "snapshot_input_identity",
        "subject_output",
        "source_files",
        "denominator",
        "claims",
    }
)
_REVIEWER_TYPED_PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "role",
        "runtime_authority_digest",
        "source_snapshot_digest",
        "runtime_input_identity",
        "snapshot_input_identity",
        "producer_authority_input_identity",
        "producer_typed_output_authority_digest",
        "producer_execution_authority_digest",
        "producer_output_identity",
        "producer_output_sha256",
        "producer_payload_digest",
        "denominator",
        "reviews",
    }
)
_METHOD_STATE_KEYS = frozenset(
    {
        "method_id",
        "method_version",
        "producer_claim_state",
        "producer_status",
        "producer_claim_digest",
        "producer_outcome",
        "review_digest",
        "review_disposition",
        "application_disposition",
    }
)
_REVIEW_DEBT_KEYS = frozenset(
    {
        "code",
        "method_id",
        "method_version",
        "claim_digest",
        "review_digest",
        "reason",
    }
)
_DENOMINATOR_DEBT_KEYS = frozenset(
    {"code", "runtime_denominator_digest", "reason"}
)


@dataclass(frozen=True)
class MethodCardRuntimeReplayWitness:
    """Every current external input required to replay runtime authority."""

    audit_snapshot: Mapping[str, Any] | bytes
    work_plan: Mapping[str, Any] | bytes
    denominator_source: Mapping[str, Any] | bytes
    expected_denominator_producer: Mapping[str, Any] | bytes
    expected_graph_binding: Mapping[str, Any] | bytes
    expected_catalog: MethodCardCatalog | None = None
    source_files: Mapping[str, bytes] | None = None


@dataclass(frozen=True)
class WorkerExecutionReplayWitness:
    """Current incorporated WorkerTransaction/PhaseIO execution authority."""

    scratchpad: Path
    authority: Mapping[str, Any]
    phase_io_contract: PhaseIOContract
    phase_io_launch: LaunchSpec
    run_id: str
    work_plan: Mapping[str, Any] | bytes
    audit_snapshot: Mapping[str, Any] | bytes


_APPLICATION_KEYS = frozenset(
    {
        "schema",
        "runtime_authority_digest",
        "worker_attempt_digest",
        "producer_receipt_digest",
        "application_review_receipt_digest",
        "denominator",
        "status",
        "application_complete",
        "method_states",
        "debt",
        "authority_limits",
        "authority_digest",
    }
)
_APPLICATION_V2_KEYS = frozenset(
    {
        "schema",
        "runtime_authority_digest",
        "source_snapshot_digest",
        "producer_typed_output_authority_digest",
        "reviewer_typed_output_authority_digest",
        "producer_payload_digest",
        "reviewer_payload_digest",
        "denominator",
        "status",
        "application_complete",
        "method_states",
        "debt",
        "typed_output_authorship",
        "authority_limits",
        "authority_digest",
    }
)


class MethodCardApplicationAuthorityError(ValueError):
    """An application receipt is incomplete, stale, or not independently bound."""


def _fail(message: str, exc: Exception | None = None) -> NoReturn:
    if exc is None:
        raise MethodCardApplicationAuthorityError(message)
    raise MethodCardApplicationAuthorityError(message) from exc


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    _fail(f"{label} fields are not closed; missing={missing}, extra={extra}")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{label} must be an object")
    return value


def _mapping_input(
    value: Mapping[str, Any] | bytes,
    *,
    label: str,
) -> dict[str, Any]:
    try:
        if isinstance(value, bytes):
            parsed = strict_json_loads(value, require_final_lf=True)
            if not isinstance(parsed, dict):
                _fail(f"{label} must be an object")
            return parsed
        if not isinstance(value, Mapping):
            _fail(f"{label} must be an object or canonical bytes")
        parsed = strict_json_loads(canonical_file_bytes(value), require_final_lf=True)
        if not isinstance(parsed, dict):
            _fail(f"{label} must be an object")
        return parsed
    except ProgramFactsTypeError as exc:
        _fail(f"{label} is not canonical JSON: {exc}", exc)


def _string(value: Any, label: str, *, opaque: bool = False) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a nonempty string")
    if opaque and _OPAQUE_RE.fullmatch(value) is None:
        _fail(f"{label} must be a portable opaque identity")
    return value


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _positive_or_zero_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(f"{label} must be a nonnegative integer")
    return value


def _digest(unsigned: Mapping[str, Any]) -> str:
    try:
        return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    except ProgramFactsTypeError as exc:
        _fail(f"signed application object is not canonical: {exc}", exc)


def _sign(unsigned: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    value = dict(unsigned)
    value.pop(digest_field, None)
    return {**value, digest_field: _digest(value)}


def _check_digest(value: Mapping[str, Any], digest_field: str, label: str) -> None:
    claimed = _hex64(value.get(digest_field), f"{label} {digest_field}")
    unsigned = dict(value)
    unsigned.pop(digest_field, None)
    if claimed != _digest(unsigned):
        _fail(f"{label} digest mismatch")


def _canonical_mapping_value(
    value: Mapping[str, Any] | bytes,
    *,
    label: str,
) -> dict[str, Any]:
    try:
        if isinstance(value, bytes):
            parsed = strict_json_loads(value, require_final_lf=True)
            if not isinstance(parsed, dict):
                _fail(f"{label} must be an object")
            return parsed
        if not isinstance(value, Mapping):
            _fail(f"{label} must be a mapping or canonical bytes")
        parsed = strict_json_loads(canonical_file_bytes(value), require_final_lf=True)
        if not isinstance(parsed, dict):
            _fail(f"{label} must be an object")
        return parsed
    except ProgramFactsTypeError as exc:
        _fail(f"{label} is not canonical: {exc}", exc)


def _runtime_value(
    value: Mapping[str, Any] | bytes,
    *,
    implementation_root: Path | str,
    replay_witness: MethodCardRuntimeReplayWitness,
) -> dict[str, Any]:
    if type(replay_witness) is not MethodCardRuntimeReplayWitness:
        _fail("runtime replay witness must be an exact MethodCardRuntimeReplayWitness")
    try:
        parsed = _mapping_input(value, label="validated runtime authority")
        if parsed.get("schema") == ACTIVATED_AUTHORITY_SCHEMA:
            if replay_witness.source_files is None:
                _fail(
                    "activated runtime replay requires exact current source files"
                )
            return validate_activated_method_card_runtime_authority(
                parsed,
                implementation_root=implementation_root,
                audit_snapshot=replay_witness.audit_snapshot,
                work_plan=replay_witness.work_plan,
                denominator_source=replay_witness.denominator_source,
                expected_denominator_producer=(
                    replay_witness.expected_denominator_producer
                ),
                expected_graph_binding=replay_witness.expected_graph_binding,
                source_files=replay_witness.source_files,
                expected_catalog=replay_witness.expected_catalog,
            )
        return validate_method_card_runtime_authority(
            parsed,
            implementation_root=implementation_root,
            audit_snapshot=replay_witness.audit_snapshot,
            work_plan=replay_witness.work_plan,
            denominator_source=replay_witness.denominator_source,
            expected_denominator_producer=(
                replay_witness.expected_denominator_producer
            ),
            expected_graph_binding=replay_witness.expected_graph_binding,
            expected_catalog=replay_witness.expected_catalog,
        )
    except (MethodCardRuntimeAuthorityError, ProgramFactsTypeError) as exc:
        _fail(f"validated runtime authority does not replay: {exc}", exc)


def _execution_value(
    witness: WorkerExecutionReplayWitness,
    *,
    runtime: Mapping[str, Any],
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    role: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(witness) is not WorkerExecutionReplayWitness:
        _fail(
            f"{role} execution witness must be an exact "
            "WorkerExecutionReplayWitness"
        )
    if type(witness.phase_io_contract) is not PhaseIOContract:
        _fail(f"{role} execution witness PhaseIO contract is not exact")
    if type(witness.phase_io_launch) is not LaunchSpec:
        _fail(f"{role} execution witness PhaseIO launch is not exact")
    try:
        execution = validate_worker_execution_authority(
            scratchpad=Path(witness.scratchpad),
            authority=witness.authority,
            contract=witness.phase_io_contract,
            launch=witness.phase_io_launch,
            run_id=witness.run_id,
        )
        plan = _replayed_work_plan(witness.work_plan)
    except (WorkerTransactionError, MethodCardRuntimeAuthorityError) as exc:
        _fail(f"{role} WorkerTransaction/PhaseIO execution does not replay: {exc}", exc)

    expected_snapshot = _canonical_mapping_value(
        runtime_replay_witness.audit_snapshot,
        label="current audit snapshot",
    )
    execution_snapshot = _canonical_mapping_value(
        witness.audit_snapshot,
        label=f"{role} execution audit snapshot",
    )
    if execution_snapshot != expected_snapshot:
        _fail(f"{role} execution does not bind the exact current source snapshot manifest")
    snapshot_digest = _hex64(
        expected_snapshot.get("snapshot_digest"),
        "current audit snapshot digest",
    )
    if plan.get("source_snapshot_digest") != snapshot_digest:
        _fail(f"{role} execution WorkPlan source snapshot is stale")
    if (
        execution.get("work_plan_digest") != plan.get("work_plan_digest")
        or execution.get("run_id") != plan.get("run_id")
        or execution.get("phase") != plan.get("phase")
        or execution.get("work_unit_id") != plan.get("work_unit_id")
    ):
        _fail(f"{role} execution receipt differs from its exact WorkPlan")
    if (
        plan.get("phase_io_contract_digest")
        != witness.phase_io_contract.digest
        or plan.get("phase_io_launch_digest") != witness.phase_io_launch.digest
    ):
        _fail(f"{role} execution WorkPlan differs from current PhaseIO authority")
    assignment = plan.get("assignment")
    members = assignment.get("members") if isinstance(assignment, Mapping) else None
    plan_outputs = (
        sorted(
            str(member.get("canonical_identity"))
            for member in members
            if isinstance(member, Mapping)
        )
        if isinstance(members, list)
        else []
    )
    contract_outputs = sorted(
        output.identity for output in witness.phase_io_contract.outputs
    )
    if plan_outputs != contract_outputs or len(plan_outputs) != len(contract_outputs):
        _fail(f"{role} execution WorkPlan output denominator differs from PhaseIO")
    if role == "producer":
        work = _mapping(runtime.get("work_plan_binding"), "runtime work plan binding")
        for field in (
            "run_id",
            "phase",
            "work_unit_id",
            "work_plan_digest",
            "source_snapshot_digest",
            "phase_io_contract_digest",
            "phase_io_launch_digest",
        ):
            if plan.get(field) != work.get(field):
                _fail(f"producer execution {field} differs from replayed runtime authority")
    else:
        work = _mapping(runtime.get("work_plan_binding"), "runtime work plan binding")
        if plan.get("run_id") != work.get("run_id"):
            _fail("reviewer execution is not from the current runtime run")
    bound_execution = dict(execution)
    bound_execution["_phase_io_output_identities"] = contract_outputs
    return bound_execution, plan


def _validate_independent_execution_pair(
    producer_execution: Mapping[str, Any],
    reviewer_execution: Mapping[str, Any],
) -> None:
    if reviewer_execution["authority_digest"] == producer_execution[
        "authority_digest"
    ]:
        _fail("application review must use an independent execution receipt")
    if (
        reviewer_execution["phase"],
        reviewer_execution["work_unit_id"],
    ) == (
        producer_execution["phase"],
        producer_execution["work_unit_id"],
    ):
        _fail(
            "application review must use an independent WorkerTransaction/PhaseIO "
            "work unit"
        )


def _selected_cards(
    runtime: Mapping[str, Any], implementation_root: Path | str
) -> tuple[tuple[dict[str, str], ...], dict[tuple[str, str], MethodCard]]:
    try:
        catalog = load_method_card_catalog(
            Path(implementation_root) / "methodology" / "method-cards-v1.yaml",
            repo_root=implementation_root,
        )
    except (MethodCardCatalogError, OSError) as exc:
        _fail(f"current MethodCard catalog cannot be validated: {exc}", exc)
    binding = _mapping(runtime.get("catalog_binding"), "runtime catalog binding")
    if (
        binding.get("catalog_digest") != catalog.digest
        or binding.get("catalog_source_sha256") != catalog.source_sha256
    ):
        _fail("validated runtime authority is stale against the current catalog")
    method_binding = _mapping(runtime.get("method_binding"), "runtime method binding")
    raw_selected = method_binding.get("selected_methods")
    if isinstance(raw_selected, (str, bytes)) or not isinstance(raw_selected, Sequence):
        _fail("runtime selected methods must be an ordered sequence")
    selected: list[dict[str, str]] = []
    by_key: dict[tuple[str, str], MethodCard] = {}
    catalog_order = {card.method_id: index for index, card in enumerate(catalog.cards)}
    prior_order = -1
    for index, raw in enumerate(raw_selected):
        row = _mapping(raw, f"runtime selected methods[{index}]")
        _exact_keys(row, frozenset({"method_id", "method_version"}), "selected method")
        method_id = _string(row["method_id"], "selected method_id", opaque=True)
        version = _string(row["method_version"], "selected method_version")
        try:
            card = catalog.card(method_id)
        except MethodCardCatalogError as exc:
            _fail(f"runtime selected method is absent from current catalog: {method_id}", exc)
        if card.method_version != version:
            _fail(f"runtime selected method version is stale for {method_id}")
        order = catalog_order[method_id]
        if order <= prior_order:
            _fail("runtime selected methods are not unique catalog order")
        prior_order = order
        key = (method_id, version)
        selected.append({"method_id": method_id, "method_version": version})
        by_key[key] = card
    if not selected or method_binding.get("selected_method_count") != len(selected):
        _fail("runtime selected method count is malformed")
    return tuple(selected), by_key


def _normalize_steps(values: Any, label: str) -> list[dict[str, str]]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail(f"{label} must be an ordered sequence")
    rows: list[dict[str, str]] = []
    for index, raw in enumerate(values):
        row = _mapping(raw, f"{label}[{index}]")
        _exact_keys(row, _STEP_KEYS, f"{label}[{index}]")
        rows.append(
            {
                "method_id": _string(row["method_id"], f"{label}.method_id", opaque=True),
                "method_version": _string(row["method_version"], f"{label}.method_version"),
                "step_id": _string(row["step_id"], f"{label}.step_id", opaque=True),
            }
        )
    return rows


def _string_sequence(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _fail(f"{label} must be an ordered sequence")
    result = [_string(item, f"{label}[{index}]", opaque=True) for index, item in enumerate(value)]
    if not allow_empty and not result:
        _fail(f"{label} must not be empty")
    if result != sorted(set(result)):
        _fail(f"{label} must be sorted and unique")
    return result


def _runtime_context(
    value: Mapping[str, Any] | bytes,
    implementation_root: Path | str,
    replay_witness: MethodCardRuntimeReplayWitness,
) -> tuple[dict[str, Any], tuple[dict[str, str], ...], dict[tuple[str, str], MethodCard]]:
    runtime = _runtime_value(
        value,
        implementation_root=implementation_root,
        replay_witness=replay_witness,
    )
    selected, cards = _selected_cards(runtime, implementation_root)
    denominator = _mapping(runtime.get("denominators"), "runtime denominator")
    if "methods" in denominator:
        projection = _denominator_projection(runtime)
        if _structural_denominator(projection) != projection:
            _fail("activated runtime denominator projection is noncanonical")
        methods = projection["methods"]
        expected_method_keys = [
            (selection["method_id"], selection["method_version"])
            for selection in selected
        ]
        if [
            (method["method_id"], method["method_version"])
            for method in methods
        ] != expected_method_keys:
            _fail("activated runtime method denominators differ from selection")
        for method in methods:
            card = cards[(method["method_id"], method["method_version"])]
            expected_steps = [
                {
                    "method_id": method["method_id"],
                    "method_version": method["method_version"],
                    "step_id": step.step_id,
                }
                for step in card.required_steps
            ]
            if method["steps"] != expected_steps:
                _fail(
                    "activated runtime method steps differ from current catalog"
                )
        unsigned = dict(denominator)
        claimed = _hex64(
            unsigned.pop("denominator_digest", None),
            "activated runtime denominator digest",
        )
        if claimed != _digest(unsigned):
            _fail("activated runtime denominator digest mismatch")
        return runtime, selected, cards
    targets = _string_sequence(denominator.get("targets"), "runtime target denominator")
    relations = _string_sequence(denominator.get("relations"), "runtime relation denominator")
    steps = _normalize_steps(denominator.get("steps"), "runtime step denominator")
    expected_steps = [
        {
            "method_id": selection["method_id"],
            "method_version": selection["method_version"],
            "step_id": step.step_id,
        }
        for selection in selected
        for step in cards[(selection["method_id"], selection["method_version"])].required_steps
    ]
    if steps != expected_steps:
        _fail("runtime step denominator differs from exact current catalog steps")
    if (
        denominator.get("target_count") != len(targets)
        or denominator.get("relation_count") != len(relations)
        or denominator.get("step_count") != len(steps)
    ):
        _fail("runtime denominator counts do not match exact denominator arrays")
    if denominator.get("coverage_kind") not in {"EXACT", "LOWER_BOUND"}:
        _fail("runtime denominator coverage kind is unsupported")
    if not isinstance(denominator.get("unknown_remainder"), bool):
        _fail("runtime denominator unknown_remainder must be boolean")
    unsigned = dict(denominator)
    claimed = _hex64(unsigned.pop("denominator_digest", None), "runtime denominator digest")
    if claimed != _digest(unsigned):
        _fail("runtime denominator digest mismatch")
    return runtime, selected, cards


def _reject_activated_legacy_application(runtime: Mapping[str, Any]) -> None:
    if runtime.get("schema") == ACTIVATED_AUTHORITY_SCHEMA:
        _fail(
            "activated MethodCard runtime requires typed application v3; "
            "legacy caller-authored receipts cannot be fallback authority"
        )


def _denominator_projection(runtime: Mapping[str, Any]) -> dict[str, Any]:
    denominator = _mapping(runtime["denominators"], "runtime denominator")
    if "methods" in denominator:
        return {
            "runtime_denominator_digest": denominator["denominator_digest"],
            "coverage_kind": denominator["coverage_kind"],
            "unknown_remainder": denominator["unknown_remainder"],
            "limitation_reason": denominator["limitation_reason"],
            "method_count": denominator["method_count"],
            "target_count": denominator["target_count"],
            "relation_count": denominator["relation_count"],
            "step_count": denominator["step_count"],
            "methods": [dict(row) for row in denominator["methods"]],
        }
    return {
        "runtime_denominator_digest": denominator["denominator_digest"],
        "coverage_kind": denominator["coverage_kind"],
        "unknown_remainder": denominator["unknown_remainder"],
        "limitation_reason": denominator["limitation_reason"],
        "target_count": denominator["target_count"],
        "relation_count": denominator["relation_count"],
        "step_count": denominator["step_count"],
        "targets": list(denominator["targets"]),
        "relations": list(denominator["relations"]),
        "steps": [dict(row) for row in denominator["steps"]],
    }


def _validate_denominator_projection(value: Any, runtime: Mapping[str, Any]) -> dict[str, Any]:
    row = _mapping(value, "application exact denominator")
    expected = _denominator_projection(runtime)
    expected_keys = (
        _ACTIVATED_DENOMINATOR_KEYS
        if "methods" in expected
        else _DENOMINATOR_KEYS
    )
    _exact_keys(row, expected_keys, "application exact denominator")
    if row != expected:
        _fail("application receipt does not bind the exact denominator")
    return expected


def _method_denominator(
    denominator: Mapping[str, Any],
    method: Mapping[str, str],
) -> Mapping[str, Any]:
    if "methods" not in denominator:
        return denominator
    matches = [
        row
        for row in denominator["methods"]
        if row["method_id"] == method["method_id"]
        and row["method_version"] == method["method_version"]
    ]
    if len(matches) != 1:
        _fail("application denominator does not bind exactly one selected method")
    return matches[0]


def _file_identity(path: str, data: bytes) -> dict[str, Any]:
    try:
        portable = validate_portable_path(path)
    except ProgramFactsTypeError as exc:
        _fail(f"file identity path is not portable: {exc}", exc)
    if not isinstance(data, bytes):
        _fail(f"file identity bytes for {portable} must be bytes")
    return {
        "path": portable,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _source_identities(source_files: Mapping[str, bytes]) -> list[dict[str, Any]]:
    if not isinstance(source_files, Mapping) or not source_files:
        _fail("source files must be a nonempty exact mapping")
    rows = [_file_identity(path, data) for path, data in source_files.items()]
    rows.sort(key=lambda row: row["path"])
    if len({row["path"] for row in rows}) != len(rows):
        _fail("source file identities must be unique")
    return rows


def _identity_value(value: Any, label: str) -> dict[str, Any]:
    row = _mapping(value, label)
    _exact_keys(row, _IDENTITY_KEYS, label)
    try:
        path = validate_portable_path(row["path"])
    except (ProgramFactsTypeError, KeyError, TypeError) as exc:
        _fail(f"{label} path is invalid", exc)
    return {
        "path": path,
        "sha256": _hex64(row["sha256"], f"{label}.sha256"),
        "size_bytes": _positive_or_zero_int(row["size_bytes"], f"{label}.size_bytes"),
    }


def _attempt_value(value: Mapping[str, Any] | bytes) -> dict[str, Any]:
    attempt = _mapping_input(value, label="worker attempt identity")
    _exact_keys(attempt, _ATTEMPT_KEYS, "worker attempt identity")
    if attempt.get("schema") != WORKER_ATTEMPT_SCHEMA:
        _fail("worker attempt identity schema is unsupported")
    _check_digest(attempt, "attempt_digest", "worker attempt identity")
    _identity_value(attempt["output"], "worker output identity")
    raw_sources = attempt["sources"]
    if isinstance(raw_sources, (str, bytes)) or not isinstance(raw_sources, Sequence):
        _fail("worker attempt source identities must be an ordered sequence")
    sources = [
        _identity_value(item, f"worker source identity[{index}]")
        for index, item in enumerate(raw_sources)
    ]
    if not sources or sources != sorted(sources, key=lambda row: row["path"]):
        _fail("worker attempt source identities must be nonempty path order")
    if len({row["path"] for row in sources}) != len(sources):
        _fail("worker attempt source identities must be unique")
    for field in (
        "runtime_authority_digest",
        "work_plan_digest",
        "source_snapshot_digest",
        "producer_execution_authority_digest",
        "phase_io_contract_digest",
        "phase_io_launch_digest",
    ):
        _hex64(attempt[field], f"worker attempt {field}")
    for field in (
        "run_id",
        "phase",
        "work_unit_id",
        "attempt_id",
    ):
        _string(attempt[field], f"worker attempt {field}", opaque=True)
    return attempt


def _validate_attempt_bindings(
    attempt: Mapping[str, Any],
    runtime: Mapping[str, Any],
    producer_execution: Mapping[str, Any],
) -> None:
    work = _mapping(runtime["work_plan_binding"], "runtime work plan binding")
    expected = {
        "runtime_authority_digest": runtime["authority_digest"],
        "run_id": work["run_id"],
        "phase": work["phase"],
        "work_unit_id": work["work_unit_id"],
        "work_plan_digest": work["work_plan_digest"],
        "source_snapshot_digest": work["source_snapshot_digest"],
        "producer_execution_authority_digest": producer_execution[
            "authority_digest"
        ],
        "phase_io_contract_digest": producer_execution["contract_digest"],
        "phase_io_launch_digest": producer_execution["launch_digest"],
        "attempt_id": producer_execution["attempt_id"],
    }
    for field, value in expected.items():
        if attempt.get(field) != value:
            _fail(f"worker attempt {field} is stale or cross-bound")
    if producer_execution.get("_phase_io_output_identities") != [
        f"scratchpad:{attempt['output']['path']}"
    ]:
        _fail("worker attempt output is not the exact producer PhaseIO output")


def _validate_attempt_bytes(
    attempt: Mapping[str, Any],
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if not isinstance(output_bytes, bytes):
        _fail("worker output must be exact bytes")
    expected_output = _file_identity(attempt["output"]["path"], output_bytes)
    if expected_output != attempt["output"]:
        _fail("worker output byte identity is stale or mismatched")
    expected_sources = _source_identities(source_files)
    if expected_sources != attempt["sources"]:
        _fail("worker source byte identities are stale or mismatched")
    blobs = {path: data for path, data in source_files.items()}
    if attempt["output"]["path"] in blobs:
        _fail("worker output path must not alias a source path")
    blobs[attempt["output"]["path"]] = output_bytes
    return blobs, expected_output


def compile_worker_attempt_identity(
    *,
    validated_runtime_authority: Mapping[str, Any] | bytes,
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    implementation_root: Path | str,
    producer_execution_witness: WorkerExecutionReplayWitness,
    output_path: str,
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    """Bind a worker attempt to exact runtime, output, and source bytes."""

    runtime = _runtime_value(
        validated_runtime_authority,
        implementation_root=implementation_root,
        replay_witness=runtime_replay_witness,
    )
    _reject_activated_legacy_application(runtime)
    producer_execution, _producer_plan = _execution_value(
        producer_execution_witness,
        runtime=runtime,
        runtime_replay_witness=runtime_replay_witness,
        role="producer",
    )
    work = _mapping(runtime.get("work_plan_binding"), "runtime work plan binding")
    output = _file_identity(output_path, output_bytes)
    sources = _source_identities(source_files)
    if output["path"] in {row["path"] for row in sources}:
        _fail("worker output path must not alias a source path")
    unsigned = {
        "schema": WORKER_ATTEMPT_SCHEMA,
        "runtime_authority_digest": runtime["authority_digest"],
        "run_id": work["run_id"],
        "phase": work["phase"],
        "work_unit_id": work["work_unit_id"],
        "work_plan_digest": work["work_plan_digest"],
        "source_snapshot_digest": work["source_snapshot_digest"],
        "producer_execution_authority_digest": producer_execution[
            "authority_digest"
        ],
        "phase_io_contract_digest": producer_execution["contract_digest"],
        "phase_io_launch_digest": producer_execution["launch_digest"],
        "attempt_id": producer_execution["attempt_id"],
        "output": output,
        "sources": sources,
    }
    return _sign(unsigned, "attempt_digest")


def _evidence_spans(value: Any, label: str, blobs: Mapping[str, bytes]) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        _fail(f"{label} evidence must be a nonempty ordered sequence")
    spans: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item_label = f"{label} evidence[{index}]"
        row = _mapping(raw, item_label)
        _exact_keys(row, _EVIDENCE_KEYS, item_label)
        try:
            path = validate_portable_path(row["path"])
        except (ProgramFactsTypeError, KeyError, TypeError) as exc:
            _fail(f"{item_label} path is invalid", exc)
        if path not in blobs:
            _fail(f"{item_label} path is outside exact output/source identities")
        start = _positive_or_zero_int(row["line_start"], f"{item_label}.line_start")
        end = _positive_or_zero_int(row["line_end"], f"{item_label}.line_end")
        lines = blobs[path].splitlines(keepends=True)
        if start < 1 or end < start or end > len(lines):
            _fail(f"{item_label} line range is outside exact bound bytes")
        claimed = _hex64(row["sha256"], f"{item_label}.sha256")
        expected = hashlib.sha256(b"".join(lines[start - 1 : end])).hexdigest()
        if claimed != expected:
            _fail(f"{item_label} digest mismatch")
        spans.append(
            {"path": path, "line_start": start, "line_end": end, "sha256": claimed}
        )
    ordering = [(row["path"], row["line_start"], row["line_end"], row["sha256"]) for row in spans]
    if ordering != sorted(set(ordering)):
        _fail(f"{label} evidence must be sorted and unique")
    return spans


def _parsed_candidate_ids(output_bytes: bytes) -> list[str]:
    """Parse real Markdown finding headings outside fenced code blocks."""

    try:
        text = output_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        _fail("worker output must be UTF-8 for candidate-set parsing", exc)
    candidates: list[str] = []
    fence_char = ""
    fence_length = 0
    for line in text.splitlines():
        fence_match = _FENCE_RE.match(line)
        if fence_char:
            if fence_match:
                marker = fence_match.group("fence")
                if marker[0] == fence_char and len(marker) >= fence_length:
                    fence_char = ""
                    fence_length = 0
            continue
        if fence_match:
            marker = fence_match.group("fence")
            fence_char = marker[0]
            fence_length = len(marker)
            continue
        heading = _FINDING_HEADING_RE.match(line)
        if heading:
            candidates.append(heading.group("candidate"))
    if len(candidates) != len(set(candidates)):
        _fail("exact parsed candidate set contains duplicate identities")
    return sorted(candidates)


def _validate_exact_candidate_set(
    claims: Sequence[Mapping[str, Any]],
    output_bytes: bytes,
) -> None:
    claimed = [
        candidate
        for claim in claims
        for candidate in claim["outcome"]["candidate_ids"]
    ]
    # A proposal may be supported by more than one semantic method.  Method
    # attribution is therefore many-to-many, while the union remains an exact
    # byte-bound proposal denominator.
    if sorted(set(claimed)) != _parsed_candidate_ids(output_bytes):
        _fail("producer claims do not equal the exact parsed candidate set")


def _method_steps(
    denominator: Mapping[str, Any],
    method: Mapping[str, str],
) -> list[dict[str, str]]:
    method_denominator = _method_denominator(denominator, method)
    return [
        dict(row)
        for row in method_denominator["steps"]
        if row["method_id"] == method["method_id"]
        and row["method_version"] == method["method_version"]
    ]


def _normalize_claim(
    raw: Any,
    *,
    expected_method: Mapping[str, str],
    denominator: Mapping[str, Any],
    card: MethodCard,
    blobs: Mapping[str, bytes],
    output_bytes: bytes,
    persisted: bool,
) -> dict[str, Any]:
    row = _mapping(raw, f"claim {expected_method['method_id']}")
    _exact_keys(row, _CLAIM_KEYS if persisted else _CLAIM_INPUT_KEYS, "producer claim")
    for field in ("method_id", "method_version"):
        if row.get(field) != expected_method[field]:
            _fail("producer claims must exactly match selected methods and order")
    if row.get("producer_claim_state") != "CLAIMED":
        _fail("producer claim state must remain CLAIMED")
    status = row.get("status")
    if status not in {
        "CLAIMED_APPLIED",
        "CLAIMED_NOT_APPLICABLE",
        "CLAIMED_UNRESOLVED",
    }:
        _fail("producer claim status is unsupported")
    targets = _string_sequence(row.get("targets_examined"), "claim targets_examined")
    relations = _string_sequence(row.get("relations_examined"), "claim relations_examined")
    steps = _normalize_steps(row.get("steps_completed"), "claim steps_completed")
    method_denominator = _method_denominator(denominator, expected_method)
    expected_targets = (
        [target["target_id"] for target in method_denominator["targets"]]
        if "methods" in denominator
        else method_denominator["targets"]
    )
    expected_relations = (
        [relation["relation_id"] for relation in method_denominator["relations"]]
        if "methods" in denominator
        else method_denominator["relations"]
    )
    expected_steps = _method_steps(denominator, expected_method)
    if (
        targets != expected_targets
        or relations != expected_relations
        or steps != expected_steps
    ):
        _fail("producer claim does not cover the exact denominator targets, relations, and steps")
    evidence = _evidence_spans(row.get("evidence"), "producer claim", blobs)
    outcome_raw = _mapping(row.get("outcome"), "producer claim outcome")
    _exact_keys(outcome_raw, _OUTCOME_KEYS, "producer claim outcome")
    kind = outcome_raw.get("kind")
    if kind not in {"NO_CANDIDATE", "CANDIDATE_PROPOSED", "NOT_APPLICABLE", "UNRESOLVED"}:
        _fail("producer claim outcome kind is unsupported")
    candidate_ids = _string_sequence(outcome_raw.get("candidate_ids"), "candidate identities")
    if any(_CANDIDATE_RE.fullmatch(item) is None for item in candidate_ids):
        _fail("candidate identity is not portable")
    detail = _string(outcome_raw.get("detail"), "producer claim outcome detail")
    assumptions = row.get("unresolved_assumptions")
    if isinstance(assumptions, (str, bytes)) or not isinstance(assumptions, Sequence):
        _fail("producer unresolved assumptions must be an ordered sequence")
    normalized_assumptions = [
        _string(item, "producer unresolved assumption") for item in assumptions
    ]
    if normalized_assumptions != sorted(set(normalized_assumptions)):
        _fail("producer unresolved assumptions must be sorted and unique")
    reason = row.get("not_applicable_reason")
    if reason is not None and not isinstance(reason, str):
        _fail("producer not-applicable reason must be a string or null")

    if status == "CLAIMED_APPLIED":
        if kind not in {"NO_CANDIDATE", "CANDIDATE_PROPOSED"}:
            _fail("CLAIMED_APPLIED outcome is inconsistent")
        if assumptions or reason is not None:
            _fail("CLAIMED_APPLIED cannot retain unresolved or N/A state")
        if kind == "NO_CANDIDATE" and candidate_ids:
            _fail("NO_CANDIDATE cannot bind candidate identities")
        if kind == "CANDIDATE_PROPOSED" and not candidate_ids:
            _fail("CANDIDATE_PROPOSED requires a candidate identity")
    elif status == "CLAIMED_UNRESOLVED":
        if (
            kind != "UNRESOLVED"
            or not normalized_assumptions
            or candidate_ids
            or reason is not None
        ):
            _fail("CLAIMED_UNRESOLVED requires unresolved assumptions only")
    else:
        if kind != "NOT_APPLICABLE" or candidate_ids or normalized_assumptions:
            _fail("CLAIMED_NOT_APPLICABLE outcome is inconsistent")
        if (
            method_denominator["coverage_kind"] != "EXACT"
            or method_denominator["unknown_remainder"]
        ):
            _fail("not-applicable requires an authoritative exact zero denominator")
        if method_denominator["targets"] or method_denominator["relations"]:
            _fail("not-applicable requires an authoritative zero denominator")
        if not card.allow_not_applicable or reason not in card.valid_not_applicable_reasons:
            _fail("not-applicable is forbidden by current MethodCard policy")

    try:
        output_text = output_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        _fail("worker output must be UTF-8 for candidate identity binding", exc)
    for candidate_id in candidate_ids:
        identity_pattern = re.compile(
            rf"(?<![A-Za-z0-9._:-]){re.escape(candidate_id)}"
            r"(?![A-Za-z0-9._:-])",
            re.ASCII,
        )
        if identity_pattern.search(output_text) is None:
            _fail(f"candidate identity {candidate_id!r} is absent from exact worker output")

    unsigned = {
        "method_id": expected_method["method_id"],
        "method_version": expected_method["method_version"],
        "producer_claim_state": "CLAIMED",
        "status": status,
        "targets_examined": targets,
        "relations_examined": relations,
        "steps_completed": steps,
        "evidence": evidence,
        "outcome": {"kind": kind, "candidate_ids": candidate_ids, "detail": detail},
        "unresolved_assumptions": normalized_assumptions,
        "not_applicable_reason": reason,
    }
    normalized = _sign(unsigned, "claim_digest")
    if persisted and row.get("claim_digest") != normalized["claim_digest"]:
        _fail("producer claim digest mismatch")
    return normalized


def _producer_value(
    value: Mapping[str, Any] | bytes,
    *,
    runtime: Mapping[str, Any],
    selected: Sequence[Mapping[str, str]],
    cards: Mapping[tuple[str, str], MethodCard],
    attempt: Mapping[str, Any],
    producer_execution: Mapping[str, Any],
    blobs: Mapping[str, bytes],
    output_bytes: bytes,
) -> dict[str, Any]:
    receipt = _mapping_input(value, label="producer application receipt")
    _exact_keys(receipt, _PRODUCER_KEYS, "producer application receipt")
    if receipt.get("schema") != PRODUCER_RECEIPT_SCHEMA:
        _fail("producer application receipt schema is unsupported")
    _check_digest(receipt, "receipt_digest", "producer application receipt")
    if receipt.get("runtime_authority_digest") != runtime["authority_digest"]:
        _fail("producer receipt runtime authority is stale")
    if receipt.get("worker_attempt_digest") != attempt["attempt_digest"]:
        _fail("producer receipt worker attempt is stale or cross-bound")
    if receipt.get("producer_execution_authority_digest") != producer_execution[
        "authority_digest"
    ]:
        _fail("producer receipt execution authority is stale or cross-bound")
    if receipt.get("output") != attempt["output"]:
        _fail("producer receipt output identity differs from exact worker output")
    denominator = _validate_denominator_projection(receipt.get("denominator"), runtime)
    raw_claims = receipt.get("claims")
    if isinstance(raw_claims, (str, bytes)) or not isinstance(raw_claims, Sequence):
        _fail("producer claims must be an ordered sequence")
    if len(raw_claims) != len(selected):
        _fail("producer claims must exactly cover every selected method")
    claims = [
        _normalize_claim(
            raw,
            expected_method=method,
            denominator=denominator,
            card=cards[(method["method_id"], method["method_version"])],
            blobs=blobs,
            output_bytes=output_bytes,
            persisted=True,
        )
        for raw, method in zip(raw_claims, selected, strict=True)
    ]
    if claims != receipt["claims"]:
        _fail("producer claims are noncanonical")
    _validate_exact_candidate_set(claims, output_bytes)
    return receipt


def compile_producer_application_receipt(
    *,
    validated_runtime_authority: Mapping[str, Any] | bytes,
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    implementation_root: Path | str,
    producer_execution_witness: WorkerExecutionReplayWitness,
    worker_attempt: Mapping[str, Any] | bytes,
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
    claims: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compile the producer's CLAIMED application receipt."""

    runtime, selected, cards = _runtime_context(
        validated_runtime_authority,
        implementation_root,
        runtime_replay_witness,
    )
    _reject_activated_legacy_application(runtime)
    producer_execution, _producer_plan = _execution_value(
        producer_execution_witness,
        runtime=runtime,
        runtime_replay_witness=runtime_replay_witness,
        role="producer",
    )
    attempt = _attempt_value(worker_attempt)
    _validate_attempt_bindings(attempt, runtime, producer_execution)
    blobs, output = _validate_attempt_bytes(attempt, output_bytes, source_files)
    if (
        isinstance(claims, (str, bytes))
        or not isinstance(claims, Sequence)
        or len(claims) != len(selected)
    ):
        _fail("producer claims must exactly cover every selected method")
    denominator = _denominator_projection(runtime)
    normalized = [
        _normalize_claim(
            raw,
            expected_method=method,
            denominator=denominator,
            card=cards[(method["method_id"], method["method_version"])],
            blobs=blobs,
            output_bytes=output_bytes,
            persisted=False,
        )
        for raw, method in zip(claims, selected, strict=True)
    ]
    _validate_exact_candidate_set(normalized, output_bytes)
    unsigned = {
        "schema": PRODUCER_RECEIPT_SCHEMA,
        "runtime_authority_digest": runtime["authority_digest"],
        "worker_attempt_digest": attempt["attempt_digest"],
        "producer_execution_authority_digest": producer_execution[
            "authority_digest"
        ],
        "output": output,
        "denominator": denominator,
        "claims": normalized,
    }
    receipt = _sign(unsigned, "receipt_digest")
    _producer_value(
        receipt,
        runtime=runtime,
        selected=selected,
        cards=cards,
        attempt=attempt,
        producer_execution=producer_execution,
        blobs=blobs,
        output_bytes=output_bytes,
    )
    return receipt


def _normalize_review(
    raw: Any,
    *,
    claim: Mapping[str, Any],
    blobs: Mapping[str, bytes],
    persisted: bool,
) -> dict[str, Any]:
    row = _mapping(raw, f"review {claim['method_id']}")
    _exact_keys(row, _REVIEW_KEYS if persisted else _REVIEW_INPUT_KEYS, "application review")
    for field in ("method_id", "method_version"):
        if row.get(field) != claim[field]:
            _fail("application reviews must exactly match producer claims and order")
    disposition = row.get("disposition")
    if disposition not in {
        "CONFIRMED_APPLICATION",
        "REJECTED_APPLICATION",
        "UNRESOLVED_APPLICATION",
    }:
        _fail("application review disposition is unsupported")
    if claim["status"] == "CLAIMED_UNRESOLVED" and disposition == "CONFIRMED_APPLICATION":
        _fail("an unresolved producer claim cannot be independently confirmed")
    evidence = _evidence_spans(row.get("evidence"), "application review", blobs)
    reason = _string(row.get("reason"), "application review reason")
    unsigned = {
        "method_id": claim["method_id"],
        "method_version": claim["method_version"],
        "claim_digest": claim["claim_digest"],
        "disposition": disposition,
        "evidence": evidence,
        "reason": reason,
    }
    normalized = _sign(unsigned, "review_digest")
    if persisted:
        if row.get("claim_digest") != claim["claim_digest"]:
            _fail("application review claim digest is stale")
        if row.get("review_digest") != normalized["review_digest"]:
            _fail("application review digest mismatch")
    return normalized


def _review_receipt_value(
    value: Mapping[str, Any] | bytes,
    *,
    runtime: Mapping[str, Any],
    attempt: Mapping[str, Any],
    producer: Mapping[str, Any],
    producer_execution: Mapping[str, Any],
    reviewer_execution: Mapping[str, Any],
    blobs: Mapping[str, bytes],
) -> dict[str, Any]:
    receipt = _mapping_input(value, label="independent application review receipt")
    _exact_keys(receipt, _REVIEW_RECEIPT_KEYS, "independent application review receipt")
    if receipt.get("schema") != REVIEW_RECEIPT_SCHEMA:
        _fail("independent application review receipt schema is unsupported")
    _check_digest(receipt, "receipt_digest", "independent application review receipt")
    if receipt.get("runtime_authority_digest") != runtime["authority_digest"]:
        _fail("application review runtime authority is stale")
    if receipt.get("worker_attempt_digest") != attempt["attempt_digest"]:
        _fail("application review worker attempt is stale or cross-bound")
    if receipt.get("producer_receipt_digest") != producer["receipt_digest"]:
        _fail("application review producer receipt is stale or cross-bound")
    if receipt.get("producer_execution_authority_digest") != producer_execution[
        "authority_digest"
    ]:
        _fail("application review producer execution is stale")
    if receipt.get("reviewer_execution_authority_digest") != reviewer_execution[
        "authority_digest"
    ]:
        _fail("application review reviewer execution is stale")
    _validate_independent_execution_pair(producer_execution, reviewer_execution)
    _validate_denominator_projection(receipt.get("denominator"), runtime)
    raw_reviews = receipt.get("reviews")
    claims = producer["claims"]
    if (
        isinstance(raw_reviews, (str, bytes))
        or not isinstance(raw_reviews, Sequence)
        or len(raw_reviews) != len(claims)
    ):
        _fail("application reviews must exactly cover every producer claim")
    reviews = [
        _normalize_review(raw, claim=claim, blobs=blobs, persisted=True)
        for raw, claim in zip(raw_reviews, claims, strict=True)
    ]
    if reviews != receipt["reviews"]:
        _fail("application reviews are noncanonical")
    return receipt


def compile_independent_application_review_receipt(
    *,
    validated_runtime_authority: Mapping[str, Any] | bytes,
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    implementation_root: Path | str,
    producer_execution_witness: WorkerExecutionReplayWitness,
    reviewer_execution_witness: WorkerExecutionReplayWitness,
    worker_attempt: Mapping[str, Any] | bytes,
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
    producer_receipt: Mapping[str, Any] | bytes,
    reviews: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compile a receipt from an identity independent of the producer."""

    runtime, selected, cards = _runtime_context(
        validated_runtime_authority,
        implementation_root,
        runtime_replay_witness,
    )
    _reject_activated_legacy_application(runtime)
    producer_execution, _producer_plan = _execution_value(
        producer_execution_witness,
        runtime=runtime,
        runtime_replay_witness=runtime_replay_witness,
        role="producer",
    )
    reviewer_execution, _reviewer_plan = _execution_value(
        reviewer_execution_witness,
        runtime=runtime,
        runtime_replay_witness=runtime_replay_witness,
        role="reviewer",
    )
    _validate_independent_execution_pair(producer_execution, reviewer_execution)
    attempt = _attempt_value(worker_attempt)
    _validate_attempt_bindings(attempt, runtime, producer_execution)
    blobs, _output = _validate_attempt_bytes(attempt, output_bytes, source_files)
    producer = _producer_value(
        producer_receipt,
        runtime=runtime,
        selected=selected,
        cards=cards,
        attempt=attempt,
        producer_execution=producer_execution,
        blobs=blobs,
        output_bytes=output_bytes,
    )
    if (
        isinstance(reviews, (str, bytes))
        or not isinstance(reviews, Sequence)
        or len(reviews) != len(producer["claims"])
    ):
        _fail("application reviews must exactly cover every producer claim")
    normalized = [
        _normalize_review(raw, claim=claim, blobs=blobs, persisted=False)
        for raw, claim in zip(reviews, producer["claims"], strict=True)
    ]
    unsigned = {
        "schema": REVIEW_RECEIPT_SCHEMA,
        "runtime_authority_digest": runtime["authority_digest"],
        "worker_attempt_digest": attempt["attempt_digest"],
        "producer_receipt_digest": producer["receipt_digest"],
        "producer_execution_authority_digest": producer_execution[
            "authority_digest"
        ],
        "reviewer_execution_authority_digest": reviewer_execution[
            "authority_digest"
        ],
        "denominator": _denominator_projection(runtime),
        "reviews": normalized,
    }
    receipt = _sign(unsigned, "receipt_digest")
    _review_receipt_value(
        receipt,
        runtime=runtime,
        attempt=attempt,
        producer=producer,
        producer_execution=producer_execution,
        reviewer_execution=reviewer_execution,
        blobs=blobs,
    )
    return receipt


def reconcile_method_card_application(
    *,
    validated_runtime_authority: Mapping[str, Any] | bytes,
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    implementation_root: Path | str,
    producer_execution_witness: WorkerExecutionReplayWitness,
    reviewer_execution_witness: WorkerExecutionReplayWitness,
    worker_attempt: Mapping[str, Any] | bytes,
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
    producer_receipt: Mapping[str, Any] | bytes,
    application_review_receipt: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    """Reconcile producer CLAIMED state with independent review or typed debt."""

    runtime, selected, cards = _runtime_context(
        validated_runtime_authority,
        implementation_root,
        runtime_replay_witness,
    )
    _reject_activated_legacy_application(runtime)
    producer_execution, _producer_plan = _execution_value(
        producer_execution_witness,
        runtime=runtime,
        runtime_replay_witness=runtime_replay_witness,
        role="producer",
    )
    reviewer_execution, _reviewer_plan = _execution_value(
        reviewer_execution_witness,
        runtime=runtime,
        runtime_replay_witness=runtime_replay_witness,
        role="reviewer",
    )
    _validate_independent_execution_pair(producer_execution, reviewer_execution)
    attempt = _attempt_value(worker_attempt)
    _validate_attempt_bindings(attempt, runtime, producer_execution)
    blobs, _output = _validate_attempt_bytes(attempt, output_bytes, source_files)
    producer = _producer_value(
        producer_receipt,
        runtime=runtime,
        selected=selected,
        cards=cards,
        attempt=attempt,
        producer_execution=producer_execution,
        blobs=blobs,
        output_bytes=output_bytes,
    )
    review_receipt = _review_receipt_value(
        application_review_receipt,
        runtime=runtime,
        attempt=attempt,
        producer=producer,
        producer_execution=producer_execution,
        reviewer_execution=reviewer_execution,
        blobs=blobs,
    )
    denominator = _denominator_projection(runtime)
    states: list[dict[str, Any]] = []
    debt: list[dict[str, Any]] = []
    dispositions = {
        "CONFIRMED_APPLICATION": "INDEPENDENTLY_CONFIRMED",
        "REJECTED_APPLICATION": "INDEPENDENTLY_REJECTED",
        "UNRESOLVED_APPLICATION": "INDEPENDENTLY_UNRESOLVED",
    }
    debt_codes = {
        "REJECTED_APPLICATION": "INDEPENDENT_APPLICATION_REVIEW_REJECTED",
        "UNRESOLVED_APPLICATION": "INDEPENDENT_APPLICATION_REVIEW_UNRESOLVED",
    }
    for claim, review in zip(producer["claims"], review_receipt["reviews"], strict=True):
        disposition = review["disposition"]
        states.append(
            {
                "method_id": claim["method_id"],
                "method_version": claim["method_version"],
                "producer_claim_state": "CLAIMED",
                "producer_status": claim["status"],
                "producer_claim_digest": claim["claim_digest"],
                "producer_outcome": claim["outcome"],
                "review_digest": review["review_digest"],
                "review_disposition": disposition,
                "application_disposition": dispositions[disposition],
            }
        )
        if disposition in debt_codes:
            debt.append(
                {
                    "code": debt_codes[disposition],
                    "method_id": claim["method_id"],
                    "method_version": claim["method_version"],
                    "claim_digest": claim["claim_digest"],
                    "review_digest": review["review_digest"],
                    "reason": review["reason"],
                }
            )
    if denominator["coverage_kind"] != "EXACT" or denominator["unknown_remainder"]:
        debt.append(
            {
                "code": "UNKNOWN_DENOMINATOR_REMAINDER",
                "runtime_denominator_digest": denominator["runtime_denominator_digest"],
                "reason": denominator["limitation_reason"],
            }
        )
    complete = not debt and all(
        row["application_disposition"] == "INDEPENDENTLY_CONFIRMED" for row in states
    )
    unsigned = {
        "schema": APPLICATION_AUTHORITY_SCHEMA,
        "runtime_authority_digest": runtime["authority_digest"],
        "worker_attempt_digest": attempt["attempt_digest"],
        "producer_receipt_digest": producer["receipt_digest"],
        "application_review_receipt_digest": review_receipt["receipt_digest"],
        "denominator": denominator,
        "status": "COMPLETE" if complete else "DEBT",
        "application_complete": complete,
        "method_states": states,
        "debt": debt,
        "authority_limits": dict(AUTHORITY_LIMITS),
    }
    return _sign(unsigned, "authority_digest")


def _structural_denominator(value: Any) -> dict[str, Any]:
    row = _mapping(value, "application authority denominator")
    if "methods" in row:
        _exact_keys(
            row,
            _ACTIVATED_DENOMINATOR_KEYS,
            "activated application authority denominator",
        )
        raw_methods = row.get("methods")
        if isinstance(raw_methods, (str, bytes)) or not isinstance(
            raw_methods, Sequence
        ) or not raw_methods:
            _fail("activated application denominator methods must be nonempty")
        methods: list[dict[str, Any]] = []
        method_keys: set[tuple[str, str]] = set()
        for index, raw_method in enumerate(raw_methods):
            label = f"activated application method denominator[{index}]"
            method = _mapping(raw_method, label)
            _exact_keys(method, _ACTIVATED_METHOD_DENOMINATOR_KEYS, label)
            method_id = _string(
                method.get("method_id"), f"{label}.method_id", opaque=True
            )
            version = _string(
                method.get("method_version"), f"{label}.method_version"
            )
            key = (method_id, version)
            if key in method_keys:
                _fail("activated application denominator duplicates a method")
            method_keys.add(key)
            raw_targets = method.get("targets")
            if isinstance(raw_targets, (str, bytes)) or not isinstance(
                raw_targets, Sequence
            ):
                _fail(f"{label}.targets must be an ordered sequence")
            targets: list[dict[str, Any]] = []
            for target_index, raw_target in enumerate(raw_targets):
                target_label = f"{label}.targets[{target_index}]"
                target = _mapping(raw_target, target_label)
                _exact_keys(target, _ACTIVATED_TARGET_KEYS, target_label)
                raw_files = target.get("source_files")
                if isinstance(raw_files, (str, bytes)) or not isinstance(
                    raw_files, Sequence
                ):
                    _fail(f"{target_label}.source_files must be ordered")
                files = [
                    _identity_value(
                        identity,
                        f"{target_label}.source_files[{identity_index}]",
                    )
                    for identity_index, identity in enumerate(raw_files)
                ]
                if files != sorted(files, key=lambda item: item["path"]):
                    _fail(f"{target_label}.source_files are not path ordered")
                if len({identity["path"] for identity in files}) != len(files):
                    _fail(f"{target_label}.source_files contain duplicates")
                targets.append(
                    {
                        "target_id": _string(
                            target.get("target_id"),
                            f"{target_label}.target_id",
                            opaque=True,
                        ),
                        "source_files": files,
                    }
                )
            if [target["target_id"] for target in targets] != sorted(
                {target["target_id"] for target in targets}
            ):
                _fail(f"{label}.targets are not unique canonical order")
            raw_relations = method.get("relations")
            if isinstance(raw_relations, (str, bytes)) or not isinstance(
                raw_relations, Sequence
            ):
                _fail(f"{label}.relations must be an ordered sequence")
            relations: list[dict[str, str]] = []
            for relation_index, raw_relation in enumerate(raw_relations):
                relation_label = f"{label}.relations[{relation_index}]"
                relation = _mapping(raw_relation, relation_label)
                _exact_keys(relation, _ACTIVATED_RELATION_KEYS, relation_label)
                relations.append(
                    {
                        field: _string(
                            relation.get(field),
                            f"{relation_label}.{field}",
                            opaque=True,
                        )
                        for field in (
                            "relation_id",
                            "selector",
                            "source_target_id",
                            "destination_target_id",
                        )
                    }
                )
            if [relation["relation_id"] for relation in relations] != sorted(
                {relation["relation_id"] for relation in relations}
            ):
                _fail(f"{label}.relations are not unique canonical order")
            steps = _normalize_steps(method.get("steps"), f"{label}.steps")
            if any(
                step["method_id"] != method_id
                or step["method_version"] != version
                for step in steps
            ):
                _fail(f"{label}.steps contain a foreign method identity")
            coverage = method.get("coverage_kind")
            unknown = method.get("unknown_remainder")
            limitation = method.get("limitation_reason")
            if coverage not in {"EXACT", "LOWER_BOUND"} or type(unknown) is not bool:
                _fail(f"{label} coverage is malformed")
            if coverage == "EXACT":
                if unknown or limitation is not None or any(
                    not target["source_files"] for target in targets
                ):
                    _fail(f"{label} exact coverage lacks exact source bindings")
            elif (
                unknown is not True
                or not isinstance(limitation, str)
                or not limitation
            ):
                _fail(f"{label} lower-bound coverage lacks explicit debt")
            for field, values in (
                ("target_count", targets),
                ("relation_count", relations),
                ("step_count", steps),
            ):
                if _positive_or_zero_int(
                    method.get(field), f"{label}.{field}"
                ) != len(values):
                    _fail(f"{label} counts are inconsistent")
            unsigned_method = {
                "method_id": method_id,
                "method_version": version,
                "coverage_kind": coverage,
                "unknown_remainder": unknown,
                "limitation_reason": limitation,
                "target_count": len(targets),
                "relation_count": len(relations),
                "step_count": len(steps),
                "targets": targets,
                "relations": relations,
                "steps": steps,
            }
            claimed_method_digest = _hex64(
                method.get("method_denominator_digest"),
                f"{label} digest",
            )
            if claimed_method_digest != _digest(unsigned_method):
                _fail(f"{label} digest mismatch")
            methods.append(
                {
                    **unsigned_method,
                    "method_denominator_digest": claimed_method_digest,
                }
            )
        coverage = row.get("coverage_kind")
        unknown = row.get("unknown_remainder")
        limitation = row.get("limitation_reason")
        if coverage not in {"EXACT", "LOWER_BOUND"} or type(unknown) is not bool:
            _fail("activated application denominator coverage is malformed")
        if coverage == "EXACT":
            if unknown or limitation is not None or any(
                method["coverage_kind"] != "EXACT" for method in methods
            ):
                _fail("activated exact denominator retains limitation debt")
        elif (
            unknown is not True
            or not isinstance(limitation, str)
            or not limitation
            or any(method["coverage_kind"] != "LOWER_BOUND" for method in methods)
        ):
            _fail("activated lower-bound denominator lacks explicit debt")
        counts = {
            "method_count": len(methods),
            "target_count": sum(method["target_count"] for method in methods),
            "relation_count": sum(method["relation_count"] for method in methods),
            "step_count": sum(method["step_count"] for method in methods),
        }
        for field, expected_count in counts.items():
            if _positive_or_zero_int(
                row.get(field), f"activated denominator {field}"
            ) != expected_count:
                _fail("activated application denominator counts are inconsistent")
        return {
            "runtime_denominator_digest": _hex64(
                row.get("runtime_denominator_digest"),
                "activated runtime denominator digest",
            ),
            "coverage_kind": coverage,
            "unknown_remainder": unknown,
            "limitation_reason": limitation,
            **counts,
            "methods": methods,
        }
    _exact_keys(row, _DENOMINATOR_KEYS, "application authority denominator")
    targets = _string_sequence(row.get("targets"), "authority denominator targets")
    relations = _string_sequence(
        row.get("relations"), "authority denominator relations"
    )
    steps = _normalize_steps(row.get("steps"), "authority denominator steps")
    if not steps or len(
        {
            (step["method_id"], step["method_version"], step["step_id"])
            for step in steps
        }
    ) != len(steps):
        _fail("application authority step denominator must be nonempty and unique")
    for field, values in (
        ("target_count", targets),
        ("relation_count", relations),
        ("step_count", steps),
    ):
        if _positive_or_zero_int(row.get(field), f"authority denominator {field}") != len(
            values
        ):
            _fail("application authority denominator counts are inconsistent")
    coverage = row.get("coverage_kind")
    unknown = row.get("unknown_remainder")
    limitation = row.get("limitation_reason")
    if coverage not in {"EXACT", "LOWER_BOUND"} or type(unknown) is not bool:
        _fail("application authority denominator coverage is malformed")
    if coverage == "EXACT":
        if unknown or limitation is not None:
            _fail("exact application denominator cannot retain limitation debt")
    elif unknown is not True or not isinstance(limitation, str) or not limitation:
        _fail("lower-bound application denominator requires explicit remainder debt")
    return {
        "runtime_denominator_digest": _hex64(
            row.get("runtime_denominator_digest"),
            "runtime denominator digest",
        ),
        "coverage_kind": coverage,
        "unknown_remainder": unknown,
        "limitation_reason": limitation,
        "target_count": len(targets),
        "relation_count": len(relations),
        "step_count": len(steps),
        "targets": targets,
        "relations": relations,
        "steps": steps,
    }


def _structural_outcome(value: Any, label: str) -> dict[str, Any]:
    row = _mapping(value, label)
    _exact_keys(row, _OUTCOME_KEYS, label)
    kind = row.get("kind")
    if kind not in {"NO_CANDIDATE", "CANDIDATE_PROPOSED", "NOT_APPLICABLE", "UNRESOLVED"}:
        _fail(f"{label} kind is unsupported")
    candidates = _string_sequence(row.get("candidate_ids"), f"{label} candidate_ids")
    if any(_CANDIDATE_RE.fullmatch(item) is None for item in candidates):
        _fail(f"{label} candidate identity is not portable")
    if (kind == "CANDIDATE_PROPOSED") != bool(candidates):
        _fail(f"{label} candidate state is inconsistent")
    if kind != "CANDIDATE_PROPOSED" and candidates:
        _fail(f"{label} non-candidate outcome retains candidate identities")
    return {
        "kind": kind,
        "candidate_ids": candidates,
        "detail": _string(row.get("detail"), f"{label} detail"),
    }


def _structural_method_states(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        _fail("MethodCard application method states must be a nonempty sequence")
    dispositions = {
        "CONFIRMED_APPLICATION": "INDEPENDENTLY_CONFIRMED",
        "REJECTED_APPLICATION": "INDEPENDENTLY_REJECTED",
        "UNRESOLVED_APPLICATION": "INDEPENDENTLY_UNRESOLVED",
    }
    states: list[dict[str, Any]] = []
    keys: set[tuple[str, str]] = set()
    for index, raw in enumerate(value):
        label = f"MethodCard application method state[{index}]"
        row = _mapping(raw, label)
        _exact_keys(row, _METHOD_STATE_KEYS, label)
        method_id = _string(row.get("method_id"), f"{label}.method_id", opaque=True)
        version = _string(row.get("method_version"), f"{label}.method_version")
        key = (method_id, version)
        if key in keys:
            _fail("MethodCard application method states contain duplicate methods")
        keys.add(key)
        producer_status = row.get("producer_status")
        if row.get("producer_claim_state") != "CLAIMED" or producer_status not in {
            "CLAIMED_APPLIED",
            "CLAIMED_NOT_APPLICABLE",
            "CLAIMED_UNRESOLVED",
        }:
            _fail(f"{label} producer state is malformed")
        outcome = _structural_outcome(row.get("producer_outcome"), f"{label} outcome")
        allowed_outcomes = {
            "CLAIMED_APPLIED": {"NO_CANDIDATE", "CANDIDATE_PROPOSED"},
            "CLAIMED_NOT_APPLICABLE": {"NOT_APPLICABLE"},
            "CLAIMED_UNRESOLVED": {"UNRESOLVED"},
        }
        if outcome["kind"] not in allowed_outcomes[producer_status]:
            _fail(f"{label} producer status/outcome is inconsistent")
        review = row.get("review_disposition")
        if (
            review not in dispositions
            or row.get("application_disposition") != dispositions[review]
        ):
            _fail(f"{label} review/application disposition is inconsistent")
        if producer_status == "CLAIMED_UNRESOLVED" and review == "CONFIRMED_APPLICATION":
            _fail("an unresolved producer claim cannot be independently confirmed")
        states.append(
            {
                "method_id": method_id,
                "method_version": version,
                "producer_claim_state": "CLAIMED",
                "producer_status": producer_status,
                "producer_claim_digest": _hex64(
                    row.get("producer_claim_digest"), f"{label} claim digest"
                ),
                "producer_outcome": outcome,
                "review_digest": _hex64(
                    row.get("review_digest"), f"{label} review digest"
                ),
                "review_disposition": review,
                "application_disposition": dispositions[review],
            }
        )
    return states


def _structural_debt(
    value: Any,
    *,
    states: Sequence[Mapping[str, Any]],
    denominator: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _fail("MethodCard application debt must be an ordered sequence")
    expected_review = {
        (state["method_id"], state["method_version"]): (
            "INDEPENDENT_APPLICATION_REVIEW_REJECTED"
            if state["review_disposition"] == "REJECTED_APPLICATION"
            else "INDEPENDENT_APPLICATION_REVIEW_UNRESOLVED"
        )
        for state in states
        if state["review_disposition"] != "CONFIRMED_APPLICATION"
    }
    seen_review: set[tuple[str, str]] = set()
    seen_denominator = False
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        label = f"MethodCard application debt[{index}]"
        row = _mapping(raw, label)
        code = row.get("code")
        if code == "UNKNOWN_DENOMINATOR_REMAINDER":
            _exact_keys(row, _DENOMINATOR_DEBT_KEYS, label)
            if seen_denominator:
                _fail("MethodCard application denominator debt is duplicated")
            seen_denominator = True
            if (
                row.get("runtime_denominator_digest")
                != denominator["runtime_denominator_digest"]
                or row.get("reason") != denominator["limitation_reason"]
            ):
                _fail("MethodCard application denominator debt is stale")
            result.append(dict(row))
            continue
        _exact_keys(row, _REVIEW_DEBT_KEYS, label)
        method_id = _string(row.get("method_id"), f"{label}.method_id", opaque=True)
        version = _string(row.get("method_version"), f"{label}.method_version")
        key = (method_id, version)
        if key in seen_review or expected_review.get(key) != code:
            _fail("MethodCard application review debt is missing, duplicate, or stale")
        state = next(
            state
            for state in states
            if (state["method_id"], state["method_version"]) == key
        )
        if (
            row.get("claim_digest") != state["producer_claim_digest"]
            or row.get("review_digest") != state["review_digest"]
        ):
            _fail("MethodCard application review debt digest is stale")
        _string(row.get("reason"), f"{label}.reason")
        seen_review.add(key)
        result.append(dict(row))
    if seen_review != set(expected_review):
        _fail("MethodCard application debt omits a rejected or unresolved review")
    requires_denominator_debt = (
        denominator["coverage_kind"] != "EXACT"
        or denominator["unknown_remainder"]
    )
    if seen_denominator != requires_denominator_debt:
        _fail("MethodCard application lower-bound denominator debt is incomplete")
    return result


def _application_value(value: Mapping[str, Any] | bytes) -> dict[str, Any]:
    authority = _mapping_input(value, label="MethodCard application authority")
    _exact_keys(authority, _APPLICATION_KEYS, "MethodCard application authority")
    if authority.get("schema") != APPLICATION_AUTHORITY_SCHEMA:
        _fail("MethodCard application authority schema is unsupported")
    _check_digest(authority, "authority_digest", "MethodCard application authority")
    if authority.get("authority_limits") != AUTHORITY_LIMITS:
        _fail("MethodCard application authority limits were broadened or altered")
    if authority.get("status") not in {"COMPLETE", "DEBT"}:
        _fail("MethodCard application authority status is unsupported")
    if not isinstance(authority.get("application_complete"), bool):
        _fail("MethodCard application completion flag must be boolean")
    if (authority["status"] == "COMPLETE") != authority["application_complete"]:
        _fail("MethodCard application status and completion flag disagree")
    denominator = _structural_denominator(authority.get("denominator"))
    states = _structural_method_states(authority.get("method_states"))
    debt = _structural_debt(
        authority.get("debt"),
        states=states,
        denominator=denominator,
    )
    complete = not debt and all(
        state["application_disposition"] == "INDEPENDENTLY_CONFIRMED"
        for state in states
    )
    if authority["application_complete"] != complete:
        _fail("MethodCard application completion contradicts method states or debt")
    normalized = dict(authority)
    normalized["denominator"] = denominator
    normalized["method_states"] = states
    normalized["debt"] = debt
    if normalized != authority:
        _fail("MethodCard application authority is structurally noncanonical")
    return authority


def canonical_method_card_application_authority_bytes(
    value: Mapping[str, Any],
) -> bytes:
    """Serialize one self-consistent authority with exactly one final LF."""

    authority = _application_value(value)
    try:
        return canonical_file_bytes(authority)
    except ProgramFactsTypeError as exc:
        _fail(f"MethodCard application authority is not canonical: {exc}", exc)


def validate_method_card_application_authority(
    value: Mapping[str, Any] | bytes,
    *,
    validated_runtime_authority: Mapping[str, Any] | bytes,
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    implementation_root: Path | str,
    producer_execution_witness: WorkerExecutionReplayWitness,
    reviewer_execution_witness: WorkerExecutionReplayWitness,
    worker_attempt: Mapping[str, Any] | bytes,
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
    producer_receipt: Mapping[str, Any] | bytes,
    application_review_receipt: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    """Replay an authority from every exact current input and compare it."""

    authority = _application_value(value)
    rebuilt = reconcile_method_card_application(
        validated_runtime_authority=validated_runtime_authority,
        runtime_replay_witness=runtime_replay_witness,
        implementation_root=implementation_root,
        producer_execution_witness=producer_execution_witness,
        reviewer_execution_witness=reviewer_execution_witness,
        worker_attempt=worker_attempt,
        output_bytes=output_bytes,
        source_files=source_files,
        producer_receipt=producer_receipt,
        application_review_receipt=application_review_receipt,
    )
    if authority != rebuilt:
        _fail(
            "MethodCard application authority differs from exact current "
            "receipts and identities"
        )
    return rebuilt


def _typed_output_value(
    witness: TypedWorkerOutputReplayWitness,
    *,
    role: str,
) -> ValidatedTypedWorkerOutput:
    expected = {
        "producer": (
            METHOD_CARD_PRODUCER_TYPED_ROLE,
            PRODUCER_TYPED_OUTPUT_SCHEMA,
        ),
        "reviewer": (
            METHOD_CARD_REVIEWER_TYPED_ROLE,
            REVIEWER_TYPED_OUTPUT_SCHEMA,
        ),
    }.get(role)
    if expected is None:
        _fail("typed MethodCard output role is unsupported")
    if (
        witness.typed_role != expected[0]
        or witness.payload_schema != expected[1]
        or witness.parser_id != STRICT_CANONICAL_JSON_PARSER_ID
    ):
        _fail(
            f"{role} typed worker output registry binding is aliased or not exact"
        )
    try:
        return replay_typed_worker_output(witness)
    except TypedWorkerOutputAuthorityError as exc:
        _fail(f"{role} typed worker output does not replay: {exc}", exc)


def _require_typed_input(
    output: ValidatedTypedWorkerOutput,
    *,
    identity: str,
    raw: bytes,
    label: str,
) -> None:
    if not isinstance(identity, str) or not identity.startswith(
        ("scratchpad:", "project:")
    ):
        _fail(f"{label} input identity is malformed")
    binding = output.input_bindings.get(identity)
    expected_sha = hashlib.sha256(raw).hexdigest()
    if (
        not isinstance(binding, Mapping)
        or binding.get("status") != "ACTIVE"
        or binding.get("sha256") != expected_sha
        or binding.get("size") != len(raw)
    ):
        _fail(f"{label} is absent from the exact typed-output input authority")


def _producer_typed_payload_value(
    output: ValidatedTypedWorkerOutput,
    *,
    runtime: Mapping[str, Any],
    selected: Sequence[Mapping[str, str]],
    cards: Mapping[tuple[str, str], MethodCard],
    runtime_snapshot: Mapping[str, Any],
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    payload = output.payload
    _exact_keys(
        payload,
        _PRODUCER_TYPED_PAYLOAD_KEYS,
        "producer typed MethodCard payload",
    )
    if (
        payload.get("schema") != PRODUCER_TYPED_OUTPUT_SCHEMA
        or payload.get("role") != "METHOD_CARD_PRODUCER"
    ):
        _fail("producer typed MethodCard payload schema or role is invalid")
    if payload.get("runtime_authority_digest") != runtime["authority_digest"]:
        _fail("producer typed payload runtime authority is stale")
    snapshot_digest = _hex64(
        runtime_snapshot.get("snapshot_digest"),
        "current source snapshot digest",
    )
    if payload.get("source_snapshot_digest") != snapshot_digest:
        _fail("producer typed payload source snapshot is stale")
    runtime_identity = payload.get("runtime_input_identity")
    snapshot_identity = payload.get("snapshot_input_identity")
    runtime_raw = canonical_file_bytes(runtime)
    snapshot_raw = canonical_file_bytes(runtime_snapshot)
    _require_typed_input(
        output,
        identity=runtime_identity,
        raw=runtime_raw,
        label="producer runtime authority",
    )
    _require_typed_input(
        output,
        identity=snapshot_identity,
        raw=snapshot_raw,
        label="producer source snapshot",
    )
    subject = _identity_value(
        payload.get("subject_output"),
        "producer typed subject output",
    )
    if subject != _file_identity(subject["path"], output_bytes):
        _fail("producer typed subject output differs from exact current bytes")
    expected_sources = _source_identities(source_files)
    raw_sources = payload.get("source_files")
    if isinstance(raw_sources, (str, bytes)) or not isinstance(
        raw_sources,
        Sequence,
    ):
        _fail("producer typed source files must be an ordered sequence")
    sources = [
        _identity_value(row, f"producer typed source file[{index}]")
        for index, row in enumerate(raw_sources)
    ]
    if sources != expected_sources:
        _fail("producer typed source files differ from exact current sources")
    subject_identity = f"scratchpad:{subject['path']}"
    _require_typed_input(
        output,
        identity=subject_identity,
        raw=output_bytes,
        label="producer subject output",
    )
    for source in sources:
        _require_typed_input(
            output,
            identity=f"project:{source['path']}",
            raw=source_files[source["path"]],
            label=f"producer source {source['path']}",
        )
    expected_input_identities = {
        runtime_identity,
        snapshot_identity,
        subject_identity,
        *(f"project:{source['path']}" for source in sources),
    }
    if set(output.input_bindings) != expected_input_identities:
        _fail("producer typed output input denominator is not exact")

    denominator = _validate_denominator_projection(
        payload.get("denominator"),
        runtime,
    )
    raw_claims = payload.get("claims")
    if (
        isinstance(raw_claims, (str, bytes))
        or not isinstance(raw_claims, Sequence)
        or len(raw_claims) != len(selected)
    ):
        _fail("producer typed claims must exactly cover every selected method")
    blobs = dict(source_files)
    if subject["path"] in blobs:
        _fail("producer typed subject output aliases a source file")
    blobs[subject["path"]] = output_bytes
    claims = [
        _normalize_claim(
            raw,
            expected_method=method,
            denominator=denominator,
            card=cards[(method["method_id"], method["method_version"])],
            blobs=blobs,
            output_bytes=output_bytes,
            persisted=True,
        )
        for raw, method in zip(raw_claims, selected, strict=True)
    ]
    if claims != raw_claims:
        _fail("producer typed claims are noncanonical")
    _validate_exact_candidate_set(claims, output_bytes)
    return {
        **payload,
        "subject_output": subject,
        "source_files": sources,
        "denominator": denominator,
        "claims": claims,
    }


def _reviewer_typed_payload_value(
    output: ValidatedTypedWorkerOutput,
    *,
    producer_output: ValidatedTypedWorkerOutput,
    producer_payload: Mapping[str, Any],
    runtime: Mapping[str, Any],
    runtime_snapshot: Mapping[str, Any],
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    payload = output.payload
    _exact_keys(
        payload,
        _REVIEWER_TYPED_PAYLOAD_KEYS,
        "reviewer typed MethodCard payload",
    )
    if (
        payload.get("schema") != REVIEWER_TYPED_OUTPUT_SCHEMA
        or payload.get("role") != "METHOD_CARD_REVIEWER"
    ):
        _fail("reviewer typed MethodCard payload schema or role is invalid")
    snapshot_digest = _hex64(
        runtime_snapshot.get("snapshot_digest"),
        "current source snapshot digest",
    )
    expected_scalar = {
        "runtime_authority_digest": runtime["authority_digest"],
        "source_snapshot_digest": snapshot_digest,
        "producer_typed_output_authority_digest": producer_output.authority[
            "authority_digest"
        ],
        "producer_execution_authority_digest": producer_output.authority[
            "worker_execution_authority_digest"
        ],
        "producer_output_identity": producer_output.authority[
            "canonical_output_identity"
        ],
        "producer_output_sha256": producer_output.authority["output_sha256"],
        "producer_payload_digest": producer_output.authority["payload_digest"],
    }
    if any(payload.get(key) != value for key, value in expected_scalar.items()):
        _fail("reviewer typed payload is stale against producer or runtime authority")
    if payload.get("denominator") != producer_payload["denominator"]:
        _fail("reviewer typed payload denominator differs from producer")
    _validate_denominator_projection(payload.get("denominator"), runtime)

    runtime_identity = payload.get("runtime_input_identity")
    snapshot_identity = payload.get("snapshot_input_identity")
    producer_authority_identity = payload.get(
        "producer_authority_input_identity"
    )
    if (
        runtime_identity != producer_payload["runtime_input_identity"]
        or snapshot_identity != producer_payload["snapshot_input_identity"]
    ):
        _fail("reviewer typed runtime/snapshot identities differ from producer")
    _require_typed_input(
        output,
        identity=runtime_identity,
        raw=canonical_file_bytes(runtime),
        label="reviewer runtime authority",
    )
    _require_typed_input(
        output,
        identity=snapshot_identity,
        raw=canonical_file_bytes(runtime_snapshot),
        label="reviewer source snapshot",
    )
    _require_typed_input(
        output,
        identity=producer_authority_identity,
        raw=canonical_typed_worker_output_authority_bytes(
            producer_output.authority
        ),
        label="reviewer producer execution authority",
    )
    _require_typed_input(
        output,
        identity=producer_output.authority["canonical_output_identity"],
        raw=producer_output.raw,
        label="reviewer producer typed receipt",
    )
    subject = producer_payload["subject_output"]
    subject_identity = f"scratchpad:{subject['path']}"
    _require_typed_input(
        output,
        identity=subject_identity,
        raw=output_bytes,
        label="reviewer producer subject output",
    )
    source_identities: set[str] = set()
    for source in producer_payload["source_files"]:
        identity = f"project:{source['path']}"
        source_identities.add(identity)
        _require_typed_input(
            output,
            identity=identity,
            raw=source_files[source["path"]],
            label=f"reviewer source {source['path']}",
        )
    expected_input_identities = {
        runtime_identity,
        snapshot_identity,
        producer_authority_identity,
        producer_output.authority["canonical_output_identity"],
        subject_identity,
        *source_identities,
    }
    if set(output.input_bindings) != expected_input_identities:
        _fail("reviewer typed output input denominator is not exact")

    claims = producer_payload["claims"]
    raw_reviews = payload.get("reviews")
    if (
        isinstance(raw_reviews, (str, bytes))
        or not isinstance(raw_reviews, Sequence)
        or len(raw_reviews) != len(claims)
    ):
        _fail("reviewer typed dispositions must exactly cover every producer claim")
    blobs = dict(source_files)
    blobs[subject["path"]] = output_bytes
    reviews = [
        _normalize_review(
            raw,
            claim=claim,
            blobs=blobs,
            persisted=True,
        )
        for raw, claim in zip(raw_reviews, claims, strict=True)
    ]
    if reviews != raw_reviews:
        _fail("reviewer typed dispositions are noncanonical")
    return {**payload, "denominator": dict(payload["denominator"]), "reviews": reviews}


def _validate_typed_output_independence(
    producer: ValidatedTypedWorkerOutput,
    reviewer: ValidatedTypedWorkerOutput,
    *,
    runtime: Mapping[str, Any],
) -> None:
    runtime_run = _mapping(
        runtime.get("work_plan_binding"),
        "runtime work plan binding",
    ).get("run_id")
    if (
        producer.authority["run_id"] != runtime_run
        or reviewer.authority["run_id"] != runtime_run
    ):
        _fail("typed producer/reviewer executions are not from the current runtime run")
    if (
        producer.authority["work_unit_id"]
        == reviewer.authority["work_unit_id"]
        or producer.authority["canonical_output_identity"]
        == reviewer.authority["canonical_output_identity"]
        or producer.authority["principal"]["identity"]
        == reviewer.authority["principal"]["identity"]
        or producer.authority["principal"]["invocation_id"]
        == reviewer.authority["principal"]["invocation_id"]
    ):
        _fail("typed producer and reviewer roles or work units are aliased")


def reconcile_method_card_application_v2(
    *,
    validated_runtime_authority: Mapping[str, Any] | bytes,
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    implementation_root: Path | str,
    producer_typed_output_witness: TypedWorkerOutputReplayWitness,
    reviewer_typed_output_witness: TypedWorkerOutputReplayWitness,
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    """Reconcile only incorporated producer claims and reviewer dispositions."""

    runtime, selected, cards = _runtime_context(
        validated_runtime_authority,
        implementation_root,
        runtime_replay_witness,
    )
    runtime_snapshot = _canonical_mapping_value(
        runtime_replay_witness.audit_snapshot,
        label="current MethodCard source snapshot",
    )
    activated = runtime.get("schema") == ACTIVATED_AUTHORITY_SCHEMA
    producer_output = _typed_output_value(
        producer_typed_output_witness,
        role="producer",
    )
    reviewer_output = _typed_output_value(
        reviewer_typed_output_witness,
        role="reviewer",
    )
    _validate_typed_output_independence(
        producer_output,
        reviewer_output,
        runtime=runtime,
    )
    producer = _producer_typed_payload_value(
        producer_output,
        runtime=runtime,
        selected=selected,
        cards=cards,
        runtime_snapshot=runtime_snapshot,
        output_bytes=output_bytes,
        source_files=source_files,
    )
    reviewer = _reviewer_typed_payload_value(
        reviewer_output,
        producer_output=producer_output,
        producer_payload=producer,
        runtime=runtime,
        runtime_snapshot=runtime_snapshot,
        output_bytes=output_bytes,
        source_files=source_files,
    )

    states: list[dict[str, Any]] = []
    debt: list[dict[str, Any]] = []
    dispositions = {
        "CONFIRMED_APPLICATION": "INDEPENDENTLY_CONFIRMED",
        "REJECTED_APPLICATION": "INDEPENDENTLY_REJECTED",
        "UNRESOLVED_APPLICATION": "INDEPENDENTLY_UNRESOLVED",
    }
    debt_codes = {
        "REJECTED_APPLICATION": "INDEPENDENT_APPLICATION_REVIEW_REJECTED",
        "UNRESOLVED_APPLICATION": "INDEPENDENT_APPLICATION_REVIEW_UNRESOLVED",
    }
    for claim, review in zip(producer["claims"], reviewer["reviews"], strict=True):
        disposition = review["disposition"]
        states.append(
            {
                "method_id": claim["method_id"],
                "method_version": claim["method_version"],
                "producer_claim_state": "CLAIMED",
                "producer_status": claim["status"],
                "producer_claim_digest": claim["claim_digest"],
                "producer_outcome": claim["outcome"],
                "review_digest": review["review_digest"],
                "review_disposition": disposition,
                "application_disposition": dispositions[disposition],
            }
        )
        if disposition in debt_codes:
            debt.append(
                {
                    "code": debt_codes[disposition],
                    "method_id": claim["method_id"],
                    "method_version": claim["method_version"],
                    "claim_digest": claim["claim_digest"],
                    "review_digest": review["review_digest"],
                    "reason": review["reason"],
                }
            )
    denominator = producer["denominator"]
    if denominator["coverage_kind"] != "EXACT" or denominator["unknown_remainder"]:
        debt.append(
            {
                "code": "UNKNOWN_DENOMINATOR_REMAINDER",
                "runtime_denominator_digest": denominator[
                    "runtime_denominator_digest"
                ],
                "reason": denominator["limitation_reason"],
            }
        )
    complete = not debt and all(
        state["application_disposition"] == "INDEPENDENTLY_CONFIRMED"
        for state in states
    )

    # Rebuild both typed authorities at the publication boundary.  This is
    # deliberately after semantic reconciliation so no parser execution or
    # concurrent PhaseIO drift can be hidden behind a would-be COMPLETE result.
    final_producer_output = _typed_output_value(
        producer_typed_output_witness,
        role="producer",
    )
    final_reviewer_output = _typed_output_value(
        reviewer_typed_output_witness,
        role="reviewer",
    )
    _validate_typed_output_independence(
        final_producer_output,
        final_reviewer_output,
        runtime=runtime,
    )
    final_producer = _producer_typed_payload_value(
        final_producer_output,
        runtime=runtime,
        selected=selected,
        cards=cards,
        runtime_snapshot=runtime_snapshot,
        output_bytes=output_bytes,
        source_files=source_files,
    )
    final_reviewer = _reviewer_typed_payload_value(
        final_reviewer_output,
        producer_output=final_producer_output,
        producer_payload=final_producer,
        runtime=runtime,
        runtime_snapshot=runtime_snapshot,
        output_bytes=output_bytes,
        source_files=source_files,
    )
    if (
        final_producer_output != producer_output
        or final_reviewer_output != reviewer_output
        or final_producer != producer
        or final_reviewer != reviewer
    ):
        _fail("typed MethodCard inputs changed before publication")
    unsigned = {
        "schema": (
            APPLICATION_AUTHORITY_V3_SCHEMA
            if activated
            else APPLICATION_AUTHORITY_V2_SCHEMA
        ),
        "runtime_authority_digest": runtime["authority_digest"],
        "source_snapshot_digest": runtime_snapshot["snapshot_digest"],
        "producer_typed_output_authority_digest": producer_output.authority[
            "authority_digest"
        ],
        "reviewer_typed_output_authority_digest": reviewer_output.authority[
            "authority_digest"
        ],
        "producer_payload_digest": producer_output.authority["payload_digest"],
        "reviewer_payload_digest": reviewer_output.authority["payload_digest"],
        "denominator": denominator,
        "status": "COMPLETE" if complete else "DEBT",
        "application_complete": complete,
        "method_states": states,
        "debt": debt,
        "typed_output_authorship": dict(V2_TYPED_OUTPUT_AUTHORSHIP),
        "authority_limits": dict(V2_AUTHORITY_LIMITS),
    }
    return _sign(unsigned, "authority_digest")


def _typed_application_value(
    value: Mapping[str, Any] | bytes,
    *,
    expected_schema: str,
) -> dict[str, Any]:
    label = (
        "MethodCard application v3 authority"
        if expected_schema == APPLICATION_AUTHORITY_V3_SCHEMA
        else "MethodCard application v2 authority"
    )
    authority = _mapping_input(value, label=label)
    _exact_keys(authority, _APPLICATION_V2_KEYS, label)
    if authority.get("schema") != expected_schema:
        _fail(f"{label} schema is unsupported")
    _check_digest(authority, "authority_digest", label)
    if authority.get("authority_limits") != V2_AUTHORITY_LIMITS:
        _fail("MethodCard application v2 authority limits were altered")
    if authority.get("typed_output_authorship") != V2_TYPED_OUTPUT_AUTHORSHIP:
        _fail("MethodCard application v2 typed-output authorship was altered")
    for field in (
        "runtime_authority_digest",
        "source_snapshot_digest",
        "producer_typed_output_authority_digest",
        "reviewer_typed_output_authority_digest",
        "producer_payload_digest",
        "reviewer_payload_digest",
    ):
        _hex64(authority.get(field), f"MethodCard application v2 {field}")
    if authority.get("status") not in {"COMPLETE", "DEBT"}:
        _fail("MethodCard application v2 status is unsupported")
    if type(authority.get("application_complete")) is not bool:
        _fail("MethodCard application v2 completion flag must be boolean")
    if (authority["status"] == "COMPLETE") != authority["application_complete"]:
        _fail("MethodCard application v2 status and completion flag disagree")
    denominator = _structural_denominator(authority.get("denominator"))
    states = _structural_method_states(authority.get("method_states"))
    debt = _structural_debt(
        authority.get("debt"),
        states=states,
        denominator=denominator,
    )
    complete = not debt and all(
        state["application_disposition"] == "INDEPENDENTLY_CONFIRMED"
        for state in states
    )
    if authority["application_complete"] != complete:
        _fail("MethodCard application v2 completion contradicts states or debt")
    normalized = dict(authority)
    normalized["denominator"] = denominator
    normalized["method_states"] = states
    normalized["debt"] = debt
    if normalized != authority:
        _fail("MethodCard application v2 authority is structurally noncanonical")
    return authority


def _application_v2_value(
    value: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    return _typed_application_value(
        value,
        expected_schema=APPLICATION_AUTHORITY_V2_SCHEMA,
    )


def _application_v3_value(
    value: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    return _typed_application_value(
        value,
        expected_schema=APPLICATION_AUTHORITY_V3_SCHEMA,
    )


def canonical_method_card_application_authority_v2_bytes(
    value: Mapping[str, Any],
) -> bytes:
    """Serialize one structurally closed v2 authority with one final LF."""

    authority = _application_v2_value(value)
    try:
        return canonical_file_bytes(authority)
    except ProgramFactsTypeError as exc:
        _fail(f"MethodCard application v2 authority is not canonical: {exc}", exc)


def canonical_method_card_application_authority_v3_bytes(
    value: Mapping[str, Any],
) -> bytes:
    """Serialize one activated per-card authority with one final LF."""

    authority = _application_v3_value(value)
    try:
        return canonical_file_bytes(authority)
    except ProgramFactsTypeError as exc:
        _fail(f"MethodCard application v3 authority is not canonical: {exc}", exc)


def reconcile_method_card_application_v3(
    **kwargs: Any,
) -> dict[str, Any]:
    """Reconcile activated v3 typed outputs; v1 runtime cannot enter."""

    authority = reconcile_method_card_application_v2(**kwargs)
    if authority.get("schema") != APPLICATION_AUTHORITY_V3_SCHEMA:
        _fail("MethodCard application v3 requires activated runtime authority")
    return authority


def validate_method_card_application_authority_v2(
    value: Mapping[str, Any] | bytes,
    *,
    validated_runtime_authority: Mapping[str, Any] | bytes,
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    implementation_root: Path | str,
    producer_typed_output_witness: TypedWorkerOutputReplayWitness,
    reviewer_typed_output_witness: TypedWorkerOutputReplayWitness,
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    """Replay a v2 authority from both exact typed worker outputs."""

    authority = _application_v2_value(value)
    rebuilt = reconcile_method_card_application_v2(
        validated_runtime_authority=validated_runtime_authority,
        runtime_replay_witness=runtime_replay_witness,
        implementation_root=implementation_root,
        producer_typed_output_witness=producer_typed_output_witness,
        reviewer_typed_output_witness=reviewer_typed_output_witness,
        output_bytes=output_bytes,
        source_files=source_files,
    )
    if authority != rebuilt:
        _fail(
            "MethodCard application v2 authority differs from exact current "
            "typed outputs and runtime inputs"
        )
    return rebuilt


def validate_method_card_application_authority_v3(
    value: Mapping[str, Any] | bytes,
    *,
    validated_runtime_authority: Mapping[str, Any] | bytes,
    runtime_replay_witness: MethodCardRuntimeReplayWitness,
    implementation_root: Path | str,
    producer_typed_output_witness: TypedWorkerOutputReplayWitness,
    reviewer_typed_output_witness: TypedWorkerOutputReplayWitness,
    output_bytes: bytes,
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    """Replay activated v3 authority from exact typed producer/reviewer bytes."""

    authority = _application_v3_value(value)
    rebuilt = reconcile_method_card_application_v3(
        validated_runtime_authority=validated_runtime_authority,
        runtime_replay_witness=runtime_replay_witness,
        implementation_root=implementation_root,
        producer_typed_output_witness=producer_typed_output_witness,
        reviewer_typed_output_witness=reviewer_typed_output_witness,
        output_bytes=output_bytes,
        source_files=source_files,
    )
    if authority != rebuilt:
        _fail(
            "MethodCard application v3 authority differs from exact current "
            "typed outputs and activated runtime inputs"
        )
    return rebuilt
