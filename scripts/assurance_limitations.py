"""Driver-owned audit-completeness and assurance-limitations projection.

The checkpoint/PhaseCommit graph is authoritative.  Markdown is a deterministic
client projection and cannot clear, reclassify, or conceal typed phase debt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from verification_operator_consumers import (
    ConsumerAuthorityError,
    validate_verifier_operator_consumer_authority,
)
from late_delivery_authority import (
    INDEPENDENT_VERIFICATION_RECORDED,
    derive_late_delivery_recovery_authority,
)
from chain_grouping_assurance import (
    ASSURANCE_FILE as CHAIN_GROUPING_ASSURANCE_FILE,
    LIMITATIONS_FILE as CHAIN_GROUPING_LIMITATIONS_FILE,
    validate_chain_grouping_assurance,
)
from chain_grouping_authority import RELATION_FILE as CHAIN_GROUPING_RELATION_FILE
from inventory_reconciliation import (
    HUMAN_REVIEW_FILE as INVENTORY_RECONCILIATION_HUMAN_REVIEW_FILE,
    RECONCILIATION_FILE as INVENTORY_RECONCILIATION_FILE,
    reconcile_inventory,
    validate_inventory_reconciliation,
)
from trust_evidence_authority import (
    TRUST_AUTHORITY_FILE,
    read_trust_review_debt,
)
from trust_evidence_provider import (
    PROVIDER_RECEIPT_FILE as TRUST_PROVIDER_RECEIPT_FILE,
    build_trust_evidence_provider_state,
    validate_trust_evidence_provider_state,
)
from candidate_negative_authority import (
    CANDIDATE_DENOMINATOR_FILE,
    CANDIDATE_PLAN_FILE,
    CandidateNegativeAuthorityError,
    validate_candidate_negative_denominator,
    validate_candidate_negative_ledger,
)
from artifact_ledger import (
    ArtifactLedgerError,
    active_committed_work_unit_authority_issues,
    read_artifact_ledger,
)
from axis_promotion_lineage import (
    authorize_downstream_inventory_tail,
    committed_promotion_output_issues,
)
import axis_disposition as axis_authority
import axis_canonical_prior as axis_prior_authority
from program_facts_types import (
    PROGRAM_FACTS_CONSUMER_ACTIVATION,
    ProgramFactsTypeError,
    derive_program_facts_reuse_key,
    strict_json_loads,
    validate_program_facts_debt,
    validate_program_facts_payload_shape,
    validate_program_facts_receipt,
)
from graph_application_authority import (
    AUTHORITY_ARTIFACT as GRAPH_APPLICATION_AUTHORITY_FILE,
    OBSERVATIONS_ARTIFACT as GRAPH_APPLICATION_OBSERVATIONS_FILE,
    RECONCILIATION_ARTIFACT as GRAPH_APPLICATION_RECONCILIATION_FILE,
    GraphApplicationAuthorityError,
    integration_contract as graph_application_integration_contract,
    load_graph_application_authority_bytes,
    load_graph_application_observations_bytes,
    load_graph_application_reconciliation_bytes,
    validate_graph_application_assurance_phaseio,
)


START_MARKER = "<!-- PLAMEN:ASSURANCE-LIMITATIONS:START -->"
END_MARKER = "<!-- PLAMEN:ASSURANCE-LIMITATIONS:END -->"
SECTION_HEADING = "## Audit Completeness and Assurance Limitations"

# The JSON manifest remains lossless authority.  These constants bound only
# the Markdown/model/client projection so thousands of mechanically repeated
# debt rows cannot consume an entire report/discriminator context window.
ASSURANCE_PROJECTION_MAX_GROUPS = 48
ASSURANCE_PROJECTION_MAX_IDENTITIES_PER_GROUP = 8
ASSURANCE_PROJECTION_MAX_MESSAGE_CHARS = 160
ASSURANCE_PROJECTION_SCHEMA = "plamen.assurance_limitations_projection.v1"

DISCOVERY_RECALL = "DISCOVERY_RECALL"
VERIFICATION_CONFIDENCE = "VERIFICATION_CONFIDENCE"
REPORT_INTEGRITY = "REPORT_INTEGRITY"
ENRICHMENT_ONLY = "ENRICHMENT_ONLY"

_ENRICHMENT_PHASES = frozenset(
    {
        "rag_sweep",
    }
)
_VERIFICATION_EXACT = frozenset(
    {
        "skeptic",
        "crossbatch",
        "external_dependency_research",
        "mechanical_verify",
        "sc_mechanical_verify",
        "verify_aggregate",
        "sc_verify_aggregate",
        "verify_queue",
        "sc_verify_queue",
    }
)
_MANAGED_BLOCK_RE = re.compile(
    r"(?:\r?\n)*"
    + re.escape(START_MARKER)
    + r"\r?\n.*?\r?\n"
    + re.escape(END_MARKER)
    + r"(?:\r?\n)?",
    re.DOTALL,
)
_LATE_DELIVERY_FIELDS = frozenset(
    {"schema_version", "proof_authority", "row_count", "rows", "receipt_sha256"}
)
_LATE_DELIVERY_ROW_FIELDS = frozenset(
    {
        "candidate_id",
        "delivery_state",
        "verify_artifact",
        "verify_sha256",
        "source_candidate_digest",
        "source_work_item_id",
        "source_operator_receipt",
        "source_operator_receipt_sha256",
        "source_operator_receipt_digest",
        "finding_lifecycle_obligation_id",
    }
)
_LATE_DELIVERY_STATES = frozenset(
    {"INDEPENDENT_VERIFICATION_RECORDED", "UNVERIFIED_HUMAN_REVIEW"}
)
_AXIS_AUTHORITY_FILES = (
    "_hot_function_axes.json",
    "_hot_function_cap_receipt.json",
    "_coverage_shortfalls.json",
    axis_prior_authority.SNAPSHOT_NAME,
    axis_prior_authority.AUTHORITY_NAME,
    "axis_disposition_worklist.json",
    "axis_execution_evidence_authority.json",
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
    "axis_disposition_initial_receipt.json",
    "axis_repair_plan.json",
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
    "axis_repair_execution_receipt.json",
    "axis_disposition_receipt.json",
    "axis_repair_work.json",
    "axis_assurance_debt.json",
    "axis_assurance_limitations.md",
    axis_authority.AXIS_PROMOTION_PLAN_NAME,
    "axis_coverage_promotion_receipt.json",
    "axis_coverage_promotion_receipt.md",
    "findings_inventory.md",
)
_AXIS_ACTIVATION_FILES = tuple(
    name
    for name in _AXIS_AUTHORITY_FILES
    if name not in {
        "_coverage_shortfalls.json",
        "findings_inventory.md",
    }
)

_PROGRAM_FACTS_V1_FILES = (
    "mechanical_program_facts.v1.json",
    "mechanical_program_facts_receipt.v1.json",
    "mechanical_program_facts_debt.v1.json",
)
_PROGRAM_FACTS_V2_FILES = (
    "mechanical_program_facts.v2.json",
    "mechanical_program_facts_receipt.v2.json",
    "mechanical_program_facts_debt.v2.json",
)
_PROGRAM_FACTS_RUNTIME_DEBT_FILE = "_program_facts_stage2_runtime_debt.json"
_PROGRAM_FACTS_RUNTIME_DEBT_ID = "PROGRAM-FACTS-STAGE2-EMIT-ONLY"
_PROGRAM_FACTS_ACTIVATION_SENTINELS = (
    "evm_analysis_workspace_receipt.v1.json",
    "_program_facts_inputs/checkpoint_capture.v1.json",
)
_GRAPH_APPLICATION_FILES = (
    GRAPH_APPLICATION_AUTHORITY_FILE,
    GRAPH_APPLICATION_OBSERVATIONS_FILE,
    GRAPH_APPLICATION_RECONCILIATION_FILE,
)
_INACTIVE_SHADOW_GATE_CLASSES = frozenset(
    {
        "PROGRAM_FACTS_AUTHORITY",
        "PROGRAM_FACTS_COVERAGE",
        "PROGRAM_FACTS_RUNTIME",
        "GRAPH_APPLICATION_AUTHORITY",
        "GRAPH_APPLICATION_OUTCOME",
    }
)


def _canonical_json(payload: Any) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _atomic_write_if_changed(path: Path, data: bytes) -> None:
    path = Path(path)
    if path.exists():
        try:
            if path.read_bytes() == data:
                return
        except OSError:
            pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _shadow_diagnostic_rows(
    rows: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    *,
    consumer_activation: bool,
    subsystem: str,
) -> tuple[dict[str, Any], ...]:
    """Bind shadow diagnostics to an explicit consumer-activation contract.

    The rows stay losslessly visible and retain their true potential assurance
    impact.  While the consumer is inactive they describe the staged subsystem,
    not a missing obligation from the active audit pipeline.
    """

    state = "ACTIVE_CONSUMER" if consumer_activation else "INACTIVE_SHADOW"
    projected: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        row["consumer_activation"] = bool(consumer_activation)
        row["activation_state"] = state
        row["terminal_success_blocking"] = bool(consumer_activation)
        if not consumer_activation:
            row["message"] = (
                f"{subsystem} is an inactive shadow diagnostic; active audit "
                "coverage and terminal success are unchanged. "
                + str(row.get("message") or "")
            ).strip()
        projected.append(row)
    return tuple(projected)


def _row_blocks_terminal_success(row: Mapping[str, Any]) -> bool:
    """Return whether one row can deny a clean terminal audit claim.

    Only the two explicitly staged subsystems may publish a nonblocking row,
    and only while they bind the closed inactive-consumer state.  This keeps an
    arbitrary supplemental producer from clearing its own real audit debt.
    """

    if row.get("assurance_impact") == ENRICHMENT_ONLY:
        return False
    if (
        row.get("gate_class") in _INACTIVE_SHADOW_GATE_CLASSES
        and row.get("consumer_activation") is False
        and row.get("activation_state") == "INACTIVE_SHADOW"
        and row.get("terminal_success_blocking") is False
    ):
        return False
    return True


def _load_late_delivery_rows(root: Path) -> dict[str, dict[str, Any]]:
    """Load the exact late-delivery receipt and bind its referenced bytes."""

    path = Path(root) / "post_verify_late_delivery.json"
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    if not isinstance(payload, dict) or set(payload) != _LATE_DELIVERY_FIELDS:
        raise ValueError("late delivery fields are not exact")
    if payload["schema_version"] != "plamen.post_verify_late_delivery.v1":
        raise ValueError("late delivery schema mismatch")
    if payload["proof_authority"] != "NONE":
        raise ValueError("late delivery acquired proof authority")
    if not isinstance(payload["rows"], list):
        raise ValueError("late delivery rows are not a list")
    if payload["row_count"] != len(payload["rows"]):
        raise ValueError("late delivery row count mismatch")
    unsigned = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    expected_digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if payload["receipt_sha256"] != expected_digest:
        raise ValueError("late delivery receipt digest mismatch")

    result: dict[str, dict[str, Any]] = {}
    for raw in payload["rows"]:
        if not isinstance(raw, dict) or set(raw) != _LATE_DELIVERY_ROW_FIELDS:
            raise ValueError("late delivery row fields are not exact")
        candidate_id = raw["candidate_id"]
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise ValueError("late delivery candidate identity is empty")
        if candidate_id in result:
            raise ValueError("late delivery candidate identity is duplicated")
        if raw["delivery_state"] not in _LATE_DELIVERY_STATES:
            raise ValueError("late delivery state is invalid")
        expected_artifact = f"verify_{candidate_id}.md"
        if raw["verify_artifact"] != expected_artifact:
            raise ValueError("late delivery verify artifact identity mismatch")
        verify_sha = raw["verify_sha256"]
        if not isinstance(verify_sha, str) or len(verify_sha) != 64:
            raise ValueError("late delivery verify digest is missing")
        if hashlib.sha256((root / expected_artifact).read_bytes()).hexdigest() != verify_sha:
            raise ValueError("late delivery verify artifact bytes changed")
        for field in (
            "source_candidate_digest",
            "source_work_item_id",
            "source_operator_receipt",
            "source_operator_receipt_sha256",
            "source_operator_receipt_digest",
            "finding_lifecycle_obligation_id",
        ):
            if raw[field] is not None and not isinstance(raw[field], str):
                raise ValueError(f"late delivery {field} has invalid type")
        source_path = raw["source_operator_receipt"]
        source_sha = raw["source_operator_receipt_sha256"]
        source_digest = raw["source_operator_receipt_digest"]
        if source_path is None:
            if source_sha is not None or source_digest is not None:
                raise ValueError("late delivery source receipt binding is partial")
        else:
            if not isinstance(source_sha, str) or len(source_sha) != 64:
                raise ValueError("late delivery source receipt digest is missing")
            if not isinstance(source_digest, str) or len(source_digest) != 64:
                raise ValueError("late delivery source authority digest is missing")
            if hashlib.sha256((root / source_path).read_bytes()).hexdigest() != source_sha:
                raise ValueError("late delivery source receipt bytes changed")
        result[candidate_id] = dict(raw)
    return result


def classify_assurance_impact(phase_name: str) -> str:
    """Classify a phase's degraded result by user-visible assurance impact.

    Unknown analysis phases default to recall impact.  That default is
    deliberate: silently understating an unknown degradation is the unsafe
    direction, while the explicit enrichment set remains precision-bounded.
    """

    phase = str(phase_name or "").strip().casefold()
    if phase in _ENRICHMENT_PHASES:
        return ENRICHMENT_ONLY
    if phase.startswith("report_") or phase in {
        "report_index",
        "report_assemble",
        "report_dedup",
        "report_disposition",
        "report_floor",
    }:
        return REPORT_INTEGRITY
    if (
        phase in _VERIFICATION_EXACT
        or phase.startswith("verify_")
        or phase.startswith("sc_verify_")
    ):
        return VERIFICATION_CONFIDENCE
    return DISCOVERY_RECALL


def _safe_cell(value: object) -> str:
    text = str(value or "-")
    # Gate messages originate in typed validators but may quote worker output.
    # Reserved block markers inside a quoted message must never become report
    # structure or make the exact managed projection unparsable.
    for marker in (START_MARKER, END_MARKER):
        escaped = marker.replace("<", "&lt;").replace(">", "&gt;")
        text = text.replace(marker, escaped)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def build_assurance_manifest(
    checkpoint: Any,
    *,
    supplemental_rows: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    """Build a deterministic manifest from typed and legacy checkpoint debt."""

    rows: list[dict[str, Any]] = []
    typed_degraded_phases: set[str] = set()
    phase_commits = getattr(checkpoint, "phase_commits", {}) or {}
    for commit_key in sorted(phase_commits):
        commit = phase_commits[commit_key]
        failures = tuple(getattr(commit, "unresolved_failures", ()) or ())
        if not failures:
            continue
        phase = str(getattr(commit, "phase_name", "") or commit_key)
        typed_degraded_phases.add(phase)
        for failure in sorted(
            failures,
            key=lambda item: (
                str(getattr(item, "gate_id", "")),
                str(getattr(item, "failure_instance_id", "")),
            ),
        ):
            rows.append(
                {
                    "phase": phase,
                    "work_unit_id": str(getattr(commit, "work_unit_id", "phase")),
                    "state": str(getattr(commit, "state", "COMPLETED_WITH_DEBT")),
                    "assurance_impact": classify_assurance_impact(phase),
                    "gate_id": str(getattr(failure, "gate_id", "unknown")),
                    "gate_class": str(getattr(failure, "gate_class", "UNKNOWN")),
                    "affected_identities": list(
                        getattr(failure, "affected_identities", ()) or ()
                    ),
                    "message": str(getattr(failure, "message", "unresolved debt")),
                    "failure_instance_id": str(
                        getattr(failure, "failure_instance_id", "")
                    ),
                }
            )

    for phase in sorted(set(getattr(checkpoint, "degraded", []) or [])):
        if phase in typed_degraded_phases:
            continue
        rows.append(
            {
                "phase": phase,
                "work_unit_id": "phase",
                "state": "LEGACY_DEGRADED",
                "assurance_impact": classify_assurance_impact(phase),
                "gate_id": f"{phase}.legacy_untyped_degradation",
                "gate_class": "LEGACY_UNTYPED_DEGRADATION",
                "affected_identities": [],
                "message": (
                    "The phase is marked degraded without a typed PhaseCommit "
                    "failure record; its assurance effect remains unresolved."
                ),
                "failure_instance_id": "",
            }
        )

    rows.extend(dict(row) for row in supplemental_rows)

    rows.sort(
        key=lambda row: (
            row["phase"],
            row["work_unit_id"],
            row["gate_id"],
            row["failure_instance_id"],
        )
    )
    counts = Counter(row["assurance_impact"] for row in rows)
    base: dict[str, Any] = {
        "schema_version": 1,
        "run_id": str(getattr(checkpoint, "run_id", "") or ""),
        "row_count": len(rows),
        "impact_counts": {key: counts[key] for key in sorted(counts)},
        "clean_full_audit_claim_allowed": not any(
            _row_blocks_terminal_success(row) for row in rows
        ),
        "rows": rows,
    }
    base["manifest_sha256"] = hashlib.sha256(_canonical_json(base)).hexdigest()
    return base


def _verification_operator_assurance_rows(
    scratchpad: Path, *, run_id: str = ""
) -> tuple[dict[str, Any], ...]:
    """Project exact compiler-operator debt into human-review assurance authority."""

    root = Path(scratchpad)
    paths = [root / "verification_operator_consumer_authority.json"] + [
        root / f"verification_operator_consumer_authority.wave{wave}.json"
        for wave in range(2, 4)
    ]
    rows: list[dict[str, Any]] = []
    delivery_rows: dict[str, dict[str, Any]] = {}
    consumer_candidate_ids: set[str] = set()
    delivery_path = root / "post_verify_late_delivery.json"
    if delivery_path.is_file():
        try:
            delivery_rows = _load_late_delivery_rows(root)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            digest = hashlib.sha256(
                f"late-delivery:{type(exc).__name__}:{exc}".encode("utf-8")
            ).hexdigest()
            rows.append(
                {
                    "phase": "verify_methods",
                    "work_unit_id": "post_verify_late_delivery",
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": VERIFICATION_CONFIDENCE,
                    "gate_id": "verification_operator_delivery_invalid",
                    "gate_class": "METHODOLOGY_APPLICATION",
                    "affected_identities": [],
                    "message": (
                        "Post-verification delivery authority is unreadable, stale, "
                        "or tampered; verifier-side observations remain unresolved."
                    ),
                    "failure_instance_id": digest,
                }
            )
    denominator_path = root / "verification_operator_denominator_authority.json"
    if denominator_path.is_file():
        try:
            denominator = json.loads(
                denominator_path.read_text(encoding="utf-8", errors="strict")
            )
            expected_fields = {
                "schema_version", "status", "queue_work_plan_digest",
                "verifier_roster_digest", "expected_work_item_ids",
                "source_receipt_count", "source_receipts", "debt_count",
                "debts", "authority_digest",
            }
            if set(denominator) != expected_fields:
                raise ValueError("operator denominator fields are not exact")
            unsigned = {
                key: value for key, value in denominator.items()
                if key != "authority_digest"
            }
            denominator_bytes = json.dumps(
                unsigned, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            if hashlib.sha256(denominator_bytes).hexdigest() != denominator[
                "authority_digest"
            ]:
                raise ValueError("operator denominator digest mismatch")
            if denominator["source_receipt_count"] != len(denominator["source_receipts"]):
                raise ValueError("operator denominator source count mismatch")
            if denominator["debt_count"] != len(denominator["debts"]):
                raise ValueError("operator denominator debt count mismatch")
            for source in denominator["source_receipts"]:
                if hashlib.sha256(
                    (root / source["path"]).read_bytes()
                ).hexdigest() != source["sha256"]:
                    raise ValueError("operator denominator source bytes changed")
            for debt in denominator["debts"]:
                rows.append(
                    {
                        "phase": "verify_methods",
                        "work_unit_id": str(debt["source_identity"]),
                        "state": "COMPLETED_WITH_DEBT",
                        "assurance_impact": VERIFICATION_CONFIDENCE,
                        "gate_id": str(debt["debt_code"]),
                        "gate_class": "METHODOLOGY_APPLICATION",
                        "affected_identities": list(debt["affected_work_item_ids"]),
                        "message": str(debt["detail"]),
                        "failure_instance_id": str(debt["debt_digest"]),
                    }
                )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, KeyError) as exc:
            digest = hashlib.sha256(
                f"denominator:{type(exc).__name__}:{exc}".encode("utf-8")
            ).hexdigest()
            rows.append(
                {
                    "phase": "verify_methods",
                    "work_unit_id": "verification_operator_denominator",
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": VERIFICATION_CONFIDENCE,
                    "gate_id": "verification_operator_denominator_invalid",
                    "gate_class": "METHODOLOGY_APPLICATION",
                    "affected_identities": [],
                    "message": "Operator receipt denominator authority is invalid or stale.",
                    "failure_instance_id": digest,
                }
            )
    for path in paths:
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
            authority = validate_verifier_operator_consumer_authority(
                payload, scratchpad=root
            )
            for source in authority["source_receipts"]:
                source_path = root / str(source["path"])
                actual = hashlib.sha256(source_path.read_bytes()).hexdigest()
                if actual != source["sha256"]:
                    raise ConsumerAuthorityError(
                        f"source receipt changed: {source['path']}"
                    )
        except (OSError, UnicodeError, json.JSONDecodeError, ConsumerAuthorityError) as exc:
            digest = hashlib.sha256(
                f"{path.name}:{type(exc).__name__}:{exc}".encode("utf-8")
            ).hexdigest()
            rows.append(
                {
                    "phase": "verify_methods",
                    "work_unit_id": path.stem,
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": VERIFICATION_CONFIDENCE,
                    "gate_id": "verification_operator_consumer_authority_invalid",
                    "gate_class": "METHODOLOGY_APPLICATION",
                    "affected_identities": [],
                    "message": (
                        "Verifier methodology-application authority is unreadable, "
                        "stale, or tampered; negative verification authority is reduced."
                    ),
                    "failure_instance_id": digest,
                }
            )
            continue
        for debt in authority["assurance_debts"]:
            rows.append(
                {
                    "phase": "verify_methods",
                    "work_unit_id": str(debt["affected_work_item_id"]),
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": VERIFICATION_CONFIDENCE,
                    "gate_id": str(debt["debt_code"]),
                    "gate_class": "METHODOLOGY_APPLICATION",
                    "affected_identities": [str(debt["affected_work_item_id"])],
                    "message": (
                        f"Verification operator {debt['operator_id']} was blocked; "
                        "negative disposition authority remains reduced. Evidence: "
                        + "; ".join(str(item) for item in debt["blocker_evidence"])
                    ),
                    "failure_instance_id": str(debt["debt_digest"]),
                }
            )
        late_work = {
            str(work["work_item_id"]): work
            for shard in authority["late_verification_shards"]
            for work in shard["rows"]
        }
        for candidate in authority["candidates"]:
            candidate_id = str(candidate["candidate_id"])
            consumer_candidate_ids.add(candidate_id)
            delivery = delivery_rows.get(candidate_id)
            work = late_work.get(candidate_id)
            exact_binding = {
                "source_candidate_digest": candidate["candidate_digest"],
                "source_work_item_id": candidate["source_work_item_id"],
                "source_operator_receipt": candidate["source_operator_receipt"],
                "source_operator_receipt_sha256": candidate[
                    "source_operator_receipt_sha256"
                ],
                "source_operator_receipt_digest": candidate[
                    "source_operator_receipt_digest"
                ],
                "finding_lifecycle_obligation_id": (
                    work["finding_lifecycle_obligation_id"] if work else None
                ),
            }
            if delivery is None or work is None or any(
                delivery.get(field) != expected
                for field, expected in exact_binding.items()
            ):
                digest = hashlib.sha256(
                    json.dumps(
                        {
                            "candidate_id": candidate_id,
                            "expected": exact_binding,
                            "delivery": delivery,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                rows.append(
                    {
                        "phase": "verify_methods",
                        "work_unit_id": candidate_id,
                        "state": "COMPLETED_WITH_DEBT",
                        "assurance_impact": VERIFICATION_CONFIDENCE,
                        "gate_id": "verification_operator_delivery_invalid",
                        "gate_class": "METHODOLOGY_APPLICATION",
                        "affected_identities": [candidate_id],
                        "message": (
                            "Verifier-side observation lacks an exact current "
                            "post-verification delivery binding."
                        ),
                        "failure_instance_id": digest,
                    }
                )
                continue
            recovery_authority = derive_late_delivery_recovery_authority(
                root,
                run_id=str(authority["run_id"]),
                expected_work=work,
            )
            claimed_verified = (
                delivery["delivery_state"]
                == INDEPENDENT_VERIFICATION_RECORDED
            )
            independently_verified = bool(
                recovery_authority["positive_authority"]
            )
            if claimed_verified and not independently_verified:
                digest = hashlib.sha256(
                    json.dumps(
                        {
                            "candidate_id": candidate_id,
                            "delivery_state": delivery["delivery_state"],
                            "recovery_authority": recovery_authority,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                rows.append(
                    {
                        "phase": "verify_methods",
                        "work_unit_id": candidate_id,
                        "state": "COMPLETED_WITH_DEBT",
                        "assurance_impact": VERIFICATION_CONFIDENCE,
                        "gate_id": "verification_operator_delivery_state_unbound",
                        "gate_class": "METHODOLOGY_APPLICATION",
                        "affected_identities": [candidate_id],
                        "message": (
                            "The delivery projection claims independent verification, "
                            "but the exact recovery contract, launch, execution receipt, "
                            "and bound operator artifacts do not authorize that state. "
                            "The candidate remains human-review work."
                        ),
                        "failure_instance_id": digest,
                    }
                )
            # Human-review is a monotonic conservative state.  A recovery
            # receipt cannot silently upgrade it; only the delivery writer may
            # claim the positive state, and only exact recovery authority can
            # validate that claim.
            if claimed_verified and independently_verified:
                continue
            rows.append(
                {
                    "phase": "verify_methods",
                    "work_unit_id": candidate_id,
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": VERIFICATION_CONFIDENCE,
                    "gate_id": "verification_operator_candidate_unresolved",
                    "gate_class": "METHODOLOGY_APPLICATION",
                    "affected_identities": [candidate_id],
                    "message": (
                        "A verifier-side observation remains proposal-only and "
                        "requires independent human review. Exact claim: "
                        f"{candidate['title']}; mechanism={candidate['mechanism']}; "
                        f"evidence={candidate['evidence']}; "
                        f"source_digest={candidate['candidate_digest']}"
                    ),
                    "failure_instance_id": str(candidate["candidate_digest"]),
                }
            )
    # Legacy post-verify candidates do not have a verifier-operator consumer
    # authority.  They still cannot acquire a positive delivery state from the
    # delivery sidecar alone: re-derive it from their exact recovery execution.
    for candidate_id, delivery in sorted(delivery_rows.items()):
        if (
            candidate_id in consumer_candidate_ids
            or delivery["delivery_state"] != INDEPENDENT_VERIFICATION_RECORDED
        ):
            continue
        expected_work = {
            "work_item_id": candidate_id,
            "source_candidate_digest": delivery["source_candidate_digest"],
            "source_work_item_id": delivery["source_work_item_id"],
            "source_operator_receipt": delivery["source_operator_receipt"],
            "source_operator_receipt_sha256": delivery[
                "source_operator_receipt_sha256"
            ],
            "source_operator_receipt_digest": delivery[
                "source_operator_receipt_digest"
            ],
            "finding_lifecycle_obligation_id": delivery[
                "finding_lifecycle_obligation_id"
            ],
        }
        recovery_authority = derive_late_delivery_recovery_authority(
            root,
            run_id=str(run_id or "unknown-run"),
            expected_work=expected_work,
        )
        if recovery_authority["positive_authority"]:
            continue
        digest = hashlib.sha256(
            json.dumps(
                {
                    "candidate_id": candidate_id,
                    "delivery_state": delivery["delivery_state"],
                    "recovery_authority": recovery_authority,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        rows.append(
            {
                "phase": "verify_methods",
                "work_unit_id": candidate_id,
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": VERIFICATION_CONFIDENCE,
                "gate_id": "verification_operator_delivery_state_unbound",
                "gate_class": "METHODOLOGY_APPLICATION",
                "affected_identities": [candidate_id],
                "message": (
                    "The legacy late-delivery projection claims independent "
                    "verification without one exact current recovery execution; "
                    "the candidate remains human-review work."
                ),
                "failure_instance_id": digest,
            }
        )
    unique = {
        (row["work_unit_id"], row["gate_id"], row["failure_instance_id"]): row
        for row in rows
    }
    return tuple(unique[key] for key in sorted(unique))


def _chain_grouping_assurance_rows(
    scratchpad: Path,
    *,
    project_root: Path,
    run_id: str,
) -> tuple[dict[str, Any], ...]:
    """Project only exact independently unreconciled P0-W members.

    Relation/group proposals are telemetry and never become limitations on
    their own.  A row appears only when the current replayable authority says
    an exact member missed a verifier/report-delivery stage, or when that
    authority is missing/stale/tampered and therefore cannot support a clean
    audit claim.
    """

    root = Path(scratchpad)
    relation = root / CHAIN_GROUPING_RELATION_FILE
    outputs = (
        root / CHAIN_GROUPING_ASSURANCE_FILE,
        root / CHAIN_GROUPING_LIMITATIONS_FILE,
    )
    if not relation.is_file() and not any(path.exists() for path in outputs):
        return ()
    rows: list[dict[str, Any]] = []
    try:
        if not relation.is_file():
            raise ValueError(
                "assurance outputs exist without current relation authority"
            )
        if not run_id:
            raise ValueError("chain grouping assurance has no current run_id")
        payload = validate_chain_grouping_assurance(
            root, Path(project_root), run_id=run_id
        )
    except (
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        fingerprints: dict[str, str | None] = {}
        for path in (relation, *outputs):
            try:
                fingerprints[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                fingerprints[path.name] = None
        digest = hashlib.sha256(
            json.dumps(
                {
                    "error": f"{type(exc).__name__}: {exc}",
                    "sources": fingerprints,
                    "run_id": run_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return (
            {
                "phase": "chain",
                "work_unit_id": "chain_grouping_assurance",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": DISCOVERY_RECALL,
                "gate_id": "chain_grouping_assurance_invalid",
                "gate_class": "METHODOLOGY_APPLICATION",
                "affected_identities": [],
                "message": (
                    "Exact chain-group member delivery cannot be replayed from "
                    "current sources; all unresolved members require human review."
                ),
                "failure_instance_id": digest,
            },
        )
    for debt in payload["assurance_debts"]:
        missing = ", ".join(str(item) for item in debt["missing_authority_stages"])
        rows.append(
            {
                "phase": "chain",
                "work_unit_id": str(debt["member_id"]),
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": DISCOVERY_RECALL,
                "gate_id": "chain_group_member_delivery_incomplete",
                "gate_class": "METHODOLOGY_APPLICATION",
                "affected_identities": [str(debt["member_id"])],
                "message": (
                    "Exact chain-group member did not independently traverse: "
                    f"{missing}; source_record_sha256="
                    f"{debt['source_record_sha256']}"
                ),
                "failure_instance_id": str(debt["debt_sha256"]),
            }
        )
    return tuple(rows)


def _inventory_reconciliation_assurance_rows(
    scratchpad: Path,
) -> tuple[dict[str, Any], ...]:
    """Project current exact raw-to-inventory debt without trusting Markdown."""

    root = Path(scratchpad)
    receipt_path = root / INVENTORY_RECONCILIATION_FILE
    has_current_manifests = any(root.glob("inventory_chunk_*.manifest.md"))
    if not receipt_path.is_file() and not has_current_manifests:
        return ()
    rows: list[dict[str, Any]] = []
    try:
        expected = reconcile_inventory(root, persist=False)
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        digest = hashlib.sha256(
            f"inventory-reconciliation:{type(exc).__name__}:{exc}".encode(
                "utf-8"
            )
        ).hexdigest()
        return (
            {
                "phase": "inventory",
                "work_unit_id": "exact_reconciliation",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": DISCOVERY_RECALL,
                "gate_id": "inventory_reconciliation_invalid",
                "gate_class": "METHODOLOGY_APPLICATION",
                "affected_identities": [],
                "message": (
                    "Exact raw-discovery to inventory disposition cannot be "
                    "re-derived from current sources; unresolved candidates "
                    "require human review."
                ),
                "failure_instance_id": digest,
            },
        )

    receipt_issues = validate_inventory_reconciliation(root)
    if receipt_issues:
        digest = hashlib.sha256(
            json.dumps(
                {
                    "issues": sorted(receipt_issues),
                    "denominator_digest": expected.get("denominator_digest"),
                    "receipt_digest": expected.get("receipt_digest"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        rows.append(
            {
                "phase": "inventory",
                "work_unit_id": "exact_reconciliation",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": DISCOVERY_RECALL,
                "gate_id": "inventory_reconciliation_invalid",
                "gate_class": "METHODOLOGY_APPLICATION",
                "affected_identities": sorted(
                    {
                        str(item.get("source_finding_id") or "")
                        for item in expected.get("candidates") or []
                        if item.get("source_finding_id")
                    }
                ),
                "message": (
                    "The stored exact inventory reconciliation is missing, "
                    "stale, or non-canonical; current-source reconciliation "
                    "remains the recall-safe authority."
                ),
                "failure_instance_id": digest,
            }
        )

    for candidate in expected.get("candidates") or []:
        if not isinstance(candidate, dict) or (
            candidate.get("disposition") != "HUMAN_REVIEW_DEBT"
        ):
            continue
        source_id = str(candidate.get("source_finding_id") or "")
        source_artifact = str(candidate.get("source_artifact") or "")
        candidate_key = str(candidate.get("candidate_key") or "")
        failure_digest = hashlib.sha256(
            json.dumps(
                {
                    "candidate_key": candidate_key,
                    "source_sha256": candidate.get("source_sha256"),
                    "source_block_sha256": candidate.get(
                        "source_block_sha256"
                    ),
                    "reason_code": candidate.get("reason_code"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        rows.append(
            {
                "phase": "inventory",
                "work_unit_id": candidate_key or source_id,
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": DISCOVERY_RECALL,
                "gate_id": "inventory_candidate_unresolved",
                "gate_class": "METHODOLOGY_APPLICATION",
                "affected_identities": [source_id] if source_id else [],
                "message": (
                    "A raw discovery candidate lacks a current exact final "
                    "inventory disposition and remains NEEDS_INVENTORY_REVIEW; "
                    f"source={source_artifact}:{source_id}; reason="
                    f"{candidate.get('reason_code')}; source_block_sha256="
                    f"{candidate.get('source_block_sha256')}"
                ),
                "failure_instance_id": failure_digest,
            }
        )
    return tuple(rows)


def _trust_evidence_assurance_rows(
    scratchpad: Path,
    *,
    run_id: str,
) -> tuple[dict[str, Any], ...]:
    """Project provider-owned trust gaps without granting negative authority."""

    root = Path(scratchpad)
    authority_path = root / TRUST_AUTHORITY_FILE
    receipt_path = root / TRUST_PROVIDER_RECEIPT_FILE
    debt_paths = sorted(root.glob("trust_evidence_debt_*.json"))
    provider_required = (
        (root / "severity_decision_ledger.shadow.json").is_file()
        or any(root.glob("verify_*.severity_decision.json"))
        or any(root.glob("severity_adjudication_*.json"))
        or bool(debt_paths)
    )
    if (
        not provider_required
        and not authority_path.is_file()
        and not receipt_path.is_file()
    ):
        return ()
    rows: list[dict[str, Any]] = []
    try:
        _ledger, receipt = build_trust_evidence_provider_state(
            root, run_id=run_id
        )
        provider_issues = list(
            validate_trust_evidence_provider_state(root, run_id=run_id)
        )
    except (OSError, TypeError, ValueError) as exc:
        receipt = {"candidate_debts": [], "global_debts": []}
        provider_issues = [f"{type(exc).__name__}: {exc}"]

    if provider_issues:
        failure_id = hashlib.sha256(
            _canonical_json({"provider_issues": sorted(provider_issues)})
        ).hexdigest()
        rows.append(
            {
                "phase": "severity_adjudication_shadow",
                "work_unit_id": "trust_evidence_reconcile",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": VERIFICATION_CONFIDENCE,
                "gate_id": "trust_evidence_provider_invalid",
                "gate_class": "TRUST_EVIDENCE_AUTHORITY",
                "affected_identities": [],
                "message": (
                    "The deterministic trust provider state is missing, stale, "
                    "or tampered. No severity reduction or PoC exemption is "
                    "authorized; exact trust premises require human review. "
                    + "; ".join(provider_issues)
                ),
                "failure_instance_id": failure_id,
            }
        )

    for code in sorted(set(receipt.get("global_debts") or [])):
        failure_id = hashlib.sha256(
            _canonical_json({"trust_global_debt": str(code), "run_id": run_id})
        ).hexdigest()
        rows.append(
            {
                "phase": "severity_adjudication_shadow",
                "work_unit_id": "trust_evidence_reconcile",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": VERIFICATION_CONFIDENCE,
                "gate_id": "trust_evidence_provider_global_debt",
                "gate_class": "TRUST_EVIDENCE_AUTHORITY",
                "affected_identities": [],
                "message": (
                    f"Trust evidence provider debt {code}; upstream severity "
                    "and verification were retained."
                ),
                "failure_instance_id": failure_id,
            }
        )

    for debt in receipt.get("candidate_debts") or []:
        if not isinstance(debt, dict):
            continue
        finding_id = str(debt.get("finding_id") or "")
        codes = sorted(str(code) for code in debt.get("debt_codes") or [])
        rows.append(
            {
                "phase": "severity_adjudication_shadow",
                "work_unit_id": finding_id or "trust_evidence_reconcile",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": VERIFICATION_CONFIDENCE,
                "gate_id": "trust_evidence_authority_unavailable",
                "gate_class": "TRUST_EVIDENCE_AUTHORITY",
                "affected_identities": [finding_id] if finding_id else [],
                "message": (
                    "The proposed trusted-actor limitation lacks exact "
                    "provider-owned scope/provenance/adjudication authority; "
                    "severity and verification were retained. debt="
                    + ",".join(codes)
                ),
                "failure_instance_id": str(debt.get("debt_digest") or ""),
            }
        )

    for debt_path in debt_paths:
        try:
            debt = read_trust_review_debt(
                debt_path, expected_run_id=run_id
            )
            finding_id = str(debt.get("finding_id") or "")
            consumer = str(debt.get("consumer") or "")
            resolution = debt.get("resolution") or {}
            codes = sorted(str(code) for code in resolution.get("debts") or [])
            rows.append(
                {
                    "phase": "severity_adjudication_shadow",
                    "work_unit_id": f"{finding_id}:{consumer}",
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": VERIFICATION_CONFIDENCE,
                    "gate_id": "trust_evidence_consumer_debt",
                    "gate_class": "TRUST_EVIDENCE_AUTHORITY",
                    "affected_identities": [finding_id],
                    "message": (
                        f"Trust consumer {consumer} retained the requested "
                        "negative action for human review. debt="
                        + ",".join(codes)
                    ),
                    "failure_instance_id": str(debt.get("debt_digest") or ""),
                }
            )
        except (OSError, UnicodeError, TypeError, ValueError) as exc:
            failure_id = hashlib.sha256(
                _canonical_json(
                    {
                        "path": debt_path.name,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            ).hexdigest()
            rows.append(
                {
                    "phase": "severity_adjudication_shadow",
                    "work_unit_id": debt_path.name,
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": VERIFICATION_CONFIDENCE,
                    "gate_id": "trust_evidence_consumer_debt_invalid",
                    "gate_class": "TRUST_EVIDENCE_AUTHORITY",
                    "affected_identities": [],
                    "message": (
                        f"Trust consumer debt {debt_path.name} is malformed; "
                        "no negative action is authorized. {type(exc).__name__}: {exc}"
                    ),
                    "failure_instance_id": failure_id,
                }
            )
    return tuple(rows)


def _candidate_negative_assurance_rows(
    scratchpad: Path,
) -> tuple[dict[str, Any], ...]:
    """Replay the candidate-negative denominator into bounded report debt.

    Supported exclusions and reopened candidates are already accounted by
    their typed receipt/projection and do not add client noise.  Invalid
    authority or unresolved identities remain discovery-recall limitations.
    """

    root = Path(scratchpad)
    ledger_paths = sorted(root.glob("candidate_negative_proposals_*.json"))
    authority_present = bool(
        ledger_paths
        or (root / CANDIDATE_PLAN_FILE).is_file()
        or (root / "candidate_negative_skeptic_receipt.json").is_file()
        or (root / CANDIDATE_DENOMINATOR_FILE).is_file()
    )
    if not authority_present:
        return ()

    ledgers: list[dict[str, Any]] = []
    affected: set[str] = set()
    errors: list[str] = []
    for path in ledger_paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
            validate_candidate_negative_ledger(payload)
            ledgers.append(payload)
            affected.update(event["event_id"] for event in payload["events"])
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            CandidateNegativeAuthorityError,
        ) as exc:
            errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
    try:
        plan = json.loads(
            (root / CANDIDATE_PLAN_FILE).read_text(
                encoding="utf-8", errors="strict"
            )
        )
        receipt = json.loads(
            (root / "candidate_negative_skeptic_receipt.json").read_text(
                encoding="utf-8", errors="strict"
            )
        )
        recorded = json.loads(
            (root / CANDIDATE_DENOMINATOR_FILE).read_text(
                encoding="utf-8", errors="strict"
            )
        )
        replay = validate_candidate_negative_denominator(
            ledgers=ledgers,
            plan=plan,
            receipt=receipt,
            projection_path=(
                root / "candidate_negative_skeptic_proposals.md"
            ),
        )
        if recorded != replay:
            errors.append("recorded candidate-negative denominator differs from replay")
        errors.extend(str(issue) for issue in replay.get("issues", []))
        if (
            replay.get("status") != "COMPLETE"
            and not replay.get("human_review_count")
            and not replay.get("issues")
        ):
            errors.append(
                "candidate-negative denominator did not reach COMPLETE: "
                f"{replay.get('status')}"
            )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        replay = {}
        errors.append(f"candidate-negative authority unavailable: {type(exc).__name__}: {exc}")

    if errors:
        failure_id = hashlib.sha256(
            _canonical_json(
                {
                    "gate": "candidate_negative_denominator_invalid",
                    "errors": sorted(set(errors)),
                    "affected": sorted(affected),
                }
            )
        ).hexdigest()
        return (
            {
                "phase": "application_skeptic",
                "work_unit_id": "candidate_negative_denominator",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": DISCOVERY_RECALL,
                "gate_id": "candidate_negative_denominator_invalid",
                "gate_class": "CANDIDATE_NEGATIVE_AUTHORITY",
                "affected_identities": sorted(affected),
                "message": (
                    "Candidate-negative outcome authority is missing, stale, or "
                    "inconsistent; no producer-authored negative is trusted. "
                    + "; ".join(sorted(set(errors)))
                ),
                "failure_instance_id": failure_id,
            },
        )

    unresolved = sorted(
        row["event_id"]
        for row in replay.get("outcomes", [])
        if row.get("outcome") == "HUMAN_REVIEW"
    )
    if not unresolved:
        return ()
    failure_id = hashlib.sha256(
        _canonical_json(
            {
                "gate": "candidate_negative_human_review",
                "denominator_digest": replay.get("denominator_digest"),
                "affected": unresolved,
            }
        )
    ).hexdigest()
    return (
        {
            "phase": "application_skeptic",
            "work_unit_id": "candidate_negative_discriminator",
            "state": "COMPLETED_WITH_DEBT",
            "assurance_impact": DISCOVERY_RECALL,
            "gate_id": "candidate_negative_human_review",
            "gate_class": "CANDIDATE_NEGATIVE_AUTHORITY",
            "affected_identities": unresolved,
            "message": (
                f"{len(unresolved)} producer-authored candidate negative(s) "
                "remain unresolved and require independent human review."
            ),
            "failure_instance_id": failure_id,
        },
    )


def _axis_json(path: Path, *, label: str) -> dict[str, Any]:
    """Read one axis authority object without accepting duplicate keys/NaN."""

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"{label} contains invalid JSON constant {value}")

    try:
        payload = json.loads(
            path.read_bytes().decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=invalid_constant,
        )
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {exc}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain one object")
    return payload


def _axis_committed_promotion_plan(
    root: Path,
    *,
    project_root: Path,
    run_id: str,
    inventory_raw: bytes,
) -> dict[str, Any]:
    """Load a live plan only when its exact PhaseIO commit still owns it."""

    path = Path(root) / axis_authority.AXIS_PROMOTION_PLAN_NAME
    raw = path.read_bytes()
    plan = _axis_json(path, label="axis promotion plan")
    validated = axis_authority.validate_axis_promotion_plan_replay(
        plan,
        None,
        run_id=run_id,
        current_inventory_raw=inventory_raw,
        downstream_tail_authorizer=lambda promotion_plan, current_raw: (
            authorize_downstream_inventory_tail(
                scratchpad=Path(root),
                project_root=Path(project_root),
                run_id=run_id,
                promotion_plan=promotion_plan,
                current_inventory_raw=current_raw,
            )
        ),
    )
    ledger = read_artifact_ledger(Path(root))
    phaseio = validated.get("phaseio_authority")
    signed_binding = (
        phaseio.get("plan") if isinstance(phaseio, dict) else None
    )
    key = (
        str(signed_binding.get("work_unit_key") or "")
        if isinstance(signed_binding, dict)
        else ""
    )
    if not key:
        raise ValueError(
            "axis promotion plan has no signed current-run PhaseIO owner"
        )
    unit = dict(ledger.get("work_units") or {}).get(key)
    if not isinstance(unit, dict):
        raise ValueError("axis promotion plan PhaseIO owner is absent")
    identity = f"scratchpad:{axis_authority.AXIS_PROMOTION_PLAN_NAME}"
    authority_issues = active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=key,
        run_id=run_id,
        expected_artifact_identities=(identity,),
    )
    if authority_issues:
        raise ValueError("; ".join(authority_issues))
    observed_binding = {
        "work_unit_key": key,
        "contract_digest": str(unit.get("contract_digest") or ""),
        "launch_digest": str(unit.get("launch_digest") or ""),
    }
    if dict(signed_binding) != observed_binding:
        raise ValueError(
            "axis promotion plan PhaseIO owner differs from immutable plan"
        )
    record = dict(unit.get("artifacts") or {}).get(identity)
    if not isinstance(record, dict):
        raise ValueError("axis promotion plan committed record is absent")
    if (
        hashlib.sha256(raw).hexdigest() != record.get("sha256")
        or len(raw) != record.get("size")
    ):
        raise ValueError(
            "axis promotion plan live bytes differ from PhaseIO commit"
        )
    return validated


def _axis_committed_promotion_output_issues(
    root: Path,
    *,
    project_root: Path,
    run_id: str,
    promotion_plan: dict[str, Any] | None = None,
) -> list[str]:
    """Require the live receipt/inventory pair to have PhaseIO commit authority.

    A promotion receipt is a semantic reconciliation record, not proof that
    its inventory MERGE committed.  Keep that execution/ownership proof
    separate so self-digested bytes written before a crash cannot certify
    themselves during assurance projection.
    """

    return committed_promotion_output_issues(
        scratchpad=Path(root),
        project_root=Path(project_root),
        run_id=run_id,
        promotion_plan=promotion_plan,
    )


def _axis_source_fingerprints(root: Path) -> dict[str, str | None]:
    fingerprints: dict[str, str | None] = {}
    for name in _AXIS_AUTHORITY_FILES:
        path = root / name
        if not path.exists():
            continue
        try:
            fingerprints[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            fingerprints[name] = None
    return fingerprints


def _axis_row(
    gate_id: str,
    *,
    work_unit_id: str,
    affected: list[str] | tuple[str, ...] = (),
    message: str,
    evidence: Any,
    gate_class: str = "METHODOLOGY_APPLICATION",
) -> dict[str, Any]:
    identities = sorted(
        {
            str(identity).strip()
            for identity in affected
            if str(identity).strip()
        }
    )
    failure_id = hashlib.sha256(
        _canonical_json(
            {
                "gate_id": gate_id,
                "work_unit_id": work_unit_id,
                "affected_identities": identities,
                "evidence": evidence,
            }
        )
    ).hexdigest()
    return {
        "phase": "axis_coverage",
        "work_unit_id": work_unit_id,
        "state": "COMPLETED_WITH_DEBT",
        "assurance_impact": DISCOVERY_RECALL,
        "gate_id": gate_id,
        "gate_class": gate_class,
        "affected_identities": identities,
        "message": message,
        "failure_instance_id": failure_id,
    }


def _axis_population_hint(root: Path) -> tuple[str, list[str], list[str]]:
    """Return non-authoritative diagnostics for a failed replay."""

    path = root / "axis_disposition_worklist.json"
    if not path.is_file():
        return "UNKNOWN", [], []
    try:
        payload = _axis_json(path, label="axis disposition worklist")
    except ValueError:
        return "UNKNOWN", [], []
    status = str(payload.get("denominator_status") or "").strip().upper()
    input_debt = [
        str(value)
        for value in payload.get("input_debt") or []
        if isinstance(value, str) and value
    ]
    identities = [
        str(row.get("work_item_id") or "")
        for row in payload.get("items") or []
        if isinstance(row, dict) and row.get("work_item_id")
    ]
    if status not in {"EXACT", "DEGRADED", "UNKNOWN"}:
        # V1 had no explicit population status. It is exact only when a
        # current typed cap receipt is bound and there is no input debt.
        records = payload.get("source_cap_records") or []
        typed_cap = any(
            isinstance(row, dict)
            and row.get("typed_receipt") == "_hot_function_cap_receipt.json"
            and row.get("receipt_sha256")
            for row in records
        )
        status = "EXACT" if typed_cap and not input_debt else (
            "DEGRADED" if input_debt else "UNKNOWN"
        )
    return status, sorted(set(input_debt)), sorted(set(identities))


def _replay_axis_disposition_authority(
    root: Path,
    *,
    project_root: Path,
    run_id: str,
) -> dict[str, Any]:
    """Replay every schema-v2 application predecessor from current bytes."""

    def required_bytes(name: str) -> bytes:
        try:
            return (root / name).read_bytes()
        except OSError as exc:
            raise ValueError(f"{name} is unavailable: {exc}") from exc

    worklist = axis_authority.load_axis_worklist_v2(
        root / axis_authority.WORKLIST_NAME
    )
    if worklist.get("run_id") != run_id:
        raise ValueError("axis worklist does not belong to the current run")

    matrix_raw = required_bytes(axis_authority.MATRIX_NAME)
    matrix = _axis_json(
        root / axis_authority.MATRIX_NAME,
        label="axis population authority",
    )
    replayed_worklist = axis_authority.compile_axis_worklist_v2(
        matrix,
        matrix_raw=matrix_raw,
        production_root=project_root,
        population_authority=worklist["population_authority"],
        run_id=run_id,
    )
    if replayed_worklist != worklist:
        raise ValueError(
            "axis worklist differs from the current population authority"
        )

    evidence = _axis_json(
        root / axis_authority.AXIS_EXECUTION_EVIDENCE_AUTHORITY_NAME,
        label="axis execution evidence authority",
    )
    axis_authority.validate_axis_execution_evidence_authority(
        evidence,
        expected_run_id=run_id,
    )
    prior_snapshot_binding = _axis_json(
        root / axis_prior_authority.SNAPSHOT_NAME,
        label="axis canonical-prior snapshot",
    )
    prior = axis_prior_authority.load_axis_canonical_prior_authority(
        root,
        expected_run_id=run_id,
        expected_worklist_hash=str(worklist["worklist_hash"]),
        expected_pipeline="sc",
        expected_mode="thorough",
        expected_ecosystem=str(
            prior_snapshot_binding.get("ecosystem") or ""
        ),
    )
    base_dispositions_raw = required_bytes(
        axis_authority.AXIS_MODEL_DISPOSITIONS_NAME
    )
    base_findings_raw = required_bytes(axis_authority.OUTPUT_NAME)
    stored_initial = _axis_json(
        root / axis_authority.AXIS_INITIAL_RECEIPT_NAME,
        label="axis initial disposition receipt",
    )
    stored_plan = _axis_json(
        root / axis_authority.AXIS_REPAIR_PLAN_NAME,
        label="axis repair plan",
    )
    repair_cap = stored_plan.get("repair_cap")
    if type(repair_cap) is not int or repair_cap < 0:
        raise ValueError("axis repair plan has an invalid repair_cap")
    initial, plan = axis_authority.reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=base_dispositions_raw,
        base_findings_raw=base_findings_raw,
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
        repair_cap=repair_cap,
    )
    if stored_initial != initial:
        raise ValueError(
            "axis initial receipt differs from replayed model application"
        )
    if stored_plan != plan:
        raise ValueError(
            "axis repair plan differs from replayed unresolved denominator"
        )

    repair_execution = _axis_json(
        root / axis_authority.AXIS_REPAIR_EXECUTION_RECEIPT_NAME,
        label="axis repair execution receipt",
    )
    repair_dispositions_path = (
        root / axis_authority.AXIS_REPAIR_MODEL_DISPOSITIONS_NAME
    )
    repair_findings_path = root / axis_authority.AXIS_REPAIR_FINDINGS_NAME
    repair_dispositions_raw = (
        repair_dispositions_path.read_bytes()
        if repair_dispositions_path.is_file()
        else None
    )
    repair_findings_raw = (
        repair_findings_path.read_bytes()
        if repair_findings_path.is_file()
        else None
    )
    replayed_receipt = axis_authority.reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair_execution,
        base_findings_raw=base_findings_raw,
        repair_dispositions_raw=repair_dispositions_raw,
        repair_findings_raw=repair_findings_raw,
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
    )
    receipt = axis_authority.load_axis_disposition_v2_receipt(
        root / axis_authority.AXIS_APPLICATION_RECEIPT_NAME,
        worklist=worklist,
    )
    if receipt != replayed_receipt:
        raise ValueError(
            "axis application receipt differs from exact predecessor replay"
        )
    if (
        _axis_json(
            root / axis_authority.REPAIR_NAME,
            label="axis residual repair work",
        )
        != receipt["repair_work"]
        or _axis_json(
            root / axis_authority.ASSURANCE_DEBT_NAME,
            label="axis assurance debt",
        )
        != receipt["assurance_debt"]
    ):
        raise ValueError(
            "axis application debt sidecars differ from the signed receipt"
        )
    axis_authority.validate_axis_disposition_authority_v2(
        receipt,
        worklist,
        production_root=project_root,
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
    )
    return {
        "receipt": receipt,
        "worklist": worklist,
        "repair_execution": repair_execution,
        "base_findings_raw": base_findings_raw,
        "repair_findings_raw": repair_findings_raw or b"",
        "prior": prior,
    }


def _axis_plan_first_assurance_state(
    root: Path,
    *,
    project_root: Path,
    run_id: str,
) -> dict[str, Any] | None:
    """Validate committed delivery before consulting mutable producer ancestors.

    A plan-backed promotion is the durable delivery checkpoint.  It does not
    prove that every earlier methodology-application artifact is still
    replayable, but loss of those mutable ancestors cannot retroactively erase
    a PhaseIO-committed inventory delivery.
    """

    promotion_path = Path(root) / axis_authority.AXIS_PROMOTION_RECEIPT_NAME
    if not promotion_path.is_file():
        return None
    promotion = _axis_json(
        promotion_path,
        label="axis promotion delivery receipt",
    )
    if not promotion.get("plan_digest"):
        return None
    inventory_path = Path(root) / "findings_inventory.md"
    inventory_raw = inventory_path.read_bytes()
    inventory_text = inventory_raw.decode("utf-8", errors="strict")
    plan = _axis_committed_promotion_plan(
        Path(root),
        project_root=Path(project_root),
        run_id=run_id,
        inventory_raw=inventory_raw,
    )
    commit_issues = _axis_committed_promotion_output_issues(
        Path(root),
        project_root=Path(project_root),
        run_id=run_id,
        promotion_plan=plan,
    )
    if commit_issues:
        raise ValueError("; ".join(commit_issues))
    axis_authority.validate_axis_promotion_authority(
        promotion,
        None,
        inventory_text=inventory_text,
        promotion_plan=plan,
        downstream_tail_authorizer=lambda committed_plan, current_raw: (
            authorize_downstream_inventory_tail(
                scratchpad=Path(root),
                project_root=Path(project_root),
                run_id=run_id,
                promotion_plan=committed_plan,
                current_inventory_raw=current_raw,
            )
        ),
    )
    return {
        "plan": plan,
        "promotion": promotion,
    }


def _axis_disposition_assurance_rows(
    scratchpad: Path,
    *,
    project_root: Path,
    run_id: str,
) -> tuple[dict[str, Any], ...]:
    """Project independently replayed v2 application and delivery debt."""

    root = Path(scratchpad)
    if not any((root / name).exists() for name in _AXIS_ACTIVATION_FILES):
        return ()
    try:
        planned = axis_authority.load_axis_worklist_v2(
            root / axis_authority.WORKLIST_NAME
        )
        if (
            planned.get("run_id") == run_id
            and planned.get("clean_empty") is True
            and planned.get("denominator_status") == "EXACT"
            and planned.get("count") == 0
            and planned.get("requires_execution") is False
            and not planned.get("input_debt")
        ):
            matrix_raw = (
                root / axis_authority.MATRIX_NAME
            ).read_bytes()
            replayed_empty = axis_authority.compile_axis_worklist_v2(
                _axis_json(
                    root / axis_authority.MATRIX_NAME,
                    label="axis population authority",
                ),
                matrix_raw=matrix_raw,
                production_root=Path(project_root),
                population_authority=planned["population_authority"],
                run_id=run_id,
            )
            evidence = _axis_json(
                root
                / axis_authority.AXIS_EXECUTION_EVIDENCE_AUTHORITY_NAME,
                label="axis execution evidence authority",
            )
            axis_authority.validate_axis_execution_evidence_authority(
                evidence,
                expected_run_id=run_id,
            )
            unexpected_zero_descendants = tuple(
                name for name in (
                    axis_prior_authority.SNAPSHOT_NAME,
                    axis_prior_authority.AUTHORITY_NAME,
                    axis_authority.OUTPUT_NAME,
                    axis_authority.AXIS_MODEL_DISPOSITIONS_NAME,
                    axis_authority.AXIS_INITIAL_RECEIPT_NAME,
                    axis_authority.AXIS_REPAIR_PLAN_NAME,
                    axis_authority.AXIS_REPAIR_EXECUTION_RECEIPT_NAME,
                    axis_authority.AXIS_APPLICATION_RECEIPT_NAME,
                    axis_authority.REPAIR_NAME,
                    axis_authority.ASSURANCE_DEBT_NAME,
                    axis_authority.AXIS_PROMOTION_RECEIPT_NAME,
                )
                if (root / name).exists()
            )
            if replayed_empty == planned and not unexpected_zero_descendants:
                return ()
    except (
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        # The normal invalid-authority row below retains the exact failure.
        pass
    source_fingerprints = _axis_source_fingerprints(root)
    population_status, population_input_debt, hinted_ids = _axis_population_hint(
        root
    )
    plan_first: dict[str, Any] | None = None
    plan_first_error = ""
    try:
        plan_first = _axis_plan_first_assurance_state(
            root,
            project_root=Path(project_root),
            run_id=run_id,
        )
    except (
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        plan_first_error = f"{type(exc).__name__}: {exc}"
    try:
        replay = _replay_axis_disposition_authority(
            root,
            project_root=Path(project_root),
            run_id=run_id,
        )
    except (
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        if plan_first is not None:
            plan = dict(plan_first["plan"])
            promotion = dict(plan_first["promotion"])
            affected = sorted(
                {
                    *(
                        str(value)
                        for value in plan.get("action_ids") or ()
                        if str(value)
                    ),
                    *(str(value) for value in hinted_ids if str(value)),
                }
            )
            detail = f"{type(exc).__name__}: {exc}"
            rows = [
                _axis_row(
                    (
                        "axis_application_ancestor_unreplayable_after_"
                        "committed_promotion"
                    ),
                    work_unit_id="reconcile.final",
                    affected=affected,
                    message=(
                        "The immutable PhaseIO-committed axis promotion remains "
                        "canonical, but one or more mutable application "
                        "ancestors can no longer be independently replayed. "
                        "Delivery is retained and the ancestor gap requires "
                        f"human review: {detail}"
                    ),
                    evidence={
                        "plan_digest": plan.get("plan_digest"),
                        "promotion_receipt_digest": promotion.get(
                            "promotion_receipt_digest"
                        ),
                        "sources": source_fingerprints,
                        "error": detail,
                    },
                )
            ]
            semantic_issues: list[str] = []
            semantic_ids: set[str] = set()
            if promotion.get("status") != "COMPLETE":
                for field in (
                    "missing_action_ids",
                    "orphan_delivered_action_ids",
                    "conflicting_claim_action_ids",
                ):
                    for value in promotion.get(field) or ():
                        if str(value):
                            semantic_ids.add(str(value))
                for raw in promotion.get("source_debt") or ():
                    if isinstance(raw, dict) and raw.get("action_id"):
                        semantic_ids.add(str(raw["action_id"]))
                semantic_issues = [
                    str(value)
                    for value in (
                        [
                            f"missing action {identity}"
                            for identity in promotion.get(
                                "missing_action_ids"
                            ) or ()
                        ]
                        + [
                            f"orphan action {identity}"
                            for identity in promotion.get(
                                "orphan_delivered_action_ids"
                            ) or ()
                        ]
                        + [
                            f"conflicting claim {identity}"
                            for identity in promotion.get(
                                "conflicting_claim_action_ids"
                            ) or ()
                        ]
                        + [
                            "source debt "
                            f"{str(raw.get('action_id') or '<unknown>')} "
                            f"source={str(raw.get('source') or '<unknown>')} "
                            f"reason={str(raw.get('reason') or '<unknown>')}"
                            for raw in promotion.get("source_debt") or ()
                            if isinstance(raw, dict)
                        ]
                    )
                    if str(value)
                ]
                if not semantic_issues:
                    semantic_issues = [
                        "promotion status is non-COMPLETE without projected debt"
                    ]
            if semantic_issues:
                rows.append(
                    _axis_row(
                        "axis_promotion_delivery_invalid",
                        work_unit_id="promotion",
                        affected=sorted(semantic_ids),
                        message=(
                            "The committed axis promotion retained explicit "
                            "delivery debt: "
                            + "; ".join(semantic_issues)
                        ),
                        evidence={
                            "plan_digest": plan.get("plan_digest"),
                            "promotion_receipt_digest": promotion.get(
                                "promotion_receipt_digest"
                            ),
                            "issues": semantic_issues,
                        },
                    )
                )
            return tuple(rows)
        detail = f"{type(exc).__name__}: {exc}"
        if plan_first_error:
            detail += (
                "; committed promotion preflight also failed: "
                + plan_first_error
            )
        return (
            _axis_row(
                "axis_disposition_authority_invalid",
                work_unit_id="reconcile.final",
                affected=hinted_ids,
                message=(
                    "Exact axis methodology-application authority is missing, "
                    "stale, or cannot be replayed from current sources; "
                    f"population_status={population_status}; {detail}"
                ),
                evidence={
                    "population_status": population_status,
                    "input_debt": population_input_debt,
                    "sources": source_fingerprints,
                    "error": detail,
                },
            ),
        )

    receipt = replay["receipt"]
    worklist = replay["worklist"]
    repair_execution = replay["repair_execution"]
    prior = replay["prior"]
    rows: list[dict[str, Any]] = []
    population_status = str(worklist["denominator_status"])
    population_input_debt = [
        str(value) for value in worklist.get("input_debt") or ()
    ]
    hinted_ids = [
        str(item["work_item_id"]) for item in worklist.get("items") or ()
    ]
    if prior.status == "DEGRADED":
        rows.append(
            _axis_row(
                "axis_canonical_prior_snapshot_degraded",
                work_unit_id="prior.snapshot",
                affected=hinted_ids,
                message=(
                    "The immutable PRE_AXIS canonical-prior capture is "
                    "degraded. Canonical-prior duplicate recognition was "
                    "disabled rather than allowing unsupported CLEAR."
                ),
                evidence={
                    "snapshot_digest": prior.snapshot_digest,
                    "authority_digest": prior.authority_digest,
                    "debt": list(prior.debt),
                },
            )
        )
    if population_status != "EXACT" or population_input_debt:
        rows.append(
            _axis_row(
                "axis_denominator_not_exact",
                work_unit_id="planning",
                affected=hinted_ids,
                message=(
                    "The hot-function x axis denominator is not exact and "
                    "cannot support a clean no-gap claim; "
                    f"population_status={population_status}; input_debt="
                    + ("; ".join(population_input_debt) or "<none recorded>")
                ),
                evidence={
                    "population_status": population_status,
                    "input_debt": population_input_debt,
                    "worklist_hash": worklist.get("worklist_hash"),
                },
            )
        )

    assurance = receipt.get("assurance_debt")
    assurance_items = (
        assurance.get("items") if isinstance(assurance, dict) else []
    )
    for item in assurance_items or []:
        if not isinstance(item, dict):
            continue
        debt_kind = str(item.get("debt_kind") or "")
        identity = str(item.get("work_item_id") or "")
        if debt_kind == "UNRESOLVED_WORK_ITEM":
            rows.append(
                _axis_row(
                    "axis_disposition_unresolved",
                    work_unit_id=identity or "reconcile.final",
                    affected=[identity] if identity else [],
                    message=(
                        "An exact hot-function x axis obligation remains "
                        "unresolved after final reconciliation and requires "
                        f"human review: {item.get('message')}"
                    ),
                    evidence={
                        "debt_digest": item.get("debt_digest"),
                        "application_receipt_digest": receipt.get(
                            "application_receipt_digest"
                        ),
                    },
                )
            )
        elif debt_kind == "RECONCILIATION_ISSUE":
            rows.append(
                _axis_row(
                    "axis_application_reconciliation_debt",
                    work_unit_id=identity or "reconcile.final",
                    affected=[identity] if identity else hinted_ids,
                    message=(
                        "Axis disposition reconciliation retained exact "
                        f"application debt: {item.get('message')}"
                    ),
                    evidence={
                        "debt_digest": item.get("debt_digest"),
                        "application_receipt_digest": receipt.get(
                            "application_receipt_digest"
                        ),
                    },
                )
            )

    repair_state = str(repair_execution.get("state") or "")
    if repair_state == "FAILED":
        rows.append(
            _axis_row(
                "axis_repair_execution_failed",
                work_unit_id="repair.worker.0001",
                affected=receipt.get("residual_work_item_ids") or hinted_ids,
                message=(
                    "The bounded axis repair execution failed; residual "
                    "obligations remain discovery-recall debt."
                ),
                evidence=repair_execution,
            )
        )
    elif repair_state == "OVERFLOW":
        rows.append(
            _axis_row(
                "axis_repair_overflow",
                work_unit_id="repair.worker.0001",
                affected=receipt.get("residual_work_item_ids") or hinted_ids,
                message=(
                    "The bounded axis repair denominator overflowed; residual "
                    "obligations remain discovery-recall debt."
                ),
                evidence=repair_execution,
            )
        )

    dispositions = receipt.get("dispositions")
    expected_actions = sorted(
        {
            str(item.get("action_id") or "")
            for item in dispositions or []
            if isinstance(item, dict)
            and item.get("application_record_complete") is True
            and item.get("disposition") in {"FINDING", "UNRESOLVED"}
            and item.get("action_id")
        }
    )
    promotion_path = root / axis_authority.AXIS_PROMOTION_RECEIPT_NAME
    promotion_error = ""
    promotion_issues: list[str] = []
    promotion_issue_ids: set[str] = set()
    if not promotion_path.is_file():
        promotion_error = "typed promotion delivery receipt is missing"
    else:
        try:
            promotion = _axis_json(
                promotion_path,
                label="axis promotion delivery receipt",
            )
            inventory_path = root / "findings_inventory.md"
            inventory_raw = (
                inventory_path.read_bytes()
                if inventory_path.is_file()
                else b""
            )
            inventory_text = inventory_raw.decode(
                "utf-8", errors="strict"
            )
            if promotion.get("plan_digest"):
                promotion_plan = _axis_committed_promotion_plan(
                    root,
                    project_root=Path(project_root),
                    run_id=run_id,
                    inventory_raw=inventory_raw,
                )
                promotion_commit_issues = (
                    _axis_committed_promotion_output_issues(
                        root,
                        project_root=Path(project_root),
                        run_id=run_id,
                        promotion_plan=promotion_plan,
                    )
                )
                if promotion_commit_issues:
                    raise ValueError("; ".join(promotion_commit_issues))
                axis_authority.validate_axis_promotion_authority(
                    promotion,
                    None,
                    inventory_text=inventory_text,
                    promotion_plan=promotion_plan,
                    downstream_tail_authorizer=(
                        lambda committed_plan, current_raw: (
                            authorize_downstream_inventory_tail(
                                scratchpad=root,
                                project_root=Path(project_root),
                                run_id=run_id,
                                promotion_plan=committed_plan,
                                current_inventory_raw=current_raw,
                            )
                        )
                    ),
                )
            else:
                # Explicit legacy receipts predate immutable promotion plans.
                # They retain their source-derived replay path; no plan-backed
                # receipt may silently fall through to this compatibility arm.
                promotion_commit_issues = (
                    _axis_committed_promotion_output_issues(
                        root,
                        project_root=Path(project_root),
                        run_id=run_id,
                    )
                )
                if promotion_commit_issues:
                    raise ValueError("; ".join(promotion_commit_issues))
                legacy_inventory_text = inventory_path.read_text(
                    encoding="utf-8", errors="strict"
                )
                axis_authority.validate_axis_promotion_authority(
                    promotion,
                    receipt,
                    base_findings_raw=replay["base_findings_raw"],
                    repair_findings_raw=replay["repair_findings_raw"],
                    inventory_text=legacy_inventory_text,
                )
            if promotion.get("status") != "COMPLETE":
                for field, label in (
                    ("missing_action_ids", "missing action"),
                    ("orphan_delivered_action_ids", "orphan action"),
                    (
                        "conflicting_claim_action_ids",
                        "conflicting claim",
                    ),
                ):
                    for value in promotion.get(field, ()):
                        identity = str(value)
                        if not identity:
                            continue
                        promotion_issue_ids.add(identity)
                        promotion_issues.append(
                            f"{label} {identity}"
                        )
                for raw in promotion.get("source_debt", ()):
                    if not isinstance(raw, dict):
                        promotion_issues.append(
                            "malformed promotion source-debt row"
                        )
                        continue
                    identity = str(raw.get("action_id") or "")
                    if identity:
                        promotion_issue_ids.add(identity)
                    promotion_issues.append(
                        "source debt "
                        f"{identity or '<unknown>'} "
                        f"source={str(raw.get('source') or '<unknown>')} "
                        f"reason={str(raw.get('reason') or '<unknown>')}"
                    )
                if not promotion_issues:
                    promotion_issues.append(
                        "non-COMPLETE promotion has no projected debt"
                    )
        except (
            KeyError,
            OSError,
            RuntimeError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            promotion_error = f"{type(exc).__name__}: {exc}"
    if promotion_error or promotion_issues:
        rows.append(
            _axis_row(
                "axis_promotion_delivery_invalid",
                work_unit_id="promotion",
                affected=(
                    sorted(promotion_issue_ids)
                    if promotion_issue_ids
                    else expected_actions
                ),
                message=(
                    "Valid axis actions lack replayable exact inventory "
                    "delivery authority; the actions remain recoverable and "
                    "must not be erased. "
                    + "; ".join(
                        value
                        for value in (promotion_error, *promotion_issues)
                        if value
                    )
                ),
                evidence={
                    "expected_action_ids": expected_actions,
                    "promotion_issues": promotion_issues,
                    "promotion_receipt_sha256": source_fingerprints.get(
                        promotion_path.name
                    ),
                },
                gate_class="DELIVERY_AUTHORITY",
            )
        )
    return tuple(rows)


def _toolchain_coverage_assurance_rows(
    scratchpad: Path,
) -> tuple[dict[str, Any], ...]:
    """Replay the tool ledger and require its exact unresolved-debt projection."""

    root = Path(scratchpad)
    path = root / "toolchain_coverage_debt.json"
    ledger_path = root / "tool_coverage_ledger.json"
    if not os.path.lexists(path) and not os.path.lexists(ledger_path):
        return ()
    try:
        if not os.path.lexists(ledger_path):
            raise ValueError("tool coverage ledger is absent")
        if ledger_path.is_symlink() or path.is_symlink():
            raise ValueError("tool coverage authority contains a symlink")
        ledger = _axis_json(ledger_path, label="tool coverage ledger")
        if set(ledger) != {
            "schema",
            "schema_version",
            "capabilities",
            "ledger_sha256",
        }:
            raise ValueError("tool coverage ledger fields drifted")
        if (
            ledger.get("schema") != "plamen.tool-coverage-ledger"
            or ledger.get("schema_version") != 1
            or not isinstance(ledger.get("capabilities"), dict)
        ):
            raise ValueError("tool coverage ledger schema drifted")
        unsigned_ledger = {
            key: value for key, value in ledger.items()
            if key != "ledger_sha256"
        }
        if ledger.get("ledger_sha256") != hashlib.sha256(
            _canonical_json(unsigned_ledger)
        ).hexdigest():
            raise ValueError("tool coverage ledger digest mismatch")

        derived_rows: list[dict[str, Any]] = []
        record_fields = {
            "capability_id",
            "tool",
            "state",
            "reason",
            "finding_count",
            "schema_validated",
            "artifacts",
            "provider_ref",
        }
        for capability_key in sorted(ledger["capabilities"]):
            raw = ledger["capabilities"][capability_key]
            if not isinstance(raw, dict) or set(raw) != record_fields:
                raise ValueError("tool coverage outcome fields drifted")
            capability = raw.get("capability_id")
            tool = raw.get("tool")
            state = raw.get("state")
            reason = raw.get("reason")
            provider_ref = raw.get("provider_ref")
            artifacts = raw.get("artifacts")
            if (
                capability != capability_key
                or not isinstance(capability, str)
                or re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", capability)
                is None
                or not isinstance(tool, str)
                or not tool.strip()
                or state not in {"SUCCEEDED", "SKIPPED", "UNAVAILABLE", "FAILED"}
                or not isinstance(reason, str)
                or not reason.strip()
                or not isinstance(raw.get("schema_validated"), bool)
                or not isinstance(artifacts, list)
                or not all(isinstance(item, str) and item for item in artifacts)
                or not isinstance(provider_ref, str)
            ):
                raise ValueError("tool coverage outcome is malformed")
            if state == "SUCCEEDED":
                finding_count = raw.get("finding_count")
                if (
                    isinstance(finding_count, bool)
                    or not isinstance(finding_count, int)
                    or finding_count < 0
                    or raw["schema_validated"] is not True
                ):
                    raise ValueError("tool success outcome is deceptive")
            elif raw.get("finding_count") is not None:
                raise ValueError("tool debt outcome claims a finding count")
            if state != "SUCCEEDED":
                derived_rows.append(
                    {
                        "capability_id": capability,
                        "tool": tool,
                        "state": state,
                        "reason": reason,
                        "provider_ref_sha256": (
                            hashlib.sha256(provider_ref.encode("utf-8")).hexdigest()
                            if provider_ref else None
                        ),
                    }
                )

        if not derived_rows:
            if os.path.lexists(path):
                raise ValueError("stale toolchain debt exists for a clean ledger")
            return ()
        if not os.path.lexists(path):
            raise ValueError("unresolved tool outcomes lack delivered debt")
        payload = _axis_json(path, label="toolchain coverage debt")
        expected = {
            "schema_version",
            "phase",
            "unresolved_count",
            "rows",
            "debt_sha256",
        }
        unsigned = {
            key: value for key, value in payload.items()
            if key != "debt_sha256"
        }
        rows = payload.get("rows")
        if (
            not isinstance(payload, dict)
            or set(payload) != expected
            or payload.get("schema_version")
            != "plamen.toolchain-coverage-debt.v1"
            or not isinstance(rows, list)
            or payload.get("unresolved_count") != len(rows)
            or payload.get("debt_sha256")
            != hashlib.sha256(_canonical_json(unsigned)).hexdigest()
            or rows != derived_rows
        ):
            raise ValueError("toolchain coverage debt schema drifted")
        phase = str(payload.get("phase") or "breadth")
        provenance = {
            "schema_version": "plamen.toolchain_coverage_assurance_source.v1",
            "ledger": {
                "path": ledger_path.name,
                "full_file_sha256": hashlib.sha256(
                    ledger_path.read_bytes()
                ).hexdigest(),
                "document_sha256": ledger["ledger_sha256"],
            },
            "debt": {
                "path": path.name,
                "full_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "document_sha256": payload["debt_sha256"],
            },
        }
        projected: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, dict):
                raise ValueError("toolchain coverage debt row is malformed")
            capability = str(raw.get("capability_id") or "")
            state = str(raw.get("state") or "")
            reason = str(raw.get("reason") or "")
            tool = str(raw.get("tool") or "")
            if not capability or not state or not reason or not tool:
                raise ValueError("toolchain coverage debt row is incomplete")
            failure_id = hashlib.sha256(
                _canonical_json(
                    {
                        "phase": phase,
                        "capability_id": capability,
                        "tool": tool,
                        "state": state,
                        "reason": reason,
                        "debt_sha256": payload["debt_sha256"],
                        "ledger_sha256": ledger["ledger_sha256"],
                    }
                )
            ).hexdigest()
            projected.append(
                {
                    "phase": phase,
                    "work_unit_id": "toolchain-coverage",
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": classify_assurance_impact(phase),
                    "gate_id": f"toolchain.{capability}",
                    "gate_class": "TOOLCHAIN_COVERAGE",
                    "affected_identities": [capability],
                    "message": (
                        f"{tool} capability is {state}; its mechanical "
                        f"coverage remains unresolved. {reason}"
                    ),
                    "failure_instance_id": failure_id,
                    "source_authority": provenance,
                }
            )
        return tuple(projected)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        fingerprints = _program_facts_file_fingerprints(
            root,
            ("tool_coverage_ledger.json", "toolchain_coverage_debt.json"),
        )
        failure_id = hashlib.sha256(
            _canonical_json(
                {
                    "error": f"{type(exc).__name__}:{exc}",
                    "files": fingerprints,
                }
            )
        ).hexdigest()
        return (
            {
                "phase": "breadth",
                "work_unit_id": "toolchain-coverage",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": classify_assurance_impact("breadth"),
                "gate_id": "toolchain.coverage-ledger-replay",
                "gate_class": "TOOLCHAIN_COVERAGE",
                "affected_identities": ["toolchain-coverage-ledger"],
                "message": (
                    "Toolchain coverage debt could not be replayed; clean "
                    "mechanical coverage is not authorized. "
                    f"{type(exc).__name__}: {exc}"
                ),
                "failure_instance_id": failure_id,
                "source_authority": {
                    "schema_version": (
                        "plamen.toolchain_coverage_assurance_source.v1"
                    ),
                    "files": fingerprints,
                },
            },
        )


def _program_facts_file_fingerprints(
    root: Path,
    names: tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    """Return stable diagnostics without treating a candidate digest as trust."""

    result: dict[str, dict[str, Any]] = {}
    for name in names:
        path = Path(root) / name
        if not os.path.lexists(path):
            result[name] = {"state": "ABSENT"}
            continue
        if path.is_symlink():
            result[name] = {"state": "SYMLINK_REJECTED"}
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            result[name] = {
                "state": "UNREADABLE",
                "error": f"{type(exc).__name__}: {exc}",
            }
            continue
        result[name] = {
            "state": "PRESENT",
            "size": len(raw),
            "full_file_sha256": hashlib.sha256(raw).hexdigest(),
        }
    return result


def _read_program_facts_json(root: Path, name: str) -> tuple[dict[str, Any], bytes]:
    path = Path(root) / name
    if path.is_symlink():
        raise ValueError(f"{name} is a symlink")
    raw = path.read_bytes()
    value = strict_json_loads(
        raw,
        require_final_lf=True,
        require_canonical=True,
    )
    if type(value) is not dict:
        raise ValueError(f"{name} must contain one canonical object")
    return value, raw


def _program_facts_invalid_row(
    *,
    gate_id: str,
    message: str,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    normalized_evidence = json.loads(_canonical_json(dict(evidence)))
    failure_id = hashlib.sha256(
        _canonical_json(
            {
                "gate_id": gate_id,
                "message": message,
                "evidence": normalized_evidence,
            }
        )
    ).hexdigest()
    return {
        "phase": "recon",
        "work_unit_id": "program_facts_bake",
        "state": "COMPLETED_WITH_DEBT",
        "assurance_impact": DISCOVERY_RECALL,
        "gate_id": gate_id,
        "gate_class": "PROGRAM_FACTS_AUTHORITY",
        "affected_identities": ["program-facts"],
        "message": message,
        "failure_instance_id": failure_id,
        "source_authority": normalized_evidence,
    }


def _validate_program_facts_v1_projection_bundle(
    root: Path,
    *,
    run_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Replay the v1 public trio deeply enough to authorize debt projection.

    This is not Program Facts production/reuse authority.  The production
    loader additionally replays source bytes, the ArtifactLedger and PhaseIO.
    Here we independently prove that the exact public files are canonical,
    self-digested, mutually bound, and unable to conceal non-full coverage.
    """

    payload, payload_raw = _read_program_facts_json(
        root, _PROGRAM_FACTS_V1_FILES[0]
    )
    receipt, receipt_raw = _read_program_facts_json(
        root, _PROGRAM_FACTS_V1_FILES[1]
    )
    debt, debt_raw = _read_program_facts_json(root, _PROGRAM_FACTS_V1_FILES[2])

    payload = validate_program_facts_payload_shape(payload)
    debt = validate_program_facts_debt(debt)
    receipt = validate_program_facts_receipt(receipt)
    if receipt["run_id"] != run_id:
        raise ValueError("Program Facts receipt belongs to another run")
    if (
        payload["snapshot_ref"]["snapshot_digest"] != debt["snapshot_digest"]
        or payload["snapshot_ref"]["source_manifest_digest"]
        != debt["source_manifest_digest"]
        or receipt["audit_snapshot"]["snapshot_digest"]
        != payload["snapshot_ref"]["snapshot_digest"]
        or receipt["audit_snapshot"]["source_scope_digest"]
        != payload["snapshot_ref"]["source_scope_digest"]
        or receipt["source_manifest"]["manifest_digest"]
        != payload["snapshot_ref"]["source_manifest_digest"]
        or receipt["source_manifest"]["eligible_files"]
        != payload["source_files"]
    ):
        raise ValueError("Program Facts bundle parent identities diverge")

    artifact_inputs = {
        "facts": (
            _PROGRAM_FACTS_V1_FILES[0],
            payload["payload_sha256"],
            payload_raw,
        ),
        "debt": (
            _PROGRAM_FACTS_V1_FILES[2],
            debt["debt_sha256"],
            debt_raw,
        ),
    }
    for kind, (name, document_sha256, raw) in artifact_inputs.items():
        binding = receipt["artifacts"][kind]
        if (
            binding["path"] != name
            or binding["document_sha256"] != document_sha256
            or binding["file_sha256"] != hashlib.sha256(raw).hexdigest()
            or binding["size"] != len(raw)
        ):
            raise ValueError(f"Program Facts {kind} artifact binding mismatch")

    debt_by_id = {row["debt_id"]: row for row in debt["debts"]}
    referenced: set[str] = set()
    for coverage in payload["coverage"]:
        unresolved = set(coverage["unresolved_debt_ids"])
        if not unresolved <= set(debt_by_id):
            raise ValueError("Program Facts coverage has dangling debt")
        for debt_id in unresolved:
            row = debt_by_id[debt_id]
            if row["capability_id"] and row["capability_id"] != coverage[
                "capability_id"
            ]:
                raise ValueError("Program Facts coverage/debt capability mismatch")
            if row["build_variant_id"] and row["build_variant_id"] != coverage[
                "build_variant_id"
            ]:
                raise ValueError("Program Facts coverage/debt build mismatch")
        referenced.update(unresolved)
    for excluded in receipt["source_manifest"]["excluded_files"]:
        matches = [
            row["debt_id"]
            for row in debt["debts"]
            if row["reason"] == "SOURCE_EXCLUDED"
            and excluded["identity"] in row["scope_ids"]
        ]
        if len(matches) != 1:
            raise ValueError(
                "Program Facts source exclusion lacks exact debt authority"
            )
        referenced.add(matches[0])
    if referenced != set(debt_by_id):
        raise ValueError("Program Facts debt accounting is not total")

    status = receipt["status"]
    coverage_states = {row["status"] for row in payload["coverage"]}
    has_debt = bool(debt_by_id)
    if status in {"WRITTEN", "REUSED"}:
        if coverage_states - {"FULL"} or has_debt:
            raise ValueError("successful Program Facts receipt conceals debt")
    elif status == "DEGRADED":
        if not has_debt:
            raise ValueError("degraded Program Facts receipt has no debt")
    elif status == "UNAVAILABLE":
        if (
            payload["nodes"]
            or payload["occurrences"]
            or payload["facts"]
            or not has_debt
            or (coverage_states and not coverage_states <= {"UNSUPPORTED", "UNKNOWN"})
        ):
            raise ValueError("unavailable Program Facts receipt is deceptive")
    elif status == "FAILED":
        if payload["nodes"] or payload["occurrences"] or payload["facts"] or not has_debt:
            raise ValueError("failed Program Facts receipt is deceptive")
    elif status == "STALE":
        if not any(
            row["reason"] == "STALE_SNAPSHOT" and row["blocks_reuse"]
            for row in debt["debts"]
        ):
            raise ValueError("stale Program Facts receipt omits blocking debt")
    if receipt["reuse_key"] != derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    ):
        raise ValueError("Program Facts receipt reuse key mismatch")

    provenance = {
        "schema_version": "plamen.program_facts_assurance_source.v1",
        "public_version": 1,
        "status": status,
        "payload": {
            "path": _PROGRAM_FACTS_V1_FILES[0],
            "full_file_sha256": hashlib.sha256(payload_raw).hexdigest(),
            "document_sha256": payload["payload_sha256"],
        },
        "receipt": {
            "path": _PROGRAM_FACTS_V1_FILES[1],
            "full_file_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "document_sha256": receipt["receipt_sha256"],
        },
        "debt": {
            "path": _PROGRAM_FACTS_V1_FILES[2],
            "full_file_sha256": hashlib.sha256(debt_raw).hexdigest(),
            "document_sha256": debt["debt_sha256"],
        },
        "snapshot_digest": debt["snapshot_digest"],
        "source_manifest_digest": debt["source_manifest_digest"],
        "phase_io": dict(receipt["phase_io"]),
    }
    return payload, receipt, debt, provenance


def _program_facts_v1_assurance_rows(
    root: Path,
    *,
    run_id: str,
) -> tuple[dict[str, Any], ...]:
    try:
        _payload, receipt, debt, provenance = (
            _validate_program_facts_v1_projection_bundle(root, run_id=run_id)
        )
    except (
        KeyError,
        OSError,
        ProgramFactsTypeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        fingerprints = _program_facts_file_fingerprints(
            root, _PROGRAM_FACTS_V1_FILES
        )
        return (
            _program_facts_invalid_row(
                gate_id="program_facts.v1-authority-replay",
                message=(
                    "Program Facts v1 authority is missing, stale, tampered, or "
                    "internally inconsistent; no clean graph/fact coverage is "
                    f"authorized. {type(exc).__name__}: {exc}"
                ),
                evidence={
                    "public_version": 1,
                    "files": fingerprints,
                    "run_id": run_id,
                },
            ),
        )

    projected: list[dict[str, Any]] = []
    for raw in debt["debts"]:
        affected = sorted(
            {
                raw["debt_id"],
                *raw["scope_ids"],
                raw["provider_id"],
                raw["capability_id"],
                raw["build_variant_id"],
            }
            - {""}
        )
        source_authority = {
            **provenance,
            "debt_id": raw["debt_id"],
            "evidence_refs": list(raw["evidence_refs"]),
        }
        failure_id = hashlib.sha256(
            _canonical_json(
                {
                    "source_authority": source_authority,
                    "debt_row": raw,
                }
            )
        ).hexdigest()
        projected.append(
            {
                "phase": "recon",
                "work_unit_id": "program_facts_bake",
                "state": "COMPLETED_WITH_DEBT",
                "assurance_impact": DISCOVERY_RECALL,
                "gate_id": f"program_facts.{raw['reason'].casefold()}",
                "gate_class": "PROGRAM_FACTS_COVERAGE",
                "affected_identities": affected,
                "message": (
                    f"Program Facts {receipt['status']} debt {raw['reason']}: "
                    f"{str(raw['explanation']).strip()} No negative inference "
                    "or clean graph-coverage claim is authorized."
                ),
                "failure_instance_id": failure_id,
                "source_authority": source_authority,
            }
        )
    return tuple(projected)


def _program_facts_runtime_assurance_rows(
    root: Path,
    *,
    run_id: str,
    checkpoint_runtime_debts: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    path = Path(root) / _PROGRAM_FACTS_RUNTIME_DEBT_FILE
    expected = checkpoint_runtime_debts.get(_PROGRAM_FACTS_RUNTIME_DEBT_ID)
    present = os.path.lexists(path)
    if expected is None and not present:
        return ()
    evidence: dict[str, Any] = {
        "schema_version": "plamen.program_facts_runtime_assurance_source.v1",
        "path": _PROGRAM_FACTS_RUNTIME_DEBT_FILE,
        "checkpoint_debt_id": _PROGRAM_FACTS_RUNTIME_DEBT_ID,
        "checkpoint_receipt_sha256": expected,
    }
    try:
        if expected is not None and (
            not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        ):
            raise ValueError(
                "legacy checkpoint runtime-debt binding is malformed"
            )
        payload, raw = _read_program_facts_json(
            root, _PROGRAM_FACTS_RUNTIME_DEBT_FILE
        )
        evidence.update(
            {
                "full_file_sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        )
        if (
            expected is not None
            and hashlib.sha256(raw).hexdigest() != expected
        ):
            raise ValueError(
                "runtime diagnostic bytes differ from legacy checkpoint binding"
            )
        if set(payload) != {
            "schema_version",
            "run_id",
            "debt_id",
            "issue",
            "consumer_activation",
        }:
            raise ValueError("runtime-debt fields are not exact")
        if (
            payload["schema_version"]
            != "plamen.program_facts_stage2_runtime_debt.v1"
            or payload["run_id"] != run_id
            or payload["debt_id"] != _PROGRAM_FACTS_RUNTIME_DEBT_ID
            or not isinstance(payload["issue"], str)
            or not payload["issue"].strip()
            or payload["consumer_activation"] is not False
        ):
            raise ValueError("runtime-debt authority does not match this run")
    except (
        KeyError,
        OSError,
        ProgramFactsTypeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        evidence["files"] = _program_facts_file_fingerprints(
            root, (_PROGRAM_FACTS_RUNTIME_DEBT_FILE,)
        )
        return (
            _program_facts_invalid_row(
                gate_id="program_facts.runtime-debt-replay",
                message=(
                    "Program Facts runtime debt is missing, stale, or tampered; "
                    "consumer activation and clean fact coverage remain denied. "
                    f"{type(exc).__name__}: {exc}"
                ),
                evidence=evidence,
            ),
        )
    failure_id = hashlib.sha256(
        _canonical_json({"source_authority": evidence, "payload": payload})
    ).hexdigest()
    return (
        {
            "phase": "recon",
            "work_unit_id": "program_facts_stage2_runtime",
            "state": "COMPLETED_WITH_DEBT",
            "assurance_impact": DISCOVERY_RECALL,
            "gate_id": "program_facts.stage2-runtime",
            "gate_class": "PROGRAM_FACTS_RUNTIME",
            "affected_identities": [_PROGRAM_FACTS_RUNTIME_DEBT_ID],
            "message": (
                "Program Facts runtime failed before a valid emit-only "
                f"publication; consumer activation remains denied. {payload['issue']}"
            ),
            "failure_instance_id": failure_id,
            "source_authority": evidence,
        },
    )


def _program_facts_assurance_rows(
    scratchpad: Path,
    *,
    run_id: str,
    checkpoint_runtime_debts: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    root = Path(scratchpad)
    v1_present = {
        name for name in _PROGRAM_FACTS_V1_FILES
        if os.path.lexists(root / name)
    }
    v2_present = {
        name for name in _PROGRAM_FACTS_V2_FILES
        if os.path.lexists(root / name)
    }
    activated = bool(
        v1_present
        or v2_present
        or any(os.path.lexists(root / name) for name in _PROGRAM_FACTS_ACTIVATION_SENTINELS)
        or os.path.lexists(root / _PROGRAM_FACTS_RUNTIME_DEBT_FILE)
        or _PROGRAM_FACTS_RUNTIME_DEBT_ID in checkpoint_runtime_debts
    )
    if not activated:
        return ()
    rows: list[dict[str, Any]] = []
    if v1_present and v2_present:
        rows.append(
            _program_facts_invalid_row(
                gate_id="program_facts.public-version-ambiguity",
                message=(
                    "Program Facts v1 and v2 public bundles coexist; no active "
                    "generation or clean coverage claim is authorized."
                ),
                evidence={
                    "v1_files": _program_facts_file_fingerprints(
                        root, _PROGRAM_FACTS_V1_FILES
                    ),
                    "v2_files": _program_facts_file_fingerprints(
                        root, _PROGRAM_FACTS_V2_FILES
                    ),
                    "run_id": run_id,
                },
            )
        )
    elif v1_present:
        rows.extend(_program_facts_v1_assurance_rows(root, run_id=run_id))
    elif v2_present:
        rows.append(
            _program_facts_invalid_row(
                gate_id="program_facts.v2-assurance-replay-unavailable",
                message=(
                    "Program Facts v2 public bytes exist without the frozen "
                    "assurance replay adapter; clean coverage is denied."
                ),
                evidence={
                    "public_version": 2,
                    "files": _program_facts_file_fingerprints(
                        root, _PROGRAM_FACTS_V2_FILES
                    ),
                    "run_id": run_id,
                },
            )
        )
    elif not os.path.lexists(root / _PROGRAM_FACTS_RUNTIME_DEBT_FILE):
        rows.append(
            _program_facts_invalid_row(
                gate_id="program_facts.public-bundle-missing",
                message=(
                    "Program Facts was activated but its exact public bundle "
                    "is absent; clean graph/fact coverage is denied."
                ),
                evidence={
                    "activation_sentinels": _program_facts_file_fingerprints(
                        root, _PROGRAM_FACTS_ACTIVATION_SENTINELS
                    ),
                    "run_id": run_id,
                },
            )
        )
    rows.extend(
        _program_facts_runtime_assurance_rows(
            root,
            run_id=run_id,
            checkpoint_runtime_debts=checkpoint_runtime_debts,
        )
    )
    return _shadow_diagnostic_rows(
        rows,
        consumer_activation=PROGRAM_FACTS_CONSUMER_ACTIVATION,
        subsystem="Program Facts",
    )


def _read_graph_application_identity(
    root: Path,
    identity: object,
) -> tuple[str, bytes]:
    """Read one scratchpad identity without following an injected symlink."""

    text = str(identity or "")
    if not text.startswith("scratchpad:"):
        raise ValueError("graph application identity is not scratchpad-rooted")
    relative = text.split(":", 1)[1].replace("\\", "/")
    path = Path(relative)
    if (
        not relative
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("graph application identity is not a safe relative path")
    candidate = Path(root) / path
    current = Path(root)
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"graph application source is a symlink: {relative}")
    if not candidate.is_file():
        raise ValueError(f"graph application source is absent: {relative}")
    raw = candidate.read_bytes()
    if not raw or len(raw) > 64 * 1024 * 1024:
        raise ValueError(f"graph application source size is invalid: {relative}")
    return relative, raw


def _graph_application_file_fingerprints(
    root: Path,
) -> dict[str, dict[str, Any]]:
    contract = graph_application_integration_contract()
    identities = [
        *_GRAPH_APPLICATION_FILES,
        *(
            str(value).split(":", 1)[1]
            for value in contract["required_parent_artifacts"]
        ),
        *(
            str(value).split(":", 1)[1]
            for value in contract["optional_parent_artifacts"]
        ),
    ]
    return _program_facts_file_fingerprints(root, tuple(identities))


def _graph_application_invalid_row(
    root: Path,
    *,
    run_id: str,
    exc: BaseException,
) -> dict[str, Any]:
    evidence = {
        "schema_version": "plamen.graph_application_assurance_source.v1",
        "run_id": run_id,
        "files": _graph_application_file_fingerprints(root),
        "error": f"{type(exc).__name__}: {exc}",
    }
    failure_id = hashlib.sha256(_canonical_json(evidence)).hexdigest()
    return {
        "phase": "chain",
        "work_unit_id": "graph_application_reconciliation",
        "state": "COMPLETED_WITH_DEBT",
        "assurance_impact": DISCOVERY_RECALL,
        "gate_id": "graph_application.authority-replay",
        "gate_class": "GRAPH_APPLICATION_AUTHORITY",
        "affected_identities": ["graph-application-authority"],
        "message": (
            "Graph availability/application authority is missing, stale, "
            "tampered, or internally inconsistent; no clean graph-consumption "
            f"claim is authorized. {type(exc).__name__}: {exc}"
        ),
        "failure_instance_id": failure_id,
        "source_authority": evidence,
    }


def _graph_application_assurance_rows(
    scratchpad: Path,
    *,
    run_id: str,
) -> tuple[dict[str, Any], ...]:
    """Replay graph application and surface every exact reconciliation debt."""

    root = Path(scratchpad)
    contract = graph_application_integration_contract()
    consumer_activation = contract.get("consumer_activation") is True

    def finish(rows: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
        return _shadow_diagnostic_rows(
            rows,
            consumer_activation=consumer_activation,
            subsystem="Graph application",
        )
    required_identities = tuple(contract["required_parent_artifacts"])
    required_names = tuple(
        str(identity).split(":", 1)[1] for identity in required_identities
    )
    control_present = {
        name for name in _GRAPH_APPLICATION_FILES if os.path.lexists(root / name)
    }
    # The shared workspace is also a Program Facts sentinel and is not by
    # itself evidence that graph production started.  Any graph/handoff input,
    # however, activates the trio requirement so a partial producer failure
    # cannot disappear from the final report.
    source_activated = any(
        os.path.lexists(root / name)
        for name in required_names
        if name != "evm_analysis_workspace_receipt.v1.json"
    )
    if not control_present and not source_activated:
        return ()

    try:
        if control_present != set(_GRAPH_APPLICATION_FILES):
            raise ValueError("graph application control trio is partial or absent")
        control_raw: dict[str, bytes] = {}
        for name in _GRAPH_APPLICATION_FILES:
            path = root / name
            if path.is_symlink():
                raise ValueError(f"graph application control is a symlink: {name}")
            control_raw[name] = path.read_bytes()

        authority = load_graph_application_authority_bytes(
            control_raw[GRAPH_APPLICATION_AUTHORITY_FILE],
            expected_run_id=run_id,
        )

        roster_binding = authority["consumer_roster"]
        provider_manifest = authority["graph_generation"]["provider_manifest"]
        if provider_manifest["state"] != "BOUND":
            raise ValueError(
                "graph provider-generation artifact is not committed/bound"
            )
        source_bindings = {
            roster_binding["artifact_identity"]:
                roster_binding["artifact_sha256"],
            roster_binding["scheduler_artifact_identity"]:
                roster_binding["scheduler_artifact_sha256"],
            authority["workspace"]["artifact_identity"]:
                authority["workspace"]["artifact_sha256"],
            authority["graph_generation"]["mechanical_graph"]["artifact_identity"]:
                authority["graph_generation"]["mechanical_graph"]["artifact_sha256"],
            authority["graph_generation"]["depth_handoff"]["artifact_identity"]:
                authority["graph_generation"]["depth_handoff"]["artifact_sha256"],
            authority["graph_generation"]["depth_handoff"][
                "depth_candidates_artifact_identity"
            ]: authority["graph_generation"]["depth_handoff"][
                "depth_candidates_sha256"
            ],
            provider_manifest["artifact_identity"]:
                provider_manifest["artifact_sha256"],
        }
        if set(source_bindings) != set(required_identities):
            raise ValueError("graph application required-parent roster differs")
        source_provenance: list[dict[str, Any]] = []
        for identity in sorted(source_bindings):
            relative, raw = _read_graph_application_identity(root, identity)
            digest = hashlib.sha256(raw).hexdigest()
            if digest != source_bindings[identity]:
                raise ValueError(f"graph application source bytes changed: {relative}")
            source_provenance.append(
                {
                    "artifact_identity": identity,
                    "artifact_sha256": digest,
                    "size": len(raw),
                }
            )

        observations = load_graph_application_observations_bytes(
            control_raw[GRAPH_APPLICATION_OBSERVATIONS_FILE],
            authority=authority,
        )
        evidence_sha256: dict[str, str] = {}
        evidence_provenance: list[dict[str, Any]] = []
        for binding in observations["evidence_artifacts"]:
            identity = binding["artifact_identity"]
            relative, raw = _read_graph_application_identity(root, identity)
            digest = hashlib.sha256(raw).hexdigest()
            if digest != binding["artifact_sha256"]:
                raise ValueError(f"graph observation evidence changed: {relative}")
            evidence_sha256[identity] = digest
            evidence_provenance.append(
                {
                    "artifact_identity": identity,
                    "artifact_sha256": digest,
                    "size": len(raw),
                }
            )
        observations = load_graph_application_observations_bytes(
            control_raw[GRAPH_APPLICATION_OBSERVATIONS_FILE],
            authority=authority,
            expected_evidence_artifact_sha256=evidence_sha256,
        )
        validate_graph_application_assurance_phaseio(
            read_artifact_ledger(root),
            run_id=run_id,
            authority=authority,
            observations=observations,
            control_artifact_sha256={
                f"scratchpad:{name}": hashlib.sha256(raw).hexdigest()
                for name, raw in control_raw.items()
            },
        )
        reconciliation = load_graph_application_reconciliation_bytes(
            control_raw[GRAPH_APPLICATION_RECONCILIATION_FILE],
            authority=authority,
            observations=observations,
        )
        if reconciliation["state"] == "COMPLETE":
            if reconciliation["debts"]:
                raise ValueError("COMPLETE graph reconciliation contains debt")
            return ()
        if not reconciliation["debts"]:
            raise ValueError("non-COMPLETE graph reconciliation omits typed debt")

        control_provenance = {
            name: {
                "full_file_sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
            for name, raw in sorted(control_raw.items())
        }
        base_provenance = {
            "schema_version": "plamen.graph_application_assurance_source.v1",
            "run_id": authority["run_id"],
            "snapshot_sha256": authority["snapshot_sha256"],
            "workspace_reference_sha256": authority["workspace"][
                "reference_sha256"
            ],
            "generation_sha256": authority["graph_generation"][
                "generation_sha256"
            ],
            "full_availability_sha256": authority[
                "full_availability_sha256"
            ],
            "element_denominator_sha256": authority[
                "element_denominator_sha256"
            ],
            "consumer_denominator_sha256": authority[
                "consumer_denominator_sha256"
            ],
            "authority_sha256": authority["authority_sha256"],
            "observations_sha256": observations["observations_sha256"],
            "reconciliation_sha256": reconciliation[
                "reconciliation_sha256"
            ],
            "required_pair_count": reconciliation["required_pair_count"],
            "reconciled_pair_count": reconciliation["reconciled_pair_count"],
            "controls": control_provenance,
            "sources": source_provenance,
            "evidence_artifacts": evidence_provenance,
        }
        consumers = {
            row["consumer_id"]: row for row in authority["consumers"]
        }
        projected: list[dict[str, Any]] = []
        for ordinal, debt in enumerate(reconciliation["debts"]):
            code = debt["code"]
            subject = debt["subject"]
            consumer_id = subject.split(":", 1)[0]
            consumer = consumers.get(consumer_id)
            phase = str(consumer["phase"] if consumer else "chain")
            source_authority = {
                **base_provenance,
                "debt_ordinal": ordinal,
                "debt": dict(debt),
            }
            failure_id = hashlib.sha256(
                _canonical_json(source_authority)
            ).hexdigest()
            projected.append(
                {
                    "phase": phase,
                    "work_unit_id": consumer_id if consumer else (
                        "graph_application_reconciliation"
                    ),
                    "state": "COMPLETED_WITH_DEBT",
                    "assurance_impact": DISCOVERY_RECALL,
                    "gate_id": (
                        "graph_application."
                        + re.sub(r"[^a-z0-9_.-]+", "-", code.casefold())
                    ),
                    "gate_class": "GRAPH_APPLICATION_OUTCOME",
                    "affected_identities": sorted(
                        {subject, consumer_id} - {""}
                    ),
                    "message": (
                        f"Graph application debt {code} for {subject}: "
                        f"{debt['reason']} No clean graph-consumption or "
                        "application outcome is authorized."
                    ),
                    "failure_instance_id": failure_id,
                    "source_authority": source_authority,
                }
            )
        return finish(tuple(projected))
    except (
        GraphApplicationAuthorityError,
        ArtifactLedgerError,
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        return finish((
            _graph_application_invalid_row(root, run_id=run_id, exc=exc),
        ))


def _supplemental_assurance_rows(
    scratchpad: Path,
    *,
    project_root: Path,
    run_id: str,
    checkpoint_runtime_debts: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], ...]:
    runtime_debts = (
        checkpoint_runtime_debts
        if isinstance(checkpoint_runtime_debts, Mapping)
        else {}
    )
    rows = (
        *_program_facts_assurance_rows(
            scratchpad,
            run_id=run_id,
            checkpoint_runtime_debts=runtime_debts,
        ),
        *_graph_application_assurance_rows(scratchpad, run_id=run_id),
        *_toolchain_coverage_assurance_rows(scratchpad),
        *_verification_operator_assurance_rows(scratchpad, run_id=run_id),
        *_inventory_reconciliation_assurance_rows(scratchpad),
        *_trust_evidence_assurance_rows(scratchpad, run_id=run_id),
        *_chain_grouping_assurance_rows(
            scratchpad,
            project_root=project_root,
            run_id=run_id,
        ),
        *_axis_disposition_assurance_rows(
            scratchpad,
            project_root=project_root,
            run_id=run_id,
        ),
        *_candidate_negative_assurance_rows(scratchpad),
    )
    unique = {
        (
            str(row["phase"]),
            str(row["work_unit_id"]),
            str(row["gate_id"]),
            str(row["failure_instance_id"]),
        ): dict(row)
        for row in rows
    }
    return tuple(unique[key] for key in sorted(unique))


def build_current_assurance_manifest(
    checkpoint: Any,
    scratchpad: Path,
    project_root: Path,
) -> dict[str, Any]:
    """Rebuild the full current manifest, including replayed side authorities."""

    run_id = str(getattr(checkpoint, "run_id", "") or "")
    return build_assurance_manifest(
        checkpoint,
        supplemental_rows=_supplemental_assurance_rows(
            Path(scratchpad),
            project_root=Path(project_root),
            run_id=run_id,
            checkpoint_runtime_debts=(
                getattr(checkpoint, "runtime_debts", {}) or {}
            ),
        ),
    )


def build_assurance_projection_manifest(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Build a bounded, digest-bound view of the lossless debt manifest.

    Grouping changes representation only.  Every source row remains in
    ``assurance_limitations.json`` and every projected or omitted group binds
    the exact full rows through ``rows_digest``.
    """

    rows = manifest.get("rows")
    if not isinstance(rows, list) or manifest.get("row_count") != len(rows):
        raise ValueError("assurance manifest row denominator is malformed")
    source_digest = str(manifest.get("manifest_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", source_digest):
        raise ValueError("assurance manifest digest is malformed")
    unsigned_manifest = {
        key: value for key, value in manifest.items() if key != "manifest_sha256"
    }
    if hashlib.sha256(_canonical_json(unsigned_manifest)).hexdigest() != source_digest:
        raise ValueError("assurance manifest digest mismatch")

    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    all_affected: set[str] = set()
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError("assurance manifest row is not an object")
        row = dict(raw)
        key = (
            str(row.get("phase") or "unknown"),
            str(row.get("assurance_impact") or "UNKNOWN"),
            str(row.get("state") or "COMPLETED_WITH_DEBT"),
            str(row.get("gate_class") or "UNKNOWN"),
        )
        grouped.setdefault(key, []).append(row)
        affected = row.get("affected_identities") or []
        if not isinstance(affected, list):
            raise ValueError("assurance affected identities are not an array")
        all_affected.update(str(value) for value in affected if str(value))

    group_rows: list[dict[str, Any]] = []
    for key, members in grouped.items():
        ordered = sorted(
            members,
            key=lambda row: (
                str(row.get("work_unit_id") or ""),
                str(row.get("gate_id") or ""),
                str(row.get("failure_instance_id") or ""),
            ),
        )
        identities = sorted(
            {
                str(value)
                for row in ordered
                for value in (row.get("affected_identities") or [])
                if str(value)
            }
        )
        gate_ids = {str(row.get("gate_id") or "") for row in ordered}
        work_units = {str(row.get("work_unit_id") or "") for row in ordered}
        message = re.sub(
            r"\s+", " ", str(ordered[0].get("message") or "unresolved debt")
        ).strip()
        message = message[:ASSURANCE_PROJECTION_MAX_MESSAGE_CHARS]
        group_core = {
            "phase": key[0],
            "assurance_impact": key[1],
            "state": key[2],
            "gate_class": key[3],
            "row_count": len(ordered),
            "gate_id_count": len(gate_ids),
            "work_unit_count": len(work_units),
            "affected_identity_count": len(identities),
            "affected_identity_samples": identities[
                :ASSURANCE_PROJECTION_MAX_IDENTITIES_PER_GROUP
            ],
            "representative_message": message,
            "rows_digest": hashlib.sha256(_canonical_json(ordered)).hexdigest(),
        }
        group_rows.append(
            {
                "group_id": "ALIM-" + hashlib.sha256(
                    _canonical_json(group_core)
                ).hexdigest()[:20].upper(),
                **group_core,
            }
        )

    impact_priority = {
        DISCOVERY_RECALL: 0,
        VERIFICATION_CONFIDENCE: 1,
        REPORT_INTEGRITY: 2,
        ENRICHMENT_ONLY: 3,
    }
    group_rows.sort(
        key=lambda row: (
            impact_priority.get(str(row["assurance_impact"]), 4),
            -int(row["row_count"]),
            str(row["phase"]),
            str(row["state"]),
            str(row["gate_class"]),
            str(row["group_id"]),
        )
    )
    retained = group_rows[:ASSURANCE_PROJECTION_MAX_GROUPS]
    omitted = group_rows[ASSURANCE_PROJECTION_MAX_GROUPS:]
    represented_rows = sum(int(row["row_count"]) for row in retained)
    omitted_rows = sum(int(row["row_count"]) for row in omitted)
    base: dict[str, Any] = {
        "schema_version": ASSURANCE_PROJECTION_SCHEMA,
        "source_manifest_sha256": source_digest,
        "source_row_count": len(rows),
        "source_affected_identity_count": len(all_affected),
        "source_group_count": len(group_rows),
        "projected_group_count": len(retained),
        "represented_row_count": represented_rows,
        "omitted_group_count": len(omitted),
        "omitted_row_count": omitted_rows,
        "omitted_groups_digest": hashlib.sha256(_canonical_json(omitted)).hexdigest(),
        "projection_complete": not omitted,
        "groups": retained,
    }
    base["projection_digest"] = hashlib.sha256(_canonical_json(base)).hexdigest()
    return base


def assurance_projection_input_paths(scratchpad: Path) -> tuple[str, ...]:
    """Enumerate existing files consulted by the supplemental replay.

    This is an ownership/PhaseIO denominator, not semantic authority.  The
    manifest builder still validates and independently re-derives every source;
    binding the exact existing files additionally makes later source addition,
    removal, or byte drift visible as a contract change on resume.
    """

    root = Path(scratchpad)
    paths: set[str] = set()

    def add(relative: object) -> None:
        value = str(relative or "").replace("\\", "/")
        candidate = Path(value)
        if (
            not value
            or candidate.is_absolute()
            or ".." in candidate.parts
            or not (root / candidate).is_file()
        ):
            return
        paths.add(candidate.as_posix())

    for name in (
        *_PROGRAM_FACTS_V1_FILES,
        *_PROGRAM_FACTS_V2_FILES,
        *_PROGRAM_FACTS_ACTIVATION_SENTINELS,
        _PROGRAM_FACTS_RUNTIME_DEBT_FILE,
        *_GRAPH_APPLICATION_FILES,
        *(
            str(identity).split(":", 1)[1]
            for identity in graph_application_integration_contract()[
                "required_parent_artifacts"
            ]
        ),
        *(
            str(identity).split(":", 1)[1]
            for identity in graph_application_integration_contract()[
                "optional_parent_artifacts"
            ]
        ),
        "tool_coverage_ledger.json",
        "tool_coverage_ledger.md",
        "toolchain_coverage_debt.json",
        "report_semantic_toolchain_coverage.md",
        "post_verify_late_delivery.json",
        "verification_operator_denominator_authority.json",
        "verification_operator_consumer_authority.json",
        "verification_operator_consumer_authority.wave2.json",
        "verification_operator_consumer_authority.wave3.json",
        CHAIN_GROUPING_ASSURANCE_FILE,
        CHAIN_GROUPING_LIMITATIONS_FILE,
        INVENTORY_RECONCILIATION_FILE,
        INVENTORY_RECONCILIATION_HUMAN_REVIEW_FILE,
        TRUST_AUTHORITY_FILE,
        TRUST_PROVIDER_RECEIPT_FILE,
        CANDIDATE_PLAN_FILE,
        "candidate_negative_skeptic_receipt.json",
        CANDIDATE_DENOMINATOR_FILE,
        "candidate_negative_skeptic_proposals.md",
        *_AXIS_AUTHORITY_FILES,
    ):
        add(name)

    for candidate_ledger in sorted(root.glob("candidate_negative_proposals_*.json")):
        add(candidate_ledger.name)

    for debt_path in sorted(root.glob("trust_evidence_debt_*.json")):
        add(debt_path.name)

    graph_observations_path = root / GRAPH_APPLICATION_OBSERVATIONS_FILE
    if graph_observations_path.is_file() and not graph_observations_path.is_symlink():
        try:
            observations = strict_json_loads(
                graph_observations_path.read_bytes(),
                require_final_lf=True,
                require_canonical=True,
            )
            if isinstance(observations, dict):
                for row in observations.get("evidence_artifacts", []):
                    if not isinstance(row, dict):
                        continue
                    identity = str(row.get("artifact_identity") or "")
                    if identity.startswith("scratchpad:"):
                        add(identity.split(":", 1)[1])
        except (OSError, ProgramFactsTypeError, TypeError, UnicodeError, ValueError):
            pass

    provider_receipt_path = root / TRUST_PROVIDER_RECEIPT_FILE
    if provider_receipt_path.is_file():
        try:
            provider_receipt = json.loads(
                provider_receipt_path.read_text(
                    encoding="utf-8", errors="strict"
                )
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            provider_receipt = {}
        for binding in provider_receipt.get("input_bindings") or []:
            if isinstance(binding, dict):
                add(binding.get("path"))

    if (
        (root / INVENTORY_RECONCILIATION_FILE).is_file()
        or any(root.glob("inventory_chunk_*.manifest.md"))
    ):
        try:
            inventory = reconcile_inventory(root, persist=False)
        except (OSError, UnicodeError, TypeError, ValueError):
            inventory = {}
        for collection in (
            inventory.get("source_artifacts") or [],
            inventory.get("manifest_artifacts") or [],
            inventory.get("observed_artifacts") or [],
        ):
            for row in collection:
                if isinstance(row, dict):
                    add(row.get("artifact"))
        add(inventory.get("authority_artifact"))
        authority_name = str(inventory.get("authority_artifact") or "")
        authority_path = root / authority_name if authority_name else None
        if authority_path is not None and authority_path.is_file():
            try:
                authority = json.loads(
                    authority_path.read_text(
                        encoding="utf-8", errors="strict"
                    )
                )
            except (OSError, UnicodeError, json.JSONDecodeError):
                authority = {}
            for row in authority.get("rows") or []:
                if isinstance(row, dict):
                    add(row.get("evidence_artifact"))

    for name in (
        "post_verify_late_delivery.json",
        "verification_operator_denominator_authority.json",
        "verification_operator_consumer_authority.json",
        "verification_operator_consumer_authority.wave2.json",
        "verification_operator_consumer_authority.wave3.json",
    ):
        path = root / name
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            # The unreadable authority itself is already bound above and will
            # deterministically project invalid-authority debt.
            continue
        if name == "post_verify_late_delivery.json":
            for row in payload.get("rows") or []:
                if not isinstance(row, dict):
                    continue
                add(row.get("verify_artifact"))
                add(row.get("source_operator_receipt"))
        else:
            for source in payload.get("source_receipts") or []:
                if isinstance(source, dict):
                    add(source.get("path"))

    recovery_root = root / "_verification_recovery"
    if recovery_root.is_dir():
        for contract_path in sorted(
            recovery_root.glob("VREC-*/contract.json"),
            key=lambda value: value.as_posix(),
        ):
            add(contract_path.relative_to(root).as_posix())
            directory = contract_path.parent
            for name in ("launch_spec.json", "execution_receipt.json"):
                add((directory / name).relative_to(root).as_posix())
            try:
                contract = json.loads(
                    contract_path.read_text(encoding="utf-8", errors="strict")
                )
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            for field in (
                "manifest_path",
                "context_path",
                "method_dispatch_path",
                "prompt_path",
            ):
                add(contract.get(field))
            for field in ("expected_model_outputs", "expected_operator_receipts"):
                for relative in contract.get(field) or []:
                    add(relative)

    return tuple(sorted(paths))


def render_assurance_section(manifest: dict[str, Any]) -> str:
    projection = build_assurance_projection_manifest(manifest)
    groups = list(projection.get("groups") or [])
    if not manifest.get("rows"):
        return ""
    lines = [
        START_MARKER,
        SECTION_HEADING,
        "",
        "The driver recorded unresolved audit work or nonterminal shadow "
        "diagnostics. These rows are assurance limitations, not vulnerability "
        "findings, and they do not authorize a negative disposition.",
        "",
        (
            f"The lossless authority is `assurance_limitations.json` "
            f"(SHA-256 `{projection['source_manifest_sha256']}`) with "
            f"{projection['source_row_count']} unresolved row(s) and "
            f"{projection['source_affected_identity_count']} affected "
            "identity/identities. The table below is a deterministic bounded "
            "group projection, not the authority."
        ),
    ]
    if not bool(manifest.get("clean_full_audit_claim_allowed")):
        lines.extend(
            [
                "",
                "Because at least one recall, verification, or report-integrity "
                "obligation remains unresolved, this run must not be represented "
                "as a clean or full audit.",
            ]
        )
    lines.extend(
        [
            "",
            "| Phase | Assurance impact | State | Gate class | Obligations | Affected identities | Representative limitation |",
            "|---|---|---|---|---:|---|---|",
        ]
    )
    for row in groups:
        samples = list(row.get("affected_identity_samples") or [])
        affected = ", ".join(samples) or "-"
        remaining = int(row.get("affected_identity_count") or 0) - len(samples)
        if remaining > 0:
            affected += f" (+{remaining} more; see authority)"
        lines.append(
            "| "
            + " | ".join(
                _safe_cell(value)
                for value in (
                    row.get("phase"),
                    row.get("assurance_impact"),
                    row.get("state"),
                    row.get("gate_class"),
                    row.get("row_count"),
                    affected,
                    row.get("representative_message"),
                )
            )
            + " |"
        )
    if int(projection.get("omitted_group_count") or 0):
        lines.extend(
            [
                "",
                (
                    f"Projection budget retained {projection['projected_group_count']} "
                    f"group(s) and omitted {projection['omitted_group_count']} "
                    f"group(s) / {projection['omitted_row_count']} row(s). "
                    "No authoritative row was deleted. Omitted-group digest: "
                    f"`{projection['omitted_groups_digest']}`."
                ),
            ]
        )
    lines.extend(["", END_MARKER])
    return "\n".join(lines)


def project_assurance_limitations(
    checkpoint: Any, scratchpad: Path, report_path: Path
) -> int:
    """Atomically persist the manifest and exact driver-owned report block."""

    scratchpad = Path(scratchpad)
    report_path = Path(report_path)
    manifest = build_current_assurance_manifest(
        checkpoint,
        scratchpad,
        report_path.parent,
    )
    _atomic_write_if_changed(
        scratchpad / "assurance_limitations.json", _canonical_json(manifest)
    )
    projection = build_assurance_projection_manifest(manifest)
    _atomic_write_if_changed(
        scratchpad / "assurance_limitations_projection.json",
        _canonical_json(projection),
    )
    section = render_assurance_section(manifest)
    _atomic_write_if_changed(
        scratchpad / "assurance_limitations.md",
        ((section + "\n") if section else "").encode("utf-8"),
    )
    # Preserve all unmanaged report bytes (including CRLF and meaningful
    # trailing spaces).  Text-mode newline conversion and ``rstrip()`` would
    # otherwise make this small driver projection rewrite unrelated content.
    report = report_path.read_bytes().decode("utf-8")
    base = _MANAGED_BLOCK_RE.sub("\n", report).rstrip("\r\n")
    rendered = base + (("\n\n" + section) if section else "") + "\n"
    _atomic_write_if_changed(report_path, rendered.encode("utf-8"))
    return int(manifest["row_count"])


def validate_assurance_projection(
    checkpoint: Any, scratchpad: Path, report_path: Path
) -> list[str]:
    """Validate both the authoritative JSON receipt and the report projection."""

    expected_manifest = build_current_assurance_manifest(
        checkpoint,
        Path(scratchpad),
        Path(report_path).parent,
    )
    manifest_path = Path(scratchpad) / "assurance_limitations.json"
    try:
        actual_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"assurance-limitations manifest unreadable: {type(exc).__name__}"]
    if actual_manifest != expected_manifest:
        return ["assurance-limitations manifest differs from authoritative checkpoint debt"]

    projection_path = Path(scratchpad) / "assurance_limitations_projection.json"
    try:
        actual_projection = json.loads(
            projection_path.read_text(encoding="utf-8", errors="strict")
        )
    except Exception as exc:
        return [
            "assurance-limitations bounded projection unreadable: "
            f"{type(exc).__name__}"
        ]
    expected_projection = build_assurance_projection_manifest(expected_manifest)
    if actual_projection != expected_projection:
        return [
            "assurance-limitations bounded projection differs from the "
            "lossless authority"
        ]
    expected_section = render_assurance_section(expected_manifest)
    expected_sidecar = ((expected_section + "\n") if expected_section else "").encode(
        "utf-8"
    )
    try:
        actual_sidecar = (Path(scratchpad) / "assurance_limitations.md").read_bytes()
    except OSError as exc:
        return [
            "assurance-limitations Markdown sidecar unreadable: "
            f"{type(exc).__name__}"
        ]
    if actual_sidecar != expected_sidecar:
        return [
            "assurance-limitations Markdown sidecar differs from the "
            "authoritative projection"
        ]
    try:
        report = Path(report_path).read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"assurance-limitations report unreadable: {type(exc).__name__}"]
    structural_counts = (
        report.count(START_MARKER),
        report.count(END_MARKER),
        report.count(SECTION_HEADING),
    )
    expected_count = 1 if expected_section else 0
    if expected_section and structural_counts == (0, 0, 0):
        return ["delivered report omits the driver-owned assurance-limitations projection"]
    if structural_counts != (expected_count, expected_count, expected_count):
        return [
            "delivered report contains orphaned or duplicate assurance-"
            "limitations markers/headings"
        ]
    match = _MANAGED_BLOCK_RE.search(report)
    if not expected_section:
        if match is not None:
            return ["clean run retains a stale assurance-limitations projection"]
        return []
    if match is None:
        return ["delivered report omits the driver-owned assurance-limitations projection"]
    if len(_MANAGED_BLOCK_RE.findall(report)) != 1:
        return ["delivered report contains duplicate assurance-limitations projections"]
    actual_section = match.group(0).strip()
    if actual_section != expected_section:
        return ["delivered report differs from the driver-owned projection"]
    return []


__all__ = [
    "ASSURANCE_PROJECTION_MAX_GROUPS",
    "ASSURANCE_PROJECTION_MAX_IDENTITIES_PER_GROUP",
    "ASSURANCE_PROJECTION_MAX_MESSAGE_CHARS",
    "ASSURANCE_PROJECTION_SCHEMA",
    "DISCOVERY_RECALL",
    "ENRICHMENT_ONLY",
    "END_MARKER",
    "REPORT_INTEGRITY",
    "SECTION_HEADING",
    "START_MARKER",
    "VERIFICATION_CONFIDENCE",
    "build_assurance_manifest",
    "build_assurance_projection_manifest",
    "build_current_assurance_manifest",
    "assurance_projection_input_paths",
    "classify_assurance_impact",
    "project_assurance_limitations",
    "render_assurance_section",
    "validate_assurance_projection",
]
