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
from typing import Any

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
    active_committed_work_unit_authority_issues,
    read_artifact_ledger,
)
from axis_promotion_lineage import (
    authorize_downstream_inventory_tail,
    committed_promotion_output_issues,
)
import axis_disposition as axis_authority
import axis_canonical_prior as axis_prior_authority


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
            row["assurance_impact"] != ENRICHMENT_ONLY for row in rows
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
    """Replay deterministic tool debt into delivered assurance limitations."""

    path = Path(scratchpad) / "toolchain_coverage_debt.json"
    if not path.is_file():
        return ()
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8", errors="strict")
        )
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
        ):
            raise ValueError("toolchain coverage debt schema drifted")
        phase = str(payload.get("phase") or "breadth")
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
        failure_id = hashlib.sha256(
            f"{type(exc).__name__}:{exc}".encode("utf-8")
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
            },
        )


def _supplemental_assurance_rows(
    scratchpad: Path,
    *,
    project_root: Path,
    run_id: str,
) -> tuple[dict[str, Any], ...]:
    rows = (
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
        "The driver recorded unresolved audit work. These rows are assurance "
        "limitations, not vulnerability findings, and they do not authorize "
        "a negative disposition.",
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
