"""Lossless reporting projections for Adaptive Attention.

The four JSON artifacts produced here are deterministic projections over the
typed denominator, effective roster, join, terminal receipts, and stop
receipt.  They are not closure authorities.  Validation reconciles the four
artifacts so a bounded Markdown projection cannot hide unresolved work.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping, Sequence

from adaptive_attention_runtime import AttentionUsageReceipt
from adaptive_attention_types import (
    AdaptiveAttentionError,
    AttentionDebt,
    AttentionDenominator,
    AttentionJoinProjection,
    AttentionRoster,
    AttentionStopReceipt,
    ChannelTerminalReceipt,
    RosterAmendment,
    canonical_json,
    digest_json,
    effective_roster_digest,
    effective_roster_material,
)


COVERAGE_SCHEMA = "plamen.adaptive_attention_coverage.v1"
DEBT_ROW_SCHEMA = "plamen.adaptive_attention_reporting_debt_row.v1"
DEBT_SCHEMA = "plamen.adaptive_attention_debt.v1"
TELEMETRY_SCHEMA = "plamen.adaptive_attention_telemetry.v1"
ASSURANCE_ROW_SCHEMA = "plamen.adaptive_attention_assurance_row.v1"
ASSURANCE_SCHEMA = "plamen.adaptive_attention_assurance.v1"
REPORTING_SET_SCHEMA = "plamen.adaptive_attention_reporting_set.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FILENAMES = (
    "adaptive_attention_coverage.json",
    "adaptive_attention_debt.json",
    "adaptive_attention_telemetry.json",
    "adaptive_attention_assurance.json",
)


class AdaptiveAttentionReportingError(ValueError):
    """A reporting projection is stale, lossy, or internally inconsistent."""


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not _SHA256_RE.fullmatch(value.lower())
    ):
        raise AdaptiveAttentionReportingError(
            f"{field} must be a SHA-256 digest"
        )
    return value.lower()


def _count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AdaptiveAttentionReportingError(
            f"{field} must be a non-negative integer"
        )
    return value


def _identity(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdaptiveAttentionReportingError(
            f"{field} must be non-empty text"
        )
    return value.strip()


def _artifact_digest(value: Any) -> str:
    payload = value.to_dict()
    supplied = payload.pop("artifact_digest")
    if digest_json(payload) != supplied:
        raise AdaptiveAttentionReportingError(
            f"{type(value).__name__} digest does not replay"
        )
    return supplied


@dataclass(frozen=True, slots=True)
class AttentionCoverageArtifact:
    coverage_kind: str
    denominator_digest: str
    join_digest: str
    denominator_count: int
    state_counts: tuple[tuple[str, int], ...]
    kind_counts: tuple[tuple[str, int], ...]
    evidence_covered_count: int
    closed_count: int
    disputed_count: int
    debt_count: int
    assignment_backlog_count: int
    candidate_union_count: int
    evidence_union_count: int
    alias_count: int
    artifact_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": COVERAGE_SCHEMA,
            "coverage_kind": self.coverage_kind,
            "denominator_digest": self.denominator_digest,
            "join_digest": self.join_digest,
            "denominator_count": self.denominator_count,
            "state_counts": [
                [name, count] for name, count in self.state_counts
            ],
            "kind_counts": [
                [name, count] for name, count in self.kind_counts
            ],
            "evidence_covered_count": self.evidence_covered_count,
            "closed_count": self.closed_count,
            "disputed_count": self.disputed_count,
            "debt_count": self.debt_count,
            "assignment_backlog_count": self.assignment_backlog_count,
            "candidate_union_count": self.candidate_union_count,
            "evidence_union_count": self.evidence_union_count,
            "alias_count": self.alias_count,
            "artifact_digest": self.artifact_digest,
        }


@dataclass(frozen=True, order=True, slots=True)
class AttentionReportingDebtRow:
    debt_id: str
    obligation_id: str
    obligation_row_digest: str
    phase: str
    dependency_generation: int
    kind: str
    state: str
    category: str
    reason_codes: tuple[str, ...]
    failed_channel_ids: tuple[str, ...]
    source_debt_digests: tuple[str, ...]
    affected_identities: tuple[str, ...]
    clean_assurance_forbidden: bool
    clearing_conditions: tuple[str, ...]
    row_digest: str

    @classmethod
    def create(
        cls,
        *,
        obligation: Any,
        category: str,
        reason_codes: Iterable[str],
        source_debt: Iterable[AttentionDebt],
    ) -> "AttentionReportingDebtRow":
        debts = tuple(
            sorted(source_debt, key=lambda row: row.debt_digest)
        )
        reasons = tuple(
            sorted(
                {
                    _identity(reason, "reason_code").upper()
                    for reason in reason_codes
                }
                | {row.reason_code for row in debts}
            )
        )
        if not reasons:
            raise AdaptiveAttentionReportingError(
                "reporting debt row requires a reason"
            )
        payload = {
            "schema_version": DEBT_ROW_SCHEMA,
            "obligation_id": obligation.obligation_id,
            "obligation_row_digest": obligation.row_digest,
            "phase": obligation.phase,
            "dependency_generation": obligation.dependency_generation,
            "kind": obligation.kind,
            "state": obligation.state,
            "category": _identity(category, "category").upper(),
            "reason_codes": list(reasons),
            "failed_channel_ids": sorted(
                {
                    channel_id
                    for row in debts
                    for channel_id in row.failed_channel_ids
                }
            ),
            "source_debt_digests": [
                row.debt_digest for row in debts
            ],
            "affected_identities": sorted(
                set(obligation.subject_ids)
                | {
                    identity
                    for row in debts
                    for identity in row.affected_identities
                }
            ),
            "clean_assurance_forbidden": bool(
                not obligation.enrichment_only
                or any(row.clean_assurance_forbidden for row in debts)
            ),
            "clearing_conditions": sorted(
                {
                    condition
                    for condition in (
                        obligation.clearing_condition,
                        *(row.clearing_condition for row in debts),
                    )
                    if condition
                }
            ),
        }
        row_digest = digest_json(payload)
        return cls(
            debt_id="AAD-" + row_digest[:24].upper(),
            obligation_id=obligation.obligation_id,
            obligation_row_digest=obligation.row_digest,
            phase=obligation.phase,
            dependency_generation=obligation.dependency_generation,
            kind=obligation.kind,
            state=obligation.state,
            category=payload["category"],
            reason_codes=reasons,
            failed_channel_ids=tuple(payload["failed_channel_ids"]),
            source_debt_digests=tuple(
                payload["source_debt_digests"]
            ),
            affected_identities=tuple(payload["affected_identities"]),
            clean_assurance_forbidden=payload[
                "clean_assurance_forbidden"
            ],
            clearing_conditions=tuple(payload["clearing_conditions"]),
            row_digest=row_digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": DEBT_ROW_SCHEMA,
            "debt_id": self.debt_id,
            "obligation_id": self.obligation_id,
            "obligation_row_digest": self.obligation_row_digest,
            "phase": self.phase,
            "dependency_generation": self.dependency_generation,
            "kind": self.kind,
            "state": self.state,
            "category": self.category,
            "reason_codes": list(self.reason_codes),
            "failed_channel_ids": list(self.failed_channel_ids),
            "source_debt_digests": list(self.source_debt_digests),
            "affected_identities": list(self.affected_identities),
            "clean_assurance_forbidden": (
                self.clean_assurance_forbidden
            ),
            "clearing_conditions": list(self.clearing_conditions),
            "row_digest": self.row_digest,
        }


@dataclass(frozen=True, slots=True)
class AttentionDebtArtifact:
    denominator_digest: str
    effective_roster_digest: str
    join_digest: str
    rows: tuple[AttentionReportingDebtRow, ...]
    unresolved_obligation_ids: tuple[str, ...]
    global_reason_codes: tuple[str, ...]
    artifact_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": DEBT_SCHEMA,
            "denominator_digest": self.denominator_digest,
            "effective_roster_digest": self.effective_roster_digest,
            "join_digest": self.join_digest,
            "rows": [row.to_dict() for row in self.rows],
            "unresolved_obligation_ids": list(
                self.unresolved_obligation_ids
            ),
            "global_reason_codes": list(self.global_reason_codes),
            "artifact_digest": self.artifact_digest,
        }


@dataclass(frozen=True, slots=True)
class AttentionTelemetryArtifact:
    denominator_digest: str
    effective_roster_digest: str
    join_digest: str
    stop_digest: str
    channel_counts: tuple[tuple[str, int], ...]
    reserved_attention_units: int
    observed_input_tokens: int
    observed_output_tokens: int
    observed_tool_invocations: int
    observed_timeout_slots: int
    usage_missing_channel_ids: tuple[str, ...]
    evidence_covered_count: int
    closed_count: int
    candidate_union_count: int
    alias_count: int
    retained_negative_proposal_count: int
    authority_debt_reason_codes: tuple[str, ...]
    found_then_lost_invariant_status: str
    artifact_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TELEMETRY_SCHEMA,
            "denominator_digest": self.denominator_digest,
            "effective_roster_digest": self.effective_roster_digest,
            "join_digest": self.join_digest,
            "stop_digest": self.stop_digest,
            "channel_counts": [
                [name, count] for name, count in self.channel_counts
            ],
            "reserved_attention_units": self.reserved_attention_units,
            "observed_input_tokens": self.observed_input_tokens,
            "observed_output_tokens": self.observed_output_tokens,
            "observed_tool_invocations": (
                self.observed_tool_invocations
            ),
            "observed_timeout_slots": self.observed_timeout_slots,
            "usage_missing_channel_ids": list(
                self.usage_missing_channel_ids
            ),
            "evidence_covered_count": self.evidence_covered_count,
            "closed_count": self.closed_count,
            "candidate_union_count": self.candidate_union_count,
            "alias_count": self.alias_count,
            "retained_negative_proposal_count": (
                self.retained_negative_proposal_count
            ),
            "authority_debt_reason_codes": list(
                self.authority_debt_reason_codes
            ),
            "found_then_lost_invariant_status": (
                self.found_then_lost_invariant_status
            ),
            "artifact_digest": self.artifact_digest,
        }


@dataclass(frozen=True, order=True, slots=True)
class AttentionAssuranceRow:
    assurance_id: str
    obligation_id: str
    category: str
    reason_codes: tuple[str, ...]
    debt_row_digest: str
    clean_assurance_forbidden: bool
    row_digest: str

    @classmethod
    def create(
        cls, debt: AttentionReportingDebtRow
    ) -> "AttentionAssuranceRow":
        payload = {
            "schema_version": ASSURANCE_ROW_SCHEMA,
            "obligation_id": debt.obligation_id,
            "category": debt.category,
            "reason_codes": list(debt.reason_codes),
            "debt_row_digest": debt.row_digest,
            "clean_assurance_forbidden": (
                debt.clean_assurance_forbidden
            ),
        }
        row_digest = digest_json(payload)
        return cls(
            assurance_id="AALIM-" + row_digest[:24].upper(),
            obligation_id=debt.obligation_id,
            category=debt.category,
            reason_codes=debt.reason_codes,
            debt_row_digest=debt.row_digest,
            clean_assurance_forbidden=debt.clean_assurance_forbidden,
            row_digest=row_digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ASSURANCE_ROW_SCHEMA,
            "assurance_id": self.assurance_id,
            "obligation_id": self.obligation_id,
            "category": self.category,
            "reason_codes": list(self.reason_codes),
            "debt_row_digest": self.debt_row_digest,
            "clean_assurance_forbidden": (
                self.clean_assurance_forbidden
            ),
            "row_digest": self.row_digest,
        }


@dataclass(frozen=True, slots=True)
class AttentionAssuranceArtifact:
    denominator_digest: str
    debt_artifact_digest: str
    stop_digest: str
    rows: tuple[AttentionAssuranceRow, ...]
    categories: tuple[tuple[str, int], ...]
    global_reason_codes: tuple[str, ...]
    clean_full_audit_claim_allowed: bool
    artifact_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ASSURANCE_SCHEMA,
            "denominator_digest": self.denominator_digest,
            "debt_artifact_digest": self.debt_artifact_digest,
            "stop_digest": self.stop_digest,
            "rows": [row.to_dict() for row in self.rows],
            "categories": [
                [name, count] for name, count in self.categories
            ],
            "global_reason_codes": list(self.global_reason_codes),
            "clean_full_audit_claim_allowed": (
                self.clean_full_audit_claim_allowed
            ),
            "artifact_digest": self.artifact_digest,
        }


@dataclass(frozen=True, slots=True)
class AdaptiveAttentionReportingArtifacts:
    coverage: AttentionCoverageArtifact
    debt: AttentionDebtArtifact
    telemetry: AttentionTelemetryArtifact
    assurance: AttentionAssuranceArtifact
    reporting_set_digest: str

    def filenames(self) -> tuple[str, ...]:
        return _FILENAMES

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REPORTING_SET_SCHEMA,
            "coverage": self.coverage.to_dict(),
            "debt": self.debt.to_dict(),
            "telemetry": self.telemetry.to_dict(),
            "assurance": self.assurance.to_dict(),
            "reporting_set_digest": self.reporting_set_digest,
        }

    def json_documents(self) -> dict[str, str]:
        return {
            _FILENAMES[0]: canonical_json(self.coverage.to_dict()),
            _FILENAMES[1]: canonical_json(self.debt.to_dict()),
            _FILENAMES[2]: canonical_json(self.telemetry.to_dict()),
            _FILENAMES[3]: canonical_json(self.assurance.to_dict()),
        }


def _category_for_obligation(row: Any) -> str:
    if row.enrichment_only:
        return "OPTIONAL_ENRICHMENT"
    if row.kind in {"VERIFIER_ITEM", "CANDIDATE_CHALLENGE"}:
        return "VERIFICATION_CONFIDENCE"
    if row.kind in {"REPORT_ITEM", "MERGE_ITEM"}:
        return "REPORT_INTEGRITY"
    return "DISCOVERY_RECALL"


def _state_reason(row: Any, *, scheduled: bool) -> str:
    if not scheduled:
        return "UNSCHEDULED_OBLIGATION"
    return {
        "UNCOVERED": "OBLIGATION_UNCOVERED",
        "ASSIGNED": "OBLIGATION_ASSIGNED",
        "EVIDENCED": "CLOSURE_PENDING",
        "DISPUTED": "NEGATIVE_OR_CONFLICT_DISPUTED",
        "DEBT": "OBLIGATION_DEBT",
        "CLOSED": "CLOSED_WITH_ACTIVE_DEBT",
    }[row.state]


def _artifact(
    cls: type[Any], payload: dict[str, Any], **fields: Any
) -> Any:
    return cls(**fields, artifact_digest=digest_json(payload))


def build_attention_reporting_artifacts(
    *,
    denominator: AttentionDenominator,
    roster: AttentionRoster,
    amendments: Sequence[RosterAmendment],
    join_projection: AttentionJoinProjection,
    stop_receipt: AttentionStopReceipt | None,
    terminal_receipts: Iterable[ChannelTerminalReceipt],
    runtime_debt: Iterable[AttentionDebt],
    usage_receipts: Iterable[AttentionUsageReceipt],
) -> AdaptiveAttentionReportingArtifacts:
    """Build all four exact artifacts or fail before publishing any."""

    try:
        AttentionDenominator.from_dict(denominator.to_dict())
        AttentionRoster.from_dict(roster.to_dict())
        AttentionJoinProjection.from_dict(join_projection.to_dict())
    except (AdaptiveAttentionError, TypeError) as exc:
        raise AdaptiveAttentionReportingError(str(exc)) from exc
    effective_digest = effective_roster_digest(roster, amendments)
    channels, roster_debt, effective_rows = effective_roster_material(
        roster, amendments
    )
    if roster.scope_digest != denominator.scope_digest:
        raise AdaptiveAttentionReportingError(
            "roster and denominator scope differ"
        )
    if {
        row.obligation_id for row in denominator.obligations
    } - {
        row.obligation_id
        for row in join_projection.denominator_obligations
    }:
        raise AdaptiveAttentionReportingError(
            "join omits base denominator obligations"
        )
    base_by_id = {
        row.obligation_id: row for row in denominator.obligations
    }
    projection_by_id = {
        row.obligation_id: row
        for row in join_projection.denominator_obligations
    }
    for obligation_id, base in base_by_id.items():
        projected = projection_by_id[obligation_id]
        if (
            projected.kind,
            projected.subject_ids,
            projected.source_bindings,
            projected.methodology_bindings,
            projected.closure_policy,
        ) != (
            base.kind,
            base.subject_ids,
            base.source_bindings,
            base.methodology_bindings,
            base.closure_policy,
        ):
            raise AdaptiveAttentionReportingError(
                "join rewrites base denominator provenance"
            )
    terminals = tuple(
        sorted(
            (
                ChannelTerminalReceipt.from_dict(row.to_dict())
                for row in terminal_receipts
            ),
            key=lambda row: row.channel_id,
        )
    )
    if len({row.channel_id for row in terminals}) != len(terminals):
        raise AdaptiveAttentionReportingError(
            "duplicate terminal channel receipts"
        )
    channels_by_id = {row.channel_id: row for row in channels}
    if not {row.channel_id for row in terminals} <= set(channels_by_id):
        raise AdaptiveAttentionReportingError(
            "terminal receipt is outside the effective roster"
        )
    if any(
        row.channel_row_digest
        != channels_by_id[row.channel_id].row_digest
        for row in terminals
    ):
        raise AdaptiveAttentionReportingError(
            "terminal receipt has a stale channel binding"
        )
    typed_runtime_debt = tuple(
        AttentionDebt.from_dict(row.to_dict()) for row in runtime_debt
    )
    all_source_debt = (*roster_debt, *typed_runtime_debt)
    source_debt_by_obligation: dict[str, list[AttentionDebt]] = {}
    for debt in all_source_debt:
        source_debt_by_obligation.setdefault(
            debt.obligation_id, []
        ).append(debt)
    join_ids = {
        row.obligation_id
        for row in join_projection.denominator_obligations
    }
    outside_debt = sorted(
        set(source_debt_by_obligation) - join_ids
    )
    if outside_debt:
        raise AdaptiveAttentionReportingError(
            "runtime or roster debt is outside the join denominator: "
            + ",".join(outside_debt)
        )
    scheduled_ids = {
        obligation_id
        for channel in channels
        for obligation_id in channel.obligation_ids
    }
    debt_rows: list[AttentionReportingDebtRow] = []
    for obligation in join_projection.denominator_obligations:
        source_rows = source_debt_by_obligation.get(
            obligation.obligation_id, []
        )
        if obligation.state == "CLOSED" and not source_rows:
            continue
        reason = _state_reason(
            obligation,
            scheduled=obligation.obligation_id in scheduled_ids,
        )
        debt_rows.append(
            AttentionReportingDebtRow.create(
                obligation=obligation,
                category=_category_for_obligation(obligation),
                reason_codes=(reason,),
                source_debt=source_rows,
            )
        )
    debt_rows_tuple = tuple(
        sorted(debt_rows, key=lambda row: row.obligation_id)
    )
    states: dict[str, int] = {}
    kinds: dict[str, int] = {}
    for row in join_projection.denominator_obligations:
        states[row.state] = states.get(row.state, 0) + 1
        kinds[row.kind] = kinds.get(row.kind, 0) + 1
    evidence_count = sum(
        states.get(state, 0)
        for state in ("EVIDENCED", "DISPUTED", "CLOSED")
    )
    coverage_payload = {
        "schema_version": COVERAGE_SCHEMA,
        "coverage_kind": denominator.coverage_kind,
        "denominator_digest": denominator.denominator_digest,
        "join_digest": join_projection.join_digest,
        "denominator_count": len(
            join_projection.denominator_obligations
        ),
        "state_counts": [
            [name, count] for name, count in sorted(states.items())
        ],
        "kind_counts": [
            [name, count] for name, count in sorted(kinds.items())
        ],
        "evidence_covered_count": evidence_count,
        "closed_count": states.get("CLOSED", 0),
        "disputed_count": states.get("DISPUTED", 0),
        "debt_count": states.get("DEBT", 0),
        "assignment_backlog_count": (
            states.get("UNCOVERED", 0) + states.get("ASSIGNED", 0)
        ),
        "candidate_union_count": len(join_projection.candidate_union),
        "evidence_union_count": len(join_projection.evidence_union),
        "alias_count": len(join_projection.alias_map),
    }
    coverage = _artifact(
        AttentionCoverageArtifact,
        coverage_payload,
        coverage_kind=denominator.coverage_kind,
        denominator_digest=denominator.denominator_digest,
        join_digest=join_projection.join_digest,
        denominator_count=coverage_payload["denominator_count"],
        state_counts=tuple(sorted(states.items())),
        kind_counts=tuple(sorted(kinds.items())),
        evidence_covered_count=evidence_count,
        closed_count=states.get("CLOSED", 0),
        disputed_count=states.get("DISPUTED", 0),
        debt_count=states.get("DEBT", 0),
        assignment_backlog_count=coverage_payload[
            "assignment_backlog_count"
        ],
        candidate_union_count=len(join_projection.candidate_union),
        evidence_union_count=len(join_projection.evidence_union),
        alias_count=len(join_projection.alias_map),
    )
    global_reason_codes = set(
        join_projection.authority_debt_reason_codes
    )
    if denominator.coverage_kind != "EXACT":
        global_reason_codes.add("DENOMINATOR_NOT_EXACT")
    global_reason_codes.update(
        terminal.reason_code
        for terminal in terminals
        if terminal.terminal_state != "COMMITTED"
    )
    if stop_receipt is not None:
        global_reason_codes.update(stop_receipt.reason_codes)
    global_reasons = tuple(sorted(global_reason_codes))
    debt_payload = {
        "schema_version": DEBT_SCHEMA,
        "denominator_digest": denominator.denominator_digest,
        "effective_roster_digest": effective_digest,
        "join_digest": join_projection.join_digest,
        "rows": [row.to_dict() for row in debt_rows_tuple],
        "unresolved_obligation_ids": [
            row.obligation_id for row in debt_rows_tuple
        ],
        "global_reason_codes": list(global_reasons),
    }
    debt_artifact = _artifact(
        AttentionDebtArtifact,
        debt_payload,
        denominator_digest=denominator.denominator_digest,
        effective_roster_digest=effective_digest,
        join_digest=join_projection.join_digest,
        rows=debt_rows_tuple,
        unresolved_obligation_ids=tuple(
            row.obligation_id for row in debt_rows_tuple
        ),
        global_reason_codes=global_reasons,
    )
    usage = tuple(
        sorted(
            (
                AttentionUsageReceipt.from_dict(row.to_dict())
                for row in usage_receipts
            ),
            key=lambda row: row.channel_id,
        )
    )
    if len({row.channel_id for row in usage}) != len(usage):
        raise AdaptiveAttentionReportingError(
            "duplicate usage receipts"
        )
    if not {row.channel_id for row in usage} <= set(channels_by_id):
        raise AdaptiveAttentionReportingError(
            "usage receipt is outside the effective roster"
        )
    terminal_counts: dict[str, int] = {
        "PLANNED": len(channels) - len(terminals)
    }
    for terminal in terminals:
        terminal_counts[terminal.terminal_state] = (
            terminal_counts.get(terminal.terminal_state, 0) + 1
        )
    stop_digest = ""
    if stop_receipt is not None:
        try:
            replayed_stop = AttentionStopReceipt.from_dict(
                stop_receipt.to_dict()
            )
        except (AdaptiveAttentionError, TypeError) as exc:
            raise AdaptiveAttentionReportingError(str(exc)) from exc
        if (
            replayed_stop.denominator_digest
            != denominator.denominator_digest
            or replayed_stop.effective_roster_digest
            != effective_digest
        ):
            raise AdaptiveAttentionReportingError(
                "stop receipt reporting bindings differ"
            )
        stop_digest = replayed_stop.stop_digest
    usage_ids = {row.channel_id for row in usage}
    telemetry_payload = {
        "schema_version": TELEMETRY_SCHEMA,
        "denominator_digest": denominator.denominator_digest,
        "effective_roster_digest": effective_digest,
        "join_digest": join_projection.join_digest,
        "stop_digest": stop_digest,
        "channel_counts": [
            [name, count]
            for name, count in sorted(terminal_counts.items())
        ],
        "reserved_attention_units": sum(
            row.resource_reservation.attention_units for row in channels
        ),
        "observed_input_tokens": sum(
            row.observed_input_tokens for row in usage
        ),
        "observed_output_tokens": sum(
            row.observed_output_tokens for row in usage
        ),
        "observed_tool_invocations": sum(
            row.observed_tool_invocations for row in usage
        ),
        "observed_timeout_slots": sum(
            row.observed_timeout_slots for row in usage
        ),
        "usage_missing_channel_ids": sorted(
            set(channels_by_id) - usage_ids
        ),
        "evidence_covered_count": evidence_count,
        "closed_count": states.get("CLOSED", 0),
        "candidate_union_count": len(join_projection.candidate_union),
        "alias_count": len(join_projection.alias_map),
        "retained_negative_proposal_count": len(
            join_projection.retained_negative_proposal_ids
        ),
        "authority_debt_reason_codes": list(
            join_projection.authority_debt_reason_codes
        ),
        "found_then_lost_invariant_status": "NOT_EVALUATED",
    }
    telemetry = _artifact(
        AttentionTelemetryArtifact,
        telemetry_payload,
        denominator_digest=denominator.denominator_digest,
        effective_roster_digest=effective_digest,
        join_digest=join_projection.join_digest,
        stop_digest=stop_digest,
        channel_counts=tuple(sorted(terminal_counts.items())),
        reserved_attention_units=telemetry_payload[
            "reserved_attention_units"
        ],
        observed_input_tokens=telemetry_payload[
            "observed_input_tokens"
        ],
        observed_output_tokens=telemetry_payload[
            "observed_output_tokens"
        ],
        observed_tool_invocations=telemetry_payload[
            "observed_tool_invocations"
        ],
        observed_timeout_slots=telemetry_payload[
            "observed_timeout_slots"
        ],
        usage_missing_channel_ids=tuple(
            telemetry_payload["usage_missing_channel_ids"]
        ),
        evidence_covered_count=evidence_count,
        closed_count=states.get("CLOSED", 0),
        candidate_union_count=len(join_projection.candidate_union),
        alias_count=len(join_projection.alias_map),
        retained_negative_proposal_count=len(
            join_projection.retained_negative_proposal_ids
        ),
        authority_debt_reason_codes=(
            join_projection.authority_debt_reason_codes
        ),
        found_then_lost_invariant_status="NOT_EVALUATED",
    )
    assurance_rows = tuple(
        sorted(
            (
                AttentionAssuranceRow.create(row)
                for row in debt_rows_tuple
            ),
            key=lambda row: row.assurance_id,
        )
    )
    categories: dict[str, int] = {}
    for row in assurance_rows:
        categories[row.category] = categories.get(row.category, 0) + 1
    clean_allowed = bool(
        stop_receipt is not None
        and stop_receipt.classification == "CLEAN_STOP"
        and stop_receipt.clean_full_assurance_claim_allowed
        and denominator.coverage_kind == "EXACT"
        and not any(
            row.clean_assurance_forbidden for row in assurance_rows
        )
        and not join_projection.authority_debt_reason_codes
    )
    assurance_payload = {
        "schema_version": ASSURANCE_SCHEMA,
        "denominator_digest": denominator.denominator_digest,
        "debt_artifact_digest": debt_artifact.artifact_digest,
        "stop_digest": stop_digest,
        "rows": [row.to_dict() for row in assurance_rows],
        "categories": [
            [name, count] for name, count in sorted(categories.items())
        ],
        "global_reason_codes": list(global_reasons),
        "clean_full_audit_claim_allowed": clean_allowed,
    }
    assurance = _artifact(
        AttentionAssuranceArtifact,
        assurance_payload,
        denominator_digest=denominator.denominator_digest,
        debt_artifact_digest=debt_artifact.artifact_digest,
        stop_digest=stop_digest,
        rows=assurance_rows,
        categories=tuple(sorted(categories.items())),
        global_reason_codes=global_reasons,
        clean_full_audit_claim_allowed=clean_allowed,
    )
    set_payload = {
        "schema_version": REPORTING_SET_SCHEMA,
        "coverage_digest": coverage.artifact_digest,
        "debt_digest": debt_artifact.artifact_digest,
        "telemetry_digest": telemetry.artifact_digest,
        "assurance_digest": assurance.artifact_digest,
    }
    result = AdaptiveAttentionReportingArtifacts(
        coverage=coverage,
        debt=debt_artifact,
        telemetry=telemetry,
        assurance=assurance,
        reporting_set_digest=digest_json(set_payload),
    )
    validate_attention_reporting_artifacts(result)
    return result


def validate_attention_reporting_artifacts(
    artifacts: AdaptiveAttentionReportingArtifacts,
) -> None:
    if not isinstance(artifacts, AdaptiveAttentionReportingArtifacts):
        raise TypeError(
            "artifacts must be AdaptiveAttentionReportingArtifacts"
        )
    for artifact in (
        artifacts.coverage,
        artifacts.debt,
        artifacts.telemetry,
        artifacts.assurance,
    ):
        _artifact_digest(artifact)
    for row in artifacts.debt.rows:
        payload = row.to_dict()
        row_digest = payload.pop("row_digest")
        debt_id = payload.pop("debt_id")
        if digest_json(payload) != row_digest or debt_id != (
            "AAD-" + row_digest[:24].upper()
        ):
            raise AdaptiveAttentionReportingError(
                "reporting debt row does not replay"
            )
    for row in artifacts.assurance.rows:
        payload = row.to_dict()
        row_digest = payload.pop("row_digest")
        assurance_id = payload.pop("assurance_id")
        if digest_json(payload) != row_digest or assurance_id != (
            "AALIM-" + row_digest[:24].upper()
        ):
            raise AdaptiveAttentionReportingError(
                "assurance row does not replay"
            )
    denominator_digests = {
        artifacts.coverage.denominator_digest,
        artifacts.debt.denominator_digest,
        artifacts.telemetry.denominator_digest,
        artifacts.assurance.denominator_digest,
    }
    if len(denominator_digests) != 1:
        raise AdaptiveAttentionReportingError(
            "reporting artifacts bind different denominators"
        )
    join_digests = {
        artifacts.coverage.join_digest,
        artifacts.debt.join_digest,
        artifacts.telemetry.join_digest,
    }
    if len(join_digests) != 1:
        raise AdaptiveAttentionReportingError(
            "reporting artifacts bind different joins"
        )
    if artifacts.assurance.debt_artifact_digest != (
        artifacts.debt.artifact_digest
    ):
        raise AdaptiveAttentionReportingError(
            "assurance does not bind the exact debt artifact"
        )
    debt_ids = tuple(row.obligation_id for row in artifacts.debt.rows)
    if debt_ids != artifacts.debt.unresolved_obligation_ids:
        raise AdaptiveAttentionReportingError(
            "debt manifest omits or reorders unresolved identities"
        )
    assurance_debt_digests = {
        row.debt_row_digest for row in artifacts.assurance.rows
    }
    if assurance_debt_digests != {
        row.row_digest for row in artifacts.debt.rows
    }:
        raise AdaptiveAttentionReportingError(
            "assurance projection is not lossless"
        )
    if artifacts.assurance.global_reason_codes != (
        artifacts.debt.global_reason_codes
    ):
        raise AdaptiveAttentionReportingError(
            "assurance omits global controller debt"
        )
    if artifacts.assurance.clean_full_audit_claim_allowed and (
        artifacts.debt.rows
        or artifacts.coverage.coverage_kind != "EXACT"
        or artifacts.telemetry.authority_debt_reason_codes
        or artifacts.debt.global_reason_codes
    ):
        raise AdaptiveAttentionReportingError(
            "clean assurance contradicts current debt or authority"
        )
    if sum(count for _state, count in artifacts.coverage.state_counts) != (
        artifacts.coverage.denominator_count
    ):
        raise AdaptiveAttentionReportingError(
            "coverage state counts do not reconcile"
        )
    if sum(count for _kind, count in artifacts.coverage.kind_counts) != (
        artifacts.coverage.denominator_count
    ):
        raise AdaptiveAttentionReportingError(
            "coverage kind counts do not reconcile"
        )
    state_counts = dict(artifacts.coverage.state_counts)
    expected_evidence = sum(
        state_counts.get(state, 0)
        for state in ("EVIDENCED", "DISPUTED", "CLOSED")
    )
    if artifacts.coverage.evidence_covered_count != expected_evidence:
        raise AdaptiveAttentionReportingError(
            "coverage counts debt as evidence or omits evidence"
        )
    if (
        artifacts.coverage.closed_count
        != state_counts.get("CLOSED", 0)
        or artifacts.coverage.disputed_count
        != state_counts.get("DISPUTED", 0)
        or artifacts.coverage.debt_count
        != state_counts.get("DEBT", 0)
        or artifacts.coverage.assignment_backlog_count
        != state_counts.get("UNCOVERED", 0)
        + state_counts.get("ASSIGNED", 0)
    ):
        raise AdaptiveAttentionReportingError(
            "coverage state projections do not reconcile"
        )
    if (
        artifacts.telemetry.evidence_covered_count
        != artifacts.coverage.evidence_covered_count
        or artifacts.telemetry.closed_count
        != artifacts.coverage.closed_count
        or artifacts.telemetry.candidate_union_count
        != artifacts.coverage.candidate_union_count
        or artifacts.telemetry.alias_count
        != artifacts.coverage.alias_count
    ):
        raise AdaptiveAttentionReportingError(
            "telemetry and coverage projections differ"
        )
    expected_categories: dict[str, int] = {}
    for row in artifacts.assurance.rows:
        expected_categories[row.category] = (
            expected_categories.get(row.category, 0) + 1
        )
    if artifacts.assurance.categories != tuple(
        sorted(expected_categories.items())
    ):
        raise AdaptiveAttentionReportingError(
            "assurance category counts do not reconcile"
        )
    set_payload = {
        "schema_version": REPORTING_SET_SCHEMA,
        "coverage_digest": artifacts.coverage.artifact_digest,
        "debt_digest": artifacts.debt.artifact_digest,
        "telemetry_digest": artifacts.telemetry.artifact_digest,
        "assurance_digest": artifacts.assurance.artifact_digest,
    }
    if digest_json(set_payload) != _sha256(
        artifacts.reporting_set_digest, "reporting_set_digest"
    ):
        raise AdaptiveAttentionReportingError(
            "reporting set digest does not replay"
        )


__all__ = [
    "AdaptiveAttentionReportingArtifacts",
    "AdaptiveAttentionReportingError",
    "AttentionAssuranceArtifact",
    "AttentionAssuranceRow",
    "AttentionCoverageArtifact",
    "AttentionDebtArtifact",
    "AttentionReportingDebtRow",
    "AttentionTelemetryArtifact",
    "build_attention_reporting_artifacts",
    "validate_attention_reporting_artifacts",
]
