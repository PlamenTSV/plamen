"""Offline, blinded 2x2 evaluator for Adaptive Attention experiments.

This module is intentionally grader-side.  It does not import the driver,
runtime, provider adapters, or audit workspaces.  Public run cells contain no
ground-truth fields; a separate private grader binds scores to opaque run and
case tokens only after bundle digests are frozen.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import random
import re
from typing import Any, Iterable, Mapping

from adaptive_attention_types import digest_json


BLINDED_RUN_CELL_SCHEMA = "plamen.adaptive_attention_run_cell.v1"
BLINDED_GRADE_SCHEMA = "plamen.adaptive_attention_blinded_grade.v1"
EVALUATION_SCHEMA = "plamen.adaptive_attention_2x2_evaluation.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$", re.ASCII)
_BUDGET_REGIMES = {
    "MATCHED_TOTAL",
    "MATCHED_PER_SEMANTIC_CHANNEL",
}
_PUBLIC_FIELDS = {
    "schema_version",
    "opaque_run_token",
    "opaque_case_token",
    "seed_token",
    "cell_id",
    "graph_enabled",
    "attention_enabled",
    "budget_regime",
    "source_snapshot_digest",
    "config_digest",
    "methodology_digest",
    "graph_treatment_digest",
    "backend_capability_label",
    "candidate_ids",
    "evidence_ids",
    "semantic_channel_grants",
    "graph_attributable_removed_candidate_ids",
    "graph_attributable_removed_evidence_ids",
    "reserved_attention_units",
    "reserved_input_tokens",
    "reserved_output_tokens",
    "reserved_tool_invocations",
    "reserved_timeout_slots",
    "bundle_digest",
    "containment_ok",
    "resume_integrity_ok",
    "clean_assurance_claim_allowed",
    "record_digest",
}


class AdaptiveAttentionEvaluationError(ValueError):
    """A public cell, private grade, or 2x2 denominator is invalid."""


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdaptiveAttentionEvaluationError(
            f"{field} must be non-empty text"
        )
    return value.strip()


def _opaque(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _OPAQUE_RE.fullmatch(text):
        raise AdaptiveAttentionEvaluationError(
            f"{field} must be an opaque non-path token"
        )
    return text


def _identity(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _ID_RE.fullmatch(text):
        raise AdaptiveAttentionEvaluationError(
            f"{field} must be a canonical identity"
        )
    return text


def _sha256(value: Any, field: str) -> str:
    text = _text(value, field).lower()
    if not _SHA256_RE.fullmatch(text):
        raise AdaptiveAttentionEvaluationError(
            f"{field} must be a SHA-256 digest"
        )
    return text


def _count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AdaptiveAttentionEvaluationError(
            f"{field} must be a non-negative integer"
        )
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise AdaptiveAttentionEvaluationError(
            f"{field} must be a boolean"
        )
    return value


def _ids(values: Iterable[Any], field: str) -> tuple[str, ...]:
    result = tuple(sorted({_identity(value, field) for value in values}))
    return result


def _cell_id(graph: bool, attention: bool) -> str:
    return f"G{int(graph)}A{int(attention)}"


@dataclass(frozen=True, slots=True)
class BlindedRunCell:
    opaque_run_token: str
    opaque_case_token: str
    seed_token: str
    cell_id: str
    graph_enabled: bool
    attention_enabled: bool
    budget_regime: str
    source_snapshot_digest: str
    config_digest: str
    methodology_digest: str
    graph_treatment_digest: str
    backend_capability_label: str
    candidate_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    semantic_channel_grants: tuple[
        tuple[str, tuple[int, int, int, int, int]], ...
    ]
    graph_attributable_removed_candidate_ids: tuple[str, ...]
    graph_attributable_removed_evidence_ids: tuple[str, ...]
    reserved_attention_units: int
    reserved_input_tokens: int
    reserved_output_tokens: int
    reserved_tool_invocations: int
    reserved_timeout_slots: int
    bundle_digest: str
    containment_ok: bool
    resume_integrity_ok: bool
    clean_assurance_claim_allowed: bool
    record_digest: str

    @classmethod
    def create(
        cls,
        *,
        opaque_run_token: str,
        opaque_case_token: str,
        seed_token: str,
        graph_enabled: bool,
        attention_enabled: bool,
        budget_regime: str,
        source_snapshot_digest: str,
        config_digest: str,
        methodology_digest: str,
        graph_treatment_digest: str,
        backend_capability_label: str,
        candidate_ids: Iterable[str],
        evidence_ids: Iterable[str],
        reserved_attention_units: int,
        reserved_input_tokens: int,
        reserved_output_tokens: int,
        reserved_tool_invocations: int,
        reserved_timeout_slots: int,
        bundle_digest: str,
        containment_ok: bool,
        resume_integrity_ok: bool,
        clean_assurance_claim_allowed: bool,
        semantic_channel_grants: Mapping[
            str, Iterable[int]
        ] | None = None,
        graph_attributable_removed_candidate_ids: Iterable[str] = (),
        graph_attributable_removed_evidence_ids: Iterable[str] = (),
    ) -> "BlindedRunCell":
        graph = _boolean(graph_enabled, "graph_enabled")
        attention = _boolean(
            attention_enabled, "attention_enabled"
        )
        regime = _text(budget_regime, "budget_regime").upper()
        if regime not in _BUDGET_REGIMES:
            raise AdaptiveAttentionEvaluationError(
                "unsupported budget regime"
            )
        grants: list[tuple[str, tuple[int, int, int, int, int]]] = []
        for channel_id, raw_grant in (
            semantic_channel_grants or {}
        ).items():
            grant = tuple(
                _count(item, "semantic channel grant")
                for item in raw_grant
            )
            if len(grant) != 5:
                raise AdaptiveAttentionEvaluationError(
                    "semantic channel grant needs AU/input/output/tool/"
                    "timeout values"
                )
            grants.append(
                (_identity(channel_id, "channel_semantic_id"), grant)
            )
        normalized_grants = tuple(sorted(grants))
        if len({identity for identity, _grant in normalized_grants}) != (
            len(normalized_grants)
        ):
            raise AdaptiveAttentionEvaluationError(
                "semantic channel grants contain duplicate identities"
            )
        payload = {
            "schema_version": BLINDED_RUN_CELL_SCHEMA,
            "opaque_run_token": _opaque(
                opaque_run_token, "opaque_run_token"
            ),
            "opaque_case_token": _opaque(
                opaque_case_token, "opaque_case_token"
            ),
            "seed_token": _opaque(seed_token, "seed_token"),
            "cell_id": _cell_id(graph, attention),
            "graph_enabled": graph,
            "attention_enabled": attention,
            "budget_regime": regime,
            "source_snapshot_digest": _sha256(
                source_snapshot_digest, "source_snapshot_digest"
            ),
            "config_digest": _sha256(config_digest, "config_digest"),
            "methodology_digest": _sha256(
                methodology_digest, "methodology_digest"
            ),
            "graph_treatment_digest": _sha256(
                graph_treatment_digest, "graph_treatment_digest"
            ),
            "backend_capability_label": _opaque(
                backend_capability_label, "backend_capability_label"
            ),
            "candidate_ids": list(_ids(candidate_ids, "candidate_id")),
            "evidence_ids": list(_ids(evidence_ids, "evidence_id")),
            "semantic_channel_grants": [
                [identity, list(grant)]
                for identity, grant in normalized_grants
            ],
            "graph_attributable_removed_candidate_ids": list(
                _ids(
                    graph_attributable_removed_candidate_ids,
                    "graph-attributable removed candidate",
                )
            ),
            "graph_attributable_removed_evidence_ids": list(
                _ids(
                    graph_attributable_removed_evidence_ids,
                    "graph-attributable removed evidence",
                )
            ),
            "reserved_attention_units": _count(
                reserved_attention_units, "reserved_attention_units"
            ),
            "reserved_input_tokens": _count(
                reserved_input_tokens, "reserved_input_tokens"
            ),
            "reserved_output_tokens": _count(
                reserved_output_tokens, "reserved_output_tokens"
            ),
            "reserved_tool_invocations": _count(
                reserved_tool_invocations,
                "reserved_tool_invocations",
            ),
            "reserved_timeout_slots": _count(
                reserved_timeout_slots, "reserved_timeout_slots"
            ),
            "bundle_digest": _sha256(bundle_digest, "bundle_digest"),
            "containment_ok": _boolean(
                containment_ok, "containment_ok"
            ),
            "resume_integrity_ok": _boolean(
                resume_integrity_ok, "resume_integrity_ok"
            ),
            "clean_assurance_claim_allowed": _boolean(
                clean_assurance_claim_allowed,
                "clean_assurance_claim_allowed",
            ),
        }
        return cls(
            record_digest=digest_json(payload),
            **{
                key: (
                    tuple(value)
                    if key
                    in {
                        "candidate_ids",
                        "evidence_ids",
                        "graph_attributable_removed_candidate_ids",
                        "graph_attributable_removed_evidence_ids",
                    }
                    else normalized_grants
                    if key == "semantic_channel_grants"
                    else value
                )
                for key, value in payload.items()
                if key != "schema_version"
            },
        )

    def reservation_tuple(self) -> tuple[int, ...]:
        return (
            self.reserved_attention_units,
            self.reserved_input_tokens,
            self.reserved_output_tokens,
            self.reserved_tool_invocations,
            self.reserved_timeout_slots,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": BLINDED_RUN_CELL_SCHEMA,
            "opaque_run_token": self.opaque_run_token,
            "opaque_case_token": self.opaque_case_token,
            "seed_token": self.seed_token,
            "cell_id": self.cell_id,
            "graph_enabled": self.graph_enabled,
            "attention_enabled": self.attention_enabled,
            "budget_regime": self.budget_regime,
            "source_snapshot_digest": self.source_snapshot_digest,
            "config_digest": self.config_digest,
            "methodology_digest": self.methodology_digest,
            "graph_treatment_digest": self.graph_treatment_digest,
            "backend_capability_label": self.backend_capability_label,
            "candidate_ids": list(self.candidate_ids),
            "evidence_ids": list(self.evidence_ids),
            "semantic_channel_grants": [
                [identity, list(grant)]
                for identity, grant in self.semantic_channel_grants
            ],
            "graph_attributable_removed_candidate_ids": list(
                self.graph_attributable_removed_candidate_ids
            ),
            "graph_attributable_removed_evidence_ids": list(
                self.graph_attributable_removed_evidence_ids
            ),
            "reserved_attention_units": self.reserved_attention_units,
            "reserved_input_tokens": self.reserved_input_tokens,
            "reserved_output_tokens": self.reserved_output_tokens,
            "reserved_tool_invocations": (
                self.reserved_tool_invocations
            ),
            "reserved_timeout_slots": self.reserved_timeout_slots,
            "bundle_digest": self.bundle_digest,
            "containment_ok": self.containment_ok,
            "resume_integrity_ok": self.resume_integrity_ok,
            "clean_assurance_claim_allowed": (
                self.clean_assurance_claim_allowed
            ),
            "record_digest": self.record_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BlindedRunCell":
        validate_public_adaptive_run_record(value)
        kwargs = {
            key: item
            for key, item in value.items()
            if key
            not in {"schema_version", "cell_id", "record_digest"}
        }
        kwargs["semantic_channel_grants"] = {
            item[0]: item[1]
            for item in value["semantic_channel_grants"]
        }
        replayed = cls.create(
            **kwargs
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionEvaluationError(
                "blinded run cell content does not replay"
            )
        return replayed


def validate_public_adaptive_run_record(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the closed public schema; private grader fields are impossible."""

    if not isinstance(value, Mapping):
        raise TypeError("public adaptive run record must be an object")
    if set(value) != _PUBLIC_FIELDS:
        raise AdaptiveAttentionEvaluationError(
            "public adaptive run record has missing or forbidden fields"
        )
    if value["schema_version"] != BLINDED_RUN_CELL_SCHEMA:
        raise AdaptiveAttentionEvaluationError(
            "unsupported public adaptive run record schema"
        )
    graph = _boolean(value["graph_enabled"], "graph_enabled")
    attention = _boolean(
        value["attention_enabled"], "attention_enabled"
    )
    if value["cell_id"] != _cell_id(graph, attention):
        raise AdaptiveAttentionEvaluationError(
            "public adaptive cell identity does not replay"
        )
    for key in (
        "opaque_run_token",
        "opaque_case_token",
        "seed_token",
        "backend_capability_label",
    ):
        _opaque(value[key], key)
    for key in (
        "source_snapshot_digest",
        "config_digest",
        "methodology_digest",
        "graph_treatment_digest",
        "bundle_digest",
        "record_digest",
    ):
        _sha256(value[key], key)
    for key in (
        "reserved_attention_units",
        "reserved_input_tokens",
        "reserved_output_tokens",
        "reserved_tool_invocations",
        "reserved_timeout_slots",
    ):
        _count(value[key], key)
    for key in (
        "containment_ok",
        "resume_integrity_ok",
        "clean_assurance_claim_allowed",
    ):
        _boolean(value[key], key)
    regime = _text(value["budget_regime"], "budget_regime").upper()
    if regime not in _BUDGET_REGIMES:
        raise AdaptiveAttentionEvaluationError(
            "unsupported budget regime"
        )
    _ids(value["candidate_ids"], "candidate_id")
    _ids(value["evidence_ids"], "evidence_id")
    if value["candidate_ids"] != sorted(set(value["candidate_ids"])):
        raise AdaptiveAttentionEvaluationError(
            "candidate identities are not canonical and unique"
        )
    if value["evidence_ids"] != sorted(set(value["evidence_ids"])):
        raise AdaptiveAttentionEvaluationError(
            "evidence identities are not canonical and unique"
        )
    raw_grants = value["semantic_channel_grants"]
    if not isinstance(raw_grants, list):
        raise AdaptiveAttentionEvaluationError(
            "semantic_channel_grants must be an array"
        )
    grants = []
    for item in raw_grants:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[1], list)
            or len(item[1]) != 5
        ):
            raise AdaptiveAttentionEvaluationError(
                "semantic channel grant is malformed"
            )
        grants.append(
            (
                _identity(item[0], "channel_semantic_id"),
                tuple(
                    _count(part, "semantic channel grant")
                    for part in item[1]
                ),
            )
        )
    if grants != sorted(grants) or len(
        {identity for identity, _grant in grants}
    ) != len(grants):
        raise AdaptiveAttentionEvaluationError(
            "semantic channel grants are not canonical and unique"
        )
    for field in (
        "graph_attributable_removed_candidate_ids",
        "graph_attributable_removed_evidence_ids",
    ):
        raw_ids = value[field]
        normalized = list(_ids(raw_ids, field))
        if raw_ids != normalized:
            raise AdaptiveAttentionEvaluationError(
                f"{field} is not canonical and unique"
            )
    payload = dict(value)
    record_digest = payload.pop("record_digest")
    if digest_json(payload) != record_digest:
        raise AdaptiveAttentionEvaluationError(
            "public adaptive run record digest does not replay"
        )
    return dict(value)


@dataclass(frozen=True, slots=True)
class BlindedAdaptiveGrade:
    cell: BlindedRunCell
    ground_truth_root_causes: int
    confirmed_root_causes: int
    ground_truth_high_root_causes: int
    confirmed_high_root_causes: int
    methodology_steps_total: int
    methodology_steps_applied: int
    found_then_lost_count: int
    unauthorized_negative_count: int
    omitted_debt_count: int
    verifier_checked_count: int
    verifier_confirmed_count: int
    overlap_attention_units: int
    unsupported_negative_reopen_count: int
    report_rows_total: int
    report_rows_correct: int
    severity_rows_total: int
    severity_rows_correct: int
    grade_digest: str

    @classmethod
    def create(
        cls,
        *,
        cell: BlindedRunCell,
        ground_truth_root_causes: int,
        confirmed_root_causes: int,
        ground_truth_high_root_causes: int,
        confirmed_high_root_causes: int,
        methodology_steps_total: int,
        methodology_steps_applied: int,
        found_then_lost_count: int,
        unauthorized_negative_count: int,
        omitted_debt_count: int,
        verifier_checked_count: int,
        verifier_confirmed_count: int,
        overlap_attention_units: int,
        unsupported_negative_reopen_count: int,
        report_rows_total: int,
        report_rows_correct: int,
        severity_rows_total: int,
        severity_rows_correct: int,
    ) -> "BlindedAdaptiveGrade":
        cell = BlindedRunCell.from_dict(cell.to_dict())
        names = (
            "ground_truth_root_causes",
            "confirmed_root_causes",
            "ground_truth_high_root_causes",
            "confirmed_high_root_causes",
            "methodology_steps_total",
            "methodology_steps_applied",
            "found_then_lost_count",
            "unauthorized_negative_count",
            "omitted_debt_count",
            "verifier_checked_count",
            "verifier_confirmed_count",
            "overlap_attention_units",
            "unsupported_negative_reopen_count",
            "report_rows_total",
            "report_rows_correct",
            "severity_rows_total",
            "severity_rows_correct",
        )
        raw = locals()
        metrics = {name: _count(raw[name], name) for name in names}
        bounded_pairs = (
            ("confirmed_root_causes", "ground_truth_root_causes"),
            (
                "confirmed_high_root_causes",
                "ground_truth_high_root_causes",
            ),
            ("methodology_steps_applied", "methodology_steps_total"),
            ("verifier_confirmed_count", "verifier_checked_count"),
            ("report_rows_correct", "report_rows_total"),
            ("severity_rows_correct", "severity_rows_total"),
        )
        if any(metrics[left] > metrics[right] for left, right in bounded_pairs):
            raise AdaptiveAttentionEvaluationError(
                "private grade numerator exceeds its denominator"
            )
        payload = {
            "schema_version": BLINDED_GRADE_SCHEMA,
            "run_record_digest": cell.record_digest,
            **metrics,
        }
        return cls(
            cell=cell,
            grade_digest=digest_json(payload),
            **metrics,
        )

    def recall(self) -> float:
        return _ratio(
            self.confirmed_root_causes, self.ground_truth_root_causes
        )

    def high_recall(self) -> float:
        return _ratio(
            self.confirmed_high_root_causes,
            self.ground_truth_high_root_causes,
        )

    def methodology_completeness(self) -> float:
        return _ratio(
            self.methodology_steps_applied,
            self.methodology_steps_total,
        )

    def verifier_yield_per_au(self) -> float:
        return _ratio(
            self.verifier_confirmed_count,
            max(1, self.cell.reserved_attention_units),
        )

    def report_accuracy(self) -> float:
        return _ratio(self.report_rows_correct, self.report_rows_total)

    def severity_accuracy(self) -> float:
        return _ratio(
            self.severity_rows_correct, self.severity_rows_total
        )

    def replay(self) -> "BlindedAdaptiveGrade":
        replayed = type(self).create(
            **{
                field: getattr(self, field)
                for field in self.__dataclass_fields__
                if field != "grade_digest"
            }
        )
        if replayed != self:
            raise AdaptiveAttentionEvaluationError(
                "private blinded grade content does not replay"
            )
        return replayed


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0 if numerator == 0 else 0.0
    return numerator / denominator


def _mean(values: Iterable[float]) -> float:
    rows = tuple(values)
    return sum(rows) / len(rows) if rows else 0.0


def _bootstrap_ci(
    values: Iterable[float],
    *,
    samples: int = 2_000,
    seed: int = 0xA771,
) -> tuple[float, float]:
    rows = tuple(values)
    if not rows:
        return (0.0, 0.0)
    if len(rows) == 1:
        return (rows[0], rows[0])
    rng = random.Random(seed)
    means = sorted(
        _mean(rows[rng.randrange(len(rows))] for _ in rows)
        for _ in range(samples)
    )
    return (
        means[math.floor(0.025 * (samples - 1))],
        means[math.floor(0.975 * (samples - 1))],
    )


@dataclass(frozen=True, slots=True)
class AdaptiveAttentionEvaluation:
    complete_2x2: bool
    cell_ids: tuple[str, ...]
    group_count: int
    case_count: int
    attention_recall_delta_by_graph: dict[str, float]
    attention_recall_ci_by_graph: dict[
        str, tuple[float, float]
    ]
    methodology_delta_by_graph: dict[str, float]
    graph_recall_delta_by_attention: dict[str, float]
    interaction_recall_delta: float
    absolute_failures: tuple[str, ...]
    quantitative_failures: tuple[str, ...]
    held_out_acceptance_ready: bool
    verdict: str
    evaluation_digest: str


def evaluate_adaptive_attention_2x2(
    grades: Iterable[BlindedAdaptiveGrade],
) -> AdaptiveAttentionEvaluation:
    """Evaluate exact paired cells without exposing private case identities."""

    rows = tuple(grade.replay() for grade in grades)
    if not rows:
        raise AdaptiveAttentionEvaluationError(
            "2x2 evaluation requires graded cells"
        )
    run_tokens = [row.cell.opaque_run_token for row in rows]
    if len(set(run_tokens)) != len(run_tokens):
        raise AdaptiveAttentionEvaluationError(
            "2x2 evaluation contains duplicate run tokens"
        )
    groups: dict[
        tuple[str, str, str, str], dict[str, BlindedAdaptiveGrade]
    ] = {}
    for row in rows:
        cell = row.cell
        key = (
            cell.opaque_case_token,
            cell.seed_token,
            cell.budget_regime,
            cell.backend_capability_label,
        )
        matrix = groups.setdefault(key, {})
        if cell.cell_id in matrix:
            raise AdaptiveAttentionEvaluationError(
                "2x2 group contains a duplicate cell"
            )
        matrix[cell.cell_id] = row
    expected_cells = {"G0A0", "G1A0", "G0A1", "G1A1"}
    incomplete = [
        key for key, matrix in groups.items()
        if set(matrix) != expected_cells
    ]
    if incomplete:
        raise AdaptiveAttentionEvaluationError(
            "every blinded denominator needs the exact 2x2 cells"
        )
    absolute: set[str] = set()
    quantitative: set[str] = set()
    for row in rows:
        if not row.cell.containment_ok:
            absolute.add("CONTAINMENT_FAILURE")
        if not row.cell.resume_integrity_ok:
            absolute.add("RESUME_INTEGRITY_FAILURE")
        if row.found_then_lost_count:
            absolute.add("FOUND_THEN_LOST")
        if row.unauthorized_negative_count:
            absolute.add("UNAUTHORIZED_NEGATIVE")
        if row.omitted_debt_count:
            absolute.add("OMITTED_DEBT")
    attention_recall_deltas: dict[str, list[float]] = {
        "G0": [],
        "G1": [],
    }
    attention_high_deltas: dict[str, list[float]] = {
        "G0": [],
        "G1": [],
    }
    methodology_deltas: dict[str, list[float]] = {"G0": [], "G1": []}
    verifier_deltas: dict[str, list[float]] = {"G0": [], "G1": []}
    report_deltas: dict[str, list[float]] = {"G0": [], "G1": []}
    severity_deltas: dict[str, list[float]] = {"G0": [], "G1": []}
    graph_deltas: dict[str, list[float]] = {"A0": [], "A1": []}
    interactions: list[float] = []
    for matrix in groups.values():
        cells = tuple(matrix.values())
        snapshots = {row.cell.source_snapshot_digest for row in cells}
        methods = {row.cell.methodology_digest for row in cells}
        if len(snapshots) != 1 or len(methods) != 1:
            absolute.add("EXPERIMENT_BINDING_MISMATCH")
        if cells[0].cell.budget_regime == "MATCHED_TOTAL":
            if len(
                {row.cell.reservation_tuple() for row in cells}
            ) != 1:
                absolute.add("MATCHED_TOTAL_RESERVATION_MISMATCH")
        else:
            grant_maps = [
                dict(row.cell.semantic_channel_grants)
                for row in cells
            ]
            if any(not grants for grants in grant_maps):
                absolute.add("MATCHED_PER_CHANNEL_GRANTS_MISSING")
            shared = set.intersection(
                *(set(grants) for grants in grant_maps)
            ) if grant_maps else set()
            if any(
                len({grants[channel_id] for grants in grant_maps}) != 1
                for channel_id in shared
            ):
                absolute.add("MATCHED_PER_CHANNEL_GRANT_MISMATCH")
        for attention in (0, 1):
            off = matrix[f"G0A{attention}"]
            on = matrix[f"G1A{attention}"]
            removed_candidates = set(
                on.cell.graph_attributable_removed_candidate_ids
            )
            removed_evidence = set(
                on.cell.graph_attributable_removed_evidence_ids
            )
            if not removed_candidates <= (
                set(off.cell.candidate_ids)
                - set(on.cell.candidate_ids)
            ) or not removed_evidence <= (
                set(off.cell.evidence_ids) - set(on.cell.evidence_ids)
            ):
                absolute.add("GRAPH_REMOVAL_ATTESTATION_INVALID")
            if removed_candidates:
                absolute.add("GRAPH_DERIVED_CANDIDATE_REMOVAL")
            if removed_evidence:
                absolute.add("GRAPH_DERIVED_EVIDENCE_REMOVAL")
            graph_deltas[f"A{attention}"].append(
                on.recall() - off.recall()
            )
        for graph in (0, 1):
            fixed = matrix[f"G{graph}A0"]
            adaptive = matrix[f"G{graph}A1"]
            key = f"G{graph}"
            attention_recall_deltas[key].append(
                adaptive.recall() - fixed.recall()
            )
            attention_high_deltas[key].append(
                adaptive.high_recall() - fixed.high_recall()
            )
            methodology_deltas[key].append(
                adaptive.methodology_completeness()
                - fixed.methodology_completeness()
            )
            verifier_deltas[key].append(
                adaptive.verifier_yield_per_au()
                - fixed.verifier_yield_per_au()
            )
            report_deltas[key].append(
                adaptive.report_accuracy() - fixed.report_accuracy()
            )
            severity_deltas[key].append(
                adaptive.severity_accuracy()
                - fixed.severity_accuracy()
            )
            if (
                adaptive.unsupported_negative_reopen_count
                > fixed.unsupported_negative_reopen_count
            ):
                quantitative.add(
                    "UNSUPPORTED_NEGATIVE_REOPEN_REGRESSION"
                )
            if fixed.overlap_attention_units > 0 and (
                adaptive.overlap_attention_units
                > 0.85 * fixed.overlap_attention_units
            ):
                quantitative.add("OVERLAP_REDUCTION_GATE_FAILED")
        interactions.append(
            (
                matrix["G1A1"].recall() - matrix["G1A0"].recall()
            )
            - (
                matrix["G0A1"].recall() - matrix["G0A0"].recall()
            )
        )
    for graph in ("G0", "G1"):
        recall_mean = _mean(attention_recall_deltas[graph])
        recall_ci = _bootstrap_ci(attention_recall_deltas[graph])
        if recall_mean < 0 or recall_ci[0] < -0.02:
            quantitative.add("ADAPTIVE_RECALL_REGRESSION_" + graph)
        if _mean(attention_high_deltas[graph]) < 0:
            quantitative.add("ADAPTIVE_HIGH_RECALL_REGRESSION_" + graph)
        methodology_ci = _bootstrap_ci(methodology_deltas[graph])
        if (
            _mean(methodology_deltas[graph]) < 0.03
            or methodology_ci[0] < 0
        ):
            quantitative.add(
                "METHODOLOGY_COMPLETENESS_GATE_FAILED_" + graph
            )
        if _mean(verifier_deltas[graph]) < 0:
            quantitative.add("VERIFIER_YIELD_REGRESSION_" + graph)
        if _mean(report_deltas[graph]) < -0.01:
            quantitative.add("REPORT_ACCURACY_REGRESSION_" + graph)
        if _mean(severity_deltas[graph]) < -0.01:
            quantitative.add("SEVERITY_ACCURACY_REGRESSION_" + graph)
    for attention in ("A0", "A1"):
        graph_ci = _bootstrap_ci(graph_deltas[attention])
        if (
            _mean(graph_deltas[attention]) < 0
            or graph_ci[0] < -0.02
        ):
            quantitative.add("GRAPH_RECALL_REGRESSION_" + attention)
    verdict = "BLOCK" if absolute or quantitative else "PASS"
    cases = {
        row.cell.opaque_case_token for row in rows
    }
    attention_means = {
        key: _mean(values)
        for key, values in attention_recall_deltas.items()
    }
    attention_cis = {
        key: _bootstrap_ci(values)
        for key, values in attention_recall_deltas.items()
    }
    methodology_means = {
        key: _mean(values)
        for key, values in methodology_deltas.items()
    }
    graph_means = {
        key: _mean(values) for key, values in graph_deltas.items()
    }
    digest_payload = {
        "schema_version": EVALUATION_SCHEMA,
        "run_record_digests": sorted(
            row.cell.record_digest for row in rows
        ),
        "grade_digests": sorted(row.grade_digest for row in rows),
        "group_count": len(groups),
        "case_count": len(cases),
        "attention_recall_delta_by_graph": attention_means,
        "attention_recall_ci_by_graph": attention_cis,
        "methodology_delta_by_graph": methodology_means,
        "graph_recall_delta_by_attention": graph_means,
        "interaction_recall_delta": _mean(interactions),
        "absolute_failures": sorted(absolute),
        "quantitative_failures": sorted(quantitative),
        "verdict": verdict,
    }
    return AdaptiveAttentionEvaluation(
        complete_2x2=True,
        cell_ids=("G0A0", "G0A1", "G1A0", "G1A1"),
        group_count=len(groups),
        case_count=len(cases),
        attention_recall_delta_by_graph=attention_means,
        attention_recall_ci_by_graph=attention_cis,
        methodology_delta_by_graph=methodology_means,
        graph_recall_delta_by_attention=graph_means,
        interaction_recall_delta=_mean(interactions),
        absolute_failures=tuple(sorted(absolute)),
        quantitative_failures=tuple(sorted(quantitative)),
        held_out_acceptance_ready=(
            len(cases) >= 12 and len(groups) >= 12 * 3
        ),
        verdict=verdict,
        evaluation_digest=digest_json(digest_payload),
    )


__all__ = [
    "AdaptiveAttentionEvaluation",
    "AdaptiveAttentionEvaluationError",
    "BlindedAdaptiveGrade",
    "BlindedRunCell",
    "evaluate_adaptive_attention_2x2",
    "validate_public_adaptive_run_record",
]
