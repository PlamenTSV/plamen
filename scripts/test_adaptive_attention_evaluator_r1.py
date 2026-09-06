"""Fixture-first contracts for the offline blinded Adaptive Attention evaluator."""
from __future__ import annotations

from pathlib import Path

import pytest

from adaptive_attention_evaluator import (
    AdaptiveAttentionEvaluationError,
    BlindedAdaptiveGrade,
    BlindedRunCell,
    evaluate_adaptive_attention_2x2,
    validate_public_adaptive_run_record,
)


H1 = "1" * 64
H2 = "2" * 64


def _cell(
    graph: bool,
    attention: bool,
    *,
    case: str = "CASE-OPAQUE-001",
    seed: str = "SEED-001",
    budget_regime: str = "MATCHED_TOTAL",
    reserved_au: int = 10,
    candidates: tuple[str, ...] = ("CAND-001",),
    graph_removed_candidates: tuple[str, ...] = (),
) -> BlindedRunCell:
    return BlindedRunCell.create(
        opaque_run_token=(
            f"RUN-{'G1' if graph else 'G0'}"
            f"{'A1' if attention else 'A0'}-{seed}"
        ),
        opaque_case_token=case,
        seed_token=seed,
        graph_enabled=graph,
        attention_enabled=attention,
        budget_regime=budget_regime,
        source_snapshot_digest=H1,
        config_digest=H2,
        methodology_digest=H1,
        graph_treatment_digest=H2 if graph else H1,
        backend_capability_label="opus-class",
        candidate_ids=candidates,
        evidence_ids=("EVID-001",),
        reserved_attention_units=reserved_au,
        reserved_input_tokens=100,
        reserved_output_tokens=20,
        reserved_tool_invocations=10,
        reserved_timeout_slots=1,
        bundle_digest=(
            f"{int(graph)}{int(attention)}".ljust(64, "a")
        ),
        containment_ok=True,
        resume_integrity_ok=True,
        clean_assurance_claim_allowed=False,
        graph_attributable_removed_candidate_ids=(
            graph_removed_candidates
        ),
    )


def _grade(cell: BlindedRunCell, *, improvement: int = 0):
    attention_bonus = improvement if cell.attention_enabled else 0
    return BlindedAdaptiveGrade.create(
        cell=cell,
        ground_truth_root_causes=10,
        confirmed_root_causes=6 + attention_bonus,
        ground_truth_high_root_causes=4,
        confirmed_high_root_causes=3 + min(attention_bonus, 1),
        methodology_steps_total=100,
        methodology_steps_applied=80 + 4 * int(cell.attention_enabled),
        found_then_lost_count=0,
        unauthorized_negative_count=0,
        omitted_debt_count=0,
        verifier_checked_count=10,
        verifier_confirmed_count=6 + attention_bonus,
        overlap_attention_units=4 - 2 * int(cell.attention_enabled),
        unsupported_negative_reopen_count=0,
        report_rows_total=10,
        report_rows_correct=9,
        severity_rows_total=10,
        severity_rows_correct=9,
    )


def _matrix(*, improvement: int = 1):
    cells = (
        _cell(False, False),
        _cell(True, False),
        _cell(False, True),
        _cell(True, True),
    )
    return tuple(
        _grade(cell, improvement=improvement) for cell in cells
    )


def _regrade(
    grade: BlindedAdaptiveGrade, **changes
) -> BlindedAdaptiveGrade:
    values = {
        field: getattr(grade, field)
        for field in grade.__dataclass_fields__
        if field != "grade_digest"
    }
    values.update(changes)
    return BlindedAdaptiveGrade.create(**values)


def test_exact_2x2_cells_are_required_and_graph_attention_are_independent():
    result = evaluate_adaptive_attention_2x2(_matrix())
    assert result.complete_2x2 is True
    assert result.cell_ids == ("G0A0", "G0A1", "G1A0", "G1A1")
    assert result.verdict == "PASS"
    with pytest.raises(AdaptiveAttentionEvaluationError, match="2x2"):
        evaluate_adaptive_attention_2x2(_matrix()[:-1])


def test_matched_total_reservations_must_be_equal_before_launch():
    grades = list(_matrix())
    grades[-1] = _regrade(
        grades[-1], cell=_cell(True, True, reserved_au=11)
    )
    result = evaluate_adaptive_attention_2x2(grades)
    assert result.verdict == "BLOCK"
    assert "MATCHED_TOTAL_RESERVATION_MISMATCH" in result.absolute_failures


def test_graph_on_candidate_union_must_not_drop_graph_off_candidates():
    cells = (
        _cell(False, False, candidates=("CAND-001", "CAND-002")),
        _cell(
            True,
            False,
            candidates=("CAND-001",),
            graph_removed_candidates=("CAND-002",),
        ),
        _cell(False, True, candidates=("CAND-001", "CAND-002")),
        _cell(
            True,
            True,
            candidates=("CAND-001",),
            graph_removed_candidates=("CAND-002",),
        ),
    )
    result = evaluate_adaptive_attention_2x2(
        tuple(_grade(cell, improvement=1) for cell in cells)
    )
    assert result.verdict == "BLOCK"
    assert "GRAPH_DERIVED_CANDIDATE_REMOVAL" in result.absolute_failures


def test_recall_regression_and_found_then_lost_are_release_blockers():
    grades = list(_matrix(improvement=-1))
    grades[1] = _regrade(grades[1], found_then_lost_count=1)
    result = evaluate_adaptive_attention_2x2(grades)
    assert result.verdict == "BLOCK"
    assert "FOUND_THEN_LOST" in result.absolute_failures
    assert result.attention_recall_delta_by_graph["G0"] < 0


def test_public_record_rejects_ground_truth_and_evaluator_fields():
    record = _cell(False, False).to_dict()
    validate_public_adaptive_run_record(record)
    for forbidden in (
        "ground_truth_path",
        "benchmark_name",
        "expected_findings",
        "private_evaluator_id",
    ):
        with pytest.raises(AdaptiveAttentionEvaluationError):
            validate_public_adaptive_run_record(
                {**record, forbidden: "secret"}
            )


def test_matched_per_channel_requires_public_exact_grants():
    cells = tuple(
        _cell(
            graph,
            attention,
            budget_regime="MATCHED_PER_SEMANTIC_CHANNEL",
        )
        for graph, attention in (
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        )
    )
    result = evaluate_adaptive_attention_2x2(
        tuple(_grade(cell, improvement=1) for cell in cells)
    )
    assert result.verdict == "BLOCK"
    assert "MATCHED_PER_CHANNEL_GRANTS_MISSING" in (
        result.absolute_failures
    )


def test_public_record_rejects_reordered_candidate_denominator():
    record = _cell(
        False, False, candidates=("CAND-001", "CAND-002")
    ).to_dict()
    record["candidate_ids"] = list(reversed(record["candidate_ids"]))
    record["record_digest"] = __import__(
        "adaptive_attention_types"
    ).digest_json(
        {
            key: value
            for key, value in record.items()
            if key != "record_digest"
        }
    )
    with pytest.raises(AdaptiveAttentionEvaluationError, match="canonical"):
        validate_public_adaptive_run_record(record)


def test_driver_never_imports_offline_evaluator():
    driver = (
        Path(__file__).resolve().parent / "plamen_driver.py"
    ).read_text(encoding="utf-8")
    assert "adaptive_attention_evaluator" not in driver
