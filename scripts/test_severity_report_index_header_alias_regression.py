"""Regression for canonical report-index candidate identity headers."""
from __future__ import annotations

from pathlib import Path

import pytest

import severity_runtime


@pytest.mark.parametrize(
    "candidate_header",
    ("Internal Hypothesis", "Internal Hypothesis ID", "Source Findings"),
)
def test_shadow_projection_loader_preserves_canonical_candidate_mapping(
    tmp_path: Path,
    candidate_header: str,
) -> None:
    (tmp_path / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n\n"
        f"| Report ID | Title | Severity | {candidate_header} |\n"
        "|---|---|---|---|\n"
        "| L-01 | Candidate | Low | INV-1 |\n",
        encoding="utf-8",
        newline="",
    )

    assert severity_runtime._legacy_report_index_rows(tmp_path) == [
        {
            "report_id": "L-01",
            "candidate_id": "INV-1",
            "severity": "Low",
            "row_number": "7",
        }
    ]


def test_shadow_projection_loader_does_not_infer_identity_from_title(
    tmp_path: Path,
) -> None:
    (tmp_path / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Notes |\n"
        "|---|---|---|---|\n"
        "| L-01 | Candidate INV-1 | Low | retained |\n",
        encoding="utf-8",
        newline="",
    )

    assert severity_runtime._legacy_report_index_rows(tmp_path) == []
