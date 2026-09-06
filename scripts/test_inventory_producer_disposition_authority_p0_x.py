"""P0-X: inventory producers cannot exclude their own candidates."""
from __future__ import annotations

from pathlib import Path

import pytest

from plamen_parsers import _queue_rows_from_inventory_with_exclusions


@pytest.mark.parametrize(
    ("field", "value", "expected_origin"),
    (
        ("Verdict", "REFUTED", "REFUTED"),
        ("Final Verdict", "FALSE_POSITIVE", "FALSE_POSITIVE"),
        ("Verdict", "CLEAR (no finding)", "REFUTED"),
        ("Status", "CLEAR", "UNRESOLVED"),
    ),
)
def test_content_bearing_inventory_negative_remains_active_for_independent_review(
    tmp_path: Path,
    field: str,
    value: str,
    expected_origin: str,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-001]: Candidate requiring independent review\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L10\n"
        "**Description**: A substantive state-transition claim.\n"
        f"**{field}**: {value}\n",
        encoding="utf-8",
    )

    active, excluded = _queue_rows_from_inventory_with_exclusions(tmp_path)

    assert [row["finding id"] for row in active] == ["INV-001"]
    assert active[0]["origin assessment"] == expected_origin
    assert excluded == []


def test_absent_origin_assessment_preserves_existing_queue_shape(
    tmp_path: Path,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-001]: Ordinary candidate\n"
        "**Severity**: High\n"
        "**Location**: src/Module.sol:L10\n",
        encoding="utf-8",
    )
    active, excluded = _queue_rows_from_inventory_with_exclusions(tmp_path)
    assert len(active) == 1 and "origin assessment" not in active[0]
    assert excluded == []
