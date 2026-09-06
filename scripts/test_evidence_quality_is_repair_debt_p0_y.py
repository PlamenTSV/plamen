"""P0-Y: weak evidence is repair debt, never producer-side deletion authority."""
from __future__ import annotations

from pathlib import Path

import pytest

from plamen_parsers import parse_verification_queue_rows
from plamen_validators import _filter_verification_queue_by_evidence


def _write_queue(scratchpad: Path) -> None:
    (scratchpad / "verification_queue.md").write_text(
        "# Verification Queue\n\n"
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---|---|---|---|\n"
        "| 1 | INV-001 | Low | substantive candidate |\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("location_status", "source_status"),
    (
        ("IDENTIFIER_UNVERIFIED", "OK"),
        ("LOCATION_NONPRODUCTION", "OK"),
        ("LOCATION_INVALID", "SOURCE_MISSING"),
        ("LOCATION_INVALID", "SOURCE_INVALID"),
    ),
)
def test_evidence_failures_remain_active_with_explicit_repair_debt(
    tmp_path: Path,
    location_status: str,
    source_status: str,
) -> None:
    _write_queue(tmp_path)
    (tmp_path / "inventory_evidence_validation.md").write_text(
        "# Inventory Evidence Validation\n\n"
        "| Finding ID | Location Status | Resolved Location | Location Reason | Source Status | Source Reason |\n"
        "|---|---|---|---|---|---|\n"
        f"| INV-001 | {location_status} | src/Maybe.sol:L9 | needs recovery | {source_status} | needs recovery |\n",
        encoding="utf-8",
    )

    removed = _filter_verification_queue_by_evidence(tmp_path)

    assert removed == []
    rows = parse_verification_queue_rows(tmp_path)
    assert [row["finding id"] for row in rows] == ["INV-001"]
    assert location_status in rows[0]["evidence debt"]
    assert source_status in rows[0]["evidence debt"]
    debt = (tmp_path / "verification_queue_evidence_debt.md").read_text(
        encoding="utf-8"
    )
    assert "INV-001" in debt
    assert "RETAINED_ACTIVE" in debt
    excluded = tmp_path / "verification_queue_evidence_excluded.md"
    assert not excluded.exists() or "INV-001" not in excluded.read_text(encoding="utf-8")


def test_good_evidence_does_not_create_debt(tmp_path: Path) -> None:
    _write_queue(tmp_path)
    (tmp_path / "inventory_evidence_validation.md").write_text(
        "| Finding ID | Location Status | Source Status |\n"
        "|---|---|---|\n"
        "| INV-001 | OK | OK |\n",
        encoding="utf-8",
    )

    assert _filter_verification_queue_by_evidence(tmp_path) == []
    rows = parse_verification_queue_rows(tmp_path)
    assert "evidence debt" not in rows[0] or not rows[0]["evidence debt"]
    debt = tmp_path / "verification_queue_evidence_debt.md"
    assert not debt.exists() or "INV-001" not in debt.read_text(encoding="utf-8")
