"""Report-tier identity coverage across the typed post-verify cutover."""
from __future__ import annotations

from pathlib import Path

from plamen_parsers import get_tier_assignments
from post_verify_candidate_delta import (
    write_or_validate_post_verify_candidate_delta,
)
from queue_work_items import QueueWorkItem, queue_records_to_json


RUN_ID = "tier-candidate-universe"


def _seed_typed_universe(root: Path) -> str:
    base = QueueWorkItem.from_legacy_row({
        "finding id": "INV-1",
        "severity": "High",
        "title": "Base candidate",
        "bug class": "STATE_TRANSITION",
        "preferred tag": "CODE-TRACE",
        "location": "src/Base.sol:10",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    })
    (root / "verification_queue.work_items.json").write_text(
        queue_records_to_json((base,)) + "\n",
        encoding="utf-8",
    )
    (root / "post_verify_extract.md").write_text(
        "# Post Verify Extract\n\n"
        "### Finding [VER-1]: Late candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Late.sol:20\n"
        "**Root Cause**: A late independent mechanism remains.\n"
        "**Impact**: A protected state transition may be violated.\n"
        "**Source Verify File**: verify_INV-1.md\n",
        encoding="utf-8",
    )
    (root / "verify_INV-1.md").write_text(
        "# Verification\n\n**Verdict**: CONFIRMED\n",
        encoding="utf-8",
    )
    payload = write_or_validate_post_verify_candidate_delta(
        root,
        run_id=RUN_ID,
        operator_proposals=(),
    )
    return str(payload["rows"][0]["work_item"]["work_item_id"])


def test_typed_count_complete_index_cannot_hide_late_candidate(
    tmp_path: Path,
) -> None:
    late_id = _seed_typed_universe(tmp_path)
    (tmp_path / "report_index.md").write_text(
        "## Summary Counts\n\n"
        "| Severity | Count |\n"
        "|---|---:|\n"
        "| High | 1 |\n"
        "| Medium | 0 |\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Internal Ref | Verify File |\n"
        "|---|---|---|\n"
        "| H-01 | INV-1 | verify_INV-1.md |\n",
        encoding="utf-8",
    )
    # Raw post-verification prose is proposal-only and must not become negative
    # authority or a severity decision.
    (tmp_path / f"verify_{late_id}.md").write_text(
        f"# Verification {late_id}\n\n"
        "**Verdict**: REFUTED\n"
        "**Severity**: Informational\n",
        encoding="utf-8",
    )
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        f"| Finding ID | Decision | Severity Change |\n"
        f"|---|---|---|\n"
        f"| {late_id} | DOWNGRADE | Medium -> Informational |\n",
        encoding="utf-8",
    )

    rows, source = get_tier_assignments(tmp_path)

    assert source == "merged"
    assert {row["finding_id"] for row in rows} == {"INV-1", late_id}
    late = next(row for row in rows if row["finding_id"] == late_id)
    assert late["severity"] == "M"


def test_legacy_count_complete_index_keeps_pre_cutover_semantics(
    tmp_path: Path,
) -> None:
    (tmp_path / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---|---|---|---|\n"
        "| 1 | INV-01 | High | active |\n"
        "| 2 | INV-02 | High | legacy excluded row |\n",
        encoding="utf-8",
    )
    (tmp_path / "report_index.md").write_text(
        "## Summary Counts\n\n"
        "| Severity | Count |\n"
        "|---|---:|\n"
        "| High | 1 |\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Internal Ref | Verify File |\n"
        "|---|---|---|\n"
        "| H-01 | INV-01 | verify_INV-01.md |\n\n"
        "## Excluded Findings\n\n"
        "| Report ID | Internal Ref | Reason |\n"
        "|---|---|---|\n"
        "| H-02 | INV-02 | FALSE_POSITIVE |\n",
        encoding="utf-8",
    )

    rows, source = get_tier_assignments(tmp_path)

    assert source == "index"
    assert [row["finding_id"] for row in rows] == ["INV-01"]
