"""Recall-safety fixtures for mechanical report-index proposals.

Verifier prose and lexical similarity can nominate follow-up work, but neither
is identity-removal or negative-closure authority.  These tests deliberately
lock the report boundary to that rule.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import plamen_mechanical as M  # noqa: E402


def _queue(root: Path, rows: list[tuple[str, str, str, str]]) -> None:
    lines = [
        "# Verification Queue",
        "",
        "| Finding ID | Severity | Title | Location | Preferred Tag |",
        "|------------|----------|-------|----------|---------------|",
    ]
    lines.extend(
        f"| {fid} | {severity} | {title} | {location} | CODE-TRACE |"
        for fid, severity, title, location in rows
    )
    (root / "verification_queue.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _verify(root: Path, fid: str, *, verdict: str, title: str) -> None:
    (root / f"verify_{fid}.md").write_text(
        "\n".join(
            [
                f"# {fid}: {title}",
                f"**Verdict**: {verdict}",
                "**Severity**: High",
                f"**Location**: src/{fid}.sol:10",
                "**Evidence Tag**: CODE-TRACE",
                "**Description**: The candidate mechanism remains mechanically traceable and requires independent adjudication.",
                "**Impact**: If the candidate premise holds, the stated security boundary can be violated with material impact.",
                "**PoC Result**: A bounded execution did not establish exhaustive negation of every premise and guard.",
                "**Recommendation**: Resolve the exact premises and guards with independent evidence before changing disposition.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_refuted_verifier_prose_stays_active_at_upstream_tier_and_visible(tmp_path: Path) -> None:
    _queue(tmp_path, [("INV-001", "High", "Candidate with disputed harm", "src/F.sol:10")])
    _verify(
        tmp_path,
        "INV-001",
        verdict="REFUTED",
        title="Candidate with disputed harm",
    )

    assert M._write_mechanical_report_index(tmp_path) == 1
    payload = json.loads((tmp_path / "report_records.json").read_text(encoding="utf-8"))
    assert payload["excluded"] == []
    assert [row["finding_id"] for row in payload["active"]] == ["INV-001"]
    assert payload["active"][0]["severity"] == "High"
    assert payload["active"][0]["unresolved"] is True
    assert "UNPROVEN_NEGATIVE(REFUTED)" in payload["active"][0]["severity_adjustments"]
    assert [row["finding_id"] for row in payload["negative_disposition_proposals"]] == ["INV-001"]

    index = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    master, proposals = index.split(
        "## Proposed Negative Dispositions (Non-authoritative)", 1
    )
    assert "| H-01 |" in master and "INV-001" in master
    assert "INV-001" in proposals
    assert "## Excluded Findings" not in index

    assert M._write_mechanical_report_tier(tmp_path, "report_critical_high") == 1
    tier = (tmp_path / "report_critical_high.md").read_text(encoding="utf-8")
    assert "[H-01]" in tier
    assert "[UNRESOLVED - needs human review]" in tier
    assert "pending independent closure authority" in tier


def test_signature_cluster_is_proposal_and_preserves_every_identity(tmp_path: Path) -> None:
    rows = [
        ("INV-001", "High", "Missing boundary event", "src/A.sol:10"),
        ("INV-002", "High", "Missing boundary event", "src/B.sol:20"),
        ("INV-003", "High", "Missing boundary event", "src/C.sol:30"),
    ]
    _queue(tmp_path, rows)
    for fid, _severity, _title, _location in rows:
        (tmp_path / f"verify_{fid}.md").write_text(
            f"# {fid}\n"
            "**Verdict**: CONFIRMED\n"
            "**Severity**: High\n"
            "**Description**: Missing event emission on an administrative state change.\n"
            "**Recommendation**: Emit an event.\n",
            encoding="utf-8",
        )

    assert M._write_mechanical_report_index(tmp_path) == 3
    payload = json.loads((tmp_path / "report_records.json").read_text(encoding="utf-8"))
    assert [row["finding_id"] for row in payload["active"]] == [
        "INV-001",
        "INV-002",
        "INV-003",
    ]
    assert all(row["absorbed_finding_ids"] == [] for row in payload["active"])
    assert len(payload["consolidation_map"]) == 1
    assert payload["consolidation_map"][0]["authority_state"] == "PROPOSAL_ONLY"
    assert payload["consolidation_map"][0]["absorbed_finding_ids"] == [
        "INV-001",
        "INV-002",
        "INV-003",
    ]

    index = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    master, proposals = index.split(
        "## Proposed Consolidation Map (Non-authoritative)", 1
    )
    assert all(fid in master for fid in ("INV-001", "INV-002", "INV-003"))
    assert all(fid in proposals for fid in ("INV-001", "INV-002", "INV-003"))
