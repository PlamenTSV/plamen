"""Focused report-time candidate-universe cutover fixtures."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_mechanical as mechanical
from post_verify_candidate_delta import (
    PostVerifyCandidateDeltaError,
    write_or_validate_post_verify_candidate_delta,
)
from queue_work_items import QueueWorkItem, queue_records_to_json


RUN_ID = "mechanical-report-universe-cutover"


def _base_item() -> QueueWorkItem:
    return QueueWorkItem.from_legacy_row({
        "finding id": "BASE-1",
        "severity": "High",
        "title": "Base candidate",
        "bug class": "STATE_TRANSITION",
        "preferred tag": "CODE-TRACE",
        "location": "src/Base.sol:10",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    })


def _seed_typed_universe(root: Path) -> str:
    root.mkdir(parents=True, exist_ok=True)
    (root / "verification_queue.work_items.json").write_text(
        queue_records_to_json((_base_item(),)) + "\n",
        encoding="utf-8",
    )
    (root / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [BASE-1]: Base candidate\n"
        "**Severity**: High\n"
        "**Location**: src/Base.sol:10\n",
        encoding="utf-8",
    )
    (root / "post_verify_extract.md").write_text(
        "# Post Verify Extract\n\n"
        "### Finding [VER-1]: Late independent candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Late.sol:22\n"
        "**Root Cause**: A late boundary observation contradicts the transition.\n"
        "**Impact**: The protected state can diverge from its required value.\n"
        "**Source Verify File**: verify_BASE-1.md\n",
        encoding="utf-8",
    )
    (root / "verify_BASE-1.md").write_text(
        "# Base verifier artifact\n",
        encoding="utf-8",
    )
    payload = write_or_validate_post_verify_candidate_delta(
        root,
        run_id=RUN_ID,
        operator_proposals=(),
    )
    late_id = payload["rows"][0]["work_item"]["work_item_id"]
    # Raw negative prose is deliberately unreceipted.  It may create visible
    # review debt, but it must not remove the typed delta identity.
    (root / f"verify_{late_id}.md").write_text(
        "# Late verifier proposal\n\n"
        "**Verdict**: REFUTED\n"
        "**Reasoning**: proposal-only negative without typed closure authority.\n",
        encoding="utf-8",
    )
    (root / "skeptic_judge_decisions.md").write_text(
        "# Skeptic proposals\n\n"
        f"## {late_id}\n"
        "**Verdict**: UNRESOLVED\n"
        f"{late_id} Medium -> Low\n",
        encoding="utf-8",
    )
    return late_id


def _manifest_ids(manifests: dict[str, dict]) -> set[str]:
    return {
        str(row.get("finding_id") or "")
        for manifest in manifests.values()
        for row in manifest.get("findings", [])
        if row.get("finding_id")
    }


def test_typed_report_consumers_enumerate_base_plus_delta_without_raw_drop(
    tmp_path: Path,
) -> None:
    late_id = _seed_typed_universe(tmp_path)

    rows = mechanical._report_candidate_universe_rows(tmp_path)
    assert {row["finding id"] for row in rows} == {"BASE-1", late_id}

    assert mechanical._write_candidate_semantic_facets(tmp_path) == 2
    facets = json.loads(
        (tmp_path / "candidate_semantic_facets.json").read_text(encoding="utf-8")
    )
    assert {row["id"] for row in facets["candidates"]} == {"BASE-1", late_id}
    late_facets = next(row for row in facets["candidates"] if row["id"] == late_id)
    assert late_facets["location"] == "src/Late.sol:22"

    assert mechanical._write_mechanical_report_index(
        tmp_path,
        prepare_body=False,
        materialize_facets=False,
    ) == 2
    records = json.loads(
        (tmp_path / "report_records.json").read_text(encoding="utf-8")
    )
    active = {row["finding_id"]: row for row in records["active"]}
    assert set(active) == {"BASE-1", late_id}
    assert active[late_id]["severity"] == "Medium"
    assert active[late_id]["unresolved"] is True
    assert any(
        row["finding_id"] == late_id
        and row["verdict"] == "REFUTED"
        for row in records["negative_disposition_proposals"]
    )

    manifests = mechanical._build_sc_body_writer_manifests(
        tmp_path,
        persist=False,
        materialize_evidence=False,
    )
    assert _manifest_ids(manifests) == {"BASE-1", late_id}
    late_manifest = next(
        row
        for manifest in manifests.values()
        for row in manifest.get("findings", [])
        if row.get("finding_id") == late_id
    )
    assert late_manifest["location"] == "src/Late.sol:22"

    # Force the tier writer's metadata fallback instead of its report-records
    # fast path.  The late row must still be sourced from the typed universe.
    (tmp_path / "report_records.json").unlink()
    assert mechanical._write_mechanical_report_tier(
        tmp_path, "report_medium"
    ) == 1
    medium_body = (tmp_path / "report_medium.md").read_text(encoding="utf-8")
    assert "Late independent candidate" in medium_body
    assert "src/Late.sol:22" in medium_body

    repaired = mechanical._repair_report_body_from_assignments(
        "# Audit Report\n\n## Priority Remediation Order\n",
        tmp_path,
    )
    assert "Late independent candidate" in repaired


def test_legacy_report_consumers_preserve_markdown_base_only_parity(
    tmp_path: Path,
) -> None:
    (tmp_path / "verification_queue.md").write_text(
        "# Verification Queue\n\n"
        "| Finding ID | Severity | Title | Location | Preferred Tag |\n"
        "|------------|----------|-------|----------|---------------|\n"
        "| LEGACY-1 | Low | Legacy candidate | src/Legacy.sol:7 | CODE-TRACE |\n",
        encoding="utf-8",
    )

    expected = mechanical.parse_verification_queue_rows(tmp_path)
    rows = mechanical._report_candidate_universe_rows(tmp_path)
    assert rows == expected
    assert [row["finding id"] for row in rows] == ["LEGACY-1"]
    assert mechanical._write_candidate_semantic_facets(tmp_path) == 1
    assert mechanical._write_mechanical_report_index(
        tmp_path,
        prepare_body=False,
        materialize_facets=False,
    ) == 1
    records = json.loads(
        (tmp_path / "report_records.json").read_text(encoding="utf-8")
    )
    assert [row["finding_id"] for row in records["active"]] == ["LEGACY-1"]


def test_typed_cutover_rejects_invalid_authority_instead_of_markdown_fallback(
    tmp_path: Path,
) -> None:
    (tmp_path / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title |\n"
        "|------------|----------|-------|\n"
        "| LEGACY-ESCAPE | High | Must not be accepted |",
        encoding="utf-8",
    )
    (tmp_path / "verification_queue.work_items.json").write_text(
        '{"schema_version":"invalid"}\n',
        encoding="utf-8",
    )

    with pytest.raises(PostVerifyCandidateDeltaError):
        mechanical._report_candidate_universe_rows(tmp_path)
