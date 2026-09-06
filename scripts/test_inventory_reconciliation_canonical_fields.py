"""Canonical producer fields stay lossless through inventory reconciliation."""

from __future__ import annotations

from pathlib import Path

from inventory_reconciliation import (
    _canonical_blocks,
    _semantic_preservation_deltas,
    reconcile_inventory,
)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _canonical_finding(
    finding_id: str,
    *,
    source_ids: str = "",
    mechanism: str = "The unchecked branch preserves a stale balance.",
    harm: str = "Depositors lose their withdrawable balance.",
) -> str:
    source_line = (
        f"**Source IDs** (upstream candidate references): {source_ids}\n"
        if source_ids
        else ""
    )
    description_line = f"**Description**: {mechanism}\n" if mechanism else ""
    return (
        f"### Finding [{finding_id}]: Canonical template fixture\n\n"
        f"{source_line}"
        "**Severity**: High\n"
        "**Location**: src/Fixture.sol:L7\n"
        "**Root Cause**: The state update is incomplete.\n"
        "**Depth Evidence** (depth agents only): [TRACE:entry -> stale state -> exit]\n"
        f"{description_line}"
        f"**Material Harm** (MANDATORY): {harm}\n"
        "**Preconditions** (reachable branch): The affected balance is nonzero.\n"
    )


def test_literal_canonical_annotations_are_fields_and_lookahead_boundaries(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "analysis_fixture.md"
    _write(artifact, _canonical_finding("F-01", source_ids="B-01"))

    blocks, issues = _canonical_blocks(artifact)

    assert issues == []
    assert len(blocks) == 1
    block = blocks[0]
    assert block["source_ids"] == ["B-01"]
    assert block["root_cause"] == "The state update is incomplete."
    assert "Depth Evidence" not in block["root_cause"]
    assert block["description"] == "The unchecked branch preserves a stale balance."
    assert block["impact"] == "Depositors lose their withdrawable balance."
    assert block["preconditions"] == "The affected balance is nonzero."


def test_description_is_the_generic_mechanism_fallback(tmp_path: Path) -> None:
    artifact = tmp_path / "analysis_fixture.md"
    finding = _canonical_finding("F-01").replace(
        "**Root Cause**: The state update is incomplete.\n", ""
    )
    _write(artifact, finding)

    blocks, issues = _canonical_blocks(artifact)

    assert issues == []
    assert blocks[0]["root_cause"] == (
        "The unchecked branch preserves a stale balance."
    )

    candidate = {"source_root_cause": blocks[0]["root_cause"]}
    target = {
        "root_cause": "A differently worded synthesis.",
        "description": blocks[0]["description"],
        "impact": "",
        "preconditions": "",
    }
    assert "ROOT_CAUSE" not in _semantic_preservation_deltas(candidate, target)


def test_unparseable_mandatory_mechanism_is_explicit_reconciliation_debt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    raw = _canonical_finding("F-01", mechanism="").replace(
        "**Root Cause**: The state update is incomplete.\n", ""
    )
    target = _canonical_finding(
        "INV-001",
        source_ids="analysis_fixture.md:F-01",
        mechanism="A downstream writer supplied a mechanism.",
    )
    _write(scratchpad / "analysis_fixture.md", raw)
    _write(
        scratchpad / "inventory_chunk_a.manifest.md",
        "# Inventory shard\n\n| File |\n|---|\n| analysis_fixture.md |\n",
    )
    _write(scratchpad / "findings_inventory_chunk_a.md", target)
    _write(scratchpad / "findings_inventory.md", target)

    receipt = reconcile_inventory(scratchpad)

    assert receipt["denominator_count"] == 1
    row = receipt["candidates"][0]
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["reason_code"] == "FINAL_SEMANTIC_PRESERVATION_DEBT"
    assert "UNPARSEABLE_ROOT_CAUSE" in row["required_preservation_axes"]
    assert row["mandatory_reverification"] is True
    assert row["mandatory_reverification_id"]


def test_unparseable_mandatory_harm_is_explicit_reconciliation_debt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    raw = _canonical_finding("F-01", harm="").replace(
        "**Material Harm** (MANDATORY): \n", ""
    )
    target = _canonical_finding(
        "INV-001",
        source_ids="analysis_fixture.md:F-01",
        harm="A downstream writer supplied a harm premise.",
    )
    _write(scratchpad / "analysis_fixture.md", raw)
    _write(
        scratchpad / "inventory_chunk_a.manifest.md",
        "# Inventory shard\n\n| File |\n|---|\n| analysis_fixture.md |\n",
    )
    _write(scratchpad / "findings_inventory_chunk_a.md", target)
    _write(scratchpad / "findings_inventory.md", target)

    receipt = reconcile_inventory(scratchpad)

    row = receipt["candidates"][0]
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["reason_code"] == "FINAL_SEMANTIC_PRESERVATION_DEBT"
    assert "UNPARSEABLE_IMPACT" in row["required_preservation_axes"]
    assert row["mandatory_reverification"] is True
