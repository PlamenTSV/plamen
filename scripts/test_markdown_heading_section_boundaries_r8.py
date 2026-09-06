"""Fixture-first CommonMark heading/section authority regressions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import enumeration_gate as EG
import plamen_markdown
from enumgap_markdown import (
    enumgap_reference_heading_ids,
    parse_enumgap_exploration_findings,
)
from enumgap_disposition import _coverage_rows
from enumeration_gate import promote_axis_findings_to_inventory
from inventory_reconciliation import reconcile_inventory
from plamen_markdown import mapped_headings


@pytest.fixture(autouse=True)
def _reviewed_4_2_metadata_shim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise reviewed grammar semantics despite this host's 4.0 metadata."""

    monkeypatch.setattr(
        plamen_markdown,
        "runtime_markdown_it_version",
        lambda: plamen_markdown.REVIEWED_MARKDOWN_IT_VERSION,
    )


def _enumgap(heading: str) -> str:
    return (
        f"{heading} Finding [NEXP-1]: mapped candidate\n\n"
        "**Severity**: Low\n\n"
        "**Location**: src/Unit.sol:L1\n\n"
        "**Description**: concrete mechanism and harm remain.\n\n"
        "## Coverage Record\n\n"
        "**Description**: sibling metadata, not finding content.\n"
    )


@pytest.mark.parametrize("heading", ("   ##", "- ##", "> ##"))
def test_enumgap_discovery_and_reference_share_mapped_commonmark_heading(
    heading: str,
) -> None:
    source = _enumgap(heading)

    findings = parse_enumgap_exploration_findings(source)

    assert [row["id"] for row in findings] == ["NEXP-1"]
    assert enumgap_reference_heading_ids(source) == frozenset({"NEXP-1"})
    assert "Coverage Record" not in findings[0]["block"]


def test_non_commonmark_hash_run_cannot_create_discovery_reference_drift() -> None:
    source = _enumgap("##").replace("## Finding", "##Finding", 1)

    assert parse_enumgap_exploration_findings(source) == ()
    assert enumgap_reference_heading_ids(source) == frozenset()


@pytest.mark.parametrize(
    "heading",
    (
        "##",
        "###",
        "####",
        "  ##",
        "   ###",
        "- ####",
        "> ###",
    ),
)
def test_enumgap_accepts_only_mapped_h2_through_h4_headings(
    heading: str,
) -> None:
    source = _enumgap(heading)

    assert [row["id"] for row in parse_enumgap_exploration_findings(source)] == [
        "NEXP-1"
    ]
    assert enumgap_reference_heading_ids(source) == frozenset({"NEXP-1"})


@pytest.mark.parametrize("marks", ("#", "#####", "######"))
def test_enumgap_rejects_mapped_heading_levels_outside_h2_h4(
    marks: str,
) -> None:
    source = _enumgap(marks)

    assert parse_enumgap_exploration_findings(source) == ()
    assert enumgap_reference_heading_ids(source) == frozenset()


@pytest.mark.parametrize(
    "source",
    (
        "    ## Finding [NEXP-1]: code\n"
        "    **Severity**: Low\n"
        "    **Location**: code.sol:L1\n"
        "    **Description**: hidden\n",
        "```md\n## Finding [NEXP-1]: fence\n"
        "**Severity**: Low\n**Location**: code.sol:L1\n"
        "**Description**: hidden\n```\n",
        "<div>\n## Finding [NEXP-1]: html\n"
        "**Severity**: Low\n**Location**: code.sol:L1\n"
        "**Description**: hidden\n</div>\n",
    ),
)
def test_code_fence_and_html_headings_cannot_create_enumgap_authority(
    source: str,
) -> None:
    assert parse_enumgap_exploration_findings(source) == ()
    assert enumgap_reference_heading_ids(source) == frozenset()


def test_enumgap_crlf_and_nested_lower_section_are_offset_stable() -> None:
    source = (
        "## Finding [NEXP-1]: mapped candidate\r\n\r\n"
        "**Severity**: Low\r\n\r\n"
        "**Location**: src/Unit.sol:L1\r\n\r\n"
        "**Description**: concrete mechanism.\r\n\r\n"
        "### Nested Evidence\r\n\r\n"
        "The lower-level evidence remains inside the finding.\r\n\r\n"
        "## Coverage Record\r\n\r\n"
        "outside\r\n"
    )

    finding = parse_enumgap_exploration_findings(source)[0]

    assert "### Nested Evidence" in finding["block"]
    assert "Coverage Record" not in finding["block"]
    assert "\r\n" in finding["block"]


def test_blockquote_fields_are_semantic_data_not_container_markers() -> None:
    source = (
        "> ## Finding [NEXP-1]: quoted candidate\n>\n"
        "> **Severity**: Medium\n>\n"
        "> **Location**: src/Quoted.sol:L7\n>\n"
        "> **Description**: concrete quoted mechanism.\n\n"
        "## Coverage Record\n"
    )

    finding = parse_enumgap_exploration_findings(source)[0]

    assert finding["fields"] == {
        "Severity": "Medium",
        "Location": "src/Quoted.sol:L7",
        "Description": "concrete quoted mechanism.",
    }


def test_reference_acknowledgement_does_not_claim_strict_delivery() -> None:
    source = "### Finding [NEXP-1]: attempted but incomplete\n"

    assert enumgap_reference_heading_ids(source) == frozenset({"NEXP-1"})
    assert parse_enumgap_exploration_findings(source) == ()


def _finding(
    finding_id: str,
    *,
    source_ids: tuple[str, ...] = (),
    impact: str | None = "SIBLING SYNTHETIC HARM",
) -> str:
    source_field = (
        f"**Source IDs**: {', '.join(source_ids)}\n"
        if source_ids
        else ""
    )
    impact_field = f"**Impact**: {impact}\n" if impact is not None else ""
    return (
        f"### Finding [{finding_id}]: Fixture\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:L10\n"
        "**Root Cause**: exact mechanism\n"
        "**Description**: exact mechanism\n"
        f"{impact_field}"
        f"{source_field}"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
    )


def _pipeline(
    root: Path,
    *,
    source: str,
    chunk: str,
    final: str,
) -> None:
    source_name = "analysis_evm_flow.md"
    (root / source_name).write_text(source, encoding="utf-8")
    (root / "inventory_chunk_a.manifest.md").write_text(
        "# Manifest\n\n"
        "| File | Estimated signals |\n"
        "|---|---|\n"
        f"| {source_name} | 1 |\n",
        encoding="utf-8",
    )
    (root / "findings_inventory_chunk_a.md").write_text(
        "# Chunk\n\n" + chunk,
        encoding="utf-8",
    )
    (root / "findings_inventory.md").write_text(
        "# Inventory\n\n" + final,
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "sibling_heading",
    ("   ## Coverage Record", "- ## Coverage Record"),
)
def test_sibling_heading_source_ids_cannot_mint_full_retention(
    tmp_path: Path,
    sibling_heading: str,
) -> None:
    sibling_chunk = (
        _finding("CC-1", source_ids=())
        + sibling_heading
        + "\n**Source IDs**: TF-1\n"
    )
    sibling_final = (
        _finding("INV-001", source_ids=())
        + sibling_heading
        + "\n**Source IDs**: TF-1, CC-1\n"
    )
    _pipeline(
        tmp_path,
        source=_finding("TF-1"),
        chunk=sibling_chunk,
        final=sibling_final,
    )

    receipt = reconcile_inventory(tmp_path)

    assert receipt["summary"]["RETAINED"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["target_inventory_id"] == ""


@pytest.mark.parametrize(
    "sibling_heading",
    ("   ## Coverage Record", "- ## Coverage Record"),
)
def test_sibling_heading_impact_cannot_contaminate_full_replay(
    tmp_path: Path,
    sibling_heading: str,
) -> None:
    def with_sibling_impact(block: str) -> str:
        return (
            block
            + sibling_heading
            + "\n**Impact**: SIBLING SYNTHETIC HARM\n"
        )

    _pipeline(
        tmp_path,
        source=with_sibling_impact(_finding("TF-1", impact=None)),
        chunk=with_sibling_impact(
            _finding("CC-1", source_ids=("TF-1",), impact=None)
        ),
        final=with_sibling_impact(
            _finding(
                "INV-001",
                source_ids=("TF-1", "CC-1"),
                impact=None,
            )
        ),
    )

    receipt = reconcile_inventory(tmp_path)

    row = receipt["candidates"][0]
    assert row["source_impact"] == ""
    assert receipt["summary"]["RETAINED"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert "UNPARSEABLE_IMPACT" in row["required_preservation_axes"]


def test_inventory_blockquote_fields_reconcile_without_prefix_pollution(
    tmp_path: Path,
) -> None:
    def quoted(finding_id: str, source_ids: tuple[str, ...]) -> str:
        source_field = (
            f"> **Source IDs**: {', '.join(source_ids)}\n"
            if source_ids
            else ""
        )
        return (
            f"> ### Finding [{finding_id}]: Quoted fixture\n>\n"
            "> **Severity**: Medium\n>\n"
            "> **Location**: src/Fixture.sol:L10\n>\n"
            "> **Root Cause**: exact quoted mechanism\n>\n"
            "> **Description**: exact quoted mechanism\n>\n"
            "> **Impact**: exact quoted harm\n>\n"
            f"{source_field}"
            "> **Verdict**: NEEDS_VERIFICATION\n\n"
        )

    _pipeline(
        tmp_path,
        source=quoted("TF-1", ()),
        chunk=quoted("CC-1", ("TF-1",)),
        final=quoted("INV-001", ("TF-1", "CC-1")),
    )

    receipt = reconcile_inventory(tmp_path)

    assert receipt["summary"]["RETAINED"] == 1
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 0
    assert receipt["candidates"][0]["source_impact"] == "exact quoted harm"


@pytest.mark.parametrize(
    "heading, prefix",
    (("> ## Coverage Record", "> "), ("- ## Coverage Record", "  ")),
)
def test_coverage_table_uses_mapped_container_section(
    heading: str,
    prefix: str,
) -> None:
    source = (
        f"{heading}\r\n"
        f"{prefix}| Obligation | Relationship | Disposition | Evidence |\r\n"
        f"{prefix}|---|---|---|---|\r\n"
        f"{prefix}| NEXP-1 | sibling | CLEAR | traced |\r\n"
        "## Sibling\r\n"
        "| NEXP-2 | sibling | CLEAR | must not leak |\r\n"
    )

    rows, debt = _coverage_rows(source)

    assert debt == []
    assert [cells[0] for _line, cells, _digest in rows] == ["NEXP-1"]


@pytest.mark.parametrize(
    "source",
    (
        "### Coverage Record\n| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n| NEXP-1 | x | CLEAR | y |\n",
        "```md\n## Coverage Record\n| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n| NEXP-1 | x | CLEAR | y |\n```\n",
    ),
)
def test_non_h2_or_hidden_coverage_heading_is_explicit_debt(source: str) -> None:
    rows, debt = _coverage_rows(source)

    assert rows == []
    assert debt == ["enumgap Coverage Record section is missing"]


def test_axis_promoter_uses_shared_mapped_finding_sections(
    tmp_path: Path,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        "# Inventory\n", encoding="utf-8"
    )
    (tmp_path / "axis_coverage_findings.md").write_text(
        "- ### Finding [AXIS-A-1]: container axis candidate\n"
        "  **Severity**: Medium\n"
        "  **Location**: src/Axis.sol:L9\n"
        "  **Description**: exact candidate mechanism\n"
        "  **Impact**: exact candidate harm\n\n"
        "## Coverage Record\n"
        "**Impact**: sibling harm must not enter the promoted block\n",
        encoding="utf-8",
    )

    result = promote_axis_findings_to_inventory(tmp_path)

    assert result == {"parsed": 1, "emitted": 1}
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "AXISGAP:AXIS-A-1" in inventory
    assert "sibling harm" not in inventory


def _enumgap_candidate() -> str:
    return (
        "## Finding [NEXP-1]: collision candidate\n\n"
        "**Severity**: Low\n\n"
        "**Location**: src/Collision.sol:L3\n\n"
        "**Description**: exact collision candidate.\n\n"
        "## Coverage Record\n"
    )


def _inventory_seed(heading: str, inventory_id: str = "INV-001") -> str:
    return (
        "# Inventory\n\n"
        f"{heading} Finding [{inventory_id}]: preexisting candidate\n"
        "**Source IDs**: BASE-1\n"
        "**Severity**: Low\n"
        "**Location**: src/Collision.sol:L1\n"
        "**Description**: exact preexisting candidate.\n\n"
        "## Coverage Record\n"
        "**Source IDs**: SIBLING-1\n"
    )


def _prepare_direct_enumgap_promotion(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    inventory: str,
) -> None:
    import plamen_mechanical

    (root / "enumgap_exploration_findings.md").write_text(
        _enumgap_candidate(), encoding="utf-8"
    )
    (root / "findings_inventory.md").write_text(
        inventory, encoding="utf-8"
    )
    monkeypatch.setattr(EG, "_promotion_phaseio_issues", lambda _root: [])
    monkeypatch.setattr(
        plamen_mechanical,
        "_write_finding_records_from_inventory",
        lambda _root: None,
    )


@pytest.mark.parametrize(
    "heading",
    ("   ###", "- ###", "> ###"),
)
def test_commonmark_preexisting_inventory_identity_cannot_collide_on_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    heading: str,
) -> None:
    _prepare_direct_enumgap_promotion(
        tmp_path,
        monkeypatch,
        inventory=_inventory_seed(heading),
    )

    outcome = EG.promote_enumgap_exploration_to_inventory(tmp_path)
    inventory = (tmp_path / "findings_inventory.md").read_text(
        encoding="utf-8"
    )
    records = EG._inventory_finding_block_records(inventory)
    ast_inventory_ids = [
        str(heading_row["content"]).split("[", 1)[1].split("]", 1)[0]
        for heading_row in mapped_headings(inventory)
        if str(heading_row["content"]).startswith("Finding [INV-")
    ]

    assert outcome == {"parsed": 1, "emitted": 1}
    assert ast_inventory_ids == ["INV-001", "INV-002"]
    assert [row["id"] for row in records] == ["INV-001", "INV-002"]
    assert "Coverage Record" not in records[0]["block"]
    assert EG.validated_enumgap_promotion_deliveries(tmp_path)["NEXP-1"][
        "inventory_id"
    ] == "INV-002"


@pytest.mark.parametrize(
    "source",
    (
        "##Finding [INV-001]: not a heading\n**Source IDs**: NEXP-1\n",
        "    ### Finding [INV-001]: code\n    **Source IDs**: NEXP-1\n",
        "```md\n### Finding [INV-001]: fence\n**Source IDs**: NEXP-1\n```\n",
        "<div>\n### Finding [INV-001]: html\n**Source IDs**: NEXP-1\n</div>\n",
    ),
)
def test_non_commonmark_inventory_heading_decoys_are_not_records(
    source: str,
) -> None:
    assert EG._inventory_finding_block_records(source) == ()


def test_rebound_authority_rejects_container_duplicate_inventory_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_direct_enumgap_promotion(
        tmp_path,
        monkeypatch,
        inventory="# Inventory\n",
    )
    assert EG.promote_enumgap_exploration_to_inventory(tmp_path) == {
        "parsed": 1,
        "emitted": 1,
    }
    inventory_path = tmp_path / "findings_inventory.md"
    inventory_path.write_text(
        "> ### Finding [INV-001]: duplicate authority claim\n"
        "> **Source IDs**: OTHER-1\n"
        "> **Severity**: Low\n"
        "> **Location**: src/Collision.sol:L8\n"
        "> **Description**: conflicting identity.\n\n"
        + inventory_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    commit_path = tmp_path / "enumgap_inventory_append_commit.json"
    commit = json.loads(commit_path.read_text(encoding="utf-8"))
    commit["inventory_sha256"] = hashlib.sha256(
        inventory_path.read_bytes()
    ).hexdigest()
    commit_path.write_text(json.dumps(commit), encoding="utf-8")

    with pytest.raises(ValueError, match="identity mismatch"):
        EG.validated_enumgap_promotion_deliveries(tmp_path)
