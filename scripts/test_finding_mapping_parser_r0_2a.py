"""R0-2a: finding_mapping relations come only from typed table columns."""
from __future__ import annotations

import plamen_mechanical as M
import plamen_parsers as P


def test_parser_uses_normalized_typed_headers_and_ignores_incidental_ids():
    text = """# Finding Mapping

H-22 is discussed beside H-24, H-02, and L-27 in narrative prose.

| Finding ID | Hypothesis ID | Mapping Status | Notes |
|------------|---------------|----------------|-------|
| INV-041 | H-22 | GROUPED; follow H-24 | H-02 and L-27 are report labels |
| `INV-042` | [H-22] | PRIMARY | retained |
| INV-043 with prose | H-22 | GROUPED | invalid source cell |
| INV-044 | maps to H-22 | GROUPED | invalid target cell |
| Report ID | Hypothesis ID | Notes |
|-----------|---------------|-------|
| H-24 | H-22 | L-27 |
"""

    rows = P.parse_finding_mapping_rows(text)

    assert rows == [
        {
            "source_ids": ("INV-041",),
            "hypothesis_ids": ("H-22",),
            "status": "GROUPED; follow H-24",
            "notes": "H-02 and L-27 are report labels",
        },
        {
            "source_ids": ("INV-042",),
            "hypothesis_ids": ("H-22",),
            "status": "PRIMARY",
            "notes": "retained",
        },
    ]


def test_parser_preserves_aliases_three_column_notes_and_source_metadata():
    text = """| Source Finding ID | Hyp | Status |
|-------------------|-----|--------|
| INV-001 | H-1 | GROUPED |

| Source ID | Mapped Hypothesis | Notes |
|-----------|-------------------|-------|
| INV-002 | H-1 | second constituent |

| Finding ID | Source | Hypothesis | Severity | Note |
|------------|--------|------------|----------|------|
| INV-003 | breadth | HC-01 | Critical | provenance column is not an ID role |
"""

    rows = P.parse_finding_mapping_rows(text)

    assert [(r["source_ids"], r["hypothesis_ids"]) for r in rows] == [
        (("INV-001",), ("H-1",)),
        (("INV-002",), ("H-1",)),
        (("INV-003",), ("HC-01",)),
    ]
    assert rows[0]["status"] == "GROUPED" and rows[0]["notes"] == ""
    assert rows[1]["status"] == "" and rows[1]["notes"] == "second constituent"


def test_parser_requires_a_real_header_and_separator():
    text = """# Finding Mapping

| INV-001 | H-1 | GROUPED | note |
| INV-002 | H-1 | GROUPED | note |

| Finding ID | Hypothesis ID |
| INV-003 | H-2 |
"""
    assert P.parse_finding_mapping_rows(text) == []


def test_directional_join_ignores_narrative_and_status_ids(tmp_path):
    (tmp_path / "report_index.md").write_text(
        """# Report Index

## Master Finding Index

| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |
|-----------|-------|----------|----------|--------------|------------|---------------------|
| H-02 | First issue | High | src/A.rs:L1 | CONFIRMED | - | H-22 |
| L-27 | Second issue | Low | src/B.rs:L2 | CONFIRMED | - | H-24 |
""",
        encoding="utf-8",
    )
    (tmp_path / "finding_mapping.md").write_text(
        """# Finding Mapping

H-22 is compared with H-24 while report labels H-02 and L-27 remain separate.

| Finding ID | Hypothesis ID | Mapping Status | Notes |
|------------|---------------|----------------|-------|
| INV-041 | H-22 | GROUPED; review H-24 | does not absorb L-27 |
| INV-116 | H-24 | GROUPED; review H-22 | does not absorb H-02 |
""",
        encoding="utf-8",
    )

    joined = M._dedup_source_ids_by_report_id(tmp_path)

    assert joined["H-02"] == {"INV-041"}
    assert joined["L-27"] == {"INV-116"}
    assert joined["H-02"].isdisjoint(joined["L-27"])


def test_hypothesis_lookup_aliases_are_not_shared_source_values(tmp_path):
    (tmp_path / "report_index.md").write_text(
        """## Master Finding Index
| Report ID | Title | Severity | Internal Hypothesis |
|-----------|-------|----------|---------------------|
| H-01 | Grouped | High | H-1 |
| M-02 | Standalone | Medium | INV-009 |
""",
        encoding="utf-8",
    )
    (tmp_path / "finding_mapping.md").write_text(
        """| Finding ID | Hypothesis ID | Notes |
|------------|---------------|-------|
| INV-001 | H-1 | first |
| INV-002 | H-1 | second |
""",
        encoding="utf-8",
    )

    joined = M._dedup_source_ids_by_report_id(tmp_path)

    assert joined["H-01"] == {"INV-001", "INV-002"}
    assert "H-1" not in joined["H-01"]
    assert joined["M-02"] == {"INV-009"}
