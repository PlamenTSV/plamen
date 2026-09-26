"""A table ID column the parser doesn't recognize destroys the whole chunk.

`_parse_chunk_table_inventory` mapped a row's identity only from a header
matching "finding id" or exactly "id". A shard that wrote `| CC ID |` produced
37 table rows with NO local_id, which then could not merge with their 37 detail
blocks -- `_parse_inventory_chunk` returned **74 rows for 37 findings**.

Everything downstream followed from that one miss:
  * every source id appeared twice -> "source-action denominator contains
    duplicates", which is NOT preservation debt, so the chunk could not degrade
    and had to retry;
  * the retry's contract is "rewrite every block", which damaged rows that were
    already correct (DODO run37 chunk_b went 2 -> 24 preservation failures);
  * `inventory_aggregate_authority` rejected the artifact outright with
    "accepted chunk material denominator differs from parsed rows", so the
    facet restoration could not even run.

chunk_a survived only by accident: its table lacked a `Location` column, so
`_parse_markdown_tables` never admitted it and the phantom rows never appeared.

Measured after the fix, on run37's real artifacts: all four (both published and
both quarantined attempt-1) parse to 37 rows, and BOTH attempt-1 artifacts pass
the chunk gate with ZERO issues -- i.e. the retry, the churn and the degrade
were all downstream of this single unrecognized column header.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from plamen_parsers import (  # noqa: E402
    _parse_inventory_chunk,
    _table_local_id_column,
    _table_source_action_column,
)


def _chunk(table_header: str, id_cells: tuple[str, ...]) -> str:
    rows = "\n".join(
        f"| {cid} | Title {i} | High | CODE-TRACE | CONFIRMED | src/A.sol:L{i} |"
        for i, cid in enumerate(id_cells, start=1)
    )
    details = "\n\n".join(
        f"""### Finding [{cid}]: Title {i}

**Source IDs**: analysis_x.md:B1-{i}
**Severity**: High
**Location**: src/A.sol:L{i}
**Preferred Tag**: CODE-TRACE
**Verdict**: CONFIRMED
**Root Cause**: mechanism {i}
**Description**: description {i}
**Impact**: impact {i}"""
        for i, cid in enumerate(id_cells, start=1)
    )
    return f"""# Chunk

## Source Summary

one source.

## Master Table

| {table_header} | Title | Severity | Preferred Tag | Verdict | Location |
|---|---|---|---|---|---|
{rows}

## Per-Finding Detail

{details}
"""


@pytest.mark.parametrize("header", [
    "CC ID", "Finding ID", "Candidate ID", "Issue ID", "ID", "Chunk ID",
])
def test_table_and_detail_merge_into_one_row(
    tmp_path: Path, header: str,
) -> None:
    """A table row and its detail block are ONE finding, not two."""
    path = tmp_path / "findings_inventory_chunk_a.md"
    path.write_text(_chunk(header, ("CC-01", "CC-02", "CC-03")), "utf-8")
    rows = _parse_inventory_chunk(path)
    assert len(rows) == 3, (
        f"header {header!r} produced {len(rows)} rows for 3 findings; "
        "unmerged table rows become phantom findings and duplicate every "
        "source action"
    )
    assert all(str(r.get("local_id") or "").strip() for r in rows)


def test_unrecognized_header_is_the_regression_being_guarded() -> None:
    """Pin the exact predicate, so the widening cannot silently narrow again."""
    assert _table_local_id_column("cc id", "CC-01")
    assert _table_local_id_column("finding id", "CC-01")
    assert _table_local_id_column("id", "CC-01")


# --------------------------------------------------------------------------
# Negative controls: widening must not let a NON-identity column capture the
# identity slot.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("key,value", [
    ("valid id", "yes"),            # a boolean column that happens to end in id
    ("has id", "no"),
    ("cc id", "Critical"),          # right header, wrong content
    ("cc id", ""),                  # empty cell
    ("cc id", "not-an-id"),
    ("severity", "CC-01"),          # right content, unrelated header
    ("location", "CC-01"),
    ("identity", "CC-01"),          # contains "id" but is not an "... id" head
    ("title", "CC-01"),
])
def test_non_identity_columns_are_refused(key: str, value: str) -> None:
    assert not _table_local_id_column(key, value), (
        f"column {key!r} with value {value!r} was treated as the finding "
        "identity column"
    )


def test_a_boolean_id_column_does_not_hijack_identity(tmp_path: Path) -> None:
    """End-to-end version of the control above."""
    path = tmp_path / "findings_inventory_chunk_a.md"
    # `Valid ID` ends in " id" but carries yes/no, so it must NOT bind identity.
    path.write_text(_chunk("Valid ID", ("yes", "yes", "yes")), "utf-8")
    rows = _parse_inventory_chunk(path)
    ids = {str(r.get("local_id") or "").strip() for r in rows}
    assert "yes" not in ids, "a non-identity column captured the identity slot"


@pytest.mark.parametrize("header", [
    "Source ID", "Source IDs", "Source Finding ID", "Source action",
    "Upstream ID", "Producer action",
])
def test_provenance_columns_are_disjoint_from_local_identity(
    header: str,
) -> None:
    """A provenance cell may contain an ID without becoming the row ID."""

    key = header.lower()
    assert _table_source_action_column(key)
    assert not _table_local_id_column(key, "analysis_x.md:B1-1")


def test_id_and_source_id_columns_merge_with_detail_without_phantom_rows(
    tmp_path: Path,
) -> None:
    """Pin the exact DODO run66 attempt-1 column-role ambiguity."""

    path = tmp_path / "findings_inventory_chunk_a.md"
    path.write_text(
        """## Master Table

| ID | Source ID | Severity | Location | Title |
|---|---|---|---|---|
| CC-01 | analysis_x.md:B1-1 | High | src/A.sol:L1 | First title |
| CC-02 | analysis_x.md:B1-2 | Medium | src/A.sol:L2 | Second title |

## Per-Finding Detail

### Finding [CC-01]: First title

**Source IDs**: analysis_x.md:B1-1
**Severity**: High
**Location**: src/A.sol:L1
**Preferred Tag**: CODE-TRACE
**Verdict**: CONFIRMED
**Root Cause**: first mechanism
**Description**: first description
**Impact**: first impact

### Finding [CC-02]: Second title

**Source IDs**: analysis_x.md:B1-2
**Severity**: Medium
**Location**: src/A.sol:L2
**Preferred Tag**: CODE-TRACE
**Verdict**: PARTIAL
**Root Cause**: second mechanism
**Description**: second description
**Impact**: second impact
""",
        encoding="utf-8",
    )

    rows = _parse_inventory_chunk(path)
    assert [row.get("local_id") for row in rows] == ["CC-01", "CC-02"]
    assert [row.get("source_actions") for row in rows] == [
        [("analysis_x.md", "B1-1")],
        [("analysis_x.md", "B1-2")],
    ]
