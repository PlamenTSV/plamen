"""A backticked Source ID is the natural spelling, and it bound to nothing.

DODO run41 `inventory_chunk_a` attempt 1 delivered a complete 91KB shard: all
27 assigned identities, `## Master Table` plus `## Per-Finding Detail`, every
block carrying its reference as

    **Source IDs**: `analysis_rescan_1.md:RS1-1`

The gate rejected it 27/27 as `UNMATCHED [MISSING_CHUNK_DISPOSITION]` -- not
"text not transcribed verbatim", but "this shard dispositioned nothing at all".

Cause: `operational_markdown_field_view` blanks inline-code spans to whitespace
(offset-preserving) so a decoy label inside a fence cannot be read as a real
field. That is correct and must stay. But `_SOURCE_FIELD_RE` consumed
post-colon whitespace OUTSIDE its value group, so it ate the entire blanked
value and captured only the trailing newline. `_FIELD_RE` already captures that
whitespace INSIDE the group, and `_field_from_views` already documents exactly
this trap -- the source field was simply the one field not using the rule.

Two fixes, both pinned here: the regex now matches `_FIELD_RE`'s shape, and the
inline-code restoration has one owner (`_restored_field_value`) that the source
field uses like every other field.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import inventory_reconciliation as R  # noqa: E402
from operational_markdown import operational_markdown_field_view  # noqa: E402


def _block(body: str) -> tuple[str, str]:
    raw = f"### Finding [CC-01]: t\n\n{body}\n"
    return raw, operational_markdown_field_view(raw)


def _refs(body: str):
    raw, op = _block(body)
    match = R._SOURCE_FIELD_RE.search(op)
    if match is None:
        return set(), set(), {"NO_FIELD"}
    value = R._restored_field_value(raw, op, *match.span("value"))
    return R._source_references(value)


def test_backticked_qualified_reference_binds() -> None:
    """The exact run41 spelling."""
    _bare, qualified, issues = _refs(
        "**Source IDs**: `analysis_rescan_1.md:RS1-1`\n**Severity**: High"
    )
    assert qualified == {("analysis_rescan_1.md", "RS1-1")}
    assert not issues


def test_unbackticked_reference_still_binds() -> None:
    """The fix must not trade one spelling for the other."""
    _bare, qualified, issues = _refs(
        "**Source IDs**: analysis_rescan_1.md:RS1-1\n**Severity**: High"
    )
    assert qualified == {("analysis_rescan_1.md", "RS1-1")}
    assert not issues


def test_multiple_backticked_references_bind() -> None:
    _bare, qualified, _ = _refs(
        "**Source IDs**: `analysis_a.md:B4-3`, `analysis_b.md:B4-9`\n"
        "**Severity**: High"
    )
    assert qualified == {
        ("analysis_a.md", "B4-3"), ("analysis_b.md", "B4-9"),
    }


def test_bare_backticked_local_id_binds() -> None:
    bare, _qualified, _ = _refs(
        "**Source IDs**: `B4-3`\n**Severity**: High"
    )
    assert bare == {"B4-3"}


def test_value_group_no_longer_collapses_to_a_newline() -> None:
    """The precise mechanism, pinned so it cannot silently return.

    With post-colon whitespace outside the group, the blanked inline-code span
    was consumed and `span('value')` covered one character: the newline.
    """
    raw, op = _block(
        "**Source IDs**: `analysis_rescan_1.md:RS1-1`\n**Severity**: High"
    )
    match = R._SOURCE_FIELD_RE.search(op)
    assert match is not None
    start, end = match.span("value")
    assert end - start > 1, "value group collapsed past the blanked span again"
    assert "analysis_rescan_1.md:RS1-1" in R._restored_field_value(
        raw, op, start, end
    )


def test_source_field_matches_the_generic_field_rule() -> None:
    """Both regexes must keep capturing post-colon whitespace inside `value`."""
    assert r"(?P<value>[ \t]*.*?)" in R._SOURCE_FIELD_RE.pattern
    assert r"(?P<value>[ \t]*.*?)" in R._FIELD_RE.pattern


# --------------------------------------------------------------------------
# The injection resistance the operational view exists for must be intact.
# --------------------------------------------------------------------------

def test_label_inside_a_fence_is_still_not_a_field() -> None:
    """Restoring inline code must not resurrect a fenced decoy."""
    raw = (
        "### Finding [CC-01]: t\n\n"
        "**Severity**: High\n\n"
        "```\n"
        "**Source IDs**: `analysis_evil.md:EVIL-1`\n"
        "```\n"
    )
    op = operational_markdown_field_view(raw)
    match = R._SOURCE_FIELD_RE.search(op)
    if match is not None:
        value = R._restored_field_value(raw, op, *match.span("value"))
        _bare, qualified, _ = R._source_references(value)
        assert not qualified, "a fenced decoy label was read as a real field"


def test_offset_drift_fails_closed() -> None:
    """The two views must stay offset-identical or the slice is meaningless."""
    with pytest.raises(R.InventoryReconciliationError):
        R._restored_field_value("abc", "abcd", 0, 1)


# --------------------------------------------------------------------------
# End-to-end on the artifact the driver actually rejected.
# --------------------------------------------------------------------------

_RUN41 = Path(
    "/Users/ptsanev/dodo-v3-validation-run41/omni-chain-contracts/.scratchpad"
    "/_retry_quarantine/inventory_chunk_a/attempt-0001"
)


@pytest.mark.skipif(
    not (_RUN41 / "findings_inventory_chunk_a.md").is_file(),
    reason="run41 quarantined shard not present on this machine",
)
def test_the_rejected_run41_shard_now_binds_every_identity() -> None:
    blocks, issues = R._artifact_blocks(
        _RUN41, ["findings_inventory_chunk_a.md"]
    )
    rows = blocks["findings_inventory_chunk_a.md"]
    assert len(rows) == 27, "shard block count changed"
    bound = [row for row in rows if row["qualified_source_ids"]]
    assert len(bound) == 27, (
        f"only {len(bound)}/27 identities bound; this artifact was rejected "
        "27/27 UNMATCHED before the fix"
    )
    assert not issues
