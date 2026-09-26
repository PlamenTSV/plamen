"""GFM table rows must be split on UNESCAPED pipes only.

DODO run29 failed its recon phase gate with::

    modifier application table has malformed/non-substantive row(s): 162, 191

Both rows were correctly authored. They contained a Solidity guard expression
whose `||` was escaped as `\\|\\|`, which GitHub-Flavoured Markdown REQUIRES for
a literal pipe inside a table cell:

    | `GatewayCrossChain.claimRefund` | `...sol:571` |
      no modifier; internal `require(bots[msg.sender] \\|\\| msg.sender==receiver)`
      at L578 | GUARDED (via inline `require`) |

`_split_markdown_table_row` split on every `|`, so a 4-column row parsed as 6
columns and was rejected. The model followed the spec; the parser did not. All
four recon workers had published successfully, and this single parser defect
failed the whole phase -- the merge and dependency wave are skipped whenever any
worker row is judged incomplete.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from plamen_parsers import _split_markdown_table_row as split  # noqa: E402


# The exact row shape that failed in production.
_LIVE_ROW = (
    "| `GatewayCrossChain.claimRefund` | `contracts/GatewayCrossChain.sol:571` "
    "| no modifier; internal `require(bots[msg.sender] \\|\\| "
    "msg.sender==receiver)` at L578 | GUARDED (via inline `require`) |"
)


def test_live_failing_row_parses_to_its_real_column_count() -> None:
    cells = split(_LIVE_ROW)
    assert len(cells) == 4, f"expected 4 columns, got {len(cells)}: {cells}"


def test_escaped_pipes_are_unescaped_in_the_cell_value() -> None:
    cells = split(_LIVE_ROW)
    assert "msg.sender] || msg.sender" in cells[2]
    assert "\\|" not in cells[2]


def test_ordinary_rows_are_unaffected() -> None:
    assert split("| a | b | c |") == ["a", "b", "c"]


def test_multiple_escaped_pipes_in_one_cell() -> None:
    assert split("| x | a \\| b \\| c | y |") == ["x", "a | b | c", "y"]


def test_escaped_pipe_adjacent_to_a_real_delimiter() -> None:
    assert split("| a\\| | b |") == ["a|", "b"]


def test_empty_cells_are_preserved_positionally() -> None:
    assert len(split("| a |  | c |")) == 3


@pytest.mark.parametrize("row", ["", "   ", "not a table row", "|"])
def test_non_rows_do_not_explode(row: str) -> None:
    split(row)
