"""A prohibition is not a declaration of intent.

DODO run34 breadth: the methodology-repair worker was refused at launch with

    [breadth_repair_worker_METHODOLOGY_APPLICATION_REPAIR_BREADTH]
    restricted Claude prompt/PhaseIO consistency denied:
    ALTERNATE_OUTPUT_WRITE@637:additional output

Line 637 of that prompt is the driver's OWN output contract:

    Write exactly <path>/analysis_methodology_repair_breadth.md
    and no other artifact.

`_ADDITIONAL_OUTPUT_RE` matched the words "other artifact" with no negation
awareness, so the guard read a RESTRICTION as a declaration that the worker
intended to write beyond its declared PhaseIO authority -- and refused to
launch the very worker the driver had just correctly constrained.

The guard itself is right to exist: a prompt that genuinely announces an
extra output contradicts its output authority and must fail closed. The
negative controls below keep that intact.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from claude_worker_prompt_consistency import (  # noqa: E402
    _declares_additional_output,
)


@pytest.mark.parametrize(
    "clause",
    [
        # The exact run34 clause.
        "Write exactly /x/.scratchpad/analysis_methodology_repair_breadth.md "
        "and no other artifact.",
        "Write the report and do not write any other files.",
        "Write exactly one file; never write additional outputs.",
        "Produce the artifact without any secondary output.",
        "You must not write another artifact.",
        "Write the summary; avoid extra files.",
    ],
)
def test_prohibitions_are_not_declarations(clause: str) -> None:
    assert not _declares_additional_output(clause), (
        "a clause FORBIDDING extra outputs was read as declaring one; this "
        "refuses the worker at launch (DODO run34 ALTERNATE_OUTPUT_WRITE@637)"
    )


@pytest.mark.parametrize(
    "clause",
    [
        "Also write an additional artifact summarising results.",
        "Write another output file with the raw data.",
        "Produce extra artifacts for the reviewer.",
        "Emit a secondary output alongside the main report.",
    ],
)
def test_genuine_declarations_are_still_denied(clause: str) -> None:
    """NEGATIVE CONTROL: the guard must still fail closed on a real conflict."""
    assert _declares_additional_output(clause), (
        "a prompt announcing an output beyond its PhaseIO authority must "
        "still be refused; the negation fix must not disarm the guard"
    )
