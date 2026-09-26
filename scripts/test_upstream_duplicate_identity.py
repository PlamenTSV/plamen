"""An upstream artifact's duplicate IDs must not kill a downstream phase.

`bind_exact_source_actions` RAISED when one source artifact contained the same
producer-local finding ID twice. That fails a CRITICAL phase over a fault in a
DIFFERENT artifact, which the inventory shard has no power to repair -- the
unwinnable-contract failure mode, one layer further up than the chunk-format
cases.

DODO run38 `inventory_chunk_b`:

    source-action authentication failed: inventory source action identity is
    duplicated: analysis_percontract_IUniswapV2Router01.md:RS-1

That artifact contains no `### Finding [PC{N}-k]:` blocks at all. Its author
wrote duplicate-suppression bookkeeping as step-labelled sections --
`### RS-1 (cross-function state) / RS-4 (economic edges) - <title>` -- where
`RS-1..RS-5` are RESCAN METHODOLOGY STEP numbers, not identities. Four sections
claimed `RS-1`.

Why the parser was NOT tightened instead: measured across that run's artifacts,
requiring a bracketed ID would have dropped 11 blocks from four artifacts that
legitimately use unbracketed per-contract/rescan headings
(GatewayTransferNative 6, GatewayCrossChain 2, rescan_3 2, IUniswapV2Factory 1).
Losing real findings to suppress phantom ones is the wrong trade.

The property this file defends: an ambiguous identity binds to NOTHING (never
to an arbitrary claimant), every unambiguous identity in the same artifact
still binds, and the ambiguity is reported rather than swallowed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from inventory_source_action_authority import (  # noqa: E402
    ambiguous_identity_debt,
    bind_exact_source_actions,
)


def _source(tmp_path: Path, name: str, ids: tuple[str, ...]) -> str:
    body = "\n\n".join(
        f"""### Finding [{fid}]: title {i}

**Severity**: High
**Location**: src/A.sol:L{i}
**Description**: mechanism {i}"""
        for i, fid in enumerate(ids, start=1)
    )
    (tmp_path / name).write_text(f"# Analysis\n\n{body}\n", encoding="utf-8")
    return name


def _entry(artifact: str, action_id: str) -> dict:
    return {"local_id": "CC-01", "source_actions": [(artifact, action_id)]}


def test_duplicate_identity_does_not_raise(tmp_path: Path) -> None:
    """The whole point: an upstream fault must not kill this phase."""
    name = _source(tmp_path, "analysis_rescan_1.md", ("RS1-1", "RS1-1"))
    ambiguous = bind_exact_source_actions(
        tmp_path, [name], [_entry(name, "RS1-1")]
    )
    assert ambiguous == [f"{name}:RS1-1"]


def test_ambiguous_identity_binds_to_nothing(tmp_path: Path) -> None:
    """It must not resolve to an arbitrary one of its claimants.

    Silently picking a claimant would attribute one finding's evidence to
    another -- exactly the identity collapse this module exists to prevent.
    """
    name = _source(tmp_path, "analysis_rescan_1.md", ("RS1-1", "RS1-1"))
    entry = _entry(name, "RS1-1")
    bind_exact_source_actions(tmp_path, [name], [entry])
    assert entry["source_actions"] == [], (
        "an ambiguous identity authenticated a source action"
    )


def test_unambiguous_identities_in_the_same_artifact_still_bind(
    tmp_path: Path,
) -> None:
    """One bad ID must not poison the rest of the artifact."""
    name = _source(
        tmp_path, "analysis_rescan_1.md", ("RS1-1", "RS1-1", "RS1-2", "RS1-3")
    )
    good_a, good_b = _entry(name, "RS1-2"), _entry(name, "RS1-3")
    bad = _entry(name, "RS1-1")
    ambiguous = bind_exact_source_actions(
        tmp_path, [name], [good_a, good_b, bad]
    )
    assert len(good_a["source_actions"]) == 1
    assert len(good_b["source_actions"]) == 1
    assert bad["source_actions"] == []
    assert ambiguous == [f"{name}:RS1-1"]


def test_clean_artifact_reports_no_ambiguity(tmp_path: Path) -> None:
    name = _source(tmp_path, "analysis_rescan_1.md", ("RS1-1", "RS1-2"))
    entry = _entry(name, "RS1-1")
    assert bind_exact_source_actions(tmp_path, [name], [entry]) == []
    assert len(entry["source_actions"]) == 1


def test_ambiguity_is_retrievable_for_reporting(tmp_path: Path) -> None:
    """Retention without visibility would be laundering."""
    from inventory_source_action_authority import (
        validate_inventory_chunk_source_actions,
    )

    name = _source(tmp_path, "analysis_rescan_1.md", ("RS1-1", "RS1-1", "RS1-2"))
    chunk = tmp_path / "findings_inventory_chunk_a.md"
    chunk.write_text(
        "# Chunk\n\n## Master Table\n\n"
        "| Finding ID | Title | Severity | Preferred Tag | Verdict | Location |\n"
        "|---|---|---|---|---|---|\n"
        "| CC-01 | t | High | CODE-TRACE | CONFIRMED | src/A.sol:L1 |\n\n"
        "## Per-Finding Detail\n\n"
        "### Finding [CC-01]: t\n\n"
        f"**Source IDs**: {name}:RS1-2\n"
        "**Severity**: High\n**Location**: src/A.sol:L1\n"
        "**Preferred Tag**: CODE-TRACE\n**Verdict**: CONFIRMED\n"
        "**Root Cause**: m\n**Description**: d\n**Impact**: i\n",
        encoding="utf-8",
    )
    validate_inventory_chunk_source_actions(
        tmp_path, chunk_name=chunk.name, source_names=[name],
    )
    assert ambiguous_identity_debt(tmp_path, chunk.name) == [f"{name}:RS1-1"]


def test_upstream_ambiguity_is_not_a_gate_failure(tmp_path: Path) -> None:
    """Gating on it re-creates the unwinnable contract in a politer form."""
    from inventory_source_action_authority import (
        validate_inventory_chunk_source_actions,
    )

    name = _source(tmp_path, "analysis_rescan_1.md", ("RS1-1", "RS1-1", "RS1-2"))
    chunk = tmp_path / "findings_inventory_chunk_a.md"
    chunk.write_text(
        "# Chunk\n\n## Master Table\n\n"
        "| Finding ID | Title | Severity | Preferred Tag | Verdict | Location |\n"
        "|---|---|---|---|---|---|\n"
        "| CC-01 | t | High | CODE-TRACE | CONFIRMED | src/A.sol:L1 |\n\n"
        "## Per-Finding Detail\n\n"
        "### Finding [CC-01]: t\n\n"
        f"**Source IDs**: {name}:RS1-2\n"
        "**Severity**: High\n**Location**: src/A.sol:L1\n"
        "**Preferred Tag**: CODE-TRACE\n**Verdict**: CONFIRMED\n"
        "**Root Cause**: m\n**Description**: d\n**Impact**: i\n",
        encoding="utf-8",
    )
    issues = validate_inventory_chunk_source_actions(
        tmp_path, chunk_name=chunk.name, source_names=[name],
    )
    assert issues == [], (
        f"upstream duplicate identity gated the shard: {issues}"
    )
