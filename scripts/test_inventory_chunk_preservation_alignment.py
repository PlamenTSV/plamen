"""Chunk facet preservation must survive interleaving, never survive loss.

`inventory_chunk_*` is a lossless one-to-one normalization boundary: one
upstream finding block in, one `### Finding [CC-NN]` block out. The gate proves
the boundary was lossless by asking whether each source facet survived into the
chunk block -- and it asked that with `source in target`, a SINGLE-RUN
containment test.

That test cannot distinguish loss from enrichment. DODO run35's
`inventory_chunk_a` shard copied its sources faithfully and inlined the real
code where the source carried prose, e.g.

    source: "... the event at L584-589 then reads the same now-zeroed
             pointer: [TRACE:claimRefund -> ...]"
    chunk:  "... the event at L584-589 then reads the same now-zeroed
             pointer (`emit EddyCrossChainRefundClaimed(externalId,
             refundInfo.token, refundInfo.amount, ...);`, L586-587)."

Strictly more evidence, every claim intact -- and one inserted clause broke
contiguity, so the gate scored it as an unpreserved facet. The shard was then
told only a COUNT ("11/49 assigned raw identity(s) remain
NEEDS_INVENTORY_REVIEW"), rewrote facets it had already carried correctly, and
drifted to 19/49. The phase is critical; the run died there having committed six
clean phases and 130 findings.

So preservation is now tested by run alignment: the contiguous runs the target
shares with the source are subtracted, and the UNCOVERED residue must carry no
material token missing from the target. Insertion and reordering are free; a
dropped identifier, literal, line reference, or table cell is not.

The relaxation is granted ONLY on the one-to-one retention path. Absorption and
merge callers keep strict containment -- semantic similarity must never
authorize destructive absorption, which is the property this whole module
exists to defend.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import inventory_reconciliation as IR  # noqa: E402


# Verbatim from DODO run35 `analysis_centralization_risk.md:B6-7` ->
# `findings_inventory_chunk_a.md:CC-17`, the case that killed the run.
_RUN35_SOURCE = (
    "`refundInfo` is a **storage** reference (`RefundInfo storage refundInfo "
    "= refundInfos[externalId];`, L572). The payout at L581 correctly reads "
    "live values, but `delete refundInfos[externalId];` at L582 zeroes the "
    "slot, and the event at L584-589 then reads the same now-zeroed pointer: "
    "[TRACE:claimRefund -> transfer uses live values -> delete -> emit logs "
    "token=0x0, amount=0]"
)
_RUN35_CHUNK = (
    "`refundInfo` is a **storage** reference (`RefundInfo storage refundInfo "
    "= refundInfos[externalId];`, L572). The payout at L581 correctly reads "
    "live values, but `delete refundInfos[externalId];` at L582 zeroes the "
    "slot, and the event at L584-589 then reads the same now-zeroed pointer "
    "(`emit EddyCrossChainRefundClaimed(externalId, refundInfo.token, "
    "refundInfo.amount, ...);`, L586-587). "
    "[TRACE:claimRefund -> transfer uses live values -> delete -> emit logs "
    "token=0x0, amount=0]"
)


# An empty SOURCE facet is its own debt axis (`UNPARSEABLE_*`), so every axis
# not under test must carry benign text that is byte-identical on both sides.
# Otherwise each assertion silently measures the empty-source path instead.
_INERT = "An unrelated but preserved facet sentence for axis isolation."


def _candidate(root_cause: str = _INERT, impact: str = _INERT,
               preconditions: str = _INERT):
    return {
        "source_root_cause": root_cause,
        "source_impact": impact,
        "source_preconditions": preconditions,
    }


def _target(root_cause: str = _INERT, description: str = "",
            impact: str = _INERT, preconditions: str = _INERT):
    return {
        "root_cause": root_cause,
        "description": description,
        "impact": impact,
        "preconditions": preconditions,
    }


# --------------------------------------------------------------------------
# The false negative that killed run35.
# --------------------------------------------------------------------------

def test_interleaved_code_citation_is_preservation_not_loss() -> None:
    assert _RUN35_SOURCE not in _RUN35_CHUNK, "fixture no longer exercises the bug"
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=_RUN35_SOURCE),
        _target(root_cause=_RUN35_CHUNK),
        allow_run_alignment=True,
    )
    assert deltas == [], (
        "an enriched chunk facet was scored as unpreserved; this is the exact "
        f"false negative that killed DODO run35: {deltas}"
    )


def test_reordered_clauses_preserve() -> None:
    source = "The setter has no bound at `Gateway.sol:L142`. The fee is read at leg 2."
    target = "The fee is read at leg 2. The setter has no bound at `Gateway.sol:L142`."
    assert IR._semantic_preservation_deltas(
        _candidate(root_cause=source), _target(root_cause=target),
        allow_run_alignment=True,
    ) == []


def test_root_cause_may_survive_in_description() -> None:
    """Description stays a valid alternate surface under alignment."""
    assert IR._semantic_preservation_deltas(
        _candidate(root_cause=_RUN35_SOURCE),
        _target(root_cause="restated differently", description=_RUN35_CHUNK),
        allow_run_alignment=True,
    ) == []


# --------------------------------------------------------------------------
# Negative controls: real loss must still be caught.
# --------------------------------------------------------------------------

def test_truncated_facet_is_still_loss() -> None:
    truncated = _RUN35_CHUNK.split("zeroes the slot")[0]
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=_RUN35_SOURCE), _target(root_cause=truncated),
        allow_run_alignment=True,
    )
    assert deltas == ["ROOT_CAUSE"], (
        "a chunk that dropped the second half of its source facet passed "
        "preservation; the alignment test is unsound"
    )


def test_dropped_line_reference_is_loss() -> None:
    """A single missing literal must fail -- these are the material facts."""
    mangled = _RUN35_CHUNK.replace("L582", "").replace("L584-589", "")
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=_RUN35_SOURCE), _target(root_cause=mangled),
        allow_run_alignment=True,
    )
    assert deltas == ["ROOT_CAUSE"]


def test_dropped_identifier_is_loss() -> None:
    mangled = _RUN35_CHUNK.replace("refundInfos[externalId]", "the mapping")
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=_RUN35_SOURCE), _target(root_cause=mangled),
        allow_run_alignment=True,
    )
    assert deltas == ["ROOT_CAUSE"]


def test_paraphrase_without_the_source_tokens_is_loss() -> None:
    """The whole point: similarity is never preservation."""
    paraphrase = (
        "A storage pointer is cleared before the event is emitted, so the log "
        "carries zeroed values instead of the amounts actually paid out."
    )
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=_RUN35_SOURCE), _target(root_cause=paraphrase),
        allow_run_alignment=True,
    )
    assert deltas == ["ROOT_CAUSE"]


def test_dropped_table_rows_are_loss() -> None:
    """run35's residual debt class: a boundary table summarized into prose."""
    source = (
        "Boundary substitution, formula `(amount * feePercent) / 1000`: "
        "| `feePercent` | effective rate | fee taken | "
        "| 5 | 0.5% | 5e15 | | 100 | 10% | 1e17 | | 1000 | 100% | 1e18 |"
    )
    target = "Boundary substitution shows the fee can reach the entire amount."
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=source), _target(root_cause=target),
        allow_run_alignment=True,
    )
    assert deltas == ["ROOT_CAUSE"]


def test_empty_source_facet_remains_unparseable_debt() -> None:
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause="", impact=""),
        _target(root_cause="anything", impact="anything"),
        allow_run_alignment=True,
    )
    assert deltas == ["UNPARSEABLE_ROOT_CAUSE", "UNPARSEABLE_IMPACT"], (
        "an absent source facet must stay ambiguity debt; alignment cannot "
        "resolve content that was never parsed"
    )


def test_operator_adjacency_is_not_laundered() -> None:
    """The module's own stated hazard: `amount * fee` != `amount fee`.

    The lossy projection keeps both identifiers, so a bag-of-tokens test would
    pass it. Run alignment must not: the dropped operator leaves no shared run
    long enough to cover the expression.
    """
    source = "The fee is computed as `(amount * feePercent) / 1000` at L297."
    target = "The fee is computed as `amount feePercent 1000` at L297."
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=source), _target(root_cause=target),
        allow_run_alignment=True,
    )
    assert deltas == ["ROOT_CAUSE"], (
        "an operator-stripped projection passed preservation; the alignment "
        "test degenerated into a bag of tokens"
    )


# --------------------------------------------------------------------------
# Scope: absorption authority must be untouched.
# --------------------------------------------------------------------------

def test_material_token_lost_inside_an_aligned_run_is_still_loss() -> None:
    """Residue alone is not enough.

    Two long runs can align around a silently swapped identifier, leaving the
    dropped name inside a 'covered' span where a residue-only test never looks.
    """
    source = (
        "The owner can call `superWithdraw` to sweep ETH and any ZRC20 to "
        "`EddyTreasurySafe`, and can also call `setEddyTreasurySafe` to "
        "redirect that sink to `attackerVault` before sweeping."
    )
    target = source.replace("`attackerVault`", "a new address")
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=source), _target(root_cause=target),
        allow_run_alignment=True,
    )
    assert deltas == ["ROOT_CAUSE"]
    assert "attackerVault" in IR._lost_material_tokens(source, target), (
        "the dropped identifier must be reported whole, not as a mid-token "
        "residue fragment"
    )


def test_alignment_is_off_by_default() -> None:
    """Merge/absorption callers pass no flag and must keep strict containment."""
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=_RUN35_SOURCE), _target(root_cause=_RUN35_CHUNK),
    )
    assert deltas == ["ROOT_CAUSE"], (
        "run alignment leaked into the default path; a merge survivor could "
        "now absorb a source it only partially reproduces"
    )


def test_only_the_one_to_one_retention_paths_grant_alignment() -> None:
    """Source-level pin on the grant sites.

    Exactly two call sites may grant run alignment: the chunk retention path
    and the final retention path, both of which propose
    ONE_TO_ONE_RETENTION_PROPOSAL (the final grant was added after DODO run43
    halted on nine enriched-but-complete final rows).  Receipt replay in
    `_load_reemit_receipt` validates a verbatim splice and must keep strict
    containment.  If a future edit hands the flag to a third site, the
    anti-absorption brake may be gone and no behavioural test above would
    notice, because they all call the comparator directly.
    """
    source = (_SCRIPTS / "inventory_reconciliation.py").read_text("utf-8")
    marker = "allow_run_alignment=True"
    grants = source.count(marker)
    assert grants == 2, (
        f"{grants} call sites grant run alignment; exactly two "
        "(chunk + final ONE_TO_ONE_RETENTION_PROPOSAL) may"
    )
    position = 0
    for _ in range(grants):
        position = source.index(marker, position)
        context = source[max(0, position - 800):position]
        assert "ONE_TO_ONE_RETENTION_PROPOSAL" in context, (
            "run alignment is granted outside a one-to-one retention path"
        )
        position += len(marker)
    reemit_body = source[source.index("def _load_reemit_receipt"):]
    reemit_body = reemit_body[:reemit_body.index("\ndef ")]
    assert marker not in reemit_body, (
        "receipt replay validates a verbatim splice and must keep strict "
        "containment"
    )


@pytest.mark.parametrize("axis_field,target_field", [
    ("source_impact", "impact"),
    ("source_preconditions", "preconditions"),
])
def test_alignment_applies_to_every_facet_axis(axis_field, target_field) -> None:
    candidate = _candidate()
    candidate[axis_field] = _RUN35_SOURCE
    target = _target()
    target[target_field] = _RUN35_CHUNK
    assert IR._semantic_preservation_deltas(
        candidate, target, allow_run_alignment=True,
    ) == []
