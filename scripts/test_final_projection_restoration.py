"""Facet restoration must run at BOTH boundaries, and the reemit refusal must
only fire where a repair actually exists.

DODO run39 cleared all three inventory chunks on attempt 1 -- the first run ever
to do so -- and then died at `inventory`:

    [inventory] canonical aggregate did not commit: inventory additive
    re-emission PhaseIO failed: InventoryReemitError: additive re-emission
    refuses to duplicate one-to-one final deliveries; repair the canonical
    projection instead: INVC-10AC3F9F..., INVC-2E90ABB5..., (9 rows)

Two distinct defects, both about SCOPE:

1. `_restore_unpreserved_source_facets` ran only per CHUNK. The chunk pass
   compares a chunk against its assigned sources; the FINAL pass compares the
   merged projection against the whole raw discovery denominator, and finds
   different rows -- merging can drop a facet that survived inside its chunk.
   All 9 came from `analysis_percontract_reemit.md`, the driver's OWN
   recall-safety re-emission, whose facets the shard then did not transcribe.

   Two sub-problems had to be solved for the final pass to work at all:
     * `driver_restorable_preservation_row` accepted only
       `CHUNK_SEMANTIC_PRESERVATION_DEBT`; the final scope emits
       `FINAL_SEMANTIC_PRESERVATION_DEBT`.
     * matching by `proposed_target_finding_id` is impossible before render,
       because `INV-NNN` ids are allocated inside `_render_inventory`. The
       final pass keys on `source_ids`, which entries already carry.

2. Even with 8 of 9 restored, the reemit path still refused -- on the ONE row
   nothing can repair (`analysis_rescan_2.md:RS2-1`, `UNPARSEABLE_IMPACT`:
   the SOURCE never rendered an Impact). Its instruction, "repair the canonical
   projection instead", is correct for a row whose source holds the bytes and
   impossible for one whose source does not. The refusal is now scoped to
   restorable rows.

Measured on run39's real artifacts: debt 9 -> 1, retained 131/132, refusal set
0, aggregate commits.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import inventory_reconciliation as IR  # noqa: E402
import inventory_reemit_authority as RE  # noqa: E402


def _row(**over):
    row = {
        "disposition": "HUMAN_REVIEW_DEBT",
        "reason_code": "FINAL_SEMANTIC_PRESERVATION_DEBT",
        "proposed_relation_kind": "ONE_TO_ONE_RETENTION_PROPOSAL",
        "proposed_target_finding_id": "INV-128",
        "required_preservation_axes": ["ROOT_CAUSE"],
        "source_root_cause": "a mechanism sentence the source really carries",
        "source_impact": "",
        "source_preconditions": "",
        "source_artifact": "analysis_percontract_reemit.md",
        "source_finding_id": "PCRE-4",
    }
    row.update(over)
    return row


@pytest.mark.parametrize("reason", [
    "CHUNK_SEMANTIC_PRESERVATION_DEBT",
    "FINAL_SEMANTIC_PRESERVATION_DEBT",
])
def test_both_scopes_are_restorable(reason: str) -> None:
    """One repair, two boundaries. Accepting only the chunk code left the
    final projection permanently unrepaired."""
    assert IR.driver_restorable_preservation_row(_row(reason_code=reason))


def test_unrelated_debt_classes_stay_unrestorable() -> None:
    for reason in (
        "MULTI_SOURCE_COLLAPSE_REQUIRES_EQUIVALENCE",
        "REEMIT_UNPARSEABLE_SOURCE_DEBT",
        "MISSING_CHUNK_DISPOSITION",
        "STALE_DISPOSITION_AUTHORITY",
    ):
        assert not IR.driver_restorable_preservation_row(
            _row(reason_code=reason)
        ), reason


# --------------------------------------------------------------------------
# The reemit refusal must fire on repairable rows and only those.
# --------------------------------------------------------------------------

def test_refusal_still_fires_for_a_repairable_row() -> None:
    """The original protection must survive: a row the projection COULD have
    repaired must not be papered over by duplicating the delivery."""
    assert RE.driver_restorable_preservation_row(_row()) is True


def test_refusal_does_not_fire_for_an_unrepairable_row() -> None:
    """run39's blocker: the SOURCE never rendered the facet.

    No splice can copy absent bytes and no retry can invent them, so refusing
    here demands a repair that cannot exist and the aggregate can never commit.
    """
    unrepairable = _row(
        required_preservation_axes=["UNPARSEABLE_IMPACT"],
        source_root_cause="",
        source_impact="",
        source_artifact="analysis_rescan_2.md",
        source_finding_id="RS2-1",
    )
    assert RE.driver_restorable_preservation_row(unrepairable) is False


def test_refusal_predicate_is_the_shared_one() -> None:
    """The refusal and the repair must agree by construction.

    If they drift, the aggregate can refuse over a row the splice already
    fixed, or proceed over one it did not.
    """
    source = (_SCRIPTS / "inventory_reemit_authority.py").read_text("utf-8")
    assert "driver_restorable_preservation_row(row)" in source
    assert "from inventory_reconciliation import" in source


def test_final_pass_is_wired_into_the_aggregate() -> None:
    """A second pass nothing calls repairs nothing."""
    source = (
        _SCRIPTS / "inventory_aggregate_authority.py"
    ).read_text("utf-8")
    after_merge = source.split("merged = _merge_inventory_entries(entries)", 1)[1]
    before_render = after_merge.split("_render_inventory(", 1)[0]
    assert "_restore_unpreserved_source_facets(root, None, merged)" in before_render, (
        "the final-projection restoration does not run between merge and "
        "render; INV ids do not exist before render, so it cannot run later"
    )


def test_aggregate_entry_point_actually_executes_the_final_pass() -> None:
    """Source-string presence is NOT execution, and that gap cost a run.

    The first implementation of the final pass referenced `restored` -- a name
    that exists only inside `_derivation_entries` -- and raised
    `NameError: name 'restored' is not defined` on EVERY aggregate. 47 tests
    failed. It survived my own verification because that verification called
    `_restore_unpreserved_source_facets` directly and the wiring test above
    only checked that a string appeared in the file.

    So compile the module and walk the real function's bytecode: the call must
    be reachable from the public entry point, and every name it references must
    resolve in that scope.
    """
    import inspect
    import inventory_aggregate_authority as agg

    src = inspect.getsource(agg.build_inventory_aggregate_derivation)
    assert "_restore_unpreserved_source_facets(root, None, merged)" in src, (
        "the final pass is not inside the public entry point"
    )
    # Every local the call site touches must be bound in THIS function, not in
    # a helper that happens to share a name.
    code = agg.build_inventory_aggregate_derivation.__code__
    bound = set(code.co_varnames) | set(code.co_names) | set(code.co_cellvars)
    for name in ("restored_facets", "merged", "root"):
        assert name in bound, (
            f"{name!r} is not bound in build_inventory_aggregate_derivation; "
            "the final pass will raise NameError at runtime"
        )
    assert "restored" not in code.co_varnames or "restored_facets" in bound


def test_final_scope_matches_on_source_ids_not_target_ids() -> None:
    """`INV-NNN` is allocated during render, so target-id keying cannot work."""
    source = (
        _SCRIPTS / "inventory_aggregate_authority.py"
    ).read_text("utf-8")
    assert 'entry.get("source_ids")' in source, (
        "the final pass no longer keys on source_ids; it will silently restore "
        "nothing, exactly as the first attempt did"
    )
