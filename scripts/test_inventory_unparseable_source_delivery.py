"""An unparseable source facet is visible debt, never a halt.

DODO run45 (2026-09-20 01:36) cleared recon, instantiate, breadth, rescan and
all three inventory chunks, then halted at the canonical aggregate: four raw
findings whose breadth block rendered no `**Impact**` / `**Root Cause**`
(`UNPARSEABLE_*` axes, nothing to splice) were additively re-emitted as their
own inventory blocks, and then

1. the re-emit receipt loader refused its own delivery as "stale or lossy"
   because it counted the UNPARSEABLE axis as target loss,
2. the re-emit authority's replay demanded RETAINED_BY_ADDITIVE_REEMIT for a
   row the reconciler deliberately keeps as REEMIT_UNPARSEABLE_SOURCE_DEBT, and
3. the parity gate blocked the aggregate on ANY review debt.

No retry, splice, or re-emission can invent a facet the producer never wrote.
The deliberate design (`test_additive_reemit_cannot_launder_invisible_entity_
source_debt`) is preserved: the row stays HUMAN_REVIEW_DEBT with mandatory
re-verification and stays in the human-review artifact.  It simply stops
blocking a phase that has no way to satisfy it.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import inventory_reemit_authority as reemit_authority  # noqa: E402
import inventory_reconciliation as IR  # noqa: E402
import plamen_validators as V  # noqa: E402
from test_inventory_reconciliation_operational_markdown_r7 import (  # noqa: E402
    _finding,
    _write_pipeline,
)


def _pipeline_with_missing_impact(tmp_path: Path) -> None:
    # Source: real mechanism + description, NO impact rendered (the breadth
    # agent used a refutation-shaped block with `Impact if real`).
    source = (
        "### Finding [TF-1]: Fixture\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:L10\n"
        "**Root Cause**: `claimRefund` deletes the refund slot before the event at L582\n"
        "**Description**: `claimRefund` deletes the refund slot before the event at L582\n"
        "**Impact if real**: repeated refunds\n"
        "**Verdict**: REFUTATION_PROPOSAL\n\n"
    )
    # Chunk: faithful one-to-one normalization (preserves what exists).
    chunk = _finding(
        "CC-1",
        source_ids=("TF-1",),
        mechanism="`claimRefund` deletes the refund slot before the event at L582",
        impact="Blocked impact, stated per the source: repeated refunds",
    )
    # Final inventory: the synthesizer dropped it entirely -> needs re-emission.
    other = _finding("INV-001", source_ids=("TF-9",))
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=other)


def test_reemitted_unparseable_row_is_delivered_with_visible_debt(tmp_path: Path) -> None:
    _pipeline_with_missing_impact(tmp_path)
    before = IR.reconcile_inventory(tmp_path, persist=False)
    (tf1,) = [r for r in before["candidates"] if r["source_finding_id"] == "TF-1"]
    # Dropped by the synthesizer: debt of SOME kind, and nothing to splice.
    assert tf1["disposition"] == "HUMAN_REVIEW_DEBT"
    assert not IR.driver_restorable_preservation_row(tf1), "nothing to splice"

    receipt = reemit_authority._apply_inventory_reemit_repair_for_tests(tmp_path)
    assert receipt["status"] != "NO_DEBT"
    (row,) = receipt["rows"]
    assert row["source_finding_id"] == "TF-1"
    target = row["target_finding_id"]
    assert f"### Finding [{target}]" in (tmp_path / "findings_inventory.md").read_text("utf-8")

    replay = IR.reconcile_inventory(tmp_path, persist=False)
    (after,) = [r for r in replay["candidates"] if r["source_finding_id"] == "TF-1"]
    # Delivered (bound to the re-emitted block) with the debt still visible.
    assert after["disposition"] == "HUMAN_REVIEW_DEBT"
    assert after["reason_code"] == "REEMIT_UNPARSEABLE_SOURCE_DEBT"
    assert after["proposed_target_finding_id"] == target
    assert replay["artifact_issues"] == [], replay["artifact_issues"]
    assert replay["summary"]["HUMAN_REVIEW_DEBT"] == 1

    # The materialized transaction replays (no InventoryReemitError)...
    planned = {
        name: (tmp_path / name).read_bytes()
        for name in reemit_authority.MATERIALIZATION_FILES
    }
    reemit_authority.validate_inventory_reemit_materialization(tmp_path, planned)
    # ...and the aggregate parity gate no longer halts on it.
    assert V._validate_inventory_parity(tmp_path) == []
    # ...while the human-review artifact still carries it.
    IR.write_inventory_reconciliation(tmp_path)
    review = (tmp_path / IR.HUMAN_REVIEW_FILE).read_text("utf-8")
    assert "TF-1" in review and "REEMIT_UNPARSEABLE_SOURCE_DEBT" in review


def test_content_bearing_debt_still_blocks_parity(tmp_path: Path) -> None:
    """Negative control: a facet the source DOES carry and the final block
    drops is real loss and keeps gating."""
    source = _finding("TF-1", mechanism="the setter has no bound at `Gateway.sol:L142`")
    chunk = _finding("CC-1", source_ids=("TF-1",), mechanism="the setter has no bound at `Gateway.sol:L142`")
    final = _finding("INV-001", source_ids=("TF-1", "CC-1"), mechanism="a paraphrase that drops every identifier")
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)
    issues = V._validate_inventory_parity(tmp_path)
    assert any("NEEDS_INVENTORY_REVIEW" in issue for issue in issues), issues


def test_irreparable_predicate_is_narrow() -> None:
    base = {
        "disposition": "HUMAN_REVIEW_DEBT",
        "reason_code": "REEMIT_UNPARSEABLE_SOURCE_DEBT",
        "required_preservation_axes": ["UNPARSEABLE_IMPACT"],
        "proposed_target_finding_id": "INV-112",
        "source_impact": "",
    }
    assert V._irreparable_source_facet_ambiguity(base)
    assert not V._irreparable_source_facet_ambiguity({**base, "proposed_target_finding_id": ""})
    assert not V._irreparable_source_facet_ambiguity({**base, "required_preservation_axes": ["UNPARSEABLE_IMPACT", "ROOT_CAUSE"], "source_root_cause": "bytes"})
    assert not V._irreparable_source_facet_ambiguity({**base, "required_preservation_axes": []})
    assert not V._irreparable_source_facet_ambiguity({**base, "reason_code": "MISSING_FINAL_DISPOSITION"})
    assert not V._irreparable_source_facet_ambiguity({**base, "disposition": "RETAINED"})
