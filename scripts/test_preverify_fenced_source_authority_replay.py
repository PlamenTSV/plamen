"""Frozen producer and authority reader agree on inert preserved source text.

The existing synthetic accepted-chain fixture owns the initial source bytes;
the real frozen producer binds them before the independent authority replays
them. No receipt is re-addressed or fabricated to bless changed output bytes.
No providers, target audits, or exploit reproduction are involved.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

import artifact_ledger as AL
from preverify_frozen_projection import (
    PreverifyFrozenProjectionError,
    prepare_preverify_frozen_projection,
)
from preverify_projection_authority import PreverifyProjectionAuthorityError
import test_chain_driver_boundary_authority_red as CHAIN
import test_preverify_chain_candidate_delta as DELTA
import test_preverify_runtime_source_replay_red as REPLAY


# Exact harmless base block emitted by the accepted-source fixture. Repeating
# its full contents tests an identical live duplicate, not a divergent claim.
BASE_BLOCK = (
    "### Finding [INV-1]: Existing candidate\n"
    "**Verdict**: CONFIRMED\n"
    "**Severity**: Medium\n"
    "**Location**: src/Fixture.sol:1\n"
    "**Description**: Existing mechanism.\n"
    "**Impact**: Existing impact.\n"
)


def _context(tmp_path, monkeypatch, *, fence="```", duplicate_live=False):
    preserved = (
        "\n**Preserved Source Block**:\n"
        f"{fence}markdown\n"
        "### Finding [A-02]: Inert producer-local identity\n"
        "### Finding [INV-999]: Inert canonical-looking identity\n"
        "### Finding [INV-1]: Inert duplicate of the live identity\n"
        f"{fence}\n"
    )
    extra = preserved
    if duplicate_live:
        extra += "\n" + BASE_BLOCK + preserved
    project, root, pair, source_before = DELTA._accepted_delta_sources(
        tmp_path, monkeypatch, base_inventory_extra=extra,
    )
    assert source_before == (root / "findings_inventory.md").read_bytes()
    assert preserved.encode("utf-8") in source_before
    frozen = prepare_preverify_frozen_projection(
        scratchpad=root, project_root=project, pipeline="sc", mode="thorough",
        ecosystem="evm", backend="claude", phase_name="sc_verify_queue",
        run_id=CHAIN.RUN_ID, chain_pair_projection=pair,
    )
    assert frozen["state"] == "OUTPUT_COMMITTED"
    context = REPLAY._context_from_frozen(root, frozen)
    assert context["inventory_raw"].startswith(source_before.rstrip())
    return context


@pytest.mark.parametrize("fence", ("```", "````", "~~~"))
def test_actual_frozen_authority_ignores_preserved_source_headings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fence: str,
):
    context = _context(tmp_path, monkeypatch, fence=fence)
    fixed = context["receipt"]["candidate_delivery_fixed_point"]
    assert fixed["base_ids"] == ["INV-1"]
    assert "A-02" not in fixed["frozen_ids"]
    assert "INV-999" not in fixed["frozen_ids"]
    records = json.loads(context["records_raw"].decode("utf-8"))["records"]
    assert sorted(row["inventory_id"] for row in records) == fixed["frozen_ids"]
    before_ledger = deepcopy(AL.read_artifact_ledger(context["root"]))
    receipt_path = context["root"] / context["authority"]["receipt_path"]
    before_receipt = receipt_path.read_bytes()
    # This independent replay formerly raw-scanned all three inert headings
    # despite exact producer bytes and a correctly derived fixed point.
    REPLAY._validate_context(context)
    REPLAY._validate_context(context)
    assert AL.read_artifact_ledger(context["root"]) == before_ledger
    assert receipt_path.read_bytes() == before_receipt


@pytest.mark.parametrize("identity", ("INV-777", "INV-1"))
def test_frozen_authority_rejects_unowned_live_extra_or_duplicate_heading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identity: str,
):
    context = _context(tmp_path, monkeypatch)
    REPLAY._validate_context(context)
    before_ledger = deepcopy(AL.read_artifact_ledger(context["root"]))
    before_receipt = deepcopy(context["receipt"])
    changed = context["inventory_raw"] + (
        f"\n### Finding [{identity}]: Unowned live identity\n"
        "**Severity**: Low\n"
    ).encode("utf-8")
    # Preserve every original authority/receipt; a live output change is not
    # equivalent to inert quoted source and cannot acquire producer authority.
    with pytest.raises(PreverifyProjectionAuthorityError, match="inventory|source|binding|bytes"):
        REPLAY._validate_context(context, inventory_raw=changed)
    assert context["receipt"] == before_receipt
    assert AL.read_artifact_ledger(context["root"]) == before_ledger


def test_identical_duplicate_live_source_heading_still_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    # Even an authenticated source cannot turn duplicate live records into a
    # unique fixed-point denominator. Accept rejection at producer or reader;
    # never weaken the reader to a set that hides the repeated live heading.
    with pytest.raises(
        (PreverifyFrozenProjectionError, PreverifyProjectionAuthorityError),
        match="duplicate|fixed point",
    ):
        context = _context(tmp_path, monkeypatch, duplicate_live=True)
        REPLAY._validate_context(context)
