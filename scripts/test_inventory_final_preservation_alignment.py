"""Final-scope facet preservation must survive enrichment, never survive loss.

DODO run43 (2026-09-19) committed recon, instantiate, breadth, rescan and all
three inventory chunks, then halted at the canonical aggregate: nine raw
identities were charged `FINAL_SEMANTIC_PRESERVATION_DEBT`, every one of them
with ZERO lost material tokens.  The final inventory block had copied the
source facet and interleaved real code citations (50-400 chars of strictly
more evidence), which broke the single-run `source in target` containment
proxy.  `driver_restorable_preservation_row` then called the rows restorable,
the aggregate cannot splice pre-render, and the reemit authority correctly
refused to duplicate one-to-one deliveries -- so the run died on rows that
were information-complete.

run42 halted on the SAME class hidden behind two other proxies (a swallowed
`---` and an empty-bytes "restorable" row); removing those exposed this one.

The chunk path had already been moved to the material-token property
(`test_inventory_chunk_preservation_alignment.py`).  This file pins the same
grant on the final ONE_TO_ONE_RETENTION_PROPOSAL path with the real run43
fixture and the same negative controls.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import inventory_reconciliation as IR  # noqa: E402

_FIXTURE = json.loads(
    (_SCRIPTS / "_fixtures_run43_final_preservation.json").read_text("utf-8")
)
_SOURCE = _FIXTURE["source_root_cause"]
_TARGET = _FIXTURE["target_root_cause"]
_DESCRIPTION = _FIXTURE["target_description"]

# Every axis not under test carries benign, byte-identical text so the
# assertion measures the enriched axis and not the empty-source path.
_INERT = "An unrelated but preserved facet sentence for axis isolation."

# The run43 scratchpad, when present on this machine, is the end-to-end oracle.
_RUN43 = Path(
    "/Users/ptsanev/dodo-v3-validation-run43/omni-chain-contracts/.scratchpad"
)


def _candidate(root_cause: str = _INERT, impact: str = _INERT,
               preconditions: str = _INERT) -> dict[str, str]:
    return {
        "source_root_cause": root_cause,
        "source_impact": impact,
        "source_preconditions": preconditions,
    }


def _target(root_cause: str = _INERT, description: str = "",
            impact: str = _INERT, preconditions: str = _INERT) -> dict[str, str]:
    return {
        "root_cause": root_cause,
        "description": description,
        "impact": impact,
        "preconditions": preconditions,
    }


def test_fixture_still_exercises_the_proxy() -> None:
    """The fixture is worthless if the substring proxy would have passed it."""
    source = IR._semantic_lexical_surface(_SOURCE)
    target = IR._semantic_lexical_surface(" ".join((_TARGET, _DESCRIPTION)))
    assert source not in target, "run43 INV-039 no longer breaks contiguity"
    assert IR._lost_material_tokens(source, target) == [], (
        "run43 INV-039 lost material tokens; the fixture is not the "
        "enriched-but-complete class"
    )
    assert len(target) > len(source) + 50, "the target is not an enrichment"


def test_enriched_final_block_is_preservation_not_loss() -> None:
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=_SOURCE),
        _target(root_cause=_TARGET, description=_DESCRIPTION),
        allow_run_alignment=True,
    )
    assert deltas == [], (
        "an enriched final facet was scored as unpreserved; this is the exact "
        f"false negative that halted DODO run43: {deltas}"
    )


def test_strict_containment_alone_would_still_charge_the_row() -> None:
    """Documents WHY the final path needs the grant: the default is the proxy."""
    assert IR._semantic_preservation_deltas(
        _candidate(root_cause=_SOURCE),
        _target(root_cause=_TARGET, description=_DESCRIPTION),
    ) == ["ROOT_CAUSE"]


def test_truncated_final_block_is_still_loss() -> None:
    truncated = _TARGET.split("tracing the failure forward")[0]
    assert IR._semantic_preservation_deltas(
        _candidate(root_cause=_SOURCE), _target(root_cause=truncated),
        allow_run_alignment=True,
    ) == ["ROOT_CAUSE"], "a truncated final facet passed preservation"


def test_dropped_line_reference_in_final_block_is_loss() -> None:
    mangled = _TARGET.replace("GatewayCrossChain.sol:522-531", "the refund branch")
    deltas = IR._semantic_preservation_deltas(
        _candidate(root_cause=_SOURCE), _target(root_cause=mangled),
        allow_run_alignment=True,
    )
    assert deltas == ["ROOT_CAUSE"]


def test_paraphrased_final_block_is_loss() -> None:
    paraphrase = (
        "One payout site uses a gas-capped transfer primitive, so contract "
        "wallets cannot receive native assets and the bridge refunds them on "
        "the origin chain instead."
    )
    assert IR._semantic_preservation_deltas(
        _candidate(root_cause=_SOURCE), _target(root_cause=paraphrase),
        allow_run_alignment=True,
    ) == ["ROOT_CAUSE"]


@pytest.mark.parametrize("axis_field,target_field", [
    ("source_impact", "impact"),
    ("source_preconditions", "preconditions"),
])
def test_final_alignment_applies_to_every_facet_axis(axis_field, target_field) -> None:
    candidate = _candidate()
    candidate[axis_field] = _SOURCE
    target = _target()
    target[target_field] = _TARGET
    assert IR._semantic_preservation_deltas(
        candidate, target, allow_run_alignment=True,
    ) == []


@pytest.mark.skipif(
    not (_RUN43 / "findings_inventory.md").is_file(),
    reason="DODO run43 scratchpad not present on this machine",
)
def test_run43_recompute_has_no_refusal_eligible_rows() -> None:
    """End-to-end oracle on the real halted scratchpad.

    Before the final-path grant: candidates=87, debt=9, restorable=9, every
    row `FINAL_SEMANTIC_PRESERVATION_DEBT` with `lost_tokens=[]`.  After: 0.
    """
    result = IR.reconcile_inventory(_RUN43, persist=False)
    rows = result["candidates"]
    assert len(rows) == 87
    debt = [r for r in rows if r.get("disposition") == "HUMAN_REVIEW_DEBT"]
    restorable = [r for r in debt if IR.driver_restorable_preservation_row(r)]
    assert restorable == [], [
        (r["source_artifact"], r["source_finding_id"], r["reason_code"])
        for r in restorable
    ]
    assert not [
        r for r in debt
        if r.get("reason_code") == "FINAL_SEMANTIC_PRESERVATION_DEBT"
        and not any(
            str(axis).startswith("UNPARSEABLE_")
            for axis in r.get("required_preservation_axes") or ()
        )
    ], "a content-bearing final preservation debt row survived the grant"
