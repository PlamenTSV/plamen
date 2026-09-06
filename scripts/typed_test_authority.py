"""Test-only helpers for exact verifier completion authority.

Legacy regression fixtures often pre-date the typed queue/work-plan/output
contract.  Tests that exercise post-verification consumers may call this
helper after writing their Markdown queue and verifier outputs.  It creates
the same immutable identity and receipt bindings production requires; it does
not patch, bypass, or relax a production validator.
"""

from __future__ import annotations

import json
from pathlib import Path

import plamen_parsers as P
from queue_work_items import (
    QueueWorkItem,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
    build_queue_work_plan,
)


def _severity_proposal_bytes(item: QueueWorkItem) -> bytes:
    constituents = [item.work_item_id, *item.constituents]
    impact = item.severity_proposal.impact or item.severity_proposal.level
    if impact not in {"High", "Medium", "Low", "Informational"}:
        impact = "Medium"
    likelihood = item.severity_proposal.likelihood or "Medium"
    if likelihood not in {"High", "Medium", "Low"}:
        likelihood = "Medium"
    payload = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": item.work_item_id,
        "constituent_ids": constituents,
        "impact": {
            "class": impact,
            "harmed_asset": "fixture protected asset",
            "harmed_capability": "fixture integrity",
            "premise_id": f"PREM-{item.work_item_id}-IMPACT",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-IMPACT"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": likelihood,
            "actor": "fixture actor",
            "preconditions": ["fixture reachable state"],
            "premise_id": f"PREM-{item.work_item_id}-LIKELIHOOD",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-{item.work_item_id}-LIKELIHOOD"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": item.severity_proposal.level,
        "adjustment": None,
        "constituent_premise_outcomes": {
            value: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
            for value in constituents
        },
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def bind_verifier_outputs(
    scratchpad: Path,
    *,
    shard: str = "fixture_verifier",
    planner_version: str = "test.typed-authority.v1",
    verifier_backend: str = "claude",
) -> None:
    """Bind every currently present output to the current queue snapshot."""
    scratchpad = Path(scratchpad)
    queue = scratchpad / "verification_queue.md"
    if not queue.is_file():
        return
    rows = P.parse_verification_queue_rows(scratchpad)
    if not rows:
        return
    # These are test fixtures whose queue is sometimes assembled incrementally.
    # Re-emit the exact current typed snapshot so a prior fixture step cannot
    # masquerade as immutable production authority for the enlarged queue.
    items = P._write_typed_queue_work_items(queue, rows)
    plan = build_queue_work_plan(
        items,
        {shard: tuple(item.work_item_id for item in items)},
        planner_version=planner_version,
    )
    (scratchpad / "verification_queue.work_plan.json").write_text(
        plan.to_json(), encoding="utf-8"
    )
    for item in items:
        output = scratchpad / item.expected_output_file
        if not output.is_file():
            continue
        proposal = _severity_proposal_bytes(item)
        (scratchpad / f"verify_{item.work_item_id}.severity_proposal.json").write_bytes(
            proposal
        )
        identity = VerifierOutputIdentity.for_assignment(item, plan, shard)
        receipt = VerifierOutputReceipt.bind(
            identity,
            output.read_bytes(),
            severity_proposal=proposal,
            launch_digest="a" * 64,
            verifier_backend=verifier_backend,
        )
        (scratchpad / f"verify_{item.work_item_id}.identity.json").write_text(
            json.dumps(identity.to_dict(), sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        (scratchpad / f"verify_{item.work_item_id}.receipt.json").write_text(
            receipt.to_json(), encoding="utf-8"
        )
