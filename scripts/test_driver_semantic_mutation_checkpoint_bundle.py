from __future__ import annotations

from pathlib import Path

import plamen_driver as D
from artifact_ledger import (
    arm_semantic_mutation,
    semantic_mutation_events,
)


RUN_ID = "12345678-1234-4123-8123-123456789abc"


def _config(tmp_path: Path) -> dict:
    return {
        "project_root": str(tmp_path),
        "_run_id": RUN_ID,
        "_active_phase_names": [
            "recon",
            "inventory",
            "depth",
            "sc_semantic_dedup",
            "chain_iter2",
            "sc_verify_queue",
        ],
    }


def test_changed_sidecar_without_descendants_is_durably_acknowledged(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    sidecar = scratch / "finding_records.json"
    sidecar.write_text("before\n", encoding="utf-8")
    event = arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:finding_records.json",
        mutation_kind="FINDING_PROMOTION_RECORDS",
        run_id=RUN_ID,
    )
    sidecar.write_text("after\n", encoding="utf-8")
    checkpoint = D.Checkpoint(completed=["recon"], run_id=RUN_ID)

    assert D._finalize_driver_semantic_mutation(
        scratch,
        _config(tmp_path),
        checkpoint,
        event,
        owner_phase="sc_semantic_dedup",
    ) == []

    event_id = str(event["event_id"])
    assert event_id in checkpoint.semantic_mutation_acks
    assert event_id in D.Checkpoint.load(scratch).semantic_mutation_acks
    durable = {row["event_id"]: row for row in semantic_mutation_events(scratch)}
    assert durable[event_id]["status"] == "INVALIDATION_APPLIED"
    assert durable[event_id]["invalidated_work_unit_keys"] == []
    assert durable[event_id]["checkpoint_reconciled"] is True


def test_authorized_successor_preserves_prior_phase_prefix_and_rewinds_later(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    checkpoint = D.Checkpoint(
        completed=[
            "recon",
            "inventory",
            "depth",
            "sc_semantic_dedup",
            "chain_iter2",
        ],
        run_id=RUN_ID,
    )
    finalized = {
        "event_id": "SMUT-" + "A" * 24,
        "status": "INVALIDATION_APPLIED",
        "invalidated_work_unit_keys": [
            "sc/core/evm/claude/inventory/exact_reconciliation",
            "sc/core/evm/claude/depth/niche.lifecycle.000001",
            "sc/core/evm/claude/chain_iter2/model",
        ],
    }
    acknowledged: list[list[str]] = []
    monkeypatch.setattr(
        D,
        "finalize_semantic_mutation",
        lambda *_args, **_kwargs: dict(finalized),
    )
    monkeypatch.setattr(
        D,
        "acknowledge_semantic_mutations",
        lambda _root, event_ids, **_kwargs: acknowledged.append(list(event_ids)),
    )

    assert D._finalize_driver_semantic_mutation(
        scratch,
        _config(tmp_path),
        checkpoint,
        {"event_id": finalized["event_id"]},
        owner_phase="sc_semantic_dedup",
    ) == []

    assert checkpoint.completed == [
        "recon",
        "inventory",
        "depth",
        "sc_semantic_dedup",
    ]
    assert acknowledged == [[finalized["event_id"]]]


def test_inventory_root_is_finalized_before_coupled_sidecars() -> None:
    events = [
        {"event_id": "id", "artifact_identity": "scratchpad:_id_ledger.json"},
        {
            "event_id": "records",
            "artifact_identity": "scratchpad:finding_records.json",
        },
        {
            "event_id": "inventory",
            "artifact_identity": "scratchpad:findings_inventory.md",
        },
    ]

    assert [
        row["event_id"]
        for row in D._driver_semantic_mutation_finalize_order(events)
    ] == ["inventory", "records", "id"]
