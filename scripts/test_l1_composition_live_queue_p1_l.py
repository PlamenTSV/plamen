from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

import l1_composition_queue_runtime as Q
import l1_composition_runtime as R
from plamen_parsers import (
    _read_typed_queue_work_items,
    _write_queue_work_item_records_manifest,
)
from queue_work_items import LineageLink, QueueWorkItem, SeverityProposal


RUN_ID = "run-l1-live-001"
SNAPSHOT = "a" * 64


def _context() -> dict[str, str]:
    return {
        "pipeline": "l1",
        "mode": "core",
        "language": "go",
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
    }


def _config() -> dict[str, object]:
    return {
        **_context(),
        "_run_id": RUN_ID,
        "_audit_snapshot": {"snapshot_digest": SNAPSHOT},
        "_l1_composition_producer_bindings": {
            "fact_producer_identity": "fact-worker",
            "fact_producer_invocation_id": "fact-invocation",
            "disposition_producer_identity": "disposition-worker",
            "disposition_producer_invocation_id": "disposition-invocation",
        },
    }


def _block(candidate_id: str) -> str:
    return (
        f"## Finding [{candidate_id}]: Candidate\n\n"
        "**Severity**: Medium\n\nBound source record.\n"
    )


def _ordinary_item() -> QueueWorkItem:
    return QueueWorkItem(
        candidate_identity="H-01",
        work_item_id="H-01",
        lineage=(LineageLink(identity="H-01", relation="ORIGIN", source_artifact="findings_inventory.md"),),
        aliases=(),
        constituents=(),
        severity_proposal=SeverityProposal(level="High"),
        evidence_class="inventory",
        bug_class="state-consistency",
        preferred_tag="CODE-TRACE",
        queue_priority=1,
        location_records=(),
        primary_artifacts=("findings_inventory.md",),
        poc_class="unit",
        title="Ordinary finding",
        effective_evidence_scope="IN_SCOPE_SOURCE",
        effective_proof_scope="ANALYTICAL",
        effective_harm_scope="UNPROVEN",
    )


def _prepare(root: Path) -> dict:
    (root / R.INVENTORY_NAME).write_text(
        "# Inventory\n\n" + _block("L1-A1") + "\n" + _block("L1-B1"),
        encoding="utf-8",
    )
    worklist = R.write_l1_composition_fact_worklist(root, **_context())
    assert worklist["occurrence_count"] == 2
    rows = {row["candidate_id"]: row for row in worklist["occurrences"]}
    atom = {"kind": "STATE", "atom_id": "ledger.commit"}
    typed = {
        "schema_version": R.TYPED_RECORDS_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "producer_identity": "fact-worker",
        "producer_invocation_id": "fact-invocation",
        "records": [
            {
                "candidate_id": rows[identity]["candidate_id"],
                "source_artifact": rows[identity]["source_artifact"],
                "source_block_sha256": rows[identity]["source_block_sha256"],
                "language": "GO",
                "layer": "execution" if identity == "L1-A1" else "consensus",
                "subsystem": "execution" if identity == "L1-A1" else "consensus",
                "root_cause_id": f"ROOT-{identity}",
                "candidate_state": "REFUTED" if identity == "L1-A1" else "CONFIRMED",
                "requires": [] if identity == "L1-A1" else [atom],
                "produces": [atom] if identity == "L1-A1" else [],
                "touches": [],
            }
            for identity in ("L1-A1", "L1-B1")
        ],
    }
    (root / R.TYPED_RECORDS_NAME).write_text(
        json.dumps(typed, indent=2) + "\n", encoding="utf-8"
    )
    assert R.validate_l1_composition_fact_records(root, **_context()) == []
    runtime = R.write_l1_composition_runtime(root, **_context())
    assert len(runtime["work_packets"]) == 1
    # Canonical NC-3: producer-local REFUTED remains eligible and visible.
    refuted = next(
        row for row in runtime["graph"]["negative_closure_suppression_denominator"]
        if row["candidate_id"] == "L1-A1"
    )
    assert refuted["terminal_suppression_authorized"] is False
    assert refuted["eligible_for_composition"] is True
    assert any(
        row["code"] == "UNBACKED_PRODUCER_REFUTATION"
        for row in runtime["graph"]["negative_closure_debt"]
    )
    dispositions = {
        "schema_version": R.MODEL_DISPOSITIONS_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "producer_identity": "disposition-worker",
        "producer_invocation_id": "disposition-invocation",
        "runtime_digest": runtime["runtime_digest"],
        "graph_digest": runtime["graph"]["graph_digest"],
        "work_packets_digest": runtime["work_packets_digest"],
        "dispositions": [
            {
                "obligation_id": runtime["work_packets"][0]["obligation_id"],
                "disposition": "COMPOUND_CANDIDATE",
                "rationale": "Independent composed reachability requires verification.",
            }
        ],
    }
    (root / R.MODEL_DISPOSITIONS_NAME).write_text(
        json.dumps(dispositions, indent=2) + "\n", encoding="utf-8"
    )
    receipt = R.write_l1_composition_receipt(root, runtime, dispositions)
    assert len(receipt["compound_handoffs"]) == 1
    _write_queue_work_item_records_manifest(
        root / "verification_queue.md", (_ordinary_item(),)
    )
    return receipt


def test_fact_worklist_is_exact_stale_detecting_and_does_not_read_typed_output(
    tmp_path: Path,
):
    (tmp_path / R.INVENTORY_NAME).write_text(
        "# Inventory\n\n" + _block("L1-A1"), encoding="utf-8"
    )
    first = R.write_l1_composition_fact_worklist(tmp_path, **_context())
    (tmp_path / R.TYPED_RECORDS_NAME).write_text("not json", encoding="utf-8")
    second = R.derive_l1_composition_fact_worklist(tmp_path, **_context())
    assert second == first
    (tmp_path / R.INVENTORY_NAME).write_text(
        "# Inventory\n\n" + _block("L1-A1") + _block("L1-B1"),
        encoding="utf-8",
    )
    assert R.validate_l1_composition_fact_worklist(
        first, tmp_path, **_context()
    )


def test_promoted_inventory_duplicates_do_not_disable_composition_graph(
    tmp_path: Path,
):
    inventory = "# Inventory\n\n" + _block("L1-A1") + "\n" + _block("L1-B1")
    (tmp_path / R.INVENTORY_NAME).write_text(inventory, encoding="utf-8")
    (tmp_path / "depth_consensus_findings.md").write_text(
        "# Depth\n\n" + _block("L1-A1") + "\n" + _block("L1-B1"),
        encoding="utf-8",
    )
    worklist = R.write_l1_composition_fact_worklist(tmp_path, **_context())
    atom = {"kind": "STATE", "atom_id": "ledger.commit"}
    records = []
    for row in worklist["occurrences"]:
        first = row["candidate_id"] == "L1-A1"
        records.append({
            "candidate_id": row["candidate_id"],
            "source_artifact": row["source_artifact"],
            "source_block_sha256": row["source_block_sha256"],
            "language": "GO",
            "layer": "execution" if first else "consensus",
            "subsystem": "execution" if first else "consensus",
            "root_cause_id": f"ROOT-{row['candidate_id']}",
            "candidate_state": "CONFIRMED",
            "requires": [] if first else [atom],
            "produces": [atom] if first else [],
            "touches": [],
        })
    (tmp_path / R.TYPED_RECORDS_NAME).write_text(json.dumps({
        "schema_version": R.TYPED_RECORDS_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "producer_identity": "fact-worker",
        "producer_invocation_id": "fact-invocation",
        "records": records,
    }), encoding="utf-8")
    assert R.validate_l1_composition_fact_records(tmp_path, **_context()) == []
    runtime = R.derive_l1_composition_runtime(tmp_path, **_context())
    assert runtime["denominator_count"] == 4
    assert runtime["represented_denominator_count"] == 4
    assert runtime["measurable_count"] == 2
    assert len(runtime["work_packets"]) == 1
    shadowed = [
        row for row in runtime["facts"]
        if row["source_artifact"] == "depth_consensus_findings.md"
    ]
    assert all(
        row["issues"] == ["DUPLICATE_SOURCE_CANDIDATE_SHADOWED_BY_INVENTORY"]
        for row in shadowed
    )


def test_live_queue_delivery_is_additive_proposal_only_and_idempotent(tmp_path: Path):
    receipt = _prepare(tmp_path)
    first = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert first.committed and first.safe_to_shard
    assert len(first.authorized_work_item_ids) == 1
    items = _read_typed_queue_work_items(tmp_path / "verification_queue.md")
    assert [item.work_item_id for item in items][0] == "H-01"
    generated = next(item for item in items if item.work_item_id.startswith("L1CH-"))
    assert generated.evidence_class == "l1-composition-generator"
    assert generated.effective_proof_scope == "NONE"
    assert generated.effective_harm_scope == "UNPROVEN"
    assert generated.severity_proposal.level == "Medium"
    assert Q.validated_authorized_work_item_ids(tmp_path, _config()) == (
        generated.work_item_id,
    )
    before = tuple(items)
    second = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert second.committed
    assert _read_typed_queue_work_items(tmp_path / "verification_queue.md") == before
    assert json.loads(
        (tmp_path / Q.DELIVERY_RECEIPT_NAME).read_text(encoding="utf-8")
    )["composition_receipt_digest"] == receipt["receipt_digest"]


def test_upstream_tamper_degrades_without_deleting_queue(tmp_path: Path):
    _prepare(tmp_path)
    before = _read_typed_queue_work_items(tmp_path / "verification_queue.md")
    receipt = json.loads((tmp_path / R.RECEIPT_NAME).read_text(encoding="utf-8"))
    receipt["compound_handoffs"] = []
    (tmp_path / R.RECEIPT_NAME).write_text(json.dumps(receipt), encoding="utf-8")
    outcome = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert not outcome.committed and outcome.safe_to_shard
    assert _read_typed_queue_work_items(tmp_path / "verification_queue.md") == before


def test_queue_rebinds_driver_principals_and_rejects_foreign_valid_rows(
    tmp_path: Path,
):
    _prepare(tmp_path)
    before = _read_typed_queue_work_items(tmp_path / "verification_queue.md")
    runtime = json.loads(
        (tmp_path / R.RUNTIME_NAME).read_text(encoding="utf-8")
    )
    dispositions_path = tmp_path / R.MODEL_DISPOSITIONS_NAME
    dispositions = json.loads(dispositions_path.read_text(encoding="utf-8"))
    dispositions["producer_identity"] = "foreign-disposition-worker"
    dispositions["producer_invocation_id"] = "foreign-disposition-invocation"
    dispositions_path.write_text(json.dumps(dispositions), encoding="utf-8")
    # This is self-consistent under the model-authored fields, but it is not
    # bound to the driver's actual launch principal.
    R.write_l1_composition_receipt(tmp_path, runtime, dispositions)

    outcome = Q.apply_l1_composition_queue_delivery(tmp_path, _config())

    assert not outcome.committed and outcome.safe_to_shard
    assert _read_typed_queue_work_items(tmp_path / "verification_queue.md") == before
    assert any("foreign" in issue.casefold() for issue in outcome.issues)


def test_exact_no_source_worklist_skips_queue_provider_without_debt(
    tmp_path: Path,
):
    R.write_l1_composition_fact_worklist(tmp_path, **_context())
    _write_queue_work_item_records_manifest(
        tmp_path / "verification_queue.md", (_ordinary_item(),)
    )
    before = _read_typed_queue_work_items(tmp_path / "verification_queue.md")

    outcome = Q.apply_l1_composition_queue_delivery(tmp_path, _config())

    assert not outcome.committed and outcome.safe_to_shard
    assert outcome.issues == ()
    assert outcome.status == {
        "state": "NOT_TRIGGERED",
        "reason": "NO_SOURCE_OCCURRENCES",
    }
    assert _read_typed_queue_work_items(tmp_path / "verification_queue.md") == before


def test_prepared_crash_recovers_exact_successor_on_resume(tmp_path: Path):
    _prepare(tmp_path)

    def crash(boundary: str) -> None:
        assert boundary == "journal_prepared"
        raise SystemExit(91)

    with pytest.raises(SystemExit, match="91"):
        Q.apply_l1_composition_queue_delivery(tmp_path, _config(), fault_hook=crash)
    journal = json.loads(
        (tmp_path / Q.DELIVERY_JOURNAL_NAME).read_text(encoding="utf-8")
    )
    assert journal["state"] == "PREPARED"
    resumed = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert resumed.committed and resumed.safe_to_shard
    assert len(Q.validated_authorized_work_item_ids(tmp_path, _config())) == 1
    journal = json.loads(
        (tmp_path / Q.DELIVERY_JOURNAL_NAME).read_text(encoding="utf-8")
    )
    assert journal["state"] == "COMMITTED"


@pytest.mark.parametrize(
    "crash_after",
    [
        "verification_queue.md",
        "verification_queue.json",
        "verification_queue.work_items.json",
        Q.DELIVERY_RECEIPT_NAME,
        Q.DELIVERY_DEBT_NAME,
        Q.DELIVERY_STATUS_NAME,
    ],
)
def test_every_publish_boundary_recovers_without_loss(
    tmp_path: Path, crash_after: str
):
    _prepare(tmp_path)

    def crash(boundary: str) -> None:
        if boundary == f"published:{crash_after}":
            raise SystemExit(93)

    with pytest.raises(SystemExit):
        Q.apply_l1_composition_queue_delivery(
            tmp_path, _config(), fault_hook=crash
        )
    journal = json.loads(
        (tmp_path / Q.DELIVERY_JOURNAL_NAME).read_text(encoding="utf-8")
    )
    assert journal["state"] == "PREPARED"
    resumed = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert resumed.committed and resumed.safe_to_shard
    items = _read_typed_queue_work_items(tmp_path / "verification_queue.md")
    assert {item.work_item_id for item in items} == {
        "H-01", *resumed.authorized_work_item_ids
    }


def test_tampered_prepared_journal_never_shards_or_mutates(tmp_path: Path):
    _prepare(tmp_path)

    def crash(_: str) -> None:
        raise SystemExit(92)

    with pytest.raises(SystemExit):
        Q.apply_l1_composition_queue_delivery(tmp_path, _config(), fault_hook=crash)
    queue_before = {
        name: (tmp_path / name).read_bytes()
        for name in ("verification_queue.md", "verification_queue.json", "verification_queue.work_items.json")
    }
    journal = json.loads(
        (tmp_path / Q.DELIVERY_JOURNAL_NAME).read_text(encoding="utf-8")
    )
    journal["after_queue_digest"] = "f" * 64
    (tmp_path / Q.DELIVERY_JOURNAL_NAME).write_text(
        json.dumps(journal), encoding="utf-8"
    )
    outcome = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert not outcome.committed and not outcome.safe_to_shard
    assert {
        name: (tmp_path / name).read_bytes() for name in queue_before
    } == queue_before


def test_recomputed_foreign_stage_journal_cannot_escape_scratchpad(
    tmp_path: Path,
):
    _prepare(tmp_path)

    def crash(boundary: str) -> None:
        if boundary == "journal_prepared":
            raise SystemExit(94)

    with pytest.raises(SystemExit, match="94"):
        Q.apply_l1_composition_queue_delivery(
            tmp_path, _config(), fault_hook=crash
        )
    journal_path = tmp_path / Q.DELIVERY_JOURNAL_NAME
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    original_stage = tmp_path / journal["stage_directory"]
    outside = tmp_path.parent / f"{tmp_path.name}-foreign-stage"
    outside.mkdir()
    outside_before: dict[str, bytes] = {}
    for name in journal["publish_order"]:
        raw = (original_stage / name).read_bytes()
        (outside / name).write_bytes(raw)
        outside_before[name] = raw
    journal["stage_directory"] = f"../{outside.name}"
    journal["journal_digest"] = ""
    journal["journal_digest"] = Q._digest(journal)
    journal_path.write_text(json.dumps(journal), encoding="utf-8")

    outcome = Q.apply_l1_composition_queue_delivery(tmp_path, _config())

    assert not outcome.committed
    assert not outcome.safe_to_shard
    assert {
        name: (outside / name).read_bytes() for name in outside_before
    } == outside_before


def test_publish_postimage_is_reread_before_commit(tmp_path: Path):
    _prepare(tmp_path)
    mutated = False

    def mutate_after_publish(boundary: str) -> None:
        nonlocal mutated
        if boundary == f"published:{Q.DELIVERY_STATUS_NAME}" and not mutated:
            mutated = True
            (tmp_path / "verification_queue.work_items.json").write_text(
                "{}\n", encoding="utf-8"
            )

    outcome = Q.apply_l1_composition_queue_delivery(
        tmp_path, _config(), fault_hook=mutate_after_publish
    )
    assert mutated
    assert not outcome.committed and not outcome.safe_to_shard
    journal = json.loads(
        (tmp_path / Q.DELIVERY_JOURNAL_NAME).read_text(encoding="utf-8")
    )
    assert journal["state"] == "PREPARED"
    resumed = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert resumed.committed and resumed.safe_to_shard
    assert len(Q.validated_authorized_work_item_ids(tmp_path, _config())) == 1


def test_symlink_stage_component_is_rejected_without_queue_mutation(
    tmp_path: Path,
):
    if not hasattr(Path, "symlink_to"):
        pytest.skip("symlinks unavailable")
    _prepare(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    stage_parent = tmp_path / "_l1_composition_queue_transaction"
    try:
        stage_parent.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    before = {
        name: (tmp_path / name).read_bytes()
        for name in ("verification_queue.md", "verification_queue.json", "verification_queue.work_items.json")
    }
    outcome = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert not outcome.committed and outcome.safe_to_shard
    assert {name: (tmp_path / name).read_bytes() for name in before} == before


def test_identity_collision_preserves_ordinary_row_and_withholds_authorization(
    tmp_path: Path,
):
    receipt = _prepare(tmp_path)
    proposal_id = receipt["compound_handoffs"][0]["proposal_id"]
    ordinary = _ordinary_item()
    collision = replace(ordinary, candidate_identity=proposal_id, work_item_id=proposal_id,
        lineage=(LineageLink(identity=proposal_id, relation="ORIGIN", source_artifact="findings_inventory.md"),),
        queue_priority=2)
    _write_queue_work_item_records_manifest(
        tmp_path / "verification_queue.md", (ordinary, collision)
    )
    outcome = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert outcome.committed and outcome.safe_to_shard
    assert outcome.authorized_work_item_ids == ()
    items = _read_typed_queue_work_items(tmp_path / "verification_queue.md")
    assert tuple(items) == (ordinary, collision)
    assert any("QUEUE_IDENTITY_COLLISION" in issue for issue in outcome.issues)


def test_recomputed_delivery_receipt_cannot_authorize_foreign_lookalike(
    tmp_path: Path,
):
    _prepare(tmp_path)
    outcome = Q.apply_l1_composition_queue_delivery(tmp_path, _config())
    assert outcome.committed
    items = list(_read_typed_queue_work_items(tmp_path / "verification_queue.md"))
    legitimate = next(item for item in items if item.work_item_id.startswith("L1CH-"))
    foreign_id = "L1CH-FOREIGNLOOKALIKE01"
    foreign = replace(
        legitimate,
        candidate_identity=foreign_id,
        work_item_id=foreign_id,
        lineage=(
            LineageLink(
                identity=foreign_id,
                relation="ORIGIN",
                source_artifact=R.RECEIPT_NAME,
            ),
        ),
        queue_priority=legitimate.queue_priority + 1,
    )
    items.append(foreign)
    _write_queue_work_item_records_manifest(
        tmp_path / "verification_queue.md", tuple(items)
    )
    delivery_path = tmp_path / Q.DELIVERY_RECEIPT_NAME
    delivery = json.loads(delivery_path.read_text(encoding="utf-8"))
    delivery["authorized_work_item_ids"] = sorted(
        [*delivery["authorized_work_item_ids"], foreign_id]
    )
    delivery["owned_work_item_digests"][foreign_id] = foreign.digest
    delivery["successor_queue_digest"] = Q.queue_record_set_digest(tuple(items))
    delivery["delivery_digest"] = ""
    delivery["delivery_digest"] = Q._digest(delivery)
    delivery_path.write_text(json.dumps(delivery), encoding="utf-8")

    with pytest.raises(ValueError, match="replay|successor|authority"):
        Q.validated_authorized_work_item_ids(tmp_path, _config())
