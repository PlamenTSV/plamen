"""Fresh additive repair preserves exact source authority through promotion.

Initial source/chunk owners are explicit synthetic fixtures. Canonical
aggregation, additive reemit, and subsequent registered delivery/promotion
use production code. These are harmless accounting records; no provider,
target audit, verification, or report pipeline is executed.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

import artifact_ledger as AL
import inventory_reemit_authority as REEMIT
import plamen_driver as D
import plamen_validators as V
import test_inventory_canonical_aggregate_phaseio_p0_l as INVENTORY


CANONICAL = ("findings_inventory.md", "finding_records.json", "_id_ledger.json")


def _bytes(root: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    return {name: (root / name).read_bytes() for name in names}


def _reemit_fixture(tmp_path: Path):
    project, root, config = INVENTORY._fixture(tmp_path)
    INVENTORY._seed_canonical_with_one_omitted_candidate(project, root, config)
    before = D._reconcile_exact_inventory(root, persist=False)
    omitted = next(row for row in before["candidates"] if row["source_finding_id"] == "A-02")
    assert omitted["disposition"] == "HUMAN_REVIEW_DEBT"
    assert D._record_inventory_reemit_phase_io(
        scratchpad=root, project_root=project, config=config, run_id=config["_run_id"],
    ) == []
    assert all(ids == {"INV-001", "INV-002"} for ids in INVENTORY._projected_inventory_ids(root))
    receipt = json.loads((root / REEMIT.REEMIT_FILE).read_text(encoding="utf-8"))
    assert len(receipt["rows"]) == 1
    row = receipt["rows"][0]
    assert row["source_artifact"] == "analysis_a.md"
    assert row["source_finding_id"] == "A-02"
    assert row["target_finding_id"] == "INV-002"
    assert row["candidate_key"] == omitted["candidate_key"]
    assert row["source_block_sha256"] == omitted["source_block_sha256"]
    source_hash = hashlib.sha256((root / "analysis_a.md").read_bytes()).hexdigest()
    assert row["source_sha256"] == source_hash == omitted["source_sha256"]
    intent = json.loads((root / REEMIT.INTENT_FILE).read_text(encoding="utf-8"))
    assert row["target_block_sha256"] == hashlib.sha256(
        intent["append_blocks"][0].strip().encode("utf-8")
    ).hexdigest()
    planned = _bytes(root, tuple(REEMIT.MATERIALIZATION_FILES))
    assert REEMIT.validate_inventory_reemit_materialization(root, planned) == receipt
    return root, config, receipt, planned


def _delivery(root: Path):
    return V._build_registered_finding_delivery_receipt_payload(
        root, V._scan_registered_finding_delivery_sources(root),
        (root / "findings_inventory.md").read_text(encoding="utf-8"),
    )


def test_reemit_exact_source_action_prevents_duplicate_promotion(tmp_path: Path):
    root, config, receipt, planned = _reemit_fixture(tmp_path)
    text = planned["findings_inventory.md"].decode("utf-8")
    source_hash = "sha256:" + receipt["rows"][0]["source_sha256"]
    assert f"**Source Actions**: analysis_a.md:A-02@{source_hash}" in text
    assert V._inventory_structural_source_action_referents(text)[
        ("analysis_a.md", "A-02")
    ] == {"INV-002"}
    assert V._inventory_structural_source_hash_action_referents(text)[
        ("analysis_a.md", "A-02", source_hash)
    ] == {"INV-002"}
    actions = {row["action_id"]: row for row in _delivery(root)["actions"]}
    assert actions["A-02"]["disposition"] == "PROMOTED_FINDING"
    assert actions["A-02"]["source_artifact_hash"] == source_hash

    before = _bytes(root, CANONICAL)
    ledger_before = deepcopy(AL.read_artifact_ledger(root))
    owner = "sc/thorough/evm/claude/inventory/additive_reemit"
    assert ledger_before["work_units"][owner]["execution_state"] == "OUTPUT_COMMITTED"
    assert ledger_before["work_units"][owner]["run_id"] == config["_run_id"]
    # This call formerly allocated INV-003 for already-reemitted A-02. Both
    # the first pass and its replay must recognize the existing exact action.
    assert V._promote_depth_findings_to_inventory(root) == []
    assert V._promote_depth_findings_to_inventory(root) == []
    assert _bytes(root, CANONICAL) == before
    assert AL.read_artifact_ledger(root) == ledger_before
    assert all(ids == {"INV-001", "INV-002"} for ids in INVENTORY._projected_inventory_ids(root))
    assert REEMIT.validate_inventory_reemit_materialization(root, planned) == receipt


def test_reemit_source_action_does_not_authenticate_changed_source(tmp_path: Path):
    root, _config, receipt, planned = _reemit_fixture(tmp_path)
    source = root / "analysis_a.md"
    original = source.read_bytes()
    before = _bytes(root, CANONICAL)
    ledger_before = deepcopy(AL.read_artifact_ledger(root))
    # Controlled input-tampering fault: retain local IDs, titles and canonical
    # output, but change the source generation. Never rewrite the old receipt.
    source.write_bytes(original + b"\nBenign changed source-generation marker.\n")
    changed_hash = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
    assert changed_hash != "sha256:" + receipt["rows"][0]["source_sha256"]
    actions = {row["action_id"]: row for row in _delivery(root)["actions"]}
    assert actions["A-02"]["source_artifact_hash"] == changed_hash
    assert actions["A-02"]["disposition"] == "RESIDUAL_DEBT"
    text = before["findings_inventory.md"].decode("utf-8")
    assert ("analysis_a.md", "A-02", changed_hash) not in (
        V._inventory_structural_source_hash_action_referents(text)
    )
    with pytest.raises(REEMIT.InventoryReemitError):
        REEMIT.validate_inventory_reemit_materialization(root, planned)
    assert _bytes(root, CANONICAL) == before
    assert AL.read_artifact_ledger(root) == ledger_before
    # Restore the exact controlled input, not a new receipt or identity: the
    # positive control must replay the originally committed materialization.
    source.write_bytes(original)
    assert REEMIT.validate_inventory_reemit_materialization(root, planned) == receipt
    actions = {row["action_id"]: row for row in _delivery(root)["actions"]}
    assert actions["A-02"]["disposition"] == "PROMOTED_FINDING"
    assert _bytes(root, CANONICAL) == before
    assert AL.read_artifact_ledger(root) == ledger_before
