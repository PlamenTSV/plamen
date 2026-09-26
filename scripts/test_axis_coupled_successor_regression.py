"""Regression coverage for the coupled axis-promotion canonical successor."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import artifact_ledger as AL
from phase_io_contracts import (
    LaunchSpec,
    registered_projection_handoff,
    resolve_phase_io_contract,
)


DIMENSIONS = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
RUN_ID = "run-axis-coupled-regression"


def _launch(contract):
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=(),
    )


def _seed_canonical(tmp_path: Path) -> tuple[Path, Path]:
    import plamen_driver as DRIVER

    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    manifest = scratch / "inventory_floor_source_manifest.json"
    manifest.write_text('{"schema_version":"fixture"}\n', encoding="utf-8")
    contract = resolve_phase_io_contract(
        **DIMENSIONS,
        phase="inventory",
        work_unit_id="late_recall_floor",
        exact_inputs=(manifest.name,),
        exact_outputs=(
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
            "inventory_floor_receipt.json",
        ),
    )
    launch = _launch(contract)
    AL.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    inventory_raw = b"# Finding Inventory\n\n## Findings\n"
    (scratch / "findings_inventory.md").write_bytes(inventory_raw)
    (scratch / "finding_records.json").write_bytes(
        DRIVER.derive_preverify_finding_records_bytes(inventory_raw)
    )
    (scratch / "_id_ledger.json").write_text(
        '{"schema_version":"plamen.id_ledger.v1","allocations":[]}\n',
        encoding="utf-8",
    )
    (scratch / "inventory_floor_receipt.json").write_text(
        '{"schema_version":"plamen.inventory_floor_receipt.v1"}\n',
        encoding="utf-8",
    )
    AL.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    return project, scratch


def _axis_contract():
    return resolve_phase_io_contract(
        **DIMENSIONS,
        phase="axis_disposition",
        work_unit_id="promotion",
        exact_inputs=("axis_coverage_promotion_plan.json",),
        exact_outputs=(
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
            "axis_coverage_promotion_receipt.json",
        ),
    )


def _commit_axis_plan(project: Path, scratch: Path) -> None:
    receipt = scratch / "axis_disposition_receipt.json"
    receipt.write_text('{"schema_version":"fixture"}\n', encoding="utf-8")
    contract = resolve_phase_io_contract(
        **DIMENSIONS,
        phase="axis_disposition",
        work_unit_id="promotion.plan",
        exact_inputs=(
            "_id_ledger.json",
            "axis_disposition_receipt.json",
            "finding_records.json",
            "findings_inventory.md",
        ),
        exact_outputs=("axis_coverage_promotion_plan.json",),
    )
    launch = _launch(contract)
    AL.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    (scratch / "axis_coverage_promotion_plan.json").write_text(
        '{"schema_version":"fixture"}\n', encoding="utf-8"
    )
    AL.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )


def test_axis_promotion_contract_owns_the_complete_canonical_triplet() -> None:
    contract = _axis_contract()
    plan_key = (
        "sc/thorough/evm/claude/axis_disposition/promotion.plan"
    )
    assert [output.path for output in contract.outputs] == [
        "findings_inventory.md",
        "finding_records.json",
        "_id_ledger.json",
        "axis_coverage_promotion_receipt.json",
    ]
    assert {
        output.path for output in contract.outputs if output.write_mode == "MERGE"
    } == {
        "findings_inventory.md",
        "finding_records.json",
        "_id_ledger.json",
    }
    for identity in (
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:_id_ledger.json",
    ):
        assert registered_projection_handoff(
            "sc/thorough/evm/claude/inventory/additive_depth_finalize",
            plan_key,
            identity,
        )
        assert registered_projection_handoff(
            "sc/thorough/evm/claude/inventory/additive_depth_finalize",
            contract.key,
            identity,
        )
        assert registered_projection_handoff(
            contract.key,
            "sc/thorough/evm/claude/inventory/gate_p_successor",
            identity,
        )


def test_axis_projection_rejects_the_historical_split_predecessor() -> None:
    import plamen_driver as DRIVER

    inventory = (
        "# Finding Inventory\n\n"
        "### Finding [INV-001]: promoted axis candidate\n"
        "**Severity**: Low\n"
        "**Location**: `contracts/Unit.sol:L2`\n"
        "**Description**: Candidate retained for verification.\n"
        "**Impact**: Independent verification determines material harm.\n"
    ).encode()
    stale_records = DRIVER.derive_preverify_finding_records_bytes(
        b"# Finding Inventory\n\n## Findings\n"
    )
    stale_ledger = (
        b'{"schema_version":"plamen.id_ledger.v1","allocations":[]}\n'
    )
    with pytest.raises(
        DRIVER.axis_disposition_authority.AxisDispositionError,
        match="inventory/record/ID identity parity failed",
    ):
        DRIVER._axis_canonical_projection_ids(
            {
                "findings_inventory.md": inventory,
                "finding_records.json": stale_records,
                "_id_ledger.json": stale_ledger,
            },
            label="predecessor",
        )


def test_axis_successor_binds_rag_inputs_to_one_authoritative_producer(
    tmp_path: Path,
) -> None:
    import plamen_driver as DRIVER

    project, scratch = _seed_canonical(tmp_path)
    predecessor = {
        name: (scratch / name).read_bytes()
        for name in DRIVER._AXIS_PROMOTION_CANONICAL
    }
    inventory_raw = predecessor["findings_inventory.md"] + (
        b"\n### Finding [INV-001]: promoted axis candidate\n"
        b"**Severity**: Low\n"
        b"**Location**: `contracts/Unit.sol:L2`\n"
        b"**Description**: Candidate retained for verification.\n"
        b"**Impact**: Independent verification determines material harm.\n"
    )
    canonical = DRIVER._axis_coupled_canonical_postimages(
        inventory_raw=inventory_raw,
        ledger_raw=predecessor["_id_ledger.json"],
    )
    _commit_axis_plan(project, scratch)
    contract = _axis_contract()
    launch = _launch(contract)
    planned = {
        **{
            f"scratchpad:{name}": raw for name, raw in canonical.items()
        },
        "scratchpad:axis_coverage_promotion_receipt.json": (
            b'{"schema_version":"plamen.axis_coverage_promotion_receipt.v2"}\n'
        ),
    }
    events = DRIVER._axis_promotion_merge_events(
        contract, predecessor, planned
    )
    successor = AL.plan_driver_successor_transaction(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        planned_output_bytes=planned,
        merge_events=events,
    )
    AL.record_work_unit_inputs(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        successor_plan=successor,
    )
    for transition in successor.transitions:
        AL.begin_driver_successor_step(
            scratch,
            project,
            contract,
            launch,
            run_id=RUN_ID,
            ordinal=transition.ordinal,
        )
        identity = str(transition.artifact_identity)
        (scratch / identity.split(":", 1)[1]).write_bytes(planned[identity])
        AL.complete_driver_successor_step(
            scratch,
            project,
            contract,
            launch,
            run_id=RUN_ID,
            ordinal=transition.ordinal,
        )
    AL.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=events,
        expected_output_records=successor.expected_output_records,
    )
    assert AL.validate_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        require_live_input_authority=False,
    ) == []

    rag = resolve_phase_io_contract(
        **DIMENSIONS,
        phase="rag_sweep",
        work_unit_id="precedent_facts",
        exact_inputs=("finding_records.json", "findings_inventory.md"),
        exact_outputs=("precedent_finding_facts.json",),
    )
    unit = AL.record_work_unit_inputs(
        scratch, project, rag, _launch(rag), run_id=RUN_ID
    )
    for identity in (
        "scratchpad:finding_records.json",
        "scratchpad:findings_inventory.md",
    ):
        binding = unit["input_bindings"][identity]
        assert binding["status"] == "ACTIVE"
        assert binding["producer_work_unit_key"] == contract.key
        assert AL.semantic_input_producer_authority_issues(
            AL.read_artifact_ledger(scratch), binding, run_id=RUN_ID
        ) == []

    records = json.loads((scratch / "finding_records.json").read_text())
    ledger = json.loads((scratch / "_id_ledger.json").read_text())
    assert {row["inventory_id"] for row in records["records"]} == {"INV-001"}
    assert {row["id"] for row in ledger["allocations"]} >= {"INV-001"}
