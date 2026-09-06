from __future__ import annotations

from pathlib import Path

from artifact_ledger import (
    arm_semantic_mutation,
    finalize_semantic_mutation,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


BASE = {
    "pipeline": "sc",
    "mode": "light",
    "ecosystem": "evm",
    "backend": "claude",
}
RUN_ID = "semantic-bundle-replay-run"
ROOTS = ("findings_inventory.md", "finding_records.json", "_id_ledger.json")


def _launch(contract: PhaseIOContract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        **BASE,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )


def _seed_bundle(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    key = "sc/light/evm/claude/inventory/canonical_bundle"
    contract = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="canonical_bundle",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            )
            for name in ROOTS
        ),
        model_invoked=False,
    )
    launch = _launch(contract)
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID,
    )
    for name in ROOTS:
        (scratch / name).write_text(f"base:{name}\n", encoding="utf-8")
    unit = record_work_unit_artifacts(
        scratch, project, contract, launch, run_id=RUN_ID, actor="DRIVER",
    )
    assert unit["semantic_status"] == "ACTIVE"
    return project, scratch


def _advance(
    scratch: Path,
    project: Path,
    name: str,
    *,
    ordinal: int,
) -> None:
    identity = f"scratchpad:{name}"
    event = arm_semantic_mutation(
        scratch,
        project,
        artifact_identity=identity,
        mutation_kind=f"BUNDLE_ADVANCE_{ordinal}",
        run_id=RUN_ID,
    )
    with (scratch / name).open("ab") as stream:
        stream.write(f"successor:{ordinal}:{name}\n".encode("utf-8"))
    finalized = finalize_semantic_mutation(
        scratch,
        project,
        str(event["event_id"]),
        run_id=RUN_ID,
    )
    assert finalized["status"] == "INVALIDATION_APPLIED"


def _consume_inventory(scratch: Path, project: Path) -> dict:
    contract = PhaseIOContract(
        **BASE,
        phase="sc_verify_queue",
        work_unit_id="bundle_reader",
        outputs=(),
        immutable_inputs=("scratchpad:findings_inventory.md",),
        model_invoked=False,
    )
    return record_work_unit_inputs(
        scratch, project, contract, _launch(contract), run_id=RUN_ID,
    )


def test_all_journaled_bundle_siblings_replay_as_one_historical_receipt(
    tmp_path: Path,
) -> None:
    project, scratch = _seed_bundle(tmp_path)
    for ordinal, name in enumerate(ROOTS, 1):
        _advance(scratch, project, name, ordinal=ordinal)

    unit = _consume_inventory(scratch, project)

    assert unit["semantic_status"] == "INPUTS_BOUND"
    record = unit["input_bindings"]["scratchpad:findings_inventory.md"]
    assert record["status"] == "ACTIVE"
    assert record["producer_work_unit_key"].startswith("semantic-mutation:")


def test_unjournaled_bundle_sibling_still_fails_closed(tmp_path: Path) -> None:
    project, scratch = _seed_bundle(tmp_path)
    _advance(scratch, project, "findings_inventory.md", ordinal=1)
    _advance(scratch, project, "finding_records.json", ordinal=2)
    with (scratch / "_id_ledger.json").open("ab") as stream:
        stream.write(b"unjournaled sibling drift\n")

    unit = _consume_inventory(scratch, project)

    assert unit["semantic_status"] == "INPUT_DEBT"
    assert (
        unit["input_bindings"]["scratchpad:findings_inventory.md"]["status"]
        == "PRODUCER_AUTHORITY_MISMATCH"
    )


def _seed_registered_inventory_successor(
    tmp_path: Path,
) -> tuple[Path, Path]:
    project = tmp_path / "registered-project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    canonical_key = "sc/light/evm/claude/inventory/canonical_aggregate"
    canonical = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="canonical_aggregate",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=canonical_key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            )
            for name in (
                "findings_inventory.md",
                "finding_records.json",
                "inventory_id_allocation_delta.json",
            )
        ),
        model_invoked=False,
    )
    record_work_unit_inputs(
        scratch, project, canonical, _launch(canonical), run_id=RUN_ID,
    )
    for output in canonical.outputs:
        (scratch / output.path).write_text(
            f"canonical:{output.path}\n", encoding="utf-8",
        )
    assert record_work_unit_artifacts(
        scratch,
        project,
        canonical,
        _launch(canonical),
        run_id=RUN_ID,
        actor="DRIVER",
    )["semantic_status"] == "ACTIVE"

    successor_key = "sc/light/evm/claude/inventory/additive_reemit"
    successor = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="additive_reemit",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=successor_key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            )
            for name in ("findings_inventory.md", "finding_records.json")
        ),
        model_invoked=False,
    )
    assert record_work_unit_inputs(
        scratch, project, successor, _launch(successor), run_id=RUN_ID,
    )["semantic_status"] == "INPUTS_BOUND"
    for output in successor.outputs:
        (scratch / output.path).write_text(
            f"successor:{output.path}\n", encoding="utf-8",
        )
    assert record_work_unit_artifacts(
        scratch,
        project,
        successor,
        _launch(successor),
        run_id=RUN_ID,
        actor="DRIVER",
    )["semantic_status"] == "ACTIVE"
    return project, scratch


def _consume_allocation_delta(scratch: Path, project: Path) -> dict:
    contract = PhaseIOContract(
        **BASE,
        phase="sc_verify_queue",
        work_unit_id="allocation_reader",
        outputs=(),
        immutable_inputs=("scratchpad:inventory_id_allocation_delta.json",),
        model_invoked=False,
    )
    return record_work_unit_inputs(
        scratch, project, contract, _launch(contract), run_id=RUN_ID,
    )


def test_retained_bundle_receipt_replays_across_registered_mutated_successor(
    tmp_path: Path,
) -> None:
    project, scratch = _seed_registered_inventory_successor(tmp_path)
    _advance(scratch, project, "findings_inventory.md", ordinal=11)
    _advance(scratch, project, "finding_records.json", ordinal=12)

    unit = _consume_allocation_delta(scratch, project)

    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["input_bindings"][
        "scratchpad:inventory_id_allocation_delta.json"
    ]["status"] == "ACTIVE"


def test_retained_bundle_receipt_rejects_unjournaled_successor_drift(
    tmp_path: Path,
) -> None:
    project, scratch = _seed_registered_inventory_successor(tmp_path)
    _advance(scratch, project, "findings_inventory.md", ordinal=11)
    with (scratch / "finding_records.json").open("ab") as stream:
        stream.write(b"unjournaled successor drift\n")

    unit = _consume_allocation_delta(scratch, project)

    assert unit["semantic_status"] == "INPUT_DEBT"
    assert unit["input_bindings"][
        "scratchpad:inventory_id_allocation_delta.json"
    ]["status"] == "PRODUCER_AUTHORITY_MISMATCH"
