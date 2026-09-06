from __future__ import annotations

import hashlib
import json
from pathlib import Path

from artifact_ledger import validate_work_unit_artifacts
from verify_queue_phaseio_authority import (
    arm_transaction_unit,
    commit_transaction_unit,
    resolve_transaction_unit_authority,
    validate_transaction_authority,
)


RUN_ID = "phaseio-helper-run"


def _plan() -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
        "phase_name": "sc_verify_queue",
        "run_id": RUN_ID,
    }


def _row(
    path: str,
    *,
    conditional: bool = False,
    condition_id: str = "",
) -> dict:
    return {
        "path": path,
        "root": "scratchpad",
        "artifact_class": (
            "CONDITIONAL" if conditional else "DRIVER_GENERATED"
        ),
        "writer": "DRIVER",
        "write_mode": "CREATE",
        **({"condition_id": condition_id} if conditional else {}),
    }


def test_arm_commit_and_zero_output_parent_are_exact(tmp_path: Path) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    (root / "source.json").write_text("{}\n", encoding="utf-8")
    unit = {
        "work_unit_id": "t0.live_upstream_authority",
        "exact_inputs": ["source.json"],
        "declared_input_denominator": ["source.json"],
        "outputs": [
            _row("_live_verify_queue_transaction/t0/snapshot.json"),
            _row("_live_verify_queue_transaction/t0/status.json"),
        ],
    }
    execute, issues, contract, launch = arm_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        plan=_plan(),
        unit=unit,
        run_id=RUN_ID,
    )
    assert execute is True
    assert issues == []
    for spec in contract.outputs:
        path = root / spec.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{spec.path}\n", encoding="utf-8")
    assert commit_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=RUN_ID,
    ) == []
    assert validate_work_unit_artifacts(
        root,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []

    parent = {
        "work_unit_id": "routing.live_parent_commit",
        "exact_inputs": [
            "_live_verify_queue_transaction/t0/snapshot.json",
            "_live_verify_queue_transaction/t0/status.json",
        ],
        "declared_input_denominator": [
            "_live_verify_queue_transaction/t0/snapshot.json",
            "_live_verify_queue_transaction/t0/status.json",
        ],
        "outputs": [],
        "read_only": True,
    }
    execute, issues, parent_contract, parent_launch = arm_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        plan=_plan(),
        unit=parent,
        run_id=RUN_ID,
    )
    assert execute is True
    assert issues == []
    assert parent_contract.outputs == ()
    assert commit_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        contract=parent_contract,
        launch=parent_launch,
        run_id=RUN_ID,
    ) == []
    assert validate_work_unit_artifacts(
        root,
        tmp_path,
        parent_contract,
        parent_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []


def test_presence_roster_binds_required_and_only_present_optional_inputs(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    (root / "required.json").write_text("{}\n", encoding="utf-8")
    unit = {
        "work_unit_id": "t0.live_upstream_authority",
        "exact_inputs": ["required.json", "optional.json"],
        "declared_input_denominator": [
            "required.json",
            "optional.json",
        ],
        "required_inputs": ["required.json"],
        "presence_roster": ["optional.json"],
        "outputs": [_row("_live_verify_queue_transaction/t0/status.json")],
    }
    absent, _launch = resolve_transaction_unit_authority(
        _plan(), unit, tmp_path, root, RUN_ID
    )
    assert absent.immutable_inputs == ("scratchpad:required.json",)

    (root / "optional.json").write_text("{}\n", encoding="utf-8")
    present, _launch = resolve_transaction_unit_authority(
        _plan(), unit, tmp_path, root, RUN_ID
    )
    assert set(present.immutable_inputs) == {
        "scratchpad:required.json",
        "scratchpad:optional.json",
    }
    assert present.digest != absent.digest


def test_conditional_consumer_binds_only_committed_produced_branch(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    (root / "source.json").write_text("{}\n", encoding="utf-8")
    receipt = "_live_verify_queue_transaction/t5/delivery_receipt.json"
    debt = "_live_verify_queue_transaction/t5/delivery_debt.json"
    status = "_live_verify_queue_transaction/t5/status.json"
    producer = {
        "work_unit_id": "t5.live_generic_compound_delta",
        "exact_inputs": ["source.json"],
        "declared_input_denominator": ["source.json"],
        "outputs": [
            _row(receipt, conditional=True, condition_id="receipt_selected"),
            _row(debt, conditional=True, condition_id="debt_selected"),
            _row(status),
        ],
    }
    execute, issues, contract, launch = arm_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        plan=_plan(),
        unit=producer,
        run_id=RUN_ID,
    )
    assert execute is True
    assert issues == []
    for relative in (receipt, status):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    assert commit_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=RUN_ID,
        conditional_states={
            receipt: "PRODUCED",
            debt: "NOT_TRIGGERED",
        },
    ) == []

    consumer = {
        "work_unit_id": "t6.live_final_typed_merge",
        "exact_inputs": [status],
        "declared_input_denominator": [status, receipt, debt],
        "outputs": [],
        "conditional_input_groups": {
            "compound_delivery": {
                "selection": "EXACTLY_ONE",
                "candidates": [receipt, debt],
                "authority_work_unit_id": (
                    "t5.live_generic_compound_delta"
                ),
                "effective_input_policy": (
                    "COMMITTED_PHASEIO_CONDITIONAL_STATE"
                ),
                "bind_selected_output_sha256_size": True,
                "bind_unselected_absence_record": True,
                "status_json_alone_is_authority": False,
            },
        },
    }
    resolved, _launch = resolve_transaction_unit_authority(
        _plan(),
        consumer,
        tmp_path,
        root,
        RUN_ID,
    )
    assert set(resolved.immutable_inputs) == {
        "scratchpad:" + status,
        "scratchpad:" + receipt,
    }
    assert "scratchpad:" + debt not in resolved.immutable_inputs


def test_compound_conditional_commit_rejects_two_produced_branches(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    (root / "source.json").write_text("{}\n", encoding="utf-8")
    receipt = "_live_verify_queue_transaction/t5/delivery_receipt.json"
    debt = "_live_verify_queue_transaction/t5/delivery_debt.json"
    producer = {
        "work_unit_id": "t5.live_generic_compound_delta",
        "exact_inputs": ["source.json"],
        "declared_input_denominator": ["source.json"],
        "outputs": [
            _row(receipt, conditional=True, condition_id="receipt_selected"),
            _row(debt, conditional=True, condition_id="debt_selected"),
            _row("_live_verify_queue_transaction/t5/status.json"),
        ],
    }
    execute, issues, contract, launch = arm_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        plan=_plan(),
        unit=producer,
        run_id=RUN_ID,
    )
    assert execute is True
    assert issues == []
    for spec in contract.outputs:
        path = root / spec.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    commit_issues = commit_transaction_unit(
        scratchpad=root,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=RUN_ID,
        conditional_states={
            receipt: "PRODUCED",
            debt: "PRODUCED",
        },
    )
    assert commit_issues
    assert any("exactly one" in issue for issue in commit_issues)


def test_transaction_validator_requires_current_child_and_parent_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    (root / "source.json").write_text("{}\n", encoding="utf-8")
    child_ids = (
        "t0.live_upstream_authority",
        "t1.live_base_queue",
        "t2.live_policy_disposition",
        "t3.live_mandatory_delta",
        "t4.live_pipeline_composition_delta",
        "t5.live_generic_compound_delta",
        "t6.live_final_typed_merge",
        "t7.live_frozen_context_and_shard_plan",
        "t8.live_immutable_publication_bundle",
        "t9.live_receipt_last_cas",
    )
    children = []
    prior = "source.json"
    for index, work_id in enumerate(child_ids):
        status = f"_live_verify_queue_transaction/t{index}/status.json"
        children.append({
            "work_unit_id": work_id,
            "exact_inputs": [prior],
            "declared_input_denominator": [prior],
            "outputs": [_row(status)],
        })
        prior = status
    parent = {
        "work_unit_id": "routing.live_parent_commit",
        "exact_inputs": [prior],
        "declared_input_denominator": [prior],
        "outputs": [],
        "read_only": True,
        "validates_work_units": list(child_ids),
    }
    plan = {
        **_plan(),
        "schema_version": "plamen.live_verify_queue_plan.v1",
        "children": children,
        "parent": parent,
        "outer_output_denominator": [
            str(unit["outputs"][0]["path"]) for unit in children
        ],
    }
    plan["plan_digest"] = hashlib.sha256(
        (
            json.dumps(
                plan,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()
    for unit in (*children, parent):
        execute, issues, contract, launch = arm_transaction_unit(
            scratchpad=root,
            project_root=tmp_path,
            plan=plan,
            unit=unit,
            run_id=RUN_ID,
        )
        assert execute is True
        assert issues == []
        for spec in contract.outputs:
            path = root / spec.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{spec.path}\n", encoding="utf-8")
        assert commit_transaction_unit(
            scratchpad=root,
            project_root=tmp_path,
            contract=contract,
            launch=launch,
            run_id=RUN_ID,
        ) == []
    assert validate_transaction_authority(
        scratchpad=root,
        project_root=tmp_path,
        plan=plan,
        run_id=RUN_ID,
        require_parent_commit=True,
    ) == []

    with (
        root / "_live_verify_queue_transaction/t4/status.json"
    ).open("ab") as stream:
        stream.write(b"mutated\n")
    assert validate_transaction_authority(
        scratchpad=root,
        project_root=tmp_path,
        plan=plan,
        run_id=RUN_ID,
        require_parent_commit=True,
    )
