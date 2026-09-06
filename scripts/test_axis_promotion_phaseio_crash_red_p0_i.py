"""RED-only PhaseIO crash specification for axis promotion.

Unlike the older text-idempotence fixture, this test deliberately keeps the
real PhaseIO arm/commit path.  It pins the transaction boundary where the
inventory successor is durable but the promotion receipt and DRIVER commit are
not yet durable.
"""
from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

import axis_disposition as AXIS
import plamen_driver as DRIVER
from artifact_ledger import (
    read_artifact_ledger,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from test_axis_repair_promotion_fault_red_p0_i import (
    _axis_phase,
    _complete_base_application,
)
from test_axis_resume_canonical_recovery_red_p0_i import (
    RUN_ID,
    _committed_model_fixture,
)


def test_append_before_receipt_replay_preserves_original_phaseio_preimage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config, worklist, application, _findings = (
        _complete_base_application(tmp_path)
    )
    original_atomic_json = DRIVER._atomic_driver_json
    crash_once = True

    def crash_after_append(path: Path, value: Mapping[str, Any]) -> None:
        nonlocal crash_once
        if (
            Path(path).name == "axis_coverage_promotion_receipt.json"
            and crash_once
        ):
            crash_once = False
            raise RuntimeError("fixture crash after inventory append")
        original_atomic_json(path, value)

    monkeypatch.setattr(DRIVER, "_atomic_driver_json", crash_after_append)
    with pytest.raises(RuntimeError, match="after inventory append"):
        DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )

    action_id = worklist["items"][0]["required_action_id"]
    inventory = scratchpad / "findings_inventory.md"
    post_crash = inventory.read_bytes()
    assert post_crash.decode("utf-8").count(f"AXISGAP:{action_id}") == 1

    project = Path(config["project_root"])
    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="promotion",
        project_root=project,
    )
    contract, launch = DRIVER._axis_disposition_contract_and_launch(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        work_unit_id="promotion",
        exact_inputs=exact_inputs,
    )
    pending = read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert pending["execution_state"] == "INPUTS_BOUND_PREEXECUTION"

    monkeypatch.setattr(DRIVER, "_atomic_driver_json", original_atomic_json)
    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    assert promotion["status"] == "COMPLETE"
    assert promotion["delivery_count"] == 1
    assert inventory.read_bytes() == post_crash
    assert issues == []
    assert validate_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
    ) == []
    assert validate_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="DRIVER",
    ) == []


def test_inert_markdown_axisgap_text_cannot_suppress_canonical_delivery(
    tmp_path: Path,
) -> None:
    scratchpad, config, worklist, application, _findings = (
        _complete_base_application(tmp_path)
    )
    action_id = worklist["items"][0]["required_action_id"]
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_text(
        "# Findings Inventory\n\n"
        "Documentation example (not an inventory finding):\n\n"
        "```text\n"
        f"Source IDs: AXISGAP:{action_id}\n"
        "```\n",
        encoding="utf-8",
    )

    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    text = inventory.read_text(encoding="utf-8", errors="strict")
    assert promotion["status"] == "COMPLETE"
    assert promotion["delivery_count"] == 1
    assert text.count(f"**Source IDs**: AXISGAP:{action_id}") == 1
    assert issues == []


def test_duplicate_exact_claims_do_not_trigger_a_third_inventory_append(
    tmp_path: Path,
) -> None:
    scratchpad, config, worklist, application, base_findings = (
        _complete_base_application(tmp_path)
    )
    actions = AXIS.referenced_axis_action_blocks(
        application,
        base_findings_raw=base_findings,
        repair_findings_raw=b"",
    )
    assert len(actions) == 1
    action_id = worklist["items"][0]["required_action_id"]
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_text(
        "# Findings Inventory\n\n"
        + AXIS.render_axis_inventory_block(actions[0], "INV-001")
        + "\n\n"
        + AXIS.render_axis_inventory_block(actions[0], "INV-002")
        + "\n",
        encoding="utf-8",
    )
    promotion, _issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    assert promotion["status"] == "COMPLETED_WITH_DEBT"
    assert promotion["missing_action_ids"] == [action_id]
    text = inventory.read_text(encoding="utf-8", errors="strict")
    assert "Finding [INV-003]" not in text
    assert text.count(f"AXISGAP:{action_id}") == 2


def test_main_artifact_recovery_runs_axis_finalizer_before_parent_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the live generic-recovery branch, not resume helper directly."""

    project, scratchpad, phase, config, worklist, _frozen, _digest = (
        _committed_model_fixture(
            tmp_path,
            monkeypatch,
            backend="claude",
            disposition="FINDING",
        )
    )
    config = {
        **config,
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
    }
    config_path = tmp_path / "axis-recovery-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    # Preserve an incomplete parent checkpoint around the already committed
    # MODEL work unit: this is the real crash state under review.
    from plamen_types import Checkpoint

    Checkpoint(run_id=RUN_ID).save(scratchpad)
    calls: list[str] = []

    class RecoveryParentCommitReached(RuntimeError):
        pass

    def finalize(**_kwargs: Any) -> tuple[dict[str, Any], list[str]]:
        calls.append("finalize")
        return {}, []

    def harvest(*_args: Any, **_kwargs: Any) -> list[str]:
        calls.append("harvest")
        return []

    def parent_commit(*_args: Any, **_kwargs: Any) -> None:
        calls.append("parent_commit")
        raise RecoveryParentCommitReached

    monkeypatch.setattr(sys, "argv", ["plamen_driver.py", str(config_path), "--force"])
    monkeypatch.setattr(DRIVER, "SC_PHASES", [phase])
    monkeypatch.setattr(DRIVER, "_detect_ecosystem", lambda _root: ("evm", "high", {}))
    monkeypatch.setattr(DRIVER, "_ensure_claude_folder_trusted", lambda *_args: [])
    monkeypatch.setattr(DRIVER, "_ensure_rule_files_materialized", lambda: [])
    monkeypatch.setattr(DRIVER, "_assert_methodology_reachable", lambda _config: None)
    monkeypatch.setattr(
        DRIVER,
        "snapshot_startup_guard",
        lambda _root: nullcontext(),
    )
    monkeypatch.setattr(
        DRIVER,
        "_bind_checkpoint_audit_snapshot",
        lambda checkpoint, *_args, **_kwargs: (checkpoint, None, None),
    )
    monkeypatch.setattr(DRIVER, "_acquire_run_lock", lambda *_args, **_kwargs: (True, ""))
    monkeypatch.setattr(
        DRIVER,
        "_run_startup_trust_boundary_before_consumers",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(DRIVER, "validate_phase_graph", lambda *_args: [])
    monkeypatch.setattr(DRIVER, "expand_shard_phases", lambda phases, _root: phases)
    monkeypatch.setattr(
        DRIVER,
        "_prune_stale_dynamic_report_checkpoint_entries",
        lambda *_args: [],
    )
    monkeypatch.setattr(DRIVER, "_rewind_completed_after_overflow", lambda *_args: [])
    monkeypatch.setattr(
        DRIVER,
        "_reconcile_completed_checkpoint_artifacts",
        lambda *_args: [],
    )
    monkeypatch.setattr(DRIVER, "_clear_stale_degraded_sentinels", lambda _root: [])
    monkeypatch.setattr(
        DRIVER,
        "_ensure_fresh_audit_sentinel",
        lambda *_args: "legacy-skip",
    )
    monkeypatch.setattr(
        DRIVER,
        "_quarantine_report_without_completed_assemble",
        lambda *_args: None,
    )
    monkeypatch.setattr(DRIVER, "_assert_audit_snapshot_still_bound", lambda *_args: None)
    monkeypatch.setattr(DRIVER, "_arm_incomplete_phase_retry", lambda *_args: None)
    monkeypatch.setattr(
        DRIVER,
        "_prepare_axis_disposition_worklist",
        lambda **_kwargs: (worklist, []),
    )
    monkeypatch.setattr(DRIVER, "gate_passes", lambda *_args, **_kwargs: (True, []))
    monkeypatch.setattr(
        DRIVER,
        "_phase_artifacts_have_active_owner_state",
        lambda *_args, **_kwargs: (True, []),
    )
    monkeypatch.setattr(DRIVER, "_existing_later_phase_artifacts", lambda *_args: [])
    monkeypatch.setattr(
        DRIVER,
        "_run_phase_validators",
        lambda *_args, **_kwargs: (True, []),
    )
    monkeypatch.setattr(DRIVER, "_finalize_axis_coverage_boundary", finalize)
    monkeypatch.setattr(DRIVER, "_harvest_candidate_negative_phase", harvest)
    monkeypatch.setattr(DRIVER, "_commit_phase_from_disk_debt", parent_commit)
    monkeypatch.setattr(DRIVER.display.graceful_stop, "install", lambda: None)
    monkeypatch.setattr(DRIVER.display.pause_toggle, "start", lambda: None)
    monkeypatch.setattr(DRIVER.display.pause_toggle, "wait_if_paused", lambda: None)
    monkeypatch.setattr(DRIVER.display, "print_banner", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        DRIVER.display,
        "print_phase_skipped",
        lambda *_args, **_kwargs: None,
    )

    import recon_prepass

    monkeypatch.setattr(recon_prepass, "run_recon_prepass", lambda _config: "fixture")

    with pytest.raises(RecoveryParentCommitReached):
        DRIVER.main()

    assert calls == ["finalize", "harvest", "parent_commit"]
