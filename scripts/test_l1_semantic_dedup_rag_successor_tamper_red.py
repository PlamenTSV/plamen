"""RED integration contract for the L1 semantic-dedup -> RAG handoff.

The prequeue apply owns five outputs as one committed transaction.  A resume
must not let the next model phase consume a canonical inventory whose bytes no
longer match that transaction, even when the reduced Markdown still parses.

This fixture deliberately exercises ``main``'s real generic prelaunch path.
Only unrelated startup/final-delivery machinery is isolated; precedent fact
construction and typed RAG input binding remain production code.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

import pytest

from artifact_ledger import read_artifact_ledger
import plamen_driver as DRIVER
from plamen_types import Checkpoint, L1_PHASES
from test_l1_semantic_dedup_prequeue_transaction_red import (
    RUN_ID,
    ROOT_OUTPUT_NAMES,
    _required_apply,
    _seed,
    _semantic_snapshot,
    _staged_sidecars,
    _transaction_generation,
)


class _RagModelLaunchObserved(RuntimeError):
    """Raised by the fixture at the forbidden model-launch boundary."""


def _required_downstream_recovery() -> Callable[..., Mapping[str, Any]]:
    helper = getattr(
        DRIVER,
        "_ensure_l1_prequeue_successor_for_downstream",
        None,
    )
    assert callable(helper), (
        "shared L1 prequeue successor recovery helper is absent; downstream "
        "phases cannot yet authenticate _sdt and restore a damaged committed "
        "five-output postimage without rerunning semantic-dedup work"
    )
    return helper


def _generation_postimages(
    scratchpad: Path,
    applied: Mapping[str, Any],
) -> tuple[str, dict[str, bytes]]:
    generation, manifest = _transaction_generation(scratchpad, applied)
    digest = generation.name.removeprefix("g_")
    postimages = {
        "findings_inventory.md": (generation / "a0.bin").read_bytes(),
        "finding_records.json": (generation / "a1.bin").read_bytes(),
        **_staged_sidecars(generation, manifest),
    }
    assert set(postimages) == set(ROOT_OUTPUT_NAMES)
    return digest, postimages


def _truncate_canonical_inventory(scratchpad: Path) -> bytes:
    path = scratchpad / "findings_inventory.md"
    committed = path.read_bytes()
    assert b"INV-003" in committed
    tampered = committed.split(b"### Finding [INV-003]", 1)[0]
    path.write_bytes(tampered)
    assert b"INV-003" not in path.read_bytes()
    return tampered


def _forbid_semantic_reanalysis(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError(
            "authenticated successor recovery invoked semantic-dedup analysis"
        )

    for name in (
        "run_phase",
        "_run_l1_dedup_pair_candidate_phase",
        "_run_l1_supplemental_dedup_proposal_phase",
        "_run_l1_semantic_dedup_noop_proposal",
    ):
        monkeypatch.setattr(DRIVER, name, forbidden)


def _assert_durable_repair_receipt(
    *,
    scratchpad: Path,
    result: Mapping[str, Any],
    generation_digest: str,
) -> bytes:
    receipt_value = result.get("repair_receipt_path") or result.get(
        "receipt_path"
    )
    assert isinstance(receipt_value, str) and receipt_value
    receipt = Path(receipt_value)
    if not receipt.is_absolute():
        receipt = scratchpad / receipt
    assert receipt.is_relative_to(scratchpad)
    raw = receipt.read_bytes()
    payload = json.loads(raw.decode("utf-8", errors="strict"))
    assert payload.get("generation_digest") == generation_digest
    assert payload.get("status") in {"RECOVERED", "ALREADY_CURRENT"}
    restored = payload.get("restored_outputs")
    assert isinstance(restored, (list, dict))
    restored_names = set(restored) if isinstance(restored, dict) else {
        str(row.get("path") if isinstance(row, Mapping) else row)
        for row in restored
    }
    assert set(ROOT_OUTPUT_NAMES) <= restored_names
    assert any(
        key.endswith(("sha256", "digest"))
        and isinstance(value, str)
        and len(value) == 64
        for key, value in payload.items()
    )
    return raw


def _silence_display(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "print_banner",
        "print_phase_start",
        "print_phase_skipped",
        "print_skipped_summary",
        "print_pipeline_complete",
    ):
        monkeypatch.setattr(DRIVER.display, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(
        DRIVER.display.graceful_stop, "install", lambda: None
    )
    monkeypatch.setattr(DRIVER.display.pause_toggle, "start", lambda: None)


def _isolate_real_main_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep real phase control flow while removing unrelated host lifecycle."""

    monkeypatch.setattr(
        DRIVER, "snapshot_startup_guard", lambda _root: contextlib.nullcontext()
    )
    monkeypatch.setattr(
        DRIVER,
        "_bind_checkpoint_audit_snapshot",
        lambda checkpoint, *args, **kwargs: (checkpoint, None, None),
    )
    monkeypatch.setattr(
        DRIVER, "_acquire_run_lock", lambda *args, **kwargs: (True, "")
    )
    monkeypatch.setattr(DRIVER, "_ensure_claude_folder_trusted", lambda *a: [])
    monkeypatch.setattr(
        DRIVER, "_detect_ecosystem", lambda *a: ("rust", "high", {})
    )
    monkeypatch.setattr(DRIVER, "_ensure_rule_files_materialized", lambda: [])
    monkeypatch.setattr(DRIVER, "_assert_methodology_reachable", lambda _c: None)
    monkeypatch.setattr(
        DRIVER, "_quarantine_report_without_completed_assemble", lambda *a: None
    )
    monkeypatch.setattr(DRIVER, "_clear_stale_degraded_sentinels", lambda _s: [])
    monkeypatch.setattr(DRIVER, "_ensure_fresh_audit_sentinel", lambda *a: "ok")
    monkeypatch.setattr(
        DRIVER,
        "_run_startup_trust_boundary_before_consumers",
        lambda *a, **k: [],
    )
    monkeypatch.setattr(DRIVER, "validate_phase_graph", lambda *a: [])
    monkeypatch.setattr(
        DRIVER, "_prune_stale_dynamic_report_checkpoint_entries", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_rewind_completed_after_overflow", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_reconcile_completed_checkpoint_artifacts", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_assert_audit_snapshot_still_bound", lambda *a: None
    )
    monkeypatch.setattr(
        DRIVER, "_legacy_assurance_migration_required", lambda *a: False
    )
    monkeypatch.setattr(
        DRIVER, "_validate_final_assurance_delivery", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_refresh_assurance_projection", lambda *a, **k: []
    )
    monkeypatch.setattr(
        DRIVER, "_finalize_report_evidence_quality", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_checkpoint_has_report_integrity_no_ship", lambda *a: False
    )
    monkeypatch.setattr(
        DRIVER, "_snapshot_deliverable_report", lambda *a: (None, None)
    )
    _silence_display(monkeypatch)
    monkeypatch.setattr(
        DRIVER.display, "print_failure_diagnosis", lambda *a, **k: None
    )


def test_resume_vetoes_rag_model_when_committed_and_private_authority_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typed-input debt is a launch veto, not permission to keep going."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    assert all((scratchpad / name).is_file() for name in ROOT_OUTPUT_NAMES)
    assert DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=RUN_ID,
    )

    generation, _manifest = _transaction_generation(scratchpad, applied)
    private_inventory = generation / "a0.bin"
    private_inventory.write_bytes(
        private_inventory.read_bytes() + b"\nPRIVATE-AUTHORITY-TAMPER\n"
    )
    canonical = scratchpad / "findings_inventory.md"
    committed = canonical.read_bytes()
    assert b"INV-003" in committed
    tampered = committed.split(b"### Finding [INV-003]", 1)[0]
    canonical.write_bytes(tampered)
    assert b"INV-003" not in canonical.read_bytes()

    # This is an actual resume: semantic_dedup is checkpoint-complete and the
    # next active phase is rag_sweep.  Keep the phase list minimal so the
    # fixture reaches the real generic model-prelaunch boundary directly.
    Checkpoint(
        completed=["recon", "semantic_dedup"],
        run_id=RUN_ID,
    ).save(scratchpad)
    config_path = scratchpad / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    semantic = next(p for p in L1_PHASES if p.name == "semantic_dedup")
    rag = next(p for p in L1_PHASES if p.name == "rag_sweep")
    monkeypatch.setattr(DRIVER, "L1_PHASES", [semantic, rag])

    # Isolate unrelated process lifecycle work.  The two security-sensitive
    # calls remain real:
    #   _prepare_precedent_facts_boundary
    #   _bind_typed_model_phase_inputs
    monkeypatch.setattr(
        DRIVER, "snapshot_startup_guard", lambda _root: contextlib.nullcontext()
    )
    monkeypatch.setattr(
        DRIVER,
        "_bind_checkpoint_audit_snapshot",
        lambda checkpoint, *args, **kwargs: (checkpoint, None, None),
    )
    monkeypatch.setattr(
        DRIVER, "_acquire_run_lock", lambda *args, **kwargs: (True, "")
    )
    monkeypatch.setattr(DRIVER, "_ensure_claude_folder_trusted", lambda *a: [])
    monkeypatch.setattr(
        DRIVER, "_detect_ecosystem", lambda *a: ("rust", "high", {})
    )
    monkeypatch.setattr(DRIVER, "_ensure_rule_files_materialized", lambda: [])
    monkeypatch.setattr(DRIVER, "_assert_methodology_reachable", lambda _c: None)
    monkeypatch.setattr(
        DRIVER, "_quarantine_report_without_completed_assemble", lambda *a: None
    )
    monkeypatch.setattr(DRIVER, "_clear_stale_degraded_sentinels", lambda _s: [])
    monkeypatch.setattr(DRIVER, "_ensure_fresh_audit_sentinel", lambda *a: "ok")
    monkeypatch.setattr(
        DRIVER, "_run_startup_trust_boundary_before_consumers", lambda *a, **k: []
    )
    monkeypatch.setattr(DRIVER, "validate_phase_graph", lambda *a: [])
    monkeypatch.setattr(
        DRIVER, "_prune_stale_dynamic_report_checkpoint_entries", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_rewind_completed_after_overflow", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_reconcile_completed_checkpoint_artifacts", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_assert_audit_snapshot_still_bound", lambda *a: None
    )
    monkeypatch.setattr(
        DRIVER, "_legacy_assurance_migration_required", lambda *a: False
    )
    monkeypatch.setattr(
        DRIVER, "_validate_final_assurance_delivery", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_refresh_assurance_projection", lambda *a, **k: []
    )
    monkeypatch.setattr(
        DRIVER, "_finalize_report_evidence_quality", lambda *a: []
    )
    monkeypatch.setattr(
        DRIVER, "_checkpoint_has_report_integrity_no_ship", lambda *a: False
    )
    monkeypatch.setattr(
        DRIVER, "_snapshot_deliverable_report", lambda *a: (None, None)
    )
    _silence_display(monkeypatch)

    launches: list[str] = []

    def forbidden_launch(phase, _config, attempt):
        launches.append(f"{phase.name}:{attempt}")
        raise _RagModelLaunchObserved(phase.name)

    monkeypatch.setattr(DRIVER, "run_phase", forbidden_launch)
    monkeypatch.setattr(sys, "argv", ["plamen_driver.py", str(config_path)])

    try:
        DRIVER.main()
    except _RagModelLaunchObserved:
        pass
    except SystemExit:
        # The repaired implementation may terminate degraded after recording
        # the launch veto.  Either terminal form is acceptable.
        pass

    debt = scratchpad / "rag_sweep.degraded"
    assert debt.is_file()
    debt_text = debt.read_text(encoding="utf-8", errors="replace")
    assert (
        "rag_sweep" in debt_text
        and (
            "findings_inventory.md" in debt_text
            or "precedent_facts" in debt_text
            or "generation" in debt_text
            or "authority" in debt_text
            or "tamper" in debt_text
        )
    )
    assert launches == [], (
        "rag_sweep reached run_phase after its committed semantic-dedup "
        "inventory successor failed exact input binding"
    )


def test_real_main_three_phase_missing_apply_quarantines_rag_and_queue_t0(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing semantic authority survives RAG skip and blocks queue cutover."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    assert DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=RUN_ID,
    )

    ledger_path = scratchpad / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    apply_keys = [
        key
        for key in ledger.get("work_units", {})
        if key.endswith("/semantic_dedup/prequeue_apply")
    ]
    assert len(apply_keys) == 1
    missing_apply_key = apply_keys[0]
    ledger["work_units"].pop(missing_apply_key)
    ledger_path.write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert not DRIVER._l1_prequeue_apply_authority_exists(
        scratchpad,
        config=config,
        run_id=RUN_ID,
    )

    # Resume immediately after semantic precision.  The real main loop must
    # carry the missing-authority entry condition across both downstream
    # phases; RAG cannot launch and queue T0 cannot arm.
    Checkpoint(
        completed=["recon", "semantic_dedup"],
        run_id=RUN_ID,
    ).save(scratchpad)
    config_path = scratchpad / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    semantic = next(p for p in L1_PHASES if p.name == "semantic_dedup")
    rag = next(p for p in L1_PHASES if p.name == "rag_sweep")
    queue = next(p for p in L1_PHASES if p.name == "verify_queue")
    monkeypatch.setattr(DRIVER, "L1_PHASES", [semantic, rag, queue])
    _isolate_real_main_loop(monkeypatch)

    model_launches: list[str] = []

    def forbidden_model_launch(phase, _config, attempt):
        model_launches.append(f"{phase.name}:{attempt}")
        raise AssertionError(
            "a quarantined downstream phase reached MODEL launch"
        )

    t0_calls: list[str] = []

    def forbidden_inventory_t0(*_args, **_kwargs):
        t0_calls.append("inventory")
        raise AssertionError("verify-queue T0 inspected quarantined inventory")

    def forbidden_projection_t0(*_args, **_kwargs):
        t0_calls.append("frozen-projection")
        raise AssertionError("verify-queue T0 froze quarantined inventory")

    queue_results: list[dict[str, Any]] = []
    real_queue_boundary = DRIVER._run_live_verify_queue_phase_boundary

    def observed_queue_boundary(**kwargs: Any) -> Mapping[str, Any]:
        result = real_queue_boundary(**kwargs)
        queue_results.append(dict(result))
        return result

    monkeypatch.setattr(DRIVER, "run_phase", forbidden_model_launch)
    monkeypatch.setattr(
        DRIVER, "_inventory_has_usable_findings", forbidden_inventory_t0
    )
    monkeypatch.setattr(
        DRIVER, "prepare_preverify_frozen_projection", forbidden_projection_t0
    )
    monkeypatch.setattr(
        DRIVER,
        "_run_live_verify_queue_phase_boundary",
        observed_queue_boundary,
    )
    monkeypatch.setattr(sys, "argv", ["plamen_driver.py", str(config_path)])

    with pytest.raises(SystemExit) as stopped:
        DRIVER.main()
    assert stopped.value.code == DRIVER.EXIT_DEGRADED

    assert model_launches == [], "RAG MODEL was launched over missing apply authority"
    assert t0_calls == [], "verify-queue T0/cutover was reached after quarantine"
    assert len(queue_results) == 1
    queue_result = queue_results[0]
    assert queue_result.get("safe_to_continue") is False
    assert queue_result.get("state") == "INCOMPLETE_WITH_DEBT"
    assert queue_result.get("cutover_result") is None
    queue_issues = " ".join(
        str(issue) for issue in queue_result.get("issues") or ()
    ).lower()
    assert any(
        token in queue_issues
        for token in ("authority", "quarantin", "semantic transaction")
    )

    rag_debt = scratchpad / "rag_sweep.degraded"
    assert rag_debt.is_file()
    rag_text = rag_debt.read_text(
        encoding="utf-8",
        errors="replace",
    ).lower()
    assert "authority" in rag_text or "quarantin" in rag_text
    status = json.loads(
        (
            scratchpad / "canonical_inventory_successor_status.json"
        ).read_text(encoding="utf-8")
    )
    assert status.get("state") == "QUARANTINED"
    assert status.get("safe_to_consume") is False
    assert status.get("downstream_phase") == "verify_queue"
    assert status.get("run_id") == RUN_ID

    checkpoint_after = Checkpoint.load(scratchpad)
    assert "rag_sweep" not in checkpoint_after.completed
    assert "verify_queue" not in checkpoint_after.completed
    assert not any(
        (scratchpad / name).exists()
        for name in (
            "verification_queue.md",
            "verification_queue.json",
            "verification_queue.work_items.json",
            "verification_queue.work_plan.json",
        )
    )
    final_ledger = read_artifact_ledger(scratchpad)
    assert missing_apply_key not in final_ledger.get("work_units", {})
    assert not any(
        "/verify_queue/routing" in key
        for key in final_ledger.get("work_units", {})
    )


def test_step5_repair_a_restores_exact_committed_generation_without_reanalysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authenticated private postimages repair all five roots byte-exactly."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    generation_digest, postimages = _generation_postimages(
        scratchpad, applied
    )
    _truncate_canonical_inventory(scratchpad)
    assert DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=RUN_ID,
    ) is False

    _forbid_semantic_reanalysis(monkeypatch)
    recover = _required_downstream_recovery()
    first = recover(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        downstream_phase="rag_sweep",
    )

    assert first.get("safe_to_consume") is True
    assert first.get("repaired") is True
    assert not first.get("issues")
    for name, expected in postimages.items():
        assert (scratchpad / name).read_bytes() == expected
    assert DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=RUN_ID,
    )
    receipt_before = _assert_durable_repair_receipt(
        scratchpad=scratchpad,
        result=first,
        generation_digest=generation_digest,
    )
    snapshot_before = _semantic_snapshot(scratchpad)

    second = recover(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        downstream_phase="rag_sweep",
    )

    assert second.get("safe_to_consume") is True
    assert not second.get("issues")
    assert second.get("state") in {
        "ALREADY_CURRENT",
        "ALREADY_RECOVERED",
        "RECOVERED",
    }
    assert _semantic_snapshot(scratchpad) == snapshot_before
    assert _assert_durable_repair_receipt(
        scratchpad=scratchpad,
        result=second,
        generation_digest=generation_digest,
    ) == receipt_before


def test_step5_repair_a_refuses_tampered_private_generation_and_leaves_veto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A damaged private postimage is debt, never restoration authority."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    generation, _manifest = _transaction_generation(scratchpad, applied)
    private_inventory = generation / "a0.bin"
    private_inventory.write_bytes(
        private_inventory.read_bytes() + b"\nPRIVATE-AUTHORITY-TAMPER\n"
    )
    tampered_root = _truncate_canonical_inventory(scratchpad)
    roots_before = {
        name: (scratchpad / name).read_bytes()
        for name in ROOT_OUTPUT_NAMES
    }

    _forbid_semantic_reanalysis(monkeypatch)
    recover = _required_downstream_recovery()
    refused = recover(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        downstream_phase="rag_sweep",
    )

    assert refused.get("safe_to_consume") is False
    assert refused.get("repaired") is not True
    issues = [str(issue) for issue in refused.get("issues") or ()]
    assert issues
    assert any(
        token in " ".join(issues).lower()
        for token in ("tamper", "digest", "generation", "authority")
    )
    for name, before in roots_before.items():
        assert (scratchpad / name).read_bytes() == before
    assert (scratchpad / "findings_inventory.md").read_bytes() == tampered_root
    assert DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=RUN_ID,
    ) is False
    debt = scratchpad / "rag_sweep.degraded"
    assert debt.is_file()
    debt_text = debt.read_text(encoding="utf-8", errors="replace").lower()
    assert any(
        token in debt_text
        for token in ("tamper", "digest", "generation", "authority")
    )


def test_step5_repair_a_never_writes_before_independent_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An arm rejection leaves every damaged/missing public root untouched."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    _truncate_canonical_inventory(scratchpad)
    (scratchpad / "dedup_absorbed_map.md").unlink()
    roots_before = {
        name: (
            (scratchpad / name).read_bytes()
            if (scratchpad / name).is_file()
            else None
        )
        for name in ROOT_OUTPUT_NAMES
    }

    _forbid_semantic_reanalysis(monkeypatch)

    def reject_before_write(*args, **kwargs):
        raise RuntimeError("fixture independent PRE arm rejection")

    # During the RED state this name is the single post-write authority.
    # The production fix replaces it with a PRE arm plus POST finalize; keep
    # both hooks rejected so the assertion remains an ordering contract.
    if hasattr(DRIVER, "arm_exact_committed_output_repair"):
        monkeypatch.setattr(
            DRIVER,
            "arm_exact_committed_output_repair",
            reject_before_write,
        )
    monkeypatch.setattr(
        DRIVER,
        "authorize_exact_committed_output_repair",
        reject_before_write,
    )

    refused = _required_downstream_recovery()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        downstream_phase="rag_sweep",
    )

    assert refused.get("safe_to_consume") is False
    assert refused.get("repaired") is not True
    for name, before in roots_before.items():
        path = scratchpad / name
        if before is None:
            assert not path.exists(), (
                f"{name} was published before independent repair arm"
            )
        else:
            assert path.read_bytes() == before, (
                f"{name} changed before independent repair arm"
            )
    assert not list((scratchpad / "_sdt").glob("r_*.json"))


def test_step5_quarantine_blocks_verify_queue_t0_after_rag_would_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The run-level quarantine is rechecked by queue T0, not only by RAG."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    generation, _manifest = _transaction_generation(scratchpad, applied)
    private_inventory = generation / "a0.bin"
    private_inventory.write_bytes(
        private_inventory.read_bytes() + b"\nPRIVATE-AUTHORITY-TAMPER\n"
    )
    _truncate_canonical_inventory(scratchpad)

    # The queue boundary must return before any T0 producer/cutover work.  If
    # quarantine is only a RAG-local continue, this sentinel is reached.
    def forbidden_t0(*args, **kwargs):
        raise AssertionError("verify-queue T0 ran over quarantined inventory")

    monkeypatch.setattr(
        DRIVER, "_inventory_has_usable_findings", forbidden_t0
    )
    monkeypatch.setattr(
        DRIVER, "_commit_incomplete_phase_attempt", lambda *a, **k: None
    )
    queue = next(p for p in L1_PHASES if p.name == "verify_queue")
    checkpoint = Checkpoint(
        completed=["recon", "semantic_dedup", "rag_sweep"],
        run_id=RUN_ID,
    )

    result = DRIVER._run_live_verify_queue_phase_boundary(
        phase=queue,
        checkpoint=checkpoint,
        scratchpad=scratchpad,
        config=config,
        phases=[queue],
        trust_preverify_issues=(),
    )

    assert result.get("safe_to_continue") is False
    assert result.get("state") == "INCOMPLETE_WITH_DEBT"
    assert any(
        token in " ".join(str(v) for v in result.get("issues") or ()).lower()
        for token in ("quarantin", "tamper", "generation", "authority")
    )
    status_path = (
        scratchpad / "canonical_inventory_successor_status.json"
    )
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status.get("state") == "QUARANTINED"
    assert status.get("safe_to_consume") is False


def test_step5_missing_apply_authority_is_context_for_quarantine_not_bypass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing ledger authority cannot suppress its own downstream guard."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    roots_before = {
        name: (scratchpad / name).read_bytes()
        for name in ROOT_OUTPUT_NAMES
    }
    ledger_path = scratchpad / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    apply_keys = [
        key
        for key in ledger.get("work_units", {})
        if key.endswith("/semantic_dedup/prequeue_apply")
    ]
    assert len(apply_keys) == 1
    ledger["work_units"].pop(apply_keys[0])
    ledger_path.write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert DRIVER._l1_prequeue_apply_authority_exists(
        scratchpad,
        config=config,
        run_id=RUN_ID,
    ) is False

    _forbid_semantic_reanalysis(monkeypatch)
    refused = _required_downstream_recovery()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        downstream_phase="rag_sweep",
        semantic_phase_completed=True,
    )

    assert refused.get("safe_to_consume") is False
    assert refused.get("state") == "QUARANTINED"
    assert any(
        "authority" in str(issue).lower()
        for issue in refused.get("issues") or ()
    )
    for name, before in roots_before.items():
        assert (scratchpad / name).read_bytes() == before


def test_step5_incomplete_precision_phase_uses_authenticated_recall_floor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No transaction intent may fall back only to an active upstream owner."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    inventory_before = (scratchpad / "findings_inventory.md").read_bytes()
    assert not (scratchpad / "_sdt").exists()

    _forbid_semantic_reanalysis(monkeypatch)
    result = _required_downstream_recovery()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        downstream_phase="rag_sweep",
        semantic_phase_completed=False,
    )

    assert result.get("safe_to_consume") is True
    assert result.get("state") == "RECALL_FLOOR_PREDECESSOR"
    assert result.get("repaired") is False
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_before
    status = json.loads(
        (
            scratchpad / "canonical_inventory_successor_status.json"
        ).read_text(encoding="utf-8")
    )
    assert status.get("state") == "RECALL_FLOOR_PREDECESSOR"
    assert status.get("safe_to_consume") is True
    authority = status.get("authority")
    assert isinstance(authority, Mapping)
    assert authority.get("authority_kind") == "ACTIVE_UPSTREAM_RECALL_FLOOR"
    owner_key = str(authority.get("producer_work_unit_key") or "")
    assert owner_key
    ledger = read_artifact_ledger(scratchpad)
    binding = ledger["artifact_bindings"][
        "scratchpad:findings_inventory.md"
    ]
    owner = ledger["work_units"][owner_key]
    assert binding["owner_key"] == owner_key
    assert binding["run_id"] == RUN_ID
    assert binding["status"] == "ACTIVE"
    assert binding["sha256"] == authority["sha256"]
    assert binding["sha256"] == hashlib.sha256(inventory_before).hexdigest()
    assert owner["run_id"] == RUN_ID
    assert owner["semantic_status"] == "ACTIVE"
    assert owner["execution_state"] == "OUTPUT_COMMITTED"
    assert owner["contract_digest"] == authority[
        "producer_contract_digest"
    ]
    assert owner["launch_digest"] == authority["producer_launch_digest"]
    assert not any(
        key.endswith("/semantic_dedup/prequeue_apply")
        for key in ledger["work_units"]
    )

    # "Active upstream" and "current run" are both necessary, not merely
    # descriptive status fields in the positive receipt.
    ledger_path = scratchpad / "_artifact_state.json"
    original_ledger_raw = ledger_path.read_bytes()
    for case in ("stale-producer", "prior-run-producer"):
        payload = json.loads(original_ledger_raw)
        mutated_owner = payload["work_units"][owner_key]
        mutated_binding = payload["artifact_bindings"][
            "scratchpad:findings_inventory.md"
        ]
        if case == "stale-producer":
            mutated_owner["semantic_status"] = "STALE_INPUT"
        else:
            prior_run = "11111111-2222-3333-4444-555555555555"
            mutated_owner["run_id"] = prior_run
            mutated_binding["run_id"] = prior_run
        ledger_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        refused = _required_downstream_recovery()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            downstream_phase="rag_sweep",
            semantic_phase_completed=False,
        )
        assert refused.get("safe_to_consume") is False, case
        assert refused.get("state") == "QUARANTINED", case
        assert refused.get("issues"), case
        assert not (scratchpad / "_sdt").exists(), case
        ledger_path.write_bytes(original_ledger_raw)

    accepted_again = _required_downstream_recovery()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        downstream_phase="rag_sweep",
        semantic_phase_completed=False,
    )
    assert accepted_again.get("safe_to_consume") is True
    assert accepted_again.get("state") == "RECALL_FLOOR_PREDECESSOR"
