"""Reviewer-owned adversarial fixtures for the P0-Z startup boundary."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import plamen_driver as D
from artifact_ledger import (
    arm_semantic_mutation,
    finalize_semantic_mutation,
    pending_semantic_mutations,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract
from plamen_types import SC_PHASES


RUN_ID = "92345678-1234-4123-8123-123456789abc"
BASE = {
    "pipeline": "sc",
    "mode": "core",
    "ecosystem": "evm",
    "backend": "claude",
}


def _phase(name: str) -> D.Phase:
    return D.Phase(
        name,
        ["Section"],
        [f"{name}.md"],
        base_timeout_s=60,
        min_artifact_bytes=1,
    )


def _checkpoint_fixture(tmp_path: Path, names=("first", "second")):
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    phases = [_phase(name) for name in names]
    for phase in phases:
        (scratch / phase.expected_artifacts[0]).write_text(
            f"{phase.name}\n", encoding="utf-8"
        )
    checkpoint = D.Checkpoint(
        completed=[phase.name for phase in phases], run_id=RUN_ID
    )
    return scratch, phases, checkpoint


def _event_digest(event: dict[str, object]) -> str:
    unsigned = {key: value for key, value in event.items() if key != "event_digest"}
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _record_consumer(
    scratch: Path,
    project: Path,
    *,
    phase: str,
    source: str,
    output: str,
) -> str:
    key = f"sc/core/evm/claude/{phase}/worker.0001"
    contract = PhaseIOContract(
        **BASE,
        phase=phase,
        work_unit_id="worker.0001",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=output,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        immutable_inputs=(f"scratchpad:{source}",),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        **BASE,
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )
    output_path = scratch / output
    staged = output_path.read_bytes() if output_path.is_file() else None
    if staged is not None:
        output_path.unlink()
    D.record_work_unit_inputs(scratch, project, contract, launch, run_id=RUN_ID)
    if staged is not None:
        output_path.write_bytes(staged)
    D.record_work_unit_artifacts(scratch, project, contract, launch, run_id=RUN_ID)
    return key


def _finalize_changed_mutation(
    scratch: Path,
    project: Path,
    *,
    run_id: str = RUN_ID,
) -> dict[str, object]:
    source = scratch / "findings_inventory.md"
    source.write_text("before\n", encoding="utf-8")
    event = arm_semantic_mutation(
        scratch,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="PROMOTION",
        run_id=run_id,
    )
    source.write_text("after\n", encoding="utf-8")
    return finalize_semantic_mutation(
        scratch, project, str(event["event_id"]), run_id=run_id
    )


def test_corrupted_mutation_event_forces_conservative_repair(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    source = scratch / "findings_inventory.md"
    source.write_text("before\n", encoding="utf-8")
    arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="PROMOTION",
        run_id=RUN_ID,
    )
    payload_path = scratch / "_semantic_mutations.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["events"][0]["mutation_kind"] = "CORRUPTED_WITHOUT_REHASH"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == [phase.name for phase in phases]
    assert checkpoint.completed == []


def test_finalized_mutation_without_typed_descendants_cannot_skip_startup_repair(
    tmp_path: Path, monkeypatch,
) -> None:
    """Close the finalize-to-checkpoint-rewind crash window."""
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    source = scratch / "findings_inventory.md"
    source.write_text("before\n", encoding="utf-8")
    event = arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="PROMOTION",
        run_id=RUN_ID,
    )
    source.write_text("after\n", encoding="utf-8")
    finalized = finalize_semantic_mutation(
        scratch, tmp_path, event["event_id"], run_id=RUN_ID
    )
    assert finalized["status"] == "INVALIDATION_APPLIED"
    assert finalized["invalidated_work_unit_keys"] == []
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == [phase.name for phase in phases]
    assert checkpoint.completed == []


def test_rehashed_terminal_forgery_cannot_suppress_armed_change(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    source = scratch / "findings_inventory.md"
    source.write_text("before\n", encoding="utf-8")
    arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="PROMOTION",
        run_id=RUN_ID,
    )
    source.write_text("after\n", encoding="utf-8")
    payload_path = scratch / "_semantic_mutations.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    event = payload["events"][0]
    event["status"] = "NO_CHANGE"
    event["event_digest"] = _event_digest(event)
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == [phase.name for phase in phases]
    assert checkpoint.completed == []


def test_cross_run_armed_event_cannot_be_silently_ignored(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    source = scratch / "findings_inventory.md"
    source.write_text("before\n", encoding="utf-8")
    arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="PROMOTION",
        run_id="foreign-run",
    )
    source.write_text("after\n", encoding="utf-8")
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == [phase.name for phase in phases]
    assert checkpoint.completed == []


def test_non_prefix_checkpoint_does_not_skip_mutation_reconciliation(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(
        tmp_path, names=("first", "second", "third")
    )
    checkpoint.completed = ["first", "third"]
    source = scratch / "source.md"
    source.write_text("before\n", encoding="utf-8")
    _record_consumer(
        scratch,
        tmp_path,
        phase="first",
        source="source.md",
        output="first.md",
    )
    arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:source.md",
        mutation_kind="REPAIR",
        run_id=RUN_ID,
    )
    source.write_text("after\n", encoding="utf-8")
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert set(removed) == {"first", "third"}
    assert checkpoint.completed == []


def test_armed_no_change_is_terminal_without_rewinding_checkpoint(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    source = scratch / "findings_inventory.md"
    source.write_text("same\n", encoding="utf-8")
    arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="IDEMPOTENT_REPAIR",
        run_id=RUN_ID,
    )
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == []
    assert checkpoint.completed == [phase.name for phase in phases]
    payload = json.loads(
        (scratch / "_semantic_mutations.json").read_text(encoding="utf-8")
    )
    assert payload["events"][0]["status"] == "NO_CHANGE"


def test_armed_change_rewinds_typed_descendant_but_preserves_typed_sibling(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    (scratch / "source.md").write_text("before\n", encoding="utf-8")
    (scratch / "stable.md").write_text("stable\n", encoding="utf-8")
    _record_consumer(
        scratch, tmp_path, phase="first", source="source.md", output="first.md"
    )
    _record_consumer(
        scratch, tmp_path, phase="second", source="stable.md", output="second.md"
    )
    arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:source.md",
        mutation_kind="REPAIR",
        run_id=RUN_ID,
    )
    (scratch / "source.md").write_text("after\n", encoding="utf-8")
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == ["first"]
    assert checkpoint.completed == ["second"]
    units = D.read_artifact_ledger(scratch)["work_units"]
    assert units["sc/core/evm/claude/first/worker.0001"]["semantic_status"] == (
        "STALE_INPUT"
    )
    assert units["sc/core/evm/claude/second/worker.0001"]["semantic_status"] == (
        "ACTIVE"
    )


def test_chain_iter2_launch_binding_matches_live_claude_runtime_policy(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    # Force the live scale_timeout path above the phase base budget.
    (tmp_path / "Large.sol").write_text("x\n" * 20_000, encoding="utf-8")
    phase = next(item for item in SC_PHASES if item.name == "chain_iter2")
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "claude_exec_mode": "headless",
        "scratchpad": str(scratch),
        "project_root": str(tmp_path),
    }

    _contract, launch = D._typed_model_phase_contract_and_launch(
        phase, scratch, config
    )

    assert {
        "model": launch.model,
        "timeout_s": launch.timeout_s,
        "exec_mode": launch.exec_mode,
    } == {
        "model": D.phase_model(phase, "thorough", config),
        "timeout_s": D.scale_timeout(
            phase.base_timeout_s,
            str(tmp_path),
            "evm",
            mode="thorough",
            hypothesis_count=0,
            backend="claude",
        ),
        "exec_mode": "headless",
    }


def test_rehashed_checkpoint_reconciled_forgery_cannot_self_ack(
    tmp_path: Path, monkeypatch,
) -> None:
    """A rehashable event sidecar is not independent checkpoint authority."""
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    finalized = _finalize_changed_mutation(scratch, tmp_path)
    assert finalized["checkpoint_reconciled"] is False

    payload_path = scratch / "_semantic_mutations.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    event = payload["events"][0]
    event["checkpoint_reconciled"] = True
    event["reconciled_by_run_id"] = RUN_ID
    event["event_digest"] = _event_digest(event)
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    forged_bytes = payload_path.read_bytes()
    forged_sha = hashlib.sha256(forged_bytes).hexdigest()
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == [phase.name for phase in phases]
    assert checkpoint.completed == []
    assert checkpoint.semantic_mutation_acks == {}
    assert json.loads(payload_path.read_text(encoding="utf-8"))["events"] == []
    quarantine = scratch / "_semantic_mutation_quarantine" / f"{forged_sha}.json"
    assert quarantine.read_bytes() == forged_bytes
    receipt = json.loads(
        (scratch / "semantic_mutation_migration.json").read_text(encoding="utf-8")
    )
    assert receipt["source_sha256"] == forged_sha
    assert "self-ack lacks checkpoint authority" in receipt["reason"]


def test_checkpoint_is_durable_before_ack_and_failed_ack_replays_safely(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    finalized = _finalize_changed_mutation(scratch, tmp_path)
    original_ack = D.acknowledge_semantic_mutations
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    def _fail_ack(*_args, **_kwargs):
        raise D.ArtifactLedgerError("injected post-checkpoint acknowledgement crash")

    monkeypatch.setattr(D, "acknowledge_semantic_mutations", _fail_ack)
    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == [phase.name for phase in phases]
    assert D.Checkpoint.load(scratch).completed == []
    assert [row["event_id"] for row in pending_semantic_mutations(scratch)] == [
        finalized["event_id"]
    ]

    # Emulate successful re-execution before the next process start. The first
    # durable checkpoint already owns event_id -> immutable outcome digest, so
    # the event-side marker is redundant. Startup may repair that marker
    # without rewinding the work that ran after the durable checkpoint repair.
    checkpoint.completed = [phase.name for phase in phases]
    checkpoint.save(scratch)
    monkeypatch.setattr(D, "acknowledge_semantic_mutations", original_ack)
    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == []
    assert checkpoint.completed == [phase.name for phase in phases]
    assert pending_semantic_mutations(scratch) == []

    checkpoint.completed = [phase.name for phase in phases]
    checkpoint.save(scratch)
    mutation_bytes = (scratch / "_semantic_mutations.json").read_bytes()
    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == []
    assert checkpoint.completed == [phase.name for phase in phases]
    assert (scratch / "_semantic_mutations.json").read_bytes() == mutation_bytes


def test_checkpoint_save_failure_cannot_ack_pending_mutation(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    checkpoint.save(scratch)
    finalized = _finalize_changed_mutation(scratch, tmp_path)
    ack_calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    def _fail_save(_scratchpad):
        raise OSError("injected checkpoint persistence failure")

    def _record_ack(*args, **_kwargs):
        ack_calls.append((*args, kwargs))
        return []

    monkeypatch.setattr(checkpoint, "save", _fail_save)
    monkeypatch.setattr(D, "acknowledge_semantic_mutations", _record_ack)
    with pytest.raises(OSError, match="checkpoint persistence failure"):
        D._reconcile_completed_checkpoint_artifacts(
            scratch, str(tmp_path), checkpoint, phases, "core", "evm"
        )

    assert ack_calls == []
    assert D.Checkpoint.load(scratch).completed == [
        phase.name for phase in phases
    ]
    assert [row["event_id"] for row in pending_semantic_mutations(scratch)] == [
        finalized["event_id"]
    ]


def test_foreign_finalized_mutation_forces_conservative_repair(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    finalized = _finalize_changed_mutation(
        scratch, tmp_path, run_id="foreign-run"
    )
    assert finalized["status"] == "INVALIDATION_APPLIED"
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == [phase.name for phase in phases]
    assert checkpoint.completed == []
    payload = json.loads(
        (scratch / "_semantic_mutations.json").read_text(encoding="utf-8")
    )
    assert payload["events"][0]["checkpoint_reconciled"] is True
    assert payload["events"][0]["reconciled_by_run_id"] == RUN_ID


def test_legacy_mutation_event_is_quarantined_without_permanent_resume_loop(
    tmp_path: Path, monkeypatch,
) -> None:
    """A pre-ack-schema event must fail safe once, not rewind forever."""
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="LEGACY_REPAIR",
        run_id=RUN_ID,
    )
    payload_path = scratch / "_semantic_mutations.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    event = payload["events"][0]
    event.pop("checkpoint_reconciled")
    event.pop("reconciled_by_run_id")
    event["event_digest"] = _event_digest(event)
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    legacy_bytes = payload_path.read_bytes()
    legacy_sha = hashlib.sha256(legacy_bytes).hexdigest()
    original_quarantine = D.quarantine_invalid_semantic_mutation_ledger
    observed_checkpoint_states: list[tuple[list[str], dict[str, str]]] = []

    def _inspect_then_quarantine(*args, **kwargs):
        durable = D.Checkpoint.load(scratch)
        observed_checkpoint_states.append(
            (list(durable.completed), dict(durable.semantic_mutation_acks))
        )
        return original_quarantine(*args, **kwargs)

    monkeypatch.setattr(
        D, "quarantine_invalid_semantic_mutation_ledger", _inspect_then_quarantine
    )
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == [phase.name for phase in phases]
    assert checkpoint.completed == []
    assert observed_checkpoint_states == [([], {})]
    quarantine = scratch / "_semantic_mutation_quarantine" / f"{legacy_sha}.json"
    assert quarantine.read_bytes() == legacy_bytes
    receipt = json.loads(
        (scratch / "semantic_mutation_migration.json").read_text(encoding="utf-8")
    )
    assert receipt["source_sha256"] == legacy_sha
    assert receipt["state"] == "QUARANTINED_AND_RESET"
    assert json.loads(payload_path.read_text(encoding="utf-8"))["events"] == []

    # After the conservative replay has completed, startup must have a durable
    # migration/quarantine disposition instead of rediscovering the same bad
    # legacy bytes and invalidating every phase on every future resume.
    checkpoint.completed = [phase.name for phase in phases]
    checkpoint.save(scratch)
    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == []
    assert checkpoint.completed == [phase.name for phase in phases]


def test_checkpoint_ack_digest_mismatch_fails_safe_and_quarantines(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    finalized = _finalize_changed_mutation(scratch, tmp_path)
    event_id = str(finalized["event_id"])
    checkpoint.semantic_mutation_acks[event_id] = "0" * 64
    checkpoint.save(scratch)
    payload_path = scratch / "_semantic_mutations.json"
    original_bytes = payload_path.read_bytes()
    original_sha = hashlib.sha256(original_bytes).hexdigest()
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == [phase.name for phase in phases]
    assert checkpoint.completed == []
    assert checkpoint.semantic_mutation_acks == {}
    assert D.Checkpoint.load(scratch).semantic_mutation_acks == {}
    assert (
        scratch / "_semantic_mutation_quarantine" / f"{original_sha}.json"
    ).read_bytes() == original_bytes
    receipt = json.loads(
        (scratch / "semantic_mutation_migration.json").read_text(encoding="utf-8")
    )
    assert "acknowledgement mismatch" in receipt["reason"]


def test_checkpoint_ack_for_missing_event_fails_safe_and_clears_authority(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch, phases, checkpoint = _checkpoint_fixture(tmp_path)
    finalized = _finalize_changed_mutation(scratch, tmp_path)
    event_id = str(finalized["event_id"])
    # The checkpoint claim survives while its event ledger is lost. The
    # artifact ledger left by finalize ensures semantic startup runs.
    checkpoint.semantic_mutation_acks[event_id] = "1" * 64
    checkpoint.save(scratch)
    (scratch / "_semantic_mutations.json").unlink()
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == [phase.name for phase in phases]
    assert checkpoint.completed == []
    assert checkpoint.semantic_mutation_acks == {}
    assert D.Checkpoint.load(scratch).semantic_mutation_acks == {}

    checkpoint.completed = [phase.name for phase in phases]
    checkpoint.save(scratch)
    assert D._reconcile_completed_checkpoint_artifacts(
        scratch, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == []


def test_typed_launch_runtime_matrix_matches_live_backend_policy(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    phase = next(item for item in SC_PHASES if item.name == "chain_iter2")
    monkeypatch.delenv("PLAMEN_CLAUDE_EXEC_MODE", raising=False)
    canonical_bin = D.CLAUDE_BIN
    cases = (
        ("claude-pty", "claude", "pty", None, canonical_bin, "pty"),
        ("claude-headless-config", "claude", "headless", None, canonical_bin, "headless"),
        ("claude-headless-alias", "claude-headless", "pty", None, canonical_bin, "headless"),
        ("codex", "codex", "pty", None, canonical_bin, "codex"),
        ("claude-headless-env", "claude", None, "headless", canonical_bin, "headless"),
        ("claude-wrapper-fallback", "claude", None, None, "claude-wrapper.cmd", "headless"),
    )
    for label, backend, configured, env_mode, binary, expected_exec in cases:
        if env_mode is None:
            monkeypatch.delenv("PLAMEN_CLAUDE_EXEC_MODE", raising=False)
        else:
            monkeypatch.setenv("PLAMEN_CLAUDE_EXEC_MODE", env_mode)
        monkeypatch.setattr(D, "CLAUDE_BIN", binary)
        config = {
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": backend,
            "scratchpad": str(scratch),
            "project_root": str(tmp_path),
        }
        if configured is not None:
            config["claude_exec_mode"] = configured

        runtime = D._live_phase_runtime_launch_policy(phase, scratch, config)
        contract, launch = D._typed_model_phase_contract_and_launch(
            phase, scratch, config
        )

        expected_backend = (
            "claude" if backend == "claude-headless" else backend
        )
        assert runtime["backend"] == expected_backend, label
        assert runtime["exec_mode"] == expected_exec, label
        assert contract.backend == expected_backend, label
        assert launch.backend == expected_backend, label
        assert launch.model == runtime["model"], label
        assert launch.timeout_s == runtime["timeout_s"], label
        assert launch.exec_mode == expected_exec, label
