"""Live startup reconciliation fixtures for P0-Z semantic freshness."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import plamen_driver as D
from artifact_ledger import (
    ArtifactLedgerError,
    arm_semantic_mutation,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


RUN_ID = "12345678-1234-4123-8123-123456789abc"
BASE = {
    "pipeline": "sc",
    "mode": "core",
    "ecosystem": "evm",
    "backend": "claude",
}


def _phase(name: str) -> D.Phase:
    return D.Phase(
        name, ["Section"], [f"{name}.md"],
        base_timeout_s=60, min_artifact_bytes=1,
    )


def _contract(
    phase: str,
    unit: str,
    *,
    source: str,
    output: str,
) -> PhaseIOContract:
    key = "/".join((*BASE.values(), phase, unit))
    return PhaseIOContract(
        **BASE,
        phase=phase,
        work_unit_id=unit,
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=output,
            owner_key=key,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="REPLACE",
        ),),
        immutable_inputs=(f"scratchpad:{source}",),
        model_invoked=False,
    )


def _record(sp: Path, contract: PhaseIOContract) -> None:
    launch = LaunchSpec(
        work_unit_key=contract.key,
        **BASE,
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )
    outputs = {
        spec.identity: (
            sp / spec.path
            if spec.root == "scratchpad"
            else sp.parent / spec.path
        )
        for spec in contract.outputs
    }
    output_bytes = {
        identity: path.read_bytes()
        for identity, path in outputs.items()
        if path.is_file()
    }
    for path in outputs.values():
        if path.is_file():
            path.unlink()
    record_work_unit_inputs(sp, sp.parent, contract, launch, run_id=RUN_ID)
    for identity, raw in output_bytes.items():
        path = outputs[identity]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    record_work_unit_artifacts(sp, sp.parent, contract, launch, run_id=RUN_ID)


def _fixture(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    for name, text in {
        "source.md": "source-a\n",
        "source_phase.md": "source phase\n",
        "derive_a.md": "a\n",
        "stable.md": "stable\n",
        "derive_b.md": "b\n",
        "aggregate.md": "aggregate\n",
    }.items():
        (sp / name).write_text(text, encoding="utf-8")
    a = _contract(
        "derive_a", "worker.0001", source="source.md", output="derive_a.md"
    )
    b = _contract(
        "derive_b", "worker.0001", source="stable.md", output="derive_b.md"
    )
    aggregate = _contract(
        "aggregate", "driver", source="derive_a.md", output="aggregate.md"
    )
    for contract in (a, b, aggregate):
        _record(sp, contract)
    phases = [_phase(name) for name in (
        "source_phase", "derive_a", "derive_b", "aggregate",
    )]
    checkpoint = D.Checkpoint(
        completed=[phase.name for phase in phases],
        run_id=RUN_ID,
    )
    return sp, phases, checkpoint, (a, b, aggregate)


def test_resume_rewinds_exact_semantic_descendants_not_independent_sibling(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, _contracts = _fixture(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "source.md").write_text("source-b\n", encoding="utf-8")

    removed = D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == ["derive_a", "aggregate"]
    assert checkpoint.completed == ["source_phase", "derive_b"]
    receipt = D.read_artifact_ledger(sp)
    assert receipt["work_units"][_contracts[0].key]["semantic_status"] == "STALE_INPUT"
    assert receipt["work_units"][_contracts[1].key]["semantic_status"] == "ACTIVE"
    assert receipt["work_units"][_contracts[2].key]["semantic_status"] == "STALE_INPUT"
    assert (sp / "semantic_resume_invalidation.json").is_file()


def test_unchanged_semantic_resume_runs_no_repair_and_is_byte_stable(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, _contracts = _fixture(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    ledger_before = (sp / "_artifact_state.json").read_bytes()

    removed = D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == []
    assert checkpoint.completed == [phase.name for phase in phases]
    assert (sp / "_artifact_state.json").read_bytes() == ledger_before
    assert not (sp / "semantic_resume_invalidation.json").exists()


def test_rerun_refreshes_receipts_and_second_resume_is_clean(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, contracts = _fixture(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "source.md").write_text("source-b\n", encoding="utf-8")
    assert D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == ["derive_a", "aggregate"]

    _record(sp, contracts[0])
    _record(sp, contracts[2])
    checkpoint.completed = [phase.name for phase in phases]
    (sp / "semantic_resume_invalidation.json").unlink()
    assert D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == []
    assert not (sp / "semantic_resume_invalidation.json").exists()


def test_stale_reexecution_rejects_tampered_invalidation_metadata(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, contracts = _fixture(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "source.md").write_text("source-b\n", encoding="utf-8")
    assert D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == ["derive_a", "aggregate"]

    ledger_path = sp / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["work_units"][contracts[0].key]["semantic_invalidation"][
        "plan_digest"
    ] = "0" * 64
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(ArtifactLedgerError, match="invalidation metadata"):
        _record(sp, contracts[0])


def test_stale_reexecution_rejects_nonstale_output_binding(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, contracts = _fixture(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "source.md").write_text("source-b\n", encoding="utf-8")
    assert D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == ["derive_a", "aggregate"]

    ledger_path = sp / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    output_identity = "scratchpad:derive_a.md"
    ledger["artifact_bindings"][output_identity]["status"] = "ACTIVE"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(ArtifactLedgerError, match="STALE_INPUT"):
        _record(sp, contracts[0])


def test_stale_reexecution_rejects_missing_output_binding(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, contracts = _fixture(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "source.md").write_text("source-b\n", encoding="utf-8")
    assert D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == ["derive_a", "aggregate"]

    ledger_path = sp / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    del ledger["artifact_bindings"]["scratchpad:derive_a.md"]
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(ArtifactLedgerError, match="STALE_INPUT"):
        _record(sp, contracts[0])


def test_stale_reexecution_trigger_must_belong_to_changed_denominator(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, contracts = _fixture(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "source.md").write_text("source-b\n", encoding="utf-8")
    assert D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == ["derive_a", "aggregate"]

    ledger_path = sp / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    authorization = ledger["work_units"][contracts[0].key][
        "semantic_invalidation"
    ]
    authorization["trigger_identities"] = ["scratchpad:unrelated.md"]
    unsigned = {
        key: value
        for key, value in authorization.items()
        if key != "authorization_digest"
    }
    authorization["authorization_digest"] = hashlib.sha256(
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(ArtifactLedgerError, match="metadata integrity"):
        _record(sp, contracts[0])


def test_changed_worker_does_not_invalidate_same_phase_sibling_receipt(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, contracts = _fixture(tmp_path)
    (sp / "derive_a_sibling.md").write_text("sibling\n", encoding="utf-8")
    sibling = _contract(
        "derive_a", "worker.0002", source="stable.md",
        output="derive_a_sibling.md",
    )
    _record(sp, sibling)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "source.md").write_text("source-b\n", encoding="utf-8")

    assert D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    ) == ["derive_a", "aggregate"]
    units = D.read_artifact_ledger(sp)["work_units"]
    assert units[contracts[0].key]["semantic_status"] == "STALE_INPUT"
    assert units[sibling.key]["semantic_status"] == "ACTIVE"


def test_untyped_downstream_forces_safe_suffix_repair_during_migration(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, _contracts = _fixture(tmp_path)
    legacy_phase = _phase("legacy_projection")
    phases.insert(2, legacy_phase)
    checkpoint.completed.insert(2, legacy_phase.name)
    (sp / "legacy_projection.md").write_text("legacy\n", encoding="utf-8")
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "source.md").write_text("source-b\n", encoding="utf-8")

    removed = D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == ["derive_a", "legacy_projection", "derive_b", "aggregate"]
    receipt = __import__("json").loads(
        (sp / "semantic_resume_invalidation.json").read_text(encoding="utf-8")
    )
    assert receipt["reason"] == "INPUT_DRIFT_WITH_UNTYPED_DESCENDANT"
    assert receipt["coverage_fallback_phases"] == [
        "legacy_projection", "derive_b", "aggregate",
    ]


def test_corrupt_semantic_ledger_repairs_without_destructive_archive(
    tmp_path: Path, monkeypatch,
):
    sp, phases, checkpoint, _contracts = _fixture(tmp_path)
    (sp / "_artifact_state.json").write_text("{broken", encoding="utf-8")
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == [phase.name for phase in phases]
    assert checkpoint.completed == []
    assert (sp / "_artifact_state.json").read_text(encoding="utf-8") == "{broken"
    assert not list(tmp_path.glob(".plamen-stale-snapshots/*"))
    receipt = __import__("json").loads(
        (sp / "semantic_resume_invalidation.json").read_text(encoding="utf-8")
    )
    assert receipt["reason"].startswith("SEMANTIC_LEDGER_INVALID:")


def test_resume_recovers_armed_mutation_without_artifact_ledger_conservatively(
    tmp_path: Path, monkeypatch,
):
    """A crash after source mutation cannot bypass startup reconciliation."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    source = sp / "findings_inventory.md"
    source.write_text("before\n", encoding="utf-8")
    event = arm_semantic_mutation(
        sp,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="PROMOTION",
        run_id=RUN_ID,
    )
    source.write_text("after\n", encoding="utf-8")
    phases = [_phase("inventory"), _phase("verify_queue")]
    checkpoint = D.Checkpoint(
        completed=[phase.name for phase in phases], run_id=RUN_ID
    )
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "core", "evm"
    )

    assert removed == ["inventory", "verify_queue"]
    assert checkpoint.completed == []
    mutation_payload = __import__("json").loads(
        (sp / "_semantic_mutations.json").read_text(encoding="utf-8")
    )
    recovered = next(
        row for row in mutation_payload["events"]
        if row["event_id"] == event["event_id"]
    )
    assert recovered["status"] == "INVALIDATION_APPLIED"
    receipt = __import__("json").loads(
        (sp / "semantic_resume_invalidation.json").read_text(encoding="utf-8")
    )
    assert receipt["reason"] == "MUTATION_WITHOUT_TYPED_DESCENDANTS"
    assert receipt["recovered_mutation_event_ids"] == [event["event_id"]]


def test_report_model_prelaunch_binding_matches_compiled_dynamic_prompt(
    tmp_path: Path,
    monkeypatch,
):
    from phase_contract_compiler import extract_compiled_phase_io
    from plamen_prompt import build_phase_prompt, plamen_home
    from plamen_types import SC_PHASES

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    required = (
        "report_index_coverage_seed.md",
        "candidate_semantic_facets.md",
        "candidate_semantic_facets.json",
        "verification_queue.md",
    )
    for name in required:
        (sp / name).write_text("{}\n" if name.endswith(".json") else "# input\n", encoding="utf-8")
    phase = next(item for item in SC_PHASES if item.name == "report_index")
    config = {
        **BASE,
        "language": "evm",
        "cli_backend": "claude",
        "scratchpad": str(sp),
        "project_root": str(tmp_path),
        "_run_id": RUN_ID,
        "proven_only": False,
    }
    # This test isolates prompt/PhaseIO denominator parity.  The independent
    # R10 report-consumer gate is covered by its own authority suites.
    monkeypatch.setattr(
        D, "_r10_report_consumer_ready_issues", lambda *_args, **_kwargs: []
    )

    assert D._bind_typed_model_phase_inputs(phase, sp, config) == []
    prompt = build_phase_prompt(
        plamen_home() / "commands" / "plamen.md", phase, config
    )
    compiled = extract_compiled_phase_io(prompt)
    unit = D.read_artifact_ledger(sp)["work_units"][compiled["work_unit_key"]]
    assert compiled["contract_digest"] == unit["contract_digest"]
    assert set(compiled["immutable_inputs"]) == {
        f"scratchpad:{name}" for name in required
    }
    assert "scratchpad:severity_binding.md" not in compiled["immutable_inputs"]
    assert set(unit["input_bindings"]) == set(compiled["immutable_inputs"])


def test_main_binds_typed_model_inputs_before_first_model_launch():
    import inspect

    source = inspect.getsource(D.main)
    bind_at = source.index("_bind_typed_model_phase_inputs(")
    first_launch_at = source.index("rc = run_phase(phase, config, attempt=1)")
    assert bind_at < first_launch_at


def test_live_promotion_arms_before_mutation_and_rewinds_existing_consumer(
    tmp_path: Path, monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text("before\n", encoding="utf-8")
    (sp / "queue.md").write_text("queue\n", encoding="utf-8")
    queue = _contract(
        "sc_verify_queue", "routing", source="findings_inventory.md",
        output="queue.md",
    )
    _record(sp, queue)
    checkpoint = D.Checkpoint(
        completed=["sc_verify_queue"], run_id=RUN_ID,
    )
    config = {
        "pipeline": "sc", "mode": "core", "language": "evm",
        "cli_backend": "claude", "project_root": str(tmp_path),
        "_run_id": RUN_ID,
    }

    def _mutate(root: Path):
        (root / "findings_inventory.md").write_text(
            "after\n", encoding="utf-8"
        )
        return ["SKEP-001"]

    monkeypatch.setattr(D, "_promote_depth_findings_to_inventory", _mutate)
    promoted = D._promote_findings_with_semantic_invalidation(
        sp, config, checkpoint
    )

    assert promoted == ["SKEP-001"]
    assert checkpoint.completed == []
    assert D.read_artifact_ledger(sp)["work_units"][queue.key][
        "semantic_status"
    ] == "STALE_INPUT"
    mutations = __import__("json").loads(
        (sp / "_semantic_mutations.json").read_text(encoding="utf-8")
    )
    events = {
        row["artifact_identity"]: row
        for row in mutations["events"]
    }
    # Promotion now arms the complete canonical inventory triple before any
    # mutation.  Event order is therefore not semantic authority: the
    # allocation ledger can remain unchanged while the structured records and
    # Markdown inventory advance.  Assert the exact changed identity instead
    # of accidentally treating the first (ledger) arm as the promotion event.
    inventory_event = events["scratchpad:findings_inventory.md"]
    assert inventory_event["status"] == "INVALIDATION_APPLIED"
    assert inventory_event["affected_record_ids"] == ["SKEP-001"]
    assert events["scratchpad:_id_ledger.json"]["status"] == "NO_CHANGE"
