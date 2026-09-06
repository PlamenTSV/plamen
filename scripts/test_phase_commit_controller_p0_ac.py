"""P0-AC regression contracts for typed, durable phase completion debt."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
import plamen_driver as D

from artifact_ledger import (
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from plamen_driver import (
    PhaseCommitController,
    _arm_incomplete_phase_retry,
    _commit_content_with_gate_debt,
    _commit_incomplete_phase_attempt,
    _commit_phase_from_disk_debt,
    _gate_failures_from_issues,
    _prune_stale_dynamic_report_checkpoint_entries,
    _resolved_phase_artifact_digest,
    _resolved_phase_contract_digest,
)
from plamen_types import (
    Checkpoint,
    GateClearance,
    GateFailure,
    Phase,
    PhaseCommit,
)
from plamen_validators import (
    _selected_skill_manifest_issues,
    _sync_degraded_sentinels_to_checkpoint,
    _validate_chain_iter2,
    _validate_id_ledger_collisions,
)


def _attention_phase() -> Phase:
    return Phase(
        "attention_repair",
        ["Attention Repair"],
        ["attention_repair_summary.md"],
        3000,
    )


def _write_valid_attention_artifacts(scratchpad: Path) -> None:
    (scratchpad / "attention_repair_queue.md").write_text(
        "| # | Kind | Target | Reason | Source | Evidence hint |\n"
        "|---|---|---|---|---|---|\n"
        "| 1 | security-obligation | SO-1 | generic | m.md | SO-1 |\n",
        encoding="utf-8",
    )
    (scratchpad / "attention_repair_summary.md").write_text(
        "# Attention Repair\n\n"
        "| Queue # | Kind | Target | Verdict | Evidence | Notes |\n"
        "|---|---|---|---|---|---|\n"
        "| 1 | security-obligation | SO-1 | SAFE | Router.sol:L10 | bound |\n",
        encoding="utf-8",
    )


def _config(project_root: Path) -> dict[str, str]:
    return {
        "project_root": str(project_root),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
    }


def _controller_failure(
    phase: Phase,
    scratchpad: Path,
    project_root: Path,
    issue: str,
) -> tuple[GateFailure, ...]:
    config = _config(project_root)
    return _gate_failures_from_issues(
        phase,
        [issue],
        contract_digest=_resolved_phase_contract_digest(phase, config),
        output_digest=_resolved_phase_artifact_digest(
            phase, scratchpad, project_root
        ),
        scratchpad=scratchpad,
    )


def test_content_presence_cannot_clear_methodology_failure(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_valid_attention_artifacts(scratchpad)
    (scratchpad / "attention_repair.degraded").write_text(
        "selected-skill application parity failed for SKILL-7\n",
        encoding="utf-8",
    )
    (scratchpad / "attention_repair_retry_hint.md").write_text(
        "repair the selected-skill consumer application\n", encoding="utf-8"
    )
    quarantine = scratchpad / "_retry_quarantine" / "attention_repair"
    quarantine.mkdir(parents=True)
    (quarantine / "attention_repair_summary.md.attempt1").write_text(
        "prior output", encoding="utf-8"
    )
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
    }

    result = _commit_content_with_gate_debt(
        _attention_phase(),
        config,
        scratchpad,
        checkpoint,
        ["selected-skill application parity failed for SKILL-7"],
    )

    assert result is None
    assert checkpoint.completed == ["attention_repair"]
    assert checkpoint.degraded == ["attention_repair"]
    commit = checkpoint.phase_commits["attention_repair"]
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert commit.unresolved_failures
    assert commit.unresolved_failures[0].gate_class in {
        "METHODOLOGY_SELECTION", "METHODOLOGY_APPLICATION"
    }
    assert (scratchpad / "attention_repair.degraded").exists()
    assert (scratchpad / "attention_repair_retry_hint.md").exists()
    assert quarantine.exists(), "before/after lineage must survive debt commit"
    assert "selected-skill application parity" in (
        scratchpad / "phase_completion_debt.md"
    ).read_text(encoding="utf-8")

    loaded = Checkpoint.load(scratchpad)
    assert loaded.phase_commits["attention_repair"] == commit


def test_clean_commit_cannot_self_certify_unresolved_failure():
    failure = GateFailure(
        gate_id="recon:methodology_application:0000000000000000",
        gate_class="METHODOLOGY_APPLICATION",
        message="application parity failed",
    )
    with pytest.raises(RuntimeError, match="CLEAN"):
        PhaseCommit(
            phase_name="recon",
            state="CLEAN",
            run_id=str(uuid.uuid4()),
            unresolved_failures=(failure,),
        )


def test_incomplete_attempt_is_durable_but_never_projects_completion(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = _attention_phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = _config(tmp_path)
    failure = _controller_failure(
        phase,
        scratchpad,
        tmp_path,
        "provider output was not committed",
    )

    commit = PhaseCommitController(
        checkpoint, scratchpad, str(tmp_path), config
    ).commit(phase, "INCOMPLETE_WITH_DEBT", failure)

    assert commit.state == "INCOMPLETE_WITH_DEBT"
    assert phase.name not in checkpoint.completed
    assert phase.name in checkpoint.degraded
    assert checkpoint.phase_commits[phase.name] == commit
    assert checkpoint.validate_phase_names({phase.name}) == []
    assert Checkpoint.load(scratchpad).phase_commits[phase.name] == commit


def test_legacy_mark_completed_cannot_override_incomplete_attempt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = _attention_phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = _config(tmp_path)
    failure = _controller_failure(
        phase,
        scratchpad,
        tmp_path,
        "exact output receipt is missing",
    )
    PhaseCommitController(
        checkpoint, scratchpad, str(tmp_path), config
    ).commit(phase, "INCOMPLETE_WITH_DEBT", failure)

    checkpoint.mark_completed(phase.name)

    assert phase.name not in checkpoint.completed
    assert phase.name in checkpoint.degraded
    assert checkpoint.phase_commits[phase.name].state == "INCOMPLETE_WITH_DEBT"


def test_checkpoint_rejects_incomplete_attempt_with_completion_projection(
    tmp_path: Path,
) -> None:
    phase = _attention_phase()
    run_id = str(uuid.uuid4())
    failure = GateFailure(
        gate_id="attention_repair.provider_completion",
        gate_class="EVIDENCE_INTEGRITY",
        message="provider completion is missing",
    )
    commit = PhaseCommit(
        phase_name=phase.name,
        state="INCOMPLETE_WITH_DEBT",
        run_id=run_id,
        unresolved_failures=(failure,),
    )
    checkpoint = Checkpoint(
        completed=[phase.name],
        degraded=[phase.name],
        run_id=run_id,
        phase_commits={phase.name: commit},
    )

    assert (
        f"phase_commits_incomplete_but_completed:{phase.name}"
        in checkpoint.validate_phase_names({phase.name})
    )


def test_semantic_dedup_delivery_debt_is_owned_by_semantic_dedup() -> None:
    source = Path(D.__file__).read_text(encoding="utf-8")
    start = source.index(
        'if phase.name == "sc_semantic_dedup" and config.get("pipeline") == "sc":'
    )
    end = source.index(
        'if phase.name == "attention_repair" and config.get("pipeline") == "sc":',
        start,
    )
    block = source[start:end]
    marker = block.index("REGISTERED_PRODUCER_DELIVERY_DEBT")
    owner_slice = block[marker - 250 : marker + 900]
    assert '"sc_semantic_dedup"' in owner_slice
    assert '"exploration_skeptic"' not in owner_slice


def test_stale_dynamic_report_prune_retires_typed_commit_too(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = str(uuid.uuid4())
    stale_name = "report_body_writer_medium_b"
    live_name = "report_body_writer_medium_a"
    failure = GateFailure(
        gate_id=f"{stale_name}.delivery",
        gate_class="DELIVERED_PROJECTION",
        message="old shard projection is incomplete",
    )
    stale_commit = PhaseCommit(
        phase_name=stale_name,
        state="COMPLETED_WITH_DEBT",
        run_id=run_id,
        unresolved_failures=(failure,),
    )
    checkpoint = Checkpoint(
        completed=[stale_name, live_name],
        degraded=[stale_name],
        run_id=run_id,
        phase_commits={stale_name: stale_commit},
    )
    (scratchpad / f"{stale_name}.degraded").write_text(
        "stale\n", encoding="utf-8"
    )

    removed = _prune_stale_dynamic_report_checkpoint_entries(
        checkpoint,
        scratchpad,
        {live_name},
    )

    assert removed == [stale_name]
    assert checkpoint.completed == [live_name]
    assert checkpoint.degraded == []
    assert checkpoint.phase_commits == {}
    assert not (scratchpad / f"{stale_name}.degraded").exists()


def test_exact_retry_clears_incomplete_attempt_and_projects_completion(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = _attention_phase()
    _write_valid_attention_artifacts(scratchpad)
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = _config(tmp_path)
    _commit_incomplete_phase_attempt(
        phase,
        checkpoint,
        scratchpad,
        config,
        ["provider output was not committed"],
    )
    assert phase.name not in checkpoint.completed
    assert (scratchpad / f"{phase.name}.degraded").is_file()

    assert _arm_incomplete_phase_retry(phase, checkpoint, scratchpad)
    assert not (scratchpad / f"{phase.name}.degraded").exists()
    commit = _commit_phase_from_disk_debt(
        phase,
        checkpoint,
        scratchpad,
        config,
        [phase],
        clean_transients=True,
    )

    assert commit.state == "CLEAN"
    assert commit.unresolved_failures == ()
    assert commit.clearance_events
    assert phase.name in checkpoint.completed
    assert phase.name not in checkpoint.degraded


def test_exact_retry_clears_old_attempt_but_retains_fresh_phase_debt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = _attention_phase()
    _write_valid_attention_artifacts(scratchpad)
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = _config(tmp_path)
    _commit_incomplete_phase_attempt(
        phase,
        checkpoint,
        scratchpad,
        config,
        ["provider output was not committed"],
    )
    assert _arm_incomplete_phase_retry(phase, checkpoint, scratchpad)
    (scratchpad / f"{phase.name}.degraded").write_text(
        "fresh report-delivery projection debt\n", encoding="utf-8"
    )

    commit = _commit_phase_from_disk_debt(
        phase,
        checkpoint,
        scratchpad,
        config,
        [phase],
        clean_transients=True,
    )

    assert commit.state == "COMPLETED_WITH_DEBT"
    assert phase.name in checkpoint.completed
    assert phase.name in checkpoint.degraded
    assert commit.clearance_events
    messages = [failure.message for failure in commit.unresolved_failures]
    assert any("fresh report-delivery" in message for message in messages)
    assert all("provider output was not committed" not in message for message in messages)


def test_checkpoint_rejects_debt_projection_mismatch(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = str(uuid.uuid4())
    failure = GateFailure(
        gate_id="chain:semantic_identity:0000000000000000",
        gate_class="SEMANTIC_IDENTITY",
        message="ID ledger collision",
    )
    commit = PhaseCommit(
        phase_name="chain",
        state="COMPLETED_WITH_DEBT",
        run_id=run_id,
        unresolved_failures=(failure,),
    )
    checkpoint = Checkpoint(
        completed=["chain"],
        degraded=[],
        run_id=run_id,
        phase_commits={"chain": commit},
    )
    assert "phase_commits_debt_not_degraded:chain" in checkpoint.validate_phase_names(
        {"chain"}
    )


def test_shutdown_sync_preserves_completed_debt_sentinel(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "chain.degraded").write_text("identity debt\n", encoding="utf-8")
    checkpoint = Checkpoint(
        completed=["chain"], degraded=["chain"], run_id=str(uuid.uuid4())
    )
    added = _sync_degraded_sentinels_to_checkpoint(scratchpad, checkpoint)
    assert added == []
    assert (scratchpad / "chain.degraded").exists()


def test_phase_debt_is_delivered_as_assurance_limitation(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    run_id = str(uuid.uuid4())
    assembly_source = scratchpad / "report_assembly_fixture_source.md"
    assembly_source.write_text(
        "# exact assembly fixture source\n", encoding="utf-8"
    )
    assembly = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="assembly",
        exact_inputs=(assembly_source.name,),
    )
    assembly_launch = LaunchSpec(
        work_unit_key=assembly.key,
        pipeline=assembly.pipeline,
        mode=assembly.mode,
        ecosystem=assembly.ecosystem,
        backend=assembly.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        assembly,
        assembly_launch,
        run_id=run_id,
    )
    report.write_text("# Audit Report\n\n## Summary\n", encoding="utf-8")
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        assembly,
        assembly_launch,
        run_id=run_id,
        actor="DRIVER",
    )
    failure = GateFailure(
        gate_id="chain:semantic_identity:0000000000000000",
        gate_class="SEMANTIC_IDENTITY",
        message="ID ledger collision for CH-7",
        affected_identities=("CH-7",),
    )
    commit = PhaseCommit(
        phase_name="chain",
        state="COMPLETED_WITH_DEBT",
        run_id=run_id,
        unresolved_failures=(failure,),
    )
    checkpoint = Checkpoint(
        completed=["chain"],
        degraded=["chain"],
        run_id=run_id,
        phase_commits={"chain": commit},
    )
    checkpoint.save(scratchpad)

    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "scratchpad": str(scratchpad),
        "_run_id": run_id,
    }
    assert D._refresh_assurance_projection(checkpoint, scratchpad, config) == []
    first = report.read_bytes()
    assert D._refresh_assurance_projection(checkpoint, scratchpad, config) == []
    assert report.read_bytes() == first
    delivered = report.read_text(encoding="utf-8")
    assert delivered.count("Audit Completeness and Assurance Limitations") == 1
    assert "Appendix E: Unresolved Phase-Completion Debt" not in delivered
    assert "CH-7" in delivered


def test_checkpoint_load_rejects_cross_run_phase_commit(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = str(uuid.uuid4())
    other_run_id = str(uuid.uuid4())
    payload = {
        "completed": ["chain"],
        "degraded": [],
        "rate_limited_at": None,
        "run_id": run_id,
        "phase_commits": {
            "chain": {
                "phase_name": "chain",
                "state": "CLEAN",
                "run_id": other_run_id,
                "work_unit_id": "phase",
                "contract_digest": "",
                "launch_digest": "",
                "artifact_digest": "",
                "unresolved_failures": [],
                "committed_at": "",
            }
        },
    }
    (scratchpad / "_v2_checkpoint.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="run_id does not match"):
        Checkpoint.load(scratchpad)


def test_registered_gate_id_does_not_hash_prose_details(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = _attention_phase()
    config = {
        "project_root": str(tmp_path), "pipeline": "sc", "mode": "thorough",
        "language": "evm", "cli_backend": "claude",
    }
    contract_digest = _resolved_phase_contract_digest(phase, config)
    output_digest = _resolved_phase_artifact_digest(phase, scratchpad, tmp_path)
    first = _gate_failures_from_issues(
        phase,
        ["methodology application parity failed for 3 rows"],
        contract_digest=contract_digest,
        output_digest=output_digest,
        scratchpad=scratchpad,
    )[0]
    second = _gate_failures_from_issues(
        phase,
        ["methodology application parity failed for 97 rows"],
        contract_digest=contract_digest,
        output_digest=output_digest,
        scratchpad=scratchpad,
    )[0]
    assert first.gate_id == second.gate_id
    assert first.gate_id.endswith("methodology_application.consumer_parity")


def test_controller_cannot_overwrite_prior_debt_without_clearance(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_valid_attention_artifacts(scratchpad)
    phase = _attention_phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = {
        "project_root": str(tmp_path), "pipeline": "sc", "mode": "thorough",
        "language": "evm", "cli_backend": "claude",
    }
    contract_digest = _resolved_phase_contract_digest(phase, config)
    output_digest = _resolved_phase_artifact_digest(phase, scratchpad, tmp_path)
    failure = _gate_failures_from_issues(
        phase,
        ["methodology application parity failed for 3 rows"],
        contract_digest=contract_digest,
        output_digest=output_digest,
        scratchpad=scratchpad,
    )
    controller = PhaseCommitController(
        checkpoint, scratchpad, str(tmp_path), config
    )
    controller.commit(phase, "COMPLETED_WITH_DEBT", failure)
    with pytest.raises(RuntimeError, match="explicit same-gate clearance"):
        controller.commit(phase, "CLEAN")
    assert checkpoint.phase_commits[phase.name].state == "COMPLETED_WITH_DEBT"


def test_work_unit_commits_have_independent_canonical_keys(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_valid_attention_artifacts(scratchpad)
    phase = _attention_phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = {
        "project_root": str(tmp_path), "pipeline": "sc", "mode": "thorough",
        "language": "evm", "cli_backend": "claude",
    }
    controller = PhaseCommitController(
        checkpoint, scratchpad, str(tmp_path), config
    )
    controller.commit(phase, "CLEAN", work_unit_id="worker-a")
    controller.commit(phase, "CLEAN", work_unit_id="worker-b")
    assert set(checkpoint.phase_commits) == {
        "attention_repair::worker-a", "attention_repair::worker-b"
    }
    assert checkpoint.completed == [], "children cannot self-complete their parent"
    assert Checkpoint.load(scratchpad).phase_commits.keys() == checkpoint.phase_commits.keys()


def test_clean_child_cannot_erase_sibling_debt_or_complete_parent(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_valid_attention_artifacts(scratchpad)
    phase = _attention_phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = {
        "project_root": str(tmp_path), "pipeline": "sc", "mode": "thorough",
        "language": "evm", "cli_backend": "claude",
    }
    controller = PhaseCommitController(checkpoint, scratchpad, str(tmp_path), config)
    contract_digest = _resolved_phase_contract_digest(phase, config)
    output_digest = _resolved_phase_artifact_digest(phase, scratchpad, tmp_path)
    failure = _gate_failures_from_issues(
        phase,
        ["methodology application parity failed for worker a"],
        contract_digest=contract_digest,
        output_digest=output_digest,
        scratchpad=scratchpad,
    )
    controller.commit(
        phase, "COMPLETED_WITH_DEBT", failure, work_unit_id="worker-a"
    )
    controller.commit(phase, "CLEAN", work_unit_id="worker-b")
    assert checkpoint.degraded == ["attention_repair"]
    assert checkpoint.completed == []
    assert checkpoint.validate_phase_names({phase.name}) == []
    with pytest.raises(RuntimeError, match="child work unit"):
        controller.commit(phase, "CLEAN")


def test_recon_nonempty_output_keeps_binding_manifest_failure_as_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    recommendations = scratchpad / "template_recommendations.md"
    recommendations.write_text(
        "# Recommendations\n\n"
        "## BINDING MANIFEST\n\n"
        "### EVM Skills\n\n"
        "| Skill | Trigger | Required | Rationale |\n"
        "|---|---|---|---|\n"
        "| TOKEN_FLOW_TRACING | flow | NO | not selected |\n\n"
        '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS"]} -->\n'
        + ("nonempty recon context " * 12),
        encoding="utf-8",
    )
    issues = _selected_skill_manifest_issues(scratchpad, "evm")
    assert issues and "ORACLE_ANALYSIS" in issues[0]

    phase = Phase(
        "recon", ["Recon"], ["template_recommendations.md"], 3000,
        min_artifact_bytes=30,
    )
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    # This unit isolates semantic-debt commit behavior. Skill-catalog resume
    # integrity has its own provider/PhaseIO suites and is not the predicate
    # under test here.
    monkeypatch.setattr(D, "_phase_content_gate_issues", lambda *args: [])
    result = _commit_content_with_gate_debt(
        phase, _config(tmp_path), scratchpad, checkpoint,
        ["recon skill manifest: " + "; ".join(issues)],
    )

    assert result is None, "nonempty Markdown is usable input, not a semantic clear"
    commit = checkpoint.phase_commits["recon"]
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert checkpoint.completed == ["recon"]
    assert checkpoint.degraded == ["recon"]
    assert [failure.gate_id for failure in commit.unresolved_failures] == [
        "recon.methodology_selection.binding_manifest"
    ]
    assert commit.unresolved_failures[0].gate_class == "METHODOLOGY_SELECTION"
    assert recommendations.exists()
    assert (scratchpad / "recon.degraded").exists()


@pytest.mark.parametrize("collision_count", [1, 29])
def test_chain_id_collisions_commit_one_stable_identity_debt(
    tmp_path: Path,
    collision_count: int,
    monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    hypotheses = scratchpad / "hypotheses.md"
    hypotheses.write_text(
        "# Hypotheses\n\n" + "\n".join(
            f"### GRP-{index:02d} - Original authorization boundary {index}"
            for index in range(1, collision_count + 1)
        ) + "\n",
        encoding="utf-8",
    )
    assert _validate_id_ledger_collisions(
        scratchpad, "chain", attempt=1
    ) == []

    hypotheses.write_text(
        "# Hypotheses\n\n" + "\n".join(
            f"### GRP-{index:02d} - Replacement accounting mismatch {index}"
            for index in range(1, collision_count + 1)
        ) + "\n",
        encoding="utf-8",
    )
    collisions = _validate_id_ledger_collisions(
        scratchpad, "chain", attempt=2
    )
    assert len(collisions) == collision_count

    phase = Phase(
        "chain", ["Chain"], ["hypotheses.md"], 3000,
        min_artifact_bytes=30,
    )
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    # Isolate the phase-commit identity predicate from the independently
    # tested state-resolution provider/PhaseIO contract.
    monkeypatch.setattr(D, "_phase_content_gate_issues", lambda *args: [])
    result = _commit_content_with_gate_debt(
        phase, _config(tmp_path), scratchpad, checkpoint,
        ["id-ledger collision: " + "; ".join(collisions)],
    )

    assert result is None
    commit = checkpoint.phase_commits["chain"]
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert [failure.gate_id for failure in commit.unresolved_failures] == [
        "chain.semantic_identity.id_ledger"
    ]
    failure = commit.unresolved_failures[0]
    assert failure.gate_class == "SEMANTIC_IDENTITY"
    assert len(failure.affected_identities) == collision_count
    assert checkpoint.completed == ["chain"]
    assert checkpoint.degraded == ["chain"]


def test_chain_iter2_degraded_coverage_is_methodology_application_debt(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "chain_candidate_pairs_iter2.json").write_text(
        json.dumps({
            "schema_version": "plamen.chain_tail.v1",
            "packet": [
                {"a": "INV-001", "b": "INV-002", "signal": "state graph"},
                {"a": "INV-003", "b": "INV-004", "signal": "shared call"},
            ],
            "overflow": [
                {"a": "INV-005", "b": "INV-006", "signal": "tail limit"}
            ],
        }),
        encoding="utf-8",
    )
    (scratchpad / "chain_iteration2.md").write_text(
        "# Chain Iteration 2 Results\n\n"
        "## Tail Pair Dispositions\n\n"
        "| Finding A | Finding B | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        "| INV-001 | INV-002 | REJECTED | compared state edges |\n",
        encoding="utf-8",
    )
    assert _validate_chain_iter2(scratchpad, "thorough") == []
    receipt = json.loads(
        (scratchpad / "chain_tail_coverage_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["status"] == "DEGRADED_COVERAGE_GAPS"
    sentinel = scratchpad / "chain_iter2.degraded"
    assert sentinel.exists()

    phase = Phase(
        "chain_iter2", ["Chain Iteration 2"], ["chain_iteration2.md"],
        3000, min_artifact_bytes=30,
    )
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    result = _commit_content_with_gate_debt(
        phase, _config(tmp_path), scratchpad, checkpoint,
        [sentinel.read_text(encoding="utf-8")],
    )

    assert result is None
    commit = checkpoint.phase_commits["chain_iter2"]
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert checkpoint.degraded == ["chain_iter2"]
    assert sentinel.exists(), "generic completion must not erase soft coverage debt"
    assert [failure.gate_id for failure in commit.unresolved_failures] == [
        "chain_iter2.methodology_application.tail_pair_disposition"
    ]
    assert commit.unresolved_failures[0].gate_class == "METHODOLOGY_APPLICATION"


def test_projection_write_crash_preserves_authoritative_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_valid_attention_artifacts(scratchpad)
    phase = _attention_phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    failure = _controller_failure(
        phase, scratchpad, tmp_path,
        "methodology application parity failed for one consumer",
    )

    def projection_crash(*_args, **_kwargs):
        raise OSError("synthetic projection write crash")

    monkeypatch.setattr(D, "_write_phase_commit_debt_projection", projection_crash)
    PhaseCommitController(
        checkpoint, scratchpad, str(tmp_path), _config(tmp_path)
    ).commit(phase, "COMPLETED_WITH_DEBT", failure)

    loaded = Checkpoint.load(scratchpad)
    assert loaded.phase_commits["attention_repair"].state == "COMPLETED_WITH_DEBT"
    assert loaded.degraded == ["attention_repair"]
    assert not (scratchpad / "phase_completion_debt.md").exists()


def test_explicit_same_gate_clearance_commits_clean(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_valid_attention_artifacts(scratchpad)
    phase = _attention_phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    controller = PhaseCommitController(
        checkpoint, scratchpad, str(tmp_path), _config(tmp_path)
    )
    failure = _controller_failure(
        phase, scratchpad, tmp_path,
        "methodology application parity failed for one consumer",
    )
    controller.commit(phase, "COMPLETED_WITH_DEBT", failure)
    gate_id = failure[0].gate_id
    clearance = GateClearance(
        gate_id=gate_id,
        clearing_gate_id=gate_id,
        evidence_digest=_resolved_phase_artifact_digest(
            phase, scratchpad, tmp_path
        ),
        authority="same registered validator re-evaluation",
    )

    clean = controller.commit(
        phase, "CLEAN", clearance_events=(clearance,)
    )

    assert clean.state == "CLEAN"
    assert clean.unresolved_failures == ()
    assert clean.clearance_events == (clearance,)
    assert checkpoint.completed == ["attention_repair"]
    assert checkpoint.degraded == []
    assert not (scratchpad / "attention_repair.degraded").exists()


def test_cross_gate_clearance_is_rejected_and_debt_survives(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_valid_attention_artifacts(scratchpad)
    phase = _attention_phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    controller = PhaseCommitController(
        checkpoint, scratchpad, str(tmp_path), _config(tmp_path)
    )
    failure = _controller_failure(
        phase, scratchpad, tmp_path,
        "methodology application parity failed for one consumer",
    )
    debt = controller.commit(phase, "COMPLETED_WITH_DEBT", failure)
    invalid_clearance = GateClearance(
        gate_id=failure[0].gate_id,
        clearing_gate_id="attention_repair.artifact_presence.required_output",
        evidence_digest=debt.artifact_digest,
        authority="weaker presence-only validator",
    )

    with pytest.raises(RuntimeError, match="only same-gate clearance"):
        controller.commit(
            phase, "CLEAN", clearance_events=(invalid_clearance,)
        )

    assert checkpoint.phase_commits["attention_repair"] == debt
    assert checkpoint.degraded == ["attention_repair"]
