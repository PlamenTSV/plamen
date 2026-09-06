"""P0-AE: typed, exact phase I/O contracts independent of the driver.

These fixtures encode the reproduced live contradictions before the substrate
is wired into ``plamen_driver.py``.  They intentionally exercise exact work
units rather than broad parent-phase globs.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from phase_io_contracts import (
    ArtifactSpec,
    ConditionalOutputReceipt,
    DriverMergeEvent,
    LaunchSpec,
    PhaseIOContract,
    WriteObservation,
    canonical_artifact_identity,
    canonical_work_unit_key,
    recon_direct_retry_output_paths,
    resolve_phase_io_contract,
)


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}


def _resolve(phase: str, work_unit_id: str, **kwargs) -> PhaseIOContract:
    params = {**BASE, **kwargs}
    return resolve_phase_io_contract(
        phase=phase,
        work_unit_id=work_unit_id,
        **params,
    )


def _ids(contract: PhaseIOContract) -> set[str]:
    return {artifact.identity for artifact in contract.outputs}


def test_exact_artifact_identity_is_posix_relative_and_collision_safe():
    assert (
        canonical_artifact_identity("scratchpad", "body_manifests/report_high.json")
        == "scratchpad:body_manifests/report_high.json"
    )
    assert canonical_artifact_identity("scratchpad", "a/result.md") != (
        canonical_artifact_identity("scratchpad", "b/result.md")
    )
    for invalid in (
        "C:/tmp/output.md",
        "/tmp/output.md",
        "../output.md",
        "nested/../../output.md",
        r"body_manifests\report_high.json",
        "report_*.md",
        "./output.md",
        "",
    ):
        with pytest.raises(ValueError):
            canonical_artifact_identity("scratchpad", invalid)


def test_work_unit_key_is_canonical_and_component_bound():
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "depth", "worker.validation_sweep"
    )
    assert key == "sc/thorough/evm/claude/depth/worker.validation_sweep"
    with pytest.raises(ValueError):
        canonical_work_unit_key(
            "sc", "thorough", "evm", "claude", "depth", "../worker"
        )


def test_records_are_immutable_and_digests_are_order_stable():
    key = canonical_work_unit_key(
        "sc", "core", "evm", "claude", "phase", "unit"
    )
    left = ArtifactSpec(
        root="scratchpad",
        path="a.md",
        owner_key=key,
        artifact_class="REQUIRED",
        writer="MODEL",
        write_mode="REPLACE",
        consumers=("z/unit", "a/unit"),
    )
    right = ArtifactSpec(
        root="scratchpad",
        path="b.md",
        owner_key=key,
        artifact_class="OPTIONAL",
        writer="DRIVER",
        write_mode="CREATE",
    )
    one = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="phase",
        work_unit_id="unit",
        outputs=(left, right),
        immutable_inputs=("scratchpad:input.md",),
    )
    two = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="phase",
        work_unit_id="unit",
        outputs=(right, left),
        immutable_inputs=("scratchpad:input.md",),
    )
    assert one.digest == two.digest
    with pytest.raises(FrozenInstanceError):
        one.phase = "changed"  # type: ignore[misc]


def test_artifact_spec_rejects_globs_bad_modes_and_unbound_conditions():
    key = canonical_work_unit_key("sc", "core", "evm", "claude", "x", "y")
    with pytest.raises(ValueError):
        ArtifactSpec(
            root="scratchpad", path="out_*.md", owner_key=key,
            artifact_class="REQUIRED", writer="MODEL", write_mode="REPLACE",
        )
    with pytest.raises(ValueError):
        ArtifactSpec(
            root="scratchpad", path="out.md", owner_key=key,
            artifact_class="REQUIRED", writer="MODEL", write_mode="UPSERT",
        )
    with pytest.raises(ValueError):
        ArtifactSpec(
            root="scratchpad", path="out.md", owner_key=key,
            artifact_class="CONDITIONAL", writer="MODEL", write_mode="REPLACE",
        )


def test_chain_agent2_contract_rejects_prior_output_update():
    contract = _resolve("chain_agent2", "model")
    assert _ids(contract) == {
        "scratchpad:chain_hypotheses.md",
        "scratchpad:composition_coverage.md",
        "scratchpad:synthesis_full.md",
    }
    assert "scratchpad:hypotheses.md" in contract.immutable_inputs
    result = contract.validate_writes(
        (
            WriteObservation.changed("scratchpad", "chain_hypotheses.md"),
            WriteObservation.changed("scratchpad", "hypotheses.md"),
        ),
        actor="MODEL",
    )
    assert not result.ok
    assert any(
        item.code == "IMMUTABLE_INPUT_WRITE"
        and item.identity == "scratchpad:hypotheses.md"
        for item in result.violations
    )


def test_chain_iter2_is_delta_only_and_generated_driver_merge_is_separate():
    model = _resolve("chain_iter2", "model")
    assert _ids(model) == {"scratchpad:chain_iteration2.md"}
    assert {
        "scratchpad:chain_hypotheses.md",
        "scratchpad:composition_coverage.md",
    } <= set(model.immutable_inputs)

    with pytest.raises(
        ValueError,
        match="CHAIN_TAIL_LEGACY_FIXED_GENERATION",
    ):
        _resolve("chain_iter2", "driver_merge")

    merge = _resolve("chain_iter2", "driver_merge.p0001.s0002")
    assert merge.key.endswith(
        "/chain_iter2/driver_merge.p0001.s0002"
    )
    assert _ids(merge) == {
        "scratchpad:chain_hypotheses.md",
        "scratchpad:composition_coverage.md",
    }
    assert merge.immutable_inputs == (
        "scratchpad:chain_iteration2.md",
    )
    assert merge.model_invoked is False
    assert all(item.writer == "DRIVER" for item in merge.outputs)
    assert all(item.write_mode == "MERGE" for item in merge.outputs)
    assert all(
        item.minimum_gate == "IDENTITY_PARITY"
        for item in merge.outputs
    )


def test_recon_contracts_assign_prepass_worker_research_and_merge_exactly():
    prepass = _resolve("recon", "prepass")
    assert _ids(prepass) == {
        "scratchpad:contract_inventory.md",
        "scratchpad:state_variables.md",
        "scratchpad:function_list.md",
        "scratchpad:build_status.md",
        "scratchpad:design_context.md",
        "scratchpad:attack_surface.md",
        "scratchpad:detected_patterns.md",
        "scratchpad:setter_list.md",
        "scratchpad:emit_list.md",
        "scratchpad:template_recommendations.md",
        "scratchpad:recon_summary.md",
        "scratchpad:meta_buffer.md",
        "scratchpad:external_dependency_research.md",
        "scratchpad:recon_prepass_publication_receipt.json",
    }
    assert all(item.writer == "DRIVER" for item in prepass.outputs)
    assert prepass.model_invoked is False
    with pytest.raises(ValueError, match="fixed by pipeline authority"):
        _resolve(
            "recon",
            "prepass",
            exact_outputs=("meta_buffer.md",),
        )

    l1_prepass = _resolve("recon", "prepass", pipeline="l1")
    assert _ids(l1_prepass) == {
        "scratchpad:subsystem_map.md",
        "scratchpad:trust_boundaries.md",
        "scratchpad:attack_surface.md",
        "scratchpad:threat_model.md",
        "scratchpad:template_recommendations.md",
        "scratchpad:recon_summary.md",
        "scratchpad:meta_buffer.md",
        "scratchpad:external_dependency_research.md",
        "scratchpad:recon_prepass_publication_receipt.json",
    }

    worker = _resolve(
        "recon", "worker.recon_design_context",
        exact_outputs=("recon_design_context.md",),
    )
    assert _ids(worker) == {"scratchpad:recon_design_context.md"}
    assert worker.outputs[0].writer == "MODEL"

    research = _resolve("recon", "dependency_research")
    research_spec = research.output("scratchpad:recon_external_dependency_research.md")
    assert research_spec.artifact_class == "CONDITIONAL"
    assert research_spec.condition_id == "external_dependency_obligations_present"

    matrix = (
        ("sc", "light", 2, 12),
        ("sc", "core", 4, 12),
        ("sc", "thorough", 4, 12),
        ("l1", "light", 3, 8),
        ("l1", "core", 5, 8),
        ("l1", "thorough", 5, 8),
    )
    for pipeline, mode, input_count, output_count in matrix:
        merge = _resolve(
            "recon", "canonical_merge", pipeline=pipeline, mode=mode
        )
        assert len(merge.immutable_inputs) == input_count
        assert len(merge.outputs) == output_count
        receipt = merge.output(
            "scratchpad:recon_signal_transform_receipt.json"
        )
        assert receipt.writer == "DRIVER"
        assert receipt.minimum_gate == "RECON_SIGNAL_TRANSFORM_RECEIPT"
        if pipeline == "sc":
            assert "scratchpad:recon_summary.md" in _ids(merge)
            assert "scratchpad:build_status.md" in _ids(merge)


def test_recon_direct_retry_is_exact_model_owned_for_sc_and_l1():
    sc_outputs = (
        "recon_summary.md",
        "design_context.md",
        "attack_surface.md",
        "state_variables.md",
        "function_list.md",
        "contract_inventory.md",
        "template_recommendations.md",
        "detected_patterns.md",
        "setter_list.md",
        "emit_list.md",
        "build_status.md",
    )
    l1_outputs = (
        "recon_summary.md",
        "threat_model.md",
        "subsystem_map.md",
        "attack_surface.md",
        "trust_boundaries.md",
        "template_recommendations.md",
        "scope_leftover.md",
    )
    for pipeline, attempt, ordinal, canonical in (
        ("sc", "direct_retry.attempt-0002", 2, sc_outputs),
        ("l1", "direct_retry.attempt-0003", 3, l1_outputs),
    ):
        expected = recon_direct_retry_output_paths(pipeline, ordinal)
        contract = _resolve(
            "recon",
            attempt,
            pipeline=pipeline,
            exact_inputs=("recon_retry_plan.json",),
            exact_outputs=expected,
        )
        assert contract.key.endswith(f"/recon/{attempt}")
        assert contract.model_invoked is True
        assert contract.immutable_inputs == (
            "scratchpad:recon_retry_plan.json",
        )
        assert contract.bounded_lookup_inputs == ()
        assert _ids(contract) == {f"scratchpad:{name}" for name in expected}
        assert not {
            f"scratchpad:{name}" for name in canonical
        } & _ids(contract)
        assert all(item.writer == "MODEL" for item in contract.outputs)
        assert all(item.write_mode == "REPLACE" for item in contract.outputs)
        assert (
            "scratchpad:recon_signal_transform_receipt.json"
            not in _ids(contract)
        )


def test_recon_direct_retry_rejects_denominator_and_attempt_drift():
    sc_outputs = (
        "recon_summary.md",
        "design_context.md",
        "attack_surface.md",
        "state_variables.md",
        "function_list.md",
        "contract_inventory.md",
        "template_recommendations.md",
        "detected_patterns.md",
        "setter_list.md",
        "emit_list.md",
        "build_status.md",
    )
    private_outputs = recon_direct_retry_output_paths("sc", 2)
    base = {
        "exact_inputs": ("recon_retry_plan.json",),
        "exact_outputs": private_outputs,
    }
    for invalid_inputs in (
        (),
        ("retry_plan.json",),
        ("recon_retry_plan.json", "foreign.md"),
    ):
        with pytest.raises(ValueError):
            _resolve(
                "recon",
                "direct_retry.attempt-0002",
                exact_inputs=invalid_inputs,
                exact_outputs=private_outputs,
            )
    for invalid_outputs in (
        (),
        private_outputs[:-1],
        (*private_outputs, "foreign.md"),
        (*private_outputs, "recon_signal_transform_receipt.json"),
    ):
        with pytest.raises(ValueError):
            _resolve(
                "recon",
                "direct_retry.attempt-0002",
                exact_inputs=("recon_retry_plan.json",),
                exact_outputs=invalid_outputs,
            )
    for invalid_attempt in (
        "direct_retry",
        "direct_retry.attempt-2",
        "direct_retry.attempt-0001",
        "direct_retry.attempt-0004",
        "direct_retry.attempt-00002",
        "direct_retry.attempt-000x",
    ):
        with pytest.raises(ValueError, match="no P0-AE resolver shape"):
            _resolve("recon", invalid_attempt, **base)


def test_rescan_prepare_and_manifest_workers_are_separate_exact_units():
    prepare = _resolve("rescan_prepare", "python")
    assert _ids(prepare) == {"scratchpad:rescan_manifest.md"}
    assert prepare.model_invoked is False

    worker = _resolve(
        "rescan", "worker.analysis_rescan_1",
        exact_outputs=("analysis_rescan_1.md",),
    )
    assert _ids(worker) == {"scratchpad:analysis_rescan_1.md"}
    assert worker.model_invoked is True


def test_depth_dynamic_job_outputs_are_owned_by_exact_work_units():
    validation = _resolve(
        "depth", "worker.validation_sweep",
        exact_outputs=("validation_sweep_findings.md",),
    )
    semantic = _resolve(
        "depth", "worker.semantic_gap",
        exact_outputs=("niche_semantic_gap_findings.md",),
        conditional_output_ids=("niche_semantic_gap_findings.md",),
        condition_id="semantic_gap_required",
    )
    assert _ids(validation) == {"scratchpad:validation_sweep_findings.md"}
    assert semantic.outputs[0].artifact_class == "CONDITIONAL"
    assert semantic.outputs[0].condition_id == "semantic_gap_required"
    assert validation.key != semantic.key


def test_depth_worker_inputs_do_not_require_mode_skipped_invariant_artifact():
    """Light skips the invariant phase, so its workers cannot bind that file."""

    light = _resolve(
        "depth",
        "worker.token_flow",
        mode="light",
        exact_outputs=("depth_token_flow_findings.md",),
    )
    core = _resolve(
        "depth",
        "worker.token_flow",
        mode="core",
        exact_outputs=("depth_token_flow_findings.md",),
    )

    assert "scratchpad:semantic_invariants.md" not in light.immutable_inputs
    assert "scratchpad:semantic_invariants.md" in core.immutable_inputs
    for required in (
        "scratchpad:findings_inventory.md",
        "scratchpad:security_feature_facts.json",
        "scratchpad:security_obligation_authority.json",
        "scratchpad:security_obligations.md",
    ):
        assert required in light.immutable_inputs


@pytest.mark.parametrize(
    ("source_phase", "repair_output"),
    (
        ("breadth", "analysis_methodology_repair_breadth.md"),
        ("rescan", "analysis_methodology_repair_rescan.md"),
        ("depth", "depth_methodology_repair_findings.md"),
    ),
)
def test_methodology_repair_contract_does_not_depend_on_parent_glob_width(
    source_phase: str, repair_output: str,
):
    contract = _resolve(
        source_phase,
        "methodology_repair",
        source_phase=source_phase,
    )
    assert f"scratchpad:{repair_output}" in _ids(contract)
    assert f"scratchpad:skill_application_receipt_{source_phase}_repair.json" in _ids(contract)
    assert f"scratchpad:methodology_skeptic_queue_{source_phase}_repair.json" in _ids(contract)
    assert f"scratchpad:report_semantic_methodology_application_{source_phase}.md" in _ids(contract)
    assert (
        f"scratchpad:methodology_repair_queue_{source_phase}.json"
        in contract.immutable_inputs
    )
    assert (
        f"scratchpad:skill_application_receipt_{source_phase}.json"
        in contract.immutable_inputs
    )
    assert contract.output(f"scratchpad:{repair_output}").writer == "MODEL"
    assert contract.output("scratchpad:skill_dispatch.json").write_mode == "MERGE"


def test_report_index_prework_model_and_routing_form_three_transactions():
    prework = _resolve("report_index", "prework")
    assert {
        "scratchpad:severity_binding.md",
        "scratchpad:status_binding.md",
        "scratchpad:report_index_coverage_seed.md",
        "scratchpad:candidate_semantic_facets.md",
        "scratchpad:candidate_semantic_facets.json",
        "scratchpad:external_research_gaps.md",
    } <= _ids(prework)
    assert prework.model_invoked is False

    model = _resolve("report_index", "model")
    assert _ids(model) == {
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
    }
    assert "scratchpad:severity_binding.md" in model.immutable_inputs

    routing = _resolve(
        "report_index", "routing",
        exact_outputs=(
            "report_records.json",
            "body_manifests/report_critical_high.json",
            "body_manifests/report_medium.json",
        ),
    )
    assert _ids(routing) == {
        "scratchpad:report_records.json",
        "scratchpad:body_manifests/report_critical_high.json",
        "scratchpad:body_manifests/report_medium.json",
    }
    assert routing.model_invoked is False


def test_severity_adjudication_shadow_has_distinct_plan_worker_bind_transactions():
    planning = _resolve(
        "severity_adjudication_shadow",
        "planning",
        exact_outputs=(
            "severity_adjudication_work_manifest.json",
            "severity_adjudication_work_plan.json",
            "severity_adjudication_context.0001.json",
            "severity_adjudication_prompt.0001.md",
            "severity_adjudication_launch_intent.0001.json",
            "severity_adjudication_tool_policy.0001.json",
        ),
        exact_inputs=("rules/severity.md",),
    )
    assert planning.model_invoked is False
    assert all(output.writer == "DRIVER" for output in planning.outputs)
    assert "scratchpad:severity_decision_ledger.shadow.json" in planning.immutable_inputs

    worker = _resolve(
        "severity_adjudication_shadow",
        "worker.0001",
        exact_outputs=(
            "verify_H-1.severity_adjudication_proposal.json",
        ),
        exact_inputs=(
            "severity_adjudication_context.0001.json",
            "severity_adjudication_prompt.0001.md",
            "severity_adjudication_launch_intent.0001.json",
            "severity_adjudication_tool_policy.0001.json",
        ),
    )
    assert worker.model_invoked is True
    assert worker.outputs[0].writer == "MODEL"
    assert "scratchpad:severity_adjudication_work_plan.json" in worker.immutable_inputs

    bind = _resolve(
        "severity_adjudication_shadow",
        "bind",
        exact_outputs=(
            "verify_H-1.severity_decision.json",
            "verify_H-1.severity_adjudication_receipt.json",
            "severity_decision_ledger.shadow.json",
            "severity_adjudication_work_reconciliation.json",
        ),
        exact_inputs=(
            "verify_H-1.severity_adjudication_proposal.json",
            "severity_adjudication_launch_intent.0001.json",
        ),
    )
    assert bind.model_invoked is False
    assert all(output.writer == "DRIVER" for output in bind.outputs)


def test_severity_shadow_report_projection_is_driver_owned_and_read_only():
    projection = _resolve(
        "severity_adjudication_shadow", "report_projection"
    )
    assert _ids(projection) == {
        "scratchpad:severity_report_shadow_receipt.json"
    }
    assert projection.outputs[0].writer == "DRIVER"
    assert projection.model_invoked is False
    assert "scratchpad:report_index.md" in projection.immutable_inputs


def test_unknown_current_phase_write_is_blocking_even_if_not_future_owned():
    contract = _resolve(
        "depth",
        "worker.crossbatch_fixture",
        exact_outputs=("cross_batch_consistency.md",),
    )
    result = contract.validate_writes(
        (
            WriteObservation.changed("scratchpad", "cross_batch_consistency.md"),
            WriteObservation.created("scratchpad", "ledger_rows.txt"),
        ),
        actor="MODEL",
    )
    assert not result.ok
    assert any(
        item.code == "UNKNOWN_WRITE"
        and item.identity == "scratchpad:ledger_rows.txt"
        for item in result.violations
    )


def test_unknown_work_unit_cannot_acquire_model_or_driver_authority_from_outputs():
    for requested_writer in (None, "MODEL", "DRIVER"):
        kwargs = {}
        if requested_writer is not None:
            kwargs["exact_writer"] = requested_writer
        with pytest.raises(ValueError, match="register the work unit"):
            _resolve(
                "unregistered_phase",
                "unregistered_work",
                exact_outputs=("plausible_output.md",),
                **kwargs,
            )


def test_caller_cannot_override_registered_writer_authority():
    with pytest.raises(ValueError, match="caller requested DRIVER"):
        _resolve(
            "depth",
            "worker.writer_override",
            exact_outputs=("depth_writer_override_findings.md",),
            exact_writer="DRIVER",
        )


def test_write_modes_and_writer_authority_are_validated():
    key = canonical_work_unit_key("sc", "core", "evm", "claude", "x", "y")
    contract = PhaseIOContract(
        pipeline="sc", mode="core", ecosystem="evm", backend="claude",
        phase="x", work_unit_id="y",
        outputs=(
            ArtifactSpec(
                root="scratchpad", path="new.md", owner_key=key,
                artifact_class="REQUIRED", writer="MODEL", write_mode="CREATE",
            ),
            ArtifactSpec(
                root="scratchpad", path="projection.md", owner_key=key,
                artifact_class="DRIVER_GENERATED", writer="DRIVER", write_mode="MERGE",
            ),
        ),
    )
    result = contract.validate_writes(
        (
            WriteObservation.changed("scratchpad", "new.md"),
            WriteObservation.changed("scratchpad", "projection.md"),
        ),
        actor="MODEL",
    )
    assert {item.code for item in result.violations} == {
        "CREATE_OVER_EXISTING",
        "WRITER_MISMATCH",
    }


def test_conditional_output_receipt_distinguishes_all_terminal_states():
    contract = _resolve("recon", "dependency_research")
    identity = "scratchpad:recon_external_dependency_research.md"
    common = {
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "artifact_identity": identity,
        "condition_id": "external_dependency_obligations_present",
    }
    not_triggered = ConditionalOutputReceipt(
        **common, state="NOT_TRIGGERED", expected_denominator=0,
    )
    triggered_empty = ConditionalOutputReceipt(
        **common, state="TRIGGERED_EMPTY", expected_denominator=0,
    )
    produced = ConditionalOutputReceipt(
        **common, state="PRODUCED", expected_denominator=2,
        produced_identities=("DEP-1", "DEP-2"),
    )
    failed = ConditionalOutputReceipt(
        **common, state="FAILED", expected_denominator=2,
        failure_ids=("dependency-fetch-timeout",),
    )
    assert len({item.digest for item in (not_triggered, triggered_empty, produced, failed)}) == 4
    produced.validate_against(contract)
    assert produced.to_dict()["contract_digest"] == contract.digest
    with pytest.raises(ValueError):
        ConditionalOutputReceipt(
            **common, state="PRODUCED", expected_denominator=1,
        )
    with pytest.raises(ValueError):
        ConditionalOutputReceipt(
            **common, state="NOT_TRIGGERED", expected_denominator=1,
        )
    mismatched = ConditionalOutputReceipt(
        **{**common, "condition_id": "wrong_condition"},
        state="NOT_TRIGGERED", expected_denominator=0,
    )
    with pytest.raises(ValueError):
        mismatched.validate_against(contract)


def test_generated_driver_merge_event_is_digest_bound_and_recall_monotonic():
    contract = _resolve(
        "chain_iter2", "driver_merge.p0001.s0002"
    )
    common = {
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "artifact_identity": "scratchpad:chain_hypotheses.md",
        "before_sha256": "a" * 64,
        "after_sha256": "b" * 64,
        "source_identities": ("scratchpad:chain_iteration2.md",),
    }
    event = DriverMergeEvent(
        **common,
        identities_before=("CH-1",),
        identities_after=("CH-1", "CH-2"),
    )
    assert event.added_identities == ("CH-2",)
    assert event.removed_identities == ()
    assert len(event.digest) == 64
    event.validate_against(contract)
    assert event.to_dict()["artifact_identity"] == "scratchpad:chain_hypotheses.md"

    other_generation = _resolve(
        "chain_iter2", "driver_merge.p0001.s0003"
    )
    with pytest.raises(
        ValueError,
        match="driver merge event work-unit key mismatch",
    ):
        event.validate_against(other_generation)

    with pytest.raises(
        ValueError,
        match="driver merge sources are absent from contract inputs",
    ):
        DriverMergeEvent(
            **{
                **common,
                "source_identities": (
                    "scratchpad:_chain_tail_shards/shard_0001/"
                    "chain_iteration2.md",
                ),
            },
            identities_before=("CH-1",),
            identities_after=("CH-1", "CH-2"),
        ).validate_against(contract)

    with pytest.raises(ValueError):
        DriverMergeEvent(
            **common,
            identities_before=("CH-1", "CH-2"),
            identities_after=("CH-2",),
        )


def test_report_routing_outputs_are_typed_as_driver_generated():
    routing = _resolve(
        "report_index", "routing",
        exact_outputs=(
            "report_records.json",
            "body_manifests/report_low_info.json",
        ),
    )
    assert all(item.artifact_class == "DRIVER_GENERATED" for item in routing.outputs)
    assert routing.to_dict()["key"] == routing.key


def test_launch_spec_binds_runtime_policy_and_is_deterministic():
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "chain_agent2", "model"
    )
    first = LaunchSpec(
        work_unit_key=key,
        pipeline="sc", mode="thorough", ecosystem="evm", backend="claude",
        model="claude-opus-4-8", timeout_s=3600, exec_mode="pty",
        tool_policy=("deny:Task", "deny:Agent", "allow:Read"),
    )
    second = LaunchSpec(
        work_unit_key=key,
        pipeline="sc", mode="thorough", ecosystem="evm", backend="claude",
        model="claude-opus-4-8", timeout_s=3600, exec_mode="pty",
        tool_policy=("allow:Read", "deny:Agent", "deny:Task"),
    )
    assert first.digest == second.digest
    assert first.model == "claude-opus-4-8"


def test_verification_runtime_debt_is_explicit_driver_retention_authority():
    contract = _resolve(
        "verify",
        "runtime_debt",
        exact_inputs=(
            "verification_queue.md",
            "verification_queue.work_plan.json",
        ),
        exact_outputs=(
            "verification_runtime_debt.json",
            "verification_runtime_debt.md",
        ),
    )
    assert contract.model_invoked is False
    assert {row.writer for row in contract.outputs} == {"DRIVER"}
    assert _ids(contract) == {
        "scratchpad:verification_runtime_debt.json",
        "scratchpad:verification_runtime_debt.md",
    }
    with pytest.raises(ValueError, match="registered exact output denominator"):
        _resolve(
            "verify",
            "runtime_debt",
            exact_inputs=("verification_queue.md",),
            exact_outputs=("verification_runtime_debt.json",),
        )


def test_runtime_debt_report_fallback_cannot_masquerade_as_model_output():
    contract = _resolve(
        "report_body",
        "report_medium.runtime_debt_fallback",
        exact_inputs=(
            "report_evidence_records.json",
            "report_evidence_manifests/report_medium.json",
        ),
        exact_outputs=("report_medium.md",),
    )
    assert contract.model_invoked is False
    assert contract.outputs[0].writer == "DRIVER"
    assert (
        contract.outputs[0].minimum_gate
        == "EXACT_RUNTIME_DEBT_RETENTION_AND_REPORT_BLOCKED_PARITY"
    )
    with pytest.raises(ValueError, match="typed bundle"):
        _resolve(
            "report_body",
            "report_medium.runtime_debt_fallback",
            exact_inputs=(
                "report_evidence_manifests/report_medium.json",
            ),
            exact_outputs=("report_medium.md",),
        )
