"""Authentic Core zero-active report-index through deterministic assembly.

This extends the supported queue/R10 fixture without inventing report bodies,
patching validators, or fabricating PhaseIO authority.
"""
from __future__ import annotations

import pytest

import plamen_driver as D
from artifact_ledger import read_artifact_ledger, validate_work_unit_artifacts
from report_empty_tier import run_empty_report_tier
from test_core_empty_report_entry_integration import (
    _run_report_child,
    core_report_prework,
)
from verify_queue_transaction import validate_live_verify_queue_publication


pytestmark = pytest.mark.integration


def _phase(case, name):
    return next(item for item in case.phases if item.name == name)


def _commit_empty_tiers(case) -> dict[str, bytes]:
    """Run the production empty-body and confirmation sequence."""

    outputs: dict[str, bytes] = {}
    for tier in ("critical_high", "medium", "low_info"):
        body_phase = _phase(case, f"report_body_writer_{tier}")
        _manifests, routing_issues = D._run_report_index_routing_transaction(
            case.root, case.config
        )
        assert routing_issues == []
        assert D._ensure_report_evidence_before_body_writer(
            body_phase, case.config, case.root
        ) == []
        assert run_empty_report_tier(
            scratchpad=case.root,
            project_root=case.project,
            config=case.config,
            phase_name=body_phase.name,
        ) is True
        D._commit_phase_from_disk_debt(
            body_phase,
            case.checkpoint,
            case.root,
            case.config,
            case.phases,
            clean_transients=True,
        )

        output = case.root / f"report_{tier}.md"
        raw = output.read_bytes()
        assert b"PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER" in raw
        outputs[tier] = raw

    for tier in ("critical_high", "medium", "low_info"):
        output = case.root / f"report_{tier}.md"
        raw = outputs[tier]
        confirmation = _phase(case, f"report_{tier}")
        assert D._validate_tier_body_against_manifest(
            case.root, confirmation.name,
            project_root=case.project, config=case.config,
        ) == []
        D._commit_accepted_phase_from_disk(
            confirmation,
            case.checkpoint,
            case.root,
            case.config,
            case.phases,
        )

        merge = _phase(case, f"report_{tier}_merge")
        D.merge_report_tier_shards(case.root, tier)
        D._commit_accepted_phase_from_disk(
            merge,
            case.checkpoint,
            case.root,
            case.config,
            case.phases,
        )
        assert output.read_bytes() == raw

    return outputs


def test_core_policy_empty_reaches_authoritative_report_assembly(
    core_report_prework, monkeypatch, request
):
    case = core_report_prework
    queue_before = {
        name: (
            (case.root / name).read_bytes()
            if (case.root / name).is_file()
            else None
        )
        for name in case.plan["public_output_denominator"]
    }

    report_index, model_contract, _model_launch = _run_report_child(
        case, monkeypatch, request
    )

    def no_worker_relaunch(*_args, **_kwargs):
        pytest.fail("zero-active report tail must not relaunch a worker")

    monkeypatch.setattr(D, "_run_one_codex_exec", no_worker_relaunch)
    assert D._run_report_index_canonicalization_transaction(
        report_index, case.root, case.config
    ) == []
    D._commit_phase_from_disk_debt(
        report_index,
        case.checkpoint,
        case.root,
        case.config,
        case.phases,
        clean_transients=True,
    )

    tier_bytes = _commit_empty_tiers(case)
    ledger = read_artifact_ledger(case.root)
    assert ledger["work_units"][model_contract.key]["execution_authority"]
    assert not [
        key
        for key in ledger["work_units"]
        if "/report_body_writer_" in key
    ]

    assert D._refresh_severity_report_shadow_projection(
        case.checkpoint,
        case.root,
        case.config,
        stage="PRE_ASSEMBLE",
    ) == []
    D._write_final_subsystem_coverage_summary(
        case.root,
        scope_file=case.config.get("scope_file"),
        scope_match_mode=case.config.get("scope_match_mode", "legacy"),
        pipeline=case.config.get("pipeline", "sc"),
        language=case.config.get("language", ""),
        run_id=case.run_id,
        source_snapshot_digest=D._security_obligation_source_snapshot_digest(
            case.config
        ),
    )

    contract, launch, execute, issues = D._arm_report_assembly_phase_io(
        scratchpad=case.root,
        config=case.config,
    )
    assert issues == []
    assert contract is not None and launch is not None
    assert execute is True

    assert D._assemble_report_python(case.root, str(case.project)) is True
    report_path = case.project / "AUDIT_REPORT.md"
    assert D._project_exact_scope_coverage_limitations(
        case.root, report_path
    ) == []
    _changed, evidence_issues = D._project_report_evidence_file(
        case.root, report_path
    )
    assert evidence_issues == []

    stub_issue = "AUDIT_REPORT.md is a stub (0 finding sections)"
    # A real empty report still needs explicit same-run replay authority.
    assert stub_issue in D._run_report_quality_gate(case.root, str(case.project))
    assert stub_issue in D._run_report_quality_gate(
        case.root, str(case.project),
        config={**case.config, "_run_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
    )
    for tier, original in tier_bytes.items():
        tier_path = case.root / f"report_{tier}.md"
        try:
            tier_path.write_bytes(original + b"\nchanged after commit\n")
            assert stub_issue in D._run_report_quality_gate(
                case.root, str(case.project), config=case.config,
            )
        finally:
            tier_path.write_bytes(original)

    # Authentic emptiness exempts only the stub check, not other quality rules.
    assembled = report_path.read_bytes()
    try:
        report_path.write_bytes(assembled + b"\nPrivate debug: verify_H-1.md\n")
        privacy_issues = D._run_report_quality_gate(
            case.root, str(case.project), config=case.config,
        )
        assert stub_issue not in privacy_issues
        assert any("internal IDs leaked" in issue for issue in privacy_issues)
    finally:
        report_path.write_bytes(assembled)

    quality_issues = D._run_report_quality_gate(
        case.root, str(case.project), config=case.config,
    )
    assert quality_issues == []
    quality_text = (case.root / "report_quality.md").read_text(encoding="utf-8")
    assert "| stub_guard | PASS |" in quality_text
    assert "all three committed empty tiers replayed" in quality_text
    assert "Overall: PASS" in quality_text
    assert D._commit_report_assembly_phase_io(
        scratchpad=case.root,
        config=case.config,
        contract=contract,
        launch=launch,
    ) == []

    committed_report = report_path.read_bytes()
    committed_assembly = read_artifact_ledger(case.root)["work_units"][contract.key]
    authority_journal = case.root / "_artifact_output_authorities.json"
    committed_authorities = authority_journal.read_bytes()
    replay_contract, replay_launch, replay_execute, replay_issues = (
        D._arm_report_assembly_phase_io(
            scratchpad=case.root,
            config=case.config,
        )
    )
    assert replay_issues == []
    assert replay_contract is not None and replay_launch is not None
    assert replay_contract.digest == contract.digest
    assert replay_launch.digest == launch.digest
    assert replay_execute is False
    # Production skips commit when the arm operation authenticates an existing
    # generation. Replay must not issue a second output-authority attempt.
    assert validate_work_unit_artifacts(
        case.root,
        case.project,
        replay_contract,
        replay_launch,
        run_id=case.run_id,
        actor="DRIVER",
    ) == []
    assert read_artifact_ledger(case.root)["work_units"][contract.key] == committed_assembly
    assert authority_journal.read_bytes() == committed_authorities
    assert report_path.read_bytes() == committed_report

    assembly_unit = read_artifact_ledger(case.root)["work_units"][contract.key]
    assembly_artifact = assembly_unit["artifacts"]["project:AUDIT_REPORT.md"]
    assert assembly_unit["semantic_status"] == "ACTIVE"
    assert assembly_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert assembly_artifact["status"] == "ACTIVE"
    assembly_sha256 = assembly_artifact["sha256"]
    assembly_size = assembly_artifact["size"]
    assert {
        "scratchpad:report_critical_high.md",
        "scratchpad:report_medium.md",
        "scratchpad:report_low_info.md",
    } <= set(assembly_unit["input_bindings"])

    assert D._refresh_assurance_projection(
        case.checkpoint,
        case.root,
        case.config,
        allow_legacy_migration=True,
    ) == []
    assembly_phase = _phase(case, "report_assemble")
    D._commit_report_phase_success(
        assembly_phase,
        case.checkpoint,
        case.root,
        case.config,
        case.phases,
    )
    assert D._refresh_assurance_projection(
        case.checkpoint, case.root, case.config
    ) == []

    assert report_path.is_file()
    assert (case.root / "report_quality.md").is_file()
    assert all(
        (case.root / f"report_{tier}.md").read_bytes() == raw
        for tier, raw in tier_bytes.items()
    )

    final_ledger = read_artifact_ledger(case.root)
    historical = final_ledger["work_units"][contract.key]
    historical_artifact = historical["artifacts"]["project:AUDIT_REPORT.md"]
    assert historical["execution_state"] == "OUTPUT_COMMITTED"
    assert historical_artifact["sha256"] == assembly_sha256
    assert historical_artifact["size"] == assembly_size
    live_report = final_ledger["artifact_bindings"]["project:AUDIT_REPORT.md"]
    assert live_report["owner_key"].endswith(
        "/report_floor/assurance_projection"
    )
    assert live_report["status"] == "ACTIVE"

    assert {
        name: (
            (case.root / name).read_bytes()
            if (case.root / name).is_file()
            else None
        )
        for name in queue_before
    } == queue_before
    assert validate_live_verify_queue_publication(
        scratchpad=case.root,
        project_root=case.project,
        plan=case.plan,
        run_id=case.run_id,
    )["safe_to_consume"] is True
