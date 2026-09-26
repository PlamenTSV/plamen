"""Same-run accepted synthetic depth output through policy-empty assembly.

Initial inventory/depth/chain producers are explicit fixtures. Their actual
successor receipts feed the production Core queue, empty verification/R10,
report prework, controlled local Codex report-index child, and report assembly.
No provider judgment, recon execution, active verification, global delivery,
or complete-audit claim is made. Source content is a harmless local contract.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import artifact_ledger as AL
import plamen_driver as D
import plamen_validators as V
import test_depth_to_queue_same_run_semantics as DEPTH
import test_live_verify_queue_main_boundary_a0 as QUEUE
from test_core_empty_report_entry_integration import _run_report_child
from test_core_empty_report_assembly_integration import _commit_empty_tiers
from verify_queue_transaction import validate_live_verify_queue_publication


pytestmark = [pytest.mark.integration, pytest.mark.posix_only]


def _phase(case, name):
    return next(phase for phase in case.phases if phase.name == name)


def _public_bytes(case):
    return {
        name: (case.root / name).read_bytes() if (case.root / name).is_file() else None
        for name in case.plan["public_output_denominator"]
    }


def _empty_queue_to_prework(case, monkeypatch):
    """Continue the existing publication; never seed or reclaim its inputs."""
    empty, reason = V.is_verification_queue_empty(case.root, "sc")
    assert empty, reason
    aggregate = _phase(case, "sc_verify_aggregate")
    kwargs = dict(scratchpad=case.root, config=case.config, phase=aggregate)
    assert D._write_empty_verify_aggregate_projection(**kwargs, reason=reason) == []
    assert D._close_empty_verify_aggregate_r10(**kwargs) == []
    compute = json.loads((case.root / "external_assumption_undemotion_compute.json").read_text())
    assert compute["outcome"] == "CLEAN_ZERO", compute

    def no_severity_worker(*_args, **_kwargs):
        pytest.fail("policy-empty denominator must not launch a severity worker")

    severity = _phase(case, "severity_adjudication_shadow")
    with monkeypatch.context() as guard:
        guard.setattr(D, "_build_severity_adjudication_worker_launch_spec", no_severity_worker)
        reconciliation, issues = D._run_severity_adjudication_shadow_phase(
            severity, case.config, case.root,
        )
    assert issues == []
    assert reconciliation["denominator_count"] == 0 and reconciliation["all_resolved"]
    assert D._reconcile_trust_evidence_provider_state(case.root, case.config) == []
    _terminal, issues = D._run_bb_policy_terminal_boundary(case.root, case.config)
    assert issues == []
    passed, issues = D.gate_passes(case.root, str(case.project), severity)
    assert passed, issues
    D.PhaseCommitController(
        case.checkpoint, case.root, str(case.project), case.config,
    ).commit(severity, "CLEAN", (), clean_transients=True)

    # Accepted synthetic depth does not invent an upstream security authority.
    assert not (case.root / "security_obligation_authority.json").exists()
    lifecycle_issues = D._record_security_obligation_lifecycle_phase_io(case.root, case.config)
    assert lifecycle_issues == [
        "security-obligation lifecycle retained unresolved/debt aliases for human review"
    ]
    assert D._validate_security_obligation_lifecycle_phase_io(case.root, case.config) == []
    case.config.setdefault("_security_obligation_lifecycle_consumer_state", {})["report_index"] = True
    for issue in lifecycle_issues:
        D._append_phase_io_debt(case.root, "report_index", "SECURITY_OBLIGATION_LIFECYCLE_DEBT", issue)
    ready, issues = D._run_report_index_prework_transaction(case.root, case.config)
    assert ready and not issues, issues
    assert D._r10_report_consumer_ready_issues(case.root, case.config) == []


def _assemble_existing_empty_tiers(case):
    """Commit the production assembly, ending before later report phases."""
    assert D._refresh_severity_report_shadow_projection(
        case.checkpoint, case.root, case.config, stage="PRE_ASSEMBLE",
    ) == []
    D._write_final_subsystem_coverage_summary(
        case.root, scope_file=case.config.get("scope_file"),
        scope_match_mode=case.config.get("scope_match_mode", "legacy"),
        pipeline="sc", language="evm", run_id=case.run_id,
        source_snapshot_digest=D._security_obligation_source_snapshot_digest(case.config),
    )
    contract, launch, execute, issues = D._arm_report_assembly_phase_io(
        scratchpad=case.root, config=case.config,
    )
    assert issues == [] and execute
    assert contract is not None and launch is not None
    assert D._assemble_report_python(case.root, str(case.project)) is True
    report = case.project / "AUDIT_REPORT.md"
    assert D._project_exact_scope_coverage_limitations(case.root, report) == []
    _changed, issues = D._project_report_evidence_file(case.root, report)
    assert issues == []
    assert D._run_report_quality_gate(case.root, str(case.project), config=case.config) == []
    assert D._commit_report_assembly_phase_io(
        scratchpad=case.root, config=case.config, contract=contract, launch=launch,
    ) == []
    assembly = deepcopy(AL.read_artifact_ledger(case.root)["work_units"][contract.key])
    assert assembly["execution_state"] == "OUTPUT_COMMITTED"
    commit = assembly["commit_authority"]
    assert commit["output_authority_actor"] == "DRIVER"
    assert assembly["model_invoked"] is False
    assert commit["contract_digest"] == contract.digest
    assert commit["launch_digest"] == launch.digest
    assert commit["run_id"] == case.run_id
    authorities = json.loads((case.root / "_artifact_output_authorities.json").read_text())
    authority = authorities["authorities"][commit["output_authority_key"]]
    assert authority["actor"] == "DRIVER"
    assert authority["authority_digest"] == commit["output_authority_digest"]
    assert authority["expected_output_records"] == commit["expected_output_records"]
    assert AL.validate_work_unit_artifacts(
        case.root, case.project, contract, launch, run_id=case.run_id, actor="DRIVER",
    ) == []
    assert assembly["artifacts"]["project:AUDIT_REPORT.md"]["sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()
    assert D._refresh_assurance_projection(
        case.checkpoint, case.root, case.config, allow_legacy_migration=True,
    ) == []
    D._commit_report_phase_success(
        _phase(case, "report_assemble"), case.checkpoint, case.root, case.config, case.phases,
    )
    assert D._refresh_assurance_projection(case.checkpoint, case.root, case.config) == []
    assert AL.read_artifact_ledger(case.root)["work_units"][contract.key] == assembly


def test_accepted_depth_identity_retains_same_run_authority_through_empty_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request,
):
    if os.name != "posix":
        pytest.skip("controlled local report child requires POSIX compatibility")

    def no_execution(*_args, **_kwargs):
        pytest.fail("only the explicitly installed local report child may execute")

    # Forbid provider execution throughout all deterministic upstream work.
    with monkeypatch.context() as upstream_guard:
        upstream_guard.setattr(D, "_run_one_codex_exec", no_execution)
        upstream_guard.setattr(D, "run_phase", no_execution)
        project, root, config = DEPTH._seed_initial_inputs(tmp_path)
        run_id = config["_run_id"]
        initial_units = deepcopy(AL.read_artifact_ledger(root)["work_units"])
        before = DEPTH._bytes(root, DEPTH.CANONICAL)
        outcome = D._run_accepted_depth_postprocessors(
            "depth", root, accepted=True, recovery_preflight=False, config=config,
        )
        assert outcome["added_inventory_ids"] == ["INV-003"], outcome
        assert "transaction" not in outcome.get("failed_processors", []), outcome
        produced = DEPTH._bytes(root, DEPTH.CANONICAL)
        ids = D._depth_additive_identity_set("findings_inventory.md", produced["findings_inventory.md"])
        assert ids == ("INV-001", "INV-002", "INV-003")
        ledger = AL.read_artifact_ledger(root)
        capture = ledger["work_units"][DEPTH.CAPTURE_KEY]
        successor = ledger["work_units"][DEPTH.SUCCESSOR_KEY]
        for name in DEPTH.CANONICAL:
            assert D._depth_additive_identity_set(name, produced[name]) == ids
            DEPTH._assert_consumes(capture, name, DEPTH.SEED_KEY,
                                  initial_units[DEPTH.SEED_KEY], before[name], run_id)
        DEPTH._assert_consumes(
            capture, "niche_runtime_findings.md", DEPTH.SOURCE_KEY,
            initial_units[DEPTH.SOURCE_KEY], (root / "niche_runtime_findings.md").read_bytes(), run_id,
        )
        DEPTH._assert_consumes(
            successor, D._DEPTH_ADDITIVE_SOURCE_MANIFEST, DEPTH.CAPTURE_KEY,
            capture, (root / D._DEPTH_ADDITIVE_SOURCE_MANIFEST).read_bytes(), run_id,
        )
        retained_units = deepcopy({**initial_units, DEPTH.CAPTURE_KEY: capture,
                                   DEPTH.SUCCESSOR_KEY: successor})
        retained_files = DEPTH._bytes(root, (*DEPTH.CANONICAL,
            "niche_runtime_findings.md", D._DEPTH_ADDITIVE_SOURCE_MANIFEST,
            D._DEPTH_ADDITIVE_FINALIZATION, D._DEPTH_ADDITIVE_DEBT))
        DEPTH._seed_queue_context(root, project, config, ids)
        # This helper only supplies missing context: no QUEUE._seed or
        # replacement/reclaim of any accepted-depth generation is permitted.
        assert DEPTH._bytes(root, tuple(retained_files)) == retained_files
        assert D._ensure_recon_dependency_parity(root, str(project), config)["expected_ids"] == []
        assert D._run_sc_semantic_dedup_noop(root, config, "synthetic preserve-all") == [
            "dedup_decisions.md", "findings_inventory_deduped.md",
        ]
        queue_phase, phases = QUEUE._phase_and_graph("sc")
        checkpoint = QUEUE._checkpoint(root, config, run_id)
        result = QUEUE._invoke(boundary=QUEUE._boundary(), phase=queue_phase,
            checkpoint=checkpoint, root=root, config=config, phases=phases)
        assert result["state"] == "COMMITTED" and result["safe_to_continue"], result
        case = SimpleNamespace(root=root, project=project, config=config,
            run_id=run_id, phases=phases, checkpoint=checkpoint,
            plan=result["cutover_result"]["plan"])
        publication = validate_live_verify_queue_publication(
            scratchpad=root, project_root=project, plan=case.plan, run_id=run_id,
        )
        assert publication["safe_to_consume"] is True
        assert V.parse_verification_queue_rows(root) == []
        excluded = json.loads((root / "verification_queue_evidence_excluded.json").read_text())["rows"]
        assert sorted(row["finding id"] for row in excluded) == list(ids)
        assert all(row["severity"] == "Low" and row["exclusion reason"] == "AUTHORIZED_EXCLUDED"
                   for row in excluded)
        queue_before = _public_bytes(case)
        _empty_queue_to_prework(case, monkeypatch)
        assert _public_bytes(case) == queue_before

    # Only this helper installs the deterministic local Codex executable.
    report_index, model_contract, _launch = _run_report_child(case, monkeypatch, request)
    monkeypatch.setattr(D, "_run_one_codex_exec", no_execution)
    monkeypatch.setattr(D, "run_phase", no_execution)
    model_record = AL.read_artifact_ledger(root)["work_units"][model_contract.key]
    assert model_record["execution_authority"]
    assert D._run_report_index_canonicalization_transaction(report_index, root, config) == []
    D._commit_phase_from_disk_debt(report_index, checkpoint, root, config, phases,
                                  clean_transients=True)
    _commit_empty_tiers(case)
    _assemble_existing_empty_tiers(case)

    final_ledger = AL.read_artifact_ledger(root)
    assert DEPTH._bytes(root, tuple(retained_files)) == retained_files
    assert all(final_ledger["work_units"][key] == unit for key, unit in retained_units.items())
    consumers = [unit for key, unit in final_ledger["work_units"].items()
        if "/sc_verify_queue/" in key
        and unit.get("input_bindings", {}).get("scratchpad:findings_inventory.md", {}).get(
            "producer_work_unit_key") == DEPTH.SUCCESSOR_KEY]
    assert consumers
    for unit in consumers:
        DEPTH._assert_consumes(unit, "findings_inventory.md", DEPTH.SUCCESSOR_KEY,
                              successor, produced["findings_inventory.md"], run_id)
    assert _public_bytes(case) == queue_before
    assert validate_live_verify_queue_publication(
        scratchpad=root, project_root=project, plan=case.plan, run_id=run_id,
    )["safe_to_consume"] is True
    final_excluded = json.loads((root / "verification_queue_evidence_excluded.json").read_text())["rows"]
    assert final_excluded == excluded
    assert any(row["finding id"] == "INV-003" for row in final_excluded)
    assert "INV-003" in (root / "report_coverage.md").read_text()
    assert (project / "AUDIT_REPORT.md").is_file()
    assert "report_assemble" in checkpoint.completed
    assert "recon" not in checkpoint.completed and "depth" not in checkpoint.completed
    assert "report_floor" not in checkpoint.completed
