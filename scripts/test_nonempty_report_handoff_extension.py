"""Proposed genuine nonempty severity-to-report handoff test extension."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence
import json

import plamen_driver as D
from artifact_ledger import ArtifactLedgerError, read_artifact_ledger
import security_obligation_lifecycle as SECURITY_LIFECYCLE
from test_nonempty_low_info_body_child import run_nonempty_low_info_body_child
from test_nonempty_report_evidence_repair_child import (
    run_nonempty_report_evidence_repair_child,
)
from test_nonempty_report_index_child import (
    canonicalize_nonempty_report_index,
    run_nonempty_report_index_child,
)
from test_nonempty_report_tail_children import run_nonempty_report_tail
from report_empty_tier import run_empty_report_tier
from report_body_evidence_projection import (
    FAULT_POINTS as REPORT_BODY_PROJECTION_FAULT_POINTS,
    validate_committed_report_body_evidence_projection,
)
from report_model_preimages import read_report_model_preimages
import pytest


class _ReportBodyProjectionCrash(RuntimeError):
    pass


def _phase(phases: Sequence[Any], name: str) -> Any:
    return next(item for item in phases if item.name == name)


def assert_nonempty_report_handoff(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    severity_issues: Sequence[str],
    monkeypatch,
) -> None:
    """Continue one already-finalized genuine live severity callback to report."""

    phases = D.SC_PHASES
    checkpoint = D.Checkpoint.load(root)
    run_id = config.get("_run_id")
    assert isinstance(run_id, str) and checkpoint.run_id == run_id
    severity = _phase(phases, "severity_adjudication_shadow")

    combined_issues = list(severity_issues)
    combined_issues.extend(D._reconcile_trust_evidence_provider_state(root, config))
    _bb_terminal, bb_issues = D._run_bb_policy_terminal_boundary(root, config)
    combined_issues.extend(bb_issues)
    gate_ok, gate_issues = D.gate_passes(root, str(project), severity)
    assert gate_ok, gate_issues
    combined_issues = list(dict.fromkeys(combined_issues))
    assert combined_issues
    assert not D._blocking_phase_authority_issues(combined_issues)
    failures = D._gate_failures_from_issues(
        severity,
        combined_issues,
        contract_digest=D._resolved_phase_contract_digest(severity, config),
        output_digest=D._resolved_phase_artifact_digest(severity, root, project),
        scratchpad=root,
        input_digest=D._resolved_phase_input_digest(severity, config),
    )
    D.PhaseCommitController(checkpoint, root, str(project), config).commit(
        severity, "COMPLETED_WITH_DEBT", failures, clean_transients=False,
    )

    # This scoped fixture starts at the queue boundary and deliberately omits
    # depth, so no post-depth security-obligation authority exists.  Mirror the
    # production report-index entrypoint: publish the real haltless lifecycle,
    # retain its explicit missing-source debt, and require exact registered
    # replay before any report prework or MODEL launch.
    report_index_phase = _phase(phases, "report_index")
    candidate_ids_before_lifecycle = tuple(
        row["finding id"] for row in D.parse_verification_queue_rows(root)
    )
    assert candidate_ids_before_lifecycle
    assert not (root / "security_obligation_authority.json").exists()
    lifecycle_issues = D._record_security_obligation_lifecycle_phase_io(
        root, config
    )
    assert lifecycle_issues == [
        "security-obligation lifecycle retained unresolved/debt aliases "
        "for human review"
    ]
    lifecycle_validation = D._validate_security_obligation_lifecycle_phase_io(
        root, config
    )
    assert lifecycle_validation == []
    assert isinstance(config, dict)
    config.setdefault(
        "_security_obligation_lifecycle_consumer_state", {}
    )[report_index_phase.name] = True
    for lifecycle_issue in lifecycle_issues:
        D._append_phase_io_debt(
            root,
            report_index_phase.name,
            "SECURITY_OBLIGATION_LIFECYCLE_DEBT",
            lifecycle_issue,
        )

    lifecycle = json.loads(
        (root / SECURITY_LIFECYCLE.AUTHORITY_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert lifecycle["schema_version"] == SECURITY_LIFECYCLE.SCHEMA_VERSION
    assert lifecycle["status"] == "DEGRADED_HUMAN_REVIEW"
    assert lifecycle["run_id"] == run_id
    assert lifecycle["source_authority_digest"] is None
    assert lifecycle["row_count"] == 0
    assert lifecycle["rows"] == []
    assert (
        "security_authority: missing, malformed, or digest-mismatched"
        in lifecycle["issues"]
    )
    lifecycle_contract, _lifecycle_launch = (
        D._security_obligation_lifecycle_contract_and_launch(root, config)
    )
    lifecycle_ledger = read_artifact_ledger(root)
    lifecycle_row = lifecycle_ledger["work_units"][lifecycle_contract.key]
    assert lifecycle_row["semantic_status"] == "ACTIVE"
    assert lifecycle_row["execution_state"] == "OUTPUT_COMMITTED"
    lifecycle_identities = {
        f"scratchpad:{SECURITY_LIFECYCLE.AUTHORITY_FILE}",
        f"scratchpad:{SECURITY_LIFECYCLE.PROJECTION_FILE}",
        f"scratchpad:{SECURITY_LIFECYCLE.REPORT_RETENTION_FILE}",
    }
    assert set(lifecycle_row["artifacts"]) == lifecycle_identities
    assert all(
        lifecycle_ledger["artifact_bindings"][identity]["owner_key"]
        == lifecycle_contract.key
        for identity in lifecycle_identities
    )
    assert "scratchpad:security_obligation_authority.json" not in (
        lifecycle_row["input_bindings"]
    )
    lifecycle_paths = tuple(
        root / identity.split(":", 1)[1]
        for identity in sorted(lifecycle_identities)
    )
    lifecycle_frozen = {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (*lifecycle_paths, root / "_artifact_state.json")
    }
    assert D._record_security_obligation_lifecycle_phase_io(root, config) == []
    assert D._validate_security_obligation_lifecycle_phase_io(root, config) == []
    assert {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (*lifecycle_paths, root / "_artifact_state.json")
    } == lifecycle_frozen
    assert tuple(
        row["finding id"] for row in D.parse_verification_queue_rows(root)
    ) == candidate_ids_before_lifecycle

    ready, prework_issues = D._run_report_index_prework_transaction(root, config)
    assert (ready, prework_issues) == (True, []), {
        "ready": ready,
        "prework_issues": prework_issues,
        "r10_outputs": {
            name: (root / name).is_file()
            for name in D._R10_REPORT_PREWORK_ROSTER
        },
    }
    assert D._r10_report_consumer_ready_issues(root, config) == []
    report_index, _contract, _launch = run_nonempty_report_index_child(
        root=root, project=project, config=config, checkpoint=checkpoint,
        phases=phases, monkeypatch=monkeypatch,
    )
    assert report_index is report_index_phase
    canonicalize_nonempty_report_index(
        root=root, config=config, checkpoint=checkpoint, phases=phases,
        phase=report_index,
    )

    # Production phase order is all body writers, then confirmation/merge.
    repair_observation = None
    for tier in ("critical_high", "medium"):
        body_phase = _phase(phases, f"report_body_writer_{tier}")
        _manifests, routing_issues = D._run_report_index_routing_transaction(
            root, config
        )
        assert routing_issues == []
        if tier == "critical_high":
            repair_observation = run_nonempty_report_evidence_repair_child(
                root=root,
                project=project,
                config=config,
                phase=body_phase,
                monkeypatch=monkeypatch,
            )
        assert D._ensure_report_evidence_before_body_writer(
            body_phase, config, root
        ) == []
        if tier == "critical_high":
            assert repair_observation is not None
            repair_observation.assert_not_relaunched_or_rewritten()
        assert run_empty_report_tier(
            scratchpad=root, project_root=project, config=config,
            phase_name=body_phase.name,
        ) is True
        D._commit_phase_from_disk_debt(
            body_phase, checkpoint, root, config, phases,
            clean_transients=True,
        )

    low_phase, low_contract, low_launch = run_nonempty_low_info_body_child(
        root=root, project=project, config=config, checkpoint=checkpoint,
        phases=phases, monkeypatch=monkeypatch,
    )

    # Enter through the production seam. The harmless child above is a
    # genuine POSIX MODEL transaction. Its exact raw bytes are committed and
    # retained before the DRIVER successor arms. This proves transport and
    # lineage only, not semantic report quality or native-provider parity.
    def crash_after_arm(point: str) -> None:
        if point == "after_arm":
            raise _ReportBodyProjectionCrash(point)

    with pytest.raises(_ReportBodyProjectionCrash, match="after_arm"):
        D._run_report_body_evidence_successor(
            low_phase, root, config, fault_hook=crash_after_arm,
        )
    retained = read_report_model_preimages(
        root, contract=low_contract, launch=low_launch, run_id=run_id,
    )
    retained_paths = retained.read_set
    model_row_before = dict(
        read_artifact_ledger(root)["work_units"][low_contract.key]
    )
    lineage_files_before = {
        name: (
            (root / name).read_bytes(),
            (root / name).stat().st_ino,
            (root / name).stat().st_mtime_ns,
        )
        for name in retained_paths
    }
    projection_key = low_contract.key.rsplit("/", 1)[0] + (
        "/evidence_projection.report_low_info"
    )
    ledger = read_artifact_ledger(root)
    assert ledger["work_units"][projection_key]["semantic_status"] == "INPUTS_BOUND"
    assert ledger["work_units"][projection_key]["execution_state"] == (
        "INPUTS_BOUND_PREEXECUTION"
    )
    state_before_read_only = (root / "_artifact_state.json").read_bytes()
    with pytest.raises(
        ArtifactLedgerError, match="projection is not committed",
    ):
        validate_committed_report_body_evidence_projection(
            scratchpad=root,
            project_root=project,
            config=config,
            phase_name=low_phase.name,
            model_contract=low_contract,
            model_launch=low_launch,
        )
    assert (root / "_artifact_state.json").read_bytes() == state_before_read_only

    # The same armed transaction advances across each remaining recovery
    # boundary. No test calls the publisher directly, and the MODEL child is
    # not relaunched.
    for selected in REPORT_BODY_PROJECTION_FAULT_POINTS[1:]:
        def crash(point: str, expected: str = selected) -> None:
            if point == expected:
                raise _ReportBodyProjectionCrash(expected)

        with pytest.raises(_ReportBodyProjectionCrash, match=selected):
            D._run_report_body_evidence_successor(
                low_phase, root, config, fault_hook=crash,
            )

    assert D._run_report_body_evidence_successor(
        low_phase, root, config,
    ) == []
    assert D._run_report_body_evidence_successor(
        low_phase, root, config, read_only=True,
    ) == []
    receipt = validate_committed_report_body_evidence_projection(
        scratchpad=root,
        project_root=project,
        config=config,
        phase_name=low_phase.name,
        model_contract=low_contract,
        model_launch=low_launch,
    )
    assert receipt["schema"] == "plamen.report_body_evidence_projection.v1"
    assert len(receipt["report_evidence_runtime_authority_digest"]) == 64
    assert D._validate_tier_body_against_manifest(
        root, "report_low_info", project_root=project, config=config,
    ) == []
    ledger = read_artifact_ledger(root)
    assert ledger["work_units"][low_contract.key] == model_row_before
    projection_row = ledger["work_units"][projection_key]
    runtime_authority = projection_row["preexecution_authority"][
        "report_evidence_runtime_authority"
    ]
    assert runtime_authority["authority_digest"] == receipt[
        "report_evidence_runtime_authority_digest"
    ]
    assert runtime_authority["read_set"]
    assert set(runtime_authority) == {
        "schema",
        "candidate_ids",
        "root_identities",
        "read_set",
        "absent_identities",
        "namespace_members",
        "implementation_identities",
        "semantic_witnesses",
        "runtime",
        "authority_digest",
    }
    assert ledger["artifact_bindings"]["scratchpad:report_low_info.md"][
        "owner_key"
    ] == projection_key
    assert ledger["artifact_bindings"][
        "scratchpad:report_evidence_projection_receipts/report_low_info.json"
    ]["owner_key"] == projection_key
    assert read_report_model_preimages(
        root, contract=low_contract, launch=low_launch, run_id=run_id,
    ) == retained
    assert {
        name: (
            (root / name).read_bytes(),
            (root / name).stat().st_ino,
            (root / name).stat().st_mtime_ns,
        )
        for name in retained_paths
    } == lineage_files_before

    body = root / "report_low_info.md"
    receipt_path = (
        root / "report_evidence_projection_receipts/report_low_info.json"
    )
    state_path = root / "_artifact_state.json"
    frozen = {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (body, receipt_path, state_path)
    }
    assert D._run_report_body_evidence_successor(
        low_phase, root, config,
    ) == []
    assert D._run_report_body_evidence_successor(
        low_phase, root, config, read_only=True,
    ) == []
    assert validate_committed_report_body_evidence_projection(
        scratchpad=root,
        project_root=project,
        config=config,
        phase_name=low_phase.name,
        model_contract=low_contract,
        model_launch=low_launch,
    ) == receipt
    assert {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (body, receipt_path, state_path)
    } == frozen

    # Exercise exact-next MODEL generation with the same issued deterministic
    # child executable/session. The helper routes distinct, still-valid raw
    # bytes from the typed attempt work-unit ID; it does not swap provider
    # identity between attempts.
    assert isinstance(config, dict)
    config.setdefault("_active_model_attempts", {})[low_phase.name] = 2
    retry_phase, retry_contract, retry_launch = run_nonempty_low_info_body_child(
        root=root, project=project, config=config, checkpoint=checkpoint,
        phases=phases, monkeypatch=monkeypatch, attempt=2,
    )
    assert retry_phase is low_phase
    assert retry_contract.work_unit_id == "model.report_low_info.attempt-0002"

    with pytest.raises(_ReportBodyProjectionCrash, match="after_arm"):
        D._run_report_body_evidence_successor(
            retry_phase, root, config, fault_hook=crash_after_arm,
        )
    retry_retained = read_report_model_preimages(
        root, contract=retry_contract, launch=retry_launch, run_id=run_id,
    )
    retry_retained_paths = retry_retained.read_set
    assert retry_retained.preimages[
        "scratchpad:report_low_info.md"
    ] != retained.preimages["scratchpad:report_low_info.md"]
    retry_lineage_before = {
        name: (
            (root / name).read_bytes(),
            (root / name).stat().st_ino,
            (root / name).stat().st_mtime_ns,
        )
        for name in retry_retained_paths
    }
    retry_projection_key = retry_contract.key.rsplit("/", 1)[0] + (
        "/evidence_projection.report_low_info.attempt-0002"
    )
    retry_model_row_before = dict(
        read_artifact_ledger(root)["work_units"][retry_contract.key]
    )
    retry_armed_row = read_artifact_ledger(root)["work_units"][retry_projection_key]
    assert retry_armed_row["semantic_status"] == "INPUTS_BOUND"
    assert retry_armed_row["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    retry_state_before_read_only = (root / "_artifact_state.json").read_bytes()
    with pytest.raises(
        ArtifactLedgerError, match="projection is not committed",
    ):
        validate_committed_report_body_evidence_projection(
            scratchpad=root,
            project_root=project,
            config=config,
            phase_name=retry_phase.name,
            model_contract=retry_contract,
            model_launch=retry_launch,
        )
    assert (root / "_artifact_state.json").read_bytes() == (
        retry_state_before_read_only
    )

    for selected in REPORT_BODY_PROJECTION_FAULT_POINTS[1:]:
        def retry_crash(point: str, expected: str = selected) -> None:
            if point == expected:
                raise _ReportBodyProjectionCrash(expected)

        with pytest.raises(_ReportBodyProjectionCrash, match=selected):
            D._run_report_body_evidence_successor(
                retry_phase, root, config, fault_hook=retry_crash,
            )

    assert D._run_report_body_evidence_successor(
        retry_phase, root, config,
    ) == []
    assert D._run_report_body_evidence_successor(
        retry_phase, root, config, read_only=True,
    ) == []
    retry_receipt = validate_committed_report_body_evidence_projection(
        scratchpad=root,
        project_root=project,
        config=config,
        phase_name=retry_phase.name,
        model_contract=retry_contract,
        model_launch=retry_launch,
    )
    assert retry_receipt["attempt_ordinal"] == 2
    assert D._validate_tier_body_against_manifest(
        root, "report_low_info", project_root=project, config=config,
    ) == []
    assert retry_receipt["model_preimage"] != receipt["model_preimage"]
    ledger = read_artifact_ledger(root)
    assert ledger["work_units"][retry_contract.key] == retry_model_row_before
    assert ledger["artifact_bindings"]["scratchpad:report_low_info.md"][
        "owner_key"
    ] == retry_projection_key
    assert ledger["artifact_bindings"][
        "scratchpad:report_evidence_projection_receipts/"
        "report_low_info.attempt-0002.json"
    ]["owner_key"] == retry_projection_key
    assert {
        name: (
            (root / name).read_bytes(),
            (root / name).stat().st_ino,
            (root / name).stat().st_mtime_ns,
        )
        for name in retry_retained_paths
    } == retry_lineage_before
    assert read_report_model_preimages(
        root, contract=low_contract, launch=low_launch, run_id=run_id,
    ) == retained
    D._commit_phase_from_disk_debt(
        low_phase, checkpoint, root, config, phases, clean_transients=True,
    )

    # Re-enter the committed body through the actual startup reconciliation
    # contract with a newly loaded checkpoint and a config reconstructed from
    # its public durable fields. The test deliberately retains the genuine
    # full checkpoint ancestry, while limiting reconciliation's phase roster
    # to the genuinely completed prefix so intentionally omitted future report
    # phases cannot manufacture a rewind signal.
    checkpoint.save(root)
    resumed_checkpoint = D.Checkpoint.load(root)
    assert resumed_checkpoint.run_id == run_id
    assert low_phase.name in resumed_checkpoint.completed
    # Reconstruct only the current startup-admitted public configuration.
    # Checkpoint-private runtime state and attempt caches are not launch
    # authority on a fresh reconciliation context.
    fresh_config = json.loads(D.canonical_semantic_config_bytes(config))
    fresh_config.update({
        "pipeline": str(config["pipeline"]),
        "mode": str(config["mode"]),
        "language": str(config["language"]),
        "cli_backend": str(config["cli_backend"]),
        "project_root": str(project),
        "scratchpad": str(root),
        "_run_id": run_id,
        "_audit_snapshot": dict(
            resumed_checkpoint.audit_snapshot or config["_audit_snapshot"]
        ),
    })
    fresh_config.pop("_active_model_attempts", None)
    fresh_config.pop("_phase_io_model_attempts", None)
    assert "_active_model_attempts" not in fresh_config
    assert "_phase_io_model_attempts" not in fresh_config
    completed_names = set(resumed_checkpoint.completed)
    resume_phases = [
        phase for phase in phases if phase.name in completed_names
    ]
    assert {phase.name for phase in resume_phases} == completed_names

    checkpoint_path = root / "_v2_checkpoint.json"
    retry_receipt_path = (
        root / "report_evidence_projection_receipts/"
        "report_low_info.attempt-0002.json"
    )
    resume_frozen = {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (body, retry_receipt_path, state_path, checkpoint_path)
    }

    def forbid_report_body_relaunch(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("committed report body resume relaunched a child")

    with monkeypatch.context() as resume_patch:
        resume_patch.setattr(D, "_run_one_codex_exec", forbid_report_body_relaunch)
        assert D._reconcile_completed_checkpoint_artifacts(
            root,
            str(project),
            resumed_checkpoint,
            resume_phases,
            str(fresh_config["mode"]),
            str(fresh_config["language"]),
            str(fresh_config["pipeline"]),
            str(fresh_config["cli_backend"]),
            current_config=fresh_config,
        ) == []
        resumed_contract, resumed_launch = (
            D._typed_model_phase_contract_and_launch(
                low_phase, root, fresh_config,
            )
        )
        assert resumed_contract.work_unit_id == (
            "model.report_low_info.attempt-0002"
        )
        assert resumed_contract.key == retry_contract.key
        assert resumed_contract.digest == retry_contract.digest
        assert resumed_launch.digest == retry_launch.digest
        assert D._validate_tier_body_against_manifest(
            root,
            "report_low_info",
            project_root=project,
            config=fresh_config,
        ) == []
        assert D._run_report_body_evidence_successor(
            low_phase, root, fresh_config, read_only=True,
        ) == []

    assert "_active_model_attempts" not in fresh_config
    assert {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (body, retry_receipt_path, state_path, checkpoint_path)
    } == resume_frozen
    checkpoint = resumed_checkpoint

    for tier in ("critical_high", "medium", "low_info"):
        confirmation = _phase(phases, f"report_{tier}")
        assert D._validate_tier_body_against_manifest(
            root, confirmation.name, project_root=project, config=config,
        ) == []
        D._commit_accepted_phase_from_disk(
            confirmation, checkpoint, root, config, phases,
        )
        merge = _phase(phases, f"report_{tier}_merge")
        D.merge_report_tier_shards(root, tier)
        D._commit_accepted_phase_from_disk(merge, checkpoint, root, config, phases)

    issues = D._refresh_severity_report_shadow_projection(
        checkpoint, root, config, stage="PRE_ASSEMBLE",
    )
    assert issues
    assert all("severity remains unresolved" in issue for issue in issues)
    ledger = read_artifact_ledger(root)
    units = [
        row for key, row in ledger["work_units"].items()
        if key.endswith("/severity_adjudication_shadow/report_projection")
    ]
    assert len(units) == 1
    unit = units[0]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    binding = unit["input_bindings"][
        "scratchpad:severity_adjudication_work_reconciliation.json"
    ]
    assert binding["producer_work_unit_key"].endswith(
        "/severity_adjudication_shadow/reconcile_final"
    )
    assert binding["producer_run_id"] == run_id
    assert binding["producer_writer"] == "DRIVER"
    assert binding["status"] == "ACTIVE"

    # Continue through production Python-native assembly, then the genuine
    # local report-tail children below. This scoped fixture still does not
    # establish global terminal publication or a full end-to-end audit.
    severity_debt_before = {
        key: commit.to_dict()
        for key, commit in checkpoint.phase_commits.items()
        if commit.phase_name == severity.name and commit.unresolved_failures
    }
    assert severity_debt_before
    assert severity.name in checkpoint.degraded
    evidence_runtime = D.validate_report_evidence_runtime(root)
    evidence_records = tuple(evidence_runtime["bundle"]["records"])
    routed_report_ids = tuple(
        evidence_runtime["bundle"]["expected_report_ids"]
    )
    assert routed_report_ids
    assert len(set(routed_report_ids)) == len(routed_report_ids)
    assert len(evidence_records) == len(routed_report_ids)
    assert set(routed_report_ids) == {
        record["report_id"] for record in evidence_records
    }
    evidence_markers = tuple(
        "<!-- PLAMEN_REPORT_EVIDENCE "
        f"rid={record['report_id']} "
        f"sha256={record['record_digest']} -->"
        for record in evidence_records
    )
    assert sum(D.parse_report_index_counts(root).values()) == len(
        routed_report_ids
    )

    D._write_final_subsystem_coverage_summary(
        root,
        scope_file=config.get("scope_file"),
        scope_match_mode=config.get("scope_match_mode", "legacy"),
        pipeline=config.get("pipeline", "sc"),
        language=config.get("language", ""),
        run_id=run_id,
        source_snapshot_digest=(
            D._security_obligation_source_snapshot_digest(config)
        ),
    )
    assembly_input_names = D._report_assembly_input_paths(root)
    assembly_inputs_before = {
        name: (root / name).read_bytes()
        for name in assembly_input_names
    }
    ledger_before_assembly = read_artifact_ledger(root)
    assembly_input_owners = {
        f"scratchpad:{name}": ledger_before_assembly["artifact_bindings"][
            f"scratchpad:{name}"
        ]["owner_key"]
        for name in assembly_input_names
    }
    later_model_outputs = (
        root / "report_dedup_agent_decisions.md",
        root / "disposition.md",
    )
    assert all(not path.exists() and not path.is_symlink()
               for path in later_model_outputs)

    def forbid_later_report_model(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError(
            "assembly/quality/assurance boundary launched a later MODEL child"
        )

    with monkeypatch.context() as assembly_patch:
        assembly_patch.setattr(
            D, "_run_one_codex_exec", forbid_later_report_model,
        )
        assembly_contract, assembly_launch, execute, assembly_issues = (
            D._arm_report_assembly_phase_io(
                scratchpad=root,
                config=config,
            )
        )
        assert assembly_issues == []
        assert assembly_contract is not None
        assert assembly_launch is not None
        assert execute is True
        assert D._assemble_report_python(root, str(project)) is True

        report_path = project / "AUDIT_REPORT.md"
        assert D._project_exact_scope_coverage_limitations(
            root, report_path,
        ) == []
        _evidence_changed, evidence_issues = D._project_report_evidence_file(
            root, report_path,
        )
        assert evidence_issues == []
        assert D._run_report_quality_gate(root, str(project)) == []
        assert D._commit_report_assembly_phase_io(
            scratchpad=root,
            config=config,
            contract=assembly_contract,
            launch=assembly_launch,
        ) == []

        assembled_report = report_path.read_bytes()
        assembled_text = assembled_report.decode("utf-8", errors="strict")
        for record, marker in zip(evidence_records, evidence_markers):
            assert f"[{record['report_id']}]" in assembled_text
            assert assembled_text.count(marker) == 1
        assert assembled_text.count(
            "<!-- PLAMEN_REPORT_EVIDENCE rid="
        ) == len(evidence_markers)
        assembly_row = read_artifact_ledger(root)["work_units"][
            assembly_contract.key
        ]
        assert assembly_row["execution_state"] == "OUTPUT_COMMITTED"
        assert assembly_row["semantic_status"] == "ACTIVE"
        assembly_artifact = assembly_row["artifacts"][
            "project:AUDIT_REPORT.md"
        ]
        assert assembly_artifact["status"] == "ACTIVE"
        assembly_sha256 = assembly_artifact["sha256"]
        assembly_size = assembly_artifact["size"]
        assert set(assembly_input_owners) <= set(
            assembly_row["input_bindings"]
        )
        for identity, owner_key in assembly_input_owners.items():
            input_binding = assembly_row["input_bindings"][identity]
            assert input_binding["producer_work_unit_key"] == owner_key
            assert input_binding["producer_run_id"] == run_id
            assert input_binding["status"] == "ACTIVE"

        # Match the live report_assemble success sequence: the first call
        # migrates the assembled report into the deterministic assurance
        # successor, the phase commit records successful assembly, and the
        # second call is an exact current-authority replay.
        assert D._refresh_assurance_projection(
            checkpoint, root, config, allow_legacy_migration=True,
        ) == []
        assembly_phase = _phase(phases, "report_assemble")
        D._commit_report_phase_success(
            assembly_phase, checkpoint, root, config, phases,
        )
        assert D._refresh_assurance_projection(
            checkpoint, root, config,
        ) == []

    assert report_path.is_file()
    assert (root / "report_quality.md").is_file()
    assert assembled_report
    delivered_text = report_path.read_text(encoding="utf-8", errors="strict")
    for record, marker in zip(evidence_records, evidence_markers):
        assert f"[{record['report_id']}]" in delivered_text
        assert delivered_text.count(marker) == 1
    assert delivered_text.count(
        "<!-- PLAMEN_REPORT_EVIDENCE rid="
    ) == len(evidence_markers)
    assert D._assert_assurance_status(checkpoint, root, project) == []
    assurance = json.loads(
        (root / "assurance_limitations.json").read_text(encoding="utf-8")
    )
    assert assurance["clean_full_audit_claim_allowed"] is False
    expected_gate_ids = {
        row["gate_id"]
        for commit in severity_debt_before.values()
        for row in commit["unresolved_failures"]
    }
    assert expected_gate_ids <= {
        row["gate_id"] for row in assurance["rows"]
    }

    # Assembly and its report successor must neither clear nor rewrite the
    # already-authenticated unresolved severity authority.
    assert {
        key: checkpoint.phase_commits[key].to_dict()
        for key in severity_debt_before
    } == severity_debt_before
    assert severity.name in checkpoint.degraded
    assert D._pipeline_terminal_exit_code(checkpoint) == D.EXIT_DEGRADED
    assert {
        name: (root / name).read_bytes()
        for name in assembly_input_names
    } == assembly_inputs_before

    final_ledger = read_artifact_ledger(root)
    historical_assembly = final_ledger["work_units"][assembly_contract.key]
    assert historical_assembly["execution_state"] == "OUTPUT_COMMITTED"
    historical_artifact = historical_assembly["artifacts"][
        "project:AUDIT_REPORT.md"
    ]
    assert historical_artifact["sha256"] == assembly_sha256
    assert historical_artifact["size"] == assembly_size
    live_report = final_ledger["artifact_bindings"]["project:AUDIT_REPORT.md"]
    assert live_report["owner_key"].endswith(
        "/report_floor/assurance_projection"
    )
    assert live_report["status"] == "ACTIVE"
    assert checkpoint.phase_commits["report_assemble"].state == "CLEAN"

    # Continue only through the scoped report-floor boundary.  The two MODEL
    # proposals use one genuine POSIX child and the deterministic phases run
    # their real transactions.  Global delivery/publication remains outside
    # this fixture, so this is deliberately not a full 75-phase E2E claim.
    observation = run_nonempty_report_tail(
        root=root,
        project=project,
        config=config,
        checkpoint=checkpoint,
        phases=phases,
        monkeypatch=monkeypatch,
        evidence_records=evidence_records,
        severity_phase_name=severity.name,
        severity_debt_before=severity_debt_before,
    )
    observation.assert_transport_stable()
    assert all(path.is_file() and not path.is_symlink()
               for path in later_model_outputs)
    assert {
        "report_dedup_agent", "report_dedup", "report_disposition",
        "report_floor",
    } <= set(checkpoint.completed)


# Callback splice after the existing final read-only replay assertions:
# assert_nonempty_report_handoff(
#     root=root, project=project, config=config,
#     severity_issues=completed_issues, monkeypatch=live_patch,
# )
