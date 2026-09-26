"""Genuine zero-active report-tail coverage for typed empty-tier publication."""
from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path

import pytest

import artifact_ledger as AL
import plamen_driver as D
import report_empty_tier as RET
import plamen_validators as V
from artifact_ledger import (
    ArtifactLedgerError,
    LEDGER_NAME,
    read_artifact_ledger,
)
from report_empty_tier import run_empty_report_tier
from test_core_empty_report_entry_integration import (
    _run_report_child,
    core_report_prework,
)


pytestmark = pytest.mark.integration


def _phase(case, name):
    return next(item for item in case.phases if item.name == name)


def test_empty_report_upstream_uses_one_bounded_validation_epoch(
    core_report_prework, monkeypatch, request
):
    case = core_report_prework
    report_index, _model_contract, _model_launch = _run_report_child(
        case, monkeypatch, request
    )
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda *_args, **_kwargs: pytest.fail(
            "empty report upstream validation must not relaunch a model"
        ),
    )
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
    body_phase = _phase(case, "report_body_writer_low_info")
    _manifests, routing_issues = D._run_report_index_routing_transaction(
        case.root, case.config
    )
    assert routing_issues == []
    assert D._ensure_report_evidence_before_body_writer(
        body_phase, case.config, case.root
    ) == []

    (
        run_id,
        pipeline,
        mode,
        ecosystem,
        backend,
        _root_identity,
        _project_identity,
    ) = RET._context(case.root, case.project, case.config)
    dimensions = (pipeline, mode, ecosystem, backend)
    ledger_path = case.root / LEDGER_NAME
    ledger_frozen = (
        ledger_path.read_bytes(),
        ledger_path.stat().st_dev,
        ledger_path.stat().st_ino,
        ledger_path.stat().st_mtime_ns,
    )

    snapshot_contexts = defaultdict(set)
    snapshot_misses = Counter()
    stable_reads = Counter()
    real_snapshot = AL._ArtifactValidationContext.snapshot
    real_stable = AL._stable_artifact_snapshot

    def tracked_snapshot(self, path):
        key = self._path_key(Path(path))
        snapshot_contexts[key].add(id(self))
        if key not in self._snapshots:
            snapshot_misses[key] += 1
        return real_snapshot(self, path)

    def tracked_stable(path, *args, **kwargs):
        key = AL._ArtifactValidationContext._path_key(Path(path))
        stable_reads[key] += 1
        return real_stable(path, *args, **kwargs)

    with monkeypatch.context() as observed:
        observed.setattr(
            AL._ArtifactValidationContext, "snapshot", tracked_snapshot
        )
        observed.setattr(AL, "_stable_artifact_snapshot", tracked_stable)
        exact_inputs, raw_inputs, runtime = RET._upstream(
            case.root,
            case.project,
            dimensions=dimensions,
            run_id=run_id,
        )

    assert exact_inputs
    assert set(raw_inputs) == set(exact_inputs)
    assert isinstance(runtime.get("bundle"), dict)
    for name in exact_inputs:
        key = AL._ArtifactValidationContext._path_key(case.root / name)
        assert len(snapshot_contexts[key]) == 1
        assert snapshot_misses[key] == 1
        # One initial snapshot and one terminal `finish()` snapshot. All
        # repeated producer/input/artifact checks use the initial capture.
        assert stable_reads[key] == 2
    assert (
        ledger_path.read_bytes(),
        ledger_path.stat().st_dev,
        ledger_path.stat().st_ino,
        ledger_path.stat().st_mtime_ns,
    ) == ledger_frozen

    prefix = f"{pipeline}/{mode}/{ecosystem}/{backend}"
    routing_key = f"{prefix}/report_index/routing"
    ledger = read_artifact_ledger(case.root)
    routing = ledger["work_units"][routing_key]
    routing_contract, routing_launch, _outputs = RET._stored_pair(
        routing, expected_key=routing_key, expected_run_id=run_id
    )
    foreign_root = case.project.parent / "foreign-report-scratchpad"
    foreign_project = case.project.parent / "foreign-report-project"
    foreign_root.mkdir()
    foreign_project.mkdir()
    identities = tuple(f"scratchpad:{name}" for name in exact_inputs)
    wrong_contexts = (
        AL._ArtifactValidationContext(
            foreign_root,
            case.project,
            ledger=json.loads(json.dumps(ledger)),
        ),
        AL._ArtifactValidationContext(
            case.root, foreign_project, ledger=ledger
        ),
    )
    for validation_context in wrong_contexts:
        assert AL.validate_work_unit_inputs(
            case.root,
            case.project,
            routing_contract,
            routing_launch,
            run_id=run_id,
            _validation_context=validation_context,
        ) == ["artifact validation context roots differ"]
        assert AL.validate_work_unit_artifacts(
            case.root,
            case.project,
            routing_contract,
            routing_launch,
            run_id=run_id,
            actor="DRIVER",
            _validation_context=validation_context,
        ) == ["artifact validation context roots differ"]
        assert AL.semantic_input_prebind_producer_authority_issues(
            case.root,
            case.project,
            identities,
            run_id=run_id,
            _validation_context=validation_context,
        ) == ["strict producer prebind validation context roots differ"]

    victim_name = next(
        name for name in exact_inputs
        if name.startswith("body_manifests/")
    )
    victim = case.root / victim_name
    victim_before = victim.read_bytes()
    victim_after = (
        (b" " if victim_before[:1] != b" " else b"\t")
        + victim_before[1:]
    )
    real_runtime = RET.validate_report_evidence_runtime

    def runtime_then_drift(root):
        result = real_runtime(root)
        victim.write_bytes(victim_after)
        return result

    with monkeypatch.context() as drift:
        drift.setattr(
            RET, "validate_report_evidence_runtime", runtime_then_drift
        )
        with pytest.raises(
            ArtifactLedgerError,
            match="empty report-tier upstream changed during replay",
        ):
            RET._upstream(
                case.root,
                case.project,
                dimensions=dimensions,
                run_id=run_id,
            )
    assert victim.read_bytes() == victim_after
    assert ledger_path.read_bytes() == ledger_frozen[0]


def test_real_empty_report_denominator_publishes_owned_tiers_and_recovers(
    core_report_prework, monkeypatch, request
):
    case = core_report_prework
    report_index, _model_contract, _model_launch = _run_report_child(
        case, monkeypatch, request
    )

    def no_worker_relaunch(*_args, **_kwargs):
        pytest.fail("empty report-tier transaction must not launch a model")

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

    for tier in ("critical_high", "medium", "low_info"):
        body_phase = _phase(case, f"report_body_writer_{tier}")
        _manifests, routing_issues = D._run_report_index_routing_transaction(
            case.root, case.config
        )
        assert routing_issues == []
        assert D._ensure_report_evidence_before_body_writer(
            body_phase, case.config, case.root
        ) == []

        if tier == "critical_high":
            fired = []

            def crash(point: str) -> None:
                if point == "after_output":
                    fired.append(point)
                    raise RuntimeError("empty report-tier publication interrupted")

            with pytest.raises(
                RuntimeError,
                match="empty report-tier publication interrupted",
            ):
                run_empty_report_tier(
                    scratchpad=case.root,
                    project_root=case.project,
                    config=case.config,
                    phase_name=body_phase.name,
                    fault_hook=crash,
                )
            assert fired == ["after_output"]
            interrupted = read_artifact_ledger(case.root)
            rows = [
                row for key, row in interrupted["work_units"].items()
                if key.endswith(
                    "/report_body/empty.report_critical_high"
                )
            ]
            assert len(rows) == 1
            assert rows[0]["semantic_status"] == "INPUTS_BOUND"
            assert rows[0]["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
            assert rows[0]["artifacts"] == {}

        assert run_empty_report_tier(
            scratchpad=case.root,
            project_root=case.project,
            config=case.config,
            phase_name=body_phase.name,
        ) is True
        output = case.root / f"report_{tier}.md"
        raw = output.read_bytes()
        assert b"PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER" in raw
        ledger = read_artifact_ledger(case.root)
        identity = f"scratchpad:report_{tier}.md"
        binding = ledger["artifact_bindings"][identity]
        assert binding["owner_key"].endswith(
            f"/report_body/empty.report_{tier}"
        )
        unit = ledger["work_units"][binding["owner_key"]]
        assert unit["semantic_status"] == "ACTIVE"
        assert unit["execution_state"] == "OUTPUT_COMMITTED"
        assert set(unit["artifacts"]) == {identity}
        assert "execution_authority" not in unit
        assert D._validate_tier_body_against_manifest(
            case.root, f"report_{tier}",
            project_root=case.project, config=case.config,
        ) == []
        # Empty tiers deliberately have no per-tier manifest. Resume must
        # replay the genuine committed DRIVER transaction, not attempt to
        # read a nonexistent MODEL routing selector or launch a body writer.
        assert not (case.root / "body_manifests" / f"report_{tier}.json").exists()
        assert D._run_report_body_evidence_successor(
            body_phase, case.root, case.config, read_only=True,
        ) == []
        wrong_run = {**case.config, "_run_id": "foreign-run"}
        assert V._empty_tier_sidecar_valid(
            case.root, f"report_{tier}", f"report_{tier}.md",
            project_root=case.project, config=wrong_run,
        ) is False

        ledger_path = case.root / LEDGER_NAME
        frozen = (
            output.read_bytes(),
            output.stat().st_dev,
            output.stat().st_ino,
            output.stat().st_mtime_ns,
            ledger_path.read_bytes(),
            ledger_path.stat().st_dev,
            ledger_path.stat().st_ino,
            ledger_path.stat().st_mtime_ns,
        )
        assert D._validate_tier_body_against_manifest(
            case.root, f"report_{tier}",
            project_root=case.project, config=case.config,
        ) == []
        assert (
            output.read_bytes(), output.stat().st_dev,
            output.stat().st_ino, output.stat().st_mtime_ns,
            ledger_path.read_bytes(), ledger_path.stat().st_dev,
            ledger_path.stat().st_ino, ledger_path.stat().st_mtime_ns,
        ) == frozen
        assert run_empty_report_tier(
            scratchpad=case.root,
            project_root=case.project,
            config=case.config,
            phase_name=body_phase.name,
        ) is True
        assert (
            output.read_bytes(),
            output.stat().st_dev,
            output.stat().st_ino,
            output.stat().st_mtime_ns,
            ledger_path.read_bytes(),
            ledger_path.stat().st_dev,
            ledger_path.stat().st_ino,
            ledger_path.stat().st_mtime_ns,
        ) == frozen

    deleted = case.root / "report_critical_high.md"
    deleted.unlink()
    assert D._validate_tier_body_against_manifest(
        case.root, "report_critical_high",
        project_root=case.project, config=case.config,
    )
    assert not deleted.exists()

    target = case.root / "report_medium.md"
    target.write_bytes(b"# forged empty tier\n")
    with pytest.raises(ArtifactLedgerError):
        run_empty_report_tier(
            scratchpad=case.root,
            project_root=case.project,
            config=case.config,
            phase_name="report_body_writer_medium",
        )


def test_legacy_raw_empty_body_is_rejected_without_adoption(
    core_report_prework, monkeypatch, request
):
    case = core_report_prework
    report_index, _model_contract, _model_launch = _run_report_child(
        case, monkeypatch, request
    )

    def no_worker_relaunch(*_args, **_kwargs):
        pytest.fail("legacy-body rejection must not launch a model")

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
    body_phase = _phase(case, "report_body_writer_medium")
    _manifests, routing_issues = D._run_report_index_routing_transaction(
        case.root, case.config
    )
    assert routing_issues == []
    assert D._ensure_report_evidence_before_body_writer(
        body_phase, case.config, case.root
    ) == []

    target = case.root / "report_medium.md"
    legacy = (
        b"# Medium Findings\n\n"
        b"Empty-Tier-Auth: PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER\n"
    )
    target.write_bytes(legacy)
    ledger_path = case.root / LEDGER_NAME
    ledger_before = ledger_path.read_bytes()
    checkpoint_path = case.root / "_v2_checkpoint.json"
    checkpoint_path.unlink()
    assert not checkpoint_path.exists()
    assert ledger_path.exists()
    # A remaining typed ledger forbids downgrade to marker-only legacy
    # acceptance even when the checkpoint was deleted.
    assert V._empty_tier_sidecar_valid(
        case.root, "report_medium", "report_medium.md",
    ) is False
    assert V._empty_tier_sidecar_valid(
        case.root, "report_medium", "report_medium.md",
        project_root=case.project, config=case.config,
    ) is False
    with pytest.raises(
        ArtifactLedgerError, match="refuses a pre-existing body"
    ):
        run_empty_report_tier(
            scratchpad=case.root,
            project_root=case.project,
            config=case.config,
            phase_name=body_phase.name,
        )
    assert target.read_bytes() == legacy
    assert ledger_path.read_bytes() == ledger_before
    assert not any(
        key.endswith("/report_body/empty.report_medium")
        for key in read_artifact_ledger(case.root)["work_units"]
    )


def test_after_commit_mutation_cannot_return_stale_success(
    core_report_prework, monkeypatch, request
):
    case = core_report_prework
    report_index, _model_contract, _model_launch = _run_report_child(
        case, monkeypatch, request
    )
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda *_args, **_kwargs: pytest.fail(
            "postcommit mutation test must not launch a model"
        ),
    )
    assert D._run_report_index_canonicalization_transaction(
        report_index, case.root, case.config
    ) == []
    D._commit_phase_from_disk_debt(
        report_index, case.checkpoint, case.root, case.config, case.phases,
        clean_transients=True,
    )
    phase = _phase(case, "report_body_writer_low_info")
    _manifests, routing_issues = D._run_report_index_routing_transaction(
        case.root, case.config
    )
    assert routing_issues == []
    assert D._ensure_report_evidence_before_body_writer(
        phase, case.config, case.root
    ) == []
    target = case.root / "report_low_info.md"
    fired = []

    def mutate(point: str) -> None:
        if point == "after_commit":
            fired.append(point)
            target.write_bytes(b"# changed after commit\n")

    with pytest.raises(ArtifactLedgerError, match="commit replay failed"):
        run_empty_report_tier(
            scratchpad=case.root,
            project_root=case.project,
            config=case.config,
            phase_name=phase.name,
            fault_hook=mutate,
        )
    assert fired == ["after_commit"]
    assert V._empty_tier_sidecar_valid(
        case.root, "report_low_info", "report_low_info.md",
        project_root=case.project, config=case.config,
    ) is False
    with pytest.raises(ArtifactLedgerError, match="output replay failed"):
        run_empty_report_tier(
            scratchpad=case.root,
            project_root=case.project,
            config=case.config,
            phase_name=phase.name,
        )


def test_empty_report_tier_resolver_rejects_unpaired_manifest_denominator():
    from phase_io_contracts import resolve_phase_io_contract

    with pytest.raises(ValueError, match="paired routing"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="core",
            ecosystem="evm",
            backend="codex",
            phase="report_body",
            work_unit_id="empty.report_medium",
            exact_inputs=(
                "report_records.json",
                "body_manifests/report_empty.json",
                "report_evidence_records.json",
            ),
            exact_outputs=("report_medium.md",),
            exact_writer="DRIVER",
        )


def test_empty_report_tier_resolver_omitted_output_is_registered_equivalent():
    from phase_io_contracts import resolve_phase_io_contract

    inputs = (
        "report_records.json",
        "body_manifests/report_empty.json",
        "report_evidence_records.json",
        "report_evidence_repair_request.json",
        "report_evidence_projection.md",
        "report_evidence_manifests/report_empty.json",
    )
    common = dict(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="codex",
        phase="report_body",
        work_unit_id="empty.report_medium",
        exact_inputs=inputs,
        exact_writer="DRIVER",
    )
    omitted = resolve_phase_io_contract(**common)
    explicit = resolve_phase_io_contract(
        **common, exact_outputs=("report_medium.md",)
    )
    assert omitted.to_dict() == explicit.to_dict()
    assert omitted.digest == explicit.digest
