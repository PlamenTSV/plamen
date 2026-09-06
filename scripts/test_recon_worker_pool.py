from __future__ import annotations

import json
import inspect
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
import plamen_mechanical as M  # noqa: E402
import artifact_ledger as L  # noqa: E402
import recon_prepass  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from plamen_validators import _validate_recon_content_structure  # noqa: E402


def _seed_prepass_authority(config: dict) -> None:
    scratch = Path(config["scratchpad"])
    project = Path(config["project_root"])
    if (scratch / L.LEDGER_NAME).exists():
        return
    run_id = str(config["_run_id"])
    mode = str(config["mode"])
    backend = str(config["cli_backend"])
    key = canonical_work_unit_key(
        "sc", mode, "evm", backend, "recon", "prepass"
    )
    payloads = {
        name: (
            M._PREPASS_MARKER
            + f"\n# {name}\n\n[LLM TO ENRICH] authenticated prepass fixture.\n"
        ).encode()
        for name in recon_prepass._SC_PREPASS_PUBLIC_OUTPUTS
    }
    contract = PhaseIOContract(
        pipeline="sc",
        mode=mode,
        ecosystem="evm",
        backend=backend,
        phase="recon",
        work_unit_id="prepass",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                minimum_gate="FIXTURE_EXACT_BYTES",
            )
            for name in payloads
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode=mode,
        ecosystem="evm",
        backend=backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    L.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=run_id
    )
    for name, raw in payloads.items():
        (scratch / name).write_bytes(raw)
    L.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )


def _cfg(
    tmp_path: Path,
    mode: str = "thorough",
    *,
    backend: str = "claude",
    run_id: str | None = None,
) -> dict:
    project = tmp_path / "project"
    scratch = tmp_path / ".scratchpad"
    project.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    (project / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Protocol {}\n",
        encoding="utf-8",
    )
    config = {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "language": "evm",
        "mode": mode,
        "pipeline": "sc",
        "cli_backend": backend,
        "_run_id": run_id or f"recon-worker-pool-{mode}",
        "run_id": run_id or f"recon-worker-pool-{mode}",
    }
    _seed_prepass_authority(config)
    return config


def _worker_shard(name: str, role: str, owner: str = "R-test") -> str:
    selection_signal = (
        '<!-- PLAMEN_SIGNALS: {"required_skills":[]} -->\n\n'
        if role in {
            "templates_patterns", "inventory_templates",
            "l1_templates_patterns", "l1_build_templates",
        }
        else ""
    )
    body = (
        f"<!-- PLAMEN_ARTIFACT: {name} -->\n"
        f"<!-- PLAMEN_OWNER: {owner} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: recon -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- RECON_ROLE: {role} -->\n"
        f"<!-- EXPECTED_OUTPUT: {name} -->\n\n"
        f"# Recon Worker {role}\n\n"
        "## Evidence\n\n"
        "Concrete source evidence covers contracts, functions, state variables, "
        "entry points, trust boundaries, build status, static detector status, "
        "required template routing, and downstream audit implications. "
        "This repeated sentence keeps the test artifact safely above gate "
        "minimums without relying on production fixtures. "
        "Concrete source evidence covers contracts, functions, state variables, "
        "entry points, trust boundaries, build status, static detector status, "
        "required template routing, and downstream audit implications.\n\n"
        "## Canonical Merge Hints\n\n"
        "- Inform the canonical recon files for this role.\n\n"
        + selection_signal
        + "<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )
    return body


def _write_exact_recon_retry_plan(
    scratch: Path, cfg: dict, phase: D.Phase, *, attempt: int = 2,
) -> None:
    input_digest = D._resolved_phase_input_digest(phase, cfg)
    contract_digest = D._resolved_phase_contract_digest(phase, cfg)
    failure = D.GateFailure(
        gate_id="recon.full_validator.l1_scope_ack",
        gate_class="SCHEMA",
        message="fresh canonical L1 scope acknowledgement required",
        affected_identities=("scope_leftover.md",),
        input_digest=input_digest,
        output_digest="2" * 64,
        contract_digest=contract_digest,
        evidence_paths=("scope_leftover.md",),
        repair_owner="recon",
        denominator_count=1,
        denominator_digest="4" * 64,
    )
    payload = {
        "schema": "plamen.retry-plan/v1", "run_id": cfg["_run_id"],
        "phase_name": "recon", "work_unit_id": "phase", "attempt": attempt,
        "input_digest": input_digest, "output_digest_before": "6" * 64,
        "contract_digest": contract_digest,
        "launch_digest": D._resolved_phase_launch_digest(phase, cfg),
        "required_output_schema": [
            {"pattern": pattern, "minimum_bytes": phase.min_artifact_bytes,
             "minimum_count": phase.min_artifacts_count}
            for pattern in phase.expected_artifacts
        ],
        "failed_predicates": [failure.to_dict()], "semantic_retry": True,
    }
    (scratch / "recon_retry_plan.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _recon_phase():
    return next(phase for phase in D.SC_PHASES if phase.name == "recon")


def _public_prepass_bytes(scratch: Path) -> dict[str, bytes]:
    return {
        name: (scratch / name).read_bytes()
        for name in recon_prepass._SC_PREPASS_PUBLIC_OUTPUTS
    }


def _merged_sc_cfg(tmp_path: Path, *, backend: str, run_id: str) -> dict:
    cfg = _cfg(tmp_path, "thorough", backend=backend, run_id=run_id)
    scratch = Path(cfg["scratchpad"])
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(
                job["output"], job["role"], owner=job["agent_id"]
            ),
            encoding="utf-8",
        )
    M._merge_recon_worker_shards(scratch, cfg)
    return cfg


def _l1_recovery_cfg(tmp_path: Path, *, backend: str, run_id: str) -> dict:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    project.mkdir(parents=True)
    scratch.mkdir()
    cfg = {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "language": "rust",
        "mode": "thorough",
        "pipeline": "l1",
        "cli_backend": backend,
        "_run_id": run_id,
        "run_id": run_id,
    }
    names = M._canonical_merge_output_names("l1")
    key = canonical_work_unit_key(
        "l1", "thorough", "rust", backend, "recon", "canonical_merge"
    )
    payloads = {
        name: (
            f"# {name}\n\nAuthenticated recovered L1 canonical evidence.\n"
        ).encode()
        for name in names
    }
    contract = PhaseIOContract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend=backend,
        phase="recon",
        work_unit_id="canonical_merge",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                minimum_gate="FIXTURE_EXACT_BYTES",
            )
            for name in names
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend=backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    L.record_work_unit_inputs(scratch, project, contract, launch, run_id=run_id)
    for name, raw in payloads.items():
        (scratch / name).write_bytes(raw)
    L.record_work_unit_artifacts(
        scratch, project, contract, launch, run_id=run_id, actor="DRIVER"
    )
    return cfg


def _publish_driver_fixture_output(
    cfg: dict,
    *,
    phase: str,
    work_unit_id: str,
    name: str,
    raw: bytes,
) -> None:
    scratch = Path(cfg["scratchpad"])
    project = Path(cfg["project_root"])
    key = canonical_work_unit_key(
        cfg["pipeline"], cfg["mode"], cfg["language"], cfg["cli_backend"],
        phase, work_unit_id,
    )
    contract = PhaseIOContract(
        pipeline=cfg["pipeline"],
        mode=cfg["mode"],
        ecosystem=cfg["language"],
        backend=cfg["cli_backend"],
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=name,
            owner_key=key,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            minimum_gate="FIXTURE_EXACT_BYTES",
        ),),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline=cfg["pipeline"],
        mode=cfg["mode"],
        ecosystem=cfg["language"],
        backend=cfg["cli_backend"],
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    L.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=cfg["_run_id"]
    )
    (scratch / name).write_bytes(raw)
    L.record_work_unit_artifacts(
        scratch, project, contract, launch,
        run_id=cfg["_run_id"], actor="DRIVER",
    )


def _forbid_recovery_mutation(name: str):
    def forbidden(*_args, **_kwargs):
        raise AssertionError(f"recovery preflight invoked mutator: {name}")

    return forbidden


def test_recon_recovery_preflight_is_byte_and_ledger_observational(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    cfg = _cfg(tmp_path, backend="codex", run_id="recon-preflight-observational")
    scratch = Path(cfg["scratchpad"])
    project = Path(cfg["project_root"])
    phase = _recon_phase()
    before_files = _public_prepass_bytes(scratch)
    ledger_path = scratch / L.LEDGER_NAME
    before_ledger = ledger_path.read_bytes()

    for name in (
        "_ensure_recon_dependency_parity",
        "_write_and_record_recon_supplementary_disposition",
        "_materialize_sc_slither_flat_files",
        "_record_recon_uncovered_in_scope_leftover",
        "_materialize_live_skill_selection_boundary",
        "strip_codex_prepass_markers",
    ):
        monkeypatch.setattr(D, name, _forbid_recovery_mutation(name))

    # Marker-stamped prepass content is intentionally rejected, but validation
    # before worker launch must not edit or reattribute any recovered byte.
    passed, missing = D._run_phase_validators(
        phase,
        cfg,
        scratch,
        list(D.SC_PHASES),
        0,
        D._snapshot_file_state(scratch, str(project)),
        recovery_preflight=True,
    )
    assert not passed
    assert missing
    assert _public_prepass_bytes(scratch) == before_files
    assert ledger_path.read_bytes() == before_ledger
    assert L.semantic_input_prebind_producer_authority_issues(
        scratch,
        project,
        tuple(
            f"scratchpad:{name}"
            for name in recon_prepass._SC_PREPASS_PUBLIC_OUTPUTS
        ),
        run_id=cfg["_run_id"],
    ) == []

    # A fresh process/config replay remains observational and retains the exact
    # producer authority required for a crash-safe retry.
    fresh_cfg = dict(cfg)
    replay_passed, replay_missing = D._run_phase_validators(
        phase,
        fresh_cfg,
        scratch,
        list(D.SC_PHASES),
        0,
        D._snapshot_file_state(scratch, str(project)),
        recovery_preflight=True,
    )
    assert (replay_passed, replay_missing) == (passed, missing)
    assert _public_prepass_bytes(scratch) == before_files
    assert ledger_path.read_bytes() == before_ledger


def test_recon_recovery_preflight_never_reblesses_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    cfg = _cfg(tmp_path, backend="codex", run_id="recon-preflight-drift")
    scratch = Path(cfg["scratchpad"])
    project = Path(cfg["project_root"])
    phase = _recon_phase()
    target = scratch / "function_list.md"
    target.write_bytes(target.read_bytes() + b"\nforeign mutation\n")
    drifted = target.read_bytes()
    before_ledger = (scratch / L.LEDGER_NAME).read_bytes()
    monkeypatch.setattr(
        D,
        "strip_codex_prepass_markers",
        _forbid_recovery_mutation("strip_codex_prepass_markers"),
    )

    passed, _missing = D._run_phase_validators(
        phase,
        cfg,
        scratch,
        list(D.SC_PHASES),
        0,
        D._snapshot_file_state(scratch, str(project)),
        recovery_preflight=True,
    )
    assert not passed
    assert target.read_bytes() == drifted
    assert (scratch / L.LEDGER_NAME).read_bytes() == before_ledger
    issues = L.semantic_input_prebind_producer_authority_issues(
        scratch,
        project,
        ("scratchpad:function_list.md", "scratchpad:meta_buffer.md"),
        run_id=cfg["_run_id"],
    )
    assert issues
    assert any("function_list.md" in issue for issue in issues)
    # Bundle replay makes the untouched sibling unavailable too; validation
    # must not hide that producer-authority failure by reblessing either file.
    assert any("meta_buffer.md" in issue for issue in issues)


def test_recon_post_execution_still_runs_registered_postprocessors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    cfg = _cfg(tmp_path, backend="codex", run_id="recon-post-execution")
    scratch = Path(cfg["scratchpad"])
    project = Path(cfg["project_root"])
    phase = _recon_phase()
    calls: list[str] = []

    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (True, []))
    monkeypatch.setattr(D, "_detect_foreign_phase_writes", lambda *_a, **_k: [])
    monkeypatch.setattr(D, "_validate_recon_coverage", lambda *_a, **_k: [])
    monkeypatch.setattr(
        D, "_validate_recon_content_structure", lambda *_a, **_k: ([], [])
    )
    monkeypatch.setattr(D, "_skill_manifest_reconciliation_issues", lambda *_a: [])
    monkeypatch.setattr(D, "_selected_skill_manifest_issues", lambda *_a: [])
    monkeypatch.setattr(D, "_validate_injectable_promotion", lambda *_a: [])
    monkeypatch.setattr(
        D,
        "_ensure_recon_dependency_parity",
        lambda *_a, **_k: calls.append("dependency") or {
            "researched": 0,
            "unresolved": 0,
        },
    )
    monkeypatch.setattr(
        D,
        "_materialize_sc_slither_flat_files",
        lambda *_a, **_k: calls.append("slither") or [],
    )
    monkeypatch.setattr(
        D,
        "_materialize_live_skill_selection_boundary",
        lambda *_a, **_k: calls.append("selection") or [],
    )
    monkeypatch.setattr(
        D,
        "strip_codex_prepass_markers",
        _forbid_recovery_mutation("strip_codex_prepass_markers"),
    )

    passed, missing = D._run_phase_validators(
        phase,
        cfg,
        scratch,
        list(D.SC_PHASES),
        0,
        D._snapshot_file_state(scratch, str(project)),
        recovery_preflight=False,
    )
    assert passed, missing
    # Dependency parity is the only canonical-output mutation here. It must be
    # last so a rejection by either earlier postprocessor leaves the captured
    # recon retry predecessor byte-exact.
    assert calls == ["slither", "selection", "dependency"]


def test_recon_marker_degrade_cannot_publish_unowned_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    cfg = _cfg(tmp_path, backend="codex", run_id="recon-marker-fail-closed")
    scratch = Path(cfg["scratchpad"])
    before = _public_prepass_bytes(scratch)
    before_ledger = (scratch / L.LEDGER_NAME).read_bytes()
    marker_issue = "function_list.md still has pre-pass overwrite marker"
    monkeypatch.setattr(
        D,
        "_validate_recon_content_structure",
        lambda *_a, **_k: ([marker_issue], []),
    )
    monkeypatch.setattr(
        D,
        "strip_codex_prepass_markers",
        _forbid_recovery_mutation("strip_codex_prepass_markers"),
    )

    passed, missing = D._try_recon_prepass_marker_degrade(
        scratch,
        cfg,
        [f"recon content: {marker_issue}"],
    )
    assert not passed
    assert missing == [f"recon content: {marker_issue}"]
    assert _public_prepass_bytes(scratch) == before
    assert (scratch / L.LEDGER_NAME).read_bytes() == before_ledger


def test_recon_recovery_containment_reports_without_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    cfg = _cfg(tmp_path, backend="codex", run_id="recon-preflight-containment")
    scratch = Path(cfg["scratchpad"])
    project = Path(cfg["project_root"])
    foreign = scratch / "analysis_future.md"
    foreign.write_bytes(b"future phase bytes remain attributable\n")
    before_ledger = (scratch / L.LEDGER_NAME).read_bytes()
    monkeypatch.setattr(
        D,
        "_detect_foreign_phase_writes",
        lambda *_a, **_k: [foreign.name],
    )
    monkeypatch.setattr(
        D,
        "_quarantine_foreign_phase_writes",
        _forbid_recovery_mutation("_quarantine_foreign_phase_writes"),
    )

    passed, missing = D._run_phase_validators(
        _recon_phase(),
        cfg,
        scratch,
        list(D.SC_PHASES),
        0,
        D._snapshot_file_state(scratch, str(project)),
        recovery_preflight=True,
    )
    assert not passed
    assert any("recovered recon has later-phase artifacts" in str(x) for x in missing)
    assert foreign.read_bytes() == b"future phase bytes remain attributable\n"
    assert not (scratch / "_overflow").exists()
    assert (scratch / L.LEDGER_NAME).read_bytes() == before_ledger


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize(
    "crash_point",
    (
        "after_canonical_authority",
        "before_dependency_parity",
        "before_slither_materialization",
        "before_skill_selection",
    ),
)
def test_recon_recovery_finalization_is_crash_safe_and_replayable(
    tmp_path: Path,
    backend: str,
    crash_point: str,
):
    assert "_finalize_recovered_recon" in D.main.__code__.co_names
    assert "_run_recon_startup_authority_barrier" in D.main.__code__.co_names
    main_source = Path(D.__file__).read_text(encoding="utf-8").split(
        "def main(", 1
    )[1]
    assert main_source.index(
        "_run_recon_startup_authority_barrier"
    ) < main_source.index("from recon_prepass import run_recon_prepass")
    cfg = _merged_sc_cfg(
        tmp_path,
        backend=backend,
        run_id=f"recon-recovery-finalize-{backend}-{crash_point}",
    )
    scratch = Path(cfg["scratchpad"])
    before_bytes, before_bindings, before_issues = (
        D._recon_recovery_canonical_snapshot(scratch, cfg)
    )
    assert before_issues == []

    class InjectedCrash(BaseException):
        pass

    def crash(point: str) -> None:
        if point == crash_point:
            raise InjectedCrash(point)

    with pytest.raises(InjectedCrash, match=crash_point):
        D._finalize_recovered_recon(
            scratch, dict(cfg), failure_injector=crash
        )
    pending, pending_issues = D._read_recon_finalization_state(scratch, cfg)
    assert pending_issues == []
    assert pending is not None and pending["state"] == "PENDING"

    crash_bytes, crash_bindings, crash_issues = (
        D._recon_recovery_canonical_snapshot(scratch, cfg)
    )
    assert crash_issues == []
    assert crash_bytes == before_bytes
    assert crash_bindings == before_bindings

    # A fresh config models process restart. Every completed predecessor is
    # replayed; the interrupted successor is completed exactly once.
    assert D._resume_recon_finalization_before_prepass(
        scratch, dict(cfg)
    ) is True
    complete, complete_issues = D._read_recon_finalization_state(scratch, cfg)
    assert complete_issues == []
    assert complete is not None and complete["state"] == "COMPLETE"
    after_bytes, after_bindings, after_issues = (
        D._recon_recovery_canonical_snapshot(scratch, cfg)
    )
    assert after_issues == []
    assert after_bytes == before_bytes
    assert after_bindings == before_bindings
    assert (scratch / "slither" / "primitive_status.md").is_file()
    assert (scratch / "skill_selection_catalog.json").is_file()
    assert L.semantic_input_prebind_producer_authority_issues(
        scratch,
        Path(cfg["project_root"]),
        (
            "scratchpad:external_dependency_research.md",
            "scratchpad:skill_selection_catalog.json",
        ),
        run_id=cfg["_run_id"],
    ) == []


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_driver_canonical_merge_arms_pending_before_any_finalizer(
    tmp_path: Path,
    backend: str,
):
    cfg = _cfg(
        tmp_path,
        "thorough",
        backend=backend,
        run_id=f"recon-merge-pending-{backend}",
    )
    scratch = Path(cfg["scratchpad"])
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(
                job["output"], job["role"], owner=job["agent_id"]
            ),
            encoding="utf-8",
        )

    assert D._merge_recon_worker_shards_and_arm_finalization(
        scratch, cfg
    )
    pending, issues = D._read_recon_finalization_state(scratch, cfg)
    assert issues == []
    assert pending is not None and pending["state"] == "PENDING"
    assert not (scratch / "slither" / "primitive_status.md").exists()
    assert not (scratch / "skill_selection_catalog.json").exists()


def test_forged_complete_control_state_fails_closed_without_repair(
    tmp_path: Path,
):
    cfg = _cfg(
        tmp_path,
        "thorough",
        backend="codex",
        run_id="recon-forged-complete",
    )
    scratch = Path(cfg["scratchpad"])
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(
                job["output"], job["role"], owner=job["agent_id"]
            ),
            encoding="utf-8",
        )
    D._merge_recon_worker_shards_and_arm_finalization(scratch, cfg)
    pending, issues = D._read_recon_finalization_state(scratch, cfg)
    assert issues == [] and pending is not None
    forged = dict(pending)
    forged["state"] = "COMPLETE"
    unsigned = {
        key: value for key, value in forged.items()
        if key != "receipt_digest"
    }
    forged["receipt_digest"] = D._stable_payload_digest(unsigned)
    (scratch / D._RECON_FINALIZATION_STATE_NAME).write_text(
        json.dumps(forged, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert not (scratch / "slither" / "primitive_status.md").exists()

    before = (scratch / D._RECON_FINALIZATION_STATE_NAME).read_bytes()
    with pytest.raises(
        D.ReconFinalizationPendingError,
        match="lacks authenticated finalizer products",
    ):
        D._resume_recon_finalization_before_prepass(scratch, dict(cfg))
    assert (scratch / D._RECON_FINALIZATION_STATE_NAME).read_bytes() == before
    assert not (scratch / "slither" / "primitive_status.md").exists()
    assert not (scratch / "skill_selection_catalog.json").exists()


def test_main_places_recon_finalization_barrier_before_every_live_write_path():
    source = Path(D.__file__).read_text(encoding="utf-8").split("def main(", 1)[1]
    barrier = source.index("_run_recon_startup_authority_barrier")
    prepass = source.index("from recon_prepass import run_recon_prepass")
    baseline = source.index("_ensure_recon_prepass_retry_baseline")
    phase_loop = source.index("for phase in phases:")
    assert barrier < prepass < baseline < phase_loop
    stale_degraded_repair = source.index(
        'checkpoint.degraded if name != "recon"', barrier
    )
    assert barrier < stale_degraded_repair < prepass

    recovery = source.index("artifact-recovery", phase_loop)
    finalizer = source.index("_finalize_recovered_recon", recovery)
    commit = source.index("_commit_phase_from_disk_debt", finalizer)
    assert recovery < finalizer < commit
    axis_recovery = source.index('if phase.name == "axis_coverage"', finalizer)
    fail_closed = source[finalizer:axis_recovery]
    assert "sys.exit(EXIT_DEGRADED)" in fail_closed
    assert "_commit_incomplete_phase_attempt" not in fail_closed


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_l1_recon_recovery_finalization_is_observational_and_replayable(
    tmp_path: Path,
    backend: str,
):
    cfg = _l1_recovery_cfg(
        tmp_path,
        backend=backend,
        run_id=f"l1-recon-recovery-finalize-{backend}",
    )
    scratch = Path(cfg["scratchpad"])
    before_bytes, before_bindings, before_issues = (
        D._recon_recovery_canonical_snapshot(scratch, cfg)
    )
    assert before_issues == []

    class InjectedCrash(BaseException):
        pass

    with pytest.raises(InjectedCrash, match="before_scope_leftover"):
        D._finalize_recovered_recon(
            scratch,
            dict(cfg),
            failure_injector=lambda point: (
                (_ for _ in ()).throw(InjectedCrash(point))
                if point == "before_scope_leftover"
                else None
            ),
        )
    assert D._finalize_recovered_recon(scratch, dict(cfg)) == []
    after_bytes, after_bindings, after_issues = (
        D._recon_recovery_canonical_snapshot(scratch, cfg)
    )
    assert after_issues == []
    assert after_bytes == before_bytes
    assert after_bindings == before_bindings


def test_l1_missing_scope_ack_stays_pending_without_degrade_or_advance(
    tmp_path: Path,
):
    cfg = _l1_recovery_cfg(
        tmp_path,
        backend="codex",
        run_id="l1-recon-missing-scope-ack",
    )
    project = Path(cfg["project_root"])
    module = project / "node" / "consensus"
    module.mkdir(parents=True)
    for index in range(10):
        (module / f"module_{index}.rs").write_text(
            f"pub fn entry_{index}() {{}}\n", encoding="utf-8"
        )
    scratch = Path(cfg["scratchpad"])
    before_bytes, before_bindings, before_issues = (
        D._recon_recovery_canonical_snapshot(scratch, cfg)
    )
    assert before_issues == []

    with pytest.raises(
        D.ReconFinalizationPendingError,
        match="fresh canonical successor",
    ):
        D._resume_recon_finalization_before_prepass(scratch, dict(cfg))
    pending, pending_issues = D._read_recon_finalization_state(scratch, cfg)
    assert pending_issues == []
    assert pending is not None
    assert pending["state"] == "REQUIRES_CANONICAL_SUCCESSOR"
    fresh = dict(cfg)
    assert D._resume_recon_finalization_before_prepass(scratch, fresh) is True
    assert fresh["_recon_l1_successor_predecessor_receipt"] == pending[
        "receipt_digest"
    ]
    assert not (scratch / "recon.degraded").exists()
    after_bytes, after_bindings, after_issues = (
        D._recon_recovery_canonical_snapshot(scratch, cfg)
    )
    assert after_issues == []
    assert after_bytes == before_bytes
    assert after_bindings == before_bindings


def test_l1_successor_requires_exact_predecessor_token_and_replay_is_not_transition(
    tmp_path: Path,
):
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    cfg = {
        "project_root": str(project), "scratchpad": str(scratch),
        "language": "rust", "mode": "thorough", "pipeline": "l1",
        "cli_backend": "codex", "_run_id": "l1-successor-token",
        "run_id": "l1-successor-token",
    }
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )
    assert D._merge_recon_worker_shards_and_arm_finalization(scratch, cfg)
    canonical, bindings, issues = D._recon_recovery_canonical_snapshot(
        scratch, cfg
    )
    assert issues == []
    required = D._recon_finalization_payload(
        config=cfg, canonical_bytes=canonical, canonical_bindings=bindings,
        state="REQUIRES_CANONICAL_SUCCESSOR",
    )
    D._atomic_driver_json(D._recon_finalization_state_path(scratch), required)

    with pytest.raises(
        D.CanonicalMergeAuthorityError, match="lacks exact predecessor",
    ):
        D._merge_recon_worker_shards_and_arm_finalization(scratch, dict(cfg))
    fresh = dict(cfg)
    assert D._resume_recon_finalization_before_prepass(scratch, fresh) is True
    # Even the correct predecessor capability cannot launch without the exact
    # authenticated retry attempt/work-unit plan, and no merge runs first.
    with pytest.raises(
        D.CanonicalMergeAuthorityError, match="supervised retry attempt",
    ):
        D._merge_recon_worker_shards_and_arm_finalization(scratch, fresh)
    replay, replay_issues = D._read_recon_finalization_state(scratch, fresh)
    assert replay_issues == []
    assert replay == required


@pytest.mark.parametrize("supervised_attempt", (2, 3))
def test_l1_required_predecessor_commits_authenticated_changed_successor(
    tmp_path: Path, supervised_attempt: int,
):
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    cfg = {
        "project_root": str(project), "scratchpad": str(scratch),
        "language": "rust", "mode": "thorough", "pipeline": "l1",
        "cli_backend": "claude", "claude_exec_mode": "pty",
        "_run_id": "l1-changed-successor",
        "run_id": "l1-changed-successor",
    }
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )
    assert D._merge_recon_worker_shards_and_arm_finalization(scratch, cfg)
    canonical, bindings, issues = D._recon_recovery_canonical_snapshot(scratch, cfg)
    assert issues == []
    required = D._recon_finalization_payload(
        config=cfg, canonical_bytes=canonical, canonical_bindings=bindings,
        state="REQUIRES_CANONICAL_SUCCESSOR",
    )
    D._atomic_driver_json(D._recon_finalization_state_path(scratch), required)
    assert D._resume_recon_finalization_before_prepass(scratch, cfg) is True

    phase = next(row for row in D.L1_PHASES if row.name == "recon")
    moved = D._quarantine_stale_on_retry(
        scratch, phase, ["recon.full_validator: L1 scope ack"],
        include_recon_canonical=True,
    )
    canonical_names = M._canonical_merge_output_names("l1")
    assert set(canonical_names[:-1]).issubset(set(moved))
    _write_exact_recon_retry_plan(scratch, cfg, phase)
    launch_authority = M.validate_recon_direct_retry_launch_authority(scratch, cfg)
    authority = M.validate_recon_direct_retry_launch_authority(scratch, cfg)
    (scratch / f"_prompt_recon.attempt{supervised_attempt}.md").write_text(
        "# RETRY ATTEMPT (driver-detected gate failure on previous attempt)\n"
        f"SCRATCHPAD: {scratch}\n", encoding="utf-8"
    )
    (scratch / f"_stdio_recon.attempt{supervised_attempt}.log").write_text(
        ("supervised retry event\n" * 30)
        + f"cwd={scratch}\n"
        + "outputs=" + ",".join(canonical_names[:-1]) + "\n"
        + '{"stop_reason":"end_turn","type":"assistant"}\n',
        encoding="utf-8",
    )
    for name in canonical_names[:-1]:
        (scratch / name).write_text(
            f"# Changed authenticated {name}\n\n" + ("successor evidence\n" * 30),
            encoding="utf-8",
        )
    outputs = D._finalize_recon_direct_fallback(
        scratch, cfg, require_retry_authority=True, semantic_attempt=2,
        supervised_attempt=supervised_attempt, launch_authority=authority,
    )
    assert outputs == list(canonical_names[:-1])
    pending, pending_issues = D._read_recon_finalization_state(scratch, cfg)
    assert pending_issues == []
    assert pending is not None and pending["state"] == "PENDING"
    transition = json.loads(
        (scratch / D._RECON_FINALIZATION_SUCCESSOR_NAME).read_text(
            encoding="utf-8"
        )
    )
    assert transition["state"] == "COMMITTED"
    assert transition["predecessor_receipt_digest"] == required["receipt_digest"]


@pytest.mark.parametrize(
    "crash_point",
    (
        "after_successor_preparing",
        "after_successor_canonical_commit",
        "after_successor_transition",
        "before_successor_pending",
    ),
)
@pytest.mark.parametrize("supervised_attempt", (2, 3))
def test_l1_changed_successor_recovers_every_transaction_seam(
    tmp_path: Path, crash_point: str, supervised_attempt: int,
):
    # Reuse the real producer setup above, keeping this fixture explicit so each
    # crash case owns an independent ledger/CAS/journal generation.
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    cfg = {
        "project_root": str(project), "scratchpad": str(scratch),
        "language": "rust", "mode": "thorough", "pipeline": "l1",
        "cli_backend": "codex", "_run_id": f"l1-crash-{crash_point}",
        "run_id": f"l1-crash-{crash_point}",
    }
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )
    D._merge_recon_worker_shards_and_arm_finalization(scratch, cfg)
    old_bytes, old_bindings, issues = D._recon_recovery_canonical_snapshot(
        scratch, cfg
    )
    assert issues == []
    required = D._recon_finalization_payload(
        config=cfg, canonical_bytes=old_bytes, canonical_bindings=old_bindings,
        state="REQUIRES_CANONICAL_SUCCESSOR",
    )
    D._atomic_driver_json(D._recon_finalization_state_path(scratch), required)
    D._resume_recon_finalization_before_prepass(scratch, cfg)
    phase = next(row for row in D.L1_PHASES if row.name == "recon")
    D._quarantine_stale_on_retry(
        scratch, phase, ["recon.full_validator: L1 scope ack"],
        include_recon_canonical=True,
    )
    _write_exact_recon_retry_plan(scratch, cfg, phase)
    launch_authority = M.validate_recon_direct_retry_launch_authority(scratch, cfg)
    canonical_names = M._canonical_merge_output_names("l1")
    (scratch / f"_prompt_recon.attempt{supervised_attempt}.md").write_text(
        "# RETRY ATTEMPT (driver-detected gate failure on previous attempt)\n"
        f"SCRATCHPAD: {scratch}\n", encoding="utf-8"
    )
    (scratch / f"_stdio_recon.attempt{supervised_attempt}.log").write_text(
        ("supervised retry event\n" * 30) + f"cwd={scratch}\n"
        + "outputs=" + ",".join(canonical_names[:-1]) + "\n"
        + '{"stop_reason":"end_turn","type":"assistant"}\n',
        encoding="utf-8",
    )
    for name in canonical_names[:-1]:
        (scratch / name).write_text(
            f"# Crash successor {name}\n\n" + ("successor evidence\n" * 30),
            encoding="utf-8",
        )

    class InjectedCrash(BaseException):
        pass

    with pytest.raises(InjectedCrash, match=crash_point):
        D._merge_recon_worker_shards_and_arm_finalization(
            scratch, cfg, supervised_attempt=supervised_attempt, semantic_attempt=2,
            successor_launch_authority=launch_authority,
            successor_failure_injector=lambda point: (
                (_ for _ in ()).throw(InjectedCrash(point))
                if point == crash_point else None
            ),
        )
    if crash_point == "after_successor_canonical_commit" and supervised_attempt == 2:
        state_path = scratch / D._RECON_FINALIZATION_STATE_NAME
        ledger_path = scratch / L.LEDGER_NAME
        state_before = state_path.read_bytes()
        ledger_before = ledger_path.read_bytes()
        manifest_path = (
            scratch / "_canonical_retry_generation" / "recon"
            / "attempt-2" / "manifest.json"
        )
        manifest_before = manifest_path.read_bytes()
        for mutation in ("run_id", "retry_plan_sha256", "extra"):
            tampered_manifest = json.loads(manifest_before)
            if mutation == "run_id":
                tampered_manifest["run_id"] = "foreign-run"
            elif mutation == "retry_plan_sha256":
                tampered_manifest["retry_plan_sha256"] = "0" * 64
            else:
                tampered_manifest["forged_extra"] = True
            # Deliberately retain the old claimed manifest_sha256.
            manifest_path.write_text(
                json.dumps(tampered_manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with pytest.raises(D.ReconCanonicalSuccessorRequired):
                D._resume_recon_finalization_before_prepass(scratch, dict(cfg))
            assert state_path.read_bytes() == state_before
            assert ledger_path.read_bytes() == ledger_before
            manifest_path.write_bytes(manifest_before)

        preparing_path = scratch / D._RECON_FINALIZATION_SUCCESSOR_NAME
        preparing_before = preparing_path.read_bytes()
        forged_preparing = json.loads(preparing_before)
        forged_preparing["launch_authority"]["predecessor_set_digest"] = "0" * 64
        forged_launch_digest = D._stable_payload_digest(
            forged_preparing["launch_authority"]
        )
        forged_preparing["launch_authority_digest"] = forged_launch_digest
        forged_preparing["launch_authority_manifest_digest"] = forged_launch_digest
        forged_unsigned = {
            key: value for key, value in forged_preparing.items()
            if key != "receipt_digest"
        }
        forged_preparing["receipt_digest"] = D._stable_payload_digest(
            forged_unsigned
        )
        preparing_path.write_text(
            json.dumps(forged_preparing, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(D.ReconCanonicalSuccessorRequired):
            D._resume_recon_finalization_before_prepass(scratch, dict(cfg))
        assert state_path.read_bytes() == state_before
        assert ledger_path.read_bytes() == ledger_before
        preparing_path.write_bytes(preparing_before)
    if crash_point == "after_successor_preparing":
        receipt_path = scratch / D._RECON_FINALIZATION_SUCCESSOR_NAME
        authentic_receipt = receipt_path.read_bytes()
        forged = json.loads(authentic_receipt)
        forged["supervised_attempt"] = 999
        unsigned = {
            key: value for key, value in forged.items()
            if key != "receipt_digest"
        }
        forged["receipt_digest"] = D._stable_payload_digest(unsigned)
        receipt_path.write_text(
            json.dumps(forged, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        state_before = (scratch / D._RECON_FINALIZATION_STATE_NAME).read_bytes()
        forged_cfg = dict(cfg)
        forged_cfg.pop("_recon_l1_successor_predecessor_receipt", None)
        with pytest.raises(
            D.ReconCanonicalSuccessorRequired,
            match="successor transaction receipt differs",
        ):
            D._resume_recon_finalization_before_prepass(scratch, forged_cfg)
        assert "_recon_l1_successor_predecessor_receipt" not in forged_cfg
        assert (scratch / D._RECON_FINALIZATION_STATE_NAME).read_bytes() == state_before
        receipt_path.write_bytes(authentic_receipt)
    fresh = dict(cfg)
    fresh.pop("_recon_l1_successor_predecessor_receipt", None)
    assert D._resume_recon_finalization_before_prepass(scratch, fresh) is True
    state, state_issues = D._read_recon_finalization_state(scratch, fresh)
    assert state_issues == [] and state is not None
    if crash_point == "after_successor_preparing":
        assert state["state"] == "REQUIRES_CANONICAL_SUCCESSOR"
        assert D._merge_recon_worker_shards_and_arm_finalization(
            scratch, fresh, supervised_attempt=supervised_attempt, semantic_attempt=2,
            successor_launch_authority=launch_authority,
        )
    else:
        assert state["state"] == "COMPLETE"
    new_bytes, _new_bindings, new_issues = D._recon_recovery_canonical_snapshot(
        scratch, fresh
    )
    assert new_issues == []
    assert new_bytes != old_bytes


@pytest.mark.parametrize("drift", ("manifest", "canonical", "transition", "ledger"))
def test_l1_successor_revalidates_every_post_transition_authority(
    tmp_path: Path, drift: str,
):
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    cfg = {
        "project_root": str(project), "scratchpad": str(scratch),
        "language": "rust", "mode": "thorough", "pipeline": "l1",
        "cli_backend": "codex", "_run_id": f"l1-post-transition-{drift}",
        "run_id": f"l1-post-transition-{drift}",
    }
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )
    D._merge_recon_worker_shards_and_arm_finalization(scratch, cfg)
    old_bytes, old_bindings, issues = D._recon_recovery_canonical_snapshot(
        scratch, cfg
    )
    assert issues == []
    required = D._recon_finalization_payload(
        config=cfg, canonical_bytes=old_bytes, canonical_bindings=old_bindings,
        state="REQUIRES_CANONICAL_SUCCESSOR",
    )
    D._atomic_driver_json(D._recon_finalization_state_path(scratch), required)
    D._resume_recon_finalization_before_prepass(scratch, cfg)
    phase = next(row for row in D.L1_PHASES if row.name == "recon")
    D._quarantine_stale_on_retry(
        scratch, phase, ["recon.full_validator: L1 scope ack"],
        include_recon_canonical=True,
    )
    _write_exact_recon_retry_plan(scratch, cfg, phase)
    launch_authority = M.validate_recon_direct_retry_launch_authority(scratch, cfg)
    canonical_names = M._canonical_merge_output_names("l1")
    (scratch / "_prompt_recon.attempt2.md").write_text(
        "# RETRY ATTEMPT (driver-detected gate failure on previous attempt)\n"
        f"SCRATCHPAD: {scratch}\n", encoding="utf-8"
    )
    (scratch / "_stdio_recon.attempt2.log").write_text(
        ("supervised retry event\n" * 30) + f"cwd={scratch}\n"
        + "outputs=" + ",".join(canonical_names[:-1]) + "\n"
        + '{"stop_reason":"end_turn","type":"assistant"}\n',
        encoding="utf-8",
    )
    for name in canonical_names[:-1]:
        (scratch / name).write_text(
            f"# TOCTOU successor {name}\n\n" + ("successor evidence\n" * 30),
            encoding="utf-8",
        )

    restored: tuple[Path, bytes] | None = None

    def drift_after_transition(point: str) -> None:
        nonlocal restored
        if point != "after_successor_transition":
            return
        if drift == "manifest":
            path = scratch / "_canonical_retry_generation/recon/attempt-2/manifest.json"
            restored = (path, path.read_bytes())
            payload = json.loads(restored[1])
            payload["run_id"] = "foreign-run"  # retain claimed sha
            path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        elif drift == "canonical":
            path = scratch / "recon_summary.md"
            restored = (path, path.read_bytes())
            path.write_bytes(restored[1] + b"\nTOCTOU drift\n")
        elif drift == "transition":
            path = scratch / D._RECON_FINALIZATION_SUCCESSOR_NAME
            restored = (path, path.read_bytes())
            payload = json.loads(restored[1])
            payload["forged_extra"] = True
            path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        else:
            path = scratch / L.LEDGER_NAME
            restored = (path, path.read_bytes())
            payload = json.loads(restored[1])
            identity = "scratchpad:recon_summary.md"
            payload["artifact_bindings"][identity]["sha256"] = "0" * 64
            path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(D.CanonicalMergeAuthorityError):
        D._merge_recon_worker_shards_and_arm_finalization(
            scratch, cfg, supervised_attempt=2, semantic_attempt=2,
            successor_launch_authority=launch_authority,
            successor_failure_injector=drift_after_transition,
        )
    state, state_issues = D._read_recon_finalization_state(scratch, cfg)
    assert state_issues == [] and state == required
    transition = json.loads(
        (scratch / D._RECON_FINALIZATION_SUCCESSOR_NAME).read_text(encoding="utf-8")
    )
    assert transition["state"] == "COMMITTED"
    assert restored is not None
    restored[0].write_bytes(restored[1])
    assert D._resume_recon_finalization_before_prepass(scratch, dict(cfg)) is True


def test_recon_outer_recovery_foreign_disposition_preserves_paths_and_ledger(
    tmp_path: Path,
):
    assert "_artifact_recovery_foreign_disposition" in D.main.__code__.co_names
    assert "_later_phase_artifact_observation" in D.main.__code__.co_names
    cfg = _merged_sc_cfg(
        tmp_path,
        backend="codex",
        run_id="recon-outer-recovery-foreign",
    )
    scratch = Path(cfg["scratchpad"])
    foreign = scratch / "analysis_future.md"
    _publish_driver_fixture_output(
        cfg,
        phase="breadth",
        work_unit_id="foreign_fixture",
        name=foreign.name,
        raw=b"pre-existing later-phase evidence\n",
    )
    # A later-looking filename without ledger ownership is not authority and
    # must not be classified by unsafe naming heuristics.
    (scratch / "verify_unbound.md").write_bytes(b"unbound filename bait\n")
    discovered = D._existing_later_phase_artifacts(
        scratch,
        cfg["project_root"],
        list(D.SC_PHASES),
        "recon",
        "sc",
        run_id=cfg["_run_id"],
    )
    assert discovered == [foreign.name]
    before_ledger = (scratch / L.LEDGER_NAME).read_bytes()
    before_paths = sorted(
        path.relative_to(scratch).as_posix()
        for path in scratch.rglob("*")
    )

    moved, failed = D._artifact_recovery_foreign_disposition(
        phase_name="recon",
        scratchpad=scratch,
        project_root=cfg["project_root"],
        foreign=tuple(discovered),
    )
    assert (moved, failed) == ([], [])
    assert foreign.read_bytes() == b"pre-existing later-phase evidence\n"
    assert sorted(
        path.relative_to(scratch).as_posix()
        for path in scratch.rglob("*")
    ) == before_paths
    assert (scratch / L.LEDGER_NAME).read_bytes() == before_ledger
    assert not (scratch / "_overflow").exists()


def test_later_phase_discovery_rejects_legacy_owner_phase_forgery_and_cross_run(
    tmp_path: Path,
):
    cfg = _merged_sc_cfg(
        tmp_path, backend="codex", run_id="foreign-authority-current"
    )
    scratch = Path(cfg["scratchpad"])
    _publish_driver_fixture_output(
        cfg,
        phase="breadth",
        work_unit_id="valid_future",
        name="analysis_future.md",
        raw=b"authenticated future output\n",
    )
    ledger_path = scratch / L.LEDGER_NAME
    state = json.loads(ledger_path.read_text(encoding="utf-8"))
    # Reviewer's proof: changing only a legacy artifact row's owner_phase must
    # not turn a recon-owned object into later-phase authority.
    state["artifacts"]["recon_summary.md"]["owner_phase"] = "breadth"
    ledger_path.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    foreign, issues = D._later_phase_artifact_observation(
        scratch, cfg["project_root"], list(D.SC_PHASES), "recon", "sc",
        run_id=cfg["_run_id"],
    )
    assert foreign == ["analysis_future.md"]
    assert any("legacy projection disagrees" in issue for issue in issues)
    assert D._existing_later_phase_artifacts(
        scratch, cfg["project_root"], list(D.SC_PHASES), "recon", "sc",
        run_id="foreign-run",
    ) == []


def test_completed_recon_restart_allows_authenticated_later_phase_authority(
    tmp_path: Path,
):
    cfg = _merged_sc_cfg(
        tmp_path, backend="codex", run_id="completed-recon-with-breadth"
    )
    scratch = Path(cfg["scratchpad"])
    assert D._finalize_recovered_recon(scratch, dict(cfg)) == []
    _publish_driver_fixture_output(
        cfg,
        phase="breadth",
        work_unit_id="completed_restart_future",
        name="analysis_future.md",
        raw=b"legitimate completed breadth output\n",
    )
    assert D._run_recon_startup_authority_barrier(
        scratch,
        dict(cfg),
        list(D.SC_PHASES),
        recon_completed=True,
    ) is True


def test_startup_foreign_observation_stops_before_finalizer_and_preserves_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    cfg = _merged_sc_cfg(
        tmp_path, backend="codex", run_id="startup-foreign-no-spawn"
    )
    scratch = Path(cfg["scratchpad"])
    _publish_driver_fixture_output(
        cfg,
        phase="breadth",
        work_unit_id="startup_future",
        name="analysis_future.md",
        raw=b"future authority\n",
    )
    checkpoint = scratch / "checkpoint.json"
    checkpoint.write_bytes(b'{"sentinel":"unchanged"}\n')
    before = {
        path.relative_to(scratch).as_posix(): path.read_bytes()
        for path in scratch.rglob("*") if path.is_file()
    }
    monkeypatch.setattr(
        D,
        "_resume_recon_finalization_before_prepass",
        _forbid_recovery_mutation("startup finalizer/model/provider"),
    )
    assert "_run_recon_startup_authority_barrier" in D.main.__code__.co_names
    with pytest.raises(
        D.ReconRecoveryForeignArtifactsError,
        match="analysis_future.md",
    ):
        D._run_recon_startup_authority_barrier(
            scratch, dict(cfg), list(D.SC_PHASES)
        )
    after = {
        path.relative_to(scratch).as_posix(): path.read_bytes()
        for path in scratch.rglob("*") if path.is_file()
    }
    assert after == before


def test_same_run_recomputed_finalization_receipt_tamper_is_not_repaired(
    tmp_path: Path,
):
    cfg = _merged_sc_cfg(
        tmp_path, backend="codex", run_id="finalization-recomputed-tamper"
    )
    scratch = Path(cfg["scratchpad"])
    state_path = scratch / D._RECON_FINALIZATION_STATE_NAME
    armed, arm_issues = D._ensure_recon_finalization_pending(scratch, cfg)
    assert arm_issues == [] and armed is not None
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["canonical"][0]["size"] += 1
    unsigned = {key: value for key, value in payload.items() if key != "receipt_digest"}
    payload["receipt_digest"] = D._stable_payload_digest(unsigned)
    state_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    tampered = state_path.read_bytes()
    with pytest.raises(
        D.ReconFinalizationPendingError,
        match="differs from its authenticated canonical generation",
    ):
        D._resume_recon_finalization_before_prepass(scratch, dict(cfg))
    assert state_path.read_bytes() == tampered


def test_recon_worker_complete_requires_assigned_job_markers(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    job = D._recon_worker_jobs(cfg)[0]
    (scratch / job["output"]).write_text(
        _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
        encoding="utf-8",
    )

    ok, reasons = D._recon_worker_complete(scratch, job["output"], job)
    assert ok, reasons

    wrong_job = dict(job)
    wrong_job["agent_id"] = "wrong-owner"
    ok, reasons = D._recon_worker_complete(scratch, job["output"], wrong_job)
    assert not ok
    assert "missing marker PLAMEN_OWNER: wrong-owner" in reasons


def test_recon_worker_jobs_match_documented_mode_counts(tmp_path: Path):
    assert len(D._recon_worker_jobs(_cfg(tmp_path, "light"))) == 2
    assert len(D._recon_worker_jobs(_cfg(tmp_path, "core"))) == 4
    assert len(D._recon_worker_jobs(_cfg(tmp_path, "thorough"))) == 4


def test_template_recon_roles_emit_machine_readable_required_skills(tmp_path: Path):
    for mode, role in (("light", "inventory_templates"),
                       ("thorough", "templates_patterns")):
        cfg = _cfg(tmp_path, mode)
        scratch = Path(cfg["scratchpad"])
        job = next(j for j in D._recon_worker_jobs(cfg) if j["role"] == role)
        prompt = D._build_recon_worker_prompt(
            job=job,
            scratchpad=scratch,
            project_root=cfg["project_root"],
            config=cfg,
            attempt=1,
        )
        assert "PLAMEN_SIGNALS" in prompt
        assert '"required_skills"' in prompt
        assert "producer/consumer contract" in prompt
        assert "Closed bindable skill catalog" in prompt
        assert "MUST be copied byte-for-byte" in prompt
        assert "`CENTRALIZATION_RISK`" in prompt
        assert "`UPGRADEABLE_PROXY`" not in prompt
        # Standalone niches bind through the separate niche-trigger authority,
        # never through the Required=YES skill-selection channel.
        assert "`CALLBACK_RECEIVER_SAFETY`" not in prompt
        assert "`MULTI_STEP_OPERATION_SAFETY`" not in prompt
        assert "`SEMANTIC_CONSISTENCY_AUDIT`" not in prompt


def test_template_recon_role_retries_invented_skill_ids_before_commit(
    tmp_path: Path,
):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    job = next(
        row for row in D._recon_worker_jobs(cfg)
        if row["role"] == "templates_patterns"
    )
    base = _worker_shard(
        job["output"], job["role"], owner=job["agent_id"]
    )
    output = scratch / job["output"]
    output.write_text(
        base.replace(
            '{"required_skills":[]}',
            '{"required_skills":["UPGRADEABLE_PROXY"]}',
        ),
        encoding="utf-8",
    )
    ok, reasons = D._recon_worker_complete(
        scratch, job["output"], job, cfg
    )
    assert not ok
    assert any("UNKNOWN_SKILL_ID" in reason for reason in reasons)

    output.write_text(
        base.replace(
            '{"required_skills":[]}',
            '{"required_skills":["CALLBACK_RECEIVER_SAFETY"]}',
        ),
        encoding="utf-8",
    )
    ok, reasons = D._recon_worker_complete(
        scratch, job["output"], job, cfg
    )
    assert not ok
    assert any("UNKNOWN_SKILL_ID" in reason for reason in reasons)

    output.write_text(
        base.replace(
            '{"required_skills":[]}',
            '{"required_skills":["CENTRALIZATION_RISK"]}',
        ),
        encoding="utf-8",
    )
    ok, reasons = D._recon_worker_complete(
        scratch, job["output"], job, cfg
    )
    assert ok, reasons


def test_recon_selection_transaction_gate_is_roster_derived(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough", backend="claude")
    scratch = Path(cfg["scratchpad"])
    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")
    job = next(
        row for row in D._recon_worker_jobs(cfg)
        if row["role"] == "templates_patterns"
    )
    contract, _launch = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=cfg,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        agent_id=str(job["agent_id"]),
        agent_role=str(job["role"]),
        output=str(job["output"]),
        timeout_s=900,
        attempt=1,
    )
    context = D._recon_selection_staged_gate_context(
        phase=phase,
        config=cfg,
        contract=contract,
        expected_outputs=(str(job["output"]),),
        attempt=1,
    )
    assert context is not None
    assert context["output"] == job["output"]
    assert "CENTRALIZATION_RISK" in context["allowed_skill_ids"]
    assert "UPGRADEABLE_PROXY" not in context["allowed_skill_ids"]

    ordinary = next(
        row for row in D._recon_worker_jobs(cfg)
        if row["role"] == "build_static"
    )
    ordinary_contract, _ = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=cfg,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        agent_id=str(ordinary["agent_id"]),
        agent_role=str(ordinary["role"]),
        output=str(ordinary["output"]),
        timeout_s=900,
        attempt=1,
    )
    assert D._recon_selection_staged_gate_context(
        phase=phase,
        config=cfg,
        contract=ordinary_contract,
        expected_outputs=(str(ordinary["output"]),),
        attempt=1,
    ) is None


def test_recon_worker_prompt_is_single_output_and_no_later_phase_leak(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    job = D._recon_worker_jobs(cfg)[0]

    prompt = D._build_recon_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        attempt=1,
    )

    assert job["output"] in prompt
    assert "spawn_manifest.md" not in prompt
    assert "Use the Task tool" not in prompt
    assert "MUST spawn" not in prompt
    assert "canonical recon files. The driver merges" in prompt
    assert "Write exactly this file and no other scratchpad artifact" in prompt
    assert "## Command Boundary" in prompt
    assert "You may run at most one initial compile command" in prompt
    assert "Build-root discovery is driver-owned in restricted Claude" in prompt
    assert "guessed root-level manifest such as `foundry.toml`" in prompt
    assert "you may move one or two parents" not in prompt
    assert "diagnose at most two distinct blockers using read-only" in prompt
    assert "Dependency installation" in prompt and "forbidden" in prompt
    assert "stop repairing" not in prompt
    assert "must not run any command matching: `forge test`" in prompt
    assert "Medusa" in prompt
    assert "Do not run tests, PoCs, fuzzers" in prompt


def test_recon_retry_prompt_binds_retry_work_unit_identity(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough")
    cfg["cli_backend"] = "codex"
    scratch = Path(cfg["scratchpad"])
    job = D._recon_worker_jobs(cfg)[0]

    prompt = D._build_recon_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        attempt=2,
    )

    assert f"/recon/worker.{job['agent_id'].lower()}.attempt-0002" in prompt


def test_external_recon_worker_has_network_without_mcp_launch_policy(
    tmp_path: Path,
    monkeypatch,
):
    cfg = _cfg(tmp_path, "thorough")
    cfg["cli_backend"] = "claude"
    scratch = Path(cfg["scratchpad"])
    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": "claude",
            "model": "fixture-model",
            "timeout_s": 900,
            "exec_mode": "headless",
        },
    )

    _, base_launch = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=cfg,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        agent_id="R1",
        output="recon_build_static.md",
        timeout_s=900,
    )
    _, research_launch = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=cfg,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        agent_id="R-EXT",
        agent_role="external_dependency_research",
        output="recon_external_dependency_research.md",
        exact_inputs=(
            "external_dependency_obligations.json",
            "recon_build_static.md",
            "recon_design_context.md",
            "recon_inventory_surface.md",
            "recon_templates_patterns.md",
        ),
        timeout_s=900,
    )

    assert base_launch.tool_policy == ("filesystem",)
    assert research_launch.tool_policy == (
        "filesystem",
        "network",
    )


@pytest.mark.parametrize(
    ("backend", "worker_name"),
    (
        ("codex", "_run_one_codex_exec"),
        ("claude-headless", "_run_one_claude_headless_breadth_worker"),
    ),
)
def test_headless_recon_fanout_executes_every_role_transactionally(
    tmp_path: Path,
    monkeypatch,
    backend: str,
    worker_name: str,
):
    cfg = _cfg(
        tmp_path,
        "thorough",
        backend="codex" if backend == "codex" else "claude",
        run_id="fixture-run",
    )
    scratch = Path(cfg["scratchpad"])
    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")
    calls: list[str] = []
    monkeypatch.setattr(
        D,
        "_enforce_recon_current_dispatch_authority",
        lambda *_args, **_kwargs: None,
    )

    monkeypatch.setattr(
        D,
        "_run_recon_dependency_research_headless",
        lambda **_kwargs: {
            "status": "not_applicable",
            "researched": 0,
            "unresolved": 0,
        },
    )

    def worker(**kwargs):
        job = (
            kwargs.get("job")
            or next(
                row for row in D._recon_worker_jobs(cfg)
                if kwargs["expected_outputs"][0] == row["output"]
            )
        )
        output = str(job["output"])
        calls.append(output)
        (scratch / output).write_text(
            _worker_shard(
                output,
                str(job["role"]),
                owner=str(job["agent_id"]),
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(D, worker_name, worker)
    rc = D._run_recon_backend_fanout(
        backend=backend,
        phase=phase,
        config=cfg,
        scratchpad=scratch,
        attempt=1,
        timeout=30,
        effective_model="fixture-model",
    )

    assert rc == 0
    assert set(calls) == {
        str(job["output"]) for job in D._recon_worker_jobs(cfg)
    }


def test_non_build_recon_roles_are_told_not_to_shell(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    job = next(j for j in D._recon_worker_jobs(cfg) if j["role"] == "design_context")

    prompt = D._build_recon_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        attempt=1,
    )

    assert "For roles other than `build_static` and `context_static`: do not run shell" in prompt
    assert "Do not write design_context.md directly" in prompt


def test_recon_command_guard_allows_build_but_blocks_later_phase_tools(
    tmp_path: Path,
    monkeypatch,
):
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()

    def fake_which(name: str, path: str | None = None):
        if name in {"forge", "npx", "npm", "yarn", "git", "slither"}:
            return f"C:/tools/{name}.exe"
        return None

    monkeypatch.setattr(D.shutil, "which", fake_which)
    guarded = D._install_recon_command_guard(scratch, {"PATH": "C:/tools"})
    guard_dir = scratch / "_recon_command_guard"

    assert guarded["PATH"].startswith(str(guard_dir))
    assert guarded["PLAMEN_REAL_FORGE"] == "C:/tools/forge.exe"
    forge = (guard_dir / "forge").read_text(encoding="utf-8")
    assert "concurrent forge build already running" in forge
    assert "remappings|config|clean" in forge
    assert "forge install mutates bound audit inputs" in forge
    assert "test|coverage|snapshot|script" in forge
    assert "outside recon build-repair allowlist" in forge
    npm = (guard_dir / "npm").read_text(encoding="utf-8")
    assert "dependency installation mutates bound audit inputs" in npm
    git = (guard_dir / "git").read_text(encoding="utf-8")
    assert "submodule update mutates bound audit inputs" in git
    svm = (guard_dir / "svm").read_text(encoding="utf-8")
    assert "compiler installation/selection mutates the bound toolchain" in svm
    solc_select = (guard_dir / "solc-select").read_text(encoding="utf-8")
    assert "compiler installation/selection mutates the bound toolchain" in solc_select
    slither = (guard_dir / "slither").read_text(encoding="utf-8")
    assert "slither target/detector runs are not allowed" in slither
    medusa = (guard_dir / "medusa").read_text(encoding="utf-8")
    assert "fuzzer/verification command is not allowed" in medusa


def test_recon_build_role_is_told_never_to_mutate_bound_inputs(tmp_path: Path):
    cfg = _cfg(tmp_path, "light")
    scratch = Path(cfg["scratchpad"])
    job = next(j for j in D._recon_worker_jobs(cfg) if j["role"] == "context_static")

    prompt = D._build_recon_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        attempt=1,
    )

    assert "Never mutate the bound project inputs" in prompt
    assert "forge install" in prompt and "forbidden" in prompt


def test_codex_recon_retains_shell_only_bounded_build_root_guidance(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough", backend="codex")
    scratch = Path(cfg["scratchpad"])
    job = next(j for j in D._recon_worker_jobs(cfg) if j["role"] == "build_static")

    prompt = D._build_recon_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        attempt=1,
    )

    assert "a runtime that exposes a shell execution tool may move" in prompt
    assert "nearest directory containing `foundry.toml`" in prompt
    assert "Build-root discovery is driver-owned in restricted Claude" not in prompt


def test_worker_pool_status_has_no_empty_counter_segment():
    status = D._format_worker_pool_progress_status(
        complete=0,
        total=4,
        active_outputs=[
            "recon_build_static.md",
            "recon_design_context.md",
            "recon_inventory_surface.md",
            "recon_templates_patterns.md",
        ],
        queued=0,
        phase_label="recon",
    )

    assert "worker pool:;" not in status
    assert status.startswith("worker pool: 4 running; 0 queued/missing;")
    assert "active recon_build_static, recon_design_context, recon_inventory_surface +1" in status


def test_recon_worker_merge_writes_canonical_gate_outputs(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"]),
            encoding="utf-8",
        )

    written = M._merge_recon_worker_shards(scratch, cfg)

    assert set(written) >= {
        "recon_summary.md",
        "design_context.md",
        "attack_surface.md",
        "template_recommendations.md",
        "build_status.md",
    }
    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")
    passed, missing = D.gate_passes(scratch, cfg["project_root"], phase)
    assert passed, missing
    hard, soft = _validate_recon_content_structure(scratch)
    assert hard == []
    assert "spawn_manifest.md" not in (scratch / "recon_summary.md").read_text(
        encoding="utf-8"
    )


def test_recon_worker_merge_preserves_structured_skill_authority(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    signal = '<!-- PLAMEN_SIGNALS: {"required_skills":["ORACLE_ANALYSIS"]} -->'
    empty_signal = '<!-- PLAMEN_SIGNALS: {"required_skills":[]} -->'
    for job in D._recon_worker_jobs(cfg):
        body = _worker_shard(job["output"], job["role"], owner=job["agent_id"])
        if job["role"] == "templates_patterns":
            body = body.replace(empty_signal, signal, 1)
        (scratch / job["output"]).write_text(body, encoding="utf-8")

    M._merge_recon_worker_shards(scratch, cfg)

    canonical = (scratch / "template_recommendations.md").read_text(encoding="utf-8")
    assert signal in canonical
    assert "PLAMEN_STATUS" not in canonical
    receipt = json.loads(
        (scratch / "recon_signal_transform_receipt.json").read_text(encoding="utf-8")
    )
    template_row = next(
        row for row in receipt["transforms"]
        if row["source"] == "recon_templates_patterns.md"
    )
    assert template_row["structured_signal_blocks_before"] == 1
    assert template_row["structured_signal_blocks_after"] == 1
    assert template_row["authority_loss"] is False


def test_recon_marker_stripper_preserves_malformed_signal_for_loud_validation():
    signal = "<!-- PLAMEN_SIGNALS: {bad json} -->"
    body = "<!-- PLAMEN_STATUS: COMPLETE -->\n" + signal + "\n"
    stripped = M._strip_recon_worker_markers(body)
    assert "PLAMEN_STATUS" not in stripped
    assert signal in stripped


def test_recon_worker_merge_strips_prepass_overwrite_marker(tmp_path: Path):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    assert M._PREPASS_MARKER in (
        scratch / "design_context.md"
    ).read_text(encoding="utf-8")
    for job in D._recon_worker_jobs(cfg):
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"]),
            encoding="utf-8",
        )

    M._merge_recon_worker_shards(scratch, cfg)

    merged = (scratch / "design_context.md").read_text(encoding="utf-8")
    assert not merged.startswith(M._PREPASS_MARKER)
    assert "Recon Worker Evidence" in merged


def test_recon_worker_pool_merges_after_last_retry_completes_missing_shard(
    tmp_path: Path,
    monkeypatch,
):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    jobs = D._recon_worker_jobs(cfg)
    missing = jobs[-1]
    for job in jobs[:-1]:
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )

    def fake_run_single(**kwargs):
        job = kwargs["job"]
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )
        return {
            "output": job["output"],
            "rc": 0,
            "status": "complete",
            "reasons": [],
        }

    monkeypatch.setattr(D, "_run_single_recon_worker_pty", fake_run_single)
    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")

    rc = D._run_recon_worker_pool_pty(
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=1,
        quiescence_s=0.1,
        attempt=1,
    )

    assert rc == 0
    assert (scratch / missing["output"]).exists()
    assert (scratch / "recon_summary.md").exists()


def test_recon_worker_pool_passes_pool_wide_allowed_outputs(
    tmp_path: Path,
    monkeypatch,
):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    jobs = D._recon_worker_jobs(cfg)
    expected_outputs = {job["output"] for job in jobs}
    seen: list[set[str]] = []

    def fake_run_single(**kwargs):
        job = kwargs["job"]
        seen.append(set(kwargs["allowed_outputs"]))
        assert set(kwargs["allowed_outputs"]) == expected_outputs
        assert D._worker_artifact_name_allowed(
            f"{jobs[-1]['output']}.tmp.24284.0e805d3fed86",
            set(kwargs["allowed_outputs"]),
        )
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )
        return {
            "output": job["output"],
            "rc": 0,
            "status": "complete",
            "reasons": [],
        }

    monkeypatch.setattr(D, "_run_single_recon_worker_pty", fake_run_single)
    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")

    rc = D._run_recon_worker_pool_pty(
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=1,
        quiescence_s=0.1,
        attempt=1,
    )

    assert rc == 0
    assert len(seen) == len(jobs)


def test_recon_worker_pool_protects_preexisting_canonical_inputs(
    tmp_path: Path,
    monkeypatch,
):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    jobs = D._recon_worker_jobs(cfg)
    assert M._PREPASS_MARKER in (
        scratch / "attack_surface.md"
    ).read_text(encoding="utf-8")
    seen_protected: list[set[str]] = []

    def fake_run_single(**kwargs):
        job = kwargs["job"]
        protected = set(kwargs["protected_input_names"])
        seen_protected.append(protected)
        assert "attack_surface.md" in protected
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )
        return {
            "output": job["output"],
            "rc": 0,
            "status": "complete",
            "reasons": [],
        }

    monkeypatch.setattr(D, "_run_single_recon_worker_pty", fake_run_single)
    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")

    rc = D._run_recon_worker_pool_pty(
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=1,
        quiescence_s=0.1,
        attempt=1,
    )

    assert rc == 0
    assert len(seen_protected) == len(jobs)


def test_recon_worker_pool_fails_closed_when_retry_budget_exhausts_partial_shards(
    tmp_path: Path,
    monkeypatch,
):
    # 2 of 4 shards complete on disk; the remaining 2 never reach COMPLETE,
    # so the retry budget exhausts. The canonical transaction must not invent
    # authority for either missing shard.
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    prepass_summary = (scratch / "recon_summary.md").read_bytes()
    jobs = D._recon_worker_jobs(cfg)
    completed = jobs[:2]
    stuck = jobs[2:]
    for job in completed:
        (scratch / job["output"]).write_text(
            _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
            encoding="utf-8",
        )

    def fake_run_single(**kwargs):
        # Stuck workers never produce their output; status stays incomplete so
        # the worker pool cannot finalize via the all-complete branches.
        job = kwargs["job"]
        return {
            "output": job["output"],
            "rc": -2,
            "status": "incomplete",
            "reasons": ["never reached COMPLETE"],
        }

    monkeypatch.setattr(D, "_run_single_recon_worker_pty", fake_run_single)
    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")

    rc = D._run_recon_worker_pool_pty(
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=1,
        quiescence_s=0.1,
        attempt=1,
    )

    assert rc == -4
    for job in stuck:
        assert not (scratch / job["output"]).exists()
    assert (scratch / "recon_summary.md").read_bytes() == prepass_summary


def test_recon_worker_timeout_uses_full_scaled_budget_not_2400_cap(
    tmp_path: Path,
    monkeypatch,
):
    # The per-worker timeout must equal max(900, scaled) — no 2400 cap — so a
    # large scaled budget reaches the worker, and a tiny scaled budget floors
    # at 900 (parity with breadth/rescan/depth).
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    jobs = D._recon_worker_jobs(cfg)
    seen_timeouts: list[float] = []

    def make_fake(record: list[float]):
        def fake_run_single(**kwargs):
            record.append(kwargs["timeout"])
            job = kwargs["job"]
            (scratch / job["output"]).write_text(
                _worker_shard(job["output"], job["role"], owner=job["agent_id"]),
                encoding="utf-8",
            )
            return {
                "output": job["output"],
                "rc": 0,
                "status": "complete",
                "reasons": [],
            }

        return fake_run_single

    phase = next(ph for ph in D.SC_PHASES if ph.name == "recon")

    large = 9000.0
    monkeypatch.setattr(D, "_run_single_recon_worker_pty", make_fake(seen_timeouts))
    rc = D._run_recon_worker_pool_pty(
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=large,
        quiescence_s=0.1,
        attempt=1,
    )
    assert rc == 0
    assert seen_timeouts, "expected at least one worker invocation"
    # No 2400 cap: a large scaled budget passes through verbatim.
    assert all(t == large for t in seen_timeouts)
    assert all(t > 2400 for t in seen_timeouts)

    # Use an independent authenticated prepass and ledger for the floor case.
    # Deleting only the ledger would leave producer-less canonical bytes.
    cfg = _cfg(tmp_path / "floor", "thorough")
    scratch = Path(cfg["scratchpad"])
    tiny_timeouts: list[float] = []
    monkeypatch.setattr(D, "_run_single_recon_worker_pty", make_fake(tiny_timeouts))
    rc = D._run_recon_worker_pool_pty(
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=5,
        quiescence_s=0.1,
        attempt=1,
    )
    assert rc == 0
    assert tiny_timeouts
    # Tiny scaled budget floors at 900.
    assert all(t == 900 for t in tiny_timeouts)


def test_recon_inventory_surface_prompt_builds_on_mechanical_no_reenumeration(
    tmp_path: Path,
):
    cfg = _cfg(tmp_path, "thorough")
    scratch = Path(cfg["scratchpad"])
    job = next(
        j for j in D._recon_worker_jobs(cfg) if j["role"] == "inventory_surface"
    )

    prompt = D._build_recon_worker_prompt(
        job=job,
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        attempt=1,
    )

    # The three mechanical enumeration filenames appear in readable-inputs.
    assert "contract_inventory.md" in prompt
    assert "function_list.md" in prompt
    assert "state_variables.md" in prompt
    # Enumeration Gaps recall guard + generic-mechanism tokens.
    assert "Enumeration Gaps" in prompt
    assert "inline assembly" in prompt
    assert "delegatecall" in prompt
    assert "fallback()/receive()" in prompt
    # No longer instructs full source re-enumeration.
    assert "DO NOT re-enumerate" in prompt


def test_depth_worker_pool_finalizes_when_last_attempt_completes_rows(
    tmp_path: Path,
    monkeypatch,
):
    cfg = _cfg(tmp_path, "core")
    cfg["pty_continuation_budget"] = 1
    scratch = Path(cfg["scratchpad"])
    job = {
        "agent_id": "depth-token-flow",
        "role": "token_flow",
        "output": "depth_token_flow_findings.md",
        "category": "standard",
        "focus": "token flow",
    }
    open_sequence = [[job], [], []]

    monkeypatch.setattr(D, "_depth_worker_jobs", lambda sp, config: [job])
    monkeypatch.setattr(
        D,
        "_depth_open_jobs",
        lambda sp, phase, jobs: open_sequence.pop(0) if open_sequence else [],
    )
    monkeypatch.setattr(
        D,
        "_run_depth_worker_batch",
        lambda **kwargs: (0, [{"output": job["output"], "status": "complete"}]),
    )
    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda sp, config: [])
    monkeypatch.setattr(D, "gate_passes", lambda sp, root, phase: (True, []))

    rc = D._run_depth_worker_pool_pty(
        scratchpad=scratch,
        project_root=cfg["project_root"],
        config=cfg,
        phase=next(ph for ph in D.SC_PHASES if ph.name == "depth"),
        base_cmd=[],
        env={},
        timeout=1,
        quiescence_s=0.1,
        attempt=1,
    )

    assert rc == 0
