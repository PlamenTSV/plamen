from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as D
from verifier_work_roster import VerifierLaunchSpec


def _verifier_spec(root: Path, prompt: bytes) -> VerifierLaunchSpec:
    return VerifierLaunchSpec(
        work_unit_id="verify-worker-0001",
        work_unit_resume_digest="a" * 64,
        backend="claude",
        model="claude-opus-4-1",
        transport="headless",
        argv=("claude",),
        cwd=str(root.resolve()),
        timeout_seconds=30,
        prompt_sha256=hashlib.sha256(prompt).hexdigest(),
        prompt_size_bytes=len(prompt),
        expected_output_files=("verify-H-01.md",),
        tool_policy_digest="b" * 64,
        foreground_only=True,
        background_children_allowed=False,
        child_join_policy="REQUIRE_JOIN_BEFORE_RECEIPT",
        process_group_policy="ISOLATED_PROCESS_GROUP",
        orphan_policy="TERMINATE_TREE_AND_RETAIN_DEBT",
    )


def test_dynamic_claude_verifier_reaches_provider_parent_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompt = b"verify the assigned finding"
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_bytes(prompt)
    observed: dict[str, object] = {}
    authority = SimpleNamespace(
        preparation=object(),
        base_argv_template=("claude", "-p", "--model", "fixture-model"),
        public_arguments={
            "environment": {},
            "environment_allowlist": (),
        },
        runtime_local_inputs={"ambient_environment": {}},
        bound_settings_bytes=None,
        selected_mcp_config_bytes=None,
    )
    boundary = ({"binding": "startup"}, {"platform": "fixture"})
    monkeypatch.setattr(
        D, "_replay_explicit_claude_headless_launch_boundary",
        lambda **_kwargs: boundary,
    )
    monkeypatch.setattr(
        D, "_compile_claude_driver_provider_authority",
        lambda **kwargs: observed.setdefault("compiled", kwargs) or authority,
    )
    # setdefault returns the dict, so use an explicit compiler for clarity.
    def compile_provider(**kwargs):
        observed["compiled"] = kwargs
        return authority
    monkeypatch.setattr(D, "_compile_claude_driver_provider_authority", compile_provider)
    monkeypatch.setattr(
        D, "_security_obligation_source_snapshot_digest", lambda _config: "c" * 64
    )
    monkeypatch.setattr(
        D, "_current_auxiliary_writable_root_startup_binding",
        lambda *_args: boundary[0],
    )

    def execute(**kwargs):
        observed["execute"] = kwargs
        argv = tuple(kwargs["command_builder"](tmp_path / "attempt-output"))
        assert "--dangerously-skip-permissions" not in argv
        assert "verify the assigned finding" not in " ".join(argv)
        assert kwargs["prompt"] == "verify the assigned finding"
        return SimpleNamespace(stdout=b"ok", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", execute)
    spec = _verifier_spec(tmp_path, prompt)
    rc = D._execute_dynamic_verifier_launch(
        spec,
        prompt_path=prompt_path,
        log_path=tmp_path / "worker.log",
        scratchpad=tmp_path,
        phase=SimpleNamespace(name="verify"),
        config={"project_root": str(tmp_path), "_run_id": "run-fixture"},
        model_io_contract=SimpleNamespace(),
        model_io_launch=SimpleNamespace(),
    )
    assert rc == 0
    assert "compiled" in observed and "execute" in observed
    assert observed["execute"]["claude_provider_preparation"] is authority.preparation


def test_verifier_prompt_drift_blocks_before_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompt_path = tmp_path / "prompt.md"
    prompt_path.write_bytes(b"changed")
    called = False
    def forbidden(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("provider must not be compiled")
    monkeypatch.setattr(D, "_compile_claude_driver_provider_authority", forbidden)
    rc = D._execute_dynamic_verifier_launch(
        _verifier_spec(tmp_path, b"original"),
        prompt_path=prompt_path,
        log_path=tmp_path / "worker.log",
        scratchpad=tmp_path,
        phase=SimpleNamespace(name="verify"),
        config={"project_root": str(tmp_path)},
        model_io_contract=SimpleNamespace(),
        model_io_launch=SimpleNamespace(),
    )
    assert rc == D.EXIT_ERROR
    assert called is False


def test_all_three_claude_auxiliary_families_have_no_direct_fallback() -> None:
    verifier = inspect.getsource(D._execute_dynamic_verifier_launch)
    severity = inspect.getsource(D._run_severity_adjudication_shadow_phase)
    skeptic = inspect.getsource(D._execute_application_skeptic_provider_shard)
    assert "execute_headless_worker(" in verifier
    assert "_compile_claude_driver_provider_authority(" in verifier
    assert "provider_executor=provider_executor" in severity
    assert "run_transactional_severity_provider" in severity
    assert "execute_headless_worker(" in skeptic
    assert "output_source_mode=" not in skeptic
    assert 'tool_policy=("filesystem",)' in skeptic
    assert "run_observed_worker(" not in verifier + severity + skeptic
    assert "--dangerously-skip-permissions" not in severity + skeptic


def _committed_replay_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[SimpleNamespace, SimpleNamespace, dict[str, object], dict[str, object]]:
    import worker_transaction as WT

    attempt_id = "attempt-" + "a" * 24
    completion_relative = f"txn/{attempt_id}/completion.json"
    view = tmp_path / "txn" / attempt_id / "view"
    view.mkdir(parents=True)
    contract = SimpleNamespace(
        key="severity_adjudication_shadow/shard-0001",
        phase="severity_adjudication_shadow",
        work_unit_id="shard-0001",
        digest="1" * 64,
        outputs=(SimpleNamespace(identity="scratchpad:decision-1.json"),),
    )
    launch = SimpleNamespace(
        digest="2" * 64,
        backend="claude",
        model="claude-opus-5",
        exec_mode="headless",
        timeout_s=30,
    )
    authority: dict[str, object] = {
        "work_plan_digest": "3" * 64,
        "attempt_completion_relative_path": completion_relative,
        "attempt_id": attempt_id,
        "provider_completion_relative_path": "provider/completion.json",
        "provider_completion_digest": "4" * 64,
    }
    unit: dict[str, object] = {
        "semantic_status": "ACTIVE",
        "execution_state": "OUTPUT_COMMITTED",
        "input_set_digest": "5" * 64,
        "execution_authority": dict(authority),
    }
    plan: dict[str, object] = {
        "work_plan_digest": authority["work_plan_digest"],
        "run_id": "run-1",
        "phase": contract.phase,
        "work_unit_id": contract.work_unit_id,
        "phase_io_contract_digest": contract.digest,
        "phase_io_launch_digest": launch.digest,
        "phase_io_input_set_digest": unit["input_set_digest"],
        "methodology_digests": ["6" * 64],
        "source_snapshot_digest": "7" * 64,
        "provider": {
            "backend": launch.backend,
            "model": launch.model,
            "transport": launch.exec_mode,
            "timeout_seconds": launch.timeout_s,
        },
        "assignment": {
            "members": [
                {"canonical_identity": contract.outputs[0].identity}
            ]
        },
    }
    (view / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    (view / "phase_roster.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        D,
        "read_artifact_ledger",
        lambda _root: {"work_units": {contract.key: unit}},
    )
    monkeypatch.setattr(D, "validate_work_unit_artifacts", lambda *_a, **_k: [])
    monkeypatch.setattr(
        WT,
        "validate_worker_execution_authority",
        lambda **_kwargs: dict(authority),
    )
    monkeypatch.setattr(
        WT,
        "validate_work_plan_phase_roster",
        lambda worker_plan, _roster: dict(worker_plan),
    )
    return contract, launch, authority, plan


def test_committed_model_replay_accepts_exact_current_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract, launch, authority, plan = _committed_replay_fixture(
        tmp_path, monkeypatch
    )
    observed = D._replay_committed_model_worker(
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id="run-1",
        contract=contract,
        launch=launch,
        methodology_digests=("6" * 64,),
        source_snapshot_digest="7" * 64,
    )
    assert observed == (authority, plan)


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("work_unit_id", "shard-foreign"),
        ("provider.model", "claude-sonnet-5"),
        ("phase_io_input_set_digest", "8" * 64),
        ("methodology_digests", ["9" * 64]),
        ("source_snapshot_digest", "a" * 64),
        ("assignment.identity", "scratchpad:foreign.json"),
    ),
)
def test_committed_model_replay_rejects_foreign_shard_model_or_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    value: object,
) -> None:
    contract, launch, _authority, plan = _committed_replay_fixture(
        tmp_path, monkeypatch
    )
    if mutation == "provider.model":
        plan["provider"]["model"] = value
    elif mutation == "assignment.identity":
        plan["assignment"]["members"][0]["canonical_identity"] = value
    else:
        plan[mutation] = value
    attempt = tmp_path / "txn" / ("attempt-" + "a" * 24) / "view"
    (attempt / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(ValueError, match="current execution authority"):
        D._replay_committed_model_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id="run-1",
            contract=contract,
            launch=launch,
            methodology_digests=("6" * 64,),
            source_snapshot_digest="7" * 64,
        )


def test_committed_model_replay_rejects_wrong_attempt_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract, launch, authority, _plan = _committed_replay_fixture(
        tmp_path, monkeypatch
    )
    authority["attempt_id"] = "attempt-" + "b" * 24
    with pytest.raises(ValueError, match="attempt path differs"):
        D._replay_committed_model_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id="run-1",
            contract=contract,
            launch=launch,
            methodology_digests=("6" * 64,),
            source_snapshot_digest="7" * 64,
        )


def test_recovered_provider_handle_rejects_tampered_completion(
    tmp_path: Path,
) -> None:
    provider_dir = tmp_path / "provider"
    provider_dir.mkdir()
    arm_digest = "a" * 64
    (provider_dir / "arm.json").write_text("{}", encoding="utf-8")
    (provider_dir / ("publish_" + "b" * 64 + ".json")).write_text(
        "{}", encoding="utf-8"
    )
    (provider_dir / "completion.json").write_text(
        json.dumps(
            {
                "completion_sha256": "c" * 64,
                "arm_relative_path": "arm.json",
                "arm_sha256": arm_digest,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="differs from outer authority"):
        D._completed_execution_from_worker_replay(
            scratchpad=tmp_path,
            authority={
                "provider_completion_relative_path": "provider/completion.json",
                "provider_completion_digest": "d" * 64,
            },
            exact_outputs=("decision-1.json",),
        )


def test_dynamic_verifier_committed_crash_window_never_calls_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replay = ({"attempt_id": "attempt-1"}, {"work_plan_digest": "a" * 64})
    monkeypatch.setattr(D, "_replay_committed_model_worker", lambda **_k: replay)
    monkeypatch.setattr(D, "_dynamic_verifier_method_digest", lambda _c: "b" * 64)
    monkeypatch.setattr(
        D, "_security_obligation_source_snapshot_digest", lambda _c: "c" * 64
    )
    monkeypatch.setattr(
        D,
        "_execute_dynamic_verifier_launch",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("committed verifier relaunched provider")
        ),
    )
    rc, observed = D._execute_or_replay_dynamic_verifier_model(
        SimpleNamespace(),
        prompt_path=tmp_path / "prompt.md",
        log_path=tmp_path / "log",
        scratchpad=tmp_path,
        phase=SimpleNamespace(name="verify"),
        config={"project_root": str(tmp_path), "_run_id": "run-1"},
        model_io_contract=SimpleNamespace(),
        model_io_launch=SimpleNamespace(),
    )
    assert rc == 0 and observed == replay


def test_skeptic_committed_crash_window_never_rearms_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = SimpleNamespace()
    launch = SimpleNamespace()
    monkeypatch.setattr(
        D,
        "_application_skeptic_io_contract_launch",
        lambda **_k: (contract, launch),
    )
    monkeypatch.setattr(
        D,
        "_replay_committed_model_worker",
        lambda **_k: ({"attempt_id": "attempt-1"}, {}),
    )
    monkeypatch.setattr(
        D, "_security_obligation_source_snapshot_digest", lambda _c: "a" * 64
    )
    monkeypatch.setattr(
        D,
        "_arm_deterministic_driver_work_unit",
        lambda **_k: (_ for _ in ()).throw(
            AssertionError("committed skeptic re-armed provider")
        ),
    )
    observed_contract, observed_launch, execute, issues = (
        D._arm_application_skeptic_io(
            scratchpad=tmp_path,
            config={"project_root": str(tmp_path), "_run_id": "run-1"},
            phase=SimpleNamespace(name="application_skeptic"),
            work_unit_id="worker.0001",
            actor="MODEL",
            committed_model_methodology_digests=("b" * 64,),
        )
    )
    assert (observed_contract, observed_launch) == (contract, launch)
    assert execute is False and issues == []


def test_pre_phase_drift_preserves_degraded_retry_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sentinel = tmp_path / "recon.degraded.json"
    sentinel.write_bytes(b'{"state":"DEGRADED"}\n')

    def drift(*_args, **_kwargs):
        raise D.AuditInputDriftError(
            "snapshot changed",
            run_id="12345678-1234-5678-9234-567812345678",
            phase="recon",
            detection_stage="PRE_PHASE_EXECUTION",
            snapshot_verdict="MISMATCH",
            changed_components=("toolchain",),
        )

    def forbidden_arm(*_args, **_kwargs):
        sentinel.unlink(missing_ok=True)
        raise AssertionError("retry evidence mutated before PRE snapshot gate")

    monkeypatch.setattr(D, "_assert_audit_snapshot_still_bound", drift)
    monkeypatch.setattr(D, "_arm_incomplete_phase_retry", forbidden_arm)
    with pytest.raises(D.AuditInputDriftError):
        D._snapshot_gate_then_arm_phase_retry(
            phase=SimpleNamespace(name="recon"),
            checkpoint=SimpleNamespace(),
            scratchpad=tmp_path,
            config={},
        )
    assert sentinel.read_bytes() == b'{"state":"DEGRADED"}\n'


def test_failed_external_drift_receipt_emits_only_uncertainty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    drift = D.AuditInputDriftError(
        "snapshot changed",
        run_id="12345678-1234-5678-9234-567812345678",
        phase="recon",
        detection_stage="PRE_PHASE_EXECUTION",
        snapshot_verdict="MISMATCH",
        changed_components=("toolchain",),
    )
    monkeypatch.setattr(
        D,
        "main",
        lambda: (_ for _ in ()).throw(drift),
    )
    monkeypatch.setattr(
        D,
        "_emit_midphase_audit_input_drift_decision",
        lambda _exc: (_ for _ in ()).throw(OSError("disk unavailable")),
    )
    monkeypatch.setattr(
        D, "_clear_audit_input_drift_decision_authority", lambda: None
    )
    assert D._run_main_entrypoint() == D.EXIT_STARTUP_DECISION
    output = capsys.readouterr().err
    assert "WRITE_FAILED" in output
    assert "cannot certify whether audit execution began" in output
    assert "before the current phase entered execution" not in output
    assert "after the current phase entered" not in output
    assert "no current-phase model generation was launched" not in output
