"""Reviewer-owned containment attacks for application_skeptic ownership."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import methodology_application_states as S
import plamen_driver as D
import plamen_validators as V
from plamen_types import L1_PHASES, SC_PHASES
from test_support_startup_permit import durable_startup_permit


RUN_ID = "00000000-0000-4000-8000-000000000001"
REQUIRED = {
    "application_skeptic_work_plan.json",
    "application_skeptic_receipt.json",
    "application_skeptic_proposals.md",
    "candidate_negative_skeptic_work_plan.json",
    "candidate_negative_skeptic_receipt.json",
    "candidate_negative_skeptic_proposals.md",
    "candidate_negative_denominator.json",
}
DYNAMIC = {
    "application_skeptic_assessments_*.json",
    "candidate_negative_skeptic_assessments_*.json",
}


def _phase(pipeline: str):
    phases = L1_PHASES if pipeline == "l1" else SC_PHASES
    return next(item for item in phases if item.name == "application_skeptic")


def _config(tmp_path: Path, pipeline: str) -> dict:
    project = tmp_path / f"project-{pipeline}"
    project.mkdir()
    return {
        "project_root": str(project),
        "pipeline": pipeline,
        "mode": "core",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": "claude",
        "_run_id": RUN_ID,
        "_active_phase_names": ["breadth", "depth", "application_skeptic"],
    }


def _negative_state(skill: Path) -> dict:
    return S.classify_application_row(
        {
            "phase": "breadth",
            "worker_id": "B1",
            "producer_invocation_id": "breadth-call-1",
            "output": "analysis_boundary.md",
            "output_sha256": "b" * 64,
            "prompt_sha256": "c" * 64,
            "dispatch_contract_sha256": "d" * 64,
            "skill": "BOUNDARY_ANALYSIS",
            "methodology_path": skill.as_posix(),
            "methodology_sha256": hashlib.sha256(skill.read_bytes()).hexdigest(),
            "step": "2.1",
            "executed": "yes",
            "evidence": "src/Boundary.rs:L9",
            "result": "SAFE: the cited guard rejects the exact transition",
            "delivery_integrity": "CURRENT",
            "trace_state": "VALID",
            "evidence_basis": "IN_SCOPE_SOURCE",
        }
    )


def _install_provider_fixture(config: dict, scratchpad: Path) -> None:
    code = (
        "import json,sys; p=json.load(sys.stdin); s=p['shard']; a=p['assessor']; "
        "rows=[{'work_item_id':w,'assessor_id':a['identity'],"
        "'assessor_invocation_id':a['invocation_id'],'outcome':'AGREE_NEGATIVE',"
        "'evidence_basis':'IN_SCOPE_SOURCE','evidence':'bound exact source trace',"
        "'rationale':'independent provider fixture assessment','candidate':None} "
        "for w in s['work_item_ids']]; "
        "json.dump({'schema_version':'plamen.application_skeptic_assessments.v1',"
        "'work_plan_digest':p['plan']['work_plan_digest'],'shard_id':s['shard_id'],"
        "'assessments':rows},sys.stdout,separators=(',',':'))"
    )
    config.update(
        {
            "cli_backend": "fixture-subprocess",
            "_skeptic_execution_test_fixture": True,
            "_skeptic_execution_fixture_argv": (sys.executable, "-c", code),
            "skeptic_execution_environment": {},
            "skeptic_execution_environment_allowlist": (),
            "_auxiliary_writable_root_startup_binding": (
                durable_startup_permit(
                    scratchpad,
                    run_id=str(config["_run_id"]),
                )
            ),
        }
    )


def _install_bounded_provider_execution(
    monkeypatch,
    config: dict,
    scratchpad: Path,
    *,
    after_publish,
) -> list[str]:
    """Replace current WER execution without launching the fixture argv."""

    _install_provider_fixture(config, scratchpad)
    calls: list[str] = []

    def execute_provider(request, **_kwargs):
        provider_dir = (
            scratchpad
            / ".worker_execution_receipts"
            / request.layout.provider_shard_id
        )
        marker = provider_dir / "bounded-fixture-completion.json"
        first_attempt = not marker.is_file()
        plan = json.loads(
            (scratchpad / "application_skeptic_work_plan.json").read_text(
                encoding="utf-8"
            )
        )
        shard = plan["shards"][0]
        assessor, invocation = D._application_skeptic_assessor_identity(
            config, plan["work_plan_digest"], shard["shard_id"]
        )
        payload = {
            "schema_version": "plamen.application_skeptic_assessments.v1",
            "work_plan_digest": plan["work_plan_digest"],
            "shard_id": shard["shard_id"],
            "assessments": [
                {
                    "work_item_id": work_id,
                    "assessor_id": assessor,
                    "assessor_invocation_id": invocation,
                    "outcome": "AGREE_NEGATIVE",
                    "evidence_basis": "IN_SCOPE_SOURCE",
                    "evidence": "src/Boundary.rs:L9 exact guard trace",
                    "rationale": "independent trace supports the negative",
                    "candidate": None,
                }
                for work_id in shard["work_item_ids"]
            ],
        }
        request.layout.canonical_output_path.write_text(
            json.dumps(payload), encoding="utf-8"
        )
        request.layout.authority_sidecar_path.write_text("{}\n", encoding="utf-8")
        if first_attempt:
            calls.append(request.layout.canonical_output_relative)
            after_publish(request)
            provider_dir.mkdir(parents=True, exist_ok=True)
            marker.write_text("{}\n", encoding="utf-8")
        return SimpleNamespace(
            authority_sidecar_path=request.layout.authority_sidecar_path
        )

    monkeypatch.setattr(D, "execute_or_resume_skeptic_execution", execute_provider)
    monkeypatch.setattr(
        D, "validate_skeptic_provider_authority", lambda *_args, **_kwargs: None
    )
    return calls


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_application_ownership_is_exact_required_plus_dynamic(
    tmp_path: Path, pipeline: str,
) -> None:
    owned = V._owned_artifact_patterns(pipeline, tmp_path)[
        "application_skeptic"
    ]
    assert set(owned) == REQUIRED | DYNAMIC

    for allowed in (
        *sorted(REQUIRED),
        "application_skeptic_assessments_0001.json",
        "candidate_negative_skeptic_assessments_0001.json",
    ):
        assert V._matches_any_pattern(allowed, owned), allowed
    for denied in (
        "application_skeptic_assessments_0001.json.bak",
        "application_skeptic_assessment_0001.json",
        "application_skeptic_receipt_extra.json",
        "application_skeptic_notes.md",
        "verification_queue.md",
        "../AUDIT_REPORT.md",
    ):
        assert not V._matches_any_pattern(denied, owned), denied


@pytest.mark.parametrize(
    ("pipeline", "phases"), [("sc", SC_PHASES), ("l1", L1_PHASES)]
)
def test_current_outputs_are_allowed_but_future_and_report_outputs_are_foreign(
    tmp_path: Path, pipeline: str, phases,
) -> None:
    project = tmp_path / f"project-{pipeline}"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    before = V._snapshot_file_state(scratch, str(project))
    for name in (*sorted(REQUIRED), "application_skeptic_assessments_0001.json"):
        (scratch / name).write_text("owned\n", encoding="utf-8")
    (scratch / "verification_queue.md").write_text("future\n", encoding="utf-8")
    (project / "AUDIT_REPORT.md").write_text("future report\n", encoding="utf-8")

    offenders = V._detect_foreign_phase_writes(
        scratch,
        str(project),
        phases,
        "application_skeptic",
        pipeline,
        before,
    )

    assert "verification_queue.md" in offenders
    assert "../AUDIT_REPORT.md" in offenders
    assert not (set(offenders) & REQUIRED)
    assert "application_skeptic_assessments_0001.json" not in offenders


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_custom_runtime_contains_report_future_and_undeclared_sibling_writes(
    tmp_path: Path, monkeypatch, pipeline: str,
) -> None:
    """The special phase must post-check its child, not trust prompt scope."""
    scratch = tmp_path / f"scratch-{pipeline}"
    scratch.mkdir()
    config = _config(tmp_path, pipeline)
    config.update(
        {
            "cli_backend": "fixture-subprocess",
            "_skeptic_execution_test_fixture": True,
            # The provider call is replaced below.  WER requires this argv
            # shape while preparing a fixture request, but it is never
            # launched, so a relocated Python executable never needs to find
            # its adjacent runtime DLL.
            "_skeptic_execution_fixture_argv": (
                sys.executable,
                "-c",
                "raise AssertionError('bounded provider seam was not intercepted')",
            ),
            "skeptic_execution_environment": {},
            "skeptic_execution_environment_allowlist": (),
            "_auxiliary_writable_root_startup_binding": durable_startup_permit(
                scratch,
                run_id=str(config["_run_id"]),
            ),
        }
    )
    project = Path(config["project_root"])
    home = tmp_path / f"home-{pipeline}"
    skill = home / "agents" / "boundary" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact boundary methodology\n", encoding="utf-8")
    S.write_application_queues(
        scratch, [_negative_state(skill)], phase="breadth"
    )
    S.write_application_queues(scratch, [], phase="depth")
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kw: [])
    snapshot_reached: list[bool] = []
    callback_reached: list[bool] = []
    callback_after_snapshot: list[bool] = []
    original_snapshot = D._snapshot_application_skeptic_child_boundary

    def record_snapshot(*args, **kwargs):
        snapshot_reached.append(True)
        return original_snapshot(*args, **kwargs)

    monkeypatch.setattr(
        D, "_snapshot_application_skeptic_child_boundary", record_snapshot
    )

    def execute_provider(request, **_kwargs):
        callback_reached.append(True)
        callback_after_snapshot.append(bool(snapshot_reached))
        plan = json.loads(
            (scratch / "application_skeptic_work_plan.json").read_text(
                encoding="utf-8"
            )
        )
        shard = plan["shards"][0]
        assessor, invocation = D._application_skeptic_assessor_identity(
            config, plan["work_plan_digest"], shard["shard_id"]
        )
        payload = {
            "schema_version": "plamen.application_skeptic_assessments.v1",
            "work_plan_digest": plan["work_plan_digest"],
            "shard_id": shard["shard_id"],
            "assessments": [
                {
                    "work_item_id": work_id,
                    "assessor_id": assessor,
                    "assessor_invocation_id": invocation,
                    "outcome": "AGREE_NEGATIVE",
                    "evidence_basis": "IN_SCOPE_SOURCE",
                    "evidence": "src/Boundary.rs:L9 exact guard trace",
                    "rationale": "independent source trace supports the negative",
                    "candidate": None,
                }
                for work_id in shard["work_item_ids"]
            ],
        }
        request.layout.canonical_output_path.write_text(
            json.dumps(payload), encoding="utf-8"
        )
        request.layout.authority_sidecar_path.write_text("{}\n", encoding="utf-8")
        # These emulate a child ignoring its prompt. The generic live monitor
        # does not inspect project-root writes or arbitrary unowned siblings;
        # the special phase therefore needs a deterministic post-run boundary.
        (project / "AUDIT_REPORT.md").write_text("rogue report\n", encoding="utf-8")
        (scratch / "verification_queue.md").write_text("rogue future\n", encoding="utf-8")
        (scratch / "application_skeptic_notes.md").write_text(
            "rogue sibling\n", encoding="utf-8"
        )
        return SimpleNamespace(
            authority_sidecar_path=request.layout.authority_sidecar_path
        )

    monkeypatch.setattr(D, "execute_or_resume_skeptic_execution", execute_provider)
    monkeypatch.setattr(
        D, "validate_skeptic_provider_authority", lambda *_args, **_kwargs: None
    )
    receipt, issues = D._run_application_skeptic_phase(
        _phase(pipeline), config, scratch
    )

    assert callback_reached == [True], issues
    assert callback_after_snapshot == [True]
    assert receipt["status"] == "COMPLETE", issues
    assert issues == []
    assert not (project / "AUDIT_REPORT.md").exists()
    assert not (scratch / "verification_queue.md").exists()
    assert not (scratch / "application_skeptic_notes.md").exists()
    containment = D._load_application_skeptic_containment_receipt(scratch)
    assert containment is not None
    event = containment["events"][-1]
    assert event["offenders"] == [
        "../AUDIT_REPORT.md",
        "application_skeptic_notes.md",
        "verification_queue.md",
    ]
    assert event["moved"] == event["offenders"]
    assert event["failed"] == []


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_provider_exception_still_reconciles_application_boundary(
    tmp_path: Path, monkeypatch, pipeline: str,
) -> None:
    scratch = tmp_path / f"scratch-provider-exception-{pipeline}"
    scratch.mkdir()
    config = _config(tmp_path, pipeline)
    _install_provider_fixture(config, scratch)
    project = Path(config["project_root"])
    home = tmp_path / f"home-provider-exception-{pipeline}"
    skill = home / "agents" / "boundary" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact boundary methodology\n", encoding="utf-8")
    S.write_application_queues(
        scratch, [_negative_state(skill)], phase="breadth"
    )
    S.write_application_queues(scratch, [], phase="depth")
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kw: [])
    callback_reached: list[bool] = []

    def fail_provider(_request, **_kwargs):
        callback_reached.append(True)
        (project / "AUDIT_REPORT.md").write_text(
            "rogue report before provider failure\n", encoding="utf-8"
        )
        raise D.SkepticExecutionIncomplete("injected bounded provider failure")

    monkeypatch.setattr(D, "execute_or_resume_skeptic_execution", fail_provider)
    receipt, issues = D._run_application_skeptic_phase(
        _phase(pipeline), config, scratch
    )

    assert callback_reached == [True]
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert any("provider incomplete" in issue for issue in issues), issues
    assert not (project / "AUDIT_REPORT.md").exists()
    containment = D._load_application_skeptic_containment_receipt(scratch)
    assert containment is not None
    event = containment["events"][-1]
    assert event["offenders"] == ["../AUDIT_REPORT.md"]
    assert event["moved"] == ["../AUDIT_REPORT.md"]
    assert event["failed"] == []


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_child_boundary_allows_only_exact_output_and_launcher_controls(
    tmp_path: Path, pipeline: str,
) -> None:
    project = tmp_path / f"project-controls-{pipeline}"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    before = D._snapshot_application_skeptic_child_boundary(scratch, project)
    exact = "application_skeptic_assessments_0001.json"
    authority = "application_skeptic_provider_authority_0001.json"
    layout = SimpleNamespace(
        staged_output_relative=".skeptic_execution_work/as/exact/staged/assessment.json",
        containment_debt_relative=".skeptic_execution_work/as/exact/containment_debt.json",
        retry_intent_relative=".skeptic_execution_work/as/exact/inputs/retry_intent.json",
        provider_shard_id="skas-exact",
        retry_provider_shard_id="skas-exact-r1",
    )
    contract = SimpleNamespace(
        outputs=(
            SimpleNamespace(root="scratchpad", path=exact),
            SimpleNamespace(root="scratchpad", path=authority),
        )
    )
    typed = {
        exact,
        authority,
        layout.staged_output_relative,
        layout.containment_debt_relative,
        layout.retry_intent_relative,
        ".worker_execution_receipts/skas-exact/completion.json",
        ".skeptic_execution_quarantine/skas-exact-r1/scratchpad/rogue.md",
    }
    for name in typed:
        path = scratch / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("typed transaction material\n", encoding="utf-8")
    # Underscore is not itself authority. These are semantic/control stores or
    # arbitrary model siblings and must never inherit the launcher exemption.
    dangerous = {
        "_v2_checkpoint.json",
        "_artifact_state.json",
        "_semantic_mutations.json",
        "_audit_snapshot.json",
        "nested/_rogue_control.json",
        "_prompt_application_skeptic_0001.attempt1.md",
        "_stdio_application_skeptic_0001.attempt1.log",
        "_subprocess_isolation.json",
        "_v2_cost_ledger.md",
        ".worker_execution_receipts/skas-other/completion.json",
    }
    for name in dangerous:
        path = scratch / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("model write\n", encoding="utf-8")
    near_miss = "application_skeptic_assessments_0001.json.bak"
    (scratch / near_miss).write_text("near miss\n", encoding="utf-8")

    offenders = set(
        D._application_skeptic_child_containment_offenders(
            scratch,
            project,
            before,
            exact_output=exact,
            phase_io_contract=contract,
            provider_layout=layout,
        )
    )

    assert dangerous | {near_miss} <= offenders
    assert not typed & offenders


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_child_boundary_detects_nested_and_modified_existing_files(
    tmp_path: Path, pipeline: str,
) -> None:
    project = tmp_path / f"project-nested-{pipeline}"
    scratch = project / ".scratchpad"
    source = project / "src" / "Existing.rs"
    source.parent.mkdir(parents=True)
    source.write_text("before\n", encoding="utf-8")
    existing_sibling = scratch / "nested" / "existing.md"
    existing_sibling.parent.mkdir(parents=True)
    existing_sibling.write_text("before\n", encoding="utf-8")
    before = D._snapshot_application_skeptic_child_boundary(scratch, project)

    source.write_text("modified\n", encoding="utf-8")
    existing_sibling.write_text("modified\n", encoding="utf-8")
    (project / "src" / "New.rs").write_text("new\n", encoding="utf-8")
    (scratch / "nested" / "new.md").write_text("new\n", encoding="utf-8")

    offenders = set(
        D._application_skeptic_child_containment_offenders(
            scratch,
            project,
            before,
            exact_output="application_skeptic_assessments_0001.json",
        )
    )

    assert {
        "../src/Existing.rs",
        "../src/New.rs",
        "nested/existing.md",
        "nested/new.md",
    } <= offenders


def test_child_boundary_content_digest_cannot_be_bypassed_by_restored_metadata(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project-metadata"
    scratch = project / ".scratchpad"
    source = project / "src" / "Existing.sol"
    source.parent.mkdir(parents=True)
    source.write_text("AAAA", encoding="utf-8")
    stat = source.stat()
    before = D._snapshot_application_skeptic_child_boundary(scratch, project)

    source.write_text("BBBB", encoding="utf-8")
    os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    offenders = D._application_skeptic_child_containment_offenders(
        scratch,
        project,
        before,
        exact_output="application_skeptic_assessments_0001.json",
    )

    assert "../src/Existing.sol" in offenders


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_failed_quarantine_remains_visible_across_phase_resume(
    tmp_path: Path, monkeypatch, pipeline: str,
) -> None:
    scratch = tmp_path / f"scratch-failed-quarantine-{pipeline}"
    scratch.mkdir()
    config = _config(tmp_path, pipeline)
    home = tmp_path / f"home-failed-quarantine-{pipeline}"
    skill = home / "agents" / "boundary" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact boundary methodology\n", encoding="utf-8")
    S.write_application_queues(
        scratch, [_negative_state(skill)], phase="breadth"
    )
    S.write_application_queues(scratch, [], phase="depth")
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kw: [])
    def write_locked_rogue(_request):
        (scratch / "verification_queue.md").write_text(
            "locked rogue future\n", encoding="utf-8"
        )

    launches = _install_bounded_provider_execution(
        monkeypatch,
        config,
        scratch,
        after_publish=write_locked_rogue,
    )
    monkeypatch.setattr(
        D,
        "_quarantine_foreign_phase_writes",
        lambda _s, _p, _phase_name, offenders: ([], list(offenders)),
    )
    first, first_issues = D._run_application_skeptic_phase(
        _phase(pipeline), config, scratch
    )
    assert first["status"] == "COMPLETED_WITH_DEBT"
    assert any("could not be quarantined" in issue for issue in first_issues), first_issues
    assert (scratch / "verification_queue.md").is_file()
    containment = D._load_application_skeptic_containment_receipt(scratch)
    assert containment is not None
    assert containment["events"][-1]["failed"] == ["verification_queue.md"]

    # A compromised assessment is never a valid cache.  Resume must retain
    # containment debt and cannot turn the prior terminal negative into proof.
    second, second_issues = D._run_application_skeptic_phase(
        _phase(pipeline), config, scratch
    )
    assert second["status"] == "COMPLETED_WITH_DEBT"
    assert any("remains live" in issue.lower() for issue in second_issues)
    assert launches == [
        "application_skeptic_assessments_0001.json",
    ]


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_no_model_path_does_not_create_false_containment_debt(
    tmp_path: Path, monkeypatch, pipeline: str,
) -> None:
    scratch = tmp_path / f"scratch-no-model-{pipeline}"
    scratch.mkdir()
    config = _config(tmp_path, pipeline)
    S.write_application_queues(scratch, [], phase="breadth")
    S.write_application_queues(scratch, [], phase="depth")
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kw: [])
    snapshots: list[object] = []
    original_snapshot = D._snapshot_application_skeptic_child_boundary

    def record_snapshot(*args, **kwargs):
        snapshots.append((args, kwargs))
        return original_snapshot(*args, **kwargs)

    monkeypatch.setattr(
        D, "_snapshot_application_skeptic_child_boundary", record_snapshot
    )
    monkeypatch.setattr(
        D,
        "execute_or_resume_skeptic_execution",
        lambda *_args, **_kw: (_ for _ in ()).throw(
            AssertionError("no provider execution expected")
        ),
    )

    receipt, issues = D._run_application_skeptic_phase(
        _phase(pipeline), config, scratch
    )

    assert receipt["status"] == "NOT_TRIGGERED"
    assert issues == []
    assert snapshots == []


def test_launcher_control_grammar_rejects_near_misses_and_nested_paths() -> None:
    legacy_untyped = {
        "_prompt_application_skeptic_0001.attempt1.md",
        "_stdio_application_skeptic_WORKER_1.attempt22.log",
        "_stdio_application_skeptic.log",
        "_codex_output_application_skeptic_0001.attempt1.md",
        "_subprocess_isolation.json",
        "_v2_cost_ledger.md",
        "_diagnostic_orphan_application_skeptic.json",
    }
    near_misses = {
        "_prompt_application_skeptic_.attempt1.md",
        "_prompt_application_skeptic_0001.attemptx.md",
        "_prompt_application_skeptic_0001.attempt1.md.bak",
        "nested/_prompt_application_skeptic_0001.attempt1.md",
        "../_prompt_application_skeptic_0001.attempt1.md",
        "_stdio_application_skeptic_WORKER_1.attempt22.log.bak",
        "_codex_output_application_skeptic_0001.attempt1.json",
        "_subprocess_isolation.json.bak",
        "_v2_cost_ledger.md.bak",
        "_diagnostic_orphan_application_skeptic.json.bak",
        "_application_skeptic_containment.json",
        "_v2_checkpoint.json",
    }
    assert not any(
        D._application_skeptic_typed_provider_control(
            name,
            phase_io_contract=None,
            provider_layout=None,
        )
        for name in legacy_untyped | near_misses
    )


def _receipt_digest(payload: dict[str, object]) -> str:
    unsigned = {
        key: value for key, value in payload.items() if key != "receipt_sha256"
    }
    return hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_containment_receipt_rejects_top_level_digest_forgery(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch-receipt-digest"
    scratch.mkdir()
    assert D._write_application_skeptic_containment_event(
        scratch,
        config={"_run_id": RUN_ID},
        shard_id="shard-0001",
        offenders=["verification_queue.md"],
        moved=[],
        failed=["verification_queue.md"],
    ) == []
    path = scratch / "_application_skeptic_containment.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["receipt_sha256"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match="digest mismatch"):
        D._load_application_skeptic_containment_receipt(scratch)


def test_containment_receipt_rejects_forged_event_under_rehashed_envelope(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch-event-digest"
    scratch.mkdir()
    rogue = scratch / "verification_queue.md"
    rogue.write_text("live rogue\n", encoding="utf-8")
    assert D._write_application_skeptic_containment_event(
        scratch,
        config={"_run_id": RUN_ID},
        shard_id="shard-0001",
        offenders=[rogue.name],
        moved=[],
        failed=[rogue.name],
    ) == []
    path = scratch / "_application_skeptic_containment.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    # Forge the event body while preserving its old event hash, then rehash the
    # outer envelope. Envelope integrity must not bless a malformed child event.
    payload["events"][0]["failed"] = []
    payload["receipt_sha256"] = _receipt_digest(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")

    issues = D._application_skeptic_durable_containment_debt(
        scratch, tmp_path
    )

    assert any("event" in issue.lower() and "invalid" in issue.lower() for issue in issues)


def test_unaccounted_containment_path_is_durable_debt(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch-unaccounted"
    project = tmp_path / "project-unaccounted"
    scratch.mkdir()
    project.mkdir()
    assert D._write_application_skeptic_containment_event(
        scratch,
        config={"_run_id": RUN_ID},
        shard_id="application-skeptic-0001",
        offenders=["deleted-before-quarantine.md"],
        moved=[],
        failed=[],
    ) == []

    issues = D._application_skeptic_durable_containment_debt(
        scratch, project
    )

    assert issues == [
        "application_skeptic phase containment: child mutation could not be "
        "quarantined (path may have been deleted): deleted-before-quarantine.md"
    ]


def test_scratch_content_digest_cannot_be_bypassed_by_restored_metadata(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project-scratch-metadata"
    scratch = project / ".scratchpad"
    existing = scratch / "nested" / "existing.md"
    existing.parent.mkdir(parents=True)
    existing.write_text("AAAA", encoding="utf-8")
    stat = existing.stat()
    before = D._snapshot_application_skeptic_child_boundary(scratch, project)

    existing.write_text("BBBB", encoding="utf-8")
    os.utime(existing, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    offenders = D._application_skeptic_child_containment_offenders(
        scratch,
        project,
        before,
        exact_output="application_skeptic_assessments_0001.json",
    )

    assert "nested/existing.md" in offenders


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_successful_quarantine_still_invalidates_compromised_assessment_on_resume(
    tmp_path: Path, monkeypatch, pipeline: str,
) -> None:
    scratch = tmp_path / f"scratch-quarantine-resume-{pipeline}"
    scratch.mkdir()
    config = _config(tmp_path, pipeline)
    home = tmp_path / f"home-quarantine-resume-{pipeline}"
    skill = home / "agents" / "boundary" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact boundary methodology\n", encoding="utf-8")
    S.write_application_queues(
        scratch, [_negative_state(skill)], phase="breadth"
    )
    S.write_application_queues(scratch, [], phase="depth")
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kw: [])
    def write_rogue(_request):
        (scratch / "verification_queue.md").write_text(
            "rogue future\n", encoding="utf-8"
        )

    legacy = scratch / "application_skeptic_assessments_0001.json"
    legacy.write_text("{}", encoding="utf-8")
    launches = _install_bounded_provider_execution(
        monkeypatch,
        config,
        scratch,
        after_publish=write_rogue,
    )
    first, first_issues = D._run_application_skeptic_phase(
        _phase(pipeline), config, scratch
    )
    assert first["status"] == "COMPLETE", first_issues
    assert any("quarantined" in issue for issue in first_issues), first_issues
    assert not (scratch / "verification_queue.md").exists()
    assert legacy.is_file()

    second, second_issues = D._run_application_skeptic_phase(
        _phase(pipeline), config, scratch
    )
    assert second["status"] == "COMPLETE", second_issues
    assert second_issues == []
    assert launches == ["application_skeptic_assessments_0001.json"]


def test_receipt_writer_failure_is_explicit_and_leaves_no_false_receipt(
    tmp_path: Path, monkeypatch,
) -> None:
    scratch = tmp_path / "scratch-receipt-write-failure"
    scratch.mkdir()
    real_replace = D.os.replace

    def fail_receipt_replace(source, destination):
        if Path(destination).name == "_application_skeptic_containment.json":
            raise OSError("injected containment receipt persistence failure")
        return real_replace(source, destination)

    monkeypatch.setattr(D.os, "replace", fail_receipt_replace)
    issues = D._write_application_skeptic_containment_event(
        scratch,
        config={"_run_id": RUN_ID},
        shard_id="shard-0001",
        offenders=["verification_queue.md"],
        moved=["verification_queue.md"],
        failed=[],
    )

    assert len(issues) == 1
    assert "receipt write failed" in issues[0]
    assert not (scratch / "_application_skeptic_containment.json").is_file()
