"""Live driver wiring for the conditional P0-B/C/D discriminator phase."""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

import methodology_application_states as S
import plamen_driver as D
import skeptic_execution_work as E
from phase_io_contracts import resolve_phase_io_contract
from plamen_types import L1_PHASES, SC_PHASES
from test_skeptic_execution_work_provider_v2 import (
    _case as _skeptic_provider_case,
    assessment_digest as _skeptic_assessment_digest,
)
from test_support_startup_permit import durable_startup_permit


def _config(tmp_path: Path, *, backend: str = "claude") -> dict:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": backend,
        "_run_id": "00000000-0000-4000-8000-000000000001",
        "_active_phase_names": ["breadth", "depth", "application_skeptic"],
    }


def _negative_state(skill: Path) -> dict:
    return S.classify_application_row(
        {
            "phase": "breadth",
            "worker_id": "B1",
            "producer_invocation_id": "breadth-call-1",
            "output": "analysis_oracle.md",
            "output_sha256": "b" * 64,
            "prompt_sha256": "c" * 64,
            "dispatch_contract_sha256": "d" * 64,
            "skill": "ORACLE_ANALYSIS",
            "methodology_path": skill.as_posix(),
            "methodology_sha256": hashlib.sha256(skill.read_bytes()).hexdigest(),
            "step": "2.1",
            "executed": "yes",
            "evidence": "src/Oracle.sol:L9",
            "result": "SAFE: the cited guard rejects the exact transition",
            "delivery_integrity": "CURRENT",
            "trace_state": "VALID",
            "evidence_basis": "IN_SCOPE_SOURCE",
        }
    )


def _seed_base_queues(scratchpad: Path, breadth_rows=()) -> None:
    S.write_application_queues(scratchpad, breadth_rows, phase="breadth")
    S.write_application_queues(scratchpad, [], phase="depth")


def _phase():
    return next(phase for phase in SC_PHASES if phase.name == "application_skeptic")


def _install_provider_fixture(
    config: dict,
    scratchpad: Path,
    *,
    outcome: str,
    candidate: dict | None = None,
    fail: bool = False,
) -> None:
    """Use the real provider boundary with a deterministic test subprocess."""

    if fail:
        code = "import sys; sys.exit(7)"
    else:
        code = (
            "import json,sys; p=json.load(sys.stdin); s=p['shard']; a=p['assessor']; "
            f"outcome={outcome!r}; candidate={candidate!r}; "
            "rows=[{'work_item_id':w,'assessor_id':a['identity'],"
            "'assessor_invocation_id':a['invocation_id'],'outcome':outcome,"
            "'evidence_basis':'IN_SCOPE_SOURCE','evidence':'bound exact source trace',"
            "'rationale':'independent provider fixture assessment',"
            "'candidate':candidate} for w in s['work_item_ids']]; "
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


def test_phase_is_before_candidate_queue_freeze_for_sc_and_l1():
    sc = [phase.name for phase in SC_PHASES]
    l1 = [phase.name for phase in L1_PHASES]
    assert sc.index("depth") < sc.index("application_skeptic") < sc.index(
        "sc_semantic_dedup"
    )
    assert l1.index("depth") < l1.index("application_skeptic") < l1.index(
        "verify_queue"
    )
    assert _phase().modes == {"core", "thorough"}


def test_provider_arm_requires_exact_current_environment_binding_schema(
    tmp_path: Path,
) -> None:
    """The skeptic consumer must match WER's canonical privacy schema exactly."""

    request, _ = _skeptic_provider_case(tmp_path / "provider")
    observed = E.execute_or_resume_skeptic_execution(
        request,
        parser_digest=_skeptic_assessment_digest,
    )
    arm_path = observed.provider_arm_path
    canonical = json.loads(arm_path.read_text(encoding="utf-8"))

    # Canonical current WER evidence passes.
    E._validate_provider_arm(request, arm_path)

    # Claude's opaque runtime uses the other exact canonical
    # _environment_binding variant: names persist, values/digest do not.
    claude_request = replace(request, backend="claude")
    redacted = copy.deepcopy(canonical)
    redacted["environment"].update(
        {
            "effective_sha256": None,
            "value_digest_persisted": False,
            "value_authority": (
                "CLAUDE_CHILD_ENVIRONMENT_IN_MEMORY_REPLAY"
            ),
        }
    )
    arm_path.write_text(
        json.dumps(redacted, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    E._validate_provider_arm(claude_request, arm_path)
    arm_path.write_text(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    mutations: list[dict] = []
    old = copy.deepcopy(canonical)
    old["environment"].pop("value_authority")
    old["environment"].pop("value_digest_persisted")
    mutations.append(old)

    incomplete = copy.deepcopy(canonical)
    incomplete["environment"].pop("value_authority")
    mutations.append(incomplete)

    extra = copy.deepcopy(canonical)
    extra["environment"]["unrecognized_authority"] = "FORBIDDEN"
    mutations.append(extra)

    for candidate in mutations:
        arm_path.write_text(
            json.dumps(candidate, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        with pytest.raises(
            E.SkepticExecutionWorkError,
            match="provider environment differs from exact intent",
        ):
            E._validate_provider_arm(request, arm_path)

    arm_path.write_text(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    E._validate_provider_arm(request, arm_path)


def test_phase_io_contracts_bind_plan_workers_and_exact_reconcile_inputs():
    common = {
        "pipeline": "sc",
        "mode": "core",
        "ecosystem": "evm",
        "backend": "claude",
        "phase": "application_skeptic",
    }
    planning = resolve_phase_io_contract(**common, work_unit_id="planning")
    worker = resolve_phase_io_contract(
        **common,
        work_unit_id="worker.0001",
        exact_outputs=(
            "application_skeptic_assessments_0001.json",
            "application_skeptic_provider_authority_0001.json",
        ),
    )
    reconcile = resolve_phase_io_contract(
        **common,
        work_unit_id="reconcile",
        exact_inputs=("application_skeptic_assessments_0001.json",),
    )

    assert planning.model_invoked is False
    assert len(planning.immutable_inputs) == 6
    assert worker.model_invoked is True
    assert {row.path for row in worker.outputs} == {
        "application_skeptic_assessments_0001.json",
        "application_skeptic_provider_authority_0001.json",
    }
    assert {row.writer for row in worker.outputs} == {"DRIVER"}
    assert {
        identity
        for identity in worker.immutable_inputs
        if identity.endswith("application_skeptic_work_plan.json")
    }
    assert reconcile.model_invoked is False
    assert {
        row.path for row in reconcile.outputs
    } >= {
        "application_skeptic_receipt.json",
        "application_skeptic_proposals.md",
        "application_skeptic_delivery_binding.json",
    }
    assert any(
        identity.endswith("application_skeptic_assessments_0001.json")
        for identity in reconcile.immutable_inputs
    )


def test_invalid_provider_input_never_records_worker_output_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    config = _config(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(D, "record_work_unit_inputs", lambda *a, **k: calls.append("inputs"))
    monkeypatch.setattr(
        D, "validate_work_unit_inputs", lambda *a, **k: ["provider authority stale"]
    )
    monkeypatch.setattr(
        D,
        "record_work_unit_artifacts",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("output authority recorded after invalid input")
        ),
    )
    issues = D._record_application_skeptic_io(
        scratchpad=scratch,
        config=config,
        phase=_phase(),
        work_unit_id="worker.0001",
        actor="DRIVER",
        exact_outputs=(
            "application_skeptic_assessments_0001.json",
            "application_skeptic_provider_authority_0001.json",
        ),
        model="fixture",
    )
    assert calls == []
    assert issues == ["provider authority stale"]


def test_empty_complete_union_writes_not_triggered_without_model(
    tmp_path: Path, monkeypatch
):
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    _seed_base_queues(scratchpad)
    config = _config(tmp_path)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kwargs: [])
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("no model work")),
    )

    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )

    assert issues == []
    assert receipt["status"] == "NOT_TRIGGERED"
    assert receipt["model_invoked"] is False
    assert (scratchpad / "application_skeptic_work_plan.json").is_file()
    assert (scratchpad / "application_skeptic_proposals.md").stat().st_size > 100


def test_runtime_phase_io_binds_planning_and_reconcile_input_denominators(
    tmp_path: Path, monkeypatch,
):
    """Presence-only outputs cannot certify stale application decisions."""
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    _seed_base_queues(scratchpad)
    config = _config(tmp_path)
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("no model work")),
    )

    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )

    assert receipt["status"] == "NOT_TRIGGERED"
    assert issues == []
    units = D.read_artifact_ledger(scratchpad)["work_units"]
    planning = units["sc/core/evm/claude/application_skeptic/planning"]
    reconcile = units["sc/core/evm/claude/application_skeptic/reconcile"]
    assert set(planning["input_bindings"]) == {
        f"scratchpad:methodology_skeptic_queue_{source}.json"
        for source in (
            "breadth", "breadth_repair", "rescan", "rescan_repair",
            "depth", "depth_repair",
        )
    }
    assert set(reconcile["input_bindings"]) == {
        "scratchpad:application_skeptic_work_plan.json"
    }


def test_application_skeptic_arms_plan_provider_and_reconcile_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    home = tmp_path / "plamen_home"
    skill = home / "agents" / "oracle" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact oracle methodology\n", encoding="utf-8")
    _seed_base_queues(scratchpad, [_negative_state(skill)])
    config = _config(tmp_path)
    _install_provider_fixture(
        config,
        scratchpad,
        outcome="AGREE_NEGATIVE",
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    real_arm = D._arm_deterministic_driver_work_unit
    observed: list[str] = []

    def arm(*, contract, **kwargs):
        if contract.phase == "application_skeptic":
            assert all(
                not (scratchpad / output.path).exists()
                for output in contract.outputs
            )
            observed.append(contract.work_unit_id)
        return real_arm(contract=contract, **kwargs)

    monkeypatch.setattr(D, "_arm_deterministic_driver_work_unit", arm)
    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )

    assert issues == []
    assert receipt["status"] == "COMPLETE"
    assert observed == ["planning", "worker.0001", "reconcile"]
    units = D.read_artifact_ledger(scratchpad)["work_units"]
    owned = {
        key: value
        for key, value in units.items()
        if "/application_skeptic/" in key
    }
    assert {
        value["semantic_status"] for value in owned.values()
    } == {"ACTIVE"}
    worker = next(
        value
        for key, value in owned.items()
        if key.endswith("/worker.0001")
    )
    assert set(worker["artifacts"]) == {
        "scratchpad:application_skeptic_assessments_0001.json",
        "scratchpad:application_skeptic_provider_authority_0001.json",
    }
    reconcile = next(
        value
        for key, value in owned.items()
        if key.endswith("/reconcile")
    )
    assert "scratchpad:application_skeptic_delivery_binding.json" in (
        reconcile["artifacts"]
    )


def test_application_queue_drift_rewinds_phase_and_untyped_descendant(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    _seed_base_queues(scratchpad)
    config = _config(tmp_path)
    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )
    assert receipt["status"] == "NOT_TRIGGERED" and issues == []

    downstream = D.Phase(
        "sc_semantic_dedup", ["Section"], ["dedup_decisions.md"],
        base_timeout_s=60, min_artifact_bytes=1,
    )
    (scratchpad / "dedup_decisions.md").write_text("done\n", encoding="utf-8")
    checkpoint = D.Checkpoint(
        completed=["application_skeptic", "sc_semantic_dedup"],
        run_id=str(config["_run_id"]),
    )
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    breadth_queue = scratchpad / "methodology_skeptic_queue_breadth.json"
    payload = json.loads(breadth_queue.read_text(encoding="utf-8"))
    payload["source_output_sha256s"] = ["a" * 64]
    breadth_queue.write_text(json.dumps(payload), encoding="utf-8")

    removed = D._reconcile_completed_checkpoint_artifacts(
        scratchpad,
        str(config["project_root"]),
        checkpoint,
        [_phase(), downstream],
        "core",
        "evm",
    )

    assert removed == ["application_skeptic", "sc_semantic_dedup"]
    assert checkpoint.completed == []


def test_claude_shard_agreement_without_terminal_provider_is_reopened_durably(
    tmp_path: Path, monkeypatch
):
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    home = tmp_path / "plamen_home"
    skill = home / "agents" / "oracle" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact oracle methodology\n", encoding="utf-8")
    _seed_base_queues(scratchpad, [_negative_state(skill)])
    config = _config(tmp_path)
    _install_provider_fixture(
        config,
        scratchpad,
        outcome="AGREE_NEGATIVE",
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)

    def launch(**kwargs):
        plan = json.loads(
            (scratchpad / "application_skeptic_work_plan.json").read_text()
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
                    "evidence": "src/Oracle.sol:L9 exact guard trace",
                    "rationale": "independent source trace supports the negative",
                    "candidate": None,
                }
                for work_id in shard["work_item_ids"]
            ],
        }
        (scratchpad / kwargs["job"]["output"]).write_text(
            json.dumps(payload), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )

    assert issues == []
    assert receipt["status"] == "COMPLETE"
    assert receipt["model_invoked"] is True
    disposition = receipt["work_dispositions"][0]
    assert disposition["disposition"] == "REGISTRY_CANDIDATE_PROPOSED"
    assert disposition["reason_code"] == "NONTERMINAL_NEGATIVE_SUPPORT_REOPENED"
    assert receipt["registry_candidate_proposals"]
    assert disposition["producer_identity"] == "B1"
    assert disposition["assessor_identity"].startswith("APPLICATION_SKEPTIC_")
    # Byte-exact resume: committed provider and reconcile authority are replayed
    # without another model invocation. Deleting a committed receipt is output
    # tamper, not a crash window, and must not be silently regenerated.
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("completed shard must not be re-launched")
        ),
    )
    resumed, resumed_issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )
    assert resumed_issues == []
    assert resumed["work_dispositions"] == receipt["work_dispositions"]

    # A committed output removed after the clean replay is explicit authority
    # debt. The driver may return an in-memory recall-safe disposition, but it
    # must not recreate and bless the missing canonical receipt.
    (scratchpad / "application_skeptic_receipt.json").unlink()
    tampered, tamper_issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )
    assert tampered["status"] == "COMPLETED_WITH_DEBT"
    assert any(
        "reexecution output authority mismatch" in issue
        for issue in tamper_issues
    )
    assert not (
        scratchpad / "application_skeptic_receipt.json"
    ).exists()


def test_claude_disagreement_uses_registered_askp_projection(
    tmp_path: Path, monkeypatch
):
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    home = tmp_path / "plamen_home"
    skill = home / "agents" / "oracle" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact oracle methodology\n", encoding="utf-8")
    _seed_base_queues(scratchpad, [_negative_state(skill)])
    config = _config(tmp_path)
    _install_provider_fixture(
        config,
        scratchpad,
        outcome="DISAGREE_CANDIDATE",
        candidate={
            "title": "Alternate state transition remains reachable",
            "mechanism": "The cited guard omits an alternate branch.",
            "harm": "State may be processed under inconsistent assumptions.",
        },
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kwargs: [])

    def launch(**kwargs):
        plan = json.loads(
            (scratchpad / "application_skeptic_work_plan.json").read_text()
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
                    "work_item_id": shard["work_item_ids"][0],
                    "assessor_id": assessor,
                    "assessor_invocation_id": invocation,
                    "outcome": "DISAGREE_CANDIDATE",
                    "evidence_basis": "IN_SCOPE_SOURCE",
                    "evidence": "src/Oracle.sol:L14 alternate reachable branch",
                    "rationale": "the alternate branch is not covered",
                    "candidate": {
                        "title": "Alternate state transition remains reachable",
                        "mechanism": "The cited guard omits an alternate branch.",
                        "harm": "State may be processed under inconsistent assumptions.",
                    },
                }
            ],
        }
        (scratchpad / kwargs["job"]["output"]).write_text(
            json.dumps(payload), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )

    assert issues == []
    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    projection = (scratchpad / "application_skeptic_proposals.md").read_text()
    assert "Finding [ASKP-1]" in projection
    assert receipt["registry_candidate_proposals"][0]["proposal_id"] in projection


def test_missing_active_queue_is_input_debt_not_silent_not_triggered(
    tmp_path: Path, monkeypatch
):
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    # Depth is active but its original queue is intentionally absent.
    S.write_application_queues(scratchpad, [], phase="breadth")
    config = _config(tmp_path)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kwargs: [])

    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )

    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert "MISSING_SOURCE_QUEUE" in issues
    assert receipt["model_invoked"] is False


def test_provider_published_assessment_tamper_preserves_last_good_additive_candidate(
    tmp_path: Path, monkeypatch
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    home = tmp_path / "plamen_home"
    skill = home / "agents" / "oracle" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact oracle methodology\n", encoding="utf-8")
    _seed_base_queues(scratchpad, [_negative_state(skill)])
    config = _config(tmp_path)
    _install_provider_fixture(
        config,
        scratchpad,
        outcome="AGREE_NEGATIVE",
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kwargs: [])

    first, first_issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )
    assert first["status"] == "COMPLETE" and first_issues == []
    assert first["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    first_proposals = first["registry_candidate_proposals"]
    first_projection = (scratchpad / "application_skeptic_proposals.md").read_bytes()
    assessment = scratchpad / "application_skeptic_assessments_0001.json"
    tampered = json.loads(assessment.read_text(encoding="utf-8"))
    tampered["assessments"][0]["rationale"] = "post-publication mutation"
    assessment.write_text(json.dumps(tampered), encoding="utf-8")

    second, second_issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )
    assert second["status"] == "COMPLETED_WITH_DEBT"
    assert second["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert second["registry_candidate_proposals"] == first_proposals
    assert (scratchpad / "application_skeptic_proposals.md").read_bytes() == (
        first_projection
    )
    assert any("last-good additive candidate" in issue for issue in second_issues)
    assert any(
        "skeptic provider unavailable" in issue
        or "skeptic provider PhaseIO arm invalid" in issue
        for issue in second_issues
    )


def test_codex_backend_is_explicit_additive_debt_without_launch(
    tmp_path: Path, monkeypatch
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    home = tmp_path / "plamen_home"
    skill = home / "agents" / "oracle" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# exact oracle methodology\n", encoding="utf-8")
    _seed_base_queues(scratchpad, [_negative_state(skill)])
    config = _config(tmp_path, backend="codex")
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kwargs: [])
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("unsupported Codex skeptic backend must not launch")
        ),
    )

    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert receipt["model_invoked"] is False
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert receipt["work_dispositions"][0]["proof_scope"] == "NONE"
    assert receipt["work_dispositions"][0]["terminal_negative_authorized"] is False
    assert any("CODEX_BACKEND_UNSUPPORTED_DEBT" in issue for issue in issues)


@pytest.mark.skipif(
    os.environ.get("PLAMEN_RUN_LIVE_CLAUDE_CANARY") != "1",
    reason="opt-in live Claude driver/provider canary",
)
def test_live_claude_driver_uses_provider_owned_strict_stdout(
    tmp_path: Path, monkeypatch
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    project = tmp_path / "project"
    source = project / "src" / "Oracle.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "contract Oracle {\n"
        "  uint256 value;\n"
        "  function set(uint256 next) external {\n"
        "    require(next != 0);\n"
        "    value = next;\n"
        "  }\n"
        "  function read() external view returns (uint256) {\n"
        "    return value;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    home = tmp_path / "plamen_home"
    skill = home / "agents" / "oracle" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(
        "# Oracle methodology\nIndependently validate the cited guard.\n",
        encoding="utf-8",
    )
    state = _negative_state(skill)
    _seed_base_queues(scratchpad, [state])
    config = _config(tmp_path)
    config["_auxiliary_writable_root_startup_binding"] = (
        durable_startup_permit(
            scratchpad,
            run_id=str(config["_run_id"]),
        )
    )
    config["project_root"] = str(project)
    config["_audit_snapshot"] = {
        "schema": "plamen.audit_snapshot.v3",
        "components": {"source_scope": {"digest": "a" * 64}},
        "snapshot_digest": "b" * 64,
    }
    config["application_skeptic_timeout_s"] = 240
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "phase_model", lambda *_args, **_kwargs: "claude-haiku-4-5")
    monkeypatch.setattr(D, "_record_application_skeptic_io", lambda **_kwargs: [])

    receipt, issues = D._run_application_skeptic_phase(
        _phase(), config, scratchpad
    )
    assert not any("skeptic provider unavailable" in issue for issue in issues), issues
    assert receipt["model_invoked"] is True
    assert (scratchpad / "application_skeptic_assessments_0001.json").is_file(), issues
    assert list((scratchpad / ".worker_execution_receipts").rglob("completion_*.json"))
