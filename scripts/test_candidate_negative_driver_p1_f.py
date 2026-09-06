from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys

import pytest

import candidate_negative_authority as N
import plamen_driver as D
from phase_io_contracts import resolve_phase_io_contract
from plamen_types import Phase, SC_PHASES
from test_support_startup_permit import durable_startup_permit


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    rule = home / "rules" / "finding-output-format.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("# exact role-aware finding contract\n", encoding="utf-8")
    return home


def _config(tmp_path: Path, *, active=()) -> dict[str, object]:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": "00000000-0000-4000-8000-000000000031",
        "_active_phase_names": list(active),
    }


def _discriminator_phase() -> Phase:
    return next(row for row in SC_PHASES if row.name == "application_skeptic")


def _depth_negative_source(ci_number: int, line: int) -> str:
    return (
        "### Finding [D-7]: candidate\n"
        "**Verdict**: REFUTED\n"
        f"**Location**: src/Vault.sol:L{line}\n"
        f"**Invariant Commitment**: CI:CI-{ci_number}\n\n"
        f"committed-invariant [CI-{ci_number}]\n"
        f"Locus: src/Vault.sol:L{line}\n"
        "Shape: FRESHNESS\n"
        "Assertion: the observed state is current at use\n"
        "Falsify Class: property\n"
        "Provenance: depth REFUTATION_PROPOSAL @ D-7\n"
    )


def _install_provider_fixture(
    config: dict[str, object],
    scratchpad: Path,
    *,
    outcome: str,
    candidate: dict[str, str] | None = None,
    fail: bool = False,
) -> None:
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


def test_phase_harvest_is_digest_bound_append_only_and_queue_disjoint(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    phase = Phase(
        "depth",
        ["Depth"],
        ["depth_*_findings.md"],
        base_timeout_s=60,
        min_artifact_bytes=1,
    )
    artifact = scratch / "depth_state_findings.md"
    artifact.write_text(_depth_negative_source(7, 7), encoding="utf-8")
    method_queue = scratch / "methodology_skeptic_queue_depth.json"
    method_queue.write_bytes(b"DO-NOT-MUTATE")

    issues = D._harvest_candidate_negative_phase(phase, _config(tmp_path), scratch)
    assert issues == []
    ledger_path = scratch / "candidate_negative_proposals_depth.json"
    first = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert first["event_count"] == 1
    assert method_queue.read_bytes() == b"DO-NOT-MUTATE"

    artifact.write_text(_depth_negative_source(8, 8), encoding="utf-8")
    rewrite_issues = D._harvest_candidate_negative_phase(
        phase, _config(tmp_path), scratch
    )
    # Input-driven deterministic refresh is invalidated and rebound before
    # the append-only projection is rewritten.
    assert rewrite_issues == ["CONFLICTING_ENTITY_CLAIM"]
    second = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert second["event_count"] == 2
    assert len({row["proposal_id"] for row in second["events"]}) == 1
    state = json.loads((scratch / "_artifact_state.json").read_text())
    unit = next(
        row
        for key, row in state["work_units"].items()
        if key.endswith("/candidate_negative_authority/harvest.depth")
    )
    assert len(unit["semantic_reexecution_history"]) == 1


def test_harvest_preserves_ambiguous_duplicate_key_prior_ledger(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    phase = Phase(
        "depth",
        ["Depth"],
        ["depth_*_findings.md"],
        base_timeout_s=60,
        min_artifact_bytes=1,
    )
    (scratch / "depth_state_findings.md").write_text(
        _depth_negative_source(7, 7), encoding="utf-8"
    )
    assert D._harvest_candidate_negative_phase(
        phase, _config(tmp_path), scratch
    ) == []
    path = scratch / "candidate_negative_proposals_depth.json"
    valid = path.read_text(encoding="utf-8")
    ambiguous = valid.replace(
        "{\n", '{\n  "schema_version": "plamen.candidate_negative_proposal_ledger.v1",\n', 1
    ).encode("utf-8")
    path.write_bytes(ambiguous)

    issues = D._harvest_candidate_negative_phase(
        phase, _config(tmp_path), scratch
    )

    assert any("duplicate JSON object key" in issue for issue in issues)
    assert path.read_bytes() == ambiguous


def test_missing_ci_without_assessment_reopens_into_preverify_union(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    phase = Phase(
        "depth",
        ["Depth"],
        ["depth_*_findings.md"],
        base_timeout_s=60,
        min_artifact_bytes=1,
    )
    (scratch / "depth_state_findings.md").write_text(
        "### Finding [D-9]: value path\n"
        "**Verdict**: REFUTED\n"
        "**Location**: src/Vault.sol:L9\n",
        encoding="utf-8",
    )
    issues = D._harvest_candidate_negative_phase(
        phase, _config(tmp_path), scratch
    )
    assert "DEPTH_COMMITTED_INVARIANT_DEBT" in issues
    plan = N.build_candidate_negative_application_plan(
        scratch, phases=("depth",), max_items_per_shard=4
    )
    assert plan["status"] == "INPUT_DEBT"
    delivered: list[dict[str, object]] = []
    receipt = N.adjudicate_candidate_negative(
        plan, [], candidate_sink=delivered.append
    )
    assert receipt["registry_candidate_proposals"] == delivered
    assert len(delivered) == 1
    D.write_application_skeptic_proposal_projection(
        scratch,
        delivered,
        projection_name=D.CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION,
    )
    scan = D._scan_registered_finding_delivery_sources(scratch)
    assert any(
        row.get("artifact") == D.CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION
        and row.get("source_action_count") == 1
        for row in scan["artifacts"]
    )


def test_empty_active_phase_still_writes_explicit_zero_denominator(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    phase = Phase(
        "attention_repair",
        ["Attention"],
        ["attention_repair_summary.md"],
        base_timeout_s=60,
        min_artifact_bytes=1,
    )
    (scratch / "attention_repair_summary.md").write_text(
        "| Queue # | Kind | Target | Verdict | Evidence | Notes |\n"
        "|---|---|---|---|---|---|\n"
        "| 1 | gap | src/A.sol | CONFIRMED | src/A.sol:L1 | finding A-1 |\n",
        encoding="utf-8",
    )
    assert D._harvest_candidate_negative_phase(phase, _config(tmp_path), scratch) == []
    ledger = json.loads(
        (scratch / "candidate_negative_proposals_attention_repair.json").read_text()
    )
    assert ledger["event_count"] == 0


def test_candidate_negative_phaseio_is_separate_and_disjoint() -> None:
    common = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
        "phase": "application_skeptic",
    }
    harvest = resolve_phase_io_contract(
        **{**common, "phase": "candidate_negative_authority"},
        work_unit_id="harvest.depth",
        exact_inputs=("depth_state_findings.md",),
        exact_outputs=("candidate_negative_proposals_depth.json",),
    )
    planning = resolve_phase_io_contract(
        **common, work_unit_id="negative.planning"
    )
    worker = resolve_phase_io_contract(
        **common,
        work_unit_id="negative.worker.0001",
        exact_outputs=(
            "candidate_negative_skeptic_assessments_0001.json",
            "candidate_negative_skeptic_provider_authority_0001.json",
        ),
    )
    reconcile = resolve_phase_io_contract(
        **common,
        work_unit_id="negative.reconcile",
        exact_inputs=("candidate_negative_skeptic_assessments_0001.json",),
    )
    assert harvest.model_invoked is False
    assert planning.model_invoked is False
    assert len(planning.immutable_inputs) == 4
    assert worker.model_invoked is True
    assert {row.path for row in worker.outputs} == {
        "candidate_negative_skeptic_assessments_0001.json",
        "candidate_negative_skeptic_provider_authority_0001.json",
    }
    assert {row.writer for row in worker.outputs} == {"DRIVER"}
    assert reconcile.model_invoked is False
    assert not (
        {row.identity for row in reconcile.outputs}
        & set(reconcile.immutable_inputs)
    )


def _seed_candidate_ledger(tmp_path: Path, scratch: Path, home: Path) -> None:
    rule = home / "rules" / "finding-output-format.md"
    ledger = N.build_candidate_negative_ledger(
        phase="breadth",
        artifacts=[
            N.ArtifactInput(
                relative_path="analysis_state.md",
                content=(
                    "### Finding [B-4]: candidate\n"
                    "**Verdict**: REFUTED\n"
                    "**Location**: src/A.sol:L4\n"
                ).encode(),
                producer_identity="BREADTH_ORIGINAL",
                producer_invocation_id="BREADTH-RUN",
            )
        ],
        methodology_path=rule,
    )
    N.write_candidate_negative_ledger(scratch, ledger)


def test_separate_runtime_discriminator_reopens_candidate(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    _seed_candidate_ledger(tmp_path, scratch, home)
    config = _config(tmp_path, active=("breadth", "application_skeptic"))
    _install_provider_fixture(
        config,
        scratch,
        outcome="DISAGREE_CANDIDATE",
        candidate={
            "title": "Reopened candidate",
            "mechanism": "The proposed guard omits a reachable transition.",
            "harm": "A protected state property may be violated.",
        },
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(
        D, "_record_candidate_negative_skeptic_io", lambda **_kwargs: []
    )

    def launch(**kwargs):
        plan = json.loads(
            (scratch / "candidate_negative_skeptic_work_plan.json").read_text()
        )
        shard = plan["shards"][0]
        assessor, invocation = D._candidate_negative_assessor_identity(
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
                    "evidence": "src/A.sol:L4 independent alternate-path trace",
                    "rationale": "the producer premise is incomplete",
                    "candidate": {
                        "title": "Reopened candidate",
                        "mechanism": "The proposed guard omits a reachable transition.",
                        "harm": "A protected state property may be violated.",
                    },
                }
            ],
        }
        (scratch / kwargs["job"]["output"]).write_text(json.dumps(payload))
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    receipt, issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    assert issues == []
    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    projection = (scratch / "candidate_negative_skeptic_proposals.md").read_text()
    assert "Finding [ASKP-1]" in projection


def test_candidate_negative_arms_plan_provider_and_reconcile_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    _seed_candidate_ledger(tmp_path, scratch, home)
    config = _config(
        tmp_path, active=("breadth", "application_skeptic")
    )
    _install_provider_fixture(
        config,
        scratch,
        outcome="DISAGREE_CANDIDATE",
        candidate={
            "title": "Reopened candidate",
            "mechanism": "A reachable transition remains unreviewed.",
            "harm": "A protected state property may be violated.",
        },
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    real_arm = D._arm_deterministic_driver_work_unit
    observed: list[str] = []

    def arm(*, contract, **kwargs):
        if (
            contract.phase == "application_skeptic"
            and contract.work_unit_id.startswith("negative.")
        ):
            assert all(
                not (scratch / output.path).exists()
                for output in contract.outputs
            )
            observed.append(contract.work_unit_id)
        return real_arm(contract=contract, **kwargs)

    monkeypatch.setattr(D, "_arm_deterministic_driver_work_unit", arm)
    receipt, issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )

    assert issues == []
    assert receipt["status"] == "COMPLETE"
    assert observed == [
        "negative.planning",
        "negative.worker.0001",
        "negative.reconcile",
    ]
    units = D.read_artifact_ledger(scratch)["work_units"]
    owned = {
        key: value
        for key, value in units.items()
        if "/application_skeptic/negative." in key
    }
    assert {
        value["semantic_status"] for value in owned.values()
    } == {"ACTIVE"}
    worker = next(
        value
        for key, value in owned.items()
        if key.endswith("/negative.worker.0001")
    )
    assert set(worker["artifacts"]) == {
        "scratchpad:candidate_negative_skeptic_assessments_0001.json",
        "scratchpad:candidate_negative_skeptic_provider_authority_0001.json",
    }


def test_empty_or_missing_runtime_denominator_never_self_certifies(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    config = _config(tmp_path, active=("breadth", "application_skeptic"))
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(
        D, "_record_candidate_negative_skeptic_io", lambda **_kwargs: []
    )
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("no work")),
    )
    receipt, issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert any("MISSING_CANDIDATE_NEGATIVE_LEDGER" in issue for issue in issues)


def test_child_containment_detects_project_file_deletion(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    victim = project / "source.sol"
    victim.write_text("contract Source {}\n", encoding="utf-8")
    before = D._snapshot_application_skeptic_child_boundary(scratch, project)
    victim.unlink()
    offenders = D._application_skeptic_child_containment_offenders(
        scratch, project, before, exact_output="assessment.json"
    )
    assert offenders == ["../source.sol"]


def test_legacy_model_authored_assessment_is_quarantined_before_provider_launch(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    _seed_candidate_ledger(tmp_path, scratch, home)
    config = _config(tmp_path, active=("breadth", "application_skeptic"))
    _install_provider_fixture(
        config,
        scratch,
        outcome="AGREE_NEGATIVE",
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(
        D, "_record_candidate_negative_skeptic_io", lambda **_kwargs: []
    )

    def launch(**kwargs):
        plan = json.loads(
            (scratch / "candidate_negative_skeptic_work_plan.json").read_text()
        )
        shard = plan["shards"][0]
        assessor, invocation = D._candidate_negative_assessor_identity(
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
                    "outcome": "AGREE_NEGATIVE",
                    "evidence_basis": "IN_SCOPE_SOURCE",
                    "evidence": "src/A.sol:L4 independent source trace",
                    "rationale": "independent assessment",
                    "candidate": None,
                }
            ],
        }
        (scratch / kwargs["job"]["output"]).write_text(json.dumps(payload))
        (scratch / "verify_foreign.md").write_text("foreign", encoding="utf-8")
        return 0

    legacy = scratch / "candidate_negative_skeptic_assessments_0001.json"
    legacy.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    receipt, issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    assert receipt["status"] == "COMPLETE"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert any("quarantined legacy unauthenticated" in issue for issue in issues)
    assert legacy.is_file()


def test_failed_quarantine_cannot_leave_terminal_negative_agreement(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    _seed_candidate_ledger(tmp_path, scratch, home)
    config = _config(tmp_path, active=("breadth", "application_skeptic"))
    _install_provider_fixture(
        config,
        scratch,
        outcome="AGREE_NEGATIVE",
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(
        D, "_record_candidate_negative_skeptic_io", lambda **_kwargs: []
    )

    def launch(**kwargs):
        plan = json.loads(
            (scratch / "candidate_negative_skeptic_work_plan.json").read_text()
        )
        shard = plan["shards"][0]
        assessor, invocation = D._candidate_negative_assessor_identity(
            config, plan["work_plan_digest"], shard["shard_id"]
        )
        payload = {
            "schema_version": "plamen.application_skeptic_assessments.v1",
            "work_plan_digest": plan["work_plan_digest"],
            "shard_id": shard["shard_id"],
            "assessments": [{
                "work_item_id": shard["work_item_ids"][0],
                "assessor_id": assessor,
                "assessor_invocation_id": invocation,
                "outcome": "AGREE_NEGATIVE",
                "evidence_basis": "IN_SCOPE_SOURCE",
                "evidence": "src/A.sol:L4 independent source trace",
                "rationale": "independent assessment",
                "candidate": None,
            }],
        }
        (scratch / kwargs["job"]["output"]).write_text(json.dumps(payload))
        (scratch / "verify_foreign.md").write_text("foreign", encoding="utf-8")
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    monkeypatch.setattr(
        D,
        "_quarantine_foreign_phase_writes",
        lambda _scratch, _project, _phase, offenders: ([], list(offenders)),
    )
    (scratch / "candidate_negative_skeptic_assessments_0001.json").write_text(
        "{}", encoding="utf-8"
    )
    receipt, issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert receipt["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert receipt["work_dispositions"][0]["proof_scope"] == "NONE"
    assert receipt["work_dispositions"][0]["terminal_negative_authorized"] is False
    assert any("remains live" in issue for issue in issues)


def test_lost_provider_authority_degrades_instead_of_self_relaunching(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    _seed_candidate_ledger(tmp_path, scratch, home)
    config = _config(tmp_path, active=("breadth", "application_skeptic"))
    _install_provider_fixture(
        config,
        scratch,
        outcome="AGREE_NEGATIVE",
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(
        D, "_record_candidate_negative_skeptic_io", lambda **_kwargs: []
    )
    launches: list[str] = []

    def launch(**kwargs):
        launches.append(kwargs["job"]["output"])
        plan = json.loads(
            (scratch / "candidate_negative_skeptic_work_plan.json").read_text()
        )
        shard = plan["shards"][0]
        assessor, invocation = D._candidate_negative_assessor_identity(
            config, plan["work_plan_digest"], shard["shard_id"]
        )
        payload = {
            "schema_version": "plamen.application_skeptic_assessments.v1",
            "work_plan_digest": plan["work_plan_digest"],
            "shard_id": shard["shard_id"],
            "assessments": [{
                "work_item_id": shard["work_item_ids"][0],
                "assessor_id": assessor,
                "assessor_invocation_id": invocation,
                "outcome": "AGREE_NEGATIVE",
                "evidence_basis": "IN_SCOPE_SOURCE",
                "evidence": "src/A.sol:L4 independent source trace",
                "rationale": "independent assessment",
                "candidate": None,
            }],
        }
        (scratch / kwargs["job"]["output"]).write_text(json.dumps(payload))
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    first, first_issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    assert first["status"] == "COMPLETE"
    assert first_issues == []
    authority = scratch / ".worker_execution_receipts"
    assert authority.is_dir()
    shutil.rmtree(authority)

    second, second_issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    assert second["status"] == "COMPLETED_WITH_DEBT"
    assert any("skeptic provider" in row for row in second_issues)


def test_valid_driver_execution_completion_allows_byte_exact_resume(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    _seed_candidate_ledger(tmp_path, scratch, home)
    config = _config(tmp_path, active=("breadth", "application_skeptic"))
    _install_provider_fixture(
        config,
        scratch,
        outcome="AGREE_NEGATIVE",
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(
        D, "_record_candidate_negative_skeptic_io", lambda **_kwargs: []
    )
    launches: list[str] = []

    def launch(**kwargs):
        launches.append(kwargs["job"]["output"])
        plan = json.loads(
            (scratch / "candidate_negative_skeptic_work_plan.json").read_text()
        )
        shard = plan["shards"][0]
        assessor, invocation = D._candidate_negative_assessor_identity(
            config, plan["work_plan_digest"], shard["shard_id"]
        )
        payload = {
            "schema_version": "plamen.application_skeptic_assessments.v1",
            "work_plan_digest": plan["work_plan_digest"],
            "shard_id": shard["shard_id"],
            "assessments": [{
                "work_item_id": shard["work_item_ids"][0],
                "assessor_id": assessor,
                "assessor_invocation_id": invocation,
                "outcome": "AGREE_NEGATIVE",
                "evidence_basis": "IN_SCOPE_SOURCE",
                "evidence": "src/A.sol:L4 independent source trace",
                "rationale": "independent assessment",
                "candidate": None,
            }],
        }
        (scratch / kwargs["job"]["output"]).write_text(json.dumps(payload))
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    first, _ = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    before = sorted(
        path.read_bytes()
        for path in (scratch / ".worker_execution_receipts").rglob(
            "completion_*.json"
        )
    )
    second, second_issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    after = sorted(
        path.read_bytes()
        for path in (scratch / ".worker_execution_receipts").rglob(
            "completion_*.json"
        )
    )
    assert first["status"] == second["status"] == "COMPLETE"
    assert second_issues == []
    assert before == after and len(after) == 1


def test_failed_resume_reassessment_preserves_last_good_reopened_candidate(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    _seed_candidate_ledger(tmp_path, scratch, home)
    config = _config(tmp_path, active=("breadth", "application_skeptic"))
    _install_provider_fixture(
        config,
        scratch,
        outcome="DISAGREE_CANDIDATE",
        candidate={
            "title": "Reopened candidate",
            "mechanism": "The claimed guard omits a reachable transition.",
            "harm": "A protected state property may be violated.",
        },
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(
        D, "_record_candidate_negative_skeptic_io", lambda **_kwargs: []
    )

    def successful_launch(**kwargs):
        plan = json.loads(
            (scratch / "candidate_negative_skeptic_work_plan.json").read_text()
        )
        shard = plan["shards"][0]
        assessor, invocation = D._candidate_negative_assessor_identity(
            config, plan["work_plan_digest"], shard["shard_id"]
        )
        payload = {
            "schema_version": "plamen.application_skeptic_assessments.v1",
            "work_plan_digest": plan["work_plan_digest"],
            "shard_id": shard["shard_id"],
            "assessments": [{
                "work_item_id": shard["work_item_ids"][0],
                "assessor_id": assessor,
                "assessor_invocation_id": invocation,
                "outcome": "DISAGREE_CANDIDATE",
                "evidence_basis": "IN_SCOPE_SOURCE",
                "evidence": "src/A.sol:L4 independent alternate-path trace",
                "rationale": "the producer premise remains open",
                "candidate": {
                    "title": "Reopened candidate",
                    "mechanism": "The claimed guard omits a reachable transition.",
                    "harm": "A protected state property may be violated.",
                },
            }],
        }
        (scratch / kwargs["job"]["output"]).write_text(json.dumps(payload))
        return 0

    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker", successful_launch
    )
    first, first_issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )
    assert first["status"] == "COMPLETE"
    assert first_issues == []
    prior_projection = (
        scratch / "candidate_negative_skeptic_proposals.md"
    ).read_bytes()
    shutil.rmtree(scratch / ".worker_execution_receipts")
    _install_provider_fixture(
        config,
        scratch,
        outcome="DISAGREE_CANDIDATE",
        candidate={
            "title": "Reopened candidate",
            "mechanism": "The claimed guard omits a reachable transition.",
            "harm": "A protected state property may be violated.",
        },
        fail=True,
    )

    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **_kwargs: 1,
    )
    second, second_issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )

    assert second["status"] == "COMPLETED_WITH_DEBT"
    assert second["registry_candidate_proposals"] == first[
        "registry_candidate_proposals"
    ]
    assert second["work_dispositions"][0]["disposition"] == (
        "REGISTRY_CANDIDATE_PROPOSED"
    )
    assert any("last-good reopened candidate" in issue for issue in second_issues)
    assert (
        scratch / "candidate_negative_skeptic_proposals.md"
    ).read_bytes() == prior_projection


def test_driver_source_wires_harvest_after_accepted_producer_boundary() -> None:
    source = Path(D.__file__).read_text(encoding="utf-8")
    accepted = source.index("_run_methodology_application_boundary(")
    harvest = source.index("_harvest_candidate_negative_phase(", accepted)
    skeptic = source.index("_run_candidate_negative_skeptic_boundary(")
    assert accepted < harvest < skeptic


@pytest.mark.skipif(
    os.environ.get("PLAMEN_RUN_LIVE_CLAUDE_CANARY") != "1",
    reason="opt-in live Claude candidate-negative driver/provider canary",
)
def test_live_claude_candidate_negative_uses_shared_provider_stdout(
    tmp_path: Path, monkeypatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = _home(tmp_path)
    _seed_candidate_ledger(tmp_path, scratch, home)
    config = _config(tmp_path, active=("breadth", "application_skeptic"))
    config["_auxiliary_writable_root_startup_binding"] = (
        durable_startup_permit(
            scratch,
            run_id=str(config["_run_id"]),
        )
    )
    project = Path(str(config["project_root"]))
    source = project / "src" / "A.sol"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "contract A {\n"
        "  uint256 value;\n"
        "  function set(uint256 next) external {\n"
        "    value = next;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    config["_audit_snapshot"] = {
        "schema": "plamen.audit_snapshot.v3",
        "components": {"source_scope": {"digest": "a" * 64}},
        "snapshot_digest": "b" * 64,
    }
    config["application_skeptic_timeout_s"] = 240
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "phase_model", lambda *_args, **_kwargs: "claude-haiku-4-5")
    monkeypatch.setattr(
        D, "_record_candidate_negative_skeptic_io", lambda **_kwargs: []
    )

    receipt, issues = D._run_candidate_negative_skeptic_boundary(
        _discriminator_phase(), config, scratch
    )

    assert not any("skeptic provider unavailable" in issue for issue in issues), issues
    assert receipt["model_invoked"] is True
    assert (scratch / "candidate_negative_skeptic_assessments_0001.json").is_file()
    completions = list(
        (scratch / ".worker_execution_receipts").rglob("completion_*.json")
    )
    assert len(completions) == 1
