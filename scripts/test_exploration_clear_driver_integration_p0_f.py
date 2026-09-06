from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import plamen_driver as D
from plamen_types import Phase


def _config(project: Path, *, backend: str = "claude", mode: str = "thorough") -> dict:
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": mode,
        "language": "evm",
        "cli_backend": backend,
        "_run_id": "12345678-1234-4567-8abc-1234567890ab",
    }


def _phase() -> Phase:
    return Phase(
        "exploration_skeptic",
        ["Phase 4b.6"],
        ["exploration_skeptic_findings.md"],
        base_timeout_s=120,
        modes={"thorough"},
        critical=False,
        model="sonnet",
    )


def _write_source(scratch: Path, evidence: str = "generic wording only") -> Path:
    source = scratch / "exploration_skeptic_findings.md"
    source.write_text(
        "# Exploration\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        f"| INV-1 | sibling path | alternate branch | NO-GAP | {evidence} |\n\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )
    return source


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("newline", (b"\n", b"\r\n"), ids=("lf", "crlf"))
def test_upstream_exploration_model_has_exact_backend_neutral_raw_contract(
    tmp_path: Path, backend: str, newline: bytes,
) -> None:
    project = tmp_path / backend / newline.hex()
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    phase = _phase()
    config = _config(project, backend=backend)
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    source = (
        "# Exploration\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| INV-1 | sibling | branch | ADD | ECLRADD-1 |\n"
    ).encode("utf-8").replace(b"\n", newline)
    (scratch / "exploration_skeptic_findings.md").write_bytes(source)
    assert D._record_typed_model_phase_artifacts(
        phase, scratch, config
    ) == []
    contract, launch = D._typed_model_phase_contract_and_launch(
        phase, scratch, config
    )
    assert contract is not None and launch is not None
    assert D.validate_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="MODEL",
    ) == []


def _repair_response(scratch: Path) -> str:
    plan = json.loads(
        (scratch / "exploration_clear_repair_plan.json").read_text(encoding="utf-8")
    )
    oid = plan["obligation_ids"][0]
    return (
        "# Exploration Clear Repair\n\n"
        f"**Plan ID**: {plan['plan_id']}\n"
        f"**Plan Hash**: {plan['plan_hash']}\n\n"
        "## Repair Dispositions\n\n"
        "| Obligation ID | Disposition | Evidence | Action ID | Rationale |\n"
        "|---|---|---|---|---|\n"
        f"| {oid} | ADD | source observation retained for verification | "
        "ECLRADD-1 | independent exploration required |\n"
    )


def test_claude_repair_is_armed_once_reconciled_and_resume_stable(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "Contract.sol").write_text("line1\nline2\n", encoding="utf-8")
    _write_source(scratch)

    launches: list[str] = []

    def fake_claude(**kwargs) -> int:
        launches.append(kwargs["prompt"])
        assert (scratch / "exploration_clear_repair_attempt.json").is_file()
        assert "SCOPE: Write ONLY" in kwargs["prompt"]
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", fake_claude)
    issues = D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    )
    assert issues == []
    assert len(launches) == 1
    receipt_bytes = (scratch / "exploration_clear_receipt.json").read_bytes()
    queue_bytes = (scratch / "exploration_clear_obligations.json").read_bytes()
    receipt = json.loads(receipt_bytes)
    assert receipt["repair_attempts"] == 1
    assert receipt["status"] == "ADDITIVE"
    assert receipt["additive_actions"][0]["proof_scope"] == "UNVERIFIED_GENERATOR_OUTPUT"
    assert json.loads(queue_bytes)["count"] == 0

    # Identical resume is byte-stable and never invokes a second model attempt.
    issues = D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    )
    assert issues == []
    assert len(launches) == 1
    assert (scratch / "exploration_clear_receipt.json").read_bytes() == receipt_bytes
    assert (scratch / "exploration_clear_obligations.json").read_bytes() == queue_bytes
    assert D._exploration_clear_resume_issues(
        scratch, project, mode="thorough"
    ) == []


def test_timeout_is_one_shot_visible_debt_and_exact_queue(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_source(scratch)
    launches = 0

    def timeout(**_kwargs) -> int:
        nonlocal launches
        launches += 1
        return -2

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", timeout)
    issues = D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    )
    assert launches == 1
    assert any("repair unavailable" in issue.lower() for issue in issues)
    receipt = json.loads(
        (scratch / "exploration_clear_receipt.json").read_text(encoding="utf-8")
    )
    queue = json.loads(
        (scratch / "exploration_clear_obligations.json").read_text(encoding="utf-8")
    )
    assert receipt["repair_attempts"] == 1
    assert receipt["status"] == "DEGRADED"
    assert queue["count"] == 1
    assert queue["tail"] == queue["items"][0]["obligation_id"]
    assert hashlib.sha256(
        json.dumps(
            {key: value for key, value in queue.items() if key != "queue_hash"},
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest() == queue["queue_hash"]

    D._run_exploration_clear_lifecycle(_phase(), _config(project), scratch)
    assert launches == 1


def test_uncommitted_legacy_arm_is_proposal_only_and_does_not_consume_attempt(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    source = _write_source(scratch)
    initial = D.compile_initial_receipt(
        source, production_root=project, canonical_prior_ids={}
    )
    plan = D.build_repair_plan(initial)
    assert plan is not None
    D.write_lifecycle_artifacts(scratch, initial, plan=plan)
    (scratch / "exploration_clear_repair_attempt.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.exploration_clear_repair_attempt.v1",
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "source_receipt_hash": plan.source_receipt_hash,
                "invocation_id": "ECRA-INTERRUPTED",
                "status": "ARMED",
                "backend": "claude",
                "model": "sonnet",
                "return_code": None,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    launches = 0

    def launch(**_kwargs) -> int:
        nonlocal launches
        launches += 1
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    issues = D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    )
    assert issues == []
    assert launches == 1
    receipt = json.loads(
        (scratch / "exploration_clear_receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["repair_attempts"] == 1
    assert receipt["status"] == "ADDITIVE"
    assert list(
        (scratch / "_exploration_clear_quarantine").glob(
            "exploration_clear_repair_attempt.json.*"
        )
    )


def test_codex_path_and_non_thorough_noop(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_source(scratch)
    codex_launches = 0

    def fake_codex(**kwargs) -> int:
        nonlocal codex_launches
        codex_launches += 1
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_codex_exec", fake_codex)
    assert D._run_exploration_clear_lifecycle(
        _phase(), _config(project, backend="codex"), scratch
    ) == []
    assert codex_launches == 1

    other = tmp_path / "core" / ".scratchpad"
    other.mkdir(parents=True)
    _write_source(other)
    assert D._run_exploration_clear_lifecycle(
        _phase(), _config(other.parent, mode="core"), other
    ) == []
    assert not (other / "exploration_clear_receipt.json").exists()


def _seed_preexisting_repair_response(project: Path) -> tuple[Path, object]:
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    source = _write_source(scratch)
    initial = D.compile_initial_receipt(
        source, production_root=project, canonical_prior_ids={}
    )
    plan = D.build_repair_plan(initial)
    assert plan is not None
    D.write_lifecycle_artifacts(scratch, initial, plan=plan)
    (scratch / "exploration_clear_repair_response.md").write_text(
        _repair_response(scratch), encoding="utf-8"
    )
    return scratch, plan


def test_preexisting_response_without_same_run_model_receipt_is_proposal_only(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch, _plan = _seed_preexisting_repair_response(project)
    launches = 0

    def launch(**_kwargs) -> int:
        nonlocal launches
        launches += 1
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    issues = D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    )

    assert launches == 1
    assert not any("unowned existing output" in issue.lower() for issue in issues)
    receipt = json.loads(
        (scratch / "exploration_clear_receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["repair_attempts"] == 1
    assert receipt["status"] == "ADDITIVE"
    quarantined = list(
        (scratch / "_exploration_clear_quarantine").glob(
            "exploration_clear_repair_response.md.*"
        )
    )
    assert quarantined


def test_worker_phaseio_debt_blocks_response_semantic_consumption(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_source(scratch)

    def launch(**_kwargs) -> int:
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    monkeypatch.setattr(
        D,
        "_record_exploration_clear_worker_output",
        lambda **_kwargs: ["injected worker output PhaseIO debt"],
    )
    issues = D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    )
    receipt = json.loads(
        (scratch / "exploration_clear_receipt.json").read_text(encoding="utf-8")
    )

    assert any("injected worker output PhaseIO debt" in issue for issue in issues)
    assert receipt["status"] == "DEGRADED"
    assert receipt["additive_actions"] == []
    assert receipt["obligations"]


def test_rehashed_lifecycle_receipt_cannot_drop_or_invent_semantics(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_source(scratch)
    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker", lambda **_kwargs: -2
    )
    D._run_exploration_clear_lifecycle(_phase(), _config(project), scratch)
    receipt_path = scratch / "exploration_clear_receipt.json"
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["obligations"] = []
    payload["additive_actions"] = [{
        "action_id": "ECLRADD-999",
        "obligation_id": "ECLR-" + ("A" * 24),
        "source_finding": "INV-999",
        "axis": "invented",
        "instance": "invented",
        "evidence": "invented",
        "rationale": "invented",
        "artifact_sha256": payload["artifact_sha256"],
        "source_row_sha256": "a" * 64,
        "source_line": 1,
        "proof_scope": "UNVERIFIED_GENERATOR_OUTPUT",
        "requires_independent_consumer": True,
    }]
    payload["status"] = "ADDITIVE"
    payload["receipt_hash"] = D._stable_payload_digest({
        key: value for key, value in payload.items() if key != "receipt_hash"
    })
    receipt_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    issues = D._exploration_clear_resume_issues(
        scratch, project, mode="thorough"
    )
    assert any("semantic" in issue.lower() for issue in issues)


def test_crash_after_attempt_write_before_launch_does_not_consume_one_shot(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_source(scratch)
    launches = 0

    def crash(**_kwargs) -> int:
        nonlocal launches
        launches += 1
        raise KeyboardInterrupt("crash before provider launch")

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", crash)
    try:
        D._run_exploration_clear_lifecycle(_phase(), _config(project), scratch)
    except KeyboardInterrupt:
        pass
    receipt = json.loads(
        (scratch / "exploration_clear_receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["repair_attempts"] == 0

    def success(**_kwargs) -> int:
        nonlocal launches
        launches += 1
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker", success
    )
    assert D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    ) == []
    assert launches == 2


@pytest.mark.parametrize(
    "boundary",
    ("initial_compile.repair", "repair_plan", "repair_arm"),
)
def test_committed_preprovider_boundary_resumes_without_consuming_model(
    tmp_path: Path, monkeypatch, boundary: str,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_source(scratch)
    original_transaction = D._exploration_clear_driver_transaction
    crashed: list[str] = []
    launches = 0

    def crash_after_transaction(**kwargs):
        result = original_transaction(**kwargs)
        work_unit_id = kwargs["work_unit_id"]
        if not result and work_unit_id == boundary and not crashed:
            crashed.append(work_unit_id)
            raise KeyboardInterrupt(f"crash after {boundary}")
        return result

    def success(**_kwargs) -> int:
        nonlocal launches
        launches += 1
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(
        D, "_exploration_clear_driver_transaction", crash_after_transaction
    )
    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", success)
    with pytest.raises(KeyboardInterrupt, match=f"crash after {boundary}"):
        D._run_exploration_clear_lifecycle(_phase(), _config(project), scratch)
    assert len(crashed) == 1
    assert launches == 0
    ledger = D.read_artifact_ledger(scratch)
    assert any(
        key.endswith(f"/{boundary}")
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
        for key, unit in ledger["work_units"].items()
    )

    monkeypatch.setattr(
        D, "_exploration_clear_driver_transaction", original_transaction
    )
    assert D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    ) == []
    assert launches == 1
    frozen = {
        name: (scratch / name).read_bytes()
        for name in (
            "exploration_clear_receipt.json",
            "exploration_clear_obligations.json",
            "exploration_clear_repair_plan.json",
        )
    }
    assert D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    ) == []
    assert launches == 1
    assert {
        name: (scratch / name).read_bytes()
        for name in frozen
    } == frozen


def test_success_uses_distinct_immutable_phaseio_transactions(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_source(scratch)

    def launch(**_kwargs) -> int:
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    assert D._run_exploration_clear_lifecycle(
        _phase(), _config(project), scratch
    ) == []
    units = json.loads(
        (scratch / "_artifact_state.json").read_text(encoding="utf-8")
    )["work_units"]
    suffixes = {
        key.rsplit("/exploration_clear/", 1)[-1]
        for key in units
        if "/exploration_clear/" in key
        and units[key].get("execution_state") == "OUTPUT_COMMITTED"
    }
    assert {
        "alias_authority",
        "initial_compile.repair",
        "repair_plan",
        "repair_arm",
        "worker.0001",
        "repair_reconcile",
    }.issubset(suffixes)
    initial_key = next(
        key for key in units if key.endswith("/initial_compile.repair")
    )
    plan_key = next(key for key in units if key.endswith("/repair_plan"))
    reconcile_key = next(
        key for key in units if key.endswith("/repair_reconcile")
    )
    assert set(units[initial_key]["artifacts"]) == {
        "scratchpad:exploration_clear_receipt.json",
        "scratchpad:exploration_clear_obligations.json",
    }
    assert set(units[plan_key]["artifacts"]) == {
        "scratchpad:exploration_clear_repair_plan.json",
    }
    ledger = D.read_artifact_ledger(scratch)
    assert ledger["artifact_bindings"][
        "scratchpad:exploration_clear_repair_plan.json"
    ]["owner_key"] == plan_key
    for name in (
        "exploration_clear_receipt.json",
        "exploration_clear_obligations.json",
    ):
        assert ledger["artifact_bindings"][f"scratchpad:{name}"][
            "owner_key"
        ] == reconcile_key
    assert "lifecycle" not in suffixes


def test_repair_plan_contract_is_dedicated_model_free_and_strict(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    inputs = (
        "exploration_skeptic_findings.md",
        "exploration_clear_prior_aliases.json",
        "project::Contract.sol",
    )
    contract, launch = D._exploration_clear_contract_launch(
        phase=_phase(),
        config=config,
        work_unit_id="repair_plan",
        exact_outputs=("exploration_clear_repair_plan.json",),
        exact_inputs=inputs,
        actor="DRIVER",
        model="driver",
        timeout_s=120,
    )
    assert contract.work_unit_id == "repair_plan"
    assert contract.model_invoked is False
    assert contract.immutable_inputs == tuple(sorted((
        "scratchpad:exploration_skeptic_findings.md",
        "scratchpad:exploration_clear_prior_aliases.json",
        "project:Contract.sol",
    )))
    assert len(contract.outputs) == 1
    assert contract.outputs[0].path == "exploration_clear_repair_plan.json"
    assert contract.outputs[0].writer == "DRIVER"
    assert launch.exec_mode == "python"
    for bad_outputs, bad_inputs in (
        (("exploration_clear_receipt.json",), inputs),
        (("exploration_clear_repair_plan.json",), inputs[:1]),
        (("exploration_clear_repair_plan.json",), (*inputs, inputs[-1])),
        (
            ("exploration_clear_repair_plan.json",),
            (*inputs[:2], "project::z.sol", "project::a.sol"),
        ),
    ):
        with pytest.raises(ValueError):
            D._exploration_clear_contract_launch(
                phase=_phase(),
                config=config,
                work_unit_id="repair_plan",
                exact_outputs=bad_outputs,
                exact_inputs=bad_inputs,
                actor="DRIVER",
                model="driver",
                timeout_s=120,
            )


@pytest.mark.parametrize("failure", ("issue", "base_exception"))
def test_reconcile_failure_restores_the_committed_provisional_pair(
    tmp_path: Path, monkeypatch, failure: str,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_source(scratch)

    def launch(**_kwargs) -> int:
        (scratch / "exploration_clear_repair_response.md").write_text(
            _repair_response(scratch), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)
    original_commit = D._commit_deterministic_driver_work_unit
    reached: list[str] = []

    def fail_reconcile(**kwargs):
        contract = kwargs["contract"]
        if contract.work_unit_id == "repair_reconcile":
            reached.append(contract.key)
            if failure == "base_exception":
                raise KeyboardInterrupt("injected reconcile crash")
            return [f"{contract.key}: injected commit refusal"]
        return original_commit(**kwargs)

    monkeypatch.setattr(D, "_commit_deterministic_driver_work_unit", fail_reconcile)
    if failure == "base_exception":
        with pytest.raises(KeyboardInterrupt, match="injected reconcile crash"):
            D._run_exploration_clear_lifecycle(
                _phase(), _config(project), scratch
            )
    else:
        issues = D._run_exploration_clear_lifecycle(
            _phase(), _config(project), scratch
        )
        assert any("injected commit refusal" in issue for issue in issues)
    assert len(reached) == 1
    ledger = D.read_artifact_ledger(scratch)
    for name in (
        "exploration_clear_receipt.json",
        "exploration_clear_obligations.json",
    ):
        binding = ledger["artifact_bindings"][f"scratchpad:{name}"]
        assert binding["owner_key"].endswith("/initial_compile.repair")
        assert D._sha256_bytes((scratch / name).read_bytes()) == binding["sha256"]


def test_live_postprocessor_projects_open_obligation_into_phase_commit_debt(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    phase = _phase()
    config = _config(project)
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    _write_source(scratch)
    monkeypatch.setattr(D, "gate_passes", lambda *_args, **_kwargs: (True, []))
    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker", lambda **_kwargs: -2
    )

    passed, missing = D._run_phase_validators(
        phase,
        config,
        scratch,
        [phase],
        0,
        {},
    )
    assert passed is False
    assert any("exploration-clear" in issue for issue in missing)
    assert any("committed-invariant" in issue for issue in missing)
    sentinel = (scratch / "exploration_skeptic.degraded").read_text(
        encoding="utf-8"
    )
    assert "EXPLORATION_CLEAR_DEBT" in sentinel
    assert "ECLR-" in sentinel

    checkpoint = D.Checkpoint(run_id=config["_run_id"])
    commit = D._commit_phase_from_disk_debt(
        phase,
        checkpoint,
        scratch,
        config,
        [phase],
        clean_transients=True,
    )
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert commit.unresolved_failures
    assert "exploration_skeptic" in checkpoint.completed
    assert "exploration_skeptic" in checkpoint.degraded


def test_late_ci_authority_failure_makes_skeptic_phase_incomplete(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    phase = Phase(
        "skeptic",
        ["Skeptic"],
        ["skeptic_findings.md"],
        base_timeout_s=120,
        modes={"thorough"},
        critical=False,
        model="sonnet",
    )
    config = _config(project)
    (scratch / "skeptic_findings.md").write_text(
        "# Skeptic\n\nno severity changes\n", encoding="utf-8"
    )
    monkeypatch.setattr(D, "gate_passes", lambda *_args, **_kwargs: (True, []))
    monkeypatch.setattr(D, "_validate_skeptic_scope", lambda *_args: [])
    monkeypatch.setattr(D, "_validate_skeptic_full_ch_coverage", lambda *_args: [])
    monkeypatch.setattr(D, "_validate_skeptic_challenge_receipt", lambda *_args: [])
    monkeypatch.setattr(
        D,
        "_run_skeptic_challenge_sidecar_transaction",
        lambda **_kwargs: (0, 0, []),
    )
    monkeypatch.setattr(
        D,
        "_validate_invariant_commitment",
        lambda *_args, **_kwargs: [
            "late committed-invariant EMISSION/INJECTED_FAILURE: write failed"
        ],
    )
    passed, missing = D._run_phase_validators(
        phase, config, scratch, [phase], 0, {}
    )
    assert passed is False
    assert missing == [
        "late committed-invariant EMISSION/INJECTED_FAILURE: write failed"
    ]
    assert "severity" not in " ".join(missing).casefold()
