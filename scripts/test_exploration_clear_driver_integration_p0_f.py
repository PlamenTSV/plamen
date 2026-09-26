from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import artifact_ledger as AL
import plamen_driver as D
from phase_io_contracts import LaunchSpec
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
        assert kwargs["phase"].name == "exploration_clear"
        assert kwargs["phase_io_contract"].phase == "exploration_clear"
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
        assert kwargs["phase"].name == "exploration_clear"
        assert kwargs["phase_io_contract"].phase == "exploration_clear"
        attempt = json.loads(
            (scratch / "exploration_clear_repair_attempt.json").read_text(
                encoding="utf-8"
            )
        )
        assert attempt["phase"] == "exploration_clear"
        assert attempt["model"] == kwargs["effective_model"]
        assert attempt["timeout_s"] == int(kwargs["timeout"])
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


@pytest.mark.skipif(D.os.name != "posix", reason="POSIX transaction boundary")
def test_headless_transaction_rejects_parent_phase_for_repair_contract(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    config = _config(project)
    contract, launch = D._exploration_clear_contract_launch(
        phase=_phase(),
        config=config,
        work_unit_id="worker.0001",
        exact_outputs=("exploration_clear_repair_response.md",),
        exact_inputs=(
            "exploration_clear_repair_plan.json",
            "exploration_clear_repair_attempt.json",
        ),
        actor="MODEL",
        model="sonnet",
        timeout_s=120,
    )
    with pytest.raises(
        D.HeadlessWorkerRuntimeError,
        match="phase identity disagrees",
    ):
        D._prepared_headless_transaction_authority(
            phase=_phase(),
            config=config,
            scratchpad=scratch,
            timeout_s=120,
            expected_outputs=("exploration_clear_repair_response.md",),
            attempt=1,
            agent_id="EXPLORATION_CLEAR_REPAIR",
            agent_role=None,
            source_phase="exploration_clear",
            phase_io_contract=contract,
            phase_io_launch=launch,
        )


def test_noncritical_exhausted_retry_restores_predecessor_and_archives_retry(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    phase = _phase()
    current = scratch / "exploration_skeptic_findings.md"
    predecessor = b"# predecessor\n" + b"p" * 600
    exhausted = b"# exhausted retry\n" + b"r" * 600
    current.write_bytes(exhausted)
    backup = (
        scratch / "_retry_quarantine" / phase.name
        / "exploration_skeptic_findings.md"
    )
    backup.parent.mkdir(parents=True)
    backup.write_bytes(predecessor)

    D._restore_quarantined_on_retry_failure(scratch, phase)

    assert current.read_bytes() == predecessor
    archived = list(
        (scratch / "_retry_quarantine" / phase.name / "_exhausted").glob(
            "exploration_skeptic_findings.md.*.attempt"
        )
    )
    assert len(archived) == 1
    assert archived[0].read_bytes() == exhausted


def _write_late_ci_fixture(scratch: Path, count: int = 8) -> None:
    (scratch / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n", encoding="utf-8"
    )
    (scratch / "finding_records.json").write_bytes(
        D.derive_preverify_finding_records_bytes(
            (scratch / "findings_inventory.md").read_bytes()
        )
    )
    (scratch / "_id_ledger.json").write_text(
        json.dumps(
            {"schema_version": "plamen.id_ledger.v1", "allocations": []},
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    blocks = []
    for index in range(1, count + 1):
        blocks.append(
            f"committed-invariant [CI-{index}]\n"
            "Locus: src/Contract.sol:L1\n"
            "Shape: NO_REVERT_AT_BOUNDARY\n"
            f"Assertion: boundary {index} does not revert\n"
            "Falsify Class: boundary\n"
            f"Provenance: skeptic clear {index}\n"
        )
    (scratch / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\n" + "\n".join(blocks),
        encoding="utf-8",
    )


def _bind_late_ci_fixture(project: Path) -> None:
    """Give the canonical triple and CI source real same-run producers."""

    scratch = project / ".scratchpad"
    config = _config(project)
    canonical = (
        "findings_inventory.md", "finding_records.json", "_id_ledger.json",
    )
    predecessor = {name: (scratch / name).read_bytes() for name in canonical}
    source_raw = (scratch / "exploration_skeptic_findings.md").read_bytes()
    for name in (*canonical, "exploration_skeptic_findings.md"):
        (scratch / name).unlink()

    manifest_name = "inventory_floor_source_manifest.json"
    (scratch / manifest_name).write_text("{}\n", encoding="utf-8")
    outputs = (*canonical, "inventory_floor_receipt.json")
    contract = D.resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="late_recall_floor",
        exact_inputs=(manifest_name,),
        exact_outputs=outputs,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=(),
    )
    D.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=config["_run_id"]
    )
    for name, raw in predecessor.items():
        (scratch / name).write_bytes(raw)
    (scratch / "inventory_floor_receipt.json").write_text(
        "{}\n", encoding="utf-8"
    )
    D.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="DRIVER",
    )

    phase = _phase()
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    (scratch / "exploration_skeptic_findings.md").write_bytes(source_raw)
    assert D._record_typed_model_phase_artifacts(phase, scratch, config) == []


def test_late_ci_recovery_is_exact_coupled_eight_candidate_successor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Contract.sol").write_text(
        "contract Contract {}\n", encoding="utf-8"
    )
    _write_late_ci_fixture(scratch)
    _bind_late_ci_fixture(project)
    before = {
        path.relative_to(scratch).as_posix(): path.read_bytes()
        for path in scratch.rglob("*") if path.is_file()
    }
    D._validate_invariant_commitment(scratch, "thorough", recover=False)
    D._validate_invariant_commitment(scratch, "thorough", recover=True)
    assert {
        path.relative_to(scratch).as_posix(): path.read_bytes()
        for path in scratch.rglob("*") if path.is_file()
    } == before

    assert D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    ) == []
    inventory = (scratch / "findings_inventory.md").read_text(encoding="utf-8")
    records = json.loads((scratch / "finding_records.json").read_text())
    ledger = json.loads((scratch / "_id_ledger.json").read_text())
    expected = [f"INV-{index:03d}" for index in range(1, 9)]
    assert D.re.findall(r"^### Finding \[(INV-\d+)\]:", inventory, D.re.M) == expected
    assert [row["inventory_id"] for row in records["records"]] == expected
    assert [row["id"] for row in ledger["allocations"]] == expected
    active = D.read_artifact_ledger(scratch)["artifact_bindings"]
    owners = {active[f"scratchpad:{name}"]["owner_key"] for name in (
        "findings_inventory.md", "finding_records.json", "_id_ledger.json",
    )}
    assert len(owners) == 1
    owner = owners.pop()
    assert "/inventory/late_ci_recovery.exploration_skeptic." in owner
    unit = D.read_artifact_ledger(scratch)["work_units"][owner]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert set(unit["artifacts"]) == {
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:_id_ledger.json",
    }
    owner_before = owner
    assert D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    ) == []
    replay = D.read_artifact_ledger(scratch)
    assert {
        replay["artifact_bindings"][f"scratchpad:{name}"]["owner_key"]
        for name in (
            "findings_inventory.md", "finding_records.json", "_id_ledger.json",
        )
    } == {owner_before}


def test_run18_late_ci_triplet_hands_off_to_axis_and_gate_p_after_semantic_mutation(
    tmp_path: Path,
) -> None:
    """Replay the two successor prestates that failed in Run18."""

    from gate_p_successor import run_gate_p_coupled_successor
    from phase_io_contracts import registered_projection_handoff

    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Contract.sol").write_text(
        "contract Contract {}\n", encoding="utf-8"
    )
    _write_late_ci_fixture(scratch)
    _bind_late_ci_fixture(project)
    config = _config(project)
    assert D._run_late_ci_recovery_transaction(
        phase=_phase(), config=config, scratchpad=scratch
    ) == []

    ledger = D.read_artifact_ledger(scratch)
    late_ci_owner = ledger["artifact_bindings"][
        "scratchpad:_id_ledger.json"
    ]["owner_key"]
    axis_key = "sc/thorough/evm/claude/axis_disposition/promotion"
    gate_key = "sc/thorough/evm/claude/inventory/gate_p_successor"
    identities = tuple(
        f"scratchpad:{name}" for name in D._AXIS_PROMOTION_CANONICAL
    )
    assert all(
        registered_projection_handoff(late_ci_owner, axis_key, identity)
        for identity in identities
    )
    assert all(
        registered_projection_handoff(late_ci_owner, gate_key, identity)
        for identity in identities
    )
    assert not registered_projection_handoff(
        late_ci_owner,
        "sc/thorough/evm/claude/axis_disposition/unregistered",
        "scratchpad:_id_ledger.json",
    )

    predecessor = {
        name: (scratch / name).read_bytes()
        for name in D._AXIS_PROMOTION_CANONICAL
    }
    inventory_raw = predecessor["findings_inventory.md"] + (
        b"\n### Finding [INV-009]: Run18 semantic successor\n"
        b"**Severity**: Low\n"
        b"**Location**: `src/Contract.sol:L1`\n"
        b"**Description**: Retained for independent verification.\n"
        b"**Impact**: Independent verification determines material harm.\n"
    )
    canonical = D._axis_coupled_canonical_postimages(
        inventory_raw=inventory_raw,
        ledger_raw=predecessor["_id_ledger.json"],
    )
    axis_contract = D.resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="axis_disposition",
        work_unit_id="promotion",
        exact_inputs=("axis_coverage_promotion_plan.json",),
        exact_outputs=(
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
            "axis_coverage_promotion_receipt.json",
        ),
    )
    axis_launch = LaunchSpec(
        work_unit_key=axis_contract.key,
        pipeline=axis_contract.pipeline,
        mode=axis_contract.mode,
        ecosystem=axis_contract.ecosystem,
        backend=axis_contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=(),
    )
    planned = {
        **{
            f"scratchpad:{name}": raw
            for name, raw in canonical.items()
        },
        "scratchpad:axis_coverage_promotion_receipt.json": b"{}\n",
    }
    axis_plan = AL.plan_driver_successor_transaction(
        scratch,
        project,
        axis_contract,
        axis_launch,
        run_id=config["_run_id"],
        planned_output_bytes=planned,
        merge_events=D._axis_promotion_merge_events(
            axis_contract, predecessor, planned
        ),
    )
    assert tuple(
        transition.artifact_identity for transition in axis_plan.transitions[:3]
    ) == identities

    # Run18 then advanced all three files under authenticated semantic-mutation
    # events before Gate P.  Reproduce that state exactly and require Gate P to
    # consume it without treating the ledger's historical hashes as unowned.
    mutation_events = [
        AL.arm_semantic_mutation(
            scratch,
            project,
            artifact_identity=f"scratchpad:{name}",
            mutation_kind=f"RUN18_{name.upper()}",
            run_id=config["_run_id"],
        )
        for name in D._AXIS_PROMOTION_CANONICAL
    ]
    for name, raw in canonical.items():
        (scratch / name).write_bytes(raw)
    for event in D._driver_semantic_mutation_finalize_order(mutation_events):
        finalized = AL.finalize_semantic_mutation(
            scratch,
            project,
            event["event_id"],
            run_id=config["_run_id"],
            affected_record_ids=("INV-009",),
        )
        assert finalized["status"] == "INVALIDATION_APPLIED"

    (scratch / "promotion_coverage_seed.md").write_text(
        "# Promotion Coverage Seed\n", encoding="utf-8"
    )

    def _zero_delta_gate_p(stage: Path) -> dict[str, int]:
        # Gate P commits its complete canonical output denominator even when
        # the evaluator finds no additive candidate.  Keep this fixture
        # aligned with that contract instead of mocking only its return value.
        for name in (
            "promotion_orphans.md",
            "promotion_routing.md",
            "promotion_orphans_appendix_c.md",
            "promotion_orphans_appendix_a.md",
            "promotion_gate_receipt.md",
        ):
            (stage / name).write_text(
                f"# {name}\n\nDeterministic zero-delta diagnostic.\n",
                encoding="utf-8",
            )
        return {"harvested": 0, "emitted_to_inventory": 0}

    gate_result = run_gate_p_coupled_successor(
        scratch,
        project,
        run_id=config["_run_id"],
        dimensions={
            "pipeline": "sc",
            "mode": "thorough",
            "ecosystem": "evm",
            "backend": "claude",
        },
        source_names=(
            "_id_ledger.json",
            "finding_records.json",
            "findings_inventory.md",
            "promotion_coverage_seed.md",
        ),
        evaluator=_zero_delta_gate_p,
    )
    assert gate_result["safe_to_consume"] is True


def test_late_ci_recovery_refuses_unauthorized_prewrite_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_late_ci_fixture(scratch, count=1)
    old = {
        name: (scratch / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json", "_id_ledger.json")
    }
    issues = D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    )
    assert issues and "source producer authority failed" in issues[0]
    assert {
        name: (scratch / name).read_bytes() for name in old
    } == old


@pytest.mark.parametrize(
    "failed_name",
    ("findings_inventory.md", "finding_records.json", "_id_ledger.json"),
)
def test_late_ci_recovery_process_death_rolls_forward_exact_coupled_vector(
    tmp_path: Path,
    failed_name: str,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_late_ci_fixture(scratch, count=8)
    _bind_late_ci_fixture(project)
    old = {
        name: (scratch / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json", "_id_ledger.json")
    }
    def crash(point: str) -> None:
        if point == f"after_replace:{failed_name}":
            raise SystemExit(91)

    with pytest.raises(SystemExit, match="91"):
        D._run_late_ci_recovery_transaction(
            phase=_phase(),
            config=_config(project),
            scratchpad=scratch,
            failure_injector=crash,
        )
    mixed = {name: (scratch / name).read_bytes() for name in old}
    assert mixed != old
    assert (scratch / "_driver_vector_transactions").is_dir()
    assert D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    ) == []
    inventory = (scratch / "findings_inventory.md").read_text(encoding="utf-8")
    expected = [f"INV-{index:03d}" for index in range(1, 9)]
    assert D.re.findall(r"^### Finding \[(INV-\d+)\]:", inventory, D.re.M) == expected
    records = json.loads((scratch / "finding_records.json").read_text())
    ledger = json.loads((scratch / "_id_ledger.json").read_text())
    assert [row["inventory_id"] for row in records["records"]] == expected
    assert [row["id"] for row in ledger["allocations"]] == expected


def test_late_ci_recovery_rejects_tampered_partial_vector(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_late_ci_fixture(scratch, count=8)
    _bind_late_ci_fixture(project)

    def crash(point: str) -> None:
        if point == "after_replace:findings_inventory.md":
            raise SystemExit(92)

    with pytest.raises(SystemExit, match="92"):
        D._run_late_ci_recovery_transaction(
            phase=_phase(),
            config=_config(project),
            scratchpad=scratch,
            failure_injector=crash,
        )
    tampered = b'{"schema_version":"tampered"}\n'
    (scratch / "finding_records.json").write_bytes(tampered)
    issues = D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    )
    assert issues and "vector recovery failed" in issues[0]
    assert (scratch / "finding_records.json").read_bytes() == tampered


def test_late_ci_precommit_refusal_restores_old_vector_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_late_ci_fixture(scratch, count=8)
    _bind_late_ci_fixture(project)
    names = ("findings_inventory.md", "finding_records.json", "_id_ledger.json")
    old = {name: (scratch / name).read_bytes() for name in names}
    original = D._commit_deterministic_driver_work_unit

    def refuse_successor(**kwargs):
        if kwargs["contract"].work_unit_id.startswith(
            "late_ci_recovery.exploration_skeptic."
        ):
            kwargs["domain_issues"] = ("injected successor precommit refusal",)
        return original(**kwargs)

    monkeypatch.setattr(D, "_commit_deterministic_driver_work_unit", refuse_successor)
    issues = D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    )
    assert issues and "precommit refusal" in issues[0]
    assert {name: (scratch / name).read_bytes() for name in names} == old
    # The old cohort is public, while the durable descriptor retains the
    # successor and authenticated physical-rebind authority for exact replay.
    assert (scratch / "_driver_vector_transactions").is_dir()
    recovered_ledger = AL.read_artifact_ledger(scratch)
    successor_key = next(
        key for key in recovered_ledger["work_units"]
        if "/inventory/late_ci_recovery.exploration_skeptic." in key
    )
    recovered_unit = recovered_ledger["work_units"][successor_key]
    assert recovered_unit["semantic_status"] == "INPUTS_BOUND"
    assert recovered_unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert recovered_unit["artifacts"] == {}
    assert "commit_authority" not in recovered_unit
    assert {
        key for key in recovered_unit
        if key.startswith("preexecution_authority")
    } == {"preexecution_authority", "preexecution_authority_digest"}
    assert all(
        recovered_ledger["artifact_bindings"][f"scratchpad:{name}"]["status"]
        == "ACTIVE"
        and recovered_ledger["artifact_bindings"][f"scratchpad:{name}"]["owner_key"]
        != successor_key
        for name in names
    )

    tampered_ledger = json.loads(json.dumps(recovered_ledger))
    tampered_ledger["work_units"][successor_key]["preexecution_authority"][
        "candidate_rows"
    ][0]["size"] += 1
    AL.write_artifact_ledger(scratch, tampered_ledger)
    tamper_issues = D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    )
    assert tamper_issues and "vector recovery failed" in tamper_issues[0]
    assert {name: (scratch / name).read_bytes() for name in names} == old
    AL.write_artifact_ledger(scratch, recovered_ledger)

    monkeypatch.setattr(D, "_commit_deterministic_driver_work_unit", original)
    assert D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    ) == []
    assert {name: (scratch / name).read_bytes() for name in names} != old


def test_late_ci_postcommit_issue_never_rolls_back_active_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    _write_late_ci_fixture(scratch, count=8)
    _bind_late_ci_fixture(project)
    names = ("findings_inventory.md", "finding_records.json", "_id_ledger.json")
    old = {name: (scratch / name).read_bytes() for name in names}
    original = D._commit_deterministic_driver_work_unit

    def issue_after_commit(**kwargs):
        issues = original(**kwargs)
        if not issues and kwargs["contract"].work_unit_id.startswith(
            "late_ci_recovery.exploration_skeptic."
        ):
            return ["injected postcommit validation issue"]
        return issues

    monkeypatch.setattr(D, "_commit_deterministic_driver_work_unit", issue_after_commit)
    issues = D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    )
    assert issues and "postcommit validation issue" in issues[0]
    new = {name: (scratch / name).read_bytes() for name in names}
    assert new != old
    ledger = D.read_artifact_ledger(scratch)
    assert all(
        ledger["artifact_bindings"][f"scratchpad:{name}"]["status"] == "ACTIVE"
        for name in names
    )

    monkeypatch.setattr(D, "_commit_deterministic_driver_work_unit", original)
    assert D._run_late_ci_recovery_transaction(
        phase=_phase(), config=_config(project), scratchpad=scratch
    ) == []
    assert {name: (scratch / name).read_bytes() for name in names} == new


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
        "exploration_clear_prior_identity_map.json",
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
        "scratchpad:exploration_clear_prior_identity_map.json",
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
def test_reconcile_failure_keeps_public_pair_consistent_with_ledger(
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
                commit_issues = original_commit(**kwargs)
                assert commit_issues == []
                raise KeyboardInterrupt("injected reconcile crash")
            kwargs["domain_issues"] = (
                f"{contract.key}: injected commit refusal",
            )
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
        if failure == "issue":
            assert binding["owner_key"].endswith("/initial_compile.repair")
        else:
            assert binding["owner_key"].endswith("/repair_reconcile")
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
    assert passed is True
    assert missing == []
    sentinel = (scratch / "exploration_skeptic.degraded").read_text(
        encoding="utf-8"
    )
    assert "EXPLORATION_CLEAR_DEBT" in sentinel
    assert "ECLR-" in sentinel
    ledger = D.read_artifact_ledger(scratch)
    binding = ledger["artifact_bindings"][
        "scratchpad:exploration_skeptic_findings.md"
    ]
    primary = ledger["work_units"][binding["owner_key"]]
    assert binding["status"] == "ACTIVE"
    assert primary["semantic_status"] == "ACTIVE"
    assert primary["execution_state"] == "OUTPUT_COMMITTED"
    assert (scratch / "exploration_skeptic_findings.md").is_file()
    assert not (
        scratch / "_retry_quarantine" / phase.name
        / "exploration_skeptic_findings.md"
    ).exists()

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
    monkeypatch.setattr(
        D, "_run_late_ci_recovery_transaction", lambda **_kwargs: []
    )
    passed, missing = D._run_phase_validators(
        phase, config, scratch, [phase], 0, {}
    )
    assert passed is False
    assert missing == [
        "late committed-invariant EMISSION/INJECTED_FAILURE: write failed"
    ]
    assert "severity" not in " ".join(missing).casefold()
