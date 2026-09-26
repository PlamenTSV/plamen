from __future__ import annotations

import ast
from contextlib import contextmanager
import json
import hashlib
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading

import pytest

import artifact_ledger as AL
import verify_queue_phaseio_authority as VQ

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_inputs,
    validate_work_unit_artifacts,
)
from phase_io_contracts import (
    ArtifactSpec,
    ConditionalOutputReceipt,
    DriverMergeEvent,
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}


def _contract(phase: str, unit: str, **kwargs):
    return resolve_phase_io_contract(
        phase=phase, work_unit_id=unit, **BASE, **kwargs
    )


def _launch(contract, *, exec_mode="python", model="driver"):
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model=model,
        timeout_s=30,
        exec_mode=exec_mode,
    )


def _independent_driver_contract(unit: str) -> PhaseIOContract:
    key = f"sc/thorough/evm/claude/depth/{unit}"
    return PhaseIOContract(
        **BASE,
        phase="depth",
        work_unit_id=unit,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=f"{unit}.md",
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        model_invoked=False,
    )


def test_committed_conditional_absence_replays_as_active_and_historical(
    tmp_path: Path,
) -> None:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    key = "sc/thorough/evm/claude/depth/conditional_absence"
    identity = "scratchpad:conditional_absence.json"
    contract = PhaseIOContract(
        **BASE,
        phase="depth",
        work_unit_id="conditional_absence",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="conditional_absence.json",
                owner_key=key,
                artifact_class="CONDITIONAL",
                writer="DRIVER",
                write_mode="REPLACE",
                condition_id="findings_present",
            ),
        ),
        model_invoked=False,
    )
    launch = _launch(contract)
    run_id = "run-conditional-absence"
    record_work_unit_inputs(sp, tmp_path, contract, launch, run_id=run_id)
    receipt = ConditionalOutputReceipt(
        work_unit_key=key,
        contract_digest=contract.digest,
        artifact_identity=identity,
        condition_id="findings_present",
        state="NOT_TRIGGERED",
        expected_denominator=0,
    )
    record_work_unit_artifacts(
        sp,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        conditional_receipts={identity: receipt},
    )
    ledger = read_artifact_ledger(sp)
    record = ledger["work_units"][key]["artifacts"][identity]
    assert {
        "status": record["status"],
        "authority_level": record["authority_level"],
        "sha256": record["sha256"],
        "size": record["size"],
    } == {
        "status": "MISSING",
        "authority_level": "NONE",
        "sha256": "",
        "size": 0,
    }
    assert AL.active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=key,
        run_id=run_id,
        expected_artifact_identities=(identity,),
    ) == []
    assert AL.stored_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=key,
        run_id=run_id,
        expected_artifact_identities=(identity,),
    ) == []

    mutations = (
        ("status", "ACTIVE"),
        ("authority_level", "ACTIVE_AUTHORITY"),
        ("sha256", "0" * 64),
        ("size", 1),
        ("receipt_version", "plamen.conditional_output.v999"),
        ("work_unit_key", key + ".forged"),
        ("contract_digest", "0" * 64),
        ("artifact_identity", "scratchpad:forged.json"),
        ("condition_id", "forged"),
        ("state", "PRODUCED"),
        ("expected_denominator", 1),
    )
    for field, value in mutations:
        forged = json.loads(json.dumps(ledger))
        forged_record = forged["work_units"][key]["artifacts"][identity]
        if field in {"status", "authority_level", "sha256", "size"}:
            forged_record[field] = value
        else:
            forged_record["conditional_receipt"][field] = value
        assert AL.active_committed_work_unit_authority_issues(
            forged,
            work_unit_key=key,
            run_id=run_id,
            expected_artifact_identities=(identity,),
        )
        assert AL.stored_committed_work_unit_authority_issues(
            forged,
            work_unit_key=key,
            run_id=run_id,
            expected_artifact_identities=(identity,),
        )


def _process_commit_worker(
    scratchpad: str,
    project_root: str,
    unit: str,
    start,
    results,
) -> None:
    sp = Path(scratchpad)
    project = Path(project_root)
    key = f"sc/thorough/evm/claude/depth/{unit}"
    output = f"{unit}.md"
    contract = PhaseIOContract(
        **BASE,
        phase="depth",
        work_unit_id=unit,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=output,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        model_invoked=False,
    )
    launch = _launch(contract)
    record_work_unit_inputs(
        sp, project, contract, launch, run_id="run-process-lock"
    )
    (sp / output).write_text(f"{unit}\n", encoding="utf-8")
    start.wait(10)
    try:
        committed = record_work_unit_artifacts(
            sp, project, contract, launch, run_id="run-process-lock"
        )
        results.put((unit, committed["semantic_status"], ""))
    except Exception as exc:
        results.put((unit, "ERROR", f"{type(exc).__name__}: {exc}"))


def test_exact_chain_merge_records_both_targets_and_legacy_projection(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    before_by_path = {
        "chain_hypotheses.md": "## Chain Hypothesis CH-01\n",
        "composition_coverage.md": "| H-01 | M-01 |\n",
    }
    for ordinal, (path, before) in enumerate(before_by_path.items(), 1):
        key = f"sc/thorough/evm/claude/chain/worker.base_{ordinal}"
        predecessor = PhaseIOContract(
            **BASE,
            phase="chain",
            work_unit_id=f"worker.base_{ordinal}",
            outputs=(
                ArtifactSpec(
                    root="scratchpad",
                    path=path,
                    owner_key=key,
                    artifact_class="DRIVER_GENERATED",
                    writer="DRIVER",
                    write_mode="REPLACE",
                ),
            ),
            model_invoked=False,
        )
        predecessor_launch = _launch(predecessor)
        record_work_unit_inputs(
            sp, tmp_path, predecessor, predecessor_launch, run_id="run-1"
        )
        (sp / path).write_text(before, encoding="utf-8")
        record_work_unit_artifacts(
            sp, tmp_path, predecessor, predecessor_launch, run_id="run-1"
        )
    (sp / "chain_iteration2.md").write_text("delta\n", encoding="utf-8")
    legacy_prestate = {
        path: (sp / path).read_bytes()
        for path in (
            "_artifact_state.json",
            "chain_hypotheses.md",
            "composition_coverage.md",
            "chain_iteration2.md",
        )
    }
    with pytest.raises(
        ValueError,
        match="CHAIN_TAIL_LEGACY_FIXED_GENERATION",
    ):
        _contract("chain_iter2", "driver_merge")
    assert {
        path: (sp / path).read_bytes()
        for path in legacy_prestate
    } == legacy_prestate

    contract = _contract("chain_iter2", "driver_merge.p0001.s0002")
    assert contract.key.endswith(
        "/chain_iter2/driver_merge.p0001.s0002"
    )
    assert contract.immutable_inputs == (
        "scratchpad:chain_iteration2.md",
    )
    assert contract.model_invoked is False
    assert all(output.writer == "DRIVER" for output in contract.outputs)
    assert all(output.write_mode == "MERGE" for output in contract.outputs)
    assert all(
        output.minimum_gate == "IDENTITY_PARITY"
        for output in contract.outputs
    )
    launch = _launch(contract)
    record_work_unit_inputs(sp, tmp_path, contract, launch, run_id="run-1")
    before_hashes = {
        path: AL._sha256(sp / path) for path in before_by_path
    }
    (sp / "chain_hypotheses.md").write_text(
        "## Chain Hypothesis CH-01\n## Chain Hypothesis CH-02\n",
        encoding="utf-8",
    )
    (sp / "composition_coverage.md").write_text(
        "| H-01 | M-01 |\n| H-02 | M-02 |\n", encoding="utf-8"
    )
    events = {
        f"scratchpad:{path}": DriverMergeEvent(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            artifact_identity=f"scratchpad:{path}",
            before_sha256=before_hashes[path],
            after_sha256=AL._sha256(sp / path),
            source_identities=("scratchpad:chain_iteration2.md",),
            identities_before=("CH-01",),
            identities_after=("CH-01", "CH-02"),
        )
        for path in before_by_path
    }

    unit = record_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-1",
        merge_events=events,
    )
    ledger = read_artifact_ledger(sp)

    assert set(unit["artifacts"]) == {
        "scratchpad:chain_hypotheses.md",
        "scratchpad:composition_coverage.md",
    }
    assert unit["model_invoked"] is False
    assert ledger["version"] == 2
    for path in before_by_path:
        identity = f"scratchpad:{path}"
        typed = ledger["artifact_bindings"][identity]
        assert typed["owner_key"] == contract.key
        assert typed["history"]
        assert typed["history"][-1]["owner_key"].startswith(
            "sc/thorough/evm/claude/chain/worker.base_"
        )
        assert ledger["artifacts"][path]["owner_key"] == contract.key
    assert validate_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-1"
    ) == []


def test_interprocess_commits_preserve_both_work_units(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_process_commit_worker,
            args=(str(sp), str(tmp_path), unit, start, results),
        )
        for unit in ("process_a", "process_b")
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    rows = sorted(results.get(timeout=5) for _ in processes)
    assert rows == [
        ("process_a", "ACTIVE", ""),
        ("process_b", "ACTIVE", ""),
    ]
    ledger = read_artifact_ledger(sp)
    assert {
        "sc/thorough/evm/claude/depth/process_a",
        "sc/thorough/evm/claude/depth/process_b",
    }.issubset(ledger["work_units"])


def test_denominator_records_missing_required_output_and_validation_fails(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    contract = _contract("chain_iter2", "model")
    launch = _launch(contract, exec_mode="pty", model="sonnet")
    for identity in contract.immutable_inputs:
        _, relative = identity.split(":", 1)
        path = sp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("input\n", encoding="utf-8")
    record_work_unit_inputs(sp, tmp_path, contract, launch, run_id="run-1")

    unit = record_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-1"
    )

    rec = unit["artifacts"]["scratchpad:chain_iteration2.md"]
    assert rec["status"] == "MISSING"
    issues = validate_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-1"
    )
    assert "scratchpad:chain_iteration2.md: required output missing" in issues
    assert any("output commit is not clean" in issue for issue in issues)


def test_report_prework_python_outputs_get_exact_driver_ownership(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    for name in (
        "severity_binding.md", "status_binding.md", "report_index_coverage_seed.md",
        "candidate_semantic_facets.md", "candidate_semantic_facets.json",
        "external_research_gaps.md",
    ):
        (sp / name).write_text(f"{name}\n", encoding="utf-8")
    contract = _contract("report_index", "prework")
    launch = _launch(contract)
    conditional_receipts = {
        spec.identity: ConditionalOutputReceipt(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            artifact_identity=spec.identity,
            condition_id=spec.condition_id,
            state="PRODUCED",
            expected_denominator=1,
            produced_identities=(spec.identity,),
        )
        for spec in contract.outputs
        if spec.artifact_class == "CONDITIONAL"
    }

    unit = record_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-report",
        conditional_receipts=conditional_receipts,
    )

    assert unit["model_invoked"] is False
    assert all(row["writer"] == "DRIVER" for row in unit["artifacts"].values())
    assert all(row["owner_key"] == contract.key for row in unit["artifacts"].values())


def test_hash_drift_and_launch_drift_are_loud(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "chain_iteration2.md").write_text("initial\n", encoding="utf-8")
    contract = _contract("chain_iter2", "model")
    launch = _launch(contract, exec_mode="pty", model="sonnet")
    record_work_unit_artifacts(sp, tmp_path, contract, launch, run_id="run-1")
    (sp / "chain_iteration2.md").write_text("mutated\n", encoding="utf-8")
    changed_launch = LaunchSpec(
        **{**launch.to_dict(), "timeout_s": 31}
    )

    issues = validate_work_unit_artifacts(
        sp, tmp_path, contract, changed_launch, run_id="run-1"
    )

    assert any("launch digest mismatch" in issue for issue in issues)
    assert any("content hash changed" in issue for issue in issues)


def test_corruption_is_not_treated_as_empty_or_clean(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "_artifact_state.json").write_text("{broken", encoding="utf-8")
    contract = _contract("chain_iter2", "model")
    launch = _launch(contract, exec_mode="pty", model="sonnet")

    try:
        read_artifact_ledger(sp)
    except ArtifactLedgerError:
        pass
    else:
        raise AssertionError("corrupt ledger must raise")
    issues = validate_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-1"
    )
    assert len(issues) == 1 and "unreadable" in issues[0]


def test_same_key_cross_run_attempt_is_preserved_but_never_rebound_active(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    output = sp / "chain_iteration2.md"
    output.write_text("delta\n", encoding="utf-8")
    contract = _contract("chain_iter2", "model")
    launch = _launch(contract, exec_mode="pty", model="sonnet")
    first = record_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-1"
    )
    ledger_path = sp / "_artifact_state.json"
    journal_path = sp / AL._OUTPUT_AUTHORITY_LEDGER_NAME
    cas_root = sp / AL._OUTPUT_AUTHORITY_CAS_DIRECTORY
    ledger_before = ledger_path.read_bytes()
    journal_before = journal_path.read_bytes()
    cas_before = {
        path.name: path.read_bytes()
        for path in sorted(cas_root.glob("*.json"))
    }
    output_before = output.read_bytes()

    with pytest.raises(
        ArtifactLedgerError,
        match="quarantine recovery history is malformed",
    ):
        record_work_unit_artifacts(
            sp, tmp_path, contract, launch, run_id="run-2"
        )

    assert ledger_path.read_bytes() == ledger_before
    assert journal_path.read_bytes() == journal_before
    assert {
        path.name: path.read_bytes()
        for path in sorted(cas_root.glob("*.json"))
    } == cas_before
    assert output.read_bytes() == output_before
    ledger = read_artifact_ledger(sp)
    assert ledger["work_units"][contract.key] == first
    assert ledger["work_units"][contract.key]["run_id"] == "run-1"
    journal = json.loads(journal_before)
    assert journal["authorities"]
    assert all(
        authority["run_id"] == "run-1"
        for authority in journal["authorities"].values()
    )
    assert b'"run-2"' not in ledger_before
    assert b'"run-2"' not in journal_before
    assert all(b'"run-2"' not in value for value in cas_before.values())


def test_model_prelaunch_denominator_cannot_be_reblessed_after_first_binding(
    tmp_path: Path,
):
    """A retry is still downstream of the first model launch opportunity.

    With no output committed, an unrestricted second ``record inputs`` call
    used to overwrite the original receipt.  A model that modified a protected
    input could therefore make its own mutation look pre-existing on retry.
    Driver-only dynamic producers have an explicit CAS API; model work units
    must instead preserve their first denominator exactly.
    """
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text("before\n", encoding="utf-8")
    contract = _contract(
        "depth",
        "worker.state_trace",
        exact_outputs=("depth_state_trace_findings.md",),
    )
    launch = _launch(contract, exec_mode="pty", model="sonnet")
    first = record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="run-model"
    )

    (sp / "findings_inventory.md").write_text("after\n", encoding="utf-8")
    with pytest.raises(
        ArtifactLedgerError, match="model prelaunch input drift"
    ):
        record_work_unit_inputs(
            sp, tmp_path, contract, launch, run_id="run-model"
        )

    ledger = read_artifact_ledger(sp)
    assert ledger["work_units"][contract.key] == first


def test_consumer_cannot_bless_bytes_changed_after_producer_commit(
    tmp_path: Path,
):
    """A producer receipt, not first-consumer timing, owns produced bytes."""

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    produced = sp / "producer.md"
    produced.write_text("producer committed bytes\n", encoding="utf-8")
    producer = _contract(
        "depth", "worker.producer", exact_outputs=("producer.md",)
    )
    producer_launch = _launch(producer, exec_mode="pty", model="sonnet")
    record_work_unit_artifacts(
        sp, tmp_path, producer, producer_launch, run_id="run-producer-binding"
    )

    produced.write_text("tampered before consumer binding\n", encoding="utf-8")
    consumer = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.consumer",
        outputs=(),
        immutable_inputs=("scratchpad:producer.md",),
    )
    consumer_launch = _launch(consumer, exec_mode="pty", model="sonnet")
    unit = record_work_unit_inputs(
        sp,
        tmp_path,
        consumer,
        consumer_launch,
        run_id="run-producer-binding",
    )

    binding = unit["input_bindings"]["scratchpad:producer.md"]
    assert binding["status"] == "PRODUCER_AUTHORITY_MISMATCH"
    assert unit["semantic_status"] == "INPUT_DEBT"
    issues = validate_work_unit_inputs(
        sp,
        tmp_path,
        consumer,
        consumer_launch,
        run_id="run-producer-binding",
    )
    assert issues == [
        "scratchpad:producer.md: semantic input binding is "
        "PRODUCER_AUTHORITY_MISMATCH"
    ]


def test_phase_contract_rejects_self_certifying_input_output_overlap():
    key = "sc/thorough/evm/claude/report_floor/unsafe_merge"
    with pytest.raises(ValueError, match="read-modify-write transaction"):
        PhaseIOContract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="report_floor",
            work_unit_id="unsafe_merge",
            outputs=(
                ArtifactSpec(
                    root="project",
                    path="AUDIT_REPORT.md",
                    owner_key=key,
                    artifact_class="DRIVER_GENERATED",
                    writer="DRIVER",
                    write_mode="MERGE",
                ),
            ),
            bounded_lookup_inputs=("project:AUDIT_REPORT.md",),
            model_invoked=False,
        )


def _single_input_contract(identity: str, unit: str) -> PhaseIOContract:
    return PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id=unit,
        outputs=(),
        immutable_inputs=(identity,),
    )


def _single_output_contract(path: str, unit: str) -> PhaseIOContract:
    key = f"sc/thorough/evm/claude/depth/{unit}"
    return PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id=unit,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=path,
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
            ),
        ),
        immutable_inputs=(),
    )


def test_producer_quarantine_after_clean_bind_is_not_silently_accepted(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    path = sp / "producer.md"
    producer = _single_output_contract("producer.md", "worker.producer")
    producer_launch = _launch(producer, exec_mode="pty", model="sonnet")
    record_work_unit_inputs(
        sp, tmp_path, producer, producer_launch, run_id="run-quarantine"
    )
    path.write_text("stable bytes\n", encoding="utf-8")
    record_work_unit_artifacts(
        sp, tmp_path, producer, producer_launch, run_id="run-quarantine"
    )
    consumer = _single_input_contract(
        "scratchpad:producer.md", "worker.consumer_quarantine"
    )
    consumer_launch = _launch(consumer, exec_mode="pty", model="sonnet")
    record_work_unit_inputs(
        sp, tmp_path, consumer, consumer_launch, run_id="run-quarantine"
    )

    record_work_unit_artifacts(
        sp,
        tmp_path,
        producer,
        producer_launch,
        run_id="run-quarantine",
        status="QUARANTINED",
    )

    assert validate_work_unit_inputs(
        sp, tmp_path, consumer, consumer_launch, run_id="run-quarantine"
    ) == ["scratchpad:producer.md: producer authority mismatch"]


def test_same_bytes_rebound_to_another_producer_changes_authority(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    path = sp / "producer.md"
    first = _single_output_contract("producer.md", "worker.first_producer")
    first_launch = _launch(first, exec_mode="pty", model="sonnet")
    record_work_unit_inputs(
        sp, tmp_path, first, first_launch, run_id="run-owner-change"
    )
    path.write_text("stable bytes\n", encoding="utf-8")
    record_work_unit_artifacts(
        sp, tmp_path, first, first_launch, run_id="run-owner-change"
    )
    consumer = _single_input_contract(
        "scratchpad:producer.md", "worker.consumer_owner_change"
    )
    consumer_launch = _launch(consumer, exec_mode="pty", model="sonnet")
    record_work_unit_inputs(
        sp, tmp_path, consumer, consumer_launch, run_id="run-owner-change"
    )

    second = _single_output_contract("producer.md", "worker.second_producer")
    second_launch = _launch(second, exec_mode="pty", model="sonnet")
    record_work_unit_artifacts(
        sp, tmp_path, second, second_launch, run_id="run-owner-change"
    )

    assert validate_work_unit_inputs(
        sp, tmp_path, consumer, consumer_launch, run_id="run-owner-change"
    ) == ["scratchpad:producer.md: producer authority mismatch"]


def test_unregistered_raw_input_remains_a_valid_exact_input(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "raw.md").write_text("raw immutable input\n", encoding="utf-8")
    consumer = _single_input_contract(
        "scratchpad:raw.md", "worker.raw_consumer"
    )
    launch = _launch(consumer, exec_mode="pty", model="sonnet")

    unit = record_work_unit_inputs(
        sp, tmp_path, consumer, launch, run_id="run-raw"
    )

    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert validate_work_unit_inputs(
        sp, tmp_path, consumer, launch, run_id="run-raw"
    ) == []


def test_output_recording_cannot_erase_input_authority_debt(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    produced = sp / "producer.md"
    produced.write_text("committed\n", encoding="utf-8")
    producer = _contract(
        "depth", "worker.debt_producer", exact_outputs=("producer.md",)
    )
    producer_launch = _launch(producer, exec_mode="pty", model="sonnet")
    record_work_unit_artifacts(
        sp, tmp_path, producer, producer_launch, run_id="run-debt"
    )
    produced.write_text("tampered\n", encoding="utf-8")
    key = "sc/thorough/evm/claude/depth/worker.debt_consumer"
    consumer = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.debt_consumer",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="consumer.md",
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
            ),
        ),
        immutable_inputs=("scratchpad:producer.md",),
    )
    launch = _launch(consumer, exec_mode="pty", model="sonnet")
    unit = record_work_unit_inputs(
        sp, tmp_path, consumer, launch, run_id="run-debt"
    )
    assert unit["semantic_status"] == "INPUT_DEBT"
    (sp / "consumer.md").write_text("consumer output\n", encoding="utf-8")

    recorded = record_work_unit_artifacts(
        sp, tmp_path, consumer, launch, run_id="run-debt"
    )

    assert recorded["semantic_status"] == "QUARANTINED"
    assert recorded["artifacts"]["scratchpad:consumer.md"][
        "authority_level"
    ] == "PROPOSAL_ONLY"


def test_input_set_digest_retains_v2_resume_compatible_field_shape():
    records = {
        "scratchpad:raw.md": {
            "identity": "scratchpad:raw.md",
            "input_class": "IMMUTABLE",
            "status": "ACTIVE",
            "size": 3,
            "sha256": "a" * 64,
            "producer_work_unit_key": "",
            "producer_contract_digest": "",
            "future_nonsemantic_field": "ignored",
        }
    }
    semantic = [
        {
            "identity": "scratchpad:raw.md",
            "input_class": "IMMUTABLE",
            "status": "ACTIVE",
            "size": 3,
            "sha256": "a" * 64,
            "producer_work_unit_key": "",
            "producer_contract_digest": "",
        }
    ]
    expected = hashlib.sha256(
        json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()

    assert AL._input_set_digest(records) == expected


def test_v1_ledger_is_upgraded_without_dropping_legacy_records(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    legacy = {
        "version": 1,
        "artifacts": {"old.md": {"owner_phase": "recon", "sha256": "a" * 64}},
    }
    (sp / "_artifact_state.json").write_text(json.dumps(legacy), encoding="utf-8")

    ledger = read_artifact_ledger(sp)

    assert ledger["version"] == 2
    assert ledger["artifacts"]["old.md"]["owner_phase"] == "recon"
    assert ledger["artifact_bindings"] == {}
    assert ledger["work_units"] == {}


def test_parallel_worker_records_do_not_lose_sibling_updates(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    rows = []
    for index in range(12):
        output = f"analysis_worker_{index}.md"
        (sp / output).write_text(f"worker {index}\n", encoding="utf-8")
        contract = _contract(
            "breadth", f"worker.b{index}", exact_outputs=(output,)
        )
        rows.append((contract, _launch(contract, exec_mode="pty", model="sonnet")))

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [
            pool.submit(
                record_work_unit_artifacts,
                sp,
                tmp_path,
                contract,
                launch,
                run_id="parallel-run",
            )
            for contract, launch in rows
        ]
        for future in futures:
            future.result()

    ledger = read_artifact_ledger(sp)
    assert {contract.key for contract, _ in rows} <= set(ledger["work_units"])
    assert len([
        key for key in ledger["artifact_bindings"]
        if key.startswith("scratchpad:analysis_worker_")
    ]) == 12


@pytest.mark.parametrize(
    "validator",
    (validate_work_unit_inputs, validate_work_unit_artifacts),
    ids=("inputs", "artifacts"),
)
def test_top_level_validation_epoch_serializes_disjoint_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    validator,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()

    target = _independent_driver_contract("validation_target")
    sibling = _independent_driver_contract("validation_sibling")
    target_launch = _launch(target)
    sibling_launch = _launch(sibling)
    for contract, launch in (
        (target, target_launch),
        (sibling, sibling_launch),
    ):
        record_work_unit_inputs(
            sp, tmp_path, contract, launch, run_id="validation-lock-run"
        )
        (sp / f"{contract.work_unit_id}.md").write_text(
            f"{contract.work_unit_id}\n", encoding="utf-8"
        )
    record_work_unit_artifacts(
        sp,
        tmp_path,
        target,
        target_launch,
        run_id="validation-lock-run",
    )

    real_lock = AL._ledger_transaction_lock
    real_context_init = AL._ArtifactValidationContext.__init__
    real_finish = AL._ArtifactValidationContext.finish
    validator_thread_id: list[int] = []
    writer_thread_id: list[int] = []
    validator_holds_lock = threading.Event()
    context_constructed_under_lock = threading.Event()
    validation_at_finish = threading.Event()
    lock_held_at_finish = threading.Event()
    writer_attempted_lock = threading.Event()
    writer_acquired_lock = threading.Event()
    writer_was_blocked_at_finish = threading.Event()

    @contextmanager
    def tracked_lock(scratchpad: Path, *, timeout_s: float = 30.0):
        is_writer = bool(
            writer_thread_id
            and threading.get_ident() == writer_thread_id[0]
        )
        if is_writer:
            writer_attempted_lock.set()
        with real_lock(scratchpad, timeout_s=timeout_s):
            if is_writer:
                writer_acquired_lock.set()
            is_validator = bool(
                validator_thread_id
                and threading.get_ident() == validator_thread_id[0]
            )
            if is_validator:
                validator_holds_lock.set()
            try:
                yield
            finally:
                if is_validator:
                    validator_holds_lock.clear()

    def tracked_context_init(context, *args, **kwargs):
        if (
            validator_thread_id
            and threading.get_ident() == validator_thread_id[0]
            and validator_holds_lock.is_set()
        ):
            context_constructed_under_lock.set()
        real_context_init(context, *args, **kwargs)

    def tracked_finish(context):
        if (
            validator_thread_id
            and threading.get_ident() == validator_thread_id[0]
        ):
            if validator_holds_lock.is_set():
                lock_held_at_finish.set()
            validation_at_finish.set()
            assert writer_attempted_lock.wait(5)
            if not writer_acquired_lock.is_set():
                writer_was_blocked_at_finish.set()
        return real_finish(context)

    monkeypatch.setattr(AL, "_ledger_transaction_lock", tracked_lock)
    monkeypatch.setattr(
        AL._ArtifactValidationContext, "__init__", tracked_context_init
    )
    monkeypatch.setattr(
        AL._ArtifactValidationContext, "finish", tracked_finish
    )

    def run_validation() -> list[str]:
        validator_thread_id.append(threading.get_ident())
        return validator(
            sp,
            tmp_path,
            target,
            target_launch,
            run_id="validation-lock-run",
        )

    def run_writer():
        writer_thread_id.append(threading.get_ident())
        return record_work_unit_artifacts(
            sp,
            tmp_path,
            sibling,
            sibling_launch,
            run_id="validation-lock-run",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        validation_future = pool.submit(run_validation)
        assert validation_at_finish.wait(5)
        writer_future = pool.submit(run_writer)
        assert writer_attempted_lock.wait(5)
        validation_issues = validation_future.result(timeout=10)
        sibling_unit = writer_future.result(timeout=10)

    assert context_constructed_under_lock.is_set()
    assert lock_held_at_finish.is_set()
    assert writer_was_blocked_at_finish.is_set()
    assert writer_acquired_lock.is_set()
    assert validation_issues == []
    assert sibling_unit["semantic_status"] == "ACTIVE"
    for contract, launch in (
        (target, target_launch),
        (sibling, sibling_launch),
    ):
        assert validate_work_unit_inputs(
            sp, tmp_path, contract, launch, run_id="validation-lock-run"
        ) == []
        assert validate_work_unit_artifacts(
            sp, tmp_path, contract, launch, run_id="validation-lock-run"
        ) == []


def test_verify_queue_shared_epoch_serializes_disjoint_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    sibling = _independent_driver_contract("verify_queue_sibling")
    sibling_launch = _launch(sibling)
    record_work_unit_inputs(
        sp,
        tmp_path,
        sibling,
        sibling_launch,
        run_id="external-validation-lock-run",
    )
    (sp / "verify_queue_sibling.md").write_text(
        "verify queue sibling\n", encoding="utf-8"
    )

    real_lock = AL._ledger_transaction_lock
    writer_thread_id: list[int] = []
    validation_inside_epoch = threading.Event()
    writer_attempted_lock = threading.Event()
    writer_acquired_lock = threading.Event()
    writer_was_blocked = threading.Event()

    @contextmanager
    def tracked_lock(scratchpad: Path, *, timeout_s: float = 30.0):
        is_writer = bool(
            writer_thread_id
            and threading.get_ident() == writer_thread_id[0]
        )
        if is_writer:
            writer_attempted_lock.set()
        with real_lock(scratchpad, timeout_s=timeout_s):
            if is_writer:
                writer_acquired_lock.set()
            yield

    def synchronized_edge_validation(**_kwargs):
        validation_inside_epoch.set()
        assert writer_attempted_lock.wait(5)
        if not writer_acquired_lock.is_set():
            writer_was_blocked.set()
        return []

    monkeypatch.setattr(AL, "_ledger_transaction_lock", tracked_lock)
    monkeypatch.setattr(VQ, "_validate_plan_digest", lambda _plan: None)
    monkeypatch.setattr(VQ, "_transaction_units", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(
        VQ, "_transaction_edge_issues", synchronized_edge_validation
    )
    plan = {
        "schema_version": "plamen.verify_queue_transaction_plan.v1",
        "plan_digest": "test-plan",
    }

    def run_writer():
        writer_thread_id.append(threading.get_ident())
        return record_work_unit_artifacts(
            sp,
            tmp_path,
            sibling,
            sibling_launch,
            run_id="external-validation-lock-run",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        validation_future = pool.submit(
            VQ.validate_transaction_authority,
            scratchpad=sp,
            project_root=tmp_path,
            plan=plan,
            run_id="external-validation-lock-run",
            require_parent_commit=False,
        )
        assert validation_inside_epoch.wait(5)
        writer_future = pool.submit(run_writer)
        assert writer_attempted_lock.wait(5)
        validation_issues = validation_future.result(timeout=10)
        sibling_unit = writer_future.result(timeout=10)

    assert writer_was_blocked.is_set()
    assert writer_acquired_lock.is_set()
    assert validation_issues == []
    assert sibling_unit["semantic_status"] == "ACTIVE"
    assert validate_work_unit_artifacts(
        sp,
        tmp_path,
        sibling,
        sibling_launch,
        run_id="external-validation-lock-run",
    ) == []


def test_production_validation_context_constructor_census():
    scripts = Path(__file__).parent
    module_names = (
        "artifact_ledger.py",
        "plamen_driver.py",
        "verify_queue_phaseio_authority.py",
        "severity_initial_source.py",
        "report_empty_tier.py",
    )
    owners_by_module: dict[str, set[str]] = {}
    for module_name in module_names:
        tree = ast.parse(
            (scripts / module_name).read_text(encoding="utf-8"),
            filename=module_name,
        )
        parents = {
            child: node
            for node in ast.walk(tree)
            for child in ast.iter_child_nodes(node)
        }
        owners: set[str] = set()
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_ArtifactValidationContext"
            ):
                continue
            parent = parents.get(node)
            while parent is not None and not isinstance(
                parent, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                parent = parents.get(parent)
            owners.add(parent.name if parent is not None else "<module>")
        owners_by_module[module_name] = owners

    assert owners_by_module == {
        "artifact_ledger.py": {
            "_artifact_validation_epoch",
            "_record_work_unit_artifacts_unlocked",
            "record_work_unit_artifacts",
            "record_work_unit_inputs",
        },
        "plamen_driver.py": set(),
        "verify_queue_phaseio_authority.py": set(),
        "severity_initial_source.py": set(),
        "report_empty_tier.py": set(),
    }


def test_unlocked_injected_validation_context_fails_closed(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    contract = _independent_driver_contract("unlocked_context")
    launch = _launch(contract)
    record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="unlocked-context-run"
    )
    (sp / "unlocked_context.md").write_text(
        "unlocked context\n", encoding="utf-8"
    )
    record_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="unlocked-context-run"
    )
    context = AL._ArtifactValidationContext(sp, tmp_path)

    expected = [
        "artifact validation context does not own ledger transaction lock"
    ]
    assert validate_work_unit_inputs(
        sp,
        tmp_path,
        contract,
        launch,
        run_id="unlocked-context-run",
        _validation_context=context,
    ) == expected
    assert validate_work_unit_artifacts(
        sp,
        tmp_path,
        contract,
        launch,
        run_id="unlocked-context-run",
        _validation_context=context,
    ) == expected
    assert context.finish() == []
