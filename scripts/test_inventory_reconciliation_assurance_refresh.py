"""Final inventory reconciliation remains typed after later mutations."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import artifact_ledger as L
from artifact_ledger import (
    arm_semantic_mutation,
    finalize_semantic_mutation,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
import plamen_driver as D
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from plamen_types import Checkpoint, SC_PHASES


def _phase(name: str):
    return next(phase for phase in SC_PHASES if phase.name == name)


def _finding(fid: str, title: str) -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        "**Severity**: Low\n"
        "**Location**: src/Fixture.sol:L1\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        f"**Root Cause**: {title}\n"
        f"**Description**: {title}\n"
        f"**Impact**: {title}\n"
    )


def _fixture(tmp_path: Path) -> tuple[Path, dict, Checkpoint]:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    run_id = str(uuid.uuid4())
    config = {
        "pipeline": "sc",
        "mode": "light",
        "language": "evm",
        "cli_backend": "claude",
        "scratchpad": str(scratch),
        "project_root": str(tmp_path),
        "_run_id": run_id,
    }
    (scratch / "analysis_fixture.md").write_text(
        "# Findings\n\n" + _finding("F-01", "original candidate"),
        encoding="utf-8",
    )
    (scratch / "inventory_chunk_a.manifest.md").write_text(
        "# Inventory shard\n\n| File |\n|---|\n| analysis_fixture.md |\n",
        encoding="utf-8",
    )
    chunk_contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="light",
        ecosystem="evm",
        backend="claude",
        phase="inventory_chunk_a",
        work_unit_id="model.attempt0001",
        exact_inputs=(
            "inventory_chunk_a.manifest.md",
            "analysis_fixture.md",
        ),
        exact_outputs=("findings_inventory_chunk_a.md",),
    )
    chunk_launch = LaunchSpec(
        work_unit_key=chunk_contract.key,
        pipeline="sc",
        mode="light",
        ecosystem="evm",
        backend="claude",
        model="fixture-model",
        timeout_s=30,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratch, tmp_path, chunk_contract, chunk_launch, run_id=run_id
    )
    (scratch / "findings_inventory_chunk_a.md").write_text(
        "# Findings Inventory\n\n" + _finding("INV-001", "original candidate")
        + "**Source IDs**: analysis_fixture.md:F-01\n",
        encoding="utf-8",
    )
    record_work_unit_artifacts(
        scratch,
        tmp_path,
        chunk_contract,
        chunk_launch,
        run_id=run_id,
        actor="MODEL",
    )
    aggregate, aggregate_issues = (
        D._run_inventory_canonical_aggregate_transaction(
            scratchpad=scratch,
            config=config,
            phase=_phase("inventory"),
            derivation_kind="single_shard",
        )
    )
    assert aggregate["finding_count"] == 1
    assert aggregate_issues == []
    checkpoint = Checkpoint(run_id=run_id)
    checkpoint.save(scratch)

    report_source = scratch / "report_assembly_fixture_source.md"
    report_source.write_text("# exact report assembly source\n", encoding="utf-8")
    report_contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="light",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="assembly",
        exact_inputs=(report_source.name,),
    )
    report_launch = LaunchSpec(
        work_unit_key=report_contract.key,
        pipeline=report_contract.pipeline,
        mode=report_contract.mode,
        ecosystem=report_contract.ecosystem,
        backend=report_contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratch, tmp_path, report_contract, report_launch, run_id=run_id
    )
    (tmp_path / "AUDIT_REPORT.md").write_text(
        "# Audit Report\n\n## Summary\n\nFixture.\n", encoding="utf-8"
    )
    record_work_unit_artifacts(
        scratch,
        tmp_path,
        report_contract,
        report_launch,
        run_id=run_id,
        actor="DRIVER",
    )
    return scratch, config, checkpoint


def _inventory_binding(scratch: Path, project: Path) -> dict:
    return L._input_binding_record(
        scratch,
        project,
        "scratchpad:findings_inventory.md",
        "IMMUTABLE",
        read_artifact_ledger(scratch),
    )


def _append_inventory(scratch: Path, marker: str) -> None:
    inventory = scratch / "findings_inventory.md"
    inventory.write_text(
        inventory.read_text(encoding="utf-8") + f"\n{marker}\n",
        encoding="utf-8",
    )


def _finalized_inventory_mutation(
    scratch: Path,
    project: Path,
    *,
    run_id: str,
    mutation_kind: str,
    marker: str,
) -> dict:
    event = arm_semantic_mutation(
        scratch,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind=mutation_kind,
        run_id=run_id,
    )
    _append_inventory(scratch, marker)
    return finalize_semantic_mutation(
        scratch,
        project,
        event["event_id"],
        run_id=run_id,
    )


def test_input_binding_accepts_exact_contiguous_finalized_mutation_chain(
    tmp_path: Path,
) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    first = _finalized_inventory_mutation(
        scratch,
        tmp_path,
        run_id=config["_run_id"],
        mutation_kind="FINDING_PROMOTION",
        marker="first authorized append",
    )
    second = _finalized_inventory_mutation(
        scratch,
        tmp_path,
        run_id=config["_run_id"],
        mutation_kind="FINDING_PROMOTION_SECOND_WAVE",
        marker="second authorized append",
    )
    assert first["status"] == second["status"] == "INVALIDATION_APPLIED"

    binding = _inventory_binding(scratch, tmp_path)

    assert binding["status"] == "ACTIVE"
    assert binding["producer_work_unit_key"] == (
        f"semantic-mutation:{second['event_id']}"
    )
    authority = binding["semantic_predecessor_authority"]
    assert authority["mutation_event_ids"] == [
        first["event_id"],
        second["event_id"],
    ]
    assert authority["terminal_event_id"] == second["event_id"]


def test_input_binding_rejects_unfinalized_mutation(tmp_path: Path) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=config["_run_id"],
    )
    _append_inventory(scratch, "write after arm without finalize")

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_input_binding_rejects_missing_finalized_mutation_event(
    tmp_path: Path,
) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    _finalized_inventory_mutation(
        scratch,
        tmp_path,
        run_id=config["_run_id"],
        mutation_kind="FINDING_PROMOTION",
        marker="authorized append whose receipt is later removed",
    )
    (scratch / L.SEMANTIC_MUTATION_LEDGER_NAME).unlink()

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_input_binding_rejects_corrupt_finalized_mutation_event(
    tmp_path: Path,
) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    _finalized_inventory_mutation(
        scratch,
        tmp_path,
        run_id=config["_run_id"],
        mutation_kind="FINDING_PROMOTION",
        marker="authorized append whose receipt is later corrupt",
    )
    path = scratch / L.SEMANTIC_MUTATION_LEDGER_NAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["events"][0]["after"]["sha256"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_input_binding_rejects_cross_run_mutation_event(tmp_path: Path) -> None:
    scratch, _config, _checkpoint = _fixture(tmp_path)
    other_run = str(uuid.uuid4())
    finalized = _finalized_inventory_mutation(
        scratch,
        tmp_path,
        run_id=other_run,
        mutation_kind="FINDING_PROMOTION",
        marker="cross-run append",
    )
    assert finalized["status"] == "INVALIDATION_APPLIED"

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_input_binding_rejects_noncontiguous_branching_mutation_chain(
    tmp_path: Path,
) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    first = arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION_A",
        run_id=config["_run_id"],
    )
    branch = arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION_B",
        run_id=config["_run_id"],
    )
    assert first["before"] == branch["before"]
    _append_inventory(scratch, "branching append")
    finalize_semantic_mutation(
        scratch, tmp_path, first["event_id"], run_id=config["_run_id"]
    )
    finalize_semantic_mutation(
        scratch, tmp_path, branch["event_id"], run_id=config["_run_id"]
    )

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_input_binding_rejects_mutation_for_wrong_artifact_identity(
    tmp_path: Path,
) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    wrong = arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:analysis_fixture.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=config["_run_id"],
    )
    _append_inventory(scratch, "unowned inventory append")
    finalized = finalize_semantic_mutation(
        scratch, tmp_path, wrong["event_id"], run_id=config["_run_id"]
    )
    assert finalized["status"] == "NO_CHANGE"

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_input_binding_rejects_changed_bytes_without_semantic_predecessor(
    tmp_path: Path,
) -> None:
    scratch, _config, _checkpoint = _fixture(tmp_path)
    _append_inventory(scratch, "unarmed and unowned append")

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_semantic_predecessor_cannot_bypass_historical_producer_validation(
    tmp_path: Path,
) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    _finalized_inventory_mutation(
        scratch,
        tmp_path,
        run_id=config["_run_id"],
        mutation_kind="FINDING_PROMOTION",
        marker="authorized append with later producer corruption",
    )
    ledger = read_artifact_ledger(scratch)
    producer_key = ledger["artifact_bindings"][
        "scratchpad:findings_inventory.md"
    ]["owner_key"]
    ledger["work_units"][producer_key]["commit_authority"][
        "receipt_digest"
    ] = "0" * 64
    L.write_artifact_ledger(scratch, ledger)

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_semantic_predecessor_does_not_exempt_producer_sibling_bytes(
    tmp_path: Path,
) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    _finalized_inventory_mutation(
        scratch,
        tmp_path,
        run_id=config["_run_id"],
        mutation_kind="FINDING_PROMOTION",
        marker="authorized target append before sibling tamper",
    )
    ledger = read_artifact_ledger(scratch)
    producer_key = ledger["artifact_bindings"][
        "scratchpad:findings_inventory.md"
    ]["owner_key"]
    assert (
        "scratchpad:finding_records.json"
        in ledger["work_units"][producer_key]["artifacts"]
    )
    (scratch / "finding_records.json").write_text(
        '{"tampered_sibling":true}\n', encoding="utf-8"
    )

    assert _inventory_binding(scratch, tmp_path)["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_final_refresh_rederives_stale_inventory_sidecars_before_assurance(
    tmp_path: Path,
) -> None:
    scratch, config, checkpoint = _fixture(tmp_path)
    assert D._record_inventory_reconciliation_phase_io(
        scratchpad=scratch, config=config, phase=_phase("inventory")
    ) == []

    event = arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=config["_run_id"],
    )
    inventory = scratch / "findings_inventory.md"
    inventory.write_text(
        inventory.read_text(encoding="utf-8")
        + "\n"
        + _finding("INV-002", "late additive candidate"),
        encoding="utf-8",
    )
    finalized = finalize_semantic_mutation(
        scratch,
        tmp_path,
        event["event_id"],
        run_id=config["_run_id"],
        affected_record_ids=("INV-002",),
    )
    assert finalized["status"] == "INVALIDATION_APPLIED"
    ledger = read_artifact_ledger(scratch)
    recon_key = "sc/light/evm/claude/inventory/exact_reconciliation"
    assert ledger["work_units"][recon_key]["semantic_status"] == "STALE_INPUT"

    assert D._refresh_final_inventory_reconciliation_phase_io(
        scratchpad=scratch, config=config
    ) == []
    assert D._validate_inventory_reconciliation_phase_io(
        scratchpad=scratch,
        project_root=tmp_path,
        phase_name="inventory",
        mode="light",
        language="evm",
        pipeline="sc",
        backend="claude",
        timeout_s=_phase("inventory").base_timeout_s,
    ) == []
    ledger = read_artifact_ledger(scratch)
    unit = ledger["work_units"][recon_key]
    assert unit["semantic_status"] == "ACTIVE"
    assert all(row["status"] == "ACTIVE" for row in unit["artifacts"].values())
    inventory_binding = unit["input_bindings"][
        "scratchpad:findings_inventory.md"
    ]
    assert inventory_binding["producer_work_unit_key"].startswith(
        "semantic-mutation:"
    )

    assert D._refresh_assurance_projection(checkpoint, scratch, config) == []
    assurance_key = "sc/light/evm/claude/report_floor/assurance_projection"
    assurance = read_artifact_ledger(scratch)["work_units"][assurance_key]
    for identity in (
        "scratchpad:inventory_reconciliation.json",
        "scratchpad:inventory_reconciliation_human_review.md",
    ):
        assert assurance["input_bindings"][identity]["status"] == "ACTIVE"


def test_final_refresh_fails_closed_when_mutation_authority_is_corrupt(
    tmp_path: Path,
) -> None:
    scratch, config, _checkpoint = _fixture(tmp_path)
    assert D._record_inventory_reconciliation_phase_io(
        scratchpad=scratch, config=config, phase=_phase("inventory")
    ) == []
    event = arm_semantic_mutation(
        scratch,
        tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=config["_run_id"],
    )
    (scratch / "findings_inventory.md").write_text(
        "unowned changed bytes\n", encoding="utf-8"
    )
    finalize_semantic_mutation(
        scratch, tmp_path, event["event_id"], run_id=config["_run_id"]
    )
    mutation_path = scratch / "_semantic_mutations.json"
    payload = json.loads(mutation_path.read_text(encoding="utf-8"))
    payload["events"][0]["after"]["sha256"] = "0" * 64
    mutation_path.write_text(json.dumps(payload), encoding="utf-8")

    issues = D._refresh_final_inventory_reconciliation_phase_io(
        scratchpad=scratch, config=config
    )
    assert issues
    assert any(
        "semantic mutation" in issue.lower()
        or "producer authority" in issue.lower()
        or "producer_authority_mismatch" in issue.lower()
        for issue in issues
    )
