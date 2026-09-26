"""Gate-P coupled-successor failure, replay, and downstream authority tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

import artifact_ledger as AL
from gate_p_successor import (
    CANONICAL_NAMES,
    GatePSuccessorError,
    PLAN_NAME,
    SUCCESSOR_OUTPUTS,
    run_gate_p_coupled_successor,
)
from driver_successor_io import materialize_driver_successor_transition
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract


DIMENSIONS = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
SUCCESSOR_KEY = "sc/thorough/evm/claude/inventory/gate_p_successor"


class InjectedBoundary(RuntimeError):
    pass


def _seed_canonical(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    manifest = scratch / "inventory_floor_source_manifest.json"
    manifest.write_text('{"schema_version":"fixture"}\n', encoding="utf-8")
    contract = resolve_phase_io_contract(
        **DIMENSIONS,
        phase="inventory",
        work_unit_id="late_recall_floor",
        exact_inputs=(manifest.name,),
        exact_outputs=(
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
            "inventory_floor_receipt.json",
        ),
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
    AL.record_work_unit_inputs(
        scratch, project, contract, launch, run_id="run-gate-p-coupled"
    )
    (scratch / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n## Findings\n", encoding="utf-8"
    )
    (scratch / "finding_records.json").write_text(
        '{"schema_version":"plamen.finding_records.v2","records":[]}\n',
        encoding="utf-8",
    )
    (scratch / "_id_ledger.json").write_text(
        '{"schema_version":"plamen.id_ledger.v1","allocations":[]}\n',
        encoding="utf-8",
    )
    (scratch / "inventory_floor_receipt.json").write_text(
        '{"schema_version":"plamen.inventory_floor_receipt.v1"}\n',
        encoding="utf-8",
    )
    AL.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id="run-gate-p-coupled",
        actor="DRIVER",
    )
    return project, scratch


def _sources(scratch: Path) -> tuple[str, ...]:
    (scratch / "promotion_coverage_seed.md").write_text(
        "# Promotion Coverage Seed\n\n| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |\n",
        encoding="utf-8",
    )
    return (*CANONICAL_NAMES, "promotion_coverage_seed.md")


def _evaluator(counter: list[int]):
    def evaluate(stage: Path) -> dict[str, int]:
        counter[0] += 1
        inventory = stage / "findings_inventory.md"
        inventory.write_bytes(inventory.read_bytes() + b"\n<!-- GATE-P -->\n")
        records = json.loads((stage / "finding_records.json").read_text())
        records["gate_p_fixture"] = True
        (stage / "finding_records.json").write_text(
            json.dumps(records, sort_keys=True) + "\n", encoding="utf-8"
        )
        ledger = json.loads((stage / "_id_ledger.json").read_text())
        ledger["gate_p_fixture"] = True
        (stage / "_id_ledger.json").write_text(
            json.dumps(ledger, sort_keys=True) + "\n", encoding="utf-8"
        )
        for name in (
            "promotion_orphans.md",
            "promotion_routing.md",
            "promotion_orphans_appendix_c.md",
            "promotion_orphans_appendix_a.md",
            "promotion_gate_receipt.md",
        ):
            (stage / name).write_text(
                f"# {name}\n\nDeterministic Gate-P fixture diagnostic.\n",
                encoding="utf-8",
            )
        return {"harvested": 1, "emitted_to_inventory": 1}

    return evaluate


def _run(
    scratch: Path,
    project: Path,
    sources: tuple[str, ...],
    counter: list[int],
    *,
    boundary: str = "",
) -> dict:
    def inject(name: str) -> None:
        if name == boundary:
            raise InjectedBoundary(name)

    return run_gate_p_coupled_successor(
        scratch,
        project,
        run_id="run-gate-p-coupled",
        dimensions=DIMENSIONS,
        source_names=sources,
        evaluator=_evaluator(counter),
        failpoint=inject if boundary else None,
    )


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS exposes its private temporary tree through /var",
)
def test_gate_p_canonicalizes_macos_var_temp_stage_for_driver_writes(
    tmp_path: Path,
) -> None:
    """A Gate-P evaluator must not inherit macOS's /var symlink spelling."""

    project, scratch = _seed_canonical(tmp_path)
    sources = _sources(scratch)
    observed_stages: list[Path] = []

    def evaluate(stage: Path) -> dict[str, int]:
        observed_stages.append(stage)
        materialize_driver_successor_transition(
            stage / "driver_owned_diagnostic.json",
            b'{}\n',
        )
        return _evaluator([0])(stage)

    result = run_gate_p_coupled_successor(
        scratch,
        project,
        run_id="run-gate-p-coupled",
        dimensions=DIMENSIONS,
        source_names=sources,
        evaluator=evaluate,
    )

    assert result["safe_to_consume"] is True
    assert len(observed_stages) == 1
    assert observed_stages[0] == observed_stages[0].resolve(strict=False)


@pytest.mark.parametrize(
    "boundary",
    (
        "capture:after_publish",
        "after_capture",
        "after_plan",
        "after_arm",
        "after_replace_1",
        "after_output_1",
        "after_replace_2",
        "after_output_2",
        "after_replace_3",
        "after_output_3",
        "after_replace_4",
        "after_output_4",
        "before_commit",
        "after_commit",
    ),
)
def test_gate_p_every_persisted_boundary_resumes_without_reevaluation(
    tmp_path: Path,
    boundary: str,
) -> None:
    project, scratch = _seed_canonical(tmp_path)
    sources = _sources(scratch)
    counter = [0]
    with pytest.raises(InjectedBoundary, match=boundary):
        _run(scratch, project, sources, counter, boundary=boundary)
    assert counter == [1]

    result = _run(scratch, project, sources, counter)
    assert result["safe_to_consume"] is True
    assert counter == [1]
    unit = AL.read_artifact_ledger(scratch)["work_units"][SUCCESSOR_KEY]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE",
        "OUTPUT_COMMITTED",
    )
    assert unit["commit_authority"]["actor"] == "DRIVER"
    assert "successor_consumption_authority" in unit


def test_gate_p_source_drift_before_capture_publication_fails_closed(
    tmp_path: Path,
) -> None:
    project, scratch = _seed_canonical(tmp_path)
    sources = _sources(scratch)
    counter = [0]

    def mutate_after_evaluation(stage: Path) -> dict[str, int]:
        result = _evaluator(counter)(stage)
        source = scratch / "promotion_coverage_seed.md"
        source.write_bytes(source.read_bytes() + b"FOREIGN\n")
        return result

    with pytest.raises(GatePSuccessorError, match="source changed after planning"):
        run_gate_p_coupled_successor(
            scratch,
            project,
            run_id="run-gate-p-coupled",
            dimensions=DIMENSIONS,
            source_names=sources,
            evaluator=mutate_after_evaluation,
        )
    assert not (scratch / PLAN_NAME).exists()
    assert SUCCESSOR_KEY not in AL.read_artifact_ledger(scratch)["work_units"]


def test_gate_p_stages_ledger_witness_without_self_referential_binding(
    tmp_path: Path,
) -> None:
    """The lineage journal is sealed for staging but cannot bind itself."""

    project, scratch = _seed_canonical(tmp_path)
    sources = (*_sources(scratch), "_artifact_state.json")
    before = (scratch / "_artifact_state.json").read_bytes()
    counter = [0]

    result = _run(scratch, project, sources, counter)

    assert result["safe_to_consume"] is True
    assert counter == [1]
    plan = json.loads((scratch / PLAN_NAME).read_text(encoding="utf-8"))
    assert any(
        row["path"] == "_artifact_state.json"
        and row["sha256"] == hashlib.sha256(before).hexdigest()
        for row in plan["source_preimages"]
    )
    capture_key = "sc/thorough/evm/claude/inventory/gate_p.source_capture"
    capture = AL.read_artifact_ledger(scratch)["work_units"][capture_key]
    assert (
        "scratchpad:_artifact_state.json"
        not in capture["contract_manifest"]["immutable_inputs"]
    )
    assert (scratch / "_artifact_state.json").read_bytes() != before


def test_phaseio_globally_rejects_self_referential_artifact_ledger_input() -> None:
    with pytest.raises(ValueError, match="mutable PhaseIO ledger"):
        resolve_phase_io_contract(
            **DIMENSIONS,
            phase="inventory",
            work_unit_id="gate_p.source_capture",
            exact_inputs=("_artifact_state.json",),
            exact_outputs=(PLAN_NAME,),
        )


@pytest.mark.parametrize("ordinal", range(1, len(SUCCESSOR_OUTPUTS) + 1))
def test_gate_p_resume_rejects_foreign_third_state(
    tmp_path: Path,
    ordinal: int,
) -> None:
    project, scratch = _seed_canonical(tmp_path)
    sources = _sources(scratch)
    counter = [0]
    with pytest.raises(InjectedBoundary):
        _run(
            scratch,
            project,
            sources,
            counter,
            boundary=f"after_output_{ordinal}",
        )
    target = SUCCESSOR_OUTPUTS[ordinal - 1]
    expected = (scratch / target).read_bytes()
    (scratch / target).write_bytes(b"FOREIGN-THIRD-STATE\n")
    with pytest.raises(AL.ArtifactLedgerError):
        _run(scratch, project, sources, counter)
    (scratch / target).write_bytes(expected)
    assert _run(scratch, project, sources, counter)["safe_to_consume"] is True


def test_gate_p_committed_replay_is_idempotent_and_rag_inputs_are_authoritative(
    tmp_path: Path,
) -> None:
    project, scratch = _seed_canonical(tmp_path)
    sources = _sources(scratch)
    counter = [0]
    first = _run(scratch, project, sources, counter)
    before = {name: (scratch / name).read_bytes() for name in CANONICAL_NAMES}
    second = _run(scratch, project, sources, counter)
    assert first["safe_to_consume"] is second["safe_to_consume"] is True
    assert second["reused"] is True
    assert counter == [1]
    assert {name: (scratch / name).read_bytes() for name in CANONICAL_NAMES} == before

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="rag_sweep",
        work_unit_id="precedent_facts",
        exact_inputs=("finding_records.json", "findings_inventory.md"),
        exact_outputs=("precedent_finding_facts.json",),
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
    unit = AL.record_work_unit_inputs(
        scratch,
        project,
        contract,
        launch,
        run_id="run-gate-p-coupled",
    )
    for identity in (
        "scratchpad:finding_records.json",
        "scratchpad:findings_inventory.md",
    ):
        binding = unit["input_bindings"][identity]
        assert binding["producer_work_unit_key"] == SUCCESSOR_KEY
        assert AL.semantic_input_producer_authority_issues(
            AL.read_artifact_ledger(scratch),
            binding,
            run_id="run-gate-p-coupled",
        ) == []


def test_gate_p_output_denominator_cannot_claim_dedup_proposal_bytes() -> None:
    contract = resolve_phase_io_contract(
        **DIMENSIONS,
        phase="inventory",
        work_unit_id="gate_p_successor",
        exact_inputs=(PLAN_NAME,),
        exact_outputs=(
            "_id_ledger.json",
            "finding_records.json",
            "findings_inventory.md",
            "promotion_orphans.md",
            "promotion_routing.md",
            "promotion_orphans_appendix_c.md",
            "promotion_orphans_appendix_a.md",
            "promotion_gate_receipt.md",
            "gate_p_successor_receipt.json",
        ),
    )
    assert {spec.path for spec in contract.outputs} == set(SUCCESSOR_OUTPUTS)
    with pytest.raises(ValueError, match="registered exact output denominator"):
        resolve_phase_io_contract(
            **DIMENSIONS,
            phase="inventory",
            work_unit_id="gate_p_successor",
            exact_inputs=(PLAN_NAME,),
            exact_outputs=(*CANONICAL_NAMES, "dedup_decisions.md"),
        )


def test_real_gate_p_evaluator_delivers_candidate_as_coupled_triplet(
    tmp_path: Path,
) -> None:
    project, scratch = _seed_canonical(tmp_path)
    sources = _sources(scratch)
    (scratch / "analysis_fixture.md").write_text(
        "## Finding [B1-1]: Missing authorization guard permits drain\n\n"
        "**Location**: `src/Vault.sol:L12`\n"
        "**Root Cause**: The withdrawal path lacks an authorization check.\n"
        "**Description**: An untrusted caller can manipulate the recipient and drain assets.\n"
        "**Impact**: Deposited funds can be stolen.\n",
        encoding="utf-8",
    )
    result = run_gate_p_coupled_successor(
        scratch,
        project,
        run_id="run-gate-p-coupled",
        dimensions=DIMENSIONS,
        source_names=(*sources, "analysis_fixture.md"),
    )
    assert result["safe_to_consume"] is True
    assert result["result"]["emitted_to_inventory"] == 1
    inventory = (scratch / "findings_inventory.md").read_text(encoding="utf-8")
    records = json.loads((scratch / "finding_records.json").read_text())
    identifiers = json.loads((scratch / "_id_ledger.json").read_text())
    assert "Promotion-Completeness Candidates (PROMOGAP)" in inventory
    source_hash = hashlib.sha256(
        (scratch / "analysis_fixture.md").read_bytes()
    ).hexdigest()
    assert (
        "**Source Actions**: analysis_fixture.md:B1-1@sha256:"
        + source_hash
    ) in inventory
    from plamen_validators import (
        _validate_current_registered_finding_delivery,
    )

    assert _validate_current_registered_finding_delivery(scratch) == []
    assert any(row.get("inventory_id") == "INV-001" for row in records["records"])
    assert any(row.get("id") == "INV-001" for row in identifiers["allocations"])
    assert (scratch / "promotion_orphans.md").is_file()
    assert (scratch / "promotion_routing.md").is_file()
    assert (scratch / "promotion_gate_receipt.md").is_file()


def test_real_gate_p_zero_orphan_commit_publishes_exact_diagnostics(
    tmp_path: Path,
) -> None:
    project, scratch = _seed_canonical(tmp_path)
    sources = _sources(scratch)

    result = run_gate_p_coupled_successor(
        scratch,
        project,
        run_id="run-gate-p-coupled",
        dimensions=DIMENSIONS,
        source_names=sources,
    )

    assert result["safe_to_consume"] is True
    assert result["result"] == {
        "appendix_a": 0,
        "appendix_c": 0,
        "body_candidates": 0,
        "emitted_to_inventory": 0,
        "harvested": 0,
    }
    for name in SUCCESSOR_OUTPUTS:
        assert (scratch / name).is_file(), name
    assert "Orphans: 0" in (
        scratch / "promotion_orphans.md"
    ).read_text(encoding="utf-8")
