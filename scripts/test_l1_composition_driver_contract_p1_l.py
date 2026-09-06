from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from phase_io_contracts import resolve_phase_io_contract
import json

import l1_composition_runtime as R
import plamen_driver as D
from plamen_types import L1_PHASES


def test_l1_composition_live_boundary_has_explicit_public_contract():
    signature = inspect.signature(D._run_l1_composition_live_boundary)

    assert tuple(signature.parameters) == ("scratchpad", "config", "phase")
    assert callable(R.write_l1_composition_runtime)
    assert callable(D.reconcile_l1_composition_runtime)


def _contract(work_unit_id: str, *, inputs=(), outputs=()):
    return resolve_phase_io_contract(
        pipeline="l1",
        mode="core",
        ecosystem="go",
        backend="claude",
        phase="verify_queue",
        work_unit_id=work_unit_id,
        exact_inputs=tuple(inputs),
        exact_outputs=tuple(outputs),
    )


def test_l1_composition_phaseio_chain_has_exact_writer_and_input_authority():
    source = ("findings_inventory.md", "depth_consensus_findings.md")
    worklist = _contract(
        "l1_composition.fact_worklist",
        inputs=source,
        outputs=("l1_composition_fact_worklist.json",),
    )
    facts = _contract(
        "worker.l1_composition_facts",
        inputs=("l1_composition_fact_worklist.json", *source),
        outputs=("l1_composition_fact_records.json",),
    )
    runtime = _contract(
        "l1_composition.runtime",
        inputs=(*source, "l1_composition_fact_records.json"),
        outputs=("l1_composition_runtime.json",),
    )
    dispositions = _contract(
        "worker.l1_composition_dispositions",
        inputs=("l1_composition_runtime.json", *source),
        outputs=("l1_composition_model_dispositions.json",),
    )
    reconcile = _contract(
        "l1_composition.reconcile",
        inputs=(
            "l1_composition_runtime.json",
            "l1_composition_model_dispositions.json",
        ),
        outputs=("l1_composition_receipt.json",),
    )
    assert [row.writer for row in worklist.outputs] == ["DRIVER"]
    assert [row.writer for row in facts.outputs] == ["MODEL"]
    assert [row.writer for row in runtime.outputs] == ["DRIVER"]
    assert [row.writer for row in dispositions.outputs] == ["MODEL"]
    assert [row.writer for row in reconcile.outputs] == ["DRIVER"]
    assert facts.immutable_inputs != dispositions.immutable_inputs


@pytest.mark.parametrize(
    ("work_id", "inputs", "outputs"),
    [
        (
            "l1_composition.fact_worklist",
            ("security_report.md",),
            ("l1_composition_fact_worklist.json",),
        ),
        (
            "worker.l1_composition_facts",
            ("findings_inventory.md",),
            ("l1_composition_fact_records.json",),
        ),
        (
            "l1_composition.runtime",
            ("l1_composition_fact_records.json", "findings_inventory.md"),
            ("l1_composition_runtime.json",),
        ),
    ],
)
def test_l1_composition_phaseio_rejects_drifted_denominators(
    work_id: str, inputs: tuple[str, ...], outputs: tuple[str, ...]
):
    with pytest.raises(ValueError):
        _contract(work_id, inputs=inputs, outputs=outputs)


@pytest.mark.parametrize("spoof_principals", [False, True])
def test_live_driver_boundary_binds_worker_principals_before_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spoof_principals: bool,
):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    (root / R.INVENTORY_NAME).write_text(
        "# Inventory\n\n"
        "## Finding [L1-A1]: A\n\n**Severity**: Medium\n\nA.\n\n"
        "## Finding [L1-B1]: B\n\n**Severity**: Medium\n\nB.\n",
        encoding="utf-8",
    )
    invocations: list[str] = []
    provider_calls: list[str] = []
    real_runtime = D.write_l1_composition_runtime
    real_reconcile = D.reconcile_l1_composition_runtime

    def observed_runtime(*args, **kwargs):
        provider_calls.append("runtime")
        return real_runtime(*args, **kwargs)

    def observed_reconcile(*args, **kwargs):
        provider_calls.append("reconcile")
        return real_reconcile(*args, **kwargs)

    monkeypatch.setattr(D, "write_l1_composition_runtime", observed_runtime)
    monkeypatch.setattr(D, "reconcile_l1_composition_runtime", observed_reconcile)

    def fake_worker(
        scratchpad, config, phase, *, phase_name, work_unit_id, output,
        prompt, validate, exact_inputs=(),
    ):
        invocations.append(work_unit_id)
        contract, launch = D._p1dm_contract_and_launch(
            root,
            config,
            phase_name=phase_name,
            work_unit_id=work_unit_id,
            phase=phase,
            exact_inputs=exact_inputs,
            exact_outputs=(output,),
            actor="MODEL",
        )
        producer_identity = (
            f"model-chosen-{work_unit_id}" if spoof_principals else contract.key
        )
        producer_invocation = (
            f"model-chosen-invocation-{work_unit_id}"
            if spoof_principals else launch.digest
        )
        if output == R.TYPED_RECORDS_NAME:
            worklist = json.loads(
                (root / R.FACT_WORKLIST_NAME).read_text(encoding="utf-8")
            )
            atom = {"kind": "STATE", "atom_id": "state.commit"}
            rows = []
            for index, source in enumerate(worklist["occurrences"]):
                rows.append({
                    "candidate_id": source["candidate_id"],
                    "source_artifact": source["source_artifact"],
                    "source_block_sha256": source["source_block_sha256"],
                    "language": "GO",
                    "layer": "execution" if index == 0 else "consensus",
                    "subsystem": "execution" if index == 0 else "consensus",
                    "root_cause_id": f"ROOT-{source['candidate_id']}",
                    "candidate_state": "CONFIRMED",
                    "requires": [] if index == 0 else [atom],
                    "produces": [atom] if index == 0 else [],
                    "touches": [],
                })
            payload = {
                "schema_version": R.TYPED_RECORDS_SCHEMA,
                "run_id": "run-live",
                "snapshot_digest": "a" * 64,
                "producer_identity": producer_identity,
                "producer_invocation_id": producer_invocation,
                "records": rows,
            }
        else:
            runtime = json.loads(
                (root / R.RUNTIME_NAME).read_text(encoding="utf-8")
            )
            payload = {
                "schema_version": R.MODEL_DISPOSITIONS_SCHEMA,
                "run_id": "run-live",
                "snapshot_digest": "a" * 64,
                "producer_identity": producer_identity,
                "producer_invocation_id": producer_invocation,
                "runtime_digest": runtime["runtime_digest"],
                "graph_digest": runtime["graph"]["graph_digest"],
                "work_packets_digest": runtime["work_packets_digest"],
                "dispositions": [{
                    "obligation_id": row["obligation_id"],
                    "disposition": "COMPOUND_CANDIDATE",
                    "rationale": "Independent composition requires verification.",
                } for row in runtime["work_packets"]],
            }
        (root / output).write_text(json.dumps(payload), encoding="utf-8")
        return list(validate())

    monkeypatch.setattr(D, "_run_p1dm_model_work_unit", fake_worker)
    config = {
        "pipeline": "l1",
        "mode": "core",
        "language": "go",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": "run-live",
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }
    phase = next(row for row in L1_PHASES if row.name == "verify_queue")
    issues = D._run_l1_composition_live_boundary(root, config, phase)
    assert invocations == [
        "worker.l1_composition_facts",
        "worker.l1_composition_dispositions",
    ]
    assert provider_calls[0] == "runtime"
    assert provider_calls.count("runtime") == 1
    assert provider_calls.count("reconcile") >= 1
    assert set(provider_calls[1:]) == {"reconcile"}
    receipt = json.loads((root / R.RECEIPT_NAME).read_text(encoding="utf-8"))
    if spoof_principals:
        assert any("not driver-bound" in issue for issue in issues)
        assert receipt["deliverable_obligation_coverage_exact"] is False
        assert receipt["compound_handoffs"] == []
    else:
        assert issues == []
        assert receipt["deliverable_obligation_coverage_exact"] is True
        assert len(receipt["compound_handoffs"]) == 1


def test_claude_typed_leaf_executes_from_the_scratchpad(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    config = {
        "pipeline": "l1",
        "mode": "core",
        "language": "go",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": "run-live",
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }
    phase = next(row for row in L1_PHASES if row.name == "application_skeptic")
    contract, launch = D._p1dm_contract_and_launch(
        root,
        config,
        phase_name="verify_queue",
        work_unit_id="worker.l1_composition_facts",
        phase=phase,
        exact_inputs=(R.FACT_WORKLIST_NAME, R.INVENTORY_NAME),
        exact_outputs=(R.TYPED_RECORDS_NAME,),
        actor="MODEL",
    )
    captured: dict[str, object] = {}

    def fake_claude(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", fake_claude)
    rc = D._execute_auxiliary_model_work_unit(
        prompt="typed leaf",
        phase=phase,
        config=config,
        scratchpad=root,
        output=R.TYPED_RECORDS_NAME,
        label="l1-facts",
        contract=contract,
        launch=launch,
    )

    assert rc == 0
    assert Path(str(captured["working_directory"])).resolve() == root.resolve()
    assert project.resolve() in {
        Path(str(path)).resolve()
        for path in captured["analysis_directories"]
    }


def test_live_boundary_does_not_launch_models_for_exact_no_source_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    config = {
        "pipeline": "l1",
        "mode": "core",
        "language": "go",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": "run-live",
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }

    def unexpected_worker(*args, **kwargs):
        raise AssertionError("no model worker is authorized for an empty source denominator")

    monkeypatch.setattr(D, "_run_p1dm_model_work_unit", unexpected_worker)
    phase = next(row for row in L1_PHASES if row.name == "verify_queue")

    issues = D._run_l1_composition_live_boundary(root, config, phase)

    assert issues == []
    worklist = json.loads(
        (root / R.FACT_WORKLIST_NAME).read_text(encoding="utf-8")
    )
    assert worklist["occurrence_count"] == 0
    assert not (root / R.TYPED_RECORDS_NAME).exists()
    assert not (root / R.RUNTIME_NAME).exists()
    assert "_l1_composition_producer_bindings" not in config


def test_live_boundary_skips_discriminator_for_exact_empty_obligation_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    (root / R.INVENTORY_NAME).write_text(
        "# Inventory\n\n## Finding [L1-A1]: A\n\nA.\n",
        encoding="utf-8",
    )
    config = {
        "pipeline": "l1",
        "mode": "core",
        "language": "go",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": "run-live",
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }
    invocations: list[str] = []

    def fake_worker(
        scratchpad, config, phase, *, phase_name, work_unit_id, output,
        prompt, validate, exact_inputs=(),
    ):
        invocations.append(work_unit_id)
        assert output == R.TYPED_RECORDS_NAME
        contract, launch = D._p1dm_contract_and_launch(
            root,
            config,
            phase_name=phase_name,
            work_unit_id=work_unit_id,
            phase=phase,
            exact_inputs=exact_inputs,
            exact_outputs=(output,),
            actor="MODEL",
        )
        worklist = json.loads(
            (root / R.FACT_WORKLIST_NAME).read_text(encoding="utf-8")
        )
        source = worklist["occurrences"][0]
        payload = {
            "schema_version": R.TYPED_RECORDS_SCHEMA,
            "run_id": "run-live",
            "snapshot_digest": "a" * 64,
            "producer_identity": contract.key,
            "producer_invocation_id": launch.digest,
            "records": [{
                "candidate_id": source["candidate_id"],
                "source_artifact": source["source_artifact"],
                "source_block_sha256": source["source_block_sha256"],
                "language": "GO",
                "layer": "execution",
                "subsystem": "execution",
                "root_cause_id": "ROOT-L1-A1",
                "candidate_state": "UNRESOLVED",
                "requires": [],
                "produces": [],
                "touches": [],
            }],
        }
        (root / output).write_text(json.dumps(payload), encoding="utf-8")
        return list(validate())

    monkeypatch.setattr(D, "_run_p1dm_model_work_unit", fake_worker)
    phase = next(row for row in L1_PHASES if row.name == "verify_queue")

    D._run_l1_composition_live_boundary(root, config, phase)

    assert invocations == ["worker.l1_composition_facts"]
    runtime = json.loads((root / R.RUNTIME_NAME).read_text(encoding="utf-8"))
    assert runtime["work_packets"] == []
    assert not (root / R.MODEL_DISPOSITIONS_NAME).exists()
    assert not (root / R.RECEIPT_NAME).exists()
    assert "_l1_composition_producer_bindings" not in config
