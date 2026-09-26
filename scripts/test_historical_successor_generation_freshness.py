"""Semantic freshness across exact registered successor generations."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import artifact_ledger as AL
from artifact_ledger import (
    begin_driver_successor_step,
    complete_driver_successor_step,
    detect_semantic_input_drift,
    plan_driver_successor_transaction,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    write_artifact_ledger,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from test_grouped_successor_history import (
    CANDIDATES,
    INITIAL,
    QUEUE,
    RUN_ID,
    _commit_bind,
    _commit_plain,
    _resolve,
    _three_candidate_case,
)


def _keys(result: dict) -> set[str]:
    return set(result["stale_work_unit_keys"])


def test_severity_historical_generations_do_not_stale_prerequisites(tmp_path: Path):
    root, source, _sl, aggregate, _al, _planning, binds = (
        _three_candidate_case(tmp_path)
    )
    result = detect_semantic_input_drift(root, tmp_path, run_id=RUN_ID)
    protected = {
        source.key,
        aggregate.key,
        *(contract.key for contract, _launch in binds),
    }
    assert not (_keys(result) & protected)
    assert not (
        set(result["changed_input_identities"])
        & {
            "scratchpad:verify_H-A.severity_decision.json",
            "scratchpad:verify_H-B.severity_decision.json",
            "scratchpad:verify_H-C.severity_decision.json",
        }
    )


@pytest.mark.parametrize("mutation", ("missing", "cross_run", "wrong_owner"))
def test_severity_historical_generation_requires_exact_lineage(
    tmp_path: Path, mutation: str,
):
    root, _source, _sl, aggregate, _al, _planning, binds = (
        _three_candidate_case(tmp_path)
    )
    ledger = read_artifact_ledger(root)
    identity = "scratchpad:verify_H-A.severity_decision.json"
    history = ledger["artifact_bindings"][identity]["history"]
    assert history
    if mutation == "missing":
        history.clear()
    elif mutation == "cross_run":
        history[0]["run_id"] = RUN_ID + "-foreign"
    else:
        history[0]["superseded_by_owner_key"] = binds[-1][0].key
    write_artifact_ledger(root, ledger)

    result = detect_semantic_input_drift(root, tmp_path, run_id=RUN_ID)
    assert aggregate.key in _keys(result)
    assert identity in result["changed_input_identities"]


def test_severity_historical_generation_rejects_unauthorized_live_write(
    tmp_path: Path,
):
    root, _source, _sl, aggregate, _al, _planning, _binds = (
        _three_candidate_case(tmp_path)
    )
    identity = "scratchpad:verify_H-C.severity_decision.json"
    (root / identity.split(":", 1)[1]).write_bytes(b"unauthorized\n")
    result = detect_semantic_input_drift(root, tmp_path, run_id=RUN_ID)
    assert aggregate.key in _keys(result)
    assert identity in result["changed_input_identities"]


def test_historical_successor_does_not_exempt_mutable_unowned_coinput(
    tmp_path: Path,
):
    root, _source, _sl, aggregate, _al, _planning, _binds = (
        _three_candidate_case(tmp_path)
    )
    (root / "verification_queue.md").write_bytes(b"changed queue\n")
    result = detect_semantic_input_drift(root, tmp_path, run_id=RUN_ID)
    assert aggregate.key in _keys(result)
    assert "scratchpad:verification_queue.md" in result[
        "changed_input_identities"
    ]


def test_registered_successor_does_not_exempt_unrelated_old_byte_consumer(
    tmp_path: Path,
):
    root = tmp_path / ".scratchpad"
    root.mkdir()
    for name in QUEUE:
        (root / name).write_bytes((name + "\n").encode())
    verifier_inputs = tuple(
        f"verify_{candidate}{suffix}"
        for candidate in CANDIDATES
        for suffix in (".md", ".severity_proposal.json", ".receipt.json")
    )
    for name in verifier_inputs:
        (root / name).write_bytes((name + "\n").encode())
    source = _resolve(
        "source_decisions.verifier-unit-0001",
        (*QUEUE, *verifier_inputs),
        tuple(
            f"verify_{candidate}.severity_decision.json"
            for candidate in CANDIDATES
        ),
    )
    source_bytes = {
        f"verify_{candidate}.severity_decision.json": (
            f'{{"candidate":"{candidate}","initial":true}}\n'.encode()
        )
        for candidate in CANDIDATES
    }
    _commit_plain(root, source, source_bytes)
    aggregate = _resolve(
        "source_aggregate",
        (*QUEUE, *source_bytes),
        ("severity_decision_ledger.shadow.json", INITIAL),
    )
    initial = b'{"schema":"test-ledger","bound_through":0}\n'
    _commit_plain(
        root,
        aggregate,
        {"severity_decision_ledger.shadow.json": initial, INITIAL: initial},
    )

    # This is a genuine registered deterministic consumer, but none of its
    # outputs participates in the severity successor transaction.  Merely
    # having consumed the old H-A bytes must not turn it into historical
    # prerequisite authority.
    unrelated_inputs = (
        "report_records.json",
        "body_manifests/report_low_info.json",
        "verify_H-A.severity_decision.json",
    )
    for name in unrelated_inputs[:2]:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((name + "\n").encode())
    unrelated = resolve_phase_io_contract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="codex",
        phase="report_body",
        work_unit_id="evidence_pre",
        exact_inputs=unrelated_inputs,
        exact_outputs=EVIDENCE,
    )
    _commit(
        root,
        unrelated,
        {name: ("unrelated:" + name + "\n").encode() for name in EVIDENCE},
    )

    _commit_bind(
        root, CANDIDATES[0], 1,
        other_decisions=(CANDIDATES[1],),
    )
    _commit_bind(
        root, CANDIDATES[1], 2,
        other_decisions=(CANDIDATES[0],),
    )
    result = detect_semantic_input_drift(root, tmp_path, run_id=RUN_ID)
    assert unrelated.key in _keys(result)
    assert aggregate.key not in _keys(result)
    assert "scratchpad:verify_H-A.severity_decision.json" in result[
        "changed_input_identities"
    ]


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "codex",
}
EVIDENCE = (
    "report_evidence_records.json",
    "report_evidence_repair_request.json",
    "report_evidence_projection.md",
    "report_evidence_manifests/report_low_info.json",
)


def _report_contract(work: str, inputs: tuple[str, ...], outputs: tuple[str, ...]):
    return resolve_phase_io_contract(
        **BASE,
        phase="report_body",
        work_unit_id=work,
        exact_inputs=inputs,
        exact_outputs=outputs,
    )


def _launch(contract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )


def _commit(
    root: Path, contract, payloads: dict[str, bytes], *, actor: str = "DRIVER",
):
    launch = _launch(contract)
    record_work_unit_inputs(root, root.parent, contract, launch, run_id=RUN_ID)
    for name, raw in payloads.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    record_work_unit_artifacts(
        root, root.parent, contract, launch, run_id=RUN_ID, actor=actor,
    )
    return launch


def _report_repair_case(tmp_path: Path):
    root = tmp_path / ".scratchpad"
    root.mkdir()
    raw_inputs = (
        "report_records.json",
        "body_manifests/report_low_info.json",
        "verify_INV-1.md",
    )
    for name in raw_inputs:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((name + "\n").encode())
    pre = _report_contract("evidence_pre", raw_inputs, EVIDENCE)
    pre_launch = _commit(
        root, pre, {name: ("old:" + name + "\n").encode() for name in EVIDENCE},
    )
    arm_inputs = (*EVIDENCE, *raw_inputs)
    arm = _report_contract(
        "evidence_repair.arm",
        arm_inputs,
        ("report_evidence_repair_attempt.json", "_prompt_report_evidence_repair.md"),
    )
    arm_launch = _commit(
        root,
        arm,
        {
            "report_evidence_repair_attempt.json": b"{}\n",
            "_prompt_report_evidence_repair.md": b"repair\n",
        },
    )
    model_inputs = (
        *EVIDENCE,
        "report_evidence_repair_attempt.json",
        "_prompt_report_evidence_repair.md",
        *raw_inputs,
    )
    model = _report_contract(
        "evidence_repair.model",
        model_inputs,
        ("report_evidence_repair_response.json",),
    )
    model_launch = _commit(
        root,
        model,
        {"report_evidence_repair_response.json": b"{}\n"},
        actor="MODEL",
    )
    prepare = _report_contract(
        "evidence_repair.prepare",
        (
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_repair_response.json",
        ),
        ("report_evidence_repair_apply_plan.json",),
    )
    prepare_launch = _commit(
        root,
        prepare,
        {"report_evidence_repair_apply_plan.json": b"{}\n"},
    )
    apply = _report_contract(
        "evidence_repair.apply",
        (
            "report_evidence_repair_apply_plan.json",
            "report_evidence_repair_response.json",
            "body_manifests/report_low_info.json",
        ),
        (*EVIDENCE, "report_evidence_repair_receipt.json"),
    )
    apply_launch = _launch(apply)
    postimages = {
        **{
            f"scratchpad:{name}": ("new:" + name + "\n").encode()
            for name in EVIDENCE
        },
        "scratchpad:report_evidence_repair_receipt.json": b"{}\n",
    }
    plan = plan_driver_successor_transaction(
        root, root.parent, apply, apply_launch,
        run_id=RUN_ID, planned_output_bytes=postimages,
    )
    record_work_unit_inputs(
        root, root.parent, apply, apply_launch,
        run_id=RUN_ID, successor_plan=plan,
    )
    for transition in plan.transitions:
        begin_driver_successor_step(
            root, root.parent, apply, apply_launch,
            run_id=RUN_ID, ordinal=transition.ordinal,
        )
        (root / transition.artifact_identity.split(":", 1)[1]).write_bytes(
            postimages[transition.artifact_identity]
        )
        complete_driver_successor_step(
            root, root.parent, apply, apply_launch,
            run_id=RUN_ID, ordinal=transition.ordinal,
        )
    record_work_unit_artifacts(
        root, root.parent, apply, apply_launch,
        run_id=RUN_ID, actor="DRIVER",
    )
    return root, (
        (pre, pre_launch),
        (arm, arm_launch),
        (model, model_launch),
        (prepare, prepare_launch),
        (apply, apply_launch),
    )


def test_report_repair_historical_generations_replay_exact_path(tmp_path: Path):
    root, units = _report_repair_case(tmp_path)
    result = detect_semantic_input_drift(root, tmp_path, run_id=RUN_ID)
    assert not (_keys(result) & {contract.key for contract, _launch in units})
    assert not set(EVIDENCE) & {
        identity.split(":", 1)[1]
        for identity in result["changed_input_identities"]
    }


def test_report_repair_historical_generation_requires_live_final_bytes(
    tmp_path: Path,
):
    root, units = _report_repair_case(tmp_path)
    (root / EVIDENCE[0]).write_bytes(b"unauthorized\n")
    result = detect_semantic_input_drift(root, tmp_path, run_id=RUN_ID)
    arm = units[1][0]
    assert arm.key in _keys(result)
    assert f"scratchpad:{EVIDENCE[0]}" in result[
        "changed_input_identities"
    ]
