"""Registered, transitive severity successor history regressions.

These tests deliberately use the production resolver and the real ledger
plan/arm/step/commit APIs.  The payload bytes are synthetic; none of the
authority receipts or successor history is fabricated.
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

import artifact_ledger as AL
from artifact_ledger import (
    ArtifactLedgerError,
    begin_driver_successor_step,
    complete_driver_successor_step,
    plan_driver_successor_transaction,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_driver_successor_transaction,
    validate_historical_driver_successor_transaction,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
    write_artifact_ledger,
)
from phase_io_contracts import (
    LaunchSpec,
    registered_read_only_consumption,
    resolve_phase_io_contract,
)


RUN_ID = "run-grouped-successor-history"
BASE = {
    "pipeline": "sc",
    "mode": "core",
    "ecosystem": "evm",
    "backend": "codex",
}
QUEUE = (
    "verification_queue.md",
    "verification_queue.work_items.json",
    "verification_queue.work_plan.json",
    "verification_runtime_roster.json",
)
CANDIDATES = ("H-A", "H-B")
THREE_CANDIDATES = ("H-A", "H-B", "H-C")
INITIAL = "_severity_adjudication_inputs/source_ledger.initial.json"
CAPTURE_INPUTS = (
    "_severity_adjudication_inputs/audit_snapshot.json",
    "_severity_adjudication_inputs/audit_config.json",
    "_severity_adjudication_inputs/finding-output-format.md",
    "_severity_adjudication_inputs/poc-execution.md",
    "_severity_adjudication_inputs/report-template.md",
)


def _launch(contract):
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


def _resolve(work: str, inputs: tuple[str, ...], outputs: tuple[str, ...]):
    return resolve_phase_io_contract(
        **BASE,
        phase="severity_adjudication_shadow",
        work_unit_id=work,
        exact_inputs=inputs,
        exact_outputs=outputs,
        exact_writer="DRIVER",
    )


def _commit_plain(root: Path, contract, output_bytes: dict[str, bytes]):
    launch = _launch(contract)
    record_work_unit_inputs(
        root, root.parent, contract, launch, run_id=RUN_ID,
    )
    for name, raw in output_bytes.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    unit = record_work_unit_artifacts(
        root, root.parent, contract, launch,
        run_id=RUN_ID, actor="DRIVER",
    )
    assert unit["semantic_status"] == "ACTIVE"
    return launch


def _bind_inputs(
    candidate: str,
    ordinal: int,
    *,
    other_decisions: tuple[str, ...] = (),
) -> tuple[str, ...]:
    return (
        "severity_adjudication_work_manifest.json",
        "severity_adjudication_work_plan.json",
        f"verify_{candidate}.severity_adjudication_proposal.json",
        f"severity_adjudication_context.{ordinal:04d}.json",
        f"severity_adjudication_prompt.{ordinal:04d}.md",
        f"severity_adjudication_tool_policy.{ordinal:04d}.json",
        f"severity_adjudication_launch_intent.{ordinal:04d}.json",
        f"severity_adjudication_worker_run.{ordinal:04d}.json",
        *(f"verify_{other}.severity_decision.json" for other in other_decisions),
    )


def _bind_outputs(candidate: str) -> tuple[str, ...]:
    return (
        f"verify_{candidate}.severity_adjudication_receipt.json",
        f"verify_{candidate}.severity_decision.json",
        "severity_decision_ledger.shadow.json",
    )


def _commit_bind(
    root: Path,
    candidate: str,
    ordinal: int,
    *,
    other_decisions: tuple[str, ...] = (),
    after_write=None,
):
    inputs = _bind_inputs(
        candidate, ordinal, other_decisions=other_decisions,
    )
    outputs = _bind_outputs(candidate)
    for name in inputs:
        path = root / name
        if not path.exists():
            path.write_bytes((name + "\n").encode())
    contract = _resolve(
        f"bind.{ordinal:04d}.{candidate.casefold()}", inputs, outputs,
    )
    launch = _launch(contract)
    if ordinal == 2:
        ledger = read_artifact_ledger(root)
        source_key = (
            "sc/core/evm/codex/severity_adjudication_shadow/"
            "source_decisions.verifier-unit-0001"
        )
        source_record = ledger["work_units"][source_key]["artifacts"][
            "scratchpad:verify_H-A.severity_decision.json"
        ]
        current = ledger["artifact_bindings"][source_record["identity"]]
        assert current["owner_key"].endswith("/bind.0001.h-a")
        assert AL.registered_projection_handoff(
            source_key, current["owner_key"], source_record["identity"]
        )
        context = AL._ArtifactValidationContext(root, root.parent, ledger=ledger)
        AL._replay_stored_completed_driver_successor_authority(
            root,
            root.parent,
            ledger,
            ledger["work_units"][current["owner_key"]],
            _validation_context=context,
        )
        assert AL._registered_successor_bundle_member_authority_view(
            root,
            root.parent,
            ledger,
            source_record,
            identity=source_record["identity"],
            expected_record=source_record,
            _validation_context=context,
        )
        assert context.finish() == []
    postimages = {
        f"scratchpad:{outputs[0]}": (
            f'{{"candidate":"{candidate}","ordinal":{ordinal}}}\n'.encode()
        ),
        f"scratchpad:{outputs[1]}": (
            f'{{"candidate":"{candidate}","bound":true}}\n'.encode()
        ),
        "scratchpad:severity_decision_ledger.shadow.json": (
            json.dumps(
                {"schema": "test-ledger", "bound_through": ordinal},
                sort_keys=True,
                separators=(",", ":"),
            ).encode() + b"\n"
        ),
    }
    plan = plan_driver_successor_transaction(
        root, root.parent, contract, launch,
        run_id=RUN_ID, planned_output_bytes=postimages,
    )
    record_work_unit_inputs(
        root, root.parent, contract, launch,
        run_id=RUN_ID, successor_plan=plan,
    )
    for transition in plan.transitions:
        begin_driver_successor_step(
            root, root.parent, contract, launch,
            run_id=RUN_ID, ordinal=transition.ordinal,
        )
        identity = transition.artifact_identity
        assert identity.startswith("scratchpad:")
        (root / identity.split(":", 1)[1]).write_bytes(postimages[identity])
        if after_write is not None:
            after_write(root, transition.ordinal)
        complete_driver_successor_step(
            root, root.parent, contract, launch,
            run_id=RUN_ID, ordinal=transition.ordinal,
        )
    unit = record_work_unit_artifacts(
        root, root.parent, contract, launch,
        run_id=RUN_ID, actor="DRIVER",
    )
    assert unit["semantic_status"] == "ACTIVE"
    return contract, launch


def _commit_owned_planning(root: Path):
    capture = _resolve(
        "planning_inputs",
        (INITIAL,),
        CAPTURE_INPUTS,
    )
    capture_launch = _commit_plain(
        root,
        capture,
        {name: (name + "\n").encode() for name in CAPTURE_INPUTS},
    )
    planning = _resolve(
        "planning",
        (INITIAL, *CAPTURE_INPUTS),
        (
            "severity_adjudication_work_manifest.json",
            "severity_adjudication_work_plan.json",
        ),
    )
    planning_launch = _commit_plain(
        root,
        planning,
        {
            "severity_adjudication_work_manifest.json": b"{}\n",
            "severity_adjudication_work_plan.json": b"{}\n",
        },
    )
    return capture, capture_launch, planning, planning_launch


def _case(tmp_path: Path, *, bind_b_after_write=None):
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
        tuple(f"verify_{candidate}.severity_decision.json" for candidate in CANDIDATES),
    )
    source_bytes = {
        f"verify_{candidate}.severity_decision.json": (
            f'{{"candidate":"{candidate}","initial":true}}\n'.encode()
        )
        for candidate in CANDIDATES
    }
    source_launch = _commit_plain(root, source, source_bytes)
    aggregate = _resolve(
        "source_aggregate",
        (*QUEUE, *source_bytes),
        ("severity_decision_ledger.shadow.json", INITIAL),
    )
    initial = b'{"schema":"test-ledger","bound_through":0}\n'
    aggregate_launch = _commit_plain(
        root, aggregate,
        {"severity_decision_ledger.shadow.json": initial, INITIAL: initial},
    )
    bind_a = _commit_bind(root, CANDIDATES[0], 1)
    bind_b = _commit_bind(
        root, CANDIDATES[1], 2, after_write=bind_b_after_write,
    )
    return root, source, source_launch, aggregate, aggregate_launch, bind_a, bind_b


def _three_candidate_case(
    tmp_path: Path,
    *,
    after_bind_a=None,
    bind_a_after_write=None,
):
    root = tmp_path / ".scratchpad"
    root.mkdir()
    for name in QUEUE:
        (root / name).write_bytes((name + "\n").encode())
    verifier_inputs = tuple(
        f"verify_{candidate}{suffix}"
        for candidate in THREE_CANDIDATES
        for suffix in (".md", ".severity_proposal.json", ".receipt.json")
    )
    for name in verifier_inputs:
        (root / name).write_bytes((name + "\n").encode())
    source = _resolve(
        "source_decisions.verifier-unit-0001",
        (*QUEUE, *verifier_inputs),
        tuple(
            f"verify_{candidate}.severity_decision.json"
            for candidate in THREE_CANDIDATES
        ),
    )
    source_launch = _commit_plain(
        root,
        source,
        {
            f"verify_{candidate}.severity_decision.json": (
                f'{{"candidate":"{candidate}","initial":true}}\n'.encode()
            )
            for candidate in THREE_CANDIDATES
        },
    )
    aggregate = _resolve(
        "source_aggregate",
        (
            *QUEUE,
            *(
                f"verify_{candidate}.severity_decision.json"
                for candidate in THREE_CANDIDATES
            ),
        ),
        ("severity_decision_ledger.shadow.json", INITIAL),
    )
    initial = b'{"schema":"test-ledger","bound_through":0}\n'
    aggregate_launch = _commit_plain(
        root,
        aggregate,
        {"severity_decision_ledger.shadow.json": initial, INITIAL: initial},
    )
    planning = _commit_owned_planning(root)
    binds = []
    for ordinal, candidate in enumerate(THREE_CANDIDATES, start=1):
        binds.append(
            _commit_bind(
                root,
                candidate,
                ordinal,
                other_decisions=tuple(
                    other for other in THREE_CANDIDATES
                    if other != candidate
                ),
                after_write=(
                    bind_a_after_write if ordinal == 1 else None
                ),
            )
        )
        if ordinal == 1 and after_bind_a is not None:
            after_bind_a(root)
    return (
        root, source, source_launch, aggregate, aggregate_launch,
        planning, tuple(binds),
    )


def test_three_candidate_other_decision_inputs_preserve_exact_ordinal_chain(
    tmp_path: Path,
):
    root, _source, _sl, aggregate, _al, planning, binds = _three_candidate_case(
        tmp_path
    )
    ledger = read_artifact_ledger(root)
    bind_a, bind_b, bind_c = (contract for contract, _launch in binds)
    canonical = "scratchpad:severity_decision_ledger.shadow.json"
    bind_a_artifact = ledger["work_units"][bind_a.key]["artifacts"][
        canonical
    ]
    context = AL._ArtifactValidationContext(root, tmp_path, ledger=ledger)
    chain = AL._registered_successor_bundle_member_authority_view(
        root,
        tmp_path,
        ledger,
        bind_a_artifact,
        identity=canonical,
        expected_record=bind_a_artifact,
        _validation_context=context,
    )
    assert [row["successor_owner_key"] for row in chain] == [
        bind_b.key,
        bind_c.key,
    ]
    assert context.finish() == []
    for contract, launch in binds:
        assert validate_historical_driver_successor_transaction(
            root, tmp_path, contract, launch, run_id=RUN_ID,
        ) == []

    authority = ledger["work_units"][bind_c.key][
        "successor_consumption_authority"
    ]
    bundles = {
        row["producer_work_unit_key"]: row
        for row in authority["producer_bundles"]
    }
    a_bundle = bundles[bind_a.key]
    assert a_bundle["consumed_input_identities"] == [
        "scratchpad:verify_H-A.severity_decision.json"
    ]
    assert a_bundle["successor_output_identities"] == []
    assert list(a_bundle["registered_successor_sibling_chains"]) == [
        "scratchpad:severity_decision_ledger.shadow.json"
    ]
    assert a_bundle["registered_successor_sibling_chains"][
        "scratchpad:severity_decision_ledger.shadow.json"
    ][-1]["successor_owner_key"] == bind_b.key
    assert not AL.registered_projection_handoff(
        bind_a.key,
        bind_c.key,
        "scratchpad:severity_decision_ledger.shadow.json",
    )
    assert AL.registered_projection_handoff(
        bind_b.key,
        bind_c.key,
        "scratchpad:severity_decision_ledger.shadow.json",
    )
    bind_c_launch = binds[-1][1]
    bind_c_unit = ledger["work_units"][bind_c.key]
    assert validate_driver_successor_transaction(
        root,
        tmp_path,
        bind_c,
        bind_c_launch,
        run_id=RUN_ID,
        require_complete=True,
    ) == []
    assert validate_driver_successor_transaction(
        root,
        tmp_path,
        bind_c,
        bind_c_launch,
        run_id=RUN_ID,
        require_complete=False,
    ) == []
    assert "preexecution_authority" not in bind_c_unit
    assert validate_work_unit_inputs(
        root,
        tmp_path,
        bind_c,
        bind_c_launch,
        run_id=RUN_ID,
    ) == []
    assert validate_work_unit_artifacts(
        root,
        tmp_path,
        bind_c,
        bind_c_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []
    assert validate_driver_successor_transaction(
        root,
        tmp_path,
        bind_c,
        bind_c_launch,
        run_id=RUN_ID + "-foreign",
        require_complete=True,
    )
    assert validate_driver_successor_transaction(
        root,
        tmp_path,
        replace(
            bind_c,
            outputs=(
                replace(
                    bind_c.outputs[0],
                    minimum_gate=(
                        bind_c.outputs[0].minimum_gate + "_FORGED"
                    ),
                ),
                *bind_c.outputs[1:],
            ),
        ),
        bind_c_launch,
        run_id=RUN_ID,
        require_complete=True,
    )
    assert validate_driver_successor_transaction(
        root,
        tmp_path,
        bind_c,
        replace(bind_c_launch, model="forged-model"),
        run_id=RUN_ID,
        require_complete=True,
    )
    for contract, launch in (planning[:2], planning[2:]):
        assert validate_work_unit_inputs(
            root, tmp_path, contract, launch, run_id=RUN_ID,
        ) == []
        assert validate_work_unit_artifacts(
            root, tmp_path, contract, launch, run_id=RUN_ID,
        ) == []
    ledger = read_artifact_ledger(root)
    snapshot_identity = f"scratchpad:{INITIAL}"
    snapshot = ledger["artifact_bindings"][snapshot_identity]
    assert snapshot["owner_key"] == aggregate.key
    assert snapshot["sha256"] == ledger["work_units"][aggregate.key][
        "artifacts"
    ][snapshot_identity]["sha256"]


def _assert_current_bind_rejected(
    root: Path, project: Path, contract, launch,
) -> None:
    for require_complete in (False, True):
        assert validate_driver_successor_transaction(
            root,
            project,
            contract,
            launch,
            run_id=RUN_ID,
            require_complete=require_complete,
        )
    assert validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )


def test_committed_extension_rejects_nonexact_history_edges(
    tmp_path: Path,
):
    root, *_prefix, binds = _three_candidate_case(tmp_path)
    bind_a, bind_b, bind_c = (contract for contract, _launch in binds)
    bind_c_launch = binds[-1][1]
    original = json.loads((root / AL.LEDGER_NAME).read_text())
    identity = "scratchpad:severity_decision_ledger.shadow.json"
    for mutation in ("skipped", "foreign", "extra"):
        ledger = json.loads(json.dumps(original))
        history = ledger["artifact_bindings"][identity]["history"]
        rows = {row["owner_key"]: row for row in history}
        assert rows[bind_a.key]["superseded_by_owner_key"] == bind_b.key
        assert rows[bind_b.key]["superseded_by_owner_key"] == bind_c.key
        if mutation == "skipped":
            history.remove(rows[bind_b.key])
            rows[bind_a.key]["superseded_by_owner_key"] = bind_c.key
        elif mutation == "foreign":
            rows[bind_b.key]["superseded_by_owner_key"] = (
                bind_c.key + ".foreign"
            )
        else:
            extra = dict(rows[bind_b.key])
            extra["owner_key"] = bind_b.key + ".extra"
            extra["superseded_by_owner_key"] = bind_c.key
            rows[bind_b.key]["superseded_by_owner_key"] = extra["owner_key"]
            history.append(extra)
        write_artifact_ledger(root, ledger)
        _assert_current_bind_rejected(
            root, tmp_path, bind_c, bind_c_launch,
        )
    write_artifact_ledger(root, original)


def test_committed_extension_rejects_current_authority_corruption(
    tmp_path: Path,
):
    root, *_prefix, binds = _three_candidate_case(tmp_path)
    bind_c, bind_c_launch = binds[-1]
    original = json.loads((root / AL.LEDGER_NAME).read_text())
    original_unit = original["work_units"][bind_c.key]
    event_digest = original_unit["successor_progress_authority"]["events"][-1][
        "event_digest"
    ]
    event_path = (
        root
        / AL._DRIVER_SUCCESSOR_PROGRESS_EVENT_CAS_DIRECTORY
        / f"{event_digest}.json"
    )
    event_bytes = event_path.read_bytes()
    for mutation in ("progress_head", "progress_event_cas", "commit_binding"):
        ledger = json.loads(json.dumps(original))
        write_artifact_ledger(root, ledger)
        if not event_path.exists():
            event_path.write_bytes(event_bytes)
            # Recreated immutable CAS must restore acceptance before this
            # iteration tests a different corruption boundary.
            assert validate_driver_successor_transaction(
                root, tmp_path, bind_c, bind_c_launch,
                run_id=RUN_ID, require_complete=True,
            ) == []
        unit = ledger["work_units"][bind_c.key]
        if mutation == "progress_head":
            unit["successor_progress_authority"]["head_event_digest"] = (
                "0" * 64
            )
            write_artifact_ledger(root, ledger)
        elif mutation == "progress_event_cas":
            event_path.unlink()
        else:
            unit["commit_authority"][
                "successor_consumption_authority_digest"
            ] = "0" * 64
            write_artifact_ledger(root, ledger)
        _assert_current_bind_rejected(
            root, tmp_path, bind_c, bind_c_launch,
        )
    write_artifact_ledger(root, original)
    if not event_path.exists():
        event_path.write_bytes(event_bytes)


def test_read_only_grouped_input_rejects_current_byte_tamper(tmp_path: Path):
    def tamper(root: Path) -> None:
        (root / "verify_H-C.severity_decision.json").write_bytes(
            b'{"forged":true}\n'
        )

    with pytest.raises(ArtifactLedgerError):
        _three_candidate_case(tmp_path, after_bind_a=tamper)


def test_retained_planning_snapshot_rejects_byte_tamper(tmp_path: Path):
    root, _source, _sl, _aggregate, _al, planning, _binds = (
        _three_candidate_case(tmp_path)
    )
    (root / INITIAL).write_bytes(b'{"forged":true}\n')
    for contract, launch in (planning[:2], planning[2:]):
        assert validate_work_unit_inputs(
            root, tmp_path, contract, launch, run_id=RUN_ID,
        )


def test_retained_planning_snapshot_replays_active_published_successor(
    tmp_path: Path,
):
    observed = []

    def validate_during_publish(root: Path, ordinal: int) -> None:
        if ordinal != 3:
            return
        ledger = read_artifact_ledger(root)
        planning = [
            unit for key, unit in ledger["work_units"].items()
            if key.endswith("/severity_adjudication_shadow/planning")
        ]
        assert len(planning) == 1
        aggregate = [
            unit for key, unit in ledger["work_units"].items()
            if key.endswith("/severity_adjudication_shadow/source_aggregate")
        ]
        assert len(aggregate) == 1
        canonical = "scratchpad:severity_decision_ledger.shadow.json"
        historical = aggregate[0]["artifacts"][canonical]
        context = AL._ArtifactValidationContext(root, tmp_path, ledger=ledger)
        live = AL._semantic_artifact_state(root, tmp_path, canonical)
        reasons = []
        assert AL._registered_active_successor_bundle_member_authority(
            root,
            tmp_path,
            context.ledger,
            historical,
            identity=canonical,
            expected_record={
                "sha256": historical["sha256"],
                "size": historical["size"],
            },
            live_state=live,
            _validation_context=context,
            _failure_reasons=reasons,
        ), reasons
        assert context.finish() == []
        context = AL._ArtifactValidationContext(root, tmp_path, ledger=ledger)
        snapshot_identity = f"scratchpad:{INITIAL}"
        snapshot_binding = context.ledger["artifact_bindings"][
            snapshot_identity
        ]
        aggregate_unit = context.ledger["work_units"][
            snapshot_binding["owner_key"]
        ]
        exemptions = AL._authenticated_bundle_live_byte_exemptions(
            root,
            tmp_path,
            context.ledger,
            snapshot_binding,
            aggregate_unit,
            verified_identity="",
            _validation_context=context,
        )
        assert canonical in exemptions, exemptions
        assert AL._replay_output_commit_authority(
            root,
            tmp_path,
            aggregate_unit,
            require_live_bytes=True,
            live_byte_exempt_identities=exemptions,
            _validation_context=context,
        ) == []
        current = AL._input_binding_record(
            root,
            tmp_path,
            snapshot_identity,
            "IMMUTABLE",
            context.ledger,
            _validation_context=context,
        )
        assert current["status"] == "ACTIVE", current
        assert context.finish() == []
        contract, launch = AL._stored_successor_authority_pair(planning[0])
        assert validate_work_unit_inputs(
            root, tmp_path, contract, launch, run_id=RUN_ID,
        ) == []
        observed.append(ordinal)

    _three_candidate_case(
        tmp_path,
        bind_a_after_write=validate_during_publish,
    )
    assert observed == [3]


@pytest.mark.parametrize("target_ordinal", (1, 3))
def test_explicit_read_only_active_replay_accepts_only_projection_lag(
    tmp_path: Path,
    target_ordinal: int,
):
    observed = []

    def validate_lagged_projection(root: Path, ordinal: int) -> None:
        if ordinal != target_ordinal:
            return
        ledger = read_artifact_ledger(root)
        rows = [
            unit for key, unit in ledger["work_units"].items()
            if key.endswith("/severity_adjudication_shadow/bind.0001.h-a")
        ]
        assert len(rows) == 1
        contract, launch = AL._stored_successor_authority_pair(rows[0])
        projection = root / AL._DRIVER_SUCCESSOR_PROGRESS_NAME
        projection.write_text(
            json.dumps(
                {
                    "schema": AL._DRIVER_SUCCESSOR_PROGRESS_SCHEMA,
                    "transactions": {},
                },
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
        )
        frozen = (
            projection.read_bytes(),
            projection.stat().st_dev,
            projection.stat().st_ino,
            projection.stat().st_mtime_ns,
        )
        ledger_path = root / AL.LEDGER_NAME
        frozen_ledger = (
            ledger_path.read_bytes(),
            ledger_path.stat().st_dev,
            ledger_path.stat().st_ino,
            ledger_path.stat().st_mtime_ns,
        )
        assert validate_driver_successor_transaction(
            root,
            tmp_path,
            contract,
            launch,
            run_id=RUN_ID,
            require_complete=False,
        )
        assert validate_driver_successor_transaction(
            root,
            tmp_path,
            contract,
            launch,
            run_id=RUN_ID,
            require_complete=False,
            allow_reconstructible_progress_projection_lag=True,
        ) == []
        planning = [
            unit for key, unit in ledger["work_units"].items()
            if key.endswith("/severity_adjudication_shadow/planning")
        ]
        assert len(planning) == 1
        planning_contract, planning_launch = (
            AL._stored_successor_authority_pair(planning[0])
        )
        assert validate_work_unit_inputs(
            root,
            tmp_path,
            planning_contract,
            planning_launch,
            run_id=RUN_ID,
        ) == []
        for invalid_policy in (1, "true", None, {}):
            assert validate_driver_successor_transaction(
                root,
                tmp_path,
                contract,
                launch,
                run_id=RUN_ID,
                require_complete=False,
                allow_reconstructible_progress_projection_lag=(
                    invalid_policy
                ),
            )
        assert (
            projection.read_bytes(),
            projection.stat().st_dev,
            projection.stat().st_ino,
            projection.stat().st_mtime_ns,
        ) == frozen
        assert (
            ledger_path.read_bytes(),
            ledger_path.stat().st_dev,
            ledger_path.stat().st_ino,
            ledger_path.stat().st_mtime_ns,
        ) == frozen_ledger
        observed.append(ordinal)

    _three_candidate_case(
        tmp_path,
        bind_a_after_write=validate_lagged_projection,
    )
    assert observed == [target_ordinal]


@pytest.mark.parametrize("tamper", ("progress_authority", "event_cas"))
def test_explicit_projection_lag_mode_still_requires_immutable_progress(
    tmp_path: Path,
    tamper: str,
):
    observed = []

    def corrupt_immutable_progress(root: Path, ordinal: int) -> None:
        if ordinal != 1:
            return
        ledger = read_artifact_ledger(root)
        rows = [
            unit for key, unit in ledger["work_units"].items()
            if key.endswith("/severity_adjudication_shadow/bind.0001.h-a")
        ]
        assert len(rows) == 1
        unit = rows[0]
        contract, launch = AL._stored_successor_authority_pair(unit)
        if tamper == "progress_authority":
            unit["successor_progress_authority"]["head_event_digest"] = (
                "0" * 64
            )
            write_artifact_ledger(root, ledger)
        else:
            event_digest = unit["successor_progress_authority"]["events"][-1][
                "event_digest"
            ]
            (
                root
                / AL._DRIVER_SUCCESSOR_PROGRESS_EVENT_CAS_DIRECTORY
                / f"{event_digest}.json"
            ).unlink()
        assert validate_driver_successor_transaction(
            root,
            tmp_path,
            contract,
            launch,
            run_id=RUN_ID,
            require_complete=False,
            allow_reconstructible_progress_projection_lag=True,
        )
        observed.append(ordinal)
        raise RuntimeError("stop after immutable-progress tamper")

    with pytest.raises(RuntimeError, match="immutable-progress tamper"):
        _three_candidate_case(
            tmp_path,
            bind_a_after_write=corrupt_immutable_progress,
        )
    assert observed == [1]



def test_two_candidate_grouped_history_and_aggregate_prefix_replay(tmp_path: Path):
    root, source, source_launch, aggregate, aggregate_launch, bind_a, bind_b = _case(tmp_path)

    assert validate_historical_driver_successor_transaction(
        root, tmp_path, *bind_a, run_id=RUN_ID,
    ) == []
    assert validate_historical_driver_successor_transaction(
        root, tmp_path, *bind_b, run_id=RUN_ID,
    ) == []
    ledger = read_artifact_ledger(root)
    source_unit = ledger["work_units"][source.key]
    source_a = source_unit["artifacts"]["scratchpad:verify_H-A.severity_decision.json"]
    context = AL._ArtifactValidationContext(root, tmp_path, ledger=ledger)
    chain = AL._registered_successor_bundle_member_authority_view(
        root, tmp_path, ledger, source_a,
        identity=source_a["identity"], expected_record=source_a,
        _validation_context=context,
    )
    assert len(chain) == 1
    assert chain[0]["successor_owner_key"] == bind_a[0].key
    aggregate_unit = ledger["work_units"][aggregate.key]
    aggregate_record = aggregate_unit["artifacts"][
        "scratchpad:severity_decision_ledger.shadow.json"
    ]
    aggregate_chain = AL._registered_successor_bundle_member_authority_view(
        root, tmp_path, ledger, aggregate_record,
        identity=aggregate_record["identity"], expected_record=aggregate_record,
        _validation_context=context,
    )
    assert [row["successor_owner_key"] for row in aggregate_chain] == [
        bind_a[0].key, bind_b[0].key,
    ]
    assert context.finish() == []
    assert (root / INITIAL).read_bytes() == (
        b'{"schema":"test-ledger","bound_through":0}\n'
    )


@pytest.mark.parametrize("kind", ("authority_cas", "progress_cas"))
def test_missing_intermediate_immutable_cas_is_denied(tmp_path: Path, kind: str):
    root, _source, _sl, _aggregate, _al, bind_a, _bind_b = _case(tmp_path)
    unit = read_artifact_ledger(root)["work_units"][bind_a[0].key]
    if kind == "authority_cas":
        digest = unit["successor_consumption_authority"]["authority_digest"]
        path = root / AL._DRIVER_SUCCESSOR_AUTHORITY_CAS_DIRECTORY / f"{digest}.json"
    else:
        digest = unit["successor_progress_authority"]["events"][-1]["event_digest"]
        path = root / AL._DRIVER_SUCCESSOR_PROGRESS_EVENT_CAS_DIRECTORY / f"{digest}.json"
    path.unlink()

    assert validate_historical_driver_successor_transaction(
        root, tmp_path, *bind_a, run_id=RUN_ID,
    )


def test_mutable_progress_projection_lag_does_not_override_immutable_history(
    tmp_path: Path,
):
    root, _source, _sl, _aggregate, _al, bind_a, _bind_b = _case(tmp_path)
    unit = read_artifact_ledger(root)["work_units"][bind_a[0].key]
    authority_digest = unit["successor_consumption_authority"][
        "authority_digest"
    ]
    progress = root / AL._DRIVER_SUCCESSOR_PROGRESS_NAME
    payload = json.loads(progress.read_text())
    transaction = payload["transactions"][authority_digest]
    transaction["events"] = transaction["events"][:-1]
    progress.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    lagged = progress.read_bytes()
    lagged_mtime = progress.stat().st_mtime_ns

    assert validate_historical_driver_successor_transaction(
        root, tmp_path, *bind_a, run_id=RUN_ID,
    ) == []
    assert progress.read_bytes() == lagged
    assert progress.stat().st_mtime_ns == lagged_mtime


def test_tampered_ledger_bound_progress_authority_is_denied(tmp_path: Path):
    root, _source, _sl, _aggregate, _al, bind_a, _bind_b = _case(tmp_path)
    ledger = read_artifact_ledger(root)
    progress = ledger["work_units"][bind_a[0].key][
        "successor_progress_authority"
    ]
    assert ledger["work_units"][bind_a[0].key][
        "execution_state"
    ] == "OUTPUT_COMMITTED"
    progress["events"] = progress["events"][:-1]
    write_artifact_ledger(root, ledger)

    assert validate_historical_driver_successor_transaction(
        root, tmp_path, *bind_a, run_id=RUN_ID,
    )


def test_tampered_bind_prefix_history_is_denied(tmp_path: Path):
    root, _source, _sl, _aggregate, _al, bind_a, _bind_b = _case(tmp_path)
    ledger = read_artifact_ledger(root)
    identity = "scratchpad:severity_decision_ledger.shadow.json"
    history = ledger["artifact_bindings"][identity]["history"]
    assert len(history) >= 2
    assert history[-1]["owner_key"] == bind_a[0].key
    history[-1]["superseded_by_owner_key"] = bind_a[0].key + ".forged"
    write_artifact_ledger(root, ledger)

    assert validate_historical_driver_successor_transaction(
        root, tmp_path, *bind_a, run_id=RUN_ID,
    )


def test_tampered_original_aggregate_history_edge_is_denied(tmp_path: Path):
    root, _source, _sl, aggregate, _al, bind_a, _bind_b = _case(tmp_path)
    ledger = read_artifact_ledger(root)
    identity = "scratchpad:severity_decision_ledger.shadow.json"
    history = ledger["artifact_bindings"][identity]["history"]
    assert history[0]["owner_key"] == aggregate.key
    history[0]["superseded_by_owner_key"] = bind_a[0].key + ".forged"
    write_artifact_ledger(root, ledger)
    ledger = read_artifact_ledger(root)
    original = ledger["work_units"][aggregate.key]["artifacts"][identity]
    context = AL._ArtifactValidationContext(root, tmp_path, ledger=ledger)

    assert AL._registered_successor_bundle_member_authority_view(
        root,
        tmp_path,
        ledger,
        original,
        identity=identity,
        expected_record=original,
        _validation_context=context,
    ) == ()
    assert context.finish() == []


def test_registered_handoff_rejects_skipped_aggregate_ordinal():
    prefix = "sc/core/evm/codex/severity_adjudication_shadow/"
    assert not AL.registered_projection_handoff(
        prefix + "source_aggregate",
        prefix + "bind.0002.h-b",
        "scratchpad:severity_decision_ledger.shadow.json",
    )


def test_registered_read_only_consumption_is_not_a_replacement_handoff():
    prefix = "sc/core/evm/codex/severity_adjudication_shadow/"
    source = prefix + "source_decisions.verifier-unit-0001"
    bind_a = prefix + "bind.0001.h-a"
    bind_b = prefix + "bind.0002.h-b"
    bind_c = prefix + "bind.0003.h-c"
    decision_a = "scratchpad:verify_H-A.severity_decision.json"
    decision_b = "scratchpad:verify_H-B.severity_decision.json"

    assert registered_read_only_consumption(source, bind_a, decision_b)
    assert registered_read_only_consumption(bind_a, bind_c, decision_a)
    assert not registered_read_only_consumption(source, bind_a, decision_a)
    assert not registered_read_only_consumption(bind_b, bind_a, decision_b)
    assert not registered_read_only_consumption(
        bind_a,
        bind_c,
        "scratchpad:severity_decision_ledger.shadow.json",
    )
    assert not registered_read_only_consumption(
        bind_a,
        bind_c,
        "scratchpad:verify_H-A.severity_adjudication_receipt.json",
    )
    assert not AL.registered_projection_handoff(
        bind_a,
        bind_c,
        decision_a,
    )


@pytest.mark.parametrize(
    "target",
    (
        "verify_H-A.severity_adjudication_receipt.json",
        "severity_decision_ledger.shadow.json",
    ),
)
def test_partial_replay_does_not_exempt_unrelated_or_wrong_postimage(
    tmp_path: Path, target: str,
):
    def tamper(root: Path, ordinal: int) -> None:
        if ordinal == 3:
            (root / target).write_bytes(b'{"forged":true}\n')

    with pytest.raises(ArtifactLedgerError):
        _case(tmp_path, bind_b_after_write=tamper)
