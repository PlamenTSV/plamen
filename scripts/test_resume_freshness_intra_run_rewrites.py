"""Resume freshness must gate on the PROPERTY, never on a representation.

Reconstructs the shape of a real paused run (recon ... invariants completed,
depth interrupted by a provider rate limit) whose resume was lost because the
freshness scan mistook the driver's own by-design rewrites for external drift:

* recon workers bound ``contract_inventory.md`` from the recon prepass; the
  later same-run ``recon/canonical_merge`` step rewrote it (registered later
  producer -> CONTENT_HASH_CHANGED + PRODUCER_AUTHORITY_CHANGED);
* breadth/rescan workers bound driver control files (``skill_dispatch.json``,
  ``rescan_manifest.md``) that the driver rewrote mid-run without a ledger
  producer (unregistered -> CONTENT_HASH_CHANGED);
* a completed work unit bound ``_v2_checkpoint.json`` as an exact
  content-hashed input, which changes at every phase boundary and pause;
* the interrupted depth phase had a work unit bound with not-yet-produced
  inputs (MISSING_AT_BINDING).

None of those is external drift.  Only a completed phase's own committed
output being modified after completion (positive control below) may
invalidate that phase and its TYPED descendants.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import plamen_driver as D
from artifact_ledger import (
    RUN_BINDING_PROJECTION_SCHEMA,
    _input_set_digest,
    arm_semantic_mutation,
    classify_resume_semantic_drift,
    detect_committed_output_tamper,
    detect_resume_semantic_drift,
    detect_semantic_input_drift,
    finalize_semantic_mutation,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    run_binding_projection_bytes,
    validate_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


RUN_ID = "af554720-9577-431b-ad68-9531cae9fe51"
OTHER_RUN_ID = "0f554720-9577-4123-8123-9531cae9fe51"
BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
SNAPSHOT = {
    "schema": "plamen.audit-input-snapshot.v1",
    "components": {
        "source_scope": {"digest": "a" * 64, "file_count": 7},
        "audit_config": {"digest": "b" * 64, "field_count": 11},
    },
    "snapshot_digest": "c" * 64,
}


def _phase(name: str) -> D.Phase:
    return D.Phase(
        name, ["Section"], [f"{name}.md"],
        base_timeout_s=60, min_artifact_bytes=1,
    )


def _key(phase: str, unit: str) -> str:
    return "/".join((*BASE.values(), phase, unit))


def _contract(
    phase: str,
    unit: str,
    *,
    output: str,
    immutable: tuple[str, ...] = (),
    bounded: tuple[str, ...] = (),
    write_mode: str = "CREATE",
) -> PhaseIOContract:
    key = _key(phase, unit)
    return PhaseIOContract(
        **BASE,
        phase=phase,
        work_unit_id=unit,
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=output,
            owner_key=key,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode=write_mode,
        ),),
        immutable_inputs=tuple(f"scratchpad:{name}" for name in immutable),
        bounded_lookup_inputs=tuple(f"scratchpad:{name}" for name in bounded),
        model_invoked=False,
    )


def _launch(contract: PhaseIOContract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        **BASE,
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )


def _bind(sp: Path, contract: PhaseIOContract, *, run_id: str = RUN_ID) -> None:
    """Pre-execution input receipt only (a work unit that never ran)."""

    record_work_unit_inputs(sp, sp.parent, contract, _launch(contract), run_id=run_id)


def _commit(
    sp: Path, contract: PhaseIOContract, raw: bytes, *, run_id: str = RUN_ID,
) -> None:
    """Bind inputs, write the output bytes, commit the output record."""

    launch = _launch(contract)
    output = sp / contract.outputs[0].path
    if output.is_file() and contract.outputs[0].write_mode == "CREATE":
        output.unlink()
    record_work_unit_inputs(sp, sp.parent, contract, launch, run_id=run_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    record_work_unit_artifacts(sp, sp.parent, contract, launch, run_id=run_id)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _run47_shape(tmp_path: Path):
    """Completed recon/breadth/rescan/invariants; depth interrupted."""

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    phases = [_phase(name) for name in (
        "recon", "breadth", "rescan", "invariants", "depth",
    )]
    checkpoint = D.Checkpoint(
        completed=["recon", "breadth", "rescan", "invariants"],
        run_id=RUN_ID,
        audit_snapshot=json.loads(json.dumps(SNAPSHOT)),
        rate_limited_at="depth",
    )
    for phase in phases:
        (sp / phase.expected_artifacts[0]).write_text(
            f"{phase.name}\n", encoding="utf-8"
        )

    # recon: prepass publishes contract_inventory.md, worker r1 consumes it
    # (bounded lookup), canonical_merge REPLACEs it later in the same phase.
    prepass = _contract("recon", "prepass", output="contract_inventory.md")
    _commit(sp, prepass, b"# prepass inventory\n")
    r1 = _contract(
        "recon", "worker.r1", output="recon_r1.md",
        bounded=("contract_inventory.md",),
    )
    _commit(sp, r1, b"# r1\n")
    merge = _contract(
        "recon", "canonical_merge", output="contract_inventory.md",
        immutable=("recon_r1.md",), write_mode="REPLACE",
    )
    _commit(sp, merge, b"# canonical inventory (merged)\n")

    # breadth: worker b1 binds the merged inventory plus an unregistered
    # driver control file the driver rewrites later.
    (sp / "skill_dispatch.json").write_text('{"dispatch": 1}\n', encoding="utf-8")
    b1 = _contract(
        "breadth", "worker.b1", output="analysis_b1.md",
        immutable=("contract_inventory.md", "skill_dispatch.json"),
    )
    _commit(sp, b1, b"# analysis b1\n")

    # rescan: worker pc1 binds b1's output plus an unregistered manifest the
    # driver rewrites within the rescan phase.
    (sp / "rescan_manifest.md").write_text("# manifest v1\n", encoding="utf-8")
    pc1 = _contract(
        "rescan", "worker.pc1", output="analysis_rescan_1.md",
        immutable=("rescan_manifest.md", "analysis_b1.md"),
    )
    _commit(sp, pc1, b"# rescan 1\n")
    (sp / "rescan_manifest.md").write_text(
        "# manifest v2 (driver repair)\n", encoding="utf-8"
    )

    # invariants: a driver step binds the run checkpoint as an exact input.
    checkpoint.completed = ["recon", "breadth", "rescan"]
    checkpoint.save(sp)
    pre = _contract(
        "invariants", "semantic_invariants.pre",
        output="semantic_invariant_worklist.json",
        immutable=("_v2_checkpoint.json",),
    )
    _commit(sp, pre, b'{"worklist": []}\n')
    checkpoint.completed = ["recon", "breadth", "rescan", "invariants"]
    checkpoint.save(sp)

    # depth (interrupted): the driver rewrote skill_dispatch.json, then bound
    # a DA worker whose inputs had not been produced yet, then hit the rate
    # limit before anything in depth committed.
    (sp / "skill_dispatch.json").write_text(
        '{"dispatch": 2, "da_iter2": true}\n', encoding="utf-8"
    )
    da = _contract(
        "depth", "worker.depth-da-iter2", output="depth_da_iter2_findings.md",
        immutable=("analysis_b1.md", "depth_token_flow_findings.md"),
    )
    _bind(sp, da)
    checkpoint.rate_limited_at = "depth"
    checkpoint.save(sp)
    return sp, phases, checkpoint, {
        "prepass": prepass, "r1": r1, "merge": merge, "b1": b1,
        "pc1": pc1, "pre": pre, "da": da,
    }


def _resume(sp: Path, tmp_path: Path, checkpoint, phases):
    return D._reconcile_completed_checkpoint_artifacts(
        sp, str(tmp_path), checkpoint, phases, "thorough", "evm",
    )


def _diagnostic(sp: Path) -> dict:
    return json.loads(
        (sp / "semantic_resume_invalidation.json").read_text(encoding="utf-8")
    )


# --------------------------------------------------------------------------
# The run47 shape: every drift row is a by-design intra-run rewrite.
# --------------------------------------------------------------------------

def test_run47_shape_keeps_every_completed_phase_and_rearms_only_depth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    sp, phases, checkpoint, units = _run47_shape(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    ledger_before = (sp / "_artifact_state.json").read_bytes()

    # Sanity: the raw scan really does see the same drift classes as run47.
    raw = detect_semantic_input_drift(sp, tmp_path, run_id=RUN_ID)
    by_unit = {row["work_unit_key"]: row for row in raw["rows"]}
    assert by_unit[units["r1"].key]["reasons"] == [
        "CONTENT_HASH_CHANGED", "PRODUCER_AUTHORITY_CHANGED",
    ]
    assert by_unit[units["b1"].key]["changed_input_identities"] == [
        "scratchpad:skill_dispatch.json",
    ]
    assert by_unit[units["pc1"].key]["changed_input_identities"] == [
        "scratchpad:rescan_manifest.md",
    ]
    assert "MISSING_AT_BINDING" in by_unit[units["da"].key]["reasons"]

    removed = _resume(sp, tmp_path, checkpoint, phases)

    assert removed == []
    assert checkpoint.completed == ["recon", "breadth", "rescan", "invariants"]
    assert checkpoint.rate_limited_at == "depth"
    # The decision is read-only: no receipt was invalidated.
    assert (sp / "_artifact_state.json").read_bytes() == ledger_before
    receipt = _diagnostic(sp)
    assert receipt["reason"] == "INTRA_RUN_REWRITES_ACCEPTED"
    assert receipt["removed_completed_phases"] == []
    assert receipt["external_changed_input_identities"] == []
    assert receipt["coverage_fallback_phases"] == []
    assert receipt["intra_run_superseded_identities"] == [
        "scratchpad:contract_inventory.md",
    ]
    assert receipt["unattributed_control_input_identities"] == [
        "scratchpad:rescan_manifest.md", "scratchpad:skill_dispatch.json",
    ]
    assert receipt["unarmed_work_unit_keys"] == [units["da"].key]
    classes = {
        (row["work_unit_key"], row["identity"]): row["drift_class"]
        for row in receipt["drift_classification"]
    }
    assert classes[(units["r1"].key, "scratchpad:contract_inventory.md")] == (
        "INTRA_RUN_SUPERSESSION"
    )
    assert classes[(units["b1"].key, "scratchpad:skill_dispatch.json")] == (
        "UNATTRIBUTED_CONTROL_INPUT"
    )
    assert classes[(units["pc1"].key, "scratchpad:rescan_manifest.md")] == (
        "UNATTRIBUTED_CONTROL_INPUT"
    )
    assert classes[(units["da"].key, "*")] == "UNARMED_WORK_UNIT"
    # The checkpoint binding did not even register as drift: its receipt is
    # the run-binding projection, which control-plane churn cannot change.
    assert units["pre"].key not in by_unit


def test_checkpoint_binding_is_run_binding_projection_not_raw_bytes(
    tmp_path: Path,
):
    sp, _phases, checkpoint, units = _run47_shape(tmp_path)
    pre = units["pre"]
    unit = read_artifact_ledger(sp)["work_units"][pre.key]
    binding = unit["input_bindings"]["scratchpad:_v2_checkpoint.json"]
    expected = run_binding_projection_bytes(
        (sp / "_v2_checkpoint.json").read_bytes()
    )
    assert binding["content_authority"] == RUN_BINDING_PROJECTION_SCHEMA
    assert binding["sha256"] == _sha(expected)
    assert binding["size"] == len(expected)
    assert binding["sha256"] != _sha((sp / "_v2_checkpoint.json").read_bytes())

    # Control-plane churn (completion list, pause marker, phase commits)
    # leaves the receipt valid ...
    checkpoint.completed = ["recon"]
    checkpoint.rate_limited_at = None
    checkpoint.degraded = ["breadth"]
    checkpoint.save(sp)
    assert validate_work_unit_inputs(
        sp, tmp_path, pre, _launch(pre), run_id=RUN_ID,
    ) == []

    # ... while a different audited-input snapshot still changes it.
    checkpoint.audit_snapshot = json.loads(json.dumps(SNAPSHOT))
    checkpoint.audit_snapshot["components"]["source_scope"]["digest"] = "d" * 64
    checkpoint.save(sp)
    issues = validate_work_unit_inputs(
        sp, tmp_path, pre, _launch(pre), run_id=RUN_ID,
    )
    assert issues == [
        "scratchpad:_v2_checkpoint.json: semantic input hash changed",
    ]

    # The projection itself is a small canonical document of identity fields.
    projection = json.loads(expected.decode("utf-8"))
    assert projection == {
        "schema": RUN_BINDING_PROJECTION_SCHEMA,
        "run_id": RUN_ID,
        "audit_snapshot_schema": SNAPSHOT["schema"],
        "audit_snapshot_digest": SNAPSHOT["snapshot_digest"],
        "audit_snapshot_component_digests": {
            "audit_config": "b" * 64,
            "source_scope": "a" * 64,
        },
    }
    assert run_binding_projection_bytes(b"not json") is None
    assert run_binding_projection_bytes(b"[]") is None


def test_legacy_raw_hashed_checkpoint_binding_is_run_control_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A ledger written before the projection must still resume cleanly."""

    sp, phases, checkpoint, units = _run47_shape(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    pre = units["pre"]
    ledger_path = sp / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    unit = ledger["work_units"][pre.key]
    binding = unit["input_bindings"]["scratchpad:_v2_checkpoint.json"]
    stale_raw = b'{"completed": ["recon", "breadth", "rescan"], "run_id": "%s"}\n' % (
        RUN_ID.encode("ascii")
    )
    binding["sha256"] = _sha(stale_raw)
    binding["size"] = len(stale_raw)
    binding.pop("content_authority", None)
    unit["input_set_digest"] = _input_set_digest(unit["input_bindings"])
    ledger_path.write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    raw = detect_semantic_input_drift(sp, tmp_path, run_id=RUN_ID)
    assert pre.key in raw["stale_work_unit_keys"]

    removed = _resume(sp, tmp_path, checkpoint, phases)

    assert removed == []
    assert checkpoint.completed == ["recon", "breadth", "rescan", "invariants"]
    receipt = _diagnostic(sp)
    assert receipt["run_control_state_identities"] == [
        "scratchpad:_v2_checkpoint.json",
    ]
    classes = {
        (row["work_unit_key"], row["identity"]): row["drift_class"]
        for row in receipt["drift_classification"]
    }
    assert classes[(pre.key, "scratchpad:_v2_checkpoint.json")] == (
        "RUN_CONTROL_STATE"
    )


def test_interrupted_phase_work_unit_with_missing_inputs_is_not_drift(
    tmp_path: Path,
):
    sp, _phases, _checkpoint, units = _run47_shape(tmp_path)
    verdict = detect_resume_semantic_drift(
        sp, tmp_path, run_id=RUN_ID,
        completed_phases=["recon", "breadth", "rescan", "invariants"],
    )
    classification = verdict["classification"]
    assert classification["unarmed_work_unit_keys"] == [units["da"].key]
    assert classification["external_changed_input_identities"] == []
    assert classification["external_phases"] == []
    assert verdict["output_tamper"]["rows"] == []
    assert verdict["ledger_has_typed_run_work_units"] is True
    # Not-yet-produced depth outputs are not changed inputs for the plan.
    assert "scratchpad:depth_token_flow_findings.md" not in (
        classification["external_changed_input_identities"]
    )


# --------------------------------------------------------------------------
# Positive controls: genuine external drift of committed state.
# --------------------------------------------------------------------------

def test_committed_output_edited_after_completion_invalidates_owner_and_typed_descendants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    sp, phases, checkpoint, units = _run47_shape(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    # contract_inventory.md is the committed output of recon/canonical_merge
    # (its current owner).  Editing it after recon completed is external.
    (sp / "contract_inventory.md").write_text(
        "# canonical inventory (hand edited)\n", encoding="utf-8"
    )

    removed = _resume(sp, tmp_path, checkpoint, phases)

    # recon (owner) + breadth (b1 binds it) + rescan (pc1 binds b1's output);
    # invariants is independent and stays; depth was never completed.
    assert removed == ["recon", "breadth", "rescan"]
    assert checkpoint.completed == ["invariants"]
    assert checkpoint.rate_limited_at == "depth"
    ledger = read_artifact_ledger(sp)["work_units"]
    assert ledger[units["b1"].key]["semantic_status"] == "STALE_INPUT"
    assert ledger[units["pc1"].key]["semantic_status"] == "STALE_INPUT"
    assert ledger[units["r1"].key]["semantic_status"] == "STALE_INPUT"
    assert ledger[units["pre"].key]["semantic_status"] == "ACTIVE"
    receipt = _diagnostic(sp)
    assert receipt["reason"] == "EXTERNAL_INPUT_DRIFT"
    assert receipt["external_changed_input_identities"] == [
        "scratchpad:contract_inventory.md",
    ]
    assert receipt["coverage_fallback_phases"] == []
    assert [
        (row["identity"], row["owner_work_unit_key"], row["live_status"])
        for row in receipt["output_tamper_rows"]
    ] == [(
        "scratchpad:contract_inventory.md", units["merge"].key, "CONTENT_CHANGED",
    )]
    # The by-design rows are still classified, not promoted to external.
    assert receipt["intra_run_superseded_identities"] == []  # r1 is external now
    assert receipt["unattributed_control_input_identities"] == [
        "scratchpad:rescan_manifest.md", "scratchpad:skill_dispatch.json",
    ]


def test_committed_output_removed_after_completion_invalidates_owner_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    sp, phases, checkpoint, units = _run47_shape(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "analysis_rescan_1.md").unlink()

    removed = _resume(sp, tmp_path, checkpoint, phases)

    assert removed == ["rescan"]
    assert checkpoint.completed == ["recon", "breadth", "invariants"]
    tamper = detect_committed_output_tamper(sp, tmp_path, run_id=RUN_ID)
    assert tamper["tampered_owner_work_unit_keys"] == [units["pc1"].key]
    assert tamper["rows"][0]["live_status"] == "MISSING"


def test_external_drift_never_falls_back_to_full_rewind_with_typed_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """External drift repairs a downstream phase it cannot prove independent.

    A completed phase with no typed input receipt cannot be shown independent
    of an externally-drifted upstream phase, so it is repaired WITH it -- but
    the repair stays scoped to that phase, never the historical blanket
    "re-run every completed phase".  (For the driver's own by-design in-run
    rewrites the same situation is recorded as debt and rewinds nothing; that
    is the run47 case, covered by
    `test_run47_shape_keeps_every_completed_phase_and_rearms_only_depth`.)
    """

    sp, phases, checkpoint, units = _run47_shape(tmp_path)
    untyped = _phase("inventory_prepare")
    phases.insert(3, untyped)
    checkpoint.completed.insert(3, untyped.name)
    (sp / "inventory_prepare.md").write_text("prepare\n", encoding="utf-8")
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "analysis_rescan_1.md").write_bytes(b"# rescan 1 (edited)\n")

    removed = _resume(sp, tmp_path, checkpoint, phases)

    assert removed == ["rescan", "inventory_prepare"]
    # upstream phases and typed downstream phases are untouched
    assert checkpoint.completed == ["recon", "breadth", "invariants"]
    receipt = _diagnostic(sp)
    assert receipt["coverage_fallback_phases"] == ["inventory_prepare"]
    assert receipt["reason"] == "EXTERNAL_DRIFT_WITH_UNTYPED_DESCENDANT"


def test_foreign_run_producer_is_external_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    sp, phases, checkpoint, units = _run47_shape(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    ledger_path = sp / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    drift_seed = detect_semantic_input_drift(sp, tmp_path, run_id=RUN_ID)
    # Rewrite r1's row as if a different run had produced its current input.
    state = {
        "reasons": ["CONTENT_HASH_CHANGED", "PRODUCER_AUTHORITY_CHANGED"],
        "recorded_status": "ACTIVE",
        "recorded_producer_work_unit_key": units["prepass"].key,
        "recorded_producer_run_id": RUN_ID,
        "current_status": "ACTIVE",
        "current_producer_work_unit_key": units["merge"].key,
        "current_producer_run_id": OTHER_RUN_ID,
    }
    drift = dict(drift_seed)
    drift["identity_states"] = {
        units["r1"].key: {"scratchpad:contract_inventory.md": state},
    }
    drift["rows"] = [
        row for row in drift_seed["rows"]
        if row["work_unit_key"] == units["r1"].key
    ]
    classification = classify_resume_semantic_drift(
        ledger, drift, None, run_id=RUN_ID,
        completed_phases=["recon", "breadth", "rescan", "invariants"],
    )
    assert classification["external_changed_input_identities"] == [
        "scratchpad:contract_inventory.md",
    ]
    assert classification["rows"][0]["drift_class"] == "EXTERNAL_FOREIGN_PRODUCER"


# --------------------------------------------------------------------------
# Semantic mutation without typed descendants: full rewind survives ONLY when
# the dependency ledger is uninformative; a typed ledger scopes it to the
# owner phase of the mutated artifact.
# --------------------------------------------------------------------------

def _mutation_fixture(tmp_path: Path, *, typed_ledger: bool):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    phases = [_phase(name) for name in ("inventory", "sc_verify_queue", "chain")]
    for phase in phases:
        (sp / phase.expected_artifacts[0]).write_text(
            f"{phase.name}\n", encoding="utf-8"
        )
    checkpoint = D.Checkpoint(
        completed=[phase.name for phase in phases], run_id=RUN_ID,
    )
    producer = _contract("inventory", "canonical", output="findings_inventory.md")
    _commit(sp, producer, b"before\n")
    if typed_ledger:
        (sp / "stable.md").write_text("stable\n", encoding="utf-8")
        consumer = _contract(
            "chain", "scaffold", output="hypotheses.md", immutable=("stable.md",),
        )
        _commit(sp, consumer, b"# hypotheses\n")
    event = arm_semantic_mutation(
        sp, tmp_path,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="PROMOTION",
        run_id=RUN_ID,
    )
    (sp / "findings_inventory.md").write_text("after\n", encoding="utf-8")
    finalized = finalize_semantic_mutation(
        sp, tmp_path, str(event["event_id"]), run_id=RUN_ID,
    )
    assert finalized["status"] == "INVALIDATION_APPLIED"
    assert finalized["invalidated_work_unit_keys"] == []
    return sp, phases, checkpoint, event


def test_armed_mutation_without_typed_descendants_repairs_conservatively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """An ARMED semantic mutation is a declared change, not a by-design rewrite.

    Scoping it to the artifact's owner phase was tried and rejected: the live
    verify-queue suite showed real descendants surviving a mutation they
    consumed, because a ledger can carry typed receipts and still say nothing
    about the phases that matter.  The arm itself proves a semantic source
    changed, and nothing here establishes which completed phases are
    independent of it, so the conservative repair stands.  This is NOT the
    run47 case: the driver's own in-run rewrites arm no mutation and are
    classified by-design.
    """
    sp, phases, checkpoint, event = _mutation_fixture(tmp_path, typed_ledger=True)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = _resume(sp, tmp_path, checkpoint, phases)

    assert removed == ["inventory", "sc_verify_queue", "chain"]
    assert checkpoint.completed == []
    receipt = _diagnostic(sp)
    assert receipt["reason"] == "MUTATION_WITHOUT_TYPED_DESCENDANTS"
    assert receipt["recovered_mutation_event_ids"] == [event["event_id"]]
    # The durable mutation chain owns the live bytes: it is not tamper.
    assert receipt["output_tamper_rows"] == []


def test_completed_dedup_transaction_empty_fanout_is_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """A committed same-run RMW postimage is already checkpoint-authorized."""
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    raw = b'{"records": []}\n'
    (scratchpad / "finding_records.json").write_bytes(raw)
    checkpoint = D.Checkpoint(
        completed=["sc_semantic_dedup"],
        run_id=RUN_ID,
        config={"pipeline": "sc"},
        phase_commits={
            "sc_semantic_dedup": D.PhaseCommit(
                phase_name="sc_semantic_dedup",
                state="CLEAN",
                run_id=RUN_ID,
            ),
        },
    )
    event = {
        "run_id": RUN_ID,
        "mutation_kind": "SEMANTIC_DEDUP_TRANSACTION_A_RECORDS",
        "artifact_identity": "scratchpad:finding_records.json",
        "plan_digest": "a" * 64,
        "after": {
            "status": "ACTIVE",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        },
    }
    monkeypatch.setattr(
        D, "read_artifact_ledger",
        lambda _root: {"work_units": {
            "sc/thorough/evm/codex/semantic_dedup/prequeue_apply": {
                "run_id": RUN_ID,
                "execution_state": "OUTPUT_COMMITTED",
                "artifacts": {
                    "scratchpad:finding_records.json": {
                        "status": "ACTIVE",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "size": len(raw),
                    },
                },
            },
        }},
    )
    assert D._completed_dedup_mutation_has_committed_postimage(
        scratchpad, checkpoint, event, list(checkpoint.completed),
    )
    (scratchpad / "finding_records.json").write_bytes(b"tampered\n")
    assert not D._completed_dedup_mutation_has_committed_postimage(
        scratchpad, checkpoint, event, list(checkpoint.completed),
    )


def test_dedup_phase_commit_acknowledges_empty_fanout_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    checkpoint = D.Checkpoint(run_id=RUN_ID)
    event_id = "SMUT-" + "A" * 24
    event = {
        "event_id": event_id,
        "run_id": RUN_ID,
        "mutation_kind": "SEMANTIC_DEDUP_TRANSACTION_A_RECORDS",
        "status": "INVALIDATION_APPLIED",
        "invalidated_work_unit_keys": [],
    }
    acknowledged = []
    monkeypatch.setattr(D, "semantic_mutation_events", lambda _root: [event])
    monkeypatch.setattr(
        D, "semantic_mutation_authority_digest", lambda _row: "a" * 64,
    )
    monkeypatch.setattr(
        D, "acknowledge_semantic_mutations",
        lambda _root, ids, **_kwargs: acknowledged.extend(ids),
    )
    monkeypatch.setattr(D, "_resolved_phase_contract_digest", lambda *_a: "")
    monkeypatch.setattr(D, "_resolved_phase_launch_digest", lambda *_a: "")
    controller = D.PhaseCommitController(
        checkpoint, scratchpad, str(tmp_path), {"pipeline": "sc"},
    )
    controller.commit(
        _phase("sc_semantic_dedup"), "CLEAN", artifact_digest="",
    )
    assert acknowledged == [event_id]
    assert D.Checkpoint.load(scratchpad).semantic_mutation_acks[event_id] == "a" * 64


def test_report_successor_requires_signed_live_transaction_before_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    checkpoint = D.Checkpoint(run_id=RUN_ID)
    event = {
        "event_id": "SMUT-" + "B" * 24,
        "run_id": RUN_ID,
        "mutation_kind": "REPORT_TRANSACTION_REPORT_FLOOR.EVIDENCE_PROJECTION",
        "artifact_identity": "project:AUDIT_REPORT.md",
        "status": "INVALIDATION_APPLIED",
        "invalidated_work_unit_keys": [],
    }
    monkeypatch.setattr(D, "semantic_mutation_events", lambda _root: [event])
    monkeypatch.setattr(
        D, "validate_report_transaction_semantic_successor",
        lambda **_kwargs: False,
    )
    called = []
    monkeypatch.setattr(
        D, "_finalize_driver_semantic_mutation",
        lambda *_args, **_kwargs: called.append(True) or [],
    )
    issues = D._acknowledge_report_transaction_successor(
        scratchpad, tmp_path, {"_run_id": RUN_ID}, checkpoint,
        "report_floor.evidence_projection",
    )
    assert issues and not called
    monkeypatch.setattr(
        D, "validate_report_transaction_semantic_successor",
        lambda **_kwargs: True,
    )
    assert D._acknowledge_report_transaction_successor(
        scratchpad, tmp_path, {"_run_id": RUN_ID}, checkpoint,
        "report_floor.evidence_projection",
    ) == []
    assert called == [True]


def test_mutation_without_typed_descendants_full_repair_only_when_ledger_uninformative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    sp, phases, checkpoint, _event = _mutation_fixture(
        tmp_path, typed_ledger=False,
    )
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])

    removed = _resume(sp, tmp_path, checkpoint, phases)

    assert removed == [phase.name for phase in phases]
    assert checkpoint.completed == []
    receipt = _diagnostic(sp)
    assert receipt["reason"] == "MUTATION_WITHOUT_TYPED_DESCENDANTS"
    assert receipt["coverage_fallback_phases"] == [
        "inventory", "sc_verify_queue", "chain",
    ]


def test_corrupt_ledger_still_repairs_conservatively_with_logged_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog,
):
    sp, phases, checkpoint, _units = _run47_shape(tmp_path)
    monkeypatch.setattr(D, "_resume_phase_contract_issues", lambda *_a, **_k: [])
    (sp / "_artifact_state.json").write_text("{broken", encoding="utf-8")

    with caplog.at_level("WARNING"):
        removed = _resume(sp, tmp_path, checkpoint, phases)

    assert removed == ["recon", "breadth", "rescan", "invariants"]
    assert checkpoint.completed == []
    assert any(
        "semantic dependency ledger is invalid" in record.getMessage()
        for record in caplog.records
    )
    assert _diagnostic(sp)["reason"].startswith("SEMANTIC_LEDGER_INVALID:")
