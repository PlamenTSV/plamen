"""P0-Z exact semantic-input freshness and targeted invalidation fixtures."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json

import artifact_ledger as artifact_ledger_module
from artifact_ledger import (
    apply_semantic_invalidation,
    arm_semantic_mutation,
    ArtifactLedgerError,
    authorize_deterministic_work_unit_reexecution,
    detect_semantic_input_drift,
    finalize_semantic_mutation,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    recover_armed_semantic_mutations,
    semantic_dependency_invalidation_plan,
    validate_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}


def _contract(
    phase: str,
    unit: str,
    *,
    output: str,
    immutable: tuple[str, ...] = (),
    bounded: tuple[str, ...] = (),
) -> PhaseIOContract:
    key = "/".join((*BASE.values(), phase, unit))
    return PhaseIOContract(
        **BASE,
        phase=phase,
        work_unit_id=unit,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=output,
                owner_key=key,
                artifact_class="REQUIRED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        immutable_inputs=immutable,
        bounded_lookup_inputs=bounded,
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


def _record(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    *,
    run_id: str = "run-1",
) -> None:
    launch = _launch(contract)
    output_paths = {
        spec.identity: (
            scratchpad / spec.path
            if spec.root == "scratchpad"
            else project_root / spec.path
        )
        for spec in contract.outputs
    }
    output_bytes = {
        identity: path.read_bytes()
        for identity, path in output_paths.items()
        if path.is_file()
    }
    for path in output_paths.values():
        if path.is_file():
            path.unlink()
    record_work_unit_inputs(
        scratchpad, project_root, contract, launch, run_id=run_id
    )
    for identity, raw in output_bytes.items():
        path = output_paths[identity]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad, project_root, contract, launch, run_id=run_id
    )


def test_prelaunch_input_binding_detects_semantic_change(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "source.json").write_text('{"value":1}\n', encoding="utf-8")
    (sp / "derived.json").write_text('{"derived":1}\n', encoding="utf-8")
    contract = _contract(
        "derive", "one", output="derived.json",
        immutable=("scratchpad:source.json",),
    )
    launch = _launch(contract)
    derived = (sp / "derived.json").read_bytes()
    (sp / "derived.json").unlink()
    record_work_unit_inputs(sp, tmp_path, contract, launch, run_id="run-1")
    (sp / "derived.json").write_bytes(derived)
    assert validate_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="run-1"
    ) == []

    (sp / "source.json").write_text('{"value":2}\n', encoding="utf-8")
    issues = validate_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="run-1"
    )
    assert issues == ["scratchpad:source.json: semantic input hash changed"]


def test_missing_input_is_durable_debt_not_empty_success(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    contract = _contract(
        "derive", "missing", output="derived.json",
        immutable=("scratchpad:missing.json",),
    )
    launch = _launch(contract)
    receipt = record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="run-1"
    )
    assert receipt["input_bindings"]["scratchpad:missing.json"]["status"] == "MISSING"
    assert validate_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="run-1"
    ) == ["scratchpad:missing.json: semantic input missing at binding"]


def test_bounded_lookup_inputs_are_hash_bound_too(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "lookup.json").write_text("one\n", encoding="utf-8")
    contract = _contract(
        "derive", "lookup", output="out.json",
        bounded=("scratchpad:lookup.json",),
    )
    launch = _launch(contract)
    receipt = record_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="run-1"
    )
    assert receipt["input_bindings"]["scratchpad:lookup.json"]["input_class"] == "BOUNDED_LOOKUP"
    (sp / "lookup.json").write_text("two\n", encoding="utf-8")
    assert "hash changed" in validate_work_unit_inputs(
        sp, tmp_path, contract, launch, run_id="run-1"
    )[0]


def test_recording_outputs_preserves_prelaunch_input_receipt(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "in.md").write_text("input\n", encoding="utf-8")
    (sp / "out.md").write_text("output\n", encoding="utf-8")
    contract = _contract(
        "derive", "preserve", output="out.md",
        immutable=("scratchpad:in.md",),
    )
    _record(sp, tmp_path, contract)
    unit = read_artifact_ledger(sp)["work_units"][contract.key]
    assert set(unit["input_bindings"]) == {"scratchpad:in.md"}
    assert unit["input_set_digest"]


def test_targeted_invalidation_walks_descendants_but_not_siblings(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    for name in ("root.md", "a.md", "b.md", "c.md", "sibling.md"):
        (sp / name).write_text(name + "\n", encoding="utf-8")
    a = _contract(
        "a", "one", output="a.md", immutable=("scratchpad:root.md",)
    )
    b = _contract(
        "b", "one", output="b.md", immutable=("scratchpad:a.md",)
    )
    c = _contract(
        "c", "one", output="c.md", immutable=("scratchpad:b.md",)
    )
    sibling = _contract(
        "sibling", "one", output="sibling.md",
        immutable=("project:README.md",),
    )
    (tmp_path / "README.md").write_text("stable\n", encoding="utf-8")
    for contract in (a, b, c, sibling):
        _record(sp, tmp_path, contract)

    plan = semantic_dependency_invalidation_plan(
        read_artifact_ledger(sp), ["scratchpad:root.md"], run_id="run-1"
    )
    assert plan["invalidated_work_unit_keys"] == [a.key, b.key, c.key]
    assert plan["invalidated_artifact_identities"] == [
        "scratchpad:a.md", "scratchpad:b.md", "scratchpad:c.md"
    ]
    assert sibling.key not in plan["invalidated_work_unit_keys"]


def test_versioned_invalidation_preserves_older_same_identity_consumers(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    root = sp / "root.md"
    root.write_text("generation-one\n", encoding="utf-8")
    (sp / "old.md").write_text("old\n", encoding="utf-8")
    old = _contract(
        "derive",
        "old-generation",
        output="old.md",
        immutable=("scratchpad:root.md",),
    )
    _record(sp, tmp_path, old)

    root.write_text("generation-two\n", encoding="utf-8")
    (sp / "new.md").write_text("new\n", encoding="utf-8")
    new = _contract(
        "derive",
        "new-generation",
        output="new.md",
        immutable=("scratchpad:root.md",),
    )
    _record(sp, tmp_path, new)
    current = root.read_bytes()
    plan = semantic_dependency_invalidation_plan(
        read_artifact_ledger(sp),
        ["scratchpad:root.md"],
        run_id="run-1",
        changed_input_states={
            "scratchpad:root.md": {
                "status": "ACTIVE",
                "size": len(current),
                "sha256": hashlib.sha256(current).hexdigest(),
            }
        },
    )
    assert new.key in plan["invalidated_work_unit_keys"]
    assert old.key not in plan["invalidated_work_unit_keys"]


def test_invalidation_marks_receipts_stale_without_mutating_semantic_files(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "root.md").write_text("root\n", encoding="utf-8")
    (sp / "out.md").write_text("semantic output\n", encoding="utf-8")
    contract = _contract(
        "derive", "stale", output="out.md",
        immutable=("scratchpad:root.md",),
    )
    _record(sp, tmp_path, contract)
    before = (sp / "out.md").read_bytes()
    plan = semantic_dependency_invalidation_plan(
        read_artifact_ledger(sp), ["scratchpad:root.md"], run_id="run-1"
    )
    applied = apply_semantic_invalidation(sp, plan, run_id="run-1")
    assert (sp / "out.md").read_bytes() == before
    assert applied["invalidated_work_unit_keys"] == [contract.key]
    unit = read_artifact_ledger(sp)["work_units"][contract.key]
    assert unit["semantic_status"] == "STALE_INPUT"
    assert unit["artifacts"]["scratchpad:out.md"]["status"] == "STALE_INPUT"


def test_invalidation_plan_is_digest_bound_and_idempotent(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "root.md").write_text("root\n", encoding="utf-8")
    (sp / "out.md").write_text("out\n", encoding="utf-8")
    contract = _contract(
        "derive", "idem", output="out.md",
        immutable=("scratchpad:root.md",),
    )
    _record(sp, tmp_path, contract)
    plan = semantic_dependency_invalidation_plan(
        read_artifact_ledger(sp), ["scratchpad:root.md"], run_id="run-1"
    )
    first = apply_semantic_invalidation(sp, plan, run_id="run-1")
    second = apply_semantic_invalidation(sp, plan, run_id="run-1")
    assert first == second
    tampered = dict(plan, invalidated_work_unit_keys=[])
    try:
        apply_semantic_invalidation(sp, tampered, run_id="run-1")
    except Exception as exc:
        assert "digest" in str(exc)
    else:
        raise AssertionError("tampered invalidation plan must fail closed")


def test_cross_run_input_receipt_and_invalidation_are_rejected(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "root.md").write_text("root\n", encoding="utf-8")
    (sp / "out.md").write_text("out\n", encoding="utf-8")
    contract = _contract(
        "derive", "run", output="out.md",
        immutable=("scratchpad:root.md",),
    )
    _record(sp, tmp_path, contract, run_id="run-1")
    assert any("run_id mismatch" in issue for issue in validate_work_unit_inputs(
        sp, tmp_path, contract, _launch(contract), run_id="run-2"
    ))
    plan = semantic_dependency_invalidation_plan(
        read_artifact_ledger(sp), ["scratchpad:root.md"], run_id="run-1"
    )
    try:
        apply_semantic_invalidation(sp, plan, run_id="run-2")
    except Exception as exc:
        assert "run" in str(exc)
    else:
        raise AssertionError("cross-run invalidation must fail")


def test_stored_receipt_drift_detection_is_exact_and_side_effect_free(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "root.md").write_text("same-size-a\n", encoding="utf-8")
    (sp / "out.md").write_text("out\n", encoding="utf-8")
    contract = _contract(
        "derive", "stored", output="out.md",
        immutable=("scratchpad:root.md",),
    )
    _record(sp, tmp_path, contract)
    before = (sp / "_artifact_state.json").read_bytes()

    clean = detect_semantic_input_drift(sp, tmp_path, run_id="run-1")
    assert clean["changed_input_identities"] == []
    assert clean["stale_work_unit_keys"] == []
    assert clean["cross_run_work_unit_keys"] == []
    assert (sp / "_artifact_state.json").read_bytes() == before

    (sp / "root.md").write_text("same-size-b\n", encoding="utf-8")
    drift = detect_semantic_input_drift(sp, tmp_path, run_id="run-1")
    assert drift["changed_input_identities"] == ["scratchpad:root.md"]
    assert drift["stale_work_unit_keys"] == [contract.key]
    assert drift["rows"][0]["reasons"] == ["CONTENT_HASH_CHANGED"]
    assert (sp / "_artifact_state.json").read_bytes() == before


def test_resume_drift_scan_reuses_one_validation_epoch_for_shared_input(
    tmp_path: Path,
    monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "shared.md").write_text("shared authority\n", encoding="utf-8")
    producer = _contract(
        "producer", "shared", output="shared.md",
    )
    _record(sp, tmp_path, producer)
    for ordinal in range(8):
        output = f"consumer_{ordinal}.md"
        (sp / output).write_text(f"consumer {ordinal}\n", encoding="utf-8")
        consumer = _contract(
            "consumer",
            f"shared_{ordinal}",
            output=output,
            immutable=("scratchpad:shared.md",),
        )
        _record(sp, tmp_path, consumer)

    calls = 0
    original = artifact_ledger_module._stable_artifact_snapshot

    def counted_snapshot(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(
        artifact_ledger_module,
        "_stable_artifact_snapshot",
        counted_snapshot,
    )
    drift = detect_semantic_input_drift(sp, tmp_path, run_id="run-1")

    assert drift["changed_input_identities"] == []
    assert drift["stale_work_unit_keys"] == []
    assert calls == 1


def test_stored_receipt_drift_rejects_cross_run_and_bound_missing_input(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "out.md").write_text("out\n", encoding="utf-8")
    contract = _contract(
        "derive", "missing-stored", output="out.md",
        immutable=("scratchpad:missing.md",),
    )
    _record(sp, tmp_path, contract, run_id="run-old")

    old = detect_semantic_input_drift(sp, tmp_path, run_id="run-old")
    assert old["changed_input_identities"] == ["scratchpad:missing.md"]
    assert old["rows"][0]["reasons"] == ["MISSING_AT_BINDING"]

    other = detect_semantic_input_drift(sp, tmp_path, run_id="run-new")
    assert other["changed_input_identities"] == []
    assert other["stale_work_unit_keys"] == []
    assert other["cross_run_work_unit_keys"] == [contract.key]


def test_mutation_event_invalidates_exact_consumers_and_preserves_siblings(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    for name in ("inventory.md", "queue.md", "stable.md", "sibling.md"):
        (sp / name).write_text(name + "\n", encoding="utf-8")
    queue = _contract(
        "queue", "routing", output="queue.md",
        immutable=("scratchpad:inventory.md",),
    )
    sibling = _contract(
        "sibling", "routing", output="sibling.md",
        immutable=("scratchpad:stable.md",),
    )
    _record(sp, tmp_path, queue)
    _record(sp, tmp_path, sibling)

    event = arm_semantic_mutation(
        sp, tmp_path,
        artifact_identity="scratchpad:inventory.md",
        mutation_kind="LATE_FINDING_PROMOTION",
        run_id="run-1",
    )
    (sp / "inventory.md").write_text("inventory changed\n", encoding="utf-8")
    result = finalize_semantic_mutation(
        sp, tmp_path, event["event_id"],
        run_id="run-1", affected_record_ids=("INV-002",),
    )

    assert result["status"] == "INVALIDATION_APPLIED"
    assert result["affected_record_ids"] == ["INV-002"]
    assert result["invalidated_work_unit_keys"] == [queue.key]
    units = read_artifact_ledger(sp)["work_units"]
    assert units[queue.key]["semantic_status"] == "STALE_INPUT"
    assert units[sibling.key]["semantic_status"] == "ACTIVE"


def test_finalized_mutation_is_the_exact_producer_for_reexecuted_consumers(
    tmp_path: Path,
):
    """An armed driver mutation must not leave its new bytes owner-less.

    The original producer remains historical authority for the pre-mutation
    bytes.  A validated before->after mutation chain is the producer authority
    for the current bytes, so an invalidated deterministic consumer can bind
    and re-execute without either reblessing the original producer or accepting
    an untracked filesystem write.
    """

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "inventory.md").write_text("before\n", encoding="utf-8")
    producer = _contract(
        "inventory", "canonical", output="inventory.md",
    )
    _record(sp, tmp_path, producer)

    (sp / "derived.md").write_text("derived-before\n", encoding="utf-8")
    consumer = _contract(
        "derive", "inventory-view", output="derived.md",
        immutable=("scratchpad:inventory.md",),
    )
    _record(sp, tmp_path, consumer)

    event = arm_semantic_mutation(
        sp,
        tmp_path,
        artifact_identity="scratchpad:inventory.md",
        mutation_kind="ADDITIVE_REEMIT",
        run_id="run-1",
    )
    (sp / "inventory.md").write_text("before\nadditive candidate\n", encoding="utf-8")
    finalized = finalize_semantic_mutation(
        sp, tmp_path, event["event_id"], run_id="run-1",
    )
    assert finalized["invalidated_work_unit_keys"] == [consumer.key]

    launch = _launch(consumer)
    rebound = record_work_unit_inputs(
        sp, tmp_path, consumer, launch, run_id="run-1"
    )
    binding = rebound["input_bindings"]["scratchpad:inventory.md"]
    assert binding["status"] == "ACTIVE"
    assert binding["producer_work_unit_key"].startswith("semantic-mutation:")
    assert len(binding["producer_contract_digest"]) == 64
    (sp / "derived.md").write_text("derived-after\n", encoding="utf-8")
    record_work_unit_artifacts(
        sp, tmp_path, consumer, launch, run_id="run-1"
    )
    assert validate_work_unit_inputs(
        sp, tmp_path, consumer, launch, run_id="run-1"
    ) == []


def test_deterministic_reexecution_is_narrow_and_armed_before_output_write(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "checkpoint.json").write_text("one\n", encoding="utf-8")
    for name in ("view_a.md", "view_b.md"):
        (sp / name).write_text(name + "\n", encoding="utf-8")
    first = _contract(
        "projection", "a", output="view_a.md",
        immutable=("scratchpad:checkpoint.json",),
    )
    sibling = _contract(
        "projection", "b", output="view_b.md",
        immutable=("scratchpad:checkpoint.json",),
    )
    _record(sp, tmp_path, first)
    _record(sp, tmp_path, sibling)
    (sp / "checkpoint.json").write_text("two\n", encoding="utf-8")

    plan = authorize_deterministic_work_unit_reexecution(
        sp, tmp_path, first, _launch(first), run_id="run-1"
    )
    assert plan is not None
    assert plan["invalidated_work_unit_keys"] == [first.key]
    units = read_artifact_ledger(sp)["work_units"]
    assert units[first.key]["semantic_status"] == "STALE_INPUT"
    assert units[sibling.key]["semantic_status"] == "ACTIVE"


def test_deterministic_reexecution_rejects_output_only_tamper(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "source.md").write_text("one\n", encoding="utf-8")
    (sp / "view.md").write_text("valid view\n", encoding="utf-8")
    contract = _contract(
        "projection", "tamper", output="view.md",
        immutable=("scratchpad:source.md",),
    )
    _record(sp, tmp_path, contract)
    (sp / "source.md").write_text("two\n", encoding="utf-8")
    (sp / "view.md").write_text("tampered before arm\n", encoding="utf-8")
    try:
        authorize_deterministic_work_unit_reexecution(
            sp, tmp_path, contract, _launch(contract), run_id="run-1"
        )
    except ArtifactLedgerError as exc:
        assert "output authority mismatch" in str(exc)
    else:
        raise AssertionError("output-only tamper was reblessed")


def test_armed_mutation_recovers_crash_between_write_and_invalidation(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "inventory.md").write_text("before\n", encoding="utf-8")
    (sp / "queue.md").write_text("queue\n", encoding="utf-8")
    queue = _contract(
        "queue", "crash", output="queue.md",
        immutable=("scratchpad:inventory.md",),
    )
    _record(sp, tmp_path, queue)
    event = arm_semantic_mutation(
        sp, tmp_path,
        artifact_identity="scratchpad:inventory.md",
        mutation_kind="REPAIR",
        run_id="run-1",
    )
    (sp / "inventory.md").write_text("after\n", encoding="utf-8")

    recovered = recover_armed_semantic_mutations(
        sp, tmp_path, run_id="run-1"
    )
    assert [row["event_id"] for row in recovered] == [event["event_id"]]
    assert recovered[0]["status"] == "INVALIDATION_APPLIED"
    assert read_artifact_ledger(sp)["work_units"][queue.key][
        "semantic_status"
    ] == "STALE_INPUT"
    assert recover_armed_semantic_mutations(
        sp, tmp_path, run_id="run-1"
    ) == []


def test_no_change_mutation_is_terminal_without_invalidating_consumer(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "inventory.md").write_text("same\n", encoding="utf-8")
    (sp / "queue.md").write_text("queue\n", encoding="utf-8")
    queue = _contract(
        "queue", "no-change", output="queue.md",
        immutable=("scratchpad:inventory.md",),
    )
    _record(sp, tmp_path, queue)
    event = arm_semantic_mutation(
        sp, tmp_path,
        artifact_identity="scratchpad:inventory.md",
        mutation_kind="IDEMPOTENT_REPAIR",
        run_id="run-1",
    )
    result = finalize_semantic_mutation(
        sp, tmp_path, event["event_id"], run_id="run-1"
    )
    assert result["status"] == "NO_CHANGE"
    assert result["invalidated_work_unit_keys"] == []
    assert read_artifact_ledger(sp)["work_units"][queue.key][
        "semantic_status"
    ] == "ACTIVE"


def test_rehashed_subset_cannot_shrink_contract_input_denominator(tmp_path: Path):
    from artifact_ledger import _input_set_digest

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    for name in ("one.md", "two.md", "out.md"):
        (sp / name).write_text(name + "\n", encoding="utf-8")
    contract = _contract(
        "derive", "denominator", output="out.md",
        immutable=("scratchpad:one.md", "scratchpad:two.md"),
    )
    _record(sp, tmp_path, contract)
    ledger_path = sp / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    unit = ledger["work_units"][contract.key]
    unit["input_bindings"].pop("scratchpad:two.md")
    unit["input_set_digest"] = _input_set_digest(unit["input_bindings"])
    ledger_path.write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    try:
        detect_semantic_input_drift(sp, tmp_path, run_id="run-1")
    except Exception as exc:
        assert "contract input denominator mismatch" in str(exc)
    else:
        raise AssertionError("rehashed subset must not author its own denominator")
