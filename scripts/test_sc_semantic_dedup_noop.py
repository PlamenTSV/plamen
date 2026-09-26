"""Focused authority tests for the conservative SC dedup passthrough."""
from __future__ import annotations

from pathlib import Path

import pytest
import sc_semantic_dedup_noop as noop
import plamen_driver as driver

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract
from sc_semantic_dedup_noop import (
    FAULT_POINTS,
    OUTPUT_NAMES,
    run_sc_semantic_dedup_noop,
)
from preverify_frozen_projection import derive_preverify_finding_records_bytes


RUN_ID = "12345678-1234-4234-9234-123456789abc"
INVENTORY = (
    "# Findings Inventory\n\n"
    "### Finding [INV-001]: Preserve this candidate\n"
    "**Severity**: Medium\n"
    "**Location**: src/Unit.sol:L1\n\n"
    "The conservative no-signal path must preserve these exact bytes.\n"
).encode("utf-8")


def _config(project: Path, root: Path, backend: str = "codex") -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": backend,
        "project_root": str(project),
        "scratchpad": str(root),
        "_run_id": RUN_ID,
    }


def _publish_inventory(
    project: Path,
    root: Path,
    *,
    raw: bytes = INVENTORY,
    backend: str = "codex",
) -> None:
    owner = f"sc/core/evm/{backend}/inventory/canonical_aggregate"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend=backend,
        phase="inventory",
        work_unit_id="canonical_aggregate",
        outputs=(ArtifactSpec(
            root="scratchpad", path="findings_inventory.md", owner_key=owner,
            artifact_class="DRIVER_GENERATED", writer="DRIVER", write_mode="CREATE",
            schema_version="unstructured.v1", minimum_gate="FIXTURE_INVENTORY",
            consumers=("sc_semantic_dedup/noop_passthrough",),
        ),),
        immutable_inputs=(), model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    record_work_unit_inputs(
        root, project, contract, launch, run_id=RUN_ID
    )
    (root / "findings_inventory.md").write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )


def _publish_sc_transaction_inputs(project: Path, root: Path) -> dict[str, object]:
    records = derive_preverify_finding_records_bytes(INVENTORY)
    owner = "sc/core/evm/codex/inventory/canonical_aggregate"
    inventory_contract = PhaseIOContract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="inventory", work_unit_id="canonical_aggregate",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad", path=name, owner_key=owner,
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                write_mode="CREATE", schema_version="unstructured.v1",
                minimum_gate="FIXTURE_INVENTORY_PAIR",
                consumers=("semantic_dedup/prequeue_apply",),
            )
            for name in ("findings_inventory.md", "finding_records.json")
        ),
        immutable_inputs=(), model_invoked=False,
    )
    inventory_launch = LaunchSpec(
        work_unit_key=inventory_contract.key, pipeline="sc", mode="core",
        ecosystem="evm", backend="codex", model="driver", timeout_s=30,
        exec_mode="python", tool_policy=(),
    )
    record_work_unit_inputs(
        root, project, inventory_contract, inventory_launch, run_id=RUN_ID
    )
    (root / "findings_inventory.md").write_bytes(INVENTORY)
    (root / "finding_records.json").write_bytes(records)
    record_work_unit_artifacts(
        root, project, inventory_contract, inventory_launch, run_id=RUN_ID,
        actor="DRIVER",
    )

    decision = (
        "# Semantic Dedup Decisions\n\n"
        "KEEP: INV-001\tindependent candidate\n"
    ).encode("utf-8")
    model_owner = "sc/core/evm/codex/sc_semantic_dedup/model"
    model_contract = PhaseIOContract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="sc_semantic_dedup", work_unit_id="model",
        outputs=(ArtifactSpec(
            root="scratchpad", path="dedup_decisions.md",
            owner_key=model_owner, artifact_class="REQUIRED", writer="MODEL",
            write_mode="CREATE", schema_version="unstructured.v1",
            minimum_gate="FIXTURE_DECISION",
            consumers=("semantic_dedup/prequeue_apply",),
        ),),
        immutable_inputs=(), model_invoked=True,
    )
    model_launch = LaunchSpec(
        work_unit_key=model_contract.key, pipeline="sc", mode="core",
        ecosystem="evm", backend="codex", model="gpt-5", timeout_s=30,
        exec_mode="headless", tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        root, project, model_contract, model_launch, run_id=RUN_ID
    )
    (root / "dedup_decisions.md").write_bytes(decision)
    record_work_unit_artifacts(
        root, project, model_contract, model_launch, run_id=RUN_ID,
        actor="MODEL",
    )
    return _config(project, root, "codex")


def test_sc_model_proposal_precedes_one_atomic_canonical_transaction(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    config = _publish_sc_transaction_inputs(project, root)

    result = driver._run_l1_prequeue_semantic_dedup_transaction(
        scratchpad=root,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )

    assert result["safe_to_consume"] is True
    assert (root / "findings_inventory.md").read_bytes() == INVENTORY
    assert (root / "findings_inventory_deduped.md").read_bytes() == INVENTORY
    ledger = read_artifact_ledger(root)
    apply = ledger["work_units"][
        "sc/core/evm/codex/semantic_dedup/prequeue_apply"
    ]
    assert apply["execution_state"] == "OUTPUT_COMMITTED"
    assert apply["semantic_status"] == "ACTIVE"
    assert not any(
        "UNOWNED_EXISTING_OUTPUT" in str(value)
        for value in apply.values()
    )


def test_sc_live_supervisor_waits_only_for_model_owned_proposal() -> None:
    phase = next(
        row for row in driver.SC_PHASES
        if row.name == "sc_semantic_dedup"
    )
    supervised = driver._model_owned_supervision_phase(phase)
    assert supervised.expected_artifacts == ["dedup_decisions.md"]
    assert "findings_inventory_deduped.md" not in supervised.expected_artifacts


def _fixture(tmp_path: Path, backend: str = "codex") -> tuple[Path, Path, dict[str, object]]:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _publish_inventory(project, root, backend=backend)
    return project, root, _config(project, root, backend)


def _run(
    project: Path,
    root: Path,
    config: dict[str, object],
    *,
    run_id: str = RUN_ID,
    reason: str = "no candidate blocks and no LIKELY-DUP tags",
    fault_hook=None,
) -> list[str]:
    return run_sc_semantic_dedup_noop(
        scratchpad=root,
        project_root=project,
        config=config,
        run_id=run_id,
        reason=reason,
        fault_hook=fault_hook,
    )


@pytest.mark.parametrize("backend", ("codex", "claude"))
def test_fresh_publish_is_exact_and_replay_is_byte_idempotent(
    tmp_path: Path, backend: str,
) -> None:
    project, root, config = _fixture(tmp_path, backend)

    assert _run(project, root, config) == list(OUTPUT_NAMES)
    assert (root / "findings_inventory_deduped.md").read_bytes() == INVENTORY
    assert (root / "findings_inventory.md").read_bytes() == INVENTORY
    decisions = (root / "dedup_decisions.md").read_text(encoding="utf-8")
    assert "**Status**: PASSTHROUGH" in decisions
    assert "**Signal Authority**: UNAVAILABLE" in decisions
    assert "**Semantic Review**: NOT PERFORMED" in decisions
    assert "No absence-of-duplicates conclusion is asserted" in decisions
    ledger = read_artifact_ledger(root)
    unit = next(
        value
        for key, value in ledger["work_units"].items()
        if key.endswith("/sc_semantic_dedup/noop_passthrough")
    )
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert all(
        unit["artifacts"][f"scratchpad:{name}"]["writer"] == "DRIVER"
        for name in OUTPUT_NAMES
    )
    before = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }

    assert _run(project, root, config) == list(OUTPUT_NAMES)
    after = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    assert after == before


@pytest.mark.parametrize("failpoint", FAULT_POINTS)
def test_every_fault_boundary_replays_the_sealed_pair(
    tmp_path: Path,
    failpoint: str,
) -> None:
    project, root, config = _fixture(tmp_path)
    fired = False

    def crash(point: str) -> None:
        nonlocal fired
        if point == failpoint and not fired:
            fired = True
            raise RuntimeError(f"fault:{point}")

    with pytest.raises(RuntimeError, match=f"fault:{failpoint}"):
        _run(project, root, config, fault_hook=crash)
    assert fired is True

    assert _run(project, root, config) == list(OUTPUT_NAMES)
    assert (root / "findings_inventory_deduped.md").read_bytes() == INVENTORY
    ledger = read_artifact_ledger(root)
    binding = ledger["artifact_bindings"][
        "scratchpad:findings_inventory_deduped.md"
    ]
    assert binding["status"] == "ACTIVE"
    assert binding["run_id"] == RUN_ID


@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_committed_output_damage_is_rejected(
    tmp_path: Path,
    damage: str,
) -> None:
    project, root, config = _fixture(tmp_path)
    _run(project, root, config)
    path = root / "findings_inventory_deduped.md"
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"tampered\n")

    with pytest.raises(ArtifactLedgerError, match="output replay failed"):
        _run(project, root, config)


@pytest.mark.parametrize("state", ("missing", "empty"))
def test_missing_or_empty_inventory_is_rejected(
    tmp_path: Path,
    state: str,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    if state == "empty":
        (root / "findings_inventory.md").write_bytes(b"")

    with pytest.raises(ArtifactLedgerError, match="inventory"):
        _run(project, root, _config(project, root))


def test_inventory_drift_after_arm_is_rejected(tmp_path: Path) -> None:
    project, root, config = _fixture(tmp_path)

    def crash(point: str) -> None:
        if point == "after_arm":
            raise RuntimeError("armed")

    with pytest.raises(RuntimeError, match="armed"):
        _run(project, root, config, fault_hook=crash)
    (root / "findings_inventory.md").write_bytes(INVENTORY + b"drift\n")

    with pytest.raises(ArtifactLedgerError, match="input replay failed"):
        _run(project, root, config)


def test_cross_run_and_reason_drift_are_rejected(tmp_path: Path) -> None:
    project, root, config = _fixture(tmp_path)
    _run(project, root, config)

    with pytest.raises(ArtifactLedgerError, match="run differs from configuration"):
        _run(
            project,
            root,
            config,
            run_id="87654321-4321-4321-8321-cba987654321",
        )
    with pytest.raises(ArtifactLedgerError, match="input replay failed"):
        _run(project, root, config, reason="oversized block file")


@pytest.mark.parametrize("name", OUTPUT_NAMES)
def test_preexisting_output_collision_is_rejected(
    tmp_path: Path,
    name: str,
) -> None:
    project, root, config = _fixture(tmp_path)
    (root / name).write_bytes(b"foreign\n")

    with pytest.raises(
        ArtifactLedgerError, match="refuses pre-existing output authority"
    ):
        _run(project, root, config)


def test_armed_third_state_is_preserved_and_rejected(tmp_path: Path) -> None:
    project, root, config = _fixture(tmp_path)

    def crash(point: str) -> None:
        if point == "after_output_1":
            raise RuntimeError("partial")

    with pytest.raises(RuntimeError, match="partial"):
        _run(project, root, config, fault_hook=crash)
    target = root / "dedup_decisions.md"
    target.write_bytes(b"unplanned output\n")
    with pytest.raises(ArtifactLedgerError, match="arbitrary partial output"):
        _run(project, root, config)
    assert target.read_bytes() == b"unplanned output\n"
    assert not (root / "findings_inventory_deduped.md").exists()


def test_unowned_inventory_is_not_a_semantic_producer(tmp_path: Path) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    (root / "findings_inventory.md").write_bytes(INVENTORY)
    with pytest.raises(ArtifactLedgerError, match="producer|input replay"):
        _run(project, root, _config(project, root))
    assert all(not (root / name).exists() for name in OUTPUT_NAMES)


def test_inventory_read_must_match_the_bound_input(tmp_path: Path, monkeypatch) -> None:
    project, root, config = _fixture(tmp_path)
    # Emulate a stale read preceding input arm. The real producer and input
    # binding retain the current bytes; no validator is replaced.
    monkeypatch.setattr(noop, "_read_inventory", lambda _path: INVENTORY + b"older read\n")
    with pytest.raises(ArtifactLedgerError, match="differ from bound input"):
        _run(project, root, config)
    assert all(not (root / name).exists() for name in OUTPUT_NAMES)


def test_dangling_output_symlink_is_not_an_absent_output(tmp_path: Path) -> None:
    project, root, config = _fixture(tmp_path)
    target = root / "dedup_decisions.md"
    try:
        target.symlink_to(root / "absent-target")
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ArtifactLedgerError, match="pre-existing output"):
        _run(project, root, config)
    assert target.is_symlink()


def test_driver_no_signal_and_oversize_branches_publish_before_commit() -> None:
    source = (Path(__file__).parent / "plamen_driver.py").read_text(
        encoding="utf-8", errors="strict"
    )
    no_signal = source[
        source.index("if not has_blocks and not has_likely_dup:") :
        source.index("# Dedup redesign: the live work is now bounded")
    ]
    oversize = source[
        source.index("if _blocks_over_budget:") :
        source.index('if phase.name == "sc_semantic_dedup":', source.index("if _blocks_over_budget:"))
    ]
    for branch in (no_signal, oversize):
        publish = branch.index("_run_sc_semantic_dedup_noop(")
        commit = branch.index("_commit_accepted_phase_from_disk(")
        assert publish < commit
