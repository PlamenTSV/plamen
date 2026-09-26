from __future__ import annotations

from pathlib import Path

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    arm_semantic_mutation,
    arm_semantic_mutation_batch,
    finalize_semantic_mutation,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_import_authority,
    semantic_mutation_events,
    write_artifact_ledger,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


RUN_ID = "run-semantic-predecessor"
IDENTITY = "scratchpad:findings_inventory.md"
OWNER = "sc/thorough/evm/codex/inventory/fixture"


def _seed_authoritative_inventory(tmp_path: Path) -> tuple[Path, Path]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="inventory",
        work_unit_id="fixture",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="findings_inventory.md",
                owner_key=OWNER,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=RUN_ID
    )
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-RECOVERED]: retained candidate\n",
        encoding="utf-8",
    )
    record_work_unit_artifacts(
        scratchpad, tmp_path, contract, launch, run_id=RUN_ID
    )
    return tmp_path, scratchpad


def _append_candidate(path: Path, finding_id: str) -> None:
    with path.open("ab") as stream:
        stream.write(
            f"\n### Finding [{finding_id}]: Gate P candidate\n".encode(
                "utf-8"
            )
        )


def _seed_authoritative_bundle(tmp_path: Path) -> tuple[Path, Path, tuple[str, ...]]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    names = ("_id_ledger.json", "finding_records.json", "findings_inventory.md")
    identities = tuple(f"scratchpad:{name}" for name in names)
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="inventory",
        work_unit_id="bundle",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key="sc/thorough/evm/codex/inventory/bundle",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            )
            for name in names
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=RUN_ID
    )
    for index, name in enumerate(names):
        (scratchpad / name).write_text(f"bundle-{index}\n", encoding="utf-8")
    record_work_unit_artifacts(
        scratchpad, tmp_path, contract, launch, run_id=RUN_ID
    )
    return tmp_path, scratchpad, identities


def test_coupled_bundle_arms_from_one_terminal_authority_epoch(
    tmp_path: Path,
) -> None:
    project, scratchpad, identities = _seed_authoritative_bundle(tmp_path)
    mutations = tuple(
        (identity, f"COUPLED_{index}")
        for index, identity in enumerate(identities)
    )

    events = arm_semantic_mutation_batch(
        scratchpad,
        project,
        mutations=mutations,
        run_id=RUN_ID,
    )

    assert [event["artifact_identity"] for event in events] == list(identities)
    assert {event["status"] for event in events} == {"ARMED"}
    assert len(semantic_mutation_events(scratchpad)) == 3
    for event in reversed(events):
        finalized = finalize_semantic_mutation(
            scratchpad,
            project,
            event["event_id"],
            run_id=RUN_ID,
        )
        assert finalized["status"] == "NO_CHANGE"


def test_coupled_bundle_arm_replay_is_exact_while_batch_is_nonterminal(
    tmp_path: Path,
) -> None:
    project, scratchpad, identities = _seed_authoritative_bundle(tmp_path)
    mutations = tuple(
        (identity, f"COUPLED_{index}")
        for index, identity in enumerate(identities)
    )

    first = arm_semantic_mutation_batch(
        scratchpad, project, mutations=mutations, run_id=RUN_ID
    )
    replay = arm_semantic_mutation_batch(
        scratchpad, project, mutations=mutations, run_id=RUN_ID
    )

    assert [row["event_id"] for row in replay] == [
        row["event_id"] for row in first
    ]
    assert len(semantic_mutation_events(scratchpad)) == len(mutations)


def test_coupled_bundle_changed_outputs_all_finalize_from_same_epoch(
    tmp_path: Path,
) -> None:
    project, scratchpad, identities = _seed_authoritative_bundle(tmp_path)
    mutations = tuple(
        (identity, f"COUPLED_{index}")
        for index, identity in enumerate(identities)
    )
    events = arm_semantic_mutation_batch(
        scratchpad, project, mutations=mutations, run_id=RUN_ID
    )
    for identity in identities:
        with (scratchpad / identity.split(":", 1)[1]).open("ab") as stream:
            stream.write(b"coupled-successor\n")

    finalized = [
        finalize_semantic_mutation(
            scratchpad, project, event["event_id"], run_id=RUN_ID
        )
        for event in reversed(events)
    ]

    assert {row["status"] for row in finalized} == {
        "INVALIDATION_APPLIED"
    }


def test_coupled_bundle_preflight_failure_publishes_no_partial_arms(
    tmp_path: Path,
) -> None:
    project, scratchpad, identities = _seed_authoritative_bundle(tmp_path)
    ledger = read_artifact_ledger(scratchpad)
    stale_identity = identities[1]
    owner = ledger["artifact_bindings"][stale_identity]["owner_key"]
    ledger["artifact_bindings"][stale_identity]["status"] = "STALE_INPUT"
    ledger["work_units"][owner]["artifacts"][stale_identity]["status"] = (
        "STALE_INPUT"
    )
    write_artifact_ledger(scratchpad, ledger)

    with pytest.raises(
        ArtifactLedgerError,
        match="predecessor lacks active current-run producer authority",
    ):
        arm_semantic_mutation_batch(
            scratchpad,
            project,
            mutations=tuple(
                (identity, f"COUPLED_{index}")
                for index, identity in enumerate(identities)
            ),
            run_id=RUN_ID,
        )

    assert semantic_mutation_events(scratchpad) == []


def test_stale_predecessor_cannot_arm_or_mutate_recovered_candidates(
    tmp_path: Path,
) -> None:
    project, scratchpad = _seed_authoritative_inventory(tmp_path)
    inventory = scratchpad / "findings_inventory.md"
    recovered = inventory.read_bytes()
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][OWNER]
    unit["semantic_status"] = "STALE_INPUT"
    unit["artifacts"][IDENTITY]["status"] = "STALE_INPUT"
    ledger["artifact_bindings"][IDENTITY]["status"] = "STALE_INPUT"
    ledger["artifacts"]["findings_inventory.md"]["status"] = "STALE_INPUT"
    write_artifact_ledger(scratchpad, ledger)

    with pytest.raises(
        ArtifactLedgerError,
        match="predecessor lacks active current-run producer authority",
    ):
        arm_semantic_mutation(
            scratchpad,
            project,
            artifact_identity=IDENTITY,
            mutation_kind="GATE_P_ADDITIVE_PROMOTION",
            run_id=RUN_ID,
        )

    assert inventory.read_bytes() == recovered
    assert b"INV-RECOVERED" in inventory.read_bytes()
    assert semantic_mutation_events(scratchpad) == []


def test_clean_contiguous_successor_preserves_recovered_candidates(
    tmp_path: Path,
) -> None:
    project, scratchpad = _seed_authoritative_inventory(tmp_path)
    inventory = scratchpad / "findings_inventory.md"

    event_ids: list[str] = []
    for ordinal in (1, 2):
        event = arm_semantic_mutation(
            scratchpad,
            project,
            artifact_identity=IDENTITY,
            mutation_kind=f"GATE_P_ADDITIVE_PROMOTION_{ordinal}",
            run_id=RUN_ID,
        )
        _append_candidate(inventory, f"INV-GATE-P-{ordinal}")
        finalized = finalize_semantic_mutation(
            scratchpad,
            project,
            str(event["event_id"]),
            run_id=RUN_ID,
            affected_record_ids=(f"INV-GATE-P-{ordinal}",),
        )
        assert finalized["transition_authority"]["transition_kind"] == (
            "STRICT_APPEND"
        )
        event_ids.append(str(finalized["event_id"]))

    authority = semantic_import_authority(
        scratchpad,
        project,
        IDENTITY,
        run_id=RUN_ID,
    )
    content = inventory.read_bytes()

    assert authority["authority_kind"] == (
        "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
    )
    assert authority["mutation_event_ids"] == event_ids
    assert b"INV-RECOVERED" in content
    assert b"INV-GATE-P-1" in content
    assert b"INV-GATE-P-2" in content
