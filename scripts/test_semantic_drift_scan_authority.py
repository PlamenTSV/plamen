"""Focused authority and epoch tests for semantic drift scanning."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import artifact_ledger as ledger_module
from artifact_ledger import (
    ArtifactLedgerError,
    _input_set_digest,
    detect_semantic_input_drift,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
RUN_ID = "semantic-drift-authority-run"


def _contract(
    phase: str,
    unit: str,
    *,
    output: str,
    inputs: tuple[str, ...] = (),
) -> PhaseIOContract:
    key = "/".join((*BASE.values(), phase, unit))
    return PhaseIOContract(
        **BASE,
        phase=phase,
        work_unit_id=unit,
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=output,
            owner_key=key,
            artifact_class="REQUIRED",
            writer="DRIVER",
            write_mode="REPLACE",
        ),),
        immutable_inputs=inputs,
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


def _commit(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    raw: bytes,
) -> None:
    launch = _launch(contract)
    output = scratchpad / contract.outputs[0].path
    record_work_unit_inputs(
        scratchpad, project_root, contract, launch, run_id=RUN_ID,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad, project_root, contract, launch, run_id=RUN_ID,
    )


def test_scan_terminally_rejoins_shared_input_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    shared = scratchpad / "shared.md"
    shared.write_bytes(b"original shared input\n")
    for ordinal in range(2):
        contract = _contract(
            "consumer",
            f"shared-{ordinal}",
            output=f"consumer-{ordinal}.md",
            inputs=("scratchpad:shared.md",),
        )
        _commit(scratchpad, tmp_path, contract, f"out {ordinal}\n".encode())

    original_snapshot = ledger_module._stable_artifact_snapshot
    changed = False

    def mutate_after_first_shared_snapshot(path, *args, **kwargs):
        nonlocal changed
        snapshot = original_snapshot(path, *args, **kwargs)
        if Path(path) == shared and not changed:
            changed = True
            shared.write_bytes(b"replacement after cached read\n")
        return snapshot

    monkeypatch.setattr(
        ledger_module, "_stable_artifact_snapshot", mutate_after_first_shared_snapshot,
    )
    with pytest.raises(ArtifactLedgerError, match="validation epoch|during semantic drift"):
        detect_semantic_input_drift(scratchpad, tmp_path, run_id=RUN_ID)


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("producer_launch_digest", "1" * 64),
        ("producer_commit_receipt_digest", "2" * 64),
    ),
)
def test_scan_rejects_rehashed_producer_authority_binding_mismatch(
    tmp_path: Path, field: str, replacement: str,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    producer = _contract("source", "producer", output="source.md")
    _commit(scratchpad, tmp_path, producer, b"source\n")
    consumer = _contract(
        "consumer", "bound", output="derived.md",
        inputs=("scratchpad:source.md",),
    )
    _commit(scratchpad, tmp_path, consumer, b"derived\n")

    ledger_path = scratchpad / "_artifact_state.json"
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][consumer.key]
    binding = unit["input_bindings"]["scratchpad:source.md"]
    assert binding[field] != replacement
    binding[field] = replacement
    unit["input_set_digest"] = _input_set_digest(unit["input_bindings"])
    ledger_path.write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )

    drift = detect_semantic_input_drift(scratchpad, tmp_path, run_id=RUN_ID)
    assert drift["changed_input_identities"] == ["scratchpad:source.md"]
    assert drift["stale_work_unit_keys"] == [consumer.key]
    assert drift["rows"] == [{
        "work_unit_key": consumer.key,
        "input_identities": ["scratchpad:source.md"],
        "changed_input_identities": ["scratchpad:source.md"],
        "reasons": ["PRODUCER_AUTHORITY_CHANGED"],
    }]


def test_drift_row_distinguishes_changed_identity_from_full_denominator(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    changed = scratchpad / "changed.md"
    stable = scratchpad / "stable.md"
    changed.write_bytes(b"before\n")
    stable.write_bytes(b"stable\n")
    consumer = _contract(
        "consumer", "mixed", output="mixed.md",
        inputs=("scratchpad:changed.md", "scratchpad:stable.md"),
    )
    _commit(scratchpad, tmp_path, consumer, b"mixed\n")
    changed.write_bytes(b"after\n")

    drift = detect_semantic_input_drift(scratchpad, tmp_path, run_id=RUN_ID)
    assert drift["changed_input_identities"] == ["scratchpad:changed.md"]
    assert drift["rows"] == [{
        "work_unit_key": consumer.key,
        "input_identities": [
            "scratchpad:changed.md", "scratchpad:stable.md",
        ],
        "changed_input_identities": ["scratchpad:changed.md"],
        "reasons": ["CONTENT_HASH_CHANGED"],
    }]
