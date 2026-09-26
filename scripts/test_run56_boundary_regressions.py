from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent))

import application_skeptic as skeptic  # noqa: E402
import plamen_driver as driver  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    registered_projection_handoff,
    resolve_phase_io_contract,
)


def test_relative_methodology_binding_is_rooted_digest_exact_and_unique(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    relative = Path("attention_repair_shard_plan.json")
    raw = b'{"schema":"exact"}\n'
    (first / relative).write_bytes(raw)
    item = {
        "methodology_path": relative.as_posix(),
        "methodology_sha256": hashlib.sha256(raw).hexdigest(),
    }
    assert skeptic.read_bound_methodology_bytes(item, [first, second]) == raw

    (second / relative).write_bytes(raw)
    with pytest.raises(skeptic.ApplicationSkepticError, match="ambiguous"):
        skeptic.read_bound_methodology_bytes(item, [first, second])


def test_sc_dedup_model_owns_only_the_decision_delta(tmp_path: Path) -> None:
    for name in ("dedup_candidate_pairs.md", "dedup_focus_inventory.md"):
        (tmp_path / name).write_text("# exact packet\n", encoding="utf-8")
    phase = next(
        value for value in driver.SC_PHASES
        if value.name == "sc_semantic_dedup"
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path),
        "scratchpad": str(tmp_path),
        "_run_id": "12345678-1234-4234-8234-1234567890ab",
    }
    contract, _launch = driver._typed_model_phase_contract_and_launch(
        phase, tmp_path, config
    )
    assert tuple(output.path for output in contract.outputs) == (
        "dedup_decisions.md",
    )


def test_enumgap_accepts_every_registered_canonical_inventory_owner() -> None:
    prefix = "sc/thorough/evm/codex/"
    target = prefix + "enumgap_delivery/inventory_append"
    producers = {
        "inventory/canonical_aggregate": (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
        ),
        "inventory/id_ledger_merge": ("scratchpad:_id_ledger.json",),
        "inventory/additive_reemit": (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
            "scratchpad:_id_ledger.json",
        ),
        "inventory/additive_depth_finalize": (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
            "scratchpad:_id_ledger.json",
        ),
        "inventory/late_recall_floor": (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
            "scratchpad:_id_ledger.json",
        ),
        "inventory/gate_p_successor": (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
            "scratchpad:_id_ledger.json",
        ),
        "semantic_dedup/prequeue_apply": (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
            "scratchpad:_id_ledger.json",
        ),
        "axis_disposition/promotion": (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
            "scratchpad:_id_ledger.json",
        ),
    }
    for producer, identities in producers.items():
        for identity in identities:
            assert registered_projection_handoff(
                prefix + producer, target, identity
            )


def test_percontract_reemit_is_a_registered_driver_producer() -> None:
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="rescan",
        work_unit_id="self_exclusion_reemit",
        exact_inputs=(
            "analysis_1.md",
            "analysis_percontract_1.md",
            "analysis_rescan_1.md",
        ),
        exact_outputs=("analysis_percontract_reemit.md",),
    )
    assert contract.model_invoked is False
    assert tuple(output.identity for output in contract.outputs) == (
        "scratchpad:analysis_percontract_reemit.md",
    )
    assert registered_projection_handoff(
        contract.key,
        "sc/thorough/evm/codex/"
        "sc_verify_queue/preverify_capture."
        + "a" * 64,
        "scratchpad:analysis_percontract_reemit.md",
    )
