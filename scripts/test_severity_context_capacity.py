"""Component coverage for the governed severity worker byte ceiling.

These tests use a synthetic, schema-valid source decision to isolate planning
capacity.  They read the real SC/L1 methodology selected by the planning-input
capture module, but do not establish live verifier ancestry or launch a model.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import severity_adjudication_work as W
import severity_planning_inputs as planning_inputs
from test_severity_adjudication_work_p0_ag3 import (
    AUDIT_DIGEST,
    CONFIG_DIGEST,
    RUN_ID,
    _decision,
    _write_state,
)
from worker_execution_receipts import environment_allowlist_sha256


IMPLEMENTATION_ROOT = Path(__file__).resolve().parents[1]
LEGACY_CONTEXT_CAP = 65_536


def _live_methodology(pipeline: str) -> dict[str, Path]:
    return {
        logical_name: IMPLEMENTATION_ROOT / source_relative
        for logical_name in planning_inputs._PIPELINE_METHODS[pipeline]
        for source_relative, _captured_relative in (
            planning_inputs._METHODOLOGY_SOURCES[logical_name],
        )
    }


def _derive(
    scratchpad: Path,
    *,
    pipeline: str,
    max_context_bytes: int = W.DEFAULT_MAX_CONTEXT_BYTES,
) -> tuple[dict, dict[str, bytes]]:
    _manifest, plan, outputs = W.derive_adjudication_work(
        scratchpad,
        run_id=RUN_ID,
        audit_snapshot_digest=AUDIT_DIGEST,
        audit_config_digest=CONFIG_DIGEST,
        methodology_files=_live_methodology(pipeline),
        backend="fixture-subprocess",
        transport="headless-subprocess",
        effective_model="fixture-python",
        working_directory=scratchpad,
        tool_policy=("filesystem",),
        environment_allowlist_digest=environment_allowlist_sha256(()),
        adjudicator_identity="capacity-component-adjudicator",
        invocation_prefix=f"capacity-{pipeline}",
        max_context_bytes_per_worker=max_context_bytes,
    )
    return plan, outputs


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_real_methodology_fits_fixed_complete_worker_packet_cap(
    tmp_path: Path,
    pipeline: str,
):
    _write_state(tmp_path, [_decision("H-1")])

    plan, outputs = _derive(tmp_path, pipeline=pipeline)

    assert W.DEFAULT_MAX_ITEMS == 4
    assert W.DEFAULT_MAX_WEIGHT == 8
    assert W.DEFAULT_MAX_CONTEXT_BYTES == 131_072
    assert plan["max_items_per_worker"] == 4
    assert plan["max_weight_per_worker"] == 8
    assert plan["max_context_bytes_per_worker"] == 131_072
    assert plan["launch_count"] == 1
    assert plan["debt_items"] == []
    shard = plan["shards"][0]
    complete_packet_size = (
        len(outputs[shard["context_file"]])
        + len(outputs[shard["prompt_file"]])
    )
    assert complete_packet_size == shard["worker_input_size_bytes"]
    assert complete_packet_size <= W.DEFAULT_MAX_CONTEXT_BYTES
    if pipeline == "sc":
        # This is the observed regression boundary: the real governed SC
        # packet cannot fit the former 64 KiB default without truncation.
        assert complete_packet_size > LEGACY_CONTEXT_CAP

    capped_plan, capped_outputs = _derive(
        tmp_path,
        pipeline=pipeline,
        max_context_bytes=complete_packet_size - 1,
    )
    assert capped_plan["launch_count"] == 0
    assert capped_plan["shards"] == []
    assert capped_plan["debt_items"] == [
        {
            "candidate_id": "H-1",
            "state": "UNSCHEDULABLE_INPUT_CAP",
            "reason": "single adjudication context exceeds configured byte cap",
        }
    ]
    assert set(capped_outputs) == {W.MANIFEST_NAME, W.WORK_PLAN_NAME}
