"""Fast structural contract for the pytest lane taxonomy.

This test must remain source-only and in the default lane so a future taxonomy
edit cannot silently make the parallel fast lane unsafe.  Git-backed packaging
contracts live in the serial ``test_python_packaging_contracts`` module.
"""
from __future__ import annotations

from pathlib import Path

import conftest as test_config


# Verified real-process files: each either launches an OS child/external tool or
# performs a real multi-second timing/process-tree exercise.  Keeping the list
# here (outside conftest) makes lane membership a ratcheted review boundary.
REQUIRED_SERIAL_STEMS = frozenset(
    {
        "test_fuzz_workspace_adversarial_review_p2_a",
        "test_fuzz_workspace_authority_p2_a",
        "test_negative_closure_broker_live_cutover",
        "test_p1_dm_phase_io_packaging",
        "test_python_packaging_contracts",
        "test_semantic_dedup_applied_authority_p0_qs",
        "test_severity_shadow_phase_runtime_p0_ag4",
        "test_severity_worker_debt_recovery_p0_ag4",
        "test_snapshot_startup_rewind_r0_8cd",
        "test_spike_mechanical_poc",
        "test_worker_execution_receipts",
        "test_worker_process_tree_adversarial_review",
        "test_worker_stdout_output_and_stream_limits",
    }
)

REQUIRED_SLOW_STEMS = REQUIRED_SERIAL_STEMS - {
    # These execute one bounded Git query and are serial for process isolation,
    # but are not themselves heavyweight.
    "test_p1_dm_phase_io_packaging",
    "test_python_packaging_contracts",
    "test_semantic_dedup_applied_authority_p0_qs",
}


def test_real_process_modules_are_excluded_from_parallel_fast_lane() -> None:
    assert REQUIRED_SERIAL_STEMS <= test_config._INTEGRATION_STEMS
    assert REQUIRED_SLOW_STEMS <= test_config._SLOW_STEMS
    assert test_config._SLOW_STEMS <= test_config._INTEGRATION_STEMS


def test_collected_marker_partition_is_total_disjoint_and_slow_is_serial() -> None:
    """Every collected item belongs to exactly one execution lane.

    This checks the collection-time receipt rather than merely comparing the
    filename allowlists: explicit per-test markers must not create an overlap,
    and an unlisted module must not fall outside both lanes.
    """

    partition = test_config._LAST_MARKER_PARTITION
    assert partition["item_count"] > 0
    assert partition["invalid"] == []
    assert partition["unit_count"] + partition["integration_count"] == partition[
        "item_count"
    ]


def test_ship_manifest_regressions_are_hermetic() -> None:
    scripts_dir = Path(__file__).resolve().parent
    for name in ("test_ship_a_contracts.py", "test_ship_b_spawn_manifest.py"):
        text = (scripts_dir / name).read_text(encoding="utf-8").lower()
        assert "glob.glob" not in text
        assert "d:\\programming" not in text
        assert "manifest fixture not" not in text
