"""Fast structural contract for the pytest lane taxonomy.

This test must remain source-only and in the default lane so a future taxonomy
edit cannot silently make the parallel fast lane unsafe.  Git-backed packaging
contracts live in the serial ``test_python_packaging_contracts`` module.
"""
from __future__ import annotations

from pathlib import Path

import conftest as test_config
import pytest


# Verified integration files: each launches an OS child/external tool, performs
# a real multi-second timing/process-tree exercise, or runs a heavyweight live
# driver transaction chain. Keeping the list
# here (outside conftest) makes lane membership a ratcheted review boundary.
REQUIRED_SERIAL_STEMS = frozenset(
    {
        "test_posix_report_execution_lineage",
        "test_breadth_refusal_checkpoint_retention",
        "test_claude_phase_tool_boundary_driver_p1_f",
        "test_darwin_cas_helper",
        "test_dynamic_verifier_backend_execution_authority_p0",
        "test_dynamic_verifier_runtime_integration_p0_ak",
        "test_fuzz_workspace_adversarial_review_p2_a",
        "test_fuzz_workspace_authority_p2_a",
        "test_live_verify_queue_semantic_success_paths",
        "test_mechanical_successor_consumer_p0_ag1",
        "test_negative_closure_broker_live_cutover",
        "test_p1_dm_phase_io_packaging",
        "test_posix_v2_compat_poc_execution",
        "test_posix_v2_compat_dependency_repair",
        "test_posix_v2_compat_prewarm",
        "test_posix_v2_compat_supply_chain_admission",
        "test_python_packaging_contracts",
        "test_r10_demotion_gate",
        "test_report_evidence_runtime_p1_k",
        "test_report_staged_verifier_execution_authority",
        "test_security_obligation_lifecycle_p1_c",
        "test_semantic_dedup_applied_authority_p0_qs",
        "test_severity_shadow_phase_runtime_p0_ag4",
        "test_severity_empty_source",
        "test_severity_zero_reconciliation",
        "test_severity_planning_inputs",
        "test_severity_planning_snapshot",
        "test_severity_planning",
        "test_severity_bind_postimage_cas",
        "test_grouped_successor_history",
        "test_severity_bind_postimages",
        "test_severity_bind_transaction",
        "test_severity_initial_source_integration",
        "test_posix_v2_compat_severity_execution",
        "test_severity_adjudication_work_p0_ag3",
        "test_severity_worker_debt_recovery_p0_ag4",
        "test_snapshot_startup_rewind_r0_8cd",
        "test_spike_mechanical_poc",
        "test_verifier_completion_authority_v2",
        "test_verification_operator_consumers_p0_ai_g",
        "test_verification_report_tail_same_run_integration",
        "test_report_index_summary_parity_successor_a0_a1",
        "test_worker_execution_preimage_authority",
        "test_report_model_preimages",
        "test_report_model_lineage",
        "test_canonical_report_model_lineage",
        "test_report_summary_recovery",
        "test_core_empty_report_entry_integration",
        "test_core_empty_report_assembly_integration",
        "test_worker_execution_receipts",
        "test_worker_process_tree_adversarial_review",
        "test_worker_stdout_output_and_stream_limits",
    }
)

REQUIRED_SLOW_STEMS = REQUIRED_SERIAL_STEMS - {
    # These are serial for process isolation but are not themselves
    # heavyweight (bounded native-helper launches or one bounded Git query).
    "test_darwin_cas_helper",
    "test_p1_dm_phase_io_packaging",
    "test_posix_v2_compat_poc_execution",
    "test_posix_v2_compat_dependency_repair",
    "test_posix_v2_compat_prewarm",
    "test_posix_v2_compat_supply_chain_admission",
    "test_python_packaging_contracts",
    "test_semantic_dedup_applied_authority_p0_qs",
}


def test_posix_v2_compat_modules_are_ignored_before_import_on_windows() -> None:
    assert test_config._platform_collect_ignore_globs("nt") == [
        "test_posix_v2_compat_*.py"
    ]
    assert test_config._platform_collect_ignore_globs("posix") == []


def test_private_quarantine_denominator_is_checkout_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = frozenset(
        {
            "scripts/bounty/test_first.py",
            "scripts/bounty/test_second.py",
        }
    )
    payload = {
        "entries": [{"nodeid": "scripts/test_public.py::test_public"}]
        + [
            {"nodeid": f"{path}::test_private"}
            for path in sorted(private)
        ]
    }
    monkeypatch.setattr(test_config, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        test_config, "_FAST_GOVERNANCE_PRIVATE_SOURCE_PATHS", private
    )

    assert set(test_config._applicable_fast_governance_entries(payload)) == {
        "scripts/test_public.py::test_public"
    }

    first = tmp_path / sorted(private)[0]
    first.parent.mkdir(parents=True)
    first.write_text("", encoding="utf-8")
    with pytest.raises(pytest.UsageError, match="materialization is partial"):
        test_config._applicable_fast_governance_entries(payload)

    second = tmp_path / sorted(private)[1]
    second.write_text("", encoding="utf-8")
    assert set(test_config._applicable_fast_governance_entries(payload)) == {
        row["nodeid"] for row in payload["entries"]
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
