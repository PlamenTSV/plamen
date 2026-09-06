"""Fixture-first contracts for the P0-AK dynamic verifier roster.

The legacy QueueWorkPlan can contain fixed, oversized phase shards.  These
fixtures require a second, backend-neutral runtime roster which treats those
shards only as tier membership and emits as many bounded child transactions as
the queue requires.  No fixture launches a model process.
"""
from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from plamen_types import L1_VERIFY_SHARD_MANIFESTS, SC_VERIFY_SHARD_MANIFESTS
from queue_work_items import QueueWorkItem, build_queue_work_plan
from verifier_work_roster import (
    DEFAULT_MAX_FINDINGS_PER_VERIFIER,
    VerifierRosterError,
    VerifierUnitReceipt,
    build_verifier_runtime_policy,
    build_verifier_work_roster,
    build_verifier_launch_spec,
    compile_verifier_transaction_phase_roster,
    plan_verifier_work_roster_haltless,
    prepare_verifier_work_roster_haltless,
    reconcile_verifier_work_roster,
    write_or_validate_verifier_work_roster,
)


def _item(index: int, severity: str = "Low", *, path: str | None = None) -> QueueWorkItem:
    finding_id = f"F-{index:04d}"
    row = {
        "queue #": str(index),
        "finding id": finding_id,
        "expected output file": f"verify_{finding_id}.md",
        "severity": severity,
        "title": f"Candidate {index}",
        "bug class": "state-transition",
        "preferred tag": "CODE-TRACE",
        "location": path or f"src/Candidate{index}.sol:{index}",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    }
    return QueueWorkItem.from_legacy_row(row)


def _fixed_slot_plan(
    count: int,
    pipeline: str,
    *,
    severity: str = "Low",
    path: str | None = None,
):
    items = tuple(_item(index + 1, severity, path=path) for index in range(count))
    manifests = (
        SC_VERIFY_SHARD_MANIFESTS if pipeline == "sc" else L1_VERIFY_SHARD_MANIFESTS
    )
    partitions = {name: [] for name in manifests}
    low_slots = [name for name in manifests if "_low_" in name]
    # Deliberately reproduce the dangerous fixed-slot fallback: every row is
    # legal queue-plan membership, but the final legacy phase is oversized.
    partitions[low_slots[-1]] = [item.work_item_id for item in items]
    return items, build_queue_work_plan(
        items,
        partitions,
        planner_version="fixture.fixed_slots.v1",
    )


def _policy(
    backend: str = "claude",
    *,
    transport: str | None = None,
    source_root: str = "/audit/source",
):
    return build_verifier_runtime_policy(
        backend=backend,
        model="claude-opus-4-6" if backend == "claude" else "gpt-5.4",
        timeout_seconds=3600,
        max_concurrency=4,
        source_root=source_root,
        transport=transport,
    )


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
@pytest.mark.parametrize("count", [5, 40, 41, 148])
def test_dynamic_roster_never_compresses_overflow_into_last_worker(
    pipeline: str, count: int
) -> None:
    _items, queue_plan = _fixed_slot_plan(count, pipeline)
    roster = build_verifier_work_roster(
        queue_plan,
        pipeline=pipeline,
        ecosystem="evm" if pipeline == "sc" else "rust-l1",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )

    assert DEFAULT_MAX_FINDINGS_PER_VERIFIER == 4
    assert len(roster.work_units) == math.ceil(count / 4)
    assert max(len(unit.ordered_work_item_ids) for unit in roster.work_units) <= 4
    assert tuple(
        work_id for unit in roster.work_units for work_id in unit.ordered_work_item_ids
    ) == queue_plan.ordered_work_item_ids
    assert len(
        {
            work_id
            for unit in roster.work_units
            for work_id in unit.ordered_work_item_ids
        }
    ) == count
    assert all("overflow" not in unit.work_unit_id for unit in roster.work_units)


@pytest.mark.parametrize("count", [0, 1, 4])
def test_zero_and_boundary_rosters_are_exact(count: int) -> None:
    _items, queue_plan = _fixed_slot_plan(count, "sc")
    roster = build_verifier_work_roster(
        queue_plan,
        pipeline="sc",
        ecosystem="soroban",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    assert len(roster.work_units) == (0 if count == 0 else 1)
    assert roster.ordered_work_item_ids == queue_plan.ordered_work_item_ids


def test_verifier_transaction_roster_requires_exact_runtime_membership() -> None:
    _items, queue_plan = _fixed_slot_plan(5, "sc")
    roster = build_verifier_work_roster(
        queue_plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    plan_digests = {
        unit.work_unit_id: f"{index:x}" * 64
        for index, unit in enumerate(roster.work_units, start=1)
    }
    transaction_roster = compile_verifier_transaction_phase_roster(
        roster,
        run_id="run-1",
        phase="verify",
        generation=1,
        work_plan_digests=plan_digests,
    )
    assert transaction_roster["required_work_unit_ids"] == sorted(plan_digests)
    assert transaction_roster["work_plan_digests"] == {
        key: plan_digests[key] for key in sorted(plan_digests)
    }

    with pytest.raises(VerifierRosterError, match="exact verifier roster"):
        compile_verifier_transaction_phase_roster(
            roster,
            run_id="run-1",
            phase="verify",
            generation=1,
            work_plan_digests={
                **plan_digests,
                "verify-foreign-0001": "f" * 64,
            },
        )


def test_mixed_tiers_are_independent_bounded_pools() -> None:
    items = tuple(
        _item(index, severity)
        for index, severity in enumerate(
            ["Critical", "High", "High", "Medium", "Medium", "Low", "Informational"],
            start=1,
        )
    )
    partitions = {
        "sc_verify_crithigh": [item.work_item_id for item in items[:3]],
        "sc_verify_medium_a": [item.work_item_id for item in items[3:5]],
        "sc_verify_low_a": [item.work_item_id for item in items[5:]],
    }
    queue_plan = build_queue_work_plan(
        items, partitions, planner_version="fixture.mixed.v1"
    )
    roster = build_verifier_work_roster(
        queue_plan,
        pipeline="sc",
        ecosystem="evm",
        mode="core",
        runtime_policy=_policy(),
        method_registry_digest="3" * 64,
        context_packet_digest="4" * 64,
    )

    assert [unit.tier_pool for unit in roster.work_units] == [
        "critical_high",
        "medium",
        "low_info",
    ]
    assert [len(unit.ordered_work_item_ids) for unit in roster.work_units] == [3, 2, 2]


def test_exact_resume_preserves_identity_order_digests_and_file_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _items, queue_plan = _fixed_slot_plan(41, "sc")
    kwargs = dict(
        pipeline="sc",
        ecosystem="solana",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="5" * 64,
        context_packet_digest="6" * 64,
    )
    first = build_verifier_work_roster(queue_plan, **kwargs)
    second = build_verifier_work_roster(queue_plan, **kwargs)

    assert first == second
    assert first.to_json() == second.to_json()
    assert first.assignment_digest == second.assignment_digest
    assert first.digest == second.digest
    assert tuple(unit.resume_digest for unit in first.work_units) == tuple(
        unit.resume_digest for unit in second.work_units
    )

    path = tmp_path / "verification_runtime_roster.json"
    replacements: list[tuple[Path, Path]] = []
    real_replace = os.replace

    def observed_replace(source, destination):
        replacements.append((Path(source), Path(destination)))
        return real_replace(source, destination)

    monkeypatch.setattr("verifier_work_roster.os.replace", observed_replace)
    write_or_validate_verifier_work_roster(path, first)
    original = path.read_bytes()
    replacement_count = len(replacements)
    write_or_validate_verifier_work_roster(path, second)
    assert path.read_bytes() == original
    assert len(replacements) == replacement_count


def test_late_append_invalidates_only_the_affected_tail_unit() -> None:
    _items5, plan5 = _fixed_slot_plan(5, "sc")
    _items6, plan6 = _fixed_slot_plan(6, "sc")
    kwargs = dict(
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="5" * 64,
        context_packet_digest="6" * 64,
    )
    before = build_verifier_work_roster(plan5, **kwargs)
    after = build_verifier_work_roster(plan6, **kwargs)

    assert before.work_units[0].ordered_work_item_ids == after.work_units[0].ordered_work_item_ids
    assert before.work_units[0].resume_digest == after.work_units[0].resume_digest
    assert before.work_units[1].resume_digest != after.work_units[1].resume_digest
    assert after.work_units[1].ordered_work_item_ids == ("F-0005", "F-0006")


def test_severity_move_preserves_untouched_sibling_unit_resume_authority() -> None:
    items = tuple(_item(index) for index in range(1, 9))
    before_plan = build_queue_work_plan(
        items,
        {"sc_verify_low_a": [item.work_item_id for item in items]},
        planner_version="fixture.before-move.v1",
    )
    moved_items = tuple(
        _item(index, "Medium" if index == 5 else "Low") for index in range(1, 9)
    )
    after_plan = build_queue_work_plan(
        moved_items,
        {
            "sc_verify_medium_a": ["F-0005"],
            "sc_verify_low_a": [
                item.work_item_id for item in moved_items if item.work_item_id != "F-0005"
            ],
        },
        planner_version="fixture.after-move.v1",
    )
    kwargs = dict(
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="5" * 64,
        context_packet_digest="6" * 64,
    )
    before = build_verifier_work_roster(before_plan, **kwargs)
    after = build_verifier_work_roster(after_plan, **kwargs)
    before_first = before.work_unit("verify-low-info-0001")
    after_first = after.work_unit("verify-low-info-0001")

    assert before_first.ordered_work_item_ids == ("F-0001", "F-0002", "F-0003", "F-0004")
    assert after_first.ordered_work_item_ids == before_first.ordered_work_item_ids
    assert after_first.resume_digest == before_first.resume_digest
    assert after.work_unit("verify-medium-0001").ordered_work_item_ids == ("F-0005",)


def test_corrupt_persisted_roster_is_retained_as_visible_debt(tmp_path: Path) -> None:
    _items, queue_plan = _fixed_slot_plan(5, "sc")
    path = tmp_path / "verification_runtime_roster.json"
    corrupt = b'{"schema_version":'
    path.write_bytes(corrupt)
    outcome = prepare_verifier_work_roster_haltless(
        path,
        queue_plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="5" * 64,
        context_packet_digest="6" * 64,
    )
    assert outcome.roster is None
    assert outcome.debts[0].reason_class == "ROSTER_PERSISTENCE_FAILURE"
    assert outcome.debts[0].affected_work_item_ids == queue_plan.ordered_work_item_ids
    assert path.read_bytes() == corrupt, "corruption must not be silently overwritten"


@pytest.mark.parametrize(
    "source_root",
    [r"D:\\Programming\\Web3\\Audit Source", "/srv/audits/project source"],
)
def test_windows_and_posix_roots_round_trip_without_host_dependent_rewrite(
    source_root: str,
) -> None:
    _items, queue_plan = _fixed_slot_plan(5, "sc", path=source_root + "/X.sol:7")
    policy = _policy(source_root=source_root)
    roster = build_verifier_work_roster(
        queue_plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=policy,
        method_registry_digest="7" * 64,
        context_packet_digest="8" * 64,
    )
    loaded = type(roster).from_json(roster.to_json())
    assert loaded.runtime_policy.source_root == source_root
    spec = build_verifier_launch_spec(
        loaded,
        loaded.work_units[0].work_unit_id,
        prompt_bytes=b"bound verifier prompt\n",
    )
    assert source_root in spec.argv
    assert spec.cwd == source_root


def test_claude_headless_pty_and_codex_share_semantic_assignment() -> None:
    _items, queue_plan = _fixed_slot_plan(5, "l1")
    rosters = []
    for backend, transport in (
        ("claude", "headless"),
        ("claude", "pty"),
        ("codex", "exec"),
    ):
        rosters.append(
            build_verifier_work_roster(
                queue_plan,
                pipeline="l1",
                ecosystem="go-l1",
                mode="thorough",
                runtime_policy=_policy(backend, transport=transport),
                method_registry_digest="9" * 64,
                context_packet_digest="a" * 64,
            )
        )

    assert len({roster.assignment_digest for roster in rosters}) == 1
    assert len(
        {
            tuple((unit.work_unit_id, unit.row_set_digest) for unit in roster.work_units)
            for roster in rosters
        }
    ) == 1
    assert len({roster.digest for roster in rosters}) == 3

    for roster in rosters:
        policy = roster.runtime_policy
        assert policy.timeout_seconds == 3600
        assert policy.max_concurrency == 4
        assert policy.max_prompt_bytes == 262_144
        assert policy.foreground_only is True
        assert policy.background_children_allowed is False
        assert policy.child_join_policy == "REQUIRE_JOIN_BEFORE_RECEIPT"
        assert policy.process_group_policy == "ISOLATED_PROCESS_GROUP"
        assert policy.orphan_policy == "TERMINATE_TREE_AND_RETAIN_DEBT"
        assert {"Task", "Agent"}.issubset(policy.tool_policy.denied_tools)
        spec = build_verifier_launch_spec(
            roster,
            roster.work_units[0].work_unit_id,
            prompt_bytes=b"same semantic verifier prompt\n",
        )
        loaded_spec = type(spec).from_json(spec.to_json())
        assert loaded_spec == spec
        assert loaded_spec.digest == spec.digest
        assert spec.foreground_only is True
        assert spec.background_children_allowed is False
        assert spec.process_group_policy == "ISOLATED_PROCESS_GROUP"
        assert spec.orphan_policy == "TERMINATE_TREE_AND_RETAIN_DEBT"
        assert spec.timeout_seconds == 3600
        assert spec.expected_output_files == roster.work_units[0].expected_output_files
        if policy.backend == "claude":
            assert "--disallowedTools" in spec.argv
            assert "--strict-mcp-config" in spec.argv
            model_at = spec.argv.index("--model")
            assert spec.argv[model_at + 1] == policy.model
            if policy.transport == "headless":
                output_at = spec.argv.index("--output-format")
                assert spec.argv[output_at + 1] == "stream-json"
                assert "--verbose" in spec.argv
                assert "--session-id" in spec.argv
                assert "--no-session-persistence" in spec.argv
        else:
            assert spec.argv[:2] == ("codex", "exec")
            assert spec.argv[-1] == "-"


def test_planner_failure_becomes_visible_debt_without_oversized_fallback() -> None:
    items = tuple(_item(index) for index in range(1, 6))
    queue_plan = build_queue_work_plan(
        items,
        {"mystery_verify_pool": [item.work_item_id for item in items]},
        planner_version="fixture.bad-tier.v1",
    )
    outcome = plan_verifier_work_roster_haltless(
        queue_plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="b" * 64,
        context_packet_digest="c" * 64,
    )
    assert outcome.roster is None
    assert len(outcome.debts) == 1
    assert outcome.debts[0].reason_class == "PLANNER_FAILURE"
    assert outcome.debts[0].affected_work_item_ids == queue_plan.ordered_work_item_ids
    assert "oversized" not in outcome.debts[0].fallback_action.lower()


def test_partial_completion_and_rate_limit_remain_exact_unit_debt() -> None:
    _items, queue_plan = _fixed_slot_plan(5, "sc")
    roster = build_verifier_work_roster(
        queue_plan,
        pipeline="sc",
        ecosystem="aptos",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="d" * 64,
        context_packet_digest="e" * 64,
    )
    first, second = roster.work_units
    receipts = (
        VerifierUnitReceipt.completed_for(
            first,
            launch_spec_digest="1" * 64,
            output_receipt_digests=tuple(
                f"{index:x}" * 64
                for index in range(2, 2 + len(first.expected_output_files))
            ),
            gate_receipt_digests=("3" * 64,),
        ),
        VerifierUnitReceipt.debt_for(second, reason_class="RATE_LIMIT"),
    )
    status = reconcile_verifier_work_roster(roster, receipts)
    assert status.completed_work_unit_ids == (first.work_unit_id,)
    assert status.pending_work_unit_ids == (second.work_unit_id,)
    assert status.state == "COMPLETED_WITH_DEBT"
    assert status.debts[0].affected_work_item_ids == second.ordered_work_item_ids
    assert status.debts[0].fallback_action == "RETRY_EXACT_WORK_UNIT"
    assert max(
        len(roster.work_unit(unit_id).ordered_work_item_ids)
        for unit_id in status.pending_work_unit_ids
    ) <= 4


def test_custom_capacity_and_complexity_weight_never_overfill() -> None:
    _items, queue_plan = _fixed_slot_plan(5, "sc")
    weights = {work_id: (3 if work_id == "F-0002" else 1) for work_id in queue_plan.ordered_work_item_ids}
    roster = build_verifier_work_roster(
        queue_plan,
        pipeline="sc",
        ecosystem="sui",
        mode="thorough",
        runtime_policy=_policy(),
        method_registry_digest="f" * 64,
        context_packet_digest="0" * 64,
        max_findings_per_verifier=3,
        max_complexity_weight=3,
        complexity_weights=weights,
    )
    assert all(len(unit.ordered_work_item_ids) <= 3 for unit in roster.work_units)
    assert all(unit.complexity_weight <= 3 for unit in roster.work_units)
    assert roster.ordered_work_item_ids == queue_plan.ordered_work_item_ids


def test_prompt_size_ceiling_refuses_launch_without_repacking_rows() -> None:
    _items, queue_plan = _fixed_slot_plan(5, "sc")
    roster = build_verifier_work_roster(
        queue_plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=build_verifier_runtime_policy(
            backend="claude",
            model="claude-opus-4-6",
            timeout_seconds=3600,
            max_concurrency=4,
            max_prompt_bytes=32,
            source_root="/audit/source",
        ),
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    with pytest.raises(VerifierRosterError, match="max_prompt_bytes"):
        build_verifier_launch_spec(
            roster,
            roster.work_units[0].work_unit_id,
            prompt_bytes=b"x" * 33,
        )
    assert max(len(unit.ordered_work_item_ids) for unit in roster.work_units) <= 4
