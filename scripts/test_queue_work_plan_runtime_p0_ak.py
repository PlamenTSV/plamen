"""Red runtime fixtures for persisted QueueWorkPlan shadow integration."""
from __future__ import annotations

import inspect
import json
import os
from pathlib import Path

import pytest

import plamen_parsers as P
import plamen_prompt as Prompt
from plamen_types import L1_VERIFY_SHARD_MANIFESTS, SC_VERIFY_SHARD_MANIFESTS
from queue_work_items import QueueWorkPlan, queue_record_set_digest


PLAN_NAME = "verification_queue.work_plan.json"

CASES = (
    (
        "l1",
        L1_VERIFY_SHARD_MANIFESTS,
        P.compute_verify_shards,
        P.ensure_verify_shard_manifests,
    ),
    (
        "sc",
        SC_VERIFY_SHARD_MANIFESTS,
        P.compute_sc_verify_shards,
        P.ensure_sc_verify_shard_manifests,
    ),
)


def _row(number: int, finding_id: str, severity: str, title: str) -> dict[str, str]:
    return {
        "queue #": str(number),
        "finding id": finding_id,
        "expected output file": f"verify_{finding_id}.md",
        "severity": severity,
        "title": title,
        "bug class": "state-transition",
        "preferred tag": "CODE-TRACE",
        "location": f"src/{finding_id}.rs:{number}",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    }


def _rows() -> list[dict[str, str]]:
    # Priority order is intentionally different from ID/severity order.
    return [
        _row(2, "H-01", "High", "High-priority boundary"),
        _row(1, "M-01", "Medium", "Medium state transition"),
        _row(3, "L-01", "Low", "Low consistency issue"),
    ]


def _write_top_queue(scratchpad: Path, rows: list[dict[str, str]]):
    top = scratchpad / "verification_queue.md"
    P._write_queue_subset_manifest(top, rows)
    return P._read_typed_queue_work_items(top)


def _expected_membership(
    typed_items, shards: dict[str, list[dict[str, str]]]
) -> dict[str, tuple[str, ...]]:
    priority = {item.work_item_id: item.queue_priority for item in typed_items}
    return {
        shard_id: tuple(
            sorted(
                (row["finding id"] for row in rows),
                key=lambda work_id: (priority[work_id], work_id.casefold(), work_id),
            )
        )
        for shard_id, rows in shards.items()
    }


@pytest.mark.parametrize("pipeline,manifests,compute,ensure", CASES)
def test_persisted_plan_binds_parent_order_membership_empty_shards_and_ownership(
    tmp_path: Path,
    pipeline: str,
    manifests: dict[str, str],
    compute,
    ensure,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    typed_items = _write_top_queue(scratchpad, _rows())
    shards = compute(scratchpad)

    plan = P._write_or_validate_queue_work_plan(
        scratchpad, typed_items, shards, pipeline
    )
    loaded = P.read_queue_work_plan(scratchpad)

    assert isinstance(plan, QueueWorkPlan)
    assert loaded == plan
    assert plan.parent_record_set_digest == queue_record_set_digest(typed_items)
    assert plan.ordered_work_item_ids == ("M-01", "H-01", "L-01")
    assert {shard.shard_id for shard in plan.shards} == set(manifests)
    assert any(not shard.ordered_work_item_ids for shard in plan.shards)
    assert any(shard.ordered_work_item_ids for shard in plan.shards)
    expected_membership = _expected_membership(typed_items, shards)
    assert {
        shard.shard_id: shard.ordered_work_item_ids for shard in plan.shards
    } == expected_membership
    assert tuple(owner.work_item_id for owner in plan.output_ownership) == (
        "M-01",
        "H-01",
        "L-01",
    )
    assert {owner.expected_output_file for owner in plan.output_ownership} == {
        "verify_M-01.md",
        "verify_H-01.md",
        "verify_L-01.md",
    }
    assert len({owner.expected_output_identity for owner in plan.output_ownership}) == 3
    plan.validate_against(typed_items)


def test_plan_json_write_is_atomic_and_unchanged_input_is_not_rewritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    typed_items = _write_top_queue(scratchpad, _rows())
    shards = P.compute_sc_verify_shards(scratchpad)
    real_replace = os.replace
    replacements: list[tuple[Path, Path]] = []

    def observed_replace(source, destination):
        replacements.append((Path(source), Path(destination)))
        return real_replace(source, destination)

    monkeypatch.setattr(P.os, "replace", observed_replace)
    first = P._write_or_validate_queue_work_plan(
        scratchpad, typed_items, shards, "sc"
    )
    plan_path = scratchpad / PLAN_NAME
    first_bytes = plan_path.read_bytes()
    first_mtime = plan_path.stat().st_mtime_ns
    replacement_count = len(replacements)

    second = P._write_or_validate_queue_work_plan(
        scratchpad, typed_items, shards, "sc"
    )

    assert first == second
    assert plan_path.read_bytes() == first_bytes
    assert plan_path.stat().st_mtime_ns == first_mtime
    assert replacement_count >= 1
    assert replacements[-1][1] == plan_path
    assert len(replacements) == replacement_count, "idempotent plan must not be rewritten"
    assert not list(scratchpad.glob(f".{PLAN_NAME}.*.tmp"))
    assert not list(scratchpad.glob(f"{PLAN_NAME}*.tmp"))


def test_changed_authoritative_queue_rebuilds_plan_with_new_parent_and_plan_digest(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    typed_items = _write_top_queue(scratchpad, _rows())
    shards = P.compute_sc_verify_shards(scratchpad)
    before = P._write_or_validate_queue_work_plan(
        scratchpad, typed_items, shards, "sc"
    )

    changed_rows = [*_rows(), _row(4, "H-02", "High", "Late queue candidate")]
    changed_items = _write_top_queue(scratchpad, changed_rows)
    changed_shards = P.compute_sc_verify_shards(scratchpad)
    after = P._write_or_validate_queue_work_plan(
        scratchpad, changed_items, changed_shards, "sc"
    )

    assert before.parent_record_set_digest != after.parent_record_set_digest
    assert before.digest != after.digest
    assert after.parent_record_set_digest == queue_record_set_digest(changed_items)
    assert "H-02" in after.ordered_work_item_ids
    assert P.read_queue_work_plan(scratchpad) == after


@pytest.mark.parametrize("corruption", ["malformed", "tampered"])
def test_read_rejects_malformed_or_digest_tampered_persisted_plan(
    tmp_path: Path, corruption: str
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    typed_items = _write_top_queue(scratchpad, _rows())
    shards = P.compute_sc_verify_shards(scratchpad)
    plan = P._write_or_validate_queue_work_plan(
        scratchpad, typed_items, shards, "sc"
    )
    path = scratchpad / PLAN_NAME
    if corruption == "malformed":
        path.write_text('{"schema_version":', encoding="utf-8")
    else:
        payload = json.loads(plan.to_json())
        payload["work_plan_digest"] = "0" * 64
        path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises((ValueError, RuntimeError, json.JSONDecodeError)):
        P.read_queue_work_plan(scratchpad)


@pytest.mark.parametrize("pipeline,manifests,compute,ensure", CASES)
def test_ensure_paths_persist_complete_plan_after_all_shard_projections(
    tmp_path: Path,
    pipeline: str,
    manifests: dict[str, str],
    compute,
    ensure,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    typed_items = _write_top_queue(scratchpad, _rows())

    shards = ensure(scratchpad)
    plan = P.read_queue_work_plan(scratchpad)

    assert plan.parent_record_set_digest == queue_record_set_digest(typed_items)
    assert {shard.shard_id for shard in plan.shards} == set(manifests)
    assert {
        shard.shard_id: shard.ordered_work_item_ids for shard in plan.shards
    } == _expected_membership(typed_items, shards)
    for markdown in manifests.values():
        path = scratchpad / markdown
        assert path.is_file()
        assert path.with_suffix(".json").is_file()
        assert path.with_suffix(".work_items.json").is_file()


@pytest.mark.parametrize(
    "ensure_name",
    ["ensure_verify_shard_manifests", "ensure_sc_verify_shard_manifests"],
)
def test_ensure_source_materializes_plan_after_shard_sidecars_before_return(
    ensure_name: str,
):
    source = inspect.getsource(getattr(P, ensure_name))
    shard_write_at = source.index("_write_queue_subset_manifest(")
    plan_at = source.find("_write_or_validate_queue_work_plan(", shard_write_at)
    return_at = source.rfind("return shards")

    assert plan_at >= 0, f"{ensure_name} must persist QueueWorkPlan"
    assert shard_write_at < plan_at < return_at


@pytest.mark.parametrize(
    "pipeline,manifests",
    [("l1", L1_VERIFY_SHARD_MANIFESTS), ("sc", SC_VERIFY_SHARD_MANIFESTS)],
)
def test_verify_prompt_checklist_consumes_persisted_membership_without_repartition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    manifests: dict[str, str],
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    rows = _rows()
    typed_items = _write_top_queue(scratchpad, rows)
    phase_names = list(manifests)
    assert len(phase_names) >= 3
    partitions = {phase_name: [] for phase_name in phase_names}
    by_id = {row["finding id"]: row for row in rows}
    partitions[phase_names[0]] = [by_id["M-01"]]
    partitions[phase_names[1]] = [by_id["H-01"]]
    partitions[phase_names[2]] = [by_id["L-01"]]
    for phase_name, shard_rows in partitions.items():
        P._write_queue_subset_manifest(
            scratchpad / manifests[phase_name], shard_rows
        )
    plan = P._write_or_validate_queue_work_plan(
        scratchpad, typed_items, partitions, pipeline
    )
    assert plan.shard(phase_names[1]).ordered_work_item_ids == ("H-01",)

    def forbidden_repartition(*args, **kwargs):
        raise AssertionError("prompt checklist must not recompute queue partition")

    monkeypatch.setattr(Prompt, "compute_verify_shards", forbidden_repartition)
    monkeypatch.setattr(Prompt, "compute_sc_verify_shards", forbidden_repartition)
    checklist = Prompt._render_verify_shard_checklist(
        {"scratchpad": str(scratchpad), "pipeline": pipeline}, phase_names[1]
    )

    assert "H-01 -> verify_H-01.md" in checklist
    assert "M-01" not in checklist
    assert "L-01" not in checklist
