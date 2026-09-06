"""Focused red/green tests for immutable axis promotion-plan replay.

These fixtures are pure in-process state checks.  They launch no model,
subprocess, network operation, or audit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import axis_disposition as AXIS
from test_axis_repair_promotion_boundary_red_p0_i import (
    _append_unreferenced_base_action_to_repair_source,
    _promotion_fixture,
)


def _resign_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = dict(plan)
    unsigned.pop("plan_digest", None)
    normalized = json.loads(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    digest = hashlib.sha256(
        json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {**normalized, "plan_digest": digest}


def _plan_fixture(
    tmp_path: Path,
) -> tuple[dict[str, Any], bytes, bytes, dict[str, Any]]:
    scratchpad, _config, application, base_findings = _promotion_fixture(
        tmp_path,
        state="EXECUTED",
    )
    repair_findings = (
        scratchpad / "axis_coverage_repair_findings.md"
    ).read_bytes()
    inventory = (scratchpad / "findings_inventory.md").read_bytes()
    plan = AXIS.build_axis_promotion_plan(
        application,
        run_id=str(application["run_id"]),
        base_findings_raw=base_findings,
        repair_findings_raw=repair_findings,
        inventory_raw=inventory,
    )
    return application, inventory, repair_findings, plan


def test_replay_only_validator_accepts_committed_plan_without_live_sources(
    tmp_path: Path,
) -> None:
    application, predecessor, _repair, plan = _plan_fixture(tmp_path)
    successor = predecessor + plan["append_suffix_utf8"].encode("utf-8")

    assert AXIS.validate_axis_promotion_plan_replay(
        plan,
        None,
        run_id=str(application["run_id"]),
        current_inventory_raw=predecessor,
    ) == plan
    assert AXIS.validate_axis_promotion_plan_replay(
        plan,
        None,
        run_id=str(application["run_id"]),
        current_inventory_raw=successor,
    ) == plan


@pytest.mark.parametrize(
    "mutation",
    (
        "application_digest",
        "action_denominator",
        "action_hash",
        "successor_cas",
        "delivery_block_hash",
    ),
)
def test_replay_only_validator_rejects_resigned_semantic_plan_tamper(
    tmp_path: Path,
    mutation: str,
) -> None:
    application, predecessor, _repair, plan = _plan_fixture(
        tmp_path / mutation
    )
    changed = json.loads(json.dumps(plan))
    if mutation == "application_digest":
        changed["application_receipt_digest"] = "a" * 64
    elif mutation == "action_denominator":
        changed["action_ids"] = changed["action_ids"][:-1]
    elif mutation == "action_hash":
        action_id = changed["action_ids"][0]
        changed["action_block_sha256s"][action_id] = "b" * 64
    elif mutation == "successor_cas":
        changed["inventory_successor"]["sha256"] = "c" * 64
    elif mutation == "delivery_block_hash":
        changed["planned_deliveries"][0][
            "inventory_block_sha256"
        ] = "d" * 64
    changed = _resign_plan(changed)

    with pytest.raises(AXIS.AxisDispositionError):
        AXIS.validate_axis_promotion_plan_replay(
            changed,
            application,
            run_id=str(application["run_id"]),
            current_inventory_raw=predecessor,
        )


def test_strict_validator_still_rederives_from_precommit_sources(
    tmp_path: Path,
) -> None:
    application, predecessor, repair_findings, plan = _plan_fixture(tmp_path)

    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)(authority|plan differs|source)",
    ):
        AXIS.validate_axis_promotion_plan(
            plan,
            application,
            run_id=str(application["run_id"]),
            base_findings_raw=b"",
            repair_findings_raw=repair_findings,
            current_inventory_raw=predecessor,
        )


def test_plan_backed_promotion_receipt_needs_no_application_or_sources(
    tmp_path: Path,
) -> None:
    application, predecessor, _repair, plan = _plan_fixture(tmp_path)
    successor = (
        predecessor + plan["append_suffix_utf8"].encode("utf-8")
    )
    inventory_text = successor.decode("utf-8", errors="strict")

    receipt = AXIS.build_axis_promotion_authority(
        None,
        run_id=str(application["run_id"]),
        inventory_text=inventory_text,
        promotion_plan=plan,
    )

    assert receipt["plan_digest"] == plan["plan_digest"]
    assert receipt["application_receipt_digest"] == plan[
        "application_receipt_digest"
    ]
    assert receipt["delivery_count"] == len(plan["action_ids"])
    assert receipt["missing_action_ids"] == []
    assert AXIS.validate_axis_promotion_authority(
        receipt,
        None,
        inventory_text=inventory_text,
        promotion_plan=plan,
    ) == receipt
    later_inventory = (
        inventory_text
        + "\n### Finding [INV-999]: later unrelated candidate\n"
        "**Source IDs**: OTHER:999\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Low\n"
        "**Description**: later unrelated candidate\n"
        "**Impact**: unrelated\n"
    )
    with pytest.raises(
        AXIS.AxisDispositionError,
        match="unauthorized downstream inventory tail",
    ):
        AXIS.validate_axis_promotion_authority(
            receipt,
            None,
            inventory_text=later_inventory,
            promotion_plan=plan,
        )

    changed = dict(receipt)
    changed["plan_digest"] = "e" * 64
    changed = _resign_receipt(changed)
    with pytest.raises(
        AXIS.AxisDispositionError,
        match=r"(?i)(authority differs|plan)",
    ):
        AXIS.validate_axis_promotion_authority(
            changed,
            None,
            inventory_text=inventory_text,
            promotion_plan=plan,
        )


def test_plan_backed_receipt_replays_preexisting_delivery_from_bound_cas(
    tmp_path: Path,
) -> None:
    application, predecessor, repair_findings, first = _plan_fixture(
        tmp_path
    )
    successor = (
        predecessor + first["append_suffix_utf8"].encode("utf-8")
    )
    scratchpad, _config, _same_application, base_findings = (
        _promotion_fixture(tmp_path / "second", state="EXECUTED")
    )
    # The helper is deterministic for this fixture; keep the original
    # application/source pair while replacing only the inventory preimage.
    second = AXIS.build_axis_promotion_plan(
        application,
        run_id=str(application["run_id"]),
        base_findings_raw=base_findings,
        repair_findings_raw=repair_findings,
        inventory_raw=successor,
    )
    assert second["planned_deliveries"] == []
    assert second["preexisting_action_ids"] == second["action_ids"]
    assert second["append_suffix_utf8"] == ""

    receipt = AXIS.build_axis_promotion_authority(
        None,
        run_id=str(application["run_id"]),
        inventory_text=successor.decode("utf-8", errors="strict"),
        promotion_plan=second,
    )
    assert receipt["plan_digest"] == second["plan_digest"]
    assert receipt["delivery_count"] == len(second["action_ids"])
    assert receipt["missing_action_ids"] == []


def _resign_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = dict(receipt)
    unsigned.pop("promotion_receipt_digest", None)
    normalized = json.loads(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    digest = hashlib.sha256(
        json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {**normalized, "promotion_receipt_digest": digest}


def test_cross_source_impostor_is_typed_debt_not_blocking_authority(
    tmp_path: Path,
) -> None:
    scratchpad, _config, application, base_findings = _promotion_fixture(
        tmp_path,
        state="EXECUTED",
    )
    action_id = _append_unreferenced_base_action_to_repair_source(
        scratchpad=scratchpad,
        application=application,
        base_findings=base_findings,
    )
    repair_findings = (
        scratchpad / "axis_coverage_repair_findings.md"
    ).read_bytes()
    inventory = (scratchpad / "findings_inventory.md").read_bytes()

    plan = AXIS.build_axis_promotion_plan(
        application,
        run_id=str(application["run_id"]),
        base_findings_raw=base_findings,
        repair_findings_raw=repair_findings,
        inventory_raw=inventory,
    )
    debt = [
        row for row in plan["source_debt"]
        if row["action_id"] == action_id
    ]

    assert action_id not in plan["blocked_action_ids"]
    assert action_id in {
        row["action_id"] for row in plan["planned_deliveries"]
    }
    assert debt == [
        {
            "action_id": action_id,
            "source": "REPAIR",
            "reason": "CROSS_SOURCE_IMPOSTOR_IGNORED",
            "expected_block_sha256": plan[
                "action_block_sha256s"
            ][action_id],
        }
    ]
    assert plan["status"] == "READY_WITH_DEBT"

    authority = AXIS.build_axis_promotion_authority(
        None,
        run_id=str(application["run_id"]),
        inventory_text=(
            inventory + plan["append_suffix_utf8"].encode("utf-8")
        ).decode("utf-8", errors="strict"),
        promotion_plan=plan,
    )
    assert authority["plan_digest"] == plan["plan_digest"]
    assert authority["source_debt"] == plan["source_debt"]
    assert action_id not in authority["missing_action_ids"]
    assert action_id in {
        row["action_id"] for row in authority["deliveries"]
    }
