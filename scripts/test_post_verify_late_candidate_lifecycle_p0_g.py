"""P0-G: verifier side observations become independently verified work."""
from __future__ import annotations

import json
from contextlib import nullcontext
from pathlib import Path

import mechanical_verify
import plamen_driver as driver
from post_verify_candidate_delta import (
    load_report_candidate_universe,
    write_or_validate_post_verify_candidate_delta,
)
from post_verify_lifecycle import parse_post_verify_candidate_proposals
from queue_work_items import QueueWorkItem, queue_records_to_json


def _write_inputs(tmp_path: Path) -> None:
    (tmp_path / "verify_H-1.md").write_text(
        "# Verify H-1\n\n## Side Findings\nA separate state inconsistency.\n",
        encoding="utf-8",
    )
    (tmp_path / "post_verify_extract.md").write_text(
        "# Post-Verification Extraction Summary\n\n"
        "## Promoted Candidate Records\n\n"
        "### Finding [VER-1]: Separate state inconsistency\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L19\n"
        "**Root Cause**: A distinct transition leaves state inconsistent.\n"
        "**Source Verify File**: verify_H-1.md\n"
        "**Evidence Pointer**: verify_H-1.md#side-findings\n"
        "**Origin Assessment**: SAFE\n",
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-1]: Existing\n"
        "**Severity**: Medium\n"
        "**Location**: src/A.sol:L1\n",
        encoding="utf-8",
    )
    (tmp_path / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---|---|---|---|\n"
        "| 1 | INV-1 | Medium | Existing |\n",
        encoding="utf-8",
    )
    item = QueueWorkItem.from_legacy_row({
        "finding id": "INV-1",
        "severity": "Medium",
        "title": "Existing",
        "location": "src/A.sol:L1",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    })
    (tmp_path / "verification_queue.work_items.json").write_text(
        queue_records_to_json((item,)) + "\n",
        encoding="utf-8",
    )


def test_side_observation_is_active_unverified_work_not_self_certified(
    tmp_path: Path,
) -> None:
    _write_inputs(tmp_path)

    inventory_before = (tmp_path / "findings_inventory.md").read_bytes()
    queue_before = (tmp_path / "verification_queue.work_items.json").read_bytes()
    proposals = parse_post_verify_candidate_proposals(tmp_path)
    derived_id = proposals["proposals"][0]["work_item_id"]
    assert derived_id != "VER-1"
    receipt = write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id="run-1", operator_proposals=()
    )
    assert receipt["rows"][0]["work_item"]["work_item_id"] == derived_id
    assert receipt["terminal_authority"] is False
    assert not (tmp_path / f"verify_{derived_id}.md").exists()
    assert (tmp_path / "findings_inventory.md").read_bytes() == inventory_before
    assert (tmp_path / "verification_queue.work_items.json").read_bytes() == queue_before


def test_late_promotion_is_idempotent(tmp_path: Path) -> None:
    _write_inputs(tmp_path)
    write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id="run-1", operator_proposals=()
    )
    inventory_once = (tmp_path / "findings_inventory.md").read_bytes()
    queue_once = (tmp_path / "verification_queue.work_items.json").read_bytes()
    delta_once = (tmp_path / "post_verify_candidate_delta.json").read_bytes()
    write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id="run-1", operator_proposals=()
    )
    assert (tmp_path / "findings_inventory.md").read_bytes() == inventory_once
    assert (tmp_path / "verification_queue.work_items.json").read_bytes() == queue_once
    assert (tmp_path / "post_verify_candidate_delta.json").read_bytes() == delta_once


def test_missing_source_is_retained_with_repair_debt(tmp_path: Path) -> None:
    _write_inputs(tmp_path)
    (tmp_path / "post_verify_extract.md").write_text(
        "### Finding [VER-2]: Source needs recovery\n"
        "**Severity**: Low\n"
        "**Location**: unresolved\n"
        "**Root Cause**: A substantive candidate remains to be checked.\n"
        "**Source Verify File**: missing.md\n",
        encoding="utf-8",
    )
    proposals = parse_post_verify_candidate_proposals(tmp_path)
    assert proposals["proposal_count"] == 1
    assert "source-repair-required" in proposals["proposals"][0]["evidence_debt"]


def test_live_hook_does_not_self_certify_unreceipted_verifier_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write_inputs(tmp_path)

    def recover(_config, missing):
        for fid, _row in missing:
            (tmp_path / f"verify_{fid}.md").write_text(
                f"# Verify {fid}\n\n**Severity**: High\n"
                "**Verdict**: CONTESTED\n**Evidence Tag**: [CODE-TRACE]\n"
                "**Location**: src/Vault.sol:L19\n"
                "**Description**: Independent analysis checked the separate "
                "state-transition claim and retained it as contested.\n",
                encoding="utf-8",
            )
        return []

    monkeypatch.setattr(driver, "_run_verify_recovery_shard", recover)
    monkeypatch.setattr(driver, "_phase_heartbeat_thread", lambda *_a, **_k: nullcontext())
    monkeypatch.setattr(
        mechanical_verify,
        "run_phase5b_mechanical_verify",
        lambda *_a, **_k: {"status": "ok"},
    )
    result = driver._route_post_verify_late_candidates(
        {
            "scratchpad": str(tmp_path),
            "project_root": str(tmp_path),
            "language": "evm",
            "pipeline": "sc",
            "mode": "thorough",
            "_run_id": "run-1",
        }
    )
    derived_id = parse_post_verify_candidate_proposals(
        tmp_path
    )["proposals"][0]["work_item_id"]
    assert result == {
        "promoted": [derived_id],
        "verified": [],
        "unresolved": [derived_id],
    }
    assert {row.item.work_item_id for row in load_report_candidate_universe(
        tmp_path, run_id="run-1"
    )} == {"INV-1", derived_id}
    delivery = json.loads(
        (tmp_path / "post_verify_late_delivery.json").read_text(encoding="utf-8")
    )
    assert delivery["rows"][0]["delivery_state"] == "UNVERIFIED_HUMAN_REVIEW"
    authority = json.loads(
        (tmp_path / "post_verify_late_verification_authority.json").read_text(
            encoding="utf-8"
        )
    )
    assert authority["terminal_negative_authority"] is False
    assert authority["rows"][0]["evidence_authority"] == "NONE"
    assert any(
        debt["debt_code"] == "LATE_RECOVERY_EVIDENCE_MISSING"
        for debt in authority["debts"]
    )


def test_live_hook_failed_recovery_remains_unverified_human_review(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write_inputs(tmp_path)
    monkeypatch.setattr(
        driver,
        "_run_verify_recovery_shard",
        lambda _config, missing: [fid for fid, _row in missing],
    )
    monkeypatch.setattr(driver, "_phase_heartbeat_thread", lambda *_a, **_k: nullcontext())
    result = driver._route_post_verify_late_candidates(
        {
            "scratchpad": str(tmp_path),
            "project_root": str(tmp_path),
            "language": "evm",
            "pipeline": "sc",
            "mode": "thorough",
            "_run_id": "run-1",
        }
    )
    derived_id = parse_post_verify_candidate_proposals(
        tmp_path
    )["proposals"][0]["work_item_id"]
    assert result["verified"] == []
    assert result["unresolved"] == [derived_id]
    verify = (tmp_path / f"verify_{derived_id}.md").read_text(encoding="utf-8")
    assert "Verdict**: UNVERIFIED" in verify
    assert "HUMAN REVIEW REQUIRED" in verify
