from __future__ import annotations

import json
from pathlib import Path

import pytest

import inventory_reemit_authority as R
from inventory_reconciliation import reconcile_inventory, write_inventory_reconciliation
import plamen_driver as D
import plamen_validators as V
from artifact_ledger import read_artifact_ledger
from plamen_types import Checkpoint, SC_PHASES


def _finding(fid: str, title: str) -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L10\n"
        f"**Root Cause**: exact root for {title}\n"
        f"**Description**: exact description for {title}\n"
        f"**Impact**: exact impact for {title}\n"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
    )


def _manifest(root: Path, *sources: str) -> None:
    (root / "inventory_chunk_a.manifest.md").write_text(
        "# manifest\n\n| File | Signals |\n|---|---|\n"
        + "".join(f"| {source} | 1 |\n" for source in sources),
        encoding="utf-8",
    )


def _chunk(root: Path, rows: list[tuple[str, str, tuple[str, ...]]]) -> None:
    text = "# Chunk\n\n"
    for fid, title, sources in rows:
        text += _finding(fid, title).replace(
            "**Verdict**: NEEDS_VERIFICATION\n",
            f"**Source IDs**: {', '.join(sources)}\n"
            "**Verdict**: NEEDS_VERIFICATION\n",
        )
    (root / "findings_inventory_chunk_a.md").write_text(text, encoding="utf-8")


def _inventory(root: Path, rows: list[tuple[str, str, tuple[str, ...]]]) -> None:
    text = "# Finding Inventory\n\n## Findings\n\n"
    for fid, title, sources in rows:
        text += _finding(fid, title).replace(
            "**Verdict**: NEEDS_VERIFICATION\n",
            f"**Source IDs**: {', '.join(sources)}\n"
            "**Verdict**: NEEDS_VERIFICATION\n",
        )
    (root / "findings_inventory.md").write_text(text, encoding="utf-8")


def test_semantically_rewritten_candidate_is_additively_reemitted_and_replays(
    tmp_path: Path,
) -> None:
    (tmp_path / "analysis_evm_a.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(tmp_path, "analysis_evm_a.md")
    _chunk(tmp_path, [("CC-1", "source mechanism", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "rewritten mechanism", ("TF-1", "CC-1"))])
    assert reconcile_inventory(tmp_path)["summary"]["HUMAN_REVIEW_DEBT"] == 1

    receipt = R._apply_inventory_reemit_repair_for_tests(tmp_path)

    assert receipt["status"] == "APPLIED"
    assert len(receipt["rows"]) == 1
    assert reconcile_inventory(tmp_path)["summary"]["HUMAN_REVIEW_DEBT"] == 0
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "exact root for source mechanism" in inventory
    assert "exact impact for source mechanism" in inventory
    assert "INDEPENDENT_VERIFICATION_REQUIRED" in inventory
    inputs = D._inventory_reconciliation_input_paths(
        tmp_path, reconcile_inventory(tmp_path)
    )
    assert "inventory_reemit_intent.json" in inputs
    assert "inventory_reemit_receipt.json" in inputs
    assert R._apply_inventory_reemit_repair_for_tests(tmp_path) == receipt


def test_reemit_contains_source_sibling_headings_inside_one_target_block(
    tmp_path: Path,
) -> None:
    """DODO regression: H3 analysis sections cannot truncate an INV block."""
    source = (
        "## Finding [TF-1]: source with analysis sections\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L10\n"
        "**Root Cause**: exact nested-heading root\n"
        "**Description**: exact nested-heading description\n"
        "**Impact**: exact nested-heading impact\n"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
        "### Precondition Analysis\n\n"
        "The attacker controls `amount`.\n\n"
        "### Postcondition Analysis\n\n"
        "The affected balance is reduced.\n"
    )
    (tmp_path / "analysis_evm_a.md").write_text(source, encoding="utf-8")
    _manifest(tmp_path, "analysis_evm_a.md")
    _chunk(tmp_path, [("CC-1", "source with analysis sections", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "rewritten mechanism", ("TF-1", "CC-1"))])

    receipt = R._apply_inventory_reemit_repair_for_tests(tmp_path)
    replay = reconcile_inventory(tmp_path)

    assert receipt["status"] == "APPLIED"
    assert replay["summary"]["HUMAN_REVIEW_DEBT"] == 0
    target_id = receipt["rows"][0]["target_finding_id"]
    blocks, block_issues = R._canonical_blocks(tmp_path / "findings_inventory.md")
    assert block_issues == []
    target = next(
        row
        for row in blocks
        if row["finding_id"] == target_id
    )
    assert target["block_sha256"] == receipt["rows"][0]["target_block_sha256"]
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "### Precondition Analysis" in inventory
    assert "### Postcondition Analysis" in inventory


def test_many_to_one_collapse_reemits_each_candidate_independently(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_a.md").write_text(
        _finding("TF-1", "mechanism A"), encoding="utf-8"
    )
    (tmp_path / "analysis_evm_b.md").write_text(
        _finding("RSW-2", "mechanism B"), encoding="utf-8"
    )
    _manifest(tmp_path, "analysis_evm_a.md", "analysis_evm_b.md")
    _chunk(tmp_path, [("CC-1", "combined", ("TF-1", "RSW-2"))])
    _inventory(tmp_path, [("INV-001", "combined", ("TF-1", "RSW-2", "CC-1"))])
    assert reconcile_inventory(tmp_path)["summary"]["HUMAN_REVIEW_DEBT"] == 2

    receipt = R._apply_inventory_reemit_repair_for_tests(tmp_path)
    replay = reconcile_inventory(tmp_path)

    assert len(receipt["rows"]) == 2
    assert replay["summary"]["HUMAN_REVIEW_DEBT"] == 0
    assert len({row["target_finding_id"] for row in receipt["rows"]}) == 2
    assert all(
        row["reemit_authority_artifact"] == "inventory_reemit_receipt.json"
        for row in replay["candidates"]
    )


def test_crash_after_inventory_replace_resumes_without_duplicate_reemit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "analysis_evm_a.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(tmp_path, "analysis_evm_a.md")
    _chunk(tmp_path, [("CC-1", "source mechanism", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "rewritten mechanism", ("TF-1", "CC-1"))])
    original = R._write_receipt

    def crash(_root: Path, _intent: dict[str, object]) -> dict[str, object]:
        raise OSError("injected receipt crash")

    monkeypatch.setattr(R, "_write_receipt", crash)
    with pytest.raises(OSError, match="injected receipt crash"):
        R._apply_inventory_reemit_repair_for_tests(tmp_path)
    after_crash = (tmp_path / "findings_inventory.md").read_bytes()
    assert (tmp_path / R.INTENT_FILE).is_file()
    assert not (tmp_path / "inventory_reemit_receipt.json").exists()

    monkeypatch.setattr(R, "_write_receipt", original)
    receipt = R._apply_inventory_reemit_repair_for_tests(tmp_path)

    assert (tmp_path / "findings_inventory.md").read_bytes() == after_crash
    assert len(receipt["rows"]) == 1
    assert reconcile_inventory(tmp_path)["summary"]["HUMAN_REVIEW_DEBT"] == 0


def test_stale_reemit_receipt_cannot_hide_later_inventory_drift(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_a.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(tmp_path, "analysis_evm_a.md")
    _chunk(tmp_path, [("CC-1", "source mechanism", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "rewritten mechanism", ("TF-1", "CC-1"))])
    R._apply_inventory_reemit_repair_for_tests(tmp_path)
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text(
        inventory.read_text(encoding="utf-8").replace(
            "exact impact for source mechanism", "changed impact"
        ),
        encoding="utf-8",
    )

    replay = write_inventory_reconciliation(tmp_path)

    assert replay["summary"]["HUMAN_REVIEW_DEBT"] >= 1
    assert any("inventory bytes are stale" in issue for issue in replay["artifact_issues"])


def test_no_debt_does_not_create_transaction_artifacts(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_a.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(tmp_path, "analysis_evm_a.md")
    _chunk(tmp_path, [("CC-1", "source mechanism", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "source mechanism", ("TF-1", "CC-1"))])

    result = R._apply_inventory_reemit_repair_for_tests(tmp_path)

    assert result["status"] == "NO_DEBT"
    assert not (tmp_path / R.INTENT_FILE).exists()
    assert not (tmp_path / "inventory_reemit_receipt.json").exists()


def test_reemit_with_missing_or_novel_source_severity_keeps_core_verify_route(
    tmp_path: Path,
) -> None:
    source = _finding("TF-1", "source mechanism").replace(
        "**Severity**: Medium\n", "**Severity**: Unranked\n"
    )
    (tmp_path / "analysis_evm_a.md").write_text(source, encoding="utf-8")
    _manifest(tmp_path, "analysis_evm_a.md")
    _chunk(tmp_path, [("CC-1", "source mechanism", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "rewritten mechanism", ("TF-1", "CC-1"))])

    R._apply_inventory_reemit_repair_for_tests(tmp_path)

    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    marker = inventory.index("[RECONCILIATION-REEMIT]")
    reemitted = inventory[inventory.rfind("### Finding", 0, marker) :]
    assert "**Severity**: Medium" in reemitted
    assert "**Delivery State**: INDEPENDENT_VERIFICATION_REQUIRED" in reemitted


def test_reemit_is_bound_as_driver_merge_before_reconciliation_phaseio(
    tmp_path: Path,
) -> None:
    run_id = "33456789-1234-4234-8234-123456789abc"
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (sp / "analysis_evm_a.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(sp, "analysis_evm_a.md")
    Checkpoint(run_id=run_id).save(sp)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": run_id,
    }
    phase = next(item for item in SC_PHASES if item.name == "inventory")
    chunk_phase = next(
        item for item in SC_PHASES if item.name == "inventory_chunk_a"
    )
    assert D._bind_typed_model_phase_inputs(chunk_phase, sp, config) == []
    _chunk(sp, [("CC-1", "rewritten mechanism", ("TF-1",))])
    assert D._record_typed_model_phase_artifacts(
        chunk_phase, sp, config
    ) == []
    assert D._record_inventory_reconciliation_phase_io_named(
        scratchpad=sp,
        config=config,
        phase_name="inventory_chunk_a",
        timeout_s=60,
    ) == []
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=sp,
        config=config,
        phase=phase,
        derivation_kind="single_shard",
    )
    assert issues == []

    assert D._record_inventory_reconciliation_phase_io(
        scratchpad=sp, config=config, phase=phase
    ) == []

    ledger = read_artifact_ledger(sp)
    merge = ledger["work_units"][
        "sc/thorough/evm/claude/inventory/additive_reemit"
    ]
    assert set(merge["artifacts"]) == {
        "scratchpad:inventory_reemit_intent.json",
        "scratchpad:inventory_reemit_receipt.json",
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:_id_ledger.json",
    }
    assert all(
        row["writer"] == "DRIVER" for row in merge["artifacts"].values()
    )
    assert merge["artifacts"]["scratchpad:findings_inventory.md"][
        "write_mode"
    ] == "MERGE"
