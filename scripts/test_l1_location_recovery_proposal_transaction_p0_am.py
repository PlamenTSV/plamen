"""L1 location recovery is MODEL proposal -> DRIVER canonical projection."""
from __future__ import annotations

import json
from pathlib import Path

import plamen_driver as D
from phase_io_contracts import resolve_phase_io_contract


def _config(root: Path, *, backend: str = "codex") -> dict:
    return {
        "pipeline": "l1",
        "mode": "thorough",
        "language": "rust",
        "cli_backend": backend,
        "project_root": str(root),
        "scratchpad": str(root),
        "_run_id": "run-location-recovery",
    }


def _seed(root: Path) -> None:
    (root / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: one\n"
        "**Location**: missing.rs:7\n"
        "**Source IDs**: [L1-1]\n\n"
        "### Finding [INV-002]: two\n"
        "**Location**: src/ok.rs:9\n"
        "**Source IDs**: [L1-2]\n",
        encoding="utf-8",
    )
    (root / "inventory_evidence_validation.md").write_text(
        "# Evidence\n", encoding="utf-8"
    )
    (root / "scip").mkdir()
    (root / "scip" / "repo_map.md").write_text(
        "# Repo\n\n`src/real.rs:11`\n", encoding="utf-8"
    )


def test_location_recovery_phaseio_separates_model_and_driver_writers() -> None:
    model = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="location_recovery",
        work_unit_id="worker.location_recovery",
        exact_outputs=("location_recovery_proposals.md",),
    )
    assert model.outputs[0].writer == "MODEL"
    assert model.immutable_inputs == (
        "scratchpad:_location_recovery_inventory_preimage.md",
        "scratchpad:_location_recovery_worklist.json",
    )
    reconcile = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="location_recovery",
        work_unit_id="reconcile",
        exact_outputs=("location_recovery.md",),
    )
    assert reconcile.outputs[0].writer == "DRIVER"
    assert reconcile.immutable_inputs == (
        "scratchpad:_location_recovery_worklist.json",
        "scratchpad:location_recovery_proposals.md",
    )


def test_worklist_exactly_contains_unresolved_inventory_ids(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _seed(tmp_path)
    monkeypatch.setattr(
        D,
        "_validate_inventory_evidence",
        lambda *_args, **_kw: {
            "INV-001": {
                "location_status": "UNRESOLVED",
                "location": "missing.rs:7",
                "source_status": "OK",
            },
            "INV-002": {
                "location_status": "OK",
                "location": "src/ok.rs:9",
                "source_status": "OK",
            },
        },
    )
    issues = D._run_l1_location_recovery_worklist_transaction(
        tmp_path, _config(tmp_path)
    )
    assert issues == []
    data = json.loads(
        (tmp_path / "_location_recovery_worklist.json").read_text()
    )
    assert data["expected_finding_ids"] == ["INV-001"]
    assert data["rows"][0]["finding_id"] == "INV-001"
    assert (
        tmp_path / "_location_recovery_inventory_preimage.md"
    ).read_bytes() == (tmp_path / "findings_inventory.md").read_bytes()


def test_reconcile_preserves_exact_denominator_and_downgrades_invalid_claims(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _seed(tmp_path)
    worklist = {
        "schema": "plamen.l1_location_recovery_worklist.v1",
        "expected_finding_ids": ["INV-001", "INV-003"],
        "rows": [
            {"finding_id": "INV-001", "location": "missing.rs:7"},
            {"finding_id": "INV-003", "location": "also-missing.rs:1"},
        ],
    }
    (tmp_path / "_location_recovery_worklist.json").write_text(
        json.dumps(worklist), encoding="utf-8"
    )
    (tmp_path / "location_recovery_proposals.md").write_text(
        "| Finding ID | Verdict | New Location | Evidence |\n"
        "|---|---|---|---|\n"
        "| INV-001 | RECOVERED | fake.rs:99 | guessed |\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        D,
        "_resolve_inventory_location",
        lambda _root, _index, loc: (
            ("UNRESOLVED", None, "not found")
            if "fake.rs" in loc
            else ("OK", loc, "")
        ),
    )
    monkeypatch.setattr(D, "_project_source_index", lambda _root: {})
    issues = D._run_l1_location_recovery_reconcile_transaction(
        tmp_path, _config(tmp_path)
    )
    assert issues == []
    text = (tmp_path / "location_recovery.md").read_text()
    assert text.count("| INV-001 |") == 1
    assert text.count("| INV-003 |") == 1
    assert "| INV-001 | UNRECOVERED |" in text
    assert "INVALID_RECOVERY_LOCATION" in text
    assert "MODEL_OMISSION" in text
