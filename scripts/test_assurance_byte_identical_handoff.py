"""Assurance must authenticate an owner handoff even when bytes are unchanged."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

import artifact_ledger as A
import plamen_driver as D
from phase_io_contracts import DriverMergeEvent
from report_mutation_transaction import apply_report_mutation_transaction
import test_report_transaction_producer_handoff_p0_ac as H


def _handoff(tmp_path, monkeypatch):
    report = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    root, producer, launch = H._seed(tmp_path, report)
    apply_report_mutation_transaction(
        scratchpad=root, project_root=tmp_path, run_id=H.RUN_ID,
        phase="report_dedup", post_report=report,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": report},
    )
    disposition = H._disposition_consumer()
    disposition_launch = H._launch(disposition)
    A.record_work_unit_inputs(
        root, tmp_path, disposition, disposition_launch, run_id=H.RUN_ID,
    )
    apply_report_mutation_transaction(
        scratchpad=root, project_root=tmp_path, run_id=H.RUN_ID,
        phase="report_floor.disposition", post_report=report,
        exact_inputs=("source.json",),
        sidecars={"report_floor.disposition.candidate.md": report},
    )
    digest = hashlib.sha256(report).hexdigest()
    A.record_work_unit_artifacts(
        root, tmp_path, disposition, disposition_launch, run_id=H.RUN_ID,
        actor="DRIVER", merge_events={
            "project:AUDIT_REPORT.md": DriverMergeEvent(
                work_unit_key=disposition.key,
                contract_digest=disposition.digest,
                artifact_identity="project:AUDIT_REPORT.md",
                before_sha256=digest, after_sha256=digest,
                source_identities=("scratchpad:source.json",),
                identities_before=(), identities_after=(),
            ),
        },
    )
    # Keep the small existing transaction fixture's contract denominator;
    # exercise the real preparation, ledger authorization and arm functions.
    monkeypatch.setattr(
        D, "_assurance_projection_contract_and_launch",
        lambda *_args: (producer, launch),
    )
    checkpoint = SimpleNamespace(run_id=H.RUN_ID)
    config = {"project_root": str(tmp_path), "_run_id": H.RUN_ID}
    return root, producer, launch, disposition, checkpoint, config


def _snapshot(path):
    info = path.stat()
    return path.read_bytes(), info.st_ino, info.st_mtime_ns


def test_real_prepare_rearms_byte_identical_authenticated_owner_handoff(
    tmp_path, monkeypatch,
):
    root, producer, launch, disposition, checkpoint, config = _handoff(
        tmp_path, monkeypatch,
    )
    before = A.read_artifact_ledger(root)
    prior = before["work_units"][producer.key]
    assert A.validate_work_unit_inputs(
        root, tmp_path, producer, launch, run_id=H.RUN_ID,
    ) == []
    assert before["artifact_bindings"]["project:AUDIT_REPORT.md"]["owner_key"] == disposition.key
    report_before = _snapshot(tmp_path / "AUDIT_REPORT.md")

    assert D._prepare_assurance_projection_reexecution(checkpoint, root, config) == []

    after = A.read_artifact_ledger(root)
    refreshed = after["work_units"][producer.key]
    assert refreshed["semantic_status"] == "STALE_INPUT"
    assert refreshed["input_bindings"] == prior["input_bindings"]
    assert refreshed["semantic_invalidation"]["changed_input_identities"] == [
        "project:AUDIT_REPORT.md",
    ]
    assert D._arm_deterministic_driver_work_unit(
        scratchpad=root, project_root=tmp_path, contract=producer,
        launch=launch, run_id=H.RUN_ID,
    ) == (True, [])
    assert _snapshot(tmp_path / "AUDIT_REPORT.md") == report_before


@pytest.mark.parametrize("corruption", ["forged_commit", "foreign_run", "unregistered_owner"])
def test_real_prepare_rejects_unauthenticated_handoff_without_publication(
    tmp_path, monkeypatch, corruption,
):
    root, _producer, _launch, disposition, checkpoint, config = _handoff(
        tmp_path, monkeypatch,
    )
    ledger = A.read_artifact_ledger(root)
    binding = ledger["artifact_bindings"]["project:AUDIT_REPORT.md"]
    if corruption == "forged_commit":
        ledger["work_units"][disposition.key]["commit_authority"]["receipt_digest"] = "0" * 64
    elif corruption == "foreign_run":
        binding["run_id"] = "foreign-run"
    else:
        binding["owner_key"] = disposition.key.rsplit("/", 1)[0] + "/unregistered"
    A.write_artifact_ledger(root, ledger)
    protected = (root / A.LEDGER_NAME, tmp_path / "AUDIT_REPORT.md")
    before = {path: _snapshot(path) for path in protected}

    issues = D._prepare_assurance_projection_reexecution(checkpoint, root, config)

    assert issues
    assert any("output authority mismatch" in issue for issue in issues)
    assert {path: _snapshot(path) for path in protected} == before
