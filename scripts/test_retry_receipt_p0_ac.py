"""Predicate-aware retry receipts: byte changes alone cannot certify repair."""
from __future__ import annotations

import uuid
from pathlib import Path

from plamen_driver import (
    _build_retry_receipt,
    _gate_failures_from_issues,
    _resolved_phase_artifact_digest,
    _resolved_phase_contract_digest,
    _retry_receipt_status,
    _write_retry_receipt,
)
from plamen_types import Checkpoint, Phase, RetryReceipt


def _fixture(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = Phase("chain", ["Chain"], ["hypotheses.md"], 300)
    (scratchpad / "hypotheses.md").write_text("# hypotheses\n", encoding="utf-8")
    config = {
        "project_root": str(tmp_path), "pipeline": "sc", "mode": "thorough",
        "language": "evm", "cli_backend": "claude",
    }
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    return scratchpad, phase, config, checkpoint


def _failures(scratchpad, phase, config, issue):
    return _gate_failures_from_issues(
        phase,
        [issue],
        contract_digest=_resolved_phase_contract_digest(phase, config),
        output_digest=_resolved_phase_artifact_digest(
            phase, scratchpad, config["project_root"]
        ),
        scratchpad=scratchpad,
    )


def test_changed_output_bytes_with_same_predicate_is_no_progress(tmp_path: Path):
    scratchpad, phase, config, checkpoint = _fixture(tmp_path)
    before = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    (scratchpad / "hypotheses.md").write_text(
        "# hypotheses\nchanged prose only\n", encoding="utf-8"
    )
    after = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    assert _retry_receipt_status(before, after) == "NO_PROGRESS"
    receipt = _build_retry_receipt(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=2,
        failures_before=before,
        failures_after=after,
        output_digest_before=before[0].output_digest,
        output_digest_after=after[0].output_digest,
    )
    assert receipt.status == "NO_PROGRESS"
    assert receipt.output_digest_before != receipt.output_digest_after


def test_exact_gate_clearance_is_cleared(tmp_path: Path):
    scratchpad, phase, config, checkpoint = _fixture(tmp_path)
    before = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    receipt = _build_retry_receipt(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=2,
        failures_before=before,
        failures_after=(),
        output_digest_before=before[0].output_digest,
        output_digest_after=_resolved_phase_artifact_digest(
            phase, scratchpad, config["project_root"]
        ),
    )
    assert receipt.status == "CLEARED"
    path = _write_retry_receipt(scratchpad, receipt)
    assert RetryReceipt.from_dict(__import__("json").loads(path.read_text())) == receipt


def test_new_gate_after_retry_is_failed_not_progress(tmp_path: Path):
    scratchpad, phase, config, _checkpoint = _fixture(tmp_path)
    before = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    after = _failures(scratchpad, phase, config, "PoC evidence integrity failed")
    assert _retry_receipt_status(before, after) == "FAILED"


def test_retry_receipt_records_quarantine_lineage(tmp_path: Path):
    scratchpad, phase, config, checkpoint = _fixture(tmp_path)
    before = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    quarantine = scratchpad / "_retry_quarantine" / "chain"
    quarantine.mkdir(parents=True)
    (quarantine / "hypotheses.md.attempt1").write_text("old", encoding="utf-8")
    receipt = _build_retry_receipt(
        checkpoint=checkpoint, phase=phase, config=config,
        scratchpad=scratchpad, attempt=2, failures_before=before,
        failures_after=before, output_digest_before=before[0].output_digest,
        output_digest_after=before[0].output_digest,
    )
    assert receipt.quarantine_lineage == (
        "_retry_quarantine/chain/hypotheses.md.attempt1",
    )
