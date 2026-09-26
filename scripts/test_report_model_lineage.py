"""Actual worker/DRIVER lineage transactions, not model audit acceptance."""
import hashlib

import pytest

import plamen_driver as D
import report_model_lineage as L
from report_index_summary_authority import (
    _build_summary_parity_receipt, _summary_parity_receipt_bytes,
)
from plamen_validators import derive_report_index_summary_master_parity
from test_report_index_summary_parity_successor_a0_a1 import _index_bytes
from test_worker_execution_preimage_authority import real_worker


pytestmark = [pytest.mark.integration, pytest.mark.parametrize(
    "real_worker", [{"report_index.md": _index_bytes().decode(),
                     "report_coverage.md": "# Coverage\n" + "Retained coverage.\n" * 20}],
    indirect=True,
)]


def _read(worker):
    contract, launch = D._report_index_summary_parity_contract_and_launch(worker.config)
    return L.read_report_model_lineage(
        worker.scratchpad, model_contract=worker.contract, model_launch=worker.launch,
        summary_contract=contract, summary_launch=launch, run_id=worker.run_id,
    )


def _summary(worker):
    contract, launch = D._report_index_summary_parity_contract_and_launch(worker.config)
    kwargs = dict(scratchpad=worker.scratchpad, project_root=worker.project,
                  contract=contract, launch=launch, run_id=worker.run_id)
    execute, issues = D._arm_deterministic_driver_work_unit(**kwargs)
    assert execute and not issues, issues
    derivation = derive_report_index_summary_master_parity(
        (worker.scratchpad / "report_index.md").read_bytes()
    )
    assert derivation.repair_required and not derivation.issues
    receipt = _build_summary_parity_receipt(
        derivation, contract=contract, run_id=worker.run_id,
        model_work_unit_key=worker.contract.key,
    )
    (worker.scratchpad / D._report_index_summary_parity_receipt_name(worker.config)).write_bytes(
        _summary_parity_receipt_bytes(receipt)
    )
    (worker.scratchpad / "report_index.md").write_bytes(derivation.output_bytes)
    assert D._commit_deterministic_driver_work_unit(**kwargs) == []
    return contract, launch, derivation


def test_model_head_survives_later_live_bytes_without_claiming_them(real_worker):
    before = _read(real_worker)
    assert before.head_owner_key == real_worker.contract.key
    assert len(before.read_set) == 5
    (real_worker.scratchpad / "report_index.md").write_bytes(b"later publication\n")
    assert _read(real_worker) == before


def test_genuine_summary_commit_replays_original_derivation(real_worker):
    contract, _, derivation = _summary(real_worker)
    lineage = _read(real_worker)
    assert lineage.head_owner_key == contract.key
    assert lineage.head_preimages["scratchpad:report_index.md"] == derivation.output_bytes
    assert len(lineage.read_set) == 6
    (real_worker.scratchpad / "report_index.md").write_bytes(b"later canonical bytes\n")
    assert _read(real_worker) == lineage
    with pytest.raises(TypeError):
        lineage.head_preimages["scratchpad:report_index.md"] = b"changed"


@pytest.mark.parametrize("field", ["predecessor_owner_key", "predecessor_contract_digest",
                                    "predecessor_launch_digest", "sha256", "size"])
def test_successor_head_join_rejects_each_mismatch(real_worker, field):
    lineage = _read(real_worker)
    prestates = {
        identity: dict(status="ACTIVE_REGISTERED_PREDECESSOR",
                       predecessor_owner_key=lineage.head_owner_key,
                       predecessor_contract_digest=lineage.head_contract_digest,
                       predecessor_launch_digest=lineage.head_launch_digest,
                       sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        for identity, raw in lineage.head_preimages.items()
    }
    L.require_report_lineage_head_prestates(lineage, prestates)
    prestates["scratchpad:report_coverage.md"][field] = "changed"
    with pytest.raises(ValueError, match="predecessor differs"):
        L.require_report_lineage_head_prestates(lineage, prestates)


def test_summary_receipt_tamper_is_not_adopted(real_worker):
    _summary(real_worker)
    receipt = real_worker.scratchpad / D._report_index_summary_parity_receipt_name(real_worker.config)
    receipt.write_bytes(receipt.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="original derivation"):
        _read(real_worker)


def test_wrong_expected_summary_attempt_rejected_even_when_absent(real_worker):
    config = dict(real_worker.config)
    config["_phase_io_model_attempts"] = {"report_index": 2}
    contract, launch = D._report_index_summary_parity_contract_and_launch(config)
    with pytest.raises(ValueError, match="attempt differs"):
        L.read_report_model_lineage(
            real_worker.scratchpad, model_contract=real_worker.contract,
            model_launch=real_worker.launch,
            summary_contract=contract,
            summary_launch=launch, run_id=real_worker.run_id,
        )
