"""Armed Summary recovery from a genuine retained MODEL execution."""
from __future__ import annotations

from pathlib import Path

import pytest

from artifact_ledger import (
    _output_prestate_digest,
    read_artifact_ledger,
    write_artifact_ledger,
)
import plamen_driver as D
from plamen_validators import derive_report_index_summary_master_parity
from report_index_summary_authority import (
    _build_summary_parity_receipt,
    _summary_parity_receipt_bytes,
)
from report_summary_recovery import (
    ReportSummaryRecoveryError,
    authenticate_report_summary_armed_recovery,
)
from test_report_index_summary_parity_successor_a0_a1 import _index_bytes
from test_worker_execution_preimage_authority import real_worker


pytestmark = [
    pytest.mark.integration,
    pytest.mark.parametrize(
        "real_worker",
        [{
            "report_index.md": _index_bytes().decode("utf-8"),
            "report_coverage.md": (
                "# Coverage\n\n" + "Retained MODEL coverage.\n" * 20
            ),
        }],
        indirect=True,
    ),
]


def _arm(worker):
    contract, launch = D._report_index_summary_parity_contract_and_launch(
        worker.config
    )
    execute, issues = D._arm_deterministic_driver_work_unit(
        scratchpad=worker.scratchpad,
        project_root=worker.project,
        contract=contract,
        launch=launch,
        run_id=worker.run_id,
    )
    assert execute and not issues, issues
    derivation = derive_report_index_summary_master_parity(
        (worker.scratchpad / "report_index.md").read_bytes()
    )
    assert derivation.repair_required and not derivation.issues
    return contract, launch, derivation


def _recover(worker, contract, launch):
    return authenticate_report_summary_armed_recovery(
        worker.scratchpad,
        model_contract=worker.contract,
        model_launch=worker.launch,
        summary_contract=contract,
        summary_launch=launch,
        run_id=worker.run_id,
    )


def _publish(worker, contract, derivation) -> Path:
    receipt = _build_summary_parity_receipt(
        derivation,
        contract=contract,
        run_id=worker.run_id,
        model_work_unit_key=worker.contract.key,
    )
    receipt_path = (
        worker.scratchpad
        / D._report_index_summary_parity_receipt_name(worker.config)
    )
    receipt_path.write_bytes(_summary_parity_receipt_bytes(receipt))
    (worker.scratchpad / "report_index.md").write_bytes(
        derivation.output_bytes
    )
    return receipt_path


def test_armed_recovery_accepts_exact_before_and_receipted_after(real_worker):
    contract, launch, derivation = _arm(real_worker)

    before = _recover(real_worker, contract, launch)
    assert before.current_state == "MODEL_PREIMAGE"
    assert before.derivation == derivation
    assert len(before.read_set) == 5

    receipt_path = _publish(real_worker, contract, derivation)
    after = _recover(real_worker, contract, launch)
    assert after.current_state == "SUMMARY_POSTIMAGE"
    assert after.derivation == derivation
    assert after.read_set == tuple(sorted((*before.read_set, receipt_path.name)))


@pytest.mark.parametrize(
    "damage",
    ("missing_receipt", "tampered_receipt", "changed_passthrough",
     "foreign_prestate", "third_report_state"),
)
def test_armed_recovery_rejects_incomplete_or_changed_authority(
    real_worker, damage: str,
):
    contract, launch, derivation = _arm(real_worker)
    receipt_path = _publish(real_worker, contract, derivation)

    if damage == "missing_receipt":
        receipt_path.unlink()
    elif damage == "tampered_receipt":
        receipt_path.write_bytes(receipt_path.read_bytes() + b"\n")
    elif damage == "changed_passthrough":
        (real_worker.scratchpad / "report_coverage.md").write_bytes(
            b"changed passthrough\n"
        )
    elif damage == "foreign_prestate":
        ledger = read_artifact_ledger(real_worker.scratchpad)
        unit = ledger["work_units"][contract.key]
        unit["output_prestates"]["scratchpad:report_coverage.md"][
            "predecessor_owner_key"
        ] = "sc/core/evm/codex/report_index/foreign"
        unit["output_prestate_digest"] = _output_prestate_digest(
            unit["output_prestates"]
        )
        write_artifact_ledger(real_worker.scratchpad, ledger)
    else:
        (real_worker.scratchpad / "report_index.md").write_bytes(
            b"arbitrary third report state\n"
        )

    with pytest.raises(ReportSummaryRecoveryError):
        _recover(real_worker, contract, launch)
