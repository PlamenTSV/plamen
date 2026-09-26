"""Genuine zero-route report reconciliation consumption integration."""
from __future__ import annotations

import json

import pytest

import plamen_driver as D
import severity_adjudication_work as W
from artifact_ledger import read_artifact_ledger
from severity_adjudication_work import RECONCILIATION_NAME
from test_severity_adjudication_work_p0_ag3 import (
    _decision,
    _prepare,
    _write_state,
)
from test_core_empty_report_assembly_integration import _commit_empty_tiers
from test_core_empty_report_entry_integration import (
    _run_report_child,
    core_report_prework,
)


def test_terminal_reconciliation_accepts_exact_zero_component(tmp_path):
    _write_state(tmp_path, [])
    _prepare(tmp_path)
    value = W.reconcile_adjudication_work(tmp_path)
    assert value["denominator_ids"] == []
    assert W.validate_terminal_reconciliation(tmp_path) == []


def test_terminal_reconciliation_rejects_exact_pending_component(tmp_path):
    _write_state(tmp_path, [_decision("H-PENDING")])
    _prepare(tmp_path)
    value = W.reconcile_adjudication_work(tmp_path)
    assert value["states"] == {"H-PENDING": "PENDING"}
    assert any(
        "no exact terminal denominator" in issue
        for issue in W.validate_terminal_reconciliation(tmp_path)
    )


def test_terminal_reconciliation_accepts_completed_unresolved_business_debt(
    tmp_path, monkeypatch,
):
    _write_state(tmp_path, [])
    _prepare(tmp_path)
    value = W.build_adjudication_work_reconciliation(tmp_path)
    unsigned = {key: item for key, item in value.items()
                if key != "reconciliation_digest"}
    unsigned.update({
        "denominator_count": 1,
        "denominator_ids": ["H-UNRESOLVED"],
        "states": {"H-UNRESOLVED": "COMPLETED_UNRESOLVED"},
        "details": {"H-UNRESOLVED": "independent decision remains unresolved"},
        "pending_ids": [],
        "bind_ready_ids": [],
        "completed_ids": [],
        "debt_ids": ["H-UNRESOLVED"],
        "all_terminal": True,
        "all_resolved": False,
    })
    value = W._signed(unsigned, digest_field="reconciliation_digest")
    (tmp_path / W.RECONCILIATION_NAME).write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        W, "build_adjudication_work_reconciliation", lambda _root: value
    )
    assert W.validate_terminal_reconciliation(tmp_path) == []


def test_terminal_reconciliation_rejects_invalid_persisted_replay(tmp_path):
    _write_state(tmp_path, [])
    _prepare(tmp_path)
    W.reconcile_adjudication_work(tmp_path)
    path = tmp_path / W.RECONCILIATION_NAME
    path.write_bytes(b"{}\n")
    assert W.validate_terminal_reconciliation(tmp_path)


def _prepare_report_projection(case, monkeypatch, request) -> None:
    """Publish the real report index and all typed empty tier products."""

    report_index, _model_contract, _model_launch = _run_report_child(
        case, monkeypatch, request
    )

    def no_worker_relaunch(*_args, **_kwargs):
        pytest.fail("report preparation must not relaunch a worker")

    monkeypatch.setattr(D, "_run_one_codex_exec", no_worker_relaunch)
    assert D._run_report_index_canonicalization_transaction(
        report_index, case.root, case.config
    ) == []
    D._commit_phase_from_disk_debt(
        report_index,
        case.checkpoint,
        case.root,
        case.config,
        case.phases,
        clean_transients=True,
    )
    _commit_empty_tiers(case)


def _projection_binding(case):
    matches = [
        row
        for key, row in read_artifact_ledger(case.root)["work_units"].items()
        if key.endswith("/severity_adjudication_shadow/report_projection")
    ]
    assert len(matches) == 1
    return matches[0]["input_bindings"][
        "scratchpad:severity_adjudication_work_reconciliation.json"
    ]


@pytest.mark.integration
def test_zero_projection_consumes_typed_terminal_reconciliation(
    core_report_prework, monkeypatch, request
):
    case = core_report_prework
    _prepare_report_projection(case, monkeypatch, request)
    assert D._refresh_severity_report_shadow_projection(
        case.checkpoint, case.root, case.config, stage="PRE_ASSEMBLE"
    ) == []
    binding = _projection_binding(case)
    assert binding["producer_work_unit_key"].endswith(
        "/severity_adjudication_shadow/reconcile_empty"
    )
    assert binding["producer_writer"] == "DRIVER"
    assert binding["status"] == "ACTIVE"


@pytest.mark.parametrize("damage", ("missing", "tampered"))
@pytest.mark.integration
def test_projection_rejects_damaged_typed_reconciliation_before_arm(
    core_report_prework, monkeypatch, request, damage
):
    case = core_report_prework
    _prepare_report_projection(case, monkeypatch, request)
    path = case.root / RECONCILIATION_NAME
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"{}\n")
    issues = D._refresh_severity_report_shadow_projection(
        case.checkpoint, case.root, case.config, stage="PRE_ASSEMBLE"
    )
    assert issues
    assert not (case.root / "severity_report_shadow_receipt.json").exists()
    assert not any(
        key.endswith("/severity_adjudication_shadow/report_projection")
        and row.get("execution_state") == "OUTPUT_COMMITTED"
        for key, row in read_artifact_ledger(case.root)["work_units"].items()
    )


def assert_pending_reconciliation_rejected_before_projection_arm(case):
    """Invoke from the genuine nonempty prepared-work fixture before a bind."""

    payload = json.loads((case.root / RECONCILIATION_NAME).read_text("utf-8"))
    assert payload["all_terminal"] is False
    issues = D._refresh_severity_report_shadow_projection(
        case.checkpoint, case.root, case.config, stage="PRE_ASSEMBLE"
    )
    assert any("no exact terminal denominator" in issue for issue in issues)
    assert not (case.root / "severity_report_shadow_receipt.json").exists()


def assert_final_unresolved_reconciliation_owner(case):
    """Invoke after genuine completed bind-prefix final publication."""

    binding = read_artifact_ledger(case.root)["artifact_bindings"][
        "scratchpad:severity_adjudication_work_reconciliation.json"
    ]
    assert binding["owner_key"].endswith(
        "/severity_adjudication_shadow/reconcile_final"
    )
    payload = json.loads((case.root / RECONCILIATION_NAME).read_text("utf-8"))
    assert payload["all_terminal"] is True
    assert payload["all_resolved"] is False
    assert set(payload["states"].values()) == {"COMPLETED_UNRESOLVED"}


# The final callbacks are consumed by the genuine compatibility binder/live
# handler fixture; they never construct PhaseIO or provider authority.
