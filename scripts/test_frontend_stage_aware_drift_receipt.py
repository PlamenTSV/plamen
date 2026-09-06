"""Strict frontend replay/render tests for stage-aware drift decisions."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
KEY = bytes(range(32))


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_stage_aware_front", ROOT / "plamen.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _decision(stage: str = "PRE_PHASE_EXECUTION") -> dict:
    pre = stage == "PRE_PHASE_EXECUTION"
    value = {
        "schema": "plamen.audit-input-drift-decision.v1",
        "decision_kind": "MID_PHASE_AUDIT_INPUT_DRIFT",
        "run_id": "12345678-1234-5678-9234-567812345678",
        "launch_intent": "RESUME_EXISTING",
        "exit_status": 5,
        "phase": "recon",
        "detection_stage": stage,
        "snapshot_verdict": "MISMATCH",
        "changed_components": ["toolchain"],
        "runtime_entry_changes": [{
            "component": "toolchain",
            "identity": "@runtime/tool/scip-go",
            "stored": {"sha256": "1" * 64, "byte_count": 123},
            "current": {"sha256": "2" * 64, "byte_count": 124},
        }],
        "stored_snapshot_digest": "3" * 64,
        "current_snapshot_digest": "4" * 64,
        "phase_execution_state": (
            "NOT_ENTERED_IN_THIS_INVOCATION"
            if pre else "EXECUTION_OR_RECOVERY_PATH_ENTERED"
        ),
        "audit_model_generation_state": (
            "NO_CURRENT_PHASE_GENERATION_LAUNCHED_IN_THIS_INVOCATION"
            if pre else "UNKNOWN_MAY_HAVE_LAUNCHED"
        ),
        "prior_phase_or_run_model_state": "NOT_ASSERTED",
        "drift_evidence_relative_path": "audit_input_drift.json",
        "existing_evidence_deletion_performed": False,
        "driver_continued_after_detection": False,
        "required_action": (
            "RESTORE_EXACT_INPUTS_OR_USE_DISTINCT_RUN_DESTINATION"
        ),
        "allowed_actions": [
            "RESTORE_EXACT_INPUTS", "USE_DISTINCT_RUN_DESTINATION",
        ],
        "receipt_authentication_scope": "ONE_FRONTEND_CHILD_INVOCATION",
        "same_user_process_compromise_out_of_scope": True,
    }
    value["decision_id"] = hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    value["receipt_mac"] = hmac.new(KEY, json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"), hashlib.sha256).hexdigest()
    return value


def _raw(value: dict) -> bytes:
    return (json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=False,
    ) + "\n").encode("utf-8")


def _install_retained_reader(front, monkeypatch, value: dict):
    raw = _raw(value)
    calls = []

    def read(root, components, *, maximum):
        calls.append((root, components, maximum))
        return ({
            "kind": "file", "links": 1, "reparse_tag": 0,
            "size": len(raw),
        }, raw)

    monkeypatch.setattr(front, "_codex_install_committed_read", read)
    return calls


@pytest.mark.parametrize("stage", ("PRE_PHASE_EXECUTION", "POST_PHASE_EXECUTION"))
def test_strict_authenticated_stage_receipt_replays_once(stage, monkeypatch, tmp_path):
    front = _load_front()
    calls = _install_retained_reader(front, monkeypatch, _decision(stage))
    loaded = front._load_midphase_audit_input_drift_decision(
        tmp_path / "decision.json", receipt_mac_key=KEY,
    )
    assert loaded["detection_stage"] == stage
    assert len(calls) == 1
    assert calls[0][2] == 1024 * 1024


@pytest.mark.parametrize(
    "mutation,match",
    (
        (lambda row: row.__setitem__("receipt_mac", "0" * 64), "authentication"),
        (lambda row: row.__setitem__("decision_id", "0" * 64), "identity"),
        (lambda row: row.__setitem__(
            "phase_execution_state", "EXECUTION_OR_RECOVERY_PATH_ENTERED"
        ), "stage relationship"),
    ),
)
def test_tamper_and_cross_stage_relationships_fail_closed(
    mutation, match, monkeypatch, tmp_path,
):
    front = _load_front()
    value = _decision()
    mutation(value)
    if match != "authentication":
        value["receipt_mac"] = hmac.new(KEY, json.dumps(
            {key: item for key, item in value.items() if key != "receipt_mac"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8"), hashlib.sha256).hexdigest()
    _install_retained_reader(front, monkeypatch, value)
    with pytest.raises(ValueError, match=match):
        front._load_midphase_audit_input_drift_decision(
            tmp_path / "decision.json", receipt_mac_key=KEY,
        )


def test_runtime_entry_rows_are_strict_bounded_and_sorted(monkeypatch, tmp_path):
    front = _load_front()
    value = _decision()
    value["runtime_entry_changes"][0]["stored"]["byte_count"] = True
    value["decision_id"] = hashlib.sha256(json.dumps(
        {key: item for key, item in value.items() if key not in {"decision_id", "receipt_mac"}},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    value["receipt_mac"] = hmac.new(KEY, json.dumps(
        {key: item for key, item in value.items() if key != "receipt_mac"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"), hashlib.sha256).hexdigest()
    _install_retained_reader(front, monkeypatch, value)
    with pytest.raises(ValueError, match="digest/size"):
        front._load_midphase_audit_input_drift_decision(
            tmp_path / "decision.json", receipt_mac_key=KEY,
        )


@pytest.mark.parametrize(
    "stage,required,forbidden",
    (
        (
            "PRE_PHASE_EXECUTION",
            "No current-phase audit-model generation was launched",
            "may have launched",
        ),
        (
            "POST_PHASE_EXECUTION",
            "may have launched",
            "No current-phase audit-model generation was launched",
        ),
    ),
)
def test_truthful_stage_specific_rendering(
    stage, required, forbidden, monkeypatch, tmp_path, capsys,
):
    front = _load_front()
    _install_retained_reader(front, monkeypatch, _decision(stage))
    assert front._render_resume_startup_decision(
        tmp_path / "decision.json", receipt_mac_key=KEY,
    ) is True
    output = capsys.readouterr().out
    assert required in output
    assert forbidden not in output
    assert "Prior phase or prior run model activity is not asserted" in output
    assert "existing audit evidence was preserved" not in output


def test_invalid_exit5_remains_explicitly_uncertain(monkeypatch, tmp_path, capsys):
    front = _load_front()
    _install_retained_reader(front, monkeypatch, _decision())
    result = front._render_driver_result(
        5, str(tmp_path / "config.json"), str(tmp_path),
        decision_receipt_path=tmp_path / "decision.json",
        decision_mac_key=b"wrong" * 6 + b"!!",
    )
    assert result == 5
    output = capsys.readouterr().out
    assert "cannot certify whether audit execution began" in output
    assert "launched no new audit-model generation" not in output
