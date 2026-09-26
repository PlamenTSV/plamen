"""Recovery diagnostics preserve cause without authorizing failed publication."""
from types import SimpleNamespace

import plamen_driver as D


def _isolate(monkeypatch, tmp_path, arm_results, recovery_issues):
    calls = []
    results = iter(arm_results)
    monkeypatch.setattr(D, "_report_output_path", lambda config: tmp_path / "AUDIT_REPORT.md")
    monkeypatch.setattr(D, "_checkpoint_memory_disk_parity_issues", lambda *args: [])
    monkeypatch.setattr(D, "_refresh_final_inventory_reconciliation_phase_io", lambda **kwargs: [])
    monkeypatch.setattr(D, "_assurance_projection_contract_and_launch", lambda *args: (object(), object()))

    def arm(**kwargs):
        calls.append("arm")
        return next(results)

    def recover(*args):
        calls.append("recover")
        return recovery_issues

    def validate(*args):
        calls.append("validate")
        return []

    monkeypatch.setattr(D, "_arm_deterministic_driver_work_unit", arm)
    monkeypatch.setattr(D, "_prepare_assurance_projection_reexecution", recover)
    monkeypatch.setattr(D, "_validate_final_assurance_delivery", validate)
    return SimpleNamespace(run_id="diagnostic-only"), calls


def test_failed_recovery_retains_original_context_and_distinct_cause(tmp_path, monkeypatch):
    initial = "deterministic prebind failed: report authority mismatch"
    cause = "assurance projection pre-write authority failed: stale sidecar"
    checkpoint, calls = _isolate(
        monkeypatch, tmp_path, [(False, [initial])], [cause, initial, cause],
    )
    assert D._refresh_assurance_projection(checkpoint, tmp_path, {}) == [initial, cause]
    assert calls == ["arm", "recover"]
    assert not list(tmp_path.iterdir())


def test_successful_recovery_still_requires_second_arm_and_replay_validation(tmp_path, monkeypatch):
    checkpoint, calls = _isolate(
        monkeypatch, tmp_path, [(False, ["initial mismatch"]), (False, [])], [],
    )
    assert D._refresh_assurance_projection(checkpoint, tmp_path, {}) == []
    assert calls == ["arm", "recover", "arm", "validate"]
    assert not list(tmp_path.iterdir())


def test_failed_second_arm_cannot_be_cleared_by_successful_recovery(tmp_path, monkeypatch):
    checkpoint, calls = _isolate(
        monkeypatch, tmp_path,
        [(False, ["initial mismatch"]), (False, ["retry rejected"])], [],
    )
    assert D._refresh_assurance_projection(checkpoint, tmp_path, {}) == ["retry rejected"]
    assert calls == ["arm", "recover", "arm"]
    assert not list(tmp_path.iterdir())
