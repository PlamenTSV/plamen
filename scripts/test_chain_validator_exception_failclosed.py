"""Regression for fail-closed chain identity-retention validation."""

from pathlib import Path

import plamen_driver as D


def test_chain_baseline_regroup_validator_exception_records_debt_and_rejects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    project_root = tmp_path / "project"
    project_root.mkdir()
    phase = D.Phase(
        name="chain",
        section_markers=[],
        expected_artifacts=[],
        base_timeout_s=1,
        critical=True,
    )
    config = {
        "_run_id": "chain-validator-exception-regression",
        "mode": "core",
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project_root),
    }

    monkeypatch.setattr(D, "gate_passes", lambda *_args: (True, []))
    monkeypatch.setattr(
        D, "_detect_foreign_phase_writes", lambda *_args: []
    )
    monkeypatch.setattr(
        D, "_validate_id_ledger_collisions", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_validate_chain_anti_absorption", lambda *_args, **_kwargs: []
    )

    def fail_baseline_regroup(*_args, **_kwargs):
        raise RuntimeError("forced baseline-regroup parser failure")

    monkeypatch.setattr(
        D, "_validate_chain_baseline_not_regrouped", fail_baseline_regroup
    )
    monkeypatch.setattr(
        D, "_validate_chain_self_restatement", lambda *_args, **_kwargs: []
    )

    passed, missing = D._run_phase_validators(
        phase,
        config,
        scratchpad,
        [phase],
        0,
        {},
    )

    assert passed is False
    assert any(
        "chain baseline-regroup validation failed" in issue
        and "forced baseline-regroup parser failure" in issue
        for issue in missing
    )
    debt = (scratchpad / "chain.degraded").read_text(encoding="utf-8")
    assert "[CHAIN_BASELINE_REGROUP_VALIDATION_DEBT]" in debt
    assert "forced baseline-regroup parser failure" in debt
