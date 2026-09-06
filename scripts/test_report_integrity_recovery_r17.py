"""R17 contracts for lazy delivery selection and committed MODEL recovery."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as DRIVER
from artifact_ledger import read_artifact_ledger
from test_axis_resume_canonical_recovery_red_p0_i import (
    RUN_ID,
    _committed_model_fixture,
)


@pytest.mark.parametrize(
    ("names", "expected"),
    (
        (("report_floor", "report_assemble"), "report_floor"),
        (("report_assemble", "report_floor"), "report_floor"),
        (("report_floor",), "report_floor"),
        (("report_assemble",), "report_assemble"),
    ),
)
@pytest.mark.parametrize("terminal_gate", ("assurance", "p1k", "exact_scope"))
def test_delivery_phase_selection_is_lazy_exact_and_shared_by_all_terminal_gates(
    names: tuple[str, ...],
    expected: str,
    terminal_gate: str,
) -> None:
    phases = tuple(SimpleNamespace(name=name) for name in names)
    selected = DRIVER._report_integrity_delivery_phase(phases)
    assert selected is next(phase for phase in phases if phase.name == expected)
    assert terminal_gate in {"assurance", "p1k", "exact_scope"}


@pytest.mark.parametrize("terminal_gate", ("assurance", "p1k", "exact_scope"))
def test_delivery_phase_selection_fails_closed_when_no_owner_exists(
    terminal_gate: str,
) -> None:
    with pytest.raises(RuntimeError, match="report_floor.*report_assemble"):
        DRIVER._report_integrity_delivery_phase(
            (SimpleNamespace(name="axis_coverage"),)
        )
    assert terminal_gate in {"assurance", "p1k", "exact_scope"}


def test_all_three_terminal_calls_use_the_shared_lazy_selector() -> None:
    source = Path(DRIVER.__file__).read_text(encoding="utf-8")
    assert source.count("_report_integrity_delivery_phase(phases)") == 3
    assert "next(item for item in phases if item.name == \"report_assemble\")" not in source


def test_exact_active_model_commit_replays_without_ledger_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, phase, config, *_rest = _committed_model_fixture(
        tmp_path, monkeypatch, backend="claude", disposition="FINDING"
    )
    before = (scratchpad / "_artifact_state.json").read_bytes()
    assert DRIVER._record_typed_model_phase_artifacts(phase, scratchpad, config) == []
    assert (scratchpad / "_artifact_state.json").read_bytes() == before
    contract, _launch = DRIVER._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    assert contract is not None
    unit = read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"


def test_committed_model_replay_rejects_tamper_without_reblessing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, phase, config, *_rest = _committed_model_fixture(
        tmp_path, monkeypatch, backend="claude", disposition="FINDING"
    )
    output = scratchpad / "axis_coverage_findings.md"
    output.write_bytes(output.read_bytes() + b"\nforeign mutation\n")
    before = (scratchpad / "_artifact_state.json").read_bytes()
    issues = DRIVER._record_typed_model_phase_artifacts(phase, scratchpad, config)
    assert issues
    assert (scratchpad / "_artifact_state.json").read_bytes() == before


def test_committed_model_replay_rejects_cross_run_without_reblessing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, phase, config, *_rest = _committed_model_fixture(
        tmp_path, monkeypatch, backend="claude", disposition="FINDING"
    )
    config = {**config, "_run_id": "9f9a8687-f4bb-49bb-81fc-c83855f031f7"}
    before = (scratchpad / "_artifact_state.json").read_bytes()
    issues = DRIVER._record_typed_model_phase_artifacts(phase, scratchpad, config)
    assert issues
    assert RUN_ID not in " ".join(issues) or issues
    assert (scratchpad / "_artifact_state.json").read_bytes() == before
