"""RED specification for the P0-I axis negative-challenge resume boundary.

The axis candidate-negative ledger is a deterministic successor of the final
typed application receipt.  For a scheduled non-empty denominator it is part
of phase completion authority even when every row is FINDING and therefore the
ledger has zero CLEAR events.  Omitting that empty-but-typed denominator would
let a crash erase axis from the independent discriminator merely by removing a
file.

These fixtures use real PhaseIO planning, MODEL commit, deterministic
finalization, harvest, and checkpoint reconciliation.  They launch no model,
subprocess, audit, or network request and make no production edits.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import plamen_driver as DRIVER
from plamen_types import Checkpoint
from test_axis_driver_transaction_red_p0_i import (
    RUN_ID as ZERO_RUN_ID,
    _axis_phase,
    _config as _zero_config,
    _prepare as _prepare_zero,
)
from test_axis_population_provider_p0_i import (
    _project as _population_project,
    _write_graph,
)
from test_axis_resume_canonical_recovery_red_p0_i import (
    _committed_model_fixture,
)


LEDGER_NAME = "candidate_negative_proposals_axis_coverage.json"


def _resume(
    *,
    project: Path,
    scratchpad: Path,
    config: dict[str, Any],
) -> list[str]:
    return DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline=str(config["pipeline"]),
        mode=str(config["mode"]),
        language=str(config["language"]),
        backend=str(config["cli_backend"]),
        run_id=str(config["_run_id"]),
    )


def _finalized_nonempty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    backend: str,
    disposition: str,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any]]:
    (
        project,
        scratchpad,
        phase,
        config,
        worklist,
        _frozen_files,
        _frozen_digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend=backend,
        disposition=disposition,
    )
    application, finalization_issues = (
        DRIVER._finalize_axis_coverage_boundary(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
        )
    )
    assert finalization_issues == [], (
        "fixture finalization must be green before testing its deterministic "
        "negative successor: " + "; ".join(finalization_issues)
    )
    assert worklist["count"] > 0
    assert application["application_record_complete"] is True
    harvest_issues = DRIVER._harvest_candidate_negative_phase(
        phase, config, scratchpad
    )
    assert harvest_issues == [], (
        "fixture negative harvest must be green before testing resume: "
        + "; ".join(harvest_issues)
    )
    return project, scratchpad, config, application


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("disposition", ("CLEAR", "FINDING"))
def test_valid_nonempty_negative_ledger_replays_on_both_backends(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    disposition: str,
) -> None:
    project, scratchpad, config, application = _finalized_nonempty(
        tmp_path,
        monkeypatch,
        backend=backend,
        disposition=disposition,
    )

    ledger = json.loads(
        (scratchpad / LEDGER_NAME).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    clear_count = sum(
        row["disposition"] == "CLEAR"
        for row in application["dispositions"]
    )
    assert ledger["event_count"] == clear_count
    if disposition == "FINDING":
        assert clear_count == 0
        assert ledger["events"] == []
    assert _resume(
        project=project,
        scratchpad=scratchpad,
        config=config,
    ) == []


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_missing_zero_event_ledger_is_resume_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    project, scratchpad, config, application = _finalized_nonempty(
        tmp_path,
        monkeypatch,
        backend=backend,
        disposition="FINDING",
    )
    assert all(
        row["disposition"] == "FINDING"
        for row in application["dispositions"]
    )
    (scratchpad / LEDGER_NAME).unlink()

    issues = _resume(
        project=project,
        scratchpad=scratchpad,
        config=config,
    )
    assert issues
    assert any(
        all(token in issue.casefold() for token in ("candidate", "negative"))
        or "ledger" in issue.casefold()
        for issue in issues
    ), "; ".join(issues)


def test_missing_file_cannot_remove_nonempty_axis_from_denominator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, config, _application = _finalized_nonempty(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    (scratchpad / LEDGER_NAME).unlink()

    phases = DRIVER._candidate_negative_phases_for_run(
        scratchpad, config
    )
    assert "axis_coverage" in phases, (
        "a missing file cannot erase a finalized, scheduled, non-empty axis "
        "producer from the discriminator denominator"
    )


def test_tampered_nonempty_negative_ledger_is_resume_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, config, _application = _finalized_nonempty(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="CLEAR",
    )
    path = scratchpad / LEDGER_NAME
    ledger = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    ledger["axis_authority_binding"]["application_receipt_digest"] = "f" * 64
    path.write_text(
        json.dumps(ledger, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    issues = _resume(
        project=project,
        scratchpad=scratchpad,
        config=config,
    )
    assert issues
    assert any(
        token in " ".join(issues).casefold()
        for token in ("candidate", "negative", "ledger", "digest")
    )


@pytest.mark.parametrize("mutation", ("missing", "tampered"))
def test_checkpoint_startup_rewinds_nonempty_axis_without_current_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    project, scratchpad, config, _application = _finalized_nonempty(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    path = scratchpad / LEDGER_NAME
    if mutation == "missing":
        path.unlink()
    else:
        ledger = json.loads(
            path.read_text(encoding="utf-8", errors="strict")
        )
        ledger["status"] = "FORGED"
        path.write_text(
            json.dumps(ledger, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    phase = _axis_phase()
    checkpoint = Checkpoint(
        completed=[phase.name],
        run_id=str(config["_run_id"]),
    )

    removed = DRIVER._reconcile_completed_checkpoint_artifacts(
        scratchpad,
        str(project),
        checkpoint,
        [phase],
        "thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
    )

    assert removed == [phase.name]
    assert checkpoint.completed == []


def test_exact_zero_axis_may_omit_negative_ledger(
    tmp_path: Path,
) -> None:
    project, scratchpad = _population_project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": [],
            }
        },
    )
    phase = _axis_phase()
    config = _zero_config(project, backend="claude")
    worklist, planning_issues = _prepare_zero(
        phase, config, scratchpad
    )
    assert planning_issues == []
    assert config["_run_id"] == ZERO_RUN_ID
    assert worklist["clean_empty"] is True
    assert not (scratchpad / LEDGER_NAME).exists()

    assert "axis_coverage" not in DRIVER._candidate_negative_phases_for_run(
        scratchpad, config
    )
    assert _resume(
        project=project,
        scratchpad=scratchpad,
        config=config,
    ) == []
