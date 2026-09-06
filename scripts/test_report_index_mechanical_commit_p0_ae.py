"""P0-AE report-index mechanical-author and fast-path commit fixtures."""
from __future__ import annotations

import inspect
from pathlib import Path
import uuid

import pytest

from artifact_ledger import read_artifact_ledger
from phase_io_contracts import resolve_phase_io_contract
import plamen_driver as D
from plamen_types import Checkpoint, PhaseCommit, SC_PHASES


def _config(tmp_path: Path, pipeline: str) -> dict:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": "claude",
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": f"report-index-mechanical-{pipeline}",
    }


def _phase():
    return next(phase for phase in SC_PHASES if phase.name == "report_index")


def _mechanical_contract(config: dict):
    return resolve_phase_io_contract(
        pipeline=config["pipeline"],
        mode=config["mode"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        phase="report_index",
        work_unit_id="mechanical",
    )


def _write_mechanical_outputs(config: dict) -> None:
    scratchpad = Path(config["scratchpad"])
    (scratchpad / "report_index.md").write_text(
        "# Mechanical Report Index\n", encoding="utf-8"
    )
    (scratchpad / "report_coverage.md").write_text(
        "# Mechanical Report Coverage\n", encoding="utf-8"
    )
    if config["pipeline"] == "l1":
        (scratchpad / "report_records.json").write_text(
            '{"active": [], "excluded": []}\n', encoding="utf-8"
        )


def _write_mechanical_inputs(config: dict) -> None:
    """Materialize every immutable input in the live mechanical contract."""

    scratchpad = Path(config["scratchpad"])
    for name, heading in (
        ("verification_queue.md", "# Verification Queue\n"),
        ("finding_mapping.md", "# Finding Mapping\n"),
        ("dedup_decisions.md", "# Dedup Decisions\n"),
    ):
        (scratchpad / name).write_text(heading, encoding="utf-8")


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_report_index_mechanical_contract_is_exact_driver_authority(
    tmp_path: Path, pipeline: str
):
    config = _config(tmp_path, pipeline)
    contract = _mechanical_contract(config)

    expected = {
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
    }
    if pipeline == "l1":
        expected.add("scratchpad:report_records.json")
    assert {spec.identity for spec in contract.outputs} == expected
    assert {spec.writer for spec in contract.outputs} == {"DRIVER"}
    assert {spec.artifact_class for spec in contract.outputs} == {
        "DRIVER_GENERATED"
    }
    assert contract.model_invoked is False
    assert not any("*" in spec.path for spec in contract.outputs)
    assert set(contract.immutable_inputs) >= {
        "scratchpad:verification_queue.md",
        "scratchpad:finding_mapping.md",
        "scratchpad:dedup_decisions.md",
    }


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_mechanical_recorder_binds_driver_outputs_to_run_backend_and_contract(
    tmp_path: Path, pipeline: str
):
    config = _config(tmp_path, pipeline)
    scratchpad = Path(config["scratchpad"])
    _write_mechanical_inputs(config)
    execute, issues = D._arm_report_index_mechanical_artifacts(
        scratchpad, config
    )
    assert execute and issues == []
    _write_mechanical_outputs(config)

    assert D._record_report_index_mechanical_artifacts(scratchpad, config) == []

    contract = _mechanical_contract(config)
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    assert unit["work_unit_key"] == (
        f"{pipeline}/thorough/{config['language']}/claude/report_index/mechanical"
    )
    assert unit["run_id"] == config["_run_id"]
    assert unit["contract_digest"] == contract.digest
    assert unit["model_invoked"] is False
    expected = {
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
    }
    if pipeline == "l1":
        expected.add("scratchpad:report_records.json")
    assert set(unit["artifacts"]) == expected
    for record in unit["artifacts"].values():
        assert record["writer"] == "DRIVER"
        assert record["artifact_class"] == "DRIVER_GENERATED"
        assert record["owner_key"] == contract.key
        assert record["run_id"] == config["_run_id"]
        assert record["status"] == "ACTIVE"


def _main_branch(start_marker: str, end_marker: str) -> str:
    source = inspect.getsource(D.main)
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def test_sc_pre_spawn_repair_records_driver_author_and_routing_after_expansion_before_commit():
    branch = _main_branch(
        'if config["pipeline"] == "sc" and phase.name == "report_index":',
        'if config["pipeline"] == "l1" and phase.name == "report_index":',
    )

    arm_at = branch.index("_arm_report_index_mechanical_artifacts(")
    repair_at = branch.index("_repair_sc_report_index_from_prior(", arm_at)
    author_at = branch.index(
        "_record_report_index_mechanical_artifacts(", repair_at
    )
    routing_at = branch.index(
        "_run_report_index_routing_transaction(", author_at
    )
    expand_at = branch.index("expand_shard_phases(phases, scratchpad)", routing_at)
    commit_at = branch.index("_commit_phase_from_disk_debt(", expand_at)

    assert author_at >= 0, (
        "SC pre-spawn mechanical repair must bind report outputs to DRIVER, "
        "not reuse report_index/model authority"
    )
    assert arm_at < repair_at < author_at < routing_at < expand_at < commit_at


def test_l1_mechanical_path_records_driver_author_and_routing_after_expansion_before_commit():
    branch = _main_branch(
        'if config["pipeline"] == "l1" and phase.name == "report_index":',
        "# Phase E11 follow-up #1: empty-shard body-writer skip",
    )

    arm_at = branch.index("_arm_report_index_mechanical_artifacts(")
    write_at = branch.index("_write_mechanical_report_index(", arm_at)
    author_at = branch.index(
        "_record_report_index_mechanical_artifacts(", write_at
    )
    expand_at = branch.index("expand_shard_phases(phases, scratchpad)", author_at)
    routing_at = branch.index(
        "_run_report_index_routing_transaction(", expand_at
    )
    commit_at = branch.index("_commit_phase_from_disk_debt(", routing_at)

    assert arm_at < write_at < author_at < expand_at < routing_at < commit_at


@pytest.mark.parametrize(
    "sentinel_text,expected_state,expects_debt",
    [
        (None, "CLEAN", False),
        (
            "[REPORT_INDEX_MECHANICAL_IO_DEBT] missing routing manifest\n",
            "COMPLETED_WITH_DEBT",
            True,
        ),
    ],
)
def test_commit_phase_from_disk_debt_creates_typed_clean_or_debt_commit(
    tmp_path: Path,
    sentinel_text: str | None,
    expected_state: str,
    expects_debt: bool,
):
    config = _config(tmp_path, "sc")
    scratchpad = Path(config["scratchpad"])
    _write_mechanical_outputs(config)
    phase = _phase()
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    if sentinel_text is not None:
        (scratchpad / "report_index.degraded").write_text(
            sentinel_text, encoding="utf-8"
        )

    commit = D._commit_phase_from_disk_debt(
        phase,
        checkpoint,
        scratchpad,
        config,
        [phase],
        clean_transients=True,
    )

    assert isinstance(commit, PhaseCommit)
    assert commit.state == expected_state
    assert commit.phase_name == "report_index"
    assert commit.run_id == checkpoint.run_id
    assert bool(commit.unresolved_failures) is expects_debt
    assert checkpoint.phase_commits["report_index"] == commit
    assert "report_index" in checkpoint.completed
    assert ("report_index" in checkpoint.degraded) is expects_debt
    if expects_debt:
        assert "missing routing manifest" in commit.unresolved_failures[0].message
        assert (scratchpad / "report_index.degraded").exists()
    else:
        assert not (scratchpad / "report_index.degraded").exists()
