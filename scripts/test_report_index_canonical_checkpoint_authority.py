"""Checkpoint-independent run authority for report-index canonicalization."""
from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from artifact_ledger import read_artifact_ledger
from phase_io_contracts import resolve_phase_io_contract
from plamen_types import Checkpoint
from report_index_canonical_validator import (
    validate_report_index_canonical_bundle,
)
from queue_work_items import queue_records_to_json
import plamen_driver as D
import plamen_validators as V
import post_verify_candidate_delta as DELTA
import test_mechanical_successor_consumer_p0_ag1 as MECHANICAL
import test_post_verify_candidate_delta as POST_VERIFY
import test_report_index_canonical_successor_a0_blocking as CANONICAL


RUN_ID = "33333333-3333-4333-8333-333333333333"


def _file_state(path: Path) -> tuple[bytes, int, int, int, int]:
    stat = path.stat()
    return (
        path.read_bytes(),
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
    )


def _legacy_typed_stage(
    root: Path,
    *,
    run_id: str,
) -> tuple[Path, DELTA.CandidateUniverseAuthority]:
    authority = DELTA.load_candidate_universe_authority(
        root,
        run_id=run_id,
    )
    stage = root / ".pio" / "ri" / "checkpoint-authority" / "staged_target"
    stage.mkdir(parents=True)
    for relative in authority.input_artifacts:
        source = root / relative
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return stage, authority


def test_canonical_contract_refuses_mutable_checkpoint_control() -> None:
    with pytest.raises(ValueError, match="cannot bind mutable checkpoint control"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="light",
            ecosystem="evm",
            backend="codex",
            phase="report_index",
            work_unit_id="canonicalize",
            exact_inputs=("_v2_checkpoint.json",),
        )


def test_explicit_run_authority_supersedes_ambient_checkpoint_bytes(
    tmp_path: Path,
) -> None:
    MECHANICAL._bound_fixture(tmp_path)
    MECHANICAL._write_report_index(tmp_path)
    Checkpoint(
        completed=["sc_verify_queue"],
        run_id="44444444-4444-4444-8444-444444444444",
    ).save(tmp_path)

    receipt = V._project_report_index_status_authority(
        tmp_path,
        expected_run_id=MECHANICAL.RUN_ID,
    )
    view = V._mechanical_successor_authority_view(
        tmp_path,
        expected_run_id=MECHANICAL.RUN_ID,
    )
    wrong = V._mechanical_successor_authority_view(
        tmp_path,
        expected_run_id="55555555-5555-4555-8555-555555555555",
    )

    assert receipt["status"] == "CLEAN"
    assert view["status"] == "CLEAN"
    assert wrong["status"] == "DEGRADED"
    assert any("run identity mismatch" in issue for issue in wrong["issues"])
    before = {
        name: _file_state(tmp_path / name)
        for name in (
            "report_index.md",
            "report_index_status_projection.json",
        )
    }
    wrong_state = V._report_index_status_projection_state(
        tmp_path,
        (tmp_path / "report_index.md").read_text(encoding="utf-8"),
        expected_run_id="55555555-5555-4555-8555-555555555555",
    )
    assert any(
        "run identity mismatch" in issue
        for issue in wrong_state["authority_debt"]
    )
    issues = V._validate_report_index_status_authority(
        tmp_path,
        expected_run_id="55555555-5555-4555-8555-555555555555",
    )
    assert issues
    assert {
        name: _file_state(tmp_path / name)
        for name in before
    } == before
    V._project_report_index_status_authority(
        tmp_path,
        expected_run_id="55555555-5555-4555-8555-555555555555",
    )
    before_gate = {
        name: _file_state(tmp_path / name)
        for name in before
    }
    gate_issues = validate_report_index_canonical_bundle(
        tmp_path,
        pipeline="sc",
        run_id="55555555-5555-4555-8555-555555555555",
    )
    assert any("run identity mismatch" in issue for issue in gate_issues)
    assert {
        name: _file_state(tmp_path / name)
        for name in before_gate
    } == before_gate
    with pytest.raises(ValueError, match="non-empty trimmed string"):
        V._mechanical_successor_authority_view(
            tmp_path,
            expected_run_id=" ",
        )


def test_historical_stage_keeps_closed_residue_run_and_byte_boundaries(
    tmp_path: Path,
) -> None:
    config = CANONICAL._config(tmp_path)
    config["_run_id"] = RUN_ID
    root = Path(config["scratchpad"])
    CANONICAL._prepare_model_attempt(
        config,
        CANONICAL._report_index_bytes(medium_summary=1, medium_master=2),
    )
    markdown_stage = (
        root / ".pio" / "ri" / "markdown-history" / "staged_target"
    )
    markdown_stage.mkdir(parents=True)
    with DELTA.authenticated_historical_typed_stage_scope(
        root,
        markdown_stage,
        run_id=RUN_ID,
    ) as authority:
        assert authority is None

    typed_root = tmp_path / "typed" / ".scratchpad"
    typed_root.mkdir(parents=True)
    (typed_root / DELTA.BASE_QUEUE).write_text(
        queue_records_to_json((POST_VERIFY._base_item(),)) + "\n",
        encoding="utf-8",
    )
    stage, authority = _legacy_typed_stage(typed_root, run_id=RUN_ID)

    with pytest.raises(
        DELTA.PostVerifyCandidateDeltaError,
        match="run_id must be a non-empty trimmed string",
    ):
        with DELTA.authenticated_historical_typed_stage_scope(
            typed_root,
            stage,
            run_id=" ",
        ):
            pass
    with DELTA.authenticated_historical_typed_stage_scope(
        typed_root,
        stage,
        run_id=RUN_ID,
    ):
        projected = DELTA.load_current_report_candidate_universe_authority(
            stage,
            run_id=RUN_ID,
        )
        assert projected.candidates == authority.candidates
        with pytest.raises(DELTA.PostVerifyCandidateDeltaError, match="stage run"):
            DELTA.load_current_report_candidate_universe_authority(
                stage,
                run_id="66666666-6666-4666-8666-666666666666",
            )

    base = stage / DELTA.BASE_QUEUE
    base.write_bytes(base.read_bytes() + b" ")
    with pytest.raises(DELTA.PostVerifyCandidateDeltaError, match="differs"):
        with DELTA.authenticated_historical_typed_stage_scope(
            typed_root,
            stage,
            run_id=RUN_ID,
        ):
            pass
    shutil.copyfile(typed_root / DELTA.BASE_QUEUE, base)

    # Any live-transaction residue closes the legacy compatibility path.  A
    # private namespace without its genuine resolved plan must fail as partial
    # T9 state rather than being adopted as historical typed authority.
    (typed_root / "_live_verify_queue_transaction").mkdir()
    with pytest.raises(
        DELTA.PostVerifyCandidateDeltaError,
        match="live T9 publication residue",
    ):
        with DELTA.authenticated_historical_typed_stage_scope(
            typed_root,
            stage,
            run_id=RUN_ID,
        ):
            pass


def test_committed_canonical_replay_survives_natural_checkpoint_advance(
    tmp_path: Path,
) -> None:
    config = CANONICAL._config(tmp_path)
    config["_run_id"] = RUN_ID
    root = Path(config["scratchpad"])
    CANONICAL._prepare_model_attempt(
        config,
        CANONICAL._report_index_bytes(
            medium_summary=1,
            medium_master=2,
        ),
    )
    # Establish the checkpoint only after the genuine legacy R10/prework
    # fixture is complete.  Claiming a typed verify-queue completion here
    # would require the live T9 publication plan that this canonical component
    # fixture intentionally does not produce.
    Checkpoint(run_id=RUN_ID).save(root)

    assert D._run_report_index_canonicalization_transaction(
        CANONICAL._phase(),
        root,
        config,
    ) == []
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root,
        config,
    )
    assert "scratchpad:_v2_checkpoint.json" not in contract.immutable_inputs
    before_checkpoint = (root / "_v2_checkpoint.json").read_bytes()
    watched = {
        "ledger": _file_state(root / "_artifact_state.json"),
        **{
            item.path: _file_state(root / item.path)
            for item in contract.outputs
        },
    }

    resumed = Checkpoint.load(root)
    resumed.rate_limited_at = "report_body_writer_low_info"
    resumed.save(root)
    assert (root / "_v2_checkpoint.json").read_bytes() != before_checkpoint

    assert D._run_report_index_canonicalization_transaction(
        CANONICAL._phase(),
        root,
        config,
    ) == []
    assert {
        "ledger": _file_state(root / "_artifact_state.json"),
        **{
            item.path: _file_state(root / item.path)
            for item in contract.outputs
        },
    } == watched
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["run_id"] == RUN_ID
