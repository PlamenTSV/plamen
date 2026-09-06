"""Production-consumer fixtures for the authenticated T9 report boundary."""
from __future__ import annotations

from pathlib import Path

import pytest

from post_verify_candidate_delta import PostVerifyCandidateDeltaError
import report_disposition_authority as DISPOSITION
import report_index_machinery as REPORT_INDEX
from test_report_candidate_universe_t9_publication_red import (
    RUN_ID,
    _commit_t9,
    _stale_item,
)
from queue_work_items import queue_records_to_json


def _stale_base(root: Path) -> None:
    (root / "verification_queue.work_items.json").write_text(
        queue_records_to_json((_stale_item(),)) + "\n",
        encoding="utf-8",
    )


@pytest.fixture
def committed_t9(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    root, _plan = _commit_t9(project)
    return project, root


def test_report_index_cannot_consume_a_rewritten_live_base(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    _stale_base(root)

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|receipt|commit)",
    ):
        REPORT_INDEX.build_report_index_candidates_json(root)


def test_report_index_cannot_downgrade_when_live_base_is_deleted(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    (root / "verification_queue.work_items.json").unlink()

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|receipt|commit)",
    ):
        REPORT_INDEX.build_report_index_candidates_json(root)


def test_report_disposition_cannot_consume_a_rewritten_live_base(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    _stale_base(root)

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|receipt|commit)",
    ):
        DISPOSITION._bound_queue_items(root, run_id=RUN_ID)
