"""Regression coverage for idempotent depth-fuzz workspace preparation."""
from __future__ import annotations

from pathlib import Path

import fuzz_workspace_authority as F
import plamen_driver as D
from artifact_ledger import (
    active_committed_work_unit_authority_issues,
    read_artifact_ledger,
)


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "Counter.sol").write_text(
        "pragma solidity ^0.8.20; contract Counter {}\n",
        encoding="utf-8",
    )
    (root / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\n",
        encoding="utf-8",
    )
    return root


def test_depth_fuzz_workspace_preparation_replays_active_index_commit(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "mode": "thorough",
        "cli_backend": "claude",
        "_run_id": "RUN-FUZZ-REPLAY",
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }

    jobs = D._depth_fuzz_jobs_if_required(scratchpad, config)
    D._prepare_depth_fuzz_workspaces(
        jobs,
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
    )
    D._prepare_depth_fuzz_workspaces(
        jobs,
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
    )

    key = "sc/thorough/evm/claude/depth/fuzz_workspace.prepare"
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][key]
    assert unit["commit_authority"]["attempt_ordinal"] == 1
    assert unit.get("semantic_reexecution_history", []) == []
    assert active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=key,
        run_id=config["_run_id"],
        expected_artifact_identities=(
            f"scratchpad:{F.WORKSPACE_INDEX_FILE}",
        ),
    ) == []
