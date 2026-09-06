"""Compatibility regression for the retired resume-exclusion route.

P0-N preserves the original objective (do not rerun unrelated completed
shards) without acknowledging a late candidate as evidence-excluded.  The
driver actively queues the identity, gives it a bounded recovery assignment,
and rewinds only the aggregate/semantic descendants.
"""

from pathlib import Path

import pytest

import plamen_driver as D
import plamen_mechanical as M
import plamen_parsers as P
import plamen_types as T
import plamen_validators as V
from test_verify_queue_no_resume_revert import (
    _COVERED,
    _UNROUTED,
    _write_inventory,
    _write_partial_canonical_queue,
    _write_verify_files,
)


def _setup_completed_verify(sp: Path) -> None:
    _write_inventory(sp)
    _write_partial_canonical_queue(sp)
    _write_verify_files(sp)


def test_excluded_backfill_is_forbidden(tmp_path: Path):
    _setup_completed_verify(tmp_path)
    with pytest.raises(ValueError, match="active verification work"):
        M.backfill_unrouted_inventory_into_queue(tmp_path, route="excluded")
    assert not (tmp_path / "verification_queue_evidence_excluded.md").exists()
    assert V._compute_unrouted_inventory_ids(tmp_path) == _UNROUTED


def test_active_backfill_creates_real_verify_file_demand(tmp_path: Path):
    _setup_completed_verify(tmp_path)
    assert M.backfill_unrouted_inventory_into_queue(tmp_path) == _UNROUTED
    active = {row["finding id"] for row in P.parse_verification_queue_rows(tmp_path)}
    assert active == set(_COVERED + _UNROUTED)
    issues = V._validate_verify_files_for_queue(tmp_path)
    assert all(any(fid in issue for issue in issues) for fid in _UNROUTED)


def test_driver_recovers_late_rows_without_rewinding_completed_shards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _setup_completed_verify(tmp_path)
    phases = [phase for phase in T.L1_PHASES if "thorough" in phase.modes]
    start = next(i for i, phase in enumerate(phases) if phase.name == "verify_queue")
    checkpoint = T.Checkpoint(
        completed=[phase.name for phase in phases[start:]], degraded=[]
    )
    completed_shards = {
        phase.name for phase in phases if phase.name in T.L1_VERIFY_PHASE_NAMES
    }

    def recover(_config: dict, missing: list[tuple[str, dict]]) -> list[str]:
        for fid, row in missing:
            (tmp_path / f"verify_{fid}.md").write_text(
                f"# Verification: {fid}\n\n"
                f"**Finding ID**: {fid}\n"
                "**Verdict**: CONFIRMED\n"
                f"**Severity**: {row['severity']}\n"
                "**Evidence Tag**: [CODE-TRACE]\n\n"
                "Bounded recovery verifier output with sufficient substantive "
                "content to satisfy the ordinary verification file gate.\n",
                encoding="utf-8",
            )
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", recover)
    result = D._repair_late_verification_backfill(
        tmp_path,
        {
            "scratchpad": str(tmp_path),
            "project_root": str(tmp_path),
            "pipeline": "l1",
            "language": "rust",
            "mode": "thorough",
            "cli_backend": "claude",
        },
        checkpoint,
        phases,
        "thorough",
    )

    assert result["recovered"] == _UNROUTED
    assert completed_shards <= set(checkpoint.completed)
    assert "verify_aggregate" not in checkpoint.completed
    assert "report_index" not in checkpoint.completed
    assert V._validate_verify_files_for_queue(tmp_path) == []


def test_driver_late_recovery_is_exact_resume_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _setup_completed_verify(tmp_path)
    phases = [phase for phase in T.L1_PHASES if "thorough" in phase.modes]
    start = next(i for i, phase in enumerate(phases) if phase.name == "verify_queue")
    checkpoint = T.Checkpoint(
        completed=[phase.name for phase in phases[start:]], degraded=[]
    )
    calls = 0

    def recover(_config: dict, missing: list[tuple[str, dict]]) -> list[str]:
        nonlocal calls
        calls += 1
        for fid, row in missing:
            (tmp_path / f"verify_{fid}.md").write_text(
                f"# Verification: {fid}\n\n**Finding ID**: {fid}\n"
                f"**Verdict**: CONFIRMED\n**Severity**: {row['severity']}\n"
                "**Evidence Tag**: [CODE-TRACE]\n\n"
                "Substantive bounded recovery output for idempotency testing.\n",
                encoding="utf-8",
            )
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", recover)
    config = {
        "scratchpad": str(tmp_path),
        "project_root": str(tmp_path),
        "pipeline": "l1",
        "language": "rust",
        "mode": "thorough",
        "cli_backend": "claude",
    }
    D._repair_late_verification_backfill(
        tmp_path, config, checkpoint, phases, "thorough"
    )
    completed = list(checkpoint.completed)
    degraded = list(checkpoint.degraded)
    second = D._repair_late_verification_backfill(
        tmp_path, config, checkpoint, phases, "thorough"
    )

    assert calls == 1
    assert second["backfilled"] == []
    assert checkpoint.completed == completed
    assert checkpoint.degraded == degraded
