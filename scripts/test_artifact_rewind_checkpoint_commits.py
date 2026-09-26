"""Regression for projection-complete artifact-gate checkpoint rewind."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

import plamen_driver as driver
from plamen_types import Checkpoint, GateFailure, Phase, PhaseCommit


def _phase(name: str) -> Phase:
    return Phase(name, [name], [f"{name}.md"], 60)


def _commit(
    phase: Phase,
    run_id: str,
    *,
    debt: bool = False,
) -> PhaseCommit:
    failures = (
        GateFailure(
            gate_id=f"{phase.name}.coverage",
            gate_class="ARTIFACT_PRESENCE",
            message="retained downstream coverage debt",
            fallback_policy="CONSUME_WITH_DEBT",
        ),
    ) if debt else ()
    return PhaseCommit(
        phase_name=phase.name,
        state="COMPLETED_WITH_DEBT" if debt else "CLEAN",
        run_id=run_id,
        unresolved_failures=failures,
    )


def test_artifact_rewind_retires_complete_typed_suffix(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A saved rewind is itself a valid, idempotent resume checkpoint."""

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phases = [_phase(name) for name in ("recon", "breadth", "inventory")]
    run_id = str(uuid.uuid4())
    checkpoint = Checkpoint(
        completed=[phase.name for phase in phases],
        degraded=[phases[2].name],
        run_id=run_id,
        phase_commits={
            phases[0].name: _commit(phases[0], run_id),
            phases[1].name: _commit(phases[1], run_id),
            phases[2].name: _commit(phases[2], run_id, debt=True),
        },
    )

    monkeypatch.setattr(
        driver,
        "_resume_semantic_issues",
        lambda phase, *_args, **_kwargs: (
            ["breadth artifact authority is absent"]
            if phase.name == "breadth"
            else []
        ),
    )

    removed = driver._reconcile_completed_checkpoint_artifacts(
        scratchpad,
        str(tmp_path),
        checkpoint,
        phases,
        "thorough",
        "evm",
        "sc",
        "codex",
    )

    assert removed == ["breadth", "inventory"]
    assert checkpoint.completed == ["recon"]
    assert checkpoint.degraded == []
    assert set(checkpoint.phase_commits) == {"recon"}
    assert checkpoint.phase_commits["recon"] == _commit(phases[0], run_id)

    checkpoint.save(scratchpad)
    replay = Checkpoint.load(scratchpad)
    assert replay.validate_phase_names({phase.name for phase in phases}) == []
    assert driver._reconcile_completed_checkpoint_artifacts(
        scratchpad,
        str(tmp_path),
        replay,
        phases,
        "thorough",
        "evm",
        "sc",
        "codex",
    ) == []
    assert replay.completed == ["recon"]
    assert set(replay.phase_commits) == {"recon"}


@pytest.mark.parametrize("opt_in", [False, True])
def test_overflow_rewind_keeps_checkpoint_projections_consistent(
    tmp_path: Path, monkeypatch, opt_in: bool,
) -> None:
    phases = [_phase(name) for name in ("recon", "breadth", "inventory")]
    run_id = str(uuid.uuid4())
    commits = {phase.name: _commit(phase, run_id, debt=phase.name == "inventory")
               for phase in phases}
    checkpoint = Checkpoint(
        completed=[phase.name for phase in phases], degraded=["inventory"],
        rate_limited_at="inventory", run_id=run_id, phase_commits=dict(commits),
    )
    overflow = tmp_path / "_overflow" / "breadth"
    overflow.mkdir(parents=True)
    retained = b"quarantined work must survive rewind\n"
    (overflow / "foreign.md").write_bytes(retained)
    (tmp_path / "inventory.degraded").write_text("existing debt\n", encoding="utf-8")
    (tmp_path / "inventory.md").write_bytes(b"retained phase output\n")
    monkeypatch.setenv("PLAMEN_REWIND_ON_OVERFLOW", "1" if opt_in else "0")
    assert checkpoint.validate_phase_names({p.name for p in phases}) == []

    removed = driver._rewind_completed_after_overflow(tmp_path, checkpoint, phases)
    assert removed == (["breadth", "inventory"] if opt_in else [])
    assert checkpoint.completed == (["recon"] if opt_in else [p.name for p in phases])
    assert checkpoint.phase_commits == ({"recon": commits["recon"]} if opt_in else commits)
    assert checkpoint.degraded == ([] if opt_in else ["inventory"])
    assert checkpoint.rate_limited_at == (None if opt_in else "inventory")
    assert (tmp_path / "inventory.degraded").exists() is (not opt_in)
    assert (tmp_path / "inventory.md").read_bytes() == b"retained phase output\n"
    archived = list((tmp_path / "_overflow").glob("breadth_*/foreign.md"))
    assert len(archived) == 1 and archived[0].read_bytes() == retained

    checkpoint.save(tmp_path)
    replay = Checkpoint.load(tmp_path)
    assert replay.validate_phase_names({p.name for p in phases}) == []
    assert driver._rewind_completed_after_overflow(tmp_path, replay, phases) == []
