"""Stale-checkpoint mode-mismatch decision boundary.

Bug: a finished Thorough audit leaves _v2_checkpoint.json (completed phases incl.
skeptic/attention_repair/...). Launching a NEW Core audit in the same scratchpad
made the driver load that stale checkpoint, and _reconcile_completed_checkpoint_
artifacts raised RuntimeError("checkpoint references phases outside the active
graph") -> main() sys.exit(EXIT_DEGRADED) -> the run "just fails" right after the
user configures it.

P0-AO correction: a normal resume may not reinterpret a graph mismatch as
authorization to rename the checkpoint and start a fresh audit. The compatibility
helper is now a non-mutating detector that returns ``None`` so the caller stops.
"""
from __future__ import annotations

from pathlib import Path

import plamen_driver as D


def _save_checkpoint(scratch: Path, completed, *, mode: str):
    cp = D.Checkpoint(completed=list(completed), degraded=[])
    cp.config = {"mode": mode, "pipeline": "sc"}
    cp.save(scratch)
    return cp


def test_mode_mismatch_preserves_checkpoint_and_requires_decision(tmp_path: Path):
    # Thorough-only completed phases, simulate a Core launch.
    cp = _save_checkpoint(
        tmp_path,
        ["recon", "skeptic", "attention_repair", "invariants_p2"],
        mode="thorough",
    )
    exc = RuntimeError(
        "checkpoint references phases outside the active graph: "
        "skeptic, attention_repair, invariants_p2"
    )
    before = (tmp_path / "_v2_checkpoint.json").read_bytes()
    fresh = D._archive_stale_mismatched_checkpoint(
        tmp_path, cp, {"mode": "core", "pipeline": "sc"}, "core", exc
    )
    assert fresh is None
    assert (tmp_path / "_v2_checkpoint.json").read_bytes() == before
    assert not list(tmp_path.glob("_v2_checkpoint.*.bak-*.json"))


def test_graph_mismatch_does_not_rename_old_checkpoint(tmp_path: Path):
    cp = _save_checkpoint(tmp_path, ["recon", "skeptic"], mode="thorough")
    exc = RuntimeError("checkpoint references phases outside the active graph: skeptic")
    result = D._archive_stale_mismatched_checkpoint(
        tmp_path, cp, {"mode": "light", "pipeline": "sc"}, "light", exc
    )
    assert result is None
    txt = (tmp_path / "_v2_checkpoint.json").read_text(encoding="utf-8")
    assert "skeptic" in txt
    assert not list(tmp_path.glob("_v2_checkpoint.*.bak-*.json"))


def test_non_mismatch_error_returns_none(tmp_path: Path):
    # An unrelated RuntimeError (not a graph mismatch) must NOT be swallowed.
    cp = _save_checkpoint(tmp_path, ["recon"], mode="core")
    exc = RuntimeError("some other corruption: invalid root object")
    result = D._archive_stale_mismatched_checkpoint(
        tmp_path, cp, {"mode": "core", "pipeline": "sc"}, "core", exc
    )
    assert result is None, "non-mismatch error must hard-exit (return None)"
    # checkpoint left intact for the caller's hard-exit path
    assert (tmp_path / "_v2_checkpoint.json").exists()
    assert not list(tmp_path.glob("_v2_checkpoint.*.bak-*.json"))


def test_empty_checkpoint_mismatch_returns_none(tmp_path: Path):
    # No completed/degraded phases => nothing stale to recover; let caller decide.
    cp = D.Checkpoint(completed=[], degraded=[])
    cp.config = {"mode": "thorough"}
    cp.save(tmp_path)
    exc = RuntimeError("checkpoint references phases outside the active graph: x")
    result = D._archive_stale_mismatched_checkpoint(
        tmp_path, cp, {"mode": "core", "pipeline": "sc"}, "core", exc
    )
    assert result is None


def test_unknown_old_mode_when_no_config(tmp_path: Path):
    cp = D.Checkpoint(completed=["recon", "skeptic"], degraded=[])
    cp.config = None  # older checkpoint without embedded config
    cp.save(tmp_path)
    exc = RuntimeError("checkpoint references phases outside the active graph: skeptic")
    fresh = D._archive_stale_mismatched_checkpoint(
        tmp_path, cp, {"mode": "core", "pipeline": "sc"}, "core", exc
    )
    assert fresh is None
    assert (tmp_path / "_v2_checkpoint.json").exists()
    assert not list(tmp_path.glob("_v2_checkpoint.*.bak-*.json"))


def test_reconcile_still_raises_on_mode_mismatch(tmp_path: Path):
    """Confirms the TRIGGER my handler keys on: reconcile raises 'outside the
    active graph' when the checkpoint has phases absent from the active graph."""
    cp = D.Checkpoint(completed=["recon", "skeptic"], degraded=[])
    phases = [D.Phase("recon", ["Section"], ["recon_summary.md"],
                      base_timeout_s=60, min_artifact_bytes=10)]
    (tmp_path / "recon_summary.md").write_text("substantial recon\n", encoding="utf-8")
    raised = False
    try:
        D._reconcile_completed_checkpoint_artifacts(
            tmp_path, str(tmp_path), cp, phases, "core"
        )
    except RuntimeError as e:
        raised = "outside the active graph" in str(e)
    assert raised, "reconcile must raise the graph-mismatch error the handler catches"
