"""DODO run47 (2026-09-20): a resume must recompute the launch-time snapshot.

The fresh-run startup runs ``prepare_snapshot_bound_inputs`` and its replayable
receipt is rendered into ``source_scope.coverage_limitations``.  The resume
startup skipped it, so the snapshot source component (and therefore the
whole-snapshot digest) differed while every component digest still matched;
the EVM workspace receipt then failed closed with "belongs to another
authority".  These tests pin the restore path.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import audit_snapshot  # noqa: E402
import plamen_driver as D  # noqa: E402
import recon_prepass as RP  # noqa: E402


def _config(tmp_path: Path) -> dict:
    project = tmp_path / "project"
    (project / "contracts").mkdir(parents=True)
    (project / "contracts" / "Main.sol").write_text(
        "pragma solidity ^0.8.20; contract Main {}\n", encoding="utf-8"
    )
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    return {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
    }


def _launch_receipt(config: dict) -> dict:
    fresh = dict(config)
    RP.prepare_snapshot_bound_inputs(fresh, posix_compat_v2=True)
    receipt = fresh["_snapshot_input_preparation"]
    assert receipt["status"] == "DEGRADED"
    assert "PRE_SNAPSHOT_MATERIALIZATION_DEFERRED" in receipt["reason"]
    return receipt


def test_resume_without_receipt_reproduces_the_run47_drift(tmp_path: Path) -> None:
    """Negative control: this is the exact defect (component digests equal, posture differs)."""
    config = _config(tmp_path)
    launch = dict(config, _snapshot_input_preparation=_launch_receipt(config))
    fresh = audit_snapshot._source_component(launch)
    resumed = audit_snapshot._source_component(dict(config))
    assert fresh["digest"] == resumed["digest"]
    assert fresh["coverage_limitations"] != resumed["coverage_limitations"]
    assert any("is DEGRADED" in row for row in fresh["coverage_limitations"])
    assert any("is UNAVAILABLE" in row for row in resumed["coverage_limitations"])


def test_restore_prefers_the_receipt_persisted_in_the_checkpoint(tmp_path: Path) -> None:
    config = _config(tmp_path)
    receipt = _launch_receipt(config)
    checkpoint = SimpleNamespace(config={"_snapshot_input_preparation": dict(receipt)})
    resumed = dict(config)
    D._restore_snapshot_input_preparation(checkpoint, resumed)
    assert resumed["_snapshot_input_preparation"] == receipt
    assert audit_snapshot._source_component(resumed) == audit_snapshot._source_component(
        dict(config, _snapshot_input_preparation=receipt)
    )


def test_restore_recomputes_the_posix_v2_deferral_when_checkpoint_lost_it(
    tmp_path: Path, monkeypatch
) -> None:
    """run47's checkpoint config had been overwritten by a failed resume; the
    compatibility deferral is deterministic and subprocess-free, so recompute it."""
    config = _config(tmp_path)
    receipt = _launch_receipt(config)
    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: True)
    checkpoint = SimpleNamespace(config={})
    resumed = dict(config)
    D._restore_snapshot_input_preparation(checkpoint, resumed)
    assert resumed["_snapshot_input_preparation"] == receipt


def test_restore_never_overwrites_a_present_receipt(tmp_path: Path) -> None:
    config = _config(tmp_path)
    present = {"schema_version": "x", "status": "PREPARED", "reason": "r", "preparation_sha256": "0" * 64}
    resumed = dict(config, _snapshot_input_preparation=dict(present))
    D._restore_snapshot_input_preparation(SimpleNamespace(config={"_snapshot_input_preparation": {"status": "DEGRADED"}}), resumed)
    assert resumed["_snapshot_input_preparation"] == present


def test_native_route_without_stored_receipt_stays_legacy(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: False)
    calls: list[int] = []
    monkeypatch.setattr(D, "_prepare_snapshot_bound_inputs", lambda cfg: calls.append(1))
    resumed = dict(config)
    D._restore_snapshot_input_preparation(SimpleNamespace(config={}), resumed)
    assert "_snapshot_input_preparation" not in resumed
    assert calls == []  # never materialize inputs on a native resume
