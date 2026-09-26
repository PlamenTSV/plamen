"""Generated crash/resume matrix for the deterministic E2E test harness.

This reference workflow is intentionally tiny.  Its purpose is to pin the
harness contract that a real driver E2E can later reuse: every named transition
is crashable, resume converges byte-for-byte with an uninterrupted run, and a
redelivered provider request is not a second logical execution.
"""

from __future__ import annotations

from itertools import product
import json
from pathlib import Path

import pytest

from test_support.deterministic_e2e import (
    DeterministicProcessAdapter,
    OutcomeKind,
    ProcessRequest,
    ProcessResult,
    run_crash_resume_case,
    snapshot_tree,
)


STAGES = ("recon", "inventory", "report")
BOUNDARIES = (
    "before_provider",
    "after_provider_before_output",
    "after_output_before_commit",
    "after_commit",
)
def _adapter() -> DeterministicProcessAdapter:
    return DeterministicProcessAdapter(
        {
            ("fixture-provider", stage): ProcessResult(
                OutcomeKind.COMPLETED,
                0,
                stdout=f"accepted:{stage}\n".encode("utf-8"),
            )
            for stage in STAGES
        }
    )


def _load_checkpoint(root: Path) -> dict:
    path = root / "checkpoint.json"
    if not path.exists():
        return {"completed": []}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_bytes_atomic(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".pending")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _drive(root: Path, adapter: DeterministicProcessAdapter, fault) -> None:
    for stage in STAGES:
        checkpoint = _load_checkpoint(root)
        if stage in checkpoint["completed"]:
            continue

        fault(f"{stage}:before_provider")
        result = adapter.run(
            ProcessRequest(
                idempotency_key=f"fixture-run:{stage}:attempt-1",
                argv=("fixture-provider", stage),
                cwd="/fixture/project",
                stdin=f"input:{stage}\n".encode("utf-8"),
                environment=(("LANG", "C.UTF-8"),),
            )
        )
        assert result.kind is OutcomeKind.COMPLETED
        assert result.returncode == 0
        fault(f"{stage}:after_provider_before_output")

        _write_bytes_atomic(root / "outputs" / f"{stage}.txt", result.stdout)
        fault(f"{stage}:after_output_before_commit")

        checkpoint = _load_checkpoint(root)
        assert checkpoint["completed"] == list(
            STAGES[: STAGES.index(stage)]
        )
        checkpoint["completed"].append(stage)
        _write_bytes_atomic(
            root / "checkpoint.json",
            (
                json.dumps(checkpoint, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8"),
        )
        fault(f"{stage}:after_commit")


def _baseline(root: Path):
    root.mkdir()
    adapter = _adapter()
    _drive(root, adapter, lambda _point: None)
    assert len(adapter.executions) == len(STAGES)
    return snapshot_tree(root)


@pytest.mark.parametrize(
    ("stage", "boundary"),
    tuple(product(STAGES, BOUNDARIES)),
    ids=lambda value: value,
)
def test_every_transition_crash_resumes_to_uninterrupted_state(
    tmp_path: Path, stage: str, boundary: str
) -> None:
    expected = _baseline(tmp_path / "baseline")
    adapter = _adapter()
    observation = run_crash_resume_case(
        root=tmp_path / "resumed",
        adapter=adapter,
        crash_point=f"{stage}:{boundary}",
        drive=_drive,
        snapshot=snapshot_tree,
        expected_snapshot=expected,
    )

    assert observation.execution_count == len(STAGES)
    assert [row.idempotency_key for row in adapter.executions] == [
        f"fixture-run:{name}:attempt-1" for name in STAGES
    ]
    expected_replays = int(
        boundary
        in {"after_provider_before_output", "after_output_before_commit"}
    )
    assert observation.replay_count == expected_replays
    assert observation.delivery_count == len(STAGES) + expected_replays


def test_idempotency_key_cannot_mask_request_drift() -> None:
    adapter = _adapter()
    original = ProcessRequest(
        idempotency_key="fixture-run:recon:attempt-1",
        argv=("fixture-provider", "recon"),
        cwd="/fixture/project",
    )
    adapter.run(original)

    with pytest.raises(RuntimeError, match="different request"):
        adapter.run(
            ProcessRequest(
                idempotency_key=original.idempotency_key,
                argv=original.argv,
                cwd=original.cwd,
                stdin=b"mutated input",
            )
        )

    assert len(adapter.executions) == 1
    assert len(adapter.deliveries) == 1
