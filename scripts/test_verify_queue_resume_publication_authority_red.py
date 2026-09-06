"""Fixture-first RED contracts for queue publication authority on resume.

A completed queue checkpoint may be skipped only when the complete public
queue is still the exact ledger-committed T9 publication.  Plausible Markdown,
a self-consistent work-items/work-plan pair, or a partially retained public
bundle are not publication authority.

The tests exercise the driver's startup checkpoint reconciler rather than a
local validator.  Unrelated inventory parity is neutralized so each result is
caused only by the T9 publication boundary.  No audit, model, network request,
subprocess, or production artifact is launched.
"""
from __future__ import annotations

import json
from pathlib import Path
import time

import pytest

import artifact_ledger as ARTIFACT_LEDGER
import plamen_driver as DRIVER
import test_live_verify_queue_transaction_semantic_closure as LIVE
import verify_queue_phaseio_authority as PHASEIO


_PHASE_NAMES = (
    "verify_queue",
    "verify_runtime_descendant",
    "report_runtime_descendant",
)


def _phase(name: str, artifacts: list[str]) -> DRIVER.Phase:
    return DRIVER.Phase(
        name,
        ["Fixture"],
        artifacts,
        base_timeout_s=60,
        min_artifact_bytes=10,
    )


def _phases() -> list[DRIVER.Phase]:
    return [
        _phase("verify_queue", ["verification_queue.md"]),
        _phase("verify_runtime_descendant", []),
        _phase("report_runtime_descendant", []),
    ]


def _publish(
    project: Path,
    *,
    pipeline: str = "l1",
    backend: str = "claude",
) -> Path:
    result, _executor, scratchpad = LIVE._execute(
        project,
        pipeline,
        backend,
    )
    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    validation = LIVE._required_callable(
        "validate_live_verify_queue_publication"
    )(
        scratchpad=scratchpad,
        project_root=project,
        plan=LIVE._plan(pipeline, backend),
        run_id=f"live-{pipeline}-{backend}",
    )
    assert validation["safe_to_consume"] is True
    return scratchpad


def _checkpoint(root: Path) -> DRIVER.Checkpoint:
    del root
    # The existing bounded T0--T9 executable fixture deliberately uses a
    # readable non-UUID run label.  Reconciliation consumes the same in-memory
    # checkpoint object startup loads; checkpoint serialization itself is an
    # independent UUID-shape contract.
    return DRIVER.Checkpoint(
        run_id="live-l1-claude",
        completed=list(_PHASE_NAMES),
        degraded=[],
    )


def _startup_reconcile(
    root: Path,
    project: Path,
    checkpoint: DRIVER.Checkpoint,
    monkeypatch: pytest.MonkeyPatch,
) -> list[str]:
    # Inventory parity is an independent queue-content contract.  These tests
    # isolate whether startup requires exact publication authority even when
    # the visible queue content is otherwise acceptable.
    monkeypatch.setattr(
        DRIVER,
        "_validate_verification_queue_inventory_parity",
        lambda *_args, **_kwargs: [],
    )
    return DRIVER._reconcile_completed_checkpoint_artifacts(
        root,
        str(project),
        checkpoint,
        _phases(),
        "thorough",
        "rust",
        "l1",
        "claude",
    )


def _assert_full_queue_rewind(
    removed: list[str],
    checkpoint: DRIVER.Checkpoint,
) -> None:
    assert removed == list(_PHASE_NAMES)
    assert checkpoint.completed == []
    assert checkpoint.degraded == []


def test_exact_t9_publication_is_startup_noop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unchanged exact T9 publication retains every checkpoint."""

    project = tmp_path / "accepted"
    root = _publish(project)
    checkpoint = _checkpoint(root)
    public_before = {
        relative: (root / relative).read_bytes()
        for relative in LIVE._pipeline_public("l1")
        if (root / relative).is_file()
    }

    removed = _startup_reconcile(
        root,
        project,
        checkpoint,
        monkeypatch,
    )

    assert removed == []
    assert checkpoint.completed == list(_PHASE_NAMES)
    assert {
        relative: (root / relative).read_bytes()
        for relative in LIVE._pipeline_public("l1")
        if (root / relative).is_file()
    } == public_before


def test_exact_t9_resume_validation_has_linear_snapshot_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T0--T9 validation snapshots each unique path at most twice.

    The live fixture has 119 input-edge occurrences and 135 output records.
    Replaying every producer's complete output denominator for every input
    edge made this startup check quadratic.  The bound deliberately permits
    one initial and one terminal epoch snapshot for every occurrence even
    though a correct implementation normally does better by de-duplicating
    identities.
    """

    project = tmp_path / "linear-bound"
    root = _publish(project)
    original = ARTIFACT_LEDGER._stable_artifact_snapshot
    calls: list[str] = []

    def counted(path: Path):
        calls.append(str(Path(path)))
        return original(Path(path))

    monkeypatch.setattr(
        ARTIFACT_LEDGER,
        "_stable_artifact_snapshot",
        counted,
    )

    started = time.monotonic()
    issues = PHASEIO.validate_transaction_authority(
        scratchpad=root,
        project_root=project,
        plan=LIVE._plan("l1", "claude"),
        run_id="live-l1-claude",
    )
    elapsed = time.monotonic() - started

    assert issues == []
    assert len(calls) <= 2 * (119 + 135)
    assert elapsed < 60.0


def test_transaction_finish_follows_edge_reconciliation_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An edge hook cannot mutate a cached input after terminal validation."""

    project = tmp_path / "finish-after-edge"
    root = _publish(project)
    target = root / "caller_map.md"
    original_bytes = target.read_bytes()
    assert original_bytes
    metadata = target.stat()
    replacement_head = b"X" if original_bytes[:1] != b"X" else b"Y"
    mutated_bytes = replacement_head + original_bytes[1:]
    assert len(mutated_bytes) == len(original_bytes)
    original_edge_check = PHASEIO._transaction_edge_issues

    def mutate_after_edge_check(**kwargs):
        edge_issues = original_edge_check(**kwargs)
        target.write_bytes(mutated_bytes)
        ARTIFACT_LEDGER.os.utime(
            target,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
        )
        return edge_issues

    monkeypatch.setattr(
        PHASEIO,
        "_transaction_edge_issues",
        mutate_after_edge_check,
    )

    issues = PHASEIO.validate_transaction_authority(
        scratchpad=root,
        project_root=project,
        plan=LIVE._plan("l1", "claude"),
        run_id="live-l1-claude",
    )

    assert any(
        "artifact changed during validation epoch" in issue
        and "caller_map.md" in issue
        for issue in issues
    )


def test_validation_epoch_detects_mutation_and_is_not_cross_call_cached(
    tmp_path: Path,
) -> None:
    """A cache is local, and terminal revalidation closes its TOCTOU gap."""

    project = tmp_path / "epoch-project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    ARTIFACT_LEDGER.write_artifact_ledger(
        root,
        {
            "version": ARTIFACT_LEDGER.LEDGER_VERSION,
            "artifacts": {},
            "artifact_bindings": {},
            "work_units": {},
        },
    )
    artifact = root / "candidate.md"
    artifact.write_bytes(b"first\n")

    first = ARTIFACT_LEDGER._ArtifactValidationContext(root, project)
    initial, initial_error = first.snapshot(artifact)
    replay, replay_error = first.snapshot(artifact)
    assert replay == initial
    assert replay_error == initial_error == ""

    artifact.write_bytes(b"second\n")
    assert any(
        "artifact changed during validation epoch" in issue
        for issue in first.finish()
    )

    second = ARTIFACT_LEDGER._ArtifactValidationContext(root, project)
    current, current_error = second.snapshot(artifact)
    assert current_error == ""
    assert current is not None and initial is not None
    assert current["sha256"] != initial["sha256"]
    assert second.finish() == []


def test_validation_epoch_rejects_ledger_receipt_change(
    tmp_path: Path,
) -> None:
    """Producer/receipt cache keys cannot outlive their ledger generation."""

    project = tmp_path / "ledger-project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    ARTIFACT_LEDGER.write_artifact_ledger(
        root,
        {
            "version": ARTIFACT_LEDGER.LEDGER_VERSION,
            "artifacts": {},
            "artifact_bindings": {},
            "work_units": {},
        },
    )
    epoch = ARTIFACT_LEDGER._ArtifactValidationContext(root, project)
    changed = ARTIFACT_LEDGER.read_artifact_ledger(root)
    changed["work_units"]["producer:changed"] = {
        "commit_authority": {"receipt_digest": "0" * 64}
    }
    ARTIFACT_LEDGER.write_artifact_ledger(root, changed)

    assert "artifact ledger changed during validation epoch" in epoch.finish()


@pytest.mark.parametrize(
    "missing",
    (
        LIVE.FINAL_RECEIPT,
        "verification_context_packets.json",
    ),
    ids=("missing-t9-receipt", "partial-public-bundle"),
)
def test_incomplete_t9_publication_rewinds_queue_and_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
) -> None:
    """Shape-valid survivors cannot bless an incomplete T9 publication."""

    project = tmp_path / "incomplete"
    root = _publish(project)
    checkpoint = _checkpoint(root)
    assert (root / missing).is_file()
    (root / missing).unlink()
    assert (root / "verification_queue.md").is_file()
    assert (root / "verification_queue.work_items.json").is_file()
    assert (root / "verification_queue.work_plan.json").is_file()

    removed = _startup_reconcile(
        root,
        project,
        checkpoint,
        monkeypatch,
    )

    _assert_full_queue_rewind(removed, checkpoint)


def test_self_consistent_stale_work_pair_rewinds_queue_and_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A coherent pair from another publication is still stale authority."""

    project = tmp_path / "current"
    root = _publish(project, pipeline="l1", backend="claude")
    checkpoint = _checkpoint(root)

    foreign_project = tmp_path / "foreign"
    foreign_root = _publish(
        foreign_project,
        pipeline="sc",
        backend="codex",
    )
    pair = (
        "verification_queue.work_items.json",
        "verification_queue.work_plan.json",
    )
    before = {relative: (root / relative).read_bytes() for relative in pair}
    for relative in pair:
        (root / relative).write_bytes(
            (foreign_root / relative).read_bytes()
        )
    after = {relative: (root / relative).read_bytes() for relative in pair}
    assert after != before

    work_items = json.loads(after[pair[0]].decode("utf-8"))
    work_plan = json.loads(after[pair[1]].decode("utf-8"))
    assert [
        row["work_item_id"] for row in work_items["rows"]
    ] == work_plan["ordered_work_item_ids"]
    # The old T9 receipt and all other public outputs remain present, making
    # this stronger than a simple missing-file case.
    assert (root / LIVE.FINAL_RECEIPT).is_file()
    active_public = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    } & set(LIVE._pipeline_public("l1"))
    assert active_public == {
        relative
        for relative in LIVE._pipeline_public("l1")
        if relative != "compound_verification_delivery_debt.json"
    }

    removed = _startup_reconcile(
        root,
        project,
        checkpoint,
        monkeypatch,
    )

    _assert_full_queue_rewind(removed, checkpoint)
