from __future__ import annotations

from copy import deepcopy
import multiprocessing
from pathlib import Path
from queue import Empty
from threading import BrokenBarrierError
from typing import Any, Mapping

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    commit_immutable_generation_selection,
    read_artifact_ledger,
)
from test_program_facts_r21_shared_seams_r7 import (
    _active_prestate,
    _commit_kwargs,
    _publication_vector,
    _selection_digest,
)


_JOIN_TIMEOUT_SECONDS = 30.0
_STALE_READ_BARRIER_TIMEOUT_SECONDS = 12.0
_WRITE_ORDER_TIMEOUT_SECONDS = 12.0


def _selection_worker(
    lane: str,
    kwargs: Mapping[str, Any],
    start_event: Any,
    first_read_event: Any,
    stale_read_barrier: Any,
    first_write_done: Any,
    result_queue: Any,
) -> None:
    """Run one real commit with deterministic process-level race controls."""

    import artifact_ledger

    original_read = artifact_ledger.read_artifact_ledger
    original_write = artifact_ledger.write_artifact_ledger
    read_count = 0

    def synchronized_read(scratchpad: Path) -> dict[str, Any]:
        nonlocal read_count
        snapshot = original_read(scratchpad)
        read_count += 1
        if read_count == 1:
            if lane == "first":
                first_read_event.set()
            try:
                stale_read_barrier.wait(
                    timeout=_STALE_READ_BARRIER_TIMEOUT_SECONDS
                )
            except BrokenBarrierError:
                # With the repaired interprocess transaction lock, the first
                # owner times out here while the peer is correctly blocked.
                # It must then commit and release the lock so the peer can
                # observe the new ACTIVE head and perform the real CAS.
                pass
        return snapshot

    def ordered_write(
        scratchpad: Path,
        ledger: dict[str, Any],
    ) -> None:
        if lane == "first":
            original_write(scratchpad, ledger)
            first_write_done.set()
            return
        if not first_write_done.wait(timeout=_WRITE_ORDER_TIMEOUT_SECONDS):
            raise RuntimeError("first process never published its postimage")
        original_write(scratchpad, ledger)

    artifact_ledger.read_artifact_ledger = synchronized_read
    artifact_ledger.write_artifact_ledger = ordered_write
    try:
        if not start_event.wait(timeout=_JOIN_TIMEOUT_SECONDS):
            raise RuntimeError("parent never released the process start gate")
        result = artifact_ledger.commit_immutable_generation_selection(
            **dict(kwargs)
        )
        result_queue.put(
            {
                "lane": lane,
                "outcome": "SUCCESS",
                "generation_id": result["generation_id"],
                "selection_digest": result["selection_digest"],
                "idempotent_replay": result["idempotent_replay"],
            }
        )
    except BaseException as exc:  # child must report, not disappear
        result_queue.put(
            {
                "lane": lane,
                "outcome": "ERROR",
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            }
        )
    finally:
        artifact_ledger.read_artifact_ledger = original_read
        artifact_ledger.write_artifact_ledger = original_write


def _join_cleanly(processes: list[Any]) -> None:
    alive: list[Any] = []
    for process in processes:
        process.join(timeout=_JOIN_TIMEOUT_SECONDS)
        if process.is_alive():
            alive.append(process)
    for process in alive:
        process.terminate()
    for process in alive:
        process.join(timeout=5.0)
    assert not alive, "child process exceeded the bounded join"
    assert all(process.exitcode == 0 for process in processes), [
        (process.name, process.exitcode) for process in processes
    ]


def _run_synchronized_pair(
    first_kwargs: Mapping[str, Any],
    second_kwargs: Mapping[str, Any],
) -> list[dict[str, Any]]:
    ctx = multiprocessing.get_context("spawn")
    start_event = ctx.Event()
    first_read_event = ctx.Event()
    stale_read_barrier = ctx.Barrier(2)
    first_write_done = ctx.Event()
    result_queue = ctx.Queue()
    processes = [
        ctx.Process(
            name="program-facts-selection-first",
            target=_selection_worker,
            args=(
                "first",
                dict(first_kwargs),
                start_event,
                first_read_event,
                stale_read_barrier,
                first_write_done,
                result_queue,
            ),
        ),
        ctx.Process(
            name="program-facts-selection-second",
            target=_selection_worker,
            args=(
                "second",
                dict(second_kwargs),
                start_event,
                first_read_event,
                stale_read_barrier,
                first_write_done,
                result_queue,
            ),
        ),
    ]
    processes[0].start()
    start_event.set()
    assert first_read_event.wait(timeout=_JOIN_TIMEOUT_SECONDS), (
        "first child never captured its ledger preimage"
    )
    processes[1].start()
    try:
        _join_cleanly(processes)
        results = []
        for _ in processes:
            try:
                results.append(result_queue.get(timeout=5.0))
            except Empty as exc:
                raise AssertionError("child exited without a result") from exc
        return sorted(results, key=lambda row: row["lane"])
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5.0)
        result_queue.close()
        result_queue.join_thread()


def _assert_one_active_history_row(
    root: Path,
    *,
    winning_result: Mapping[str, Any],
) -> None:
    ledger = read_artifact_ledger(root)
    history = ledger["program_facts_v2_generation_selections"]
    active = ledger["program_facts_v2_active_selection"]
    assert len(history) == 1
    assert set(history) == {winning_result["generation_id"]}
    assert history[winning_result["generation_id"]]["selection_digest"] == (
        winning_result["selection_digest"]
    )
    assert active == {
        "state": "PRESENT",
        "generation_id": winning_result["generation_id"],
        "selection_digest": winning_result["selection_digest"],
    }


def test_t1_control_single_process_commit_and_exact_replay_are_idempotent(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(
        root,
        "T-1/control-single-process-idempotent",
        transaction_nonce="t1-control",
    )
    first = commit_immutable_generation_selection(**_commit_kwargs(vector))
    replay = commit_immutable_generation_selection(**_commit_kwargs(vector))

    assert first["idempotent_replay"] is False
    assert replay == {**first, "idempotent_replay": True}
    assert first["selection_digest"] == _selection_digest(vector["selection"])
    _assert_one_active_history_row(root, winning_result=first)


def test_t1_red_two_processes_from_same_absent_head_have_one_cas_winner(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    first = _publication_vector(
        root,
        "T-1/interprocess-distinct-stale-preimage",
        transaction_nonce="t1-distinct-first",
    )
    second = _publication_vector(
        root,
        "T-1/interprocess-distinct-stale-preimage",
        transaction_nonce="t1-distinct-second",
    )
    assert first["selection"]["prior_active"] == {"state": "ABSENT"}
    assert second["selection"]["prior_active"] == {"state": "ABSENT"}
    assert first["selection"]["generation_id"] != second["selection"][
        "generation_id"
    ]

    results = _run_synchronized_pair(
        _commit_kwargs(first),
        _commit_kwargs(second),
    )
    successes = [row for row in results if row["outcome"] == "SUCCESS"]
    errors = [row for row in results if row["outcome"] == "ERROR"]

    assert len(successes) == 1, results
    assert successes[0]["idempotent_replay"] is False
    assert len(errors) == 1, results
    assert errors[0]["error_type"] == ArtifactLedgerError.__name__
    assert "Program Facts prior ACTIVE selection CAS failed" in errors[0][
        "error_message"
    ]
    _assert_one_active_history_row(root, winning_result=successes[0])


def test_t1_red_two_processes_identical_generation_allow_only_exact_replay(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(
        root,
        "T-1/interprocess-identical-idempotent",
        transaction_nonce="t1-identical",
    )
    kwargs = _commit_kwargs(vector)
    results = _run_synchronized_pair(kwargs, deepcopy(kwargs))

    assert all(row["outcome"] == "SUCCESS" for row in results), results
    assert sorted(row["idempotent_replay"] for row in results) == [False, True]
    assert len({row["generation_id"] for row in results}) == 1
    assert len({row["selection_digest"] for row in results}) == 1
    winner = next(row for row in results if not row["idempotent_replay"])
    _assert_one_active_history_row(root, winning_result=winner)
