from __future__ import annotations

from copy import deepcopy
import multiprocessing
from pathlib import Path
from queue import Empty
from threading import BrokenBarrierError
import time
from typing import Any, Mapping

from artifact_ledger import (
    ArtifactLedgerError,
    commit_immutable_generation_selection,
    read_artifact_ledger,
)
from test_program_facts_r21_shared_seams_r7 import (
    _commit_kwargs,
    _publication_vector,
    _selection_digest,
)


_JOIN_TIMEOUT_SECONDS = 30.0
_STALE_READ_BARRIER_TIMEOUT_SECONDS = 12.0
_WRITE_ORDER_TIMEOUT_SECONDS = 12.0
_POLL_SECONDS = 0.05


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
                # Once production owns the canonical interprocess transaction
                # lock, the second process cannot reach this barrier until the
                # first commits. The bounded break lets the first release that
                # lock, after which the second performs the real CAS/replay.
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


def _queued_detail(result_queue: Any) -> str:
    try:
        return repr(result_queue.get(timeout=1.0))
    except Empty:
        return "no typed child result"


def _wait_for_first_read(
    process: Any,
    first_read_event: Any,
    result_queue: Any,
) -> None:
    deadline = time.monotonic() + _JOIN_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if first_read_event.wait(timeout=_POLL_SECONDS):
            return
        if process.exitcode is not None:
            process.join(timeout=1.0)
            detail = _queued_detail(result_queue)
            raise AssertionError(
                "first child exited before capturing its ledger preimage: "
                f"exitcode={process.exitcode}, result={detail}"
            )
    raise AssertionError("first child never captured its ledger preimage")


def _wait_for_children(processes: list[Any]) -> None:
    deadline = time.monotonic() + _JOIN_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        unfinished = [
            process for process in processes if process.exitcode is None
        ]
        if not unfinished:
            break
        for process in unfinished:
            process.join(timeout=_POLL_SECONDS)
    unfinished = [process for process in processes if process.exitcode is None]
    if unfinished:
        raise AssertionError(
            "child process exceeded the bounded join: "
            + ", ".join(process.name for process in unfinished)
        )
    failures = [
        (process.name, process.exitcode)
        for process in processes
        if process.exitcode != 0
    ]
    assert not failures, failures


def _terminate_and_join_started(processes: list[Any]) -> None:
    for process in processes:
        if process.is_alive():
            process.terminate()
    for process in processes:
        process.join(timeout=5.0)
    survivors = [process for process in processes if process.is_alive()]
    for process in survivors:
        process.kill()
    for process in survivors:
        process.join(timeout=5.0)
    final_survivors = [process.name for process in processes if process.is_alive()]
    assert not final_survivors, (
        "child process survived terminate/kill cleanup: "
        + ", ".join(final_survivors)
    )


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
    started: list[Any] = []
    try:
        processes[0].start()
        started.append(processes[0])
        start_event.set()
        _wait_for_first_read(
            processes[0],
            first_read_event,
            result_queue,
        )
        processes[1].start()
        started.append(processes[1])
        _wait_for_children(started)

        results = []
        for _ in started:
            try:
                results.append(result_queue.get(timeout=5.0))
            except Empty as exc:
                raise AssertionError("child exited without a result") from exc
        return sorted(results, key=lambda row: row["lane"])
    finally:
        # This scope begins before the first Process.start(). Every startup,
        # first-read, second-start, join, queue, or assertion failure therefore
        # converges on the same process and feeder-thread cleanup.
        _terminate_and_join_started(started)
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


def test_t1_v2_control_single_process_commit_and_exact_replay_are_idempotent(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(
        root,
        "T-1-V2/control-single-process-idempotent",
        transaction_nonce="t1-v2-control",
    )
    first = commit_immutable_generation_selection(**_commit_kwargs(vector))
    replay = commit_immutable_generation_selection(**_commit_kwargs(vector))

    assert first["idempotent_replay"] is False
    assert replay == {**first, "idempotent_replay": True}
    assert first["selection_digest"] == _selection_digest(vector["selection"])
    _assert_one_active_history_row(root, winning_result=first)


def test_t1_v2_red_two_processes_from_same_absent_head_have_one_cas_winner(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    first = _publication_vector(
        root,
        "T-1-V2/interprocess-distinct-stale-preimage",
        transaction_nonce="t1-v2-distinct-first",
    )
    second = _publication_vector(
        root,
        "T-1-V2/interprocess-distinct-stale-preimage",
        transaction_nonce="t1-v2-distinct-second",
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


def test_t1_v2_red_two_processes_identical_generation_allow_only_exact_replay(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(
        root,
        "T-1-V2/interprocess-identical-idempotent",
        transaction_nonce="t1-v2-identical",
    )
    kwargs = _commit_kwargs(vector)
    results = _run_synchronized_pair(kwargs, deepcopy(kwargs))

    assert all(row["outcome"] == "SUCCESS" for row in results), results
    assert sorted(row["idempotent_replay"] for row in results) == [False, True]
    assert len({row["generation_id"] for row in results}) == 1
    assert len({row["selection_digest"] for row in results}) == 1
    winner = next(row for row in results if not row["idempotent_replay"])
    _assert_one_active_history_row(root, winning_result=winner)
