from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import textwrap
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

import artifact_ledger as ledger_api


def _seed(scratchpad: Path, **extra: object) -> dict[str, object]:
    ledger = ledger_api.read_artifact_ledger(scratchpad)
    ledger.update(extra)
    ledger_api.write_artifact_ledger(scratchpad, ledger)
    return ledger_api.read_artifact_ledger(scratchpad)


def test_stale_expected_digest_is_rejected_without_publication(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    initial = _seed(scratchpad, cas_value="initial")
    initial_digest = ledger_api.artifact_ledger_digest(initial)

    def first(ledger: dict[str, object]) -> None:
        ledger["cas_value"] = "first"

    committed, committed_digest = ledger_api.compare_and_swap_artifact_ledger(
        scratchpad,
        expected_digest=initial_digest,
        mutator=first,
    )
    assert committed["cas_value"] == "first"
    assert committed_digest == ledger_api.artifact_ledger_digest(committed)

    with pytest.raises(
        ledger_api.ArtifactLedgerCASMismatch,
        match="preimage is stale",
    ):
        ledger_api.compare_and_swap_artifact_ledger(
            scratchpad,
            expected_digest=initial_digest,
            mutator=lambda value: value.update(cas_value="stale"),
        )
    assert ledger_api.read_artifact_ledger(scratchpad)["cas_value"] == "first"


def test_mutator_exception_publishes_no_partial_ledger(tmp_path: Path) -> None:
    scratchpad = tmp_path / "scratch"
    initial = _seed(scratchpad, cas_value="initial")
    expected_digest = ledger_api.artifact_ledger_digest(initial)
    ledger_path = scratchpad / ledger_api.LEDGER_NAME
    before = ledger_path.read_bytes()

    def interrupted(ledger: dict[str, object]) -> None:
        ledger["cas_value"] = "partial"
        raise RuntimeError("simulated callback crash")

    with pytest.raises(RuntimeError, match="callback crash"):
        ledger_api.compare_and_swap_artifact_ledger(
            scratchpad,
            expected_digest=expected_digest,
            mutator=interrupted,
        )
    assert ledger_path.read_bytes() == before
    assert ledger_api.read_artifact_ledger(scratchpad)["cas_value"] == "initial"


def test_publication_exception_keeps_preimage_and_cleans_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    initial = _seed(scratchpad, cas_value="initial")
    expected_digest = ledger_api.artifact_ledger_digest(initial)
    ledger_path = scratchpad / ledger_api.LEDGER_NAME
    before = ledger_path.read_bytes()

    def interrupted(_source: Path, _destination: Path) -> None:
        raise OSError("simulated durable replace interruption")

    monkeypatch.setattr(ledger_api, "_durable_replace", interrupted)
    with pytest.raises(OSError, match="replace interruption"):
        ledger_api.compare_and_swap_artifact_ledger(
            scratchpad,
            expected_digest=expected_digest,
            mutator=lambda value: value.update(cas_value="partial"),
        )
    assert ledger_path.read_bytes() == before
    assert not any(
        entry.name.startswith("_.p.") and entry.name.endswith(".tmp")
        for entry in scratchpad.iterdir()
    )


def test_invalid_candidate_is_rejected_before_publication(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    initial = _seed(scratchpad, cas_value="initial")
    expected_digest = ledger_api.artifact_ledger_digest(initial)
    ledger_path = scratchpad / ledger_api.LEDGER_NAME
    before = ledger_path.read_bytes()

    def invalidate(value: dict[str, object]) -> None:
        value["version"] = True
        value["cas_value"] = "partial"

    with pytest.raises(
        ledger_api.ArtifactLedgerError,
        match="unsupported artifact ledger version",
    ):
        ledger_api.compare_and_swap_artifact_ledger(
            scratchpad,
            expected_digest=expected_digest,
            mutator=invalidate,
        )
    assert ledger_path.read_bytes() == before


def test_two_processes_racing_one_preimage_have_exactly_one_winner(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    initial = _seed(scratchpad, cas_value="initial")
    expected_digest = ledger_api.artifact_ledger_digest(initial)
    scripts = Path(ledger_api.__file__).resolve().parent
    program = textwrap.dedent(
        """
        import pathlib
        import sys
        import time

        sys.path.insert(0, sys.argv[1])
        import artifact_ledger as api

        def mutate(value):
            value["cas_value"] = sys.argv[4]
            time.sleep(0.2)

        try:
            api.compare_and_swap_artifact_ledger(
                pathlib.Path(sys.argv[2]),
                expected_digest=sys.argv[3],
                mutator=mutate,
                timeout_s=5.0,
            )
        except api.ArtifactLedgerCASMismatch:
            raise SystemExit(23)
        """
    )
    commands = [
        [
            sys.executable,
            "-c",
            program,
            os.fspath(scripts),
            os.fspath(scratchpad),
            expected_digest,
            winner,
        ]
        for winner in ("alpha", "beta")
    ]
    processes = [subprocess.Popen(command) for command in commands]
    return_codes = [process.wait(timeout=15) for process in processes]
    assert sorted(return_codes) == [0, 23]
    assert ledger_api.read_artifact_ledger(scratchpad)["cas_value"] in {
        "alpha",
        "beta",
    }


def test_reader_serializes_with_concurrent_atomic_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run52: a valid sibling publication must not look like ledger tampering."""

    scratchpad = tmp_path / "scratch"
    initial = _seed(scratchpad, cas_value="initial")
    expected_digest = ledger_api.artifact_ledger_digest(initial)
    real_lock = ledger_api._ledger_transaction_lock
    real_read = ledger_api._read_stable_regular_bytes
    reader_thread: list[int] = []
    writer_thread: list[int] = []
    reader_inside_descriptor_read = threading.Event()
    writer_attempted_lock = threading.Event()
    writer_acquired_lock = threading.Event()

    @contextmanager
    def tracked_lock(scratchpad: Path, *, timeout_s: float = 30.0):
        is_writer = bool(
            writer_thread
            and threading.get_ident() == writer_thread[0]
        )
        if is_writer:
            writer_attempted_lock.set()
        with real_lock(scratchpad, timeout_s=timeout_s):
            if is_writer:
                writer_acquired_lock.set()
            yield

    def paused_read(*args, **kwargs):
        if (
            reader_thread
            and threading.get_ident() == reader_thread[0]
        ):
            reader_inside_descriptor_read.set()
            assert writer_attempted_lock.wait(5)
            assert not writer_acquired_lock.is_set()
        return real_read(*args, **kwargs)

    monkeypatch.setattr(ledger_api, "_ledger_transaction_lock", tracked_lock)
    monkeypatch.setattr(ledger_api, "_read_stable_regular_bytes", paused_read)

    def run_reader() -> dict[str, object]:
        reader_thread.append(threading.get_ident())
        return ledger_api.read_artifact_ledger(scratchpad)

    def run_writer() -> tuple[dict[str, object], str]:
        writer_thread.append(threading.get_ident())
        return ledger_api.compare_and_swap_artifact_ledger(
            scratchpad,
            expected_digest=expected_digest,
            mutator=lambda value: value.update(cas_value="published"),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(run_reader)
        assert reader_inside_descriptor_read.wait(5)
        write_future = pool.submit(run_writer)
        observed = read_future.result(timeout=10)
        published, _digest = write_future.result(timeout=10)

    assert observed["cas_value"] == "initial"
    assert published["cas_value"] == "published"
    assert writer_acquired_lock.is_set()
    assert ledger_api.read_artifact_ledger(scratchpad)["cas_value"] == "published"


def test_nested_same_thread_cas_preserves_inner_commit_and_stales_outer(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    initial = _seed(scratchpad, cas_value="initial")
    expected_digest = ledger_api.artifact_ledger_digest(initial)

    def outer(outer_value: dict[str, object]) -> None:
        def inner(inner_value: dict[str, object]) -> None:
            inner_value["cas_value"] = "inner"

        ledger_api.compare_and_swap_artifact_ledger(
            scratchpad,
            expected_digest=expected_digest,
            mutator=inner,
        )
        outer_value["cas_value"] = "outer"

    with pytest.raises(
        ledger_api.ArtifactLedgerCASMismatch,
        match="changed during mutation",
    ):
        ledger_api.compare_and_swap_artifact_ledger(
            scratchpad,
            expected_digest=expected_digest,
            mutator=outer,
        )
    assert ledger_api.read_artifact_ledger(scratchpad)["cas_value"] == "inner"


def test_legacy_read_write_remain_compatible_with_cas(tmp_path: Path) -> None:
    scratchpad = tmp_path / "scratch"
    legacy = _seed(scratchpad, compatibility=["legacy"])
    assert ledger_api.read_artifact_ledger(scratchpad) == legacy

    expected_digest = ledger_api.artifact_ledger_digest(legacy)
    committed, _digest = ledger_api.compare_and_swap_artifact_ledger(
        scratchpad,
        expected_digest=expected_digest,
        mutator=lambda value: value["compatibility"].append("cas"),
    )
    assert committed["compatibility"] == ["legacy", "cas"]

    legacy_after = ledger_api.read_artifact_ledger(scratchpad)
    legacy_after["compatibility"].append("legacy-after")
    ledger_api.write_artifact_ledger(scratchpad, legacy_after)
    assert ledger_api.read_artifact_ledger(scratchpad)["compatibility"] == [
        "legacy",
        "cas",
        "legacy-after",
    ]
