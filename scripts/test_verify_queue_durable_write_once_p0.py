"""Crash-safe publication fixtures for verify-queue write-once artifacts."""

from __future__ import annotations

import hashlib
import inspect
import os
from pathlib import Path
import sys

import pytest

import live_verify_queue_executor as LIVE
import rooted_path_io as RIO
import verify_queue_transaction as VQT


def _stages(directory: Path) -> list[Path]:
    return sorted(directory.glob(".plamen-write-once-*.stage"))


def _force_windows_directory_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[object, list[int]]:
    real_flush = RIO._FlushFileBuffers
    calls: list[int] = []

    def _flush(handle: int) -> int:
        calls.append(handle)
        return 0 if len(calls) == 1 else real_flush(handle)

    monkeypatch.setattr(RIO, "_FlushFileBuffers", _flush)
    return real_flush, calls


def test_short_write_failure_never_materializes_authoritative_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b'{"queue":"complete-postimage"}\n'
    real_write = RIO.os.write
    calls = 0

    def _partial_then_fail(descriptor: int, value: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, value[: max(1, len(value) // 2)])
        raise OSError("injected short-write crash")

    monkeypatch.setattr(RIO.os, "write", _partial_then_fail)

    with pytest.raises(
        RIO.DurableWriteOnceDebtError,
        match="short-write crash",
    ) as caught:
        RIO.durable_write_once_bytes(destination, expected)

    assert not destination.exists()
    stages = _stages(tmp_path)
    if sys.platform.startswith("linux"):
        assert stages == []
        assert caught.value.durability_debt["cleanup_state"] == (
            "ANONYMOUS_PUBLICATION_FAILED_ABSENT"
        )
    else:
        assert len(stages) == 1
        assert caught.value.durability_debt["stage"] == str(stages[0])
        assert caught.value.durability_debt["cleanup_state"] == (
            "PARTIAL_STAGE_PRESERVED"
        )


def test_exact_durable_stage_survives_publish_fault_and_resumes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b'{"queue":"complete-postimage"}\n'
    stage = RIO._write_once_stage_path(destination, expected)
    stage.write_bytes(expected)
    real_publish = RIO._publish_validated_write_once_stage

    def _fail_before_publish(
        source: Path, target: Path, _raw: bytes
    ) -> None:
        raise OSError("injected crash before publish")

    monkeypatch.setattr(
        RIO, "_publish_validated_write_once_stage", _fail_before_publish
    )
    with pytest.raises(OSError, match="crash before publish"):
        RIO.durable_write_once_bytes(destination, expected)

    stages = _stages(tmp_path)
    assert not destination.exists()
    assert len(stages) == 1
    assert stages[0].read_bytes() == expected

    monkeypatch.setattr(
        RIO, "_publish_validated_write_once_stage", real_publish
    )
    if sys.platform.startswith("linux"):
        with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
            RIO.durable_write_once_bytes(destination, expected)
        assert caught.value.cleanup_state == (
            "EXACT_STAGE_RETIREMENT_REQUIRES_RECOVERY"
        )
        stage.unlink()
        RIO.durable_write_once_bytes(destination, expected)
    else:
        RIO.durable_write_once_bytes(destination, expected)

    assert destination.read_bytes() == expected
    assert _stages(tmp_path) == []


def test_foreign_final_bytes_are_never_replaced(tmp_path: Path) -> None:
    destination = tmp_path / "verification_queue.json"
    destination.write_bytes(b'{"queue":"foreign"}\n')

    with pytest.raises(FileExistsError, match="foreign bytes"):
        RIO.durable_write_once_bytes(
            destination,
            b'{"queue":"expected"}\n',
        )

    assert destination.read_bytes() == b'{"queue":"foreign"}\n'
    assert _stages(tmp_path) == []


def test_exact_existing_postimage_is_idempotent_resume(tmp_path: Path) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b'{"queue":"already-published"}\n'
    destination.write_bytes(expected)

    RIO.durable_write_once_bytes(destination, expected)

    assert destination.read_bytes() == expected
    assert _stages(tmp_path) == []


def test_mismatched_deterministic_stage_is_explicit_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b'{"queue":"expected"}\n'
    stage = RIO._write_once_stage_path(destination, expected)
    stage.write_bytes(expected)
    stage.write_bytes(b"partial-or-foreign")

    expected_sha = hashlib.sha256(expected).hexdigest()
    observed = b"partial-or-foreign"
    with pytest.raises(RIO.RootedPathIOError, match="staging bytes") as caught:
        RIO.durable_write_once_bytes(destination, expected)

    assert not destination.exists()
    assert stage.read_bytes() == observed
    message = str(caught.value)
    assert str(stage) in message
    assert expected_sha in message
    assert hashlib.sha256(observed).hexdigest() in message
    assert f"expected_size={len(expected)}" in message
    assert f"observed_size={len(observed)}" in message


def test_exact_final_hardlink_alias_is_not_accepted(tmp_path: Path) -> None:
    expected = b'{"queue":"exact-but-aliased"}\n'
    origin = tmp_path / "foreign-alias-owner.json"
    destination = tmp_path / "verification_queue.json"
    origin.write_bytes(expected)
    os.link(origin, destination)

    with pytest.raises(RIO.RootedPathIOError, match="single-link"):
        RIO.durable_write_once_bytes(destination, expected)

    assert origin.read_bytes() == expected
    assert destination.stat().st_nlink >= 2


def test_exact_stage_hardlink_alias_is_not_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b'{"queue":"exact-but-aliased"}\n'
    destination = tmp_path / "verification_queue.json"
    stage = RIO._write_once_stage_path(destination, expected)
    origin = tmp_path / "foreign-stage-owner.json"
    origin.write_bytes(expected)
    os.link(origin, stage)

    with pytest.raises(RIO.RootedPathIOError, match="single-link"):
        RIO.durable_write_once_bytes(destination, expected)

    assert not destination.exists()
    assert origin.read_bytes() == expected


def test_stage_name_swap_after_validation_cannot_publish_foreign_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b'{"queue":"validated"}\n'
    foreign = b'{"queue":"swapped-foreign"}\n'
    destination = tmp_path / "verification_queue.json"
    displaced = tmp_path / ".displaced-validated-stage"
    stage = RIO._write_once_stage_path(destination, expected)
    stage.write_bytes(expected)
    fired = False

    def _swap(stage: Path, _destination: Path) -> None:
        nonlocal fired
        fired = True
        os.replace(stage, displaced)
        stage.write_bytes(foreign)

    monkeypatch.setattr(
        RIO,
        "_write_once_pre_publish_hook",
        _swap,
        raising=False,
    )

    with pytest.raises(
        RIO.DurableWriteOnceStageError,
        match="expected_sha256=.*observed_sha256",
    ):
        RIO.durable_write_once_bytes(destination, expected)

    assert fired is True
    # Publication is descriptor/handle-bound: a name swap may leave a foreign
    # deterministic stage (which must be surfaced), but can never become the
    # authoritative final.  Windows consumes the displaced validated object by
    # handle; POSIX may reject before publication, so both safe outcomes stand.
    if destination.exists():
        assert destination.read_bytes() == expected
    assert not displaced.exists() or displaced.read_bytes() == expected
    assert _stages(tmp_path)[0].read_bytes() == foreign


def test_no_replace_race_accepts_only_exact_concurrent_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b'{"queue":"concurrent-exact"}\n'
    destination = tmp_path / "verification_queue.json"
    monkeypatch.setattr(
        RIO,
        "_write_once_pre_publish_hook",
        lambda _stage, target: target.write_bytes(expected),
    )

    RIO.durable_write_once_bytes(destination, expected)

    assert destination.read_bytes() == expected
    assert destination.stat().st_nlink == 1
    assert _stages(tmp_path) == []


def test_no_replace_race_never_replaces_foreign_concurrent_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b'{"queue":"expected"}\n'
    foreign = b'{"queue":"foreign-race-winner"}\n'
    destination = tmp_path / "verification_queue.json"
    monkeypatch.setattr(
        RIO,
        "_write_once_pre_publish_hook",
        lambda _stage, target: target.write_bytes(foreign),
    )

    with pytest.raises(FileExistsError, match="foreign bytes"):
        RIO.durable_write_once_bytes(destination, expected)

    assert destination.read_bytes() == foreign
    assert destination.stat().st_nlink == 1
    if sys.platform.startswith("linux"):
        assert _stages(tmp_path) == []
    else:
        assert _stages(tmp_path)[0].read_bytes() == expected


def test_exact_final_resume_reestablishes_file_and_directory_durability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b'{"queue":"already-published"}\n'
    destination = tmp_path / "verification_queue.json"
    destination.write_bytes(expected)
    fsynced: list[int] = []
    flushed: list[int] = []
    directories: list[Path] = []
    real_fsync = RIO.os.fsync
    real_directory = RIO._fsync_directory
    real_flush = getattr(RIO, "_FlushFileBuffers", None)

    def _fsync(descriptor: int) -> None:
        fsynced.append(descriptor)
        real_fsync(descriptor)

    def _directory(path: Path) -> None:
        directories.append(Path(path))
        real_directory(path)

    monkeypatch.setattr(RIO.os, "fsync", _fsync)
    monkeypatch.setattr(RIO, "_fsync_directory", _directory)
    if os.name == "nt":
        def _flush(handle: int) -> int:
            flushed.append(handle)
            return real_flush(handle)

        monkeypatch.setattr(RIO, "_FlushFileBuffers", _flush)

    RIO.durable_write_once_bytes(destination, expected)

    assert flushed if os.name == "nt" else fsynced
    assert tmp_path in directories
    assert destination.read_bytes() == expected


def test_exact_stage_resume_reestablishes_durability_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b'{"queue":"staged"}\n'
    destination = tmp_path / "verification_queue.json"
    stage = RIO._write_once_stage_path(destination, expected)
    stage.write_bytes(expected)
    order: list[str] = []
    real_fsync = RIO.os.fsync
    real_directory = RIO._fsync_directory
    real_flush = getattr(RIO, "_FlushFileBuffers", None)

    def _fsync(descriptor: int) -> None:
        order.append("file_fsync")
        real_fsync(descriptor)

    def _directory(path: Path) -> None:
        order.append("directory_fsync")
        real_directory(path)

    monkeypatch.setattr(RIO.os, "fsync", _fsync)
    monkeypatch.setattr(RIO, "_fsync_directory", _directory)
    if os.name == "nt":
        def _flush(handle: int) -> int:
            order.append("file_flush")
            return real_flush(handle)

        monkeypatch.setattr(RIO, "_FlushFileBuffers", _flush)
    monkeypatch.setattr(
        RIO,
        "_write_once_pre_publish_hook",
        lambda _stage, _destination: order.append("publish"),
        raising=False,
    )

    if sys.platform.startswith("linux"):
        with pytest.raises(RIO.DurableWriteOnceDebtError):
            RIO.durable_write_once_bytes(destination, expected)
    else:
        RIO.durable_write_once_bytes(destination, expected)

    file_barrier = "file_flush" if os.name == "nt" else "file_fsync"
    assert order.index(file_barrier) < order.index("directory_fsync")
    assert order.index("directory_fsync") < order.index("publish")
    assert destination.read_bytes() == expected


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory fsync contract")
def test_write_once_publish_requests_parent_directory_durability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[Path] = []
    real_fsync_directory = RIO._fsync_directory

    def _observe(path: Path) -> None:
        observed.append(Path(path))
        real_fsync_directory(path)

    monkeypatch.setattr(RIO, "_fsync_directory", _observe)
    destination = tmp_path / "verification_queue.json"

    RIO.durable_write_once_bytes(destination, b"{}\n")

    assert destination.read_bytes() == b"{}\n"
    assert tmp_path in observed


def test_windows_publication_branch_requests_no_replace_without_emulation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This checks dispatch flags, not unsupported cross-host Win32 semantics."""

    source = tmp_path / ".prepared.stage"
    destination = tmp_path / "verification_queue.json"
    source.write_bytes(b"{}\n")
    observed: list[tuple[Path, Path, bool]] = []

    monkeypatch.setattr(RIO, "_windows_publication_host", lambda: True)
    monkeypatch.setattr(
        RIO,
        "_windows_move",
        lambda left, right, *, replace_existing: observed.append(
            (left, right, replace_existing)
        ),
    )

    RIO.durable_publish_new(source, destination)

    assert observed == [(source, destination, False)]


def test_queue_publishers_delegate_public_cas_and_keep_private_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Path, bytes]] = []

    def _record(path: Path, raw: bytes) -> None:
        calls.append((path, raw))

    monkeypatch.setattr(RIO, "durable_write_once_bytes", _record)
    public = tmp_path / "verification_queue.json"
    VQT._atomic_write(public, b"public\n")
    LIVE._cas_create_or_exact(tmp_path / "verification_queue.md", b"live\n")

    private = tmp_path / "_verify_queue_transaction" / "t0" / "status.json"
    VQT._atomic_write(private, b"first\n")
    VQT._atomic_write(private, b"second\n")

    assert calls == [
        (public, b"public\n"),
        (tmp_path / "verification_queue.md", b"live\n"),
    ]
    assert private.read_bytes() == b"second\n"


def test_legacy_exact_public_file_paths_remain_idempotent(tmp_path: Path) -> None:
    first = tmp_path / "verification_queue.json"
    second = tmp_path / "verification_queue.md"
    first.write_bytes(b"exact-json\n")
    second.write_bytes(b"exact-markdown\n")

    VQT._atomic_write(first, b"exact-json\n")
    LIVE._cas_create_or_exact(second, b"exact-markdown\n")

    assert first.read_bytes() == b"exact-json\n"
    assert second.read_bytes() == b"exact-markdown\n"


def test_stage_debt_metadata_survives_both_queue_wrappers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"expected-public-postimage\n"
    observed = b"partial-stage\n"
    real_publish = RIO._publish_validated_write_once_stage

    for destination in (
        tmp_path / "verification_queue.json",
        tmp_path / "verification_queue.md",
    ):
        monkeypatch.setattr(
            RIO,
            "_publish_validated_write_once_stage",
            lambda _source, _target, _raw: (_ for _ in ()).throw(
                OSError("stop-before-publish")
            ),
        )
        with pytest.raises(OSError, match="stop-before-publish"):
            RIO.durable_write_once_bytes(destination, expected)
        stage = _stages(tmp_path)[0]
        stage.write_bytes(observed)
        monkeypatch.setattr(
            RIO, "_publish_validated_write_once_stage", real_publish
        )

        if destination.suffix == ".json":
            with pytest.raises(VQT.VerifyQueueTransactionError) as caught:
                VQT._atomic_write(destination, expected)
        else:
            with pytest.raises(LIVE.LiveVerifyQueueError) as caught:
                LIVE._cas_create_or_exact(destination, expected)
        message = str(caught.value)
        assert str(stage) in message
        assert hashlib.sha256(expected).hexdigest() in message
        assert hashlib.sha256(observed).hexdigest() in message
        debt = caught.value.durability_debt
        assert debt["stage"] == str(stage)
        assert debt["destination"] == str(destination)
        assert debt["expected_sha256"] == hashlib.sha256(expected).hexdigest()
        assert debt["observed_sha256"] == hashlib.sha256(observed).hexdigest()
        assert debt["expected_size"] == len(expected)
        assert debt["observed_size"] == len(observed)
        assert debt["cleanup_state"] == "STAGE_MISMATCH_PRESERVED"
        stage.unlink()


@pytest.mark.skipif(os.name != "nt", reason="Windows share-mode contract")
def test_exact_final_resume_refuses_preexisting_write_capability(
    tmp_path: Path,
) -> None:
    expected = b'AAAAAAAAAAAAAAAA\n'
    foreign = b'BBBBBBBBBBBBBBBB\n'
    destination = tmp_path / "verification_queue.json"
    destination.write_bytes(expected)
    writer = RIO._CreateFileW(
        RIO.native_path(destination),
        RIO._GENERIC_WRITE,
        RIO._FILE_SHARE_READ | RIO._FILE_SHARE_WRITE | RIO._FILE_SHARE_DELETE,
        None,
        RIO._OPEN_EXISTING,
        0,
        None,
    )
    assert writer != RIO._INVALID_HANDLE_VALUE
    try:
        with pytest.raises(
            RIO.DurableWriteOnceDebtError,
            match="write-excluding handle",
        ) as caught:
            RIO.durable_write_once_bytes(destination, expected)
        assert caught.value.durability_debt["cleanup_state"] == (
            "EXACT_FINAL_NOT_EXCLUSIVELY_LOCKED"
        )
    finally:
        RIO._CloseHandle(writer)

    # Once the conflicting capability is released, exact resume is durable.
    assert destination.read_bytes() == expected
    RIO.durable_write_once_bytes(destination, expected)
    assert destination.read_bytes() == expected
    assert destination.read_bytes() != foreign


@pytest.mark.skipif(os.name != "nt", reason="Windows handle retirement contract")
def test_exact_stage_retirement_never_deletes_swapped_foreign_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"exact-stage\n"
    foreign = b"foreign-stage\n"
    destination = tmp_path / "verification_queue.json"
    destination.write_bytes(expected)
    stage = RIO._write_once_stage_path(destination, expected)
    stage.write_bytes(expected)
    displaced = tmp_path / ".validated-stage-displaced"
    fired = False

    def _swap(candidate: Path, _destination: Path) -> None:
        nonlocal fired
        fired = True
        os.replace(candidate, displaced)
        candidate.write_bytes(foreign)

    monkeypatch.setattr(
        RIO,
        "_write_once_pre_retire_hook",
        _swap,
        raising=False,
    )

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO.durable_write_once_bytes(destination, expected)

    assert fired is True
    assert destination.read_bytes() == expected
    assert stage.read_bytes() == foreign
    assert caught.value.durability_debt["cleanup_state"] == (
        "FOREIGN_STAGE_NAME_PRESERVED"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
def test_directory_barrier_success_keeps_marker_delete_excluding_through_retire(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "a" * 32
    source = tmp_path / f".plamen-dir-sync-{token}.stage"
    destination = tmp_path / f".plamen-dir-sync-{token}.done"
    displaced = tmp_path / ".displaced-directory-marker"
    real_rename = RIO._windows_rename_open_handle_new
    real_flush = RIO._FlushFileBuffers
    fired = False
    flush_calls = 0

    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": token})(),
    )
    def _force_directory_fallback(handle: int) -> int:
        nonlocal flush_calls
        flush_calls += 1
        return 0 if flush_calls == 1 else real_flush(handle)

    monkeypatch.setattr(RIO, "_FlushFileBuffers", _force_directory_fallback)

    def _rename_then_attack(handle: int, target: Path) -> None:
        nonlocal fired
        real_rename(handle, target)
        fired = True
        with pytest.raises(OSError):
            os.replace(target, displaced)

    monkeypatch.setattr(
        RIO, "_windows_rename_open_handle_new", _rename_then_attack
    )

    RIO._windows_directory_write_through_barrier(tmp_path)

    assert fired is True
    assert not source.exists()
    assert not destination.exists()
    assert not displaced.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
def test_directory_barrier_rename_failure_preserves_exact_marker_not_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "b" * 32
    source = tmp_path / f".plamen-dir-sync-{token}.stage"
    destination = tmp_path / f".plamen-dir-sync-{token}.done"
    displaced = tmp_path / ".displaced-directory-marker"
    real_flush = RIO._FlushFileBuffers
    fired = False
    flush_calls = 0

    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": token})(),
    )
    def _force_directory_fallback(handle: int) -> int:
        nonlocal flush_calls
        flush_calls += 1
        return 0 if flush_calls == 1 else real_flush(handle)

    monkeypatch.setattr(RIO, "_FlushFileBuffers", _force_directory_fallback)

    def _attack_then_fail(_handle: int, _target: Path) -> None:
        nonlocal fired
        fired = True
        with pytest.raises(OSError):
            os.replace(source, displaced)
        raise OSError("injected handle-bound rename failure")

    monkeypatch.setattr(
        RIO, "_windows_rename_open_handle_new", _attack_then_fail
    )

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO._windows_directory_write_through_barrier(tmp_path)

    assert fired is True
    assert source.read_bytes() == b"\x00"
    assert not destination.exists()
    assert not displaced.exists()
    debt = caught.value.durability_debt
    assert debt["stage"] == str(source)
    assert debt["destination"] == str(destination)
    assert debt["expected_sha256"] == hashlib.sha256(b"\x00").hexdigest()
    assert debt["observed_sha256"] == hashlib.sha256(b"\x00").hexdigest()
    assert debt["cleanup_state"] == (
        "DIRECTORY_BARRIER_RENAME_FAILED_MARKER_PRESERVED"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
@pytest.mark.parametrize(
    "boundary",
    ("before_rename", "after_rename", "after_publication_flush", "retire"),
)
def test_directory_barrier_hardlink_at_every_boundary_is_preserved_as_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    token = "c" * 32
    source = tmp_path / f".plamen-dir-sync-{token}.stage"
    destination = tmp_path / f".plamen-dir-sync-{token}.done"
    alias = tmp_path / f"attacker-{boundary}.alias"
    real_rename = RIO._windows_rename_open_handle_new
    real_mark = RIO._windows_mark_open_link_for_deletion
    real_flush, flush_calls = _force_windows_directory_fallback(monkeypatch)
    fired = False

    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": token})(),
    )

    def _rename(handle: int, target: Path) -> None:
        nonlocal fired
        if boundary == "before_rename":
            os.link(source, alias)
            fired = True
        real_rename(handle, target)
        if boundary == "after_rename":
            os.link(destination, alias)
            fired = True

    def _flush(handle: int) -> int:
        nonlocal fired
        # 1 = rejected directory flush, 2 = source data, 3 = renamed marker.
        result = 0 if not flush_calls else real_flush(handle)
        flush_calls.append(handle)
        if boundary == "after_publication_flush" and len(flush_calls) == 3:
            os.link(destination, alias)
            fired = True
        return result

    def _mark(handle: int) -> None:
        nonlocal fired
        if boundary == "retire":
            os.link(destination, alias)
            fired = True
        real_mark(handle)

    # Replace the helper-installed flush so this fixture can inject precisely
    # after the renamed marker's write-through flush.
    flush_calls.clear()
    monkeypatch.setattr(RIO, "_FlushFileBuffers", _flush)
    monkeypatch.setattr(RIO, "_windows_rename_open_handle_new", _rename)
    monkeypatch.setattr(RIO, "_windows_mark_open_link_for_deletion", _mark)

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO._windows_directory_write_through_barrier(tmp_path)

    assert fired is True
    assert alias.read_bytes() == b"\x00"
    assert source.exists() or destination.exists()
    assert all(
        path.read_bytes() == b"\x00"
        for path in (source, destination, alias)
        if path.exists()
    )
    assert "PRESERVED" in caught.value.durability_debt["cleanup_state"]


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
def test_directory_barrier_marker_collision_preserves_foreign_bytes_as_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "d" * 32
    source = tmp_path / f".plamen-dir-sync-{token}.stage"
    destination = tmp_path / f".plamen-dir-sync-{token}.done"
    foreign = b"foreign-directory-marker"
    source.write_bytes(foreign)
    _force_windows_directory_fallback(monkeypatch)
    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": token})(),
    )

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO._windows_directory_write_through_barrier(tmp_path)

    assert source.read_bytes() == foreign
    assert not destination.exists()
    debt = caught.value.durability_debt
    assert debt["observed_sha256"] == hashlib.sha256(foreign).hexdigest()
    assert debt["observed_size"] == len(foreign)
    assert debt["cleanup_state"] == (
        "DIRECTORY_BARRIER_MARKER_CREATE_FAILED_PRESERVED"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
def test_directory_barrier_retirement_failure_preserves_exact_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "e" * 32
    source = tmp_path / f".plamen-dir-sync-{token}.stage"
    destination = tmp_path / f".plamen-dir-sync-{token}.done"
    _force_windows_directory_fallback(monkeypatch)
    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": token})(),
    )
    monkeypatch.setattr(
        RIO,
        "_windows_mark_open_link_for_deletion",
        lambda _handle: (_ for _ in ()).throw(
            OSError("injected FileDisposition failure")
        ),
    )

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO._windows_directory_write_through_barrier(tmp_path)

    assert not source.exists()
    assert destination.read_bytes() == b"\x00"
    assert caught.value.durability_debt["cleanup_state"] == (
        "DIRECTORY_BARRIER_RETIREMENT_FAILED_MARKER_PRESERVED"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
def test_directory_barrier_vacated_source_replacement_is_preserved_as_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "f" * 32
    source = tmp_path / f".plamen-dir-sync-{token}.stage"
    destination = tmp_path / f".plamen-dir-sync-{token}.done"
    foreign = b"foreign-vacated-source"
    real_rename = RIO._windows_rename_open_handle_new
    _force_windows_directory_fallback(monkeypatch)
    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": token})(),
    )

    def _rename_then_replace_source(handle: int, target: Path) -> None:
        real_rename(handle, target)
        source.write_bytes(foreign)

    monkeypatch.setattr(
        RIO,
        "_windows_rename_open_handle_new",
        _rename_then_replace_source,
    )

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO._windows_directory_write_through_barrier(tmp_path)

    assert source.read_bytes() == foreign
    assert not destination.exists()
    assert caught.value.durability_debt["cleanup_state"] == (
        "DIRECTORY_BARRIER_FOREIGN_NAME_PRESERVED"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
def test_directory_barrier_post_retirement_replacement_is_preserved_as_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "1" * 32
    source = tmp_path / f".plamen-dir-sync-{token}.stage"
    destination = tmp_path / f".plamen-dir-sync-{token}.done"
    foreign = b"foreign-after-retirement"
    real_close = RIO._CloseHandle
    marker_handle: list[int] = []
    real_write = RIO._WriteFile
    _force_windows_directory_fallback(monkeypatch)
    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": token})(),
    )

    def _capture_write(handle, *args):
        marker_handle[:] = [handle]
        return real_write(handle, *args)

    def _close_then_replace(handle: int) -> int:
        result = real_close(handle)
        if marker_handle and handle == marker_handle[0]:
            destination.write_bytes(foreign)
        return result

    monkeypatch.setattr(RIO, "_WriteFile", _capture_write)
    monkeypatch.setattr(RIO, "_CloseHandle", _close_then_replace)

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO._windows_directory_write_through_barrier(tmp_path)

    assert not source.exists()
    assert destination.read_bytes() == foreign
    assert caught.value.durability_debt["cleanup_state"] == (
        "DIRECTORY_BARRIER_FOREIGN_NAME_PRESERVED"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
def test_directory_barrier_marker_handle_rejects_concurrent_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "2" * 32
    source = tmp_path / f".plamen-dir-sync-{token}.stage"
    destination = tmp_path / f".plamen-dir-sync-{token}.done"
    real_write = RIO._WriteFile
    denied = False
    _force_windows_directory_fallback(monkeypatch)
    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": token})(),
    )

    def _write_with_conflict_probe(handle, *args):
        nonlocal denied
        writer = RIO._CreateFileW(
            RIO.native_path(source),
            RIO._GENERIC_WRITE,
            RIO._FILE_SHARE_READ | RIO._FILE_SHARE_WRITE | RIO._FILE_SHARE_DELETE,
            None,
            RIO._OPEN_EXISTING,
            0,
            None,
        )
        denied = writer == RIO._INVALID_HANDLE_VALUE
        if writer != RIO._INVALID_HANDLE_VALUE:
            RIO._CloseHandle(writer)
        return real_write(handle, *args)

    monkeypatch.setattr(RIO, "_WriteFile", _write_with_conflict_probe)

    RIO._windows_directory_write_through_barrier(tmp_path)

    assert denied is True
    assert not source.exists()
    assert not destination.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory barrier contract")
def test_directory_barrier_crash_residue_is_preserved_and_next_barrier_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_token = "3" * 32
    second_token = "4" * 32
    first_source = tmp_path / f".plamen-dir-sync-{first_token}.stage"
    first_destination = tmp_path / f".plamen-dir-sync-{first_token}.done"
    second_source = tmp_path / f".plamen-dir-sync-{second_token}.stage"
    second_destination = tmp_path / f".plamen-dir-sync-{second_token}.done"
    real_rename = RIO._windows_rename_open_handle_new
    tokens = iter((first_token, second_token))
    monkeypatch.setattr(
        RIO.uuid,
        "uuid4",
        lambda: type("FixedUUID", (), {"hex": next(tokens)})(),
    )
    _force_windows_directory_fallback(monkeypatch)
    monkeypatch.setattr(
        RIO,
        "_windows_rename_open_handle_new",
        lambda _handle, _target: (_ for _ in ()).throw(
            OSError("injected crash before namespace transition")
        ),
    )

    with pytest.raises(RIO.DurableWriteOnceDebtError):
        RIO._windows_directory_write_through_barrier(tmp_path)
    assert first_source.read_bytes() == b"\x00"
    assert not first_destination.exists()

    _force_windows_directory_fallback(monkeypatch)
    monkeypatch.setattr(RIO, "_windows_rename_open_handle_new", real_rename)
    RIO._windows_directory_write_through_barrier(tmp_path)

    assert first_source.read_bytes() == b"\x00"
    assert not second_source.exists()
    assert not second_destination.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows handle publication contract")
@pytest.mark.parametrize(
    "hook_name,source_name",
    (
        ("_write_once_pre_rename_hook", "stage"),
        ("_write_once_post_publish_hook", "destination"),
    ),
)
def test_hardlink_inserted_at_publication_boundary_is_rolled_back_by_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hook_name: str,
    source_name: str,
) -> None:
    expected = b"single-link-publication\n"
    destination = tmp_path / "verification_queue.json"
    alias = tmp_path / "attacker-alias.json"
    fired = False

    def _link(stage: Path, target: Path) -> None:
        nonlocal fired
        fired = True
        source = stage if source_name == "stage" else target
        os.link(source, alias)

    monkeypatch.setattr(RIO, hook_name, _link, raising=False)

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO.durable_write_once_bytes(destination, expected)

    assert fired is True
    assert not destination.exists()
    assert alias.read_bytes() == expected
    assert caught.value.durability_debt["cleanup_state"] == (
        "PUBLISHED_LINK_ROLLED_BACK"
    )


def test_darwin_mutable_stage_clone_fails_closed_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"darwin-exact-stage\n"
    foreign = b"darwin-mutated-stage\n"
    destination = tmp_path / "verification_queue.json"
    stage = RIO._write_once_stage_path(destination, expected)
    stage.write_bytes(expected)
    clone_called = False

    def _unsafe_clone(descriptor: int, target: Path) -> str:
        nonlocal clone_called
        clone_called = True
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.write(descriptor, foreign)
        os.ftruncate(descriptor, len(foreign))
        target.write_bytes(foreign)
        return "CLONE"

    monkeypatch.setattr(RIO.sys, "platform", "darwin")
    monkeypatch.setattr(RIO, "_posix_link_open_descriptor", _unsafe_clone)

    with pytest.raises(
        RIO.DurableWriteOnceDebtError,
        match="immutable anonymous snapshot",
    ) as caught:
        RIO._posix_publish_open_stage(stage, destination, expected)

    assert clone_called is False
    assert not destination.exists()
    assert caught.value.durability_debt["cleanup_state"] == (
        "DARWIN_IMMUTABLE_SNAPSHOT_UNAVAILABLE"
    )


def test_linux_publication_uses_unnamed_descriptor_and_never_stage_unlink() -> None:
    publication = inspect.getsource(RIO._linux_publish_anonymous_bytes)
    retirement = inspect.getsource(RIO._retire_exact_write_once_stage)
    staged_publication = inspect.getsource(RIO._posix_publish_open_stage)

    assert "O_TMPFILE" in publication
    assert "_posix_link_open_descriptor(descriptor, destination)" in publication
    assert "os.unlink" not in publication
    assert "durable_unlink(stage)" not in retirement
    assert "os.unlink" not in staged_publication
