"""Behavior parity for byte-only DRIVER successor materialization."""
from __future__ import annotations

from pathlib import Path

import pytest

from driver_successor_io import (
    canonicalize_trusted_driver_temporary_directory,
    materialize_driver_successor_transition,
)
import rooted_path_io as rooted_io
import plamen_driver as driver


def test_temporary_directory_canonicalizer_rejects_arbitrary_symlink(
    tmp_path: Path,
) -> None:
    referent = tmp_path / "referent"
    referent.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(referent, target_is_directory=True)

    with pytest.raises(rooted_io.RootedPathIOError):
        canonicalize_trusted_driver_temporary_directory(alias)


def test_exact_safe_postimage_is_inode_preserving_noop(tmp_path: Path) -> None:
    target = tmp_path / "output.json"
    target.write_bytes(b"exact\n")
    before = target.stat()
    assert materialize_driver_successor_transition(target, b"exact\n") is False
    after = target.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_mtime_ns,
    )


def test_shared_driver_publisher_cannot_replace_exact_safe_postimage(
    tmp_path: Path,
) -> None:
    """No phase may bypass no-op physical-identity preservation."""

    target = tmp_path / "canonical.md"
    target.write_bytes(b"canonical\n")
    before = target.stat()
    driver._atomic_driver_bytes(target, b"canonical\n")
    after = target.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_mtime_ns,
    )


def test_shared_driver_publisher_still_replaces_real_transition(
    tmp_path: Path,
) -> None:
    target = tmp_path / "canonical.md"
    target.write_bytes(b"before\n")
    before = target.stat()
    driver._atomic_driver_bytes(target, b"after\n")
    after = target.stat()
    assert target.read_bytes() == b"after\n"
    assert (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)


def test_different_or_missing_output_is_durably_replaced(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "output.json"
    assert materialize_driver_successor_transition(target, b"first\n") is True
    first_inode = target.stat().st_ino
    assert target.read_bytes() == b"first\n"
    assert materialize_driver_successor_transition(target, b"second\n") is True
    assert target.read_bytes() == b"second\n"
    assert target.stat().st_ino != first_inode


def test_hardlink_is_replaced_without_mutating_peer(tmp_path: Path) -> None:
    peer = tmp_path / "peer"
    target = tmp_path / "output"
    peer.write_bytes(b"old\n")
    target.hardlink_to(peer)
    assert materialize_driver_successor_transition(target, b"new\n") is True
    assert target.read_bytes() == b"new\n"
    assert peer.read_bytes() == b"old\n"
    assert target.stat().st_ino != peer.stat().st_ino


def test_symlink_is_replaced_without_mutating_referent(tmp_path: Path) -> None:
    referent = tmp_path / "referent"
    target = tmp_path / "output"
    referent.write_bytes(b"old\n")
    target.symlink_to(referent)
    assert materialize_driver_successor_transition(target, b"new\n") is True
    assert not target.is_symlink()
    assert target.read_bytes() == b"new\n"
    assert referent.read_bytes() == b"old\n"


def test_byte_publisher_callback_runs_only_for_replacement(tmp_path: Path) -> None:
    target = tmp_path / "output"
    target.write_bytes(b"old\n")
    calls: list[tuple[Path, bytes]] = []

    def publish(path: Path, raw: bytes) -> None:
        calls.append((path, raw))
        path.write_bytes(raw)

    assert materialize_driver_successor_transition(
        target, b"old\n", byte_publisher=publish,
    ) is False
    assert calls == []
    assert materialize_driver_successor_transition(
        target, b"new\n", byte_publisher=publish,
    ) is True
    assert calls == [(target, b"new\n")]
