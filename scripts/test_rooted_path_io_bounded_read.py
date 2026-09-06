"""Descriptor-bound size and stability regressions for rooted reads."""
from __future__ import annotations

from pathlib import Path

import pytest

import rooted_path_io as R


@pytest.mark.parametrize("invalid", (True, -1))
def test_bounded_read_rejects_invalid_limits(tmp_path: Path, invalid: object):
    source = tmp_path / "input.bin"
    source.write_bytes(b"data")
    with pytest.raises(ValueError, match="max_bytes"):
        R.read_bytes(source, max_bytes=invalid)  # type: ignore[arg-type]


def test_bounded_read_accepts_exact_limit_and_default_is_unchanged(tmp_path: Path):
    source = tmp_path / "input.bin"
    raw = b"0123456789"
    source.write_bytes(raw)
    assert R.read_bytes(source, max_bytes=len(raw)) == raw
    assert R.read_bytes(source) == raw


def test_bounded_read_accepts_repeated_immediate_in_place_rewrites(tmp_path: Path):
    source = tmp_path / "input.bin"
    for ordinal in range(1, 33):
        raw = (f"revision-{ordinal}-".encode("ascii") * ordinal)
        source.write_bytes(raw)
        assert R.read_bytes(source, max_bytes=len(raw)) == raw


def test_bounded_read_rejects_preopen_oversize(tmp_path: Path):
    source = tmp_path / "input.bin"
    source.write_bytes(b"0123456789")
    with pytest.raises(R.RootedPathIOError, match="read bound"):
        R.read_bytes(source, max_bytes=9)


def test_bounded_read_rejects_same_inode_growth_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    source = tmp_path / "input.bin"
    source.write_bytes(b"01234567")

    def grow(opened: Path) -> None:
        assert opened == source.resolve()
        with source.open("ab") as handle:
            handle.write(b"growth")

    monkeypatch.setattr(R, "_bounded_read_pre_read_hook", grow)
    with pytest.raises(R.RootedPathIOError, match="read bound|changed"):
        R.read_bytes(source, max_bytes=8)
