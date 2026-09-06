"""Regression fixtures for public BB rooted publication on long Windows paths."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import bb_path_authority


_MAX_BYTES = 1024


def _long_relative_name() -> str:
    return "/".join(
        ["segment-" + ("a" * 46)] * 6
        + ["provider-request.json"]
    )


def test_public_rooted_publication_roundtrips_beyond_windows_max_path(
    tmp_path: Path,
) -> None:
    relative = _long_relative_name()
    target = tmp_path.joinpath(*relative.split("/"))
    assert len(str(target)) >= 377

    created = bb_path_authority.publish_rooted_bytes(
        tmp_path,
        relative,
        b"long-path-payload",
        label="public BB long-path fixture",
        replay_exact=False,
        max_bytes=_MAX_BYTES,
    )
    replayed = bb_path_authority.publish_rooted_bytes(
        tmp_path,
        relative,
        b"long-path-payload",
        label="public BB long-path fixture",
        replay_exact=True,
        max_bytes=_MAX_BYTES,
    )

    assert created.status == "CREATED"
    assert replayed.status == "EXACT_REPLAY"
    assert created.path == target
    assert (
        bb_path_authority.read_rooted_bytes(
            tmp_path,
            relative,
            label="public BB long-path fixture",
            max_bytes=_MAX_BYTES,
        )
        == b"long-path-payload"
    )


def test_public_interrupted_long_path_publication_cleans_and_resumes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = _long_relative_name()
    real_write = os.write
    writes = 0

    def interrupted_write(descriptor: int, raw: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            real_write(descriptor, raw[:1])
            raise OSError("fixture interruption after partial write")
        return real_write(descriptor, raw)

    monkeypatch.setattr(bb_path_authority.os, "write", interrupted_write)
    with pytest.raises(OSError, match="fixture interruption"):
        bb_path_authority.publish_rooted_bytes(
            tmp_path,
            relative,
            b"resume-payload",
            label="public BB interrupted long-path fixture",
            replay_exact=False,
            max_bytes=_MAX_BYTES,
        )

    monkeypatch.setattr(bb_path_authority.os, "write", real_write)
    resumed = bb_path_authority.publish_rooted_bytes(
        tmp_path,
        relative,
        b"resume-payload",
        label="public BB interrupted long-path fixture",
        replay_exact=False,
        max_bytes=_MAX_BYTES,
    )
    assert resumed.status == "CREATED"
    assert (
        bb_path_authority.read_rooted_bytes(
            tmp_path,
            relative,
            label="public BB interrupted long-path fixture",
            max_bytes=_MAX_BYTES,
        )
        == b"resume-payload"
    )


def test_public_rooted_read_rejects_hardlink_source_alias(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    source = tmp_path / "source.bin"
    source.write_bytes(b"aliased")
    try:
        os.link(source, root / "aliased.bin")
    except OSError as exc:
        pytest.skip(f"host cannot create a hardlink fixture: {exc}")

    with pytest.raises(
        bb_path_authority.BBPathAuthorityError,
        match="single-link",
    ):
        bb_path_authority.read_rooted_bytes(
            root,
            "aliased.bin",
            label="public BB hardlink source fixture",
            max_bytes=_MAX_BYTES,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows device namespace only")
@pytest.mark.parametrize("prefix", ("\\\\?\\", "\\\\.\\"))
def test_public_authority_rejects_caller_device_namespace(
    tmp_path: Path,
    prefix: str,
) -> None:
    raw = str(tmp_path)
    if prefix == "\\\\?\\":
        attempted = prefix + raw
    else:
        attempted = prefix + raw.removeprefix("\\")
    with pytest.raises(
        bb_path_authority.BBPathAuthorityError,
        match="device namespace",
    ):
        bb_path_authority.validate_directory_root(
            attempted,
            label="public BB device namespace fixture",
        )
