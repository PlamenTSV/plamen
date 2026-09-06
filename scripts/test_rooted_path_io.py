"""Cross-platform contracts for the shared rooted artifact-I/O layer."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import rooted_path_io as RIO


def test_portable_checked_read_and_descendant_contract(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "ExactDir"
    directory.mkdir()
    artifact = directory / "Evidence.JSON"
    artifact.write_bytes(b'{"status":"BOUND"}\n')

    assert RIO.checked_directory(tmp_path) == tmp_path
    assert RIO.checked_file(artifact) == artifact
    assert RIO.read_bytes(artifact) == b'{"status":"BOUND"}\n'
    assert (
        RIO.safe_descendant(
            tmp_path,
            "ExactDir/Evidence.JSON",
            allow_missing=False,
        )
        == artifact
    )
    with pytest.raises(RIO.RootedPathIOError, match="safe relative path"):
        RIO.safe_descendant(
            tmp_path,
            "../escape",
            allow_missing=False,
        )
    with pytest.raises(
        RIO.RootedPathIOError,
        match="casing mismatch|missing",
    ):
        RIO.safe_descendant(
            tmp_path,
            "exactdir/evidence.json",
            allow_missing=False,
        )


def test_portable_descendant_rejects_symlink_or_reparse(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evidence.json").write_bytes(b"{}\n")
    link = tmp_path / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(
        RIO.RootedPathIOError,
        match="symlink/reparse",
    ):
        RIO.safe_descendant(
            tmp_path,
            "link/evidence.json",
            allow_missing=False,
        )


def test_native_spelling_is_platform_local(tmp_path: Path) -> None:
    lexical = tmp_path / "directory" / ".." / "artifact.json"
    native = RIO.native_path(lexical)
    expected = os.path.abspath(os.fspath(lexical))
    if os.name == "nt":
        assert native == "\\\\?\\" + expected
    else:
        assert native == expected
        assert not native.startswith("\\\\?\\")


def test_durable_replace_publishes_exact_successor(
    tmp_path: Path,
) -> None:
    target = tmp_path / "authority.json"
    source = tmp_path / ".authority.tmp"
    target.write_bytes(b'{"generation":1}\n')
    source.write_bytes(b'{"generation":2}\n')

    RIO.durable_replace(source, target)

    assert target.read_bytes() == b'{"generation":2}\n'
    assert not RIO.lexists(source)


def test_durable_publish_new_is_write_once_and_consumes_source(
    tmp_path: Path,
) -> None:
    target = tmp_path / "authority-cas.json"
    source = tmp_path / ".authority.tmp"
    source.write_bytes(b'{"authority":"first"}\n')

    RIO.durable_publish_new(source, target)

    assert target.read_bytes() == b'{"authority":"first"}\n'
    assert not RIO.lexists(source)

    replay = tmp_path / ".authority-replay.tmp"
    replay.write_bytes(b'{"authority":"second"}\n')
    with pytest.raises(FileExistsError):
        RIO.durable_publish_new(replay, target)
    assert target.read_bytes() == b'{"authority":"first"}\n'
    assert replay.read_bytes() == b'{"authority":"second"}\n'


def test_link_fallback_recovers_interrupted_two_name_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "authority-cas.json"
    source = tmp_path / ".authority-cas.publishing.tmp"
    source.write_bytes(b'{"authority":"recoverable"}\n')
    real_retire = RIO._retire_publication_source
    interrupted = False

    def _interrupt_once(path: Path) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise OSError("simulated interruption after link")
        real_retire(path)

    monkeypatch.setattr(
        RIO,
        "_retire_publication_source",
        _interrupt_once,
    )
    with pytest.raises(OSError, match="interruption after link"):
        RIO._durable_publish_new_link_fallback(source, target)
    assert source.is_file()
    assert target.is_file()
    assert source.stat().st_ino == target.stat().st_ino
    assert target.stat().st_nlink == 2

    RIO._durable_publish_new_link_fallback(source, target)

    assert not RIO.lexists(source)
    assert target.read_bytes() == b'{"authority":"recoverable"}\n'
    assert target.stat().st_nlink == 1


def test_durable_unlink_removes_the_authoritative_name(
    tmp_path: Path,
) -> None:
    target = tmp_path / "driver-sidecar.json"
    target.write_bytes(b"{}\n")

    RIO.durable_unlink(target)

    assert not RIO.lexists(target)


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows namespace-injection contract",
)
def test_windows_extended_namespace_is_internal_only() -> None:
    for injected in (
        r"\\?\C:\alpha\..\beta",
        r"\\?\UNC\server\share\directory",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1",
    ):
        with pytest.raises(
            RIO.RootedPathIOError,
            match="caller-supplied Windows extended path",
        ):
            RIO.native_path(injected)
