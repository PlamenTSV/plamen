"""Focused contracts for Apple's hardlinked Git dispatch shim."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
from types import SimpleNamespace

import pytest

import audit_snapshot as SNAP


def _component(path: Path, payload: bytes) -> dict[str, object]:
    return {
        "path": str(path),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "device": 1,
        "file_id": abs(hash(str(path))),
        "mode": 0o755,
        "uid": 0,
        "gid": 0,
        "link_count": 1,
    }


def test_dispatch_binds_real_git_and_revalidates_entire_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = Path("/Library/Developer/CommandLineTools/usr/bin/git")
    components = {
        SNAP._DARWIN_GIT_SHIM: {
            **_component(SNAP._DARWIN_GIT_SHIM, b"shim"),
            "link_count": 78,
        },
        SNAP._DARWIN_XCRUN: _component(SNAP._DARWIN_XCRUN, b"xcrun"),
        selected: _component(selected, b"real-git"),
    }
    captures: list[Path] = []

    def capture(path: Path, **_kwargs: object) -> dict[str, object]:
        captures.append(path)
        return dict(components[path])

    selection_calls = 0

    def run(command: tuple[str, ...], **_kwargs: object):
        nonlocal selection_calls
        if command == (str(SNAP._DARWIN_XCRUN), "--find", "git"):
            selection_calls += 1
            return 0, f"{selected}\n".encode(), b""
        assert command == (str(selected), "--version")
        return 0, b"git version 2.39.5 (Apple Git-154)\n", b""

    monkeypatch.setattr(SNAP, "_capture_darwin_dispatch_component", capture)
    monkeypatch.setattr(SNAP, "_bounded_darwin_dispatch_command", run)
    path, version, digest, size, chain = SNAP._darwin_git_dispatch_identity(
        ("git", "--version"), project_root=None
    )

    assert path == selected
    assert version == "rc=0\ngit version 2.39.5 (Apple Git-154)"
    assert digest == components[selected]["sha256"]
    assert size == components[selected]["bytes"]
    assert chain["shim"] == components[SNAP._DARWIN_GIT_SHIM]
    assert chain["resolver"] == components[SNAP._DARWIN_XCRUN]
    assert chain["selected_real_git"] == components[selected]
    assert selection_calls == 2
    assert captures == [
        SNAP._DARWIN_GIT_SHIM,
        SNAP._DARWIN_XCRUN,
        selected,
        SNAP._DARWIN_GIT_SHIM,
        SNAP._DARWIN_XCRUN,
        selected,
    ]


def test_dispatch_rejects_component_drift_after_version_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = Path("/Library/Developer/CommandLineTools/usr/bin/git")
    calls: dict[Path, int] = {}

    def capture(path: Path, **_kwargs: object) -> dict[str, object]:
        calls[path] = calls.get(path, 0) + 1
        result = _component(path, str(path).encode())
        if path == selected and calls[path] == 2:
            result["sha256"] = "f" * 64
        if path == SNAP._DARWIN_GIT_SHIM:
            result["link_count"] = 78
        return result

    def run(command: tuple[str, ...], **_kwargs: object):
        if command[0] == str(SNAP._DARWIN_XCRUN):
            return 0, f"{selected}\n".encode(), b""
        return 0, b"git version fixture\n", b""

    monkeypatch.setattr(SNAP, "_capture_darwin_dispatch_component", capture)
    monkeypatch.setattr(SNAP, "_bounded_darwin_dispatch_command", run)
    with pytest.raises(SNAP.SnapshotInputError, match="chain changed"):
        SNAP._darwin_git_dispatch_identity(
            ("git", "--version"), project_root=None
        )


def test_dispatch_rejects_xcrun_selection_toctou(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = Path("/Library/Developer/CommandLineTools/usr/bin/git")
    second = Path("/Applications/Xcode.app/Contents/Developer/usr/bin/git")
    selections = iter((first, second))

    def capture(path: Path, **_kwargs: object) -> dict[str, object]:
        result = _component(path, str(path).encode())
        if path == SNAP._DARWIN_GIT_SHIM:
            result["link_count"] = 78
        return result

    def run(command: tuple[str, ...], **_kwargs: object):
        if command[0] == str(SNAP._DARWIN_XCRUN):
            return 0, f"{next(selections)}\n".encode(), b""
        return 0, b"git version fixture\n", b""

    monkeypatch.setattr(SNAP, "_capture_darwin_dispatch_component", capture)
    monkeypatch.setattr(SNAP, "_bounded_darwin_dispatch_command", run)
    with pytest.raises(SNAP.SnapshotInputError, match="selection changed"):
        SNAP._darwin_git_dispatch_identity(
            ("git", "--version"), project_root=None
        )


def test_dispatch_honors_no_version_probe_but_still_replays_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = Path("/Library/Developer/CommandLineTools/usr/bin/git")
    commands: list[tuple[str, ...]] = []

    def capture(path: Path, **_kwargs: object) -> dict[str, object]:
        result = _component(path, str(path).encode())
        if path == SNAP._DARWIN_GIT_SHIM:
            result["link_count"] = 78
        return result

    def run(command: tuple[str, ...], **_kwargs: object):
        commands.append(command)
        assert command == (str(SNAP._DARWIN_XCRUN), "--find", "git")
        return 0, f"{selected}\n".encode(), b""

    monkeypatch.setattr(SNAP, "_capture_darwin_dispatch_component", capture)
    monkeypatch.setattr(SNAP, "_bounded_darwin_dispatch_command", run)
    _path, version, _digest, _size, _chain = (
        SNAP._darwin_git_dispatch_identity(
            ("git", "--version"),
            project_root=None,
            probe_version=False,
        )
    )
    assert version == "NOT_PROBED_NONAUTHORITATIVE"
    assert commands == [
        (str(SNAP._DARWIN_XCRUN), "--find", "git"),
        (str(SNAP._DARWIN_XCRUN), "--find", "git"),
    ]


@pytest.mark.parametrize("name", SNAP._DARWIN_XCRUN_OVERRIDE_VARIABLES)
def test_ambient_xcrun_selection_overrides_are_rejected(name: str) -> None:
    with pytest.raises(SNAP.SnapshotInputError, match=name):
        SNAP._assert_no_darwin_xcrun_environment_override({name: "/tmp/evil"})


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"relative/git\n", "one absolute path"),
        (b"/first/git\n/second/git\n", "one absolute path"),
        (b"/first/../git\n", "canonical"),
        (b"/first/git\x00suffix\n", "one absolute path"),
    ],
)
def test_xcrun_selection_parser_rejects_ambiguous_or_unsafe_output(
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(SNAP.SnapshotInputError, match=message):
        SNAP._parse_darwin_git_selection(raw)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"st_uid": 501}, "root-owned"),
        ({"st_mode": stat.S_IFREG | 0o775}, "writable"),
        ({"st_nlink": 2}, "hardlink"),
        ({"st_mode": stat.S_IFLNK | 0o777}, "regular file"),
    ],
)
def test_real_git_metadata_rejects_nonroot_writable_linked_or_nonregular(
    changes: dict[str, int],
    message: str,
) -> None:
    values = {
        "st_mode": stat.S_IFREG | 0o755,
        "st_uid": 0,
        "st_nlink": 1,
    }
    values.update(changes)
    row = SimpleNamespace(**values)
    with pytest.raises(SNAP.SnapshotInputError, match=message):
        SNAP._validate_darwin_dispatch_metadata(
            row,
            label="xcrun-selected real Git",
            allow_protected_git_shim_hardlinks=False,
        )


def test_only_exact_protected_darwin_shim_can_request_hardlink_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "git"
    candidate.write_bytes(b"not the Apple dispatch shim")
    candidate.chmod(0o755)
    monkeypatch.setattr(SNAP.sys, "platform", "darwin")
    monkeypatch.setattr(
        SNAP,
        "_assert_no_lexical_links",
        lambda path, **_kwargs: Path(path).absolute(),
    )
    with pytest.raises(SNAP.SnapshotInputError, match="exact protected shim"):
        SNAP._capture_darwin_dispatch_component(
            candidate,
            label="fake shim",
            project_root=None,
            allow_protected_git_shim_hardlinks=True,
            require_protected_system_volume=True,
        )


def test_protected_shim_exception_requires_read_only_system_volume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SNAP.sys, "platform", "darwin")
    monkeypatch.setattr(
        SNAP.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_flag=0),
    )
    with pytest.raises(SNAP.SnapshotInputError, match="protected read-only"):
        SNAP._capture_darwin_dispatch_component(
            SNAP._DARWIN_GIT_SHIM,
            label="Darwin Git dispatch shim",
            project_root=None,
            allow_protected_git_shim_hardlinks=True,
            require_protected_system_volume=True,
        )


def test_selected_real_git_symlink_is_rejected(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real-git"
    linked = tmp_path / "selected-git"
    real.write_bytes(b"real git")
    linked.symlink_to(real)
    with pytest.raises(SNAP.SnapshotInputError, match="link"):
        SNAP._capture_darwin_dispatch_component(
            linked,
            label="xcrun-selected real Git",
            project_root=None,
        )


def test_selected_git_inside_target_is_rejected_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "target"
    selected = project / "bin" / "git"
    selected.parent.mkdir(parents=True)
    selected.write_bytes(b"target-controlled git")
    selected.chmod(0o755)
    monkeypatch.setattr(SNAP, "_assert_darwin_root_path_authority", lambda *_a, **_k: None)
    with pytest.raises(SNAP.SnapshotInputError, match="inside audit target"):
        SNAP._capture_darwin_dispatch_component(
            selected,
            label="xcrun-selected real Git",
            project_root=project,
        )


def test_generic_darwin_git_hardlink_remains_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "git"
    alias = tmp_path / "git-alias"
    executable.write_bytes(b"ordinary hardlinked git")
    executable.chmod(0o755)
    os.link(executable, alias)
    monkeypatch.setattr(SNAP.sys, "platform", "darwin")
    monkeypatch.setattr(SNAP.shutil, "which", lambda _name: str(executable))
    with pytest.raises(SNAP.SnapshotInputError, match="hardlink"):
        SNAP._runtime_tool_fingerprint(("git", "--version"))


def test_non_darwin_runtime_path_preserves_ordinary_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "git"
    payload = b"ordinary Linux git"
    executable.write_bytes(payload)
    executable.chmod(0o755)
    monkeypatch.setattr(SNAP.sys, "platform", "linux")
    monkeypatch.setattr(SNAP.shutil, "which", lambda _name: str(executable))
    monkeypatch.setattr(
        SNAP,
        "_command_version",
        lambda _command: b"rc=0\ngit version fixture",
    )
    observed = json.loads(SNAP._runtime_tool_fingerprint(("git", "--version")))
    assert "darwin_git_dispatch_chain" not in observed
    assert observed["resolved_executable"] == str(executable)
    assert observed["executable_sha256"] == hashlib.sha256(payload).hexdigest()


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin process groups")
def test_bounded_runner_kills_closed_pipe_same_group_descendant() -> None:
    result = SNAP._bounded_darwin_dispatch_command(
        (
            "/bin/sh",
            "-c",
            "sleep 30 </dev/null >/dev/null 2>/dev/null & echo $!",
        )
    )
    assert result[0] == 0
    descendant = int(result[1].decode("ascii").strip())
    deadline = time.monotonic() + 1
    while True:
        try:
            os.kill(descendant, 0)
        except ProcessLookupError:
            break
        if time.monotonic() >= deadline:
            pytest.fail("same-group descendant survived bounded runner cleanup")
        time.sleep(0.01)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin process groups")
def test_bounded_runner_terminates_on_output_overflow() -> None:
    with pytest.raises(SNAP.SnapshotInputError, match="output exceeded"):
        SNAP._bounded_darwin_dispatch_command(
            ("/usr/bin/yes",),
            output_limit=1024,
        )


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="live Apple dispatch contract",
)
def test_live_apple_dispatch_hashes_selected_real_git() -> None:
    if SNAP.shutil.which("git") != str(SNAP._DARWIN_GIT_SHIM):
        pytest.skip("Apple Git shim is not selected by PATH")
    observed = json.loads(SNAP._runtime_tool_fingerprint(("git", "--version")))
    chain = observed["darwin_git_dispatch_chain"]
    assert observed["resolved_executable"] == chain["selected_real_git"]["path"]
    assert observed["resolved_executable"] != str(SNAP._DARWIN_GIT_SHIM)
    assert observed["executable_sha256"] == chain["selected_real_git"]["sha256"]
    assert observed["version"].startswith("rc=0\ngit version ")
