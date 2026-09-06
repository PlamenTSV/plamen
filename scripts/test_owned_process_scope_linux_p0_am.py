"""Linux cgroup-v2 capability and trusted pre-exec helper fixtures."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import owned_process_scope as S


class _GatedProcess:
    def __init__(self, process_id: int) -> None:
        self.pid = process_id
        self.kill_calls = 0
        self.wait_calls = 0

    def poll(self) -> int | None:
        return None

    def kill(self) -> None:
        self.kill_calls += 1

    def wait(self, *, timeout: float) -> int:
        del timeout
        self.wait_calls += 1
        return 0


def _bare_linux_creation_scope(cgroup: Path) -> S.OwnedProcessScope:
    scope = object.__new__(S.OwnedProcessScope)
    scope._closed = False
    scope._process_creation_attempted = False
    scope._process_creation_state = "NOT_ATTEMPTED"
    scope._created_process = None
    scope._created_process_termination_proven = False
    scope._job_handle = None
    scope._windows_job_owned_suspended = False
    scope._linux_cgroup = cgroup
    scope._linux_created_process_cgroup_membership_proven = False
    scope._population_zero_timeout_seconds = 0.25
    return scope


def _fake_delegated_root(path: Path) -> Path:
    path.mkdir()
    for name in ("cgroup.controllers", "cgroup.events", "cgroup.procs"):
        (path / name).write_text("", encoding="ascii")
    return path


def test_linux_delegated_root_is_exact_absolute_cgroup2_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fake_delegated_root(tmp_path / "delegated")
    monkeypatch.setenv("PLAMEN_CGROUP_V2_ROOT", str(root))
    monkeypatch.setattr(S, "_linux_cgroup2_mounts", lambda: (tmp_path,))
    resolved, limitation = S._linux_delegated_cgroup_root()
    assert resolved == root.resolve()
    assert limitation is None

    monkeypatch.setenv(
        "PLAMEN_CGROUP_V2_ROOT",
        str(tmp_path / "delegated" / ".." / "delegated") + " ",
    )
    assert S._linux_delegated_cgroup_root() == (
        None,
        "DELEGATED_CGROUP_V2_ROOT_INVALID",
    )


def test_linux_capability_binds_root_helper_and_interpreter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "delegated"
    root.mkdir()
    helper_binding = {
        "helper_path": "/trusted/linux_cgroup_exec.py",
        "helper_sha256": "a" * 64,
        "interpreter_path": "/trusted/python",
        "interpreter_sha256": "b" * 64,
    }
    monkeypatch.setattr(S, "_host_platform", lambda: "LINUX")
    monkeypatch.setattr(
        S,
        "_linux_delegated_cgroup_root",
        lambda: (root, None),
    )
    monkeypatch.setattr(S, "_linux_helper_binding", lambda: helper_binding)
    monkeypatch.setattr(S, "_linux_landlock_abi", lambda: 5)
    capability = S.process_tree_termination_capability()
    assert capability["exhaustive_descendant_termination_authority"] is True
    assert capability["delegated_root"] == str(root)
    assert capability["helper_sha256"] == "a" * 64
    assert capability["interpreter_sha256"] == "b" * 64
    assert capability["population_zero_proof"] == (
        "CGROUP_EVENTS_POPULATED_ZERO"
    )
    assert capability["exhaustive_write_confinement_authority"] is True
    assert capability["write_confinement"] == "LANDLOCK_ABI_5_PATH_BENEATH"


def test_linux_without_delegation_is_explicit_non_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(S, "_host_platform", lambda: "LINUX")
    monkeypatch.setattr(
        S,
        "_linux_delegated_cgroup_root",
        lambda: (None, "FIXTURE_NO_DELEGATION"),
    )
    capability = S.process_tree_termination_capability()
    assert capability["exhaustive_descendant_termination_authority"] is False
    assert capability["limitation"] == "FIXTURE_NO_DELEGATION"
    assert capability["population_zero_proof"] == "UNAVAILABLE"


def test_linux_create_returns_only_after_exact_helper_is_cgroup_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cgroup = tmp_path / "scope"
    cgroup.mkdir()
    process = _GatedProcess(8181)
    (cgroup / "cgroup.procs").write_text(
        f"{process.pid}\n",
        encoding="ascii",
    )
    scope = _bare_linux_creation_scope(cgroup)
    monkeypatch.setattr(S.os, "name", "posix")

    returned = scope.create_process(
        ("/trusted/linux-helper", "--"),
        popen_factory=lambda *_a, **_k: process,
    )

    assert returned is process
    assert scope.process_creation_state == "PROCESS_CREATED"
    assert scope._linux_created_process_cgroup_membership_proven is True
    assert process.kill_calls == 0
    assert process.wait_calls == 0


@pytest.mark.skipif(
    os.name == "nt",
    reason="pass_fds and execve protocol require a POSIX test host",
)
def test_trusted_helper_waits_for_parent_ack_before_exec(
    tmp_path: Path,
) -> None:
    procs = tmp_path / "cgroup.procs"
    procs.write_text("", encoding="ascii")
    marker = tmp_path / "executed.txt"
    read_fd, write_fd = os.pipe()
    status_read, status_write = os.pipe()
    try:
        helper = Path(S.__file__).with_name("linux_cgroup_exec.py")
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                str(helper),
                str(procs),
                str(read_fd),
                str(status_write),
                str(tmp_path),
                "--",
                sys.executable,
                "-I",
                "-S",
                "-c",
                (
                    "from pathlib import Path; "
                    f"Path({str(marker)!r}).write_text('yes')"
                ),
            ],
            pass_fds=(read_fd, status_write),
        )
        os.close(read_fd)
        read_fd = -1
        os.close(status_write)
        status_write = -1
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if procs.read_text(encoding="ascii").strip():
                break
            time.sleep(0.01)
        assert procs.read_text(encoding="ascii").strip() == str(process.pid)
        assert os.read(status_read, 64).startswith(b"LANDLOCK_READY:")
        assert not marker.exists()
        os.write(write_fd, b"1")
        os.close(write_fd)
        write_fd = -1
        assert process.wait(timeout=10) == 0
        assert marker.read_text(encoding="utf-8") == "yes"
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        if status_read >= 0:
            os.close(status_read)
        if status_write >= 0:
            os.close(status_write)


@pytest.mark.skipif(
    os.name == "nt",
    reason="pass_fds and execve protocol require a POSIX test host",
)
def test_trusted_helper_parent_gate_eof_exits_without_exec(
    tmp_path: Path,
) -> None:
    procs = tmp_path / "cgroup.procs"
    procs.write_text("", encoding="ascii")
    marker = tmp_path / "must-not-execute.txt"
    read_fd, write_fd = os.pipe()
    status_read, status_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    try:
        helper = Path(S.__file__).with_name("linux_cgroup_exec.py")
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                str(helper),
                str(procs),
                str(read_fd),
                str(status_write),
                str(tmp_path),
                "--",
                sys.executable,
                "-I",
                "-S",
                "-c",
                (
                    "from pathlib import Path; "
                    f"Path({str(marker)!r}).write_text('unsafe')"
                ),
            ],
            pass_fds=(read_fd, status_write),
        )
        os.close(read_fd)
        read_fd = -1
        os.close(status_write)
        status_write = -1
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if procs.read_text(encoding="ascii").strip():
                break
            time.sleep(0.01)
        assert procs.read_text(encoding="ascii").strip() == str(process.pid)
        assert os.read(status_read, 64).startswith(b"LANDLOCK_READY:")
        assert marker.exists() is False

        # A hard-crashed parent closes its last write end without emitting the
        # one-byte acknowledgement.  The helper must stop at the trusted gate
        # and must never exec the requested provider command.
        os.close(write_fd)
        write_fd = -1
        assert process.wait(timeout=10) == 72
        assert marker.exists() is False
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        if status_read >= 0:
            os.close(status_read)
        if status_write >= 0:
            os.close(status_write)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
