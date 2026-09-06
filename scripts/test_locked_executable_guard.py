from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

import locked_executable_guard as guard


class _FakeLinuxSnapshotOS:
    MFD_ALLOW_SEALING = 0x2
    MFD_CLOEXEC = 0x1

    def __init__(self, content: bytes, *, mutate_after_read: bool = False) -> None:
        self.files = {10: bytearray(content)}
        self.positions = {20: 0}
        self.closed: set[int] = set()
        self.sealed: set[int] = set()
        self.source_fstat_calls = 0
        self.mutate_after_read = mutate_after_read

    def fstat(self, descriptor: int):
        if descriptor == 10:
            self.source_fstat_calls += 1
            if self.mutate_after_read and self.source_fstat_calls >= 2:
                self.files[10][:] = b"mutated"
                timestamp = 2
            else:
                timestamp = 1
            return SimpleNamespace(
                st_dev=7,
                st_ino=11,
                st_size=len(self.files[10]),
                st_mtime_ns=timestamp,
                st_ctime_ns=timestamp,
                st_mode=0o100755,
            )
        return SimpleNamespace(
            st_dev=0,
            st_ino=descriptor,
            st_size=len(self.files[descriptor]),
            st_mtime_ns=1,
            st_ctime_ns=1,
            st_mode=0o100755,
        )

    def memfd_create(self, name: str, flags: int) -> int:
        assert name == "plamen-owned-executable"
        assert flags == self.MFD_ALLOW_SEALING | self.MFD_CLOEXEC
        self.files[20] = bytearray()
        return 20

    def set_inheritable(self, descriptor: int, inheritable: bool) -> None:
        assert descriptor == 20
        assert inheritable is False

    def pread(self, descriptor: int, size: int, offset: int) -> bytes:
        return bytes(self.files[descriptor][offset : offset + size])

    def write(self, descriptor: int, content: bytes) -> int:
        if descriptor in self.sealed:
            raise PermissionError("sealed")
        self.files[descriptor].extend(content)
        return len(content)

    def fchmod(self, descriptor: int, mode: int) -> None:
        assert descriptor == 20
        assert mode == 0o755

    def close(self, descriptor: int) -> None:
        self.closed.add(descriptor)


class _FakeLinuxFcntl:
    F_ADD_SEALS = 1
    F_GET_SEALS = 2
    F_SEAL_WRITE = 0x1
    F_SEAL_GROW = 0x2
    F_SEAL_SHRINK = 0x4
    F_SEAL_SEAL = 0x8

    def __init__(self, os_api: _FakeLinuxSnapshotOS) -> None:
        self.os_api = os_api
        self.seals: dict[int, int] = {}

    def fcntl(self, descriptor: int, operation: int, value: int = 0) -> int:
        if operation == self.F_ADD_SEALS:
            self.seals[descriptor] = value
            self.os_api.sealed.add(descriptor)
            return 0
        assert operation == self.F_GET_SEALS
        return self.seals.get(descriptor, 0)


def _fake_linux_binding(content: bytes) -> dict[str, object]:
    return {
        "schema": "plamen.locked_executable_guard.v2",
        "enforcement": "LINUX_RETAINED_IDENTITY_SEALED_MEMFD_AT_LAUNCH",
        "identity": [7, 11],
        "size": len(content),
        "mtime_ns": 1,
        "ctime_ns": 1,
        "sha256": hashlib.sha256(content).hexdigest(),
        "inheritable": False,
        "host_path_recorded": False,
    }


@pytest.fixture(autouse=True)
def _release_guards():
    guard.release_locked_executables()
    yield
    guard.release_locked_executables()


def test_guard_rejects_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(guard.LockedExecutableGuardError):
        guard.retain_locked_executable(tmp_path / "missing.exe")


def test_linux_sealed_snapshot_copies_exact_bytes_and_rejects_writes() -> None:
    content = b"#!/bin/sh\necho sealed\n"
    os_api = _FakeLinuxSnapshotOS(content)
    fcntl_api = _FakeLinuxFcntl(os_api)

    launch_path, descriptor = guard._create_linux_sealed_snapshot(
        10,
        _fake_linux_binding(content),
        os_api=os_api,
        fcntl_api=fcntl_api,
        proc_fd_exists=lambda path: path == "/proc/self/fd/20",
    )

    assert launch_path == "/proc/self/fd/20"
    assert descriptor == 20
    assert bytes(os_api.files[20]) == content
    assert fcntl_api.seals[20] == 0xF
    with pytest.raises(PermissionError, match="sealed"):
        os_api.write(20, b"forged")


def test_linux_sealed_snapshot_rejects_source_mutation_during_copy() -> None:
    content = b"reviewed executable"
    os_api = _FakeLinuxSnapshotOS(content, mutate_after_read=True)
    fcntl_api = _FakeLinuxFcntl(os_api)

    with pytest.raises(
        guard.LockedExecutableGuardError,
        match="changed during sealed acquisition",
    ):
        guard._create_linux_sealed_snapshot(
            10,
            _fake_linux_binding(content),
            os_api=os_api,
            fcntl_api=fcntl_api,
            proc_fd_exists=lambda _path: True,
        )
    assert 20 in os_api.closed


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux sealed-memfd execution semantics",
)
def test_linux_kernel_executes_sealed_bytes_after_source_mutation(
    tmp_path: Path,
) -> None:
    import fcntl

    executable = tmp_path / "tool"
    executable.write_bytes(b"#!/bin/sh\nprintf 'reviewed\\n'\n")
    executable.chmod(0o755)
    binding = guard.bind_locked_executable(executable)
    launch_path, descriptor = guard.acquire_locked_executable_launch(
        executable,
        binding,
    )
    assert descriptor is not None
    try:
        required = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        assert fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == required
        with pytest.raises(OSError):
            os.write(descriptor, b"forged")
        executable.write_bytes(b"#!/bin/sh\nprintf 'forged\\n'\n")
        completed = subprocess.run(
            [launch_path],
            pass_fds=(descriptor,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "reviewed"
    finally:
        os.close(descriptor)


def test_guard_reuses_exact_identity(tmp_path: Path) -> None:
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"reviewed")
    first = guard.retain_locked_executable(executable)
    second = guard.retain_locked_executable(executable)
    assert first["acquired"] is True
    assert second["acquired"] is False
    assert first["identity"] == second["identity"]
    assert first["sha256"] == second["sha256"]
    assert first["size"] == len(b"reviewed")
    assert first["inheritable"] is False
    assert first["host_path_recorded"] is False


def test_binding_rejects_same_path_identity_and_content_replacement(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"reviewed")
    binding = guard.bind_locked_executable(executable)

    guard.release_locked_executables()
    replacement = tmp_path / "replacement.exe"
    replacement.write_bytes(b"forged")
    os.replace(replacement, executable)
    with pytest.raises(
        guard.LockedExecutableGuardError,
        match="identity or content",
    ):
        guard.validate_locked_executable_binding(executable, binding)

    guard.release_locked_executables()
    executable.write_bytes(b"mutated")
    with pytest.raises(
        guard.LockedExecutableGuardError,
        match="identity or content",
    ):
        guard.validate_locked_executable_binding(executable, binding)


@pytest.mark.skipif(os.name != "nt", reason="Windows share denial semantics")
def test_windows_guard_denies_updater_rename_delete_and_write(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"reviewed")
    guard.retain_locked_executable(executable)

    with pytest.raises(OSError):
        executable.rename(tmp_path / "claude.exe.old.123")
    with pytest.raises(OSError):
        executable.unlink()
    with pytest.raises(OSError):
        executable.write_bytes(b"mutated")
    assert executable.read_bytes() == b"reviewed"


@pytest.mark.skipif(os.name != "nt", reason="Windows share denial semantics")
def test_windows_guard_allows_parallel_process_launch_but_blocks_updater(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "claude.exe"
    shutil.copy2(sys.executable, executable)
    binding = guard.bind_locked_executable(executable)

    # Model the exact bind-to-Popen race: replacement is attempted after the
    # content/identity receipt exists but before any process is created.
    with pytest.raises(OSError):
        executable.rename(tmp_path / "claude.exe.old.concurrent")
    replacement = tmp_path / "replacement.exe"
    shutil.copy2(sys.executable, replacement)
    with pytest.raises(OSError):
        os.replace(replacement, executable)
    children = [
        subprocess.Popen(
            [str(executable), "-c", "print('worker-ok')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    assert guard.validate_locked_executable_binding(executable, binding) == binding
    results = [child.communicate(timeout=30) for child in children]
    assert all(child.returncode == 0 for child in children)
    assert all(stdout.strip() == "worker-ok" for stdout, _ in results)


def test_release_restores_normal_filesystem_lifecycle(tmp_path: Path) -> None:
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"reviewed")
    guard.retain_locked_executable(executable)
    guard.release_locked_executables()
    renamed = tmp_path / "claude.exe.old.123"
    executable.rename(renamed)
    assert renamed.read_bytes() == b"reviewed"
