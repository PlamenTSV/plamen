"""Focused contracts for the non-integrated Linux guest-scope helper."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

import linux_guest_scope as L


ATTEMPT = "a" * 64
BINDING = "b" * 64
LIMITS = L.LinuxGuestLimits(
    pids_max=64,
    memory_max=512 * 1024 * 1024,
    cpu_quota=50_000,
    cpu_period=100_000,
    wall_time_ms=60_000,
)
FAKE_ADMISSION = {
    "system": "Linux",
    "machine": "aarch64",
    "release": "fixture",
    "pointer_bits": 64,
    "effective_uid": 0,
}


def _directory(path: Path) -> int:
    path.mkdir(mode=0o700)
    return os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )


def _interpreter(path: Path) -> int:
    path.write_bytes(b"\x7fELF" + b"fixture interpreter")
    path.chmod(0o500)
    return os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )


def _driver_script(path: Path) -> int:
    path.write_bytes(b"from plamen_driver import main\nmain()\n")
    path.chmod(0o400)
    return os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )


def _fake_read_only_mount(descriptor: int) -> dict[str, object]:
    del descriptor
    return {
        "mount_id": 41,
        "read_only": True,
        "xattrs_empty": True,
        "inode_flags": 0,
    }


def _receipt(payload: str, key: bytes) -> bytes:
    mac = hmac.new(key, payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"PLAMEN_LINUX_SCOPE {payload};mac={mac}\n".encode("ascii")


def _final_fields() -> dict[str, str]:
    values = {
        "schema": L.RECEIPT_SCHEMA,
        "phase": "FINAL",
        "attempt": ATTEMPT,
        "binding": BINDING,
        "interpreter_access_mode": "O_RDONLY",
        "driver_access_mode": "O_RDONLY",
        "wait_status": "0",
        "timed_out": "0",
        "exec_verified": "1",
        "cleanup": "COMPLETE",
    }
    return {name: values[name] for name in L.FINAL_RECEIPT_FIELDS}


def _pins(interpreter: int, driver: int, runtime: int) -> dict[str, str]:
    interpreter_identity = L._file_identity(
        interpreter,
        maximum_bytes=L.MAX_INTERPRETER_BYTES,
        executable=True,
        require_elf=True,
        require_root_owner=False,
    )
    driver_identity = L._file_identity(
        driver,
        maximum_bytes=L.MAX_DRIVER_SCRIPT_BYTES,
        executable=False,
        require_elf=False,
        require_root_owner=False,
    )
    _, runtime_digest = L._runtime_roster_identity(
        (runtime,),
        require_root_owner=False,
        mount_observer=_fake_read_only_mount,
    )
    return {
        "expected_interpreter_sha256": interpreter_identity["sha256"],
        "expected_driver_script_sha256": driver_identity["sha256"],
        "expected_runtime_roster_sha256": runtime_digest,
    }


def _ready_fields() -> dict[str, str]:
    values = {
        "schema": L.RECEIPT_SCHEMA,
        "phase": "READY",
        "attempt": ATTEMPT,
        "binding": BINDING,
        "child": "100",
        "cgroup_name": f"plamen-{ATTEMPT}",
        "cgroup_parent_device": "1",
        "cgroup_parent_inode": "2",
        "cgroup_device": "1",
        "cgroup_inode": "3",
        "pids_max": str(LIMITS.pids_max),
        "memory_max": str(LIMITS.memory_max),
        "cpu_quota": str(LIMITS.cpu_quota),
        "cpu_period": str(LIMITS.cpu_period),
        "landlock_abi": str(L.MIN_LANDLOCK_ABI),
        "handled_fs": "65535",
        "handled_net": "3",
        "uid": "65534",
        "gid": "65534",
        "caps_effective": "0",
        "caps_permitted": "0",
        "caps_inheritable": "0",
        "caps_ambient": "0",
        "no_new_privs": "1",
        "mount_propagation": "PRIVATE",
        "interpreter_exec_fd": str(L.INTERPRETER_EXEC_FD),
        "driver_script_fd": str(L.DRIVER_SCRIPT_EXEC_FD),
        "surviving_fds": "0:1:2:197:198",
        "procfs": "VERIFIED",
        "path_lookup": "0",
        "direct_shebang_exec": "0",
        "interpreter_device": "4",
        "interpreter_inode": "50",
        "interpreter_mode": str(stat.S_IFREG | 0o500),
        "interpreter_owner_uid": "0",
        "interpreter_owner_gid": "0",
        "interpreter_link_count": "1",
        "interpreter_access_mode": "O_RDONLY",
        "interpreter_size": "100",
        "interpreter_sha256": "c" * 64,
        "driver_device": "4",
        "driver_inode": "51",
        "driver_mode": str(stat.S_IFREG | 0o400),
        "driver_owner_uid": "0",
        "driver_owner_gid": "0",
        "driver_link_count": "1",
        "driver_access_mode": "O_RDONLY",
        "driver_size": "100",
        "driver_sha256": "d" * 64,
        "runtime_count": "1",
        "runtime_mounts_read_only": "1",
        "runtime_roster_sha256": "e" * 64,
        "argv_sha256": "f" * 64,
        "overlay_storage_device": "4",
        "overlay_storage_inode": "60",
        "overlay_storage_mount": "61",
    }
    for prefix, offset in (
        ("lower", 10),
        ("upper", 20),
        ("work", 30),
        ("merged", 40),
    ):
        values[f"{prefix}_device"] = "4"
        values[f"{prefix}_inode"] = str(offset)
        values[f"{prefix}_mount"] = str(offset + 1)
    return {name: values[name] for name in L.READY_RECEIPT_FIELDS}


def test_binding_is_descriptor_exact_and_declines_network_claim(
    tmp_path: Path,
) -> None:
    descriptors = (
        _directory(tmp_path / "cgroup"),
        _directory(tmp_path / "overlay-storage"),
        _interpreter(tmp_path / "python"),
        _driver_script(tmp_path / "plamen_driver.py"),
        _directory(tmp_path / "runtime"),
        _directory(tmp_path / "project"),
        _directory(tmp_path / "code"),
        _directory(tmp_path / "scratch"),
    )
    cgroup, storage, interpreter, driver, runtime, project, code, scratch = descriptors
    try:
        binding = L.build_guest_binding(
            cgroup_parent_fd=cgroup,
            overlay_storage_fd=storage,
            interpreter_fd=interpreter,
            driver_script_fd=driver,
            runtime_root_fds=(runtime,),
            **_pins(interpreter, driver, runtime),
            read_only_root_fds=(project, code),
            writable_root_fds=(scratch,),
            target_uid=65534,
            target_gid=65534,
            limits=LIMITS,
            attempt_id=ATTEMPT,
            driver_argv=("--fixture",),
            admission=FAKE_ADMISSION,
            runtime_mount_observer=_fake_read_only_mount,
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)

    assert binding["network_isolation_claimed"] is False
    assert binding["shell_used"] is False
    final_argv = (
        L.INTERPRETER_ARGUMENT,
        *L.INTERPRETER_FLAGS,
        L.DRIVER_SCRIPT_ARGUMENT,
        "--fixture",
    )
    framed = b"".join(
        str(len(item.encode())).encode() + b":" + item.encode() + b";"
        for item in final_argv
    )
    assert binding["invocation"]["argv_sha256"] == hashlib.sha256(
        framed
    ).hexdigest()
    assert binding["invocation"]["driver_script_argv"] == (
        "/proc/self/fd/198"
    )
    assert binding["interpreter"]["format"] == "ELF"
    assert binding["interpreter"]["access_mode"] == "O_RDONLY"
    assert binding["driver_script"]["format"] == "PYTHON_SOURCE"
    assert binding["driver_script"]["access_mode"] == "O_RDONLY"
    assert binding["runtime_roots"][0]["inode"] == (
        tmp_path / "runtime"
    ).stat().st_ino
    assert binding["overlay_storage"]["inode"] == (
        tmp_path / "overlay-storage"
    ).stat().st_ino
    assert binding["overlay_storage"] not in binding["read_only_roots"]
    assert binding["overlay_storage"] not in binding["writable_roots"]
    assert binding["overlay"] == {
        "host_target_write_policy": "READ_ONLY_BIND_LOWER",
        "lower_root_index": 0,
        "merged_write_policy": "LANDLOCK_READ_ONLY",
        "storage_capability": "DEDICATED_NOT_LANDLOCK_GRANTED",
    }
    assert binding["read_only_roots"][0]["inode"] == (
        tmp_path / "project"
    ).stat().st_ino
    assert len(L.binding_sha256(binding)) == 64


def test_protocol_is_bounded_fd_only_and_has_no_shell_or_ambient_paths() -> None:
    argv = L._build_helper_argv(
        Path("/private/helper"),
        auth_fd=10,
        status_fd=11,
        gate_fd=12,
        cgroup_parent_fd=13,
        overlay_storage_fd=20,
        interpreter_fd=14,
        driver_script_fd=15,
        runtime_root_fds=(16,),
        expected_interpreter_sha256="1" * 64,
        expected_driver_script_sha256="2" * 64,
        expected_runtime_roster_sha256="3" * 64,
        read_only_root_fds=(17, 18),
        writable_root_fds=(19,),
        target_uid=65534,
        target_gid=65534,
        limits=LIMITS,
        attempt_id=ATTEMPT,
        binding_digest=BINDING,
        driver_argv=("--fixture",),
    )

    assert argv[:9] == (
        "/private/helper",
        "--v1",
        "10",
        "11",
        "12",
        "13",
        "20",
        "14",
        "15",
    )
    assert argv[9:17] == (
        "65534",
        "65534",
        "64",
        str(512 * 1024 * 1024),
        "50000",
        "100000",
        "60000",
        ATTEMPT,
    )
    assert argv[-2:] == ("--", "--fixture")
    assert "/bin/sh" not in argv
    assert "shell" not in " ".join(argv).casefold()


def test_protocol_rejects_unbounded_or_aliased_capabilities(
    tmp_path: Path,
) -> None:
    cgroup = _directory(tmp_path / "cgroup")
    storage = _directory(tmp_path / "overlay-storage")
    interpreter = _interpreter(tmp_path / "python")
    driver = _driver_script(tmp_path / "plamen_driver.py")
    runtime = _directory(tmp_path / "runtime")
    project = _directory(tmp_path / "project")
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L.build_guest_binding(
                cgroup_parent_fd=cgroup,
                overlay_storage_fd=storage,
                interpreter_fd=interpreter,
                driver_script_fd=driver,
                runtime_root_fds=(runtime,),
                **_pins(interpreter, driver, runtime),
                read_only_root_fds=(project,),
                writable_root_fds=(project,),
                target_uid=65534,
                target_gid=65534,
                limits=LIMITS,
                attempt_id=ATTEMPT,
                driver_argv=(),
                admission=FAKE_ADMISSION,
                runtime_mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "DESCRIPTOR_ALIAS"
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._build_helper_argv(
                Path("/private/helper"),
                auth_fd=10,
                status_fd=11,
                gate_fd=12,
                cgroup_parent_fd=13,
                overlay_storage_fd=20,
                interpreter_fd=14,
                driver_script_fd=15,
                runtime_root_fds=(16,),
                expected_interpreter_sha256="1" * 64,
                expected_driver_script_sha256="2" * 64,
                expected_runtime_roster_sha256="3" * 64,
                read_only_root_fds=(17,),
                writable_root_fds=(18,),
                target_uid=65534,
                target_gid=65534,
                limits=LIMITS,
                attempt_id=ATTEMPT,
                binding_digest=BINDING,
                driver_argv=("x" * 4097,),
            )
        assert raised.value.reason_code == "COMMAND_INVALID"
    finally:
        os.close(cgroup)
        os.close(storage)
        os.close(interpreter)
        os.close(driver)
        os.close(runtime)
        os.close(project)


def test_separately_opened_aliases_and_invalid_recovery_timeout_are_rejected(
    tmp_path: Path,
) -> None:
    cgroup = _directory(tmp_path / "cgroup")
    storage = _directory(tmp_path / "overlay-storage")
    interpreter = _interpreter(tmp_path / "python")
    driver = _driver_script(tmp_path / "plamen_driver.py")
    runtime = _directory(tmp_path / "runtime")
    project = _directory(tmp_path / "project")
    project_alias = os.open(
        tmp_path / "project",
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L.build_guest_binding(
                cgroup_parent_fd=cgroup,
                overlay_storage_fd=storage,
                interpreter_fd=interpreter,
                driver_script_fd=driver,
                runtime_root_fds=(runtime,),
                **_pins(interpreter, driver, runtime),
                read_only_root_fds=(project,),
                writable_root_fds=(project_alias,),
                target_uid=65534,
                target_gid=65534,
                limits=LIMITS,
                attempt_id=ATTEMPT,
                driver_argv=(),
                admission=FAKE_ADMISSION,
                runtime_mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "DESCRIPTOR_ALIAS"

        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L.recover_guest_scope(
                cgroup_parent_fd=cgroup,
                overlay_storage_fd=storage,
                attempt_id=ATTEMPT,
                timeout_s=float("nan"),
            )
        assert raised.value.reason_code == "RECOVERY_TIMEOUT_INVALID"
    finally:
        os.close(cgroup)
        os.close(storage)
        os.close(interpreter)
        os.close(driver)
        os.close(runtime)
        os.close(project)
        os.close(project_alias)


def test_helper_source_snapshot_replay_detects_in_place_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "helper.c"
    source.write_bytes(b"int main(void) { return 0; }\n")
    monkeypatch.setattr(L, "_HELPER_SOURCE", source)
    descriptor, identity = L._open_source_snapshot()
    try:
        source.write_bytes(b"int main(void) { return 1; }\n")
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._replay_source_snapshot(descriptor, identity)
        assert raised.value.reason_code == "HELPER_SOURCE_DRIFT"
    finally:
        os.close(descriptor)


def test_pinned_interpreter_and_script_mutation_change_bound_identity(
    tmp_path: Path,
) -> None:
    interpreter_path = tmp_path / "python"
    driver_path = tmp_path / "plamen_driver.py"
    interpreter = _interpreter(interpreter_path)
    driver = _driver_script(driver_path)
    try:
        original_interpreter = L._file_identity(
            interpreter,
            maximum_bytes=L.MAX_INTERPRETER_BYTES,
            executable=True,
            require_elf=True,
            require_root_owner=False,
        )
        original_driver = L._file_identity(
            driver,
            maximum_bytes=L.MAX_DRIVER_SCRIPT_BYTES,
            executable=False,
            require_elf=False,
            require_root_owner=False,
        )
        interpreter_path.chmod(0o700)
        interpreter_path.write_bytes(b"\x7fELFsubstituted interpreter")
        driver_path.chmod(0o600)
        driver_path.write_bytes(b"raise SystemExit('mutated')\n")
        interpreter_path.chmod(0o500)
        driver_path.chmod(0o400)
        replayed_interpreter = L._file_identity(
            interpreter,
            maximum_bytes=L.MAX_INTERPRETER_BYTES,
            executable=True,
            require_elf=True,
            require_root_owner=False,
        )
        replayed_driver = L._file_identity(
            driver,
            maximum_bytes=L.MAX_DRIVER_SCRIPT_BYTES,
            executable=False,
            require_elf=False,
            require_root_owner=False,
        )
        assert replayed_interpreter["sha256"] != original_interpreter["sha256"]
        assert replayed_driver["sha256"] != original_driver["sha256"]
    finally:
        os.close(interpreter)
        os.close(driver)


def test_driver_arguments_cannot_become_interpreter_options() -> None:
    identity = L._command_identity(("-c", "import os", "--fixture"))
    final = (
        L.INTERPRETER_ARGUMENT,
        *L.INTERPRETER_FLAGS,
        L.DRIVER_SCRIPT_ARGUMENT,
        "-c",
        "import os",
        "--fixture",
    )
    framed = b"".join(
        str(len(item.encode())).encode() + b":" + item.encode() + b";"
        for item in final
    )

    assert final.index(L.DRIVER_SCRIPT_ARGUMENT) < final.index("-c")
    assert identity["argv_sha256"] == hashlib.sha256(framed).hexdigest()
    assert identity["fixed_interpreter_flags"] == ["-I", "-B", "-P"]


def test_driver_script_is_refused_as_the_direct_exec_target(tmp_path: Path) -> None:
    path = tmp_path / "plamen_driver.py"
    path.write_bytes(b"#!/usr/bin/python3\nraise SystemExit(0)\n")
    path.chmod(0o500)
    driver = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._file_identity(
                driver,
                maximum_bytes=L.MAX_INTERPRETER_BYTES,
                executable=True,
                require_elf=True,
                require_root_owner=False,
            )
        assert raised.value.reason_code == "EXECUTABLE_MATERIAL_INVALID"
    finally:
        os.close(driver)


def test_read_write_interpreter_and_driver_descriptors_are_rejected(
    tmp_path: Path,
) -> None:
    interpreter_path = tmp_path / "python"
    interpreter_path.write_bytes(b"\x7fELFfixture interpreter")
    interpreter_path.chmod(0o700)
    interpreter = os.open(interpreter_path, os.O_RDWR)
    interpreter_path.chmod(0o500)
    driver_path = tmp_path / "plamen_driver.py"
    driver_path.write_bytes(b"raise SystemExit(0)\n")
    driver_path.chmod(0o600)
    driver = os.open(driver_path, os.O_RDWR)
    driver_path.chmod(0o400)
    try:
        for descriptor, executable, require_elf, maximum in (
            (interpreter, True, True, L.MAX_INTERPRETER_BYTES),
            (driver, False, False, L.MAX_DRIVER_SCRIPT_BYTES),
        ):
            with pytest.raises(L.LinuxGuestScopeError) as raised:
                L._file_identity(
                    descriptor,
                    maximum_bytes=maximum,
                    executable=executable,
                    require_elf=require_elf,
                    require_root_owner=False,
                )
            assert raised.value.reason_code == "EXECUTABLE_ACCESS_INVALID"
    finally:
        os.close(interpreter)
        os.close(driver)


def test_file_identity_replay_rejects_access_mode_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _driver_script(tmp_path / "plamen_driver.py")
    real_fcntl = L.fcntl.fcntl
    getfl_calls = 0

    def replaying_fcntl(descriptor: int, operation: int, *args: object) -> int:
        nonlocal getfl_calls
        result = int(real_fcntl(descriptor, operation, *args))
        if operation == L.fcntl.F_GETFL:
            getfl_calls += 1
            if getfl_calls == 2:
                return (result & ~os.O_ACCMODE) | os.O_RDWR
        return result

    monkeypatch.setattr(L.fcntl, "fcntl", replaying_fcntl)
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._file_identity(
                driver,
                maximum_bytes=L.MAX_DRIVER_SCRIPT_BYTES,
                executable=False,
                require_elf=False,
                require_root_owner=False,
            )
        assert raised.value.reason_code == "EXECUTABLE_ACCESS_INVALID"
        assert getfl_calls == 2
    finally:
        os.close(driver)


@pytest.mark.parametrize(
    "field",
    ("interpreter_access_mode", "driver_access_mode"),
)
def test_final_receipt_requires_read_only_exec_descriptors(field: str) -> None:
    fields = _final_fields()
    L._validate_final_receipt(fields)
    fields[field] = "O_RDWR"
    with pytest.raises(L.LinuxGuestScopeError) as raised:
        L._validate_final_receipt(fields)
    assert raised.value.reason_code == "RECOVERY_REQUIRED"


def test_dynamic_runtime_roster_rejects_widening(tmp_path: Path) -> None:
    runtime_path = tmp_path / "runtime"
    runtime = _directory(runtime_path)
    try:
        runtime_path.chmod(0o770)
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,),
                require_root_owner=False,
                mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "RUNTIME_ROOTS_INVALID"

        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,) * (L.MAX_RUNTIME_ROOTS + 1),
                require_root_owner=False,
                mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "RUNTIME_ROOTS_INVALID"
    finally:
        os.close(runtime)


def test_runtime_roster_requires_read_only_mount_proof_and_binds_mount_id(
    tmp_path: Path,
) -> None:
    runtime_path = tmp_path / "runtime"
    runtime = _directory(runtime_path)
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,),
                require_root_owner=False,
                mount_observer=lambda _fd: {
                    "mount_id": 41,
                    "read_only": False,
                    "xattrs_empty": True,
                    "inode_flags": 0,
                },
            )
        assert raised.value.reason_code == "RUNTIME_MOUNT_PROOF_INVALID"

        first, first_digest = L._runtime_roster_identity(
            (runtime,),
            require_root_owner=False,
            mount_observer=lambda _fd: {
                "mount_id": 41,
                "read_only": True,
                "xattrs_empty": True,
                "inode_flags": 0,
            },
        )
        second, second_digest = L._runtime_roster_identity(
            (runtime,),
            require_root_owner=False,
            mount_observer=lambda _fd: {
                "mount_id": 42,
                "read_only": True,
                "xattrs_empty": True,
                "inode_flags": 0,
            },
        )
        injected = runtime_path / "mutable" / "injected.so"
        injected.parent.mkdir()
        injected.write_bytes(b"not part of the pinned runtime")
        _, injected_digest = L._runtime_roster_identity(
            (runtime,),
            require_root_owner=False,
            mount_observer=lambda _fd: {
                "mount_id": 41,
                "read_only": True,
                "xattrs_empty": True,
                "inode_flags": 0,
            },
        )
        assert first[0]["mount_read_only"] == 1
        assert first[0]["mount_id"] == 41
        assert second[0]["mount_id"] == 42
        assert first_digest != injected_digest
        # Mount IDs are namespace-local and change after unshare(CLONE_NEWNS).
        # They remain binding fields, while the replay digest stays portable.
        assert first_digest == second_digest
    finally:
        os.close(runtime)


def test_nested_runtime_and_writable_root_are_rejected_by_topology(
    tmp_path: Path,
) -> None:
    cgroup = _directory(tmp_path / "cgroup")
    storage = _directory(tmp_path / "overlay-storage")
    interpreter = _interpreter(tmp_path / "python")
    driver = _driver_script(tmp_path / "plamen_driver.py")
    runtime = _directory(tmp_path / "runtime")
    nested_scratch = _directory(tmp_path / "runtime" / "scratch")
    project = _directory(tmp_path / "project")
    descriptors = (
        cgroup, storage, interpreter, driver, runtime, nested_scratch, project,
    )
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L.build_guest_binding(
                cgroup_parent_fd=cgroup,
                overlay_storage_fd=storage,
                interpreter_fd=interpreter,
                driver_script_fd=driver,
                runtime_root_fds=(runtime,),
                **_pins(interpreter, driver, runtime),
                read_only_root_fds=(project,),
                writable_root_fds=(nested_scratch,),
                target_uid=65534,
                target_gid=65534,
                limits=LIMITS,
                attempt_id=ATTEMPT,
                driver_argv=(),
                admission=FAKE_ADMISSION,
                runtime_mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "ROOT_TOPOLOGY_OVERLAP"
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_overlay_storage_is_not_reachable_from_child_writable_scratch(
    tmp_path: Path,
) -> None:
    cgroup = _directory(tmp_path / "cgroup")
    interpreter = _interpreter(tmp_path / "python")
    driver = _driver_script(tmp_path / "plamen_driver.py")
    runtime = _directory(tmp_path / "runtime")
    project = _directory(tmp_path / "project")
    scratch = _directory(tmp_path / "scratch")
    storage = _directory(tmp_path / "scratch" / "overlay-storage")
    descriptors = (
        cgroup, interpreter, driver, runtime, project, scratch, storage,
    )
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L.build_guest_binding(
                cgroup_parent_fd=cgroup,
                overlay_storage_fd=storage,
                interpreter_fd=interpreter,
                driver_script_fd=driver,
                runtime_root_fds=(runtime,),
                **_pins(interpreter, driver, runtime),
                read_only_root_fds=(project,),
                writable_root_fds=(scratch,),
                target_uid=65534,
                target_gid=65534,
                limits=LIMITS,
                attempt_id=ATTEMPT,
                driver_argv=(),
                admission=FAKE_ADMISSION,
                runtime_mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "ROOT_TOPOLOGY_OVERLAP"
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_runtime_hardlink_into_scratch_is_rejected_before_alias_mutation(
    tmp_path: Path,
) -> None:
    runtime_path = tmp_path / "runtime"
    scratch_path = tmp_path / "scratch"
    runtime = _directory(runtime_path)
    scratch = _directory(scratch_path)
    library = runtime_path / "library.so"
    alias = scratch_path / "writable-alias.so"
    library.write_bytes(b"authenticated runtime")
    library.chmod(0o600)
    os.link(library, alias)
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,),
                require_root_owner=False,
                mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "RUNTIME_HARDLINK_INVALID"
        alias.write_bytes(b"mutation through scratch")
        assert library.read_bytes() == b"mutation through scratch"
    finally:
        os.close(runtime)
        os.close(scratch)


@pytest.mark.parametrize("target", ("payload", "/etc/passwd"))
def test_runtime_manifest_rejects_all_symlinks(
    tmp_path: Path,
    target: str,
) -> None:
    runtime_path = tmp_path / "runtime"
    runtime = _directory(runtime_path)
    if target == "payload":
        (runtime_path / target).write_bytes(b"payload")
    (runtime_path / "alias").symlink_to(target)
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,),
                require_root_owner=False,
                mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "RUNTIME_SYMLINK_INVALID"
    finally:
        os.close(runtime)


def test_runtime_manifest_rejects_nested_mount_identity(tmp_path: Path) -> None:
    runtime_path = tmp_path / "runtime"
    runtime = _directory(runtime_path)
    nested_path = runtime_path / "nested"
    nested_path.mkdir(mode=0o700)
    root_inode = os.fstat(runtime).st_ino

    def observer(descriptor: int) -> dict[str, object]:
        return {
            "mount_id": 41 if os.fstat(descriptor).st_ino == root_inode else 42,
            "read_only": True,
            "xattrs_empty": True,
            "inode_flags": 0,
        }

    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,),
                require_root_owner=False,
                mount_observer=observer,
            )
        assert raised.value.reason_code == "RUNTIME_NESTED_MOUNT"
    finally:
        os.close(runtime)


@pytest.mark.parametrize(
    "proof",
    (
        {
            "mount_id": 41,
            "read_only": True,
            "xattrs_empty": False,
            "inode_flags": 0,
        },
        {
            "mount_id": 41,
            "read_only": True,
            "xattrs_empty": True,
            "inode_flags": 0x00000004,
        },
    ),
)
def test_runtime_manifest_rejects_xattrs_and_compression_flags(
    tmp_path: Path,
    proof: dict[str, object],
) -> None:
    runtime = _directory(tmp_path / "runtime")
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,),
                require_root_owner=False,
                mount_observer=lambda _fd: proof,
            )
        assert raised.value.reason_code == "RUNTIME_METADATA_INVALID"
    finally:
        os.close(runtime)


@pytest.mark.parametrize("unsafe_field", ("xattrs_empty", "inode_flags"))
def test_runtime_descendant_native_metadata_is_validated_recursively(
    tmp_path: Path,
    unsafe_field: str,
) -> None:
    runtime_path = tmp_path / "runtime"
    runtime = _directory(runtime_path)
    library = runtime_path / "library.so"
    library.write_bytes(b"payload")
    library.chmod(0o600)
    root_inode = os.fstat(runtime).st_ino

    def observer(descriptor: int) -> dict[str, object]:
        proof: dict[str, object] = {
            "mount_id": 41,
            "read_only": True,
            "xattrs_empty": True,
            "inode_flags": 0,
        }
        if os.fstat(descriptor).st_ino != root_inode:
            proof[unsafe_field] = False if unsafe_field == "xattrs_empty" else 4
        return proof

    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,),
                require_root_owner=False,
                mount_observer=observer,
            )
        assert raised.value.reason_code == "RUNTIME_METADATA_INVALID"
    finally:
        os.close(runtime)


def test_runtime_manifest_rejects_unsafe_descendant_mode(tmp_path: Path) -> None:
    runtime_path = tmp_path / "runtime"
    runtime = _directory(runtime_path)
    unsafe = runtime_path / "group-writable.so"
    unsafe.write_bytes(b"payload")
    unsafe.chmod(0o620)
    try:
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L._runtime_roster_identity(
                (runtime,),
                require_root_owner=False,
                mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "RUNTIME_METADATA_INVALID"
    finally:
        os.close(runtime)


def test_image_lock_rejects_interpreter_script_and_runtime_substitution(
    tmp_path: Path,
) -> None:
    cgroup = _directory(tmp_path / "cgroup")
    storage = _directory(tmp_path / "overlay-storage")
    interpreter_path = tmp_path / "python"
    driver_path = tmp_path / "plamen_driver.py"
    interpreter = _interpreter(interpreter_path)
    driver = _driver_script(driver_path)
    runtime = _directory(tmp_path / "runtime")
    runtime_extra = _directory(tmp_path / "runtime-extra")
    project = _directory(tmp_path / "project")
    scratch = _directory(tmp_path / "scratch")
    descriptors = (
        cgroup,
        storage,
        interpreter,
        driver,
        runtime,
        runtime_extra,
        project,
        scratch,
    )
    try:
        pins = _pins(interpreter, driver, runtime)
        interpreter_path.chmod(0o700)
        interpreter_path.write_bytes(b"\x7fELFreplaced")
        interpreter_path.chmod(0o500)
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L.build_guest_binding(
                cgroup_parent_fd=cgroup,
                overlay_storage_fd=storage,
                interpreter_fd=interpreter,
                driver_script_fd=driver,
                runtime_root_fds=(runtime,),
                **pins,
                read_only_root_fds=(project,),
                writable_root_fds=(scratch,),
                target_uid=65534,
                target_gid=65534,
                limits=LIMITS,
                attempt_id=ATTEMPT,
                driver_argv=(),
                admission=FAKE_ADMISSION,
                runtime_mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "INTERPRETER_SUBSTITUTION"

        pins = _pins(interpreter, driver, runtime)
        driver_path.chmod(0o600)
        driver_path.write_bytes(b"raise SystemExit(7)\n")
        driver_path.chmod(0o400)
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L.build_guest_binding(
                cgroup_parent_fd=cgroup,
                overlay_storage_fd=storage,
                interpreter_fd=interpreter,
                driver_script_fd=driver,
                runtime_root_fds=(runtime,),
                **pins,
                read_only_root_fds=(project,),
                writable_root_fds=(scratch,),
                target_uid=65534,
                target_gid=65534,
                limits=LIMITS,
                attempt_id=ATTEMPT,
                driver_argv=(),
                admission=FAKE_ADMISSION,
                runtime_mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "DRIVER_SCRIPT_MUTATION"

        pins = _pins(interpreter, driver, runtime)
        with pytest.raises(L.LinuxGuestScopeError) as raised:
            L.build_guest_binding(
                cgroup_parent_fd=cgroup,
                overlay_storage_fd=storage,
                interpreter_fd=interpreter,
                driver_script_fd=driver,
                runtime_root_fds=(runtime, runtime_extra),
                **pins,
                read_only_root_fds=(project,),
                writable_root_fds=(scratch,),
                target_uid=65534,
                target_gid=65534,
                limits=LIMITS,
                attempt_id=ATTEMPT,
                driver_argv=(),
                admission=FAKE_ADMISSION,
                runtime_mount_observer=_fake_read_only_mount,
            )
        assert raised.value.reason_code == "RUNTIME_ROOTS_WIDENED"
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_c_exec_contract_survives_only_pinned_fds_and_requires_procfs() -> None:
    source = (Path(__file__).with_name("linux_guest_scope_helper.c")).read_text()
    observe = source[source.index("observe_pinned_file(") : source.index(
        "same_pinned_file("
    )]
    same = source[source.index("same_pinned_file(") : source.index(
        "static int mount_id_for_fd"
    )]
    child = source[source.index("child_enter_scope(") : source.index(
        "emit_receipt("
    )]
    exec_offset = child.index("fexecve(INTERPRETER_EXEC_FD")
    final_replay = child.rfind(
        "if (observe_pinned_file(INTERPRETER_EXEC_FD",
        0,
        exec_offset,
    )

    assert source.index("verify_procfs_fixed_descriptors(&interpreter,&driver)") < (
        source.index("setup_cgroup(r,&cgroup)")
    )
    assert "PROC_SUPER_MAGIC" in source
    assert "dup3(ready_fd,EXEC_STATUS_FD,O_CLOEXEC)" in source
    assert "fcntl(INTERPRETER_EXEC_FD,F_SETFD,flags&~FD_CLOEXEC)" in source
    assert "fcntl(DRIVER_SCRIPT_EXEC_FD,F_SETFD,flags&~FD_CLOEXEC)" in source
    assert "syscall(__NR_close_range,3U" in source
    assert "DRIVER_SCRIPT_EXEC_FD+1U" in source
    assert 'exec_argv[used++]="/proc/self/fd/198"' in source
    assert "fexecve(INTERPRETER_EXEC_FD" in source
    assert "fexecve(DRIVER_SCRIPT_EXEC_FD" not in source
    assert "before_flags=fcntl(fd,F_GETFL)" in observe
    assert "after_flags=fcntl(fd,F_GETFL)" in observe
    assert observe.count("O_ACCMODE)!=O_RDONLY") == 2
    assert "left->access_mode==O_RDONLY" in same
    assert "right->access_mode==O_RDONLY" in same
    assert child.count("observe_pinned_file(INTERPRETER_EXEC_FD") == 2
    assert child.count("observe_pinned_file(DRIVER_SCRIPT_EXEC_FD") == 2
    assert final_replay >= 0
    assert final_replay < child.index("syscall(__NR_close_range", final_replay)
    assert child.index("syscall(__NR_close_range", final_replay) < exec_offset
    assert "exec_verified=1" in source


def test_authenticated_receipt_rejects_tamper_and_replays_posture() -> None:
    key = b"k" * 32
    fields = _ready_fields()
    payload = ";".join(f"{name}={value}" for name, value in fields.items())
    raw = _receipt(payload, key)

    parsed = L._parse_receipt(
        raw,
        authentication_key=key,
        expected_attempt=ATTEMPT,
        expected_binding=BINDING,
        expected_phase="READY",
    )
    L._validate_ready_receipt(
        parsed,
        limits=LIMITS,
        target_uid=65534,
        target_gid=65534,
        attempt_id=ATTEMPT,
    )
    with pytest.raises(L.LinuxGuestScopeError) as raised:
        L._parse_receipt(
            raw.replace(b"pids_max=64", b"pids_max=65"),
            authentication_key=key,
            expected_attempt=ATTEMPT,
            expected_binding=BINDING,
            expected_phase="READY",
        )
    assert raised.value.reason_code == "RECEIPT_AUTHENTICATION_FAILED"


@pytest.mark.parametrize("mutation", ("unknown", "missing", "reordered"))
def test_authenticated_receipt_requires_exact_canonical_field_order(
    mutation: str,
) -> None:
    key = b"s" * 32
    items = list(_ready_fields().items())
    if mutation == "unknown":
        items.append(("unexpected", "1"))
    elif mutation == "missing":
        items.pop(-1)
    else:
        items[4], items[5] = items[5], items[4]
    payload = ";".join(f"{name}={value}" for name, value in items)

    with pytest.raises(L.LinuxGuestScopeError) as raised:
        L._parse_receipt(
            _receipt(payload, key),
            authentication_key=key,
            expected_attempt=ATTEMPT,
            expected_binding=BINDING,
            expected_phase="READY",
        )
    assert raised.value.reason_code == "RECEIPT_INVALID"


def test_receipt_rejects_noncanonical_numeric_encoding() -> None:
    fields = _ready_fields()
    fields["child"] = "0100"
    with pytest.raises(L.LinuxGuestScopeError) as raised:
        L._validate_ready_receipt(
            fields,
            limits=LIMITS,
            target_uid=65534,
            target_gid=65534,
            attempt_id=ATTEMPT,
        )
    assert raised.value.reason_code == "ENFORCEMENT_INCOMPLETE"


def test_authenticated_receipt_binds_interpreter_script_runtime_and_argv(
    tmp_path: Path,
) -> None:
    descriptors = (
        _directory(tmp_path / "cgroup"),
        _directory(tmp_path / "overlay-storage"),
        _interpreter(tmp_path / "python"),
        _driver_script(tmp_path / "plamen_driver.py"),
        _directory(tmp_path / "runtime"),
        _directory(tmp_path / "project"),
        _directory(tmp_path / "scratch"),
    )
    cgroup, storage, interpreter, driver, runtime, project, scratch = descriptors
    try:
        binding = L.build_guest_binding(
            cgroup_parent_fd=cgroup,
            overlay_storage_fd=storage,
            interpreter_fd=interpreter,
            driver_script_fd=driver,
            runtime_root_fds=(runtime,),
            **_pins(interpreter, driver, runtime),
            read_only_root_fds=(project,),
            writable_root_fds=(scratch,),
            target_uid=65534,
            target_gid=65534,
            limits=LIMITS,
            attempt_id=ATTEMPT,
            driver_argv=("--fixture",),
            admission=FAKE_ADMISSION,
            runtime_mount_observer=_fake_read_only_mount,
        )
        fields = _ready_fields()
        fields["cgroup_parent_device"] = str(binding["cgroup_parent"]["device"])
        fields["cgroup_parent_inode"] = str(binding["cgroup_parent"]["inode"])
        fields["overlay_storage_device"] = str(
            binding["overlay_storage"]["device"]
        )
        fields["overlay_storage_inode"] = str(
            binding["overlay_storage"]["inode"]
        )
        fields["lower_device"] = str(binding["read_only_roots"][0]["device"])
        fields["lower_inode"] = str(binding["read_only_roots"][0]["inode"])
        for prefix, key in (("interpreter", "interpreter"), ("driver", "driver_script")):
            identity = binding[key]
            fields[f"{prefix}_device"] = str(identity["device"])
            fields[f"{prefix}_inode"] = str(identity["inode"])
            fields[f"{prefix}_mode"] = str(identity["mode"])
            fields[f"{prefix}_owner_uid"] = str(identity["owner_uid"])
            fields[f"{prefix}_owner_gid"] = str(identity["owner_gid"])
            fields[f"{prefix}_link_count"] = str(identity["link_count"])
            fields[f"{prefix}_size"] = str(identity["size"])
            fields[f"{prefix}_sha256"] = identity["sha256"]
        fields["runtime_count"] = "1"
        fields["runtime_roster_sha256"] = binding["runtime_roster_sha256"]
        fields["argv_sha256"] = binding["invocation"]["argv_sha256"]
        key = b"r" * 32
        payload = ";".join(f"{name}={value}" for name, value in fields.items())
        parsed = L._parse_receipt(
            _receipt(payload, key),
            authentication_key=key,
            expected_attempt=ATTEMPT,
            expected_binding=BINDING,
            expected_phase="READY",
        )
        L._validate_ready_receipt(
            parsed,
            limits=LIMITS,
            target_uid=65534,
            target_gid=65534,
            attempt_id=ATTEMPT,
            binding=binding,
        )
        for field in ("interpreter_sha256", "driver_sha256", "argv_sha256"):
            drifted = dict(parsed)
            drifted[field] = "0" * 64
            with pytest.raises(L.LinuxGuestScopeError) as raised:
                L._validate_ready_receipt(
                    drifted,
                    limits=LIMITS,
                    target_uid=65534,
                    target_gid=65534,
                    attempt_id=ATTEMPT,
                    binding=binding,
                )
            assert raised.value.reason_code == "ENFORCEMENT_IDENTITY_DRIFT"
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("no_new_privs", "0"),
        ("caps_effective", "1"),
        ("mount_propagation", "SHARED"),
        ("landlock_abi", "5"),
        ("upper_inode", "30"),
    ),
)
def test_ready_receipt_fails_closed_on_partial_enforcement(
    field: str,
    value: str,
) -> None:
    fields = _ready_fields()
    fields[field] = value
    with pytest.raises(L.LinuxGuestScopeError) as raised:
        L._validate_ready_receipt(
            fields,
            limits=LIMITS,
            target_uid=65534,
            target_gid=65534,
            attempt_id=ATTEMPT,
        )
    assert raised.value.reason_code == "ENFORCEMENT_INCOMPLETE"


def test_compiled_source_contains_required_kernel_enforcement_order() -> None:
    source = (Path(__file__).with_name("linux_guest_scope_helper.c")).read_text()

    assert "setup_parent_controllers" in source
    assert "pids.max" in source and "memory.max" in source and "cpu.max" in source
    assert "MS_REC|MS_PRIVATE" in source
    assert "READ_ONLY_BIND_LOWER" not in source
    assert 'mount("overlay"' in source
    assert "PR_CAPBSET_DROP" in source
    assert source.index("setup_overlay(r,&overlay)") < source.index(
        "drop_privileges(r->uid,r->gid,&ready)"
    )
    assert source.index("drop_privileges(r->uid,r->gid,&ready)") < source.index(
        "install_landlock(r,overlay.visible_fd"
    )
    assert "PR_SET_NO_NEW_PRIVS" in source
    assert "__NR_landlock_restrict_self" in source
    assert "landlock_path(fd,INTERPRETER_EXEC_FD" in source
    assert "landlock_path(fd,DRIVER_SCRIPT_EXEC_FD" in source
    assert "for (i=0;i<r->runtime_count;i++)" in source
    assert "objects[i].st_dev==objects[j].st_dev" in source
    assert "verify_procfs_fixed_descriptors" in source
    assert "PROC_SUPER_MAGIC" in source
    assert "dup3(r->interpreter_fd,INTERPRETER_EXEC_FD,O_CLOEXEC)" in source
    assert "dup3(r->driver_fd,DRIVER_SCRIPT_EXEC_FD,O_CLOEXEC)" in source
    assert "fcntl(DRIVER_SCRIPT_EXEC_FD,F_SETFD,flags&~FD_CLOEXEC)" in source
    assert "syscall(__NR_close_range,3U" in source
    assert "fexecve(INTERPRETER_EXEC_FD,exec_argv,environment)" in source
    assert "fexecve(DRIVER_SCRIPT_EXEC_FD" not in source
    assert '"PATH=' not in source
    assert "system(" not in source and "popen(" not in source
    assert "CLONE_NEWNET" not in source


def test_compiled_source_rejects_root_topology_and_unpinned_runtime_mounts() -> None:
    source = (Path(__file__).with_name("linux_guest_scope_helper.c")).read_text()

    assert "directory_contains_fd" in source
    assert "root_topology_disjoint(r)!=0" in source
    assert source.index("root_topology_disjoint(r)!=0") < source.index(
        "observe_pinned_file(r->interpreter_fd"
    )
    runtime_body = source[
        source.index("runtime_roster(const struct request") : source.index(
            "hash_one_argument"
        )
    ]
    native_proof = source[
        source.index("runtime_native_proof(") : source.index(
            "struct runtime_manifest_state"
        )
    ]
    assert "fstatvfs(fd,&filesystem)" in native_proof
    assert "(filesystem.f_flag&ST_RDONLY)==0" in native_proof
    assert "mount_id_for_fd(fd,mount_id)" in native_proof
    assert "flistxattr(fd,NULL,0)" in native_proof
    assert "ioctl(fd,FS_IOC_GETFLAGS,&flags)" in native_proof
    assert "~RUNTIME_SAFE_INODE_FLAGS" in native_proof
    assert "before.st_nlink!=1" in source
    assert "S_ISLNK(row.st_mode)" in source and "errno=ELOOP" in source
    assert "manifest_directory(r->runtime_fds[i]" in runtime_body
    assert "manifest_regular_file" in source


def test_compiled_overlay_storage_is_private_and_never_landlock_granted() -> None:
    source = (Path(__file__).with_name("linux_guest_scope_helper.c")).read_text()
    setup = source[source.index("setup_overlay(") : source.index("landlock_abi(")]
    landlock = source[source.index("install_landlock(") : source.index(
        "drop_privileges("
    )]
    child = source[source.index("child_enter_scope(") : source.index(
        "emit_receipt("
    )]
    topology = source[source.index("root_topology_disjoint(") : source.index(
        "parse_request("
    )]

    assert "r->overlay_storage_fd" in setup
    assert "r->rw_fds[0]" not in setup
    assert '"index=off,metacopy=off,xino=off"' in setup
    assert "mount_is_private(scope->storage_mnt)!=1" in setup
    assert "landlock_path(fd,r->overlay_storage_fd" not in landlock
    assert "roots[count++]=r->overlay_storage_fd" in topology
    assert child.index("close(r->overlay_storage_fd)") < child.index(
        "drop_privileges(r->uid,r->gid,&ready)"
    )
    assert "overlay_storage_device=" in source
    assert "overlay_storage_inode=" in source
    assert "overlay_storage_mount=" in source


def test_x86_64_fails_with_precise_architecture_policy_debt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(L.sys, "platform", "linux")
    monkeypatch.setattr(
        L.platform,
        "uname",
        lambda: SimpleNamespace(
            system="Linux",
            machine="x86_64",
            release="fixture",
        ),
    )
    monkeypatch.setattr(L.os, "geteuid", lambda: 0)

    with pytest.raises(L.LinuxGuestScopeError) as raised:
        L._exact_host_admission()
    assert raised.value.reason_code == "ARCHITECTURE_POLICY_UNAVAILABLE"

    source = (Path(__file__).with_name("linux_guest_scope_helper.c")).read_text()
    admission = source[source.index("admit_linux_architecture(") : source.index(
        "write_control_exact("
    )]
    assert 'strcmp(host.machine,"x86_64")==0' in admission
    assert '"ARCHITECTURE_POLICY_UNAVAILABLE"' in source


@pytest.mark.parametrize(
    ("blocked_fcntl", "spoofed_platform"),
    ((True, "linux"), (False, "win32")),
)
def test_cross_os_import_defers_fcntl_failure_to_posix_operation(
    blocked_fcntl: bool,
    spoofed_platform: str,
) -> None:
    module_directory = Path(__file__).resolve().parent
    probe = r"""
import builtins
import os
import pathlib
import platform
import selectors
import subprocess
import sys
import tempfile

module_directory, spoofed_platform, blocked_fcntl = sys.argv[1:]
real_import = builtins.__import__
if blocked_fcntl == "1":
    def guarded_import(name, *args, **kwargs):
        if name == "fcntl":
            raise ModuleNotFoundError("simulated missing fcntl")
        return real_import(name, *args, **kwargs)
    builtins.__import__ = guarded_import
sys.platform = spoofed_platform
sys.path.insert(0, module_directory)
import linux_guest_scope as scope

scope.LinuxGuestLimits(
    pids_max=1,
    memory_max=16 * 1024 * 1024,
    cpu_quota=1000,
    cpu_period=1000,
    wall_time_ms=100,
).validate()
assert scope.binding_sha256({"platform": "portable"})
try:
    scope.build_guest_binding(
        cgroup_parent_fd=0,
        overlay_storage_fd=1,
        interpreter_fd=2,
        driver_script_fd=3,
        runtime_root_fds=(),
        expected_interpreter_sha256="0" * 64,
        expected_driver_script_sha256="0" * 64,
        expected_runtime_roster_sha256="0" * 64,
        read_only_root_fds=(),
        writable_root_fds=(),
        target_uid=1,
        target_gid=1,
        limits=scope.LinuxGuestLimits(1, 16 * 1024 * 1024, 1000, 1000, 100),
        attempt_id="0" * 64,
        driver_argv=("audit",),
    )
except scope.LinuxGuestScopeError as exc:
    assert exc.reason_code == "PLATFORM_UNSUPPORTED", exc.reason_code
else:
    raise AssertionError("public POSIX plan unexpectedly accepted")
descriptor = os.open(scope.__file__, os.O_RDONLY)
try:
    try:
        scope._file_identity(
            descriptor,
            maximum_bytes=scope.MAX_HELPER_SOURCE_BYTES,
            executable=False,
            require_elf=False,
            require_root_owner=False,
        )
    except scope.LinuxGuestScopeError as exc:
        assert exc.reason_code == "PLATFORM_UNSUPPORTED", exc.reason_code
    else:
        raise AssertionError("POSIX operation unexpectedly accepted")
finally:
    os.close(descriptor)

if spoofed_platform == "win32":
    try:
        scope._exact_host_admission()
    except scope.LinuxGuestScopeError as exc:
        assert exc.reason_code == "HOST_UNSUPPORTED", exc.reason_code
    else:
        raise AssertionError("spoofed host unexpectedly admitted")

events = []
real_fstat = scope.os.fstat
real_listdir = scope.os.listdir
scope.os.fstat = lambda *_args, **_kwargs: events.append("fstat")
scope.os.listdir = lambda *_args, **_kwargs: events.append("listdir")
def observer(_descriptor):
    events.append("observer")
    return {
        "mount_id": 1,
        "read_only": True,
        "xattrs_empty": True,
        "inode_flags": 0,
    }
try:
    for operation in (
        lambda: scope._runtime_roster_identity(
            (3,), require_root_owner=False, mount_observer=observer,
        ),
        lambda: scope._runtime_native_proof(3, observer=observer),
    ):
        try:
            operation()
        except scope.LinuxGuestScopeError as exc:
            assert exc.reason_code == "PLATFORM_UNSUPPORTED", exc.reason_code
        else:
            raise AssertionError("runtime observer seam unexpectedly accepted")
    assert events == [], events
finally:
    scope.os.fstat = real_fstat
    scope.os.listdir = real_listdir
print("OK")
"""
    result = subprocess.run(
        (
            sys.executable,
            "-I",
            "-c",
            probe,
            str(module_directory),
            spoofed_platform,
            "1" if blocked_fcntl else "0",
        ),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "OK\n"


def test_compiled_exec_success_requires_kernel_exec_event_and_failure_marker() -> None:
    source = (Path(__file__).with_name("linux_guest_scope_helper.c")).read_text()
    child = source[source.index("child_enter_scope(") : source.index("emit_receipt(")]
    parent_start = source.index("run_request(")
    parent = source[parent_start : source.index("int\nmain(", parent_start)]

    dup_failure = child[
        child.index("if (dup3(ready_fd,EXEC_STATUS_FD,O_CLOEXEC)<0)") :
        child.index("close(ready_fd)")
    ]
    assert 'write_all(ready_fd,"F",1)' in dup_failure
    assert "ptrace(PTRACE_TRACEME" in child
    assert "PTRACE_O_TRACEEXEC" in parent
    assert "PTRACE_EVENT_EXEC" in parent
    assert parent.index("PTRACE_EVENT_EXEC") < parent.index(
        "do { exec_amount=read(ready_pipe[0]"
    )
    assert parent.index("PTRACE_EVENT_EXEC") < parent.index("exec_verified=1")


def test_compiled_and_python_receipt_schemas_have_one_exact_order() -> None:
    source = (Path(__file__).with_name("linux_guest_scope_helper.c")).read_text()
    ready_start = source.index(
        '"schema=plamen.linux_guest_scope.v1;phase=READY;attempt='
    )
    ready_end = source.index("r->attempt,r->binding", ready_start)
    final_start = source.index(
        '"schema=plamen.linux_guest_scope.v1;phase=FINAL;attempt='
    )
    final_end = source.index("r->attempt,r->binding", final_start)
    field_pattern = re.compile(r"([a-z][a-z0-9_]*)=")

    assert tuple(field_pattern.findall(source[ready_start:ready_end])) == (
        L.READY_RECEIPT_FIELDS
    )
    assert tuple(field_pattern.findall(source[final_start:final_end])) == (
        L.FINAL_RECEIPT_FIELDS
    )


@pytest.mark.skipif(
    not (
        sys.platform == "linux"
        and platform.machine().casefold() in {"aarch64", "arm64"}
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
    ),
    reason=(
        "actual cgroup-v2/overlay/Landlock proof requires the privileged "
        "Linux/arm64 OCI guest; this macOS host provides protocol proof only"
    ),
)
def test_actual_linux_arm64_helper_compiles() -> None:
    helper = L._helper_executable()
    row = helper.stat()

    assert stat.S_ISREG(row.st_mode)
    assert stat.S_IMODE(row.st_mode) == 0o500
    subprocess.run(
        (os.fspath(helper),),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={},
        shell=False,
        check=False,
        timeout=2.0,
    )
