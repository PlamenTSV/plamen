from __future__ import annotations

import ctypes
import os
from pathlib import Path
import platform
import stat
import subprocess

import pytest


ROOT = Path(__file__).resolve().parent.parent

CREATE = 1
START = 2
WAIT = 3
TERM = 4
KILL = 5
CLEANUP = 6
REMOVE = 7
TEARDOWN = 8
OBSERVE = 9


@pytest.fixture(scope="module")
def library(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    suffix = ".dylib" if platform.system() == "Darwin" else ".so"
    output = tmp_path_factory.mktemp("podman-native-lifecycle") / (
        "lifecycle" + suffix
    )
    compiler = "/usr/bin/clang" if platform.system() == "Darwin" else "cc"
    command = [
        compiler,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-DPLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEST_ONLY=1",
        "-I",
        str(ROOT / "native" / "linux"),
    ]
    if platform.system() == "Darwin":
        command.append("-dynamiclib")
    else:
        command.extend(["-shared", "-fPIC"])
    command.extend(
        [
            str(
                ROOT
                / "native"
                / "linux"
                / "plamen_broker_v2_podman_admission.c"
            ),
            str(
                ROOT
                / "native"
                / "linux"
                / "plamen_broker_v2_podman_lifecycle.c"
            ),
            str(
                ROOT
                / "native"
                / "linux"
                / "plamen_broker_v2_linux_process.c"
            ),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-o",
            str(output),
        ]
    )
    if platform.system() == "Linux":
        command.append("-lcrypto")
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    loaded = ctypes.CDLL(str(output))
    loaded.plamen_broker_v2_podman_lifecycle_transition_valid.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    loaded.plamen_broker_v2_podman_lifecycle_test_render.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    loaded.plamen_broker_v2_podman_lifecycle_test_decision.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    loaded.plamen_broker_v2_podman_lifecycle_execute.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    loaded.plamen_broker_v2_podman_lifecycle_parse_wait_status.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int32),
    ]
    loaded.plamen_broker_v2_podman_lifecycle_test_journal_roundtrip.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
    ]
    loaded.plamen_broker_v2_podman_lifecycle_test_journal_replay.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
    ]
    loaded.plamen_broker_v2_podman_lifecycle_test_journal_wrong_boot_rejected.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
    ]
    return loaded


@pytest.mark.parametrize(
    ("operation", "before", "intent", "after"),
    [
        (CREATE, 0, 1, 2),
        (START, 2, 3, 4),
        (WAIT, 4, 5, 8),
        (TERM, 4, 6, 8),
        (KILL, 4, 7, 8),
        (CLEANUP, 8, 9, 10),
        (REMOVE, 10, 11, 12),
        (TEARDOWN, 12, 13, 14),
    ],
)
def test_state_machine_requires_durable_intent_before_effect(
    library: ctypes.CDLL,
    operation: int,
    before: int,
    intent: int,
    after: int,
) -> None:
    transition = library.plamen_broker_v2_podman_lifecycle_transition_valid
    assert transition(before, intent, operation) == 1
    assert transition(intent, after, operation) == 1
    assert transition(before, after, operation) == 0


def _render(library: ctypes.CDLL, operation: int, network: int = 0) -> tuple[str, ...]:
    output = ctypes.create_string_buffer(128 * 1024)
    size = ctypes.c_size_t()
    assert library.plamen_broker_v2_podman_lifecycle_test_render(
        operation, network, output, len(output), ctypes.byref(size)
    ) == 0
    if size.value == 0:
        return ()
    return tuple(output.raw[: size.value].rstrip(b"\0").decode().split("\0"))


def test_create_is_digest_only_default_deny_and_descriptor_addressed(
    library: ctypes.CDLL,
) -> None:
    command = _render(library, CREATE)
    assert command[0] == "/proc/self/fd/101"
    assert "--remote=false" in command
    assert "--pull=never" in command
    assert ("container", "create") == command[
        command.index("container") : command.index("container") + 2
    ]
    assert "--network=none" in command
    assert "--restart=no" in command
    assert "--replace" not in command
    assert "--rm" not in command
    assert "--privileged" not in command
    assert "seccomp=/proc/self/fd/302" in command
    assert "io.plamen.request-sha256=" + "08" * 32 in command
    assert "io.plamen.attempt=plamen-attempt-0123456789abcdef" in command
    assert command[-3:] == (
        "localhost/plamen/runtime@sha256:" + "2" * 64,
        "-B",
        "/opt/plamen/driver.py",
    )
    mount = command[command.index("--mount") + 1]
    assert "source=/proc/self/fd/301" in mount
    assert "bind-propagation=rprivate" in mount


def test_verified_egress_is_an_explicit_namespace_handoff(
    library: ctypes.CDLL,
) -> None:
    command = _render(library, CREATE, 1)
    assert "--network=ns:/proc/self/fd/401" in command
    assert "--network=none" not in command


@pytest.mark.parametrize(
    ("operation", "tail"),
    [
        (START, ("container", "start", "1" * 64)),
        (
            WAIT,
            (
                "container",
                "wait",
                "--condition=stopped",
                "--interval",
                "250ms",
                "1" * 64,
            ),
        ),
        (TERM, ("container", "kill", "--signal", "TERM", "1" * 64)),
        (KILL, ("container", "kill", "--signal", "KILL", "1" * 64)),
        (CLEANUP, ("container", "cleanup", "1" * 64)),
        (REMOVE, ("container", "rm", "--ignore", "1" * 64)),
    ],
)
def test_mutation_command_family_is_exact_and_uses_full_container_id(
    library: ctypes.CDLL, operation: int, tail: tuple[str, ...]
) -> None:
    command = _render(library, operation)
    assert command[-len(tail) :] == tail


def test_observation_is_exact_id_not_list_filter_or_events(
    library: ctypes.CDLL,
) -> None:
    command = _render(library, OBSERVE)
    assert command[-1] == "1" * 64
    assert command[-4:-2] == ("inspect", "--format")
    assert "ps" not in command
    assert "events" not in command


@pytest.mark.parametrize("raw, expected", [(b"0\n", 0), (b"137\n", 137), (b"255\n", 255)])
def test_wait_status_is_one_strict_decimal_line(
    library: ctypes.CDLL, raw: bytes, expected: int
) -> None:
    result = ctypes.c_int32()
    assert library.plamen_broker_v2_podman_lifecycle_parse_wait_status(
        raw, len(raw), ctypes.byref(result)
    ) == 0
    assert result.value == expected


@pytest.mark.parametrize(
    "raw", [b"", b"-1\n", b"01\n", b"256\n", b"0", b"0\n1\n", b" 0\n"]
)
def test_wait_status_rejects_ambiguous_or_noncanonical_output(
    library: ctypes.CDLL, raw: bytes
) -> None:
    result = ctypes.c_int32()
    assert library.plamen_broker_v2_podman_lifecycle_parse_wait_status(
        raw, len(raw), ctypes.byref(result)
    ) != 0


def test_teardown_is_native_cleanup_not_a_podman_command(
    library: ctypes.CDLL,
) -> None:
    assert _render(library, TEARDOWN) == ()


def test_receipt_record_roundtrip_and_tamper_rejection(
    library: ctypes.CDLL,
) -> None:
    assert (
        library.plamen_broker_v2_podman_lifecycle_test_receipt_and_record_integrity()
        == 0
    )


def test_operation_key_replay_recovery_and_conflict_decisions(
    library: ctypes.CDLL,
) -> None:
    decision = ctypes.c_uint32()
    decide = library.plamen_broker_v2_podman_lifecycle_test_decision
    assert decide(0, 0, 0, ctypes.byref(decision)) == 0
    assert decision.value == 1
    assert decide(1, 1, 0, ctypes.byref(decision)) == 3
    assert decision.value == 3
    assert decide(2, 1, 0, ctypes.byref(decision)) == 0
    assert decision.value == 2
    assert decide(2, 1, 1, ctypes.byref(decision)) == 2
    assert decision.value == 0


def test_descriptor_rooted_journal_is_durable_idempotent_and_tamper_evident(
    library: ctypes.CDLL, tmp_path: Path
) -> None:
    tmp_path.chmod(0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    parent_fd = os.open(tmp_path, flags)
    try:
        assert (
            library.plamen_broker_v2_podman_lifecycle_test_journal_roundtrip(
                parent_fd, b"attempt-0123456789abcdef"
            )
            == 0
        )
        assert (
            library.plamen_broker_v2_podman_lifecycle_test_journal_replay(
                parent_fd, b"attempt-0123456789abcdef"
            )
            == 0
        )
        assert (
            library.plamen_broker_v2_podman_lifecycle_test_journal_wrong_boot_rejected(
                parent_fd, b"attempt-0123456789abcdef"
            )
            == 0
        )
    finally:
        os.close(parent_fd)
    journal = tmp_path / "attempt-0123456789abcdef"
    records = sorted(journal.glob("*.lcj"))
    assert len(records) == 4
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in records)
    tampered = records[-1]
    raw = bytearray(tampered.read_bytes())
    raw[300] ^= 1
    tampered.chmod(0o600)
    tampered.write_bytes(raw)
    tampered.chmod(0o400)
    parent_fd = os.open(tmp_path, flags)
    try:
        assert (
            library.plamen_broker_v2_podman_lifecycle_test_journal_replay(
                parent_fd, b"attempt-0123456789abcdef"
            )
            != 0
        )
    finally:
        os.close(parent_fd)


def test_compatibility_executor_is_unsupported_off_linux(
    library: ctypes.CDLL,
) -> None:
    if platform.system() == "Linux":
        pytest.skip("Linux rejects compatibility calls without journal authority")
    assert library.plamen_broker_v2_podman_lifecycle_execute(None, None, 1, None) == 78


def test_no_shell_path_or_podman_service_authority_in_native_source() -> None:
    source = (
        ROOT / "native" / "linux" / "plamen_broker_v2_podman_lifecycle.c"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "system(",
        "popen(",
        "/bin/sh",
        "podman system service",
        "getenv(",
        "execvp(",
        "posix_spawnp(",
    ):
        assert forbidden not in source


def test_linux_process_custody_is_descriptor_executed_and_cgroup_wide() -> None:
    source = (
        ROOT / "native" / "linux" / "plamen_broker_v2_linux_process.c"
    ).read_text(encoding="utf-8")
    assert "fexecve(request->executable_fd" in source
    assert 'write_control_at(request->cgroup_fd, "cgroup.procs"' in source
    assert 'write_control_at(custody->cgroup_fd, "cgroup.kill", "1\\n")' in source
    assert "pidfd_open_native(child)" in source
    assert "proc_start_ticks(custody->leader_pid" in source
    assert "wait_population_zero(custody->cgroup_fd" in source
    assert "plamen_broker_v2_linux_cgroup_leaf_admit" in source
    for forbidden in (
        "system(", "popen(", "execvp(", "posix_spawnp(", "getenv(",
        "kill(-", "pkill", "killall",
    ):
        assert forbidden not in source


def test_journaled_linux_executor_binds_effect_and_postconditions() -> None:
    source = (
        ROOT / "native" / "linux" / "plamen_broker_v2_podman_lifecycle.c"
    ).read_text(encoding="utf-8")
    header = (
        ROOT / "native" / "linux" / "plamen_broker_v2_podman_lifecycle.h"
    ).read_text(encoding="utf-8")
    assert "plamen_broker_v2_podman_lifecycle_execute_journaled" in header
    assert "plamen_broker_v2_podman_lifecycle_journal_append_intent" in source
    assert "execute_command_retained" in source
    assert "fexecve(custody->component_fds[" in source
    assert source.count("plamen_broker_v2_podman_cgroup_path_revalidate(") >= 3
    assert "plamen_broker_v2_linux_cgroup_leaf_admit(custody->cgroup_fd)" in source
    assert "remove_directory_contents" in source
    assert "PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER" in source
    assert "PLAMEN_BROKER_V2_PODMAN_ROOT_WORK" in source
    assert "plamen_broker_v2_podman_lifecycle_journal_commit" in source


def test_linux_provider_state_distinguishes_source_from_live_availability() -> None:
    import podman_linux_provider as provider

    assert "EXECUTOR" in provider.NATIVE_LIFECYCLE_STATUS
    assert "LIVE_ROOTLESS_LINUX_RECEIPTS_PENDING" in provider.NATIVE_LIFECYCLE_STATUS
    assert provider.NATIVE_LIFECYCLE_AVAILABLE is False


def test_linux_process_custody_nonlinux_surface_stays_fail_closed(
    library: ctypes.CDLL,
) -> None:
    if platform.system() == "Linux":
        pytest.skip("requires the dedicated live cgroup-v2 integration lane")
    library.plamen_broker_v2_linux_cgroup_leaf_admit.argtypes = [ctypes.c_int]
    library.plamen_broker_v2_linux_process_spawn_retained.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    assert library.plamen_broker_v2_linux_cgroup_leaf_admit(-1) == -1
    assert library.plamen_broker_v2_linux_process_spawn_retained(None, None) == 78
