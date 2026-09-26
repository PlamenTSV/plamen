"""Native macOS Seatbelt and descendant-authority acceptance tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from typing import Callable

import pytest

import owned_process_scope as S


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="native Seatbelt and kqueue contracts are macOS-only",
)


def _launch_seatbelt_helper(
    writable_root: Path,
    command: tuple[str, ...],
) -> tuple[subprocess.Popen[bytes], int, int]:
    capability = S.process_tree_termination_capability()
    gate_read, gate_write = os.pipe()
    status_read, status_write = os.pipe()
    root_descriptor = os.open(
        writable_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    for descriptor in (gate_read, status_write, root_descriptor):
        os.set_inheritable(descriptor, True)
    argv = [
        str(capability["sandbox_exec_path"]),
        "-p",
        S._darwin_seatbelt_profile((writable_root.resolve(strict=True),)),
        str(capability["interpreter_path"]),
        "-I",
        "-S",
        str(capability["helper_path"]),
        str(gate_read),
        str(status_write),
        "1",
        str(root_descriptor),
        str(writable_root.resolve(strict=True)),
        "--",
        *command,
    ]
    try:
        process = subprocess.Popen(
            argv,
            pass_fds=(gate_read, status_write, root_descriptor),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        os.close(gate_read)
        os.close(status_write)
        os.close(root_descriptor)
    return process, gate_write, status_read


def _release_helper(
    process: subprocess.Popen[bytes],
    gate: int,
    status: int,
    *,
    before_release: Callable[[], None] | None = None,
) -> None:
    try:
        readable, _, _ = select.select([status], [], [], 5)
        assert readable, "trusted Seatbelt helper did not acknowledge readiness"
        assert os.read(status, 64) == b"SEATBELT_READY:1\n"
    finally:
        os.close(status)
    if before_release is not None:
        before_release()
    try:
        assert os.write(gate, b"1") == 1
    finally:
        os.close(gate)
    assert process.wait(timeout=10) == 0, process.stderr.read().decode(
        "utf-8", "replace"
    )


def test_darwin_seatbelt_allows_write_beneath_authenticated_root(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable"
    writable.mkdir()
    destination = writable / "inside.txt"
    code = (
        "from pathlib import Path; import sys; "
        "Path(sys.argv[1]).write_text('inside', encoding='utf-8')"
    )
    process, gate, status = _launch_seatbelt_helper(
        writable,
        (sys.executable, "-I", "-S", "-c", code, str(destination)),
    )
    def assert_gated() -> None:
        assert destination.exists() is False

    try:
        _release_helper(
            process,
            gate,
            status,
            before_release=assert_gated,
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    assert destination.read_text(encoding="utf-8") == "inside"


def test_darwin_seatbelt_denies_write_outside_authenticated_root(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable"
    denied = tmp_path / "denied"
    writable.mkdir()
    denied.mkdir()
    destination = denied / "outside.txt"
    result = writable / "errno.txt"
    code = "\n".join(
        (
            "import pathlib, sys",
            "destination = pathlib.Path(sys.argv[1])",
            "result = pathlib.Path(sys.argv[2])",
            "try:",
            "    destination.write_text('escaped', encoding='utf-8')",
            "except OSError as exc:",
            "    result.write_text(str(exc.errno), encoding='ascii')",
            "else:",
            "    result.write_text('WRITE_ALLOWED', encoding='ascii')",
        )
    )
    process, gate, status = _launch_seatbelt_helper(
        writable,
        (
            sys.executable,
            "-I",
            "-S",
            "-c",
            code,
            str(destination),
            str(result),
        ),
    )
    try:
        _release_helper(process, gate, status)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    assert destination.exists() is False
    assert result.read_text(encoding="ascii") == "1"


def test_darwin_seatbelt_is_inherited_by_setsid_double_fork_descendant(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable"
    denied = tmp_path / "denied"
    writable.mkdir()
    denied.mkdir()
    destination = denied / "descendant-outside.txt"
    result = writable / "descendant-errno.txt"
    code = "\n".join(
        (
            "import os, pathlib, sys, time",
            "destination = pathlib.Path(sys.argv[1])",
            "result = pathlib.Path(sys.argv[2])",
            "first = os.fork()",
            "if first == 0:",
            "    os.setsid()",
            "    second = os.fork()",
            "    if second == 0:",
            "        try:",
            "            destination.write_text('escaped', encoding='utf-8')",
            "        except OSError as exc:",
            "            result.write_text(str(exc.errno), encoding='ascii')",
            "        else:",
            "            result.write_text('WRITE_ALLOWED', encoding='ascii')",
            "        os._exit(0)",
            "    os._exit(0)",
            "deadline = time.monotonic() + 5",
            "while not result.exists() and time.monotonic() < deadline:",
            "    time.sleep(0.01)",
            "raise SystemExit(0 if result.exists() else 73)",
        )
    )
    process, gate, status = _launch_seatbelt_helper(
        writable,
        (
            sys.executable,
            "-I",
            "-S",
            "-c",
            code,
            str(destination),
            str(result),
        ),
    )
    try:
        _release_helper(process, gate, status)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    assert destination.exists() is False
    assert result.read_text(encoding="ascii") == "1"


def test_darwin_seatbelt_denies_network_in_setsid_descendant(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable"
    writable.mkdir()
    result = writable / "network-errno.txt"
    code = "\n".join(
        (
            "import os, pathlib, socket, sys, time",
            "result = pathlib.Path(sys.argv[1])",
            "first = os.fork()",
            "if first == 0:",
            "    os.setsid()",
            "    second = os.fork()",
            "    if second == 0:",
            "        probe = socket.socket()",
            "        try:",
            "            probe.connect(('127.0.0.1', 9))",
            "        except OSError as exc:",
            "            result.write_text(str(exc.errno), encoding='ascii')",
            "        else:",
            "            result.write_text('NETWORK_ALLOWED', encoding='ascii')",
            "        os._exit(0)",
            "    os._exit(0)",
            "deadline = time.monotonic() + 5",
            "while not result.exists() and time.monotonic() < deadline:",
            "    time.sleep(0.01)",
            "raise SystemExit(0 if result.exists() else 73)",
        )
    )
    process, gate, status = _launch_seatbelt_helper(
        writable,
        (sys.executable, "-I", "-S", "-c", code, str(result)),
    )
    try:
        _release_helper(process, gate, status)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    assert result.read_text(encoding="ascii") == "1"


def test_darwin_capability_fails_closed_for_obsolete_note_track() -> None:
    capability = S.process_tree_termination_capability()
    for path_key, digest_key in (
        ("helper_path", "helper_sha256"),
        ("interpreter_path", "interpreter_sha256"),
        ("sandbox_exec_path", "sandbox_exec_sha256"),
    ):
        source = Path(str(capability[path_key]))
        assert source.is_file()
        assert hashlib.sha256(source.read_bytes()).hexdigest() == capability[digest_key]
    assert S._darwin_note_track_available() == (
        False,
        "DARWIN_KQUEUE_NOTE_TRACK_UNSUPPORTED_SINCE_10_5",
    )
    assert capability["exhaustive_descendant_termination_authority"] is False
    assert capability["provider_owns_tree"] is False
    assert capability["population_zero_proof"] == "UNAVAILABLE"
    assert capability["exhaustive_write_confinement_authority"] is True
    assert capability["exhaustive_network_confinement_authority"] is True
    assert capability["write_confinement"] == (
        "DARWIN_SEATBELT_PATH_SUBPATH_V1"
    )
    assert capability["network_confinement"] == (
        "DARWIN_SEATBELT_NETWORK_DENY_V1"
    )
    assert capability[
        "seatbelt_write_confinement_provider_available"
    ] is True
    assert capability["limitation"] == (
        "DARWIN_KQUEUE_NOTE_TRACK_UNSUPPORTED_SINCE_10_5"
    )


def _reduced_scope_or_skip(tmp_path: Path) -> S.OwnedProcessScope:
    capability = S.process_tree_termination_capability()
    if capability["exhaustive_descendant_termination_authority"] is True:
        pytest.skip("host has the stronger NOTE_TRACK process-tree provider")
    if capability["exhaustive_write_confinement_authority"] is not True:
        pytest.skip(str(capability["limitation"]))
    return S.OwnedProcessScope(
        writable_roots=(tmp_path,),
        population_zero_timeout_seconds=5,
    )


def test_reduced_darwin_scope_gates_execution_and_never_claims_population_zero(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "released.txt"
    scope = _reduced_scope_or_skip(tmp_path)
    process: subprocess.Popen[bytes] | None = None
    try:
        physical = scope.wrap_argv(
            (
                sys.executable,
                "-I",
                "-S",
                "-c",
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text('released')",
                str(destination),
            )
        )
        process = scope.create_process(
            physical,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            **scope.popen_kwargs(),
        )
        assert destination.exists() is False
        scope.attach(process)
        assert process.wait(timeout=5) == 0
        assert destination.read_text(encoding="utf-8") == "released"
        assert scope.write_confinement_proven is True
        assert scope.containment_evidence["network_confinement_proven"] is True
        scope.terminate()
        scope.close()
        assert scope.population_zero_proven is False
        assert scope.containment_evidence[
            "exhaustive_descendant_termination_authority"
        ] is False
        assert scope.write_confinement_binding == {
            "protocol": "DARWIN_SANDBOX_EXEC_SEATBELT_REDUCED_V1",
            "writable_roots_sha256": hashlib.sha256(
                str(tmp_path.resolve()).encode("utf-8")
            ).hexdigest(),
            "helper_sha256": scope.scope_capability["helper_sha256"],
            "sandbox_exec_sha256": scope.scope_capability[
                "sandbox_exec_sha256"
            ],
            "network_confinement": "DARWIN_SEATBELT_NETWORK_DENY_V1",
            "descendant_termination_authority": False,
            "persistent_recovery_authority": False,
        }
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if not scope.closed:
            scope.emergency_close()


def test_reduced_darwin_scope_rejects_preopened_writable_escape(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable"
    denied = tmp_path / "denied"
    writable.mkdir()
    denied.mkdir()
    scope = _reduced_scope_or_skip(writable)
    destination = denied / "preopened.txt"
    try:
        physical = scope.wrap_argv((sys.executable, "-I", "-S", "-c", "pass"))
        with destination.open("wb") as escaped:
            with pytest.raises(
                S.OwnedProcessScopeError,
                match="descriptor escapes admitted roots",
            ):
                scope.create_process(
                    physical,
                    stdin=subprocess.DEVNULL,
                    stdout=escaped,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    **scope.popen_kwargs(),
                )
        assert scope.process_creation_state == "NOT_ATTEMPTED"
    finally:
        scope.emergency_close()


def test_reduced_darwin_scope_does_not_misreport_escaped_descendant_cleanup(
    tmp_path: Path,
) -> None:
    descendant_file = tmp_path / "escaped-descendant.pid"
    code = "\n".join(
        (
            "import os, pathlib, sys, time",
            "first = os.fork()",
            "if first == 0:",
            "    os.setsid()",
            "    second = os.fork()",
            "    if second == 0:",
            "        pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))",
            "        time.sleep(60)",
            "    os._exit(0)",
            "time.sleep(60)",
        )
    )
    scope = _reduced_scope_or_skip(tmp_path)
    process: subprocess.Popen[bytes] | None = None
    descendant_pid: int | None = None
    try:
        physical = scope.wrap_argv(
            (sys.executable, "-I", "-S", "-c", code, str(descendant_file))
        )
        process = scope.create_process(
            physical,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            **scope.popen_kwargs(),
        )
        scope.attach(process)
        deadline = time.monotonic() + 5
        while not descendant_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert descendant_file.is_file()
        descendant_pid = int(descendant_file.read_text(encoding="ascii"))
        scope.terminate()
        process.wait(timeout=5)
        # setsid escaped the process group.  Seatbelt still confines this
        # descendant's effects, but PGID cleanup cannot prove or force tree
        # extinction and must never be promoted to population-zero authority.
        os.kill(descendant_pid, 0)
        with pytest.raises(
            S.OwnedProcessScopeError,
            match="cannot prove exact scope membership",
        ):
            scope.contains_process_id(descendant_pid)
        scope.close()
        assert scope.population_zero_proven is False
    finally:
        if descendant_pid is not None:
            try:
                os.kill(descendant_pid, 9)
            except ProcessLookupError:
                pass
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if not scope.closed:
            scope.emergency_close()


def test_darwin_note_trackerr_is_sticky_and_never_mints_authority() -> None:
    class _Event:
        ident = 12345
        flags = 0
        fflags = S.select.KQ_NOTE_TRACKERR

    class _Queue:
        def control(self, *_args):
            return [_Event()]

    scope = object.__new__(S.OwnedProcessScope)
    scope._darwin_kqueue = _Queue()
    scope._darwin_tracking_error = None
    scope._darwin_tracked_processes = {12345}
    with pytest.raises(S.OwnedProcessScopeError, match="NOTE_TRACKERR"):
        scope._drain_darwin_process_events(timeout_seconds=0)
    assert scope._darwin_tracked_processes == {12345}
    with pytest.raises(S.OwnedProcessScopeError, match="NOTE_TRACKERR"):
        scope._drain_darwin_process_events(timeout_seconds=0)


def test_darwin_note_track_terminates_setsid_double_fork_descendant(
    tmp_path: Path,
) -> None:
    capability = S.process_tree_termination_capability()
    if capability["exhaustive_descendant_termination_authority"] is not True:
        pytest.skip(str(capability["limitation"]))
    descendant_pid = tmp_path / "descendant.pid"
    code = "\n".join(
        (
            "import os, pathlib, sys, time",
            "first = os.fork()",
            "if first == 0:",
            "    os.setsid()",
            "    second = os.fork()",
            "    if second == 0:",
            "        pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))",
            "        time.sleep(60)",
            "    os._exit(0)",
            "time.sleep(60)",
        )
    )
    scope = S.OwnedProcessScope(
        writable_roots=(tmp_path,),
        population_zero_timeout_seconds=5,
    )
    process = None
    try:
        physical = scope.wrap_argv(
            (sys.executable, "-I", "-S", "-c", code, str(descendant_pid))
        )
        process = scope.create_process(
            physical,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            **scope.popen_kwargs(),
        )
        scope.attach(process)
        deadline = time.monotonic() + 5
        while not descendant_pid.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert descendant_pid.is_file()
        tracked_pid = int(descendant_pid.read_text(encoding="ascii"))
        assert scope.contains_process_id(tracked_pid) is True
        scope.terminate()
        process.wait(timeout=5)
        scope.close()
        assert scope.population_zero_proven is True
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if not scope.closed:
            scope.emergency_close()
