"""Regression evidence for physically bounded owned-process output capture."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

import owned_process_runner as O


_PYTHON = str(Path(sys.executable).resolve())


def _spawn_with_captures(
    source: str,
    *,
    limit: int,
) -> tuple[
    subprocess.Popen[bytes],
    O._BoundedPipeCapture,
    O._BoundedPipeCapture,
]:
    stdout = O._BoundedPipeCapture(limit=limit, label="test-stdout")
    stderr = O._BoundedPipeCapture(limit=limit, label="test-stderr")
    try:
        process = subprocess.Popen(
            [_PYTHON, "-I", "-S", "-c", source],
            stdin=subprocess.DEVNULL,
            stdout=stdout.child_stream,
            stderr=stderr.child_stream,
            close_fds=(os.name != "nt"),
        )
    except BaseException:
        stdout.close_parent_writer()
        stderr.close_parent_writer()
        O._finish_captures(stdout, stderr)
        raise
    stdout.close_parent_writer()
    stderr.close_parent_writer()
    return process, stdout, stderr


def test_dual_stream_capture_is_bounded_without_backpressure() -> None:
    limit = 1024
    stdout_size = 6 * 1024 * 1024
    stderr_size = 7 * 1024 * 1024
    process, stdout, stderr = _spawn_with_captures(
        (
            "import os\n"
            "def write_all(fd, data):\n"
            " view=memoryview(data)\n"
            " while view:\n"
            "  view=view[os.write(fd,view):]\n"
            "write_all(1,b'H'*600+b'M'*6290256+b'T'*600)\n"
            f"write_all(2,b'E'*{stderr_size})\n"
        ),
        limit=limit,
    )

    assert process.wait(timeout=15) == 0
    stdout_text = stdout.text(encoding="ascii", errors="strict")
    stderr_text = stderr.text(encoding="ascii", errors="strict")

    assert stdout.observed_bytes == stdout_size
    assert stderr.observed_bytes == stderr_size
    assert stdout.retained_bytes == limit
    assert stderr.retained_bytes == limit
    assert stdout_text.startswith("H" * (limit // 2))
    assert stdout_text.endswith("T" * (limit - limit // 2))
    assert f"omitted {stdout_size - limit} bytes" in stdout_text
    assert "retained first 512 and final 512 bytes" in stdout_text
    assert f"omitted {stderr_size - limit} bytes" in stderr_text
    assert stdout.sha256 == hashlib.sha256(
        b"H" * 600 + b"M" * 6290256 + b"T" * 600
    ).hexdigest()
    assert stderr.sha256 == hashlib.sha256(b"E" * stderr_size).hexdigest()


def test_capture_keeps_exact_bytes_when_stream_does_not_overflow() -> None:
    process, stdout, stderr = _spawn_with_captures(
        "import os;os.write(1,b'exact-stdout');os.write(2,b'exact-stderr')",
        limit=64,
    )

    assert process.wait(timeout=10) == 0
    assert stdout.text(encoding="ascii", errors="strict") == "exact-stdout"
    assert stderr.text(encoding="ascii", errors="strict") == "exact-stderr"
    assert stdout.overflowed is False
    assert stderr.overflowed is False
    assert stdout.sha256 == hashlib.sha256(b"exact-stdout").hexdigest()
    assert stderr.sha256 == hashlib.sha256(b"exact-stderr").hexdigest()


def test_eof_timeout_stops_reader_and_closes_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = O._BoundedPipeCapture(limit=64, label="leaked-writer")
    inherited_writer = os.dup(capture.child_stream.fileno())
    read_descriptor = capture._read_descriptor
    monkeypatch.setattr(O, "_CAPTURE_EOF_TIMEOUT_SECONDS", 0.02)
    try:
        with pytest.raises(
            O.OwnedProcessRunnerError,
            match="did not reach EOF",
        ):
            capture.finish()
        assert capture._reader.is_alive() is False
        with pytest.raises(OSError):
            os.fstat(read_descriptor)
    finally:
        os.close(inherited_writer)


@pytest.mark.skipif(os.name == "nt", reason="POSIX readiness backend")
def test_capture_supports_descriptor_above_select_fdsetsize() -> None:
    held: list[int] = []
    process = None
    stdout = None
    stderr = None
    try:
        while not held or held[-1] <= 1030:
            try:
                held.append(os.open(os.devnull, os.O_RDONLY))
            except OSError as exc:
                pytest.skip(f"host descriptor ceiling is too low: {exc}")
        process, stdout, stderr = _spawn_with_captures(
            "import os;os.write(1,b'high-fd')",
            limit=64,
        )
        assert stdout._read_descriptor > 1024
        assert process.wait(timeout=10) == 0
        assert stdout.text(encoding="ascii", errors="strict") == "high-fd"
        assert stderr.text(encoding="ascii", errors="strict") == ""
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        for descriptor in reversed(held):
            os.close(descriptor)


def test_expired_cancel_poll_never_accepts_completed_process() -> None:
    class CompletedProcess:
        @staticmethod
        def poll() -> int:
            return 0

    with pytest.raises(subprocess.TimeoutExpired):
        O._wait_for_owned_process(
            CompletedProcess(),  # type: ignore[arg-type]
            argv=(_PYTHON,),
            timeout=1.0,
            deadline=time.monotonic() - 1.0,
            cancel_token=lambda: False,
        )


def test_terminated_noisy_process_reaches_capture_eof_without_deadlock() -> None:
    process, stdout, stderr = _spawn_with_captures(
        (
            "import os\n"
            "chunk=b'x'*65536\n"
            "while True:\n"
            " os.write(1,chunk)\n"
            " os.write(2,chunk)\n"
        ),
        limit=2048,
    )
    deadline = time.monotonic() + 5
    while stdout.observed_bytes <= 2048 or stderr.observed_bytes <= 2048:
        assert time.monotonic() < deadline
        time.sleep(0.01)

    process.kill()
    process.wait(timeout=10)
    started = time.monotonic()
    O._finish_captures(stdout, stderr)

    assert time.monotonic() - started < 2
    assert stdout.retained_bytes == 2048
    assert stderr.retained_bytes == 2048
    assert stdout.overflowed is True
    assert stderr.overflowed is True


class _TestProcessScope:
    """Small subprocess-backed scope used to test runner plumbing portably."""

    instances: list["_TestProcessScope"] = []

    def __init__(self, **_kwargs: object) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self.create_kwargs: dict[str, object] = {}
        self.attached = False
        self.terminated = False
        self.write_confinement_proven = True
        type(self).instances.append(self)

    def wrap_argv(self, argv: tuple[str, ...]) -> tuple[str, ...]:
        return argv

    def popen_kwargs(self) -> dict[str, object]:
        return {}

    def create_process(
        self,
        argv: tuple[str, ...],
        *,
        popen_factory: object,
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        del popen_factory
        self.create_kwargs = dict(kwargs)
        self.process = subprocess.Popen(argv, **kwargs)
        return self.process

    def attach(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.attached = True

    def terminate_created_process(self) -> None:
        self.terminate()

    def terminate(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)
        self.terminated = True

    def close(self) -> None:
        return None

    def emergency_close(self) -> None:
        self.terminate()


@pytest.fixture
def runner_with_test_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    _TestProcessScope.instances.clear()
    monkeypatch.setattr(O, "OwnedProcessScope", _TestProcessScope)
    monkeypatch.setattr(
        O,
        "process_tree_termination_capability",
        lambda: {
            "platform": "TEST",
            "pre_execution_assignment": True,
            "exhaustive_descendant_termination_authority": True,
            "exhaustive_write_confinement_authority": True,
        },
    )


def test_timeout_terminates_scope_then_returns_bounded_stream_evidence(
    runner_with_test_scope: None,
) -> None:
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        O.run_owned_process(
            [
                _PYTHON,
                "-I",
                "-S",
                "-c",
                (
                    "import os,time\n"
                    "chunk=b'z'*65536\n"
                    "while True:\n"
                    " os.write(1,chunk)\n"
                    " os.write(2,chunk)\n"
                    " time.sleep(.001)\n"
                ),
            ],
            timeout=0.25,
            output_limit_bytes=1024,
        )

    assert _TestProcessScope.instances[-1].terminated is True
    assert "output truncated" in caught.value.output
    assert "output truncated" in caught.value.stderr
    assert len(caught.value.output.encode("utf-8")) < 1200
    assert len(caught.value.stderr.encode("utf-8")) < 1200
    assert caught.value.stdout_observed_bytes > 1024
    assert caught.value.stderr_observed_bytes > 1024
    assert caught.value.stdout_retained_bytes == 1024
    assert caught.value.stderr_retained_bytes == 1024
    assert caught.value.stdout_truncated is True
    assert caught.value.stderr_truncated is True
    assert len(caught.value.stdout_sha256) == 64
    assert len(caught.value.stderr_sha256) == 64
    assert len(caught.value.executable_binding_sha256) == 64


def test_completed_result_exposes_full_raw_invalid_utf8_digest(
    runner_with_test_scope: None,
) -> None:
    raw = b"\xff\xfe" + b"x" * 4096 + b"\x80"
    result = O.run_owned_process(
        [
            _PYTHON,
            "-I",
            "-S",
            "-c",
            f"import os;os.write(1,{raw!r});os.write(2,b'err')",
        ],
        timeout=5,
        output_limit_bytes=64,
    )
    assert result.returncode == 0
    assert result.stdout_observed_bytes == len(raw)
    assert result.stdout_retained_bytes == 64
    assert result.stdout_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.stdout_truncated is True
    assert result.stderr_observed_bytes == 3
    assert result.stderr_sha256 == hashlib.sha256(b"err").hexdigest()
    assert result.stderr_truncated is False
    assert "\ufffd" in result.stdout
    assert len(result.executable_binding_sha256) == 64


def test_timeout_strict_decode_boundary_preserves_timeout_classification(
    runner_with_test_scope: None,
) -> None:
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        O.run_owned_process(
            [
                _PYTHON,
                "-I",
                "-S",
                "-c",
                (
                    "import os,time;"
                    "os.write(1,'😀'.encode()*100);"
                    "time.sleep(60)"
                ),
            ],
            timeout=0.15,
            output_limit_bytes=11,
            errors="strict",
        )

    assert "requested diagnostic decoding failed" in caught.value.output
    assert _TestProcessScope.instances[-1].create_kwargs["close_fds"] is True


def test_locked_launch_descriptor_closes_when_wrapping_fails(
    runner_with_test_scope: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import locked_executable_guard as guard

    descriptor = os.open(os.devnull, os.O_RDONLY)
    monkeypatch.setattr(guard, "bind_locked_executable", lambda _path: {})
    monkeypatch.setattr(
        guard,
        "validate_locked_executable_binding",
        lambda _path, _binding: {},
    )
    monkeypatch.setattr(
        guard,
        "acquire_locked_executable_launch",
        lambda _path, _binding: (_PYTHON, descriptor),
    )
    monkeypatch.setattr(
        _TestProcessScope,
        "wrap_argv",
        lambda _self, _argv: (_ for _ in ()).throw(RuntimeError("wrap failed")),
    )

    with pytest.raises(O.OwnedProcessRunnerError, match="wrap failed"):
        O.run_owned_process([_PYTHON, "-c", "pass"], timeout=1)
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_cancellation_terminates_scope_and_capture_threads(
    runner_with_test_scope: None,
    tmp_path: Path,
) -> None:
    cancel = threading.Event()
    marker = tmp_path / "started"

    def request_cancel() -> bool:
        if marker.exists():
            cancel.set()
        return cancel.is_set()

    with pytest.raises(
        O.OwnedProcessRunnerError,
        match="execution was cancelled",
    ) as caught:
        O.run_owned_process(
            [
                _PYTHON,
                "-I",
                "-S",
                "-c",
                (
                    "import os,pathlib,time\n"
                    f"pathlib.Path({str(marker)!r}).write_text('ready')\n"
                    "chunk=b'c'*65536\n"
                    "while True:\n"
                    " os.write(1,chunk)\n"
                    " time.sleep(.001)\n"
                ),
            ],
            timeout=10,
            output_limit_bytes=1024,
            writable_roots=(tmp_path,),
            lease_cancel_token=request_cancel,
        )

    assert _TestProcessScope.instances[-1].terminated is True
    assert "output truncated" in caught.value.stdout
    assert len(caught.value.stdout.encode("utf-8")) < 1200
