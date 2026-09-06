"""Provider-owned lifecycle primitive for the trusted PTY transport host.

This module owns process creation, the OS Job/cgroup, bounded host frames and
terminal cleanup.  It intentionally cannot authorize model-semantic success;
the WorkerTransaction layer must independently replay final transcript and
assigned-output bytes after this provider proves population zero and closes.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
from typing import BinaryIO, Sequence

from owned_process_scope import OwnedProcessScope, OwnedProcessScopeError
from pty_worker_host import load_host_manifest
from pty_worker_protocol import (
    Frame,
    FrameType,
    PtyProtocolError,
    read_frame,
    strict_json_loads,
    write_frame,
)


DEFAULT_PTY_BYTE_LIMIT = 32 * 1024 * 1024
DEFAULT_HOST_STDERR_LIMIT = 256 * 1024
_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


class PtyProviderError(RuntimeError):
    """The PTY transport could not preserve its bounded lifecycle contract."""


def _digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _strict_control_json(frame: Frame, fields: set[str]) -> dict[str, object]:
    try:
        value = strict_json_loads(frame.payload)
    except PtyProtocolError as exc:
        raise PtyProviderError("host control frame is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != fields:
        raise PtyProviderError("host control frame fields are invalid")
    return value


class PtyHostHandle:
    """One contained PTY host and its exact bounded transport streams."""

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        scope: OwnedProcessScope,
        pty_byte_limit: int,
        stderr_limit: int,
        host_path: Path,
        manifest_path: Path,
    ) -> None:
        self._process = process
        self._scope = scope
        self._pty_byte_limit = pty_byte_limit
        self._stderr_limit = stderr_limit
        self.host_path = host_path
        self.host_sha256 = _digest_file(host_path)
        self.manifest_path = manifest_path
        self.manifest_sha256 = _digest_file(manifest_path)
        self._events: queue.Queue[Frame | BaseException] = queue.Queue()
        self._write_lock = threading.Lock()
        self._reader_done = threading.Event()
        self._stderr_done = threading.Event()
        self._stderr = bytearray()
        self._stderr_overflow = False
        self._total_pty_bytes = 0
        self._child_pid: int | None = None
        self._child_membership_proven = False
        self._closed = False
        self._population_zero_proven = False
        self._reader_thread = threading.Thread(
            target=self._read_frames,
            name=f"plamen-pty-provider-{process.pid}",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            name=f"plamen-pty-stderr-{process.pid}",
            daemon=True,
        )
        self._reader_thread.start()
        self._stderr_thread.start()

    @classmethod
    def launch(
        cls,
        *,
        manifest_path: str | Path,
        writable_roots: Sequence[str | Path],
        persistent_identity: str,
        pty_byte_limit: int = DEFAULT_PTY_BYTE_LIMIT,
        stderr_limit: int = DEFAULT_HOST_STDERR_LIMIT,
    ) -> "PtyHostHandle":
        if (
            not isinstance(persistent_identity, str)
            or not _IDENTITY_RE.fullmatch(persistent_identity)
        ):
            raise PtyProviderError("PTY process-scope identity is invalid")
        for value, label in (
            (pty_byte_limit, "PTY byte ceiling"),
            (stderr_limit, "host stderr ceiling"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise PtyProviderError(f"{label} must be positive")
        manifest = Path(manifest_path).resolve(strict=True)
        if manifest.is_symlink() or not manifest.is_file():
            raise PtyProviderError("PTY host manifest must be a real regular file")
        # Parse before any native child exists.  The transaction layer also
        # hash-binds and replays these bytes around execution.
        load_host_manifest(manifest)
        roots = tuple(Path(item).resolve(strict=True) for item in writable_roots)
        host_path = Path(__file__).with_name("pty_worker_host.py").resolve(strict=True)
        interpreter = Path(sys.executable).resolve(strict=True)
        scope: OwnedProcessScope | None = None
        process: subprocess.Popen[bytes] | None = None
        try:
            scope = OwnedProcessScope(
                writable_roots=roots,
                persistent_identity=persistent_identity,
            )
            physical_argv = scope.wrap_argv(
                [
                    str(interpreter),
                    "-I",
                    "-S",
                    "-B",
                    str(host_path),
                    str(manifest),
                ]
            )
            process = scope.create_process(
                physical_argv,
                popen_factory=None,
                cwd=str(host_path.parent),
                env=dict(os.environ),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=(os.name != "nt"),
                **scope.popen_kwargs(),
            )
            scope.attach(process)
            if (
                process.stdin is None
                or process.stdout is None
                or process.stderr is None
            ):
                raise PtyProviderError("PTY host streams were not created")
            return cls(
                process=process,
                scope=scope,
                pty_byte_limit=pty_byte_limit,
                stderr_limit=stderr_limit,
                host_path=host_path,
                manifest_path=manifest,
            )
        except BaseException as exc:
            if scope is not None:
                try:
                    if scope.attached and not scope.terminated:
                        scope.terminate()
                    scope.close()
                except BaseException:
                    with contextlib.suppress(BaseException):
                        scope.emergency_close()
            if process is not None:
                with contextlib.suppress(BaseException):
                    process.kill()
                with contextlib.suppress(BaseException):
                    process.wait(timeout=5)
            if isinstance(exc, PtyProviderError):
                raise
            raise PtyProviderError(
                f"PTY host launch failed: {type(exc).__name__}"
            ) from exc

    def _read_frames(self) -> None:
        assert self._process.stdout is not None
        saw_terminal = False
        try:
            while not saw_terminal:
                frame = read_frame(self._process.stdout)
                if frame.kind is FrameType.PTY_BYTES:
                    self._total_pty_bytes += len(frame.payload)
                    if self._total_pty_bytes > self._pty_byte_limit:
                        raise PtyProviderError("PTY byte ceiling exceeded")
                self._events.put(frame)
                saw_terminal = frame.kind in {
                    FrameType.CHILD_EXIT,
                    FrameType.HOST_ERROR,
                }
        except BaseException as exc:
            self._events.put(
                exc
                if isinstance(exc, PtyProviderError)
                else PtyProviderError(
                    f"PTY host protocol failed: {type(exc).__name__}"
                )
            )
        finally:
            self._reader_done.set()

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        try:
            while True:
                raw = self._process.stderr.read(65536)
                if not raw:
                    return
                remaining = self._stderr_limit - len(self._stderr)
                if remaining > 0:
                    self._stderr.extend(raw[:remaining])
                if len(raw) > remaining:
                    self._stderr_overflow = True
                    return
        finally:
            self._stderr_done.set()

    def _send(self, kind: FrameType, payload: bytes = b"") -> None:
        if self._closed:
            raise PtyProviderError("PTY host scope is already closed")
        if self._process.stdin is None:
            raise PtyProviderError("PTY host input stream is unavailable")
        with self._write_lock:
            try:
                write_frame(self._process.stdin, kind, payload)
            except (OSError, PtyProtocolError) as exc:
                raise PtyProviderError("PTY host command transport failed") from exc

    def write(self, raw: bytes) -> None:
        if not isinstance(raw, bytes):
            raise PtyProviderError("PTY write payload must be bytes")
        self._send(FrameType.WRITE, raw)

    def resize(self, *, columns: int, rows: int) -> None:
        for value, label in ((columns, "columns"), (rows, "rows")):
            if isinstance(value, bool) or not isinstance(value, int):
                raise PtyProviderError(f"PTY {label} must be an integer")
            if value < 1 or value > 1000:
                raise PtyProviderError(f"PTY {label} is outside the supported range")
        self._send(
            FrameType.RESIZE,
            json.dumps(
                {"columns": columns, "rows": rows},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def interrupt(self) -> None:
        self._send(FrameType.INTERRUPT)

    def close_input(self) -> None:
        self._send(FrameType.CLOSE_INPUT)

    def poll_event(self, *, timeout_seconds: float) -> Frame:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise PtyProviderError("PTY event timeout must be positive")
        try:
            item = self._events.get(timeout=float(timeout_seconds))
        except queue.Empty as exc:
            if self._process.poll() is not None:
                raise PtyProviderError(
                    "PTY host exited without a terminal protocol frame"
                ) from exc
            raise PtyProviderError("PTY host event wait timed out") from exc
        if isinstance(item, BaseException):
            if isinstance(item, PtyProviderError):
                raise item
            raise PtyProviderError(
                f"PTY host reader failed: {type(item).__name__}"
            ) from item
        if item.kind is FrameType.HOST_ERROR:
            value = _strict_control_json(item, {"code"})
            code = value["code"]
            if not isinstance(code, str) or not code:
                raise PtyProviderError("PTY host error code is invalid")
            raise PtyProviderError(f"PTY host reported transport error: {code}")
        return item

    def wait_ready(self, *, timeout_seconds: float) -> None:
        deadline = time.monotonic() + float(timeout_seconds)
        ready = False
        while not (ready and self._child_pid is not None):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PtyProviderError("PTY host readiness timed out")
            frame = self.poll_event(timeout_seconds=remaining)
            if not ready:
                if frame.kind is not FrameType.READY:
                    raise PtyProviderError("PTY host did not emit READY first")
                value = _strict_control_json(frame, {"protocol"})
                if value["protocol"] != "PLP1":
                    raise PtyProviderError("PTY host protocol identity is invalid")
                ready = True
                continue
            if frame.kind is not FrameType.CHILD_PID:
                raise PtyProviderError("PTY host did not emit CHILD_PID second")
            value = _strict_control_json(frame, {"pid"})
            pid = value["pid"]
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                raise PtyProviderError("PTY child PID is invalid")
            contains = getattr(self._scope, "contains_process_id", None)
            if not callable(contains):
                raise PtyProviderError(
                    "owned process scope cannot prove PTY child membership"
                )
            try:
                member = bool(contains(pid))
            except OwnedProcessScopeError as exc:
                raise PtyProviderError(
                    "PTY child Job/cgroup membership query failed"
                ) from exc
            if not member:
                raise PtyProviderError(
                    "PTY child did not inherit the provider-owned process scope"
                )
            self._child_pid = pid
            self._child_membership_proven = True

    def terminate_scope(self) -> None:
        if self._closed:
            return
        primary_error: BaseException | None = None
        try:
            if self._scope.attached and not self._scope.terminated:
                self._scope.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                primary_error = PtyProviderError(
                    "PTY host did not exit after process-scope termination"
                )
                primary_error.__cause__ = exc
            for stream in (
                self._process.stdin,
                self._process.stdout,
                self._process.stderr,
            ):
                if stream is not None:
                    with contextlib.suppress(OSError, ValueError):
                        stream.close()
            self._reader_thread.join(timeout=2)
            self._stderr_thread.join(timeout=2)
            if self._reader_thread.is_alive() or self._stderr_thread.is_alive():
                primary_error = primary_error or PtyProviderError(
                    "PTY host stream readers did not close"
                )
            try:
                self._scope.close()
            except OwnedProcessScopeError as exc:
                primary_error = primary_error or exc
                with contextlib.suppress(OwnedProcessScopeError):
                    self._scope.emergency_close()
            self._population_zero_proven = self._scope.population_zero_proven
            self._closed = self._scope.closed
            if self._stderr_overflow:
                primary_error = primary_error or PtyProviderError(
                    "PTY host stderr byte ceiling exceeded"
                )
        except BaseException as exc:
            primary_error = primary_error or exc
            with contextlib.suppress(BaseException):
                self._scope.emergency_close()
            self._closed = self._scope.closed
        if primary_error is not None:
            if isinstance(primary_error, PtyProviderError):
                raise primary_error
            raise PtyProviderError(
                f"PTY process-scope cleanup failed: {type(primary_error).__name__}"
            ) from primary_error

    @property
    def child_pid(self) -> int | None:
        return self._child_pid

    @property
    def child_membership_proven(self) -> bool:
        return self._child_membership_proven

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def population_zero_proven(self) -> bool:
        return self._population_zero_proven

    @property
    def can_authorize_completion(self) -> bool:
        return False

    @property
    def stderr_tail(self) -> bytes:
        return bytes(self._stderr)


__all__ = [
    "DEFAULT_HOST_STDERR_LIMIT",
    "DEFAULT_PTY_BYTE_LIMIT",
    "PtyHostHandle",
    "PtyProviderError",
]
