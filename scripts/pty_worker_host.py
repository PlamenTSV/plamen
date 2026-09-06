"""Trusted PTY transport host launched inside an owned OS process scope.

This helper is intentionally semantically blind.  It transports exact PTY
bytes and child lifecycle facts; it never decides whether an LLM turn or an
assigned output is complete.  The parent provider must treat any observation
as provisional until the complete Job/cgroup is empty and closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import queue
import signal
import struct
import subprocess
import sys
import sysconfig
import threading
import time
from typing import Any, BinaryIO, Mapping

# Isolated mode intentionally removes the script directory and site-packages
# from ``sys.path``.  Re-add only the directory containing this hash-bound host
# so its reviewed protocol sibling can be imported; provider packages are
# admitted separately at their exact interpreter installation roots below.
_HOST_SOURCE_ROOT = str(Path(__file__).resolve(strict=True).parent)
if _HOST_SOURCE_ROOT not in sys.path:
    sys.path.insert(0, _HOST_SOURCE_ROOT)

from pty_worker_protocol import (
    FrameType,
    PtyProtocolError,
    read_frame,
    strict_json_loads,
    write_frame,
)


HOST_MANIFEST_SCHEMA = "plamen.pty_worker_host_manifest.v1"
_MANIFEST_FIELDS = {
    "schema",
    "argv",
    "cwd",
    "environment",
    "rows",
    "columns",
}


class PtyHostError(RuntimeError):
    """The trusted PTY host configuration or transport was invalid."""


@dataclass(frozen=True)
class HostManifest:
    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    rows: int
    columns: int


def _dimension(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PtyHostError(f"{label} must be an integer")
    if value < 1 or value > 1000:
        raise PtyHostError(f"{label} is outside the supported range")
    return value


def parse_host_manifest_bytes(raw: bytes) -> HostManifest:
    try:
        value = strict_json_loads(raw)
    except PtyProtocolError as exc:
        raise PtyHostError("host manifest is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
        raise PtyHostError("host manifest fields are invalid")
    if value["schema"] != HOST_MANIFEST_SCHEMA:
        raise PtyHostError("host manifest schema is unsupported")
    argv = value["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) or not item or "\x00" in item for item in argv)
    ):
        raise PtyHostError("host argv is invalid")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise PtyHostError("host argv executable must be absolute")
    try:
        resolved_executable = executable.resolve(strict=True)
    except OSError as exc:
        raise PtyHostError("host argv executable is unavailable") from exc
    if not resolved_executable.is_file():
        raise PtyHostError("host argv executable must be a regular file")
    argv = [str(resolved_executable), *argv[1:]]
    cwd_raw = value["cwd"]
    if not isinstance(cwd_raw, str) or not cwd_raw or "\x00" in cwd_raw:
        raise PtyHostError("host cwd is invalid")
    cwd = Path(cwd_raw)
    if not cwd.is_absolute():
        raise PtyHostError("host cwd must be absolute")
    try:
        cwd = cwd.resolve(strict=True)
    except OSError as exc:
        raise PtyHostError("host cwd is unavailable") from exc
    if not cwd.is_dir():
        raise PtyHostError("host cwd must be a directory")
    environment = value["environment"]
    if not isinstance(environment, dict):
        raise PtyHostError("host environment is invalid")
    clean_env: dict[str, str] = {}
    folded_environment_names: set[str] = set()
    for key, item in environment.items():
        if (
            not isinstance(key, str)
            or not key
            or "=" in key
            or "\x00" in key
            or not isinstance(item, str)
            or "\x00" in item
        ):
            raise PtyHostError("host environment entry is invalid")
        folded = key.casefold()
        if folded in folded_environment_names:
            raise PtyHostError("host environment names collide by case")
        folded_environment_names.add(folded)
        clean_env[key] = item
    return HostManifest(
        argv=tuple(argv),
        cwd=cwd,
        environment={key: clean_env[key] for key in sorted(clean_env)},
        rows=_dimension(value["rows"], "rows"),
        columns=_dimension(value["columns"], "columns"),
    )


def load_host_manifest(path: str | Path) -> HostManifest:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise PtyHostError("host manifest path must be absolute")
    if candidate.is_symlink():
        raise PtyHostError("host manifest cannot be a symlink")
    try:
        raw = candidate.read_bytes()
    except OSError as exc:
        raise PtyHostError("host manifest could not be read") from exc
    if len(raw) > 4 * 1024 * 1024:
        raise PtyHostError("host manifest exceeds its byte ceiling")
    return parse_host_manifest_bytes(raw)


class _FramedEmitter:
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def send(self, kind: FrameType, payload: bytes = b"") -> None:
        with self._lock:
            write_frame(self._stream, kind, payload)

    def json(self, kind: FrameType, value: Mapping[str, Any]) -> None:
        self.send(
            kind,
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )


class _WindowsPty:
    def __init__(self, manifest: HostManifest) -> None:
        # ``-S`` suppresses automatic site initialization.  pywinpty is a
        # platform provider, so admit only this interpreter's canonical
        # purelib/platlib roots.  The parent transaction must hash-bind the
        # resolved provider modules before it launches this host.
        for label in ("purelib", "platlib"):
            module_root = sysconfig.get_paths().get(label)
            if module_root and module_root not in sys.path:
                sys.path.append(module_root)
        import winpty  # type: ignore

        self._pty = winpty.PtyProcess.spawn(
            list(manifest.argv),
            cwd=str(manifest.cwd),
            env=dict(manifest.environment),
            dimensions=(manifest.rows, manifest.columns),
            backend=winpty.Backend.ConPTY,
        )
        self.pid = int(self._pty.pid)

    def read(self) -> bytes:
        value = self._pty.read(65536)
        if isinstance(value, str):
            # ConPTY exposes Unicode text through pywinpty.  Canonical UTF-8 is
            # the honest transport representation; malformed surrogate state
            # is terminal debt rather than silent byte replacement.
            return value.encode("utf-8", errors="strict")
        return bytes(value)

    def write(self, raw: bytes) -> None:
        self._pty.write(raw.decode("utf-8", errors="strict"))

    def resize(self, columns: int, rows: int) -> None:
        self._pty.setwinsize(rows, columns)

    def interrupt(self) -> None:
        self._pty.sendintr()

    def close_input(self) -> None:
        self._pty.sendeof()

    def alive(self) -> bool:
        return bool(self._pty.isalive())

    def returncode(self) -> int:
        value = self._pty.exitstatus
        return int(value if value is not None else 1)


class _PosixPty:
    def __init__(self, manifest: HostManifest) -> None:
        import fcntl
        import pty
        import termios

        master_fd, slave_fd = pty.openpty()
        fcntl.ioctl(
            slave_fd,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", manifest.rows, manifest.columns, 0, 0),
        )
        try:
            self._process = subprocess.Popen(
                list(manifest.argv),
                cwd=str(manifest.cwd),
                env=dict(manifest.environment),
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                restore_signals=True,
            )
        finally:
            os.close(slave_fd)
        self._master_fd = master_fd
        self.pid = self._process.pid

    def read(self) -> bytes:
        return os.read(self._master_fd, 65536)

    def write(self, raw: bytes) -> None:
        os.write(self._master_fd, raw)

    def resize(self, columns: int, rows: int) -> None:
        import fcntl
        import termios

        fcntl.ioctl(
            self._master_fd,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, columns, 0, 0),
        )

    def interrupt(self) -> None:
        self.write(b"\x03")

    def close_input(self) -> None:
        self.write(b"\x04")

    def alive(self) -> bool:
        return self._process.poll() is None

    def returncode(self) -> int:
        value = self._process.poll()
        return int(value if value is not None else 1)


def _run_host(manifest: HostManifest, reader: BinaryIO, writer: BinaryIO) -> int:
    emitter = _FramedEmitter(writer)
    transport = _WindowsPty(manifest) if os.name == "nt" else _PosixPty(manifest)
    emitter.json(FrameType.READY, {"protocol": "PLP1"})
    emitter.json(FrameType.CHILD_PID, {"pid": transport.pid})
    reader_error: list[BaseException] = []

    def drain() -> None:
        try:
            while True:
                raw = transport.read()
                if raw:
                    emitter.send(FrameType.PTY_BYTES, raw)
                    continue
                if not transport.alive():
                    return
        except (EOFError, OSError):
            return
        except BaseException as exc:  # pragma: no cover - defensive host boundary
            reader_error.append(exc)

    drain_thread = threading.Thread(target=drain, name="plamen-pty-drain", daemon=True)
    drain_thread.start()
    command_queue: queue.Queue[object] = queue.Queue()

    def receive_commands() -> None:
        try:
            while True:
                command_queue.put(read_frame(reader))
        except BaseException as exc:
            command_queue.put(exc)

    command_thread = threading.Thread(
        target=receive_commands,
        name="plamen-pty-command-reader",
        daemon=True,
    )
    command_thread.start()
    protocol_error: BaseException | None = None
    try:
        while transport.alive():
            try:
                item = command_queue.get(timeout=0.025)
            except queue.Empty:
                continue
            if isinstance(item, BaseException):
                raise item
            if not hasattr(item, "kind") or not hasattr(item, "payload"):
                raise PtyProtocolError("host command queue item is invalid")
            frame = item
            if frame.kind is FrameType.WRITE:
                transport.write(frame.payload)
            elif frame.kind is FrameType.RESIZE:
                try:
                    size = strict_json_loads(frame.payload)
                except PtyProtocolError as exc:
                    raise PtyProtocolError("resize payload is invalid") from exc
                if not isinstance(size, dict) or set(size) != {"columns", "rows"}:
                    raise PtyProtocolError("resize payload fields are invalid")
                transport.resize(
                    _dimension(size["columns"], "columns"),
                    _dimension(size["rows"], "rows"),
                )
            elif frame.kind is FrameType.CLOSE_INPUT:
                if frame.payload:
                    raise PtyProtocolError("close-input payload must be empty")
                transport.close_input()
            elif frame.kind is FrameType.INTERRUPT:
                if frame.payload:
                    raise PtyProtocolError("interrupt payload must be empty")
                transport.interrupt()
            else:
                raise PtyProtocolError("driver sent a host-only frame type")
    except BaseException as exc:
        protocol_error = exc
    finally:
        drain_thread.join(timeout=1.0)
        if drain_thread.is_alive() and protocol_error is None:
            protocol_error = PtyHostError(
                "PTY drain did not reach a verified terminal state"
            )

    if protocol_error is not None:
        emitter.json(
            FrameType.HOST_ERROR,
            {"code": type(protocol_error).__name__},
        )
        return 2
    if reader_error:
        emitter.json(FrameType.HOST_ERROR, {"code": "PTY_DRAIN_FAILED"})
        return 3
    emitter.json(FrameType.CHILD_EXIT, {"returncode": transport.returncode()})
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        return 64
    try:
        manifest = load_host_manifest(args[0])
        return _run_host(manifest, sys.stdin.buffer, sys.stdout.buffer)
    except BaseException:
        # Never print manifest/environment values or exception text: both can
        # contain secret-bearing paths or provider state.  The parent records
        # lifecycle debt from the non-zero host exit.
        return 70


if __name__ == "__main__":
    # The command reader is intentionally allowed to remain blocked while a
    # child exits naturally.  Avoid interpreter-finalization races in native
    # PTY modules and buffered stdin by leaving through the process primitive
    # after every emitted frame has been synchronously flushed.
    _exit_code = main()
    try:
        sys.stdout.buffer.flush()
    finally:
        os._exit(_exit_code)


__all__ = [
    "HOST_MANIFEST_SCHEMA",
    "HostManifest",
    "PtyHostError",
    "load_host_manifest",
    "main",
    "parse_host_manifest_bytes",
]
