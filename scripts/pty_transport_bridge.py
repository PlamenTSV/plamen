"""Semantically blind PTY bridge used as a WorkerTransaction child.

The bridge is deliberately not a lifecycle authority.  Its parent must create
it inside an already-owned Job/cgroup, observe a provisional signal from exact
transcript/output bytes, terminate the full outer scope, and replay those bytes.
This process only starts the trusted PTY host, submits one bootstrap prompt and
forwards exact terminal bytes to stdout.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any, BinaryIO


_SOURCE_ROOT = str(Path(__file__).resolve(strict=True).parent)
if _SOURCE_ROOT not in sys.path:
    sys.path.insert(0, _SOURCE_ROOT)

from pty_worker_protocol import FrameType, PtyProtocolError, read_frame, write_frame
from pty_worker_protocol import strict_json_loads


BRIDGE_MANIFEST_SCHEMA = "plamen.pty_transport_bridge_manifest.v1"
MAX_BOOTSTRAP_PROMPT_BYTES = 8 * 1024 * 1024
MAX_HOST_STDERR_BYTES = 256 * 1024
_FIELDS = {
    "schema",
    "host_manifest_path",
    "bootstrap_prompt_path",
    "submit_bytes_hex",
}


class PtyBridgeError(RuntimeError):
    """The bridge manifest or host transport was invalid."""


@dataclass(frozen=True)
class BridgeManifest:
    host_manifest_path: Path
    bootstrap_prompt_path: Path
    submit_bytes: bytes


def _real_file(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PtyBridgeError(f"{label} is invalid")
    raw = Path(value)
    if not raw.is_absolute() or raw.is_symlink():
        raise PtyBridgeError(f"{label} must be an absolute regular file")
    try:
        path = raw.resolve(strict=True)
    except OSError as exc:
        raise PtyBridgeError(f"{label} is unavailable") from exc
    if not path.is_file():
        raise PtyBridgeError(f"{label} must be a regular file")
    return path


def parse_bridge_manifest_bytes(raw: bytes) -> BridgeManifest:
    try:
        value = strict_json_loads(raw)
    except PtyProtocolError as exc:
        raise PtyBridgeError("bridge manifest is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise PtyBridgeError("bridge manifest fields are invalid")
    if value["schema"] != BRIDGE_MANIFEST_SCHEMA:
        raise PtyBridgeError("bridge manifest schema is unsupported")
    submit_hex = value["submit_bytes_hex"]
    if (
        not isinstance(submit_hex, str)
        or len(submit_hex) > 16
        or len(submit_hex) % 2
    ):
        raise PtyBridgeError("bridge submit bytes are invalid")
    try:
        submit = bytes.fromhex(submit_hex)
    except ValueError as exc:
        raise PtyBridgeError("bridge submit bytes are invalid") from exc
    if not submit:
        raise PtyBridgeError("bridge submit bytes cannot be empty")
    return BridgeManifest(
        host_manifest_path=_real_file(
            value["host_manifest_path"], "host manifest"
        ),
        bootstrap_prompt_path=_real_file(
            value["bootstrap_prompt_path"], "bootstrap prompt"
        ),
        submit_bytes=submit,
    )


def load_bridge_manifest(path: str | Path) -> BridgeManifest:
    manifest = _real_file(str(path), "bridge manifest")
    try:
        raw = manifest.read_bytes()
    except OSError as exc:
        raise PtyBridgeError("bridge manifest could not be read") from exc
    if len(raw) > 1024 * 1024:
        raise PtyBridgeError("bridge manifest exceeds its byte ceiling")
    return parse_bridge_manifest_bytes(raw)


def _host_error_code(payload: bytes) -> str:
    try:
        value = strict_json_loads(payload)
    except PtyProtocolError:
        return "MALFORMED_HOST_ERROR"
    if not isinstance(value, dict) or set(value) != {"code"}:
        return "MALFORMED_HOST_ERROR"
    code = value["code"]
    return code if isinstance(code, str) and code else "MALFORMED_HOST_ERROR"


def _strict_control_payload(
    payload: bytes,
    *,
    expected_fields: set[str],
    label: str,
) -> dict[str, Any]:
    try:
        value = strict_json_loads(payload)
    except PtyProtocolError as exc:
        raise PtyBridgeError(f"PTY host {label} frame is malformed") from exc
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise PtyBridgeError(f"PTY host {label} frame fields are malformed")
    return value


def run_bridge(
    manifest: BridgeManifest,
    *,
    output: BinaryIO,
    diagnostics: BinaryIO,
) -> int:
    try:
        prompt = manifest.bootstrap_prompt_path.read_bytes()
    except OSError as exc:
        raise PtyBridgeError("bootstrap prompt could not be read") from exc
    if len(prompt) > MAX_BOOTSTRAP_PROMPT_BYTES:
        raise PtyBridgeError("bootstrap prompt exceeds its byte ceiling")
    if not prompt:
        raise PtyBridgeError("bootstrap prompt cannot be empty")
    host_path = Path(__file__).with_name("pty_worker_host.py").resolve(strict=True)
    process = subprocess.Popen(
        [
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            "-S",
            "-B",
            str(host_path),
            str(manifest.host_manifest_path),
        ],
        cwd=str(host_path.parent),
        env=dict(os.environ),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=(os.name != "nt"),
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise PtyBridgeError("PTY host streams are unavailable")
    stderr_tail = bytearray()
    stderr_state = {"overflow": False, "error": False}

    def drain_stderr() -> None:
        try:
            while True:
                raw = process.stderr.read(65536)
                if not raw:
                    return
                remaining = MAX_HOST_STDERR_BYTES - len(stderr_tail)
                if remaining > 0:
                    stderr_tail.extend(raw[:remaining])
                if len(raw) > remaining:
                    stderr_state["overflow"] = True
        except BaseException:
            stderr_state["error"] = True

    stderr_thread = threading.Thread(
        target=drain_stderr,
        name="plamen-pty-bridge-stderr",
        daemon=True,
    )
    stderr_thread.start()
    ready = False
    child_seen = False
    try:
        while True:
            frame = read_frame(process.stdout)
            if frame.kind is FrameType.READY:
                if ready or child_seen:
                    raise PtyBridgeError("PTY host readiness order is invalid")
                ready_payload = _strict_control_payload(
                    frame.payload,
                    expected_fields={"protocol"},
                    label="readiness",
                )
                if ready_payload["protocol"] != "PLP1":
                    raise PtyBridgeError(
                        "PTY host readiness protocol is unsupported"
                    )
                ready = True
                continue
            if frame.kind is FrameType.CHILD_PID:
                if not ready or child_seen:
                    raise PtyBridgeError("PTY host child order is invalid")
                child_payload = _strict_control_payload(
                    frame.payload,
                    expected_fields={"pid"},
                    label="child identity",
                )
                child_pid = child_payload["pid"]
                if (
                    isinstance(child_pid, bool)
                    or not isinstance(child_pid, int)
                    or child_pid <= 0
                ):
                    raise PtyBridgeError(
                        "PTY host child identity is invalid"
                    )
                child_seen = True
                write_frame(process.stdin, FrameType.WRITE, prompt)
                write_frame(process.stdin, FrameType.WRITE, manifest.submit_bytes)
                continue
            if frame.kind is FrameType.PTY_BYTES:
                if not child_seen:
                    raise PtyBridgeError("PTY bytes arrived before child identity")
                output.write(frame.payload)
                output.flush()
                continue
            if frame.kind is FrameType.CHILD_EXIT:
                try:
                    value = strict_json_loads(frame.payload)
                    if not isinstance(value, dict) or set(value) != {
                        "returncode"
                    }:
                        raise PtyBridgeError(
                            "PTY child exit frame fields are malformed"
                        )
                    returncode = value["returncode"]
                except (PtyProtocolError, KeyError, TypeError):
                    raise PtyBridgeError("PTY child exit frame is malformed")
                if isinstance(returncode, bool) or not isinstance(returncode, int):
                    raise PtyBridgeError("PTY child return code is malformed")
                process.wait(timeout=5)
                return int(returncode)
            if frame.kind is FrameType.HOST_ERROR:
                code = _host_error_code(frame.payload)
                diagnostics.write(f"PTY_HOST_ERROR:{code}\n".encode("ascii", "replace"))
                diagnostics.flush()
                process.wait(timeout=5)
                return 70
            raise PtyBridgeError("PTY host emitted a driver-only frame")
    finally:
        if process.poll() is None:
            with contextlib.suppress(Exception):
                process.kill()
            with contextlib.suppress(Exception):
                process.wait(timeout=5)
        stderr_thread.join(timeout=1)
        if stderr_thread.is_alive() or stderr_state["error"]:
            raise PtyBridgeError("PTY host stderr drain did not close")
        if stderr_state["overflow"]:
            raise PtyBridgeError("PTY host stderr exceeded its byte ceiling")
        if stderr_tail:
            diagnostics.write(b"PTY_HOST_STDERR_PRESENT\n")
            diagnostics.flush()


def implementation_files() -> tuple[Path, ...]:
    """Return the exact stdlib-independent bridge/host source closure."""

    values = {
        Path(__file__).resolve(strict=True),
        Path(__file__).with_name("pty_worker_host.py").resolve(strict=True),
        Path(__file__).with_name("pty_worker_protocol.py").resolve(strict=True),
    }
    return tuple(sorted(values, key=lambda item: str(item).casefold()))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        return 64
    try:
        manifest = load_bridge_manifest(args[0])
        return run_bridge(
            manifest,
            output=sys.stdout.buffer,
            diagnostics=sys.stderr.buffer,
        )
    except BaseException as exc:
        # Error class only; never persist prompt, environment, credentials or
        # provider exception text.
        sys.stderr.buffer.write(
            f"PTY_BRIDGE_ERROR:{type(exc).__name__}\n".encode("ascii", "replace")
        )
        sys.stderr.buffer.flush()
        return 70


if __name__ == "__main__":
    # See the host: native PTY reader threads must not participate in Python's
    # interpreter shutdown after their outer Job/cgroup is being torn down.
    _code = main()
    try:
        sys.stdout.buffer.flush()
        sys.stderr.buffer.flush()
    finally:
        os._exit(_code)


__all__ = [
    "BRIDGE_MANIFEST_SCHEMA",
    "MAX_HOST_STDERR_BYTES",
    "MAX_BOOTSTRAP_PROMPT_BYTES",
    "BridgeManifest",
    "PtyBridgeError",
    "load_bridge_manifest",
    "implementation_files",
    "main",
    "parse_bridge_manifest_bytes",
    "run_bridge",
]
