"""A phase child that stops emitting bytes is a stall, not a slow turn.

DODO run45 `inventory_chunk_c` attempt 1: the Claude CLI did 711 KB of normal
work, entered its internal `api_retry` loop, the retried request hung on an
open HTTPS connection, and no stdout byte arrived for 2.5 hours (11.75 s CPU in
150 min, empty output directory) while the multi-hour phase deadline had not
fired. The runtime now bounds silence with `PLAMEN_STREAM_INACTIVITY_S`
(default 900 s) and surfaces a stall as the ordinary TIMEOUT failure.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import posix_v2_compat_runtime as R  # noqa: E402


def _reader_over_pipe():
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "rb", buffering=0)
    reader = R._BoundedReader(stream, 1024 * 1024, "test-stdout")
    return reader, write_fd


def test_reader_tracks_last_activity_per_chunk() -> None:
    reader, write_fd = _reader_over_pipe()
    try:
        before = reader.last_activity
        time.sleep(0.05)
        os.write(write_fd, b'{"type":"system","subtype":"thinking_tokens"}\n')
        deadline = time.monotonic() + 2.0
        while reader.last_activity == before and time.monotonic() < deadline:
            time.sleep(0.01)
        assert reader.last_activity > before, "a received chunk must refresh activity"
    finally:
        os.close(write_fd)
        reader.result()


def test_stall_predicate_fires_only_after_silence() -> None:
    reader, write_fd = _reader_over_pipe()
    try:
        now = reader.last_activity
        assert not R._stream_stalled(now + 899.0, reader, budget_s=900.0)
        assert R._stream_stalled(now + 900.0, reader, budget_s=900.0)
        assert not R._stream_stalled(now + 1e9, reader, budget_s=0), "0 disables the watchdog"
    finally:
        os.close(write_fd)
        reader.result()


def test_any_active_reader_resets_the_stall() -> None:
    """stderr chatter alone proves the child is alive."""
    out, out_fd = _reader_over_pipe()
    err, err_fd = _reader_over_pipe()
    try:
        base = min(out.last_activity, err.last_activity)
        os.write(err_fd, b"progress\n")
        deadline = time.monotonic() + 2.0
        while err.last_activity <= base and time.monotonic() < deadline:
            time.sleep(0.01)
        probe = out.last_activity + 900.0
        assert R._stream_stalled(probe, out, budget_s=900.0)
        assert not R._stream_stalled(probe, out, err, budget_s=900.0) or (
            err.last_activity + 900.0 <= probe
        )
    finally:
        os.close(out_fd)
        os.close(err_fd)
        out.result()
        err.result()


def test_default_budget_is_fifteen_minutes_and_phase_loop_consults_it() -> None:
    assert R._STREAM_INACTIVITY_S == 900.0 or os.environ.get("PLAMEN_STREAM_INACTIVITY_S")
    source = (_SCRIPTS / "posix_v2_compat_runtime.py").read_text("utf-8")
    loop = source[source.index('_BoundedReader(child.stdout, _MAX_STDOUT_BYTES, "stdout")'):]
    loop = loop[:loop.index("_terminate_group(child)")]
    assert "_stream_stalled(now, stdout_reader, stderr_reader)" in loop
    assert "timed_out = True" in loop.split("_stream_stalled")[1], (
        "a stall must surface as the ordinary TIMEOUT so downstream semantics are unchanged"
    )
