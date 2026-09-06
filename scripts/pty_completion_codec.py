"""Provider-side PTY completion observation with post-closure replay.

This module deliberately separates a provisional liveness signal from completion
authority.  The caller arms an invocation baseline before launch, feeds exact PTY
transport bytes, and polls only the transcript suffix created by that invocation.
After terminating and closing the complete owned process scope, the caller performs
one bounded final read and replay.  No model-authored marker is proof by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Any, Callable, Mapping, Sequence

from pty_exec import (
    event_is_overloaded,
    event_is_rate_limited,
    text_shows_overloaded,
    text_shows_rate_limit,
)
from pty_worker_protocol import PtyProtocolError, strict_json_loads


TURN_END = "TURN_END"
OUTPUT_READY = "OUTPUT_READY"
_SIGNALS = {TURN_END, OUTPUT_READY}
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_DEFAULT_TRANSCRIPT_LIMIT = 64 * 1024 * 1024
_DEFAULT_OUTPUT_LIMIT = 64 * 1024 * 1024
_MAX_JSONL_LINE = 4 * 1024 * 1024


class PtyCompletionError(RuntimeError):
    """PTY evidence is terminal debt or disagrees with its final replay."""


OutputValidator = Callable[[Path, bytes], str]


@dataclass(frozen=True)
class OutputSnapshot:
    path: Path
    size: int
    sha256: str
    parsed_sha256: str | None = None


@dataclass(frozen=True)
class ProvisionalPtyObservation:
    signal: str
    observed_at_monotonic_ns: int
    transcript_size: int
    transcript_prefix_sha256: str
    transcript_line_count: int
    output_snapshot: tuple[OutputSnapshot, ...]
    pty_byte_position: int


@dataclass(frozen=True)
class FinalPtyReplay:
    signal: str
    transcript_size: int
    transcript_sha256: str
    transcript_line_count: int
    output_snapshot: tuple[OutputSnapshot, ...]
    pty_byte_position: int


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return bool(
        getattr(info, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _absolute_path(value: str | Path, *, label: str) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise PtyCompletionError(f"{label} path is malformed")
    return Path(os.path.abspath(raw))


def _file_identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _read_regular_bounded(
    path: Path,
    *,
    limit: int,
    allow_missing: bool,
    label: str,
) -> tuple[bytes, tuple[int, int] | None]:
    """Read one exact unaliased regular-file snapshot under a byte ceiling."""

    if not os.path.lexists(path):
        if allow_missing:
            return b"", None
        raise PtyCompletionError(f"{label} is missing")
    if path.is_symlink() or _is_reparse(path):
        raise PtyCompletionError(f"{label} is a symlink/reparse point")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PtyCompletionError(f"{label} could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1)) != 1
        ):
            raise PtyCompletionError(f"{label} is not an unaliased regular file")
        if int(before.st_size) > limit:
            raise PtyCompletionError(f"{label} exceeds its byte ceiling")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise PtyCompletionError(f"{label} exceeds its byte ceiling")
        after = os.fstat(descriptor)
        if (
            _file_identity(before) != _file_identity(after)
            or int(before.st_size) != int(after.st_size)
            or int(after.st_size) != total
        ):
            raise PtyCompletionError(f"{label} changed during its bounded read")
        return b"".join(chunks), _file_identity(after)
    except OSError as exc:
        raise PtyCompletionError(f"{label} could not be read") from exc
    finally:
        os.close(descriptor)


def _read_regular_suffix_bounded(
    path: Path,
    *,
    offset: int,
    limit: int,
    expected_identity: tuple[int, int] | None,
) -> tuple[bytes, int, tuple[int, int] | None]:
    """Read only bytes appended after ``offset`` from the bound transcript."""

    if not os.path.lexists(path):
        if offset == 0 and expected_identity is None:
            return b"", 0, None
        raise PtyCompletionError("transcript disappeared after invocation arm")
    if path.is_symlink() or _is_reparse(path):
        raise PtyCompletionError("transcript is a symlink/reparse point")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PtyCompletionError("transcript could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        identity = _file_identity(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1)) != 1
        ):
            raise PtyCompletionError(
                "transcript is not an unaliased regular file"
            )
        if expected_identity is not None and identity != expected_identity:
            raise PtyCompletionError("transcript file identity changed")
        target_size = int(before.st_size)
        if target_size < offset:
            raise PtyCompletionError("transcript truncated after invocation arm")
        if target_size > limit:
            raise PtyCompletionError("transcript exceeds its byte ceiling")
        remaining = target_size - offset
        os.lseek(descriptor, offset, os.SEEK_SET)
        chunks: list[bytes] = []
        captured = 0
        while captured < remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining - captured))
            if not chunk:
                raise PtyCompletionError(
                    "transcript changed during incremental read"
                )
            chunks.append(chunk)
            captured += len(chunk)
        after = os.fstat(descriptor)
        if (
            _file_identity(after) != identity
            or int(after.st_size) < target_size
        ):
            raise PtyCompletionError(
                "transcript changed during incremental read"
            )
        return b"".join(chunks), target_size, identity
    except OSError as exc:
        raise PtyCompletionError("transcript could not be read") from exc
    finally:
        os.close(descriptor)


def _require_digest(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PtyCompletionError(f"{label} did not return a SHA-256 digest")
    return value


def _event_state(raw: bytes) -> Mapping[str, Any]:
    """Parse complete JSONL events from one exact byte snapshot."""

    rate_limited = False
    overloaded = False
    turn_end = False
    line_count = 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        if len(line) > _MAX_JSONL_LINE:
            raise PtyCompletionError("transcript JSONL line exceeds its byte ceiling")
        try:
            event = strict_json_loads(line)
        except PtyProtocolError as exc:
            raise PtyCompletionError(
                "transcript contains malformed JSONL"
            ) from exc
        if not isinstance(event, dict):
            raise PtyCompletionError(
                "transcript event is not a JSON object"
            )
        line_count += 1
        overloaded_event = event_is_overloaded(event)
        if overloaded_event:
            overloaded = True
        elif event_is_rate_limited(event):
            rate_limited = True
        message = event.get("message")
        if (
            event.get("type") == "assistant"
            and isinstance(message, dict)
            and str(message.get("stop_reason") or "").lower() == "end_turn"
        ):
            turn_end = True
    return {
        "rate_limited": rate_limited,
        "overloaded": overloaded,
        "turn_end": turn_end,
        "line_count": line_count,
    }


def _output_paths(
    paths: Sequence[str | Path],
) -> tuple[Path, ...]:
    normalized = tuple(
        _absolute_path(item, label="expected output") for item in paths
    )
    folded = [os.path.normcase(str(path)) for path in normalized]
    if len(set(folded)) != len(folded):
        raise PtyCompletionError("expected output paths collide")
    return normalized


def _snapshot_outputs(
    paths: tuple[Path, ...],
    *,
    limit: int,
    validator: OutputValidator | None,
    require_nonempty_and_parsed: bool,
) -> tuple[OutputSnapshot, ...] | None:
    rows: list[OutputSnapshot] = []
    for path in paths:
        if not os.path.lexists(path):
            return None
        raw, _identity = _read_regular_bounded(
            path,
            limit=limit,
            allow_missing=False,
            label="expected output",
        )
        if require_nonempty_and_parsed and not raw:
            return None
        parsed_sha: str | None = None
        if validator is not None:
            try:
                parsed_sha = _require_digest(
                    validator(path, raw),
                    label="output validator",
                )
            except PtyCompletionError:
                if require_nonempty_and_parsed:
                    return None
                raise
            except BaseException as exc:
                if require_nonempty_and_parsed:
                    return None
                raise PtyCompletionError("output validator rejected bytes") from exc
        elif require_nonempty_and_parsed:
            raise PtyCompletionError(
                "OUTPUT_READY requires a trusted output validator"
            )
        rows.append(OutputSnapshot(path, len(raw), _digest(raw), parsed_sha))
    return tuple(rows)


class ClaudePtyCodec:
    """Bounded incremental observer for one explicitly armed PTY invocation."""

    def __init__(
        self,
        *,
        recent_byte_limit: int = 1024 * 1024,
        output_quiescence_seconds: float = 2.0,
        transcript_limit_bytes: int = _DEFAULT_TRANSCRIPT_LIMIT,
        output_limit_bytes: int = _DEFAULT_OUTPUT_LIMIT,
        output_validator: OutputValidator | None = None,
    ) -> None:
        for value, label in (
            (recent_byte_limit, "recent PTY byte ceiling"),
            (transcript_limit_bytes, "transcript byte ceiling"),
            (output_limit_bytes, "output byte ceiling"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise PtyCompletionError(f"{label} must be positive")
        if (
            isinstance(output_quiescence_seconds, bool)
            or not isinstance(output_quiescence_seconds, (int, float))
            or output_quiescence_seconds < 0
        ):
            raise PtyCompletionError("output quiescence must be non-negative")
        if output_validator is not None and not callable(output_validator):
            raise PtyCompletionError("output_validator must be callable")
        self._recent_byte_limit = recent_byte_limit
        self._output_quiescence_seconds = float(output_quiescence_seconds)
        self._transcript_limit = transcript_limit_bytes
        self._output_limit = output_limit_bytes
        self._output_validator = output_validator
        self._recent = bytearray()
        self._pty_scan_tail = b""
        self._total_bytes = 0
        self._rate_limited = False
        self._overloaded = False
        self._armed = False
        self._transcript_path: Path | None = None
        self._output_paths: tuple[Path, ...] = ()
        self._baseline_outputs: tuple[OutputSnapshot, ...] | None = None
        self._transcript_identity: tuple[int, int] | None = None
        self._baseline_size = 0
        self._cursor = 0
        self._transcript_hasher = hashlib.sha256()
        self._line_tail = b""
        self._line_count = 0
        self._turn_end = False
        self._last_output_key: tuple[tuple[str, int, str, str | None], ...] | None = None
        self._output_stable_since: float | None = None

    def arm(
        self,
        *,
        transcript_path: str | Path,
        expected_outputs: Sequence[str | Path] = (),
    ) -> None:
        """Bind the prelaunch transcript/output baseline exactly once."""

        if self._armed:
            raise PtyCompletionError("PTY completion codec is already armed")
        transcript = _absolute_path(transcript_path, label="transcript")
        outputs = _output_paths(expected_outputs)
        raw, identity = _read_regular_bounded(
            transcript,
            limit=self._transcript_limit,
            allow_missing=True,
            label="transcript",
        )
        if raw and not raw.endswith((b"\n", b"\r")):
            raise PtyCompletionError(
                "prelaunch transcript baseline ends with a partial JSONL line"
            )
        self._transcript_path = transcript
        self._output_paths = outputs
        self._transcript_identity = identity
        self._baseline_size = len(raw)
        self._cursor = len(raw)
        self._transcript_hasher.update(raw)
        self._line_count = len(raw.splitlines())
        self._baseline_outputs = _snapshot_outputs(
            outputs,
            limit=self._output_limit,
            validator=self._output_validator,
            require_nonempty_and_parsed=False,
        )
        self._armed = True

    def feed(self, raw: bytes) -> None:
        if not isinstance(raw, bytes):
            raise PtyCompletionError("PTY transport payload must be bytes")
        self._total_bytes += len(raw)
        scan = (self._pty_scan_tail + raw).decode("utf-8", errors="replace")
        if text_shows_overloaded(scan):
            self._overloaded = True
        elif text_shows_rate_limit(scan):
            self._rate_limited = True
        self._pty_scan_tail = (self._pty_scan_tail + raw)[-4096:]
        self._recent.extend(raw)
        overflow = len(self._recent) - self._recent_byte_limit
        if overflow > 0:
            del self._recent[:overflow]

    def _require_arm(
        self,
        transcript_path: str | Path,
        expected_outputs: Sequence[str | Path],
    ) -> tuple[Path, tuple[Path, ...]]:
        if not self._armed or self._transcript_path is None:
            raise PtyCompletionError(
                "PTY completion codec must be armed before observation"
            )
        transcript = _absolute_path(transcript_path, label="transcript")
        outputs = _output_paths(expected_outputs)
        if (
            os.path.normcase(str(transcript))
            != os.path.normcase(str(self._transcript_path))
            or tuple(os.path.normcase(str(path)) for path in outputs)
            != tuple(os.path.normcase(str(path)) for path in self._output_paths)
        ):
            raise PtyCompletionError(
                "observation paths differ from the prelaunch baseline"
            )
        return transcript, outputs

    def _consume_transcript_suffix(self, transcript: Path) -> None:
        suffix, target_size, identity = _read_regular_suffix_bounded(
            transcript,
            offset=self._cursor,
            limit=self._transcript_limit,
            expected_identity=self._transcript_identity,
        )
        if self._transcript_identity is None and identity is not None:
            self._transcript_identity = identity
        if not suffix:
            return
        self._transcript_hasher.update(suffix)
        self._cursor = target_size
        combined = self._line_tail + suffix
        complete_lines = combined.splitlines(keepends=True)
        self._line_tail = b""
        if complete_lines and not complete_lines[-1].endswith((b"\n", b"\r")):
            self._line_tail = complete_lines.pop()
        if len(self._line_tail) > _MAX_JSONL_LINE:
            raise PtyCompletionError(
                "transcript partial JSONL line exceeds its byte ceiling"
            )
        state = _event_state(b"".join(complete_lines))
        self._line_count += int(state["line_count"])
        self._rate_limited = self._rate_limited or bool(state["rate_limited"])
        self._overloaded = self._overloaded or bool(state["overloaded"])
        self._turn_end = self._turn_end or bool(state["turn_end"])

    def _reject_terminal_transport_state(self) -> None:
        if self._overloaded:
            raise PtyCompletionError("PTY execution reached an overloaded state")
        if self._rate_limited:
            raise PtyCompletionError("PTY execution reached a rate-limit state")

    def observe(
        self,
        *,
        transcript_path: str | Path,
        expected_outputs: Sequence[str | Path] = (),
        allow_output_ready: bool = False,
    ) -> ProvisionalPtyObservation | None:
        if not isinstance(allow_output_ready, bool):
            raise PtyCompletionError("allow_output_ready must be boolean")
        transcript, outputs_paths = self._require_arm(
            transcript_path, expected_outputs
        )
        self._consume_transcript_suffix(transcript)
        self._reject_terminal_transport_state()
        outputs = _snapshot_outputs(
            outputs_paths,
            limit=self._output_limit,
            validator=self._output_validator,
            require_nonempty_and_parsed=allow_output_ready,
        )

        signal: str | None = TURN_END if self._turn_end else None
        if (
            signal is None
            and allow_output_ready
            and outputs_paths
            and outputs is not None
            and outputs != self._baseline_outputs
        ):
            key = tuple(
                (
                    os.path.normcase(str(row.path)),
                    row.size,
                    row.sha256,
                    row.parsed_sha256,
                )
                for row in outputs
            )
            now = time.monotonic()
            if key != self._last_output_key:
                self._last_output_key = key
                self._output_stable_since = now
            elif (
                self._output_stable_since is not None
                and now - self._output_stable_since
                >= self._output_quiescence_seconds
            ):
                signal = OUTPUT_READY
        if signal is None:
            return None
        return ProvisionalPtyObservation(
            signal=signal,
            observed_at_monotonic_ns=time.monotonic_ns(),
            transcript_size=self._cursor,
            transcript_prefix_sha256=self._transcript_hasher.hexdigest(),
            transcript_line_count=self._line_count,
            output_snapshot=outputs or (),
            pty_byte_position=self._total_bytes,
        )

    def final_replay(
        self,
        observation: ProvisionalPtyObservation,
        *,
        transcript_path: str | Path,
        expected_outputs: Sequence[str | Path] = (),
    ) -> FinalPtyReplay:
        if not isinstance(observation, ProvisionalPtyObservation):
            raise PtyCompletionError("provisional PTY observation is invalid")
        if observation.signal not in _SIGNALS:
            raise PtyCompletionError("provisional PTY signal is unsupported")
        transcript, outputs_paths = self._require_arm(
            transcript_path, expected_outputs
        )
        transcript_raw, identity = _read_regular_bounded(
            transcript,
            limit=self._transcript_limit,
            allow_missing=False,
            label="final transcript",
        )
        if (
            self._transcript_identity is not None
            and identity != self._transcript_identity
        ):
            raise PtyCompletionError("final transcript file identity changed")
        if len(transcript_raw) < observation.transcript_size:
            raise PtyCompletionError("final transcript truncated its observed prefix")
        if (
            _digest(transcript_raw[: observation.transcript_size])
            != observation.transcript_prefix_sha256
        ):
            raise PtyCompletionError(
                "final transcript prefix changed after observation"
            )
        invocation_raw = transcript_raw[self._baseline_size :]
        state = _event_state(invocation_raw)
        recent = bytes(self._recent).decode("utf-8", errors="replace")
        if (
            self._overloaded
            or state["overloaded"]
            or text_shows_overloaded(recent)
        ):
            raise PtyCompletionError("PTY execution reached an overloaded state")
        if (
            self._rate_limited
            or state["rate_limited"]
            or text_shows_rate_limit(recent)
        ):
            raise PtyCompletionError("PTY execution reached a rate-limit state")
        if observation.signal == TURN_END and not state["turn_end"]:
            raise PtyCompletionError(
                "final invocation transcript does not prove turn completion"
            )

        outputs = _snapshot_outputs(
            outputs_paths,
            limit=self._output_limit,
            validator=self._output_validator,
            require_nonempty_and_parsed=(
                observation.signal == OUTPUT_READY
            ),
        )
        if observation.signal == OUTPUT_READY:
            if outputs is None:
                raise PtyCompletionError("final assigned output is missing")
            if outputs != observation.output_snapshot:
                raise PtyCompletionError(
                    "assigned output changed after observation"
                )
        return FinalPtyReplay(
            signal=observation.signal,
            transcript_size=len(transcript_raw),
            transcript_sha256=_digest(transcript_raw),
            transcript_line_count=(
                self._baseline_size
                and len(transcript_raw[: self._baseline_size].splitlines())
                or 0
            )
            + int(state["line_count"]),
            output_snapshot=outputs or (),
            pty_byte_position=self._total_bytes,
        )


__all__ = [
    "ClaudePtyCodec",
    "FinalPtyReplay",
    "OUTPUT_READY",
    "OutputSnapshot",
    "OutputValidator",
    "ProvisionalPtyObservation",
    "PtyCompletionError",
    "TURN_END",
]
