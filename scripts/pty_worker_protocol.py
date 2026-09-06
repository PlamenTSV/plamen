"""Bounded binary transport between the trusted PTY host and its provider.

The protocol carries transport facts only.  In particular, it has no frame
whose meaning is "the model turn completed"; that decision belongs to the
parent-side transcript/output observer and remains provisional until the
provider has closed the complete OS process scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import io
import json
import struct
from typing import Any, BinaryIO


PROTOCOL_MAGIC = b"PLP1"
MAX_FRAME_BYTES = 8 * 1024 * 1024
_HEADER = struct.Struct(">4sBI")


class PtyProtocolError(RuntimeError):
    """A PTY host frame was malformed or exceeded its exact bound."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PtyProtocolError("JSON object contains a duplicate key")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise PtyProtocolError(f"JSON constant is unsupported: {value}")


def strict_json_loads(raw: bytes) -> Any:
    """Decode strict UTF-8 JSON while rejecting duplicates and non-finite values."""

    if not isinstance(raw, bytes):
        raise PtyProtocolError("JSON payload must be bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PtyProtocolError("payload is not strict UTF-8 JSON") from exc


class FrameType(IntEnum):
    WRITE = 1
    RESIZE = 2
    PTY_BYTES = 3
    CLOSE_INPUT = 4
    INTERRUPT = 5
    READY = 16
    CHILD_PID = 17
    CHILD_EXIT = 18
    HOST_ERROR = 19


@dataclass(frozen=True)
class Frame:
    kind: FrameType
    payload: bytes


def _read_exact(stream: BinaryIO, size: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise PtyProtocolError(f"truncated {label}")
        if not isinstance(chunk, (bytes, bytearray)):
            raise PtyProtocolError(f"{label} stream is not binary")
        chunks.append(bytes(chunk))
        remaining -= len(chunk)
    return b"".join(chunks)


def encode_frame(
    kind: FrameType,
    payload: bytes,
    *,
    max_frame_bytes: int = MAX_FRAME_BYTES,
) -> bytes:
    if not isinstance(kind, FrameType):
        raise PtyProtocolError("frame type is unknown")
    if not isinstance(payload, bytes):
        raise PtyProtocolError("frame payload must be bytes")
    if len(payload) > max_frame_bytes:
        raise PtyProtocolError("frame exceeds byte ceiling")
    return _HEADER.pack(PROTOCOL_MAGIC, int(kind), len(payload)) + payload


def write_frame(
    stream: BinaryIO,
    kind: FrameType,
    payload: bytes,
    *,
    max_frame_bytes: int = MAX_FRAME_BYTES,
) -> None:
    raw = encode_frame(kind, payload, max_frame_bytes=max_frame_bytes)
    written = stream.write(raw)
    if written is not None and written != len(raw):
        raise PtyProtocolError("truncated frame write")
    stream.flush()


def read_frame(
    stream: BinaryIO,
    *,
    max_frame_bytes: int = MAX_FRAME_BYTES,
) -> Frame:
    if not isinstance(max_frame_bytes, int) or isinstance(max_frame_bytes, bool):
        raise PtyProtocolError("frame byte ceiling is invalid")
    if max_frame_bytes <= 0 or max_frame_bytes > MAX_FRAME_BYTES:
        raise PtyProtocolError("frame byte ceiling is invalid")
    header = _read_exact(stream, _HEADER.size, "frame header")
    magic, raw_kind, size = _HEADER.unpack(header)
    if magic != PROTOCOL_MAGIC:
        raise PtyProtocolError("frame magic is invalid")
    try:
        kind = FrameType(raw_kind)
    except ValueError as exc:
        raise PtyProtocolError("frame type is unknown") from exc
    if size > max_frame_bytes:
        raise PtyProtocolError("frame exceeds byte ceiling")
    return Frame(kind, _read_exact(stream, size, "frame payload"))


def decode_one(raw: bytes) -> Frame:
    """Decode exactly one frame and reject trailing bytes."""

    stream = io.BytesIO(raw)
    frame = read_frame(stream)
    if stream.read(1):
        raise PtyProtocolError("frame has trailing bytes")
    return frame


__all__ = [
    "Frame",
    "FrameType",
    "MAX_FRAME_BYTES",
    "PROTOCOL_MAGIC",
    "PtyProtocolError",
    "decode_one",
    "encode_frame",
    "read_frame",
    "strict_json_loads",
    "write_frame",
]
