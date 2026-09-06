from __future__ import annotations

import io
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

import pty_worker_host as H
import pty_worker_protocol as P


def test_protocol_round_trip_preserves_binary_pty_bytes() -> None:
    raw = b"\x00\xffpartial\r\njson-looking:{\"x\":1}"
    encoded = P.encode_frame(P.FrameType.PTY_BYTES, raw)
    assert P.read_frame(io.BytesIO(encoded)) == P.Frame(P.FrameType.PTY_BYTES, raw)


@pytest.mark.parametrize(
    "raw, expected",
    [
        (b"PLP1\x03\x00\x00", "truncated"),
        (b"NOPE\x03\x00\x00\x00\x00", "magic"),
        (b"PLP1\xff\x00\x00\x00\x00", "type"),
        (
            b"PLP1\x03" + (P.MAX_FRAME_BYTES + 1).to_bytes(4, "big"),
            "ceiling",
        ),
        (b"PLP1\x03\x00\x00\x00\x05abc", "truncated"),
    ],
)
def test_protocol_rejects_malformed_oversized_and_truncated_frames(
    raw: bytes,
    expected: str,
) -> None:
    with pytest.raises(P.PtyProtocolError, match=expected):
        P.read_frame(io.BytesIO(raw))


def test_host_manifest_is_strict_and_hash_bound_shape(tmp_path: Path) -> None:
    manifest = {
        "schema": H.HOST_MANIFEST_SCHEMA,
        "argv": [str(Path(sys.executable).resolve()), "-c", "print('ok')"],
        "cwd": str(tmp_path.resolve()),
        "environment": {"PATH": "bound"},
        "rows": 40,
        "columns": 120,
    }
    parsed = H.parse_host_manifest_bytes(
        json.dumps(manifest, sort_keys=True).encode("utf-8")
    )
    assert parsed.argv == tuple(manifest["argv"])
    assert parsed.rows == 40
    assert parsed.columns == 120

    manifest["unbound"] = True
    with pytest.raises(H.PtyHostError, match="fields"):
        H.parse_host_manifest_bytes(json.dumps(manifest).encode("utf-8"))


def test_host_manifest_rejects_duplicate_json_and_environment_aliases(
    tmp_path: Path,
) -> None:
    executable = str(Path(sys.executable).resolve())
    cwd = str(tmp_path.resolve())
    duplicate_top = (
        '{"schema":"plamen.pty_worker_host_manifest.v1",'
        '"schema":"plamen.pty_worker_host_manifest.v1",'
        f'"argv":[{json.dumps(executable)}],"cwd":{json.dumps(cwd)},'
        '"environment":{},"rows":40,"columns":120}'
    ).encode("utf-8")
    with pytest.raises(H.PtyHostError, match="strict UTF-8 JSON"):
        H.parse_host_manifest_bytes(duplicate_top)

    duplicate_nested = (
        '{"schema":"plamen.pty_worker_host_manifest.v1",'
        f'"argv":[{json.dumps(executable)}],"cwd":{json.dumps(cwd)},'
        '"environment":{"PATH":"one","PATH":"two"},'
        '"rows":40,"columns":120}'
    ).encode("utf-8")
    with pytest.raises(H.PtyHostError, match="strict UTF-8 JSON"):
        H.parse_host_manifest_bytes(duplicate_nested)

    case_alias = {
        "schema": H.HOST_MANIFEST_SCHEMA,
        "argv": [executable],
        "cwd": cwd,
        "environment": {"PATH": "one", "Path": "two"},
        "rows": 40,
        "columns": 120,
    }
    with pytest.raises(H.PtyHostError, match="collide"):
        H.parse_host_manifest_bytes(json.dumps(case_alias).encode("utf-8"))


def test_host_cannot_claim_semantic_completion_and_forces_conpty() -> None:
    source = inspect.getsource(H)
    assert "TURN_END" not in source
    assert "OUTPUT_READY" not in source
    assert "Backend.ConPTY" in source
    assert 'errors="replace"' not in source


def test_host_observes_natural_child_exit_without_waiting_for_driver_input(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": H.HOST_MANIFEST_SCHEMA,
                "argv": [
                    str(Path(sys.executable).resolve()),
                    "-u",
                    "-c",
                    "import time; print('host-child'); time.sleep(0.15)",
                ],
                "cwd": str(tmp_path.resolve()),
                "environment": dict(os.environ),
                "rows": 40,
                "columns": 120,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(H.__file__).resolve()),
            str(manifest_path.resolve()),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    frames: list[P.Frame] = []

    def read_until_exit() -> None:
        while True:
            frame = P.read_frame(proc.stdout)
            frames.append(frame)
            if frame.kind in {P.FrameType.CHILD_EXIT, P.FrameType.HOST_ERROR}:
                return

    reader = threading.Thread(target=read_until_exit, daemon=True)
    reader.start()
    reader.join(timeout=5)
    if reader.is_alive():
        proc.kill()
        proc.wait(timeout=5)
    assert not reader.is_alive()
    assert [frame.kind for frame in frames[:2]] == [
        P.FrameType.READY,
        P.FrameType.CHILD_PID,
    ]
    assert any(
        frame.kind is P.FrameType.PTY_BYTES and b"host-child" in frame.payload
        for frame in frames
    )
    assert frames[-1].kind is P.FrameType.CHILD_EXIT
    assert proc.wait(timeout=5) == 0
