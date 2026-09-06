from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import pty_worker_host as H
import pty_worker_protocol as P
import pty_worker_provider as W


def _manifest(
    path: Path,
    *,
    argv: list[str],
    cwd: Path,
) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema": H.HOST_MANIFEST_SCHEMA,
                "argv": argv,
                "cwd": str(cwd.resolve()),
                "environment": dict(os.environ),
                "rows": 40,
                "columns": 120,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job inheritance proof")
def test_provider_proves_child_membership_and_kills_late_descendant(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "attempt-output"
    writable.mkdir()
    marker = writable / "late.txt"
    grandchild = (
        "import pathlib,time; time.sleep(0.8); "
        f"pathlib.Path({str(marker)!r}).write_text('late')"
    )
    child = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-c',{grandchild!r}],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
        "stderr=subprocess.DEVNULL); print('child-ready'); time.sleep(0.1)"
    )
    manifest = _manifest(
        tmp_path / "host-manifest.json",
        argv=[str(Path(sys.executable).resolve()), "-u", "-c", child],
        cwd=tmp_path,
    )
    handle = W.PtyHostHandle.launch(
        manifest_path=manifest,
        writable_roots=(writable,),
        persistent_identity=f"pty-fixture-{os.getpid()}-{time.time_ns()}",
    )
    try:
        handle.wait_ready(timeout_seconds=5)
        assert handle.child_pid is not None
        assert handle.child_membership_proven is True
        while True:
            event = handle.poll_event(timeout_seconds=5)
            if event.kind is P.FrameType.CHILD_EXIT:
                break
    finally:
        handle.terminate_scope()

    time.sleep(1.0)
    assert handle.closed is True
    assert handle.population_zero_proven is True
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows provider checkpoint")
def test_provider_bounded_pty_stream_overflow_is_terminal_debt(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "attempt-output"
    writable.mkdir()
    manifest = _manifest(
        tmp_path / "overflow-manifest.json",
        argv=[
            str(Path(sys.executable).resolve()),
            "-u",
            "-c",
            "print('x' * 200000)",
        ],
        cwd=tmp_path,
    )
    handle = W.PtyHostHandle.launch(
        manifest_path=manifest,
        writable_roots=(writable,),
        persistent_identity=f"pty-overflow-{os.getpid()}-{time.time_ns()}",
        pty_byte_limit=1024,
    )
    try:
        handle.wait_ready(timeout_seconds=5)
        with pytest.raises(W.PtyProviderError, match="ceiling"):
            while True:
                handle.poll_event(timeout_seconds=5)
    finally:
        handle.terminate_scope()
    assert handle.closed is True
    assert handle.can_authorize_completion is False


def test_provider_has_no_semantic_self_certification_surface() -> None:
    source = inspect.getsource(W)
    assert "TURN_END" not in source
    assert "OUTPUT_READY" not in source
    assert not hasattr(W.PtyHostHandle, "complete")
