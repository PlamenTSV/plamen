from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import pty_transport_bridge as B


def test_bridge_forwards_exact_pty_bytes_and_bootstrap(tmp_path: Path) -> None:
    host_manifest = tmp_path / "host.json"
    host_manifest.write_text(
        json.dumps(
            {
                "schema": "plamen.pty_worker_host_manifest.v1",
                "argv": [
                    str(Path(sys.executable).resolve()),
                    "-u",
                    "-c",
                    "value=input(); print('BRIDGE:'+value)",
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
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("hello-bridge", encoding="utf-8")
    bridge_manifest = tmp_path / "bridge.json"
    bridge_manifest.write_text(
        json.dumps(
            {
                "schema": B.BRIDGE_MANIFEST_SCHEMA,
                "host_manifest_path": str(host_manifest.resolve()),
                "bootstrap_prompt_path": str(prompt.resolve()),
                "submit_bytes_hex": "0d",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(B.__file__).resolve()),
            str(bridge_manifest.resolve()),
        ],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert b"BRIDGE:hello-bridge" in completed.stdout
    assert b"hello-bridge" not in completed.stderr


def test_bridge_has_no_semantic_completion_authority() -> None:
    source = inspect.getsource(B)
    assert "TURN_END" not in source
    assert "OUTPUT_READY" not in source
    assert "inspect_transcript" not in source


def test_bridge_manifest_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    host = tmp_path / "host.json"
    host.write_text("{}", encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("x", encoding="utf-8")
    raw = (
        '{"schema":"plamen.pty_transport_bridge_manifest.v1",'
        '"schema":"plamen.pty_transport_bridge_manifest.v1",'
        f'"host_manifest_path":{json.dumps(str(host.resolve()))},'
        f'"bootstrap_prompt_path":{json.dumps(str(prompt.resolve()))},'
        '"submit_bytes_hex":"0d"}'
    ).encode("utf-8")
    with pytest.raises(B.PtyBridgeError, match="strict UTF-8 JSON"):
        B.parse_bridge_manifest_bytes(raw)


def test_bridge_control_payloads_are_strict_and_typed() -> None:
    assert B._strict_control_payload(
        b'{"protocol":"PLP1"}',
        expected_fields={"protocol"},
        label="readiness",
    ) == {"protocol": "PLP1"}
    with pytest.raises(B.PtyBridgeError, match="malformed"):
        B._strict_control_payload(
            b'{"protocol":"old","protocol":"PLP1"}',
            expected_fields={"protocol"},
            label="readiness",
        )
    with pytest.raises(B.PtyBridgeError, match="fields"):
        B._strict_control_payload(
            b'{"pid":1,"extra":true}',
            expected_fields={"pid"},
            label="child identity",
        )


def test_bridge_reads_bounded_prompt_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = tmp_path / "host.json"
    host.write_text("{}", encoding="utf-8")
    prompt = tmp_path / "prompt.txt"
    prompt.write_bytes(b"x" * (B.MAX_BOOTSTRAP_PROMPT_BYTES + 1))
    manifest = B.BridgeManifest(
        host_manifest_path=host.resolve(),
        bootstrap_prompt_path=prompt.resolve(),
        submit_bytes=b"\r",
    )
    launched = False

    def forbidden_launch(*_args: object, **_kwargs: object) -> object:
        nonlocal launched
        launched = True
        raise AssertionError("host launch occurred before prompt validation")

    monkeypatch.setattr(B.subprocess, "Popen", forbidden_launch)
    with pytest.raises(B.PtyBridgeError, match="prompt exceeds"):
        B.run_bridge(
            manifest,
            output=subprocess.DEVNULL,  # type: ignore[arg-type]
            diagnostics=subprocess.DEVNULL,  # type: ignore[arg-type]
        )
    assert launched is False


def test_bridge_implementation_closure_is_exact() -> None:
    paths = B.implementation_files()
    assert paths == tuple(sorted(set(paths), key=lambda item: str(item).casefold()))
    assert Path(B.__file__).resolve() in paths
    assert any(path.name == "pty_worker_host.py" for path in paths)
    assert any(path.name == "pty_worker_protocol.py" for path in paths)
