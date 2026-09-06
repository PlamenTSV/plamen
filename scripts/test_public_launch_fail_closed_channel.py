"""Focused regressions for the public launch fail-closed boundary."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_public_launch_fail_closed", ROOT / "plamen.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _cap(available: bool, reason: str = "") -> dict:
    return {
        "available": available,
        "platform": "TEST",
        "reason": reason,
        "write_authority": "EXHAUSTIVE" if available else None,
    }


def test_claude_audit_never_falls_back_to_pty_when_containment_is_unavailable():
    front = _load_front()
    with pytest.raises(RuntimeError) as stopped:
        front._resolve_new_claude_transport(
            "sc", "thorough", "claude",
            capability=_cap(False, "NO_DESCENDANT_AUTHORITY"),
        )
    message = str(stopped.value)
    assert "NO_DESCENDANT_AUTHORITY" in message
    assert "choose Codex explicitly" in message


def test_explicit_legacy_pty_is_rejected_even_when_headless_is_available():
    front = _load_front()
    with pytest.raises(RuntimeError, match="legacy Claude PTY audit execution"):
        front._resolve_new_claude_transport(
            "sc", "thorough", "claude", "pty", capability=_cap(True)
        )


def test_non_authoritative_resolution_still_cannot_emit_pty():
    front = _load_front()
    with pytest.raises(RuntimeError, match="choose Codex explicitly"):
        front._resolve_new_claude_transport(
            "sc", "thorough", "claude", capability=_cap(False, "TEST_ONLY"),
            audit_model_launch=False,
        )


def test_unsafe_claude_launch_stops_before_creating_scratchpad(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    front = _load_front()
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(
        front, "_claude_headless_transport_capability",
        lambda: _cap(False, "NO_CONTAINMENT"),
    )
    with pytest.raises(SystemExit, match="1"):
        front.launch_v2(
            "sc", "thorough", str(project), "evm", cli_backend="claude"
        )
    assert not (project / ".scratchpad").exists()


@pytest.mark.parametrize(
    ("pipeline", "mode", "language"),
    (("sc", "light", "evm"), ("sc", "core", "evm"),
     ("l1", "thorough", "go")),
)
def test_unsupported_claude_route_stops_before_creating_scratchpad(
    tmp_path: Path, pipeline: str, mode: str, language: str,
):
    front = _load_front()
    project = tmp_path / f"{pipeline}-{mode}"
    project.mkdir()
    with pytest.raises(SystemExit, match="1"):
        front.launch_v2(
            pipeline, mode, str(project), language, cli_backend="claude"
        )
    assert not (project / ".scratchpad").exists()


def test_paid_failure_diagnosis_flag_never_spawns_a_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import plamen_display

    (tmp_path / "_stdio_recon.log").write_text(
        "gate timed out before recon_summary.md\n", encoding="utf-8"
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("failure diagnosis attempted a provider process")

    monkeypatch.setattr(plamen_display.subprocess, "Popen", forbidden)
    monkeypatch.setattr(plamen_display.subprocess, "run", forbidden)
    monkeypatch.setattr(plamen_display, "_find_claude_bin", forbidden)
    monkeypatch.setattr(plamen_display, "_find_codex_bin", forbidden)
    plamen_display.print_failure_diagnosis(
        "recon", str(tmp_path), ["recon_summary.md"],
        {
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": "claude",
            "allow_paid_failure_diagnosis": True,
        },
    )
    diagnosis = (tmp_path / "_diagnosis_recon.md").read_text(encoding="utf-8")
    assert "deterministic local diagnosis" in diagnosis
    assert "canonical contained provider" in diagnosis
    assert not (tmp_path / "_diagnosis_prompt_recon.md").exists()


def test_start_config_uses_authenticated_one_use_decision_channel_and_zeros_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    front = _load_front()
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad-new"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text(
        json.dumps({
            "project_root": str(project),
            "scratchpad": str(scratchpad),
            "pipeline": "sc",
            "mode": "thorough",
        }),
        encoding="utf-8",
    )
    runtime = tmp_path / "runtime"
    (runtime / "scripts").mkdir(parents=True)
    (runtime / "scripts" / "plamen_driver.py").write_text(
        "# fixture\n", encoding="utf-8"
    )
    receipt = tmp_path / "private-state" / "decision.json"
    receipt.parent.mkdir()
    calls = []
    rendered = []
    tracked = []

    class TrackingBytearray(bytearray):
        def __new__(cls, value=b""):
            instance = super().__new__(cls, value)
            tracked.append(instance)
            return instance

    def fake_run(argv, *, env):
        calls.append((list(argv), env))
        assert env["PLAMEN_STARTUP_DECISION_MAC_KEY"] == "a5" * 32
        assert "PLAMEN_STARTUP_DECISION_MAC_KEY" not in front.os.environ
        return SimpleNamespace(returncode=5)

    def fake_render(returncode, config_arg, target_arg, **kwargs):
        rendered.append((returncode, config_arg, target_arg, kwargs))
        assert kwargs["decision_receipt_path"] == receipt
        assert kwargs["decision_mac_key"] == bytes.fromhex("a5" * 32)
        return 5

    monkeypatch.setattr(front, "PLAMEN_HOME", str(runtime))
    monkeypatch.setattr(front.sys, "executable", "managed-python")
    monkeypatch.setattr(front, "_resume_startup_decision_destination", lambda *_: receipt)
    monkeypatch.setattr(front.secrets, "token_bytes", lambda count: bytes([0xA5]) * count)
    monkeypatch.setattr(front, "bytearray", TrackingBytearray, raising=False)
    monkeypatch.delenv("PLAMEN_STARTUP_DECISION_MAC_KEY", raising=False)
    monkeypatch.setattr(front.subprocess, "run", fake_run)
    monkeypatch.setattr(front, "_render_driver_result", fake_render)

    with pytest.raises(SystemExit, match="5"):
        front.start_config_v2(str(config_path))

    assert calls[0][0] == [
        "managed-python",
        str(runtime / "scripts" / "plamen_driver.py"),
        "--startup-intent",
        "START_NEW_RUN",
        "--startup-decision-receipt",
        str(receipt),
        str(config_path),
    ]
    assert "PLAMEN_STARTUP_DECISION_MAC_KEY" not in calls[0][1]
    assert len(rendered) == 1
    assert len(tracked) == 1
    assert tracked[0] == b"\x00" * 32
