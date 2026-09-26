"""Frontend pre-audit identity/toolchain ordering regressions."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_native_start_preflight_test", ROOT / "plamen.py"
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


@pytest.mark.parametrize(
    "config",
    (
        {"pipeline": "l1", "mode": "thorough", "language": "go"},
        {"pipeline": "sc", "mode": "core", "language": "solana"},
    ),
)
def test_unrelated_modes_do_not_require_completion_or_managed_evm(
    monkeypatch, config,
):
    front = _load_front()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: False)
    monkeypatch.setattr(
        front, "_native_start_completion_identity",
        lambda *_a, **_k: pytest.fail("completion identity is SC Thorough only"),
    )
    monkeypatch.setattr(
        front, "_native_managed_evm_setup_effects_for_start",
        lambda *_a, **_k: pytest.fail("managed EVM setup is SC EVM only"),
    )

    assert front._prepare_native_new_run_config(config) == config


def test_sc_thorough_binds_one_preallocated_completion_identity(monkeypatch):
    front = _load_front()
    observed = []
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: False)

    def capture(config, *, run_id):
        observed.append((dict(config), run_id))
        return {"run_id": run_id, "bound": "exact"}

    monkeypatch.setattr(front, "_native_start_completion_identity", capture)
    config = {"pipeline": "sc", "mode": "thorough", "language": "solana"}
    prepared = front._prepare_native_new_run_config(config)

    assert len(observed) == 1
    assert prepared["_run_id"] == observed[0][1]
    assert prepared["_audit_completion_identity"] == {
        "run_id": observed[0][1], "bound": "exact",
    }


def test_sc_evm_setup_is_not_consumed_by_host_front(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: False)
    monkeypatch.setattr(
        front, "_native_start_completion_identity",
        lambda *_a, **_k: pytest.fail("Core does not capture completion identity"),
    )
    monkeypatch.setattr(
        front, "_native_managed_evm_setup_effects_for_start",
        lambda *_a, **_k: pytest.fail("host must not consume driver setup authority"),
    )

    config = {"pipeline": "sc", "mode": "core", "language": "evm"}
    assert front._prepare_native_new_run_config(config) == config


def test_compat_public_help_requires_native_without_local_execution_offer(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: True)
    rendered = front._public_help_text("test")
    assert "reinstall plamen with the native installer" in rendered.casefold()
    assert "reduced isolation" not in rendered.casefold()
    assert "--codex | --claude" not in rendered


def test_compat_start_fails_before_identity_or_toolchain(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: True)
    monkeypatch.setattr(
        front, "_native_start_completion_identity",
        lambda *_a, **_k: pytest.fail("compat must stop before identity capture"),
    )
    monkeypatch.setattr(
        front, "_native_managed_evm_setup_effects_for_start",
        lambda *_a, **_k: pytest.fail("compat must stop before toolchain setup"),
    )

    with pytest.raises(RuntimeError, match="native installer"):
        front._prepare_native_new_run_config({
            "pipeline": "sc", "mode": "core", "language": "evm",
        })


@pytest.mark.parametrize("mode", ("light", "core", "thorough"))
def test_windows_dispatches_through_completion_capable_start(monkeypatch, mode):
    front = _load_front()
    monkeypatch.setattr(front.os, "name", "nt")
    config = {"pipeline": "sc", "mode": mode, "language": "evm"}
    monkeypatch.setattr(
        front, "_prepare_native_new_run_config",
        lambda value: {**value, "windows_start": "admitted"},
    )
    assert front._prepare_new_run_config(config) == {
        **config, "windows_start": "admitted",
    }


def test_start_config_persists_identity_before_driver_launch(
    tmp_path, monkeypatch,
):
    front = _load_front()
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text(json.dumps({
        "project_root": str(project), "scratchpad": str(scratchpad),
        "pipeline": "sc", "mode": "thorough", "language": "solana",
        "cli_backend": "codex", "claude_exec_mode": "headless",
    }), encoding="utf-8")
    identity = {"run_id": "00000000-0000-4000-8000-000000000001"}
    events = []
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: False)

    def prepare(config):
        events.append("prepare")
        result = dict(config)
        result["_run_id"] = identity["run_id"]
        result["_audit_completion_identity"] = identity
        return result

    def run(*_args, **_kwargs):
        persisted = json.loads(config_path.read_text(encoding="utf-8"))
        assert persisted["_audit_completion_identity"] == identity
        assert persisted["_run_id"] == identity["run_id"]
        events.append("driver")
        return types.SimpleNamespace(returncode=130)

    monkeypatch.setattr(front, "_prepare_new_run_config", prepare)
    monkeypatch.setattr(
        front, "_resume_startup_decision_destination",
        lambda *_a, **_k: scratchpad / "startup-decision.json",
    )
    monkeypatch.setattr(front.subprocess, "run", run)
    monkeypatch.setattr(front, "_render_driver_result", lambda *_a, **_k: 130)

    with pytest.raises(SystemExit) as stopped:
        front.start_config_v2(str(config_path))

    assert stopped.value.code == 130
    assert events == ["prepare", "driver"]


def test_completion_capture_failure_precedes_destination_and_provider(
    tmp_path, monkeypatch, capsys,
):
    front = _load_front()
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: False)
    monkeypatch.setattr(
        front, "_native_start_completion_identity",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("identity unavailable")),
    )
    monkeypatch.setattr(
        front, "_native_managed_evm_setup_effects_for_start",
        lambda *_a, **_k: pytest.fail("identity failure precedes toolchain setup"),
    )
    original_makedirs = front.os.makedirs

    def guarded_makedirs(path, *args, **kwargs):
        if Path(path) == project / ".scratchpad":
            pytest.fail("identity failure must precede scratchpad creation")
        return original_makedirs(path, *args, **kwargs)

    monkeypatch.setattr(front.os, "makedirs", guarded_makedirs)
    monkeypatch.setattr(
        front.subprocess, "run",
        lambda *_a, **_k: pytest.fail("identity failure must precede provider/driver"),
    )

    with pytest.raises(SystemExit) as stopped:
        front.launch_v2(
            "sc", "thorough", str(project), "solana", cli_backend="codex",
        )

    assert stopped.value.code == 1
    assert "identity unavailable" in capsys.readouterr().out
    assert not (project / ".scratchpad").exists()
