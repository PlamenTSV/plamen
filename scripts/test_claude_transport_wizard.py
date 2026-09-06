"""Capability-gated Claude transport UX and config regressions."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_transport_front", ROOT / "plamen.py"
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


def test_sc_thorough_defaults_to_headless_only_with_exact_capability(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(front, "_claude_headless_transport_capability", lambda: _cap(True))
    config = front._launch_v2_config_value(
        "sc", "thorough", ".", "evm", cli_backend="claude"
    )
    assert config["cli_backend"] == "claude"
    assert config["claude_exec_mode"] == "headless"


def test_sc_thorough_unsupported_host_fails_closed_with_visible_reason(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(
        front,
        "_claude_headless_transport_capability",
        lambda: _cap(False, "NATIVE_SANDBOX_PROCESS_AUTHORITY_NOT_CONFIGURED"),
    )
    with pytest.raises(RuntimeError) as stopped:
        front._resolve_new_claude_transport("sc", "thorough", "claude")
    message = str(stopped.value)
    assert "NATIVE_SANDBOX_PROCESS_AUTHORITY_NOT_CONFIGURED" in message
    assert "choose Codex explicitly" in message


def test_explicit_headless_fails_closed_without_capability(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(
        front,
        "_claude_headless_transport_capability",
        lambda: _cap(False, "DELEGATED_CGROUP_V2_PROVIDER_NOT_CONFIGURED"),
    )
    with pytest.raises(RuntimeError, match="DELEGATED_CGROUP_V2"):
        front._launch_v2_config_value(
            "sc", "thorough", ".", "evm",
            cli_backend="claude", claude_exec_mode="headless",
        )


def test_every_new_config_has_literal_mode_and_alias_is_canonical(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(front, "_claude_headless_transport_capability", lambda: _cap(True))
    alias = front._launch_v2_config_value(
        "sc", "thorough", ".", "evm", cli_backend="claude-headless"
    )
    codex = front._launch_v2_config_value(
        "sc", "core", ".", "evm", cli_backend="codex"
    )
    assert alias["cli_backend"] == "claude"
    assert alias["claude_exec_mode"] == "headless"
    assert codex["cli_backend"] == "codex"
    assert codex["claude_exec_mode"] == "headless"


def test_codex_primary_with_authorized_claude_fallback_persists_headless(monkeypatch):
    front = _load_front()
    config = front._launch_v2_config_value(
        "sc", "core", ".", "evm", cli_backend="codex",
        allow_model_fallback=True,
    )
    assert config["cli_backend"] == "codex"
    assert config["allow_model_fallback"] is True
    assert config["claude_exec_mode"] == "headless"


def test_raw_codex_config_still_rejects_explicit_claude_mode():
    front = _load_front()
    with pytest.raises(RuntimeError, match="Claude transport flags cannot be used"):
        front._launch_v2_config_value(
            "sc", "core", ".", "evm", cli_backend="codex",
            claude_exec_mode="headless",
        )


def test_bound_codex_config_does_not_resolve_transport_twice(monkeypatch):
    front = _load_front()
    resolution = front._bind_new_claude_transport(
        "sc", "core", "codex",
    )
    monkeypatch.setattr(
        front, "_resolve_new_claude_transport",
        lambda *_args, **_kwargs: pytest.fail("bound transport was re-resolved"),
    )
    config = front._launch_v2_bound_config_value(
        "sc", "core", ".", "evm", cli_backend="codex",
        claude_exec_mode="headless", transport_resolution=resolution,
    )
    assert config["cli_backend"] == "codex"
    assert config["claude_exec_mode"] == "headless"


def test_bound_transport_rejects_forgery_context_and_argument_substitution():
    front = _load_front()
    resolution = front._bind_new_claude_transport(
        "sc", "core", "codex",
    )
    with pytest.raises(TypeError, match="authority is invalid"):
        front._launch_v2_bound_config_value(
            "sc", "core", ".", "evm", cli_backend="codex",
            claude_exec_mode="headless", transport_resolution=object(),
        )
    constructor_forgery = type(resolution)(
        "sc", "core", "codex", "headless", "",
    )
    with pytest.raises(TypeError, match="was not issued"):
        front._launch_v2_bound_config_value(
            "sc", "core", ".", "evm", cli_backend="codex",
            claude_exec_mode="headless",
            transport_resolution=constructor_forgery,
        )
    with pytest.raises(RuntimeError, match="context differs"):
        front._launch_v2_bound_config_value(
            "l1", "core", ".", "go", cli_backend="codex",
            claude_exec_mode="headless", transport_resolution=resolution,
        )
    with pytest.raises(RuntimeError, match="differs from launch arguments"):
        front._launch_v2_bound_config_value(
            "sc", "core", ".", "evm", cli_backend="claude",
            claude_exec_mode="headless", transport_resolution=resolution,
        )


def test_bound_transport_rejects_object_setattr_mutation():
    front = _load_front()
    resolution = front._bind_new_claude_transport(
        "sc", "core", "codex",
    )
    object.__setattr__(resolution, "_backend", "claude")
    with pytest.raises(TypeError, match="changed after issuance"):
        front._launch_v2_bound_config_value(
            "sc", "core", ".", "evm", cli_backend="claude",
            claude_exec_mode="headless", transport_resolution=resolution,
        )


def test_launch_rejects_invalid_bound_authority_before_project_write(
    tmp_path, capsys
):
    front = _load_front()
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(SystemExit) as stopped:
        front.launch_v2(
            "sc", "core", str(project), "evm", cli_backend="codex",
            claude_exec_mode="headless", _transport_resolution=object(),
        )
    assert stopped.value.code == 1
    assert "Refusing unsafe audit launch" in capsys.readouterr().out
    assert not (project / ".scratchpad").exists()


@pytest.mark.parametrize(
    "args",
    (
        ["project", "--claude-headless", "--claude-pty"],
        ["project", "--claude-headless", "--claude-exec-mode", "pty"],
        ["project", "--codex", "--claude-exec-mode", "headless"],
        ["project", "--claude-exec-mode", "automatic"],
    ),
)
def test_noninteractive_transport_conflicts_and_invalid_values_reject(args):
    front = _load_front()
    with pytest.raises(SystemExit) as stopped:
        front._parse_cli_opts(args)
    assert stopped.value.code == 2


def test_noninteractive_headless_flag_is_explicit_and_canonical():
    front = _load_front()
    opts = front._parse_cli_opts(["project", "--claude-headless"])
    assert opts["cli_backend"] == "claude"
    assert opts["claude_exec_mode"] == "headless"


def test_public_plan_reports_transport_without_provider_or_project_write(
    tmp_path, monkeypatch
):
    front = _load_front()
    project = tmp_path / "project"
    project.mkdir()
    (project / "A.sol").write_text("contract A {}\n", encoding="utf-8")
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["claude"])
    monkeypatch.setattr(front, "_claude_headless_transport_capability", lambda: _cap(True))
    plan = front._public_plan("thorough", [str(project), "--claude"])
    assert plan["backend"] == "claude"
    assert plan["claude_exec_mode"] == "headless"
    assert plan["provider_invocations"] == 0
    assert not (project / ".scratchpad").exists()


def test_public_codex_plan_resolves_once_without_provider_or_project_write(
    tmp_path, monkeypatch
):
    front = _load_front()
    project = tmp_path / "project"
    project.mkdir()
    (project / "A.sol").write_text("contract A {}\n", encoding="utf-8")
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["codex"])
    original = front._resolve_new_claude_transport
    calls = []

    def counted(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(front, "_resolve_new_claude_transport", counted)
    plan = front._public_plan("core", [str(project), "--codex"])
    assert len(calls) == 1
    assert plan["backend"] == "codex"
    assert plan["claude_exec_mode"] == "headless"
    assert plan["provider_invocations"] == 0
    assert not (project / ".scratchpad").exists()


@pytest.mark.parametrize(
    "pipeline,mode,source_name,argv",
    (
        ("sc", "core", "A.sol", ["core", "{project}", "--codex", "--yes"]),
        ("l1", "core", "main.go", ["l1", "core", "{project}", "--codex", "--yes"]),
    ),
)
def test_public_cli_passes_its_single_resolution_to_launch(
    tmp_path, monkeypatch, pipeline, mode, source_name, argv
):
    front = _load_front()
    project = tmp_path / pipeline
    project.mkdir()
    (project / source_name).write_text("contract A {}\n", encoding="utf-8")
    calls = []
    captured = {}
    original = front._resolve_new_claude_transport

    def counted(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    def capture_launch(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

    monkeypatch.setattr(front, "_enforce_public_claude_projection_preflight", lambda: None)
    monkeypatch.setattr(front, "_check_claude_md_version", lambda: None)
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["codex"])
    monkeypatch.setattr(front, "_detect_language", lambda _target: "go" if pipeline == "l1" else "evm")
    monkeypatch.setattr(front, "_detect_fork", lambda _target: False)
    monkeypatch.setattr(front, "_resolve_new_claude_transport", counted)
    monkeypatch.setattr(front, "launch_v2", capture_launch)
    concrete_argv = [part.format(project=str(project)) for part in argv]
    monkeypatch.setattr(front.sys, "argv", ["plamen.py", *concrete_argv])
    front.main()
    assert len(calls) == 1
    resolution = captured["kwargs"]["_transport_resolution"]
    backend, exec_mode, warning = front._replay_new_transport_resolution(
        resolution, pipeline=pipeline, mode=mode,
    )
    assert (backend, exec_mode, warning) == ("codex", "headless", "")
    assert captured["kwargs"]["cli_backend"] == backend
    assert captured["kwargs"]["claude_exec_mode"] == exec_mode


def test_interactive_wizard_passes_its_single_resolution_to_launch(
    tmp_path, monkeypatch
):
    front = _load_front()
    project = tmp_path / "wizard-project"
    project.mkdir()
    (project / "A.sol").write_text("contract A {}\n", encoding="utf-8")
    calls = []
    captured = {}
    original = front._resolve_new_claude_transport

    class TTYBuffer:
        def __init__(self):
            self.text = ""

        def isatty(self):
            return True

        def write(self, value):
            self.text += value
            return len(value)

        def flush(self):
            return None

    class Prompt:
        def execute(self):
            return False

    def counted(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    def capture_launch(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

    monkeypatch.setattr(front.sys, "argv", ["plamen.py"])
    monkeypatch.setattr(front.sys, "stdin", TTYBuffer())
    monkeypatch.setattr(front.sys, "stdout", TTYBuffer())
    monkeypatch.setattr(front, "_enforce_public_claude_projection_preflight", lambda: None)
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(front, "_check_claude_md_version", lambda: None)
    monkeypatch.setattr(front, "_find_existing_audit", lambda: None)
    monkeypatch.setattr(front, "show_hint_panel", lambda: None)
    monkeypatch.setattr(front, "_quick_check_required", lambda: True)
    monkeypatch.setattr(front, "select_pipeline", lambda: "sc")
    monkeypatch.setattr(front, "select_audit_mode", lambda _pipeline: "core")
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["codex"])
    monkeypatch.setattr(front, "select_target", lambda: (str(project), ""))
    monkeypatch.setattr(front, "select_docs", lambda: "")
    monkeypatch.setattr(front, "select_scope", lambda: ("", ""))
    monkeypatch.setattr(front.inquirer, "select", lambda **_kwargs: Prompt())
    monkeypatch.setattr(front, "estimate_cost", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(front, "show_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(front, "confirm_launch", lambda: "launch")
    monkeypatch.setattr(front, "_resolve_new_claude_transport", counted)
    monkeypatch.setattr(front, "launch_v2", capture_launch)
    front.main()
    assert len(calls) == 1
    resolution = captured["kwargs"]["_transport_resolution"]
    backend, exec_mode, warning = front._replay_new_transport_resolution(
        resolution, pipeline="sc", mode="core",
    )
    assert (backend, exec_mode, warning) == ("codex", "headless", "")
    assert captured["kwargs"]["cli_backend"] == backend
    assert captured["kwargs"]["claude_exec_mode"] == exec_mode


@pytest.mark.parametrize(
    "available,selection,expected_default,expected_choices",
    ((True, "headless", "headless", {"headless"}),
     (False, "__back__", "__back__", set())),
)
def test_wizard_choice_is_capability_gated_and_defaults_safely(
    monkeypatch, available, selection, expected_default, expected_choices
):
    front = _load_front()
    captured = {}

    class Prompt:
        def execute(self):
            return selection

    def fake_select(**kwargs):
        captured.update(kwargs)
        return Prompt()

    monkeypatch.setattr(front, "_claude_headless_transport_capability", lambda: _cap(
        available, "UNSUPPORTED_TEST_HOST" if not available else ""
    ))
    monkeypatch.setattr(front, "_drain_stdin", lambda: None)
    monkeypatch.setattr(front.inquirer, "select", fake_select)
    selected, warning = front.select_claude_transport("sc", "thorough")
    if selection == front._BACK:
        assert selected == selection
    else:
        backend, transport, bound_warning = front._replay_new_transport_resolution(
            selected, pipeline="sc", mode="thorough",
        )
        assert (backend, transport, bound_warning) == ("claude", selection, "")
    assert captured["default"] == expected_default
    values = {
        item.get("value") for item in captured["choices"] if isinstance(item, dict)
    }
    assert values - {front._BACK} == expected_choices
    assert warning == ""


def test_summary_shows_only_contained_headless_transport(capsys):
    front = _load_front()
    front.show_summary(
        "thorough", os.getcwd(), "", pipeline="sc", language="evm",
        backend="claude", claude_exec_mode="headless",
    )
    rendered = capsys.readouterr().out
    assert "Transport" in rendered
    assert "Contained headless" in rendered
    assert "PTY compatibility" not in rendered
