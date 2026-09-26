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


def test_compat_claude_auth_rejection_precedes_destination_writes(
    tmp_path, monkeypatch, capsys,
):
    front = _load_front()
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: True)

    def no_write(*_args, **_kwargs):
        pytest.fail("transport rejection must not create a scratchpad")

    monkeypatch.setattr(
        front, "_check_local_claude_login_before_launch",
        lambda: (_ for _ in ()).throw(RuntimeError("Claude login unavailable")),
    )
    monkeypatch.setattr(front.os, "makedirs", no_write)
    with pytest.raises(SystemExit) as stopped:
        front.launch_v2("sc", "core", str(project), "evm", cli_backend="claude")
    assert stopped.value.code == 1
    rendered = capsys.readouterr().out
    assert "Claude login unavailable" in rendered
    assert list(project.iterdir()) == []


def test_sc_thorough_selection_does_not_use_stale_host_probe(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(
        front,
        "_claude_headless_transport_capability",
        lambda: pytest.fail("backend selection must not use the legacy host probe"),
    )
    assert front._resolve_new_claude_transport(
        "sc", "thorough", "claude"
    ) == ("claude", "headless", "")


def test_explicit_headless_is_platform_neutral_at_selection(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(
        front,
        "_claude_headless_transport_capability",
        lambda: pytest.fail("backend selection must not use the legacy host probe"),
    )
    config = front._launch_v2_config_value(
        "sc", "thorough", ".", "evm",
        cli_backend="claude", claude_exec_mode="headless",
    )
    assert (config["cli_backend"], config["claude_exec_mode"]) == (
        "claude", "headless",
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
    assert "Cannot start audit" in capsys.readouterr().out
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


@pytest.mark.parametrize("compatibility", (True, False))
@pytest.mark.parametrize("dirty_destination", (True, False))
def test_codex_plan_reports_compatibility_assurance_without_side_effects(
    tmp_path, monkeypatch, compatibility, dirty_destination,
):
    front = _load_front()
    project = tmp_path / "project"
    project.mkdir()
    (project / "A.sol").write_text("contract A {}\n", encoding="utf-8")
    if dirty_destination:
        (project / ".scratchpad").mkdir()
        (project / ".scratchpad" / "existing.md").write_text("retained\n")
    before = {p.relative_to(project): p.read_bytes()
              for p in project.rglob("*") if p.is_file()}
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["codex"])
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: compatibility)

    def no_external_effect(*_args, **_kwargs):
        pytest.fail("planning must not launch providers or write audit state")

    monkeypatch.setattr(front, "launch_v2", no_external_effect)
    monkeypatch.setattr(front.subprocess, "run", no_external_effect)
    monkeypatch.setattr(front.os, "makedirs", no_external_effect)
    plan = front._public_plan("core", [str(project), "--codex"])

    assert plan["backend"] == "codex"
    assert plan["provider_invocations"] == 0
    assert plan["launchable"] is (not dirty_destination)
    assert bool(plan["runtime_notice"]) is compatibility
    if compatibility:
        assert "supports local audits" in plan["runtime_notice"]
        assert "does not provide native containment" in plan["runtime_notice"]
        assert plan["runtime_notice"] in front._public_help_text("test")
    assert any("destination is not clean" in issue
               for issue in plan["issues"]) is dirty_destination
    assert {p.relative_to(project): p.read_bytes()
            for p in project.rglob("*") if p.is_file()} == before


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


def test_wizard_resolves_claude_without_host_probe_or_transport_question(
    monkeypatch,
):
    front = _load_front()

    def no_prompt(**kwargs):
        pytest.fail("transport is an implementation detail, not a wizard choice")

    monkeypatch.setattr(
        front, "_claude_headless_transport_capability",
        lambda: pytest.fail("legacy host probe must not decide backend selection"),
    )
    monkeypatch.setattr(front, "_drain_stdin", lambda: None)
    monkeypatch.setattr(front.inquirer, "select", no_prompt)
    selected, warning = front.select_claude_transport("sc", "thorough")
    backend, transport, bound_warning = front._replay_new_transport_resolution(
        selected, pipeline="sc", mode="thorough",
    )
    assert (backend, transport, bound_warning) == ("claude", "headless", "")
    assert warning == ""


@pytest.mark.parametrize(
    "host_platform,compatibility,pipeline,mode",
    (
        ("win32", False, "sc", "thorough"),
        ("darwin", False, "sc", "core"),
        ("linux", False, "l1", "light"),
        ("darwin", True, "sc", "core"),
        ("linux", True, "l1", "light"),
    ),
)
def test_claude_transport_platform_matrix_is_native_driver_bound(
    monkeypatch, host_platform, compatibility, pipeline, mode,
):
    front = _load_front()
    probe_calls = []

    def capability():
        probe_calls.append(True)
        return _cap(True)

    monkeypatch.setattr(front.sys, "platform", host_platform)
    monkeypatch.setattr(
        front, "_posix_v2_compat_install_active", lambda: compatibility,
    )
    monkeypatch.setattr(front, "_claude_headless_transport_capability", capability)
    monkeypatch.setattr(front, "_check_local_claude_login_before_launch", lambda: None)
    monkeypatch.setattr(
        front.inquirer, "select",
        lambda **_kwargs: pytest.fail("transport implementation must not be prompted"),
    )

    selected, warning = front.select_claude_transport(pipeline, mode)
    assert probe_calls == []
    backend, transport, replay_warning = front._replay_new_transport_resolution(
        selected, pipeline=pipeline, mode=mode,
    )
    assert (backend, transport) == ("claude", "headless")
    assert warning == ""
    assert replay_warning == ""


def test_stale_host_probe_cannot_disable_sole_claude_selection(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: False)
    monkeypatch.setattr(
        front, "_claude_headless_transport_capability",
        lambda: pytest.fail("legacy host probe must not run"),
    )
    selected, warning = front.select_claude_transport("sc", "thorough")
    assert front._replay_new_transport_resolution(
        selected, pipeline="sc", mode="thorough",
    ) == ("claude", "headless", "")
    assert warning == ""


def test_multi_backend_wizard_accepts_claude_before_target(monkeypatch):
    front = _load_front()

    class ReachedTarget(Exception):
        pass

    class TTYBuffer:
        def isatty(self):
            return True

        def write(self, value):
            return len(value)

        def flush(self):
            return None

    class Prompt:
        def execute(self):
            return "claude"

    prompts = []

    def choose_backend(**kwargs):
        prompts.append(kwargs)
        assert kwargs["message"] == "AI runtime?"
        return Prompt()

    monkeypatch.setattr(front.sys, "argv", ["plamen.py"])
    monkeypatch.setattr(front.sys, "stdin", TTYBuffer())
    monkeypatch.setattr(front.sys, "stdout", TTYBuffer())
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: False)
    monkeypatch.setattr(front, "_enforce_public_claude_projection_preflight", lambda: None)
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(front, "_check_claude_md_version", lambda: None)
    monkeypatch.setattr(front, "_show_installed_audit_runtime", lambda: None)
    monkeypatch.setattr(front, "_find_existing_audit", lambda: None)
    monkeypatch.setattr(front, "show_hint_panel", lambda: None)
    monkeypatch.setattr(front, "_quick_check_required", lambda: True)
    monkeypatch.setattr(front, "select_pipeline", lambda: "sc")
    monkeypatch.setattr(front, "select_audit_mode", lambda _pipeline: "thorough")
    monkeypatch.setattr(front, "_audit_cli_backends", lambda: ["claude", "codex"])
    monkeypatch.setattr(front, "_skip_backend_prompt", lambda: False)
    monkeypatch.setattr(front, "_claude_headless_transport_capability", lambda: pytest.fail("legacy host probe must not run"))
    monkeypatch.setattr(front.inquirer, "select", choose_backend)
    monkeypatch.setattr(front, "select_target", lambda: (_ for _ in ()).throw(ReachedTarget))

    with pytest.raises(ReachedTarget):
        front.main()
    assert len(prompts) == 1
    choices = [choice for choice in prompts[0]["choices"] if isinstance(choice, dict)]
    assert [choice["value"] for choice in choices] == [
        "claude", "codex", front._BACK,
    ]
    assert any(choice["name"] == "← Go back" for choice in choices)
    assert all("compare" not in str(choice).casefold() for choice in choices)


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
