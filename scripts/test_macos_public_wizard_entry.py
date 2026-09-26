"""macOS public-entry tests for the terminal wizard and compat launcher.

These tests never launch an audit or provider.  The POSIX compatibility flag
is an authenticated installed-runtime ABI detail; it must not become a public
wizard requirement or a claim of native assurance.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import sys
import time
import types

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS public entry")


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_macos_public_wizard_entry_test", ROOT / "plamen.py"
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


class _TTY:
    def __init__(self, terminal: bool = True) -> None:
        self.terminal = terminal
        self.text = ""

    def isatty(self) -> bool:
        return self.terminal

    def write(self, value: str) -> int:
        self.text += value
        return len(value)

    def flush(self) -> None:
        return None


class _Prompt:
    def __init__(self, value: object) -> None:
        self.value = value

    def execute(self) -> object:
        return self.value


def _deny_effect(name: str):
    def denied(*_args, **_kwargs):
        pytest.fail(f"{name} reached")
    return denied


def _admit_compat(front, monkeypatch) -> None:
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: True)
    monkeypatch.setattr(
        front, "_enforce_public_claude_projection_preflight",
        _deny_effect("legacy Claude projection preflight"),
    )


def test_plain_public_subprocess_reaches_first_prompt_and_eof_creates_no_audit_state(
    tmp_path,
) -> None:
    """The real POSIX front may collect choices before native admission.

    Importing pytest in the isolated child selects plamen.py's existing
    read-only test bootstrap seam, so this regression exercises the top-level
    entrypoint and terminal state machine without installing a user runtime.
    The pseudo-terminal is important: a pipe would correctly select the
    separate non-interactive usage-error path instead of the public wizard.
    """
    import pty

    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    child_code = (
        "import runpy,sys;"
        # -I intentionally excludes user-site packages. Bind the test runner's
        # known pytest distribution explicitly, not HOME/PYTHONPATH discovery.
        f"sys.path.insert(0,{str(Path(pytest.__file__).resolve().parent.parent)!r});"
        "import pytest;"
        "sys.argv=['plamen'];"
        f"runpy.run_path({str(ROOT / 'plamen.py')!r},run_name='__main__')"
    )
    environment = dict(os.environ)
    environment.update({
        "HOME": str(home),
        "NO_COLOR": "1",
        "PLAMEN_PLAIN_OUTPUT": "1",
        "PLAMEN_PLAIN_WIZARD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    })
    environment.pop("USERPROFILE", None)

    pid, terminal = pty.fork()
    if pid == 0:  # pragma: no cover - assertions are made by the parent
        os.chdir(project)
        os.execve(
            sys.executable,
            [sys.executable, "-I", "-B", "-c", child_code],
            environment,
        )

    output = bytearray()
    reaped = False
    status = None
    try:
        deadline = time.monotonic() + 15.0
        while b"Choice: " not in output and time.monotonic() < deadline:
            readable, _, _ = select.select([terminal], [], [], 0.2)
            if not readable:
                continue
            try:
                output.extend(os.read(terminal, 4096))
            except OSError:
                break
        rendered = output.decode("utf-8", "replace")
        assert "What are you auditing?" in rendered
        assert "Choice: " in rendered

        # EOT at an empty canonical-input line makes input() raise EOFError;
        # the public top-level handler treats this as a safe operator cancel.
        os.write(terminal, b"\x04")
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            observed, status = os.waitpid(pid, os.WNOHANG)
            if observed == pid:
                reaped = True
                break
            readable, _, _ = select.select([terminal], [], [], 0.1)
            if readable:
                try:
                    output.extend(os.read(terminal, 4096))
                except OSError:
                    pass
        assert reaped, "plain wizard did not exit after terminal EOF"
        assert status is not None
        assert os.waitstatus_to_exitcode(status) == 0
        assert "Cancelled." in output.decode("utf-8", "replace")
        assert not (project / ".scratchpad").exists()
        assert not (project / "config.json").exists()
    finally:
        if not reaped:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        os.close(terminal)


def test_bare_non_tty_is_a_no_write_no_provider_usage_error(monkeypatch) -> None:
    front = _load_front()
    stdin = _TTY(False)
    stdout = _TTY(False)
    stderr = _TTY(False)
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front.sys, "argv", ["plamen"])
    monkeypatch.setattr(front.sys, "stdin", stdin)
    monkeypatch.setattr(front.sys, "stdout", stdout)
    monkeypatch.setattr(front.sys, "stderr", stderr)
    monkeypatch.setattr(front, "_find_existing_audit", _deny_effect("workspace scan"))
    monkeypatch.setattr(front, "launch_v2", _deny_effect("provider launch"))
    monkeypatch.setattr(front, "run_install", _deny_effect("installer"))
    monkeypatch.setattr(front.os, "makedirs", _deny_effect("filesystem write"))
    monkeypatch.setattr(front.os, "open", _deny_effect("filesystem open"))

    with pytest.raises(SystemExit) as stopped:
        front.main()

    assert stopped.value.code == 2
    assert "needs a real terminal" in stderr.text
    assert "native" not in (stdout.text + stderr.text).casefold()


def test_existing_audit_cancel_precedes_warnings_writes_and_provider(monkeypatch) -> None:
    front = _load_front()
    stream = _TTY()
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front.sys, "argv", ["plamen"])
    monkeypatch.setattr(front.sys, "stdin", stream)
    monkeypatch.setattr(front.sys, "stdout", stream)
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(
        front, "_find_existing_audit",
        lambda: {"config_path": "/retained/.scratchpad/config.json"},
    )
    monkeypatch.setattr(front, "_resume_audit_prompt", lambda _audit: "cancel")
    monkeypatch.setattr(front, "resume_v2", _deny_effect("resume"))
    monkeypatch.setattr(front, "launch_v2", _deny_effect("provider launch"))
    monkeypatch.setattr(front, "show_hint_panel", _deny_effect("wizard continuation"))
    monkeypatch.setattr(front.os, "makedirs", _deny_effect("filesystem write"))

    front.main()

    assert "Scratchpad left intact" in stream.text
    assert "CLAUDE.md" not in stream.text
    assert "plamen install" not in stream.text


def test_bare_wizard_can_select_codex_from_both_eligible_backends(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    project = tmp_path / "project"
    project.mkdir()
    (project / "A.sol").write_text("contract A {}\n", encoding="utf-8")
    stream = _TTY()
    captured: dict[str, object] = {}
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front.sys, "argv", ["plamen"])
    monkeypatch.setattr(front.sys, "stdin", stream)
    monkeypatch.setattr(front.sys, "stdout", stream)
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(front, "_find_existing_audit", lambda: None)
    monkeypatch.setattr(front, "show_hint_panel", lambda: None)
    monkeypatch.setattr(front, "_quick_check_required", lambda: True)
    monkeypatch.setattr(front, "select_pipeline", lambda: "sc")
    monkeypatch.setattr(front, "select_audit_mode", lambda _pipeline: "core")
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["claude", "codex"])
    monkeypatch.setattr(front, "select_target", lambda: (str(project), ""))
    monkeypatch.setattr(front, "_detect_language", lambda _target: "evm")
    monkeypatch.setattr(front, "select_docs", lambda: "")
    monkeypatch.setattr(front, "select_scope", lambda: ("", ""))
    monkeypatch.setattr(front, "estimate_cost", lambda *_a, **_k: {})
    monkeypatch.setattr(front, "show_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(front, "confirm_launch", lambda: "launch")

    prompts: list[str] = []
    runtime_choices: list[object] = []

    def select(**kwargs):
        prompts.append(kwargs.get("message", ""))
        if kwargs.get("message") == "AI runtime?":
            runtime_choices.extend(kwargs["choices"])
            return _Prompt("codex")
        if kwargs.get("message") == "Proven-only mode?":
            return _Prompt(False)
        pytest.fail(f"unexpected prompt: {kwargs.get('message')}")

    def launch(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

    monkeypatch.setattr(front.inquirer, "select", select)
    monkeypatch.setattr(front, "launch_v2", launch)

    front.main()

    assert captured["args"][:4] == ("sc", "core", str(project), "evm")
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["cli_backend"] == "codex"
    assert "posix_compat_v2" not in kwargs
    assert not any("native" in str(key).casefold() for key in kwargs)
    assert front._audit_cli_backends() == ["claude", "codex"]
    assert prompts.count("AI runtime?") == 1
    runtime_values = [
        choice.get("value") for choice in runtime_choices
        if isinstance(choice, dict)
    ]
    assert runtime_values == ["claude", "codex", front._BACK]
    assert any(
        isinstance(choice, dict)
        and choice.get("name") == "← Go back"
        for choice in runtime_choices
    )
    assert not any("compare" in str(choice).casefold() for choice in runtime_choices)
    assert not any("transport" in prompt.casefold() for prompt in prompts)
    assert "CLAUDE.md" not in stream.text
    assert not (project / ".scratchpad").exists()


def test_ai_runtime_go_back_is_visible_and_returns_to_depth(monkeypatch) -> None:
    front = _load_front()
    stream = _TTY()
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front.sys, "argv", ["plamen"])
    monkeypatch.setattr(front.sys, "stdin", stream)
    monkeypatch.setattr(front.sys, "stdout", stream)
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(front, "_find_existing_audit", lambda: None)
    monkeypatch.setattr(front, "show_hint_panel", lambda: None)
    monkeypatch.setattr(front, "_quick_check_required", lambda: True)
    monkeypatch.setattr(front, "select_pipeline", lambda: "sc")
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["claude", "codex"])
    depth_calls: list[str] = []
    runtime_choices: list[object] = []

    class ReturnedToDepth(Exception):
        pass

    def select_depth(pipeline):
        depth_calls.append(pipeline)
        if len(depth_calls) == 1:
            return "core"
        raise ReturnedToDepth

    def select(**kwargs):
        assert kwargs["message"] == "AI runtime?"
        runtime_choices.extend(kwargs["choices"])
        return _Prompt(front._BACK)

    monkeypatch.setattr(front, "select_audit_mode", select_depth)
    monkeypatch.setattr(front.inquirer, "select", select)
    monkeypatch.setattr(front, "select_target", _deny_effect("target selection"))
    monkeypatch.setattr(front, "launch_v2", _deny_effect("provider launch"))

    with pytest.raises(ReturnedToDepth):
        front.main()

    assert depth_calls == ["sc", "sc"]
    assert any(
        isinstance(choice, dict)
        and choice.get("name") == "← Go back"
        and choice.get("value") == front._BACK
        for choice in runtime_choices
    )
    assert not any("compare" in str(choice).casefold() for choice in runtime_choices)


def test_compat_runtime_emits_no_reduced_isolation_advertisement(monkeypatch) -> None:
    front = _load_front()
    stream = _TTY()
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front.sys, "stdout", stream)

    front._show_installed_audit_runtime()

    assert stream.text == ""


def test_claude_only_compat_wizard_reaches_target_without_native_probe(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    project = tmp_path / "claude-project"
    project.mkdir()
    (project / "A.sol").write_text("contract A {}\n", encoding="utf-8")
    stream = _TTY()
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front.sys, "argv", ["plamen"])
    monkeypatch.setattr(front.sys, "stdin", stream)
    monkeypatch.setattr(front.sys, "stdout", stream)
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(front, "_find_existing_audit", lambda: None)
    monkeypatch.setattr(front, "show_hint_panel", lambda: None)
    monkeypatch.setattr(front, "_quick_check_required", lambda: True)
    monkeypatch.setattr(front, "select_pipeline", lambda: "sc")
    monkeypatch.setattr(front, "select_audit_mode", lambda _pipeline: "core")
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["claude"])
    class ReachedTarget(Exception):
        pass

    monkeypatch.setattr(
        front, "select_target", lambda: (_ for _ in ()).throw(ReachedTarget())
    )
    monkeypatch.setattr(
        front, "_check_local_claude_login_before_launch", lambda: None,
    )
    monkeypatch.setattr(
        front, "_claude_headless_transport_capability",
        _deny_effect("native contained-transport probe"),
    )

    monkeypatch.setattr(front.inquirer, "select", _deny_effect("wizard prompt"))
    monkeypatch.setattr(front, "show_summary", _deny_effect("summary"))
    monkeypatch.setattr(front, "launch_v2", _deny_effect("provider launch"))

    with pytest.raises(ReachedTarget):
        front.main()

    assert front._audit_cli_backends() == ["claude"]
    assert "Claude execution transport?" not in stream.text
    assert not (project / ".scratchpad").exists()


def test_public_plan_defaults_to_only_eligible_codex_without_writes(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    project = tmp_path / "plan-project"
    project.mkdir()
    (project / "A.sol").write_text("contract A {}\n", encoding="utf-8")
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["claude", "codex"])
    monkeypatch.setattr(front, "_ambient_backend", lambda _backends: "codex")
    monkeypatch.setattr(front, "_detect_language", lambda _target: "evm")
    monkeypatch.setattr(front, "estimate_cost", lambda *_a, **_k: {})

    plan = front._public_plan("core", [str(project)])

    assert plan["backend"] == "codex"
    assert plan["provider_invocations"] == 0
    assert plan["launchable"] is True
    assert "reduced host-process isolation" in plan["runtime_notice"]
    assert "supports local audits" in front._public_help_text("test")
    assert "cannot launch governed audits" not in front._public_help_text("test")
    assert not (project / ".scratchpad").exists()


def test_quick_check_uses_running_python_without_ambient_python_alias(
    monkeypatch,
) -> None:
    front = _load_front()
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["codex"])

    def find_bin(name, *_args):
        if name in {"python", "python3"}:
            return ""
        return f"/admitted/{name}"

    monkeypatch.setattr(front, "_find_bin", find_bin)

    assert Path(front.sys.executable).is_file()
    assert front._quick_check_required() is True


@pytest.mark.parametrize(
    "command,expected_code,expected_launches",
    (("start-config", 130, 1), ("resume", 130, 1)),
)
def test_ordinary_public_config_command_selects_internal_compat_abi_only(
    command, expected_code, expected_launches, tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    project = tmp_path / command
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text(
        json.dumps({
            "project_root": str(project), "scratchpad": str(scratchpad),
            "pipeline": "sc", "mode": "core", "language": "evm",
            "cli_backend": "codex",
        }),
        encoding="utf-8",
    )
    calls: list[tuple[list[str], dict[str, str]]] = []
    rendered: list[dict[str, object]] = []
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front.sys, "argv", ["plamen", command, str(config_path)])
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(front.console, "print", lambda *_a, **_k: None)
    monkeypatch.setattr(
        front, "_resume_startup_decision_destination",
        lambda *_a, **_k: scratchpad / "startup-decision.json",
    )

    def run(argv, *, env):
        calls.append((list(argv), dict(env)))
        return types.SimpleNamespace(returncode=130)

    def render(*_args, **kwargs):
        rendered.append(dict(kwargs))
        return 130

    monkeypatch.setattr(front.subprocess, "run", run)
    monkeypatch.setattr(front, "_render_driver_result", render)

    with pytest.raises(SystemExit) as stopped:
        front.main()

    assert stopped.value.code == expected_code
    assert "--posix-compat-v2" not in front.sys.argv
    assert len(calls) == expected_launches
    child_argv, child_env = calls[0]
    assert child_argv.count("--posix-compat-v2") == 1
    assert len(child_env["PLAMEN_STARTUP_DECISION_MAC_KEY"]) == 64
    assert len(rendered) == 1
    assert rendered[0]["decision_receipt_path"] == (
        scratchpad / "startup-decision.json"
    )
    assert isinstance(rendered[0]["decision_mac_key"], bytes)
    assert len(rendered[0]["decision_mac_key"]) == 32
    assert rendered[0]["posix_compat_v2"] is True


def test_macos_compat_help_describes_local_execution_assurance(
    monkeypatch,
) -> None:
    front = _load_front()
    stream = _TTY(False)
    _admit_compat(front, monkeypatch)
    monkeypatch.setattr(front.sys, "argv", ["plamen", "help"])
    monkeypatch.setattr(front.sys, "stdout", stream)
    monkeypatch.setattr(front, "show_banner", lambda: None)

    front.main()

    rendered = stream.text.casefold()
    assert "plamen resume" in rendered
    assert "plamen start-config" in rendered
    assert "plamen install" not in rendered
    assert "supports local audits with reduced host-process isolation" in rendered
    assert "does not provide native containment or native audit-completion receipts" in rendered
    assert "reinstall plamen with the native installer" not in rendered
    assert "--codex | --claude" not in rendered
    assert "reduced isolation" not in rendered
    assert "--claude-exec-mode headless" not in rendered
