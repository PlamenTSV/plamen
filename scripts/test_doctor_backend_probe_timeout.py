"""Focused authenticated backend-health probe regressions."""

import ctypes
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(
        "plamen_doctor_backend_probe_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _authority(tmp_path: Path):
    row = {
        "execution_kind": "native",
        "relative_path": "payload/claude.exe",
        "version": "2.1.252",
        "size": 123,
        "sha256": "a" * 64,
        "member_authority": {"signed": "member"},
    }
    selection = {
        "store_root": str(tmp_path / "store"),
        "generation_id": "npm-" + "b" * 64,
        "receipt_sha256": "c" * 64,
        "census_sha256": "d" * 64,
        "request_sha256": "e" * 64,
        "generation_policy_sha256": "f" * 64,
        "backend_launches": {"claude": row, "codex": dict(row)},
    }
    return {
        "plamen_root": str(ROOT),
        "paths": {
            "claude": tmp_path / "plamen-claude.cmd",
            "codex": tmp_path / "plamen-codex.cmd",
        },
        "selection": selection,
    }


class _Runtime:
    def __init__(self, command):
        self.command = command
        self.calls = []

    def launch_generation_member(self, *args, **kwargs):
        self.calls.append((args, dict(kwargs)))
        popen_factory = kwargs.pop("popen_factory")
        forwarded = {
            key: kwargs[key]
            for key in ("stdin", "stdout", "stderr", "cwd")
        }
        return popen_factory(
            self.command,
            env=os.environ.copy(),
            **forwarded,
        )


class _FakeProcess:
    def __init__(self):
        self.args = ["selected-member"]
        self.returncode = 0
        self.pid = 4242
        self.wait_timeouts = []
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        return self.returncode

    def poll(self):
        return self.returncode


class _FakeScope:
    last = None

    def __init__(self, **_kwargs):
        type(self).last = self
        self.attached = False
        self.closed = False
        self.population_zero_proven = False
        self.process_creation_state = "NOT_ATTEMPTED"
        self.process = None

    def popen_kwargs(self):
        return {}

    def wrap_argv(self, command):
        return command

    def create_process(self, _command, **_kwargs):
        self.process_creation_state = "PROCESS_CREATED"
        self.process = _FakeProcess()
        return self.process

    def attach(self, _process):
        self.attached = True

    def terminate(self):
        return None

    def terminate_created_process(self):
        return None

    def close(self):
        self.closed = True
        self.population_zero_proven = True

    def emergency_close(self):
        self.close()


class _FakeScopeModule:
    OwnedProcessScope = _FakeScope

    @staticmethod
    def process_tree_termination_capability():
        return {"platform": "WINDOWS"}


def _patch_authority(monkeypatch, front, authority, runtime):
    selection_calls = []

    def selected(**kwargs):
        selection_calls.append(kwargs)
        return authority["selection"]

    monkeypatch.setattr(front, "_validated_mcp_current_selection", selected)
    monkeypatch.setattr(
        front,
        "_locked_backend_cli",
        lambda backend, _root, *, selection: authority["paths"][backend],
    )
    monkeypatch.setattr(
        front,
        "_validated_committed_install_receipt",
        lambda: {"plamen_root": str(ROOT)},
    )
    monkeypatch.setattr(front, "_mcp_runtime_module", lambda _root: runtime)
    verifier = object()
    monkeypatch.setattr(
        front,
        "_mcp_receipt_callbacks",
        lambda _receipt: (object(), verifier, "public", "key"),
    )
    return selection_calls, verifier


def test_direct_probe_uses_exact_selected_member_authority_and_not_public_shim(
    tmp_path, monkeypatch,
):
    front = _load_front()
    authority = _authority(tmp_path)
    runtime = _Runtime(
        [sys.executable, "-c", "import sys;sys.stdout.write('direct-member\\n')"]
    )
    selection_calls, verifier = _patch_authority(
        monkeypatch, front, authority, runtime,
    )

    result = front._run_authenticated_backend_member(
        authority, "claude", ("--version",), timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout.replace(b"\r\n", b"\n") == b"direct-member\n"
    assert result.stderr == b""
    assert selection_calls == [{
        "backend": "claude", "full_generation": False,
        "verify_generation_receipt": True,
    }]
    assert len(runtime.calls) == 1
    args, kwargs = runtime.calls[0]
    row = authority["selection"]["backend_launches"]["claude"]
    assert args == (
        authority["selection"]["store_root"],
        authority["selection"]["generation_id"],
        row["relative_path"],
    )
    assert kwargs["execution_kind"] == row["execution_kind"]
    assert kwargs["expected_size"] == row["size"]
    assert kwargs["expected_sha256"] == row["sha256"]
    assert kwargs["verifier"] is verifier
    assert kwargs["authenticated_member_authority"] is row["member_authority"]
    assert kwargs["member_args"] == ["--version"]
    assert kwargs["full_census"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
    assert os.fspath(authority["paths"]["claude"]) not in result.args


def test_direct_probe_refuses_launch_before_current_selection_and_shim_replay(
    tmp_path, monkeypatch,
):
    front = _load_front()
    authority = _authority(tmp_path)
    runtime = _Runtime([sys.executable, "-c", "raise SystemExit(99)"])
    _patch_authority(monkeypatch, front, authority, runtime)
    monkeypatch.setattr(
        front,
        "_validated_mcp_current_selection",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("selection differs")),
    )

    with pytest.raises(RuntimeError, match="selection differs"):
        front._run_authenticated_backend_member(
            authority, "claude", ("--version",), timeout=10,
        )

    assert runtime.calls == []


def test_slow_authority_replay_does_not_consume_member_deadline(
    tmp_path, monkeypatch,
):
    front = _load_front()
    authority = _authority(tmp_path)
    runtime = _Runtime(["selected-member"])
    _patch_authority(monkeypatch, front, authority, runtime)
    clock = {"now": 0.0}

    def selected(**_kwargs):
        clock["now"] = 50.0
        return authority["selection"]

    monkeypatch.setattr(front, "_validated_mcp_current_selection", selected)
    monkeypatch.setattr(front.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        front, "_backend_probe_scope_module", lambda _root: _FakeScopeModule,
    )

    result = front._run_authenticated_backend_member(
        authority, "claude", ("--version",), timeout=60,
    )

    assert result.returncode == 0
    assert runtime.calls
    assert _FakeScope.last.process.wait_timeouts == [0.05]


def test_authority_replay_over_budget_never_spawns_and_is_not_backend_timeout(
    tmp_path, monkeypatch,
):
    front = _load_front()
    authority = _authority(tmp_path)
    runtime = _Runtime(["selected-member"])
    _patch_authority(monkeypatch, front, authority, runtime)
    clock = {"now": 0.0}

    def selected(**_kwargs):
        clock["now"] = 61.0
        return authority["selection"]

    monkeypatch.setattr(front, "_validated_mcp_current_selection", selected)
    monkeypatch.setattr(front.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        front, "_backend_probe_scope_module", lambda _root: _FakeScopeModule,
    )

    with pytest.raises(RuntimeError, match="authority replay exceeded"):
        front._run_authenticated_backend_member(
            authority, "claude", ("--version",), timeout=60,
        )

    assert runtime.calls == []


def _pid_is_alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(0x00100000, False, pid)
    if not handle:
        return False
    try:
        return kernel32.WaitForSingleObject(handle, 0) == 258
    finally:
        kernel32.CloseHandle(handle)


def test_true_timeout_terminates_spawned_descendant(tmp_path, monkeypatch):
    front = _load_front()
    authority = _authority(tmp_path)
    child_pid = tmp_path / "child.pid"
    script = (
        "import pathlib,subprocess,sys,time;"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid));"
        "time.sleep(30)"
    )
    runtime = _Runtime([sys.executable, "-c", script])
    _patch_authority(monkeypatch, front, authority, runtime)

    with pytest.raises(subprocess.TimeoutExpired):
        front._run_authenticated_backend_member(
            authority, "claude", ("--version",), timeout=1.0,
        )

    assert child_pid.exists()
    pid = int(child_pid.read_text())
    deadline = time.monotonic() + 3
    while _pid_is_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _pid_is_alive(pid)


def test_direct_probe_rejects_output_beyond_bounded_stream(tmp_path, monkeypatch):
    front = _load_front()
    authority = _authority(tmp_path)
    runtime = _Runtime(
        [sys.executable, "-c", "import sys;sys.stdout.write('12345')"]
    )
    _patch_authority(monkeypatch, front, authority, runtime)
    monkeypatch.setattr(front, "_BACKEND_PROBE_OUTPUT_LIMIT_BYTES", 4)

    with pytest.raises(RuntimeError, match="stdout exceeds bound"):
        front._run_authenticated_backend_member(
            authority, "claude", ("--version",), timeout=10,
        )


def test_output_cap_immediately_terminates_spawned_descendant(
    tmp_path, monkeypatch,
):
    front = _load_front()
    authority = _authority(tmp_path)
    child_pid = tmp_path / "noisy-child.pid"
    script = (
        "import os,pathlib,subprocess,sys,time;"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        f"pathlib.Path({str(child_pid)!r}).write_text(str(p.pid));"
        "os.write(sys.stdout.fileno(),b'x'*65536);"
        "time.sleep(30)"
    )
    runtime = _Runtime([sys.executable, "-c", script])
    _patch_authority(monkeypatch, front, authority, runtime)
    monkeypatch.setattr(front, "_BACKEND_PROBE_OUTPUT_LIMIT_BYTES", 1024)

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="stdout exceeds bound"):
        front._run_authenticated_backend_member(
            authority, "claude", ("--version",), timeout=20,
        )
    assert time.monotonic() - started < 5

    assert child_pid.exists()
    pid = int(child_pid.read_text())
    deadline = time.monotonic() + 3
    while _pid_is_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _pid_is_alive(pid)


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    (
        (0, b"2.1.251 (Claude Code)\n", b""),
        (7, b"2.1.252 (Claude Code)\n", b""),
        (0, b"", b"2.1.252 (Claude Code)\n"),
        (0, b"2.1.252 (Claude Code) decorated\n", b""),
    ),
)
def test_doctor_rejects_nonexact_output_stderr_and_nonzero(
    tmp_path, monkeypatch, returncode, stdout, stderr,
):
    front = _load_front()
    authority = _authority(tmp_path)
    monkeypatch.setattr(
        front,
        "_run_authenticated_backend_member",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["direct-member"], returncode, stdout, stderr,
        ),
    )
    passed = []
    failed = []

    front._doctor_probe_backend_versions(
        authority,
        (("Claude", authority["paths"]["claude"], "2.1.252"),),
        ok=passed.append,
        fail=failed.append,
    )

    assert passed == []
    assert failed == ["Locked Claude version mismatch (expected 2.1.252)"]


def test_doctor_accepts_only_exact_direct_member_version(monkeypatch, tmp_path):
    front = _load_front()
    authority = _authority(tmp_path)
    observed = []

    def direct(managed, backend, member_args, *, timeout):
        observed.append((managed, backend, member_args, timeout))
        return subprocess.CompletedProcess(
            ["direct-member"], 0, b"2.1.252 (Claude Code)\n", b"",
        )

    monkeypatch.setattr(front, "_run_authenticated_backend_member", direct)
    passed = []
    failed = []

    front._doctor_probe_backend_versions(
        authority,
        (("Claude", authority["paths"]["claude"], "2.1.252"),),
        ok=passed.append,
        fail=failed.append,
    )

    assert observed == [(
        authority, "claude", ("--version",),
        front._DOCTOR_BACKEND_VERSION_PROBE_TIMEOUT_SECONDS,
    )]
    assert passed == [
        "Locked Claude selected resource closure and version 2.1.252"
    ]
    assert failed == []


def test_doctor_claude_auth_uses_same_direct_selected_member(monkeypatch, tmp_path):
    front = _load_front()
    authority = _authority(tmp_path)
    observed = []

    def direct(managed, backend, member_args, *, timeout):
        observed.append((managed, backend, member_args, timeout))
        return subprocess.CompletedProcess(
            ["direct-member"], 0, b'{"loggedIn":true}\n', b"",
        )

    monkeypatch.setattr(front, "_run_authenticated_backend_member", direct)

    assert front._doctor_authenticated_claude_status(authority) is True
    assert observed == [(
        authority, "claude", ("auth", "status", "--json"),
        front._DOCTOR_BACKEND_VERSION_PROBE_TIMEOUT_SECONDS,
    )]


@pytest.mark.parametrize("payload", (b"[]", b"true", b'"loggedIn"', b"7"))
def test_doctor_claude_auth_rejects_nonobject_json(
    monkeypatch, tmp_path, payload,
):
    front = _load_front()
    authority = _authority(tmp_path)
    monkeypatch.setattr(
        front,
        "_run_authenticated_backend_member",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["direct-member"], 0, payload, b"",
        ),
    )

    assert front._doctor_authenticated_claude_status(authority) is False
