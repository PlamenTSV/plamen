"""Proof-grade containment regressions for the public MCP server route."""

from __future__ import annotations

import ctypes
from concurrent.futures import ThreadPoolExecutor
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_installer():
    spec = importlib.util.spec_from_file_location(
        "plamen_mcp_public_containment_test", ROOT / "plamen.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    prior = sys.argv
    sys.argv = [str(ROOT / "plamen.py")]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = prior
    return module


INSTALLER = _load_installer()


def _selection(work: Path) -> dict:
    digest = {
        "receipt_sha256": "1" * 64,
        "census_sha256": "2" * 64,
        "request_sha256": "3" * 64,
        "generation_policy_sha256": "4" * 64,
    }
    return {
        "store_root": str(work / "store"),
        "generation_id": "5" * 64,
        **digest,
        "server_launches": {
            "memory": {
                "entrypoint": "schema-sanitizer.js",
                "environment_names": [],
                "node_args": ["--", "memory-server"],
                "cwd": str(work),
            }
        },
        "backend_launches": {},
    }


class _Runtime:
    RECEIPT_NAME = "generation-receipt.json"

    def __init__(self, generation_path: Path, launch):
        self._generation_path = generation_path
        self._launch = launch
        generation_path.mkdir(parents=True)
        (generation_path / self.RECEIPT_NAME).write_bytes(b"receipt")

    def validate_generation(self, *_args, **_kwargs):
        return SimpleNamespace(generation_path=self._generation_path)

    @staticmethod
    def _parse_receipt(_raw, _generation_id, _verifier):
        return {
            "authority": {
                "node_executable_authority": {
                    "canonical_path": str(Path(sys.executable).absolute()),
                },
                "generation_request": {"finalizer_policy": {}},
            }
        }

    @staticmethod
    def _request_from_authority(_authority):
        return object()

    @staticmethod
    def generation_policy_sha256(_request):
        return "4" * 64

    def launch_node_generation(self, *_args, **kwargs):
        return self._launch(**kwargs)


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    launch,
) -> tuple[dict, list[str]]:
    selection = _selection(tmp_path)
    runtime = _Runtime(tmp_path / "authenticated-generation", launch)
    monkeypatch.setattr(
        INSTALLER,
        "_validated_mcp_current_selection",
        lambda *, backend, **_kwargs: selection,
    )
    monkeypatch.setattr(
        INSTALLER,
        "_validated_committed_install_receipt",
        lambda: {"plamen_root": str(ROOT)},
    )
    monkeypatch.setattr(INSTALLER, "_mcp_runtime_module", lambda _root: runtime)
    monkeypatch.setattr(
        INSTALLER,
        "_mcp_receipt_callbacks",
        lambda _receipt: (None, lambda *_args: True, None, None),
    )
    argv = INSTALLER._mcp_launcher_args(
        selection, backend="claude", server="memory"
    )
    return selection, argv


def _python_launch(code: str, *arguments: str):
    def launch(*, popen_factory, base_env, cwd, **_kwargs):
        launch.environments.append(dict(base_env))
        return popen_factory(
            [sys.executable, "-c", code, *arguments],
            env=base_env,
            cwd=cwd,
        )

    launch.environments = []
    return launch


def _windows_pid_alive(pid: int) -> bool:
    synchronize = 0x00100000
    query_limited = 0x1000
    still_active = 259
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.GetExitCodeProcess.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(synchronize | query_limited, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_uint32()
        return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def _install_fake_linux_scope(
    monkeypatch: pytest.MonkeyPatch,
    events: list[object],
    *, wait_error: BaseException | None = None,
    close_error: BaseException | None = None,
    emergency_error: BaseException | None = None,
) -> None:
    original = importlib.util.spec_from_file_location

    class Process:
        pid = 4242

        def wait(self):
            events.append("wait")
            if wait_error is not None:
                raise wait_error
            return 0

    class Scope:
        def __init__(self, *, writable_roots, persistent_identity):
            events.append(("scope", tuple(writable_roots), persistent_identity))
            self.persistent_identity = persistent_identity
            self.attached = False
            self.closed = False
            self.population_zero_proven = False
            self.process_creation_state = "NOT_ATTEMPTED"

        @property
        def scope_capability(self):
            return _fake_linux_capability()

        @property
        def containment_evidence(self):
            return {
                "provider_owns_tree": True,
                "exhaustive_descendant_termination_authority": True,
                "write_confinement_proven": True,
                "population_zero_proven": self.population_zero_proven,
                "closed": self.closed,
            }

        @staticmethod
        def popen_kwargs():
            return {"start_new_session": True}

        @staticmethod
        def wrap_argv(command):
            return list(command)

        def create_process(self, _command, **_kwargs):
            events.append("create")
            self.process_creation_state = "PROCESS_CREATED"
            self.process = Process()
            return self.process

        def attach(self, process):
            assert process is self.process
            events.append("attach")
            self.attached = True
            self.process_creation_state = "ATTACHED"

        def terminate(self):
            events.append("terminate")

        def terminate_created_process(self):
            events.append("terminate-created")

        def close(self):
            events.append("close")
            if close_error is not None:
                raise close_error
            self.population_zero_proven = True
            self.closed = True

        def emergency_close(self):
            events.append("emergency")
            if emergency_error is not None:
                self.closed = True
                raise emergency_error
            self.population_zero_proven = True
            self.closed = True

    class Loader:
        @staticmethod
        def create_module(_spec):
            return None

        @staticmethod
        def exec_module(module):
            module.OwnedProcessScope = Scope
            module.process_tree_termination_capability = _fake_linux_capability
            module.mcp_linux_persistent_identity = lambda digest: (
                events.append(("identity", digest)) or "plamen-mcp-p1-s1-t1-" + digest[:24]
            )
            module.recover_stale_mcp_process_scopes = lambda: (
                events.append("recover-stale") or ()
            )
            module.recover_persisted_process_scope = lambda identity: (
                events.append(("recover", identity))
                or {"population_zero": True}
            )

    def replacement(name, location, *args, **kwargs):
        if Path(location).name == "owned_process_scope.py":
            return importlib.machinery.ModuleSpec(name, Loader())
        return original(name, location, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "spec_from_file_location", replacement)
    monkeypatch.setattr(INSTALLER.sys, "platform", "linux")


def _fake_linux_capability():
    return {
        "platform": "LINUX",
        "provider_owns_tree": True,
        "pre_execution_assignment": True,
        "termination_scope": "CGROUP_V2_SUBTREE",
        "population_zero_proof": "CGROUP_EVENTS_POPULATED_ZERO",
        "exhaustive_descendant_termination_authority": True,
        "exhaustive_write_confinement_authority": True,
    }


@pytest.mark.skipif(sys.platform != "win32", reason="requires a real Windows Job")
def test_mcp_public_route_kills_detached_grandchild_and_removes_private_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "grandchild.pid"
    grandchild = "import time; time.sleep(60)"
    parent = (
        "import pathlib,subprocess,sys;"
        "p=subprocess.Popen([sys.executable,'-c',sys.argv[2]],"
        "creationflags=0x00000008|0x00000200);"
        "pathlib.Path(sys.argv[1]).write_text(str(p.pid),encoding='ascii')"
    )
    launch = _python_launch(parent, str(pid_file), grandchild)
    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)

    assert INSTALLER._mcp_public_route(argv) == 0
    pid = int(pid_file.read_text(encoding="ascii"))
    deadline = time.monotonic() + 3.0
    while _windows_pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _windows_pid_alive(pid)
    assert len(launch.environments) == 1
    environment = launch.environments[0]
    assert environment["TEMP"] == environment["TMP"] == environment["TMPDIR"]
    assert not Path(environment["TEMP"]).exists()


@pytest.mark.skipif(sys.platform != "win32", reason="requires a real Windows Job")
def test_mcp_public_route_emergency_cleanup_preserves_primary_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}

    def launch(*, popen_factory, base_env, cwd, **_kwargs):
        observed["temp"] = base_env["TEMP"]
        process = popen_factory(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            env=base_env,
            cwd=cwd,
        )
        observed["pid"] = process.pid
        raise ValueError("primary launch failure")

    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    with pytest.raises(ValueError, match="primary launch failure"):
        INSTALLER._mcp_public_route(argv)
    pid = int(observed["pid"])
    deadline = time.monotonic() + 3.0
    while _windows_pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _windows_pid_alive(pid)
    assert not Path(str(observed["temp"])).exists()


@pytest.mark.skipif(sys.platform != "win32", reason="requires real parallel Jobs")
def test_two_mcp_public_routes_use_independent_job_and_temp_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launch = _python_launch("import time; time.sleep(0.1)")
    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: INSTALLER._mcp_public_route(argv), range(2)))
    assert results == [0, 0]
    roots = [row["TEMP"] for row in launch.environments]
    assert len(set(roots)) == 2
    assert all(not Path(root).exists() for root in roots)


def test_linux_wait_failure_uses_normal_whole_scope_cleanup_before_returning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[object] = []
    _install_fake_linux_scope(
        monkeypatch, events, wait_error=ValueError("injected wait failure"),
    )

    def launch(*, popen_factory, base_env, cwd, **_kwargs):
        events.append(("temp", base_env["TEMP"]))
        return popen_factory([sys.executable, "-c", "pass"], env=base_env, cwd=cwd)

    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    with pytest.raises(ValueError, match="injected wait failure"):
        INSTALLER._mcp_public_route(argv)
    assert "recover-stale" in events
    assert any(isinstance(row, tuple) and row[0] == "recover" for row in events)
    assert events.index("wait") < events.index("terminate") < events.index("close")
    assert "emergency" not in events
    temp = next(row[1] for row in events if isinstance(row, tuple) and row[0] == "temp")
    assert not Path(temp).exists()


def test_linux_close_failure_falls_back_to_emergency_without_masking_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[object] = []
    _install_fake_linux_scope(
        monkeypatch, events, close_error=OSError("injected close failure"),
    )

    def launch(*, popen_factory, base_env, cwd, **_kwargs):
        return popen_factory([sys.executable, "-c", "pass"], env=base_env, cwd=cwd)

    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    with pytest.raises(OSError, match="injected close failure"):
        INSTALLER._mcp_public_route(argv)
    assert events.count("terminate") >= 2
    assert events.count("close") >= 2
    assert events[-1] == "emergency"


def test_linux_unresolved_emergency_surfaces_recoverable_persistent_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[object] = []
    _install_fake_linux_scope(
        monkeypatch, events,
        close_error=OSError("injected close failure"),
        emergency_error=OSError("injected cgroup cleanup debt"),
    )

    def launch(*, popen_factory, base_env, cwd, **_kwargs):
        return popen_factory([sys.executable, "-c", "pass"], env=base_env, cwd=cwd)

    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    with pytest.raises(OSError, match="injected close failure") as captured:
        INSTALLER._mcp_public_route(argv)
    notes = getattr(captured.value, "__notes__", [])
    assert any("retained durable scope plamen-mcp-" in note for note in notes)
    assert any("injected cgroup cleanup debt" in note for note in notes)


def _supported_linux_scope_or_skip():
    if sys.platform != "linux":
        pytest.skip("requires Linux")
    scope = _load_scope_module_for_test()
    capability = scope.process_tree_termination_capability()
    if not (
        capability.get("termination_scope") == "CGROUP_V2_SUBTREE"
        and capability.get("exhaustive_descendant_termination_authority") is True
        and capability.get("exhaustive_write_confinement_authority") is True
    ):
        pytest.skip("requires delegated cgroup v2 and Landlock")
    return scope


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
def test_supported_linux_route_kills_detached_grandchild_after_wait_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supported_linux_scope_or_skip()
    observed = {}
    parent = (
        "import pathlib,subprocess,sys;"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
        "start_new_session=True);"
        "pathlib.Path(sys.argv[1]).write_text(str(p.pid),encoding='ascii')"
    )

    def launch(*, popen_factory, base_env, cwd, **_kwargs):
        pid_file = Path(base_env["TEMP"]) / "linux-grandchild.pid"
        actual = popen_factory(
            [sys.executable, "-c", parent, str(pid_file)], env=base_env, cwd=cwd,
        )

        class WaitFailure:
            def wait(self):
                deadline = time.monotonic() + 3.0
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                observed["pid"] = int(pid_file.read_text(encoding="ascii"))
                raise ValueError("injected wait failure")

        return WaitFailure()

    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    with pytest.raises(ValueError, match="injected wait failure"):
        INSTALLER._mcp_public_route(argv)
    pid = observed["pid"]
    deadline = time.monotonic() + 3.0
    while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not Path(f"/proc/{pid}").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
def test_supported_linux_route_recovers_same_thread_persisted_scope_before_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope_module = _supported_linux_scope_or_skip()
    selection = _selection(tmp_path)
    authority = json.dumps({
        "backend": "claude", "server": "memory",
        "store_root": selection["store_root"],
        "generation_id": selection["generation_id"],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    import hashlib
    identity = scope_module.mcp_linux_persistent_identity(
        hashlib.sha256(authority).hexdigest()
    )
    writable = tmp_path / "predecessor-temp"
    writable.mkdir()
    predecessor = scope_module.OwnedProcessScope(
        writable_roots=(writable,), persistent_identity=identity,
    )
    process = predecessor.create_process(
        predecessor.wrap_argv([sys.executable, "-c", "import time;time.sleep(60)"]),
        **predecessor.popen_kwargs(),
    )
    predecessor.attach(process)
    launch = _python_launch("pass")
    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    assert INSTALLER._mcp_public_route(argv) == 0
    process.wait(timeout=3)


@pytest.mark.parametrize("unsupported", ["darwin", "freebsd13"])
def test_unsupported_posix_mcp_route_fails_before_runtime_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsupported: str
) -> None:
    calls = []

    def launch(**_kwargs):
        calls.append("spawn")
        raise AssertionError("runtime launch must not be reached")

    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    monkeypatch.setattr(INSTALLER.sys, "platform", unsupported)
    with pytest.raises(RuntimeError, match="proof-grade Windows Job or Linux cgroup"):
        INSTALLER._mcp_public_route(argv)
    assert calls == []


def test_linux_without_exact_cgroup_authority_fails_before_runtime_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if sys.platform == "linux":
        capability = None
    else:
        # On Windows, changing sys.platform is sufficient for the route while
        # the exact module still truthfully reports its native Windows host.
        capability = "native-mismatch"
    calls = []

    def launch(**_kwargs):
        calls.append("spawn")
        raise AssertionError("runtime launch must not be reached")

    _selection_row, argv = _wire(monkeypatch, tmp_path, launch)
    if capability is None:
        scope = _load_scope_module_for_test()
        if (
            scope.process_tree_termination_capability().get(
                "exhaustive_descendant_termination_authority"
            )
            is True
        ):
            pytest.skip("host provides the exact delegated cgroup authority")
    else:
        monkeypatch.setattr(INSTALLER.sys, "platform", "linux")
    with pytest.raises(RuntimeError, match="delegated cgroup-v2"):
        INSTALLER._mcp_public_route(argv)
    assert calls == []


def test_linux_stale_scope_scan_recovers_dead_owner_but_preserves_live_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope = _load_scope_module_for_test()
    root = tmp_path / "delegated"
    root.mkdir()
    live = "plamen-mcp-p11-s101-t12-u102-" + "a" * 24
    dead = "plamen-mcp-p21-s201-t22-u202-" + "b" * 24
    (root / live).mkdir(); (root / dead).mkdir()
    monkeypatch.setattr(scope, "_host_platform", lambda: "LINUX")
    monkeypatch.setattr(scope, "_linux_delegated_cgroup_root", lambda: (root, None))

    def ticks(pid, tid=None):
        if pid == 11 and tid is None:
            return "101"
        if pid == 11 and tid == 12:
            return "102"
        return None

    recovered = []
    monkeypatch.setattr(scope, "_linux_task_start_ticks", ticks)
    monkeypatch.setattr(
        scope, "recover_persisted_process_scope",
        lambda identity, **_kwargs: (
            recovered.append(identity)
            or {"identity": identity, "population_zero": True}
        ),
    )
    result = scope.recover_stale_mcp_process_scopes()
    assert recovered == [dead]
    assert result == ({"identity": dead, "population_zero": True},)


def test_linux_concurrent_stale_scans_share_successful_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two public routes may discover and recover one dead cgroup together."""

    scope = _load_scope_module_for_test()
    root = tmp_path / "delegated"
    root.mkdir()
    dead = "plamen-mcp-p21-s201-t22-u202-" + "b" * 24
    cgroup = root / dead
    cgroup.mkdir()
    (cgroup / "cgroup.kill").write_text("", encoding="ascii")
    (cgroup / "cgroup.events").write_text("populated 0\n", encoding="ascii")
    monkeypatch.setattr(scope, "_host_platform", lambda: "LINUX")
    monkeypatch.setattr(scope, "_linux_delegated_cgroup_root", lambda: (root, None))
    monkeypatch.setattr(scope, "_linux_task_start_ticks", lambda *_args: None)

    scan_barrier = threading.Barrier(2)
    remove_barrier = threading.Barrier(2)
    remove_lock = threading.Lock()
    real_scandir = scope.os.scandir
    real_rmdir = scope.Path.rmdir

    def synchronized_scandir(path):
        iterator = real_scandir(path)
        if Path(path) == root:
            scan_barrier.wait(timeout=5)
        return iterator

    def synchronized_rmdir(path):
        if path == cgroup:
            remove_barrier.wait(timeout=5)
            # Real cgroup-v2 controls are virtual kernel files and do not make
            # rmdir report ENOTEMPTY. Model that property for this ordinary
            # temporary directory before forcing the competing rmdir calls.
            with remove_lock:
                if os.path.lexists(path):
                    for control in (path / "cgroup.kill", path / "cgroup.events"):
                        try:
                            control.unlink()
                        except FileNotFoundError:
                            pass
        return real_rmdir(path)

    monkeypatch.setattr(scope.os, "scandir", synchronized_scandir)
    monkeypatch.setattr(scope.Path, "rmdir", synchronized_rmdir)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _item: scope.recover_stale_mcp_process_scopes(),
                range(2),
            )
        )

    cleanup = sorted(result[0]["cleanup"] for result in results)
    assert cleanup == [
        "CGROUP_KILL_POPULATED_ZERO_REMOVE",
        "SCOPE_REMOVED_BY_CONCURRENT_RECOVERY",
    ]
    assert all(result[0]["population_zero"] is True for result in results)
    assert not os.path.lexists(cgroup)


def test_linux_recovery_rejects_scope_recreated_after_rmdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope = _load_scope_module_for_test()
    root = tmp_path / "delegated"; root.mkdir()
    identity = "plamen-mcp-p21-s201-t22-u202-" + "c" * 24
    cgroup = root / identity; cgroup.mkdir()
    (cgroup / "cgroup.kill").write_text("", encoding="ascii")
    (cgroup / "cgroup.events").write_text("populated 0\n", encoding="ascii")
    monkeypatch.setattr(scope, "_host_platform", lambda: "LINUX")
    monkeypatch.setattr(scope, "_linux_delegated_cgroup_root", lambda: (root, None))
    real_rmdir = scope.Path.rmdir

    def remove_then_recreate(path):
        if path == cgroup:
            for control in (path / "cgroup.kill", path / "cgroup.events"):
                control.unlink()
            real_rmdir(path)
            path.mkdir()
            return None
        return real_rmdir(path)

    monkeypatch.setattr(scope.Path, "rmdir", remove_then_recreate)
    with pytest.raises(scope.OwnedProcessScopeError, match="recreated"):
        scope.recover_persisted_process_scope(identity)


def test_linux_recovery_rejects_identity_swap_before_control_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope = _load_scope_module_for_test()
    root = tmp_path / "delegated"; root.mkdir()
    identity = "plamen-mcp-p21-s201-t22-u202-" + "d" * 24
    cgroup = root / identity; cgroup.mkdir()
    events = cgroup / "cgroup.events"
    kill = cgroup / "cgroup.kill"
    kill.write_text("", encoding="ascii")
    events.write_text("populated 0\n", encoding="ascii")
    monkeypatch.setattr(scope, "_host_platform", lambda: "LINUX")
    monkeypatch.setattr(scope, "_linux_delegated_cgroup_root", lambda: (root, None))
    real_is_file = scope.Path.is_file
    swapped = False

    def swap_on_control_probe(path):
        nonlocal swapped
        if path == events and not swapped:
            kill.unlink(); events.unlink(); cgroup.rmdir(); cgroup.mkdir()
            (cgroup / "cgroup.kill").write_text("", encoding="ascii")
            (cgroup / "cgroup.events").write_text("populated 0\n", encoding="ascii")
            swapped = True
        return real_is_file(path)

    monkeypatch.setattr(scope.Path, "is_file", swap_on_control_probe)
    with pytest.raises(scope.OwnedProcessScopeError, match="identity changed"):
        scope.recover_persisted_process_scope(identity)
    assert swapped is True


def _load_scope_module_for_test():
    spec = importlib.util.spec_from_file_location(
        "plamen_owned_scope_capability_test", ROOT / "scripts" / "owned_process_scope.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
