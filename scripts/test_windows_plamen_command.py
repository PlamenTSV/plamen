"""Regression coverage for the public Windows ``plamen`` dispatcher."""

import importlib.util
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
import uuid
import zlib

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_windows_command_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _installed_tree(tmp_path: Path) -> tuple[Path, Path]:
    user_root = tmp_path / "user"
    plamen_root = user_root / ".plamen"
    plamen_root.mkdir(parents=True)
    (plamen_root / "plamen.py").write_text("# installed\n", encoding="utf-8")
    return user_root, plamen_root


def _secure_launcher_test_directory(front, directory: Path) -> None:
    directory.parent.mkdir(parents=True, exist_ok=True)
    if directory.exists():
        return
    if os.name == "nt":
        front._win_launcher_create_directory_secure(directory)
    else:
        directory.mkdir(mode=0o700)


def _authenticated_selection_fixture(front, user_root: Path, monkeypatch):
    """Install the already-validated selection boundary used by shim tests."""
    digest = "a" * 64
    member = lambda backend: {
        "authority": {
            "schema": "plamen.mcp_generation_member_authority.v1",
            "backend": backend,
            "generation_id": "npm-" + "1" * 64,
            "receipt_sha256": "2" * 64,
            "census_sha256": "3" * 64,
            "request_sha256": "4" * 64,
            "generation_policy_sha256": "5" * 64,
        },
        "authentication": {
            "scheme": "ed25519", "key_id": "6" * 64,
            "signature": "7" * 128,
        },
    }
    selection = {
        "schema": front._MCP_SELECTION_SCHEMA,
        "store_root": str(user_root / ".local" / "share" / "plamen" / "mcp-runtime"),
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64,
        "census_sha256": "3" * 64,
        "request_sha256": "4" * 64,
        "generation_policy_sha256": "5" * 64,
        "receipt_key_id": "6" * 64,
        "receipt_public_key": "8" * 64,
        "install_transaction_id": "9" * 32,
        "install_receipt_sha256": digest,
        "install_source_manifest_sha256": digest,
        "install_runtime_manifest_sha256": digest,
        "install_adapter_manifest_sha256": digest,
        "server_launches": {"memory": {
            "entrypoint": "schema-sanitizer.js", "node_args": [],
            "cwd": None, "environment_names": [],
        }},
        "backend_launches": {
            "claude": {
                "execution_kind": "native",
                "relative_path": "node_modules/@anthropic-ai/claude-code/bin/claude.exe",
                "version": "2.1.252", "size": 1, "sha256": digest,
                "member_authority": member("claude"),
            },
            "codex": {
                "execution_kind": "native",
                "relative_path": (
                    "node_modules/@openai/codex-win32-x64/vendor/"
                    "x86_64-pc-windows-msvc/bin/codex.exe"
                ),
                "version": "0.152.0", "size": 1, "sha256": digest,
                "member_authority": member("codex"),
            },
        },
        "backend_acquisition_policy_sha256": "c" * 64,
        "backend_receipts": {"claude": {"signed": True}, "codex": {"signed": True}},
        "signature": "b" * 128,
    }
    assert set(selection) == front._MCP_SELECTION_FIELDS
    admissions = []

    def validated(**kwargs):
        admissions.append(kwargs)
        assert kwargs == {"backend": "codex", "full_generation": False}
        return selection

    suffix = ".cmd" if sys.platform == "win32" else ""
    paths = {
        backend: user_root / ".local" / "bin" / f"plamen-{backend}{suffix}"
        for backend in ("claude", "codex")
    }
    monkeypatch.setattr(front, "_validated_mcp_current_selection", validated)
    monkeypatch.setattr(front, "_backend_shim_path", lambda backend: paths[backend])
    return selection, paths, admissions


def _assert_authenticated_backend_shim(path: Path, backend: str, selection) -> None:
    raw = path.read_bytes()
    assert b"authenticated immutable backend launcher" in raw
    assert b"backend-launch" in raw
    backend_binding = (
        f'"--backend" "{backend}"'.encode()
        if raw.startswith(b"@echo off\r\n")
        else f"--backend {backend}".encode()
    )
    assert backend_binding in raw
    for value in (
        selection["generation_id"], selection["receipt_sha256"],
        selection["census_sha256"], selection["request_sha256"],
        selection["generation_policy_sha256"],
    ):
        assert value.encode() in raw
    assert b"node_modules" not in raw and b"mcp-packages" not in raw


def _run_bound_source_bootstrap(front, target, *, identity=None, release=None, args=()):
    identity = identity or front._windows_bound_source_identity(target)
    encoded_target = base64.b64encode(os.fsencode(str(Path(target).absolute()))).decode()
    encoded_release = (
        base64.b64encode(os.fsencode(str(Path(release).absolute()))).decode()
        if release is not None else "-"
    )
    return subprocess.run(
        [
            sys.executable, "-I", "-B", "-c",
            front._WINDOWS_BOUND_SOURCE_BOOTSTRAP,
            encoded_target,
            "-" if release is not None else identity["sha256"],
            "0" if release is not None else str(identity["size"]),
            encoded_release,
            *args,
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=10,
    )


def test_mcp_runtime_module_is_loaded_lazily_and_root_bound(tmp_path):
    front = _load_front()
    runtime_root = tmp_path / "runtime"
    module_path = runtime_root / "scripts" / "plamen_mcp_runtime.py"
    module_path.parent.mkdir(parents=True)
    module_path.write_text("RUNTIME_SENTINEL = 17\n", encoding="utf-8")
    module_name = "_plamen_authenticated_mcp_runtime"
    prior = sys.modules.pop(module_name, None)
    try:
        loaded = front._mcp_runtime_module(runtime_root)
        assert loaded.RUNTIME_SENTINEL == 17
        assert Path(loaded.__file__).absolute() == module_path.absolute()
        assert front._mcp_runtime_module(runtime_root) is loaded
        with pytest.raises(RuntimeError, match="authority root changed"):
            front._mcp_runtime_module(tmp_path / "different-runtime")
    finally:
        sys.modules.pop(module_name, None)
        if prior is not None:
            sys.modules[module_name] = prior


def test_mcp_runtime_module_import_failure_does_not_cache_partial_module(tmp_path):
    front = _load_front()
    module_path = tmp_path / "scripts" / "plamen_mcp_runtime.py"
    module_path.parent.mkdir(parents=True)
    module_path.write_text("raise RuntimeError('incomplete runtime')\n", encoding="utf-8")
    module_name = "_plamen_authenticated_mcp_runtime"
    prior = sys.modules.pop(module_name, None)
    try:
        with pytest.raises(RuntimeError, match="incomplete runtime"):
            front._mcp_runtime_module(tmp_path)
        assert front._MCP_RUNTIME_MODULE is None
        assert module_name not in sys.modules
    finally:
        sys.modules.pop(module_name, None)
        if prior is not None:
            sys.modules[module_name] = prior


@pytest.mark.parametrize("machine", ["", "i686", "riscv64", "sparc64"])
def test_backend_platform_name_rejects_unknown_architecture(monkeypatch, machine):
    front = _load_front()
    monkeypatch.setattr(front.platform, "machine", lambda: machine)
    with pytest.raises(RuntimeError, match="unsupported on this architecture"):
        front._backend_platform_name()


def test_install_command_argv_preserves_metacharacter_paths_without_shell(monkeypatch):
    front = _load_front()
    checkout = r"C:\source & echo PWNED ^ %TEMP% (release)"
    command = [
        "git", "-C", checkout, "submodule", "update", "--init", "--recursive",
    ]
    calls = []
    monkeypatch.setattr(front, "_find_bin", lambda name, _paths=None: "/managed/" + name)
    monkeypatch.setattr(
        front.subprocess, "run",
        lambda argv, **kwargs: (
            calls.append((argv, kwargs))
            or type("Result", (), {"returncode": 0})()
        ),
    )

    assert front._run_install_cmd(command, retries=1) is True
    assert calls == [([
        "/managed/git", *command[1:],
    ], {"timeout": None, "cwd": None, "shell": False})]


def test_install_command_rejects_shell_form_without_execution(monkeypatch):
    front = _load_front()
    calls = []
    monkeypatch.setattr(
        front.subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    assert front._run_install_cmd("git -C safe && echo PWNED") is False
    assert calls == []


def test_package_install_commands_are_argv_only_and_path_persistence_is_deferred():
    front = _load_front()
    dependency_source = inspect.getsource(front._setup_python_deps)
    install_source = inspect.getsource(front.run_install)
    assert "[*pip_base, \"-r\", path]" in dependency_source
    assert "git\", \"-C\", str(PLAMEN_HOME)" in install_source
    assert "_update_path_env(path_persistence_dirs, persist=False)" in install_source
    persistence = install_source.rindex(
        "_update_path_env(path_persistence_dirs, persist=True)"
    )
    failure_gate = install_source.index('Rule(title="INSTALL INCOMPLETE"')
    assert persistence > failure_gate


def test_atomic_write_preserves_mode_and_flushes_parent(tmp_path, monkeypatch):
    front = _load_front()
    target = tmp_path / "settings.json"
    target.write_bytes(b"old\n")
    target.chmod(0o600)
    flushed = []
    monkeypatch.setattr(
        front, "_claude_projection_fsync_parent",
        lambda path: flushed.append(Path(path)),
    )

    front._atomic_write_bytes(target, b"new\n")

    assert target.read_bytes() == b"new\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert flushed == [target.absolute()]


def test_atomic_write_rejects_stale_preimage_without_overwriting_it(
    tmp_path, monkeypatch,
):
    front = _load_front()
    target = tmp_path / "settings.json"
    target.write_bytes(b"admitted\n")
    target.chmod(0o600)
    real_fsync = front.os.fsync
    fired = False

    def race_after_stage(descriptor):
        nonlocal fired
        real_fsync(descriptor)
        if not fired:
            fired = True
            target.write_bytes(b"foreign concurrent update\n")

    monkeypatch.setattr(front.os, "fsync", race_after_stage)
    with pytest.raises(RuntimeError, match="changed before replacement"):
        front._atomic_write_bytes(target, b"plamen successor\n")
    assert fired
    assert target.read_bytes() == b"foreign concurrent update\n"


def test_bound_source_bootstrap_executes_only_descriptor_authenticated_bytes(tmp_path):
    front = _load_front()
    target = tmp_path / "entry.py"
    target.write_text("import json,sys;print(json.dumps(sys.argv))\n", encoding="utf-8")
    identity = front._windows_bound_source_identity(target)

    accepted = _run_bound_source_bootstrap(
        front, target, identity=identity, args=("alpha", "two words"),
    )
    assert accepted.returncode == 0
    assert json.loads(accepted.stdout) == [str(target.absolute()), "alpha", "two words"]
    assert accepted.stderr == ""

    target.write_text("raise SystemExit('tampered source ran')\n", encoding="utf-8")
    denied = _run_bound_source_bootstrap(front, target, identity=identity)
    assert denied.returncode != 0
    assert "source bytes differ from the installed release authority" in denied.stderr
    assert "tampered source ran" not in denied.stderr


def test_bound_source_bootstrap_rejects_symlinked_source_path(tmp_path):
    front = _load_front()
    target = tmp_path / "entry.py"
    target.write_text("print('must not run')\n", encoding="utf-8")
    identity = front._windows_bound_source_identity(target)
    link = tmp_path / "linked.py"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    denied = _run_bound_source_bootstrap(front, link, identity=identity)
    assert denied.returncode != 0
    assert "source path is indirect" in denied.stderr
    assert "must not run" not in denied.stdout


def test_release_bound_launcher_bytes_stay_stable_across_package_update(tmp_path):
    front = _load_front()
    target = tmp_path / "plamen.py"
    release = tmp_path / front._WINDOWS_RELEASE_AUTHORITY_NAME
    target.write_text("VERSION = 1\n", encoding="utf-8")
    before = front._windows_bound_source_command(
        sys.executable, target, release_path=release,
    )
    target.write_text("VERSION = 2\n", encoding="utf-8")
    after = front._windows_bound_source_command(
        sys.executable, target, release_path=release,
    )
    assert before == after
    assert '"-" "0"' in after


def test_release_authority_makes_all_update_domains_launch_preconditions(tmp_path):
    front = _load_front()
    target = tmp_path / "entry.py"
    target.write_text("print('release accepted')\n", encoding="utf-8")
    identity = front._windows_bound_source_identity(target)
    artifacts = []
    for name in (
        "python.exe", "package-receipt.json", "mcp-selection.json", "config.toml",
    ):
        artifact = tmp_path / name
        artifact.write_text(name + "\n", encoding="utf-8")
        row = front._windows_release_artifact_identity(artifact, name)
        row["path"] = str(artifact.absolute())
        artifacts.append(row)
    release = tmp_path / front._WINDOWS_RELEASE_AUTHORITY_NAME
    release_value = {
        "artifacts": artifacts,
        "entry_point": {
            key: identity[key] for key in ("path", "sha256", "size")
        },
        "schema": front._WINDOWS_RELEASE_AUTHORITY_SCHEMA,
        "selection": {
            "generation_id": "npm-" + "1" * 64,
            "receipt_sha256": "2" * 64,
            "census_sha256": "3" * 64,
            "request_sha256": "4" * 64,
            "generation_policy_sha256": "5" * 64,
        },
    }
    release_value["entry_point"]["path"] = str(target.absolute())
    release.write_bytes((
        json.dumps(release_value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode())

    accepted = _run_bound_source_bootstrap(front, target, release=release)
    assert accepted.returncode == 0
    assert accepted.stdout == "release accepted\n"

    (tmp_path / "config.toml").write_text("partial update\n", encoding="utf-8")
    denied = _run_bound_source_bootstrap(front, target, release=release)
    assert denied.returncode != 0
    assert "release artifact bytes differ" in denied.stderr
    assert "release accepted" not in denied.stdout


def test_execution_path_authority_rejects_junction_or_symlink_spelling(tmp_path):
    front = _load_front()
    target = tmp_path / "python.exe"
    target.write_bytes(b"MZ")
    linked = tmp_path / "runtime-python.exe"
    try:
        linked.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(RuntimeError, match="ancestry is indirect"):
        front._windows_launcher_execution_path_authority(
            linked, "interpreter",
        )


def test_release_and_three_launchers_publish_as_one_recoverable_transaction(
    tmp_path,
):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_launcher_test_directory(front, directory)
    rows = []
    for label in ("release", "claude", "codex", "public"):
        path = directory / (label + (".json" if label == "release" else ".cmd"))
        rows.append({
            "label": label,
            "path": path,
            "raw": (label + "-successor\n").encode(),
            "state": front._launcher_absent_state(path),
            "admitted_predecessor_raws": (),
        })
    selection = {
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64,
        "census_sha256": "3" * 64,
        "request_sha256": "4" * 64,
        "generation_policy_sha256": "5" * 64,
    }

    assert front._launcher_transaction_publish_locked(
        directory, rows, selection,
    ) == "COMMITTED"
    assert all(row["path"].read_bytes() == row["raw"] for row in rows)
    assert not (directory / ".plamen-launcher-transaction.json").exists()


def test_four_artifact_release_transaction_recovers_after_process_death(
    tmp_path, monkeypatch,
):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_launcher_test_directory(front, directory)
    rows = []
    for label in ("release", "claude", "codex", "public"):
        path = directory / (label + (".json" if label == "release" else ".cmd"))
        rows.append({
            "label": label,
            "path": path,
            "raw": (label + "-successor\n").encode(),
            "state": front._launcher_absent_state(path),
            "admitted_predecessor_raws": (),
        })
    selection = {
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64,
        "census_sha256": "3" * 64,
        "request_sha256": "4" * 64,
        "generation_policy_sha256": "5" * 64,
    }
    real_rename = front._launcher_transaction_rename
    real_recover = front._launcher_transaction_recover

    class ProcessDeath(BaseException):
        pass

    fired = False

    def die_after_codex_publish(guard, source, destination, *args, **kwargs):
        nonlocal fired
        result = real_rename(guard, source, destination, *args, **kwargs)
        if Path(source).name.endswith("-codex.stage") and not fired:
            fired = True
            raise ProcessDeath("power loss after codex publication")
        return result

    monkeypatch.setattr(front, "_launcher_transaction_rename", die_after_codex_publish)
    monkeypatch.setattr(
        front, "_launcher_transaction_recover",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ProcessDeath("process exited before recovery")
        ),
    )
    with pytest.raises(ProcessDeath):
        front._launcher_transaction_publish_locked(directory, rows, selection)
    assert fired
    assert (directory / ".plamen-launcher-transaction.json").is_file()

    monkeypatch.setattr(front, "_launcher_transaction_rename", real_rename)
    monkeypatch.setattr(front, "_launcher_transaction_recover", real_recover)
    assert front._launcher_transaction_publish_locked(
        directory, rows, selection,
    ) == "RECOVERED"
    assert all(not os.path.lexists(row["path"]) for row in rows)
    assert not (directory / ".plamen-launcher-transaction.json").exists()

    assert front._launcher_transaction_publish_locked(
        directory, rows, selection,
    ) == "COMMITTED"
    assert all(row["path"].read_bytes() == row["raw"] for row in rows)
    assert not (directory / ".plamen-launcher-transaction.json").exists()


def test_release_authority_binds_package_cache_dependency_mcp_and_config(
    tmp_path, monkeypatch,
):
    front = _load_front()
    installed = tmp_path / ".plamen"
    codex_root = tmp_path / ".codex"
    store_root = tmp_path / "mcp-runtime"
    transaction_id = "9" * 32
    installed.mkdir(); codex_root.mkdir(); store_root.mkdir()
    target = installed / "plamen.py"
    target.write_text("print('installed')\n", encoding="utf-8")
    receipt = codex_root / front._CODEX_INSTALL_RECEIPT
    config = codex_root / "config.toml"
    selection_path = store_root / "current-selection.json"
    runtime_stamp = tmp_path / "python-runtime.stamp.json"
    cache = (
        codex_root / ".plamen-install-transactions" / transaction_id
        / "source-cache.json"
    )
    cache.parent.mkdir(parents=True)
    for path in (receipt, config, selection_path, runtime_stamp, cache):
        path.write_text(path.name + "\n", encoding="utf-8")
    committed = {
        "transaction_id": transaction_id,
        "source_root": str(tmp_path / "source"),
        "plamen_root": str(installed),
        "codex_root": str(codex_root),
    }
    selection = {
        "store_root": str(store_root),
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64,
        "census_sha256": "3" * 64,
        "request_sha256": "4" * 64,
        "generation_policy_sha256": "5" * 64,
    }
    monkeypatch.setattr(
        front, "_validated_committed_install_receipt", lambda: committed,
    )
    monkeypatch.setattr(front, "_runtime_stamp_path", lambda: runtime_stamp)

    raw = front._windows_release_authority_bytes(
        installed, sys.executable,
        front._windows_bound_source_identity(target), selection,
    )
    value = json.loads(raw)
    names = {front.PureWindowsPath(row["path"]).name for row in value["artifacts"]}
    assert names == {
        Path(sys.executable).resolve().name,
        front._CODEX_INSTALL_RECEIPT,
        "current-selection.json",
        "config.toml",
        runtime_stamp.name,
        "source-cache.json",
    }
    assert value["selection"] == {
        key: selection[key]
        for key in front._LAUNCHER_TRANSACTION_SELECTION_FIELDS
    }
    assert raw == (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def test_prior_secure_backend_shim_is_admitted_only_by_retained_generation(
    tmp_path, monkeypatch,
):
    front = _load_front()
    plamen_root = tmp_path / ".plamen"
    plamen_root.mkdir()
    (plamen_root / "plamen.py").write_text("print('prior')\n", encoding="utf-8")
    command_dir = tmp_path / "bin"
    command_dir.mkdir()
    monkeypatch.setattr(front.sys, "platform", "win32")
    monkeypatch.setattr(
        front, "_backend_shim_path",
        lambda backend: command_dir / f"plamen-{backend}.cmd",
    )
    prior = {
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64,
        "census_sha256": "3" * 64,
        "request_sha256": "1" * 64,
        "generation_policy_sha256": "4" * 64,
        "backend_launches": {"claude": {}, "codex": {}},
    }
    release_path = command_dir / front._WINDOWS_RELEASE_AUTHORITY_NAME
    raw = front._backend_shim_bytes(
        "codex", plamen_root, sys.executable, selection=prior,
        platform_name="win32", release_path=release_path,
    )
    monkeypatch.setattr(
        front, "_validated_committed_install_receipt",
        lambda: {"plamen_root": str(plamen_root)},
    )
    verifier = object()
    monkeypatch.setattr(
        front, "_mcp_receipt_callbacks",
        lambda _committed: (None, verifier, None, None),
    )
    calls = []

    class Runtime:
        @staticmethod
        def validate_generation_authority_fast(*args, **kwargs):
            calls.append((args, kwargs))

    monkeypatch.setattr(front, "_mcp_runtime_module", lambda _root: Runtime)
    assert front._authenticated_retained_backend_shim(
        raw, backend="codex", plamen_root=plamen_root,
        interpreter=sys.executable, store_root=tmp_path / "store",
    ) is True
    assert calls and calls[0][0][1] == prior["generation_id"]
    assert front._authenticated_retained_backend_shim(
        raw.replace(b'"--" %*', b'"--" "forged" %*'),
        backend="codex", plamen_root=plamen_root,
        interpreter=sys.executable, store_root=tmp_path / "store",
    ) is False


def test_windows_command_is_created_with_current_runtime_path(tmp_path, monkeypatch):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )

    command = front._ensure_windows_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="win32",
    )

    assert command == user_root / ".local" / "bin" / "plamen.cmd"
    expected = front._windows_plamen_command_bytes(
        sys.executable, plamen_root / "plamen.py", shims["claude"], shims["codex"],
    )
    assert command.read_bytes() == expected
    assert str(Path(sys.executable).resolve()).encode() in command.read_bytes()
    assert b"\npython " not in command.read_bytes().lower()
    assert base64.b64encode(
        os.fsencode(str(front.PureWindowsPath((plamen_root / "plamen.py").resolve())))
    ) in command.read_bytes()
    assert b".claude\\plamen.py" not in command.read_bytes()
    assert b" -I -B -c " in command.read_bytes()
    assert b"zlib.decompress" in command.read_bytes()
    assert all(
        len(line.decode("utf-8")) <= front._WINDOWS_CMD_LINE_MAX_CHARS
        for line in command.read_bytes().splitlines()
    )
    assert hashlib.sha256((plamen_root / "plamen.py").read_bytes()).hexdigest().encode() in command.read_bytes()
    packed = re.search(
        rb"zlib\.decompress\(base64\.b64decode\('([A-Za-z0-9+/=]+)'\)\)",
        command.read_bytes(),
    )
    assert packed is not None
    assert zlib.decompress(base64.b64decode(packed.group(1))).decode("ascii") == (
        front._WINDOWS_BOUND_SOURCE_BOOTSTRAP
    )
    _assert_authenticated_backend_shim(shims["claude"], "claude", selection)
    _assert_authenticated_backend_shim(shims["codex"], "codex", selection)
    assert admissions == [
        {"backend": "codex", "full_generation": False},
    ] * 3


def test_windows_command_exports_locked_claude_runtime(tmp_path, monkeypatch):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )

    command = front._ensure_windows_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="win32",
    )

    assert f'set "CLAUDE_BIN={shims["claude"].resolve()}"'.encode() in command.read_bytes()
    _assert_authenticated_backend_shim(shims["claude"], "claude", selection)


def test_windows_command_exports_locked_codex_runtime(tmp_path, monkeypatch):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )

    command = front._ensure_windows_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="win32",
    )

    assert f'set "CODEX_BIN={shims["codex"].absolute()}"'.encode() in command.read_bytes()
    _assert_authenticated_backend_shim(shims["codex"], "codex", selection)


def test_legacy_claude_dispatcher_is_atomically_repaired_and_idempotent(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    command.write_bytes(
        b'@echo off\r\npython "%USERPROFILE%\\.claude\\plamen.py" %*\r\n'
    )

    repaired = front._ensure_windows_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="win32",
    )
    before = repaired.stat().st_mtime_ns
    front._ensure_windows_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="win32",
    )

    assert repaired.read_bytes() == front._windows_plamen_command_bytes(
        sys.executable, plamen_root / "plamen.py", shims["claude"], shims["codex"],
    )
    assert repaired.stat().st_mtime_ns == before
    assert not list(repaired.parent.glob(".plamen.cmd.*.tmp"))


def test_exact_path_bound_predecessor_launcher_is_repaired(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    predecessors = front._legacy_windows_plamen_command_bytes(
        sys.executable, plamen_root / "plamen.py", plamen_root,
    )
    prior = next(
        raw for raw in predecessors
        if b"CLAUDE_BIN=" in raw and b"CODEX_BIN=" in raw
    )
    command.write_bytes(prior)

    repaired = front._ensure_windows_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="win32",
    )

    assert repaired.read_bytes() == front._windows_plamen_command_bytes(
        sys.executable, plamen_root / "plamen.py", shims["claude"], shims["codex"],
    )


def test_exact_live_authenticated_shim_predecessors_migrate_to_bytecode_safe(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    for backend, path in shims.items():
        path.write_bytes(front._backend_shim_bytes(
            backend,
            plamen_root,
            sys.executable,
            selection=selection,
            suppress_bytecode=False,
            platform_name="win32",
        ))
    command.write_bytes(front._windows_plamen_command_bytes(
        sys.executable,
        plamen_root / "plamen.py",
        shims["claude"],
        shims["codex"],
        allow_unpublished_backend_shims=True,
        suppress_bytecode=False,
    ))

    front._ensure_windows_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="win32",
    )

    assert command.read_bytes() == front._windows_plamen_command_bytes(
        sys.executable, plamen_root / "plamen.py", shims["claude"], shims["codex"],
    )
    for backend, path in shims.items():
        assert path.read_bytes() == front._backend_shim_bytes(
            backend, plamen_root, sys.executable, selection=selection,
            platform_name="win32",
        )
        assert b" -B " in path.read_bytes()
    assert b" -B " in command.read_bytes()


@pytest.mark.parametrize("seam", [
    "take-claude", "publish-claude", "take-codex", "publish-codex",
    "take-public", "publish-public",
])
def test_three_launcher_transaction_recovers_after_each_legacy_seam(
    tmp_path, monkeypatch, seam,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, _ = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    for backend, path in shims.items():
        path.write_bytes(front._backend_shim_bytes(
            backend, plamen_root, sys.executable, selection=selection,
            suppress_bytecode=False,
            platform_name="win32",
        ))
    command.write_bytes(front._windows_plamen_command_bytes(
        sys.executable, plamen_root / "plamen.py", shims["claude"],
        shims["codex"], allow_unpublished_backend_shims=True,
        suppress_bytecode=False,
    ))
    real_rename = front._launcher_transaction_rename
    real_recover = front._launcher_transaction_recover

    class HardKill(BaseException):
        pass

    fired = False

    def kill_at_seam(guard, source, destination, *args, **kwargs):
        nonlocal fired
        result = real_rename(guard, source, destination, *args, **kwargs)
        source_name = Path(source).name
        destination_name = Path(destination).name
        observed = None
        for label in ("claude", "codex", "public"):
            if destination_name.endswith(f"-{label}.backup"):
                observed = f"take-{label}"
            if source_name.endswith(f"-{label}.stage"):
                observed = f"publish-{label}"
        if observed == seam and not fired:
            fired = True
            raise HardKill(seam)
        return result

    monkeypatch.setattr(front, "_launcher_transaction_rename", kill_at_seam)
    monkeypatch.setattr(
        front, "_launcher_transaction_recover",
        lambda *args, **kwargs: (_ for _ in ()).throw(HardKill("process exited")),
    )
    with pytest.raises(HardKill):
        front._ensure_windows_plamen_command(
            user_root=user_root, plamen_root=plamen_root, platform_name="win32",
        )
    assert fired
    monkeypatch.setattr(front, "_launcher_transaction_rename", real_rename)
    monkeypatch.setattr(front, "_launcher_transaction_recover", real_recover)

    front._ensure_windows_plamen_command(
        user_root=user_root, plamen_root=plamen_root, platform_name="win32",
    )
    assert b" -B " in command.read_bytes()
    assert all(b" -B " in path.read_bytes() for path in shims.values())
    assert not (command.parent / ".plamen-launcher-transaction.json").exists()


@pytest.mark.parametrize("seam", [
    "publish-claude", "publish-codex", "publish-public",
])
def test_three_absent_launchers_recover_after_each_publish(
    tmp_path, monkeypatch, seam,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _ = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    real_rename = front._launcher_transaction_rename
    real_recover = front._launcher_transaction_recover

    class HardKill(BaseException):
        pass

    fired = False

    def kill_at_publish(guard, source, destination, *args, **kwargs):
        nonlocal fired
        result = real_rename(guard, source, destination, *args, **kwargs)
        source_name = Path(source).name
        for label in ("claude", "codex", "public"):
            if source_name.endswith(f"-{label}.stage") and seam == f"publish-{label}":
                fired = True
                raise HardKill(seam)
        return result

    monkeypatch.setattr(front, "_launcher_transaction_rename", kill_at_publish)
    monkeypatch.setattr(
        front, "_launcher_transaction_recover",
        lambda *args, **kwargs: (_ for _ in ()).throw(HardKill("process exited")),
    )
    with pytest.raises(HardKill):
        front._ensure_windows_plamen_command(
            user_root=user_root, plamen_root=plamen_root, platform_name="win32",
        )
    assert fired
    monkeypatch.setattr(front, "_launcher_transaction_rename", real_rename)
    monkeypatch.setattr(front, "_launcher_transaction_recover", real_recover)
    command = front._ensure_windows_plamen_command(
        user_root=user_root, plamen_root=plamen_root, platform_name="win32",
    )
    assert command.is_file() and all(path.is_file() for path in shims.values())
    assert not (command.parent / ".plamen-launcher-transaction.json").exists()


def test_command_directory_symlink_never_creates_or_writes_outside_user_root(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    outside = tmp_path / "foreign"
    outside.mkdir()
    try:
        os.symlink(outside, user_root / ".local", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")
    _authenticated_selection_fixture(front, user_root, monkeypatch)

    with pytest.raises(RuntimeError, match="directory component is indirect"):
        front._ensure_windows_plamen_command(
            user_root=user_root, plamen_root=plamen_root, platform_name="win32",
        )

    assert not (outside / "bin").exists()
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("variant", [
    "reordered", "forged-public-predecessor", "forged-backend-predecessor",
])
def test_forged_launcher_transaction_journal_is_rejected(
    tmp_path, monkeypatch, variant,
):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_launcher_test_directory(front, directory)
    selection = {
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64,
        "census_sha256": "3" * 64,
        "request_sha256": "4" * 64,
        "generation_policy_sha256": "5" * 64,
    }
    rows = []
    for label in ("claude", "codex", "public"):
        path = directory / (label + ".cmd")
        rows.append({
            "label": label, "path": path, "raw": (label + "-new").encode(),
            "state": front._launcher_absent_state(path),
            "admitted_predecessor_raws": ((label + "-old").encode(),),
        })
    real_publish = front._launcher_transaction_publish_bytes

    class HardKill(BaseException):
        pass

    def leave_journal(guard, path, raw, *, mode):
        result = real_publish(guard, path, raw, mode=mode)
        if Path(path).name == ".plamen-launcher-transaction.json":
            raise HardKill("after journal")
        return result

    monkeypatch.setattr(front, "_launcher_transaction_publish_bytes", leave_journal)
    with pytest.raises(HardKill):
        front._launcher_transaction_publish(directory, rows, selection)
    monkeypatch.setattr(front, "_launcher_transaction_publish_bytes", real_publish)
    journal_path = directory / ".plamen-launcher-transaction.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    if variant == "reordered":
        journal["rows"][0], journal["rows"][1] = (
            journal["rows"][1], journal["rows"][0]
        )
    else:
        label = "public" if variant.startswith("forged-public") else "claude"
        row = next(item for item in journal["rows"] if item["label"] == label)
        forged = (label + "-foreign").encode()
        row.update({
            "predecessor_kind": "exact-existing",
            "predecessor_sha256": hashlib.sha256(forged).hexdigest(),
            "predecessor_size": len(forged),
            "predecessor_identity": [1, 2, len(forged), 1, 0o700],
            "changed": True,
        })
    journal_path.write_bytes(front._launcher_transaction_journal_raw(journal))

    with pytest.raises(RuntimeError, match="row order|predecessor"):
        front._launcher_transaction_publish(directory, rows, selection)
    assert journal_path.exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_indirect_launcher_transaction_journal_is_rejected(
    tmp_path, monkeypatch, kind,
):
    front = _load_front()
    directory = tmp_path / "bin"; _secure_launcher_test_directory(front, directory)
    selection = {
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64, "census_sha256": "3" * 64,
        "request_sha256": "4" * 64, "generation_policy_sha256": "5" * 64,
    }
    rows = [{
        "label": label, "path": directory / (label + ".cmd"),
        "raw": label.encode(),
        "state": front._launcher_absent_state(directory / (label + ".cmd")),
        "admitted_predecessor_raws": (),
    } for label in ("claude", "codex", "public")]
    real_publish = front._launcher_transaction_publish_bytes

    class HardKill(BaseException):
        pass

    def leave_journal(guard, path, raw, *, mode):
        result = real_publish(guard, path, raw, mode=mode)
        if Path(path).name == ".plamen-launcher-transaction.json":
            raise HardKill
        return result

    monkeypatch.setattr(front, "_launcher_transaction_publish_bytes", leave_journal)
    with pytest.raises(HardKill):
        front._launcher_transaction_publish(directory, rows, selection)
    monkeypatch.setattr(front, "_launcher_transaction_publish_bytes", real_publish)
    journal = directory / ".plamen-launcher-transaction.json"
    target = directory / "foreign-journal"
    target.write_bytes(journal.read_bytes())
    journal.unlink()
    if kind == "symlink":
        try:
            os.symlink(target, journal)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlinks unavailable: {exc}")
    else:
        os.link(target, journal)
    with pytest.raises((OSError, RuntimeError)):
        front._launcher_transaction_publish(directory, rows, selection)


def test_current_launcher_hardlink_alias_is_rejected(tmp_path, monkeypatch):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, _ = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = front._ensure_windows_plamen_command(
        user_root=user_root, plamen_root=plamen_root, platform_name="win32",
    )
    alias = command.with_name("public-alias.cmd")
    os.link(command, alias)

    with pytest.raises(RuntimeError, match="indirect|changed"):
        front._ensure_windows_plamen_command(
            user_root=user_root, plamen_root=plamen_root, platform_name="win32",
        )

    alias.write_bytes(b"foreign")
    assert command.read_bytes() == b"foreign"
    assert all(path.is_file() for path in shims.values())


@pytest.mark.parametrize("foreign", [b"", b"x", b"\0x"])
def test_foreign_launcher_lock_bytes_are_never_blessed(
    tmp_path, monkeypatch, foreign,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _ = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    directory = user_root / ".local" / "bin"
    _secure_launcher_test_directory(front, directory)
    lock = directory / ".plamen-launcher.lock"
    if os.name == "nt":
        descriptor = front._win_launcher_create_file_descriptor(
            lock, os.O_WRONLY, 0o600,
        )
        try:
            if foreign:
                os.write(descriptor, foreign)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        lock.write_bytes(foreign)

    with pytest.raises(RuntimeError, match="lock bytes differ"):
        front._ensure_windows_plamen_command(
            user_root=user_root, plamen_root=plamen_root, platform_name="win32",
        )

    assert lock.read_bytes() == foreign
    assert not any(path.exists() for path in shims.values())
    assert not (directory / "plamen.cmd").exists()


def test_tampered_authenticated_shim_neighbor_blocks_all_migration(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    legacy = {}
    for backend, path in shims.items():
        legacy[backend] = front._backend_shim_bytes(
            backend, plamen_root, sys.executable, selection=selection,
            suppress_bytecode=False,
            platform_name="win32",
        )
        path.write_bytes(legacy[backend])
    tampered = legacy["codex"] + b"REM foreign neighbor\r\n"
    shims["codex"].write_bytes(tampered)
    public = front._windows_plamen_command_bytes(
        sys.executable,
        plamen_root / "plamen.py",
        shims["claude"],
        shims["codex"],
        allow_unpublished_backend_shims=True,
        suppress_bytecode=False,
    )
    command.write_bytes(public)

    with pytest.raises(RuntimeError, match="foreign backend shim"):
        front._ensure_windows_plamen_command(
            user_root=user_root,
            plamen_root=plamen_root,
            platform_name="win32",
        )

    assert shims["claude"].read_bytes() == legacy["claude"]
    assert shims["codex"].read_bytes() == tampered
    assert command.read_bytes() == public


def test_backend_predecessor_publish_crash_restores_exact_legacy_bytes(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    legacy = front._backend_shim_bytes(
        "claude", plamen_root, sys.executable, selection=selection,
        suppress_bytecode=False,
    )
    _secure_launcher_test_directory(front, shims["claude"].parent)
    shims["claude"].write_bytes(legacy)
    shims["codex"].write_bytes(front._backend_shim_bytes(
        "codex", plamen_root, sys.executable, selection=selection,
    ))
    real_rename = front._launcher_rename_noreplace
    injected = False

    def fail_staged_publish(source, destination, *args, **kwargs):
        nonlocal injected
        source = Path(source); destination = Path(destination)
        if (
            destination == shims["claude"]
            and source.name.endswith(".tmp")
            and not injected
        ):
            injected = True
            raise OSError("simulated publish crash")
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(front, "_launcher_rename_noreplace", fail_staged_publish)
    with pytest.raises(OSError, match="simulated publish crash"):
        front._ensure_backend_cli_shims(plamen_root, sys.executable)

    assert injected is True
    assert shims["claude"].read_bytes() == legacy
    assert not list(shims["claude"].parent.glob(".*.tmp"))
    assert not list(shims["claude"].parent.glob(".*.recovery"))


def test_path_bound_predecessor_shape_with_foreign_target_is_rejected(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _authenticated_selection_fixture(front, user_root, monkeypatch)
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    foreign = front._windows_plamen_command_bytes(
        sys.executable,
        plamen_root / "plamen.py",
        plamen_root / "mcp-packages" / "node_modules" / "@anthropic-ai"
        / "claude-code" / "bin" / "claude.exe",
        plamen_root / "mcp-packages" / "node_modules" / ".bin" / "codex.cmd",
        allow_unpublished_backend_shims=True,
    )
    admitted_path = str(front.PureWindowsPath((plamen_root / "plamen.py").resolve()))
    foreign_path = str(front.PureWindowsPath((tmp_path / "foreign" / "plamen.py").resolve()))
    foreign = foreign.replace(
        base64.b64encode(os.fsencode(admitted_path)),
        base64.b64encode(os.fsencode(foreign_path)),
    )
    command.write_bytes(foreign)

    with pytest.raises(RuntimeError, match="unrecognized plamen command"):
        front._ensure_windows_plamen_command(
            user_root=user_root,
            plamen_root=plamen_root,
            platform_name="win32",
        )
    assert command.read_bytes() == foreign


def test_foreign_command_is_never_overwritten(tmp_path, monkeypatch):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _authenticated_selection_fixture(front, user_root, monkeypatch)
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    foreign = b"@echo off\r\necho user-owned command\r\n"
    command.write_bytes(foreign)

    with pytest.raises(RuntimeError, match="unrecognized plamen command"):
        front._ensure_windows_plamen_command(
            user_root=user_root,
            plamen_root=plamen_root,
            platform_name="win32",
        )

    assert command.read_bytes() == foreign


def test_windows_generated_shape_from_foreign_root_is_never_overwritten(
    tmp_path, monkeypatch,
):
    """A launcher-shaped batch file is not ownership authority by itself."""
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    foreign = (
        b'@echo off\r\n'
        b'"C:\\foreign\\python.exe" "C:\\foreign\\plamen.py" %*\r\n'
    )
    command.write_bytes(foreign)

    with pytest.raises(RuntimeError, match="unrecognized plamen command"):
        front._ensure_windows_plamen_command(
            user_root=user_root,
            plamen_root=plamen_root,
            platform_name="win32",
        )

    assert command.read_bytes() == foreign
    assert not any(path.exists() for path in shims.values())


def test_backend_shim_marker_spoof_is_never_overwritten(tmp_path, monkeypatch):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    shim = shims["codex"]
    shim.parent.mkdir(parents=True, exist_ok=True)
    foreign = b"user-owned; Plamen authenticated immutable backend launcher\n"
    shim.write_bytes(foreign)

    with pytest.raises(RuntimeError, match="foreign backend shim"):
        front._ensure_backend_cli_shims(plamen_root, sys.executable)

    assert shim.read_bytes() == foreign
    assert not shims["claude"].exists(), (
        "the all-shim collision preflight must run before any sibling publish"
    )


def test_raced_backend_shim_collision_is_preserved_and_siblings_roll_back(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    foreign = b"foreign backend command created after preflight\n"
    real_rename = front._launcher_rename_noreplace
    collided = []

    def collide(source, destination, *args, **kwargs):
        destination = Path(destination)
        if destination == shims["codex"] and not collided:
            destination.write_bytes(foreign)
            collided.append(destination)
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(front, "_launcher_rename_noreplace", collide)
    with pytest.raises(RuntimeError, match="raced foreign backend shim"):
        front._ensure_backend_cli_shims(plamen_root, sys.executable)

    assert collided == [shims["codex"]]
    assert shims["codex"].read_bytes() == foreign
    assert not shims["claude"].exists(), (
        "the earlier newly-created sibling must roll back on a later collision"
    )
    assert not list(shims["codex"].parent.glob(".*.tmp"))


def test_raced_public_command_is_preserved_and_new_backend_shims_roll_back(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen.cmd"
    foreign = b"foreign public command created after preflight\r\n"
    real_rename = front._launcher_transaction_rename
    collided = []

    def collide(guard, source, destination, *args, **kwargs):
        destination = Path(destination)
        if destination == command and not collided:
            destination.write_bytes(foreign)
            collided.append(destination)
        return real_rename(guard, source, destination, *args, **kwargs)

    monkeypatch.setattr(front, "_launcher_transaction_rename", collide)
    with pytest.raises(RuntimeError, match="raced foreign plamen command"):
        front._ensure_windows_plamen_command(
            user_root=user_root,
            plamen_root=plamen_root,
            platform_name="win32",
        )

    assert collided == [command]
    assert command.read_bytes() == foreign
    assert not any(path.exists() for path in shims.values()), (
        "new backend shims must roll back when public-command publication fails"
    )
    assert not list(command.parent.glob(".*.tmp"))


def test_absent_public_launcher_rejects_staged_path_substitution(
    tmp_path, monkeypatch,
):
    front = _load_front()
    command = tmp_path / "plamen.cmd"
    desired = b"authenticated launcher\r\n"
    foreign = b"foreign staged substitution\r\n"
    state = front._launcher_absent_state(command)
    real_snapshot = front._launcher_regular_snapshot
    raced = False

    def substitute_after_replay(path, expected, label):
        nonlocal raced
        result = real_snapshot(path, expected, label)
        path = Path(path)
        if label == "staged launcher" and not raced:
            path.replace(tmp_path / "displaced-authenticated-stage")
            path.write_bytes(foreign)
            raced = True
        return result

    monkeypatch.setattr(front, "_launcher_regular_snapshot", substitute_after_replay)
    with pytest.raises(RuntimeError, match="unverified launcher publication was retracted"):
        front._publish_public_launcher(command, desired, state, mode=0o600)

    assert raced is True
    assert not command.exists()
    assert (tmp_path / "displaced-authenticated-stage").read_bytes() == desired
    recoveries = list(tmp_path.glob(".plamen.cmd.unverified-*.recovery"))
    assert len(recoveries) == 1
    assert recoveries[0].read_bytes() == foreign
    assert not list(tmp_path.glob(".plamen.cmd.*.tmp"))


def test_existing_public_launcher_restores_predecessor_on_staged_substitution(
    tmp_path, monkeypatch,
):
    front = _load_front()
    command = tmp_path / "plamen.cmd"
    predecessor = b"recognized predecessor\r\n"
    desired = b"authenticated replacement\r\n"
    foreign = b"foreign staged substitution\r\n"
    command.write_bytes(predecessor)
    state = front._launcher_existing_state(
        command, predecessor, "preflight public launcher",
    )
    real_snapshot = front._launcher_regular_snapshot
    raced = False
    staged_replays = 0

    def substitute_after_replay(path, expected, label):
        nonlocal raced, staged_replays
        result = real_snapshot(path, expected, label)
        path = Path(path)
        if label == "staged public launcher":
            staged_replays += 1
        if label == "staged public launcher" and staged_replays == 2 and not raced:
            path.replace(tmp_path / "displaced-authenticated-stage")
            path.write_bytes(foreign)
            raced = True
        return result

    monkeypatch.setattr(front, "_launcher_regular_snapshot", substitute_after_replay)
    with pytest.raises(RuntimeError, match="unverified launcher publication was retracted"):
        front._publish_public_launcher(command, desired, state, mode=0o600)

    assert raced is True
    assert command.read_bytes() == predecessor
    assert not list(tmp_path.glob(".plamen.cmd.take-*.recovery"))
    recoveries = list(tmp_path.glob(".plamen.cmd.unverified-*.recovery"))
    assert len(recoveries) == 1
    assert recoveries[0].read_bytes() == foreign
    assert not list(tmp_path.glob(".plamen.cmd.*.tmp"))


def test_existing_public_launcher_race_before_atomic_take_restores_foreign(
    tmp_path, monkeypatch,
):
    front = _load_front()
    command = tmp_path / "plamen.cmd"
    predecessor = b"recognized predecessor\r\n"
    desired = b"replacement launcher\r\n"
    foreign = b"foreign object swapped before atomic take\r\n"
    command.write_bytes(predecessor)
    state = front._launcher_existing_state(
        command, predecessor, "preflight public launcher",
    )
    real_rename = front._launcher_rename_noreplace
    raced = False

    def swap_before_take(source, destination, *args, **kwargs):
        nonlocal raced
        if Path(source) == command and not raced:
            replacement = tmp_path / "foreign-before-take"
            replacement.write_bytes(foreign)
            replacement.replace(command)
            raced = True
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(front, "_launcher_rename_noreplace", swap_before_take)
    with pytest.raises(RuntimeError, match="raced foreign plamen command"):
        front._publish_public_launcher(
            command, desired, state, mode=0o600,
        )

    assert raced is True
    assert command.read_bytes() == foreign
    assert not list(tmp_path.glob(".plamen.cmd.take-*.recovery"))
    assert not list(tmp_path.glob(".plamen.cmd.*.tmp"))


def test_existing_public_command_take_race_rolls_back_new_backend_shims(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen.cmd"
    _secure_launcher_test_directory(front, command.parent)
    command.write_bytes(front._WINDOWS_PLAMEN_COMMAND)
    foreign = b"foreign public command swapped before atomic take\r\n"
    real_rename = front._launcher_transaction_rename
    raced = False

    def swap_before_take(guard, source, destination, *args, **kwargs):
        nonlocal raced
        source = Path(source)
        if source == command and not raced:
            replacement = tmp_path / "foreign-public-command"
            replacement.write_bytes(foreign)
            replacement.replace(command)
            raced = True
        return real_rename(guard, source, destination, *args, **kwargs)

    monkeypatch.setattr(front, "_launcher_transaction_rename", swap_before_take)
    with pytest.raises(RuntimeError, match="raced foreign plamen command"):
        front._ensure_windows_plamen_command(
            user_root=user_root,
            plamen_root=plamen_root,
            platform_name="win32",
        )

    assert raced is True
    assert command.read_bytes() == foreign
    assert not any(path.exists() for path in shims.values())
    assert not list(command.parent.glob(".plamen.cmd.take-*.recovery"))
    assert not list(command.parent.glob(".*.tmp"))


def test_existing_public_launcher_race_after_take_preserves_both_objects(
    tmp_path, monkeypatch,
):
    front = _load_front()
    command = tmp_path / "plamen.cmd"
    predecessor = b"recognized predecessor\r\n"
    desired = b"replacement launcher\r\n"
    foreign = b"foreign object created after atomic take\r\n"
    command.write_bytes(predecessor)
    state = front._launcher_existing_state(
        command, predecessor, "preflight public launcher",
    )
    real_rename = front._launcher_rename_noreplace
    raced = False

    def create_after_take(source, destination, *args, **kwargs):
        nonlocal raced
        source = Path(source); destination = Path(destination)
        if destination == command and source != command and not raced:
            command.write_bytes(foreign)
            raced = True
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(front, "_launcher_rename_noreplace", create_after_take)
    with pytest.raises(RuntimeError, match="preserved for explicit recovery"):
        front._publish_public_launcher(
            command, desired, state, mode=0o600,
        )

    quarantines = list(tmp_path.glob(".plamen.cmd.take-*.recovery"))
    assert raced is True
    assert command.read_bytes() == foreign
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == predecessor
    assert not list(tmp_path.glob(".plamen.cmd.*.tmp"))


def test_atomic_take_foreign_replay_restore_collision_preserves_both_racers(
    tmp_path, monkeypatch,
):
    front = _load_front()
    command = tmp_path / "plamen.cmd"
    predecessor = b"recognized predecessor\r\n"
    first_foreign = b"first foreign race\r\n"
    second_foreign = b"second foreign race\r\n"
    command.write_bytes(predecessor)
    state = front._launcher_existing_state(
        command, predecessor, "preflight public launcher",
    )
    real_rename = front._launcher_rename_noreplace
    raced = False

    def two_racers(source, destination, *args, **kwargs):
        nonlocal raced
        source = Path(source); destination = Path(destination)
        if source == command and not raced:
            replacement = tmp_path / "first-racer"
            replacement.write_bytes(first_foreign)
            replacement.replace(command)
            result = real_rename(source, destination, *args, **kwargs)
            command.write_bytes(second_foreign)
            raced = True
            return result
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(front, "_launcher_rename_noreplace", two_racers)
    with pytest.raises(RuntimeError, match="preserved for explicit recovery"):
        front._publish_public_launcher(
            command, b"replacement launcher\r\n", state, mode=0o600,
        )

    quarantines = list(tmp_path.glob(".plamen.cmd.take-*.recovery"))
    assert raced is True
    assert command.read_bytes() == second_foreign
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == first_foreign
    assert not list(tmp_path.glob(".plamen.cmd.*.tmp"))


def test_exact_current_public_launcher_performs_no_publication_write(
    tmp_path, monkeypatch,
):
    front = _load_front()
    command = tmp_path / "plamen.cmd"
    desired = b"exact current launcher\r\n"
    command.write_bytes(desired)
    state = front._launcher_existing_state(
        command, desired, "preflight public launcher",
    )
    identity = (command.stat().st_ino, command.stat().st_mtime_ns)

    monkeypatch.setattr(
        front, "_launcher_rename_noreplace",
        lambda *_args, **_kwargs: pytest.fail("exact-current launcher was renamed"),
    )
    monkeypatch.setattr(
        front, "_launcher_publish_bytes_noreplace",
        lambda *_args, **_kwargs: pytest.fail("exact-current launcher was published"),
    )
    assert front._publish_public_launcher(
        command, desired, state, mode=0o600,
    ) is None
    assert (command.stat().st_ino, command.stat().st_mtime_ns) == identity
    assert command.read_bytes() == desired


@pytest.mark.skipif(
    not hasattr(Path, "symlink_to"), reason="path symlinks unavailable",
)
def test_posix_symlink_predecessor_is_validated_after_atomic_take(
    tmp_path, monkeypatch,
):
    front = _load_front()
    target = tmp_path / "plamen.py"
    target.write_bytes(b"# installed\n")
    command = tmp_path / "plamen"
    try:
        command.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    admitted = {target.resolve()}
    state = front._launcher_symlink_state(
        command, admitted, "preflight POSIX launcher",
    )
    desired = b"#!/bin/sh\nexec /absolute/plamen \"$@\"\n"

    front._publish_public_launcher(
        command, desired, state, mode=0o700, admitted_targets=admitted,
    )

    assert not command.is_symlink()
    assert command.read_bytes() == desired
    assert not list(tmp_path.glob(".plamen.take-*.recovery"))


def test_byte_identical_existing_backend_shims_are_not_replaced(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    front._ensure_backend_cli_shims(plamen_root, sys.executable)
    identities = {
        backend: (path.stat().st_ino, path.stat().st_mtime_ns)
        for backend, path in shims.items()
    }

    def no_publication(*_args, **_kwargs):
        pytest.fail("byte-identical existing shim was replaced")

    monkeypatch.setattr(front, "_launcher_rename_noreplace", no_publication)
    assert front._ensure_backend_cli_shims(
        plamen_root, sys.executable,
    ) == shims
    assert {
        backend: (path.stat().st_ino, path.stat().st_mtime_ns)
        for backend, path in shims.items()
    } == identities


def test_non_windows_install_does_not_create_a_dispatcher(tmp_path):
    front = _load_front()
    user_root = tmp_path / "user"

    assert front._ensure_windows_plamen_command(
        user_root=user_root,
        plamen_root=user_root / ".plamen",
        platform_name="linux",
    ) is None
    assert not (user_root / ".local" / "bin" / "plamen.cmd").exists()


def test_posix_command_binds_absolute_paths_and_survives_symlink_invocation(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )

    command = front._ensure_posix_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="linux",
    )

    text = command.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n# Plamen managed launcher v2;")
    assert str(Path(sys.executable).resolve()) in text
    assert str((plamen_root / "plamen.py").resolve()) in text
    assert "dirname" not in text
    assert "CLAUDE_BIN=" in text and str(shims["claude"]) in text
    assert "CODEX_BIN=" in text and str(shims["codex"]) in text
    _assert_authenticated_backend_shim(shims["claude"], "claude", selection)
    _assert_authenticated_backend_shim(shims["codex"], "codex", selection)
    if sys.platform != "win32":
        assert command.stat().st_mode & 0o100


def test_posix_marker_spoof_is_never_overwritten(tmp_path, monkeypatch):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _selection, shims, _admissions = _authenticated_selection_fixture(
        front, user_root, monkeypatch,
    )
    command = user_root / ".local" / "bin" / "plamen"
    _secure_launcher_test_directory(front, command.parent)
    foreign = (
        b"#!/bin/sh\n"
        b"# Plamen managed launcher v2; user-owned documentation only\n"
        b"echo user-owned plamen.py\n"
    )
    command.write_bytes(foreign)

    with pytest.raises(RuntimeError, match="unrecognized plamen command"):
        front._ensure_posix_plamen_command(
            user_root=user_root,
            plamen_root=plamen_root,
            platform_name="linux",
        )

    assert command.read_bytes() == foreign
    assert not any(path.exists() for path in shims.values())


def test_posix_exact_committed_package_launcher_predecessor_is_repaired(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _authenticated_selection_fixture(front, user_root, monkeypatch)
    legacy = b'#!/bin/sh\n# Plamen launcher\nexec python "$(dirname "$0")/plamen.py" "$@"\n'
    (plamen_root / "plamen").write_bytes(legacy)
    command = user_root / ".local" / "bin" / "plamen"
    _secure_launcher_test_directory(front, command.parent)
    command.write_bytes(legacy)

    repaired = front._ensure_posix_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="linux",
    )

    assert repaired == command
    assert repaired.read_bytes() != legacy
    assert b"# Plamen managed launcher v2;" in repaired.read_bytes()


@pytest.mark.skipif(
    not hasattr(Path, "symlink_to"), reason="path symlinks unavailable",
)
def test_posix_foreign_same_basename_symlink_is_never_overwritten(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _authenticated_selection_fixture(front, user_root, monkeypatch)
    command = user_root / ".local" / "bin" / "plamen"
    _secure_launcher_test_directory(front, command.parent)
    foreign_target = tmp_path / "foreign" / "plamen.py"
    foreign_target.parent.mkdir()
    foreign_target.write_text("# user owned\n", encoding="utf-8")
    try:
        command.symlink_to(foreign_target)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(RuntimeError, match="foreign plamen symlink"):
        front._ensure_posix_plamen_command(
            user_root=user_root,
            plamen_root=plamen_root,
            platform_name="linux",
        )

    assert command.is_symlink()
    assert command.resolve() == foreign_target.resolve()


@pytest.mark.skipif(
    not hasattr(Path, "symlink_to"), reason="path symlinks unavailable",
)
def test_posix_exact_committed_target_symlink_is_repaired(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _authenticated_selection_fixture(front, user_root, monkeypatch)
    command = user_root / ".local" / "bin" / "plamen"
    _secure_launcher_test_directory(front, command.parent)
    try:
        command.symlink_to(plamen_root / "plamen.py")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    repaired = front._ensure_posix_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="linux",
    )

    assert repaired == command
    assert not repaired.is_symlink()
    assert b"# Plamen managed launcher v2;" in repaired.read_bytes()


def test_posix_exact_current_launcher_is_admitted_and_not_rewritten(
    tmp_path, monkeypatch,
):
    front = _load_front()
    user_root, plamen_root = _installed_tree(tmp_path)
    _authenticated_selection_fixture(front, user_root, monkeypatch)
    command = front._ensure_posix_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="linux",
    )
    identity = (command.stat().st_ino, command.stat().st_mtime_ns)

    def no_rename(*_args, **_kwargs):
        pytest.fail("exact-current POSIX launcher or backend shim was renamed")

    monkeypatch.setattr(front, "_launcher_rename_noreplace", no_rename)
    assert front._ensure_posix_plamen_command(
        user_root=user_root,
        plamen_root=plamen_root,
        platform_name="linux",
    ) == command
    assert (command.stat().st_ino, command.stat().st_mtime_ns) == identity


def test_codex_install_repairs_command_after_the_package_commits(monkeypatch):
    front = _load_front()
    events = []
    receipt = {
        "transaction_id": "1" * 32,
        "source_count": 762,
        "plamen_root": "C:/Users/test/.plamen",
        "codex_root": "C:/Users/test/.codex",
    }
    monkeypatch.setattr(
        front,
        "_install_codex_package_transaction",
        lambda **kwargs: (
            events.append(("commit", kwargs)) or receipt
        ),
    )
    monkeypatch.setattr(
        front,
        "_ensure_windows_plamen_command",
        lambda **_kwargs: events.append("command") or Path("plamen.cmd"),
    )
    monkeypatch.setattr(
        front,
        "_sync_codex_adapter_source_cache",
        lambda _receipt: 0,
    )
    monkeypatch.setattr(
        front,
        "_setup_mcp_packages",
        lambda *_args, **_kwargs: events.append("mcp") or True,
    )
    monkeypatch.setattr(
        front,
        "_merge_codex_mcp_toml",
        lambda *_args, **_kwargs: events.append("mcp-config") or True,
    )
    monkeypatch.setattr(sys, "argv", ["plamen.py", "install", "--codex"])

    assert front._install_codex_adapter(lambda _text: None)
    assert events == [
        ("commit", {"enable_claude_projection": False}),
        "mcp", "mcp-config", "command",
    ]


def test_installed_codex_install_validates_instead_of_replacing_live_entrypoint(monkeypatch):
    front = _load_front()
    events = []
    installed = Path("C:/Users/test/.plamen").absolute()
    codex_home = Path("C:/Users/test/.codex").absolute()
    receipt = {
        "transaction_id": "2" * 32,
        "source_count": 762,
        "plamen_root": str(installed),
        "codex_root": str(codex_home),
    }
    monkeypatch.setattr(front, "PLAMEN_HOME", str(installed))
    real_expanduser = front.os.path.expanduser
    monkeypatch.setattr(
        front.os.path,
        "expanduser",
        lambda value: (
            str(installed) if value == "~/.plamen" else
            str(codex_home) if value == "~/.codex" else
            real_expanduser(value)
        ),
    )
    monkeypatch.setattr(front, "_codex_install_doctor_issues", lambda **_kwargs: [])
    monkeypatch.setattr(
        front,
        "_codex_install_committed_read",
        lambda *_args, **_kwargs: ({}, json.dumps(receipt).encode("utf-8")),
    )
    monkeypatch.setattr(
        front,
        "_install_codex_package_transaction",
        lambda: pytest.fail("a live installed entrypoint must not replace itself"),
    )
    monkeypatch.setattr(front, "_sync_codex_adapter_source_cache", lambda _receipt: 0)
    monkeypatch.setattr(
        front,
        "_setup_mcp_packages",
        lambda *_args, **_kwargs: events.append("mcp") or True,
    )
    monkeypatch.setattr(
        front,
        "_merge_codex_mcp_toml",
        lambda *_args, **_kwargs: events.append("mcp-config") or True,
    )
    monkeypatch.setattr(
        front,
        "_ensure_windows_plamen_command",
        lambda **_kwargs: events.append("command") or Path("plamen.cmd"),
    )
    monkeypatch.setattr(sys, "argv", ["plamen.py", "install", "--codex"])

    assert front._install_codex_adapter(lambda _text: None)
    assert events == ["mcp", "mcp-config", "command"]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle-transfer keeper")
def test_windows_install_keeper_binds_and_releases(tmp_path):
    """Exercise the real venv/interpreter/PID handshake without a full install."""
    front = _load_front()
    transaction_id = uuid.uuid4().hex
    writer_generation = "test:" + transaction_id
    codex_home = tmp_path / ".codex"
    plamen_root = tmp_path / ".plamen"
    source_root = ROOT
    codex_home.mkdir()
    plamen_root.mkdir()
    transaction_root = (
        codex_home / ".plamen-install-transactions" / transaction_id
    )
    transaction_root.mkdir(parents=True)
    _anchor, writer_handle, writer_close = front._open_install_admission_anchor(
        codex_home, writer=True, create=True
    )
    keeper = None
    try:
        pipe = rf"\\.\pipe\plamen-install-{transaction_id}-{uuid.uuid4().hex}"
        authkey = front.os.urandom(32)
        emergency_raw = b'{"state":"TEST"}\n'
        receipt = {
            "source_manifest_sha256": "1" * 64,
            "runtime_manifest_sha256": "2" * 64,
            "adapter_manifest_sha256": "3" * 64,
            "inverse_sha256": "4" * 64,
        }
        descriptor = front._codex_install_keeper_descriptor(
            transaction_id=transaction_id,
            writer_generation=writer_generation,
            writer_handle=writer_handle,
            codex_home=codex_home,
            plamen_root=plamen_root,
            source_root=source_root,
            receipt=receipt,
            emergency_raw=emergency_raw,
            pipe=pipe,
            authkey=authkey,
        )
        descriptor_raw = front._borrowed_reader_canonical_bytes(descriptor)
        (transaction_root / "keeper-descriptor.json").write_bytes(descriptor_raw)

        def publish_binding(raw):
            (transaction_root / "keeper-binding.json").write_bytes(raw)
            return raw

        keeper = front._start_codex_install_keeper(
            transaction_id=transaction_id,
            writer_handle=writer_handle,
            writer_generation=writer_generation,
            codex_home=codex_home,
            plamen_root=plamen_root,
            source_root=source_root,
            descriptor_sha256=hashlib.sha256(descriptor_raw).hexdigest(),
            pipe=pipe,
            authkey=authkey,
            pipe_instance_nonce=descriptor["pipe_instance_nonce"],
            binding_publisher=publish_binding,
        )
        front._release_codex_install_keeper(keeper)
        keeper = None
    finally:
        if keeper is not None and keeper["process"].poll() is None:
            keeper["process"].kill()
            keeper["process"].wait(timeout=30)
        writer_close()


def test_rollback_atomic_temp_resolves_to_governed_destination(tmp_path):
    """A rollback copy nests an atomic temp below the rollback temp name."""
    front = _load_front()
    transaction_id = "a" * 32
    dispatcher = front._CodexInstallMutationDispatcher.__new__(
        front._CodexInstallMutationDispatcher
    )
    dispatcher.transaction_id = transaction_id
    dispatcher.closed = False
    dispatcher.codex_home = tmp_path / "codex"
    dispatcher.plamen_root = tmp_path / "plamen"
    dispatcher.source_root = tmp_path / "source"
    dispatcher._address_owner = object()
    dispatcher._stable_b_keys = set()
    base = ("scripts", "example.py")
    dispatcher._operation_policy = {
        ("plamen", base): {"REPLACE_DESTINATION", "UNLINK"}
    }
    nested = dispatcher.address(
        "plamen",
        (
            "scripts",
            f"example.py.{transaction_id}.rollback."
            f"{transaction_id}.00000042.tmp",
        ),
    )

    assert dispatcher._authorized_operation_key("TEMP_BYTES", nested) == (
        "plamen",
        nested.components,
    )


def test_receipt_restore_atomic_temp_prefers_nearest_governed_key(tmp_path):
    """The explicit receipt restore authority wins over its deeper base key."""
    front = _load_front()
    transaction_id = "b" * 32
    dispatcher = front._CodexInstallMutationDispatcher.__new__(
        front._CodexInstallMutationDispatcher
    )
    dispatcher.transaction_id = transaction_id
    dispatcher.closed = False
    dispatcher.codex_home = tmp_path / "codex"
    dispatcher.plamen_root = tmp_path / "plamen"
    dispatcher.source_root = tmp_path / "source"
    dispatcher._address_owner = object()
    dispatcher._stable_b_keys = set()
    receipt = front._CODEX_INSTALL_RECEIPT
    restore = f"{receipt}.{transaction_id}.restore"
    dispatcher._operation_policy = {
        ("codex", (receipt,)): {"ATOMIC_BYTES"},
        ("codex", (restore,)): {"EXCLUSIVE_BYTES", "REPLACE_SOURCE"},
    }
    nested = dispatcher.address(
        "codex", (f"{restore}.{transaction_id}.00000017.tmp",),
    )

    assert dispatcher._authorized_operation_key("TEMP_BYTES", nested) == (
        "codex",
        nested.components,
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native sharing semantics")
def test_read_only_install_root_opens_inside_owned_low_integrity_runner(tmp_path):
    """Read admission must not accidentally request low-integrity-denied writes."""
    from owned_process_runner import run_owned_process

    python = (
        Path.home()
        / ".local" / "share" / "plamen" / "runtime"
        / "py312" / "Scripts" / "python.exe"
    )
    if not python.is_file() or os.stat(python).st_nlink != 1:
        pytest.skip("single-link managed Python runtime is unavailable")

    root = tmp_path / "medium-integrity-root"
    root.mkdir()
    source = ROOT / "plamen.py"
    code = (
        "import importlib.util;"
        f"s=importlib.util.spec_from_file_location('front',{str(source)!r});"
        "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
        f"h,c=m._codex_dispatcher_open_root({str(root)!r},full_mutation=False);"
        "print('OPEN_OK');c()"
    )
    command = [str(python), "-I", "-B", "-c", code]

    direct = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=60,
        check=False,
    )
    assert direct.returncode == 0, direct.stderr
    assert direct.stdout.strip() == "OPEN_OK"

    owned = run_owned_process(command, cwd=ROOT, timeout=60)
    assert owned.returncode == 0, owned.stderr
    assert owned.stdout.strip() == "OPEN_OK"
    assert owned.process_tree_terminated is True
    assert owned.containment_capability["write_confinement"] == (
        "LOW_INTEGRITY_TOKEN_PLUS_SERIALIZED_PLAMEN_STAGE_LEASE"
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native sharing semantics")
def test_read_only_install_root_still_denies_replacement_and_share_conflicts(
    tmp_path,
):
    import ctypes
    from ctypes import wintypes

    front = _load_front()
    root = tmp_path / "retained-root"
    renamed = tmp_path / "renamed-root"
    root.mkdir()

    handle, close = front._codex_dispatcher_open_root(
        root, full_mutation=False,
    )
    try:
        with pytest.raises(PermissionError):
            root.rename(renamed)
    finally:
        close()
    root.rename(renamed)
    renamed.rename(root)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    blocker = kernel32.CreateFileW(
        str(root),
        0x80000000 | 0x00100000,  # GENERIC_READ | SYNCHRONIZE
        0,  # deliberately deny every subsequent share request
        None,
        3,
        0x00200000 | 0x02000000,
        None,
    )
    assert blocker != wintypes.HANDLE(-1).value
    try:
        with pytest.raises(OSError) as denied:
            front._codex_dispatcher_open_root(root, full_mutation=False)
        assert denied.value.errno == 32
    finally:
        assert kernel32.CloseHandle(int(blocker))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native sharing semantics")
def test_native_relative_open_retries_transient_sharing_violation(tmp_path):
    front = _load_front()
    root = tmp_path / "native-sharing"
    root.mkdir()
    (root / "receipt.json").write_bytes(b"{}\n")
    root_handle = holder = opened = None
    closer = None
    try:
        root_handle, root_close = front._codex_dispatcher_open_root(
            root, full_mutation=False,
        )
        holder = front._codex_native_open_relative(
            root_handle, "receipt.json", directory=False, create=False,
            access=0x80000000 | 0x00100000, share_delete=False,
        )

        def release_holder():
            nonlocal holder
            time.sleep(0.10)
            front._codex_native_close(holder)
            holder = None

        closer = threading.Thread(target=release_holder)
        closer.start()
        started = time.monotonic()
        opened = front._codex_native_open_relative(
            root_handle, "receipt.json", directory=False, create=False,
            access=0x80000000 | 0x00010000 | 0x00100000,
            share_delete=True,
        )
        assert time.monotonic() - started >= 0.06
    finally:
        if closer is not None:
            closer.join(timeout=5)
        if opened is not None:
            front._codex_native_close(opened)
        if holder is not None:
            front._codex_native_close(holder)
        if root_handle is not None:
            root_close()


def test_descriptor_absent_emergency_recovery_selects_archived_predecessor(
    tmp_path, monkeypatch,
):
    front = _load_front()
    transaction_id = "c" * 32
    pointer = {
        "schema": "plamen.install.terminal.pointer.v1",
        "writer_generation": "public:" + transaction_id,
    }
    shared = {
        "transaction_id": transaction_id,
        "source_count": 759,
        "source_manifest_sha256": "1" * 64,
        "runtime_count": 727,
        "runtime_manifest_sha256": "2" * 64,
        "adapter_count": 31,
        "adapter_manifest_sha256": "3" * 64,
        "codex_root": str(tmp_path / "codex"),
        "plamen_root": str(tmp_path / "plamen"),
        "source_root": str(tmp_path / "source"),
        "transaction_root": str(tmp_path / "transaction"),
        "stage_root": str(tmp_path / "stage"),
        "backup_root": str(tmp_path / "backup"),
        "inverse_path": str(tmp_path / "inverse.json"),
        "inverse_sha256": "4" * 64,
        "journal_path": str(tmp_path / "journal.json"),
        "lock_identity": [1, 2],
        "owner": {"pid": 1},
        "rows": [{"source_path": "plamen.py"}],
        "journal": [],
        "created_junction": False,
    }
    current = {
        **shared, "schema": front._CODEX_INSTALL_SCHEMA,
        "state": "EMERGENCY_REPAIR_REQUIRED", "terminal_evidence": pointer,
    }
    current["rows"] = [*shared["rows"], {"source_path": "scripts/plamen_driver.py"}]
    terminal = {
        **shared, "rows": current["rows"],
        "schema": "plamen.codex_install.emergency_result.v1",
        "state": "EMERGENCY_REPAIR_REQUIRED", "terminal_evidence": pointer,
    }
    failed = {
        **shared, "schema": front._CODEX_INSTALL_SCHEMA,
        "state": "PREPARING", "terminal_evidence": None,
    }
    encoded = {
        "emergency-result.json": front._borrowed_reader_canonical_bytes(terminal),
        "failed-successor-receipt.json": front._borrowed_reader_canonical_bytes(failed),
    }

    def committed_read(_root, components, *, directory):
        assert directory is False
        raw = encoded[components[-1]]
        return {"sha256": hashlib.sha256(raw).hexdigest()}, raw

    validated = []
    monkeypatch.setattr(front, "_codex_install_committed_read", committed_read)
    monkeypatch.setattr(
        front, "_validate_codex_install_terminal_evidence",
        lambda *args, **kwargs: validated.append((args, kwargs)),
    )

    selected = front._codex_install_bootstrap_current(
        transaction_id=transaction_id,
        codex_home=tmp_path / "codex",
        transaction_components=(".plamen-install-transactions", transaction_id),
        current=current,
    )

    assert selected == failed
    assert len(validated) == 1
    assert validated[0][1]["expected_outcome"] == "EMERGENCY_REPAIR_REQUIRED"


def test_front_and_driver_share_current_install_denominator():
    driver_source = (ROOT / "scripts" / "plamen_driver.py").read_text(
        encoding="utf-8",
    )
    assert "_CODEX_INSTALL_SOURCE_COUNT = 1090" in driver_source
    assert "_CODEX_INSTALL_RUNTIME_COUNT = 1059" in driver_source
    assert "_CODEX_INSTALL_ADAPTER_COUNT = 31" in driver_source
    admission = driver_source[
        driver_source.index("def _admit_installed_driver_before_local_imports"):
        driver_source.index("def _driver_discovery_before_local_imports")
    ]
    assert "receipt.get(\"source_count\") != _CODEX_INSTALL_SOURCE_COUNT" in admission
    assert "receipt.get(\"runtime_count\") != _CODEX_INSTALL_RUNTIME_COUNT" in admission
    assert "len(receipt.get(\"journal\", ())) != _CODEX_INSTALL_SOURCE_COUNT" in admission
    assert "type(receipt.get(\"source_count\")) is not int" in admission
    assert "type(receipt.get(\"runtime_count\")) is not int" in admission
    assert "type(receipt.get(\"adapter_count\")) is not int" in admission
    row_validation = driver_source[
        driver_source.index("def _validate_installed_package_rows"):
        driver_source.index("def _admit_installed_driver_before_local_imports")
    ]
    assert "type(terminal.get(\"verified_count\")) is not int" in row_validation
