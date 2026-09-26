"""Adversarial tests for the mutation-free source install handoff."""

from __future__ import annotations

import ast
import hashlib
import inspect
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

import pytest

import posix_native_install_dispatch as D


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX only")


class _ExecIntercept(BaseException):
    pass


def _layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = tmp_path / "source"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    dispatcher = scripts / "posix_native_install_dispatch.py"
    builder = scripts / "build_posix_native_supervisor.py"
    dispatcher.write_bytes(b"# admitted dispatcher\n")
    builder.write_bytes(b"# admitted builder\n")
    dispatcher.chmod(0o600)
    builder.chmod(0o600)

    python = tmp_path / "runtime" / "python3.12"
    python.parent.mkdir()
    python.write_bytes(b"admitted-cpython-3.12-image")
    python.chmod(0o700)

    home = tmp_path / "account"
    home.mkdir()
    record = types.SimpleNamespace(pw_uid=os.getuid(), pw_dir=str(home))
    monkeypatch.setattr(D, "__file__", str(dispatcher))
    monkeypatch.setattr(D, "PYTHON_CANDIDATES", (str(python),))
    monkeypatch.setattr(D.pwd, "getpwuid", lambda uid: record)
    monkeypatch.setattr(D, "_dispatch_started", False)
    return repository, dispatcher, builder, python, home


def test_exact_one_way_exec_uses_pwd_and_closed_environment(tmp_path, monkeypatch):
    repository, _dispatcher, builder, python, home = _layout(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path / "attacker-home"))
    monkeypatch.setenv("PYTHONPATH", "/attacker")
    monkeypatch.setenv("PLAMEN_TOKEN", "forbidden")
    observed = {}

    def intercept(path, argv, environment):
        assert os.get_inheritable(int(argv[5])) is True
        assert os.pread(int(argv[5]), 1024, 0) == builder.read_bytes()
        observed.update(path=path, argv=argv, environment=environment)
        raise _ExecIntercept

    monkeypatch.setattr(D.os, "execve", intercept)
    with pytest.raises(_ExecIntercept):
        D.exec_native_install(["install", "--codex"])

    assert observed["path"] == str(python)
    assert observed["argv"][:5] == [
        str(python), "-I", "-B", "-c", D._RETAINED_BUILDER_LOADER,
    ]
    assert observed["argv"][7] == hashlib.sha256(
        builder.read_bytes()
    ).hexdigest()
    assert observed["argv"][8:] == [
        str(builder), str(os.getuid()), str(stat.S_IMODE(builder.stat().st_mode)),
    ]
    assert observed["environment"] == {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
    }
    assert str(repository) in observed["argv"][8]
    assert str(home) not in observed["argv"]
    assert "attacker-home" not in repr(observed)


def test_darwin_public_install_execs_retained_compat_transaction(
    tmp_path, monkeypatch,
):
    repository, _dispatcher, _builder, python, home = _layout(
        tmp_path, monkeypatch,
    )
    installer = repository / "scripts" / "posix_v2_compat_install.py"
    installer.write_bytes(b"# admitted compatibility installer\n")
    installer.chmod(0o600)
    python_fd = os.open(python, os.O_RDONLY)
    python_info = os.fstat(python_fd)
    monkeypatch.setattr(D.sys, "platform", "darwin")
    monkeypatch.setattr(
        D, "_open_python_candidate",
        lambda path, uid: (os.dup(python_fd), python_info, python_info),
    )
    monkeypatch.setattr(D, "_revalidate_python", lambda *_args: None)
    observed = {}

    def intercept(path, argv, environment):
        retained = int(argv[5])
        assert os.get_inheritable(retained) is True
        assert os.pread(retained, 4096, 0) == installer.read_bytes()
        observed.update(path=path, argv=argv, environment=environment)
        raise _ExecIntercept

    monkeypatch.setattr(D.os, "execve", intercept)
    try:
        with pytest.raises(_ExecIntercept):
            D.exec_posix_install(["install", "--codex"])
    finally:
        os.close(python_fd)

    expected_python = str(
        home / ".local/share/plamen/runtime/py312/bin/python"
    )
    assert observed["path"] == expected_python
    assert observed["argv"][:5] == [
        expected_python, "-I", "-B", "-c",
        D._RETAINED_COMPAT_INSTALLER_LOADER,
    ]
    assert observed["argv"][-3:] == [str(repository), str(home), expected_python]
    assert observed["environment"] == D.CLOSED_ENVIRONMENT


def test_linux_public_install_keeps_native_transaction(monkeypatch):
    monkeypatch.setattr(D.sys, "platform", "linux")
    monkeypatch.setattr(
        D, "exec_native_install",
        lambda argv: (_ for _ in ()).throw(_ExecIntercept(argv)),
    )
    with pytest.raises(_ExecIntercept):
        D.exec_posix_install(["install", "--codex"])


@pytest.mark.parametrize(
    "argv",
    (
        [],
        ["install"],
        ["install", "--claude"],
        ["install", "--codex", "extra"],
        ["INSTALL", "--codex"],
        ("install", "--codex"),
        "install --codex",
        None,
    ),
)
def test_rejects_every_nonexact_source_argv_before_admission(
    tmp_path, monkeypatch, argv,
):
    _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        D.pwd, "getpwuid", lambda _uid: pytest.fail("pwd must not be queried")
    )
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeInstallDispatchError):
        D.exec_native_install(argv)
    assert D._dispatch_started is False


def test_valid_attempt_is_process_local_one_shot(tmp_path, monkeypatch):
    _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(D.os, "execve", lambda *_args: (_ for _ in ()).throw(_ExecIntercept))
    with pytest.raises(_ExecIntercept):
        D.exec_native_install(["install", "--codex"])
    with pytest.raises(D.PosixNativeInstallDispatchError, match="already attempted"):
        D.exec_native_install(["install", "--codex"])


def test_pwd_identity_and_home_are_mandatory(tmp_path, monkeypatch):
    _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        D.pwd,
        "getpwuid",
        lambda uid: types.SimpleNamespace(
            pw_uid=uid + 1,
            pw_dir=str(tmp_path / "attacker-home"),
        ),
    )
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeInstallDispatchError):
        D.exec_native_install(["install", "--codex"])


def test_fixed_candidate_link_is_bound_to_its_target_identity(tmp_path, monkeypatch):
    _repository, _dispatcher, builder, python, _home = _layout(tmp_path, monkeypatch)
    target = python.with_name("python-image")
    python.rename(target)
    python.symlink_to(target.name)
    observed = {}

    def intercept(path, argv, environment):
        observed.update(path=path, argv=argv, environment=environment)
        raise _ExecIntercept

    monkeypatch.setattr(D.os, "execve", intercept)
    with pytest.raises(_ExecIntercept):
        D.exec_native_install(["install", "--codex"])
    assert observed["path"] == str(python)
    assert observed["argv"][8] == str(builder)


def test_retained_loader_executes_only_exact_inherited_builder_bytes(tmp_path):
    builder = tmp_path / "display-only-builder.py"
    marker = tmp_path / "marker"
    raw = (
        "from pathlib import Path\n"
        "import sys\n"
        "assert sys.modules[__name__].__dict__ is globals()\n"
        "assert sys.argv == [__file__, '--install-codex']\n"
        "assert __spec__ is None and __package__ is None\n"
        f"Path({str(marker)!r}).write_text(__file__+'|'+repr(__name__))\n"
    ).encode("utf-8")
    builder.write_bytes(raw)
    builder.chmod(0o600)
    descriptor = os.open(builder, os.O_RDONLY)
    try:
        info = os.fstat(descriptor)
        retained = tmp_path / "retained-builder.py"
        builder.rename(retained)
        builder.write_text("raise RuntimeError('pathname executed')\n")
        completed = subprocess.run(
            [
                sys.executable, "-I", "-B", "-c", D._RETAINED_BUILDER_LOADER,
                str(descriptor), str(len(raw)),
                hashlib.sha256(raw).hexdigest(), str(builder),
                str(info.st_uid), str(stat.S_IMODE(info.st_mode)),
            ],
            check=False, pass_fds=(descriptor,), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=dict(D.CLOSED_ENVIRONMENT),
        )
    finally:
        os.close(descriptor)
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == b""
    assert marker.read_text() == f"{builder}|'__main__'"


@pytest.mark.parametrize("mismatch", ["sha256", "size", "mode", "uid"])
def test_retained_loader_rejects_mismatched_admission(tmp_path, mismatch):
    builder = tmp_path / "builder.py"
    marker = tmp_path / "executed"
    raw = f"open({str(marker)!r}, 'w').close()\n".encode()
    builder.write_bytes(raw)
    builder.chmod(0o600)
    descriptor = os.open(builder, os.O_RDONLY)
    try:
        info = os.fstat(descriptor)
        admitted = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw), "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
        }
        admitted[mismatch] = (
            "0" * 64 if mismatch == "sha256" else admitted[mismatch] + 1
        )
        completed = subprocess.run(
            [
                sys.executable, "-I", "-B", "-c", D._RETAINED_BUILDER_LOADER,
                str(descriptor), str(admitted["size"]), admitted["sha256"],
                str(builder), str(admitted["uid"]), str(admitted["mode"]),
            ],
            check=False, pass_fds=(descriptor,), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=dict(D.CLOSED_ENVIRONMENT), timeout=10,
        )
    finally:
        os.close(descriptor)
    assert completed.returncode == 126
    assert not marker.exists()


def test_retained_loader_identity_excludes_only_access_time():
    assignment = next(
        node for node in ast.parse(D._RETAINED_BUILDER_LOADER).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "identity"
                for target in node.targets)
    )
    identity = eval(compile(ast.Expression(assignment.value), "<identity-test>", "eval"))
    fields = (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns",
    )
    original = dict.fromkeys(fields, 1)
    original["st_atime_ns"] = 1
    observed = identity(types.SimpleNamespace(**original))
    assert identity(types.SimpleNamespace(**{**original, "st_atime_ns": 2})) == observed
    for field in fields:
        assert identity(types.SimpleNamespace(**{**original, field: 2})) != observed


def test_missing_interpreters_fail_without_exec(tmp_path, monkeypatch):
    _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        D,
        "PYTHON_CANDIDATES",
        (str(tmp_path / "missing-a/python3.12"), str(tmp_path / "missing-b/python3.12")),
    )
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeInstallDispatchError, match="unavailable"):
        D.exec_native_install(["install", "--codex"])


def test_existing_unsafe_candidate_does_not_fall_through(tmp_path, monkeypatch):
    _repository, _dispatcher, _builder, safe_python, _home = _layout(
        tmp_path, monkeypatch
    )
    unsafe = tmp_path / "unsafe" / "python3.12"
    unsafe.parent.mkdir()
    unsafe.write_bytes(b"unsafe")
    unsafe.chmod(0o722)
    monkeypatch.setattr(D, "PYTHON_CANDIDATES", (str(unsafe), str(safe_python)))
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeInstallDispatchError, match="authority differs"):
        D.exec_native_install(["install", "--codex"])


def test_dangling_fixed_candidate_does_not_fall_through(tmp_path, monkeypatch):
    _repository, _dispatcher, _builder, safe_python, _home = _layout(
        tmp_path, monkeypatch
    )
    dangling = tmp_path / "dangling" / "python3.12"
    dangling.parent.mkdir()
    dangling.symlink_to("missing-python-image")
    monkeypatch.setattr(D, "PYTHON_CANDIDATES", (str(dangling), str(safe_python)))
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeInstallDispatchError, match="target is unavailable"):
        D.exec_native_install(["install", "--codex"])


def test_builder_and_dispatcher_links_are_rejected(tmp_path, monkeypatch):
    _repository, dispatcher, builder, _python, _home = _layout(tmp_path, monkeypatch)
    real_builder = builder.with_name("real-builder.py")
    builder.rename(real_builder)
    builder.symlink_to(real_builder.name)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeInstallDispatchError):
        D.exec_native_install(["install", "--codex"])

    monkeypatch.setattr(D, "_dispatch_started", False)
    builder.unlink()
    real_builder.rename(builder)
    real_dispatcher = dispatcher.with_name("real-dispatcher.py")
    dispatcher.rename(real_dispatcher)
    dispatcher.symlink_to(real_dispatcher.name)
    with pytest.raises(D.PosixNativeInstallDispatchError):
        D.exec_native_install(["install", "--codex"])


def test_builder_identity_swap_before_exec_is_rejected(tmp_path, monkeypatch):
    _repository, _dispatcher, builder, _python, _home = _layout(tmp_path, monkeypatch)
    original = D._revalidate_builder

    def swap(*args):
        builder.unlink()
        builder.write_bytes(b"replacement builder\n")
        builder.chmod(0o600)
        return original(*args)

    monkeypatch.setattr(D, "_revalidate_builder", swap)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeInstallDispatchError, match="identity drifted"):
        D.exec_native_install(["install", "--codex"])


def test_interpreter_identity_swap_before_exec_is_rejected(tmp_path, monkeypatch):
    _repository, _dispatcher, _builder, python, _home = _layout(tmp_path, monkeypatch)
    original = D._revalidate_python

    def swap(*args):
        python.unlink()
        python.write_bytes(b"replacement interpreter")
        python.chmod(0o700)
        return original(*args)

    monkeypatch.setattr(D, "_revalidate_python", swap)
    monkeypatch.setattr(
        D.os, "execve", lambda *_args: pytest.fail("exec must not run")
    )
    with pytest.raises(D.PosixNativeInstallDispatchError, match="identity drifted"):
        D.exec_native_install(["install", "--codex"])


def test_dispatcher_contains_no_pre_exec_mutation_or_ambient_authority():
    source = inspect.getsource(D)
    assert "ctypes" not in source
    assert "Security" not in source
    assert "subprocess" not in source
    assert "os.environ" not in source
    assert "getenv(" not in source
    assert "mkdir(" not in source
    assert "makedirs(" not in source
    assert "replace(" not in source
    assert "rename(" not in source
    assert "unlink(" not in source
    assert "chmod(" not in source
    assert "O_CREAT" not in source
    assert "O_TRUNC" not in source
    assert "O_WRONLY" not in source
    assert "/opt/homebrew/bin/python3.12" in source
    assert (
        "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
        in source
    )
