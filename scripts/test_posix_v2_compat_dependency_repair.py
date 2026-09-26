"""Execution-level regressions for the compatibility dependency repair route."""

from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import sys
import types
import venv


ROOT = Path(__file__).resolve().parents[1]


def _actual_bootstrap():
    tree = ast.parse((ROOT / "plamen.py").read_text(encoding="utf-8"))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_bootstrap"
    )
    namespace: dict[str, object] = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "plamen.py", "exec"), namespace)
    return namespace["_bootstrap"]


def _exercise_bootstrap(tmp_path: Path, *, cache_valid: bool):
    bootstrap = _actual_bootstrap()
    managed_root = tmp_path / "runtime" / "py312"
    managed = managed_root / "bin" / "python"
    base = tmp_path / "base" / "python3.12"
    managed.parent.mkdir(parents=True)
    base.parent.mkdir()
    base.write_bytes(b"base interpreter fixture\n")
    managed.symlink_to(base)
    source = tmp_path / "installed"
    source.mkdir()
    (source / "requirements-runtime-core.lock").write_text("core\n", encoding="utf-8")
    (source / "requirements-runtime-full.lock").write_text("full\n", encoding="utf-8")
    calls: list[list[str]] = []
    repaired = False

    class Completed:
        def __init__(self, argv, returncode=0):
            self.args = argv
            self.returncode = returncode
            self.stdout = ""
            self.stderr = ""

    class Subprocess:
        CompletedProcess = Completed
        SubprocessError = subprocess.SubprocessError

        @staticmethod
        def run(argv, **_kwargs):
            nonlocal repaired
            rendered = [str(value) for value in argv]
            calls.append(rendered)
            if rendered[1:6] == ["-I", "-B", "-m", "pip", "install"]:
                repaired = True
            return Completed(rendered)

    fake_sys = types.SimpleNamespace(
        argv=["plamen.py", "install", "--posix-compat-v2-dependencies"],
        implementation=types.SimpleNamespace(name="cpython"),
        version_info=(3, 12, 9), prefix=str(managed_root),
        executable=str(managed), modules={}, dont_write_bytecode=False,
        stderr=types.SimpleNamespace(write=lambda _value: None),
    )

    def stamp_status(_authority, **kwargs):
        valid = cache_valid or repaired or kwargs.get("expected_manifest") is not None
        observation = kwargs.get("validated_observation")
        if valid and isinstance(observation, list):
            observation.append({
                "path": "stamp", "identity": {}, "raw_sha256": "c" * 64,
                "census_summary": {
                    "census_sha256": "d" * 64, "directory_count": 1,
                    "file_count": 2, "total_bytes": 3,
                },
            })
        return "VALID" if valid else "INVALID"

    globals_ = bootstrap.__globals__
    globals_.update({
        "sys": fake_sys, "os": __import__("os"), "Path": Path,
        "subprocess": Subprocess, "time": __import__("time"),
        "re": __import__("re"), "_RUNTIME_PYTHON": (3, 12),
        "_PYTHON_DEPENDENCY_TRUST_BOUNDARY": "USER_WRITABLE_DRIFT_DETECTION_ONLY",
        "_managed_runtime_root": lambda: managed_root,
        "_managed_runtime_python": lambda: managed,
        "_runtime_lock_path": lambda: source / "requirements-runtime-core.lock",
        "_file_sha256": lambda _path: "a" * 64,
        "_runtime_stamp_valid": lambda _digest: True,
        "_public_cli_route_policy": lambda: "GOVERNED",
        "_PUBLIC_CLI_SOURCE_PACKAGE_CHECK": "SOURCE_PACKAGE_CHECK",
        "_python_dependency_authority": lambda _root=None: "b" * 64,
        "_python_dependency_stamp_status": stamp_status,
        "_retire_legacy_python_dependency_stamp": lambda: True,
        "_write_python_dependency_stamp": lambda *_args, **_kwargs: {},
        "_invalidate_python_dependency_stamp": lambda: True,
        "_publish_python_dependency_bootstrap_attestation": lambda **_kwargs: None,
        "__file__": str(source / "plamen.py"),
    })
    assert bootstrap() is True
    return managed, calls


def test_invalid_cache_repair_and_all_postconditions_use_venv_spelling(tmp_path):
    managed, calls = _exercise_bootstrap(tmp_path, cache_valid=False)
    assert len(calls) == 3
    assert all(argv[0] == str(managed) for argv in calls)
    install, probe, check = calls
    assert install[1:6] == ["-I", "-B", "-m", "pip", "install"]
    assert "--force-reinstall" in install
    assert probe[1:4] == ["-I", "-B", "-c"]
    assert check[1:] == ["-I", "-B", "-m", "pip", "check"]
    assert "--break-system-packages" not in {item for call in calls for item in call}


def test_valid_cache_probe_uses_venv_spelling_without_repair(tmp_path):
    managed, calls = _exercise_bootstrap(tmp_path, cache_valid=True)
    assert len(calls) == 1
    assert calls[0][0] == str(managed)
    assert calls[0][1:4] == ["-I", "-B", "-c"]


def test_genuine_stdlib_venv_child_preserves_prefix_identity(tmp_path):
    runtime = tmp_path / "real-venv"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(runtime)
    managed = runtime / "bin" / "python"
    completed = subprocess.run(
        [str(managed), "-I", "-B", "-c", "import sys; print(sys.prefix); print(sys.base_prefix)"],
        check=True, capture_output=True, text=True, timeout=15,
    )
    prefix, base_prefix = completed.stdout.splitlines()
    assert Path(prefix) == runtime
    assert Path(base_prefix) != runtime
