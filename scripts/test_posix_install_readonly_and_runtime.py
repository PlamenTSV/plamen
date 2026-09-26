"""Focused POSIX install discovery and managed-launcher regressions."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys
import types

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX install front only")


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_posix_install_readonly_front", ROOT / "plamen.py",
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _fake_managed_python(tmp_path: Path):
    runtime = (tmp_path / "runtime" / "py312").absolute()
    base = (tmp_path / "base" / "python3.12").absolute()
    runtime.joinpath("bin").mkdir(parents=True)
    base.parent.mkdir(parents=True)
    base.write_bytes(b"fake-cpython-3.12\n")
    base.chmod(0o700)
    managed = runtime / "bin" / "python"
    managed.symlink_to(base)
    lock = tmp_path / "requirements-runtime-core.lock"
    lock.write_bytes(b"locked\n")
    return runtime, managed, base, lock


def test_posix_front_admits_only_exact_read_only_install_check(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(front, "__name__", "__main__")

    monkeypatch.setattr(
        front.sys, "argv", ["plamen.py", "install", "--codex", "--check"],
    )
    front._early_refuse_unsupported_posix_production_command()

    for argv in (
        ["plamen.py", "install", "--codex"],
        ["plamen.py", "install", "--check", "--codex"],
        ["plamen.py", "install", "--codex", "--check", "--extra"],
    ):
        monkeypatch.setattr(front.sys, "argv", argv)
        with pytest.raises(SystemExit) as stopped:
            front._early_refuse_unsupported_posix_production_command()
        assert stopped.value.code == 3


def test_posix_front_admits_bare_wizard_but_not_direct_audit_without_runtime(
    monkeypatch,
):
    front = _load_front()
    monkeypatch.setattr(front, "__name__", "__main__")
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: False)

    monkeypatch.setattr(front.sys, "argv", ["plamen.py"])
    front._early_refuse_unsupported_posix_production_command()

    monkeypatch.setattr(
        front.sys, "argv", ["plamen.py", "core", "/unadmitted/project"],
    )
    with pytest.raises(SystemExit) as stopped:
        front._early_refuse_unsupported_posix_production_command()
    assert stopped.value.code == 3


@pytest.mark.parametrize("dependency_status", ["VALID", "INVALID"])
def test_posix_read_only_check_never_repairs_runtime(
    tmp_path, monkeypatch, dependency_status,
):
    front = _load_front()
    runtime, managed, _base, lock = _fake_managed_python(tmp_path)
    modules = dict(sys.modules)
    modules.pop("pytest", None)

    monkeypatch.setattr(front.sys, "modules", modules)
    monkeypatch.setattr(front.sys, "implementation", types.SimpleNamespace(name="cpython"))
    monkeypatch.setattr(front.sys, "version_info", (3, 12, 12))
    monkeypatch.setattr(front.sys, "prefix", str(runtime))
    monkeypatch.setattr(front.sys, "executable", str(managed))
    monkeypatch.setattr(
        front.sys, "argv", ["plamen.py", "install", "--codex", "--check"],
    )
    monkeypatch.setattr(front, "_managed_runtime_root", lambda: runtime)
    monkeypatch.setattr(front, "_managed_runtime_python", lambda: managed)
    monkeypatch.setattr(front, "_runtime_lock_path", lambda: lock)
    monkeypatch.setattr(front, "_runtime_stamp_valid", lambda _digest: True)
    monkeypatch.setattr(front, "_file_sha256", lambda _path: "a" * 64)
    monkeypatch.setattr(front, "_python_dependency_authority", lambda _root: "b" * 64)
    monkeypatch.setattr(
        front, "_python_dependency_stamp_status",
        lambda _authority, **_kwargs: dependency_status,
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("read-only package check attempted runtime mutation")

    monkeypatch.setattr(front, "_write_runtime_stamp", forbidden)
    monkeypatch.setattr(front, "_write_python_dependency_stamp", forbidden)
    monkeypatch.setattr(front, "_invalidate_python_dependency_stamp", forbidden)
    monkeypatch.setattr(front.os, "execv", forbidden)
    monkeypatch.setattr(front.subprocess, "run", forbidden)

    assert front._bootstrap() is (dependency_status == "VALID")


def test_posix_managed_launcher_retains_venv_path_not_resolved_base(
    tmp_path, monkeypatch,
):
    front = _load_front()
    _runtime, managed, base, _lock = _fake_managed_python(tmp_path)
    monkeypatch.setattr(front, "_managed_runtime_python", lambda: managed)

    selected = front._serialized_launcher_interpreter(managed)

    assert selected == managed
    assert selected != base
    assert selected.resolve(strict=True) == base


def test_managed_launcher_authority_requires_active_cpython312_venv(
    tmp_path, monkeypatch,
):
    front = _load_front()
    runtime, managed, base, lock = _fake_managed_python(tmp_path)
    monkeypatch.setattr(front, "_managed_runtime_root", lambda: runtime)
    monkeypatch.setattr(front, "_managed_runtime_python", lambda: managed)
    monkeypatch.setattr(front, "_runtime_lock_path", lambda: lock)
    monkeypatch.setattr(front, "_runtime_stamp_valid", lambda _digest: True)
    monkeypatch.setattr(front, "_file_sha256", lambda _path: "c" * 64)
    monkeypatch.setattr(front.sys, "implementation", types.SimpleNamespace(name="cpython"))
    monkeypatch.setattr(front.sys, "version_info", (3, 12, 12))
    monkeypatch.setattr(front.sys, "prefix", str(runtime))
    monkeypatch.setattr(front.sys, "executable", str(managed))

    assert front._managed_runtime_launcher_python() == managed

    monkeypatch.setattr(front.sys, "executable", str(base))
    with pytest.raises(RuntimeError, match="active managed CPython 3.12"):
        front._managed_runtime_launcher_python()

    monkeypatch.setattr(front.sys, "executable", str(managed))
    monkeypatch.setattr(front.sys, "version_info", (3, 14, 2))
    with pytest.raises(RuntimeError, match="active managed CPython 3.12"):
        front._managed_runtime_launcher_python()


def test_doctor_uses_verified_posix_receipt_without_forging_codex_receipt(
    tmp_path, monkeypatch,
):
    front = _load_front()
    installed = (tmp_path / ".plamen").absolute()
    installed.mkdir()
    generation = "d" * 64
    provenance = {
        "generation_sha256": generation,
        "source_entry_count": 917,
    }

    monkeypatch.setattr(
        front,
        "_posix_v2_compat_install_evidence",
        lambda: {
            "installed_root": installed,
            "generation_sha256": generation,
        },
    )
    monkeypatch.setattr(
        front,
        "_verify_installed_posix_v2_compat_runtime",
        lambda root: provenance if root == installed else None,
    )

    def forbidden_codex_receipt(*_args, **_kwargs):
        raise AssertionError("compatibility Doctor requested a native receipt")

    monkeypatch.setattr(
        front, "_codex_install_doctor_issues", forbidden_codex_receipt,
    )
    evidence = front._doctor_installed_package_evidence(
        {"address": installed}, tmp_path / ".codex",
    )

    assert evidence == {
        "kind": "POSIX_COMPAT_V2",
        "generation_sha256": generation,
        "source_entry_count": 917,
    }


def test_doctor_posix_receipt_verification_is_fail_closed(tmp_path, monkeypatch):
    front = _load_front()
    installed = (tmp_path / ".plamen").absolute()
    installed.mkdir()
    monkeypatch.setattr(
        front,
        "_posix_v2_compat_install_evidence",
        lambda: {
            "installed_root": installed,
            "generation_sha256": "d" * 64,
        },
    )

    def reject_drift(_root):
        raise RuntimeError("installed compatibility runtime differs from provenance")

    monkeypatch.setattr(
        front, "_verify_installed_posix_v2_compat_runtime", reject_drift,
    )
    with pytest.raises(RuntimeError, match="differs from provenance"):
        front._doctor_installed_package_evidence(
            {"address": installed}, tmp_path / ".codex",
        )


def test_doctor_posix_receipt_cannot_cross_install_roots(tmp_path, monkeypatch):
    front = _load_front()
    installed = (tmp_path / "installed" / ".plamen").absolute()
    admitted = (tmp_path / "admitted" / ".plamen").absolute()
    installed.mkdir(parents=True)
    admitted.mkdir(parents=True)
    monkeypatch.setattr(
        front,
        "_posix_v2_compat_install_evidence",
        lambda: {
            "installed_root": admitted,
            "generation_sha256": "d" * 64,
        },
    )
    monkeypatch.setattr(
        front,
        "_verify_installed_posix_v2_compat_runtime",
        lambda _root: pytest.fail("cross-root receipt reached census verification"),
    )

    with pytest.raises(RuntimeError, match="root differs from admission"):
        front._doctor_installed_package_evidence(
            {"address": installed}, tmp_path / ".codex",
        )


def test_doctor_native_install_still_requires_codex_receipt(tmp_path, monkeypatch):
    front = _load_front()
    installed = (tmp_path / ".plamen").absolute()
    installed.mkdir()
    codex = (tmp_path / ".codex").absolute()
    expected = ["committed Codex install receipt unavailable: FileNotFoundError"]
    monkeypatch.setattr(
        front, "_posix_v2_compat_install_evidence", lambda: None,
    )
    monkeypatch.setattr(
        front,
        "_codex_install_doctor_issues",
        lambda *, codex_home, plamen_root: (
            expected
            if codex_home == codex and plamen_root == installed
            else ["wrong authority roots"]
        ),
    )

    evidence = front._doctor_installed_package_evidence(
        {"address": installed}, codex,
    )

    assert evidence["kind"] == "CODEX_COMMITTED"
    assert evidence["issues"] == expected
    assert evidence["source_entry_count"] == front._CODEX_INSTALL_SOURCE_COUNT


def test_posix_front_rejects_candidate_derived_js_anchor():
    front = _load_front()
    candidate_anchor = "0" * 64
    census_sha256 = "1" * 64
    signed = {
        "anchor_path": front._POSIX_V2_JS_ANCHOR_PATH,
        "anchor_sha256": candidate_anchor,
        "schema": front._POSIX_V2_JS_BINDING_SCHEMA,
        "source_census_sha256": census_sha256,
        "trust_boundary": front._POSIX_V2_JS_TRUST_BOUNDARY,
    }
    raw = (
        json.dumps(signed, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    provenance = {
        "js_package_binding": {
            **signed,
            "js_package_binding_sha256": hashlib.sha256(raw).hexdigest(),
        }
    }
    census = {
        front._POSIX_V2_JS_ANCHOR_PATH: {
            "kind": "file",
            "mode": 0o644,
            "path": front._POSIX_V2_JS_ANCHOR_PATH,
            "sha256": candidate_anchor,
            "size": 1,
        }
    }

    with pytest.raises(RuntimeError, match="JS binding is malformed"):
        front._posix_v2_compat_js_binding(
            provenance, census_sha256, census
        )
