"""Doctor repair advice must agree with the public platform admission gate."""
from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(
        "plamen_doctor_platform_guidance_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def test_posix_toolchain_guidance_does_not_offer_refused_setup() -> None:
    front = _load_front()
    advice = front._doctor_toolchain_repair_guidance("posix")
    assert advice == (
        "qualified repair is unavailable on POSIX compatibility; "
        "ordinary `plamen install`/`plamen setup` is refused until a governed "
        "POSIX installer is qualified"
    )
    assert "run `plamen setup`" not in advice


def test_windows_toolchain_guidance_keeps_supported_setup_route() -> None:
    front = _load_front()
    assert front._doctor_toolchain_repair_guidance("nt") == (
        "run `plamen setup` from a real terminal"
    )


@pytest.mark.parametrize("command", ["plamen install", "plamen install --codex"])
def test_windows_noninteractive_install_advice_does_not_require_tty(command) -> None:
    front = _load_front()
    assert front._doctor_platform_repair_guidance(command, "nt") == f"run `{command}`"


def test_doctor_applies_platform_guidance_to_missing_and_mismatched_commands() -> None:
    front = _load_front()
    source = inspect.getsource(front.run_doctor)
    assert source.count("_doctor_toolchain_repair_guidance()") == 2
    assert "elif status == \"UNAVAILABLE\" and identity_id != \"protobuf\"" in source
    assert "if identity_id != \"protobuf\"" in source


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX public guidance")
def test_posix_doctor_output_retains_hard_failure_without_refused_repair_advice(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    front = _load_front()
    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    monkeypatch.setattr(front, "CLAUDE_HOME", str(claude_home))
    monkeypatch.setattr(front, "PLAMEN_HOME", str(tmp_path))
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(front.console, "print", lambda *_a, **_k: None)
    monkeypatch.setattr(front, "_has_admitted_install_command", lambda *_a: False)
    monkeypatch.setattr(front, "_claude_projection_pending", lambda: False)
    monkeypatch.setattr(front, "_installed_runtime_root", lambda: None)
    monkeypatch.setattr(
        front,
        "_doctor_runtime_integrity_issues",
        lambda _runtime: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(front, "_python_dependency_authority", lambda: "a" * 64)
    monkeypatch.setattr(front, "_python_dependency_stamp_status", lambda _a: "VALID")
    monkeypatch.setattr(front, "_find_bin", lambda name, *_a: f"/fixture/{name}")
    monkeypatch.setattr(front, "_find_claude_bin", lambda: "/fixture/claude")
    monkeypatch.setattr(front, "_find_codex_bin", lambda: "")
    monkeypatch.setattr(
        front,
        "_codex_install_committed_descriptor",
        lambda *_a, **_k: (_ for _ in ()).throw(FileNotFoundError()),
    )
    monkeypatch.setattr(
        front,
        "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {
            "missing": ["scripts/runtime.py"],
            "mismatched": [],
        },
    )
    monkeypatch.setattr(
        front,
        "_missing_claude_verification_policy_files",
        lambda: ["verification_policy/__init__.py"],
    )
    monkeypatch.setattr(
        front,
        "_locked_toolchain_identity_report",
        lambda: [{
            "identity_id": "scip-go",
            "expected_version": "0.2.7",
            "observed_version": "0.2.4",
            "identity_status": "MISMATCH",
            "provider_ready": False,
            "provider_authority_status": "OBSERVED_NONAUTHORITATIVE",
        }],
    )

    assert front.run_doctor() == 1
    output = capsys.readouterr().out
    assert "`scip-go` expected=0.2.7 observed=0.2.4" in output
    assert "Claude runtime package incomplete" in output
    assert "Claude verification-policy install incomplete" in output
    assert "qualified repair is unavailable on POSIX compatibility" in output
    assert "ordinary `plamen install`/`plamen setup` is refused" in output
    assert "run `plamen setup`" not in output


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX dependency maintenance")
@pytest.mark.parametrize("admitted", [False, True])
def test_python_dependency_advice_preserves_only_admitted_compat_maintenance(
    monkeypatch, admitted: bool,
) -> None:
    front = _load_front()
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: admitted)
    advice = front._doctor_python_dependency_repair_guidance()
    if admitted:
        assert advice == "run `plamen install --posix-compat-v2-dependencies`"
    else:
        assert "qualified repair is unavailable" in advice
        assert "--posix-compat-v2-dependencies" not in advice
