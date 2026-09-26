"""Compatibility Doctor validates the committed runtime, not a phantom copy."""
from pathlib import Path

from test_cli_release_readiness import _load_front


def test_policy_census_accepts_explicit_compatibility_runtime(tmp_path):
    front = _load_front()
    policy = tmp_path / "verification_policy"
    policy.mkdir()
    for name in front._VERIFICATION_POLICY_INSTALL_FILES:
        (policy / name).write_text("fixture", encoding="utf-8")

    assert front._missing_claude_verification_policy_files(str(tmp_path)) == []


def test_policy_census_reports_only_missing_explicit_runtime_files(tmp_path):
    front = _load_front()
    policy = tmp_path / "verification_policy"
    policy.mkdir()
    present = front._VERIFICATION_POLICY_INSTALL_FILES[0]
    (policy / present).write_text("fixture", encoding="utf-8")

    assert front._missing_claude_verification_policy_files(str(tmp_path)) == list(
        front._VERIFICATION_POLICY_INSTALL_FILES[1:]
    )


def test_doctor_keeps_native_and_compatibility_roots_distinct():
    source = __import__("inspect").getsource(_load_front().run_doctor)
    assert "plamen_dir if compatibility_install else CLAUDE_HOME" in source
    assert "if compatibility_install\n            else _missing_claude_verification_policy_files()" in source
