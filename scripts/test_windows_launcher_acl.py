"""Focused native ACL coverage for the public launcher namespace."""

import importlib.util
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_windows_launcher_acl_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows ACL contract")


def test_native_launcher_objects_are_created_with_exact_protected_acl(tmp_path):
    front = _load_front()
    directory = tmp_path / "protected"
    front._win_launcher_create_directory_secure(directory)
    directory_security = front._win_launcher_security_snapshot_path(
        directory, directory=True,
        dangerous_mask=front._WIN_LAUNCHER_EXACT_DANGEROUS,
        require_exact=True,
    )
    assert directory_security[-1] is True

    path = directory / "plamen.cmd"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = front._win_launcher_create_file_descriptor(path, flags, 0o700)
    try:
        os.write(descriptor, b"@echo off\r\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    authority = front._launcher_regular_snapshot(
        path, b"@echo off\r\n", "native protected launcher",
    )
    assert front._win_launcher_authority_is_exact(authority)


def test_inherited_existing_bin_and_byte_current_file_are_not_current(tmp_path):
    front = _load_front()
    user_root = tmp_path / "user"
    bin_path = user_root / ".local" / "bin"
    bin_path.mkdir(parents=True)
    with pytest.raises(RuntimeError, match="exact protected authority"):
        front._launcher_safe_command_directory(user_root)

    protected = tmp_path / "protected-bin"
    front._win_launcher_create_directory_secure(protected)
    command = protected / "plamen.cmd"
    command.write_bytes(b"current")
    state = front._launcher_existing_state(
        command, b"current", "inherited byte-current launcher",
    )
    assert state["kind"] == "exact-existing"
    assert state["security_current"] is False


def test_byte_current_unsafe_acls_are_republished_as_one_transaction(tmp_path):
    front = _load_front()
    directory = tmp_path / "protected-bin"
    front._win_launcher_create_directory_secure(directory)
    rows = []
    for label in ("public", "claude", "codex"):
        path = directory / f"{label}.cmd"
        raw = f"{label}-current\n".encode()
        path.write_bytes(raw)
        state = front._launcher_existing_state(
            path, raw, "inherited byte-current transaction predecessor",
        )
        assert state["security_current"] is False
        rows.append({
            "label": label,
            "path": path,
            "raw": raw,
            "state": state,
            "admitted_predecessor_raws": (raw,),
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

    for row in rows:
        current = front._launcher_existing_state(
            row["path"], row["raw"], "protected transaction successor",
        )
        assert current["security_current"] is True
    assert {item.name for item in directory.iterdir()} == {
        ".plamen-launcher.lock", "public.cmd", "claude.cmd", "codex.cmd",
    }
