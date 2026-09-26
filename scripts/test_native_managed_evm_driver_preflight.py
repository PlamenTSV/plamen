from __future__ import annotations

import copy
from pathlib import Path
import pickle
import types

import pytest

import native_managed_evm_driver_preflight as preflight
import posix_backend_execution as runtime


def test_preflight_authority_is_nonconstructible_and_nonserializable() -> None:
    with pytest.raises(TypeError):
        preflight.NativeManagedEVMAuditPreflight()
    shell = object.__new__(preflight.NativeManagedEVMAuditPreflight)
    with pytest.raises(TypeError):
        copy.copy(shell)
    with pytest.raises(TypeError):
        copy.deepcopy(shell)
    with pytest.raises(TypeError):
        pickle.dumps(shell)


def test_adapter_has_no_ambient_or_cold_install_fallback() -> None:
    source = Path(preflight.__file__).read_text(encoding="utf-8")
    assert "NativeManagedEVMSetupEffects" in source
    assert "DarwinColdInstallEffects" not in source
    assert "Path.home(" not in source
    assert "expanduser(" not in source
    assert "subprocess" not in source
    assert "os.environ" not in source
    assert "managed_evm_slither_snapshot_projection(" in source
    assert "execute_managed_evm_setup_transaction(" in source


def test_posix_edge_rejects_absent_installed_generation_producer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    module = types.ModuleType("_plamen_native_supervisor")
    record = types.SimpleNamespace(module=module, managed_initial=object())
    authority = object()
    monkeypatch.setattr(runtime, "_native_guest_runtime_record", lambda value: record)
    project = tmp_path / "project"
    home = tmp_path / "home"
    project.mkdir()
    home.mkdir()
    descriptor = __import__("os").open(
        project,
        __import__("os").O_RDONLY | getattr(__import__("os"), "O_DIRECTORY", 0),
    )
    try:
        with pytest.raises(runtime.PosixBackendExecutionError) as raised:
            runtime.native_guest_managed_evm_setup_effects(
                authority,
                home=home,
                project_fd=descriptor,
                project_identity_sha256="1" * 64,
            )
        assert raised.value.code == "NATIVE_MANAGED_INSTALLED_GENERATION_UNAVAILABLE"
    finally:
        __import__("os").close(descriptor)


def test_unsupported_platform_fails_before_project_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "plan9")
    with pytest.raises(
        preflight.NativeManagedEVMDriverPreflightError,
        match="UNSUPPORTED_NATIVE_MANAGED_EVM_PLATFORM",
    ):
        preflight.prepare_native_managed_evm_for_audit(
            account_root=tmp_path / "absent-home",
            native_runtime=object(),
            project_root=tmp_path / "absent-project",
            project_identity_sha256="1" * 64,
        )


def test_windows_route_is_explicitly_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "win32")
    with pytest.raises(
        preflight.NativeManagedEVMDriverPreflightError,
        match="WINDOWS_NATIVE_MANAGED_EVM_UNAVAILABLE",
    ):
        preflight.prepare_native_managed_evm_for_audit(
            account_root=tmp_path,
            native_runtime=object(),
            project_root=tmp_path,
            project_identity_sha256="1" * 64,
        )
