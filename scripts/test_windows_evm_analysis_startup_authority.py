"""Windows SC/EVM startup authority regressions."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import plamen_driver as D
import recon_prepass


class _WindowsOSProxy:
    name = "nt"
    PathLike = os.PathLike

    @staticmethod
    def fspath(value: object) -> str:
        return os.fspath(value)


def _config() -> D._DriverConfig:
    return D._DriverConfig(
        {
            "_run_id": "windows-run-001",
            "pipeline": "sc",
            "mode": "core",
            "language": "evm",
            "cli_backend": "codex",
            "project_root": r"C:\Audit Targets\Protocol",
            "scratchpad": r"C:\Audit Targets\Protocol\.scratchpad",
        },
        native_guest_runtime_authorities=None,
    )


def _workspace(*, project_root: str | None = None) -> dict[str, object]:
    tools = [
        {
            "tool_id": tool_id,
            "tool_row_sha256": str(index) * 64,
        }
        for index, tool_id in enumerate(
            ("forge", "opengrep", "semgrep", "slither", "solc"), start=1
        )
    ]
    return {
        "run_id": "windows-run-001",
        "receipt_sha256": "a" * 64,
        "owner": {
            "work_unit_key": (
                "sc/core/evm/codex/recon/evm_analysis_workspace_capture"
            ),
        },
        "snapshot": {"snapshot_sha256": "b" * 64},
        "project_root": {
            "absolute_path": (
                project_root or r"c:\audit targets\protocol"
            ),
        },
        "build_root": {
            "absolute_path": r"C:\Audit Targets\Protocol",
        },
        "root_relation": {"relation_sha256": "c" * 64},
        "tools": tools,
    }


def _issue_and_bind(config: D._DriverConfig) -> object:
    authority = D._issue_evm_analysis_session_for_startup(
        _workspace(),
        config=config,
        scratchpad=r"C:\AUDIT TARGETS\PROTOCOL\.scratchpad",
        run_id="windows-run-001",
        snapshot_sha256="b" * 64,
        observed_tool_authorities={},
        implementation_root=Path.cwd(),
    )
    D._bind_evm_session_tool_authority(config, authority)
    return authority


def test_windows_path_form_startup_binds_non_executable_workspace_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(D, "os", _WindowsOSProxy())
    monkeypatch.setattr(
        D,
        "issue_session_bound_evm_tool_authority",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("Windows startup entered POSIX session issuance")
        ),
    )
    monkeypatch.setattr(
        D,
        "_native_guest_runtime_authorities_for_launch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("Windows startup requested POSIX native authority")
        ),
    )
    config = _config()

    authority = _issue_and_bind(config)
    binding = D._require_windows_evm_analysis_session_authority(
        config, authority
    )

    assert D._windows_evm_analysis_session_authority_for_launch(config) is authority
    assert config.get("_evm_session_tool_authority") is authority
    assert config.get("_native_guest_runtime_authority") is None
    assert authority.tool_ids == ()
    assert binding["schema"] == "plamen.windows_evm_analysis_session.v1"
    assert binding["project_root"] == r"c:\audit targets\protocol"
    assert binding["scratchpad"] == r"c:\audit targets\protocol\.scratchpad"
    assert binding["execution_authority"] is False
    assert binding["tool_ids"] == []


def test_windows_snapshot_preparation_does_not_request_posix_native_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(D, "os", _WindowsOSProxy())
    config = _config()
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        D,
        "_native_guest_runtime_authorities_for_launch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("Windows preparation requested POSIX native authority")
        ),
    )

    def prepare(value, **kwargs):
        observed["config"] = value
        observed["kwargs"] = kwargs
        return {"status": "PREPARED", "reason": "windows-local-workspace"}

    monkeypatch.setattr(recon_prepass, "prepare_snapshot_bound_inputs", prepare)

    assert D._prepare_snapshot_bound_inputs(config) == {
        "status": "PREPARED",
        "reason": "windows-local-workspace",
    }
    assert observed == {"config": config, "kwargs": {}}


def test_windows_session_absent_or_forged_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(D, "os", _WindowsOSProxy())
    config = _config()

    with pytest.raises(
        D.HeadlessWorkerRuntimeError,
        match="session authority is absent, forged, or expired",
    ):
        D._windows_evm_analysis_session_authority_for_launch(config)

    forged = object.__new__(D._WindowsEVMAnalysisSessionAuthority)
    with pytest.raises(
        D.HeadlessWorkerRuntimeError,
        match="session authority is absent, forged, or expired",
    ):
        D._bind_evm_session_tool_authority(config, forged)


def test_windows_session_rejects_root_tamper_after_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(D, "os", _WindowsOSProxy())
    config = _config()
    _issue_and_bind(config)

    dict.__setitem__(
        config,
        "scratchpad",
        r"C:\Audit Targets\Protocol\foreign-scratchpad",
    )
    with pytest.raises(
        D.HeadlessWorkerRuntimeError,
        match="belongs to another audit",
    ):
        config.get("_evm_session_tool_authority")


def test_windows_session_rejects_workspace_root_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(D, "os", _WindowsOSProxy())
    config = _config()

    with pytest.raises(
        D.HeadlessWorkerRuntimeError,
        match="workspace differs from startup authority",
    ):
        D._issue_windows_evm_analysis_session_authority(
            _workspace(project_root=r"D:\Foreign\Protocol"),
            config=config,
            scratchpad=r"C:\Audit Targets\Protocol\.scratchpad",
            run_id="windows-run-001",
            snapshot_sha256="b" * 64,
        )


def test_posix_driver_config_still_requires_native_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _PosixOSProxy(_WindowsOSProxy):
        name = "posix"

    monkeypatch.setattr(D, "os", _PosixOSProxy())
    with pytest.raises(TypeError, match="requires native guest authority"):
        D._DriverConfig(
            {
                "pipeline": "sc",
                "mode": "core",
                "language": "evm",
                "cli_backend": "codex",
            },
            native_guest_runtime_authorities=None,
        )
