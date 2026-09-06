"""Regression coverage for prelaunch Windows lease activation recovery."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import windows_low_integrity_lease as lease_module


@pytest.mark.skipif(os.name != "nt", reason="Windows MIC regression")
def test_medium_restore_accepts_a_max_path_descendant(tmp_path: Path) -> None:
    cursor = tmp_path
    while len(str(cursor / "AccessControlUpgradeable.json")) < 270:
        cursor = cursor / ("forge-artifact-" + "x" * 30)
        lease_module._windows_extended_path(cursor).mkdir()
    artifact = cursor / "AccessControlUpgradeable.json"
    lease_module._windows_extended_path(artifact).write_text(
        "{}", encoding="utf-8"
    )

    assert len(str(artifact)) >= 270
    assert lease_module._windows_extended_path(artifact).is_file()
    lease_module.restore_windows_medium_integrity_tree(tmp_path)


def test_failed_activation_accepts_implicit_medium_label(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        lease_module,
        "_set_windows_integrity_label",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            lease_module.WindowsLowIntegrityLeaseError("access denied")
        ),
    )
    monkeypatch.setattr(
        lease_module, "_windows_integrity_label_sddl", lambda _path: ""
    )
    lease_module._restore_failed_activation_root(tmp_path)


def test_failed_activation_rejects_low_label_when_restore_is_denied(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        lease_module,
        "_set_windows_integrity_label",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            lease_module.WindowsLowIntegrityLeaseError("access denied")
        ),
    )
    monkeypatch.setattr(
        lease_module,
        "_windows_integrity_label_sddl",
        lambda _path: "S:(ML;OICI;NW;;;LW)",
    )
    with pytest.raises(
        lease_module.WindowsLowIntegrityLeaseError, match="access denied"
    ):
        lease_module._restore_failed_activation_root(tmp_path)


def test_predecessor_recovery_failure_is_not_overwritten_as_idle(
    monkeypatch,
) -> None:
    lease = lease_module.WindowsLowIntegrityExecutionLease.__new__(
        lease_module.WindowsLowIntegrityExecutionLease
    )
    events: list[str] = []
    lease._acquire_lock = lambda: events.append("lock")
    lease._recover_previous_state = lambda: (_ for _ in ()).throw(
        lease_module.WindowsLowIntegrityLeaseError("stale recovery failed")
    )
    lease._unlock = lambda: events.append("unlock")
    monkeypatch.setattr(
        lease_module,
        "_write_state",
        lambda *_args, **_kwargs: events.append("write") or "digest",
    )

    with pytest.raises(
        lease_module.WindowsLowIntegrityLeaseError,
        match="stale recovery failed",
    ):
        lease._acquire_and_activate()

    assert events == ["lock", "unlock"]
