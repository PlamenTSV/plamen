from __future__ import annotations

import copy
from pathlib import Path

import pytest

import auxiliary_writable_root_lease as lease_authority
import auxiliary_writable_root_startup as startup_authority
import plamen_driver as driver
from plamen_types import Checkpoint, EXIT_DEGRADED


RUN_ID = "12345678-1234-4abc-8def-1234567890ab"
OTHER_DEBT = "UNRELATED-RUNTIME-DEBT"
OTHER_DIGEST = "b" * 64


def _scratchpad(tmp_path: Path) -> Path:
    root = tmp_path / "project" / ".scratchpad"
    root.mkdir(parents=True)
    return root


def _runtime_namespace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        lease_authority,
        "_default_runtime_namespace",
        lambda: tmp_path / "provider-runtime",
    )


def test_clean_startup_clears_only_prior_auxiliary_debt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _runtime_namespace(monkeypatch, tmp_path)
    scratchpad = _scratchpad(tmp_path)
    checkpoint = Checkpoint(
        run_id=RUN_ID,
        runtime_debts={
            driver._AUXILIARY_ROOT_RUNTIME_DEBT_ID: "a" * 64,
            OTHER_DEBT: OTHER_DIGEST,
        },
    )
    config = {"_run_id": RUN_ID}

    decision = driver._run_auxiliary_writable_root_startup_boundary(
        scratchpad,
        config,
        checkpoint,
    )

    assert decision["allocation_permitted"] is True
    assert decision["allocation_disposition"] == "ALLOW_NEW_LEASES"
    assert checkpoint.runtime_debts == {OTHER_DEBT: OTHER_DIGEST}
    assert (
        config["_auxiliary_writable_root_startup_binding"]
        == decision["binding"]
    )
    loaded = Checkpoint.load(scratchpad)
    assert loaded.runtime_debts == {OTHER_DEBT: OTHER_DIGEST}


def test_quarantine_continues_with_dedicated_runtime_debt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _runtime_namespace(monkeypatch, tmp_path)
    scratchpad = _scratchpad(tmp_path)
    checkpoint = Checkpoint(run_id=RUN_ID)
    config = {"_run_id": RUN_ID}
    clean = lease_authority.reconcile_auxiliary_writable_root_leases()
    (Path(clean["registry"]) / "unexpected").write_text(
        "untrusted",
        encoding="utf-8",
    )

    decision = driver._run_auxiliary_writable_root_startup_boundary(
        scratchpad,
        config,
        checkpoint,
    )

    assert decision["allocation_permitted"] is True
    assert (
        decision["allocation_disposition"]
        == "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT"
    )
    assert checkpoint.degraded == []
    assert checkpoint.runtime_debts == {
        driver._AUXILIARY_ROOT_RUNTIME_DEBT_ID: (
            decision["receipt_sha256"]
        )
    }


def test_denial_is_durable_and_never_exposed_as_launch_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratchpad = _scratchpad(tmp_path)
    checkpoint = Checkpoint(run_id=RUN_ID)
    config = {"_run_id": RUN_ID}

    def fail() -> dict[str, object]:
        raise OSError("fixture")

    monkeypatch.setattr(
        startup_authority,
        "reconcile_auxiliary_writable_root_leases",
        fail,
    )
    decision = driver._run_auxiliary_writable_root_startup_boundary(
        scratchpad,
        config,
        checkpoint,
    )

    assert decision["allocation_permitted"] is False
    assert decision["allocation_disposition"] == "DENY_NEW_LEASES"
    assert "_auxiliary_writable_root_startup_binding" not in config
    assert checkpoint.runtime_debts == {
        driver._AUXILIARY_ROOT_RUNTIME_DEBT_ID: (
            decision["receipt_sha256"]
        )
    }
    assert (
        driver._pipeline_terminal_exit_code(checkpoint)
        == EXIT_DEGRADED
    )


def test_launch_binding_is_replayed_from_disk_and_rejects_memory_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _runtime_namespace(monkeypatch, tmp_path)
    scratchpad = _scratchpad(tmp_path)
    checkpoint = Checkpoint(run_id=RUN_ID)
    config = {"_run_id": RUN_ID}
    decision = driver._run_auxiliary_writable_root_startup_boundary(
        scratchpad,
        config,
        checkpoint,
    )

    assert driver._current_auxiliary_writable_root_startup_binding(
        scratchpad,
        config,
    ) == decision["binding"]
    drifted = copy.deepcopy(decision["binding"])
    drifted["receipt_sha256"] = "f" * 64
    config["_auxiliary_writable_root_startup_binding"] = drifted
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="binding",
    ):
        driver._current_auxiliary_writable_root_startup_binding(
            scratchpad,
            config,
        )


def test_terminal_exit_is_clean_only_without_phase_or_runtime_debt() -> None:
    assert driver._pipeline_terminal_exit_code(Checkpoint()) == 0
    assert (
        driver._pipeline_terminal_exit_code(
            Checkpoint(degraded=["recon"])
        )
        == EXIT_DEGRADED
    )
    assert (
        driver._pipeline_terminal_exit_code(
            Checkpoint(runtime_debts={OTHER_DEBT: OTHER_DIGEST})
        )
        == EXIT_DEGRADED
    )
