"""Recoverable pre-audit managed-EVM setup transaction for POSIX installs.

Package/native installation is project agnostic.  This distinct transaction is
invoked by start-config only after it has exact project, policy, acquisition,
and native-runtime authorities.  Its durable output is a signed installed-
generation receipt; callers obtain execution authority only through the
effects validator's fresh opaque admission.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import posix_native_install_transaction as native_install


JOURNAL_SCHEMA = "plamen.posix-managed-evm-setup.journal.v1"
RECEIPT_SCHEMA = "plamen.posix-managed-evm-setup.receipt.v1"
_STATES = {
    "ARMED", "STAGED", "COMMITTED", "ROLLING_BACK",
    "RECOVERY_REQUIRED", "ROLLED_BACK",
}


class PosixManagedEVMSetupError(RuntimeError):
    """A fail-closed project setup transaction error."""


class TEST_ONLY_ManagedEVMSetupCrash(BaseException):
    """Test-only process-loss simulation."""


def _fail(message: str) -> None:
    raise PosixManagedEVMSetupError(message) from None


def _effect(effects: object, name: str):
    value = getattr(effects, name, None)
    if not callable(value):
        _fail(f"managed EVM setup effect {name} is unavailable")
    return value


def _seal(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value); result.pop("journal_sha256", None)
    result["journal_sha256"] = native_install._digest(result)
    return result


def _validate_prestate(value: object, home: Path) -> dict[str, Any]:
    fields = {
        "schema", "home", "package_receipt", "native_install_receipt",
        "deployment_receipt", "prior_managed_evm_generation_receipt",
        "input_binding_sha256",
    }
    if (
        type(value) is not dict or set(value) != fields
        or value.get("schema") != "plamen.posix-managed-evm-setup.prestate.v1"
        or value.get("home") != str(home)
        or native_install._HEX64.fullmatch(
            value.get("input_binding_sha256", "")
        ) is None
    ):
        _fail("managed EVM setup predecessor is malformed")
    native_install._validate_artifact(value["package_receipt"], "package-receipt")
    native_install._validate_artifact(
        value["native_install_receipt"], "native-install-receipt",
    )
    native_install._validate_artifact(
        value["deployment_receipt"], "deployment-receipt",
    )
    prior = value["prior_managed_evm_generation_receipt"]
    if prior is not None:
        native_install._validate_artifact(
            prior, "managed-evm-generation-receipt",
        )
    return dict(value)


def _new_journal(
    transaction_id: str, plan_sha256: str, prestate: dict[str, Any],
) -> dict[str, Any]:
    return _seal({
        "schema": JOURNAL_SCHEMA, "transaction_id": transaction_id,
        "plan_sha256": plan_sha256, "state": "ARMED",
        "prestate": prestate, "stage": None, "managed_evm_receipt": None,
        "error": None,
    })


def _validate_journal(
    value: object, transaction_id: str, plan_sha256: str, home: Path,
) -> dict[str, Any]:
    fields = {
        "schema", "transaction_id", "plan_sha256", "state", "prestate",
        "stage", "managed_evm_receipt", "error", "journal_sha256",
    }
    if (
        type(value) is not dict or set(value) != fields
        or value.get("schema") != JOURNAL_SCHEMA
        or value.get("transaction_id") != transaction_id
        or value.get("plan_sha256") != plan_sha256
        or value.get("state") not in _STATES
        or native_install._HEX64.fullmatch(
            value.get("journal_sha256", "")
        ) is None
    ):
        _fail("managed EVM setup journal differs")
    unsigned = dict(value); digest = unsigned.pop("journal_sha256")
    if native_install._digest(unsigned) != digest:
        _fail("managed EVM setup journal digest differs")
    _validate_prestate(value["prestate"], home)
    return dict(value)


def _write_transition(
    transaction_fd: int, journal: dict[str, Any], state: str, fault: Any,
) -> dict[str, Any]:
    value = dict(journal); value["state"] = state; value["error"] = None
    value = _seal(value)
    native_install._atomic_write(transaction_fd, "managed-evm-journal.json", value)
    if fault is not None:
        fault(state)
    return value


def _terminal(journal: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema": RECEIPT_SCHEMA,
        "transaction_id": journal["transaction_id"],
        "plan_sha256": journal["plan_sha256"],
        "installed_prestate": journal["prestate"],
        "managed_evm_generation_receipt": journal["managed_evm_receipt"],
        "state": "COMMITTED",
    }
    value["receipt_sha256"] = native_install._digest(value)
    return value


def _validate_terminal(
    value: object, journal: dict[str, Any], effects: object,
) -> dict[str, Any]:
    fields = {
        "schema", "transaction_id", "plan_sha256", "installed_prestate",
        "managed_evm_generation_receipt", "state", "receipt_sha256",
    }
    if (
        type(value) is not dict or set(value) != fields
        or value.get("schema") != RECEIPT_SCHEMA
        or value.get("transaction_id") != journal["transaction_id"]
        or value.get("plan_sha256") != journal["plan_sha256"]
        or value.get("installed_prestate") != journal["prestate"]
        or value.get("state") != "COMMITTED"
    ):
        _fail("managed EVM setup terminal differs")
    unsigned = dict(value); digest = unsigned.pop("receipt_sha256", None)
    if digest != native_install._digest(unsigned):
        _fail("managed EVM setup terminal digest differs")
    receipt = native_install._validate_artifact(
        value["managed_evm_generation_receipt"],
        "managed-evm-generation-receipt",
    )
    _effect(effects, "validate_managed_evm_setup_receipt")(
        receipt, journal["stage"], journal["prestate"],
    )
    return dict(value)


def _rollback(
    transaction_fd: int, journal: dict[str, Any], effects: object,
) -> dict[str, Any]:
    value = _write_transition(transaction_fd, journal, "ROLLING_BACK", None)
    try:
        if value["stage"] is not None:
            _effect(effects, "rollback_managed_evm_setup")(
                value["managed_evm_receipt"], value["stage"], value["prestate"],
            )
    except Exception as exc:
        value["state"] = "RECOVERY_REQUIRED"
        value["error"] = f"{type(exc).__name__}:{str(exc)[:1000]}"
        value = _seal(value)
        native_install._atomic_write(
            transaction_fd, "managed-evm-journal.json", value,
        )
        raise
    return _write_transition(transaction_fd, value, "ROLLED_BACK", None)


def execute_managed_evm_setup_transaction(
    *, home: Path, effects: object, fault: Any = None,
) -> dict[str, Any]:
    """Provision/sign/admit one project-bound generation before phase launch."""

    account = home.absolute()
    if not account.is_dir() or account.is_symlink():
        _fail("managed EVM setup account authority differs")
    prestate = _validate_prestate(
        _effect(effects, "observe_managed_evm_setup_prestate")(account), account,
    )
    plan_prestate = dict(prestate)
    plan_prestate.pop("prior_managed_evm_generation_receipt")
    plan = {
        "schema": "plamen.posix-managed-evm-setup.plan.v1",
        "home": str(account), "installed_inputs": plan_prestate,
    }
    plan_sha256 = native_install._digest(plan)
    transaction_id = hashlib.sha256(
        b"PLAMEN-POSIX-MANAGED-EVM-SETUP-V1\0"
        + native_install._canonical(plan)
    ).hexdigest()[:32]
    root_fd, transaction_fd = native_install._open_control(account, transaction_id)
    try:
        with native_install._writer_lock(root_fd):
            existing = native_install._strict_read(
                transaction_fd, "managed-evm-journal.json",
            )
            if existing is None:
                locked = _validate_prestate(
                    _effect(effects, "observe_managed_evm_setup_prestate")(account),
                    account,
                )
                if locked != prestate:
                    _fail("managed EVM setup predecessor changed before arm")
                journal = _new_journal(transaction_id, plan_sha256, prestate)
                native_install._atomic_write(
                    transaction_fd, "managed-evm-journal.json", journal,
                )
                if fault is not None:
                    fault("ARMED")
            else:
                journal = _validate_journal(
                    existing, transaction_id, plan_sha256, account,
                )
                if journal["state"] == "COMMITTED":
                    terminal = native_install._strict_read(
                        transaction_fd, "managed-evm-receipt.json",
                    )
                    if terminal is None:
                        _fail("managed EVM setup terminal is absent")
                    return _validate_terminal(terminal, journal, effects)
                if journal["state"] in {"ROLLING_BACK", "RECOVERY_REQUIRED"}:
                    journal = _rollback(transaction_fd, journal, effects)
                if journal["state"] == "ROLLED_BACK":
                    current = _validate_prestate(
                        _effect(effects, "observe_managed_evm_setup_prestate")(
                            account,
                        ), account,
                    )
                    if current != prestate:
                        _fail("managed EVM rolled-back predecessor differs")
                    journal = _new_journal(transaction_id, plan_sha256, prestate)
                    native_install._atomic_write(
                        transaction_fd, "managed-evm-journal.json", journal,
                    )
            try:
                if journal["stage"] is None:
                    stage = native_install._validate_stage(
                        _effect(effects, "stage_managed_evm_setup")(
                            account,
                            account.joinpath(*native_install.CONTROL_SUFFIX, transaction_id),
                            prestate,
                        ), "managed-evm", transaction_id,
                    )
                    journal["stage"] = stage
                    journal = _write_transition(
                        transaction_fd, journal, "STAGED", fault,
                    )
                _effect(effects, "validate_managed_evm_setup_stage")(
                    journal["stage"], prestate,
                )
                if journal["managed_evm_receipt"] is None:
                    receipt = native_install._validate_artifact(
                        _effect(effects, "commit_managed_evm_setup")(
                            journal["stage"], prestate,
                        ), "managed-evm-generation-receipt",
                    )
                    _effect(effects, "validate_managed_evm_setup_receipt")(
                        receipt, journal["stage"], prestate,
                    )
                    journal["managed_evm_receipt"] = receipt
                terminal = _terminal(journal)
                native_install._atomic_write(
                    transaction_fd, "managed-evm-receipt.json", terminal,
                )
                journal = _write_transition(
                    transaction_fd, journal, "COMMITTED", fault,
                )
                return _validate_terminal(terminal, journal, effects)
            except Exception as operation_error:
                try:
                    _rollback(transaction_fd, journal, effects)
                except Exception as rollback_error:
                    raise PosixManagedEVMSetupError(
                        "managed EVM setup failed and authenticated rollback is incomplete: "
                        f"{type(operation_error).__name__}:{str(operation_error)[:500]} | "
                        f"{type(rollback_error).__name__}:{str(rollback_error)[:500]}"
                    ) from operation_error
                raise
    finally:
        os.close(transaction_fd); os.close(root_fd)


__all__ = [
    "JOURNAL_SCHEMA", "RECEIPT_SCHEMA", "PosixManagedEVMSetupError",
    "TEST_ONLY_ManagedEVMSetupCrash", "execute_managed_evm_setup_transaction",
]
