"""Independent red fixture for the post-arm Claude request-compile boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import claude_runtime_materialization as M
import worker_transaction as T
from headless_worker_runtime import HeadlessWorkerRuntimeError
from test_claude_launch_authority_fixtures import (
    install_test_only_launch_authority_adapter,
)
from test_worker_work_plan_v2_roster_binding_p0_am import (
    _arm_phaseio,
    _run_headless,
)


def test_typed_request_compile_failure_terminalizes_active_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recoverable post-arm rejection must not leave a phantom active row."""

    install_test_only_launch_authority_adapter(monkeypatch.setattr)
    _arm_phaseio(tmp_path)

    def reject_request(**_kwargs: object) -> object:
        raise M.ClaudeRuntimeMaterializationError(
            "RUNTIME_REQUEST_FIXTURE_REJECTED",
            "fixture request rejection"
        )

    monkeypatch.setattr(
        T,
        "compile_claude_runtime_materialization_request",
        reject_request,
    )
    with pytest.raises(
        HeadlessWorkerRuntimeError,
        match="runtime request was rejected",
    ):
        _run_headless(
            tmp_path,
            attempt_id="attempt-" + "7" * 24,
        )

    transaction_root = tmp_path / ".worker_transactions"
    registry = json.loads(
        (transaction_root / "active_attempts.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert registry["attempts"] == {}
    debts = list(
        (transaction_root / "depth").glob("**/debt.json")
    )
    assert len(debts) == 1
    debt = json.loads(
        debts[0].read_text(encoding="utf-8", errors="strict")
    )
    assert debt["reason_code"] == "CLAUDE_RUNTIME_REQUEST_REJECTED"
    assert debt["completion_emitted"] is False
