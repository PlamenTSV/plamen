"""Regression coverage for Codex compatibility exit attribution."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as D
import posix_v2_compat_runtime as compat


def _receipt(root: Path, *, failure: str, adapter_rc: int, provider_rc: int) -> None:
    receipts = root / ".posix_v2_compat_receipts"
    receipts.mkdir()
    (receipts / "recon.recon_worker_R-EXT.attempt1.fixture.json").write_text(
        json.dumps({
            "schema": D._POSIX_V2_COMPAT_EXECUTION_RECEIPT_SCHEMA,
            "phase": "recon",
            "label": "recon_worker_R-EXT",
            "attempt": 1,
            "failure_code": failure,
            "returncode": provider_rc,
            "compatibility_return_value": adapter_rc,
        }),
        encoding="utf-8",
    )


def test_codex_exec_preserves_compatibility_adapter_exit_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = SimpleNamespace(
        phase="breadth", backend="codex", work_unit_id="worker.fixture",
        immutable_inputs=(), bounded_lookup_inputs=(),
    )
    launch = SimpleNamespace(timeout_s=10, model="gpt-fixture")
    monkeypatch.setattr(
        D, "_prepared_headless_transaction_authority",
        lambda **_kwargs: (contract, launch),
    )
    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: True)
    monkeypatch.setattr(D, "_posix_v2_compat_session_for_launch", object)
    monkeypatch.setattr(D, "_surface_exact_worker_log_to_phase_canonical", lambda **_k: None)
    monkeypatch.setattr(
        D.headless_phase_identity,
        "requires_standard_posix_model_incorporation",
        lambda **_kwargs: False,
    )
    monkeypatch.setattr(
        compat, "run_codex_exec", lambda **_kwargs: compat.COMPAT_EXIT_ERROR,
    )

    rc = D._run_one_codex_exec(
        prompt="fixture", phase=SimpleNamespace(name="breadth", needs_mcp=False),
        config={"project_root": str(tmp_path), "_run_id": "fixture"},
        scratchpad=tmp_path, attempt=1, label="breadth_worker_fixture",
        expected_outputs=[], timeout=10, effective_model="gpt-fixture",
    )

    assert rc == compat.COMPAT_EXIT_ERROR
    assert rc != D.EXIT_ERROR


def test_adapter_stream_failure_reports_provider_success_distinctly(
    tmp_path: Path,
) -> None:
    _receipt(
        tmp_path, failure="RESEARCH_EVENT_STREAM",
        adapter_rc=compat.COMPAT_EXIT_ERROR, provider_rc=0,
    )

    reason = D._codex_compat_failure_reason(
        tmp_path, "recon", "recon_worker_R-EXT", 1,
        compat.COMPAT_EXIT_ERROR,
    )

    assert reason == (
        "compatibility adapter failure RESEARCH_EVENT_STREAM "
        "(adapter rc=2, provider rc=0)"
    )
    assert "provider returned" not in reason


def test_timeout_is_not_typed_as_staged_semantic_rejection(tmp_path: Path) -> None:
    receipts = tmp_path / ".posix_v2_compat_receipts"
    receipts.mkdir()
    (receipts / "depth.worker_semantic.attempt1.fixture.json").write_text(
        json.dumps({
            "schema": D._POSIX_V2_COMPAT_EXECUTION_RECEIPT_SCHEMA,
            "phase": "depth", "label": "worker_semantic", "attempt": 1,
            "failure_code": "TIMEOUT", "returncode": -2,
            "compatibility_return_value": -2,
        }),
        encoding="utf-8",
    )

    reason = D._codex_compat_failure_reason(
        tmp_path, "depth", "worker_semantic", 1, -2,
    )
    assert reason == "compatibility adapter failure TIMEOUT (adapter rc=-2, provider rc=-2)"
    assert not reason.startswith(
        "compatibility adapter failure STAGED_SEMANTIC_REJECTED "
    )


def test_staged_rejection_receipt_reaches_verifier_retry_classifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = SimpleNamespace(
        phase="sc_verify_crithigh", backend="codex", work_unit_id="worker.fixture",
        immutable_inputs=(), bounded_lookup_inputs=(),
    )
    monkeypatch.setattr(
        D, "_prepared_headless_transaction_authority",
        lambda **_kwargs: (contract, SimpleNamespace(timeout_s=10, model="gpt-fixture")),
    )
    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: True)
    monkeypatch.setattr(D, "_posix_v2_compat_session_for_launch", object)
    monkeypatch.setattr(D, "_surface_exact_worker_log_to_phase_canonical", lambda **_k: None)
    monkeypatch.setattr(
        D.headless_phase_identity,
        "requires_standard_posix_model_incorporation",
        lambda **_kwargs: False,
    )

    def rejected(**kwargs) -> int:
        scratch = kwargs["scratchpad"]
        label = kwargs["label"]
        attempt = kwargs["attempt"]
        (scratch / f"_stdio_{label}.attempt{attempt}.log").write_text(
            "provider completed normally\n", encoding="utf-8"
        )
        receipts = scratch / ".posix_v2_compat_receipts"
        receipts.mkdir()
        (receipts / f"{contract.phase}.{label}.attempt{attempt}.fixture.json").write_text(
            json.dumps({
                "schema": D._POSIX_V2_COMPAT_EXECUTION_RECEIPT_SCHEMA,
                "phase": contract.phase, "label": label, "attempt": attempt,
                "failure_code": "STAGED_SEMANTIC_REJECTED", "returncode": 0,
                "compatibility_return_value": -2,
            }), encoding="utf-8",
        )
        return -2

    monkeypatch.setattr(compat, "run_codex_exec", rejected)
    label = "verify_unit_fixture"
    rc = D._run_one_codex_exec(
        prompt="fixture", phase=SimpleNamespace(name="sc_verify_crithigh", needs_mcp=False),
        config={"project_root": str(tmp_path), "_run_id": "fixture"},
        scratchpad=tmp_path, attempt=1, label=label,
        expected_outputs=[], timeout=10, effective_model="gpt-fixture",
    )
    worker_log = tmp_path / f"_stdio_{label}.attempt1.log"
    assert rc == -2
    assert D._dynamic_verifier_staged_validation_failed(worker_log)
    assert D._dynamic_verifier_execution_debt_reason(
        returncode=rc, backend="codex", transport="exec", stdio_log=worker_log,
    ) == "VALIDATION_DEBT"
