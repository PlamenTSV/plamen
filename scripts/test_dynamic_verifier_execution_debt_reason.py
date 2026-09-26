"""A generic child error is not evidence of backend quota exhaustion."""

from pathlib import Path

import pytest

import plamen_driver as D


@pytest.mark.parametrize("backend", ["codex", "claude"])
@pytest.mark.parametrize("detail", [None, "execution authority commit failed\n"])
def test_generic_exit_one_is_execution_debt(
    tmp_path: Path, backend: str, detail: str | None,
) -> None:
    log = tmp_path / "worker.log"
    if detail is not None:
        log.write_text(detail, encoding="utf-8")
    assert D._dynamic_verifier_execution_debt_reason(
        returncode=1, backend=backend, transport="exec", stdio_log=log,
    ) == "WORKER_EXECUTION_DEBT"


@pytest.mark.parametrize("backend", ["codex", "claude"])
def test_structured_rate_limit_retains_quota_classification(
    tmp_path: Path, backend: str,
) -> None:
    log = tmp_path / "worker.log"
    log.write_text(
        '{"is_error":true,"api_error_status":429,'
        '"error":{"type":"rate_limit_exceeded"}}\n', encoding="utf-8",
    )
    assert D._dynamic_verifier_execution_debt_reason(
        returncode=1, backend=backend, transport="exec", stdio_log=log,
    ) == "RATE_LIMIT_DEBT"


def test_codex_authentication_failure_is_not_quota_debt(tmp_path: Path) -> None:
    log = tmp_path / "worker.log"
    log.write_text("error: HTTP 401 unauthorized\n", encoding="utf-8")
    assert D._dynamic_verifier_execution_debt_reason(
        returncode=1, backend="codex", transport="exec", stdio_log=log,
    ) == "WORKER_EXECUTION_DEBT"


@pytest.mark.parametrize(
    ("returncode", "backend", "transport", "expected"),
    [
        (D._CODEX_WORKER_POLICY_REFUSAL_RC, "codex", "exec",
         "PROVIDER_POLICY_REFUSAL_DEBT"),
        (D._UNTRUSTED_COMPLETION_TRANSPORT_RC, "claude", "pty",
         "UNTRUSTED_COMPLETION_TRANSPORT"),
        (-2, "codex", "exec", "TIMEOUT_DEBT"),
        (17, "codex", "exec", "WORKER_EXECUTION_DEBT"),
    ],
)
def test_specific_terminal_reason_precedes_rate_limit_log(
    tmp_path: Path, returncode: int, backend: str, transport: str, expected: str,
) -> None:
    log = tmp_path / "worker.log"
    log.write_text("PLAMEN_RATE_LIMIT_DETECTED=1\n", encoding="utf-8")
    assert D._dynamic_verifier_execution_debt_reason(
        returncode=returncode, backend=backend, transport=transport, stdio_log=log,
    ) == expected


def test_success_is_not_execution_debt(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="successful execution"):
        D._dynamic_verifier_execution_debt_reason(
            returncode=0, backend="codex", transport="exec",
            stdio_log=tmp_path / "absent.log",
        )


def test_missing_current_attempt_log_cannot_reuse_old_quota_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import test_dynamic_verifier_backend_execution_authority_p0 as fixture

    case = fixture._build_case(tmp_path)
    binary = fixture._fake_codex(tmp_path / "codex", tmp_path / "count")
    session = fixture._issue_session(case)
    try:
        fixture._activate_compat(monkeypatch, session=session, binary=binary)
        case.log_path.write_text("rate_limit_exceeded\n", encoding="utf-8")
        # Negative boundary only: no child, log, or execution authority is
        # manufactured. The previous attempt's diagnostic must not survive.
        monkeypatch.setattr(D, "_run_one_codex_exec", lambda **_kwargs: 1)
        rc, authority = fixture._execute_case(case)
        assert rc == 1
        assert authority is None
        assert "produced no worker log" in case.log_path.read_text(encoding="utf-8")
        assert D._dynamic_verifier_execution_debt_reason(
            returncode=rc, backend="codex", transport="exec",
            stdio_log=case.log_path,
        ) == "WORKER_EXECUTION_DEBT"
    finally:
        session.close()
