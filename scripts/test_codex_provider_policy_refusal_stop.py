"""Provider-policy refusal is durable debt, never an automatic retry hint."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import plamen_driver as driver


_REFUSAL = (
    "ERROR: This content was flagged for possible cybersecurity risk. "
    "If this seems wrong, try rephrasing your request. To get authorized "
    "for security work, join the Trusted Access for Cyber program: "
    "https://chatgpt.com/cyber\n"
).encode()


def _write_bound_worker_refusal(
    root: Path,
    *,
    phase: str = "depth",
    label: str = "depth_worker_depth-edge-case",
    attempt: int = 1,
) -> Path:
    separator = b"\n[plamen-compat-stderr]\n"
    (root / f"_stdio_{label}.attempt{attempt}.log").write_bytes(
        separator + _REFUSAL
    )
    receipts = root / ".posix_v2_compat_receipts"
    receipts.mkdir(exist_ok=True)
    payload = {
        "schema": "plamen.posix_v2_compat_execution_receipt.v1",
        "status": "NONZERO_EXIT",
        "failure_code": "NONZERO_EXIT",
        "phase": phase,
        "label": label,
        "attempt": attempt,
        "returncode": 1,
        "compatibility_return_value": 1,
        "stdout_size": 0,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_size": len(_REFUSAL),
        "stderr_sha256": hashlib.sha256(_REFUSAL).hexdigest(),
    }
    path = receipts / f"{phase}.{label}.attempt{attempt}.fixture.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_stale_canonical_refusal_cannot_qualify_current_attempt(
    tmp_path: Path,
) -> None:
    (tmp_path / "_stdio_depth.log").write_bytes(_REFUSAL)
    assert driver._codex_provider_policy_refusal_evidence(
        scratchpad=tmp_path,
        phase_name="depth",
        attempt=2,
        returncode=1,
    ) == ()

    attempt_log = tmp_path / "_stdio_depth.attempt2.log"
    attempt_log.write_bytes(_REFUSAL)
    evidence = driver._codex_provider_policy_refusal_evidence(
        scratchpad=tmp_path,
        phase_name="depth",
        attempt=2,
        returncode=1,
    )
    assert len(evidence) == 1
    assert evidence[0]["scope"] == "PHASE_ATTEMPT"
    assert evidence[0]["log_artifact"] == attempt_log.name
    assert evidence[0]["log_sha256"] == hashlib.sha256(_REFUSAL).hexdigest()


def test_fanout_refusal_requires_hash_bound_current_worker_receipt(
    tmp_path: Path,
) -> None:
    receipt = _write_bound_worker_refusal(tmp_path)
    evidence = driver._codex_provider_policy_refusal_evidence(
        scratchpad=tmp_path,
        phase_name="depth",
        attempt=1,
        returncode=1,
    )
    assert len(evidence) == 1
    assert evidence[0]["scope"] == "WORKER_ATTEMPT"
    assert evidence[0]["label"] == "depth_worker_depth-edge-case"
    assert evidence[0]["execution_receipt_sha256"] == hashlib.sha256(
        receipt.read_bytes()
    ).hexdigest()

    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["stderr_sha256"] = "0" * 64
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    assert driver._codex_provider_policy_refusal_evidence(
        scratchpad=tmp_path,
        phase_name="depth",
        attempt=1,
        returncode=1,
    ) == ()


def test_depth_resume_uses_disjoint_current_transport_attempts(
    tmp_path: Path,
) -> None:
    _write_bound_worker_refusal(tmp_path, attempt=1)
    current_attempts = driver._codex_phase_refusal_worker_attempts(
        "depth", 2, {"pty_continuation_budget": 3}
    )
    assert current_attempts == (6, 7)
    assert driver._codex_provider_policy_refusal_evidence(
        scratchpad=tmp_path,
        phase_name="depth",
        attempt=2,
        returncode=1,
        worker_attempts=current_attempts,
    ) == ()

    _write_bound_worker_refusal(tmp_path, attempt=6)
    evidence = driver._codex_provider_policy_refusal_evidence(
        scratchpad=tmp_path,
        phase_name="depth",
        attempt=2,
        returncode=1,
        worker_attempts=current_attempts,
    )
    assert len(evidence) == 1
    assert evidence[0]["attempt"] == 6
    assert evidence[0]["log_artifact"].endswith(".attempt6.log")


def test_refusal_receipt_commits_typed_incomplete_debt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: dict[str, object] = {}
    checkpoint = SimpleNamespace(
        run_id="run-17",
        save=lambda root: calls.setdefault("saved", Path(root)),
    )
    phase = SimpleNamespace(name="depth")
    monkeypatch.setattr(
        driver,
        "_append_phase_io_debt",
        lambda *args: calls.setdefault("debt", args),
    )
    monkeypatch.setattr(
        driver,
        "_commit_incomplete_phase_attempt",
        lambda *args: calls.setdefault("commit", args),
    )
    evidence = ({
        "scope": "PHASE_ATTEMPT",
        "label": "depth",
        "attempt": 1,
        "returncode": 1,
        "log_artifact": "_stdio_depth.attempt1.log",
        "log_sha256": "a" * 64,
        "log_size": 42,
        "execution_receipt_artifact": "",
        "execution_receipt_sha256": "",
    },)

    receipt_path = driver._record_codex_provider_policy_refusal(
        phase=phase,
        checkpoint=checkpoint,
        scratchpad=tmp_path,
        config={"project_root": str(tmp_path)},
        attempt=1,
        returncode=1,
        evidence=evidence,
    )
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == (
        "plamen.codex_provider_policy_refusal.v1"
    )
    assert payload["disposition"] == "INCOMPLETE_WITH_DEBT"
    assert payload["recovery"] == "EXPLICIT_OPERATOR_RESUME_REQUIRED"
    assert payload["automatic_retry_authorized"] is False
    assert payload["prompt_rewrite_authorized"] is False
    assert payload["model_switch_authorized"] is False
    assert payload["feedback_submission_authorized"] is False
    assert payload["evidence"] == list(evidence)
    assert "commit" in calls
    assert "debt" in calls
    assert calls["saved"] == tmp_path


def test_both_refusal_branches_stop_before_generic_retry() -> None:
    source = inspect.getsource(driver.main)
    first = source.split("if _policy_refusal_evidence:", 1)[1].split(
        "# Esc halt", 1
    )[0]
    retry = source.split("if _retry_policy_refusal_evidence:", 1)[1].split(
        "# v2.4.3", 1
    )[0]
    for branch in (first, retry):
        assert "_record_codex_provider_policy_refusal(" in branch
        assert "sys.exit(EXIT_DEGRADED)" in branch
        assert "_run_retry_phase(" not in branch
        assert "_write_retry_hint(" not in branch
        assert "false positive" not in branch.lower()
        assert "display.print_provider_policy_stop(" in branch
        assert "display.print_failure_diagnosis(" not in branch


def test_sc_and_l1_depth_guidance_never_respawn_policy_refusals() -> None:
    for pipeline in ("sc", "l1"):
        guidance = driver._codex_depth_artifact_checklist(
            pipeline, "thorough"
        )
        assert "Classify the terminal result first" in guidance
        assert "explicitly refused the work: STOP" in guidance
        assert "do not respawn, rephrase, or switch models" in guidance
        assert (
            "Only for\nan independently retryable thread, transport, or "
            "silent execution\nfailure"
        ) in guidance
        assert "thread limit, content filter, or silent failure" not in guidance
