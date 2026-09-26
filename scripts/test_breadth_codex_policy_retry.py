"""Exact, row-local Codex cybersecurity-refusal retry regressions."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
from pathlib import Path

import plamen_driver as D
import pytest


_REFUSAL = (
    "ERROR: This content was flagged for possible cybersecurity risk. "
    "If this seems wrong, try rephrasing your request. To get authorized "
    "for security work, join the Trusted Access for Cyber program: "
    "https://chatgpt.com/cyber\n"
).encode()


def _write_compat_refusal(
    scratchpad: Path,
    *,
    label: str = "breadth_worker_B2",
    attempt: int = 1,
    returncode: int = 1,
) -> Path:
    separator = b"\n[plamen-compat-stderr]\n"
    scratchpad.joinpath(
        f"_stdio_{label}.attempt{attempt}.log"
    ).write_bytes(separator + _REFUSAL)
    receipt_root = scratchpad / ".posix_v2_compat_receipts"
    receipt_root.mkdir()
    receipt = {
        "schema": "plamen.posix_v2_compat_execution_receipt.v1",
        "status": "NONZERO_EXIT",
        "failure_code": "NONZERO_EXIT",
        "phase": "breadth",
        "label": label,
        "attempt": attempt,
        "returncode": returncode,
        "compatibility_return_value": returncode,
        "stdout_size": 0,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_size": len(_REFUSAL),
        "stderr_sha256": hashlib.sha256(_REFUSAL).hexdigest(),
    }
    path = receipt_root / f"breadth.{label}.attempt{attempt}.fixture.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path


def test_exact_worker_refusal_requires_matching_hash_bound_compat_receipt(
    tmp_path: Path,
) -> None:
    receipt = _write_compat_refusal(tmp_path)
    assert D._detect_exact_codex_worker_policy_refusal(
        scratchpad=tmp_path,
        phase_name="breadth",
        label="breadth_worker_B2",
        attempt=1,
        returncode=1,
    )

    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["label"] = "breadth_worker_B3"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    assert not D._detect_exact_codex_worker_policy_refusal(
        scratchpad=tmp_path,
        phase_name="breadth",
        label="breadth_worker_B2",
        attempt=1,
        returncode=1,
    )


def test_unrelated_nonzero_worker_exit_is_not_policy_refusal(
    tmp_path: Path,
) -> None:
    tmp_path.joinpath("_stdio_breadth_worker_B2.attempt1.log").write_text(
        "ERROR: transport disconnected while receiving response\n",
        encoding="utf-8",
    )
    assert not D._detect_exact_codex_worker_policy_refusal(
        scratchpad=tmp_path,
        phase_name="breadth",
        label="breadth_worker_B2",
        attempt=1,
        returncode=1,
    )


def test_worker_logs_surface_model_unavailable_atomically_for_phase_detector(
    tmp_path: Path,
) -> None:
    logs: list[tuple[str, Path, bytes]] = []
    for index in range(12):
        label = f"breadth_worker_B{index + 1}"
        payload = (
            b"Error: The model `gpt-daybreak-blue-latest` does not exist\n"
            if index == 7
            else (f"healthy-worker-{index}\n".encode() * 2048)
        )
        path = tmp_path / f"_stdio_{label}.attempt1.log"
        path.write_bytes(payload)
        logs.append((label, path, payload))

    def surface(row: tuple[str, Path, bytes]) -> None:
        label, path, _payload = row
        D._surface_exact_worker_log_to_phase_canonical(
            scratchpad=tmp_path,
            phase_name="breadth",
            label=label,
            log_path=path,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        list(executor.map(surface, logs))

    canonical = tmp_path / "_stdio_breadth.log"
    aggregate = canonical.read_bytes()
    for label, path, payload in logs:
        assert aggregate.count(f"# {path.name}\n".encode()) == 1
        assert aggregate.count(payload) == 1
    assert D._detect_codex_model_not_available(canonical)


def test_unavailable_model_retry_always_uses_fresh_attempt() -> None:
    assert D._codex_unavailable_model_retry_attempt(1) == 2
    assert D._codex_unavailable_model_retry_attempt(4) == 5


def test_breadth_refusal_stops_after_wave_and_preserves_healthy_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = D.Phase(
        "breadth", ["breadth"], ["analysis_*.md"],
        base_timeout_s=120, min_artifact_bytes=1,
    )
    jobs = [
        {
            "agent_id": "B1", "role": "general",
            "output": "analysis_refused.md", "focus_area": "state",
        },
        {
            "agent_id": "B2", "role": "general",
            "output": "analysis_healthy.md", "focus_area": "access",
        },
    ]
    completed: set[str] = set()
    committed: list[str] = []
    calls: list[tuple[str, int, str]] = []
    dispatch_reasons: list[tuple[int, dict[str, list[str]]]] = []

    def dispatch_plan(**kwargs):
        attempt = int(kwargs["attempt"])
        reasons = {
            str(key): list(value)
            for key, value in kwargs["retry_reasons_by_output"].items()
        }
        dispatch_reasons.append((attempt, reasons))
        return [
            {
                "job": dict(job),
                "prompt": (
                    f"row={job['agent_id']} attempt={attempt}"
                    + D._breadth_worker_retry_block(
                        str(job["output"]), reasons.get(str(job["output"]))
                    )
                ),
            }
            for job in jobs
        ]

    monkeypatch.setattr(D, "_breadth_dispatch_plan", dispatch_plan)
    monkeypatch.setattr(
        D, "_breadth_open_jobs",
        lambda _sp, _phase, rows: [
            row for row in rows if str(row["output"]) not in completed
        ],
    )
    monkeypatch.setattr(
        D, "_write_breadth_dispatch_contract", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        D, "_prepare_typed_model_worker_launch", lambda **_k: []
    )
    def record_artifact(**kwargs):
        committed.append(str(kwargs["output"]))
        return []

    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", record_artifact)
    monkeypatch.setattr(
        D, "compute_breadth_row_statuses",
        lambda *_a, **_k: [
            {
                "name": str(job["output"]),
                "status": (
                    "complete" if str(job["output"]) in completed else "missing"
                ),
            }
            for job in jobs
        ],
    )
    monkeypatch.setattr(
        D, "gate_passes",
        lambda *_a, **_k: (
            len(completed) == len(jobs),
            [
                str(job["output"]) for job in jobs
                if str(job["output"]) not in completed
            ],
        ),
    )

    def fake_codex(**kwargs) -> int:
        output = str(kwargs["expected_outputs"][0])
        attempt = int(kwargs["attempt"])
        prompt = str(kwargs["prompt"])
        calls.append((output, attempt, prompt))
        if output == "analysis_refused.md" and attempt == 1:
            # Even a complete-looking uncommitted leaf must not satisfy the
            # gate after its provider invocation exits under policy refusal.
            tmp_path.joinpath(output).write_text("untrusted\n", encoding="utf-8")
            tmp_path.joinpath(
                "_stdio_breadth_worker_B1.attempt1.log"
            ).write_bytes(_REFUSAL)
            return 1
        tmp_path.joinpath(output).write_text("healthy\n", encoding="utf-8")
        completed.add(output)
        return 0

    monkeypatch.setattr(D, "_run_one_codex_exec", fake_codex)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path),
        "_run_id": "policy-retry-test",
    }
    assert D._run_breadth_backend_fanout(
        backend="codex",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        timeout=120,
        effective_model="gpt-5.6-sol",
    ) == D._CODEX_WORKER_POLICY_REFUSAL_RC

    assert committed == ["analysis_healthy.md"]
    assert [call[:2] for call in calls].count(("analysis_healthy.md", 1)) == 1
    assert not any(
        output == "analysis_healthy.md" and attempt == 2
        for output, attempt, _prompt in calls
    )
    assert [call[:2] for call in calls].count(
        ("analysis_refused.md", 1)
    ) == 1
    assert not any(attempt == 2 for _output, attempt, _prompt in calls)
    assert dispatch_reasons == [(1, {})]
    assert all(
        "Provider Policy Refusal Retry" not in prompt
        for _output, _attempt, prompt in calls
    )
    assert tmp_path.joinpath("analysis_healthy.md").read_text() == "healthy\n"
    quarantined = list(
        tmp_path.glob(
            "_quarantine/breadth_policy_refusal/attempt-0001/analysis_refused.md"
        )
    )
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding="utf-8") == "untrusted\n"
