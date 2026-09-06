"""Independent adversarial reds for the P0-AM observer/lease cutover.

These tests intentionally state the security/lifecycle contract, not the
current implementation behavior.  They should remain red until production
code closes the corresponding boundary.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys

import pytest

import pty_completion_observer as O
import worker_execution_receipts as W
from test_worker_provisional_completion_p0_am import (
    _auxiliary_lease,
    _bindings as _provisional_bindings,
    _bridge_environment,
    _bridge_invocation,
    _fixed_observer_kwargs,
    _parser,
)
from pty_exec import encode_claude_project_dir


def _bindings(
    tmp_path: Path,
    shard: str,
    environment_allowlist: tuple[str, ...],
) -> W.ExecutionBindings:
    """Keep observer/lease reds backend-neutral under the Claude runtime cutover."""

    bindings = _provisional_bindings(
        tmp_path,
        shard,
        environment_allowlist,
    )
    (tmp_path / "plan.txt").write_text(
        "{}",
        encoding="utf-8",
    )
    intent = tmp_path / "intent.txt"
    value = json.loads(intent.read_text(encoding="utf-8"))
    value["effective_backend"] = "codex"
    value["effective_model"] = "fixture-model"
    intent.write_text(
        json.dumps(value, sort_keys=True),
        encoding="utf-8",
    )
    return W.ExecutionBindings(
        run_id=bindings.run_id,
        shard_id=bindings.shard_id,
        plan=bindings.plan,
        manifest=bindings.manifest,
        intent=bindings.intent,
        context=bindings.context,
        prompt=bindings.prompt,
        tool_policy=bindings.tool_policy,
        worker=bindings.worker,
        assessors=bindings.assessors,
        effective_backend="codex",
        effective_model="fixture-model",
    )


def _self_authored_end_turn_script(output: Path, runtime: Path) -> str:
    """An arbitrary child authors both output and supposed Claude evidence."""

    event = json.dumps(
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "stop_reason": "end_turn",
                "content": [],
            },
        }
    )
    return (
        "import pathlib;"
        f"pathlib.Path({str(output / 'result.json')!r}).write_text("
        "'{\"ok\": true}');"
        f"pathlib.Path({str(runtime / 'session.jsonl')!r}).write_text("
        f"{(event + chr(10))!r})"
    )


def _observer_configuration() -> dict[str, object]:
    return {
        "schema": O.OBSERVER_SCHEMA,
        "transcript_evidence_id": "transcript",
        "transcript_root_index": 0,
        "transcript_relative_path": "session.jsonl",
        "recent_pty_byte_limit": 4096,
        "transcript_limit_bytes": 64 * 1024,
    }


def _run_observer(
    tmp_path: Path,
    *,
    shard: str,
    lease: object,
    scope_identity: str,
    runtime: Path,
    script: str,
    publish_canonical: bool = False,
    **extra: object,
) -> W.CompletedExecution:
    environment, environment_allowlist = _bridge_environment()
    bindings = _bindings(tmp_path, shard, environment_allowlist)
    session_id = f"session-{shard}"
    transcript = (
        runtime
        / "projects"
        / encode_claude_project_dir(tmp_path)
        / f"{session_id}.jsonl"
    )
    script = script.replace(
        repr(str(runtime / "session.jsonl")),
        repr(str(transcript)),
    )
    if repr(str(transcript)) in script:
        script = (
            "import pathlib;"
            f"pathlib.Path({str(transcript)!r}).parent.mkdir("
            "parents=True,exist_ok=True);"
            + script
        )
    argv, exact_transcript = _bridge_invocation(
        tmp_path,
        runtime=runtime,
        shard=shard,
        script=script,
    )
    assert exact_transcript == transcript
    worker_kwargs: dict[str, object] = {
        "scratchpad": tmp_path,
        "bindings": bindings,
        "argv": argv,
        "cwd": tmp_path,
        "output_scope_relative": f"worker-output-{shard}",
        "expected_outputs": [
            W.ExpectedOutput(
                "result",
                "result.json",
                f"canonical-{shard}.json",
            )
        ],
        "parser_digest": _parser,
        "environment": environment,
        "environment_allowlist": environment_allowlist,
        "timeout_seconds": 10,
        "publish_canonical": publish_canonical,
        "auxiliary_root_leases": (lease,),
        "process_scope_identity": scope_identity,
    }
    worker_kwargs.update(_fixed_observer_kwargs(runtime, transcript))
    worker_kwargs.update(extra)
    return W.run_observed_worker(**worker_kwargs)


def test_duplicate_json_keys_cannot_form_completion_evidence(
    tmp_path: Path,
) -> None:
    """Ambiguous JSONL must be debt, matching WER's strict-JSON policy."""

    runtime = O.prepare_claude_turn(
        {
            "observer_configuration": _observer_configuration(),
            "auxiliary_writable_roots": (tmp_path,),
        }
    )
    # Python's default JSON decoder resolves this to the last ``type`` value.
    # A security boundary must reject the ambiguity instead.
    raw = (
        b'{"type":"user","type":"assistant",'
        b'"message":{"role":"assistant","stop_reason":"end_turn","content":[]}}\n'
    )
    (tmp_path / "session.jsonl").write_bytes(raw)
    with pytest.raises(Exception, match="malformed"):
        O.probe_claude_turn(
            {
                "observer_runtime_state": runtime,
                "stdout": b"",
            }
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_arbitrary_child_cannot_self_mint_a_claude_turn_end(
    tmp_path: Path,
) -> None:
    """Observer authority must be bound to a trusted PTY producer, not JSON shape."""

    lease, scope_identity = _auxiliary_lease(
        attempt_id="review-self-authored-end-turn"
    )
    runtime = lease.root
    output = tmp_path / "worker-output-review-self-authored-end-turn"
    try:
        with pytest.raises(W.WorkerExecutionIncomplete) as captured:
            _run_observer(
                tmp_path,
                shard="review-self-authored-end-turn",
                lease=lease,
                scope_identity=scope_identity,
                runtime=runtime,
                script=_self_authored_end_turn_script(output, runtime),
                publish_canonical=True,
            )
        assert captured.value.debt_path is not None
        debt = json.loads(
            captured.value.debt_path.read_text(encoding="utf-8")
        )
        assert debt["reason_code"] == "UNTRUSTED_COMPLETION_TRANSPORT"
        observation = debt["process_observation"]
        assert observation["process_scope_cleanup_succeeded"] is True
        assert observation["process_population_zero_proven"] is True
        assert observation["completion_signal"] == "TURN_END"
        assert observation["final_completion_replay"]["accepted"] is True
        shard_dir = captured.value.arm_path.parent
        assert not list(shard_dir.glob("completion.*.json"))
        assert not list(shard_dir.glob("publish_arm.*.json"))
        assert not list(shard_dir.glob("publish.*.json"))
        assert not (tmp_path / "canonical-review-self-authored-end-turn.json").exists()
    finally:
        # Current behavior completes and revokes.  If an earlier failure leaves
        # the review root live, keep this red fixture hygienic.
        if runtime.exists():
            shutil.rmtree(runtime, ignore_errors=True)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
@pytest.mark.parametrize(
    ("case", "expected_reason"),
    (
        ("malformed-transcript", "OBSERVATION_FAILED"),
        ("timeout", "TIMEOUT"),
        ("stream-overflow", "STREAM_LIMIT_EXCEEDED"),
        ("nonzero-exit", "NONZERO_EXIT"),
    ),
)
def test_specific_transport_debt_precedes_untrusted_completion_transport(
    tmp_path: Path,
    case: str,
    expected_reason: str,
) -> None:
    """Prefer specific debt when the backend-neutral PTY can prove it."""

    attempt_id = {
        "malformed-transcript": "precedence-malformed",
        "timeout": "precedence-timeout",
        "stream-overflow": "precedence-overflow",
        "nonzero-exit": "precedence-nonzero",
    }[case]
    lease, scope_identity = _auxiliary_lease(attempt_id=attempt_id)
    runtime = lease.root
    output = tmp_path / f"worker-output-{attempt_id}"
    extra: dict[str, object] = {}
    if case == "malformed-transcript":
        malformed = (
            b'{"type":"user","type":"assistant",'
            b'"message":{"role":"assistant","stop_reason":"end_turn",'
            b'"content":[]}}\n'
        )
        script = (
            "import pathlib,time;"
            f"pathlib.Path({str(output / 'result.json')!r}).write_text("
            "'{\"ok\": true}');"
            f"pathlib.Path({str(runtime / 'session.jsonl')!r}).write_bytes("
            f"{malformed!r});time.sleep(30)"
        )
    elif case == "timeout":
        script = "import time;time.sleep(30)"
        extra["timeout_seconds"] = 0.2
    elif case == "stream-overflow":
        script = (
            "import sys,time;"
            "sys.stdout.buffer.write(b'x'*4096);"
            "sys.stdout.buffer.flush();time.sleep(30)"
        )
        extra["stdout_limit_bytes"] = 32
    else:
        script = "import os;os._exit(7)"
    try:
        with pytest.raises(W.WorkerExecutionIncomplete) as captured:
            _run_observer(
                tmp_path,
                shard=attempt_id,
                lease=lease,
                scope_identity=scope_identity,
                runtime=runtime,
                script=script,
                **extra,
            )
        assert captured.value.debt_path is not None
        debt = json.loads(
            captured.value.debt_path.read_text(encoding="utf-8")
        )
        assert debt["reason_code"] == expected_reason
        assert not list(
            captured.value.arm_path.parent.glob("completion.*.json")
        )
    finally:
        if runtime.exists():
            shutil.rmtree(runtime, ignore_errors=True)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_cancelled_before_process_creation_revokes_accepted_auxiliary_lease(
    tmp_path: Path,
) -> None:
    """Once WER persists its arm, an accepted lease must have a terminal state."""

    lease, scope_identity = _auxiliary_lease(
        attempt_id="review-cancel-before-launch"
    )
    runtime = lease.root
    try:
        with pytest.raises(W.WorkerExecutionIncomplete) as captured:
            _run_observer(
                tmp_path,
                shard="review-cancel-before-launch",
                lease=lease,
                scope_identity=scope_identity,
                runtime=runtime,
                script="raise SystemExit(99)",
                cancel_token=lambda: True,
            )
        assert captured.value.debt_path is not None
        debt = json.loads(captured.value.debt_path.read_text(encoding="utf-8"))
        assert debt["reason_code"] == "CANCELLED_BEFORE_LAUNCH"
        leaked = runtime.exists()
    finally:
        if runtime.exists():
            shutil.rmtree(runtime, ignore_errors=True)
    assert leaked is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_unsupported_process_authority_revokes_accepted_auxiliary_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fail-closed launch must not orphan its already-accepted writable root."""

    lease, scope_identity = _auxiliary_lease(
        attempt_id="review-unsupported-authority"
    )
    runtime = lease.root
    capability = W.process_tree_termination_capability()
    capability["exhaustive_descendant_termination_authority"] = False
    monkeypatch.setattr(
        W,
        "process_tree_termination_capability",
        lambda: capability,
    )
    try:
        with pytest.raises(W.WorkerExecutionIncomplete) as captured:
            _run_observer(
                tmp_path,
                shard="review-unsupported-authority",
                lease=lease,
                scope_identity=scope_identity,
                runtime=runtime,
                script="raise SystemExit(99)",
            )
        assert captured.value.debt_path is not None
        debt = json.loads(captured.value.debt_path.read_text(encoding="utf-8"))
        assert debt["reason_code"] == "PROCESS_AUTHORITY_UNSUPPORTED"
        leaked = runtime.exists()
    finally:
        if runtime.exists():
            shutil.rmtree(runtime, ignore_errors=True)
    assert leaked is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_final_evidence_capture_failure_still_revokes_auxiliary_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected provisional signal still owns cleanup of its writable root."""

    lease, scope_identity = _auxiliary_lease(
        attempt_id="review-capture-failure"
    )
    runtime = lease.root
    output = tmp_path / "worker-output-review-capture-failure"

    def reject_capture(**_kwargs: object) -> object:
        raise W.WorkerExecutionError("injected exact-evidence capture failure")

    monkeypatch.setattr(W, "_capture_completion_evidence", reject_capture)
    try:
        with pytest.raises(W.WorkerExecutionIncomplete) as captured:
            _run_observer(
                tmp_path,
                shard="review-capture-failure",
                lease=lease,
                scope_identity=scope_identity,
                runtime=runtime,
                script=(
                    _self_authored_end_turn_script(output, runtime)
                    + ";import time;time.sleep(30)"
                ),
            )
        assert captured.value.debt_path is not None
        debt = json.loads(captured.value.debt_path.read_text(encoding="utf-8"))
        assert debt["reason_code"] == "FINAL_REPLAY_REJECTED"
        leaked = runtime.exists()
    finally:
        if runtime.exists():
            shutil.rmtree(runtime, ignore_errors=True)
    assert leaked is False
