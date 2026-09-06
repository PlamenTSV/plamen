from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Mapping

import pytest

import auxiliary_writable_root_lease as A
import pty_completion_observer as O
import pty_transport_bridge as B
import pty_worker_host as H
import worker_execution_receipts as W
from pty_exec import encode_claude_project_dir


def _parser(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8"))
    if value != {"ok": True}:
        raise ValueError("unexpected output")
    return hashlib.sha256(b'{"ok":true}').hexdigest()


def _probe(context: Mapping[str, Any]) -> Mapping[str, Any] | None:
    transcript = Path(context["auxiliary_writable_roots"][0]) / "session.jsonl"
    if not transcript.is_file():
        return None
    raw = transcript.read_bytes()
    if b'"stop_reason": "end_turn"' not in raw:
        return None
    return {
        "signal": "TURN_END",
        "transcript_size": len(raw),
        "transcript_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _final_replay(
    observation: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Mapping[str, Any]:
    raw = context["completion_evidence"]["transcript"]
    size = int(observation["transcript_size"])
    accepted = (
        len(raw) >= size
        and hashlib.sha256(raw[:size]).hexdigest()
        == observation["transcript_sha256"]
        and b'"stop_reason": "end_turn"' in raw
    )
    return {
        "accepted": accepted,
        "signal": observation["signal"],
        "replay_digest": context["evidence_replay_digest"],
    }


def _reject_final(
    observation: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Mapping[str, Any]:
    del context
    return {
        "accepted": False,
        "signal": observation["signal"],
        "replay_digest": context["evidence_replay_digest"],
    }


def _bad_digest_final(
    observation: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Mapping[str, Any]:
    del context
    return {
        "accepted": True,
        "signal": observation["signal"],
        "replay_digest": "0" * 64,
    }


def _sleep_probe(context: Mapping[str, Any]) -> Mapping[str, Any] | None:
    del context
    time.sleep(0.3)
    return None


def _observer_configuration(relative_path: str) -> dict[str, Any]:
    return {
        "schema": O.OBSERVER_SCHEMA,
        "transcript_evidence_id": "transcript",
        "transcript_root_index": 0,
        "transcript_relative_path": relative_path,
        "recent_pty_byte_limit": 1024 * 1024,
        "transcript_limit_bytes": 4 * 1024 * 1024,
    }


def _fixed_observer_kwargs(
    runtime: Path,
    transcript: Path | None = None,
) -> dict[str, Any]:
    transcript = transcript or runtime / "session.jsonl"
    relative = transcript.relative_to(runtime).as_posix()
    return {
        "provisional_completion_probe": O.probe_claude_turn,
        "final_completion_replay": O.replay_claude_turn,
        "provisional_completion_signals": ("TURN_END",),
        "completion_observer_configuration": _observer_configuration(relative),
        "completion_evidence_files": {
            "transcript": transcript,
        },
        "completion_evidence_limit_bytes": 4 * 1024 * 1024,
    }


def _bindings(
    tmp_path: Path,
    shard: str,
    environment_allowlist: tuple[str, ...] = (),
) -> W.ExecutionBindings:
    for name in ("plan", "manifest", "context", "prompt", "tool_policy"):
        (tmp_path / f"{name}.txt").write_text(
            "{}" if name == "plan" else name,
            encoding="utf-8",
        )
    (tmp_path / "intent.txt").write_text(
        json.dumps(
            {
                # The child is a Python transport stand-in.  These fixtures
                # validate the backend-neutral provisional observer contract;
                # opaque Claude provider materialization has its own exact
                # lifecycle suite.
                "effective_backend": "native",
                "effective_model": "native-pty-observer-fixture",
                "environment_allowlist_sha256": (
                    W.environment_allowlist_sha256(environment_allowlist)
                ),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return W.ExecutionBindings(
        run_id="run-provisional",
        shard_id=shard,
        plan=W.BoundInput("plan.txt"),
        manifest=W.BoundInput("manifest.txt"),
        intent=W.BoundInput("intent.txt"),
        context=W.BoundInput("context.txt"),
        prompt=W.BoundInput("prompt.txt"),
        tool_policy=W.BoundInput("tool_policy.txt"),
        worker=W.PrincipalInvocation("worker", "invocation"),
        assessors=(),
        effective_backend="native",
        effective_model="native-pty-observer-fixture",
    )


def _bridge_environment() -> tuple[dict[str, str], tuple[str, ...]]:
    environment = dict(os.environ)
    allowlist = tuple(sorted(environment, key=str.casefold))
    return environment, allowlist


def _auxiliary_lease(
    *,
    attempt_id: str,
) -> tuple[A.AuxiliaryWritableRootLease, str]:
    scope_identity = f"scope-{attempt_id}"
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id=attempt_id,
        purpose="completion-evidence",
    )
    lease = reservation.arm(
        attempt_arm_sha256=hashlib.sha256(
            f"arm:{attempt_id}".encode("utf-8")
        ).hexdigest(),
        process_scope_identity=scope_identity,
    )
    return lease, scope_identity


def _script(output: Path, transcript: Path) -> str:
    marker = output / "late.txt"
    descendant = (
        "import pathlib,time; time.sleep(0.8); "
        f"pathlib.Path({str(marker)!r}).write_text('late')"
    )
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
        "import json,pathlib,subprocess,sys,time;"
        f"pathlib.Path({str(output / 'result.json')!r}).write_text("
        "'{\"ok\": true}');"
        f"pathlib.Path({str(transcript)!r}).parent.mkdir(parents=True,exist_ok=True);"
        f"pathlib.Path({str(transcript)!r}).write_text("
        f"{(event + chr(10))!r});"
        f"subprocess.Popen([sys.executable,'-c',{descendant!r}],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
        "stderr=subprocess.DEVNULL);time.sleep(30)"
    )


def _bridge_invocation(
    tmp_path: Path,
    *,
    runtime: Path,
    shard: str,
    script: str,
) -> tuple[list[str], Path]:
    session_id = f"session-{shard}"
    transcript = (
        runtime
        / "projects"
        / encode_claude_project_dir(tmp_path)
        / f"{session_id}.jsonl"
    )
    host_manifest = tmp_path / f"host-{shard}.json"
    host_manifest.write_text(
        json.dumps(
            {
                "schema": H.HOST_MANIFEST_SCHEMA,
                "argv": [
                    str(Path(sys.executable).resolve(strict=True)),
                    "-u",
                    "-c",
                    script,
                    "--session-id",
                    session_id,
                ],
                "cwd": str(tmp_path.resolve(strict=True)),
                "environment": {
                    **dict(os.environ),
                    "CLAUDE_CONFIG_DIR": str(runtime.resolve(strict=True)),
                },
                "rows": 40,
                "columns": 120,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    bridge_manifest = tmp_path / f"bridge-{shard}.json"
    bridge_manifest.write_text(
        json.dumps(
            {
                "schema": B.BRIDGE_MANIFEST_SCHEMA,
                "host_manifest_path": str(host_manifest.resolve(strict=True)),
                "bootstrap_prompt_path": str(
                    (tmp_path / "prompt.txt").resolve(strict=True)
                ),
                "submit_bytes_hex": "0d",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return (
        [
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            "-S",
            "-B",
            str(Path(B.__file__).resolve(strict=True)),
            str(bridge_manifest.resolve(strict=True)),
        ],
        transcript,
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_provisional_signal_requires_scope_close_and_final_replay_before_transport_debt(
    tmp_path: Path,
) -> None:
    output = tmp_path / "worker-output"
    lease, scope_identity = _auxiliary_lease(attempt_id="provisional-ok")
    runtime = lease.root
    environment, environment_allowlist = _bridge_environment()
    bindings = _bindings(
        tmp_path,
        "provisional-ok",
        environment_allowlist,
    )
    transcript = (
        runtime
        / "projects"
        / encode_claude_project_dir(tmp_path)
        / "session-provisional-ok.jsonl"
    )
    argv, exact_transcript = _bridge_invocation(
        tmp_path,
        runtime=runtime,
        shard="provisional-ok",
        script=_script(output, transcript),
    )
    assert exact_transcript == transcript
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=argv,
            cwd=tmp_path,
            output_scope_relative="worker-output",
            expected_outputs=[
                W.ExpectedOutput("result", "result.json", "canonical.json")
            ],
            parser_digest=_parser,
            environment=environment,
            environment_allowlist=environment_allowlist,
            timeout_seconds=10,
            publish_canonical=False,
            auxiliary_root_leases=(lease,),
            process_scope_identity=scope_identity,
            **_fixed_observer_kwargs(runtime, transcript),
        )

    assert captured.value.debt_path is not None
    debt = json.loads(captured.value.debt_path.read_text(encoding="utf-8"))
    assert debt["reason_code"] == "UNTRUSTED_COMPLETION_TRANSPORT"
    observation = debt["process_observation"]
    assert observation["completion_signal"] == "TURN_END"
    assert observation["root_exit_origin"] == "PROVIDER_TERMINATED"
    assert observation["process_population_zero_proven"] is True
    assert observation["process_scope_cleanup_succeeded"] is True
    assert observation["final_completion_replay"]["accepted"] is True
    assert not list(captured.value.arm_path.parent.glob("completion.*.json"))
    assert not runtime.exists()
    time.sleep(1)
    assert not (output / "late.txt").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_non_terminal_transcript_emits_debt_not_completion(tmp_path: Path) -> None:
    output = tmp_path / "worker-output"
    lease, scope_identity = _auxiliary_lease(attempt_id="provisional-reject")
    runtime = lease.root
    nonterminal = json.dumps(
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "stop_reason": "tool_use",
                "content": [],
            },
        }
    )
    environment, environment_allowlist = _bridge_environment()
    bindings = _bindings(
        tmp_path,
        "provisional-reject",
        environment_allowlist,
    )
    transcript = (
        runtime
        / "projects"
        / encode_claude_project_dir(tmp_path)
        / "session-provisional-reject.jsonl"
    )
    script = (
        "import pathlib;"
        f"pathlib.Path({str(output / 'result.json')!r}).write_text("
        "'{\"ok\": true}');"
        f"pathlib.Path({str(transcript)!r}).parent.mkdir(parents=True,exist_ok=True);"
        f"pathlib.Path({str(transcript)!r}).write_text("
        f"{(nonterminal + chr(10))!r})"
    )
    argv, exact_transcript = _bridge_invocation(
        tmp_path,
        runtime=runtime,
        shard="provisional-reject",
        script=script,
    )
    assert exact_transcript == transcript
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=argv,
            cwd=tmp_path,
            output_scope_relative="worker-output",
            expected_outputs=[
                W.ExpectedOutput("result", "result.json", "canonical.json")
            ],
            parser_digest=_parser,
            environment=environment,
            environment_allowlist=environment_allowlist,
            timeout_seconds=10,
            publish_canonical=False,
            auxiliary_root_leases=(lease,),
            process_scope_identity=scope_identity,
            **_fixed_observer_kwargs(runtime, transcript),
        )
    assert captured.value.debt_path is not None
    debt = json.loads(captured.value.debt_path.read_text(encoding="utf-8"))
    assert debt["reason_code"] == "COMPLETION_SIGNAL_MISSING"
    assert not runtime.exists()
    assert not list(
        captured.value.arm_path.parent.glob("completion.*.json")
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_final_probe_recovers_signal_written_immediately_before_natural_exit(
    tmp_path: Path,
) -> None:
    output = tmp_path / "worker-output"
    lease, scope_identity = _auxiliary_lease(attempt_id="fast-final-signal")
    runtime = lease.root
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
    environment, environment_allowlist = _bridge_environment()
    bindings = _bindings(
        tmp_path,
        "fast-final-signal",
        environment_allowlist,
    )
    transcript = (
        runtime
        / "projects"
        / encode_claude_project_dir(tmp_path)
        / "session-fast-final-signal.jsonl"
    )
    script = (
        "import pathlib;"
        f"pathlib.Path({str(output / 'result.json')!r}).write_text("
        "'{\"ok\": true}');"
        f"pathlib.Path({str(transcript)!r}).parent.mkdir(parents=True,exist_ok=True);"
        f"pathlib.Path({str(transcript)!r}).write_text("
        f"{(event + chr(10))!r})"
    )
    argv, exact_transcript = _bridge_invocation(
        tmp_path,
        runtime=runtime,
        shard="fast-final-signal",
        script=script,
    )
    assert exact_transcript == transcript
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=argv,
            cwd=tmp_path,
            output_scope_relative="worker-output",
            expected_outputs=[
                W.ExpectedOutput("result", "result.json", "canonical.json")
            ],
            parser_digest=_parser,
            environment=environment,
            environment_allowlist=environment_allowlist,
            timeout_seconds=10,
            publish_canonical=False,
            auxiliary_root_leases=(lease,),
            process_scope_identity=scope_identity,
            **_fixed_observer_kwargs(runtime, transcript),
        )
    assert captured.value.debt_path is not None
    debt = json.loads(captured.value.debt_path.read_text(encoding="utf-8"))
    assert debt["reason_code"] == "UNTRUSTED_COMPLETION_TRANSPORT"
    assert debt["process_observation"]["completion_signal"] == "TURN_END"
    assert debt["process_observation"]["final_completion_replay"]["accepted"] is True
    assert debt["process_observation"]["root_exit_origin"] in {
        "PROVIDER_TERMINATED",
        "NATURAL_SIGNAL_OBSERVED_POSTEXIT",
    }
    assert not list(captured.value.arm_path.parent.glob("completion.*.json"))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_turn_end_without_complete_assigned_output_emits_debt(
    tmp_path: Path,
) -> None:
    lease, scope_identity = _auxiliary_lease(
        attempt_id="turn-end-output-missing"
    )
    runtime = lease.root
    environment, environment_allowlist = _bridge_environment()
    bindings = _bindings(
        tmp_path,
        "turn-end-output-missing",
        environment_allowlist,
    )
    transcript = (
        runtime
        / "projects"
        / encode_claude_project_dir(tmp_path)
        / "session-turn-end-output-missing.jsonl"
    )
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
    script = (
        "import pathlib,time;"
        f"pathlib.Path({str(transcript)!r}).parent.mkdir("
        "parents=True,exist_ok=True);"
        f"pathlib.Path({str(transcript)!r}).write_text("
        f"{(event + chr(10))!r});time.sleep(30)"
    )
    argv, exact_transcript = _bridge_invocation(
        tmp_path,
        runtime=runtime,
        shard="turn-end-output-missing",
        script=script,
    )
    assert exact_transcript == transcript
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=argv,
            cwd=tmp_path,
            output_scope_relative="worker-output",
            expected_outputs=[
                W.ExpectedOutput("result", "result.json", "canonical.json")
            ],
            parser_digest=_parser,
            environment=environment,
            environment_allowlist=environment_allowlist,
            timeout_seconds=10,
            publish_canonical=False,
            auxiliary_root_leases=(lease,),
            process_scope_identity=scope_identity,
            **_fixed_observer_kwargs(runtime, transcript),
        )
    debt = json.loads(captured.value.debt_path.read_text(encoding="utf-8"))
    assert debt["reason_code"] == "OUTPUT_NOT_READY_AT_COMPLETION"
    assert not runtime.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_assigned_output_mutation_after_turn_end_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "worker-output"
    lease, scope_identity = _auxiliary_lease(
        attempt_id="turn-end-output-mutates"
    )
    runtime = lease.root
    environment, environment_allowlist = _bridge_environment()
    bindings = _bindings(
        tmp_path,
        "turn-end-output-mutates",
        environment_allowlist,
    )
    transcript = (
        runtime
        / "projects"
        / encode_claude_project_dir(tmp_path)
        / "session-turn-end-output-mutates.jsonl"
    )
    argv, exact_transcript = _bridge_invocation(
        tmp_path,
        runtime=runtime,
        shard="turn-end-output-mutates",
        script=_script(output, transcript),
    )
    assert exact_transcript == transcript
    real_snapshot = W._provisional_assigned_output_snapshot

    def snapshot_then_mutate(**kwargs: object) -> list[dict[str, Any]]:
        snapshot = real_snapshot(**kwargs)
        (output / "result.json").write_text(
            '{"ok": true} ',
            encoding="utf-8",
        )
        return snapshot

    monkeypatch.setattr(
        W,
        "_provisional_assigned_output_snapshot",
        snapshot_then_mutate,
    )
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=argv,
            cwd=tmp_path,
            output_scope_relative="worker-output",
            expected_outputs=[
                W.ExpectedOutput("result", "result.json", "canonical.json")
            ],
            parser_digest=_parser,
            environment=environment,
            environment_allowlist=environment_allowlist,
            timeout_seconds=10,
            publish_canonical=False,
            auxiliary_root_leases=(lease,),
            process_scope_identity=scope_identity,
            **_fixed_observer_kwargs(runtime, transcript),
        )
    debt = json.loads(captured.value.debt_path.read_text(encoding="utf-8"))
    assert debt["reason_code"] == "OUTPUT_CHANGED_AFTER_COMPLETION_SIGNAL"
    assert not runtime.exists()


def test_partial_observer_or_scratchpad_auxiliary_root_fails_before_arm(
    tmp_path: Path,
) -> None:
    bindings = _bindings(tmp_path, "invalid-observer")
    common = {
        "scratchpad": tmp_path,
        "bindings": bindings,
        "argv": [sys.executable, "-c", "raise SystemExit(99)"],
        "cwd": tmp_path,
        "output_scope_relative": "worker-output",
        "expected_outputs": [
            W.ExpectedOutput("result", "result.json", "canonical.json")
        ],
        "parser_digest": _parser,
        "environment": {},
        "environment_allowlist": (),
        "publish_canonical": False,
    }
    with pytest.raises(W.WorkerExecutionError, match="requires probe"):
        W.run_observed_worker(
            **common,
            provisional_completion_probe=_probe,
        )
    with pytest.raises(W.WorkerExecutionError, match="raw auxiliary"):
        W.run_observed_worker(
            **common,
            auxiliary_writable_roots=(tmp_path,),
        )
    assert not (tmp_path / ".worker_execution_receipts").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_arbitrary_final_callback_is_rejected_before_arm(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        W.WorkerExecutionError,
        match="reviewed Claude JSONL package",
    ):
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=_bindings(tmp_path, "arbitrary-digest"),
            argv=[sys.executable, "-c", "raise SystemExit(99)"],
            cwd=tmp_path,
            output_scope_relative="worker-output",
            expected_outputs=[
                W.ExpectedOutput("result", "result.json", "canonical.json")
            ],
            parser_digest=_parser,
            environment={},
            environment_allowlist=(),
            publish_canonical=False,
            provisional_completion_probe=_probe,
            final_completion_replay=_bad_digest_final,
            provisional_completion_signals=("TURN_END",),
        )
    assert not (tmp_path / ".worker_execution_receipts").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows lifecycle checkpoint")
def test_callback_timeout_helper_is_bounded() -> None:
    started = time.monotonic()
    with pytest.raises(W.WorkerExecutionError, match="armed timeout"):
        W._invoke_bounded_callback(
            _sleep_probe,
            ({},),
            timeout_seconds=0.05,
            label="test sleeper",
        )
    assert time.monotonic() - started < 3


def test_negative_transport_signal_is_rejected_before_arm(tmp_path: Path) -> None:
    runtime = tmp_path / "never-materialized"
    with pytest.raises(W.WorkerExecutionError, match="reviewed positive"):
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=_bindings(tmp_path, "negative-signal"),
            argv=[sys.executable, "-c", "raise SystemExit(99)"],
            cwd=tmp_path,
            output_scope_relative="worker-output",
            expected_outputs=[
                W.ExpectedOutput("result", "result.json", "canonical.json")
            ],
            parser_digest=_parser,
            environment={},
            environment_allowlist=(),
            publish_canonical=False,
            provisional_completion_probe=_probe,
            final_completion_replay=_final_replay,
            provisional_completion_signals=("RATE_LIMIT",),
            completion_evidence_files={
                "transcript": runtime / "session.jsonl",
            },
        )
    assert not (tmp_path / ".worker_execution_receipts").exists()
