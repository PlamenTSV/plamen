from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import worker_execution_receipts as W


def strict_json_digest(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("finding_id"), str):
        raise ValueError("output must be a finding object")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _bindings(tmp_path: Path, shard: str) -> W.ExecutionBindings:
    inputs = tmp_path / f"inputs-{shard}"
    inputs.mkdir()
    allowlist_sha = W.environment_allowlist_sha256(())
    intent = {
        # These fixtures exercise backend-neutral stream and output authority.
        # Use the native lane so they do not bypass or counterfeit the
        # separately tested opaque Claude provider-runtime parent.
        "effective_backend": "native",
        "effective_model": "native-fixture",
        "environment_allowlist_sha256": allowlist_sha,
    }
    for name, content in {
        "plan.json": "{}\n",
        "manifest.json": "{}\n",
        "intent.json": json.dumps(intent, sort_keys=True) + "\n",
        "context.md": "context\n",
        "prompt.md": "prompt\n",
        "tool-policy.json": '{"filesystem_write":false}\n',
    }.items():
        (inputs / name).write_text(content, encoding="utf-8")
    prefix = inputs.relative_to(tmp_path).as_posix()
    return W.ExecutionBindings(
        run_id="stream-run",
        shard_id=shard,
        plan=W.BoundInput(f"{prefix}/plan.json"),
        manifest=W.BoundInput(f"{prefix}/manifest.json"),
        intent=W.BoundInput(f"{prefix}/intent.json"),
        context=W.BoundInput(f"{prefix}/context.md"),
        prompt=W.BoundInput(f"{prefix}/prompt.md"),
        tool_policy=W.BoundInput(f"{prefix}/tool-policy.json"),
        worker=W.PrincipalInvocation("stream-worker", f"worker-{shard}"),
        assessors=(W.PrincipalInvocation("stream-assessor", f"assessor-{shard}"),),
        effective_backend="native",
        effective_model="native-fixture",
    )


def _run(
    tmp_path: Path,
    *,
    shard: str,
    script: str,
    source_mode: str = W.STDOUT_ASSIGNED_OUTPUT,
    stdout_limit: int = 4096,
    stderr_limit: int = 4096,
    expected_outputs: tuple[W.ExpectedOutput, ...] | None = None,
    timeout: float = 5.0,
) -> W.CompletedExecution:
    return W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=_bindings(tmp_path, shard),
        argv=[sys.executable, "-c", script],
        cwd=tmp_path,
        output_scope_relative=f"worker-out-{shard}",
        expected_outputs=expected_outputs
        or (W.ExpectedOutput("finding-H-01", "result.json", f"canonical/{shard}.json"),),
        parser_digest=strict_json_digest,
        environment={},
        environment_allowlist=(),
        timeout_seconds=timeout,
        output_source_mode=source_mode,
        stdout_limit_bytes=stdout_limit,
        stderr_limit_bytes=stderr_limit,
    )


def _stdout_script(raw: bytes, *, stderr: bytes = b"") -> str:
    return (
        "import sys; "
        f"sys.stdout.buffer.write({raw!r}); sys.stdout.buffer.flush(); "
        f"sys.stderr.buffer.write({stderr!r}); sys.stderr.buffer.flush()"
    )


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_stdout_is_raw_single_assigned_output_without_worker_filesystem_write(
    tmp_path: Path,
) -> None:
    raw = b'{"finding_id":"H-01","status":"PROPOSED"}\n'
    completed = _run(
        tmp_path,
        shard="stdout-success",
        script=_stdout_script(raw, stderr=b"diagnostic\n"),
        stdout_limit=len(raw),
        stderr_limit=len(b"diagnostic\n"),
    )

    staged = tmp_path / "worker-out-stdout-success" / "result.json"
    assert staged.read_bytes() == raw
    assert completed.published_paths[0].read_bytes() == raw
    arm = _load(completed.arm_path)
    receipt = _load(completed.receipt_path)
    assert arm["output_contract"]["source_mode"] == W.STDOUT_ASSIGNED_OUTPUT  # type: ignore[index]
    assert arm["process_intent"]["stream_limits"] == {  # type: ignore[index]
        "stdout_bytes": len(raw),
        "stderr_bytes": len(b"diagnostic\n"),
    }
    assert receipt["output_source_mode"] == W.STDOUT_ASSIGNED_OUTPUT
    assert receipt["stream_limits"] == arm["process_intent"]["stream_limits"]  # type: ignore[index]
    assert receipt["stream_observation"] == {
        "stdout_captured_size": len(raw),
        "stderr_captured_size": len(b"diagnostic\n"),
        "stdout_overflow": False,
        "stderr_overflow": False,
    }


def test_default_worker_file_source_mode_is_preserved_and_bound(tmp_path: Path) -> None:
    script = (
        "from pathlib import Path; "
        "p=Path('worker-out-file-default/result.json'); "
        "p.parent.mkdir(parents=True, exist_ok=True); "
        "p.write_text('{\"finding_id\":\"H-01\"}', encoding='utf-8')"
    )
    completed = W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=_bindings(tmp_path, "file-default"),
        argv=[sys.executable, "-c", script],
        cwd=tmp_path,
        output_scope_relative="worker-out-file-default",
        expected_outputs=(
            W.ExpectedOutput("finding-H-01", "result.json", "canonical/file-default.json"),
        ),
        parser_digest=strict_json_digest,
        environment={},
        environment_allowlist=(),
        timeout_seconds=5,
    )

    arm = _load(completed.arm_path)
    receipt = _load(completed.receipt_path)
    assert arm["output_contract"]["source_mode"] == W.WORKER_FILE_OUTPUTS  # type: ignore[index]
    assert receipt["output_source_mode"] == W.WORKER_FILE_OUTPUTS
    assert arm["process_intent"]["stream_limits"] == {  # type: ignore[index]
        "stdout_bytes": W.DEFAULT_STDOUT_LIMIT_BYTES,
        "stderr_bytes": W.DEFAULT_STDERR_LIMIT_BYTES,
    }


def test_stdout_mode_requires_exactly_one_assigned_output_before_arm(tmp_path: Path) -> None:
    with pytest.raises(W.WorkerExecutionError, match="exactly one"):
        _run(
            tmp_path,
            shard="stdout-two",
            script=_stdout_script(b"{}"),
            expected_outputs=(
                W.ExpectedOutput("one", "one.json", "canonical/one.json"),
                W.ExpectedOutput("two", "two.json", "canonical/two.json"),
            ),
        )
    assert not list(tmp_path.glob(".worker_execution_receipts/stdout-two/arm_*.json"))


def test_stdout_mode_rejects_worker_created_scope_bytes(tmp_path: Path) -> None:
    raw = b'{"finding_id":"H-01"}\n'
    script = (
        "import sys; from pathlib import Path; "
        "p=Path('worker-out-stdout-contamination/foreign.txt'); "
        "p.parent.mkdir(parents=True, exist_ok=True); "
        "p.write_text('foreign', encoding='utf-8'); "
        f"sys.stdout.buffer.write({raw!r}); sys.stdout.buffer.flush()"
    )
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(
            tmp_path,
            shard="stdout-contamination",
            script=script,
            stdout_limit=len(raw),
            stderr_limit=0,
        )

    assert captured.value.debt_path is not None
    debt = _load(captured.value.debt_path)
    assert debt["reason_code"] == "OUTPUT_SOURCE_CONTAMINATION"
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))
    assert not (tmp_path / "canonical" / "stdout-contamination.json").exists()


@pytest.mark.parametrize(
    "stdout_limit,stderr_limit,stdout_bytes,stderr_bytes,overflow_stream",
    [
        pytest.param(32, 4096, b"x" * 100_000, b"", "stdout", id="stdout"),
        pytest.param(4096, 16, b"", b"y" * 100_000, "stderr", id="stderr"),
        pytest.param(4096, 0, b"", b"one-byte", "stderr", id="stderr-zero"),
    ],
)
def test_stream_overflow_terminates_tree_is_bounded_and_emits_durable_debt(
    tmp_path: Path,
    stdout_limit: int,
    stderr_limit: int,
    stdout_bytes: bytes,
    stderr_bytes: bytes,
    overflow_stream: str,
) -> None:
    marker = tmp_path / f"{overflow_stream}-descendant-survived.txt"
    descendant = (
        "import time; from pathlib import Path; time.sleep(0.7); "
        f"Path({marker.name!r}).write_text('alive', encoding='utf-8')"
    )
    script = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL); "
        f"sys.stdout.buffer.write({stdout_bytes[:1]!r} * {len(stdout_bytes)}); "
        "sys.stdout.buffer.flush(); "
        f"sys.stderr.buffer.write({stderr_bytes[:1]!r} * {len(stderr_bytes)}); "
        "sys.stderr.buffer.flush(); "
        "time.sleep(10)"
    )
    started = time.monotonic()
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(
            tmp_path,
            shard=f"overflow-{overflow_stream}-{stderr_limit}",
            script=script,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            timeout=5,
        )

    assert time.monotonic() - started < 2.0
    assert captured.value.debt_path is not None
    debt = _load(captured.value.debt_path)
    assert debt["reason_code"] == "STREAM_LIMIT_EXCEEDED"
    observation = debt["process_observation"]
    assert observation["process_tree_terminated"] is True  # type: ignore[index]
    assert observation["stream_observation"][f"{overflow_stream}_overflow"] is True  # type: ignore[index]
    blob = debt[f"{overflow_stream}_blob"]
    assert blob["size"] == (stdout_limit if overflow_stream == "stdout" else stderr_limit)  # type: ignore[index]
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))
    retained_scope = (
        tmp_path / f"worker-out-overflow-{overflow_stream}-{stderr_limit}"
    )
    assert retained_scope.is_dir()
    assert not list(retained_scope.iterdir())
    time.sleep(0.85)
    assert not marker.exists()


def test_stream_capture_never_calls_unbounded_popen_communicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> tuple[bytes, bytes]:
        raise AssertionError("Popen.communicate is an unbounded stream accumulator")

    monkeypatch.setattr(subprocess.Popen, "communicate", forbidden)
    raw = b'{"finding_id":"H-01"}\n'
    completed = _run(
        tmp_path,
        shard="no-communicate",
        script=_stdout_script(raw),
        stdout_limit=len(raw),
        stderr_limit=0,
    )
    assert completed.published_paths[0].read_bytes() == raw


def test_stream_reader_failure_terminates_promptly_and_emits_no_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_drain(reader: W._BoundedPipeReader) -> None:
        reader.error = OSError("injected bounded-reader failure")
        reader.done.set()
        reader._state_changed.set()

    monkeypatch.setattr(W._BoundedPipeReader, "_drain", failed_drain)
    started = time.monotonic()
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(
            tmp_path,
            shard="reader-failure",
            script="import time; time.sleep(10)",
            stdout_limit=8,
            stderr_limit=8,
            timeout=5,
        )

    assert time.monotonic() - started < 2.0
    assert captured.value.debt_path is not None
    debt = _load(captured.value.debt_path)
    assert debt["reason_code"] == "OBSERVATION_FAILED"
    assert "bounded stdout capture failed" in debt["detail"]
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))


def test_stream_ceiling_also_applies_to_default_worker_file_mode(
    tmp_path: Path,
) -> None:
    script = (
        "import sys; from pathlib import Path; "
        "p=Path('worker-out-file-overflow/result.json'); p.parent.mkdir(parents=True); "
        "p.write_text('{\"finding_id\":\"H-01\"}', encoding='utf-8'); "
        "sys.stdout.buffer.write(b'x' * 100000); sys.stdout.buffer.flush()"
    )
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(
            tmp_path,
            shard="file-overflow",
            script=script,
            source_mode=W.WORKER_FILE_OUTPUTS,
            stdout_limit=8,
            stderr_limit=0,
        )

    assert captured.value.debt_path is not None
    assert _load(captured.value.debt_path)["reason_code"] == "STREAM_LIMIT_EXCEEDED"
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))
    assert not (tmp_path / "canonical" / "file-overflow.json").exists()


@pytest.mark.parametrize("field", ("output_source_mode", "stream_limits", "stream_observation"))
def test_replay_rejects_forged_completion_transport_binding(
    tmp_path: Path, field: str
) -> None:
    raw = b'{"finding_id":"H-01"}\n'
    completed = _run(
        tmp_path,
        shard=f"forge-{field}",
        script=_stdout_script(raw),
        stdout_limit=len(raw),
        stderr_limit=0,
    )
    payload = _load(completed.receipt_path)
    payload.pop("completion_sha256")
    if field == "output_source_mode":
        payload[field] = W.WORKER_FILE_OUTPUTS
        match = "source mode"
    elif field == "stream_limits":
        payload[field] = {"stdout_bytes": len(raw) + 1, "stderr_bytes": 0}
        match = "stream limits"
    else:
        payload[field]["stdout_captured_size"] = 0  # type: ignore[index]
        match = "stream observation"
    forged_path, forged_sha = W._persist_hashed_json(
        completed.receipt_path.parent, "completion", payload
    )

    with pytest.raises(W.WorkerExecutionError, match=match):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=forged_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=forged_sha,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_byte_limits_are_exact_nonnegative_integers(tmp_path: Path) -> None:
    for invalid in (-1, W.MAX_STREAM_LIMIT_BYTES + 1, 1.5, True, "10", None):
        with pytest.raises(W.WorkerExecutionError, match="byte ceiling"):
            _run(
                tmp_path,
                shard=f"bad-limit-{str(invalid).replace('.', '-')}",
                script=_stdout_script(b"{}"),
                stdout_limit=invalid,  # type: ignore[arg-type]
            )


def test_posix_capability_remains_explicitly_non_exhaustive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(W.os, "name", "posix")
    monkeypatch.setattr(W.sys, "platform", "linux")
    capability = W.process_tree_termination_capability()
    assert capability["provider_owns_tree"] is False
    assert capability["exhaustive_descendant_termination_authority"] is False
    assert capability["termination_scope"] == "PROCESS_GROUP_ONLY"
