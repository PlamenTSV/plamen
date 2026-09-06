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


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Job Object review")


def _strict_json_digest(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("finding_id"), str):
        raise ValueError("output must be a finding object")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _bindings(tmp_path: Path, shard: str) -> W.ExecutionBindings:
    inputs = tmp_path / "launch-inputs"
    inputs.mkdir(exist_ok=True)
    allowlist_sha = W.environment_allowlist_sha256(())
    intent = {
        "effective_backend": "codex",
        "effective_model": "fixture-model",
        "environment_allowlist_sha256": allowlist_sha,
    }
    contents = {
        "plan.json": "{}\n",
        "manifest.json": "{}\n",
        "intent.json": json.dumps(intent, sort_keys=True) + "\n",
        "context.md": "context\n",
        "prompt.md": "prompt\n",
        "tool-policy.json": '{"network":false}\n',
    }
    for name, content in contents.items():
        (inputs / name).write_text(content, encoding="utf-8")
    return W.ExecutionBindings(
        run_id="review-run",
        shard_id=shard,
        plan=W.BoundInput("launch-inputs/plan.json"),
        manifest=W.BoundInput("launch-inputs/manifest.json"),
        intent=W.BoundInput("launch-inputs/intent.json"),
        context=W.BoundInput("launch-inputs/context.md"),
        prompt=W.BoundInput("launch-inputs/prompt.md"),
        tool_policy=W.BoundInput("launch-inputs/tool-policy.json"),
        worker=W.PrincipalInvocation("review-worker", "review-worker-invocation"),
        assessors=(
            W.PrincipalInvocation("review-assessor", "review-assessor-invocation"),
        ),
        effective_backend="codex",
        effective_model="fixture-model",
    )


def _run(
    tmp_path: Path,
    *,
    shard: str,
    script: str,
    timeout: float = 5.0,
) -> W.CompletedExecution:
    return W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=_bindings(tmp_path, shard),
        argv=[sys.executable, "-c", script],
        cwd=tmp_path,
        output_scope_relative=f"worker-out-{shard}",
        expected_outputs=(
            W.ExpectedOutput(
                "finding-H-01",
                "result.json",
                f"canonical/{shard}.json",
            ),
        ),
        parser_digest=_strict_json_digest,
        environment={},
        environment_allowlist=(),
        timeout_seconds=timeout,
    )


def _result_script(shard: str, prefix: str = "") -> str:
    return (
        prefix
        + "from pathlib import Path; "
        + f"p=Path('worker-out-{shard}/result.json'); "
        + "p.parent.mkdir(parents=True, exist_ok=True); "
        + "p.write_text('{\"finding_id\":\"H-01\"}', encoding='utf-8')"
    )


def _assert_no_completion(exc: W.WorkerExecutionIncomplete) -> dict[str, object]:
    assert exc.arm_path.is_file()
    assert exc.debt_path is not None and exc.debt_path.is_file()
    assert not list(exc.arm_path.parent.glob("completion_*.json"))
    return json.loads(exc.debt_path.read_text(encoding="utf-8"))


def test_windows_worker_is_still_suspended_at_provider_resume_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "worker-out-suspended" / "result.json"
    original = W._OwnedProcessTree._resume_only_thread
    observations: list[bool] = []

    def delayed_resume(process_id: int) -> None:
        # attach() calls this only after AssignProcessToJobObject and after marking
        # the controller attached.  Holding this boundary proves CREATE_SUSPENDED
        # prevented even the first worker instruction from running beforehand.
        observations.append(marker.exists())
        time.sleep(0.2)
        observations.append(marker.exists())
        original(process_id)

    monkeypatch.setattr(
        W._OwnedProcessTree, "_resume_only_thread", staticmethod(delayed_resume)
    )
    script = _result_script("suspended")
    completed = _run(tmp_path, shard="suspended", script=script)

    assert observations == [False, False]
    assert marker.is_file()
    assert json.loads(completed.receipt_path.read_text(encoding="utf-8"))[
        "process_observation"
    ]["process_tree_terminated"] is True


def test_clean_parent_exit_cannot_leave_background_descendant(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "clean-exit-descendant-survived.txt"
    descendant = (
        "import time; from pathlib import Path; time.sleep(0.6); "
        "Path('clean-exit-descendant-survived.txt').write_text('alive', encoding='utf-8')"
    )
    prefix = (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL); "
    )
    started = time.monotonic()
    completed = _run(
        tmp_path,
        shard="clean-tree",
        script=_result_script("clean-tree", prefix),
    )

    assert time.monotonic() - started < 2.0
    time.sleep(0.8)
    assert not marker.exists()
    receipt = json.loads(completed.receipt_path.read_text(encoding="utf-8"))
    assert receipt["process_observation"]["returncode"] == 0
    assert receipt["process_observation"]["process_tree_terminated"] is True


def test_injected_assignment_failure_is_bounded_and_worker_never_executes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "assignment-failure-worker-ran.txt"

    def fail_attach(
        _self: W._OwnedProcessTree, _process: subprocess.Popen[bytes]
    ) -> None:
        raise W.WorkerExecutionError("injected AssignProcessToJobObject failure")

    monkeypatch.setattr(W._OwnedProcessTree, "attach", fail_attach)
    script = (
        "from pathlib import Path; "
        "Path('assignment-failure-worker-ran.txt').write_text('ran', encoding='utf-8'); "
        + _result_script("assign-fail")
    )
    started = time.monotonic()
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(tmp_path, shard="assign-fail", script=script)

    assert time.monotonic() - started < 2.0
    debt = _assert_no_completion(captured.value)
    assert debt["reason_code"] == "CLAUDE_RUNTIME_PROCESS_ATTACH_FAILED"
    assert "AssignProcessToJobObject" in str(debt["detail"])
    assert not marker.exists()


def test_injected_resume_failure_terminates_assigned_suspended_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "resume-failure-worker-ran.txt"

    def fail_resume(_process_id: int) -> None:
        raise W.WorkerExecutionError("injected ResumeThread failure")

    monkeypatch.setattr(
        W._OwnedProcessTree, "_resume_only_thread", staticmethod(fail_resume)
    )
    script = (
        "from pathlib import Path; "
        "Path('resume-failure-worker-ran.txt').write_text('ran', encoding='utf-8'); "
        + _result_script("resume-fail")
    )
    started = time.monotonic()
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(tmp_path, shard="resume-fail", script=script)

    assert time.monotonic() - started < 2.0
    debt = _assert_no_completion(captured.value)
    assert debt["reason_code"] == "CLAUDE_RUNTIME_PROCESS_ATTACH_FAILED"
    assert "ResumeThread" in str(debt["detail"])
    assert not marker.exists()


def test_injected_terminate_failure_emits_no_completion_and_job_close_kills_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Emergency close deliberately quarantines the global low-integrity lease
    # until its provider process dies because population zero was not observed.
    # Exercise that production boundary in a disposable provider process so
    # this pytest coordinator does not become the artificial long-lived owner.
    child_marker = "PLAMEN_TERMINATE_FAILURE_CHILD"
    if os.environ.get(child_marker) != "1":
        env = dict(os.environ)
        env[child_marker] = "1"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                f"{Path(__file__).resolve()}::"
                "test_injected_terminate_failure_emits_no_completion_and_job_close_kills_tree",
            ],
            cwd=str(Path(__file__).resolve().parents[1]),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout
        return
    marker = (
        tmp_path
        / "worker-out-terminate-fail"
        / "terminate-failure-descendant-survived.txt"
    )
    descendant = (
        "import time; from pathlib import Path; time.sleep(0.6); "
        "Path('worker-out-terminate-fail/terminate-failure-descendant-survived.txt')"
        ".write_text('alive', encoding='utf-8')"
    )
    prefix = (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL); "
    )

    def fail_terminate(_self: W._OwnedProcessTree) -> None:
        raise W.WorkerExecutionError("injected TerminateJobObject failure")

    monkeypatch.setattr(W._OwnedProcessTree, "terminate", fail_terminate)
    started = time.monotonic()
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(
            tmp_path,
            shard="terminate-fail",
            script=_result_script("terminate-fail", prefix),
        )

    assert time.monotonic() - started < 2.0
    debt = _assert_no_completion(captured.value)
    assert debt["reason_code"] == "PROCESS_SCOPE_CLEANUP_FAILED"
    assert "TerminateJobObject" in str(debt["detail"])
    assert debt["process_observation"]["process_scope_emergency_close_succeeded"] is True
    assert debt["process_observation"]["process_population_zero_proven"] is False
    time.sleep(0.8)
    assert not marker.exists()


@pytest.mark.parametrize("tamper", ("terminated", "strategy"))
def test_replay_rejects_forged_process_tree_authority_even_with_valid_new_hash(
    tmp_path: Path, tamper: str
) -> None:
    completed = _run(
        tmp_path,
        shard=f"forge-{tamper}",
        script=_result_script(f"forge-{tamper}"),
    )
    payload = json.loads(completed.receipt_path.read_text(encoding="utf-8"))
    payload.pop("completion_sha256")
    observation = payload["process_observation"]
    if tamper == "terminated":
        observation["process_tree_terminated"] = False
        match = "descendant termination"
    else:
        observation["process_tree_strategy"]["pre_execution_assignment"] = False
        match = "strategy mismatch"
    forged_path, forged_sha = W._persist_hashed_json(
        completed.receipt_path.parent, "completion", payload
    )

    with pytest.raises(W.WorkerExecutionError, match=match):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=forged_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=_strict_json_digest,
            expected_completion_sha256=forged_sha,
            expected_publish_sha256=completed.publish_sha256,
        )
