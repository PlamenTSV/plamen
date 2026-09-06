"""Adversarial WorkPlan/WER Claude stream-policy consistency fixtures."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

import test_worker_execution_receipts as fixtures
import worker_execution_receipts as W


WORK_PLAN_SCHEMA = "plamen.worker_work_plan.v2"
POLICY_KEY = "provider_stdout_evidence_configuration"


def _write_recognized_plan(
    tmp_path: Path,
    policy: dict[str, object] | None,
) -> None:
    (tmp_path / "launch-inputs").mkdir(exist_ok=True)
    plan = {
        "schema": WORK_PLAN_SCHEMA,
        "completion_policy": (
            {} if policy is None else {POLICY_KEY: copy.deepcopy(policy)}
        ),
    }
    (tmp_path / "launch-inputs" / "plan.json").write_text(
        json.dumps(plan, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _exact_stream_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    publish_canonical: bool = False,
) -> W.CompletedExecution:
    case = fixtures._runtime_case(
        tmp_path,
        label="workplan-exact",
        monkeypatch=monkeypatch,
    )
    fixtures._install_runtime_case(monkeypatch, case)
    kwargs = case.wer_kwargs()
    kwargs["publish_canonical"] = publish_canonical
    kwargs["parser_digest"] = fixtures.strict_json_digest
    return W.run_observed_worker(**kwargs)


def test_declared_workplan_stream_policy_cannot_be_omitted_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = fixtures._runtime_case(
        tmp_path,
        label="workplan-omitted",
        monkeypatch=monkeypatch,
    )

    monkeypatch.setattr(
        W.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "provider launched before WorkPlan/WER policy reconciliation"
        ),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="Claude opaque runtime requires launch security",
    ):
        kwargs = case.wer_kwargs()
        kwargs.pop("provider_stdout_evidence_configuration")
        W.run_observed_worker(**kwargs)


def test_declared_workplan_stream_policy_cannot_be_substituted_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = fixtures._runtime_case(
        tmp_path,
        label="workplan-substituted",
        monkeypatch=monkeypatch,
    )
    declared = case.stream
    substituted = copy.deepcopy(declared)
    substituted_session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    substituted["expected_session_id"] = substituted_session
    argv = list(case.base_argv)
    argv[argv.index(case.session_id)] = substituted_session

    monkeypatch.setattr(
        W.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "provider launched before WorkPlan/WER policy reconciliation"
        ),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="Claude runtime authority differs.*base_argv_sha256",
    ):
        kwargs = case.wer_kwargs()
        kwargs["argv"] = argv
        kwargs["provider_stdout_evidence_configuration"] = substituted
        W.run_observed_worker(**kwargs)


def test_ambiguous_workplan_json_cannot_downgrade_policy_detection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = fixtures._runtime_case(
        tmp_path,
        label="workplan-duplicate",
        monkeypatch=monkeypatch,
    )
    plan_path = tmp_path / case.bindings.plan.relative_path
    plan_path.write_text(
        (
            '{"schema":"plamen.worker_work_plan.v2",'
            '"completion_policy":{},'
            '"completion_policy":'
            '{"provider_stdout_evidence_configuration":{}}}\n'
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        W.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "ambiguous WorkPlan reached provider launch"
        ),
    )

    with pytest.raises(
        W.WorkerExecutionError,
        match="bound WorkPlan contains duplicate JSON keys",
    ):
        W.run_observed_worker(**case.wer_kwargs())


def test_exact_declared_workplan_stream_policy_arms_completes_and_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = _exact_stream_execution(tmp_path, monkeypatch)

    replay = W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        parser_digest=fixtures.strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
    )
    arm = json.loads(completed.arm_path.read_text(encoding="utf-8"))
    assert arm["process_intent"]["provider_stdout_evidence"] is not None
    assert replay["provider_stdout_evidence"] is not None


@pytest.mark.parametrize("drift", ["downgraded-to-none", "different-policy"])
def test_replay_rejects_self_consistent_arm_completion_policy_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    completed = _exact_stream_execution(tmp_path, monkeypatch)
    shard_dir = completed.receipt_path.parent
    arm = json.loads(completed.arm_path.read_text(encoding="utf-8"))
    completion = json.loads(completed.receipt_path.read_text(encoding="utf-8"))
    arm.pop("arm_sha256")
    completion.pop("completion_sha256")

    if drift == "downgraded-to-none":
        arm["process_intent"]["provider_stdout_evidence"] = None
        completion["provider_stdout_evidence"] = None
        completion["process_observation"]["provider_stdout_evidence"] = None
    else:
        arm["process_intent"]["provider_stdout_evidence"][
            "max_line_bytes"
        ] //= 2

    drifted_arm_path, drifted_arm_sha = W._persist_hashed_json(
        shard_dir,
        "arm",
        arm,
    )
    completion["arm_relative_path"] = drifted_arm_path.name
    completion["arm_sha256"] = drifted_arm_sha
    drifted_completion_path, drifted_completion_sha = W._persist_hashed_json(
        shard_dir,
        "completion",
        completion,
    )

    with pytest.raises(
        W.WorkerExecutionError,
        match="WorkPlan provider stdout evidence policy differs from the arm",
    ):
        W.validate_staged_execution(
            scratchpad=tmp_path,
            receipt_path=drifted_completion_path,
            parser_digest=fixtures.strict_json_digest,
            expected_completion_sha256=drifted_completion_sha,
        )


def test_recognized_workplan_without_stream_policy_preserves_generic_none(
    tmp_path: Path,
) -> None:
    bindings = fixtures._bindings(tmp_path)
    _write_recognized_plan(tmp_path, None)
    completed = W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=bindings,
        argv=[
            sys.executable,
            "-c",
            fixtures._script_for("worker-out/result.json"),
        ],
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=(
            W.ExpectedOutput(
                "finding-H-01",
                "result.json",
                "canonical/result.json",
            ),
        ),
        parser_digest=fixtures.strict_json_digest,
        environment={},
        environment_allowlist=(),
        timeout_seconds=10,
        publish_canonical=False,
    )

    replay = W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        parser_digest=fixtures.strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
    )
    assert replay["provider_stdout_evidence"] is None
