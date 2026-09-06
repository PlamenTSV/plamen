"""Fixture-first integration contract for AG-3 worker execution authority.

The severity work planner may describe an adjudicator launch, but only the
provider-owned subprocess observer may prove that it ran.  These fixtures keep
that distinction executable: a canonical proposal is content, provider
completion/publication receipts are transport authority, and the severity
worker-run receipt is the consumer-facing join between them.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

import severity_adjudication_work as W
import severity_runtime
import worker_execution_receipts as X
from severity_decision_ledger import parse_severity_adjudication_proposal
from test_severity_adjudication_work_p0_ag3 import (
    RUN_ID,
    _adjudication_proposal,
    _decision,
    _prepare,
    _write_proposal,
    _write_state,
)
from test_support_startup_permit import durable_startup_permit


CANDIDATE_ID = "H-PROVIDER"


def severity_proposal_digest(_path: Path, raw: bytes) -> str:
    """Strict, source-bindable provider parser for severity output bytes."""

    proposal = parse_severity_adjudication_proposal(raw)
    canonical = json.dumps(
        proposal,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _prepare_one(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    _write_state(root, [_decision(CANDIDATE_ID)])
    plan = _prepare(
        root,
        backend="fixture-subprocess",
        transport="headless-subprocess",
        effective_model="fixture-python",
        environment_allowlist_digest=X.environment_allowlist_sha256(()),
        timeout_seconds_per_worker=10,
    )
    assert len(plan["shards"]) == 1
    return plan, plan["shards"][0]


def _intent(root: Path, shard: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(
        (root / str(shard["launch_intent_file"])).read_text(encoding="utf-8")
    )


def _script(
    shard: Mapping[str, Any],
    *,
    extra_staged_file: bool = False,
    returncode: int = 0,
) -> str:
    scope = str(shard["staging_output_scope"])
    staged_name = str(shard["staged_outputs"][CANDIDATE_ID])
    raw = (
        json.dumps(
            _adjudication_proposal(CANDIDATE_ID),
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    statements = [
        "from pathlib import Path",
        f"p=Path({(scope + '/' + staged_name)!r})",
        "p.parent.mkdir(parents=True, exist_ok=True)",
        f"p.write_bytes({raw!r})",
    ]
    if extra_staged_file:
        statements.append("(p.parent/'unassigned.json').write_text('{}\\n', encoding='utf-8')")
    statements.append(f"raise SystemExit({returncode})")
    return "; ".join(statements)


def _execute(
    root: Path,
    shard: Mapping[str, Any],
    *,
    script: str | None = None,
    startup_authority_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    execute = getattr(W, "execute_adjudication_worker", None)
    assert callable(execute), (
        "severity_adjudication_work must expose one provider-owned "
        "execute_adjudication_worker boundary"
    )
    result = execute(
        root,
        shard_id=shard["shard_id"],
        argv=[sys.executable, "-c", script or _script(shard)],
        environment={},
        environment_allowlist=(),
        startup_authority_binding=startup_authority_binding,
    )
    assert isinstance(result, dict)
    return result


def _provider_evidence(root: Path, shard: Mapping[str, Any], prefix: str) -> Path:
    matches = list(
        (
            root
            / ".worker_execution_receipts"
            / str(shard["shard_id"])
        ).glob(f"{prefix}_*.json")
    )
    if prefix == "publish":
        matches = [path for path in matches if not path.name.startswith("publish_arm_")]
    assert len(matches) == 1, (prefix, matches)
    return matches[0]


def _canonical_output(root: Path, shard: Mapping[str, Any]) -> Path:
    return root / str(shard["expected_outputs"][CANDIDATE_ID])


def _worker_run_path(root: Path, shard: Mapping[str, Any]) -> Path:
    suffix = str(shard["launch_intent_file"]).removeprefix(
        "severity_adjudication_launch_intent."
    ).removesuffix(".json")
    return root / f"severity_adjudication_worker_run.{suffix}.json"


def test_actual_observed_subprocess_stages_and_provider_publishes_canonical(
    tmp_path: Path,
) -> None:
    _plan, shard = _prepare_one(tmp_path)

    worker_run = _execute(tmp_path, shard)
    replay = W.validate_completed_worker_run_for_candidate(
        tmp_path, CANDIDATE_ID
    )

    staged = (
        tmp_path
        / str(shard["staging_output_scope"])
        / str(shard["staged_outputs"][CANDIDATE_ID])
    )
    canonical = _canonical_output(tmp_path, shard)
    assert staged.is_file() and canonical.is_file()
    assert staged.read_bytes() == canonical.read_bytes()
    assert parse_severity_adjudication_proposal(canonical.read_bytes())
    assert replay == worker_run
    assert replay["receipt_digest"] == worker_run["receipt_digest"]
    assert _provider_evidence(tmp_path, shard, "completion").is_file()
    assert _provider_evidence(tmp_path, shard, "publish").is_file()
    arm = json.loads(
        _provider_evidence(tmp_path, shard, "arm").read_text(
            encoding="utf-8"
        )
    )
    stdin = arm["process_intent"]["stdin"]
    assert stdin["state"] == "BOUND_INPUT"
    assert stdin["input_name"] == "prompt"
    assert stdin["relative_path"] == shard["prompt_file"]


def test_no_public_or_callable_raw_worker_completion_writer_exists() -> None:
    assert "record_completed_worker_run" not in set(W.__all__)
    assert not hasattr(W, "record_completed_worker_run"), (
        "a non-exported raw receipt writer is still callable and therefore "
        "still permits caller self-attestation"
    )
    assert callable(getattr(W, "execute_adjudication_worker", None))


def test_runtime_timeout_must_equal_the_immutable_worker_plan(
    tmp_path: Path,
) -> None:
    _plan, shard = _prepare_one(tmp_path)

    with pytest.raises(W.AdjudicationWorkError, match="timeout.*work plan"):
        W.execute_adjudication_worker(
            tmp_path,
            shard_id=shard["shard_id"],
            argv=[sys.executable, "-c", _script(shard)],
            environment={},
            environment_allowlist=(),
            timeout_seconds=11,
        )

    assert not (
        tmp_path / ".worker_execution_receipts" / str(shard["shard_id"])
    ).exists()


def test_raw_canonical_proposal_cannot_self_certify_or_bind(tmp_path: Path) -> None:
    plan, shard = _prepare_one(tmp_path)
    _write_proposal(tmp_path, CANDIDATE_ID)
    intent = _intent(tmp_path, shard)
    original_decision = (
        tmp_path / f"verify_{CANDIDATE_ID}.severity_decision.json"
    ).read_bytes()

    with pytest.raises(W.AdjudicationWorkError):
        W.validate_completed_worker_run_for_candidate(tmp_path, CANDIDATE_ID)
    written, issues = severity_runtime.bind_shadow_adjudication_for_candidate(
        tmp_path,
        CANDIDATE_ID,
        backend=intent["backend"],
        launch_digest=intent["intent_digest"],
        run_id=plan["run_id"],
        worker_identity=intent["worker_identity"],
        invocation_id=intent["invocation_id"],
    )

    assert not written and issues
    assert (
        tmp_path / f"verify_{CANDIDATE_ID}.severity_decision.json"
    ).read_bytes() == original_decision
    reconciliation = W.reconcile_adjudication_work(tmp_path)
    assert reconciliation["states"][CANDIDATE_ID] == "OUTPUT_UNATTESTED"
    assert CANDIDATE_ID not in reconciliation["bind_ready_ids"]


def test_exact_resume_revalidates_receipts_without_relaunch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _plan, shard = _prepare_one(tmp_path)
    first = _execute(tmp_path, shard)
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    def forbidden_relaunch(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("exact resume attempted to relaunch completed work")

    monkeypatch.setattr(W, "run_observed_worker", forbidden_relaunch, raising=False)
    monkeypatch.setattr(X, "run_observed_worker", forbidden_relaunch)
    resumed = _execute(tmp_path, shard)
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    assert resumed == first
    assert after == before
    assert W.validate_completed_worker_run_for_candidate(
        tmp_path, CANDIDATE_ID
    ) == first


def test_crash_after_provider_publish_recovers_worker_receipt_without_relaunch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _plan, shard = _prepare_one(tmp_path)
    first = _execute(tmp_path, shard)
    _worker_run_path(tmp_path, shard).unlink()

    def forbidden_relaunch(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("provider-complete crash recovery relaunched work")

    monkeypatch.setattr(W, "run_observed_worker", forbidden_relaunch)
    recovered = _execute(tmp_path, shard)

    assert recovered == first
    assert W.validate_completed_worker_run_for_candidate(
        tmp_path, CANDIDATE_ID
    ) == first


@pytest.mark.parametrize(
    "target,mutation",
    (
        ("completion", "delete"),
        ("completion", "tamper"),
        ("publish", "delete"),
        ("publish", "tamper"),
        ("canonical", "delete"),
        ("canonical", "tamper"),
    ),
)
def test_missing_or_tampered_provider_authority_fails_consumer_replay(
    tmp_path: Path, target: str, mutation: str
) -> None:
    _plan, shard = _prepare_one(tmp_path)
    _execute(tmp_path, shard)
    victim = (
        _canonical_output(tmp_path, shard)
        if target == "canonical"
        else _provider_evidence(tmp_path, shard, target)
    )
    if mutation == "delete":
        victim.unlink()
    else:
        victim.write_bytes(victim.read_bytes() + b" ")

    with pytest.raises(W.AdjudicationWorkError):
        W.validate_completed_worker_run_for_candidate(tmp_path, CANDIDATE_ID)


def test_provider_rejects_worker_assessor_principal_collision(
    tmp_path: Path,
) -> None:
    plan, shard = _prepare_one(tmp_path)
    intent = _intent(tmp_path, shard)
    assessor = intent["assessor_principals"][0]

    with pytest.raises(X.WorkerExecutionError, match="worker and assessor"):
        X.ExecutionBindings(
            run_id=plan["run_id"],
            shard_id=shard["shard_id"],
            plan=X.BoundInput(W.WORK_PLAN_NAME),
            manifest=X.BoundInput(W.MANIFEST_NAME),
            intent=X.BoundInput(shard["launch_intent_file"]),
            context=X.BoundInput(shard["context_file"]),
            prompt=X.BoundInput(shard["prompt_file"]),
            tool_policy=X.BoundInput(shard["tool_policy_file"]),
            worker=X.PrincipalInvocation(
                assessor["identity"], assessor["invocation_id"] + "-worker"
            ),
            assessors=(
                X.PrincipalInvocation(
                    assessor["identity"], assessor["invocation_id"]
                ),
            ),
            effective_backend=intent["effective_backend"],
            effective_model=intent["effective_model"],
        )


def test_claude_launch_intent_cannot_be_satisfied_by_python_process(
    tmp_path: Path,
) -> None:
    _write_state(tmp_path, [_decision(CANDIDATE_ID)])
    plan = _prepare(
        tmp_path,
        backend="claude",
        transport="headless-subprocess",
        effective_model="claude-opus-test",
        environment_allowlist_digest=X.environment_allowlist_sha256(()),
    )
    shard = plan["shards"][0]
    startup_authority_binding = durable_startup_permit(
        tmp_path,
        run_id=RUN_ID,
    )

    with pytest.raises(W.AdjudicationWorkError, match="backend|executable|argv"):
        _execute(
            tmp_path,
            shard,
            startup_authority_binding=startup_authority_binding,
        )

    assert not (
        tmp_path / ".worker_execution_receipts" / str(shard["shard_id"])
    ).exists()


@pytest.mark.parametrize(
    "field,bad_value",
    (
        ("backend", "forged-backend"),
        ("launch_digest", "f" * 64),
        ("worker_identity", "forged-worker"),
        ("invocation_id", "forged-invocation"),
    ),
)
def test_runtime_binder_rejects_caller_metadata_differing_from_provider_receipt(
    tmp_path: Path, field: str, bad_value: str
) -> None:
    plan, shard = _prepare_one(tmp_path)
    worker_run = _execute(tmp_path, shard)
    intent = _intent(tmp_path, shard)
    original_decision = (
        tmp_path / f"verify_{CANDIDATE_ID}.severity_decision.json"
    ).read_bytes()
    arguments = {
        "backend": intent["backend"],
        "launch_digest": worker_run["receipt_digest"],
        "run_id": plan["run_id"],
        "worker_identity": intent["worker_identity"],
        "invocation_id": intent["invocation_id"],
    }
    arguments[field] = bad_value

    written, issues = severity_runtime.bind_shadow_adjudication_for_candidate(
        tmp_path, CANDIDATE_ID, **arguments
    )

    assert not written and issues
    assert (
        tmp_path / f"verify_{CANDIDATE_ID}.severity_decision.json"
    ).read_bytes() == original_decision


def test_extra_file_in_staged_denominator_leaves_debt_without_worker_receipt(
    tmp_path: Path,
) -> None:
    _plan, shard = _prepare_one(tmp_path)

    with pytest.raises((X.WorkerExecutionIncomplete, W.AdjudicationWorkError)):
        _execute(
            tmp_path,
            shard,
            script=_script(shard, extra_staged_file=True),
        )

    assert not _worker_run_path(tmp_path, shard).exists()
    assert not _canonical_output(tmp_path, shard).exists()
    debt = list(
        (
            tmp_path
            / ".worker_execution_receipts"
            / str(shard["shard_id"])
        ).glob("debt_*.json")
    )
    assert debt
    assert any(
        json.loads(path.read_text(encoding="utf-8"))["reason_code"]
        == "OUTPUT_DENOMINATOR_MISMATCH"
        for path in debt
    )


def test_nonzero_process_leaves_debt_and_no_worker_receipt(tmp_path: Path) -> None:
    _plan, shard = _prepare_one(tmp_path)

    with pytest.raises((X.WorkerExecutionIncomplete, W.AdjudicationWorkError)):
        _execute(tmp_path, shard, script=_script(shard, returncode=17))

    assert not _worker_run_path(tmp_path, shard).exists()
    assert not _canonical_output(tmp_path, shard).exists()
    debt = list(
        (
            tmp_path
            / ".worker_execution_receipts"
            / str(shard["shard_id"])
        ).glob("debt_*.json")
    )
    assert debt
    assert any(
        json.loads(path.read_text(encoding="utf-8"))["reason_code"]
        == "NONZERO_EXIT"
        for path in debt
    )
