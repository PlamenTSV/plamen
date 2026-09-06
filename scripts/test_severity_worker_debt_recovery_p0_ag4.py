"""Fixture-first contracts for severity worker debt and exact crash recovery.

Provider evidence is durable execution state, not an invitation to retry.  These
tests require reconciliation to surface every armed-but-incomplete worker shard,
and require the receipt-first semantic commit window to recover through a narrow
API that derives authority from the already persisted receipts.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Mapping, Sequence

import pytest

import severity_adjudication_work as W
import severity_runtime
import worker_execution_receipts as X
from test_severity_adjudication_work_p0_ag3 import (
    RUN_ID,
    _adjudication_proposal,
    _decision,
    _prepare,
    _receipt_first_payload,
    _write_state,
)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _prepare_candidates(
    root: Path,
    candidate_ids: Sequence[str],
    *,
    timeout_seconds_per_worker: int = 30,
) -> dict[str, Any]:
    _write_state(root, [_decision(candidate_id) for candidate_id in candidate_ids])
    return _prepare(
        root,
        backend="fixture-subprocess",
        transport="headless-subprocess",
        effective_model="fixture-python",
        environment_allowlist_digest=X.environment_allowlist_sha256(()),
        timeout_seconds_per_worker=timeout_seconds_per_worker,
    )


def _execute(
    root: Path,
    shard: Mapping[str, Any],
    script: str,
    *,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    return W.execute_adjudication_worker(
        root,
        shard_id=str(shard["shard_id"]),
        argv=[sys.executable, "-c", script],
        environment={},
        environment_allowlist=(),
        timeout_seconds=timeout_seconds,
    )


def _valid_output_script(shard: Mapping[str, Any]) -> str:
    payloads = {
        candidate_id: _adjudication_proposal(candidate_id)
        for candidate_id in shard["candidate_ids"]
    }
    return (
        "import json; from pathlib import Path; "
        f"payloads=json.loads({json.dumps(payloads, sort_keys=True)!r}); "
        f"names=json.loads({json.dumps(shard['staged_outputs'], sort_keys=True)!r}); "
        f"scope=Path({str(shard['staging_output_scope'])!r}); "
        "scope.mkdir(parents=True, exist_ok=True); "
        "[(scope/names[c]).write_text(json.dumps(payloads[c], sort_keys=True)+'\\n', "
        "encoding='utf-8') for c in sorted(payloads)]"
    )


def _worker_run_path(root: Path, shard: Mapping[str, Any]) -> Path:
    suffix = str(shard["launch_intent_file"]).split(".")[-2]
    return root / f"severity_adjudication_worker_run.{suffix}.json"


def _evidence_dir(root: Path, shard: Mapping[str, Any]) -> Path:
    return root / ".worker_execution_receipts" / str(shard["shard_id"])


def _debt_reason_codes(root: Path, shard: Mapping[str, Any]) -> set[str]:
    return {
        str(json.loads(path.read_text(encoding="utf-8"))["reason_code"])
        for path in _evidence_dir(root, shard).glob("debt_*.json")
    }


def _assert_execution_debt(
    root: Path,
    candidate_ids: Sequence[str],
    reason_code: str,
) -> dict[str, Any]:
    reconciliation = W.reconcile_adjudication_work(root)
    assert reconciliation["states"] == {
        candidate_id: "WORKER_EXECUTION_DEBT" for candidate_id in candidate_ids
    }
    assert reconciliation["pending_ids"] == []
    assert reconciliation["bind_ready_ids"] == []
    assert reconciliation["debt_ids"] == sorted(candidate_ids)
    assert all(
        reason_code in reconciliation["details"][candidate_id]
        for candidate_id in candidate_ids
    )
    return reconciliation


def _assert_durable_debt_never_relaunches(
    root: Path,
    shard: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in _evidence_dir(root, shard).rglob("*")
        if path.is_file()
    }

    def forbidden_relaunch(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("durable worker debt was silently relaunched")

    monkeypatch.setattr(W, "run_observed_worker", forbidden_relaunch)
    with pytest.raises(W.AdjudicationWorkError, match="incomplete|ambiguous"):
        _execute(root, shard, "raise SystemExit(0)")
    after = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in _evidence_dir(root, shard).rglob("*")
        if path.is_file()
    }
    assert after == before


def test_timeout_becomes_explicit_worker_execution_debt_and_never_relaunches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _prepare_candidates(
        tmp_path,
        ["H-TIMEOUT"],
        timeout_seconds_per_worker=1,
    )
    shard = plan["shards"][0]

    with pytest.raises(W.AdjudicationWorkError, match="timed out|did not complete"):
        _execute(tmp_path, shard, "import time; time.sleep(5)", timeout_seconds=1)

    assert "TIMEOUT" in _debt_reason_codes(tmp_path, shard)
    assert not _worker_run_path(tmp_path, shard).exists()
    _assert_execution_debt(tmp_path, ["H-TIMEOUT"], "TIMEOUT")
    _assert_durable_debt_never_relaunches(tmp_path, shard, monkeypatch)


def test_nonzero_exit_becomes_explicit_worker_execution_debt_and_never_relaunches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _prepare_candidates(tmp_path, ["H-NONZERO"])
    shard = plan["shards"][0]

    with pytest.raises(W.AdjudicationWorkError, match="non-zero|did not complete"):
        _execute(tmp_path, shard, "raise SystemExit(23)")

    assert "NONZERO_EXIT" in _debt_reason_codes(tmp_path, shard)
    assert not _worker_run_path(tmp_path, shard).exists()
    _assert_execution_debt(tmp_path, ["H-NONZERO"], "NONZERO_EXIT")
    _assert_durable_debt_never_relaunches(tmp_path, shard, monkeypatch)


def test_partial_publication_marks_the_whole_shard_as_worker_execution_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate_ids = ["H-PARTIAL-1", "H-PARTIAL-2"]
    plan = _prepare_candidates(tmp_path, candidate_ids)
    shard = plan["shards"][0]
    assert shard["candidate_ids"] == candidate_ids

    # Process confinement correctly prevents a child from touching canonical
    # destinations.  Simulate the publication race at the trusted publisher
    # boundary instead: occupy the second destination after provider execution
    # but immediately before the real transactional publisher runs.
    blocker = str(shard["expected_outputs"][candidate_ids[1]])
    original_publish = X._publish_completed_outputs

    def race_second_destination(**kwargs: object) -> object:
        root = Path(kwargs["root"])
        destination = root / blocker
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"unreceipted-blocker")
        return original_publish(**kwargs)

    monkeypatch.setattr(
        X,
        "_publish_completed_outputs",
        race_second_destination,
    )
    with pytest.raises(W.AdjudicationWorkError, match="publication|did not complete"):
        _execute(tmp_path, shard, _valid_output_script(shard))

    assert "PUBLISH_FAILED" in _debt_reason_codes(tmp_path, shard)
    assert list(_evidence_dir(tmp_path, shard).glob("publish_arm_*.json"))
    assert not list(
        path
        for path in _evidence_dir(tmp_path, shard).glob("publish_*.json")
        if not path.name.startswith("publish_arm_")
    )
    assert not _worker_run_path(tmp_path, shard).exists()
    _assert_execution_debt(tmp_path, candidate_ids, "PUBLISH_FAILED")
    _assert_durable_debt_never_relaunches(tmp_path, shard, monkeypatch)


def test_ambiguous_multiple_receipt_chains_are_debt_not_resume_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate_id = "H-AMBIGUOUS"
    plan = _prepare_candidates(tmp_path, [candidate_id])
    shard = plan["shards"][0]
    _execute(tmp_path, shard, _valid_output_script(shard))
    evidence = _evidence_dir(tmp_path, shard)
    first_chain = {
        path.relative_to(evidence).as_posix(): path.read_bytes()
        for path in evidence.rglob("*")
        if path.is_file()
    }
    _worker_run_path(tmp_path, shard).unlink()

    # Re-run only after removing every first-run execution/output byte, then
    # restore the first receipts alongside the second.  Both chains were emitted
    # by the real provider for the same immutable shard/cwd and bind identical
    # output bytes; neither is a forged filename pretending to be a second chain.
    (tmp_path / str(shard["expected_outputs"][candidate_id])).unlink()
    shutil.rmtree(tmp_path / str(shard["staging_output_scope"]))
    shutil.rmtree(evidence)
    _execute(tmp_path, shard, _valid_output_script(shard))
    _worker_run_path(tmp_path, shard).unlink()

    for relative, raw in first_chain.items():
        path = evidence / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            assert path.read_bytes() == raw
        else:
            path.write_bytes(raw)
    assert len(list(evidence.glob("completion_*.json"))) == 2
    assert len(
        [
            path
            for path in evidence.glob("publish_*.json")
            if not path.name.startswith("publish_arm_")
        ]
    ) == 2

    _assert_execution_debt(tmp_path, [candidate_id], "AMBIGUOUS_RECEIPT_CHAINS")
    _assert_durable_debt_never_relaunches(tmp_path, shard, monkeypatch)


def _write_receipt_first_window(
    root: Path,
    candidate_id: str,
) -> tuple[dict[str, Any], Path]:
    decision = _decision(candidate_id)
    _write_state(root, [decision])
    plan = _prepare_candidates(root, [candidate_id])
    receipt = _receipt_first_payload(
        root,
        decision=decision,
        plan=plan,
        candidate_id=candidate_id,
    )
    receipt_path = root / f"verify_{candidate_id}.severity_adjudication_receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert W.reconcile_adjudication_work(root)["states"] == {
        candidate_id: "RECEIPT_PENDING_DECISION_COMMIT"
    }
    return receipt, receipt_path


def _exact_recovery_api():
    recovery = getattr(
        severity_runtime,
        "recover_receipt_pending_decision_commit",
        None,
    )
    assert callable(recovery), (
        "receipt-first recovery needs a dedicated API with no caller-authored "
        "backend, identity, invocation, or launch-digest parameters"
    )
    return recovery


def test_receipt_pending_decision_commit_uses_dedicated_exact_recovery_api(
    tmp_path: Path,
) -> None:
    candidate_id = "H-RECEIPT-FIRST"
    _write_receipt_first_window(tmp_path, candidate_id)

    written, issues = _exact_recovery_api()(tmp_path, candidate_id)

    assert written and not issues
    reconciliation = W.reconcile_adjudication_work(tmp_path)
    assert reconciliation["states"] == {candidate_id: "COMPLETED"}
    assert reconciliation["completed_ids"] == [candidate_id]
    assert reconciliation["debt_ids"] == []


def test_exact_receipt_first_recovery_rejects_tamper_without_overwrite(
    tmp_path: Path,
) -> None:
    candidate_id = "H-RECEIPT-TAMPER"
    receipt, receipt_path = _write_receipt_first_window(tmp_path, candidate_id)
    receipt["launch_receipt"]["backend"] = "tampered-backend"
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    receipt["receipt_digest"] = _digest(unsigned)
    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    tracked = {
        path.name: path.read_bytes()
        for path in (
            receipt_path,
            tmp_path / f"verify_{candidate_id}.severity_decision.json",
            tmp_path / W.SOURCE_LEDGER_NAME,
        )
    }

    written, issues = _exact_recovery_api()(tmp_path, candidate_id)

    assert not written and issues
    assert {name: (tmp_path / name).read_bytes() for name in tracked} == tracked
    assert W.reconcile_adjudication_work(tmp_path)["states"] == {
        candidate_id: "RECEIPT_INVALID"
    }


def test_pending_denominator_ids_are_counted_as_phase_debt(tmp_path: Path) -> None:
    candidate_id = "H-NOT-LAUNCHED"
    _prepare_candidates(tmp_path, [candidate_id])

    reconciliation = W.reconcile_adjudication_work(tmp_path)

    assert reconciliation["states"] == {candidate_id: "PENDING"}
    assert reconciliation["pending_ids"] == [candidate_id]
    assert reconciliation["debt_ids"] == [candidate_id]
    assert reconciliation["all_terminal"] is False
    assert reconciliation["all_resolved"] is False
