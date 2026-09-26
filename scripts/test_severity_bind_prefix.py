"""Focused completed-prefix runtime-evidence classification tests.

These tests exercise the narrow post-validation classifier used after the
real worker and historical bind transaction have replayed.  They do not
manufacture a completed PhaseIO transaction; the genuine transaction/prefix
proof remains in ``test_severity_bind_transaction.py``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from artifact_ledger import ArtifactLedgerError
from severity_bind_transaction import (
    _runtime_evidence_names,
    _runtime_evidence_witness,
)


RUN_ID = "11111111-2222-4333-8444-555555555555"
OWNER = (
    "sc/core/evm/codex/severity_adjudication_shadow/"
    "worker.severity-adjudication-0001"
)
DIGEST = "a" * 64


def _binding(identity: str, raw: bytes) -> dict[str, object]:
    return {
        "identity": identity,
        "input_class": "IMMUTABLE",
        "mtime_ns": 123456789,
        "status": "ACTIVE",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "producer_commit_receipt_digest": "",
        "producer_contract_digest": "",
        "producer_launch_digest": "",
        "producer_run_id": "",
        "producer_work_unit_key": "",
        "producer_writer": "",
    }


def _worker(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": (
            "plamen.severity_adjudication_worker_run.posix_compat.v1"
        ),
        "run_id": RUN_ID,
        "phase_io_owner_key": OWNER,
        "receipt_digest": DIGEST,
        "compatibility_receipt_relative_path": (
            ".posix_v2_compat_receipts/worker-0001.json"
        ),
    }
    value.update(changes)
    return value


def test_exact_compat_runtime_roster_is_bounded_by_worker_and_execution(
    tmp_path: Path,
) -> None:
    attempt = (
        ".worker_transactions/posix_v2_compat_severity/worker.0001/attempt.0001"
    )
    execution = {
        "attempt_completion_relative_path": f"{attempt}/completion.json",
        "provider_completion_relative_path": f"{attempt}/provider_completion.json",
        "incorporation_relative_path": f"{attempt}/incorporation.json",
    }
    ledger = {"work_units": {OWNER: {"execution_authority": execution}}}
    (tmp_path / "_artifact_state.json").write_text(
        json.dumps(ledger), encoding="utf-8",
    )
    plan = {
        "shards": [{
            "candidate_ids": ["INV-1"],
            "launch_intent_file": "severity_adjudication_launch_intent.0001.json",
            "context_file": "severity_adjudication_context.0001.json",
            "prompt_file": "severity_adjudication_prompt.0001.md",
            "tool_policy_file": "severity_adjudication_tool_policy.0001.json",
        }],
    }

    assert _runtime_evidence_names(
        tmp_path, candidate="INV-1", worker=_worker(), plan=plan, ledger=ledger,
    ) == {
        "severity_adjudication_worker_run.0001.json": "WORKER_RUN",
        ".posix_v2_compat_receipts/worker-0001.json": "POSIX_COMPAT_RECEIPT",
        f"{attempt}/completion.json": "TRANSACTION_COMPLETION",
        f"{attempt}/provider_completion.json": "PROVIDER_COMPLETION",
        f"{attempt}/incorporation.json": "TRANSACTION_INCORPORATION",
        f"{attempt}/plan.json": "TRANSACTION_PLAN",
    }


def test_runtime_evidence_witness_binds_exact_unowned_input_record() -> None:
    raw = b'{"completed":true}\n'
    identity = "scratchpad:.worker_transactions/worker.0001/completion.json"
    binding = _binding(identity, raw)

    assert _runtime_evidence_witness(
        identity=identity,
        raw=raw,
        input_binding=binding,
        candidate="INV-1",
        run_id=RUN_ID,
        worker=_worker(),
        evidence_kind="TRANSACTION_COMPLETION",
    ) == {
        "candidate_id": "INV-1",
        "run_id": RUN_ID,
        "worker_schema": (
            "plamen.severity_adjudication_worker_run.posix_compat.v1"
        ),
        "worker_principal": {
            "kind": "PHASE_IO_OWNER",
            "phase_io_owner_key": OWNER,
        },
        "worker_run_digest": DIGEST,
        "evidence_kind": "TRANSACTION_COMPLETION",
        "input_binding": binding,
    }


def test_native_runtime_witness_uses_provider_principal_not_phase_io_owner() -> None:
    raw = b'{"provider":"completed"}\n'
    identity = "scratchpad:.provider_transactions/completion.json"
    worker = {
        "schema_version": "plamen.severity_adjudication_worker_run.v2",
        "run_id": RUN_ID,
        "receipt_digest": DIGEST,
        "shard_id": "severity-adjudication-0001",
        "worker_identity": "severity-adjudicator",
        "invocation_id": "invocation-0001",
        "backend": "claude",
    }

    record = _runtime_evidence_witness(
        identity=identity,
        raw=raw,
        input_binding=_binding(identity, raw),
        candidate="INV-1",
        run_id=RUN_ID,
        worker=worker,
        evidence_kind="PROVIDER_COMPLETION",
    )
    assert record["worker_schema"] == (
        "plamen.severity_adjudication_worker_run.v2"
    )
    assert record["worker_principal"] == {
        "kind": "NATIVE_PROVIDER_WORKER",
        "shard_id": "severity-adjudication-0001",
        "worker_identity": "severity-adjudicator",
        "invocation_id": "invocation-0001",
        "backend": "claude",
    }
    invalid = dict(worker)
    invalid["worker_identity"] = 7
    with pytest.raises(ArtifactLedgerError, match="runtime evidence differs"):
        _runtime_evidence_witness(
            identity=identity,
            raw=raw,
            input_binding=_binding(identity, raw),
            candidate="INV-1",
            run_id=RUN_ID,
            worker=invalid,
            evidence_kind="PROVIDER_COMPLETION",
        )


@pytest.mark.parametrize(
    ("worker_changes", "raw_changes", "binding_changes", "kind"),
    [
        ({"run_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}, None, {},
         "TRANSACTION_COMPLETION"),
        ({"receipt_digest": "b" * 63}, None, {}, "TRANSACTION_COMPLETION"),
        ({}, b"tampered\n", {}, "TRANSACTION_COMPLETION"),
        ({}, None, {"producer_writer": "DRIVER"}, "TRANSACTION_COMPLETION"),
        ({}, None, {}, "UNRELATED_UNOWNED_FILE"),
        ({"schema_version": "plamen.unknown-worker.v1"}, None, {},
         "TRANSACTION_COMPLETION"),
    ],
    ids=(
        "wrong-run", "wrong-receipt", "tampered", "foreign-producer",
        "unrelated", "unknown-worker-schema",
    ),
)
def test_runtime_evidence_witness_rejects_unrelated_or_changed_authority(
    worker_changes: dict[str, object],
    raw_changes: bytes | None,
    binding_changes: dict[str, object],
    kind: str,
) -> None:
    raw = b'{"completed":true}\n'
    identity = "scratchpad:.worker_transactions/worker.0001/completion.json"
    binding = _binding(identity, raw)
    binding.update(binding_changes)
    with pytest.raises(ArtifactLedgerError, match="runtime evidence differs"):
        _runtime_evidence_witness(
            identity=identity,
            raw=raw if raw_changes is None else raw_changes,
            input_binding=binding,
            candidate="INV-1",
            run_id=RUN_ID,
            worker=_worker(**worker_changes),
            evidence_kind=kind,
        )
