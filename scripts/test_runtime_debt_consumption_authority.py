"""Adversarial consumption authority for proof-free verifier runtime debt."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import uuid

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import plamen_validators as V  # noqa: E402
from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    write_artifact_ledger,
)
from phase_io_contracts import (  # noqa: E402
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)
from plamen_types import Checkpoint  # noqa: E402
from test_verifier_output_receipt_runtime_p0_aj import _setup_plan  # noqa: E402


def _receipt_digest(payload: dict) -> str:
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    return hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _write_debt(
    scratchpad: Path,
    *,
    run_id: str,
    pending_ids: tuple[str, ...] = ("H-01",),
    issues: list[str] | None = None,
) -> dict:
    queue = scratchpad / "verification_queue.md"
    plan = scratchpad / "verification_queue.work_plan.json"
    by_id = {
        str(row.get("finding id") or ""): row
        for row in V.parse_verification_queue_rows(scratchpad)
    }
    payload = {
        "schema_version": "plamen.verification_runtime_debt.v2",
        "state": "COMPLETED_WITH_DEBT",
        "proof_authority": "NONE",
        "verifier_status": "UNRESOLVED",
        "report_verification_projection": "CONTESTED",
        "run_id": run_id,
        "queue_artifact": "verification_queue.md",
        "queue_sha256": hashlib.sha256(queue.read_bytes()).hexdigest(),
        "queue_work_plan_artifact": "verification_queue.work_plan.json",
        "queue_work_plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "pending_work_item_ids": list(pending_ids),
        "pending_queue_rows": [by_id[value] for value in pending_ids],
        "issues": list(issues or ["bounded provider completion debt"]),
        "fallback_action": "HUMAN_REVIEW_OR_RETRY_EXACT_WORK_UNITS",
    }
    payload["receipt_digest"] = _receipt_digest(payload)
    (scratchpad / "verification_runtime_debt.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (scratchpad / "verification_runtime_debt.md").write_text(
        "# Verification Runtime Debt\n\nProof Authority: NONE\n",
        encoding="utf-8",
    )
    return payload


def _debt_contract(
    *,
    run_id: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    del run_id
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="verify",
        work_unit_id="runtime_debt",
        exact_inputs=(
            "verification_queue.md",
            "verification_queue.work_plan.json",
        ),
        exact_outputs=(
            "verification_runtime_debt.json",
            "verification_runtime_debt.md",
        ),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _bind_debt(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    contract, launch = _debt_contract(run_id=run_id)
    record_work_unit_inputs(
        scratchpad, project_root, contract, launch, run_id=run_id
    )
    return contract, launch


def _commit_debt(
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    run_id: str,
    checkpoint: bool = True,
) -> str:
    record_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    if checkpoint:
        Checkpoint(run_id=run_id).save(scratchpad)
    return contract.key


def test_preledger_compatibility_receipt_remains_proof_free_retention(
    tmp_path: Path,
) -> None:
    scratchpad, _phase, _items, _plan = _setup_plan(tmp_path, "sc")
    _write_debt(scratchpad, run_id="isolated-pre-ledger-fixture")

    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )

    assert issues == []
    assert covered == {"H-01"}


def test_live_runtime_debt_requires_exact_current_run_and_phaseio_owner(
    tmp_path: Path,
) -> None:
    scratchpad, _phase, _items, _plan = _setup_plan(tmp_path, "sc")
    current_run = str(uuid.uuid4())
    _write_debt(scratchpad, run_id="stale-run")
    Checkpoint(run_id=current_run).save(scratchpad)
    (scratchpad / "_artifact_state.json").write_text(
        json.dumps({"version": 2, "artifacts": {}, "artifact_bindings": {}, "work_units": {}}),
        encoding="utf-8",
    )

    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )

    assert covered == set()
    assert any("run" in issue.lower() and "stale" in issue.lower() for issue in issues)


def test_live_runtime_debt_rejects_unowned_exact_bytes(tmp_path: Path) -> None:
    scratchpad, _phase, _items, _plan = _setup_plan(tmp_path, "sc")
    run_id = str(uuid.uuid4())
    _write_debt(scratchpad, run_id=run_id)
    Checkpoint(run_id=run_id).save(scratchpad)
    (scratchpad / "_artifact_state.json").write_text(
        json.dumps({"version": 2, "artifacts": {}, "artifact_bindings": {}, "work_units": {}}),
        encoding="utf-8",
    )

    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )

    assert covered == set()
    assert any("ownership" in issue.lower() for issue in issues)


def test_runtime_debt_json_symlink_is_not_consumed(tmp_path: Path) -> None:
    scratchpad, _phase, _items, _plan = _setup_plan(tmp_path, "sc")
    path = scratchpad / "verification_runtime_debt.json"
    _write_debt(scratchpad, run_id="isolated-pre-ledger-fixture")
    target = scratchpad / "runtime_debt_target.json"
    path.replace(target)
    try:
        path.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unsupported: {exc}")

    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )

    assert covered == set()
    assert any("regular file" in issue.lower() or "symlink" in issue.lower() for issue in issues)


def test_runtime_debt_oversized_file_and_payload_budgets_cover_nothing(
    tmp_path: Path,
) -> None:
    scratchpad, _phase, _items, _plan = _setup_plan(tmp_path, "sc")
    path = scratchpad / "verification_runtime_debt.json"
    path.write_bytes(b"{" + b" " * V._RUNTIME_DEBT_MAX_JSON_BYTES + b"}")

    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )

    assert covered == set()
    assert any("size budget" in issue.lower() for issue in issues)

    _write_debt(
        scratchpad,
        run_id="isolated-pre-ledger-fixture",
        issues=["debt"] * (V._RUNTIME_DEBT_MAX_ISSUES + 1),
    )
    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )
    assert covered == set()
    assert any("issue count budget" in issue.lower() for issue in issues)


def test_runtime_debt_pending_and_string_budgets_cover_nothing(
    tmp_path: Path,
) -> None:
    scratchpad, _phase, _items, _plan = _setup_plan(tmp_path, "sc")
    payload = _write_debt(
        scratchpad, run_id="isolated-pre-ledger-fixture"
    )
    payload["pending_work_item_ids"] = [
        f"H-{index}" for index in range(V._RUNTIME_DEBT_MAX_PENDING_ROWS + 1)
    ]
    payload["pending_queue_rows"] = [
        {"finding id": value} for value in payload["pending_work_item_ids"]
    ]
    payload["receipt_digest"] = _receipt_digest(payload)
    (scratchpad / "verification_runtime_debt.json").write_text(
        json.dumps(payload, separators=(",", ":")), encoding="utf-8"
    )

    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )
    assert covered == set()
    assert any("pending row count budget" in issue.lower() for issue in issues)

    payload = _write_debt(
        scratchpad,
        run_id="isolated-pre-ledger-fixture",
        issues=["x" * (V._RUNTIME_DEBT_MAX_ISSUE_CHARS + 1)],
    )
    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )
    assert covered == set()
    assert any("string length budget" in issue.lower() for issue in issues)


def test_live_runtime_debt_rejects_stale_phaseio_input_binding(
    tmp_path: Path,
) -> None:
    scratchpad, _phase, _items, _plan = _setup_plan(tmp_path, "sc")
    run_id = str(uuid.uuid4())
    contract, launch = _bind_debt(scratchpad, tmp_path, run_id=run_id)
    _write_debt(scratchpad, run_id=run_id)
    owner_key = _commit_debt(
        scratchpad, tmp_path, contract, launch, run_id=run_id
    )
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][owner_key]
    binding = unit["input_bindings"]["scratchpad:verification_queue.md"]
    binding["sha256"] = "0" * 64
    unit["input_set_digest"] = V._runtime_debt_input_set_digest(
        unit["input_bindings"]
    )
    write_artifact_ledger(scratchpad, ledger)

    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )

    assert covered == set()
    assert any("semantic input" in issue.lower() and "stale" in issue.lower() for issue in issues)


@pytest.mark.parametrize("with_checkpoint", [False, True])
def test_exact_owned_current_runtime_debt_is_retention_authority(
    tmp_path: Path,
    with_checkpoint: bool,
) -> None:
    scratchpad, _phase, _items, _plan = _setup_plan(tmp_path, "sc")
    run_id = str(uuid.uuid4())
    contract, launch = _bind_debt(scratchpad, tmp_path, run_id=run_id)
    _write_debt(scratchpad, run_id=run_id)
    _commit_debt(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        checkpoint=with_checkpoint,
    )

    covered, issues = V._verification_runtime_debt_coverage(
        scratchpad, ("H-01",)
    )

    assert issues == []
    assert covered == {"H-01"}
