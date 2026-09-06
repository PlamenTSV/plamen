"""Focused durable startup-permit propagation fixtures for P0-AM."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import worker_transaction as T
import worker_execution_receipts as W
from auxiliary_writable_root_startup import (
    STARTUP_BINDING_SCHEMA,
    STARTUP_RECEIPT_DIRECTORY_NAME,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)


RUN_ID = "123e4567-e89b-42d3-a456-426614174000"


def _permit(
    *,
    run_id: str = RUN_ID,
    epoch: str = "1" * 32,
    pointer_digest: str = "2" * 64,
    receipt_digest: str = "3" * 64,
) -> dict[str, object]:
    return {
        "schema": STARTUP_BINDING_SCHEMA,
        "run_id": run_id,
        "startup_epoch": epoch,
        "current_pointer_sha256": pointer_digest,
        "receipt_relative_path": (
            f"{STARTUP_RECEIPT_DIRECTORY_NAME}/"
            f"startup-{epoch}-{receipt_digest}.json"
        ),
        "receipt_sha256": receipt_digest,
        "allocation_disposition": "ALLOW_NEW_LEASES",
    }


def _phase_authority() -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "codex",
        "depth",
        "depth-1",
    )
    artifact = ArtifactSpec(
        root="scratchpad",
        path="depth_result.md",
        owner_key=key,
        artifact_class="REQUIRED",
        writer="MODEL",
        write_mode="CREATE",
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="depth",
        work_unit_id="depth-1",
        outputs=(artifact,),
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="gpt-fixture",
        timeout_s=30,
        exec_mode="exec",
    )
    return contract, launch


def _provider(
    executable: Path,
    *,
    environment_allowlist: tuple[str, ...] = (),
) -> dict[str, object]:
    raw = executable.read_bytes() if executable.exists() else b"fixture"
    return {
        "backend": "codex",
        "model": "gpt-fixture",
        "transport": "exec",
        "resolved_executable": str(executable.resolve()),
        "executable_sha256": hashlib.sha256(raw).hexdigest(),
        "argv": [str(executable.resolve()), "--fixture"],
        "environment_allowlist_digest": W.environment_allowlist_sha256(
            environment_allowlist
        ),
        "timeout_seconds": 30,
        "stream_limits": {
            "stdout_bytes": 4096,
            "stderr_bytes": 4096,
            "staged_member_bytes": 4096,
        },
    }


def _assignment() -> dict[str, object]:
    return {
        "assignment_id": "depth-1-output",
        "members": [
            {
                "staged_relative_path": "result.md",
                "canonical_identity": "scratchpad:depth_result.md",
                "parser_binding": {"implementation_sha256": "4" * 64},
                "projection_mode": "CREATE_ABSENT",
                "canonical_prestate": {
                    "status": "MISSING",
                    "sha256": "",
                    "size": 0,
                },
            }
        ],
    }


def _plan(
    executable: Path,
    *,
    permit: dict[str, object] | None = None,
    completion_policy: dict[str, object] | None = None,
    prompt_raw: bytes = b"bounded prompt\n",
) -> tuple[dict[str, object], PhaseIOContract, LaunchSpec]:
    contract, launch = _phase_authority()
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
    )
    policy = (
        completion_policy
        if completion_policy is not None
        else {
            "accepted_signals": ["PROCESS_EXIT_ZERO"],
            T.AUXILIARY_STARTUP_POLICY_KEY: (
                _permit() if permit is None else permit
            ),
        }
    )
    plan = T.compile_worker_plan(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        generation=1,
        phase_roster_denominator_digest=denominator[
            "roster_denominator_digest"
        ],
        phase_io_contract_digest=contract.digest,
        phase_io_launch_digest=launch.digest,
        phase_io_input_set_digest="5" * 64,
        prompt_template_sha256=hashlib.sha256(prompt_raw).hexdigest(),
        methodology_digests=("6" * 64,),
        source_snapshot_digest="7" * 64,
        provider=_provider(executable),
        assignment=_assignment(),
        write_scope=T.compile_attempt_write_scope_template(
            run_id=RUN_ID,
            phase="depth",
            work_unit_id="depth-1",
        ),
        child_denominator={"required": []},
        completion_policy=policy,
        retry_policy={"max_attempts": 1},
        terminal_debt_policy={"safe_authority": False},
    )
    return plan, contract, launch


def _adapter(
    root: Path,
    *,
    permit: dict[str, object] | None,
    input_relative_paths: dict[str, str] | None = None,
    attempt_id: str | None = None,
) -> T.HeadlessModelAdapter:
    return T.HeadlessModelAdapter(
        scratchpad=root,
        cwd=root,
        input_relative_paths=input_relative_paths or {},
        parser_digest=lambda _path, raw: hashlib.sha256(raw).hexdigest(),
        environment={},
        environment_allowlist=(),
        attempt_id=attempt_id,
        startup_authority_binding=permit,
    )


def test_workplan_normalizes_exact_v2_startup_permit() -> None:
    executable = Path("C:/fixture/provider.exe")
    permit = _permit()
    plan, _contract, _launch = _plan(executable, permit=permit)
    assert (
        plan["completion_policy"][T.AUXILIARY_STARTUP_POLICY_KEY]
        == permit
    )


@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda value: value.pop("receipt_sha256"),
            "schema drift",
        ),
        (
            lambda value: value.__setitem__("unexpected", True),
            "schema drift",
        ),
        (
            lambda value: value.__setitem__("schema", "v1"),
            "not a permit",
        ),
        (
            lambda value: value.__setitem__(
                "run_id",
                "123e4567-e89b-42d3-a456-426614174001",
            ),
            "this run",
        ),
        (
            lambda value: value.__setitem__(
                "receipt_relative_path",
                (
                    f"{STARTUP_RECEIPT_DIRECTORY_NAME}/"
                    f"startup-{'1' * 32}-{'8' * 64}.json"
                ),
            ),
            "epoch/digest",
        ),
    ],
)
def test_workplan_rejects_startup_permit_schema_or_authority_drift(
    mutation,
    match: str,
) -> None:
    executable = Path("C:/fixture/provider.exe")
    permit = _permit()
    mutation(permit)
    with pytest.raises(T.WorkerTransactionError, match=match):
        _plan(executable, permit=permit)


def test_headless_adapter_cannot_omit_bound_startup_permit(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"fixture")
    plan, _contract, _launch = _plan(executable)
    with pytest.raises(
        T.WorkerTransactionError,
        match="cannot be dropped or substituted",
    ):
        T.execute_worker_transaction(
            plan,
            _adapter(tmp_path, permit=None),
        )


def test_headless_workplan_cannot_omit_adapter_startup_permit(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"fixture")
    plan, _contract, _launch = _plan(
        executable,
        completion_policy={
            "accepted_signals": ["PROCESS_EXIT_ZERO"],
        },
    )
    with pytest.raises(
        T.WorkerTransactionError,
        match="cannot be dropped or substituted",
    ):
        T.execute_worker_transaction(
            plan,
            _adapter(tmp_path, permit=_permit()),
        )


def test_headless_adapter_cannot_substitute_bound_startup_permit(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"fixture")
    plan, _contract, _launch = _plan(executable)
    substitute = _permit(
        epoch="8" * 32,
        pointer_digest="9" * 64,
        receipt_digest="a" * 64,
    )
    with pytest.raises(
        T.WorkerTransactionError,
        match="cannot be dropped or substituted",
    ):
        T.execute_worker_transaction(
            plan,
            _adapter(tmp_path, permit=substitute),
        )


def test_attempt_arm_preserves_exact_workplan_startup_permit(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"fixture")
    prompt = b"bounded prompt\n"
    permit = _permit()
    plan, _contract, _launch = _plan(
        executable,
        permit=permit,
        prompt_raw=prompt,
    )
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    intent = {
        "effective_backend": "codex",
        "effective_model": "gpt-fixture",
        "environment_allowlist_sha256": W.environment_allowlist_sha256(()),
        "auxiliary_writable_root_startup": permit,
    }
    rows = {
        "manifest": b"{}\n",
        "intent": (
            json.dumps(intent, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8"),
        "context": b"bounded context\n",
        "prompt": prompt,
        "tool_policy": b"{}\n",
    }
    paths: dict[str, str] = {}
    for name, raw in rows.items():
        path = inputs / f"{name}.data"
        path.write_bytes(raw)
        paths[name] = path.relative_to(tmp_path).as_posix()
    attempt_id = "attempt-" + "a" * 24
    with pytest.raises(
        T.WorkerTransactionError,
        match="cancelled before launch",
    ):
        T.execute_worker_transaction(
            plan,
            _adapter(
                tmp_path,
                permit=permit,
                input_relative_paths=paths,
                attempt_id=attempt_id,
            ),
            cancel_token=lambda: True,
        )
    attempt = (
        tmp_path
        / ".worker_transactions"
        / "depth"
        / "depth-1"
        / "attempts"
        / attempt_id
    )
    arm = json.loads((attempt / "arm.json").read_text(encoding="utf-8"))
    assert arm[T.AUXILIARY_STARTUP_POLICY_KEY] == permit
    assert T._validate_arm(
        arm,
        run_id=RUN_ID,
        phase_dir=attempt.parents[2],
        unit_dir=attempt.parents[1],
        plan_dir=attempt.parent,
        attempt_dir=attempt,
    )[T.AUXILIARY_STARTUP_POLICY_KEY] == permit


def test_incorporation_rejects_valid_but_substituted_attempt_arm_permit(
    tmp_path: Path,
) -> None:
    executable = Path("C:/fixture/provider.exe")
    permit = _permit()
    plan, contract, launch = _plan(executable, permit=permit)
    attempt_id = "attempt-" + "b" * 24
    attempt = (
        tmp_path
        / ".worker_transactions"
        / "depth"
        / "depth-1"
        / "attempts"
        / attempt_id
    )
    attempt.mkdir(parents=True)
    substitute = _permit(
        epoch="c" * 32,
        pointer_digest="d" * 64,
        receipt_digest="e" * 64,
    )
    arm: dict[str, object] = {
        "schema": T.WORKER_ATTEMPT_ARM_SCHEMA_V2,
        "run_id": RUN_ID,
        "phase": "depth",
        "work_unit_id": "depth-1",
        "generation": 1,
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": attempt_id,
        "process_scope": {
            "state": "ARMED",
            "capability": "FIXTURE",
            "persistent_identity": "fixture-scope",
        },
        "phase_roster_digest": "8" * 64,
        "phase_roster_denominator_digest": plan[
            "phase_roster_denominator_digest"
        ],
        T.AUXILIARY_STARTUP_POLICY_KEY: substitute,
        "materialized": {
            "argv": list(plan["provider"]["argv_template"]),
            "argv_sha256": T._argv_sha256(
                plan["provider"]["argv_template"]
            ),
            "prompt_sha256": plan["prompt_template_sha256"],
            "write_scope": T.compile_attempt_write_scope(
                run_id=RUN_ID,
                phase="depth",
                work_unit_id="depth-1",
                attempt_id=attempt_id,
            ),
        },
    }
    arm["arm_digest"] = T._digest(arm)
    (attempt / "arm.json").write_text(
        json.dumps(arm, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    execution_ref = T.ExecutionRef(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        generation=1,
        work_plan_digest=plan["work_plan_digest"],
        attempt_id=attempt_id,
        attempt_directory=attempt,
        attempt_completion_path=attempt / "completion.json",
        provider_execution=object(),
    )
    with pytest.raises(
        T.WorkerTransactionError,
        match="WorkPlan and AttemptArm startup permits differ",
    ):
        T.incorporate_worker_execution(
            execution_ref,
            contract,
            phase_io_launch=launch,
            work_plan=plan,
            parser_digest=lambda _path, raw: hashlib.sha256(raw).hexdigest(),
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=RUN_ID,
        )
