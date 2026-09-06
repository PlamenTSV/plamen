"""P0-AM schema, digest, and recovery authority fixtures."""

from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys

import pytest

import worker_transaction as T
import worker_execution_receipts as W
import artifact_ledger as L
import rooted_path_io as RIO
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from test_support_startup_permit import (
    FIXTURE_RUN_ID,
    durable_startup_permit,
)
from test_claude_launch_authority_fixtures import (
    install_test_only_launch_authority_adapter,
)


@pytest.fixture(autouse=True)
def _test_only_provider_authority_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if (
        os.name == "nt"
        and int(getattr(Path(sys.executable).stat(), "st_nlink", 1)) != 1
    ):
        reviewed = Path(r"C:\p27rt\python.exe")
        if (
            reviewed.is_file()
            and int(getattr(reviewed.stat(), "st_nlink", 1)) == 1
        ):
            monkeypatch.setattr(sys, "executable", str(reviewed.resolve(strict=True)))
    install_test_only_launch_authority_adapter(monkeypatch.setattr)


def test_safe_directory_tree_accepts_only_concurrent_regular_directory(
    tmp_path: Path,
) -> None:
    with ThreadPoolExecutor(max_workers=8) as executor:
        paths = list(
            executor.map(
                lambda _index: T._make_safe_directory_tree(
                    tmp_path,
                    "attention_repair/shared/attempts",
                ),
                range(32),
            )
        )
    expected = tmp_path / "attention_repair" / "shared" / "attempts"
    assert paths == [expected] * 32
    assert expected.is_dir()


def _provider(*, backend: str = "claude", model: str = "opus") -> dict:
    return {
        "backend": backend,
        "model": model,
        "transport": "headless" if backend == "claude" else "exec",
        "resolved_executable": "C:/tools/provider.exe",
        "executable_sha256": "a" * 64,
        "argv": ["C:/tools/provider.exe", "--fixture"],
        "environment_allowlist_digest": "b" * 64,
        "timeout_seconds": 300,
        "stream_limits": {
            "stdout_bytes": 1024,
            "stderr_bytes": 1024,
            "staged_member_bytes": 4096,
        },
    }


def _assignment() -> dict:
    return {
        "assignment_id": "depth-1-output",
        "members": [
            {
                "staged_relative_path": "result.md",
                "canonical_identity": "scratchpad:depth_result.md",
                "parser_binding": {"implementation_sha256": "c" * 64},
                "projection_mode": "CREATE_ABSENT",
                "canonical_prestate": {"status": "MISSING", "sha256": "", "size": 0},
            }
        ],
    }


def _plan(**overrides: object) -> dict:
    run_id = str(overrides.pop("run_id", "run-1"))
    denominator = T.compile_phase_work_roster_denominator(
        run_id=run_id,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
    )
    values: dict[str, object] = {
        "run_id": run_id,
        "phase": "depth",
        "work_unit_id": "depth-1",
        "generation": 1,
        "phase_roster_denominator_digest": denominator[
            "roster_denominator_digest"
        ],
        "phase_io_contract_digest": "d" * 64,
        "phase_io_launch_digest": "e" * 64,
        "phase_io_input_set_digest": "f" * 64,
        "prompt_sha256": "1" * 64,
        "methodology_digests": ("2" * 64, "3" * 64),
        "source_snapshot_digest": "4" * 64,
        "provider": _provider(),
        "assignment": _assignment(),
        "write_scope": {"mode": "ATTEMPT_ONLY", "roots": ["output"]},
        "child_denominator": {"required": []},
        "completion_policy": {"accepted_signals": ["PROCESS_EXIT_ZERO"]},
        "retry_policy": {"max_attempts": 2},
        "terminal_debt_policy": {"safe_authority": False},
    }
    values.update(overrides)
    return T.compile_worker_plan(**values)  # type: ignore[arg-type]


def test_roster_uses_a_noncyclic_denominator_digest() -> None:
    denominator = T.compile_phase_work_roster_denominator(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-2", "depth-1"),
        optional_work_unit_ids=("niche-1",),
    )
    assert denominator["required_work_unit_ids"] == ["depth-1", "depth-2"]
    assert "work_plan_digests" not in denominator
    assert "roster_digest" not in denominator

    roster = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1", "depth-2"),
        optional_work_unit_ids=("niche-1",),
        work_plan_digests={
            "depth-1": "a" * 64,
            "depth-2": "b" * 64,
            "niche-1": "c" * 64,
        },
    )
    assert (
        roster["roster_denominator_digest"]
        == denominator["roster_denominator_digest"]
    )
    assert roster["roster_digest"] != roster["roster_denominator_digest"]


def test_work_plan_digest_is_stable_and_every_provider_drift_changes_it() -> None:
    baseline = _plan()
    assert _plan() == baseline
    changed_model = _provider(model="sonnet")
    changed_argv = _provider()
    changed_argv["argv"] = [changed_argv["resolved_executable"], "--different"]
    changed_environment = _provider()
    changed_environment["environment_allowlist_digest"] = "9" * 64

    assert _plan(provider=changed_model)["work_plan_digest"] != baseline[
        "work_plan_digest"
    ]
    assert _plan(provider=changed_argv)["work_plan_digest"] != baseline[
        "work_plan_digest"
    ]
    assert _plan(provider=changed_environment)["work_plan_digest"] != baseline[
        "work_plan_digest"
    ]
    assert _plan(prompt_sha256="8" * 64)["work_plan_digest"] != baseline[
        "work_plan_digest"
    ]


@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda value: value["members"].append(dict(value["members"][0])),
            "collide",
        ),
        (
            lambda value: value["members"][0].__setitem__(
                "staged_relative_path", "../escape.md"
            ),
            "safe relative",
        ),
        (
            lambda value: value["members"][0].__setitem__(
                "canonical_identity", "project:source.sol"
            ),
            "scratchpad",
        ),
        (
            lambda value: value.__setitem__("unexpected", True),
            "schema drift",
        ),
    ],
)
def test_assignment_schema_rejects_ambiguity(
    mutation, match: str
) -> None:
    assignment = _assignment()
    mutation(assignment)
    with pytest.raises(T.WorkerTransactionError, match=match):
        _plan(assignment=assignment)


def test_work_plan_rejects_backend_transport_confusion() -> None:
    provider = _provider(backend="codex")
    provider["transport"] = "pty"
    with pytest.raises(T.WorkerTransactionError, match="pairing"):
        _plan(provider=provider)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _write_attempt(
    root: Path,
    *,
    phase: str,
    unit: str,
    plan_digest: str,
    attempt_id: str,
    generation: int = 1,
    terminal: str | None = None,
) -> Path:
    attempt = (
        root
        / ".worker_transactions"
        / phase
        / unit
        / plan_digest[:32]
        / attempt_id
    )
    attempt = T._make_safe_directory_tree(
        root,
        attempt.relative_to(root).as_posix(),
    )
    arm = {
        "schema": T.WORKER_ATTEMPT_ARM_SCHEMA,
        "run_id": "run-1",
        "phase": phase,
        "work_unit_id": unit,
        "generation": generation,
        "work_plan_digest": plan_digest,
        "attempt_id": attempt_id,
        "process_scope": {
            "state": "ARMED",
            "capability": "WINDOWS",
            "persistent_identity": f"scope-{attempt_id}",
        },
    }
    arm["arm_digest"] = hashlib.sha256(_canonical(arm)).hexdigest()
    with open(RIO.native_path(attempt / "arm.json"), "wb") as stream:
        stream.write(_canonical(arm) + b"\n")
    if terminal == "completion":
        completion = {
            "schema": "plamen.worker_attempt_completion.v1",
            "run_id": "run-1",
            "phase": phase,
            "work_unit_id": unit,
            "generation": generation,
            "work_plan_digest": plan_digest,
            "attempt_id": attempt_id,
            "arm_digest": arm["arm_digest"],
            "provider_completion_relative_path": (
                ".worker_execution_receipts/fixture/completion.json"
            ),
            "provider_completion_digest": "f" * 64,
            "canonical_projection_state": "PENDING_PHASE_IO",
        }
        completion["completion_digest"] = hashlib.sha256(
            _canonical(completion)
        ).hexdigest()
        with open(
            RIO.native_path(attempt / "completion.json"), "wb"
        ) as stream:
            stream.write(_canonical(completion) + b"\n")
    elif terminal == "debt":
        debt = {
            "schema": T.WORKER_ATTEMPT_DEBT_SCHEMA,
            "run_id": "run-1",
            "phase": phase,
            "work_unit_id": unit,
            "generation": generation,
            "work_plan_digest": plan_digest,
            "attempt_id": attempt_id,
            "arm_digest": arm["arm_digest"],
            "reason_code": "FIXTURE_TERMINAL_DEBT",
            "detail": "explicit fixture terminal debt",
            "completion_emitted": False,
            "retry_required": False,
        }
        debt["debt_digest"] = hashlib.sha256(_canonical(debt)).hexdigest()
        with open(
            RIO.native_path(attempt / "debt.json"), "wb"
        ) as stream:
            stream.write(_canonical(debt) + b"\n")
    elif terminal is not None:
        raise AssertionError(f"unsupported fixture terminal state: {terminal}")
    return attempt


def test_recovery_fails_closed_on_arm_digest_tamper(tmp_path: Path) -> None:
    attempt = (
        tmp_path
        / ".worker_transactions"
        / "depth"
        / "depth-1"
        / ("a" * 64)
        / "attempt-1"
    )
    attempt.mkdir(parents=True)
    arm = {
        "schema": T.WORKER_ATTEMPT_ARM_SCHEMA,
        "run_id": "run-1",
        "phase": "depth",
        "work_unit_id": "depth-1",
        "generation": 1,
        "work_plan_digest": "a" * 64,
        "attempt_id": "attempt-1",
        "process_scope": {
            "state": "ARMED",
            "capability": "WINDOWS_JOB_OR_LINUX_CGROUP",
            "persistent_identity": "scope-1",
        },
    }
    arm["arm_digest"] = hashlib.sha256(_canonical(arm)).hexdigest()
    arm["generation"] = 2
    (attempt / "arm.json").write_bytes(_canonical(arm) + b"\n")

    with pytest.raises(T.WorkerTransactionError, match="digest mismatch"):
        T.recover_worker_transactions(run_id="run-1", scratchpad=tmp_path)
    assert not (attempt / "debt.json").exists()


def test_recovery_blocks_retry_when_persisted_scope_cleanup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt = _write_attempt(
        tmp_path,
        phase="depth",
        unit="depth-1",
        plan_digest="a" * 64,
        attempt_id="attempt-orphan",
    )

    def fail_scope_recovery(_identity: str) -> dict:
        raise T.OwnedProcessScopeError("fixture cgroup remains populated")

    monkeypatch.setattr(
        T,
        "recover_persisted_process_scope",
        fail_scope_recovery,
    )
    status = T.recover_worker_transactions(
        run_id="run-1",
        scratchpad=tmp_path,
    )
    debt = json.loads(
        (attempt / "debt.json").read_text(encoding="utf-8")
    )
    assert debt["reason_code"] == "INTERRUPTED_SCOPE_CLEANUP_FAILED"
    assert debt["retry_required"] is False
    assert status.retry_work_unit_ids == ()
    assert status.blocked_work_unit_ids == ("depth-1",)


def test_roster_rejects_missing_or_extra_plan_rows() -> None:
    with pytest.raises(T.WorkerTransactionError, match="denominator"):
        T.compile_phase_work_roster(
            run_id="run-1",
            phase="depth",
            generation=1,
            required_work_unit_ids=("depth-1",),
            work_plan_digests={"depth-2": "a" * 64},
        )


def test_roster_reconcile_never_treats_missing_work_as_clean(
    tmp_path: Path,
) -> None:
    roster = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        work_plan_digests={"depth-1": "a" * 64},
    )
    status = T.reconcile_phase_work_roster(roster, scratchpad=tmp_path)
    assert status.clean is False
    assert status.completed_with_debt is False
    assert status.missing_work_unit_ids == ("depth-1",)


def test_roster_reconcile_marks_terminal_but_unincorporated_as_debt(
    tmp_path: Path,
) -> None:
    plan_digest = "a" * 64
    _write_attempt(
        tmp_path,
        phase="depth",
        unit="depth-1",
        plan_digest=plan_digest,
        attempt_id="attempt-terminal",
        terminal="completion",
    )
    roster = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        work_plan_digests={"depth-1": plan_digest},
    )
    status = T.reconcile_phase_work_roster(roster, scratchpad=tmp_path)
    assert status.clean is False
    assert status.completed_with_debt is True
    assert status.debt_work_unit_ids == ("depth-1",)
    assert status.missing_work_unit_ids == ()


def test_roster_reconcile_active_attempt_blocks_phase_completion(
    tmp_path: Path,
) -> None:
    plan_digest = "a" * 64
    _write_attempt(
        tmp_path,
        phase="depth",
        unit="depth-1",
        plan_digest=plan_digest,
        attempt_id="attempt-active",
    )
    roster = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        work_plan_digests={"depth-1": plan_digest},
    )
    status = T.reconcile_phase_work_roster(roster, scratchpad=tmp_path)
    assert status.clean is False
    assert status.completed_with_debt is False
    assert status.active_attempt_ids == ("attempt-active",)
    assert status.missing_work_unit_ids == ("depth-1",)


def test_roster_reconcile_rejects_active_registry_schema_drift(
    tmp_path: Path,
) -> None:
    transaction_root = tmp_path / ".worker_transactions"
    transaction_root.mkdir()
    registry = {
        "schema": "plamen.worker_active_attempts.v1",
        "attempts": {
            "attempt-forged": {
                "run_id": "run-1",
                "phase": "depth",
                "work_unit_id": "depth-1",
                "generation": 1,
                "work_plan_digest": "a" * 64,
                "attempt_relative_path": (
                    "depth/depth-1/"
                    + ("a" * 32)
                    + "/attempt-forged"
                ),
                "arm_digest": "b" * 64,
                "unexpected": True,
            }
        },
    }
    registry["registry_digest"] = hashlib.sha256(
        _canonical(registry)
    ).hexdigest()
    (transaction_root / "active_attempts.json").write_bytes(
        _canonical(registry) + b"\n"
    )
    roster = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        work_plan_digests={"depth-1": "a" * 64},
    )
    with pytest.raises(T.WorkerTransactionError, match="schema drift"):
        T.reconcile_phase_work_roster(roster, scratchpad=tmp_path)


def test_roster_reconcile_rejects_terminal_receipt_binding_drift(
    tmp_path: Path,
) -> None:
    attempt = _write_attempt(
        tmp_path,
        phase="depth",
        unit="depth-1",
        plan_digest="a" * 64,
        attempt_id="attempt-drift",
        terminal="completion",
    )
    completion = json.loads(
        (attempt / "completion.json").read_text(encoding="utf-8")
    )
    completion["generation"] = 2
    unsigned = {
        key: value
        for key, value in completion.items()
        if key != "completion_digest"
    }
    completion["completion_digest"] = hashlib.sha256(
        _canonical(unsigned)
    ).hexdigest()
    (attempt / "completion.json").write_bytes(
        _canonical(completion) + b"\n"
    )
    roster = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        work_plan_digests={"depth-1": "a" * 64},
    )
    with pytest.raises(T.WorkerTransactionError, match="generation differs"):
        T.reconcile_phase_work_roster(roster, scratchpad=tmp_path)


def _strict_proposal_digest(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8"))
    if value != {"status": "PROPOSED"}:
        raise ValueError("unexpected native proposal")
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_native_transaction_stages_without_canonical_publication(
    tmp_path: Path,
) -> None:
    prompt = b"native fixture prompt\n"
    allowlist = W.environment_allowlist_sha256(())
    inputs = {
        "manifest.json": b"{}\n",
        "intent.json": (
            json.dumps(
                {
                    "effective_backend": "native",
                    "effective_model": "python-fixture",
                    "environment_allowlist_sha256": allowlist,
                },
                sort_keys=True,
            ).encode()
            + b"\n"
        ),
        "context.md": b"fixture context\n",
        "prompt.md": prompt,
        "tool_policy.json": b'{"network":false}\n',
    }
    for name, raw in inputs.items():
        (tmp_path / name).write_bytes(raw)

    executable = Path(sys.executable).resolve()
    provider = {
        "backend": "native",
        "model": "python-fixture",
        "transport": "native",
        "resolved_executable": str(executable),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "argv": [
            str(executable),
            "-c",
            "print('{\"status\":\"PROPOSED\"}')",
        ],
        "environment_allowlist_digest": allowlist,
        "timeout_seconds": 30,
        "stream_limits": {
            "stdout_bytes": 4096,
            "stderr_bytes": 4096,
            "staged_member_bytes": 4096,
        },
    }
    plan = _plan(
        provider=provider,
        prompt_sha256=hashlib.sha256(prompt).hexdigest(),
    )
    execution = T.execute_worker_transaction(
        plan,
        T.NativeCommandAdapter(
            scratchpad=tmp_path,
            cwd=tmp_path,
            input_relative_paths={
                "manifest": "manifest.json",
                "intent": "intent.json",
                "context": "context.md",
                "prompt": "prompt.md",
                "tool_policy": "tool_policy.json",
            },
            parser_digest=_strict_proposal_digest,
            environment={},
            environment_allowlist=(),
        ),
    )

    assert execution.attempt_completion_path.is_file()
    assert not (tmp_path / "depth_result.md").exists()
    assert execution.provider_execution.publish_receipt_path is None
    W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=execution.provider_execution.receipt_path,
        parser_digest=_strict_proposal_digest,
        expected_completion_sha256=(
            execution.provider_execution.completion_sha256
        ),
    )
    registry = json.loads(
        (tmp_path / ".worker_transactions" / "active_attempts.json").read_text(
            encoding="utf-8"
        )
    )
    assert registry["attempts"] == {}


def test_headless_model_uses_precompiled_attempt_lane_and_cannot_publish_canonical(
    tmp_path: Path,
) -> None:
    allowlist = W.environment_allowlist_sha256(())
    startup_permit = durable_startup_permit(tmp_path)
    scope = T.compile_attempt_write_scope(
        run_id=FIXTURE_RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id="attempt-" + "a" * 24,
    )
    output = T.attempt_output_directory(tmp_path, scope) / "result.md"
    prompt = (
        f"Write the assigned artifact only to {output.as_posix()}\n"
    ).encode()
    inputs = {
        "manifest.json": b"{}\n",
        "intent.json": (
            json.dumps(
                {
                    "effective_backend": "codex",
                    "effective_model": "fixture-model",
                    "environment_allowlist_sha256": allowlist,
                    "auxiliary_writable_root_startup": startup_permit,
                },
                sort_keys=True,
            ).encode()
            + b"\n"
        ),
        "context.md": b"fixture model context\n",
        "prompt.md": prompt,
        "tool_policy.json": b'{"network":false}\n',
    }
    for name, raw in inputs.items():
        (tmp_path / name).write_bytes(raw)

    executable = Path(sys.executable).resolve()
    provider = {
        "backend": "codex",
        "model": "fixture-model",
        "transport": "exec",
        "resolved_executable": str(executable),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "argv": [
            str(executable),
            "-I",
            "-c",
            (
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text("
                "'{\"status\":\"PROPOSED\"}', encoding='utf-8')"
            ),
            str(output),
        ],
        "environment_allowlist_digest": allowlist,
        "timeout_seconds": 30,
        "stream_limits": {
            "stdout_bytes": 4096,
            "stderr_bytes": 4096,
            "staged_member_bytes": 4096,
        },
    }
    plan = _plan(
        run_id=FIXTURE_RUN_ID,
        provider=provider,
        prompt_sha256=hashlib.sha256(prompt).hexdigest(),
        write_scope=scope,
        completion_policy={
            "accepted_signals": ["PROCESS_EXIT_ZERO"],
            T.AUXILIARY_STARTUP_POLICY_KEY: startup_permit,
        },
    )
    execution = T.execute_worker_transaction(
        plan,
        T.HeadlessModelAdapter(
            scratchpad=tmp_path,
            cwd=tmp_path,
            input_relative_paths={
                "manifest": "manifest.json",
                "intent": "intent.json",
                "context": "context.md",
                "prompt": "prompt.md",
                "tool_policy": "tool_policy.json",
            },
            parser_digest=_strict_proposal_digest,
            environment={},
            environment_allowlist=(),
            attempt_id=str(scope["attempt_id"]),
            startup_authority_binding=startup_permit,
        ),
    )

    assert execution.attempt_id == scope["attempt_id"]
    assert execution.attempt_directory == output.parent.parent
    assert output.is_file()
    assert not (tmp_path / "depth_result.md").exists()
    assert execution.provider_execution.publish_receipt_path is None

    with pytest.raises(T.WorkerTransactionError, match="already exists"):
        T.execute_worker_transaction(
            plan,
            T.HeadlessModelAdapter(
                scratchpad=tmp_path,
                cwd=tmp_path,
                input_relative_paths={
                    "manifest": "manifest.json",
                    "intent": "intent.json",
                    "context": "context.md",
                    "prompt": "prompt.md",
                    "tool_policy": "tool_policy.json",
                },
                parser_digest=_strict_proposal_digest,
                environment={},
                environment_allowlist=(),
                attempt_id=str(scope["attempt_id"]),
                startup_authority_binding=startup_permit,
            ),
        )


def test_phaseio_incorporation_is_the_only_canonical_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = b"native incorporation prompt\n"
    allowlist = W.environment_allowlist_sha256(())
    inputs = {
        "manifest.json": b"{}\n",
        "intent.json": (
            json.dumps(
                {
                    "effective_backend": "native",
                    "effective_model": "python-fixture",
                    "environment_allowlist_sha256": allowlist,
                },
                sort_keys=True,
            ).encode()
            + b"\n"
        ),
        "context.md": b"fixture context\n",
        "prompt.md": prompt,
        "tool_policy.json": b'{"network":false}\n',
    }
    for name, raw in inputs.items():
        (tmp_path / name).write_bytes(raw)

    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "native", "depth", "depth-1"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="native",
        phase="depth",
        work_unit_id="depth-1",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="depth_result.md",
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
            ),
        ),
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="native",
        model="python-fixture",
        timeout_s=30,
        exec_mode="native",
    )
    prelaunch = L.record_work_unit_inputs(
        tmp_path,
        tmp_path,
        contract,
        launch,
        run_id="run-1",
    )
    prestate = prelaunch["output_prestates"]["scratchpad:depth_result.md"]

    executable = Path(sys.executable).resolve()
    provider = {
        "backend": "native",
        "model": "python-fixture",
        "transport": "native",
        "resolved_executable": str(executable),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "argv": [
            str(executable),
            "-c",
            "print('{\"status\":\"PROPOSED\"}')",
        ],
        "environment_allowlist_digest": allowlist,
        "timeout_seconds": 30,
        "stream_limits": {
            "stdout_bytes": 4096,
            "stderr_bytes": 4096,
            "staged_member_bytes": 4096,
        },
    }
    assignment = _assignment()
    assignment["members"][0]["canonical_prestate"] = prestate
    plan = _plan(
        provider=provider,
        assignment=assignment,
        prompt_sha256=hashlib.sha256(prompt).hexdigest(),
        phase_io_contract_digest=contract.digest,
        phase_io_launch_digest=launch.digest,
        phase_io_input_set_digest=prelaunch["input_set_digest"],
    )
    adapter = T.NativeCommandAdapter(
        scratchpad=tmp_path,
        cwd=tmp_path,
        input_relative_paths={
            "manifest": "manifest.json",
            "intent": "intent.json",
            "context": "context.md",
            "prompt": "prompt.md",
            "tool_policy": "tool_policy.json",
        },
        parser_digest=_strict_proposal_digest,
        environment={},
        environment_allowlist=(),
    )
    execution = T.execute_worker_transaction(plan, adapter)
    assert not (tmp_path / "depth_result.md").exists()

    original_write_absent_json = T._write_absent_json

    def fail_before_member_receipt(path: Path, payload: dict) -> None:
        if path.name == "member-0000.json":
            raise RuntimeError("fixture crash after canonical CAS projection")
        original_write_absent_json(path, payload)

    monkeypatch.setattr(T, "_write_absent_json", fail_before_member_receipt)
    with pytest.raises(
        RuntimeError,
        match="fixture crash after canonical CAS projection",
    ):
        T.incorporate_worker_execution(
            execution,
            contract,
            phase_io_launch=launch,
            work_plan=plan,
            parser_digest=_strict_proposal_digest,
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id="run-1",
        )
    assert (tmp_path / "depth_result.md").is_file()
    assert L.read_artifact_ledger(tmp_path)["work_units"][key][
        "semantic_status"
    ] == "INPUTS_BOUND"

    def fail_before_incorporation_receipt(path: Path, payload: dict) -> None:
        if path.name == "incorporation.json":
            raise RuntimeError("fixture crash after member progress")
        original_write_absent_json(path, payload)

    monkeypatch.setattr(T, "_write_absent_json", fail_before_incorporation_receipt)
    with pytest.raises(RuntimeError, match="fixture crash after member progress"):
        T.incorporate_worker_execution(
            execution,
            contract,
            phase_io_launch=launch,
            work_plan=plan,
            parser_digest=_strict_proposal_digest,
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id="run-1",
        )
    assert L.read_artifact_ledger(tmp_path)["work_units"][key][
        "semantic_status"
    ] == "INPUTS_BOUND"

    monkeypatch.setattr(T, "_write_absent_json", original_write_absent_json)
    incorporation = T.incorporate_worker_execution(
        execution,
        contract,
        phase_io_launch=launch,
        work_plan=plan,
        parser_digest=_strict_proposal_digest,
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id="run-1",
    )
    assert incorporation.projected_paths == (tmp_path / "depth_result.md",)
    assert (tmp_path / "depth_result.md").is_file()
    unit = L.read_artifact_ledger(tmp_path)["work_units"][key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_authority"]["incorporation_digest"] == (
        incorporation.incorporation_digest
    )
    roster = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        work_plan_digests={"depth-1": plan["work_plan_digest"]},
    )
    phase_status = T.reconcile_phase_work_roster(
        roster,
        scratchpad=tmp_path,
    )
    assert phase_status.clean is True
    assert phase_status.completed_with_debt is False
    assert phase_status.incorporated_work_unit_ids == ("depth-1",)
    assert phase_status.debt_work_unit_ids == ()
    assert phase_status.missing_work_unit_ids == ()
    assert phase_status.active_attempt_ids == ()
    optional_plan_digest = "9" * 64
    _write_attempt(
        tmp_path,
        phase="depth",
        unit="niche-1",
        plan_digest=optional_plan_digest,
        attempt_id="attempt-optional-debt",
        terminal="debt",
    )
    roster_with_optional = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        optional_work_unit_ids=("niche-1",),
        work_plan_digests={
            "depth-1": plan["work_plan_digest"],
            "niche-1": optional_plan_digest,
        },
    )
    optional_status = T.reconcile_phase_work_roster(
        roster_with_optional,
        scratchpad=tmp_path,
    )
    assert optional_status.clean is False
    assert optional_status.completed_with_debt is True
    assert optional_status.incorporated_work_unit_ids == ("depth-1",)
    assert optional_status.debt_work_unit_ids == ("niche-1",)

    _write_attempt(
        tmp_path,
        phase="depth",
        unit="unrostered-1",
        plan_digest="8" * 64,
        attempt_id="attempt-unrostered",
        terminal="debt",
    )
    unrostered_status = T.reconcile_phase_work_roster(
        roster_with_optional,
        scratchpad=tmp_path,
    )
    assert unrostered_status.clean is False
    assert unrostered_status.completed_with_debt is True
    assert unrostered_status.debt_work_unit_ids == (
        "niche-1",
        "unrostered-1",
    )

    drifted_roster = T.compile_phase_work_roster(
        run_id="run-1",
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        optional_work_unit_ids=("niche-1",),
        work_plan_digests={
            "depth-1": "7" * 64,
            "niche-1": optional_plan_digest,
        },
    )
    drifted_status = T.reconcile_phase_work_roster(
        drifted_roster,
        scratchpad=tmp_path,
    )
    assert drifted_status.clean is False
    assert drifted_status.completed_with_debt is True
    assert drifted_status.incorporated_work_unit_ids == ()
    assert drifted_status.debt_work_unit_ids == (
        "depth-1",
        "niche-1",
        "unrostered-1",
    )
    replay = T.incorporate_worker_execution(
        execution,
        contract,
        phase_io_launch=launch,
        work_plan=plan,
        parser_digest=_strict_proposal_digest,
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id="run-1",
    )
    assert replay.incorporation_digest == incorporation.incorporation_digest

    (tmp_path / "depth_result.md").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(T.WorkerTransactionError, match="canonical bytes changed"):
        T.validate_worker_execution_authority(
            scratchpad=tmp_path,
            authority=unit["execution_authority"],
            contract=contract,
            launch=launch,
            run_id="run-1",
        )
