"""P0-AM RED fixtures for attempt-independent WorkPlan v2.

These fixtures pin the non-cyclic identity split:

* WorkPlan v2 contains stable templates and the phase roster denominator.
* The final phase roster binds every WorkPlan digest.
* AttemptArm binds both identities plus the exact attempt materialization.

No final roster or attempt-local path may be inferred after launch.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

import artifact_ledger as ledger
from test_claude_launch_authority_fixtures import (
    claude_test_postprocess_state_update_source,
    compile_test_claude_launch_authority,
    compile_test_claude_provider_preparation,
    install_test_only_launch_authority_adapter,
)
import headless_worker_runtime as runtime
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import worker_transaction as T
from test_support_startup_permit import (
    FIXTURE_RUN_ID as RUN_ID,
    durable_startup_permit,
)

STDOUT_LIMIT = 16 * 1024 * 1024


@pytest.fixture(autouse=True)
def _test_only_provider_authority_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform == "win32" and int(
        getattr(Path(sys.executable).stat(), "st_nlink", 1)
    ) != 1:
        reviewed = Path(r"C:\p27rt\python.exe")
        if reviewed.is_file() and int(
            getattr(reviewed.stat(), "st_nlink", 1)
        ) == 1:
            monkeypatch.setattr(
                sys,
                "executable",
                str(reviewed.resolve(strict=True)),
            )
    install_test_only_launch_authority_adapter(monkeypatch.setattr)


def _provider(scope: dict[str, object]) -> dict[str, object]:
    return {
        "backend": "claude",
        "model": "fixture-model",
        "transport": "headless",
        "resolved_executable": "C:/tools/provider.exe",
        "executable_sha256": "a" * 64,
        "argv": [
            "C:/tools/provider.exe",
            "--output",
            str(scope["output_relative_path"]),
        ],
        "environment_allowlist_digest": "b" * 64,
        "timeout_seconds": 30,
        "stream_limits": {
            "stdout_bytes": 1024,
            "stderr_bytes": 1024,
            "staged_member_bytes": 4096,
        },
    }


def _assignment() -> dict[str, object]:
    return {
        "assignment_id": "depth-1-output",
        "members": [
            {
                "staged_relative_path": "result.md",
                "canonical_identity": "scratchpad:result.md",
                "parser_binding": {"implementation_sha256": "c" * 64},
                "projection_mode": "CREATE_ABSENT",
                "canonical_prestate": {
                    "status": "ABSENT",
                    "sha256": "",
                    "size": 0,
                },
            }
        ],
    }


def _compile_plan(
    *,
    scope: dict[str, object],
    denominator_digest: str,
    work_unit_id: str = "depth-1",
    completion_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    return T.compile_worker_plan(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id=work_unit_id,
        generation=1,
        phase_roster_denominator_digest=denominator_digest,
        phase_io_contract_digest="d" * 64,
        phase_io_launch_digest="e" * 64,
        phase_io_input_set_digest="f" * 64,
        prompt_template_sha256="1" * 64,
        methodology_digests=("2" * 64,),
        source_snapshot_digest="3" * 64,
        provider=_provider(scope),
        assignment=_assignment(),
        write_scope=scope,
        child_denominator={"required": [], "optional": []},
        completion_policy=(
            {"accepted_signals": ["PROCESS_EXIT_ZERO"]}
            if completion_policy is None
            else completion_policy
        ),
        retry_policy={
            "max_attempts": 2,
            "retry_requires_new_attempt_id": True,
        },
        terminal_debt_policy={
            "safe_authority": False,
            "human_review_on_exhaustion": True,
        },
    )


def _fixture_staged_validator(outputs, context):
    del outputs, context
    return []


def test_attempt_identity_and_path_do_not_change_work_plan_v2_digest() -> None:
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
    )
    first_scope = T.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id="attempt-" + "a" * 24,
    )
    second_scope = T.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id="attempt-" + "b" * 24,
    )

    first = _compile_plan(
        scope=first_scope,
        denominator_digest=denominator["roster_denominator_digest"],
    )
    second = _compile_plan(
        scope=second_scope,
        denominator_digest=denominator["roster_denominator_digest"],
    )

    assert first["schema"] == "plamen.worker_work_plan.v2"
    assert first["work_plan_digest"] == second["work_plan_digest"]
    assert first["write_scope_template"] == second["write_scope_template"]
    assert first["provider"]["argv_template"] == second["provider"]["argv_template"]
    assert "attempt-" + "a" * 24 not in json.dumps(first, sort_keys=True)
    assert "attempt-" + "b" * 24 not in json.dumps(second, sort_keys=True)
    assert "write_scope" not in first
    assert "argv" not in first["provider"]


def test_staged_gate_is_bound_after_attempt_path_normalization() -> None:
    first_scope = T.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id="attempt-" + "a" * 24,
    )
    second_scope = T.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id="attempt-" + "b" * 24,
    )

    def gate(scope: dict[str, object]) -> dict[str, object]:
        return T.staged_output_validator_binding(
            _fixture_staged_validator,
            context={
                "schema": "fixture.staged-gate-context.v1",
                "output_directory": (
                    "C:/stable-scratchpad/"
                    + str(scope["output_relative_path"])
                ),
            },
            required_input_bindings={},
            write_scope=scope,
        )

    first = gate(first_scope)
    second = gate(second_scope)
    assert first == second
    assert first["context"]["output_directory"] == (
        "C:/stable-scratchpad/"
        + T.ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER
    )
    assert "attempt-" not in json.dumps(first["context"], sort_keys=True)
    unsigned = {
        key: value
        for key, value in first.items()
        if key != "binding_sha256"
    }
    assert first["binding_sha256"] == hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_staged_gate_tampered_binding_digest_fails_closed() -> None:
    scope = T.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id="attempt-" + "c" * 24,
    )
    gate = T.staged_output_validator_binding(
        _fixture_staged_validator,
        context={
            "output_directory": (
                "C:/stable-scratchpad/"
                + str(scope["output_relative_path"])
            )
        },
        required_input_bindings={},
        write_scope=scope,
    )
    gate["binding_sha256"] = "0" * 64
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
    )
    with pytest.raises(
        T.WorkerTransactionError,
        match="staged semantic validator binding digest mismatch",
    ):
        _compile_plan(
            scope=scope,
            denominator_digest=denominator["roster_denominator_digest"],
            completion_policy={
                "accepted_signals": ["PROCESS_EXIT_ZERO"],
                "staged_semantic_gate": gate,
            },
        )


def test_plan_roster_mismatch_and_foreign_unit_fail_closed() -> None:
    depth_one = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
    )
    scope = T.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id="attempt-" + "c" * 24,
    )
    plan = _compile_plan(
        scope=scope,
        denominator_digest=depth_one["roster_denominator_digest"],
    )
    mismatched = T.compile_phase_work_roster(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        work_plan_digests={"depth-1": "9" * 64},
    )
    with pytest.raises(T.WorkerTransactionError, match="WorkPlan.*roster"):
        T.validate_work_plan_phase_roster(plan, mismatched)

    depth_two = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-2",),
    )
    foreign_plan = _compile_plan(
        scope=scope,
        denominator_digest=depth_two["roster_denominator_digest"],
    )
    foreign_roster = T.compile_phase_work_roster(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-2",),
        work_plan_digests={
            "depth-2": foreign_plan["work_plan_digest"],
        },
    )
    with pytest.raises(T.WorkerTransactionError, match="foreign work unit"):
        T.validate_work_plan_phase_roster(foreign_plan, foreign_roster)


def _contract() -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "depth",
        "worker.role-1",
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.role-1",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="depth_role_1_findings.md",
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
        backend="claude",
        model="fixture-model",
        timeout_s=30,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _arm_phaseio(root: Path) -> tuple[PhaseIOContract, LaunchSpec]:
    contract, launch = _contract()
    ledger.record_work_unit_inputs(
        root,
        root,
        contract,
        launch,
        run_id=RUN_ID,
    )
    return contract, launch


def _retryable_writer(root: Path, *, authority: dict[str, object]):
    allow = root / "allow-success"
    provider_script = root / "fixture-retryable-provider.py"
    provider_script.write_text(
        "from pathlib import Path\n"
        "import re\n"
        "import sys\n"
        f"allow=Path({str(allow)!r})\n"
        "prompt=sys.stdin.buffer.read().decode('utf-8')\n"
        "targets=re.findall(r'-> `([^`]+)`', prompt)\n"
        "if len(targets) != 1:\n"
        "    raise SystemExit(8)\n"
        "output=Path(targets[0])\n"
        "if not allow.exists():\n"
        "    raise SystemExit(7)\n"
        "output.parent.mkdir(parents=True, exist_ok=True)\n"
        "output.write_text("
        "'## Findings\\n\\nNo finding was proven unsafe.\\n', "
        "encoding='utf-8')\n"
        f"{claude_test_postprocess_state_update_source()}"
        f"sys.stdout.buffer.write({authority['stream_bytes']!r})\n",
        encoding="utf-8",
    )

    def build(output_directory: Path) -> tuple[str, ...]:
        del output_directory
        suffix = tuple(authority["command_suffix"])
        return (
            sys.executable,
            str(provider_script),
            suffix[0],
            *suffix[1:],
        )

    return build


def _run_headless(
    root: Path,
    *,
    attempt_id: str,
) -> runtime.HeadlessWorkerResult:
    contract, launch = _contract()
    authority = compile_test_claude_launch_authority(
        cwd=root,
        launch_model=launch.model,
        stdout_limit_bytes=STDOUT_LIMIT,
        session_label="v2-roster",
    )
    builder = _retryable_writer(root, authority=authority)
    startup = durable_startup_permit(root)
    provider_preparation = compile_test_claude_provider_preparation(
        authority=authority,
        base_argv=builder(Path("unused")),
        cwd=root,
        run_id=RUN_ID,
        phase=contract.phase,
        startup_authority_binding=startup,
        source_snapshot_sha256="a" * 64,
    )
    return runtime.execute_headless_worker(
        scratchpad=root,
        project_root=root,
        run_id=RUN_ID,
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze the assigned role and write its artifact.",
        command_builder=builder,
        cwd=root,
        environment={},
        environment_allowlist=authority["environment_allowlist"],
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=startup,
        stdout_limit_bytes=STDOUT_LIMIT,
        provider_stdout_evidence_configuration=authority[
            "stream_configuration"
        ],
        claude_launch_security=authority["policy"],
        claude_launch_security_request=authority["request"],
        claude_provider_preparation=provider_preparation,
        claude_runtime_local_inputs=authority["runtime_local_inputs"],
        attempt_id=attempt_id,
    )


def test_attempt_arm_binds_final_roster_digest_and_exact_membership(
    tmp_path: Path,
) -> None:
    _arm_phaseio(tmp_path)
    (tmp_path / "allow-success").write_text("yes", encoding="utf-8")

    result = _run_headless(
        tmp_path,
        attempt_id="attempt-" + "d" * 24,
    )
    arm = json.loads(
        (result.execution.attempt_directory / "arm.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )

    assert arm["schema"] == "plamen.worker_attempt_arm.v3"
    assert arm["phase_roster_digest"] == result.phase_roster["roster_digest"]
    persisted_roster = json.loads(
        (
            result.execution.attempt_directory
            / "view"
            / "phase_roster.json"
        ).read_text(encoding="utf-8", errors="strict")
    )
    assert persisted_roster == result.phase_roster
    assert arm["phase_roster_denominator_digest"] == result.work_plan[
        "phase_roster_denominator_digest"
    ]
    assert result.phase_roster["work_plan_digests"] == {
        "worker.role-1": result.work_plan["work_plan_digest"]
    }
    assert arm["work_plan_digest"] == result.work_plan["work_plan_digest"]
    assert arm["materialized"]["write_scope"]["attempt_id"] == (
        "attempt-" + "d" * 24
    )
    assert arm["materialized"]["final_argv_authority"] == (
        "INNER_PROVIDER_ARM_AFTER_RUNTIME_MATERIALIZATION"
    )
    assert "base_argv" in arm["materialized"]
    assert "base_argv_sha256" in arm["materialized"]
    assert "argv" not in arm["materialized"]
    assert "argv_sha256" not in arm["materialized"]
    assert any(
        token in json.dumps(result.work_plan, sort_keys=True)
        for token in (
            T.ATTEMPT_ID_PLACEHOLDER,
            T.ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER,
            T.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER,
        )
    )
    assert not any(
        token in json.dumps(arm["materialized"], sort_keys=True)
        for token in (
            T.ATTEMPT_ID_PLACEHOLDER,
            T.ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER,
            T.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER,
        )
    )
    materialized_prompt = (
        result.execution.attempt_directory / "view" / "prompt.md"
    ).read_text(encoding="utf-8", errors="strict")
    assert "attempt-" + "d" * 24 in materialized_prompt
    assert T.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER not in materialized_prompt
    assert arm["materialized"]["prompt_sha256"] != result.work_plan[
        "prompt_template_sha256"
    ]


def test_retry_retains_work_plan_and_final_roster_digests(
    tmp_path: Path,
) -> None:
    _arm_phaseio(tmp_path)
    with pytest.raises(runtime.HeadlessWorkerRuntimeError):
        _run_headless(
            tmp_path,
            attempt_id="attempt-" + "e" * 24,
        )

    (tmp_path / "allow-success").write_text("yes", encoding="utf-8")
    result = _run_headless(
        tmp_path,
        attempt_id="attempt-" + "f" * 24,
    )
    arms = [
        json.loads(path.read_text(encoding="utf-8", errors="strict"))
        for path in sorted(
            (tmp_path / ".worker_transactions" / "depth").glob(
                "**/arm.json"
            )
        )
    ]
    transaction_arms = [
        arm for arm in arms if arm.get("schema") == "plamen.worker_attempt_arm.v3"
    ]

    assert len(transaction_arms) == 2
    assert {arm["attempt_id"] for arm in transaction_arms} == {
        "attempt-" + "e" * 24,
        "attempt-" + "f" * 24,
    }
    assert {arm["work_plan_digest"] for arm in transaction_arms} == {
        result.work_plan["work_plan_digest"]
    }
    assert {arm["phase_roster_digest"] for arm in transaction_arms} == {
        result.phase_roster["roster_digest"]
    }
    assert len(
        {
            arm["materialized"]["prompt_sha256"]
            for arm in transaction_arms
        }
    ) == 2


def test_prompt_template_digest_is_the_exact_stable_template() -> None:
    token = T.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER
    raw = f"write only to {token}/result.md".encode("utf-8")
    assert T.prompt_template_sha256(raw) == hashlib.sha256(raw).hexdigest()


def test_work_plan_v2_rejects_self_consistent_schema_extension() -> None:
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
    )
    scope = T.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id="attempt-" + "9" * 24,
    )
    plan = _compile_plan(
        scope=scope,
        denominator_digest=denominator["roster_denominator_digest"],
    )
    plan["unexpected"] = True
    unsigned = {
        key: value
        for key, value in plan.items()
        if key != "work_plan_digest"
    }
    plan["work_plan_digest"] = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    with pytest.raises(T.WorkerTransactionError, match="schema drift"):
        T._validate_compiled_plan(plan)


def test_v2_armed_attempt_recovers_to_retry_without_losing_roster_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
    )
    attempt_id = "attempt-" + "8" * 24
    scope = T.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase="depth",
        work_unit_id="depth-1",
        attempt_id=attempt_id,
    )
    plan = _compile_plan(
        scope=scope,
        denominator_digest=denominator["roster_denominator_digest"],
    )
    roster = T.compile_phase_work_roster(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=("depth-1",),
        work_plan_digests={
            "depth-1": plan["work_plan_digest"],
        },
    )
    attempt = (
        tmp_path
        / ".worker_transactions"
        / "depth"
        / "depth-1"
        / "attempts"
        / attempt_id
    )
    attempt.mkdir(parents=True)
    argv = ["C:/tools/provider.exe", scope["output_relative_path"]]
    arm = {
        "schema": T.WORKER_ATTEMPT_ARM_SCHEMA_V2,
        "run_id": RUN_ID,
        "phase": "depth",
        "work_unit_id": "depth-1",
        "generation": 1,
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": attempt_id,
        "process_scope": {
            "state": "ARMED",
            "capability": "WINDOWS",
            "persistent_identity": "fixture-v2-recovery",
        },
        "phase_roster_digest": roster["roster_digest"],
        "phase_roster_denominator_digest": roster[
            "roster_denominator_digest"
        ],
        T.AUXILIARY_STARTUP_POLICY_KEY: None,
        "materialized": {
            "argv": argv,
            "argv_sha256": T._argv_sha256(argv),
            "prompt_sha256": "7" * 64,
            "write_scope": scope,
        },
    }
    unsigned_arm = json.dumps(
        arm,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    arm["arm_digest"] = hashlib.sha256(unsigned_arm).hexdigest()
    (attempt / "arm.json").write_text(
        json.dumps(
            arm,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        T,
        "recover_persisted_process_scope",
        lambda _identity: {
            "cleanup": "RECOVERED",
            "population_zero_proven": True,
        },
    )

    status = T.recover_worker_transactions(
        run_id=RUN_ID,
        scratchpad=tmp_path,
    )
    debt = json.loads(
        (attempt / "debt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )

    assert status.retry_work_unit_ids == ("depth-1",)
    assert debt["work_plan_digest"] == plan["work_plan_digest"]
    assert debt["arm_digest"] == arm["arm_digest"]
    persisted_arm = json.loads(
        (attempt / "arm.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert persisted_arm["phase_roster_digest"] == roster["roster_digest"]
