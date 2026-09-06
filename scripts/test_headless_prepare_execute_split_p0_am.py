"""P0-AM fixtures for prepare -> roster freeze -> execute ordering."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys

import pytest

import artifact_ledger as ledger
import claude_provider_preparation as P
import claude_runtime_materialization as M
from test_claude_launch_authority_fixtures import (
    claude_test_postprocess_state_update_source,
    compile_test_claude_launch_authority,
    compile_test_claude_provider_preparation,
    compile_test_claude_runtime_local_inputs,
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
    install_test_only_launch_authority_adapter(monkeypatch.setattr)


def _authority(
    root: Path,
    unit_id: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "depth",
        unit_id,
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id=unit_id,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=f"{unit_id}.md",
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
    ledger.record_work_unit_inputs(
        root,
        root,
        contract,
        launch,
        run_id=RUN_ID,
    )
    return contract, launch


def _writer(
    root: Path,
    *,
    authority: dict[str, object],
    output_name: str = "worker.role-1.md",
    count_file: Path | None = None,
):
    allow = root / "allow-success"
    provider_script = root / (
        "fixture-provider-" + output_name.replace(".", "-") + ".py"
    )
    provider_script.write_text(
        "from pathlib import Path\n"
        "import re\n"
        "import sys\n"
        f"allow=Path({str(allow)!r})\n"
        f"counter=Path({str(count_file)!r}) "
        f"if {count_file is not None!r} else None\n"
        "if counter:\n"
        "    counter.write_text("
        "(counter.read_text() if counter.exists() else '')+'x')\n"
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


def _prepare(
    root: Path,
    *,
    unit_id: str,
    denominator_digest: str,
    command_builder=None,
) -> runtime.PreparedHeadlessWorker:
    contract, launch = _authority(root, unit_id)
    authority = compile_test_claude_launch_authority(
        cwd=root,
        launch_model=launch.model,
        stdout_limit_bytes=STDOUT_LIMIT,
        session_label=f"prepare-split:{unit_id}",
    )
    builder = command_builder or _writer(
        root,
        authority=authority,
        output_name=f"{unit_id}.md",
    )
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
    return runtime.prepare_headless_worker(
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
        phase_roster_denominator_digest=denominator_digest,
        stdout_limit_bytes=STDOUT_LIMIT,
        provider_stdout_evidence_configuration=authority[
            "stream_configuration"
        ],
        claude_launch_security=authority["policy"],
        claude_launch_security_request=authority["request"],
        claude_provider_preparation=provider_preparation,
        claude_runtime_local_inputs=authority["runtime_local_inputs"],
    )


def test_six_prepares_share_denominator_and_do_not_launch_before_roster_freeze(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    units = tuple(f"worker.role-{index}" for index in range(1, 7))
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=units,
    )
    launches = 0

    def forbidden_launch(*_args, **_kwargs):
        nonlocal launches
        launches += 1
        raise AssertionError("provider launched during prepare")

    monkeypatch.setattr(runtime, "execute_worker_transaction", forbidden_launch)
    prepared = [
        _prepare(
            tmp_path,
            unit_id=unit,
            denominator_digest=denominator["roster_denominator_digest"],
        )
        for unit in units
    ]

    assert launches == 0
    assert {
        item.work_plan["phase_roster_denominator_digest"]
        for item in prepared
    } == {denominator["roster_denominator_digest"]}
    assert not (tmp_path / ".worker_transactions").exists()
    assert all(
        "attempt-" not in json.dumps(item.work_plan, sort_keys=True)
        for item in prepared
    )
    assert all(
        re.search(
            rb"attempt-[0-9a-f]{24}",
            b"".join(item.input_payloads.values()),
        )
        is None
        for item in prepared
    )


def test_retry_of_same_prepared_unit_keeps_plan_and_roster_but_gets_new_attempt(
    tmp_path: Path,
) -> None:
    unit = "worker.role-1"
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=(unit,),
    )
    prepared = _prepare(
        tmp_path,
        unit_id=unit,
        denominator_digest=denominator["roster_denominator_digest"],
    )
    roster = T.compile_phase_work_roster(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=(unit,),
        work_plan_digests={
            unit: prepared.work_plan["work_plan_digest"],
        },
    )

    with pytest.raises(runtime.HeadlessWorkerRuntimeError):
        runtime.execute_prepared_headless_worker(prepared, roster, None)
    (tmp_path / "allow-success").write_text("yes", encoding="utf-8")
    # The semantic preparation is reusable.  Every execution attaches a fresh
    # one-shot runtime parent without changing the WorkPlan denominator.
    result = runtime.execute_prepared_headless_worker(
        prepared,
        roster,
        None,
    )
    arms = [
        json.loads(path.read_text(encoding="utf-8", errors="strict"))
        for path in sorted(
            (tmp_path / ".worker_transactions" / "depth").glob("**/arm.json")
        )
    ]
    transaction_arms = [
        arm
        for arm in arms
        if arm.get("schema") == T.WORKER_ATTEMPT_ARM_SCHEMA_V3
    ]

    assert len(transaction_arms) == 2
    assert len({arm["attempt_id"] for arm in transaction_arms}) == 2
    assert {arm["work_plan_digest"] for arm in transaction_arms} == {
        prepared.work_plan["work_plan_digest"]
    }
    assert {arm["phase_roster_digest"] for arm in transaction_arms} == {
        roster["roster_digest"]
    }
    assert result.work_plan == prepared.work_plan


def test_raw_host_inputs_cannot_reach_production_but_claimed_parent_does(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "worker.role-1"
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=(unit,),
    )
    prepared = _prepare(
        tmp_path,
        unit_id=unit,
        denominator_digest=denominator["roster_denominator_digest"],
    )
    roster = T.compile_phase_work_roster(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=(unit,),
        work_plan_digests={
            unit: prepared.work_plan["work_plan_digest"],
        },
    )
    local = compile_test_claude_runtime_local_inputs(cwd=tmp_path)
    raw_host_inputs = M.compile_claude_runtime_host_inputs(
        auth_route="OAUTH_TOKEN",
        ambient_environment=local["ambient_environment"],
        source_config_dir=None,
        project_root=tmp_path,
        trusted_cwds=local["trusted_cwds"],
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="exact claimed provider runtime is required",
    ):
        M.compile_claude_runtime_materialization_request(
            launch_security_request=(
                prepared.claude_launch_security_request
            ),
            host_inputs=raw_host_inputs,
            base_argv=prepared.work_plan["provider"]["argv_template"],
            scratchpad=tmp_path,
            startup_permit_binding=prepared.work_plan[
                "completion_policy"
            ][T.AUXILIARY_STARTUP_POLICY_KEY],
            run_id=RUN_ID,
            outer_attempt_arm_sha256="1" * 64,
            work_plan_sha256="2" * 64,
            attempt_id="attempt-" + "a" * 24,
            process_scope_identity="scope-fixture",
        )

    real_compile = T.compile_claude_runtime_materialization_request
    observed: dict[str, object] = {}

    def require_claimed_parent(**kwargs):
        observed["provider_runtime"] = kwargs.get("provider_runtime")
        assert "host_inputs" not in kwargs
        assert (
            type(kwargs["provider_runtime"])
            is P.ClaimedClaudeProviderRuntime
        )
        return real_compile(**kwargs)

    monkeypatch.setattr(
        T,
        "compile_claude_runtime_materialization_request",
        require_claimed_parent,
    )
    (tmp_path / "allow-success").write_text("yes", encoding="utf-8")
    runtime.execute_prepared_headless_worker(prepared, roster, None)
    assert (
        type(observed["provider_runtime"])
        is P.ClaimedClaudeProviderRuntime
    )


@pytest.mark.parametrize("kind", ("digest", "foreign"))
def test_roster_mismatch_fails_before_attempt_or_provider_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    unit = "worker.role-1"
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=(unit,),
    )
    prepared = _prepare(
        tmp_path,
        unit_id=unit,
        denominator_digest=denominator["roster_denominator_digest"],
    )
    if kind == "digest":
        roster = T.compile_phase_work_roster(
            run_id=RUN_ID,
            phase="depth",
            generation=1,
            required_work_unit_ids=(unit,),
            work_plan_digests={unit: "9" * 64},
        )
    else:
        foreign = "worker.role-2"
        foreign_denominator = T.compile_phase_work_roster_denominator(
            run_id=RUN_ID,
            phase="depth",
            generation=1,
            required_work_unit_ids=(foreign,),
        )
        foreign_prepared = _prepare(
            tmp_path,
            unit_id=foreign,
            denominator_digest=foreign_denominator[
                "roster_denominator_digest"
            ],
        )
        roster = T.compile_phase_work_roster(
            run_id=RUN_ID,
            phase="depth",
            generation=1,
            required_work_unit_ids=(foreign,),
            work_plan_digests={
                foreign: foreign_prepared.work_plan["work_plan_digest"],
            },
        )
    launches = 0

    def forbidden_launch(*_args, **_kwargs):
        nonlocal launches
        launches += 1
        raise AssertionError("invalid roster reached provider")

    monkeypatch.setattr(runtime, "execute_worker_transaction", forbidden_launch)
    with pytest.raises(runtime.HeadlessWorkerRuntimeError, match="roster|Roster"):
        runtime.execute_prepared_headless_worker(prepared, roster, None)

    assert launches == 0
    assert not list(
        (tmp_path / ".worker_transactions").glob("**/arm.json")
    ) if (tmp_path / ".worker_transactions").exists() else True


def test_resume_selection_executes_only_sixth_prepared_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    units = tuple(f"worker.role-{index}" for index in range(1, 7))
    denominator = T.compile_phase_work_roster_denominator(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=units,
    )
    prepared = [
        _prepare(
            tmp_path,
            unit_id=unit,
            denominator_digest=denominator["roster_denominator_digest"],
        )
        for unit in units
    ]
    roster = T.compile_phase_work_roster(
        run_id=RUN_ID,
        phase="depth",
        generation=1,
        required_work_unit_ids=units,
        work_plan_digests={
            item.work_plan["work_unit_id"]: item.work_plan["work_plan_digest"]
            for item in prepared
        },
    )
    (tmp_path / "allow-success").write_text("yes", encoding="utf-8")
    real_execute = runtime.execute_worker_transaction
    launches = 0

    def counted_execute(*args, **kwargs):
        nonlocal launches
        launches += 1
        return real_execute(*args, **kwargs)

    monkeypatch.setattr(
        runtime,
        "execute_worker_transaction",
        counted_execute,
    )

    # Resume selection is an orchestration concern: five already-completed
    # units are not submitted; the immutable final roster still covers all six.
    runtime.execute_prepared_headless_worker(prepared[-1], roster, None)

    assert launches == 1
    assert (tmp_path / f"{units[-1]}.md").is_file()
    assert all(not (tmp_path / f"{unit}.md").exists() for unit in units[:-1])
