"""P0-AM Claude stream-json policy propagation and replay fixtures."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, Mapping

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
import worker_execution_receipts as W
import worker_transaction as T
from test_support_startup_permit import (
    FIXTURE_RUN_ID as RUN_ID,
    durable_startup_permit,
)


SESSION_ID = "11111111-2222-4333-8444-555555555555"
OTHER_SESSION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
STDOUT_LIMIT = 16 * 1024 * 1024


@pytest.fixture(autouse=True)
def _test_only_provider_authority_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt" and int(getattr(Path(sys.executable).stat(), "st_nlink", 1)) != 1:
        reviewed = Path(r"C:\p27rt\python.exe")
        if reviewed.is_file() and int(getattr(reviewed.stat(), "st_nlink", 1)) == 1:
            monkeypatch.setattr(sys, "executable", str(reviewed.resolve(strict=True)))
    install_test_only_launch_authority_adapter(monkeypatch.setattr)


def _authority(
    root: Path,
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "depth",
        "worker.stream-policy",
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.stream-policy",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="depth_stream_policy_findings.md",
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


def _policy(root: Path) -> dict[str, Any]:
    return _authority_bundle(root)["stream_configuration"]


def _stream(root: Path) -> bytes:
    return _authority_bundle(root)["stream_bytes"]


def _authority_bundle(
    root: Path,
    *,
    settings_mode: str = "SAFE_MODE",
) -> dict[str, Any]:
    return compile_test_claude_launch_authority(
        cwd=root,
        launch_model="fixture-model",
        observed_model="fixture-observed-model",
        accepted_models=(
            "fixture-model",
            "fixture-observed-model",
        ),
        stdout_limit_bytes=STDOUT_LIMIT,
        session_label="stream-policy",
        session_id=SESSION_ID,
        settings_mode=settings_mode,
    )


def _stream_writer(
    root: Path,
    authority: Mapping[str, Any] | None = None,
) -> Callable[[Path], tuple[str, ...]]:
    bundle = authority or _authority_bundle(root)
    raw = bundle["stream_bytes"]
    provider_script = root / "fixture_stream_provider.py"
    provider_script.write_text(
        "from pathlib import Path\n"
        "import re\n"
        "import sys\n"
        "prompt=sys.stdin.buffer.read().decode('utf-8')\n"
        "targets=re.findall(r'-> `([^`]+)`', prompt)\n"
        "if len(targets) != 1:\n"
        "    raise SystemExit(8)\n"
        "output=Path(targets[0])\n"
        "output.parent.mkdir(parents=True, exist_ok=True)\n"
        "output.write_text("
        "'## Findings\\n\\nProvider stream policy survived.\\n', "
        "encoding='utf-8')\n"
        f"{claude_test_postprocess_state_update_source()}"
        f"sys.stdout.buffer.write({raw!r})\n",
        encoding="utf-8",
    )

    def build(output_directory: Path) -> tuple[str, ...]:
        del output_directory
        suffix = tuple(bundle["command_suffix"])
        return (
            sys.executable,
            str(provider_script),
            suffix[0],
            *suffix[1:],
        )

    return build


def _plain_writer() -> Callable[[Path], tuple[str, ...]]:
    def build(output_directory: Path) -> tuple[str, ...]:
        return (
            sys.executable,
            "-I",
            "-c",
            (
                "from pathlib import Path; import sys; "
                "sys.stdin.buffer.read(); root=Path(sys.argv[1]); "
                "(root/'depth_stream_policy_findings.md').write_text("
                "'## Findings\\n\\nGeneric execution.\\n',encoding='utf-8')"
            ),
            str(output_directory),
        )

    return build


def _prepare(
    root: Path,
    *,
    policy: Mapping[str, Any] | None,
    command_builder: Callable[[Path], tuple[str, ...]] | None = None,
    authority_override: Mapping[str, Any] | None = None,
) -> runtime.PreparedHeadlessWorker:
    contract, launch = _authority(root)
    authority = (
        (
            dict(authority_override)
            if authority_override is not None
            else _authority_bundle(root)
        )
        if policy is not None
        else None
    )
    builder = (
        command_builder
        or (
            _stream_writer(root, authority)
            if authority is not None
            else _plain_writer()
        )
    )
    startup = durable_startup_permit(root)
    provider_preparation = (
        None
        if authority is None
        else compile_test_claude_provider_preparation(
            authority=authority,
            base_argv=builder(Path("unused")),
            cwd=root,
            run_id=RUN_ID,
            phase=contract.phase,
            startup_authority_binding=startup,
            source_snapshot_sha256="a" * 64,
        )
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
        environment_allowlist=(
            authority["environment_allowlist"]
            if authority is not None
            else ()
        ),
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=startup,
        stdout_limit_bytes=STDOUT_LIMIT,
        provider_stdout_evidence_configuration=policy,
        claude_launch_security=(
            authority["policy"]
            if authority is not None
            else None
        ),
        claude_launch_security_request=(
            authority["request"]
            if authority is not None
            else None
        ),
        claude_provider_preparation=provider_preparation,
        claude_runtime_local_inputs=(
            authority["runtime_local_inputs"]
            if authority is not None
            else None
        ),
        claude_bound_settings_bytes=(
            authority["bound_settings_bytes"]
            if authority is not None
            else None
        ),
        claude_selected_mcp_config_bytes=(
            authority["selected_mcp_config_bytes"]
            if authority is not None
            else None
        ),
    )


def _roster(
    prepared: runtime.PreparedHeadlessWorker,
) -> dict[str, Any]:
    plan = prepared.work_plan
    return T.compile_phase_work_roster(
        run_id=plan["run_id"],
        phase=plan["phase"],
        generation=plan["generation"],
        required_work_unit_ids=(plan["work_unit_id"],),
        work_plan_digests={
            plan["work_unit_id"]: plan["work_plan_digest"],
        },
    )


def test_opt_in_policy_survives_prepare_execute_and_provider_replay(
    tmp_path: Path,
) -> None:
    expected_policy = _policy(tmp_path)
    prepared = _prepare(tmp_path, policy=expected_policy)

    plan = prepared.work_plan
    assert plan["completion_policy"][
        "provider_stdout_evidence_configuration"
    ] == expected_policy

    result = runtime.execute_prepared_headless_worker(
        prepared,
        _roster(prepared),
    )
    receipt = W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=result.execution.provider_execution.receipt_path,
        parser_digest=prepared.parser_digest,
        expected_completion_sha256=(
            result.execution.provider_execution.completion_sha256
        ),
    )
    arm = json.loads(
        result.execution.provider_execution.arm_path.read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    binding = arm["process_intent"]["provider_stdout_evidence"]

    assert binding["expected_session_id"] == SESSION_ID
    assert binding["expected_init_contract"] == expected_policy[
        "expected_init_contract"
    ]
    assert binding["max_stream_bytes"] == STDOUT_LIMIT
    assert receipt["provider_stdout_evidence"]["init_applicability"] == (
        "MATCHED"
    )
    assert receipt["provider_stdout_evidence"]["raw_sha256"] == (
        hashlib.sha256(_stream(tmp_path)).hexdigest()
    )


def test_bound_settings_sources_reach_exact_runtime_and_wer(
    tmp_path: Path,
) -> None:
    authority = _authority_bundle(
        tmp_path,
        settings_mode="BOUND_SETTINGS",
    )
    prepared = _prepare(
        tmp_path,
        policy=authority["stream_configuration"],
        command_builder=_stream_writer(tmp_path, authority),
        authority_override=authority,
    )
    result = runtime.execute_prepared_headless_worker(
        prepared,
        _roster(prepared),
    )
    receipt = W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=result.execution.provider_execution.receipt_path,
        parser_digest=prepared.parser_digest,
        expected_completion_sha256=(
            result.execution.provider_execution.completion_sha256
        ),
    )
    arm = json.loads(
        result.execution.provider_execution.arm_path.read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    headless = arm["process_intent"]["provider_stdout_evidence"][
        "command_contract"
    ]["headless_profile"]
    assert headless["safe_mode"] is False
    assert headless["settings"]["sha256"] == hashlib.sha256(
        authority["bound_settings_bytes"]
    ).hexdigest()
    assert headless["mcp_config"]["sha256"] == hashlib.sha256(
        authority["selected_mcp_config_bytes"]
    ).hexdigest()
    assert Path(headless["settings"]["path"]).is_absolute()
    assert Path(headless["mcp_config"]["path"]).is_absolute()
    assert receipt["provider_stdout_evidence"]["init_applicability"] == (
        "MATCHED"
    )


@pytest.mark.parametrize("mutation", ("drop", "substitute"))
def test_plan_required_policy_cannot_be_dropped_or_substituted_by_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    prepared = _prepare(tmp_path, policy=_policy(tmp_path))
    real_execute = runtime.execute_worker_transaction

    def sabotaged_execute(
        plan: Mapping[str, Any],
        adapter: T.NativeCommandAdapter | T.HeadlessModelAdapter,
        cancel_token: Any,
    ) -> T.ExecutionRef:
        assert isinstance(adapter, T.HeadlessModelAdapter)
        replacement: Mapping[str, Any] | None
        if mutation == "drop":
            replacement = None
        else:
            replacement = dict(
                adapter.provider_stdout_evidence_configuration or {}
            )
            replacement["expected_session_id"] = OTHER_SESSION_ID
        return real_execute(
            plan,
            replace(
                adapter,
                provider_stdout_evidence_configuration=replacement,
            ),
            cancel_token,
        )

    monkeypatch.setattr(
        runtime,
        "execute_worker_transaction",
        sabotaged_execute,
    )
    with pytest.raises(
        runtime.HeadlessWorkerRuntimeError,
        match="cannot be dropped or substituted",
    ):
        runtime.execute_prepared_headless_worker(
            prepared,
            _roster(prepared),
        )
    assert not list(
        tmp_path.glob(".worker_transactions/depth/**/arm.json")
    )


@pytest.mark.parametrize("mutation", ("drop", "substitute"))
def test_final_roster_rejects_policy_mutation_after_prepare(
    tmp_path: Path,
    mutation: str,
) -> None:
    prepared = _prepare(tmp_path, policy=_policy(tmp_path))
    roster = _roster(prepared)
    changed = prepared.work_plan
    if mutation == "drop":
        changed["completion_policy"].pop(
            "provider_stdout_evidence_configuration"
        )
    else:
        changed["completion_policy"][
            "provider_stdout_evidence_configuration"
        ]["expected_session_id"] = OTHER_SESSION_ID
    unsigned = {
        key: value
        for key, value in changed.items()
        if key != "work_plan_digest"
    }
    changed["work_plan_digest"] = T._digest(unsigned)

    with pytest.raises(
        T.WorkerTransactionError,
        match="WorkPlan digest does not match the final phase roster",
    ):
        T.validate_work_plan_phase_roster(changed, roster)


def test_generic_claude_path_is_rejected_before_command_builder(
    tmp_path: Path,
) -> None:
    calls: list[Path] = []

    def builder(output_directory: Path) -> tuple[str, ...]:
        calls.append(output_directory)
        return _plain_writer()(output_directory)

    with pytest.raises(
        runtime.HeadlessWorkerRuntimeError,
        match="launch-security|stream",
    ):
        _prepare(
            tmp_path,
            policy=None,
            command_builder=builder,
        )
    assert calls == []
    assert not (tmp_path / ".worker_transactions").exists()
