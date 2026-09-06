"""P0-AM headless Claude/Codex transactional runtime fixtures."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Callable

import pytest

import artifact_ledger as ledger
import claude_phase_tool_policy as claude_policy
from test_claude_launch_authority_fixtures import (
    claude_test_postprocess_state_update_source,
    compile_test_claude_launch_authority,
    compile_test_claude_provider_preparation,
    install_test_only_launch_authority_adapter,
)
import headless_worker_runtime as runtime
import plamen_driver as driver
import semantic_invariant_authority as semantic_authority
import test_p1_dm_live_driver_cutover as p1d_fixture
import worker_transaction as transaction
import worker_execution_receipts as W
from test_support_startup_permit import (
    FIXTURE_RUN_ID as RUN_ID,
    durable_startup_permit,
    rotate_startup_permit,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)

STDOUT_LIMIT = 16 * 1024 * 1024
WINDOWS_AUDIT_SCRATCHPAD = (
    r"D:\audit-root\example-protocol\contracts\.scratchpad"
)


def test_codex_phaseio_append_composes_fragment_and_preserves_preimage(
    tmp_path: Path,
) -> None:
    p1d_fixture._checkpoint(tmp_path)
    p1d_fixture._graph(tmp_path)
    config = p1d_fixture._config(tmp_path, backend="codex")
    driver._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    p1d_fixture._bind_pass1(tmp_path, config)
    worklist = json.loads(
        (tmp_path / semantic_authority.WORKLIST_FILE).read_text(
            encoding="utf-8"
        )
    )
    semantic = tmp_path / "semantic_invariants.md"
    semantic.write_text(
        p1d_fixture._semantic_markdown(
            p1d_fixture._application_payload(worklist)
        ),
        encoding="utf-8",
    )
    assert driver._finalize_semantic_invariant_post_boundary(
        tmp_path, config
    ) == []
    assert driver._prepare_semantic_invariant_pass2_boundary(
        tmp_path, config
    ) == []
    phase = p1d_fixture._phase("invariants_p2")
    assert driver._bind_typed_model_phase_inputs(phase, tmp_path, config) == []
    contract, launch = driver._typed_model_phase_contract_and_launch(
        phase, tmp_path, config
    )
    assert contract is not None and launch is not None
    preimage = semantic.read_bytes()
    append = b"\n## Pass 2: Recursive Trace Results\n\nNo extra gap.\n"

    def builder(output_directory: Path) -> tuple[str, ...]:
        script = (
            "from pathlib import Path\n"
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            "out=Path(sys.argv[1])\n"
            "out.mkdir(parents=True, exist_ok=True)\n"
            "(out/'semantic_invariants.md').write_bytes(" + repr(append) + ")\n"
        )
        return (sys.executable, "-I", "-c", script, str(output_directory))

    result = runtime.execute_headless_worker(
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id=config["_run_id"],
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Append the bounded Pass-2 section.",
        command_builder=builder,
        cwd=tmp_path,
        environment={},
        environment_allowlist=(),
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=durable_startup_permit(
            tmp_path, run_id=config["_run_id"]
        ),
        attempt_id="attempt-" + "e" * 24,
        codex_auth_bytes=b'{"auth_mode":"fixture"}',
    )

    assert semantic.read_bytes() == preimage + append
    assert result.incorporation.projected_paths == (semantic,)
    assert driver._finalize_semantic_invariant_pass2_boundary(
        tmp_path, config
    ) == []
    final = json.loads(
        (tmp_path / semantic_authority.FINAL_BYTE_AUTHORITY_FILE).read_text(
            encoding="utf-8"
        )
    )
    assert final["status"] == "VALID_FINAL_BYTES"
    assert final["append_byte_count"] == len(append)


@pytest.fixture(autouse=True)
def _test_only_provider_authority_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt" and int(getattr(Path(sys.executable).stat(), "st_nlink", 1)) != 1:
        reviewed = Path(r"C:\p27rt\python.exe")
        if reviewed.is_file() and int(getattr(reviewed.stat(), "st_nlink", 1)) == 1:
            monkeypatch.setattr(sys, "executable", str(reviewed.resolve(strict=True)))
    install_test_only_launch_authority_adapter(monkeypatch.setattr)


def _contract(
    backend: str,
    *,
    work_unit_id: str = "worker.role-1",
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        backend,
        "depth",
        work_unit_id,
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend=backend,
        phase="depth",
        work_unit_id=work_unit_id,
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
        backend=backend,
        model="fixture-model",
        timeout_s=30,
        exec_mode="exec" if backend == "codex" else "headless",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _arm(
    root: Path,
    *,
    backend: str,
    work_unit_id: str = "worker.role-1",
) -> tuple[PhaseIOContract, LaunchSpec]:
    contract, launch = _contract(backend, work_unit_id=work_unit_id)
    ledger.record_work_unit_inputs(
        root,
        root,
        contract,
        launch,
        run_id=RUN_ID,
    )
    return contract, launch


def _claude_authority(
    root: Path,
    *,
    label: str,
) -> dict[str, object]:
    return compile_test_claude_launch_authority(
        cwd=root,
        launch_model="fixture-model",
        stdout_limit_bytes=STDOUT_LIMIT,
        session_label=label,
    )


def _claude_kwargs(
    authority: dict[str, object] | None,
    *,
    root: Path | None = None,
    builder=None,
    startup_authority_binding=None,
    phase: str = "depth",
) -> dict[str, object]:
    if authority is None:
        return {}
    if root is None or builder is None or startup_authority_binding is None:
        raise AssertionError("Claude provider fixture parent inputs are absent")
    provider_preparation = compile_test_claude_provider_preparation(
        authority=authority,
        base_argv=builder(Path("unused")),
        cwd=root,
        run_id=RUN_ID,
        phase=phase,
        startup_authority_binding=startup_authority_binding,
        source_snapshot_sha256="a" * 64,
    )
    return {
        "stdout_limit_bytes": STDOUT_LIMIT,
        "provider_stdout_evidence_configuration": authority[
            "stream_configuration"
        ],
        "claude_launch_security": authority["policy"],
        "claude_launch_security_request": authority["request"],
        "claude_provider_preparation": provider_preparation,
        "claude_runtime_local_inputs": authority["runtime_local_inputs"],
    }


def _writer(
    extra: bool = False,
    *,
    authority: dict[str, object] | None = None,
    root: Path | None = None,
    content: str = "## Findings\n\nNo finding was proven unsafe.\n",
):
    provider_script: Path | None = None
    if authority is not None:
        if root is None:
            raise AssertionError("Claude fixture writer requires its root")
        session_id = authority["stream_configuration"][
            "expected_session_id"
        ]
        provider_script = root / f"fixture-provider-{session_id}.py"
        script = (
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
            f"{content!r}, "
            "encoding='utf-8')\n"
        )
        if extra:
            script += (
                "(output.parent/'foreign.md').write_text("
                "'foreign', encoding='utf-8')\n"
            )
        script += (
            claude_test_postprocess_state_update_source()
            +
            "sys.stdout.buffer.write("
            f"{authority['stream_bytes']!r})\n"
        )
        provider_script.write_text(script, encoding="utf-8")

    def build(output_directory: Path) -> tuple[str, ...]:
        if provider_script is not None:
            del output_directory
            suffix = tuple(authority["command_suffix"])
            return (
                sys.executable,
                str(provider_script),
                suffix[0],
                *suffix[1:],
            )
        script = (
            "from pathlib import Path; import sys; "
            "sys.stdin.buffer.read(); "
            "root=Path(sys.argv[1]); "
            "(root/'depth_role_1_findings.md').write_text("
            f"{content!r}, encoding='utf-8'); "
        )
        if extra:
            script += "(root/'foreign.md').write_text('foreign', encoding='utf-8'); "
        return (
            sys.executable,
            "-I",
            "-c",
            script,
            str(output_directory),
        )

    return build


def _failing_claude_writer(
    root: Path,
    authority: dict[str, object],
    *,
    advance_runtime_state: bool = True,
) -> Callable[[Path], tuple[str, ...]]:
    provider_script = root / "fixture-provider-failure.py"
    state_update = (
        claude_test_postprocess_state_update_source()
        if advance_runtime_state
        else ""
    )
    provider_script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        f"{state_update}"
        "raise SystemExit(7)\n",
        encoding="utf-8",
    )

    def build(_output_directory: Path) -> tuple[str, ...]:
        suffix = tuple(authority["command_suffix"])
        return (
            sys.executable,
            str(provider_script),
            suffix[0],
            *suffix[1:],
        )

    return build


def _fixture_staged_semantic_validator(outputs, context):
    required = str(context.get("required") or "")
    if len(outputs) != 1:
        return ["fixture staged output denominator mismatch"]
    raw = next(iter(outputs.values()))
    return [] if required.encode("utf-8") in raw else [
        "fixture required semantic token is absent"
    ]


def _fixture_claude_exact_staged_validator(outputs, context):
    expected_context_fields = {
        "schema",
        "policy_path",
        "manifest_digest",
        "output_directory",
        "expected_outputs",
    }
    if (
        set(context) != expected_context_fields
        or context.get("schema")
        != "plamen.claude_exact_staged_gate.v1"
        or context.get("expected_outputs")
        != ["depth_role_1_findings.md"]
        or sorted(outputs) != ["scratchpad:depth_role_1_findings.md"]
    ):
        return ["fixture Claude exact staged context is malformed"]
    return []


def _live_shaped_windows_staged_context(scope):
    scratchpad = WINDOWS_AUDIT_SCRATCHPAD
    output_relative = str(scope["output_relative_path"]).replace("/", "\\")
    return {
        "schema": "plamen.claude_exact_staged_gate.v1",
        "policy_path": scratchpad + r"\_ctp\07e2738a8c7b067c\p.json",
        "manifest_digest": "7" * 64,
        "output_directory": scratchpad + "\\" + output_relative,
        "expected_outputs": ["depth_role_1_findings.md"],
    }


def test_codex_auth_is_bound_to_an_isolated_runtime_home(
    tmp_path: Path,
) -> None:
    contract, launch = _arm(tmp_path, backend="codex")
    auth = b'{"auth_mode":"fixture"}'
    prepared = runtime.prepare_headless_worker(
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze the assigned role and write its artifact.",
        command_builder=_writer(),
        cwd=tmp_path,
        environment={},
        environment_allowlist=(),
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=durable_startup_permit(tmp_path),
        codex_auth_bytes=auth,
    )

    plan = prepared.work_plan
    assert prepared.environment["CODEX_HOME"] == (
        transaction.CODEX_HOME_PLACEHOLDER
    )
    assert "CODEX_HOME" in prepared.environment_allowlist
    assert plan["completion_policy"][
        transaction.CODEX_RUNTIME_AUTH_POLICY_KEY
    ] == {
        "mode": "AUTH_JSON_COPY",
        "sha256": hashlib.sha256(auth).hexdigest(),
        "size": len(auth),
    }
    assert "auth.json" not in json.dumps(plan)


def test_claude_workplan_rejects_codex_auth_before_provider_attachment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract, launch = _arm(tmp_path, backend="claude")
    monkeypatch.setattr(
        runtime,
        "_normalize_claude_launch_contract",
        lambda **_kwargs: ({}, {}, {}),
    )

    with pytest.raises(
        runtime.HeadlessWorkerRuntimeError,
        match="Claude WorkPlans cannot carry Codex authentication material",
    ):
        runtime.prepare_headless_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned role and write its artifact.",
            command_builder=_writer(),
            cwd=tmp_path,
            environment={},
            environment_allowlist=(),
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=durable_startup_permit(tmp_path),
            codex_auth_bytes=b"{}",
        )


def test_codex_runtime_home_with_long_cache_paths_is_revoked(
    tmp_path: Path,
) -> None:
    contract, launch = _arm(tmp_path, backend="codex")
    startup_permit = durable_startup_permit(tmp_path)

    def builder(output_directory: Path) -> tuple[str, ...]:
        script = """
from pathlib import Path
import os
import sys
sys.stdin.buffer.read()
output = Path(sys.argv[1])
(output / 'depth_role_1_findings.md').write_text(
    '## Findings\\n\\nNo finding was proven unsafe.\\n', encoding='utf-8'
)
deep = Path(os.environ['CODEX_HOME'])
while len(str(deep / 'cache.bin')) <= 300:
    deep /= 'codex-plugin-cache-segment-0123456789'
native = chr(92) * 2 + '?' + chr(92) + str(deep)
os.makedirs(native)
with open(os.path.join(native, 'cache.bin'), 'wb') as stream:
    stream.write(b'fixture')
"""
        return (sys.executable, "-I", "-c", script, str(output_directory))

    result = runtime.execute_headless_worker(
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze the assigned role and write its artifact.",
        command_builder=builder,
        cwd=tmp_path,
        environment={},
        environment_allowlist=(),
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=startup_permit,
        attempt_id="attempt-" + "c" * 24,
        codex_auth_bytes=b'{"auth_mode":"fixture"}',
    )

    completion = json.loads(
        result.execution.provider_execution.receipt_path.read_text(
            encoding="utf-8"
        )
    )
    revocation = completion["auxiliary_root_revocations"][0]["revocation"]
    assert revocation["root_absent_after"] is True
    assert revocation["entries_removed"] > 1


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_backend_neutral_headless_worker_stages_then_phaseio_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    contract, launch = _arm(tmp_path, backend=backend)
    real_incorporate = runtime.incorporate_worker_execution
    observed = {"canonical_absent_before_incorporation": False}

    def guarded_incorporation(*args, **kwargs):
        observed["canonical_absent_before_incorporation"] = not (
            tmp_path / "depth_role_1_findings.md"
        ).exists()
        return real_incorporate(*args, **kwargs)

    monkeypatch.setattr(
        runtime,
        "incorporate_worker_execution",
        guarded_incorporation,
    )
    startup_permit = durable_startup_permit(tmp_path)
    claude_authority = (
        _claude_authority(tmp_path, label="backend-neutral")
        if backend == "claude"
        else None
    )
    builder = _writer(
        authority=claude_authority,
        root=tmp_path,
    )
    result = runtime.execute_headless_worker(
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze the assigned role and write its artifact.",
        command_builder=builder,
        cwd=tmp_path,
        environment={},
        environment_allowlist=(
            claude_authority["environment_allowlist"]
            if claude_authority is not None
            else ()
        ),
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=startup_permit,
        attempt_id="attempt-" + ("a" if backend == "claude" else "b") * 24,
        codex_auth_bytes=(b'{"auth_mode":"fixture"}' if backend == "codex" else None),
        **_claude_kwargs(
            claude_authority,
            root=tmp_path,
            builder=builder,
            startup_authority_binding=startup_permit,
        ),
    )

    canonical = tmp_path / "depth_role_1_findings.md"
    assert observed["canonical_absent_before_incorporation"] is True
    assert canonical.read_text(encoding="utf-8").startswith("## Findings")
    assert result.stdout == (
        claude_authority["stream_bytes"]
        if claude_authority is not None
        else b""
    )
    assert result.stderr == b""
    assert result.incorporation.projected_paths == (canonical,)
    assert result.work_plan["completion_policy"][
        "auxiliary_writable_root_startup_permit"
    ] == startup_permit
    if backend == "codex":
        completion = json.loads(
            result.execution.provider_execution.receipt_path.read_text(
                encoding="utf-8"
            )
        )
        revocations = completion["auxiliary_root_revocations"]
        assert len(revocations) == 1
        assert revocations[0]["revocation"]["root_absent_after"] is True
    else:
        assert transaction.CODEX_RUNTIME_AUTH_POLICY_KEY not in (
            result.work_plan["completion_policy"]
        )
    attempt_arm = json.loads(
        (result.execution.attempt_directory / "arm.json").read_text(
            encoding="utf-8",
        )
    )
    assert attempt_arm["auxiliary_writable_root_startup_permit"] == (
        startup_permit
    )
    provider_arm = json.loads(
        result.execution.provider_execution.arm_path.read_text(
            encoding="utf-8",
        )
    )
    assert provider_arm["process_intent"]["startup_authority_evidence"][
        "binding"
    ] == startup_permit
    rotate_startup_permit(tmp_path)
    W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=result.execution.provider_execution.receipt_path,
        parser_digest=runtime.strict_nonempty_artifact_digest,
        expected_completion_sha256=(
            result.execution.provider_execution.completion_sha256
        ),
    )
    assert (
        result.work_plan["provider"]["backend"] == backend
        and result.work_plan["assignment"]["members"][0][
            "canonical_identity"
        ]
        == "scratchpad:depth_role_1_findings.md"
    )


def test_headless_worker_failure_leaves_canonical_absent_and_durable_debt(
    tmp_path: Path,
) -> None:
    contract, launch = _arm(tmp_path, backend="claude")
    authority = _claude_authority(
        tmp_path,
        label="nonzero-failure",
    )
    builder = _failing_claude_writer(tmp_path, authority)
    startup = durable_startup_permit(tmp_path)

    with pytest.raises(runtime.HeadlessWorkerRuntimeError) as raised:
        runtime.execute_headless_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned role and write its artifact.",
            command_builder=builder,
            cwd=tmp_path,
            environment={},
            environment_allowlist=authority["environment_allowlist"],
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=startup,
            attempt_id="attempt-" + "c" * 24,
            **_claude_kwargs(
                authority,
                root=tmp_path,
                builder=builder,
                startup_authority_binding=startup,
            ),
        )

    assert raised.value.returncode == 7
    assert raised.value.reason_code == "NONZERO_EXIT"
    assert not (tmp_path / "depth_role_1_findings.md").exists()
    assert list(
        (tmp_path / ".worker_transactions" / "depth").glob(
            "**/debt.json"
        )
    )
    unit = ledger.read_artifact_ledger(tmp_path)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"


def test_headless_worker_nonzero_without_runtime_state_transition_is_lifecycle_debt(
    tmp_path: Path,
) -> None:
    contract, launch = _arm(tmp_path, backend="claude")
    authority = _claude_authority(
        tmp_path,
        label="nonzero-no-state-transition",
    )
    builder = _failing_claude_writer(
        tmp_path,
        authority,
        advance_runtime_state=False,
    )
    startup = durable_startup_permit(tmp_path)

    with pytest.raises(runtime.HeadlessWorkerRuntimeError) as raised:
        runtime.execute_headless_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned role and write its artifact.",
            command_builder=builder,
            cwd=tmp_path,
            environment={},
            environment_allowlist=authority["environment_allowlist"],
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=startup,
            attempt_id="attempt-" + "d" * 24,
            **_claude_kwargs(
                authority,
                root=tmp_path,
                builder=builder,
                startup_authority_binding=startup,
            ),
        )

    assert raised.value.returncode == 7
    assert raised.value.reason_code == "NONZERO_EXIT"
    assert not (tmp_path / "depth_role_1_findings.md").exists()
    attempt_debt_paths = list(
        (tmp_path / ".worker_transactions" / "depth").glob(
            "**/debt.json"
        )
    )
    assert len(attempt_debt_paths) == 1
    attempt_debt = json.loads(
        attempt_debt_paths[0].read_text(encoding="utf-8")
    )
    assert attempt_debt["reason_code"] == "PROVIDER_EXECUTION_DEBT"
    provider_debt = json.loads(
        (
            tmp_path
            / attempt_debt["provider_debt_relative_path"]
        ).read_text(encoding="utf-8")
    )
    assert provider_debt["reason_code"] == "NONZERO_EXIT"
    cleanup = provider_debt["process_observation"][
        "claude_runtime_failure_cleanup"
    ]
    assert cleanup == {
        "status": "CLEANED",
        "primary_reason_code": "NONZERO_EXIT",
        "secondary_reason_code": None,
    }
    lifecycle = provider_debt["process_observation"][
        "claude_runtime_lifecycle"
    ]
    assert lifecycle["closure_mode"] == (
        "NORMAL_SCOPE_FAILURE_CLEANUP"
    )
    assert lifecycle["completion_authority"] is False
    unit = ledger.read_artifact_ledger(tmp_path)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["artifacts"] == {}


def test_headless_worker_rejects_foreign_staged_artifact_without_publication(
    tmp_path: Path,
) -> None:
    contract, launch = _arm(tmp_path, backend="codex")
    with pytest.raises(
        runtime.HeadlessWorkerRuntimeError,
        match="denominator mismatch",
    ):
        runtime.execute_headless_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned role and write its artifact.",
            command_builder=_writer(extra=True),
            cwd=tmp_path,
            environment={},
            environment_allowlist=(),
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=durable_startup_permit(tmp_path),
            attempt_id="attempt-" + "d" * 24,
        )
    assert not (tmp_path / "depth_role_1_findings.md").exists()


def test_staged_semantic_gate_rejects_before_canonical_publication(
    tmp_path: Path,
) -> None:
    contract, launch = _arm(tmp_path, backend="claude")
    authority = _claude_authority(
        tmp_path,
        label="semantic-gate",
    )
    builder = _writer(
        authority=authority,
        root=tmp_path,
    )
    startup = durable_startup_permit(tmp_path)
    with pytest.raises(
        runtime.HeadlessWorkerRuntimeError,
        match="staged semantic validation failed",
    ):
        runtime.execute_headless_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned role and write its artifact.",
            command_builder=builder,
            cwd=tmp_path,
            environment={},
            environment_allowlist=authority["environment_allowlist"],
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=startup,
            attempt_id="attempt-" + "f" * 24,
            staged_output_validator=(
                _fixture_staged_semantic_validator
            ),
            staged_output_context={"required": "SEMANTICALLY_ACCEPTED"},
            **_claude_kwargs(
                authority,
                root=tmp_path,
                builder=builder,
                startup_authority_binding=startup,
            ),
        )
    assert not (tmp_path / "depth_role_1_findings.md").exists()
    unit = ledger.read_artifact_ledger(tmp_path)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["artifacts"] == {}


def test_recon_selection_gate_rejects_invented_id_before_transaction_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_executable = Path(sys.executable).resolve(strict=True)
    fixture_executable = tmp_path / "private-python" / source_executable.name
    fixture_executable.parent.mkdir()
    shutil.copyfile(source_executable, fixture_executable)
    if sys.platform == "win32":
        for name in (
            "python3.dll",
            "python312.dll",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
        ):
            dependency = source_executable.parent / name
            if dependency.is_file():
                shutil.copyfile(
                    dependency,
                    fixture_executable.parent / name,
                )
    fixture_executable.chmod(0o700)
    fixture_executable = fixture_executable.resolve(strict=True)
    assert fixture_executable.stat().st_nlink == 1
    # The offline authority fixture observes ``sys.executable`` and registers
    # its exact provider command template. Point both authorities at this
    # private single-link copy so the production hardlink rejection remains
    # enabled even when the test runner's interpreter has external aliases.
    monkeypatch.setattr(sys, "executable", str(fixture_executable))

    contract, launch = _arm(tmp_path, backend="claude")
    authority = _claude_authority(
        tmp_path,
        label="recon-selection-semantic-gate",
    )
    invented = (
        "# Recon selection\n\n"
        '<!-- PLAMEN_SIGNALS: {"required_skills":["UPGRADEABLE_PROXY"]} -->\n'
    )
    builder = _writer(
        authority=authority,
        root=tmp_path,
        content=invented,
    )
    startup = durable_startup_permit(tmp_path)
    context = claude_policy.recon_selection_signal_staged_context(
        output="depth_role_1_findings.md",
        allowed_rows=("CENTRALIZATION_RISK",),
    )
    with pytest.raises(
        runtime.HeadlessWorkerRuntimeError,
        match="UNKNOWN_SKILL_ID",
    ) as raised:
        runtime.execute_headless_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned recon selection role.",
            command_builder=builder,
            cwd=tmp_path,
            environment={},
            environment_allowlist=authority["environment_allowlist"],
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=startup,
            attempt_id="attempt-" + "9" * 24,
            staged_output_validator=(
                claude_policy.staged_recon_selection_signal_validator
            ),
            staged_output_context=context,
            **_claude_kwargs(
                authority,
                root=tmp_path,
                builder=builder,
                startup_authority_binding=startup,
            ),
        )
    assert raised.value.reason_code == "STAGED_SEMANTIC_REJECTED"
    assert not (tmp_path / "depth_role_1_findings.md").exists()
    unit = ledger.read_artifact_ledger(tmp_path)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["artifacts"] == {}


def test_retry_attempt_paths_share_one_staged_gate_and_both_incorporate(
    tmp_path: Path,
) -> None:
    gates = []
    for suffix in ("a", "b"):
        root = tmp_path / suffix
        root.mkdir()
        contract, launch = _arm(root, backend="codex")
        attempt_id = "attempt-" + suffix * 24
        scope = runtime.compile_attempt_write_scope(
            run_id=RUN_ID,
            phase=contract.phase,
            work_unit_id=contract.work_unit_id,
            attempt_id=attempt_id,
        )
        result = runtime.execute_headless_worker(
            scratchpad=root,
            project_root=root,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned role and write its artifact.",
            command_builder=_writer(),
            cwd=root,
            environment={},
            environment_allowlist=(),
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=durable_startup_permit(root),
            attempt_id=attempt_id,
            staged_output_validator=_fixture_staged_semantic_validator,
            staged_output_context={
                "required": "No finding",
                "output_directory": (
                    "C:/stable-scratchpad/"
                    + str(scope["output_relative_path"])
                ),
            },
        )
        gates.append(
            result.work_plan["completion_policy"][
                "staged_semantic_gate"
            ]
        )
        assert (root / "depth_role_1_findings.md").is_file()

    assert gates[0] == gates[1]
    assert gates[0]["context"]["output_directory"] == (
        "C:/stable-scratchpad/"
        + runtime.ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows long-path contract")
def test_transaction_launch_inputs_support_extended_length_scratchpad_paths(
    tmp_path: Path,
) -> None:
    # Keep the scratchpad itself below MAX_PATH so this test isolates the
    # transaction-owned descendants that cross the legacy 260-character edge.
    padding = max(
        32,
        159 - len(str(tmp_path)) - len("scratchpad-") - 1,
    )
    root = tmp_path / ("scratchpad-" + "x" * padding)
    root.mkdir()
    contract, launch = _arm(
        root,
        backend="codex",
        work_unit_id="direct_retry.attempt-0002",
    )
    attempt_id = "attempt-" + "7" * 24
    scope = runtime.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase=contract.phase,
        work_unit_id=contract.work_unit_id,
        attempt_id=attempt_id,
    )
    expected_input = (
        root
        / ".worker_transactions"
        / "inputs"
        / contract.phase
        / contract.work_unit_id
        / str(scope["attempt_id"])
        / "prompt.md"
    )
    assert len(str(expected_input)) > 260

    result = runtime.execute_headless_worker(
        scratchpad=root,
        project_root=root,
        run_id=RUN_ID,
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze the assigned role and write its artifact.",
        command_builder=_writer(),
        cwd=root,
        environment={},
        environment_allowlist=(),
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=durable_startup_permit(root),
        attempt_id=attempt_id,
    )

    assert len(result.execution.provider_execution.completion_sha256) == 64
    assert (root / "depth_role_1_findings.md").is_file()


def test_claude_windows_backslash_staged_gate_is_retry_stable_and_tamper_safe(
    tmp_path: Path,
) -> None:
    gates = []
    scopes = []
    for suffix in ("e", "f"):
        root = tmp_path / suffix
        root.mkdir()
        contract, launch = _arm(root, backend="claude")
        attempt_id = "attempt-" + suffix * 24
        scope = runtime.compile_attempt_write_scope(
            run_id=RUN_ID,
            phase=contract.phase,
            work_unit_id=contract.work_unit_id,
            attempt_id=attempt_id,
        )
        authority = _claude_authority(
            root,
            label=f"windows-staged-gate-{suffix}",
        )
        builder = _writer(authority=authority, root=root)
        startup = durable_startup_permit(root)
        result = runtime.execute_headless_worker(
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
            attempt_id=attempt_id,
            staged_output_validator=_fixture_claude_exact_staged_validator,
            staged_output_context=_live_shaped_windows_staged_context(scope),
            **_claude_kwargs(
                authority,
                root=root,
                builder=builder,
                startup_authority_binding=startup,
            ),
        )
        gate = result.work_plan["completion_policy"][
            "staged_semantic_gate"
        ]
        unsigned = {
            key: value
            for key, value in gate.items()
            if key != "binding_sha256"
        }
        assert gate["binding_sha256"] == hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        assert (root / "depth_role_1_findings.md").is_file()
        gates.append(gate)
        scopes.append(scope)

    expected_output_directory = (
        WINDOWS_AUDIT_SCRATCHPAD
        + "\\"
        + runtime.ATTEMPT_OUTPUT_RELATIVE_PATH_PLACEHOLDER
    )
    assert gates[0] == gates[1]
    assert gates[0]["context"]["output_directory"] == (
        expected_output_directory
    )
    assert "attempt-" not in gates[0]["context"]["output_directory"]

    tampered_gate = dict(gates[0])
    tampered_gate["binding_sha256"] = "0" * 64
    with pytest.raises(
        transaction.WorkerTransactionError,
        match="staged semantic validator binding digest mismatch",
    ):
        transaction._completion_policy_contract(
            {
                "accepted_signals": ["PROCESS_EXIT_ZERO"],
                "staged_semantic_gate": tampered_gate,
            },
            run_id=RUN_ID,
            provider={"backend": "codex"},
            write_scope=scopes[0],
        )

    wrong_root = tmp_path / "wrong-attempt"
    wrong_root.mkdir()
    contract, launch = _arm(wrong_root, backend="claude")
    actual_attempt_id = "attempt-" + "1" * 24
    wrong_scope = runtime.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase=contract.phase,
        work_unit_id=contract.work_unit_id,
        attempt_id="attempt-" + "2" * 24,
    )
    authority = _claude_authority(wrong_root, label="windows-wrong-attempt")
    builder = _writer(authority=authority, root=wrong_root)
    startup = durable_startup_permit(wrong_root)
    with pytest.raises(
        runtime.HeadlessWorkerRuntimeError,
        match="retains a concrete attempt identity",
    ):
        runtime.execute_headless_worker(
            scratchpad=wrong_root,
            project_root=wrong_root,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned role and write its artifact.",
            command_builder=builder,
            cwd=wrong_root,
            environment={},
            environment_allowlist=authority["environment_allowlist"],
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=startup,
            attempt_id=actual_attempt_id,
            staged_output_validator=_fixture_claude_exact_staged_validator,
            staged_output_context=(
                _live_shaped_windows_staged_context(wrong_scope)
            ),
            **_claude_kwargs(
                authority,
                root=wrong_root,
                builder=builder,
                startup_authority_binding=startup,
            ),
        )
    assert not (wrong_root / "depth_role_1_findings.md").exists()


def test_staged_gate_rejects_context_bound_to_a_different_attempt(
    tmp_path: Path,
) -> None:
    contract, launch = _arm(tmp_path, backend="codex")
    attempt_id = "attempt-" + "c" * 24
    wrong_scope = runtime.compile_attempt_write_scope(
        run_id=RUN_ID,
        phase=contract.phase,
        work_unit_id=contract.work_unit_id,
        attempt_id="attempt-" + "d" * 24,
    )
    with pytest.raises(
        runtime.HeadlessWorkerRuntimeError,
        match="retains a concrete attempt identity",
    ):
        runtime.execute_headless_worker(
            scratchpad=tmp_path,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase_io_contract=contract,
            phase_io_launch=launch,
            prompt="Analyze the assigned role and write its artifact.",
            command_builder=_writer(),
            cwd=tmp_path,
            environment={},
            environment_allowlist=(),
            source_snapshot_digest="a" * 64,
            methodology_digests=("b" * 64,),
            startup_authority_binding=durable_startup_permit(tmp_path),
            attempt_id=attempt_id,
            staged_output_validator=_fixture_staged_semantic_validator,
            staged_output_context={
                "required": "No finding",
                "output_directory": (
                    "C:/stable-scratchpad/"
                    + str(wrong_scope["output_relative_path"])
                ),
            },
        )

    assert not (tmp_path / "depth_role_1_findings.md").exists()


def test_prompt_and_backend_are_bound_but_logical_assignment_is_equal(
    tmp_path: Path,
) -> None:
    rows = {}
    for index, backend in enumerate(("claude", "codex")):
        root = tmp_path / backend
        root.mkdir()
        contract, launch = _arm(root, backend=backend)
        authority = (
            _claude_authority(root, label="backend-comparison")
            if backend == "claude"
            else None
        )
        builder = _writer(
            authority=authority,
            root=root,
        )
        startup = durable_startup_permit(root)
        result = runtime.execute_headless_worker(
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
                attempt_id="attempt-" + str(index + 1) * 24,
            **_claude_kwargs(
                authority,
                root=root,
                builder=builder,
                startup_authority_binding=startup,
            ),
        )
        rows[backend] = result.work_plan

    for field in (
        "canonical_identity",
        "staged_relative_path",
        "parser_binding",
        "projection_mode",
    ):
        assert (
            rows["claude"]["assignment"]["members"][0][field]
            == rows["codex"]["assignment"]["members"][0][field]
        )
    assert (
        rows["claude"]["assignment"]["members"][0]["canonical_prestate"][
            "status"
        ]
        == rows["codex"]["assignment"]["members"][0]["canonical_prestate"][
            "status"
        ]
        == "ABSENT"
    )
    assert (
        rows["claude"]["provider"]["backend"],
        rows["codex"]["provider"]["backend"],
    ) == ("claude", "codex")
    assert rows["claude"]["prompt_template_sha256"] != hashlib.sha256(
        b"Analyze the assigned role and write its artifact."
    ).hexdigest()


def test_headless_incorporation_binds_produced_conditional_receipt(
    tmp_path: Path,
) -> None:
    base, launch = _contract("claude")
    original = base.outputs[0]
    contract = PhaseIOContract(
        pipeline=base.pipeline,
        mode=base.mode,
        ecosystem=base.ecosystem,
        backend=base.backend,
        phase=base.phase,
        work_unit_id=base.work_unit_id,
        outputs=(
            ArtifactSpec(
                root=original.root,
                path=original.path,
                owner_key=base.key,
                artifact_class="CONDITIONAL",
                writer="MODEL",
                write_mode="CREATE",
                condition_id="fixture_gap_present",
            ),
        ),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model=launch.model,
        timeout_s=launch.timeout_s,
        exec_mode=launch.exec_mode,
        tool_policy=launch.tool_policy,
    )
    ledger.record_work_unit_inputs(
        tmp_path,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )
    authority = _claude_authority(
        tmp_path,
        label="conditional-output",
    )
    builder = _writer(
        authority=authority,
        root=tmp_path,
    )
    startup = durable_startup_permit(tmp_path)
    runtime.execute_headless_worker(
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze the assigned role and write its conditional artifact.",
        command_builder=builder,
        cwd=tmp_path,
        environment={},
        environment_allowlist=authority["environment_allowlist"],
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=startup,
        attempt_id="attempt-" + "e" * 24,
        **_claude_kwargs(
            authority,
            root=tmp_path,
            builder=builder,
            startup_authority_binding=startup,
        ),
    )
    record = ledger.read_artifact_ledger(tmp_path)["work_units"][
        contract.key
    ]["artifacts"]["scratchpad:depth_role_1_findings.md"]
    assert record["conditional_receipt"]["state"] == "PRODUCED"
    assert record["conditional_receipt"]["condition_id"] == (
        "fixture_gap_present"
    )
