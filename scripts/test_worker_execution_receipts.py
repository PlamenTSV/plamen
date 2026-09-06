from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

import pytest

import test_claude_provider_preparation as provider_fixtures
import test_wer_claude_runtime_lifecycle_p0_am as runtime_fixtures
import worker_execution_receipts as W


CLAUDE_STREAM_SESSION = "11111111-2222-4333-8444-555555555555"


def _runtime_case(
    tmp_path: Path,
    *,
    label: str,
    monkeypatch: pytest.MonkeyPatch,
) -> runtime_fixtures.RuntimeCase:
    provider_fixtures._install_observers(
        monkeypatch,
        Path(sys.executable).resolve(strict=True),
    )
    return runtime_fixtures._case(tmp_path, label=label)


def _install_runtime_case(
    monkeypatch: pytest.MonkeyPatch,
    case: runtime_fixtures.RuntimeCase,
    *,
    advance_provider_state: bool = True,
) -> list[dict[str, object]]:
    return runtime_fixtures._install_fake_cli(
        monkeypatch,
        (case,),
        advance_provider_state=advance_provider_state,
    )


def _set_runtime_case_stream(
    case: runtime_fixtures.RuntimeCase,
    raw_stream: bytes,
    *,
    write_output: bool = True,
) -> None:
    output_path = case.root / case.output_scope / "result.json"
    output_source = (
        "from pathlib import Path\n"
        f"p=Path({str(output_path)!r})\n"
        "p.parent.mkdir(parents=True,exist_ok=True)\n"
        "p.write_text('{\"finding_id\":\"H-01\"}',encoding='utf-8')\n"
        if write_output
        else ""
    )
    case.fake_script.write_text(
        output_source
        + "import sys\n"
        + f"sys.stdout.buffer.write({raw_stream!r})\n",
        encoding="utf-8",
    )


def _runtime_case_stream_bytes(
    case: runtime_fixtures.RuntimeCase,
    *,
    include_result: bool = True,
    result_is_error: bool = False,
    post_result_event: dict[str, object] | None = None,
) -> bytes:
    rows = [
        json.loads(line)
        for line in runtime_fixtures._stream_bytes(
            root=case.root,
            session_id=case.session_id,
            profile=case.profile,
        ).splitlines()
    ]
    if not include_result:
        rows = [row for row in rows if row.get("type") != "result"]
    elif result_is_error:
        result = rows[-1]
        assert result["type"] == "result"
        result["subtype"] = "error_during_execution"
        result["is_error"] = True
    if post_result_event is not None:
        rows.append(dict(post_result_event))
    return b"".join(
        json.dumps(
            row,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for row in rows
    )


def _claude_stream_bytes(
    *,
    cwd: str = "C:\\audit",
    include_result: bool = True,
    result_is_error: bool = False,
    post_result_event: dict[str, object] | None = None,
) -> bytes:
    events: list[dict[str, object]] = [
        {
            "type": "system",
            "subtype": "init",
            "uuid": "init-uuid",
            "session_id": CLAUDE_STREAM_SESSION,
            "claude_code_version": "2.1.220",
            "cwd": cwd,
            "model": "claude-opus-5",
            "permissionMode": "bypassPermissions",
            "apiKeySource": "subscription",
            "tools": ["Read", "Write"],
            "mcp_servers": [],
            "slash_commands": [],
            "output_style": "default",
            "skills": [],
            "plugins": [],
        },
        {
            "type": "assistant",
            "uuid": "assistant-root",
            "session_id": CLAUDE_STREAM_SESSION,
            "parent_tool_use_id": None,
            "message": {
                "id": "msg-root-end-turn",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "complete"}],
                "model": "claude-opus-5",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 20},
            },
        },
    ]
    if include_result:
        events.append(
            {
                "type": "result",
                "subtype": (
                    "error_during_execution"
                    if result_is_error
                    else "success"
                ),
                "uuid": "result-uuid",
                "session_id": CLAUDE_STREAM_SESSION,
                "duration_ms": 101,
                "duration_api_ms": 91,
                "is_error": result_is_error,
                "num_turns": 1,
                "result": "complete",
                "total_cost_usd": 0.25,
                "usage": {"input_tokens": 10, "output_tokens": 20},
                "modelUsage": {"claude-opus-5": {"inputTokens": 10}},
                "permission_denials": [],
                "stop_reason": "end_turn",
                "origin": {"kind": "human"},
            }
        )
    if post_result_event is not None:
        events.append(post_result_event)
    return b"".join(
        json.dumps(
            event,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for event in events
    )


def _claude_stream_configuration(tmp_path: Path) -> dict[str, object]:
    return {
        "schema": W.CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
        "expected_session_id": CLAUDE_STREAM_SESSION,
        "expected_init_contract": {
            "schema": "plamen.claude-expected-init/v1",
            "claude_code_version": "2.1.220",
            "cwd": str(tmp_path.resolve()),
            "accepted_models": ["claude-opus-5"],
            "permission_mode": "bypassPermissions",
            "expected_tools": ["Read", "Write"],
            "expected_mcp_servers": [],
            "expected_plugins": [],
            "expected_skills": [],
            "expected_agents": [],
            "accepted_api_key_sources": ["subscription"],
            "required_capabilities": [],
            "expected_slash_commands": [],
            "expected_output_style": "default",
        },
        "max_line_bytes": 2 * 1024 * 1024,
        "max_stream_bytes": W.DEFAULT_STDOUT_LIMIT_BYTES,
    }


def _claude_stream_provider_script(
    tmp_path: Path,
    raw_stream: bytes,
    *,
    write_output: bool = True,
) -> Path:
    script = tmp_path / f"fixture-provider-{uuid.uuid4().hex}.py"
    output_statement = (
        "p=Path('worker-out/result.json');"
        "p.parent.mkdir(parents=True,exist_ok=True);"
        "p.write_text('{\"finding_id\":\"H-01\"}',encoding='utf-8');"
        if write_output
        else ""
    )
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        f"{output_statement}\n"
        f"sys.stdout.buffer.write({raw_stream!r})\n",
        encoding="utf-8",
    )
    return script


def _claude_stream_argv(script: Path) -> list[str]:
    return [
        sys.executable,
        str(script),
        "-p",
        "--model",
        "claude-opus",
        "--output-format",
        "stream-json",
        "--verbose",
        "--session-id",
        CLAUDE_STREAM_SESSION,
        "--no-session-persistence",
    ]


def strict_json_digest(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("finding_id"), str):
        raise ValueError("output must be a finding object")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _bindings(
    tmp_path: Path,
    *,
    environment_allowlist: tuple[str, ...] = (),
    backend: str = "codex",
    model: str = "fixture-model",
    **overrides: object,
) -> W.ExecutionBindings:
    allowlist_sha = W.environment_allowlist_sha256(environment_allowlist)
    inputs = tmp_path / "launch-inputs"
    inputs.mkdir(exist_ok=True)
    intent = {
        "effective_backend": backend,
        "effective_model": model,
        "environment_allowlist_sha256": allowlist_sha,
    }
    for name, content in {
        "plan.json": "{}\n",
        "manifest.json": "{}\n",
        "intent.json": json.dumps(intent, sort_keys=True) + "\n",
        "context.md": "context\n",
        "prompt.md": "prompt\n",
        "tool-policy.json": '{"network":false}\n',
    }.items():
        (inputs / name).write_text(content, encoding="utf-8")
    values: dict[str, object] = {
        "run_id": "run-001",
        "shard_id": "shard-001",
        "plan": W.BoundInput("launch-inputs/plan.json"),
        "manifest": W.BoundInput("launch-inputs/manifest.json"),
        "intent": W.BoundInput("launch-inputs/intent.json"),
        "context": W.BoundInput("launch-inputs/context.md"),
        "prompt": W.BoundInput("launch-inputs/prompt.md"),
        "tool_policy": W.BoundInput("launch-inputs/tool-policy.json"),
        "worker": W.PrincipalInvocation("worker-001", "worker-invocation-001"),
        "assessors": (
            W.PrincipalInvocation("assessor-001", "assessor-invocation-001"),
            W.PrincipalInvocation("assessor-002", "assessor-invocation-002"),
        ),
        "effective_backend": backend,
        "effective_model": model,
    }
    values.update(overrides)
    return W.ExecutionBindings(**values)  # type: ignore[arg-type]


def _script_for(relative: str, *, payload: str | None = None, extra: str = "") -> str:
    body = payload if payload is not None else '{"finding_id":"H-01","status":"PROPOSED"}'
    return (
        "from pathlib import Path; "
        f"p=Path({relative!r}); p.parent.mkdir(parents=True, exist_ok=True); "
        f"p.write_text({body!r}, encoding='utf-8'); "
        f"{extra}"
    )


def _run(
    tmp_path: Path,
    *,
    script: str | None = None,
    expected: tuple[W.ExpectedOutput, ...] | None = None,
    parser=W.ParserDigest,
) -> W.CompletedExecution:
    del parser
    return W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=_bindings(tmp_path),
        argv=[
            sys.executable,
            "-c",
            script or _script_for("worker-out/result.json"),
        ],
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=expected
        or (W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),),
        parser_digest=strict_json_digest,
        environment={},
        environment_allowlist=(),
        timeout_seconds=10,
    )


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_provider_owned_success_binds_process_authority_and_replays(tmp_path: Path) -> None:
    completed = _run(tmp_path)

    receipt = W.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )
    arm = _load(completed.arm_path)

    assert arm["schema_version"] == W.ARM_SCHEMA
    assert arm["launcher"]["identity"] == W.LAUNCHER_IDENTITY  # type: ignore[index]
    assert arm["bindings"]["effective_backend"] == "codex"  # type: ignore[index]
    assert arm["bindings"]["effective_model"] == "fixture-model"  # type: ignore[index]
    assert arm["process_intent"]["stdin"] == {"state": "DEVNULL"}  # type: ignore[index]
    assert arm["process_intent"]["timeout_seconds"] == "10"
    assert arm["output_contract"]["expected_outputs"][0]["pre_state"] == "ABSENT"  # type: ignore[index]
    observation = receipt["process_observation"]
    assert observation["pid"] > 0
    assert observation["returncode"] == 0
    assert observation["timed_out"] is False
    if os.name == "nt":
        assert observation["creation_identity"]["kind"] == "WINDOWS_FILETIME"
    elif sys.platform == "darwin":
        assert observation["creation_identity"]["kind"] == (
            "MACOS_PROC_PIDTBSDINFO_START_TIME"
        )
    else:
        assert observation["creation_identity"]["kind"] == "POSIX_PROCFS_START_TICKS"
    assert receipt["outputs"][0]["raw_size"] > 0
    assert receipt["stdout_blob"]["size"] == 0
    assert receipt["stderr_blob"]["size"] == 0
    assert completed.published_paths == (tmp_path / "canonical" / "result.json",)
    assert completed.published_paths[0].read_bytes() == (
        tmp_path / "worker-out" / "result.json"
    ).read_bytes()
    publish = _load(completed.publish_receipt_path)
    assert publish["schema_version"] == W.PUBLISH_SCHEMA
    assert publish["completion_sha256"] == completed.completion_sha256
    assert publish["destinations"][0]["pre_state"] == "ABSENT"  # type: ignore[index]
    assert publish["destinations"][0]["post_state"] == "PRESENT"  # type: ignore[index]


def test_claude_stream_stdout_is_armed_replayed_and_never_overclaims_producer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _runtime_case(
        tmp_path,
        label="stream-evidence",
        monkeypatch=monkeypatch,
    )
    raw = _runtime_case_stream_bytes(case)
    _set_runtime_case_stream(case, raw)
    _install_runtime_case(monkeypatch, case)
    kwargs = case.wer_kwargs()
    kwargs["publish_canonical"] = True
    kwargs["parser_digest"] = strict_json_digest
    completed = W.run_observed_worker(**kwargs)

    receipt = W.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )
    arm = _load(completed.arm_path)
    binding = arm["process_intent"]["provider_stdout_evidence"]  # type: ignore[index]
    evidence = receipt["provider_stdout_evidence"]

    assert binding["expected_session_id"] == case.session_id
    assert binding["command_contract"]["output_format"] == "stream-json"
    assert binding["parser_runtime"]["implementation"] == sys.implementation.name
    assert binding["parser_runtime"]["executable"]["sha256"] == hashlib.sha256(
        Path(sys.executable).resolve(strict=True).read_bytes()
    ).hexdigest()
    assert binding["parser_runtime"]["schema"] == (
        "plamen.claude_stream_parser_runtime.v2"
    )
    assert {
        "_json",
        "json",
        "json.decoder",
        "json.encoder",
        "json.scanner",
    }.issubset(
        {
            row["module"]
            for row in binding["parser_runtime"]["modules"]
        }
    )
    assert binding["parser_runtime"]["native_binaries"]
    assert evidence["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["process_observation"]["provider_stdout_evidence"] == evidence  # type: ignore[index]
    if os.name == "nt":
        assert binding["producer_exclusivity_capability"] == (
            "PRODUCER_EXCLUSIVITY_UNPROVEN_NATIVE_WINDOWS"
        )
    else:
        assert binding["producer_exclusivity_capability"] == (
            "PRODUCER_EXCLUSIVITY_NOT_ESTABLISHED"
        )


@pytest.mark.parametrize("failure_kind", ["missing-result", "error", "late-row"])
def test_claude_stream_stdout_semantic_rejection_is_durable_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    case = _runtime_case(
        tmp_path,
        label=f"stream-reject-{failure_kind}",
        monkeypatch=monkeypatch,
    )
    options: dict[str, object] = {}
    if failure_kind == "missing-result":
        options["include_result"] = False
    elif failure_kind == "error":
        options["result_is_error"] = True
    else:
        options["post_result_event"] = {
            "type": "assistant",
            "uuid": "late-assistant",
            "session_id": case.session_id,
            "parent_tool_use_id": None,
            "message": {
                "role": "assistant",
                "content": [],
                "stop_reason": "end_turn",
            },
        }
    raw = _runtime_case_stream_bytes(case, **options)
    _set_runtime_case_stream(case, raw)
    _install_runtime_case(monkeypatch, case)
    with pytest.raises(W.WorkerExecutionIncomplete) as caught:
        W.run_observed_worker(**case.wer_kwargs())

    debt = _load(caught.value.debt_path)
    assert debt["reason_code"] == "PROVIDER_STREAM_EVIDENCE_REJECTED"
    assert debt["stdout_blob"]["sha256"] == hashlib.sha256(raw).hexdigest()  # type: ignore[index]


def test_claude_stream_command_flags_are_bound_before_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _runtime_case(
        tmp_path,
        label="stream-flags",
        monkeypatch=monkeypatch,
    )
    argv = list(case.expected_final_argv)
    argv.append("--include-partial-messages")

    with pytest.raises(
        W.WorkerExecutionError,
        match="unsupported output/session flags",
    ):
        W._claude_stream_stdout_binding(
            case.stream,
            argv=argv,
            stdout_limit_bytes=W.DEFAULT_STDOUT_LIMIT_BYTES,
            cwd=tmp_path.resolve(),
            effective_model=runtime_fixtures.MODEL,
        )


def test_claude_stream_parser_runtime_drift_rejects_receipt_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _runtime_case(
        tmp_path,
        label="stream-parser-drift",
        monkeypatch=monkeypatch,
    )
    raw = _runtime_case_stream_bytes(case)
    _set_runtime_case_stream(case, raw)
    _install_runtime_case(monkeypatch, case)
    kwargs = case.wer_kwargs()
    kwargs["publish_canonical"] = True
    kwargs["parser_digest"] = strict_json_digest
    completed = W.run_observed_worker(**kwargs)
    original = W._claude_stream_parser_runtime_binding

    def drifted_runtime() -> dict[str, object]:
        binding = original()
        binding["unicode_database_version"] = "DRIFTED"
        return binding

    monkeypatch.setattr(
        W,
        "_claude_stream_parser_runtime_binding",
        drifted_runtime,
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="provider stdout evidence binding changed",
    ):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_provider_implementation_closure_is_armed_and_replayed(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "trusted-provider.py"
    implementation.write_text("PROVIDER_VERSION = 1\n", encoding="utf-8")
    completed = W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=_bindings(tmp_path),
        argv=[
            sys.executable,
            "-c",
            _script_for("worker-out/result.json"),
        ],
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=(
            W.ExpectedOutput(
                "finding-H-01",
                "result.json",
                "canonical/result.json",
            ),
        ),
        parser_digest=strict_json_digest,
        environment={},
        environment_allowlist=(),
        timeout_seconds=10,
        implementation_files=(implementation,),
    )
    arm = _load(completed.arm_path)
    record = arm["process_intent"]["implementation_files"][0]  # type: ignore[index]
    assert record["path"] == str(implementation.resolve())
    assert record["sha256"] == hashlib.sha256(
        implementation.read_bytes()
    ).hexdigest()

    implementation.write_text("PROVIDER_VERSION = 2\n", encoding="utf-8")
    with pytest.raises(W.WorkerExecutionError, match="implementation file"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_provider_owned_bound_prompt_stdin_drives_real_subprocess_and_replays(
    tmp_path: Path,
) -> None:
    bindings = _bindings(tmp_path)
    script = (
        "from pathlib import Path; import hashlib, json, sys; "
        "raw=sys.stdin.buffer.read(); "
        "p=Path('worker-out/result.json'); "
        "p.parent.mkdir(parents=True, exist_ok=True); "
        "p.write_text(json.dumps({'finding_id': hashlib.sha256(raw).hexdigest()}), "
        "encoding='utf-8')"
    )
    completed = W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=bindings,
        argv=[sys.executable, "-c", script],
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=(
            W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
        ),
        parser_digest=strict_json_digest,
        environment={},
        environment_allowlist=(),
        stdin_input=bindings.prompt,
        timeout_seconds=10,
    )

    prompt_raw = (tmp_path / "launch-inputs" / "prompt.md").read_bytes()
    expected_digest = hashlib.sha256(prompt_raw).hexdigest()
    assert json.loads(completed.published_paths[0].read_text(encoding="utf-8")) == {
        "finding_id": expected_digest
    }
    arm = _load(completed.arm_path)
    assert arm["process_intent"]["stdin"] == {  # type: ignore[index]
        "state": "BOUND_INPUT",
        "input_name": "prompt",
        "relative_path": "launch-inputs/prompt.md",
        "sha256": expected_digest,
        "size": len(prompt_raw),
    }
    W.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )


def test_phaseio_only_staging_does_not_require_canonical_destination_absent(
    tmp_path: Path,
) -> None:
    """A staged REPLACE must not be rejected by the legacy absent-only publisher.

    The OS boundary grants the child write access only to ``worker-out`` and
    PhaseIO performs the later compare-and-swap projection.  Therefore an
    existing canonical preimage is expected and must remain byte-identical
    throughout provider execution.
    """

    canonical = tmp_path / "canonical" / "result.json"
    canonical.parent.mkdir()
    canonical.write_text(
        '{"finding_id":"OLD","status":"PROPOSED"}',
        encoding="utf-8",
    )
    prior = canonical.read_bytes()
    bindings = _bindings(tmp_path)
    completed = W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=bindings,
        argv=[sys.executable, "-c", _script_for("worker-out/result.json")],
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=(
            W.ExpectedOutput(
                "finding-H-01",
                "result.json",
                "canonical/result.json",
            ),
        ),
        parser_digest=strict_json_digest,
        environment={},
        environment_allowlist=(),
        stdin_input=bindings.prompt,
        timeout_seconds=10,
        publish_canonical=False,
    )

    assert completed.publish_receipt_path is None
    assert canonical.read_bytes() == prior
    assert (tmp_path / "worker-out" / "result.json").is_file()
    W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        parser_digest=strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
    )


@pytest.mark.parametrize(
    "stdin_input",
    (
        W.BoundInput("launch-inputs/not-bound.md"),
        W.BoundInput("launch-inputs/Prompt.md"),
        object(),
    ),
)
def test_stdin_must_be_an_exact_bound_semantic_input(
    tmp_path: Path, stdin_input: object
) -> None:
    bindings = _bindings(tmp_path)
    with pytest.raises(W.WorkerExecutionError, match="stdin"):
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=[sys.executable, "-c", "pass"],
            cwd=tmp_path,
            output_scope_relative="worker-out",
            expected_outputs=(
                W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
            ),
            parser_digest=strict_json_digest,
            environment={},
            environment_allowlist=(),
            stdin_input=stdin_input,  # type: ignore[arg-type]
        )

    assert not list(tmp_path.glob(".worker_execution_receipts/shard-001/arm_*.json"))


def test_bound_stdin_mutation_is_rejected_on_replay(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path)
    completed = W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=bindings,
        argv=[sys.executable, "-c", _script_for("worker-out/result.json")],
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=(
            W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
        ),
        parser_digest=strict_json_digest,
        environment={},
        environment_allowlist=(),
        stdin_input=bindings.prompt,
        timeout_seconds=10,
    )
    (tmp_path / "launch-inputs" / "prompt.md").write_text(
        "changed\n", encoding="utf-8"
    )

    with pytest.raises(W.WorkerExecutionError, match="bound prompt bytes changed"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_symlinked_bound_stdin_is_rejected_before_launch(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path)
    prompt = tmp_path / "launch-inputs" / "prompt.md"
    target = tmp_path / "real-prompt.md"
    target.write_text("prompt\n", encoding="utf-8")
    prompt.unlink()
    try:
        prompt.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(W.WorkerExecutionError, match="symlink|reparse"):
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=bindings,
            argv=[sys.executable, "-c", "pass"],
            cwd=tmp_path,
            output_scope_relative="worker-out",
            expected_outputs=(
                W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
            ),
            parser_digest=strict_json_digest,
            environment={},
            environment_allowlist=(),
            stdin_input=bindings.prompt,
        )


def test_arm_is_fsynced_before_child_can_observe_it(tmp_path: Path) -> None:
    # The child can only see an arm if persistence happened before Popen.
    evidence_glob = ".worker_execution_receipts/shard-001/arm_*.json"
    script = (
        "from pathlib import Path; import glob; "
        f"assert len(glob.glob({evidence_glob!r})) == 1; "
        "p=Path('worker-out/result.json'); "
        "p.parent.mkdir(parents=True, exist_ok=True); "
        "p.write_text('{\"finding_id\":\"H-01\"}', encoding='utf-8')"
    )
    completed = _run(tmp_path, script=script)
    assert completed.receipt_path.is_file()


def test_preexisting_output_bytes_never_count_and_child_never_launches(tmp_path: Path) -> None:
    output = tmp_path / "worker-out" / "result.json"
    output.parent.mkdir()
    output.write_text('{"finding_id":"old"}', encoding="utf-8")
    marker = tmp_path / "launched.txt"

    expected_error = (
        "fresh private leaf" if os.name == "nt" else "not empty"
    )
    with pytest.raises(W.WorkerExecutionError, match=expected_error):
        _run(
            tmp_path,
            script=_script_for(
                "worker-out/result.json",
                extra="Path('launched.txt').write_text('yes', encoding='utf-8')",
            ),
        )

    assert output.read_text(encoding="utf-8") == '{"finding_id":"old"}'
    assert not marker.exists()
    assert not list(tmp_path.glob(".worker_execution_receipts/shard-001/arm_*.json"))


@pytest.mark.parametrize(
    ("script", "reason"),
    [
        ("pass", "OUTPUT_DENOMINATOR_MISMATCH"),
        (_script_for("worker-out/extra.json"), "OUTPUT_DENOMINATOR_MISMATCH"),
        (_script_for("worker-out/Result.json"), "OUTPUT_DENOMINATOR_MISMATCH"),
    ],
)
def test_missing_unassigned_and_miscased_outputs_leave_debt_not_completion(
    tmp_path: Path, script: str, reason: str
) -> None:
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(tmp_path, script=script)

    exc = captured.value
    assert exc.arm_path.is_file()
    assert exc.debt_path is not None and exc.debt_path.is_file()
    assert _load(exc.debt_path)["reason_code"] == reason
    assert not list(exc.arm_path.parent.glob("completion_*.json"))


def test_nonzero_exit_records_streams_and_debt_but_no_completion(tmp_path: Path) -> None:
    script = "import sys; print('worker failed'); print('detail', file=sys.stderr); sys.exit(7)"
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(tmp_path, script=script)

    debt = _load(captured.value.debt_path)  # type: ignore[arg-type]
    assert debt["reason_code"] == "NONZERO_EXIT"
    assert debt["process_observation"]["returncode"] == 7  # type: ignore[index]
    assert debt["stdout_blob"]["size"] > 0  # type: ignore[index]
    assert debt["stderr_blob"]["size"] > 0  # type: ignore[index]
    assert debt["completion_emitted"] is False


def test_parser_rejection_is_visible_observation_debt(tmp_path: Path) -> None:
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(tmp_path, script=_script_for("worker-out/result.json", payload="not-json"))

    debt = _load(captured.value.debt_path)  # type: ignore[arg-type]
    assert debt["reason_code"] == "OBSERVATION_FAILED"
    assert "JSONDecodeError" in debt["detail"]
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))


def test_timeout_leaves_arm_streams_and_debt_but_no_completion(tmp_path: Path) -> None:
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=_bindings(tmp_path),
            argv=[sys.executable, "-c", "import time; print('started'); time.sleep(2)"],
            cwd=tmp_path,
            output_scope_relative="worker-out",
            expected_outputs=(
                W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
            ),
            parser_digest=strict_json_digest,
            environment={},
            environment_allowlist=(),
            timeout_seconds=0.05,
        )

    debt = _load(captured.value.debt_path)  # type: ignore[arg-type]
    assert debt["reason_code"] == "TIMEOUT"
    assert debt["process_observation"]["timed_out"] is True  # type: ignore[index]
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))


def test_timeout_terminates_the_owned_process_tree_before_returning(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived.txt"
    descendant = (
        "import time; from pathlib import Path; time.sleep(0.5); "
        "Path('descendant-survived.txt').write_text('alive', encoding='utf-8')"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL); time.sleep(10)"
    )

    started = time.monotonic()
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=_bindings(tmp_path),
            argv=[sys.executable, "-c", parent],
            cwd=tmp_path,
            output_scope_relative="worker-out",
            expected_outputs=(
                W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
            ),
            parser_digest=strict_json_digest,
            environment={},
            environment_allowlist=(),
            timeout_seconds=0.05,
        )

    assert time.monotonic() - started < 2.0
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(0.025)
    assert not marker.exists()
    debt = _load(captured.value.debt_path)  # type: ignore[arg-type]
    assert debt["process_observation"]["process_tree_terminated"] is True  # type: ignore[index]


def test_launch_authority_changed_by_child_cannot_complete(tmp_path: Path) -> None:
    script = _script_for(
        "worker-out/result.json",
        extra="Path('launch-inputs/context.md').write_text('mutated', encoding='utf-8')",
    )
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(tmp_path, script=script)

    debt = _load(captured.value.debt_path)  # type: ignore[arg-type]
    if os.name == "nt":
        # The low-integrity token denies this protected write before the
        # post-exit replay is needed.
        assert debt["reason_code"] == "NONZERO_EXIT"
        assert (
            tmp_path / "launch-inputs" / "context.md"
        ).read_text(encoding="utf-8") != "mutated"
    else:
        assert debt["reason_code"] == "OBSERVATION_FAILED"
        assert "bound context bytes changed" in debt["detail"]
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))


def test_publish_failure_leaves_completion_publish_arm_and_debt_no_canonical_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = W._publish_absent_bytes

    def fail_canonical(path: Path, raw: bytes) -> None:
        if path == tmp_path / "canonical" / "result.json":
            raise OSError("injected publish failure")
        original(path, raw)

    monkeypatch.setattr(W, "_publish_absent_bytes", fail_canonical)
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(tmp_path)

    shard = captured.value.arm_path.parent
    debt = _load(captured.value.debt_path)  # type: ignore[arg-type]
    assert debt["reason_code"] == "PUBLISH_FAILED"
    assert len(list(shard.glob("completion_*.json"))) == 1
    assert len(list(shard.glob("publish_arm_*.json"))) == 1
    assert not [
        path for path in shard.glob("publish_*.json") if not path.name.startswith("publish_arm_")
    ]
    assert not (tmp_path / "canonical" / "result.json").exists()


def test_identical_canonical_race_never_counts_as_provider_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = W._publish_absent_bytes

    def inject_equal_race(path: Path, raw: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        original(path, raw)

    monkeypatch.setattr(W, "_publish_absent_bytes", inject_equal_race)
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run(tmp_path)

    shard = captured.value.arm_path.parent
    assert _load(captured.value.debt_path)["reason_code"] == "PUBLISH_FAILED"  # type: ignore[arg-type]
    assert (tmp_path / "canonical" / "result.json").is_file()
    assert not [
        path for path in shard.glob("publish_*.json") if not path.name.startswith("publish_arm_")
    ]


def test_output_tamper_or_deletion_is_rejected_on_replay(tmp_path: Path) -> None:
    completed = _run(tmp_path)
    output = tmp_path / "worker-out" / "result.json"
    output.write_text('{"finding_id":"H-02"}', encoding="utf-8")

    with pytest.raises(W.WorkerExecutionError, match="raw bytes changed"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )

    output.unlink()
    with pytest.raises(W.WorkerExecutionError, match="output denominator"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_stream_deletion_is_rejected_on_replay(tmp_path: Path) -> None:
    completed = _run(tmp_path, script=_script_for("worker-out/result.json", extra="print('ok')"))
    receipt = _load(completed.receipt_path)
    stdout_path = completed.receipt_path.parent / receipt["stdout_blob"]["relative_path"]  # type: ignore[index]
    stdout_path.unlink()

    with pytest.raises(W.WorkerExecutionError, match="missing"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_bound_input_tamper_is_rejected_on_replay(tmp_path: Path) -> None:
    completed = _run(tmp_path)
    (tmp_path / "launch-inputs" / "context.md").write_text("changed\n", encoding="utf-8")

    with pytest.raises(W.WorkerExecutionError, match="bound context bytes changed"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_canonical_publish_tamper_is_rejected_on_replay(tmp_path: Path) -> None:
    completed = _run(tmp_path)
    completed.published_paths[0].write_text('{"finding_id":"H-99"}', encoding="utf-8")

    with pytest.raises(W.WorkerExecutionError, match="canonical published bytes changed"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_launch_intent_environment_authority_must_match_provider_allowlist(
    tmp_path: Path,
) -> None:
    with pytest.raises(W.WorkerExecutionError, match="does not match the launch intent"):
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=_bindings(tmp_path),
            argv=[sys.executable, "-c", _script_for("worker-out/result.json")],
            cwd=tmp_path,
            output_scope_relative="worker-out",
            expected_outputs=(
                W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
            ),
            parser_digest=strict_json_digest,
            environment={"PLAMEN_TEST_FLAG": "x"},
            environment_allowlist=("PLAMEN_TEST_FLAG",),
        )

    assert not list(tmp_path.glob(".worker_execution_receipts/shard-001/arm_*.json"))


def test_transcript_state_is_explicit_and_published(tmp_path: Path) -> None:
    completed = _run(
        tmp_path,
        script=_script_for("worker-out/transcript.json"),
        expected=(
            W.ExpectedOutput(
                "transcript-001",
                "transcript.json",
                "canonical/transcript.json",
                is_transcript=True,
            ),
        ),
    )
    receipt = _load(completed.receipt_path)
    arm = _load(completed.arm_path)

    assert arm["process_intent"]["stream_mode"] == "SEPARATE_STDOUT_STDERR"  # type: ignore[index]
    assert arm["output_contract"]["transcript_expectation"] == "PRESENT"  # type: ignore[index]
    assert receipt["stream_mode"] == "SEPARATE_STDOUT_STDERR"
    assert receipt["transcript"] == {
        "state": "PRESENT",
        "assignment_ids": ["transcript-001"],
    }


def test_worker_and_multiple_assessor_invocations_are_exactly_bound(tmp_path: Path) -> None:
    completed = _run(tmp_path)
    arm = _load(completed.arm_path)
    bindings = arm["bindings"]

    assert bindings["worker"] == {  # type: ignore[index]
        "identity": "worker-001",
        "invocation_id": "worker-invocation-001",
    }
    assert bindings["assessors"] == [  # type: ignore[index]
        {"identity": "assessor-001", "invocation_id": "assessor-invocation-001"},
        {"identity": "assessor-002", "invocation_id": "assessor-invocation-002"},
    ]


def test_arm_tamper_is_rejected_even_when_completion_bytes_are_unchanged(tmp_path: Path) -> None:
    completed = _run(tmp_path)
    raw = completed.arm_path.read_bytes()
    completed.arm_path.write_bytes(
        raw.replace(b'"fixture-model"', b'"fixture-fake"')
    )

    with pytest.raises(W.WorkerExecutionError, match="digest mismatch"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_authority_hash_prevents_content_addressed_receipt_substitution(tmp_path: Path) -> None:
    completed = _run(tmp_path)

    with pytest.raises(W.WorkerExecutionError, match="expected authority"):
        W.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=completed.receipt_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=strict_json_digest,
            expected_completion_sha256="f" * 64,
            expected_publish_sha256=completed.publish_sha256,
        )


def test_environment_is_allowlisted_hash_bound_and_values_are_not_persisted(tmp_path: Path) -> None:
    secretish_value = "not-persisted-value"
    completed = W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=_bindings(tmp_path, environment_allowlist=("PLAMEN_TEST_FLAG",)),
        argv=[sys.executable, "-c", _script_for("worker-out/result.json")],
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=(
            W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
        ),
        parser_digest=strict_json_digest,
        environment={"PLAMEN_TEST_FLAG": secretish_value},
        environment_allowlist=("PLAMEN_TEST_FLAG",),
        timeout_seconds=10,
    )
    raw = completed.arm_path.read_text(encoding="utf-8")
    arm = json.loads(raw)

    assert secretish_value not in raw
    assert arm["environment"]["effective_names"] == ["PLAMEN_TEST_FLAG"]
    assert arm["environment"]["values_persisted"] is False
    assert len(arm["environment"]["effective_sha256"]) == 64


def test_unallowlisted_environment_and_identity_alias_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(W.WorkerExecutionError, match="not allowlisted"):
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=_bindings(tmp_path),
            argv=[sys.executable, "-c", "pass"],
            cwd=tmp_path,
            output_scope_relative="worker-out",
            expected_outputs=(
                W.ExpectedOutput("finding-H-01", "result.json", "canonical/result.json"),
            ),
            parser_digest=strict_json_digest,
            environment={"NOT_ALLOWED": "x"},
            environment_allowlist=(),
        )

    with pytest.raises(W.WorkerExecutionError, match="case-distinct"):
        _bindings(
            tmp_path,
            worker=W.PrincipalInvocation(
                W.LAUNCHER_IDENTITY.lower(), "worker-invocation-001"
            ),
        )

    assert W.environment_allowlist_sha256(("B", "A")) == W.environment_allowlist_sha256(
        ("A", "B")
    )
    with pytest.raises(W.WorkerExecutionError, match="case collision"):
        W.environment_allowlist_sha256(("PATH", "Path"))


def test_output_escape_and_case_colliding_assignment_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(W.WorkerExecutionError, match="unsafe component"):
        W.ExpectedOutput("finding-H-01", "../escape.json", "canonical/result.json")

    with pytest.raises(W.WorkerExecutionError, match="collide by case"):
        W.run_observed_worker(
            scratchpad=tmp_path,
            bindings=_bindings(tmp_path),
            argv=[sys.executable, "-c", "pass"],
            cwd=tmp_path,
            output_scope_relative="worker-out",
            expected_outputs=(
                W.ExpectedOutput("one", "Result.json", "canonical/one.json"),
                W.ExpectedOutput("two", "result.json", "canonical/two.json"),
            ),
            parser_digest=strict_json_digest,
            environment={},
            environment_allowlist=(),
        )


def test_no_public_raw_receipt_or_completion_writer_exists() -> None:
    exported = set(W.__all__)
    assert not any("write" in name.casefold() for name in exported)
    assert not any("record" in name.casefold() for name in exported)
    assert not any("receipt" in name.casefold() and "validate" not in name.casefold() for name in exported)
    assert "run_observed_worker" in exported
