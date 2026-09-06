"""Red-to-green contract for the provider-owned skeptic stdout transport."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any

import pytest

import skeptic_execution_work as S


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _declared_digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).rstrip(b"\n")).hexdigest()


EXPECTED_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["rows"],
    "properties": {
        "rows": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["work_item_id", "result"],
                "properties": {
                    "work_item_id": {"type": "string"},
                    "result": {"enum": ["OPEN", "SUPPORTED_NEGATIVE"]},
                },
            },
        }
    },
}


def assessment_digest(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8", errors="strict"))
    if not isinstance(value, dict) or set(value) != {"rows"}:
        raise ValueError("assessment fields are not exact")
    if not isinstance(value["rows"], list) or not value["rows"]:
        raise ValueError("assessment denominator is empty")
    return hashlib.sha256(_canonical(value)).hexdigest()


def _case(
    root: Path,
    *,
    workflow: str = "candidate_negative",
    script_suffix: str = "",
    raw_script: str | None = None,
    project_root: Path | None = None,
    stdout: bytes | None = None,
    stdout_limit_bytes: int = 4096,
    stderr_limit_bytes: int = 2048,
    environment: dict[str, str] | None = None,
    environment_allowlist: tuple[str, ...] = (),
) -> tuple[S.PreparedSkepticExecution, bytes]:
    root.mkdir(parents=True, exist_ok=True)
    unsigned_shard = {
        "shard_id": "negative-shard-0001",
        "work_item_ids": ["NEG-0001"],
    }
    shard = {**unsigned_shard, "shard_digest": _declared_digest(unsigned_shard)}
    unsigned_plan = {"schema_version": "test.plan.v1", "shards": [shard]}
    plan = {**unsigned_plan, "work_plan_digest": _declared_digest(unsigned_plan)}
    plan_path = root / f"{workflow}_plan.json"
    plan_path.write_bytes(_canonical(plan))
    output = stdout or _canonical(
        {"rows": [{"work_item_id": "NEG-0001", "result": "OPEN"}]}
    )
    script = raw_script or (
        "import sys; packet=sys.stdin.buffer.read(); "
        "assert b'plamen.skeptic_execution_packet.v2' in packet; "
        f"sys.stdout.buffer.write({output!r}); sys.stdout.buffer.flush()"
    )
    if script_suffix:
        script += "; " + script_suffix
    layout = S.skeptic_execution_layout(
        root,
        workflow=workflow,
        run_id="RUN-V2-0001",
        plan_digest=plan["work_plan_digest"],
        shard_id=shard["shard_id"],
        canonical_output=f"{workflow}_assessments_0001.json",
    )
    policy = S.canonical_tool_policy(
        backend="fixture-subprocess",
        read_roots=[],
        staged_output=str(layout.staged_output_path),
    )
    request = S.prepare_skeptic_execution(
        scratchpad=root,
        project_root=project_root or root,
        workflow=workflow,
        run_id="RUN-V2-0001",
        plan_path=plan_path,
        expected_plan_digest=plan["work_plan_digest"],
        shard=shard,
        context={
            "methodology": "enumerate the assigned obligation exactly once",
            "source_context": [{"path": "src/Generic.sol", "bytes": "contract C {}"}],
            "work_items": [{"work_item_id": "NEG-0001"}],
        },
        snapshot={
            "snapshot_id": "SNAPSHOT-0001",
            "source_tree_sha256": "a" * 64,
        },
        rendered_prompt="Assess only the assigned row and return strict JSON.",
        expected_output_schema=EXPECTED_SCHEMA,
        backend="fixture-subprocess",
        model="fixture-python",
        argv=[sys.executable, "-c", script],
        tool_policy=policy,
        worker_identity="FIXTURE_SKEPTIC_WORKER",
        worker_invocation_id="FIXTURE-WORKER-0001",
        assessor_identity="PLAMEN_SKEPTIC_CONSUMER",
        assessor_invocation_id="FIXTURE-CONSUMER-0001",
        canonical_output=layout.canonical_output_relative,
        timeout_seconds=10,
        cwd=root,
        environment=environment or {},
        environment_allowlist=environment_allowlist,
        parser_digest=assessment_digest,
        stdout_limit_bytes=stdout_limit_bytes,
        stderr_limit_bytes=stderr_limit_bytes,
    )
    return request, output


def test_claude_profile_has_no_tools_files_settings_or_session(tmp_path: Path) -> None:
    layout = S.skeptic_execution_layout(
        tmp_path,
        workflow="candidate_negative",
        run_id="RUN-V2",
        plan_digest="1" * 64,
        shard_id="shard-1",
        canonical_output="assessment.json",
    )
    policy = S.canonical_tool_policy(
        backend="claude", read_roots=[], staged_output=str(layout.staged_output_path)
    )
    argv = S.canonical_backend_argv(
        backend="claude",
        executable="claude",
        model="claude-opus-4-1",
        tool_policy=policy,
        system_prompt=S.SKEPTIC_SYSTEM_PROMPT,
        expected_output_schema=EXPECTED_SCHEMA,
    )
    assert argv == (
        "claude",
        "--print",
        "--output-format",
        "text",
        "--input-format",
        "text",
        "--model",
        "claude-opus-4-1",
        "--no-session-persistence",
        "--safe-mode",
        "--system-prompt",
        S.SKEPTIC_SYSTEM_PROMPT,
        "--tools",
        "",
        "--setting-sources",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--json-schema",
        json.dumps(EXPECTED_SCHEMA, sort_keys=True, separators=(",", ":")),
    )
    assert policy["allowed_tools"] == []
    assert policy["model_filesystem_access"] == "NONE"
    assert policy["model_output_channel"] == "RAW_STDOUT_ONLY"
    assert not {
        "--dangerously-skip-permissions",
        "--add-dir",
        "--allowedTools",
        "--disallowedTools",
        "--append-system-prompt",
    }.intersection(argv)


@pytest.mark.parametrize(
    "extra",
    (
        ("--dangerously-skip-permissions",),
        ("--add-dir", "C:/source"),
        ("--tools", "Read"),
        ("--setting-sources", "user"),
    ),
)
def test_claude_profile_rejects_any_ambient_or_model_file_authority(
    tmp_path: Path, extra: tuple[str, ...]
) -> None:
    layout = S.skeptic_execution_layout(
        tmp_path,
        workflow="application_skeptic",
        run_id="RUN-V2",
        plan_digest="2" * 64,
        shard_id="shard-1",
        canonical_output="assessment.json",
    )
    policy = S.canonical_tool_policy(
        backend="claude", read_roots=[], staged_output=str(layout.staged_output_path)
    )
    argv = list(
        S.canonical_backend_argv(
            backend="claude",
            executable="claude",
            model="claude-opus-4-1",
                tool_policy=policy,
                expected_output_schema=EXPECTED_SCHEMA,
        )
    )
    if extra[0] in argv:
        argv[argv.index(extra[0]) + 1] = extra[1]
    else:
        argv.extend(extra)
    with pytest.raises(S.SkepticExecutionWorkError):
        S.validate_skeptic_backend_contract(
            backend="claude",
            model="claude-opus-4-1",
            argv=argv,
            tool_policy=policy,
            expected_output_schema=EXPECTED_SCHEMA,
        )


def test_one_immutable_packet_contains_every_semantic_input(tmp_path: Path) -> None:
    request, _ = _case(tmp_path)
    packet = json.loads(request.packet_path.read_text(encoding="utf-8"))
    assert packet["schema_version"] == "plamen.skeptic_execution_packet.v2"
    assert packet["workflow"] == "candidate_negative"
    assert packet["plan"]["work_plan_digest"] == request.plan_digest
    assert packet["shard"]["shard_digest"] == request.shard_digest
    assert packet["snapshot"] == {
        "snapshot_id": "SNAPSHOT-0001",
        "source_tree_sha256": "a" * 64,
    }
    assert packet["methodology_and_source_context"]["methodology"]
    assert packet["methodology_and_source_context"]["source_context"]
    assert packet["instructions"].startswith("Assess only")
    assert packet["expected_output_schema"] == EXPECTED_SCHEMA
    assert packet["transport_contract"] == {
        "input": "THIS_EXACT_IMMUTABLE_JSON_PACKET_ON_STDIN",
        "output": "ONE_RAW_JSON_OBJECT_ON_STDOUT",
        "tools": "NONE",
    }


def test_provider_materializes_exact_stdout_and_resume_replays_every_byte(
    tmp_path: Path,
) -> None:
    request, output = _case(tmp_path)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    assert observed.canonical_output_path.read_bytes() == output
    assert observed.output_source_mode == "STDOUT_ASSIGNED_OUTPUT"
    assert observed.terminal_negative_closure_eligible is False  # fixture backend
    arm = json.loads(observed.provider_arm_path.read_text(encoding="utf-8"))
    assert arm["output_contract"]["source_mode"] == "STDOUT_ASSIGNED_OUTPUT"
    assert arm["process_intent"]["stdin"]["relative_path"] == request.packet_path.relative_to(
        tmp_path
    ).as_posix()
    assert arm["process_intent"]["stream_limits"] == {
        "stdout_bytes": 4096,
        "stderr_bytes": 2048,
    }
    resumed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    assert resumed == observed


def test_worker_cannot_prewrite_provider_owned_stage(tmp_path: Path) -> None:
    request, _ = _case(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    staged = other / request.layout.staged_output_relative
    probe, _ = _case(
        other,
        script_suffix=(
            "from pathlib import Path; "
            f"p=Path({str(staged)!r}); p.parent.mkdir(parents=True,exist_ok=True); "
            "p.write_text('{}',encoding='utf-8')"
        ),
    )
    with pytest.raises(S.SkepticExecutionIncomplete) as caught:
        S.execute_or_resume_skeptic_execution(probe, parser_digest=assessment_digest)
    debt = json.loads(caught.value.provider_debt_path.read_text(encoding="utf-8"))
    assert debt["reason_code"] == "OUTPUT_SOURCE_CONTAMINATION"
    assert not probe.layout.canonical_output_path.exists()


def test_current_packet_and_published_bytes_are_resume_authority(tmp_path: Path) -> None:
    request, _ = _case(tmp_path)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    request.packet_path.write_bytes(request.packet_path.read_bytes() + b" ")
    with pytest.raises(S.SkepticExecutionWorkError):
        S.validate_skeptic_execution(request, observed, parser_digest=assessment_digest)

    # Restore only to isolate the published-byte check.
    request.packet_path.write_bytes(request.packet_path.read_bytes()[:-1])
    observed.canonical_output_path.write_bytes(b'{"rows":[]}\n')
    with pytest.raises(S.SkepticExecutionWorkError):
        S.validate_skeptic_execution(request, observed, parser_digest=assessment_digest)


def test_codex_is_explicitly_unsupported_until_same_boundary_exists(tmp_path: Path) -> None:
    policy = S.canonical_tool_policy(
        backend="codex",
        read_roots=[],
        staged_output=str(tmp_path / "stage" / "assessment.json"),
    )
    assert policy["terminal_negative_closure_authority"] == "UNSUPPORTED_DEBT"
    with pytest.raises(S.SkepticExecutionWorkError, match="UNSUPPORTED.*CODEX|CODEX.*UNSUPPORTED"):
        S.canonical_backend_argv(
            backend="codex",
            executable="codex",
            model="gpt-5",
            tool_policy=policy,
        )


def test_claude_2_1_214_rejects_unloadable_schema_dialect_before_launch(
    tmp_path: Path,
) -> None:
    schema = {**EXPECTED_SCHEMA, "$schema": "https://json-schema.org/draft/2020-12/schema"}
    policy = S.canonical_tool_policy(
        backend="claude",
        read_roots=[],
        staged_output=str(tmp_path / "stage" / "assessment.json"),
    )
    with pytest.raises(S.SkepticExecutionWorkError, match=r"omit \$schema"):
        S.canonical_backend_argv(
            backend="claude",
            executable="claude",
            model="claude-haiku-4-5",
            tool_policy=policy,
            expected_output_schema=schema,
        )


@pytest.mark.parametrize(
    "schema",
    (
        {
            **EXPECTED_SCHEMA,
            "properties": {
                **EXPECTED_SCHEMA["properties"],
                "open": {"type": "object", "properties": {"why": {"type": "string"}}},
            },
        },
        {
            **EXPECTED_SCHEMA,
            "$defs": {"row": {"$ref": "https://example.invalid/schema.json"}},
        },
    ),
)
def test_schema_is_closed_and_offline_before_launch(
    tmp_path: Path, schema: dict[str, Any]
) -> None:
    policy = S.canonical_tool_policy(
        backend="claude",
        read_roots=[],
        staged_output=str(tmp_path / "stage" / "assessment.json"),
    )
    with pytest.raises(S.SkepticExecutionWorkError, match="not closed|external"):
        S.canonical_backend_argv(
            backend="claude",
            executable="claude",
            model="claude-haiku-4-5",
            tool_policy=policy,
            expected_output_schema=schema,
        )


def test_non_exhaustive_process_scope_never_authorizes_terminal_negative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        S,
        "process_tree_termination_capability",
        lambda: {
            "platform": "LINUX",
            "exhaustive_descendant_termination_authority": False,
        },
    )
    assert S.terminal_negative_closure_eligibility("claude") == {
        "eligible": False,
        "reason": "NON_EXHAUSTIVE_PROVIDER_PROCESS_SCOPE",
    }


def test_adapter_uses_provider_process_scope_plus_restorable_boundary_not_process_kill() -> None:
    source = Path(S.__file__).read_text(encoding="utf-8")
    assert "process.kill()" not in source
    assert "_capture_boundary" in source
    assert "_reconcile_boundary" in source
    assert "CONTAINMENT_VIOLATION" in source


@pytest.mark.skipif(
    os.environ.get("PLAMEN_RUN_LIVE_CLAUDE_CANARY") != "1",
    reason="opt-in live Claude transport canary",
)
def test_live_claude_2_1_214_no_tool_stdout_transport(tmp_path: Path) -> None:
    executable = shutil.which("claude")
    if executable is None:
        pytest.skip("Claude CLI is unavailable")
    unsigned_shard = {
        "shard_id": "live-negative-shard-0001",
        "work_item_ids": ["NEG-LIVE-0001"],
    }
    shard = {**unsigned_shard, "shard_digest": _declared_digest(unsigned_shard)}
    unsigned_plan = {"schema_version": "test.live.plan.v1", "shards": [shard]}
    plan = {**unsigned_plan, "work_plan_digest": _declared_digest(unsigned_plan)}
    plan_path = tmp_path / "live_plan.json"
    plan_path.write_bytes(_canonical(plan))
    layout = S.skeptic_execution_layout(
        tmp_path,
        workflow="candidate_negative",
        run_id="RUN-LIVE-CLAUDE-V2",
        plan_digest=plan["work_plan_digest"],
        shard_id=shard["shard_id"],
        canonical_output="live_assessment.json",
    )
    policy = S.canonical_tool_policy(
        backend="claude", read_roots=[], staged_output=str(layout.staged_output_path)
    )
    model = os.environ.get("PLAMEN_LIVE_CLAUDE_MODEL", "claude-haiku-4-5")
    argv = S.canonical_backend_argv(
        backend="claude",
        executable=executable,
        model=model,
        tool_policy=policy,
        expected_output_schema=EXPECTED_SCHEMA,
    )
    environment_names = (
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    )
    environment = {
        name: os.environ[name] for name in environment_names if name in os.environ
    }
    request = S.prepare_skeptic_execution(
        scratchpad=tmp_path,
        workflow="candidate_negative",
        run_id="RUN-LIVE-CLAUDE-V2",
        plan_path=plan_path,
        expected_plan_digest=plan["work_plan_digest"],
        shard=shard,
        context={
            "methodology": "Return an unresolved row for the exact assigned item.",
            "source_context": [{"kind": "GENERIC_FIXTURE", "value": "no finding proof"}],
        },
        snapshot={"snapshot_id": "LIVE-CANARY", "source_tree_sha256": "b" * 64},
        rendered_prompt=(
            "Return exactly one rows entry with work_item_id NEG-LIVE-0001 and "
            "result OPEN. Do not return SUPPORTED_NEGATIVE."
        ),
        expected_output_schema=EXPECTED_SCHEMA,
        backend="claude",
        model=model,
        argv=argv,
        tool_policy=policy,
        worker_identity="LIVE_CLAUDE_SKEPTIC_WORKER",
        worker_invocation_id="LIVE-CLAUDE-WORKER-0001",
        assessor_identity="PLAMEN_SKEPTIC_CONSUMER",
        assessor_invocation_id="LIVE-CONSUMER-0001",
        canonical_output=layout.canonical_output_relative,
        timeout_seconds=180,
        cwd=tmp_path,
        environment=environment,
        environment_allowlist=tuple(environment),
        parser_digest=assessment_digest,
        stdout_limit_bytes=64 * 1024,
        stderr_limit_bytes=64 * 1024,
    )
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    resumed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    assert resumed == observed
    payload = json.loads(observed.canonical_output_path.read_text(encoding="utf-8"))
    assert payload == {
        "rows": [{"work_item_id": "NEG-LIVE-0001", "result": "OPEN"}]
    }
    assert observed.output_source_mode == "STDOUT_ASSIGNED_OUTPUT"
    assert observed.terminal_negative_closure_eligible is (
        S.timeout_process_tree_capability().get(
            "exhaustive_descendant_termination_authority"
        )
        is True
    )
