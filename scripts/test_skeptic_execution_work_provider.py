"""Adversarial and resume coverage for skeptic stdout transport v2.

The former version of this suite exercised model-authored files plus an adapter
filesystem snapshot.  These tests preserve its useful real-subprocess, tamper,
resume, and partial-state coverage against the provider-owned stdout boundary.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys

import pytest

import skeptic_execution_work as S
import worker_execution_receipts as X
from test_skeptic_execution_work_provider_v2 import (
    EXPECTED_SCHEMA,
    _case,
    assessment_digest,
)


@pytest.mark.parametrize("workflow", ("candidate_negative", "application_skeptic"))
def test_real_fixture_subprocess_binds_stdout_cas_and_publication(
    tmp_path: Path, workflow: str
) -> None:
    request, expected = _case(tmp_path, workflow=workflow)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    replay = S.validate_skeptic_execution(
        request, observed, parser_digest=assessment_digest
    )
    assert replay == observed
    assert observed.request_digest == request.request_digest
    assert observed.canonical_output_path.read_bytes() == expected
    assert observed.output_source_mode == "STDOUT_ASSIGNED_OUTPUT"
    assert observed.terminal_negative_closure_eligible is False


def test_provider_backed_resume_never_relaunches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, _ = _case(tmp_path)
    first = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("resume relaunched worker")

    monkeypatch.setattr(S, "run_observed_worker", forbidden)
    resumed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    assert resumed == first


@pytest.mark.parametrize(
    "target,mutation",
    (
        ("provider_completion_path", "delete"),
        ("provider_publish_path", "tamper"),
        ("canonical_output_path", "tamper"),
        ("provider_arm_path", "tamper"),
    ),
)
def test_missing_or_tampered_provider_authority_blocks_resume_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    mutation: str,
) -> None:
    request, _ = _case(tmp_path)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    victim = getattr(observed, target)
    if mutation == "delete":
        victim.unlink()
    else:
        victim.write_bytes(victim.read_bytes() + b" ")

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("invalid persisted state relaunched worker")

    monkeypatch.setattr(S, "run_observed_worker", forbidden)
    with pytest.raises(S.SkepticExecutionWorkError):
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )


def test_raw_cached_assessment_without_provider_chain_is_not_authority(
    tmp_path: Path,
) -> None:
    request, output = _case(tmp_path)
    request.layout.canonical_output_path.write_bytes(output)
    with pytest.raises(S.SkepticExecutionWorkError, match="without provider"):
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )


@pytest.mark.parametrize(
    "relative",
    (
        "shard.lock",
        "arm_" + "0" * 64 + ".json",
        "publish_arm_" + "0" * 64 + ".json",
        "blobs/output_" + "0" * 64 + ".bin",
    ),
)
def test_any_partial_provider_state_blocks_relaunch(
    tmp_path: Path,
    relative: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, _ = _case(tmp_path)
    partial = (
        tmp_path
        / ".worker_execution_receipts"
        / request.layout.provider_shard_id
        / relative
    )
    partial.parent.mkdir(parents=True, exist_ok=True)
    partial.write_bytes(b"partial")

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("partial provider state relaunched worker")

    monkeypatch.setattr(S, "run_observed_worker", forbidden)
    with pytest.raises(S.SkepticExecutionWorkError, match="incomplete|ambiguous"):
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )


@pytest.mark.parametrize(
    "field",
    (
        "plan_path",
        "manifest_path",
        "intent_path",
        "context_path",
        "instructions_path",
        "packet_path",
        "tool_policy_path",
        "expected_output_schema_path",
    ),
)
def test_any_bound_input_tamper_blocks_launch_or_resume(
    tmp_path: Path, field: str
) -> None:
    request, _ = _case(tmp_path)
    victim = getattr(request, field)
    victim.write_bytes(victim.read_bytes() + b" ")
    with pytest.raises(S.SkepticExecutionWorkError):
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("model", "forged-model"),
        ("worker_identity", "FORGED_WORKER"),
        ("stdout_limit_bytes", 123),
        ("terminal_negative_closure_eligible", True),
    ),
)
def test_replaced_request_fields_fail_before_launch(
    tmp_path: Path, field: str, value: object
) -> None:
    request, _ = _case(tmp_path)
    forged = replace(request, **{field: value})
    with pytest.raises(S.SkepticExecutionWorkError):
        S.execute_or_resume_skeptic_execution(
            forged, parser_digest=assessment_digest
        )


def test_replaced_layout_destination_and_same_byte_path_alias_fail_before_launch(
    tmp_path: Path,
) -> None:
    request, _ = _case(tmp_path)
    forged_layout = replace(
        request,
        layout=replace(
            request.layout,
            canonical_output_relative="forged.json",
            provider_publish_relative="forged.json",
        ),
    )
    with pytest.raises(S.SkepticExecutionWorkError, match="intent|layout|output"):
        S.execute_or_resume_skeptic_execution(
            forged_layout, parser_digest=assessment_digest
        )

    alias = tmp_path / "same_bytes_plan.json"
    alias.write_bytes(request.plan_path.read_bytes())
    forged_path = replace(request, plan_path=alias)
    with pytest.raises(S.SkepticExecutionWorkError, match="path|intent"):
        S.execute_or_resume_skeptic_execution(
            forged_path, parser_digest=assessment_digest
        )


def test_source_plan_mutation_after_prepare_cannot_change_bound_packet(
    tmp_path: Path,
) -> None:
    request, expected = _case(tmp_path)
    source = tmp_path / "candidate_negative_plan.json"
    bound_before = request.plan_path.read_bytes()
    packet_before = request.packet_path.read_bytes()
    source.write_text('{"untrusted":"later"}\n', encoding="utf-8")
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    assert observed.canonical_output_path.read_bytes() == expected
    assert request.plan_path.read_bytes() == bound_before
    assert request.packet_path.read_bytes() == packet_before


def test_provider_effective_environment_is_bound_in_intent_and_arm(
    tmp_path: Path,
) -> None:
    request, _ = _case(tmp_path)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    intent = json.loads(request.intent_path.read_text(encoding="utf-8"))
    arm = json.loads(observed.provider_arm_path.read_text(encoding="utf-8"))
    assert intent["environment_allowlist_sha256"] == arm["environment"][
        "allowlist_sha256"
    ]
    assert intent["environment_effective_sha256"] == arm["environment"][
        "effective_sha256"
    ]


def test_provider_chain_with_different_effective_environment_is_debt(
    tmp_path: Path,
) -> None:
    request, _ = _case(
        tmp_path,
        environment={"BOUND": "intended"},
        environment_allowlist=("BOUND",),
    )
    strict_parser = S._make_strict_parser(request, assessment_digest)
    X.run_observed_worker(
        scratchpad=tmp_path,
        bindings=S._execution_bindings(request),
        argv=request.argv,
        cwd=request.cwd,
        output_scope_relative=request.layout.output_scope_relative,
        expected_outputs=(
            X.ExpectedOutput(
                request.shard_id,
                "assessment.json",
                request.layout.canonical_output_relative,
            ),
        ),
        parser_digest=strict_parser,
        environment={"BOUND": "different"},
        environment_allowlist=("BOUND",),
        stdin_input=X.BoundInput(
            request.packet_path.relative_to(tmp_path).as_posix()
        ),
        timeout_seconds=request.timeout_seconds,
        output_source_mode=X.STDOUT_ASSIGNED_OUTPUT,
        stdout_limit_bytes=request.stdout_limit_bytes,
        stderr_limit_bytes=request.stderr_limit_bytes,
    )
    with pytest.raises(S.SkepticExecutionWorkError, match="environment"):
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )


@pytest.mark.parametrize("ambiguity", ("second_completion", "completion_with_debt"))
def test_ambiguous_provider_chains_never_resume(
    tmp_path: Path, ambiguity: str
) -> None:
    request, _ = _case(tmp_path)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    evidence = observed.provider_completion_path.parent
    if ambiguity == "second_completion":
        (evidence / ("completion_" + "0" * 64 + ".json")).write_bytes(
            observed.provider_completion_path.read_bytes()
        )
    else:
        (evidence / ("debt_" + "0" * 64 + ".json")).write_text(
            "{}\n", encoding="utf-8"
        )
    with pytest.raises(S.SkepticExecutionWorkError):
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )


def test_nonzero_child_leaves_provider_debt_and_no_canonical_output(
    tmp_path: Path,
) -> None:
    request, _ = _case(tmp_path, script_suffix="raise SystemExit(17)")
    with pytest.raises(S.SkepticExecutionIncomplete) as caught:
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )
    assert caught.value.provider_debt_path is not None
    assert not request.layout.canonical_output_path.exists()


def test_stdout_schema_violation_leaves_provider_debt(tmp_path: Path) -> None:
    request, _ = _case(tmp_path, stdout=b"```json\n{}\n```\n")
    with pytest.raises(S.SkepticExecutionIncomplete) as caught:
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )
    assert caught.value.provider_debt_path is not None
    assert not request.layout.canonical_output_path.exists()


def test_stdout_stream_limit_is_bound_and_fail_closed(tmp_path: Path) -> None:
    request, _ = _case(tmp_path, stdout_limit_bytes=8)
    with pytest.raises(S.SkepticExecutionIncomplete) as caught:
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )
    debt = json.loads(caught.value.provider_debt_path.read_text(encoding="utf-8"))
    assert debt["reason_code"] == "STREAM_LIMIT_EXCEEDED"
    assert not request.layout.canonical_output_path.exists()


def test_exact_packet_plan_shard_model_policy_parser_and_limits_are_bound(
    tmp_path: Path,
) -> None:
    request, _ = _case(tmp_path)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    intent = json.loads(request.intent_path.read_text(encoding="utf-8"))
    arm = json.loads(observed.provider_arm_path.read_text(encoding="utf-8"))
    assert intent["plan_digest"] == request.plan_digest
    assert intent["shard_digest"] == request.shard_digest
    assert intent["effective_model"] == request.model
    assert intent["caller_parser_binding"] == request.caller_parser_binding
    assert intent["resolved_executable"] == request.resolved_argv[0]
    assert len(intent["resolved_executable_sha256"]) == 64
    assert arm["bindings"]["inputs"]["prompt"]["relative_path"] == (
        request.packet_path.relative_to(tmp_path).as_posix()
    )
    assert arm["output_contract"]["source_mode"] == "STDOUT_ASSIGNED_OUTPUT"
    assert arm["process_intent"]["stream_limits"] == {
        "stdout_bytes": request.stdout_limit_bytes,
        "stderr_bytes": request.stderr_limit_bytes,
    }


def test_exact_claude_argv_is_legacy_safe_no_tool_profile(tmp_path: Path) -> None:
    output = tmp_path / "stage" / "assessment.json"
    policy = S.canonical_tool_policy(
        backend="claude", read_roots=[], staged_output=str(output)
    )
    argv = S.canonical_backend_argv(
        backend="claude",
        executable="claude",
        model="claude-opus-test",
        tool_policy=policy,
        expected_output_schema=EXPECTED_SCHEMA,
    )
    assert S.validate_skeptic_backend_contract(
        backend="claude",
        model="claude-opus-test",
        argv=argv,
        tool_policy=policy,
        expected_output_schema=EXPECTED_SCHEMA,
    ) == argv
    assert "--safe-mode" in argv
    assert argv[argv.index("--tools") + 1] == ""
    assert argv[argv.index("--setting-sources") + 1] == ""
    assert "--dangerously-skip-permissions" not in argv


def test_codex_profile_is_typed_debt(tmp_path: Path) -> None:
    policy = S.canonical_tool_policy(
        backend="codex",
        read_roots=[],
        staged_output=str(tmp_path / "stage" / "assessment.json"),
    )
    with pytest.raises(S.SkepticExecutionWorkError, match="UNSUPPORTED_DEBT"):
        S.validate_skeptic_backend_contract(
            backend="codex",
            model="gpt-test",
            argv=("codex", "exec", "-"),
            tool_policy=policy,
        )


def test_process_scope_capability_is_provider_owned_and_candid() -> None:
    capability = S.timeout_process_tree_capability()
    assert capability["descendant_termination_required"] is True
    assert "exhaustive_descendant_termination_authority" in capability
    if sys.platform == "win32":
        assert capability["exhaustive_descendant_termination_authority"] is True
        assert capability["termination_scope"] == "JOB_TREE"
