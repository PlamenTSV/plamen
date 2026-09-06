"""Fixture-first semantic_v1 -> disposable-executor WER integration.

The legacy WorkPlan path is intentionally unchanged.  Only a strictly replayed
semantic plan/execution/attempt plus its exact prompt snapshot may select the
disposable executor.  The coordinator must never fall back to direct provider
launch after that authority has been supplied.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any

import pytest

import isolated_execution_host as H
from semantic_prompt_snapshot import (
    SEMANTIC_COMPLETION_LANGUAGE,
    SemanticPlanPromptBundle,
    capture_methodology_files,
    compile_semantic_prompt_snapshot,
    methodology_bundle_digest,
    obligation_bundle_digest,
    output_contract_digest,
    semantic_input_manifest_digest,
)
from semantic_work_plan import (
    BackendArmExecutionIdentity,
    ExecutionAttemptIdentity,
    NATIVE_TEMPLATE_ID,
    SemanticAttemptBundle,
    SemanticExecutionBundle,
    SemanticWorkPlan,
)
import worker_execution_receipts as W


MODEL = "python-fixture-native"
ASSIGNMENT = "semantic-native-result"
MANIFEST_RAW = b'{"source_snapshot":"native-fixture"}\n'
TOOL_POLICY_RAW = b'{"capabilities":["ASSIGNED_OUTPUT_WRITE"]}\n'


def _digest(number: int) -> str:
    return format(number, "064x")


def _strict_json_digest(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8"))
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _semantic_authority() -> tuple[
    SemanticAttemptBundle,
    SemanticPlanPromptBundle,
]:
    methodologies = {
        "methodology://shared/native-fixture.md": b"emit exact JSON\n",
    }
    obligations = ("OB-NATIVE-EXACT-OUTPUT",)
    inputs = ("artifact://input/native-fixture.json",)
    outputs = ("artifact://output/result.json",)
    seed = SemanticWorkPlan.create(
        run_id="semantic-run-fixture",
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        semantic_generation=1,
        phase_semantic_id="depth",
        roster_id="depth.g1",
        roster_position=1,
        roster_denominator=1,
        semantic_work_unit_id="depth.native.fixture.001",
        role_id="depth.native.fixture",
        assignment_id=ASSIGNMENT,
        semantic_template_id=NATIVE_TEMPLATE_ID,
        source_snapshot_digest=hashlib.sha256(
            MANIFEST_RAW
        ).hexdigest(),
        deterministic_fact_snapshot_digests=(_digest(2),),
        semantic_input_manifest_digest=semantic_input_manifest_digest(inputs),
        semantic_prompt_snapshot_digest=_digest(3),
        methodology_bundle_digest=methodology_bundle_digest(
            capture_methodology_files(methodologies)
        ),
        obligation_bundle_digest=obligation_bundle_digest(obligations),
        output_contract_digest=output_contract_digest(
            logical_output_uris=outputs,
            output_schema="fixture.semantic-native-output.v1",
            completion_language=SEMANTIC_COMPLETION_LANGUAGE,
        ),
        tool_capability_manifest_digest=hashlib.sha256(
            TOOL_POLICY_RAW
        ).hexdigest(),
        resource_grant_digest=_digest(5),
        model_capability_tier="N0_NATIVE_DETERMINISTIC",
        required_capabilities=("ASSIGNED_OUTPUT_WRITE",),
        retry_policy={
            "max_attempts": 2,
            "same_prompt": True,
            "same_model_capability_tier": True,
            "same_tools": True,
            "model_change_requires_new_generation": True,
        },
        completion_policy={
            "requires_process_scope_empty": True,
            "requires_stream_eof": True,
            "requires_parser_acceptance": True,
            "requires_exact_output_denominator": True,
            "requires_phase_io_incorporation": True,
        },
    )
    snapshot = compile_semantic_prompt_snapshot(
        plan=seed,
        methodology_sources=methodologies,
        obligation_ids=obligations,
        logical_input_uris=inputs,
        logical_output_uris=outputs,
        output_schema="fixture.semantic-native-output.v1",
    )
    plan = replace(
        seed,
        semantic_prompt_snapshot_digest=snapshot.snapshot_digest,
        methodology_bundle_digest=methodology_bundle_digest(
            snapshot.methodology_files
        ),
    )
    prompt = SemanticPlanPromptBundle(plan=plan, snapshot=snapshot)
    execution = BackendArmExecutionIdentity.bind(
        plan,
        backend_arm_id="native.fixture.primary",
        backend="native",
        execution_generation=1,
        exact_model_id=MODEL,
        model_capability_tier="N0_NATIVE_DETERMINISTIC",
        capability_receipt_digest=_digest(6),
    )
    execution_bundle = SemanticExecutionBundle(
        plan=plan,
        execution=execution,
    )
    attempt = ExecutionAttemptIdentity.bind(
        execution,
        plan=plan,
        attempt_number=1,
    )
    return SemanticAttemptBundle(execution_bundle, attempt), prompt


def _case(
    root: Path,
    *,
    code: str = "import sys;sys.stdin.buffer.read();print('{\"ok\":true}')",
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    attempt, prompt = _semantic_authority()
    files = {
        "plan.json": attempt.execution_bundle.plan.to_bytes(),
        "manifest.json": MANIFEST_RAW,
        "intent.json": json.dumps(
            {
                "effective_backend": "native",
                "effective_model": MODEL,
                "environment_allowlist_sha256": (
                    W.environment_allowlist_sha256(())
                ),
                "semantic_profile": "semantic_v1",
                "semantic_work_unit_key": (
                    attempt.execution_bundle.plan.semantic_work_unit_key
                ),
                "execution_work_unit_key": (
                    attempt.execution_bundle.execution.execution_work_unit_key
                ),
                "attempt_key": attempt.attempt.attempt_key,
                "resource_grant_digest": (
                    attempt.execution_bundle.plan.resource_grant_digest
                ),
                "capability_receipt_digest": (
                    attempt.execution_bundle.execution.capability_receipt_digest
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n",
        "context.md": b"fixture context\n",
        "prompt.md": prompt.snapshot.prompt_bytes,
        "tool_policy.json": TOOL_POLICY_RAW,
    }
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    bindings = W.ExecutionBindings(
        run_id=attempt.execution_bundle.plan.run_id,
        shard_id="semantic-disposable-fixture",
        plan=W.BoundInput("plan.json"),
        manifest=W.BoundInput("manifest.json"),
        intent=W.BoundInput("intent.json"),
        context=W.BoundInput("context.md"),
        prompt=W.BoundInput("prompt.md"),
        tool_policy=W.BoundInput("tool_policy.json"),
        worker=W.PrincipalInvocation(
            "semantic-native-worker",
            attempt.attempt.attempt_key,
        ),
        effective_backend="native",
        effective_model=MODEL,
    )
    return {
        "scratchpad": root,
        "bindings": bindings,
        "argv": (sys.executable, "-I", "-S", "-c", code),
        "cwd": root,
        "output_scope_relative": "semantic-output",
        "expected_outputs": (
            W.ExpectedOutput(
                ASSIGNMENT,
                "result.json",
                "canonical/result.json",
            ),
        ),
        "parser_digest": _strict_json_digest,
        "environment": {},
        "environment_allowlist": (),
        "stdin_input": bindings.prompt,
        "timeout_seconds": timeout_seconds,
        "output_source_mode": W.STDOUT_ASSIGNED_OUTPUT,
        "publish_canonical": False,
        "process_scope_identity": "semantic-disposable-fixture-scope",
        "semantic_attempt_authority": attempt,
        "semantic_prompt_authority": prompt,
    }


def _semantic_records(root: Path, prefix: str) -> list[Path]:
    directory_id = hashlib.sha256(
        b"semantic-disposable-fixture"
    ).hexdigest()[:16]
    directory = (
        root
        / ".worker_execution_receipts"
        / f"semwer-{directory_id}"
    )
    return sorted(directory.glob(f"{prefix}_*.json"))


def _patch_fixture_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    starter: Any,
) -> None:
    class FixtureLifecycle:
        def __init__(
            self,
            payload_core: dict[str, Any],
            outer_arm_sha256: str,
        ) -> None:
            self._payload_core = payload_core
            self._outer_arm_sha256 = outer_arm_sha256
            self._attempt: Any = None
            self.terminal_receipt: dict[str, Any] | None = None

        def __enter__(self) -> Any:
            try:
                self._attempt = starter(
                    self._payload_core,
                    outer_arm_sha256=self._outer_arm_sha256,
                )
                return self._attempt
            except H.IsolatedExecutionHostError as exc:
                self.terminal_receipt = dict(exc.receipt)
                raise

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> bool:
            del exc_type, traceback
            abort = getattr(self._attempt, "abort", None)
            if exc is not None and callable(abort):
                self.terminal_receipt = abort(
                    reason_code="EXECUTOR_BOUNDARY_INTERRUPTED"
                )
            elif exc is not None:
                self.terminal_receipt = (
                    H.untrusted_wer_failure_receipt(
                        "EXECUTOR_BOUNDARY_FAILED"
                    )
                )
            return False

    monkeypatch.setattr(
        H,
        "isolated_wer_provider_lifecycle",
        lambda payload_core, *, outer_arm_sha256: FixtureLifecycle(
            payload_core,
            outer_arm_sha256,
        ),
    )


def test_untyped_legacy_call_cannot_silently_enter_semantic_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    direct = object()
    calls: list[str] = []

    def direct_call(**_kwargs: object) -> object:
        calls.append("direct")
        return direct

    def isolated_call(**_kwargs: object) -> object:
        calls.append("isolated")
        raise AssertionError("untyped call entered semantic executor")

    monkeypatch.setattr(W, "_run_observed_worker_direct", direct_call)
    monkeypatch.setattr(W, "_run_observed_worker_semantic_isolated", isolated_call)
    assert W.run_observed_worker(
        scratchpad="unused",
        bindings=object(),  # type: ignore[arg-type]
        argv=("unused",),
        cwd="unused",
        output_scope_relative="unused",
        expected_outputs=(),
        parser_digest=_strict_json_digest,
    ) is direct
    assert calls == ["direct"]


def test_semantic_authority_is_paired_and_never_falls_back_to_direct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt, prompt = _semantic_authority()
    isolated = object()
    calls: list[str] = []

    def direct_call(**_kwargs: object) -> object:
        calls.append("direct")
        raise AssertionError("semantic_v1 fell back to direct launch")

    def isolated_call(**kwargs: object) -> object:
        calls.append("isolated")
        assert kwargs["semantic_attempt_authority"] is attempt
        assert kwargs["semantic_prompt_authority"] is prompt
        return isolated

    monkeypatch.setattr(W, "_run_observed_worker_direct", direct_call)
    monkeypatch.setattr(W, "_run_observed_worker_semantic_isolated", isolated_call)
    common = {
        "scratchpad": "unused",
        "bindings": object(),
        "argv": ("unused",),
        "cwd": "unused",
        "output_scope_relative": "unused",
        "expected_outputs": (),
        "parser_digest": _strict_json_digest,
    }
    with pytest.raises(W.WorkerExecutionError, match="paired"):
        W.run_observed_worker(
            **common,
            semantic_attempt_authority=attempt,
        )
    assert W.run_observed_worker(
        **common,
        semantic_attempt_authority=attempt,
        semantic_prompt_authority=prompt,
    ) is isolated
    assert calls == ["isolated"]


def test_bound_semantic_plan_cannot_fall_back_when_authorities_omitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        W,
        "_run_observed_worker_direct",
        lambda **_kwargs: calls.append("direct"),
    )
    monkeypatch.setattr(
        W,
        "_run_observed_worker_semantic_isolated",
        lambda **_kwargs: calls.append("isolated"),
    )
    kwargs = _case(tmp_path)
    kwargs.pop("semantic_attempt_authority")
    kwargs.pop("semantic_prompt_authority")
    with pytest.raises(
        W.WorkerExecutionError,
        match="direct launch is forbidden",
    ):
        W.run_observed_worker(**kwargs)
    assert calls == []


def test_bound_plan_bytes_must_equal_typed_semantic_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path)
    (tmp_path / "plan.json").write_bytes(
        (tmp_path / "plan.json").read_bytes() + b" "
    )
    monkeypatch.setattr(
        H,
        "start_isolated_wer_provider",
        lambda *_args, **_kwargs: pytest.fail(
            "inconsistent semantic plan reached executor launch"
        ),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="bound plan bytes differ",
    ):
        W.run_observed_worker(**kwargs)
    assert not _semantic_records(tmp_path, "semantic_executor_arm")


@pytest.mark.parametrize(
    ("relative_path", "replacement", "message"),
    (
        (
            "manifest.json",
            b'{"source_snapshot":"changed"}\n',
            "source manifest differs",
        ),
        (
            "tool_policy.json",
            b'{"capabilities":[]}\n',
            "tool policy differs",
        ),
        (
            "intent.json",
            b'{"semantic_profile":"semantic_v1"}\n',
            "launch intent differs",
        ),
    ),
)
def test_bound_semantic_support_artifacts_cannot_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    replacement: bytes,
    message: str,
) -> None:
    kwargs = _case(tmp_path)
    (tmp_path / relative_path).write_bytes(replacement)
    monkeypatch.setattr(
        H,
        "start_isolated_wer_provider",
        lambda *_args, **_kwargs: pytest.fail(
            "inconsistent semantic artifact reached executor launch"
        ),
    )
    with pytest.raises(W.WorkerExecutionError, match=message):
        W.run_observed_worker(**kwargs)
    assert not _semantic_records(tmp_path, "semantic_executor_arm")


@pytest.mark.parametrize(
    "mode",
    (
        "runtime-error",
        "malformed-host-error",
        "request-sha-observer-error",
    ),
)
def test_unexpected_executor_boundary_failure_is_durable_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    class FailedAttempt:
        @property
        def request_sha256(self) -> str:
            if mode == "request-sha-observer-error":
                raise RuntimeError("fixture request digest observer failed")
            return _digest(35)

        def wait(self, **_kwargs: object) -> object:
            if mode in {
                "runtime-error",
                "request-sha-observer-error",
            }:
                raise RuntimeError("fixture boundary failure")
            raise H.IsolatedExecutionHostError(
                "forged fixture host error",
                receipt={
                    "payload": [],
                    "completion_authority": False,
                },
            )

    _patch_fixture_lifecycle(
        monkeypatch,
        lambda *_args, **_kwargs: FailedAttempt(),
    )
    with pytest.raises(W.WorkerExecutionIncomplete):
        W.run_observed_worker(**_case(tmp_path))
    debts = _semantic_records(tmp_path, "semantic_executor_debt")
    assert len(debts) == 1
    debt = json.loads(debts[0].read_text(encoding="utf-8"))
    assert debt["completion_authority"] is False
    assert debt["executor_receipt"]["completion_authority"] is False
    assert not _semantic_records(
        tmp_path,
        "semantic_executor_completion",
    )


@pytest.mark.parametrize("interrupt_type", (KeyboardInterrupt, SystemExit))
def test_baseexception_after_outer_arm_aborts_executor_and_persists_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt_type: type[BaseException],
) -> None:
    attempt_state = {"aborted": False}

    class InterruptedAttempt:
        request_sha256 = _digest(36)

        def wait(self, **_kwargs: object) -> object:
            raise interrupt_type("fixture interrupt after arm")

        def abort(self, *, reason_code: str) -> dict[str, Any]:
            assert reason_code == "EXECUTOR_BOUNDARY_INTERRUPTED"
            attempt_state["aborted"] = True
            return H.untrusted_wer_failure_receipt(reason_code)

    attempt = InterruptedAttempt()

    class InterruptedLifecycle:
        terminal_receipt: dict[str, Any] | None = None

        def __enter__(self) -> InterruptedAttempt:
            return attempt

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> bool:
            del exc_type, traceback
            if exc is not None:
                self.terminal_receipt = attempt.abort(
                    reason_code="EXECUTOR_BOUNDARY_INTERRUPTED"
                )
            return False

    monkeypatch.setattr(
        H,
        "start_isolated_wer_provider",
        lambda *_args, **_kwargs: attempt,
    )
    monkeypatch.setattr(
        H,
        "isolated_wer_provider_lifecycle",
        lambda *_args, **_kwargs: InterruptedLifecycle(),
        raising=False,
    )
    with pytest.raises(interrupt_type):
        W.run_observed_worker(**_case(tmp_path))
    assert attempt_state["aborted"] is True
    debts = _semantic_records(tmp_path, "semantic_executor_debt")
    assert len(debts) == 1
    debt = json.loads(debts[0].read_text(encoding="utf-8"))
    assert debt["completion_authority"] is False
    assert debt["reason_code"] == "EXECUTOR_BOUNDARY_INTERRUPTED"
    assert not _semantic_records(
        tmp_path,
        "semantic_executor_completion",
    )


def test_semantic_runtime_dependency_closure_is_exact_and_content_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def capture(
        payload_core: dict[str, Any],
        *,
        outer_arm_sha256: str,
    ) -> object:
        captured["payload_core"] = payload_core
        captured["outer_arm_sha256"] = outer_arm_sha256
        raise H.IsolatedExecutionHostError(
            "fixture stop after request capture",
            receipt=H.untrusted_wer_failure_receipt("FIXTURE_STOP"),
        )

    _patch_fixture_lifecycle(monkeypatch, capture)
    with pytest.raises(W.WorkerExecutionIncomplete):
        W.run_observed_worker(**_case(tmp_path))

    runtime = captured["payload_core"]["runtime_dependency_binding"]
    assert runtime["schema"] == (
        "plamen.semantic-wer-runtime-dependencies.v1"
    )
    module_names = {row["module_name"] for row in runtime["modules"]}
    assert {
        "owned_process_scope",
        "auxiliary_writable_root_lease",
        "provider_command_authority",
    } <= module_names
    loaded_schema_runtime = {
        name
        for name, module in sys.modules.items()
        if any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in (
                "attr",
                "attrs",
                "jsonschema",
                "referencing",
                "rpds",
            )
        )
        and getattr(module, "__file__", None)
    }
    assert loaded_schema_runtime <= module_names
    assert runtime["site_initialization"] == (
        "DISABLED_EXPLICIT_IMPORT_ROOTS"
    )
    distributions = {
        row["distribution_name"]: row
        for row in runtime["distributions"]
    }
    assert distributions["jsonschema"]["version"]
    implementation_paths = {
        row["path"]
        for row in captured["payload_core"]["implementation_files"]
    }
    assert str(Path(sys.executable).resolve(strict=True)) in (
        implementation_paths
    )
    assert {
        row["path"]
        for row in runtime["modules"]
        if row["path"] is not None
    } <= implementation_paths
    outer_arm = json.loads(
        _semantic_records(
            tmp_path,
            "semantic_executor_arm",
        )[0].read_text(encoding="utf-8")
    )
    assert outer_arm["runtime_dependency_sha256"] == runtime[
        "runtime_dependency_sha256"
    ]


def test_semantic_runtime_dependency_closure_ignores_incidental_live_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before, _ = W._semantic_runtime_dependency_binding()

    def fixture_only_callback() -> None:
        raise AssertionError("fixture-only callback must never be invoked")

    monkeypatch.setattr(
        H,
        "_fixture_only_incidental_value",
        fixture_only_callback,
        raising=False,
    )
    after, _ = W._semantic_runtime_dependency_binding()

    assert after == before
    assert __name__ not in {
        row["module_name"] for row in after["modules"]
    }


def test_semantic_native_rejects_explicit_environment_before_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path)
    kwargs["environment"] = {"SEMANTIC_SECRET": "red"}
    kwargs["environment_allowlist"] = ("SEMANTIC_SECRET",)
    monkeypatch.setattr(
        H,
        "start_isolated_wer_provider",
        lambda *_args, **_kwargs: pytest.fail(
            "secret-bearing environment reached executor arm"
        ),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="empty environment",
    ):
        W.run_observed_worker(**kwargs)
    assert not _semantic_records(tmp_path, "semantic_executor_arm")


def test_windows_semantic_command_budget_rejects_before_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path)
    kwargs["argv"] = (
        sys.executable,
        "-I",
        "-S",
        "-c",
        "x" * 40_065,
    )
    monkeypatch.setattr(
        H,
        "start_isolated_wer_provider",
        lambda *_args, **_kwargs: pytest.fail(
            "over-budget command reached executor arm"
        ),
    )
    with pytest.raises(
        W.WorkerExecutionError,
        match="Windows command-line budget",
    ):
        W.run_observed_worker(**kwargs)
    assert not _semantic_records(tmp_path, "semantic_executor_arm")


def test_scope_lease_wait_budget_is_not_the_worker_runtime_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A short target timeout must not turn lock contention into setup debt."""

    observed: dict[str, float] = {}

    class RefusingScope:
        def __init__(
            self,
            *,
            lease_acquisition_deadline_monotonic: float,
            **_kwargs: object,
        ) -> None:
            observed["remaining"] = (
                lease_acquisition_deadline_monotonic - time.monotonic()
            )
            raise RuntimeError("fixture stops before process creation")

    monkeypatch.setattr(W, "_OwnedProcessTree", RefusingScope)
    kwargs = _case(tmp_path)
    kwargs.pop("semantic_attempt_authority")
    kwargs.pop("semantic_prompt_authority")
    kwargs["timeout_seconds"] = 0.2
    kwargs["lock_timeout_seconds"] = 7.0
    with pytest.raises(W.WorkerExecutionIncomplete):
        W._run_observed_worker_direct(**kwargs)

    # The serialized-scope wait is a lock/setup concern.  It must retain the
    # caller's lock budget instead of inheriting the target's 200 ms runtime.
    assert observed["remaining"] >= 5.0


def test_implementation_drift_after_outer_arm_is_durable_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    implementation = tmp_path / "fixture_implementation.py"
    implementation.write_bytes(b"VALUE = 1\n")
    captured: dict[str, Any] = {}

    def drift_after_arm(
        payload_core: dict[str, Any],
        *,
        outer_arm_sha256: str,
    ) -> object:
        captured["payload_core"] = payload_core
        captured["outer_arm_sha256"] = outer_arm_sha256
        implementation.write_bytes(b"VALUE = 2\n")
        # The exact child-side pre-authority replay must now fail.
        H.wer_provider_request_core_sha256(payload_core)
        raise AssertionError("implementation drift was accepted")

    _patch_fixture_lifecycle(monkeypatch, drift_after_arm)
    kwargs = _case(tmp_path)
    kwargs["implementation_files"] = (implementation,)
    with pytest.raises(W.WorkerExecutionIncomplete):
        W.run_observed_worker(**kwargs)
    records = captured["payload_core"]["implementation_files"]
    fixture_record = next(
        row for row in records if row["path"] == str(implementation)
    )
    assert fixture_record["sha256"] == hashlib.sha256(
        b"VALUE = 1\n"
    ).hexdigest()
    arms = _semantic_records(tmp_path, "semantic_executor_arm")
    assert len(arms) == 1
    arm = json.loads(arms[0].read_text(encoding="utf-8"))
    assert len(arm["implementation_files_sha256"]) == 64
    assert arm["implementation_files"] == records
    assert len(_semantic_records(tmp_path, "semantic_executor_debt")) == 1
    assert not _semantic_records(
        tmp_path,
        "semantic_executor_completion",
    )


def test_forged_post_executor_receipt_is_durable_debt_not_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ForgedAttempt:
        request_sha256 = _digest(40)

        def wait(self, **_kwargs: object) -> object:
            return H.IsolatedWERCompleted(
                coordinator_receipt={
                    "completion_authority": True,
                    "receipt_sha256": _digest(41),
                    "payload": {
                        "executor_population_zero_proven": True,
                    },
                },
                child_receipt={
                    "completion_authority": True,
                    "receipt_sha256": _digest(42),
                    "payload": {
                        "inner_receipt_relative_path": (
                            "missing/completion.json"
                        ),
                    },
                },
            )

    _patch_fixture_lifecycle(
        monkeypatch,
        lambda *_args, **_kwargs: ForgedAttempt(),
    )
    with pytest.raises(W.WorkerExecutionIncomplete) as caught:
        W.run_observed_worker(**_case(tmp_path))
    debts = _semantic_records(tmp_path, "semantic_executor_debt")
    assert len(debts) == 1
    debt = json.loads(debts[0].read_text(encoding="utf-8"))
    assert debt["reason_code"] == "EXECUTOR_COMPLETION_REPLAY_FAILED"
    assert debt["completion_authority"] is False
    assert caught.value.debt_path == debts[0]
    assert not _semantic_records(
        tmp_path,
        "semantic_executor_completion",
    )


def test_wer_handler_rejects_legacy_completion_receipt_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def capture(
        payload_core: dict[str, Any],
        *,
        outer_arm_sha256: str,
    ) -> object:
        captured["payload_core"] = payload_core
        captured["outer_arm_sha256"] = outer_arm_sha256
        raise H.IsolatedExecutionHostError(
            "fixture stop",
            receipt=H._unbound_wer_debt_receipt(
                "PLATFORM_UNSUPPORTED"
            ),
        )

    _patch_fixture_lifecycle(monkeypatch, capture)
    with pytest.raises(W.WorkerExecutionIncomplete):
        W.run_observed_worker(**_case(tmp_path))
    request = H._build_wer_provider_request(
        captured["payload_core"],
        outer_arm_sha256=captured["outer_arm_sha256"],
    )
    forged = H._build_terminal_receipt(
        receipt_type="COMPLETED",
        request=request,
        executor_pid=7171,
        completion_authority=True,
        payload={
            "args": list(request["payload"]["argv"]),
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "duration_s": 0.1,
            "process_tree_terminated": True,
            "containment_capability": {"platform": "WINDOWS"},
        },
    )
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="receipt type",
    ):
        H._validate_terminal_receipt(
            forged,
            expected_request=request,
            expected_executor_pid=7171,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_semantic_native_success_crosslinks_exact_nested_authority(
    tmp_path: Path,
) -> None:
    completed = W.run_observed_worker(**_case(tmp_path))
    W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        parser_digest=_strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
    )
    arms = _semantic_records(tmp_path, "semantic_executor_arm")
    receipts = _semantic_records(
        tmp_path,
        "semantic_executor_completion",
    )
    assert len(arms) == len(receipts) == 1
    outer_arm = json.loads(arms[0].read_text(encoding="utf-8"))
    outer = json.loads(receipts[0].read_text(encoding="utf-8"))
    inner_arm = json.loads(completed.arm_path.read_text(encoding="utf-8"))
    inner_completion = json.loads(
        completed.receipt_path.read_text(encoding="utf-8")
    )
    assert outer["outer_arm_sha256"] == outer_arm["outer_arm_sha256"]
    assert outer["inner_arm_sha256"] == completed.arm_sha256
    assert (
        outer["inner_completion_sha256"]
        == completed.completion_sha256
    )
    assert (
        outer["executor_receipt_sha256"]
        == outer["executor_receipt"]["receipt_sha256"]
    )
    assert outer["executor_receipt"]["completion_authority"] is True
    assert outer["executor_receipt"]["payload"][
        "executor_population_zero_proven"
    ] is True
    child_payload = outer["executor_receipt"]["payload"][
        "child_receipt"
    ]["payload"]
    assert outer["executor_receipt"]["payload"][
        "runtime_dependency_sha256"
    ] == outer_arm["runtime_dependency_sha256"]
    assert child_payload["runtime_dependency_sha256"] == outer_arm[
        "runtime_dependency_sha256"
    ]
    assert child_payload["implementation_files_sha256"] == (
        outer_arm["implementation_files_sha256"]
    )
    assert inner_arm["process_intent"]["implementation_files"] == (
        outer_arm["implementation_files"]
    )
    parent = inner_arm["process_intent"]["disposable_executor_parent"]
    assert parent["executor_request_sha256"] == outer[
        "executor_request_sha256"
    ]
    assert parent["outer_arm_sha256"] == outer_arm["outer_arm_sha256"]
    assert inner_completion["process_observation"][
        "process_population_zero_proven"
    ] is True
    prompt_record = inner_arm["bindings"]["inputs"]["prompt"]
    assert prompt_record["sha256"] == _semantic_authority()[
        1
    ].snapshot.prompt_sha256


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
@pytest.mark.parametrize("mode", ("timeout", "cancel"))
def test_semantic_executor_timeout_and_cancel_are_durable_debt(
    tmp_path: Path,
    mode: str,
) -> None:
    kwargs = _case(
        tmp_path,
        code="import time;time.sleep(60)",
        timeout_seconds=(0.25 if mode == "timeout" else 30.0),
    )
    if mode == "cancel":
        cancelled = threading.Event()
        cancelled.set()
        kwargs["cancel_token"] = cancelled
    with pytest.raises(W.WorkerExecutionIncomplete) as caught:
        W.run_observed_worker(**kwargs)
    debts = _semantic_records(tmp_path, "semantic_executor_debt")
    assert len(debts) == 1
    debt = json.loads(debts[0].read_text(encoding="utf-8"))
    assert debt["completion_authority"] is False
    assert debt["executor_receipt"]["completion_authority"] is False
    assert not _semantic_records(
        tmp_path,
        "semantic_executor_completion",
    )
    assert caught.value.debt_path == debts[0]


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_executor_death_or_forged_receipt_never_mints_wer_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_lifecycle = H.isolated_wer_provider_lifecycle

    class CrashLifecycle:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._inner = real_lifecycle(*args, **kwargs)

        @property
        def terminal_receipt(self) -> object:
            return self._inner.terminal_receipt

        def __enter__(self) -> object:
            attempt = self._inner.__enter__()
            handle = attempt._executor_process_handle_for_test()
            kernel32 = __import__("ctypes").WinDLL(
                "kernel32",
                use_last_error=True,
            )
            kernel32.TerminateProcess(
                __import__("ctypes").c_void_p(handle),
                91,
            )
            return attempt

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> bool:
            return self._inner.__exit__(exc_type, exc, traceback)

    monkeypatch.setattr(
        H,
        "isolated_wer_provider_lifecycle",
        lambda *args, **kwargs: CrashLifecycle(*args, **kwargs),
    )
    with pytest.raises(W.WorkerExecutionIncomplete):
        W.run_observed_worker(**_case(tmp_path))
    debts = _semantic_records(tmp_path, "semantic_executor_debt")
    assert len(debts) == 1
    debt = json.loads(debts[0].read_text(encoding="utf-8"))
    assert debt["executor_receipt"]["payload"]["reason_code"] in {
        "EXECUTOR_DIED_WITHOUT_RECEIPT",
        "EXECUTOR_RECEIPT_INVALID",
    }
    assert not _semantic_records(
        tmp_path,
        "semantic_executor_completion",
    )


@pytest.mark.skipif(os.name == "nt", reason="portable fail-closed contract")
def test_semantic_executor_is_fail_closed_when_parent_death_is_unavailable(
    tmp_path: Path,
) -> None:
    with pytest.raises(W.WorkerExecutionIncomplete):
        W.run_observed_worker(**_case(tmp_path))
    debt = json.loads(
        _semantic_records(
            tmp_path,
            "semantic_executor_debt",
        )[0].read_text(encoding="utf-8")
    )
    assert debt["executor_receipt"]["payload"]["reason_code"] == (
        "PLATFORM_UNSUPPORTED"
    )
    assert debt["completion_authority"] is False
