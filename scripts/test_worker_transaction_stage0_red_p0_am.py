"""P0-AM Stage-0 fixtures: freeze raw launches before WorkerTransaction cutover.

The AST inventory is intentionally green on the pre-migration tree and fails
only when a new raw launch/kill site appears.  The behavioral fixtures are
intentionally red until the unified WorkerTransaction boundary exists.  They
use only local Python children and deterministic fault seams; no Claude/Codex
network or authentication path is exercised.
"""
from __future__ import annotations

import ast
from collections import Counter
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import sys
import threading
import time
import warnings
from typing import Any, Callable, Mapping

import pytest

import worker_execution_receipts as W


_RUNTIME_LAUNCH_FILES = (
    "scripts/plamen_driver.py",
    "scripts/pty_exec.py",
    "scripts/worker_execution_receipts.py",
    "scripts/fuzz_workspace_authority.py",
    "scripts/owned_process_runner.py",
    "scripts/recon_prepass.py",
    "scripts/mechanical_verify.py",
    "scripts/audit_snapshot.py",
    "scripts/supply_chain_gate.py",
    "scripts/spike_mechanical_poc.py",
    "scripts/plamen_display.py",
    "scripts/preflight_pty_transports.py",
)
_RAW_PROCESS_CALLS = frozenset(
    {
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "winpty.PtyProcess.spawn",
        "os.killpg",
        "os.system",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
    }
)

# Warning-mode ratchet: removals are allowed during migration; additions are
# not.  Counts matter so another call cannot be hidden inside an already-known
# function.  The two explicitly retired driver launchers remain visible as
# deletion targets rather than becoming permanent provider exemptions.
_RAW_LAUNCH_BASELINE = Counter(
    {
        ("scripts/plamen_driver.py", "_terminate_process_tree", "subprocess.run"): 1,
        ("scripts/plamen_driver.py", "_terminate_process_tree", "os.killpg"): 2,
        (
            "scripts/plamen_driver.py",
            "_execute_dynamic_verifier_launch",
            "subprocess.Popen",
        ): 1,
        (
            "scripts/plamen_driver.py",
            "_run_verify_recovery_shard_legacy_retired",
            "subprocess.Popen",
        ): 1,
        ("scripts/plamen_driver.py", "_run_one_codex_exec", "subprocess.Popen"): 1,
        (
            "scripts/plamen_driver.py",
            "_run_one_claude_headless_breadth_worker",
            "subprocess.Popen",
        ): 1,
        ("scripts/plamen_driver.py", "run_phase", "subprocess.Popen"): 1,
        ("scripts/pty_exec.py", "spawn", "winpty.PtyProcess.spawn"): 1,
        ("scripts/pty_exec.py", "spawn", "subprocess.Popen"): 1,
        ("scripts/pty_exec.py", "terminate", "subprocess.run"): 1,
        ("scripts/pty_exec.py", "terminate", "os.killpg"): 2,
        (
            "scripts/worker_execution_receipts.py",
            "terminate",
            "os.killpg",
        ): 1,
        (
            "scripts/worker_execution_receipts.py",
            "run_observed_worker",
            "subprocess.Popen",
        ): 1,
        (
            "scripts/fuzz_workspace_authority.py",
            "_popen_contained",
            "subprocess.Popen",
        ): 1,
        (
            "scripts/fuzz_workspace_authority.py",
            "_terminate_process_tree",
            "subprocess.run",
        ): 1,
        (
            "scripts/fuzz_workspace_authority.py",
            "_terminate_process_tree",
            "os.killpg",
        ): 2,
        (
            "scripts/owned_process_runner.py",
            "run_owned_process",
            "subprocess.Popen",
        ): 1,
        (
            "scripts/recon_prepass.py",
            "_hardened_tree_kill",
            "subprocess.run",
        ): 1,
        ("scripts/recon_prepass.py", "_hardened_tree_kill", "os.killpg"): 1,
        ("scripts/recon_prepass.py", "_run_hardened", "subprocess.Popen"): 1,
        ("scripts/audit_snapshot.py", "_git_head", "subprocess.run"): 1,
        ("scripts/audit_snapshot.py", "_git_submodule_state", "subprocess.run"): 1,
        ("scripts/audit_snapshot.py", "_command_version", "subprocess.run"): 1,
        (
            "scripts/supply_chain_gate.py",
            "_call_offline_scanner",
            "subprocess.run",
        ): 1,
        ("scripts/spike_mechanical_poc.py", "run_forge_test", "subprocess.run"): 1,
        (
            "scripts/plamen_display.py",
            "_terminate_diagnosis_process",
            "subprocess.run",
        ): 1,
        (
            "scripts/plamen_display.py",
            "print_failure_diagnosis",
            "subprocess.Popen",
        ): 1,
        (
            "scripts/preflight_pty_transports.py",
            "get_claude_version",
            "subprocess.run",
        ): 1,
    }
)


def _symbol(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _symbol(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _raw_launch_inventory(repo: Path) -> Counter[tuple[str, str, str]]:
    result: Counter[tuple[str, str, str]] = Counter()
    for relative in _RUNTIME_LAUNCH_FILES:
        path = repo / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            callee = _symbol(node.func)
            if callee not in _RAW_PROCESS_CALLS:
                continue
            owner = "<module>"
            current: ast.AST = node
            while current in parents:
                current = parents[current]
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = current.name
                    break
            result[(relative, owner, callee)] += 1
    return result


def test_raw_launch_warning_inventory_has_no_unreviewed_expansion() -> None:
    repo = Path(__file__).resolve().parents[1]
    current = _raw_launch_inventory(repo)
    unexpected = current - _RAW_LAUNCH_BASELINE
    rendered = "\n".join(
        f"{count}x {path}:{owner}:{callee}"
        for (path, owner, callee), count in sorted(current.items())
    )
    warnings.warn(
        "P0-AM raw launcher warning inventory (migration targets):\n" + rendered,
        UserWarning,
        stacklevel=1,
    )
    assert not unexpected, (
        "new raw process/PTY lifecycle authority was added outside "
        f"WorkerTransaction: {dict(unexpected)!r}"
    )


def _strict_result_digest(_path: Path, raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8", errors="strict"))
    if value != {"status": "PROPOSED"}:
        raise ValueError("unexpected staged result")
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _bindings(tmp_path: Path, shard: str) -> W.ExecutionBindings:
    launch = tmp_path / f"launch-{shard}"
    launch.mkdir()
    allowlist_sha = W.environment_allowlist_sha256(())
    for name, raw in {
        "plan.json": "{}\n",
        "manifest.json": "{}\n",
        "intent.json": json.dumps(
            {
                "effective_backend": "native",
                "effective_model": "python-fixture",
                "environment_allowlist_sha256": allowlist_sha,
            },
            sort_keys=True,
        )
        + "\n",
        "context.md": "fixture context\n",
        "prompt.md": "fixture prompt\n",
        "tool-policy.json": '{"network":false}\n',
    }.items():
        (launch / name).write_text(raw, encoding="utf-8")
    prefix = launch.relative_to(tmp_path).as_posix()
    return W.ExecutionBindings(
        run_id="p0-am-stage0",
        shard_id=shard,
        plan=W.BoundInput(f"{prefix}/plan.json"),
        manifest=W.BoundInput(f"{prefix}/manifest.json"),
        intent=W.BoundInput(f"{prefix}/intent.json"),
        context=W.BoundInput(f"{prefix}/context.md"),
        prompt=W.BoundInput(f"{prefix}/prompt.md"),
        tool_policy=W.BoundInput(f"{prefix}/tool-policy.json"),
        worker=W.PrincipalInvocation(f"worker-{shard}", f"attempt-{shard}"),
        # Legacy WER still requires a named assessor.  P0-AM will remove this
        # name-only authority, but it must not mask the lifecycle REDs here.
        assessors=(
            W.PrincipalInvocation(
                f"fixture-observer-{shard}",
                f"fixture-observer-attempt-{shard}",
            ),
        ),
        effective_backend="native",
        effective_model="python-fixture",
    )


def _run_fixture(
    tmp_path: Path,
    *,
    shard: str,
    script: str,
    **overrides: Any,
) -> W.CompletedExecution:
    return W.run_observed_worker(
        scratchpad=tmp_path,
        bindings=_bindings(tmp_path, shard),
        argv=[sys.executable, "-c", script],
        cwd=tmp_path,
        output_scope_relative=f"stage-{shard}",
        expected_outputs=(
            W.ExpectedOutput(
                f"assignment-{shard}",
                "result.json",
                f"canonical/{shard}.json",
            ),
        ),
        parser_digest=_strict_result_digest,
        environment={},
        environment_allowlist=(),
        timeout_seconds=10,
        **overrides,
    )


def _write_result_script(shard: str, *, prefix: str = "") -> str:
    return (
        prefix
        + "from pathlib import Path; "
        + f"p=Path('stage-{shard}/result.json'); "
        + "p.parent.mkdir(parents=True, exist_ok=True); "
        + "p.write_text('{\"status\":\"PROPOSED\"}', encoding='utf-8')"
    )


def _debt(exc: W.WorkerExecutionIncomplete) -> Mapping[str, Any]:
    assert exc.debt_path is not None and exc.debt_path.is_file()
    return json.loads(exc.debt_path.read_text(encoding="utf-8"))


def test_execution_completion_is_persisted_only_after_scope_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    original_close = W._OwnedProcessTree.close
    original_persist = W._persist_hashed_json

    def observed_close(scope: W._OwnedProcessTree) -> None:
        original_close(scope)
        events.append("scope-cleaned")

    def observed_persist(
        directory: Path, prefix: str, payload: Mapping[str, Any]
    ) -> tuple[Path, str]:
        if prefix == "completion":
            events.append("completion-persisted")
        return original_persist(directory, prefix, payload)

    monkeypatch.setattr(W._OwnedProcessTree, "close", observed_close)
    monkeypatch.setattr(W, "_persist_hashed_json", observed_persist)
    _run_fixture(
        tmp_path,
        shard="cleanup-order",
        script=_write_result_script("cleanup-order"),
    )

    assert events.index("scope-cleaned") < events.index("completion-persisted")


def test_cleanup_failure_emits_debt_and_never_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_close = W._OwnedProcessTree.close

    def close_then_fail(scope: W._OwnedProcessTree) -> None:
        original_close(scope)
        raise W.WorkerExecutionError("injected provider cleanup failure")

    monkeypatch.setattr(W._OwnedProcessTree, "close", close_then_fail)
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run_fixture(
            tmp_path,
            shard="cleanup-debt",
            script=_write_result_script("cleanup-debt"),
        )

    assert _debt(captured.value)["reason_code"] == "PROCESS_SCOPE_CLEANUP_FAILED"
    evidence = captured.value.arm_path.parent
    assert not list(evidence.glob("completion_*.json"))
    assert not list(evidence.glob("publish_*.json"))
    assert not (tmp_path / "canonical" / "cleanup-debt.json").exists()


def test_running_worker_cancellation_closes_tree_and_emits_debt(
    tmp_path: Path,
) -> None:
    shard = "cancel-running"
    marker = tmp_path / f"stage-{shard}" / "late-descendant.txt"
    descendant = (
        "import time; from pathlib import Path; time.sleep(0.7); "
        f"Path('stage-{shard}/late-descendant.txt').write_text("
        "'late', encoding='utf-8')"
    )
    script = (
        "import subprocess, sys, time; from pathlib import Path; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL); "
        f"p=Path('stage-{shard}/result.json'); "
        "p.parent.mkdir(parents=True, exist_ok=True); "
        "p.write_text('{\"status\":\"PROPOSED\"}', encoding='utf-8'); "
        "time.sleep(10)"
    )
    cancelled = threading.Event()
    timer = threading.Timer(0.2, cancelled.set)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(W.WorkerExecutionIncomplete) as captured:
            _run_fixture(
                tmp_path,
                shard=shard,
                script=script,
                cancel_token=cancelled,
            )
    finally:
        timer.cancel()

    assert time.monotonic() - started < 2.0
    debt = _debt(captured.value)
    assert debt["reason_code"] == "CANCELLED"
    assert debt["process_observation"]["process_tree_terminated"] is True
    assert debt["process_observation"]["process_population_zero_proven"] is True
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))
    assert not (tmp_path / "canonical" / f"{shard}.json").exists()
    time.sleep(0.8)
    assert not marker.exists()


def test_non_exhaustive_posix_capability_is_debt_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "unsupported-provider-launched.txt"
    monkeypatch.setattr(
        W,
        "process_tree_termination_capability",
        lambda: {
            "platform": "POSIX_UNSUPPORTED",
            "strategy": "PROCESS_GROUP_ONLY",
            "provider_owns_tree": False,
            "descendant_termination_required": True,
            "pre_execution_assignment": True,
            "termination_scope": "PROCESS_GROUP_ONLY",
            "exhaustive_descendant_termination_authority": False,
            "limitation": "P0_AM_TEST_UNSUPPORTED",
        },
    )
    script = (
        f"from pathlib import Path; "
        f"Path({str(marker)!r}).write_text('launched', encoding='utf-8'); "
        + _write_result_script("unsupported-posix")
    )

    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run_fixture(tmp_path, shard="unsupported-posix", script=script)

    assert _debt(captured.value)["reason_code"] == "PROCESS_AUTHORITY_UNSUPPORTED"
    assert not marker.exists()
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))


@pytest.mark.parametrize("alias_kind", ("symlink", "hardlink", "reparse"))
def test_staged_aliases_are_rejected_as_typed_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    alias_kind: str,
) -> None:
    shard = f"alias-{alias_kind}"
    source = tmp_path / f"{alias_kind}-source.json"
    source.write_text('{"status":"PROPOSED"}', encoding="utf-8")
    output = tmp_path / f"stage-{shard}" / "result.json"

    if alias_kind == "symlink":
        probe = tmp_path / "symlink-probe"
        try:
            probe.symlink_to(source)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
        else:
            probe.unlink()
        prefix = (
            "import os; from pathlib import Path; "
            f"p=Path({str(output)!r}); "
            "p.parent.mkdir(parents=True, exist_ok=True); "
            f"os.symlink({str(source)!r}, p); "
        )
    elif alias_kind == "hardlink":
        prefix = (
            "import os; from pathlib import Path; "
            f"p=Path({str(output)!r}); "
            "p.parent.mkdir(parents=True, exist_ok=True); "
            f"os.link({str(source)!r}, p); "
        )
    else:
        original_is_reparse = W._is_reparse

        def injected_reparse(path: Path) -> bool:
            return (
                Path(path) == output
                and os.path.lexists(path)
            ) or original_is_reparse(path)

        monkeypatch.setattr(W, "_is_reparse", injected_reparse)
        prefix = _write_result_script(shard)

    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run_fixture(tmp_path, shard=shard, script=prefix)

    reason = _debt(captured.value)["reason_code"]
    if os.name == "nt" and alias_kind in {"symlink", "hardlink"}:
        # MIC denies the unsafe alias before staged parsing; the reparse
        # fixture below still exercises the parser-side rejection.
        assert reason == "NONZERO_EXIT"
        assert not output.exists()
    else:
        assert reason == "UNSAFE_STAGED_ENTRY"
    assert source.read_text(encoding="utf-8") == '{"status":"PROPOSED"}'
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))
    assert not (tmp_path / "canonical" / f"{shard}.json").exists()


@pytest.mark.parametrize("alias_kind", ("symlink", "hardlink"))
def test_staged_reader_rejects_aliases_created_outside_the_worker(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    source = tmp_path / "source.json"
    source.write_text('{"status":"PROPOSED"}', encoding="utf-8")
    alias = tmp_path / "alias.json"
    try:
        if alias_kind == "symlink":
            alias.symlink_to(source)
        else:
            os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"{alias_kind} creation is unavailable: {exc}")
    with pytest.raises(Exception, match="alias|link|regular"):
        W._read_staged_regular_file(alias, limit_bytes=4096)


def test_staged_member_read_obeys_an_explicit_byte_ceiling(
    tmp_path: Path,
) -> None:
    parameters = inspect.signature(W.run_observed_worker).parameters
    assert "staged_output_limit_bytes" in parameters, (
        "WorkerTransaction staging has no explicit member-read byte ceiling"
    )
    shard = "bounded-stage"
    script = (
        "from pathlib import Path; "
        f"p=Path('stage-{shard}/result.json'); "
        "p.parent.mkdir(parents=True, exist_ok=True); "
        "p.write_bytes(b'{\"status\":\"PROPOSED\",\"padding\":\"' + "
        "b'x' * 512 + b'\"}')"
    )
    with pytest.raises(W.WorkerExecutionIncomplete) as captured:
        _run_fixture(
            tmp_path,
            shard=shard,
            script=script,
            staged_output_limit_bytes=256,
        )
    assert _debt(captured.value)["reason_code"] == "STAGED_OUTPUT_LIMIT_EXCEEDED"
    assert not list(captured.value.arm_path.parent.glob("completion_*.json"))


def _worker_transaction_api(name: str) -> Callable[..., Any]:
    try:
        module = importlib.import_module("worker_transaction")
    except ModuleNotFoundError:
        pytest.fail(
            "P0-AM WorkerTransaction provider does not exist yet",
            pytrace=False,
        )
    value = getattr(module, name, None)
    assert callable(value), f"WorkerTransaction API {name} is missing"
    return value


def _canonical_object(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_armed_attempt_bundle_is_recovered_to_persistent_debt(
    tmp_path: Path,
) -> None:
    attempt = (
        tmp_path
        / ".worker_transactions"
        / "breadth"
        / "unit-1"
        / ("a" * 64)
        / "attempt-1"
    )
    attempt.mkdir(parents=True)
    arm: dict[str, Any] = {
        "schema": "plamen.worker_attempt_arm.v1",
        "run_id": "recovery-run",
        "phase": "breadth",
        "work_unit_id": "unit-1",
        "generation": 1,
        "work_plan_digest": "a" * 64,
        "attempt_id": "attempt-1",
        "process_scope": {
            "state": "ARMED",
            "capability": "WINDOWS_JOB_OR_LINUX_CGROUP",
            "persistent_identity": "fixture-scope-1",
        },
    }
    arm["arm_digest"] = hashlib.sha256(_canonical_object(arm)).hexdigest()
    (attempt / "arm.json").write_bytes(_canonical_object(arm) + b"\n")

    recover = _worker_transaction_api("recover_worker_transactions")
    status = recover(run_id="recovery-run", scratchpad=tmp_path)

    debt_path = attempt / "debt.json"
    assert debt_path.is_file()
    debt = json.loads(debt_path.read_text(encoding="utf-8"))
    assert debt["reason_code"] == "INTERRUPTED_PROVIDER_CRASH"
    assert not (attempt / "completion.json").exists()
    assert list(status.active_attempt_ids) == []
    assert list(status.retry_work_unit_ids) == ["unit-1"]


def test_phase_roster_denominator_is_backend_neutral() -> None:
    compile_roster = _worker_transaction_api("compile_phase_work_roster")
    common = {
        "run_id": "roster-run",
        "phase": "depth",
        "generation": 1,
        "required_work_unit_ids": ("depth-1", "depth-2"),
        "optional_work_unit_ids": ("niche-1",),
        "aggregation_predicate": "ALL_REQUIRED_INCORPORATED",
    }
    claude = compile_roster(
        **common,
        work_plan_digests={
            "depth-1": "a" * 64,
            "depth-2": "b" * 64,
            "niche-1": "c" * 64,
        },
    )
    codex = compile_roster(
        **common,
        work_plan_digests={
            "depth-1": "d" * 64,
            "depth-2": "e" * 64,
            "niche-1": "f" * 64,
        },
    )

    assert claude["required_work_unit_ids"] == codex["required_work_unit_ids"]
    assert claude["optional_work_unit_ids"] == codex["optional_work_unit_ids"]
    assert claude["aggregation_predicate"] == codex["aggregation_predicate"]
    for roster in (claude, codex):
        assert not ({"backend", "model", "transport"} & set(roster))
        assert roster["required_work_unit_ids"] == ["depth-1", "depth-2"]
        assert roster["optional_work_unit_ids"] == ["niche-1"]


def test_staged_execution_waits_for_phaseio_canonical_projection(
    tmp_path: Path,
) -> None:
    execution = _run_fixture(
        tmp_path,
        shard="phaseio-only",
        script=_write_result_script("phaseio-only"),
        publish_canonical=False,
    )

    assert execution.publish_receipt_path is None
    assert execution.publish_sha256 is None
    assert execution.published_paths == ()
    assert not (tmp_path / "canonical" / "phaseio-only.json").exists()
    completion = W.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=execution.receipt_path,
        parser_digest=_strict_result_digest,
        expected_completion_sha256=execution.completion_sha256,
    )
    arm = json.loads(execution.arm_path.read_text(encoding="utf-8"))
    assert arm["output_contract"]["publication_authority"] == "PHASE_IO_ONLY"
    assert completion["outputs"][0]["assignment_id"] == "assignment-phaseio-only"
