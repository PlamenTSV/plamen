"""Windows rooted-I/O fixtures for WER evidence at the MAX_PATH boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

import test_worker_execution_receipts as fixtures
import test_worker_transaction_contracts_p0_am as wtx_fixtures
import rooted_path_io as RIO
import worker_execution_receipts as W
import worker_transaction as WT


pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows extended-length rooted I/O fixture",
)


def _scratchpad_for_stdout_length(tmp_path: Path, target: int) -> Path:
    digest = hashlib.sha256(b"").hexdigest()
    suffix = (
        Path(W._EVIDENCE_DIR)
        / "shard-001"
        / "blobs"
        / f"stdout_{digest}.bin"
    )
    suffix_text = os.sep + os.fspath(suffix)
    scratch_length = target - len(suffix_text)
    prefix = os.fspath(tmp_path.resolve()) + os.sep
    filler_length = scratch_length - len(prefix)
    if filler_length < 1 or filler_length > 240:
        pytest.skip("pytest temporary root cannot express exact path boundary")
    scratchpad = tmp_path / ("s" * filler_length)
    scratchpad.mkdir()
    stdout_path = scratchpad / suffix
    assert len(os.fspath(stdout_path.resolve(strict=False))) == target
    return scratchpad


def _scratchpad_at_length(tmp_path: Path, target: int) -> Path:
    prefix = os.fspath(tmp_path.resolve()) + os.sep
    filler_length = target - len(prefix)
    if filler_length < 1 or filler_length > 240:
        pytest.skip("pytest temporary root cannot express exact path boundary")
    scratchpad = tmp_path / ("r" * filler_length)
    W._mkdir_rooted(scratchpad)
    assert len(os.fspath(scratchpad)) == target
    return scratchpad


def _copy_rooted_tree(source: Path, destination: Path) -> None:
    if not W._rooted_lexists(destination):
        W._mkdir_rooted(destination)
    for entry in os.scandir(W._native_rooted_path(source)):
        source_child = source / entry.name
        destination_child = destination / entry.name
        if entry.is_dir(follow_symlinks=False):
            _copy_rooted_tree(source_child, destination_child)
        else:
            W._atomic_immutable_bytes(
                destination_child,
                W._read_rooted_bytes(source_child),
            )


def _remove_rooted_tree(path: Path) -> None:
    if not W._rooted_lexists(path):
        return
    if not W._rooted_is_dir(path):
        W._unlink_rooted(path)
        return
    for entry in os.scandir(W._native_rooted_path(path)):
        child = path / entry.name
        if entry.is_dir(follow_symlinks=False):
            _remove_rooted_tree(child)
        else:
            W._unlink_rooted(child)
    os.rmdir(W._native_rooted_path(path))


def _execute_wtx_without_incorporation(scratchpad: Path) -> WT.ExecutionRef:
    prompt = b"long attempt semantic input\n"
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
        W._atomic_immutable_bytes(scratchpad / name, raw)

    key = wtx_fixtures.canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "native",
        "depth",
        "depth-1",
    )
    contract = wtx_fixtures.PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="native",
        phase="depth",
        work_unit_id="depth-1",
        outputs=(
            wtx_fixtures.ArtifactSpec(
                root="scratchpad",
                path="depth_result.md",
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
            ),
        ),
    )
    launch = wtx_fixtures.LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="native",
        model="python-fixture",
        timeout_s=30,
        exec_mode="native",
    )
    prelaunch = wtx_fixtures.L.record_work_unit_inputs(
        scratchpad,
        scratchpad,
        contract,
        launch,
        run_id="run-1",
    )
    executable = Path(sys.executable).resolve(strict=True)
    provider = {
        "backend": "native",
        "model": "python-fixture",
        "transport": "native",
        "resolved_executable": str(executable),
        "executable_sha256": hashlib.sha256(
            executable.read_bytes()
        ).hexdigest(),
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
    assignment = wtx_fixtures._assignment()
    assignment["members"][0]["canonical_prestate"] = prelaunch[
        "output_prestates"
    ]["scratchpad:depth_result.md"]
    plan = wtx_fixtures._plan(
        provider=provider,
        assignment=assignment,
        prompt_sha256=hashlib.sha256(prompt).hexdigest(),
        phase_io_contract_digest=contract.digest,
        phase_io_launch_digest=launch.digest,
        phase_io_input_set_digest=prelaunch["input_set_digest"],
    )
    adapter = WT.NativeCommandAdapter(
        scratchpad=scratchpad,
        cwd=scratchpad,
        input_relative_paths={
            "manifest": "manifest.json",
            "intent": "intent.json",
            "context": "context.md",
            "prompt": "prompt.md",
            "tool_policy": "tool_policy.json",
        },
        parser_digest=wtx_fixtures._strict_proposal_digest,
        environment={},
        environment_allowlist=(),
    )
    return WT.execute_worker_transaction(plan, adapter)


def _write_rooted_terminal_debt(
    scratchpad: Path,
    *,
    plan_digest: str,
) -> None:
    attempt_id = "attempt-terminal"
    relative = (
        ".worker_transactions/depth/depth-1/"
        f"{plan_digest[:32]}/{attempt_id}"
    )
    attempt = WT._make_safe_directory_tree(scratchpad, relative)
    arm = {
        "schema": WT.WORKER_ATTEMPT_ARM_SCHEMA,
        "run_id": "run-1",
        "phase": "depth",
        "work_unit_id": "depth-1",
        "generation": 1,
        "work_plan_digest": plan_digest,
        "attempt_id": attempt_id,
        "process_scope": {
            "state": "ARMED",
            "capability": "WINDOWS",
            "persistent_identity": f"scope-{attempt_id}",
        },
    }
    arm["arm_digest"] = hashlib.sha256(
        json.dumps(
            arm,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    W._atomic_immutable_bytes(
        attempt / "arm.json",
        json.dumps(
            arm,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n",
    )
    debt = {
        "schema": WT.WORKER_ATTEMPT_DEBT_SCHEMA,
        "run_id": "run-1",
        "phase": "depth",
        "work_unit_id": "depth-1",
        "generation": 1,
        "work_plan_digest": plan_digest,
        "attempt_id": attempt_id,
        "arm_digest": arm["arm_digest"],
        "reason_code": "FIXTURE_TERMINAL_DEBT",
        "detail": "explicit rooted long-path fixture terminal debt",
        "completion_emitted": False,
        "retry_required": False,
    }
    debt["debt_digest"] = hashlib.sha256(
        json.dumps(
            debt,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    W._atomic_immutable_bytes(
        attempt / "debt.json",
        json.dumps(
            debt,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n",
    )


@pytest.mark.parametrize("target_length", (259, 260, 261))
def test_public_wer_persists_replays_and_reuses_boundary_blobs(
    tmp_path: Path,
    target_length: int,
) -> None:
    scratchpad = _scratchpad_for_stdout_length(tmp_path, target_length)

    completed = fixtures._run(scratchpad)
    first = W.validate_completed_execution(
        scratchpad=scratchpad,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=fixtures.strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )
    second = W.validate_completed_execution(
        scratchpad=scratchpad,
        receipt_path=completed.receipt_path,
        publish_receipt_path=completed.publish_receipt_path,
        parser_digest=fixtures.strict_json_digest,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=completed.publish_sha256,
    )

    assert first == second
    stdout = first["stdout_blob"]
    assert stdout["sha256"] == hashlib.sha256(b"").hexdigest()
    assert stdout["size"] == 0
    blob_path = completed.receipt_path.parent / stdout["relative_path"]
    assert len(os.fspath(blob_path.resolve(strict=False))) == target_length
    assert W._read_rooted_bytes(blob_path) == b""
    assert (
        WT._safe_relative_file(
            completed.receipt_path.parent,
            stdout["relative_path"],
            "boundary stdout blob",
        )
        == blob_path
    )
    assert WT._artifact_state(blob_path) == {
        "status": "ACTIVE",
        "sha256": hashlib.sha256(b"").hexdigest(),
        "size": 0,
    }

    # Equal-byte persistence is the idempotent retry path; a differing body
    # must remain an immutable collision.
    assert W._persist_blob(blob_path.parent, "stdout", b"") == stdout
    with pytest.raises(W.WorkerExecutionError, match="collision"):
        W._atomic_immutable_bytes(blob_path, b"different")
    W._unlink_rooted(blob_path)
    assert W._rooted_lexists(blob_path) is False
    assert W._persist_blob(blob_path.parent, "stdout", b"") == stdout
    assert W._read_rooted_bytes(blob_path) == b""

    receipt_bytes = W._read_rooted_bytes(completed.receipt_path)
    assert b"\\\\?\\" not in receipt_bytes
    assert os.fspath(scratchpad).encode("utf-8") not in receipt_bytes
    json.loads(receipt_bytes.decode("utf-8"))


def test_public_wtx_executes_with_long_attempt_scoped_semantic_inputs(
    tmp_path: Path,
) -> None:
    scratchpad = _scratchpad_at_length(tmp_path, 170)
    execution = _execute_wtx_without_incorporation(scratchpad)

    attempt_plan = execution.attempt_directory / "view" / "plan.json"
    assert len(os.fspath(attempt_plan)) > 260
    assert WT._rooted_is_file(attempt_plan)
    assert WT._rooted_is_file(execution.attempt_completion_path)
    completion = W.validate_staged_execution(
        scratchpad=scratchpad,
        receipt_path=execution.provider_execution.receipt_path,
        parser_digest=wtx_fixtures._strict_proposal_digest,
        expected_completion_sha256=(
            execution.provider_execution.completion_sha256
        ),
    )
    assert completion["output_source_mode"] == W.STDOUT_ASSIGNED_OUTPUT


@pytest.mark.parametrize("scratchpad_length", (238, 270))
def test_public_wer_replays_from_a_long_nested_evidence_root(
    tmp_path: Path,
    scratchpad_length: int,
) -> None:
    short = tmp_path / "short"
    short.mkdir()
    completed = fixtures._run(short)
    long_root = _scratchpad_at_length(tmp_path, scratchpad_length)
    try:
        _copy_rooted_tree(short, long_root)
        receipt = long_root / completed.receipt_path.relative_to(short)
        publish = (
            long_root / completed.publish_receipt_path.relative_to(short)
            if completed.publish_receipt_path is not None
            else None
        )
        assert len(os.fspath(receipt)) > 260
        assert (
            len(
                os.fspath(
                    long_root / "launch-inputs" / "plan.json"
                )
            )
            > 260
        )
        assert (
            len(
                os.fspath(
                    long_root / "worker-out" / "result.json"
                )
            )
            > 260
        )
        replayed = W.validate_completed_execution(
            scratchpad=long_root,
            receipt_path=receipt,
            publish_receipt_path=publish,
            parser_digest=fixtures.strict_json_digest,
            expected_completion_sha256=completed.completion_sha256,
            expected_publish_sha256=completed.publish_sha256,
        )
        assert replayed["completion_sha256"] == completed.completion_sha256
    finally:
        _remove_rooted_tree(long_root)


@pytest.mark.parametrize("scratchpad_length", (238, 270))
def test_wtx_reconcile_enumerates_long_existing_phase_tree(
    tmp_path: Path,
    scratchpad_length: int,
) -> None:
    scratchpad = _scratchpad_at_length(tmp_path, scratchpad_length)
    try:
        plan_digest = "a" * 64
        _write_rooted_terminal_debt(
            scratchpad,
            plan_digest=plan_digest,
        )
        transaction_root = scratchpad / ".worker_transactions"
        phase_directory = transaction_root / "depth"
        if scratchpad_length == 238:
            assert len(os.fspath(transaction_root)) == 259
            assert len(os.fspath(phase_directory)) == 265
        else:
            assert len(os.fspath(transaction_root)) > 260
            assert len(os.fspath(phase_directory)) > 260
        assert WT._rooted_is_dir(transaction_root)
        assert WT._rooted_is_dir(phase_directory)

        roster = WT.compile_phase_work_roster(
            run_id="run-1",
            phase="depth",
            generation=1,
            required_work_unit_ids=("depth-1",),
            work_plan_digests={"depth-1": plan_digest},
        )
        status = WT.reconcile_phase_work_roster(
            roster,
            scratchpad=scratchpad,
        )
        assert status.completed_with_debt is True
        assert status.debt_work_unit_ids == ("depth-1",)
        assert status.missing_work_unit_ids == ()
    finally:
        _remove_rooted_tree(scratchpad)


def test_wtx_safe_relative_file_rejects_case_distinct_spelling(
    tmp_path: Path,
) -> None:
    actual = tmp_path / "CaseDir"
    actual.mkdir()
    (actual / "File.JSON").write_bytes(b"{}\n")

    with pytest.raises(WT.WorkerTransactionError, match="casing mismatch"):
        WT._safe_relative_file(
            tmp_path,
            "casedir/file.json",
            "case-bound authority",
        )


def test_shared_native_path_owns_extended_spelling_and_rejects_injection() -> None:
    assert RIO.native_path(r"C:\alpha\..\beta") == r"\\?\C:\beta"
    assert (
        RIO.native_path(r"\\server\share\directory")
        == r"\\?\UNC\server\share\directory"
    )
    for injected in (
        r"\\?\C:\alpha\..\beta",
        r"\\?\UNC\server\share\directory",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1",
    ):
        with pytest.raises(
            RIO.RootedPathIOError,
            match="caller-supplied Windows extended path",
        ):
            RIO.native_path(injected)


@pytest.mark.parametrize("scratchpad_length", (150, 151, 155, 160))
def test_public_incorporation_crosses_wer_wtx_and_artifact_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scratchpad_length: int,
) -> None:
    scratchpad = _scratchpad_at_length(tmp_path, scratchpad_length)
    wtx_fixtures.test_phaseio_incorporation_is_the_only_canonical_publisher(
        scratchpad,
        monkeypatch,
    )
