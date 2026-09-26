"""Real-child contracts for the compatibility mechanical process executor."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading

import pytest

import posix_v2_compat_runtime as R


H = "1" * 64
FIXTURE = b"""\
from pathlib import Path
import sys
import time

mode = sys.argv[1]
output = Path(sys.argv[2])
sys.stderr.write("PLAMEN_REAL_CHILD_STDERR\\n")
if mode == "timeout":
    time.sleep(5.0)
if mode == "fast-overflow":
    sys.stdout.buffer.write(b"x" * (256 * 1024))
    sys.stdout.buffer.flush()
if mode == "binary-streams":
    sys.stdout.buffer.write(b"\\x00\\xff\\r\\n")
    sys.stdout.buffer.flush()
output.write_bytes(b'{"assertion":"PASS","schema":"plamen.test-poc-result.v1"}')
print("PLAMEN_REAL_POC_CHILD_PASS", flush=True)
"""


def test_exec_observer_helper_is_in_shipped_runtime_closure() -> None:
    root = Path(__file__).resolve().parent.parent
    manifest = json.loads(
        (root / "verification_policy/toolchain_runtime_closure.v1.json").read_bytes()
    )
    helper = "scripts/posix_v2_compat_exec_helper.py"
    assert helper in manifest["files"]
    rows = [row for row in manifest["assets"] if row["path"] == helper]
    assert len(rows) == 1 and rows[0]["kind"] == "python-source"
    assert rows[0]["sha256"] == hashlib.sha256((root / helper).read_bytes()).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rehash(payload: dict[str, object]) -> bytes:
    unsigned = dict(payload)
    unsigned.pop("request_sha256", None)
    payload["request_sha256"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
    return _canonical(payload)


def _directory_identity(path: Path) -> dict[str, int]:
    observed = path.stat(follow_symlinks=False)
    assert stat.S_ISDIR(observed.st_mode)
    return {
        "device": int(observed.st_dev),
        "inode": int(observed.st_ino),
        "mode": int(observed.st_mode),
        "owner": int(observed.st_uid),
        "group": int(observed.st_gid),
    }


def _tree_sha(root: Path) -> str:
    rows: list[dict[str, object]] = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        current_path = Path(current)
        for name in files:
            path = current_path / name
            raw = path.read_bytes()
            rows.append({
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            })
    rows.sort(key=lambda row: os.fsencode(str(row["path"])))
    return hashlib.sha256(_canonical(rows)).hexdigest()


def _fixture_roots(tmp_path: Path) -> tuple[Path, Path, object]:
    project = tmp_path / "project"
    source = project / "source"
    scratch = project / ".scratchpad"
    source.mkdir(parents=True)
    scratch.mkdir()
    (source / "source.txt").write_text("immutable audited source\n", encoding="ascii")
    session = R.issue_posix_v2_compat_session_for_installed_front(
        run_id="run-poc-test",
        project_root=project,
        scratchpad=scratch,
    )
    return source, scratch, session


def _request(
    *,
    source: Path,
    scratch: Path,
    session: object,
    attempt: int,
    mode: str,
) -> tuple[bytes, Path]:
    workspace = scratch / f"poc-workspace-{attempt}"
    test = workspace / "test" / "poc_fixture.py"
    home = workspace / ".home"
    temporary = workspace / ".tmp"
    test.parent.mkdir(parents=True)
    home.mkdir()
    temporary.mkdir()
    test.write_bytes(FIXTURE)
    output = workspace / "poc-result.json"
    executable = Path(sys.executable).resolve(strict=True)
    executable_raw = executable.read_bytes()
    environment = {
        "HOME": os.fspath(home),
        "LANG": "C",
        "PATH": os.fspath(executable.parent),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": os.fspath(temporary),
    }
    payload = {
        "schema": R.POC_REQUEST_SCHEMA,
        "request_sha256": "",
        "session_binding_sha256": dict(session.binding)["session_binding_sha256"],
        "run_id": "run-poc-test",
        "purpose": "CANDIDATE_POC",
        "work_unit_id": "verify.TEST-1",
        "finding_id": "TEST-1",
        "constituent_id": "TEST-1.constituent",
        "attempt_number": attempt,
        "work_authority_sha256": "6" * 64,
        "policy_sha256": H,
        "verifier_receipt_sha256": "2" * 64,
        "supply_chain_admission_sha256": "3" * 64,
        "audit_snapshot_sha256": "4" * 64,
        "source_census_sha256": "5" * 64,
        "source_build_root": os.fspath(source.resolve(strict=True)),
        "source_build_root_identity_sha256": hashlib.sha256(
            _canonical(_directory_identity(source))
        ).hexdigest(),
        "workspace_root": os.fspath(workspace.resolve(strict=True)),
        "workspace_root_identity_sha256": hashlib.sha256(
            _canonical(_directory_identity(workspace))
        ).hexdigest(),
        "workspace_pre_tree_sha256": _tree_sha(workspace),
        "subject_kind": "GENERATED_POC_TEST",
        "subject_relative_path": "test/poc_fixture.py",
        "subject_sha256": _file_sha(test),
        "subject_size": len(FIXTURE),
        "test_function": "test_real_child",
        "tool_id": "python-test-fixture",
        "executable_path": os.fspath(executable),
        "executable_sha256": hashlib.sha256(executable_raw).hexdigest(),
        "executable_size": len(executable_raw),
        "argv": [
            os.fspath(executable),
            "-I",
            "-S",
            "-B",
            os.fspath(test),
            mode,
            os.fspath(output),
        ],
        "cwd_relative_path": ".",
        "environment": environment,
        "timeout_seconds": 0.15 if mode == "timeout" else 5.0,
        "stdout_limit_bytes": 64 * 1024,
        "stderr_limit_bytes": 64 * 1024,
        "expected_outputs": [] if mode == "timeout" else ["poc-result.json"],
        "offline_intent": True,
    }
    return _rehash(payload), output


def _prewarm_request(
    *, source: Path, scratch: Path, session: object, attempt: int
) -> bytes:
    raw, _output = _request(
        source=source,
        scratch=scratch,
        session=session,
        attempt=attempt,
        mode="success",
    )
    payload = json.loads(raw.decode("ascii"))
    workspace = Path(payload["workspace_root"])
    manifest = workspace / "build-manifest.json"
    manifest.write_bytes(_canonical({
        "schema": "plamen.test-build-manifest.v1",
        "source_census_sha256": payload["source_census_sha256"],
        "source_entry": "source.txt",
    }))
    payload.update({
        "purpose": "PREWARM_BUILD",
        "work_unit_id": "prewarm.python-fixture",
        "finding_id": None,
        "constituent_id": None,
        "policy_sha256": None,
        "verifier_receipt_sha256": None,
        "subject_kind": "BUILD_MANIFEST",
        "subject_relative_path": "build-manifest.json",
        "subject_sha256": _file_sha(manifest),
        "subject_size": int(manifest.stat().st_size),
        "test_function": None,
        "argv": [payload["executable_path"], "-I", "-S", "-B", "-c", "pass"],
        "expected_outputs": [],
        "workspace_pre_tree_sha256": _tree_sha(workspace),
    })
    return _rehash(payload)


def test_real_child_success_and_live_session_exact_replay(tmp_path: Path) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        request, output = _request(
            source=source,
            scratch=scratch,
            session=session,
            attempt=1,
            mode="success",
        )
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session,
            request_bytes=request,
        )
        projected = R.project_posix_v2_compat_mechanical_poc_terminal(
            session, terminal
        )
        value = json.loads(projected.decode("ascii"))
        assert output.read_bytes() == (
            b'{"assertion":"PASS","schema":"plamen.test-poc-result.v1"}'
        )
        assert value["schema"] == R.POC_TERMINAL_SCHEMA
        assert value["mode"] == R.COMPATIBILITY_MODE
        assert value["status"] == "COMPLETED"
        assert value["process_launch_attempted"] is True
        assert value["actual_tool_execution"] == "STARTED"
        assert value["actual_tool_started"] is True
        assert value["actual_tool_start_observation_complete"] is True
        assert value["actual_tool_completion_observed"] is True
        assert value["selected_test_body_execution"] == "UNPROVEN"
        assert value["poc_attempted"] is True
        assert value["nonattempt_reason"] is None
        assert value["returncode"] == 0
        assert value["process_group_empty_observed"] is True
        assert value["population_zero_proven"] is False
        assert value["native_broker_authority"] is False
        assert value["wer_authority"] is False
        assert value["network_denial_proven"] is False
        assert value["cross_process_recovery_authority"] is False
        assert value["stdout_observation_complete"] is True
        assert value["stdout_observed_sha256"] == hashlib.sha256(
            b"PLAMEN_REAL_POC_CHILD_PASS\n"
        ).hexdigest()
        stdout, stderr = R.project_posix_v2_compat_mechanical_poc_streams(
            session, terminal
        )
        assert stdout == b"PLAMEN_REAL_POC_CHILD_PASS\n"
        assert stderr == b"PLAMEN_REAL_CHILD_STDERR\n"
        outcome = R.project_posix_v2_compat_mechanical_process_outcome(
            session, terminal)
        assert outcome.actual_tool_started is True
        assert outcome.completion_observed is True
        assert outcome.selected_test_body_started is False
        assert outcome.argv == tuple(json.loads(request)["argv"])
        assert outcome.policy_sha256 == H
        assert outcome.verifier_receipt_sha256 == "2" * 64
        assert outcome.stdout == stdout and outcome.stderr == stderr
        assert (scratch / value["stdout_retained_path"]).read_bytes() == stdout
        assert (scratch / value["stderr_retained_path"]).read_bytes() == stderr
        replay = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session,
            request_bytes=request,
        )
        assert replay is terminal
        assert R.project_posix_v2_compat_mechanical_poc_terminal(
            session, replay
        ) == projected
    finally:
        session.close()


def test_real_child_timeout_is_raw_process_evidence_not_poc_proof(tmp_path: Path) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        request, output = _request(
            source=source,
            scratch=scratch,
            session=session,
            attempt=2,
            mode="timeout",
        )
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session,
            request_bytes=request,
        )
        value = json.loads(
            R.project_posix_v2_compat_mechanical_poc_terminal(
                session, terminal
            ).decode("ascii")
        )
        assert not output.exists()
        assert value["status"] == "TIMED_OUT"
        assert value["process_launch_attempted"] is True
        assert value["actual_tool_execution"] == "STARTED"
        assert value["actual_tool_started"] is True
        assert value["actual_tool_start_observation_complete"] is True
        assert value["actual_tool_completion_observed"] is False
        assert value["poc_attempted"] is True
        assert value["nonattempt_reason"] is None
        assert value["timed_out"] is True
        assert value["population_zero_proven"] is False
    finally:
        session.close()


@pytest.mark.parametrize("raw", [b"", b"{", b'{}\n', b'{}'])
def test_missing_truncated_or_forged_start_ack_remains_unknown(raw: bytes) -> None:
    started, completed, returncode, reason = R._poc_start_observation(
        raw, nonce="a" * 64, request_sha256="b" * 64,
        executable_sha256="c" * 64)
    assert started is False and completed is False and returncode is None
    assert reason != "ACKNOWLEDGED"


def test_timeout_start_ack_without_completion_preserves_started() -> None:
    start = _canonical({
        "schema": R.POC_EXEC_START_SCHEMA, "kind": "EXEC_STARTED",
        "nonce": "a" * 64, "request_sha256": "b" * 64,
        "executable_sha256": "c" * 64, "pid": 42}) + b"\n"
    assert R._poc_start_observation(
        start, nonce="a" * 64, request_sha256="b" * 64,
        executable_sha256="c" * 64) == (
            True, False, None, "CONTROL_COMPLETION_ACK_ABSENT")


def test_wrapper_setup_failure_closes_private_control_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    request, _ = _request(
        source=source, scratch=scratch, session=session, attempt=24, mode="success")
    descriptors: list[int] = []
    real_pipe = R.os.pipe
    def observed_pipe() -> tuple[int, int]:
        pair = real_pipe(); descriptors.extend(pair); return pair
    monkeypatch.setattr(R.os, "pipe", observed_pipe)
    monkeypatch.setattr(
        R, "_poc_physical_argv",
        lambda *_a, **_k: R._fail("POC_SANDBOX", "wrapper unavailable"))
    try:
        with pytest.raises(R.PosixV2CompatRuntimeError, match="POC_SANDBOX"):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session, request_bytes=request)
        assert descriptors
        for descriptor in descriptors:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        session.close()


def test_fast_child_overflow_cannot_be_reported_completed(tmp_path: Path) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        request, _output = _request(
            source=source,
            scratch=scratch,
            session=session,
            attempt=20,
            mode="fast-overflow",
        )
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session,
            request_bytes=request,
        )
        value = json.loads(
            R.project_posix_v2_compat_mechanical_poc_terminal(
                session, terminal
            ).decode("ascii")
        )
        assert value["status"] == "OUTPUT_LIMIT"
        assert value["overflowed_stream"] == "stdout"
        assert value["stdout_observation_complete"] is False
        assert value["stdout_observed_sha256"] is None
        assert value["stdout_observed_bytes"] is None
        assert value["stdout_retained_bytes"] <= 64 * 1024
        assert value["actual_tool_started"] is True
        assert value["poc_attempted"] is True
    finally:
        session.close()


def test_divergent_replay_and_redigested_public_terminal_are_rejected(
    tmp_path: Path,
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        request, _output = _request(
            source=source,
            scratch=scratch,
            session=session,
            attempt=3,
            mode="success",
        )
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session,
            request_bytes=request,
        )
        divergent = json.loads(request.decode("ascii"))
        divergent["offline_intent"] = False
        divergent.pop("request_sha256")
        divergent["request_sha256"] = hashlib.sha256(
            _canonical(divergent)
        ).hexdigest()
        with pytest.raises(R.PosixV2CompatRuntimeError, match="POC_REPLAY"):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session,
                request_bytes=_canonical(divergent),
            )

        receipt_path = next(
            (scratch / ".posix_v2_compat_poc_receipts").glob("*.json")
        )
        forged = json.loads(receipt_path.read_text(encoding="ascii"))
        forged["network_denial_proven"] = True
        forged.pop("receipt_sha256")
        forged["receipt_sha256"] = hashlib.sha256(_canonical(forged)).hexdigest()
        receipt_path.chmod(0o600)
        receipt_path.write_bytes(_canonical(forged) + b"\n")
        with pytest.raises(R.PosixV2CompatRuntimeError, match="POC_TERMINAL"):
            R.project_posix_v2_compat_mechanical_poc_terminal(session, terminal)
    finally:
        session.close()


def test_prewarm_binds_build_manifest_and_never_claims_poc(tmp_path: Path) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        request = _prewarm_request(
            source=source, scratch=scratch, session=session, attempt=4
        )
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session, request_bytes=request
        )
        value = json.loads(
            R.project_posix_v2_compat_mechanical_poc_terminal(
                session, terminal
            ).decode("ascii")
        )
        assert value["purpose"] == "PREWARM_BUILD"
        assert value["subject_kind"] == "BUILD_MANIFEST"
        assert value["subject_stable"] is True
        assert value["poc_attempted"] is False
        assert value["nonattempt_reason"] == "PREWARM_NOT_POC"
        assert value["actual_tool_started"] is True
        assert value["selected_test_body_execution"] == "UNPROVEN"
    finally:
        session.close()


@pytest.mark.parametrize("fault_site", [
    "wrapper", "poststate", "persistence", "stdout_persistence", "stderr_persistence"
])
def test_every_post_activation_fault_burns_key_and_leaves_no_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_site: str,
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    request, _output = _request(
        source=source, scratch=scratch, session=session, attempt=10, mode="success"
    )
    original_tree = R._poc_tree_digest
    original_write = R._write_absent_bytes
    tree_calls = 0

    def fail_wrapper(*_args: object, **_kwargs: object) -> object:
        R._fail("POC_SANDBOX", "injected wrapper failure")

    def fail_poststate(*args: object, **kwargs: object) -> object:
        nonlocal tree_calls
        tree_calls += 1
        if tree_calls == 2:
            R._fail("POC_WORKSPACE", "injected poststate failure")
        return original_tree(*args, **kwargs)

    def fail_persistence(*_args: object, **_kwargs: object) -> object:
        R._fail("POC_PERSIST", "injected persistence failure")

    def fail_stream(path: Path, raw: bytes, mode: int) -> None:
        if path.suffix == "." + fault_site.removesuffix("_persistence"):
            R._fail("POC_PERSIST", "injected stream persistence failure")
        original_write(path, raw, mode)

    if fault_site == "wrapper":
        monkeypatch.setattr(R, "_poc_physical_argv", fail_wrapper)
    elif fault_site == "poststate":
        monkeypatch.setattr(R, "_poc_tree_digest", fail_poststate)
    elif fault_site in {"stdout_persistence", "stderr_persistence"}:
        monkeypatch.setattr(R, "_write_absent_bytes", fail_stream)
    else:
        monkeypatch.setattr(R, "_persist_receipt", fail_persistence)
    try:
        with pytest.raises(R.PosixV2CompatRuntimeError):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session, request_bytes=request
            )
        # Remove the injection, then prove the failed operation cannot execute.
        monkeypatch.undo()
        with pytest.raises(R.PosixV2CompatRuntimeError, match="POC_REPLAY"):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session, request_bytes=request
            )
        assert not R._POC_COMMITTED_BY_SESSION.get(id(session), {})
        assert not any(
            row.session_id == id(session) for row in R._POC_TERMINALS.values()
        )
        if fault_site == "wrapper":
            assert not (scratch / R._POC_RECEIPT_DIRECTORY).exists()
    finally:
        session.close()


def test_interrupt_cleans_and_burns_without_ordinary_failure_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    request, _output = _request(
        source=source, scratch=scratch, session=session, attempt=11, mode="success"
    )

    def interrupt(*_args: object, **_kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(R, "_poc_physical_argv", interrupt)
    try:
        with pytest.raises(KeyboardInterrupt):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session, request_bytes=request
            )
        monkeypatch.undo()
        with pytest.raises(R.PosixV2CompatRuntimeError, match="POC_REPLAY"):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session, request_bytes=request
            )
        assert not R._POC_COMMITTED_BY_SESSION.get(id(session), {})
    finally:
        session.close()


def test_session_close_destroys_live_terminal_registry(tmp_path: Path) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    request, _output = _request(
        source=source, scratch=scratch, session=session, attempt=12, mode="success"
    )
    terminal = R.execute_posix_v2_compat_mechanical_poc(
        session_authority=session, request_bytes=request
    )
    terminal_id = id(terminal)
    session_id = id(session)
    assert terminal_id in R._POC_TERMINALS
    assert session_id in R._POC_COMMITTED_BY_SESSION
    session.close()
    assert terminal_id not in R._POC_TERMINALS
    assert session_id not in R._POC_COMMITTED_BY_SESSION
    with pytest.raises(R.PosixV2CompatRuntimeError):
        R.project_posix_v2_compat_mechanical_poc_terminal(session, terminal)
    with pytest.raises(R.PosixV2CompatRuntimeError):
        R.project_posix_v2_compat_mechanical_poc_streams(session, terminal)


def test_retained_streams_preserve_binary_bytes_without_decoding(tmp_path: Path) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        request, _ = _request(
            source=source, scratch=scratch, session=session,
            attempt=22, mode="binary-streams",
        )
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session, request_bytes=request
        )
        stdout, stderr = R.project_posix_v2_compat_mechanical_poc_streams(session, terminal)
        assert stdout == b"\x00\xff\r\nPLAMEN_REAL_POC_CHILD_PASS\n"
        assert stderr == b"PLAMEN_REAL_CHILD_STDERR\n"
    finally:
        session.close()


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
@pytest.mark.parametrize("mutation", ["changed_bytes", "identical_replacement", "symlink"])
def test_retained_stream_tampering_rejects_projection_and_replay(
    tmp_path: Path, stream_name: str, mutation: str,
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        request, _ = _request(
            source=source, scratch=scratch, session=session,
            attempt=23, mode="success",
        )
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session, request_bytes=request
        )
        value = json.loads(R.project_posix_v2_compat_mechanical_poc_terminal(session, terminal))
        path = scratch / value[f"{stream_name}_retained_path"]
        replacement = path.with_suffix(".replacement")
        if mutation == "changed_bytes":
            path.chmod(0o600)
            path.write_bytes(b"x" * path.stat().st_size)
        else:
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o400)
            if mutation == "identical_replacement":
                os.replace(replacement, path)
            else:
                link = path.with_suffix(".link")
                link.symlink_to(replacement)
                os.replace(link, path)
        with pytest.raises(R.PosixV2CompatRuntimeError):
            R.project_posix_v2_compat_mechanical_poc_streams(session, terminal)
        with pytest.raises(R.PosixV2CompatRuntimeError):
            R.project_posix_v2_compat_mechanical_poc_terminal(session, terminal)
        with pytest.raises(R.PosixV2CompatRuntimeError):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session, request_bytes=request
            )
    finally:
        session.close()


def test_distinct_constituents_do_not_collide_in_one_work_unit(tmp_path: Path) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        first, _output = _request(
            source=source, scratch=scratch, session=session, attempt=13, mode="success"
        )
        second, _output = _request(
            source=source, scratch=scratch, session=session, attempt=14, mode="success"
        )
        second_value = json.loads(second.decode("ascii"))
        second_value["attempt_number"] = 13
        second_value["constituent_id"] = "TEST-1.second-constituent"
        second = _rehash(second_value)
        first_terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session, request_bytes=first
        )
        second_terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session, request_bytes=second
        )
        assert first_terminal is not second_terminal
    finally:
        session.close()


def test_executable_symlink_resolving_into_project_is_rejected(tmp_path: Path) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    try:
        request, _output = _request(
            source=source, scratch=scratch, session=session, attempt=15, mode="success"
        )
        target = source / "target-controlled-tool"
        target.write_bytes(b"#!/bin/sh\nexit 0\n")
        target.chmod(0o700)
        alias = tmp_path / "outside-looking-tool"
        alias.symlink_to(target)
        value = json.loads(request.decode("ascii"))
        value["executable_path"] = os.fspath(alias)
        value["executable_sha256"] = _file_sha(target)
        value["executable_size"] = int(target.stat().st_size)
        value["argv"][0] = os.fspath(alias)
        with pytest.raises(R.PosixV2CompatRuntimeError, match="POC_EXECUTABLE"):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session,
                request_bytes=_rehash(value),
            )
    finally:
        session.close()


def test_wrapper_exit_does_not_inflate_tool_or_poc_attempt_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    request, _output = _request(
        source=source, scratch=scratch, session=session, attempt=16, mode="success"
    )

    def rejected_wrapper(_argv: object, _workspace: object) -> tuple[list[str], str]:
        return [sys.executable, "-I", "-S", "-B", "-c", "raise SystemExit(125)"], (
            "DARWIN_SEATBELT"
        )

    monkeypatch.setattr(R, "_poc_physical_argv", rejected_wrapper)
    try:
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session, request_bytes=request
        )
        value = json.loads(
            R.project_posix_v2_compat_mechanical_poc_terminal(
                session, terminal
            ).decode("ascii")
        )
        assert value["status"] == "NONZERO_EXIT"
        assert value["returncode"] == 125
        assert value["wrapper_started"] is True
        assert value["actual_tool_execution"] == "UNKNOWN"
        assert value["poc_attempted"] is False
        assert value["nonattempt_reason"] == "TOOL_START_UNPROVEN"
    finally:
        session.close()


def test_operation_key_encoding_is_unambiguous_with_colon_identifiers() -> None:
    left = R._poc_operation_key(
        purpose="CANDIDATE_POC",
        work_unit_id="a:b",
        attempt=1,
        finding_id="c",
        constituent_id="d",
    )
    right = R._poc_operation_key(
        purpose="CANDIDATE_POC",
        work_unit_id="a",
        attempt=1,
        finding_id="b:c",
        constituent_id="d",
    )
    assert left != right


def test_spawn_failure_diagnostics_are_not_child_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    request, _output = _request(
        source=source, scratch=scratch, session=session, attempt=20, mode="success"
    )

    def failed_spawn(*_args: object, **_kwargs: object) -> object:
        raise OSError("injected spawn failure")

    monkeypatch.setattr(R.subprocess, "Popen", failed_spawn)
    try:
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session, request_bytes=request
        )
        value = json.loads(R.project_posix_v2_compat_mechanical_poc_terminal(
            session, terminal
        ))
        assert value["status"] == "PRELAUNCH_FAILED"
        assert value["child_pid_observed"] is None
        assert value["poc_attempted"] is False
        assert "injected spawn failure" in " ".join(value["controller_diagnostics"])
        assert value["stderr_retained_bytes"] == 0
        assert value["stderr_retained_sha256"] == hashlib.sha256(b"").hexdigest()
        assert value["stderr_observation_complete"] is False
        assert value["stderr_observed_sha256"] is None
        assert R.project_posix_v2_compat_mechanical_poc_streams(session, terminal) == (b"", b"")
    finally:
        session.close()


def test_capture_error_retains_only_child_prefix_without_complete_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    request, _output = _request(
        source=source, scratch=scratch, session=session, attempt=21, mode="success"
    )
    original_result = R._BoundedReader.result
    seen_readers = []

    def result_with_error(reader: object, *args: object, **kwargs: object) -> bytes:
        seen_readers.append(reader)
        raw = original_result(reader, *args, **kwargs)
        if reader._name == "poc-stderr":
            R._fail("STREAM", "injected captured-stream failure")
        return raw

    monkeypatch.setattr(R._BoundedReader, "result", result_with_error)
    try:
        terminal = R.execute_posix_v2_compat_mechanical_poc(
            session_authority=session, request_bytes=request
        )
        value = json.loads(R.project_posix_v2_compat_mechanical_poc_terminal(
            session, terminal
        ))
        expected = b"PLAMEN_REAL_CHILD_STDERR\n"
        assert value["status"] == "RUNTIME_FAILED"
        assert value["stdout_observation_complete"] is True
        assert value["stderr_retained_bytes"] == len(expected)
        assert value["stderr_retained_sha256"] == hashlib.sha256(expected).hexdigest()
        _, retained_stderr = R.project_posix_v2_compat_mechanical_poc_streams(session, terminal)
        assert retained_stderr == expected
        assert value["stderr_observation_complete"] is False
        assert value["stderr_observed_sha256"] is None
        assert "injected captured-stream failure" in " ".join(value["controller_diagnostics"])
        assert len(seen_readers) == 2
        assert all(reader._stream.closed for reader in seen_readers)
    finally:
        session.close()


def test_concurrent_duplicate_cannot_clear_original_activation_or_launch_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, scratch, session = _fixture_roots(tmp_path)
    request, _output = _request(
        source=source, scratch=scratch, session=session, attempt=17, mode="success"
    )
    entered = threading.Event()
    release = threading.Event()
    original_wrapper = R._poc_physical_argv
    wrapper_calls = 0
    outcome: list[object] = []

    def blocked_wrapper(argv: object, workspace: object) -> object:
        nonlocal wrapper_calls
        wrapper_calls += 1
        entered.set()
        assert release.wait(timeout=5.0)
        return original_wrapper(argv, workspace)

    def first_call() -> None:
        try:
            outcome.append(R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session, request_bytes=request
            ))
        except BaseException as exc:  # captured for assertion in test thread
            outcome.append(exc)

    monkeypatch.setattr(R, "_poc_physical_argv", blocked_wrapper)
    worker = threading.Thread(target=first_call, name="original-poc-attempt")
    worker.start()
    try:
        assert entered.wait(timeout=5.0)
        with pytest.raises(R.PosixV2CompatRuntimeError, match="POC_REPLAY"):
            R.execute_posix_v2_compat_mechanical_poc(
                session_authority=session, request_bytes=request
            )
        assert len(R._session_record(session).active_invocations) == 1
        with pytest.raises(R.PosixV2CompatRuntimeError):
            session.close()
        assert len(R._session_record(session).active_invocations) == 1
        assert wrapper_calls == 1
    finally:
        release.set()
        worker.join(timeout=10.0)
    assert not worker.is_alive()
    assert len(outcome) == 1
    assert type(outcome[0]) is R.PosixV2CompatMechanicalPoCTerminal
    session.close()
