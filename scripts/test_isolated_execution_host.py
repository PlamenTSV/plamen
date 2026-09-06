"""Fixture-first tests for disposable per-attempt owned-process execution."""
from __future__ import annotations

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import threading
import time
from typing import Any

import pytest

import isolated_execution_host as H
from windows_low_integrity_lease import LEASE_DIRECTORY_ENV, LEASE_TEST_OVERRIDE_ENV


def _python(code: str) -> tuple[str, ...]:
    return (sys.executable, "-I", "-S", "-c", code)


def _wait_for_file(path: Path, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert path.exists()


def _windows_process_is_running(process_id: int) -> bool:
    if os.name != "nt":
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, process_id)
    if not handle:
        return False
    try:
        return int(kernel32.WaitForSingleObject(handle, 0)) == 0x00000102
    finally:
        kernel32.CloseHandle(handle)


def _terminate_exact_process_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.TerminateProcess.restype = ctypes.c_int
    assert kernel32.TerminateProcess(ctypes.c_void_p(handle), 91)


@pytest.fixture
def isolated_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    # The production runner correctly rejects the test-only lease namespace as
    # write authority.  These serialized integration fixtures therefore use
    # the real per-user lease under explicit inter-agent ownership.
    monkeypatch.delenv(LEASE_TEST_OVERRIDE_ENV, raising=False)
    monkeypatch.delenv(LEASE_DIRECTORY_ENV, raising=False)
    return tmp_path


def test_forged_completion_receipts_are_rejected() -> None:
    request = H._build_request(
        command=_python("print('ok')"),
        cwd=None,
        env={"SAFE": "1"},
        timeout=2,
        encoding="utf-8",
        errors="replace",
        output_limit_bytes=4096,
        writable_roots=(),
    )
    valid = H._build_terminal_receipt(
        receipt_type="COMPLETED",
        request=request,
        executor_pid=7171,
        completion_authority=True,
        payload={
            "args": list(request["payload"]["command"]),
            "returncode": 0,
            "stdout": "ok\n",
            "stderr": "",
            "duration_s": 0.1,
            "process_tree_terminated": True,
            "containment_capability": {"platform": "WINDOWS"},
        },
    )
    H._validate_terminal_receipt(
        valid,
        expected_request=request,
        expected_executor_pid=7171,
    )
    assert H._receipt_surface_failure_reason(
        valid,
        expected_request=request,
        expected_executor_pid=7171,
    ) is None

    bad_digest = json.loads(json.dumps(valid))
    bad_digest["payload"]["stdout"] = "tampered"
    assert H._receipt_surface_failure_reason(
        bad_digest,
        expected_request=request,
        expected_executor_pid=7171,
    ) == "EXECUTOR_RECEIPT_DIGEST_INVALID"

    mutations: list[dict[str, Any]] = []
    wrong_result = json.loads(json.dumps(valid))
    wrong_result["payload"]["process_tree_terminated"] = False
    mutations.append(wrong_result)
    wrong_pid = json.loads(json.dumps(valid))
    wrong_pid["executor_pid"] = 8181
    wrong_pid["receipt_sha256"] = H._digest_receipt(wrong_pid)
    assert H._receipt_surface_failure_reason(
        wrong_pid,
        expected_request=request,
        expected_executor_pid=7171,
    ) == "EXECUTOR_RECEIPT_BINDING_INVALID"
    mutations.append(wrong_pid)
    wrong_request = json.loads(json.dumps(valid))
    wrong_request["request_sha256"] = "0" * 64
    wrong_request["receipt_sha256"] = H._digest_receipt(wrong_request)
    mutations.append(wrong_request)
    extra_field = json.loads(json.dumps(valid))
    extra_field["forged"] = True
    extra_field["receipt_sha256"] = H._digest_receipt(extra_field)
    assert H._receipt_surface_failure_reason(
        extra_field,
        expected_request=request,
        expected_executor_pid=7171,
    ) == "EXECUTOR_RECEIPT_SCHEMA_INVALID"
    mutations.append(extra_field)

    payload_invalid = json.loads(json.dumps(valid))
    payload_invalid["payload"]["process_tree_terminated"] = False
    payload_invalid["receipt_sha256"] = H._digest_receipt(payload_invalid)
    assert H._receipt_surface_failure_reason(
        payload_invalid,
        expected_request=request,
        expected_executor_pid=7171,
    ) is None
    with pytest.raises(H.IsolatedExecutionProtocolError):
        H._validate_terminal_receipt(
            payload_invalid,
            expected_request=request,
            expected_executor_pid=7171,
        )

    for forged in mutations:
        with pytest.raises(H.IsolatedExecutionProtocolError):
            H._validate_terminal_receipt(
                forged,
                expected_request=request,
                expected_executor_pid=7171,
            )


def test_exact_local_source_loader_ignores_unchecked_malicious_bytecode(
    tmp_path: Path,
) -> None:
    source = tmp_path / "closure_probe.py"
    source.write_text("VALUE = 'malicious'\n", encoding="utf-8")
    cache = Path(importlib.util.cache_from_source(str(source)))
    cache.parent.mkdir()
    py_compile.compile(
        str(source),
        cfile=str(cache),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    source.write_text("VALUE = 'trusted'\n", encoding="utf-8")
    finder = H._ExactLocalSourceFinder({"closure_probe": source})
    spec = finder.find_spec("closure_probe")
    assert spec is not None
    assert isinstance(spec.loader, H._ExactLocalSourceLoader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.VALUE == "trusted"


def test_bare_executable_request_dually_binds_signed_path_and_receipt(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    executable_name = "bound-tool.exe" if os.name == "nt" else "bound-tool"
    for root in (first, second):
        executable = root / executable_name
        executable.write_bytes(b"fixture")
        executable.chmod(0o755)

    request = H._build_request(
        command=(executable_name, "--version"),
        cwd=None,
        env={"PATH": str(first), "PATHEXT": ".EXE"},
        timeout=2,
        encoding="utf-8",
        errors="replace",
        output_limit_bytes=4096,
        writable_roots=(),
    )
    assert request["payload"]["requested_command"] == [
        executable_name,
        "--version",
    ]
    assert request["payload"]["command"] == [
        str((first / executable_name).resolve()),
        "--version",
    ]

    valid = H._build_terminal_receipt(
        receipt_type="COMPLETED",
        request=request,
        executor_pid=7171,
        completion_authority=True,
        payload={
            "args": list(request["payload"]["command"]),
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "duration_s": 0.1,
            "process_tree_terminated": True,
            "containment_capability": {"platform": "WINDOWS"},
        },
    )
    H._validate_terminal_receipt(
        valid,
        expected_request=request,
        expected_executor_pid=7171,
    )

    forged_receipt = json.loads(json.dumps(valid))
    forged_receipt["payload"]["args"] = list(
        request["payload"]["requested_command"]
    )
    forged_receipt["receipt_sha256"] = H._digest_receipt(forged_receipt)
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="completed payload",
    ):
        H._validate_terminal_receipt(
            forged_receipt,
            expected_request=request,
            expected_executor_pid=7171,
        )

    drifted_path = json.loads(json.dumps(request))
    drifted_path["payload"]["env"]["PATH"] = str(second)
    drifted_path["request_sha256"] = H._digest_request(drifted_path)
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="requested/resolved command binding",
    ):
        H._validate_request(drifted_path)

    forged_resolved = json.loads(json.dumps(request))
    forged_resolved["payload"]["command"][0] = str(
        (second / executable_name).resolve()
    )
    forged_resolved["request_sha256"] = H._digest_request(forged_resolved)
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="requested/resolved command binding",
    ):
        H._validate_request(forged_resolved)

    forged_argument = json.loads(json.dumps(request))
    forged_argument["payload"]["requested_command"][1] = "--forged"
    forged_argument["request_sha256"] = H._digest_request(forged_argument)
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="requested/resolved command binding",
    ):
        H._validate_request(forged_argument)

    forged_guard = json.loads(json.dumps(request))
    forged_guard["payload"]["executable_guard"]["sha256"] = "0" * 64
    forged_guard["request_sha256"] = H._digest_request(forged_guard)
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="executable guard binding",
    ):
        H._validate_request(forged_guard)


def test_throwing_cancel_observer_reaps_exact_executor_and_allows_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = H._build_request(
        command=_python("print('unused')"),
        cwd=None,
        env={},
        timeout=2,
        encoding="utf-8",
        errors="replace",
        output_limit_bytes=4096,
        writable_roots=(),
    )

    class FakeProcess:
        pid = 7171
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    class FakeJob:
        finalize_calls = 0

        def finalize(
            self,
            process: FakeProcess,
            *,
            force_terminate: bool,
            timeout: float,
        ) -> bool:
            assert force_terminate is True
            assert timeout == 10.0
            self.finalize_calls += 1
            process.returncode = 91
            return True

    class FakeCollector:
        def finish(self, *, timeout: float) -> bytes:
            assert timeout == 10.0
            return b""

    class ThrowingCancel:
        def is_set(self) -> bool:
            raise RuntimeError("cancel observer failed")

    process = FakeProcess()
    job = FakeJob()
    monkeypatch.setattr(
        H,
        "_ACTIVE_EXECUTOR_REQUEST_ID",
        request["request_id"],
    )
    monkeypatch.setattr(H, "_AMBIGUOUS_EXECUTOR_LATCH", False)
    attempt = H.IsolatedExecutionAttempt(
        request=request,
        process=process,  # type: ignore[arg-type]
        job=job,  # type: ignore[arg-type]
        stdout_collector=FakeCollector(),  # type: ignore[arg-type]
        stderr_collector=FakeCollector(),  # type: ignore[arg-type]
        executor_argv=("fixture",),
    )
    with pytest.raises(H.IsolatedExecutionHostError) as caught:
        attempt.wait(
            coordinator_timeout=1,
            cancel_token=ThrowingCancel(),
        )
    assert job.finalize_calls == 1
    assert process.returncode == 91
    assert H._ACTIVE_EXECUTOR_REQUEST_ID is None
    assert H._AMBIGUOUS_EXECUTOR_LATCH is False
    assert caught.value.receipt["completion_authority"] is False
    assert caught.value.receipt["payload"]["reason_code"] == (
        "COORDINATOR_OBSERVATION_FAILED"
    )
    assert attempt.terminal_receipt == caught.value.receipt


def test_typed_attempt_abort_reaps_once_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = H._build_request(
        command=_python("print('unused')"),
        cwd=None,
        env={},
        timeout=2,
        encoding="utf-8",
        errors="replace",
        output_limit_bytes=4096,
        writable_roots=(),
    )

    class FakeProcess:
        pid = 7272
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    class FakeJob:
        finalize_calls = 0

        def finalize(
            self,
            process: FakeProcess,
            *,
            force_terminate: bool,
            timeout: float,
        ) -> bool:
            assert force_terminate is True
            assert timeout == 10.0
            self.finalize_calls += 1
            process.returncode = 97
            return True

    class FakeCollector:
        def finish(self, *, timeout: float) -> bytes:
            assert timeout == 10.0
            return b""

    process = FakeProcess()
    job = FakeJob()
    monkeypatch.setattr(
        H,
        "_ACTIVE_EXECUTOR_REQUEST_ID",
        request["request_id"],
    )
    monkeypatch.setattr(H, "_AMBIGUOUS_EXECUTOR_LATCH", False)
    attempt = H.IsolatedExecutionAttempt(
        request=request,
        process=process,  # type: ignore[arg-type]
        job=job,  # type: ignore[arg-type]
        stdout_collector=FakeCollector(),  # type: ignore[arg-type]
        stderr_collector=FakeCollector(),  # type: ignore[arg-type]
        executor_argv=("fixture",),
    )
    first = attempt.abort(
        reason_code="EXECUTOR_BOUNDARY_INTERRUPTED"
    )
    second = attempt.abort(
        reason_code="EXECUTOR_BOUNDARY_INTERRUPTED"
    )
    assert first == second
    assert first["completion_authority"] is False
    assert first["payload"]["reason_code"] == (
        "EXECUTOR_BOUNDARY_INTERRUPTED"
    )
    assert job.finalize_calls == 1
    assert process.returncode == 97
    assert H._ACTIVE_EXECUTOR_REQUEST_ID is None
    assert H._AMBIGUOUS_EXECUTOR_LATCH is False


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_success_receipt_is_ephemeral_bound_and_secret_free(
    isolated_lease: Path,
) -> None:
    del isolated_lease
    secret = "TOP-SECRET-ENV-VALUE-9421"
    env = dict(os.environ)
    env["ISOLATED_FIXTURE_SECRET"] = secret
    attempt = H.start_isolated_owned_process(
        _python("print('isolated-ok')"),
        env=env,
        timeout=5,
    )

    result = attempt.wait(coordinator_timeout=15)

    assert result.returncode == 0
    assert result.stdout.strip() == "isolated-ok"
    assert result.process_tree_terminated is True
    serialized_receipt = json.dumps(
        attempt.terminal_receipt,
        sort_keys=True,
    )
    assert secret not in serialized_receipt
    assert secret not in repr(attempt)
    assert secret not in "\0".join(attempt.executor_argv)


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_direct_bare_executable_success_binds_resolved_receipt(
    isolated_lease: Path,
) -> None:
    del isolated_lease
    executable_name = Path(sys.executable).name
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).resolve().parent)
    attempt = H.start_isolated_owned_process(
        (executable_name, "-I", "-S", "-c", "print('bare-ok')"),
        env=env,
        timeout=5,
    )

    result = attempt.wait(coordinator_timeout=15)

    assert result.returncode == 0
    assert result.stdout.strip() == "bare-ok"
    assert attempt._request["payload"]["requested_command"][0] == (
        executable_name
    )
    assert result.args == tuple(attempt._request["payload"]["command"])
    assert Path(result.args[0]) == Path(sys.executable).resolve()


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_executor_hard_crash_is_debt_no_survivor_then_same_driver_retries(
    tmp_path: Path,
    isolated_lease: Path,
) -> None:
    del isolated_lease
    target_pid_path = tmp_path / "hard-crash-target.pid"
    attempt = H.start_isolated_owned_process(
        _python(
            "import os,time;"
            f"open({str(target_pid_path)!r},'w').write(str(os.getpid()));"
            "time.sleep(60)"
        ),
        timeout=30,
        writable_roots=(tmp_path,),
    )
    _wait_for_file(target_pid_path)
    target_pid = int(target_pid_path.read_text(encoding="ascii"))
    _terminate_exact_process_handle(attempt._executor_process_handle_for_test())

    with pytest.raises(H.IsolatedExecutionHostError) as caught:
        attempt.wait(coordinator_timeout=10)

    assert caught.value.receipt["completion_authority"] is False
    assert caught.value.receipt["receipt_type"] == "COORDINATOR_DEBT"
    assert _windows_process_is_running(target_pid) is False

    retry = H.run_isolated_owned_process(
        _python("print('retry-ok')"),
        timeout=5,
        coordinator_timeout=15,
    )
    assert retry.stdout.strip() == "retry-ok"


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_target_timeout_kills_and_watches_exact_executor_tree(
    tmp_path: Path,
    isolated_lease: Path,
) -> None:
    del isolated_lease
    target_pid_path = tmp_path / "timeout-target.pid"
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        H.run_isolated_owned_process(
            _python(
                "import os,time;"
                f"open({str(target_pid_path)!r},'w').write(str(os.getpid()));"
                "time.sleep(60)"
            ),
            timeout=0.4,
            coordinator_timeout=15,
            writable_roots=(tmp_path,),
        )

    assert getattr(caught.value, "isolated_receipt")[
        "completion_authority"
    ] is False
    target_pid = int(target_pid_path.read_text(encoding="ascii"))
    assert _windows_process_is_running(target_pid) is False


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_coordinator_cancel_kills_and_watches_without_completion(
    tmp_path: Path,
    isolated_lease: Path,
) -> None:
    del isolated_lease
    target_pid_path = tmp_path / "cancel-target.pid"
    cancel = threading.Event()
    attempt = H.start_isolated_owned_process(
        _python(
            "import os,time;"
            f"open({str(target_pid_path)!r},'w').write(str(os.getpid()));"
            "time.sleep(60)"
        ),
        timeout=30,
        writable_roots=(tmp_path,),
    )
    _wait_for_file(target_pid_path)
    target_pid = int(target_pid_path.read_text(encoding="ascii"))
    cancel.set()

    with pytest.raises(H.IsolatedExecutionCancelled) as caught:
        attempt.wait(cancel_token=cancel, coordinator_timeout=10)

    assert caught.value.receipt["completion_authority"] is False
    assert _windows_process_is_running(target_pid) is False


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_contender_cannot_complete_while_live_executor_owns_lease(
    tmp_path: Path,
    isolated_lease: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del isolated_lease
    owner_started = tmp_path / "owner-started.txt"
    owner = H.start_isolated_owned_process(
        _python(
            "import time;"
            f"open({str(owner_started)!r},'w').write('yes');"
            "time.sleep(1.2);"
            "print('owner-done')"
        ),
        timeout=5,
        writable_roots=(tmp_path,),
    )
    _wait_for_file(owner_started)

    real_popen = H.subprocess.Popen

    def forbid_second_executor(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a second executor must not be launched")

    monkeypatch.setattr(H.subprocess, "Popen", forbid_second_executor)
    with pytest.raises(H.IsolatedExecutionHostError) as contender:
        H.run_isolated_owned_process(
            _python("print('must-not-run')"),
            timeout=0.25,
            coordinator_timeout=5,
        )
    assert contender.value.receipt["completion_authority"] is False
    assert contender.value.receipt["payload"]["reason_code"] == (
        "EXECUTOR_ATTEMPT_ALREADY_ACTIVE"
    )
    monkeypatch.setattr(H.subprocess, "Popen", real_popen)

    assert owner.wait(coordinator_timeout=10).stdout.strip() == "owner-done"
    after = H.run_isolated_owned_process(
        _python("print('after-owner')"),
        timeout=5,
        coordinator_timeout=15,
    )
    assert after.stdout.strip() == "after-owner"


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
@pytest.mark.parametrize(
    ("invalid_bytes", "expected_reason"),
    (
        (b"{", "EXECUTOR_RECEIPT_JSON_INVALID"),
        (b"\xff", "EXECUTOR_RECEIPT_UTF8_INVALID"),
        (b'{"value":NaN}', "EXECUTOR_RECEIPT_JSON_INVALID"),
        (b'{"value":Infinity}', "EXECUTOR_RECEIPT_JSON_INVALID"),
        (b'{"value":-Infinity}', "EXECUTOR_RECEIPT_JSON_INVALID"),
        (b'{"value":1,"value":2}', "EXECUTOR_RECEIPT_JSON_INVALID"),
        (b'{"value":"\\ud800"}', "EXECUTOR_RECEIPT_JSON_INVALID"),
        (
            b"[" * 1100 + b"0" + b"]" * 1100,
            "EXECUTOR_RECEIPT_JSON_INVALID",
        ),
    ),
)
def test_invalid_receipt_after_exact_death_is_debt_but_does_not_block_retry(
    isolated_lease: Path,
    invalid_bytes: bytes,
    expected_reason: str,
) -> None:
    del isolated_lease
    attempt = H.start_isolated_owned_process(
        _python("print('receipt-will-be-corrupted')"),
        timeout=5,
    )
    attempt._process.wait(timeout=15)
    attempt._stdout_collector._thread.join(timeout=5)
    assert not attempt._stdout_collector._thread.is_alive()
    attempt._stdout_collector._data = bytearray(invalid_bytes)

    with pytest.raises(H.IsolatedExecutionHostError) as caught:
        attempt.wait(coordinator_timeout=5)

    assert caught.value.receipt["payload"]["reason_code"] == expected_reason
    retry = H.run_isolated_owned_process(
        _python("print('receipt-retry-ok')"),
        timeout=5,
        coordinator_timeout=15,
    )
    assert retry.stdout.strip() == "receipt-retry-ok"


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_live_request_replay_failure_has_distinct_closed_debt(
    isolated_lease: Path,
) -> None:
    del isolated_lease
    attempt = H.start_isolated_owned_process(
        _python("print('request-replay-will-drift')"),
        timeout=5,
    )
    attempt._process.wait(timeout=15)
    attempt._stdout_collector._thread.join(timeout=5)
    assert not attempt._stdout_collector._thread.is_alive()
    attempt._request["payload"]["timeout"] = 6

    with pytest.raises(H.IsolatedExecutionHostError) as caught:
        attempt.wait(coordinator_timeout=5)

    assert caught.value.receipt["payload"]["reason_code"] == (
        "EXECUTOR_RECEIPT_REQUEST_REPLAY_INVALID"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows disposable Job ownership")
def test_coordinator_parent_death_kills_executor_and_target(
    tmp_path: Path,
    isolated_lease: Path,
) -> None:
    del isolated_lease
    target_pid_path = tmp_path / "parent-death-target.pid"
    scripts_root = Path(H.__file__).resolve().parent
    coordinator_code = "\n".join(
        (
            "import os,sys,time",
            f"sys.path.insert(0, {str(scripts_root)!r})",
            "import isolated_execution_host as H",
            "attempt = H.start_isolated_owned_process(",
            "    (sys.executable, '-I', '-S', '-c',",
            (
                "     "
                + repr(
                    "import os,time;"
                    f"open({str(target_pid_path)!r},'w').write(str(os.getpid()));"
                    "time.sleep(60)"
                )
                + "),"
            ),
            "    timeout=30,",
            f"    writable_roots=({str(tmp_path)!r},),",
            ")",
            f"marker = {str(target_pid_path)!r}",
            "deadline = time.monotonic() + 10",
            "while not os.path.exists(marker) and time.monotonic() < deadline:",
            "    time.sleep(0.01)",
            "os._exit(93)",
        )
    )
    coordinator = subprocess.run(
        [sys.executable, "-I", "-S", "-c", coordinator_code],
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    assert coordinator.returncode == 93, coordinator.stderr.decode(
        "utf-8",
        errors="replace",
    )
    target_pid = int(target_pid_path.read_text(encoding="ascii"))
    deadline = time.monotonic() + 5
    while (
        _windows_process_is_running(target_pid)
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert _windows_process_is_running(target_pid) is False


def test_owned_runner_isolated_adapter_is_lazy_and_registered() -> None:
    import owned_process_runner as O

    assert callable(O.run_owned_process_isolated)
    assert H.REGISTERED_HANDLER_IDS == (
        "RUN_OWNED_PROCESS_V1",
        "RUN_WER_PROVIDER_V1",
    )
    assert H._executor_argv(H.HANDLER_RUN_WER_PROVIDER)[1:3] == (
        "-I",
        "-S",
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows environment semantics")
def test_executor_environment_canonicalizes_case_insensitive_system_keys() -> None:
    environment = H._executor_environment()
    ambient = {key.casefold(): value for key, value in os.environ.items()}
    for canonical in ("SystemRoot", "ComSpec"):
        folded = canonical.casefold()
        if folded in ambient:
            assert environment[canonical] == ambient[folded]
    assert len({key.casefold() for key in environment}) == len(environment)


@pytest.mark.skipif(os.name != "nt", reason="Windows CPython venv redirector")
def test_managed_venv_launch_preserves_identity_and_exact_receipt_pid(
    tmp_path: Path,
) -> None:
    managed = tmp_path / "managed-runtime"
    created = subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(managed)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert created.returncode == 0, created.stderr.decode(
        "utf-8", errors="replace"
    )
    launcher = managed / "Scripts" / "python.exe"
    module_root = Path(H.__file__).resolve().parent
    coordinator_code = "\n".join(
        (
            "import json, os, sys",
            f"sys.path.insert(0, {str(module_root)!r})",
            "import isolated_execution_host as H",
            "logical = str(H._windows_cpython_executor_paths()[0])",
            "physical = str(H._windows_cpython_executor_paths()[1])",
            "attempt = H.start_isolated_owned_process(",
            "    (physical, '-I', '-S', '-c', "
            "\"import json,os;print(json.dumps({'reserved': any(" 
            "k.casefold() == '__pyvenv_launcher__' for k in os.environ)}))\"),",
            "    timeout=10,",
            ")",
            "result = attempt.wait(coordinator_timeout=20)",
            "receipt = attempt.terminal_receipt",
            "print(json.dumps({",
            "    'logical': logical,",
            "    'physical': physical,",
            "    'popen_pid': attempt._process.pid,",
            "    'receipt_pid': receipt['executor_pid'],",
            "    'target': json.loads(result.stdout),",
            "    'reserved_env_visible': any(",
            "        key.casefold() == '__pyvenv_launcher__'",
            "        for key in os.environ",
            "    ),",
            "}))",
        )
    )
    completed = subprocess.run(
        [str(launcher), "-I", "-S", "-c", coordinator_code],
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=40,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", errors="replace"
    )
    observation = json.loads(completed.stdout.decode("utf-8"))
    assert Path(observation["logical"]) == launcher.resolve()
    assert Path(observation["physical"]) == Path(
        getattr(sys, "_base_executable", sys.executable)
    ).resolve()
    assert observation["popen_pid"] == observation["receipt_pid"]
    assert observation["target"]["reserved"] is False
    assert observation["reserved_env_visible"] is False
