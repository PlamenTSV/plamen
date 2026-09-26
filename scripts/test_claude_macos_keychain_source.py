from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import claude_auth_route as A
import claude_stored_subscription_source as S


_ACCOUNT = "fixture-user"
_TOOL_IDENTITY = {
    "path": S.MACOS_SECURITY_TOOL,
    "device": 1,
    "inode": 2,
    "mode": 0o100755,
    "owner_uid": 0,
    "size": 123,
    "mtime_ns": 4,
    "ctime_ns": 5,
    "link_count": 1,
    "sha256": "a" * 64,
}


def _credentials(secret: str = "fake-keychain-secret") -> bytes:
    return json.dumps(
        {
            "claudeAiOauth": {
                "accessToken": secret,
                "refreshToken": f"{secret}-refresh",
                "expiresAt": 4_102_444_800_000,
                "scopes": ["user:inference", "user:profile"],
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class _FakeRunner:
    def __init__(
        self,
        *,
        returncode: int,
        stdout: bytearray | None = None,
        stderr: bytearray | None = None,
        timed_out: bool = False,
        overflowed: bool = False,
    ) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
        self.result = S._SecurityCommandResult(
            returncode=returncode,
            stdout=stdout if stdout is not None else bytearray(),
            stderr=stderr if stderr is not None else bytearray(),
            timed_out=timed_out,
            overflowed=overflowed,
        )

    def __call__(self, argv: tuple[str, ...], **kwargs: object):
        self.calls.append((argv, kwargs))
        return self.result


def _install_fake_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(S, "_detect_host_platform", lambda: S.HOST_MACOS)
    monkeypatch.setattr(S, "_macos_current_account", lambda: _ACCOUNT)
    monkeypatch.setattr(
        S,
        "_macos_security_tool_identity",
        lambda: dict(_TOOL_IDENTITY),
    )


def _private_target(
    path: Path,
) -> tuple[int, S.PrivateCredentialTargetCapability]:
    descriptor = os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    digest = hashlib.sha256(b"macos-keychain-fixture").hexdigest()
    parent = path.parent.stat()
    authority = {
        "schema": S.PRIVATE_CREDENTIAL_TARGET_AUTHORITY_SCHEMA,
        "run_id": "run-macos-keychain-fixture",
        "startup_permit_sha256": digest,
        "outer_attempt_arm_sha256": digest,
        "execution_generation_sha256": digest,
        "work_plan_sha256": digest,
        "attempt_id": "attempt-macos-keychain-fixture",
        "process_scope_identity": "scope-macos-keychain-fixture",
        "auxiliary_lease_binding_sha256": digest,
        "launch_security_policy_sha256": digest,
        "executable_observation_sha256": digest,
        "auth_environment_receipt_sha256": digest,
        "settings_authority_sha256": digest,
        "mcp_authority_sha256": digest,
        "target_role": "CLAUDE_STORED_SUBSCRIPTION_CREDENTIAL",
        "credential_parent_identity": {
            "device": int(parent.st_dev),
            "inode": int(parent.st_ino),
        },
    }
    return descriptor, S.authorize_private_credential_target(
        descriptor,
        destination_path=path,
        target_authority=authority,
    )


def test_observation_uses_only_exact_service_account_and_redacts_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)
    runner = _FakeRunner(
        returncode=0,
        stdout=bytearray(b"non-secret metadata"),
    )

    evidence = S._observe_macos_keychain(runner=runner)

    assert runner.calls == [
        (
            (
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "Claude Code-credentials",
                "-a",
                _ACCOUNT,
            ),
            {
                "timeout_s": S.MACOS_KEYCHAIN_TIMEOUT_SECONDS,
                "stdout_ceiling": (
                    S.MAX_KEYCHAIN_OBSERVATION_STDOUT_BYTES
                ),
                "stderr_ceiling": S.MAX_KEYCHAIN_STDERR_BYTES,
            },
        )
    ]
    assert evidence["store_class"] == "OS_KEYCHAIN"
    assert evidence["available"] is True
    assert evidence["source_size"] == 0
    assert evidence["source_identity"].startswith("keychain-macos-")
    serialized = json.dumps(evidence, sort_keys=True)
    assert _ACCOUNT not in serialized
    assert S.MACOS_CLAUDE_KEYCHAIN_SERVICE not in serialized
    assert "credentials-" not in runner.calls[0][0][3]
    assert A.replay_stored_subscription_source_evidence(evidence) == evidence
    assert runner.result.stdout == bytearray()


def test_observation_replays_injected_tool_identity_around_command() -> None:
    identities = iter(
        (
            dict(_TOOL_IDENTITY),
            {**_TOOL_IDENTITY, "sha256": "b" * 64},
        )
    )
    observed = 0

    def observe_identity() -> dict[str, object]:
        nonlocal observed
        observed += 1
        return next(identities)

    captured = bytearray(b"redacted metadata")
    runner = _FakeRunner(returncode=0, stdout=captured)

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="command authority changed",
    ) as raised:
        S._observe_macos_keychain(
            runner=runner,
            account=_ACCOUNT,
            tool_identity_observer=observe_identity,
        )

    assert raised.value.reason_code == "KEYCHAIN_TOOL_CHANGED"
    assert observed == 2
    assert len(runner.calls) == 1
    assert all(value == 0 for value in captured)


def test_oauth_token_absence_observation_never_queries_keychain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)

    def forbidden_runner(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("OAuth-token absence evidence queried Keychain")

    monkeypatch.setattr(S, "_run_bounded_security_command", forbidden_runner)
    evidence = S.observe_stored_subscription_source(source_path=None)

    assert evidence["store_class"] == "OS_KEYCHAIN"
    assert evidence["available"] is False
    assert evidence["source_identity"] == "keychain-macos-route-not-selected"

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="stored-route marker",
    ):
        S.acquire_stored_subscription_materialization(source_path=None)


@pytest.mark.parametrize(
    ("returncode", "timed_out", "identity_fragment"),
    (
        (44, False, "unavailable"),
        (36, False, "interaction"),
        (128, False, "interaction"),
        (-9, True, "interaction"),
    ),
)
def test_observation_distinguishes_absence_from_interaction_without_output(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    timed_out: bool,
    identity_fragment: str,
) -> None:
    _install_fake_host(monkeypatch)
    captured = bytearray(b"must-be-erased")
    runner = _FakeRunner(
        returncode=returncode,
        stdout=captured,
        timed_out=timed_out,
    )

    evidence = S._observe_macos_keychain(runner=runner)

    assert evidence["available"] is False
    assert identity_fragment in evidence["source_identity"]
    assert all(value == 0 for value in captured)


def test_keychain_acquisition_materializes_once_and_zeroizes_source_buffer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)
    raw = _credentials()
    captured = bytearray(raw + b"\n")
    runner = _FakeRunner(returncode=0, stdout=captured)
    monkeypatch.setattr(S, "_run_bounded_security_command", runner)
    marker = tmp_path / ".claude" / ".credentials.json"

    capability = S.acquire_stored_subscription_materialization(
        source_path=marker
    )
    evidence = capability.source_evidence
    assert evidence["store_class"] == "OS_KEYCHAIN"
    assert evidence["source_size"] == len(raw)
    assert runner.calls[0][0][-1] == "-w"
    assert runner.calls[0][0][2:6] == (
        "-s",
        "Claude Code-credentials",
        "-a",
        _ACCOUNT,
    )

    target = tmp_path / "attempt-credentials"
    descriptor, target_capability = _private_target(target)
    try:
        receipt = capability.consume_into_private_descriptor(
            target_capability,
            expected_source_evidence=evidence,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(raw) + 1) == raw
    finally:
        os.close(descriptor)

    assert receipt["source_descriptor_replayed"] is False
    assert receipt["source_path_reopened"] is False
    assert receipt["source_bytes_reread"] is False
    assert S.replay_stored_subscription_materialization_receipt(receipt) == receipt
    assert all(value == 0 for value in captured)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="no longer available",
    ):
        capability.discard()


def test_acquisition_replays_injected_tool_identity_around_command() -> None:
    identities = iter(
        (
            dict(_TOOL_IDENTITY),
            {**_TOOL_IDENTITY, "inode": 999},
        )
    )
    observed = 0

    def observe_identity() -> dict[str, object]:
        nonlocal observed
        observed += 1
        return next(identities)

    captured = bytearray(_credentials())
    runner = _FakeRunner(returncode=0, stdout=captured)

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="command authority changed",
    ) as raised:
        S._acquire_macos_keychain_materialization(
            runner=runner,
            account=_ACCOUNT,
            tool_identity_observer=observe_identity,
        )

    assert raised.value.reason_code == "KEYCHAIN_TOOL_CHANGED"
    assert observed == 2
    assert len(runner.calls) == 1
    assert all(value == 0 for value in captured)


def test_acquisition_failures_are_typed_sanitized_and_zeroized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)
    secret = "never-include-this-secret-in-diagnostics"
    captured = bytearray(secret.encode("utf-8"))
    runner = _FakeRunner(
        returncode=-9,
        stdout=captured,
        timed_out=True,
    )

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="requires user interaction",
    ) as raised:
        S._acquire_macos_keychain_materialization(runner=runner)

    assert raised.value.reason_code == "KEYCHAIN_INTERACTION_REQUIRED"
    assert secret not in str(raised.value)
    assert all(value == 0 for value in captured)


@pytest.mark.parametrize(
    "captured",
    (
        bytearray(
            b'{"claudeAiOauth":{"accessToken":"exception-chain-secret",'
        ),
        bytearray(b"\xffexception-chain-secret"),
    ),
    ids=("malformed-json", "invalid-utf8"),
)
def test_acquisition_parse_errors_retain_no_secret_exception_chain(
    monkeypatch: pytest.MonkeyPatch,
    captured: bytearray,
) -> None:
    _install_fake_host(monkeypatch)
    runner = _FakeRunner(returncode=0, stdout=captured)

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="unsupported credential-store format",
    ) as raised:
        S._acquire_macos_keychain_materialization(runner=runner)

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "exception-chain-secret" not in str(raised.value)
    assert "exception-chain-secret" not in repr(raised.value)
    assert all(value == 0 for value in captured)


def test_semantic_validation_error_clears_secret_traceback_locals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)
    secret = "semantic-traceback-secret"
    captured = bytearray(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": secret,
                    "refreshToken": "",
                    "expiresAt": 4_102_444_800_000,
                    "scopes": ["user:inference"],
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    runner = _FakeRunner(returncode=0, stdout=captured)

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="unsupported credential-store format",
    ) as raised:
        S._acquire_macos_keychain_materialization(runner=runner)

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    validation_locals: dict[str, object] | None = None
    traceback = raised.value.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code.co_name == "_validate_file_store_shape":
            validation_locals = dict(traceback.tb_frame.f_locals)
            break
        traceback = traceback.tb_next
    assert validation_locals is not None

    def contains_secret(value: object, seen: set[int]) -> bool:
        identity = id(value)
        if identity in seen:
            return False
        seen.add(identity)
        if isinstance(value, str):
            return secret in value
        if isinstance(value, (bytes, bytearray)):
            return secret.encode("utf-8") in value
        if isinstance(value, dict):
            return any(
                contains_secret(item, seen)
                for pair in value.items()
                for item in pair
            )
        if isinstance(value, (list, tuple, set, frozenset)):
            return any(contains_secret(item, seen) for item in value)
        return False

    assert not any(
        contains_secret(value, set()) for value in validation_locals.values()
    )
    assert all(value == 0 for value in captured)


def test_bounded_runner_uses_no_shell_input_environment_or_inherited_cwd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)
    captured: dict[str, object] = {}

    class _FakeProcess:
        pid = 999_999

        def __init__(self) -> None:
            stdout_reader, stdout_writer = os.pipe()
            stderr_reader, stderr_writer = os.pipe()
            os.write(stdout_writer, b"metadata")
            os.close(stdout_writer)
            os.close(stderr_writer)
            self.stdout = os.fdopen(stdout_reader, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_reader, "rb", buffering=0)
            self.returncode = 0

        def wait(self, timeout: float) -> int:
            assert timeout > 0
            return 0

    def fake_popen(argv: tuple[str, ...], **kwargs: object) -> _FakeProcess:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _FakeProcess()

    monkeypatch.setattr(S.subprocess, "Popen", fake_popen)
    argv = (
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        "Claude Code-credentials",
        "-a",
        _ACCOUNT,
    )
    result = S._run_bounded_security_command(
        argv,
        timeout_s=1.0,
        stdout_ceiling=1024,
        stderr_ceiling=1024,
    )
    try:
        assert result.stdout == bytearray(b"metadata")
        assert captured["argv"] == argv
        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        assert kwargs["stdin"] is S.subprocess.DEVNULL
        assert kwargs["env"] == {}
        assert kwargs["cwd"] == "/"
        assert kwargs["shell"] is False
        assert kwargs["close_fds"] is True
        assert kwargs["start_new_session"] is True
        assert kwargs["text"] is False
    finally:
        result.discard()


def test_bounded_runner_rejects_every_non_query_security_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)

    def forbidden_popen(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a rejected Keychain command was launched")

    monkeypatch.setattr(S.subprocess, "Popen", forbidden_popen)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="command policy is malformed",
    ):
        S._run_bounded_security_command(
            (
                "/usr/bin/security",
                "delete-generic-password",
                "-s",
                "Claude Code-credentials",
                "-a",
                _ACCOUNT,
            ),
            timeout_s=1.0,
            stdout_ceiling=1024,
            stderr_ceiling=1024,
        )


def test_bounded_runner_timeout_kills_group_reaps_and_closes_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)

    class _HangingProcess:
        pid = 999_998

        def __init__(self) -> None:
            stdout_reader, self._stdout_writer = os.pipe()
            stderr_reader, self._stderr_writer = os.pipe()
            self.stdout = os.fdopen(stdout_reader, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_reader, "rb", buffering=0)
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float) -> int:
            if self.returncode is None:
                raise S.subprocess.TimeoutExpired("security", timeout)
            return self.returncode

        def kill(self) -> None:
            if self.returncode is not None:
                return
            self.returncode = -9
            os.close(self._stdout_writer)
            os.close(self._stderr_writer)

    process = _HangingProcess()
    killed_groups: list[tuple[int, int]] = []

    monkeypatch.setattr(S.subprocess, "Popen", lambda *_a, **_kw: process)
    monkeypatch.setattr(S.os, "getpgid", lambda pid: pid)

    def fake_killpg(pid: int, sig: int) -> None:
        killed_groups.append((pid, sig))
        process.kill()

    monkeypatch.setattr(S.os, "killpg", fake_killpg)
    result = S._run_bounded_security_command(
        (
            "/usr/bin/security",
            "find-generic-password",
            "-s",
            "Claude Code-credentials",
            "-a",
            _ACCOUNT,
        ),
        timeout_s=0.01,
        stdout_ceiling=1024,
        stderr_ceiling=1024,
    )
    try:
        assert result.timed_out is True
        assert process.returncode == -9
        assert len(killed_groups) >= 1
        assert all(
            row == (process.pid, S.signal.SIGKILL)
            for row in killed_groups
        )
        assert process.stdout.closed is True
        assert process.stderr.closed is True
    finally:
        result.discard()


def test_bounded_runner_kills_exited_leader_group_with_open_real_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)

    class _ExitedLeaderWithDescendantPipes:
        pid = 999_997

        def __init__(self) -> None:
            stdout_reader, self._stdout_writer = os.pipe()
            stderr_reader, self._stderr_writer = os.pipe()
            self.stdout = os.fdopen(stdout_reader, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_reader, "rb", buffering=0)
            self.returncode = 0
            self.waits = 0
            self.descendant_pipes_closed = False

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float) -> int:
            self.waits += 1
            return 0

        def close_descendant_pipes(self) -> None:
            if self.descendant_pipes_closed:
                return
            os.close(self._stdout_writer)
            os.close(self._stderr_writer)
            self.descendant_pipes_closed = True

    process = _ExitedLeaderWithDescendantPipes()
    killed_groups: list[tuple[int, int]] = []
    monkeypatch.setattr(S.subprocess, "Popen", lambda *_a, **_kw: process)

    def fake_killpg(pid: int, sig: int) -> None:
        killed_groups.append((pid, sig))
        process.close_descendant_pipes()

    monkeypatch.setattr(S.os, "killpg", fake_killpg)
    result = S._run_bounded_security_command(
        (
            "/usr/bin/security",
            "find-generic-password",
            "-s",
            "Claude Code-credentials",
            "-a",
            _ACCOUNT,
        ),
        timeout_s=0.01,
        stdout_ceiling=1024,
        stderr_ceiling=1024,
    )
    try:
        assert result.timed_out is True
        assert len(killed_groups) >= 1
        assert all(
            row == (process.pid, S.signal.SIGKILL)
            for row in killed_groups
        )
        assert process.descendant_pipes_closed is True
        assert process.waits >= 1
        assert process.stdout.closed is True
        assert process.stderr.closed is True
    finally:
        process.close_descendant_pipes()
        result.discard()


def test_selector_constructor_failure_still_kills_reaps_and_closes_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)

    class _Process:
        pid = 999_996

        def __init__(self) -> None:
            stdout_reader, self._stdout_writer = os.pipe()
            stderr_reader, self._stderr_writer = os.pipe()
            self.stdout = os.fdopen(stdout_reader, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_reader, "rb", buffering=0)
            self.returncode: int | None = None
            self.waits = 0

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float) -> int:
            self.waits += 1
            if self.returncode is None:
                raise S.subprocess.TimeoutExpired("security", timeout)
            return self.returncode

        def kill(self) -> None:
            if self.returncode is not None:
                return
            self.returncode = -9
            os.close(self._stdout_writer)
            os.close(self._stderr_writer)

    process = _Process()
    killed_groups: list[tuple[int, int]] = []
    monkeypatch.setattr(S.subprocess, "Popen", lambda *_a, **_kw: process)

    def fake_killpg(pid: int, sig: int) -> None:
        killed_groups.append((pid, sig))
        process.kill()

    monkeypatch.setattr(S.os, "killpg", fake_killpg)

    def fail_selector() -> None:
        raise OSError("fake selector allocation failure")

    monkeypatch.setattr(S.selectors, "DefaultSelector", fail_selector)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="command capture failed",
    ) as raised:
        S._run_bounded_security_command(
            (
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "Claude Code-credentials",
                "-a",
                _ACCOUNT,
            ),
            timeout_s=0.01,
            stdout_ceiling=1024,
            stderr_ceiling=1024,
        )

    assert raised.value.reason_code == "KEYCHAIN_CAPTURE_FAILED"
    assert killed_groups
    assert process.waits >= 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_selector_close_failure_cannot_skip_process_and_pipe_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_host(monkeypatch)

    class _CompletedProcess:
        pid = 999_995

        def __init__(self) -> None:
            stdout_reader, stdout_writer = os.pipe()
            stderr_reader, stderr_writer = os.pipe()
            os.close(stdout_writer)
            os.close(stderr_writer)
            self.stdout = os.fdopen(stdout_reader, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_reader, "rb", buffering=0)
            self.returncode = 0
            self.waits = 0

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float) -> int:
            self.waits += 1
            return 0

    process = _CompletedProcess()
    real_selector = S.selectors.DefaultSelector()

    class _CloseFailingSelector:
        def register(self, *args: object, **kwargs: object):
            return real_selector.register(*args, **kwargs)

        def unregister(self, *args: object, **kwargs: object):
            return real_selector.unregister(*args, **kwargs)

        def get_map(self):
            return real_selector.get_map()

        def select(self, *args: object, **kwargs: object):
            return real_selector.select(*args, **kwargs)

        def close(self) -> None:
            real_selector.close()
            raise OSError("fake selector close failure")

    killed_groups: list[tuple[int, int]] = []
    monkeypatch.setattr(S.subprocess, "Popen", lambda *_a, **_kw: process)
    monkeypatch.setattr(
        S.selectors,
        "DefaultSelector",
        lambda: _CloseFailingSelector(),
    )
    monkeypatch.setattr(
        S.os,
        "killpg",
        lambda pid, sig: killed_groups.append((pid, sig)),
    )

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="command capture failed",
    ) as raised:
        S._run_bounded_security_command(
            (
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "Claude Code-credentials",
                "-a",
                _ACCOUNT,
            ),
            timeout_s=0.1,
            stdout_ceiling=1024,
            stderr_ceiling=1024,
        )

    assert raised.value.reason_code == "KEYCHAIN_CAPTURE_FAILED"
    assert killed_groups
    assert process.waits >= 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True
