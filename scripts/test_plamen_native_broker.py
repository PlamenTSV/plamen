"""Focused TEST_ONLY wire tests for the native POSIX broker core."""

from __future__ import annotations

import array
import ctypes
import errno
import fcntl
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
from types import ModuleType
from typing import Any, Iterator

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER = REPO_ROOT / "scripts" / "TEST_ONLY_build_posix_native_broker.py"
MAGIC = b"PLMBRK1\0"
HEADER_SIZE = 196
HEADER = struct.Struct(">8sHHIIIHHQ32s32s32s32s32s")
ZERO = bytes(32)
FRAME_RECEIPT = 3
FRAME_RECEIPT_CANDIDATE = 4
FRAME_RECEIPT_ACK = 5
FRAME_RECEIPT_COMMIT_ACK = 6

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="Darwin broker core; other POSIX targets hard-stop"
)


def _clear_owned_test_immutable_flags(root: Path) -> None:
    """Restore only Darwin flags created below one pytest-owned root."""

    immutable = getattr(stat, "UF_IMMUTABLE", 0)
    if sys.platform != "darwin" or not immutable or not root.is_absolute():
        return

    def clear(path: Path) -> None:
        try:
            info = path.lstat()
            if (
                not stat.S_ISLNK(info.st_mode)
                and info.st_uid == os.geteuid()
                and getattr(info, "st_flags", 0) & immutable
            ):
                os.chflags(
                    path, int(info.st_flags) & ~immutable,
                    follow_symlinks=False,
                )
        except OSError:
            pass

    clear(root)
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        clear(parent)
        for name in (*names, *files):
            clear(parent / name)


@pytest.fixture(autouse=True)
def _restore_test_output_flags(request: pytest.FixtureRequest):
    yield
    root = request.node.funcargs.get("tmp_path")
    if not isinstance(root, Path):
        return
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        return
    if resolved == Path(os.path.abspath(os.fspath(root))):
        _clear_owned_test_immutable_flags(resolved)


def _read_exact(stream: socket.socket, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = stream.recv(size - len(value))
        if not chunk:
            raise EOFError("broker frame was truncated")
        value.extend(chunk)
    return bytes(value)


def _sha256_fd(descriptor: int) -> bytes:
    info = os.fstat(descriptor)
    digest = hashlib.sha256()
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(descriptor, min(65536, info.st_size - offset), offset)
        assert chunk
        digest.update(chunk)
        offset += len(chunk)
    return digest.digest()


def _identity(descriptor: int) -> bytes:
    info = os.fstat(descriptor)
    content = _sha256_fd(descriptor) if stat.S_ISREG(info.st_mode) else ZERO
    canonical = struct.pack(
        ">10Q32s",
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns // 1_000_000_000,
        info.st_mtime_ns % 1_000_000_000,
        info.st_ctime_ns // 1_000_000_000,
        info.st_ctime_ns % 1_000_000_000,
        content,
    )
    return hashlib.sha256(canonical).digest()


def _text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def _frame(
    *, frame_type: int, sequence: int, session: bytes, nonce: bytes,
    previous: bytes, payload: bytes, key: bytes, fd_count: int,
) -> bytes:
    digest = hashlib.sha256(payload).digest()
    prefix = HEADER.pack(
        MAGIC, 1, frame_type, 0, HEADER_SIZE, len(payload), fd_count, 0,
        sequence, session, nonce, previous, digest, ZERO,
    )
    authenticator = hmac.new(key, prefix[:164] + payload, hashlib.sha256).digest()
    return prefix[:164] + authenticator + payload


def _receive_frame(stream: socket.socket) -> tuple[tuple[object, ...], bytes]:
    raw_header = _read_exact(stream, HEADER_SIZE)
    fields = HEADER.unpack(raw_header)
    payload = _read_exact(stream, int(fields[5]))
    assert hashlib.sha256(payload).digest() == fields[12]
    return fields, payload


def _authenticated_frame_digest(fields: tuple[object, ...], payload: bytes) -> bytes:
    return hashlib.sha256(HEADER.pack(*fields) + payload).digest()


def _process_executable() -> Path:
    library = ctypes.CDLL(None, use_errno=True)
    buffer = ctypes.create_string_buffer(4096)
    amount = library.proc_pidpath(os.getpid(), buffer, len(buffer))
    assert amount > 0
    return Path(buffer.value.decode("utf-8"))


def test_test_only_builder_compiles_retained_source_not_mutated_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_test_builder()
    source = tmp_path / "broker.c"
    original = (REPO_ROOT / "native" / "posix" / "plamen_native_broker.c").read_bytes()
    mutated = original.replace(b"{'P','L','M'", b"{'X','L','M'", 1)
    assert mutated != original and len(mutated) == len(original)
    source.write_bytes(original)
    monkeypatch.setattr(builder, "SOURCE", source)
    real_run = builder.subprocess.run
    real_freeze = builder._freeze_descriptor
    compiler_output = bytearray()
    attacked = False
    source_was_read_only = False

    def mutate_before_compiler(command: object, *args: object, **kwargs: object) -> object:
        nonlocal attacked, source_was_read_only
        if (
            isinstance(command, tuple)
            and "-DPLAMEN_NATIVE_BROKER_TEST_ONLY=1" in command
            and not attacked
        ):
            attacked = True
            source_descriptor = int(command[-3].rsplit("/", 1)[1])
            assert (
                fcntl.fcntl(source_descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            ) == os.O_RDONLY
            with pytest.raises(OSError) as rejected:
                os.pwrite(source_descriptor, b"X", 0)
            assert rejected.value.errno == errno.EBADF
            source_was_read_only = True
            source.write_bytes(mutated)
        return real_run(command, *args, **kwargs)

    def retain_compiler_output(
        descriptor: int, mode: int, *, expected_nlink: int,
    ) -> dict[str, int | str]:
        identity = real_freeze(
            descriptor, mode, expected_nlink=expected_nlink,
        )
        raw = os.pread(descriptor, int(identity["size"]), 0)
        if raw.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
            compiler_output.extend(raw)
        return identity

    monkeypatch.setattr(builder.subprocess, "run", mutate_before_compiler)
    monkeypatch.setattr(builder, "_freeze_descriptor", retain_compiler_output)
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    with pytest.raises(builder.TestOnlyBuildError, match="original source changed"):
        builder.build_for_testing(root)
    assert attacked is True
    assert source_was_read_only is True
    assert b"PLMBRK1\0" in compiler_output
    assert not list(root.iterdir())


def test_test_only_builder_binds_exact_include_root_and_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_test_builder()
    native = tmp_path / "native"
    posix = native / "posix"
    include = native / "include"
    posix.mkdir(parents=True)
    include.mkdir()
    source = posix / "plamen_native_broker.c"
    header = include / "plamen_broker_v2.h"
    source.write_bytes(
        (REPO_ROOT / "native" / "posix" / "plamen_native_broker.c").read_bytes()
    )
    header.write_bytes(
        (REPO_ROOT / "native" / "include" / "plamen_broker_v2.h").read_bytes()
    )
    monkeypatch.setattr(builder, "SOURCE", source)
    monkeypatch.setattr(builder, "SOURCE_INCLUDE_ROOT", posix)
    monkeypatch.setattr(builder, "SHARED_BROKER_HEADER", header)
    real_run = builder.subprocess.run
    attacked = False

    def mutate_header_after_compile(command, *args, **kwargs):
        nonlocal attacked
        result = real_run(command, *args, **kwargs)
        if (
            isinstance(command, tuple)
            and "-DPLAMEN_NATIVE_BROKER_TEST_ONLY=1" in command
            and not attacked
        ):
            attacked = True
            header.write_bytes(header.read_bytes() + b"\n/* drift */\n")
        return result

    monkeypatch.setattr(builder.subprocess, "run", mutate_header_after_compile)
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    with pytest.raises(
        builder.TestOnlyBuildError,
        match="admitted include authority changed",
    ):
        builder.build_for_testing(root)
    assert attacked is True
    assert not list(root.iterdir())


def test_test_only_builder_returns_descriptor_identity_and_detects_path_replacement(
    tmp_path: Path,
) -> None:
    builder = _load_test_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    artifact = builder.build_for_testing(root)
    try:
        result = artifact.public_result()
        assert "artifact_path" not in result
        retained = artifact.read_bytes()
        with pytest.raises(builder.TestOnlyBuildError, match="pathname execution"):
            artifact.TEST_ONLY_spawn_path()
        observed_path = root / artifact.build_key_sha256 / builder.OUTPUT_NAME
        os.chflags(observed_path, 0)
        observed_path.unlink()
        observed_path.write_bytes(b"ATTACKER-SUBSTITUTION")
        with pytest.raises(builder.TestOnlyBuildError):
            artifact.revalidate()
        assert os.pread(artifact.fileno(), len(retained), 0) == retained
    finally:
        artifact.close()


def test_test_only_builder_rejects_output_root_ancestor_rebind(
    tmp_path: Path,
) -> None:
    builder = _load_test_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    artifact = builder.build_for_testing(root)
    retained = artifact.read_bytes()
    moved = tmp_path / "retained-root-moved"
    marker = tmp_path / "substituted-path-executed"
    try:
        root.rename(moved)
        root.mkdir(mode=0o700)
        attacker_build = root / artifact.build_key_sha256
        attacker_build.mkdir(mode=0o700)
        attacker = attacker_build / builder.OUTPUT_NAME
        attacker.write_text(
            "#!/bin/sh\n/usr/bin/touch " + os.fspath(marker) + "\n",
            encoding="utf-8",
        )
        attacker.chmod(0o700)
        with pytest.raises(builder.TestOnlyBuildError, match="output-root pathname"):
            artifact.revalidate()
        with pytest.raises(builder.TestOnlyBuildError, match="pathname execution"):
            artifact.TEST_ONLY_spawn_path()
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with pytest.raises(builder.TestOnlyBuildError, match="unavailable on Darwin"):
                artifact.TEST_ONLY_spawn(child.fileno())
        finally:
            parent.close()
            child.close()
        assert not marker.exists()
        assert os.pread(artifact.fileno(), len(retained), 0) == retained
    finally:
        artifact.close()


def test_authority_claiming_spawn_hardstops_before_fork_or_path_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_test_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    artifact = builder.build_for_testing(root)
    marker = tmp_path / "authority-spawn-effect-ran"

    def forbidden_popen(*_args: object, **_kwargs: object) -> object:
        marker.touch()
        raise AssertionError("pathname Popen must be unreachable")

    def forbidden_fork() -> int:
        marker.touch()
        raise AssertionError("fork must be unreachable")

    def forbidden_read(*_args: object, **_kwargs: object) -> bytes:
        marker.touch()
        raise KeyboardInterrupt

    monkeypatch.setattr(builder.subprocess, "Popen", forbidden_popen)
    monkeypatch.setattr(builder.os, "fork", forbidden_fork)
    monkeypatch.setattr(builder.os, "read", forbidden_read)
    try:
        with pytest.raises(builder.TestOnlyBuildError, match="unavailable on Darwin"):
            artifact.TEST_ONLY_spawn(object())
        assert not marker.exists()
    finally:
        artifact.close()


def test_test_only_builder_returns_only_read_only_retained_artifact(
    tmp_path: Path,
) -> None:
    builder = _load_test_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    artifact = builder.build_for_testing(root)
    try:
        assert fcntl.fcntl(artifact.fileno(), fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        with pytest.raises(OSError) as rejected:
            os.pwrite(artifact.fileno(), b"X", 0)
        assert rejected.value.errno == errno.EBADF
        artifact.revalidate()
    finally:
        artifact.close()


def _load_test_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("plamen_TEST_ONLY_broker_builder", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def broker(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Any]:
    root = tmp_path_factory.mktemp("native-broker-test")
    root.chmod(0o700)
    artifact = _load_test_builder().build_for_testing(root)
    try:
        result = artifact.public_result()
        assert result["production_packaging_allowed"] is False
        assert result["artifact_descriptor_handoff"] == (
            "RETAINED_IMMUTABLE_TEST_ONLY_FD"
        )
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == (
            result["artifact_identity"]["sha256"]
        )
        assert result["artifact_identity"]["nlink"] == 1
        yield artifact
    finally:
        artifact.close()
        _clear_owned_test_immutable_flags(root.resolve(strict=True))


class Session:
    def __init__(self, broker: Any, tmp_path: Path) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket = parent
        broker.revalidate()
        self.process = broker.UNAUTHENTICATED_TEST_HARNESS_spawn(child.fileno())
        assert type(self.process).__name__ == (
            "UNAUTHENTICATED_TEST_HARNESS_BrokerProcess"
        )
        child.close()
        fields, hello = _receive_frame(parent)
        assert fields[:9] == (MAGIC, 1, 1, 0, HEADER_SIZE, 48, 0, 0, 0)
        assert fields[10] == ZERO and fields[11] == ZERO and fields[13] == ZERO
        self.session = fields[9]
        self.key = hello[:32]
        self.creator_pid, self.creator_birth = struct.unpack(">QQ", hello[32:])
        assert self.creator_pid == os.getpid()
        self.nonce = hashlib.sha256(os.urandom(32)).digest()
        self.opened: list[int] = []

        interpreter = os.open(_process_executable(), os.O_RDONLY | os.O_NOFOLLOW)
        executable_path = Path("/bin/sh")
        executable = os.open(executable_path, os.O_RDONLY | os.O_NOFOLLOW)
        cwd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stdin_path = tmp_path / "stdin"
        stdin_path.write_bytes(b"STDIN-VALUE\n")
        stdin_fd = os.open(stdin_path, os.O_RDONLY | os.O_NOFOLLOW)
        pass_path = tmp_path / "passed"
        pass_path.write_bytes(b"PASS-VALUE\n")
        pass_fd = os.open(pass_path, os.O_RDONLY | os.O_NOFOLLOW)
        self.opened.extend((interpreter, executable, cwd, stdin_fd, pass_fd))
        executable_name = os.path.realpath(executable_path)
        script = (
            "IFS= read -r passed <&9; IFS= read -r input; "
            "printf '%s|%s|%s|%s' \"$A\" \"$PWD\" \"$passed\" \"$input\"; "
            "printf 'STDERR-VALUE' >&2"
        )
        self.script = script
        self.environment = ["A=ENV-VALUE", "PATH=/usr/bin:/bin"]
        argv = [executable_name, "-c", script]
        environment = self.environment
        payload = bytearray(
            struct.pack(
                ">IQQIII",
                1, self.creator_pid, self.creator_birth, 10_000, 4096, 4096,
            )
        )
        payload.extend(_identity(interpreter))
        payload.extend(_identity(executable))
        payload.extend(_identity(cwd))
        payload.extend(_identity(stdin_fd))
        payload.extend(_text("attempt-native-broker-001"))
        payload.extend(struct.pack(">I", len(argv)))
        for item in argv:
            payload.extend(_text(item))
        payload.extend(struct.pack(">I", len(environment)))
        for item in environment:
            payload.extend(_text(item))
        payload.extend(struct.pack(">I", 1))
        payload.extend(struct.pack(">I", 9))
        payload.extend(_identity(pass_fd))
        self.payload = bytes(payload)

    def payload_with_script(self, replacement: str) -> bytes:
        original = self.script.encode("utf-8")
        changed = replacement.encode("utf-8")
        assert len(changed) <= len(original)
        changed += b" " * (len(original) - len(changed))
        assert self.payload.count(original) == 1
        return self.payload.replace(original, changed)

    def send(self, *, payload: bytes | None = None, key: bytes | None = None,
             fds: list[int] | None = None) -> None:
        body = self.payload if payload is None else payload
        roster = self.opened if fds is None else fds
        wire = _frame(
            frame_type=2, sequence=1, session=self.session,
            nonce=self.nonce, previous=ZERO, payload=body,
            key=self.key if key is None else key, fd_count=len(roster),
        )
        sent = self.socket.sendmsg(
            [wire[:HEADER_SIZE]],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", roster))],
        )
        assert sent == HEADER_SIZE
        self.socket.sendall(wire[HEADER_SIZE:])

    def request_wire(
        self, *, payload: bytes | None = None, key: bytes | None = None,
        fds: list[int] | None = None,
    ) -> tuple[bytes, list[int]]:
        body = self.payload if payload is None else payload
        roster = self.opened if fds is None else fds
        return _frame(
            frame_type=2, sequence=1, session=self.session,
            nonce=self.nonce, previous=ZERO, payload=body,
            key=self.key if key is None else key, fd_count=len(roster),
        ), roster

    def acknowledge(
        self, *, frame_type: int, sequence: int, previous: bytes,
    ) -> bytes:
        wire = _frame(
            frame_type=frame_type, sequence=sequence, session=self.session,
            nonce=self.nonce, previous=previous, payload=previous,
            key=self.key, fd_count=0,
        )
        self.socket.sendall(wire)
        return hashlib.sha256(wire).digest()

    def close(self) -> None:
        self.socket.close()
        for descriptor in self.opened:
            os.close(descriptor)
        self.process.wait(timeout=10)


def _receive_committed_receipt(
    session: Session,
) -> tuple[tuple[object, ...], bytes]:
    candidate_fields, candidate_payload = _receive_frame(session.socket)
    assert candidate_fields[:9] == (
        MAGIC, 1, FRAME_RECEIPT_CANDIDATE, 0, HEADER_SIZE,
        len(candidate_payload), 0, 0, 2,
    )
    assert hmac.new(
        session.key,
        HEADER.pack(*candidate_fields)[:164] + candidate_payload,
        hashlib.sha256,
    ).digest() == candidate_fields[13]
    candidate_digest = _authenticated_frame_digest(
        candidate_fields, candidate_payload,
    )
    ack_digest = session.acknowledge(
        frame_type=FRAME_RECEIPT_ACK, sequence=3, previous=candidate_digest,
    )
    commit_fields, commit_payload = _receive_frame(session.socket)
    assert commit_fields[:9] == (
        MAGIC, 1, FRAME_RECEIPT, 0, HEADER_SIZE, 32, 0, 0, 4,
    )
    assert commit_fields[9] == session.session
    assert commit_fields[10] == session.nonce
    assert commit_fields[11] == ack_digest
    assert commit_payload == candidate_digest
    assert hmac.new(
        session.key,
        HEADER.pack(*commit_fields)[:164] + commit_payload,
        hashlib.sha256,
    ).digest() == commit_fields[13]
    commit_digest = _authenticated_frame_digest(commit_fields, commit_payload)
    session.acknowledge(
        frame_type=FRAME_RECEIPT_COMMIT_ACK,
        sequence=5,
        previous=commit_digest,
    )
    assert session.socket.recv(1) == b""
    assert session.process.wait(timeout=10) == 0
    return candidate_fields, candidate_payload


def _parse_receipt(payload: bytes) -> dict[str, object]:
    offset = 0

    def take(fmt: str) -> tuple[object, ...]:
        nonlocal offset
        row = struct.Struct(fmt)
        values = row.unpack_from(payload, offset)
        offset += row.size
        return values

    version, status, rc, signal_number = take(">IIII")
    child, creator, birth = take(">QQQ")
    containment, extinct = take(">II")
    (attempt_size,) = take(">I")
    attempt = payload[offset : offset + int(attempt_size)].decode("ascii")
    offset += int(attempt_size)
    digests = []
    for _ in range(13):
        digests.append(payload[offset : offset + 32])
        offset += 32
    (stdout_observed,) = take(">Q")
    stdout_size, stdout_truncated = take(">II")
    stdout = payload[offset : offset + int(stdout_size)]
    offset += int(stdout_size)
    (stderr_observed,) = take(">Q")
    stderr_size, stderr_truncated = take(">II")
    stderr = payload[offset : offset + int(stderr_size)]
    offset += int(stderr_size)
    assert offset == len(payload)
    return {
        "version": version, "status": status, "rc": rc,
        "signal": signal_number, "child": child, "creator": creator,
        "birth": birth, "containment": containment, "extinct": extinct,
        "attempt": attempt, "digests": digests,
        "stdout_observed": stdout_observed, "stdout_truncated": stdout_truncated,
        "stdout": stdout, "stderr_observed": stderr_observed,
        "stderr_truncated": stderr_truncated, "stderr": stderr,
    }


def test_native_broker_launch_wait_receipt_and_fd_bindings(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        session.send()
        fields, payload = _receive_committed_receipt(session)
        assert fields[:9] == (
            MAGIC, 1, FRAME_RECEIPT_CANDIDATE, 0,
            HEADER_SIZE, len(payload), 0, 0, 2,
        )
        assert fields[9] == session.session
        assert fields[10] == session.nonce
        assert fields[11] == hashlib.sha256(session.payload).digest()
        assert hmac.new(
            session.key,
            HEADER.pack(*fields)[:164] + payload,
            hashlib.sha256,
        ).digest() == fields[13]
        receipt = _parse_receipt(payload)
        assert receipt["version"] == 1
        assert receipt["status"] == 0
        assert receipt["rc"] == 0
        assert receipt["signal"] == 0
        assert receipt["creator"] == os.getpid()
        assert receipt["birth"] == session.creator_birth
        assert receipt["containment"] == 1  # dedicated process-group scope
        assert receipt["extinct"] == 1
        assert receipt["attempt"] == "attempt-native-broker-001"
        expected_stdout = (
            f"ENV-VALUE|{tmp_path}|PASS-VALUE|STDIN-VALUE".encode()
        )
        assert receipt["stdout"] == expected_stdout
        assert receipt["stdout_observed"] == len(expected_stdout)
        assert receipt["stdout_truncated"] == 0
        assert receipt["stderr"] == b"STDERR-VALUE"
        assert receipt["stderr_observed"] == len(b"STDERR-VALUE")
        assert receipt["stderr_truncated"] == 0
        assert receipt["digests"][9] == hashlib.sha256(expected_stdout).digest()
        assert receipt["digests"][10] == hashlib.sha256(expected_stdout).digest()
    finally:
        session.close()


def test_native_broker_rejects_bad_authenticator_without_receipt(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        session.send(key=bytes([session.key[0] ^ 1]) + session.key[1:])
        assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_native_broker_rejects_descriptor_substitution(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        substituted = list(session.opened)
        substituted[3], substituted[4] = substituted[4], substituted[3]
        session.send(fds=substituted)
        assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_native_broker_rejects_truncated_request(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        wire = _frame(
            frame_type=2, sequence=1, session=session.session,
            nonce=session.nonce, previous=ZERO, payload=session.payload,
            key=session.key, fd_count=len(session.opened),
        )
        sent = session.socket.sendmsg(
            [wire[:HEADER_SIZE]],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", session.opened))],
        )
        assert sent == HEADER_SIZE
        session.socket.sendall(wire[HEADER_SIZE:-1])
        session.socket.shutdown(socket.SHUT_WR)
        assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_native_broker_binds_creator_pid_even_with_valid_authenticator(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        payload = bytearray(session.payload)
        payload[4:12] = struct.pack(">Q", session.creator_pid + 1)
        session.send(payload=bytes(payload))
        assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_native_broker_rejects_aliased_fd_roster(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        roster = list(session.opened)
        roster[4] = roster[3]
        session.send(fds=roster)
        assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_native_broker_rejects_a_queued_replay_before_launch(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        wire, roster = session.request_wire()
        sent = session.socket.sendmsg(
            [wire[:HEADER_SIZE]],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", roster))],
        )
        assert sent == HEADER_SIZE
        session.socket.sendall(wire[HEADER_SIZE:] + wire)
        assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_native_broker_retains_bounded_output_and_commits_full_digest(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        payload = bytearray(session.payload)
        payload[24:28] = struct.pack(">I", 8)
        session.send(payload=bytes(payload))
        fields, response = _receive_committed_receipt(session)
        assert hmac.new(
            session.key, HEADER.pack(*fields)[:164] + response, hashlib.sha256,
        ).digest() == fields[13]
        receipt = _parse_receipt(response)
        complete = f"ENV-VALUE|{tmp_path}|PASS-VALUE|STDIN-VALUE".encode()
        assert receipt["status"] == 0
        assert receipt["stdout"] == complete[:8]
        assert receipt["stdout_observed"] == len(complete)
        assert receipt["stdout_truncated"] == 1
        assert receipt["digests"][9] == hashlib.sha256(complete).digest()
        assert receipt["digests"][10] == hashlib.sha256(complete[:8]).digest()
    finally:
        session.close()


def test_native_broker_timeout_kills_and_reaps_direct_child(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        payload = bytearray(session.payload_with_script("while :; do :; done"))
        payload[20:24] = struct.pack(">I", 50)
        session.send(payload=bytes(payload))
        _fields, response = _receive_committed_receipt(session)
        receipt = _parse_receipt(response)
        assert receipt["status"] == 1
        assert receipt["rc"] == 0xFFFFFFFF
        assert receipt["signal"] == 9
        assert receipt["extinct"] == 1
    finally:
        session.close()


def test_native_broker_spawn_closes_unlisted_descriptors(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        check = (
            "leak=; for i in 3 4 5 6 7 8 10 11 12 13; do "
            "[ ! -e \"/dev/fd/$i\" ] || leak=BAD; done; "
            "printf '%s' \"${leak:-CLOSED}\""
        )
        session.send(payload=session.payload_with_script(check))
        _fields, response = _receive_committed_receipt(session)
        receipt = _parse_receipt(response)
        assert receipt["status"] == 0
        assert receipt["stdout"] == b"CLOSED"
    finally:
        session.close()


def test_native_broker_rejects_noncanonical_environment_order(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        first, second = map(_text, session.environment)
        pair = first + second
        assert session.payload.count(pair) == 1
        session.send(payload=session.payload.replace(pair, second + first))
        assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_native_broker_rejects_duplicate_environment_names(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        original = b"".join(map(_text, session.environment))
        duplicate_names = _text("A=ENV-VALUE") + _text("A=SECOND-VALUE")
        assert session.payload.count(original) == 1
        session.send(payload=session.payload.replace(original, duplicate_names))
        assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_native_broker_sorts_environment_by_name_not_whole_entry(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    try:
        original = b"".join(map(_text, session.environment))
        canonical_prefix_names = _text("A=ENV-VALUE") + _text("A0=SECOND-VALUE")
        assert session.payload.count(original) == 1
        session.send(payload=session.payload.replace(original, canonical_prefix_names))
        _fields, response = _receive_committed_receipt(session)
        receipt = _parse_receipt(response)
        assert receipt["status"] == 0
        assert bytes(receipt["stdout"]).startswith(b"ENV-VALUE|")
    finally:
        session.close()


def test_forked_inheritor_cannot_use_parent_authenticated_stream(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    marker = tmp_path / "fork-writer-was-accepted"
    payload = session.payload_with_script(": > fork-writer-was-accepted")
    child = os.fork()
    if child == 0:  # pragma: no branch - child terminates without pytest teardown
        try:
            session.send(payload=payload)
        except OSError:
            pass
        os._exit(0)
    try:
        waited, status = os.waitpid(child, 0)
        assert waited == child and os.WIFEXITED(status)
        try:
            fields, candidate = _receive_frame(session.socket)
        except EOFError:
            pass
        else:
            assert fields[2] == FRAME_RECEIPT_CANDIDATE
            candidate_digest = _authenticated_frame_digest(fields, candidate)
            session.acknowledge(
                frame_type=FRAME_RECEIPT_ACK,
                sequence=3,
                previous=candidate_digest,
            )
            assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70
    assert not marker.exists()


def test_creator_fork_after_effect_cannot_cross_receipt_boundary(
    broker: Path, tmp_path: Path,
) -> None:
    session = Session(broker, tmp_path)
    marker = tmp_path / "effect-complete-before-fork"
    command = (
        "/usr/bin/head -c 1048576 /dev/zero; "
        ": > effect-complete-before-fork"
    )
    session.send(payload=session.payload_with_script(command))
    deadline = __import__("time").monotonic() + 10
    while not marker.exists() and __import__("time").monotonic() < deadline:
        pass
    assert marker.exists()
    child = os.fork()
    if child == 0:  # pragma: no branch - inherited writer must invalidate the lease
        os._exit(0)
    try:
        waited, status = os.waitpid(child, 0)
        assert waited == child and os.WIFEXITED(status)
        try:
            fields, candidate = _receive_frame(session.socket)
        except EOFError:
            pass
        else:
            assert fields[2] == FRAME_RECEIPT_CANDIDATE
            candidate_digest = _authenticated_frame_digest(fields, candidate)
            session.acknowledge(
                frame_type=FRAME_RECEIPT_ACK,
                sequence=3,
                previous=candidate_digest,
            )
            assert session.socket.recv(1) == b""
    finally:
        session.close()
    assert session.process.returncode == 70


def test_unsupported_posix_variant_is_a_typed_hardstop(tmp_path: Path) -> None:
    sdk = subprocess.run(
        ["/usr/bin/xcrun", "--show-sdk-path"], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    ).stdout.decode("utf-8", "strict").strip()
    artifact = tmp_path / "unsupported-broker"
    compiled = subprocess.run(
        [
            "/Library/Developer/CommandLineTools/usr/bin/clang",
            "-isysroot", sdk, "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-Wconversion", "-O2",
            "-DPLAMEN_NATIVE_BROKER_FORCE_UNSUPPORTED=1",
            str(REPO_ROOT / "native" / "posix" / "plamen_native_broker.c"),
            "-o", str(artifact),
        ],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=False, env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    assert compiled.returncode == 0, compiled.stdout.decode("utf-8", "replace")
    completed = subprocess.run(
        [str(artifact)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env={},
    )
    assert completed.returncode == 78
    assert completed.stdout == b""
    assert completed.stderr == (
        b"PLAMEN_NATIVE_BROKER_HARDSTOP_UNSUPPORTED_POSIX_AUTHORITY\n"
    )


def test_darwin_production_build_hardstops_without_native_v2_adapter(
    tmp_path: Path,
) -> None:
    sdk = subprocess.run(
        ["/usr/bin/xcrun", "--show-sdk-path"], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    ).stdout.decode("utf-8", "strict").strip()
    artifact = tmp_path / "production-broker"
    compiled = subprocess.run(
        [
            "/Library/Developer/CommandLineTools/usr/bin/clang",
            "-isysroot", sdk, "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-Wconversion", "-O2",
            str(REPO_ROOT / "native" / "posix" / "plamen_native_broker.c"),
            "-o", str(artifact),
        ],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=False, env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    assert compiled.returncode == 0, compiled.stdout.decode("utf-8", "replace")
    completed = subprocess.run(
        [str(artifact)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env={},
    )
    assert completed.returncode == 78
    assert completed.stdout == b""
    assert completed.stderr == (
        b"PLAMEN_NATIVE_BROKER_HARDSTOP_NATIVE_V2_ADAPTER_REQUIRED\n"
    )
