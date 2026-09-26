"""Native-only tests for the durable broker V2 wire and journal core.

The peers are separately compiled with explicit TEST_ONLY macros.  The installed
production broker remains fail-closed until the launchd/XPC or Linux user-service
authority channel is integrated.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "native" / "include"
POSIX = ROOT / "native" / "posix"
TESTS = ROOT / "native" / "tests"
PROTOCOL = POSIX / "plamen_broker_v2_protocol.c"
JOURNAL = POSIX / "plamen_broker_v2_journal.c"
TEST_PEER = TESTS / "broker_v2_test_peer.c"
FAULT_PEER = TESTS / "broker_v2_fault_broker.c"
PRODUCTION_BROKER = POSIX / "plamen_native_broker.c"
HEADER = INCLUDE / "plamen_broker_v2.h"


def _external_profile_v2(provider: bytes, backend: bytes) -> bytes:
    data = bytearray(2048)
    data[:8] = b"PLMBPF2\0"
    struct.pack_into(">HHII", data, 8, 2, 256, 2048, 1)
    data[32:64] = hashlib.sha256(provider).digest()
    data[64:96] = hashlib.sha256(backend).digest()
    data[96:116] = b"p" * 20
    data[128:148] = b"b" * 20
    fields = (
        (256, b"com.apple.container.cli"),
        (384, b"UPBK2H6LZM"),
        (512, b"container CLI version 1.3.1"),
        (640, b"codex"),
        (768, b"2DC432GLL2"),
        (896, b"codex-cli 0.153.4"),
        (1024, b"0.153.4-aarch64-apple-darwin"),
        (1280, b"codex"),
        (1312, b"apple-container-v2"),
    )
    struct.pack_into(">" + "H" * 11, data, 160, 20, 20,
                     *(len(value) for _, value in fields))
    for offset, value in fields:
        data[offset:offset + len(value)] = value
    data[2016:] = hashlib.sha256(data[:2016]).digest()
    return bytes(data)


def _minimal_runtime_manifest_v2(profile: bytes) -> bytes:
    """Build the smallest byte-exact role-8 manifest accepted by the composer."""
    entry_count = 1
    body = bytearray(256 + 2048 + 640 * entry_count)
    body[:8] = b"PLMRPM2\0"
    struct.pack_into(">HHIII", body, 8, 2, 256, len(body) + 32, 640, entry_count)
    struct.pack_into(">II", body, 64, 2048, 14)
    body[160:178] = b"lib/plamen/runtime"
    binding = 256
    body[binding:binding + 8] = b"PLMRPB2\0"
    image_ref = b"registry.invalid/plamen@sha256:" + b"a" * 64
    init = b"/usr/local/libexec/plamen-guest"
    struct.pack_into(">HHHHHHHH", body, binding + 8,
                     2, 2048, 1, 2, len(image_ref), len(init), 14, 1)
    body[binding + 32:binding + 64] = bytes.fromhex(
        "cbec56ecf9485cc1ca05d2faa09ea61575e9deffd736fd1ad8e411a18629ffbe"
    )
    for index in range(14):
        body[binding + 64 + index * 32:binding + 96 + index * 32] = (
            hashlib.sha256(f"role8-binding-{index}".encode()).digest()
        )
    body[binding + 512:binding + 512 + len(image_ref)] = image_ref
    body[binding + 1024:binding + 1024 + len(init)] = init
    row = 256 + 2048
    profile_path = b"profiles/codex-v2.bin"
    struct.pack_into(">HHIQIHH", body, row, 2, len(profile_path), 0o400,
                     len(profile), 1, 2, 0)
    body[row + 24:row + 56] = hashlib.sha256(profile).digest()
    body[row + 56:row + 56 + len(profile_path)] = profile_path
    return bytes(body) + hashlib.sha256(body).digest()


def _compiler() -> str:
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("a C11 compiler is required")
    return compiler


def _base_compile() -> list[str]:
    return [
        _compiler(), "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-Wno-deprecated-declarations", "-I", os.fspath(INCLUDE),
        "-I", os.fspath(POSIX),
    ]


def _crypto_link() -> list[str]:
    return ["-lcrypto"] if sys.platform.startswith("linux") else []


@pytest.fixture(scope="module")
def native_peers(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    build = tmp_path_factory.mktemp("broker-v2-native")
    peer = build / "broker-v2-test-peer"
    fault = build / "broker-v2-fault-peer"
    peer_sources = [
        "-DPLAMEN_BROKER_V2_TEST_ONLY=1", os.fspath(TEST_PEER),
        os.fspath(PROTOCOL), os.fspath(JOURNAL),
    ]
    if sys.platform.startswith("linux"):
        peer_sources.extend([
            "-DPLAMEN_NATIVE_BROKER_NO_MAIN=1", os.fspath(PRODUCTION_BROKER),
        ])
    subprocess.run(
        _base_compile()
        + peer_sources
        + ["-o", os.fspath(peer)]
        + _crypto_link(),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        _base_compile()
        + [
            "-DPLAMEN_BROKER_V2_FAULT_TEST_ONLY=1", os.fspath(FAULT_PEER),
            "-o", os.fspath(fault),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return peer, fault


def _private_root(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def test_RED_BROKER_V2_ABI_CONSTANT_EQUALITY(
    native_peers: tuple[Path, Path],
) -> None:
    source = HEADER.read_text(encoding="utf-8")
    assert "PLAMEN_BROKER_V2_VERSION 2U" in source
    assert "PLAMEN_BROKER_V2_HEADER_SIZE 196U" in source
    assert "PLAMEN_BROKER_V2_AUTH_OFFSET 164U" in source
    assert "PLAMEN_BROKER_V2_MAX_PAYLOAD 2097152U" in source
    assert "PLAMEN_BROKER_V2_MAX_FDS 16U" in source
    assert "PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE 124U" in source
    assert "PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE 1488U" in source
    assert "PLAMEN_BROKER_V2_SERVICE_MAX_FDS 15U" in source
    assert "PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT 14U" in source
    assert "PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE 210U" in source
    assert "PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE 96U" in source
    assert "PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE 954U" in source
    assert "PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE 410U" in source
    assert "PLAMEN_BROKER_V2_SERVICE_SESSION_ACK_SIZE 164U" in source
    assert 'PLAMEN_BROKER_V2_DARWIN_SERVICE_NAME "com.plamen.audit.broker.v2"' in source
    assert "PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR = 1" in source
    assert "PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER = 2" in source
    assert "PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION = 3" in source
    assert '"plamen.native_audit_request_projection.v1"' in source
    assert "PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT 10U" in source
    assert "PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT 1U" in source
    assert "PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE 392U" in source
    assert "PLAMEN_BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE 104U" in source
    assert "PLAMEN_BROKER_V2_BACKEND_PROCESS_IDENTITY_SIZE 212U" in source
    completed = subprocess.run(
        [os.fspath(native_peers[0]), "selftest"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_RED_BROKER_V2_AUTHENTICATED_HELLO_ONLY_and_frame_forgery(
    native_peers: tuple[Path, Path],
) -> None:
    # The native self-test covers authenticated HELLO, payload/header/HMAC
    # forgery, short/trailing frames, descriptor-count mismatch, chain replay,
    # session mismatch, and irreversible session burn.
    subprocess.run([os.fspath(native_peers[0]), "selftest"], check=True)


def test_RED_BROKER_V2_NATIVE_SERVICE_BOOTSTRAP_AND_ROLE_BINDING_EXACT(
    native_peers: tuple[Path, Path],
) -> None:
    # Native self-test covers registration/session envelope sizes, canonical
    # payloads, descriptor roster, initial-vs-recovery, direction, and wrong-role.
    subprocess.run([os.fspath(native_peers[0]), "selftest"], check=True)


def test_RED_BROKER_V2_CONFIG_TO_PROJECTION_COMPOSER_EXACT(
    native_peers: tuple[Path, Path], tmp_path: Path,
) -> None:
    project = tmp_path / "dodo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    docs = project / "README.md"
    docs.write_text("# DODO\n", encoding="utf-8")
    config = scratch / "config.json"
    config.write_text(json.dumps({
        "project_root": os.fspath(project),
        "scratchpad": os.fspath(scratch),
        "docs_path": os.fspath(docs),
        "scope_file": None,
        "pipeline": "sc",
        "mode": "core",
        "cli_backend": "codex",
        "language": "evm",
        "docs_inputs": None,
    }, indent=2), encoding="utf-8")
    export = scratch / "export"
    export.mkdir()
    names = ("role5-schema", "runtime-manifest", "provider", "backend",
             "profile", "credential", "egress-policy", "egress-admission")
    inputs = [tmp_path / name for name in names]
    provider = b"provider executable"
    backend = b"backend executable"
    profile = _external_profile_v2(provider, backend)
    config_bytes = config.read_bytes()
    profile_sha = hashlib.sha256(profile).hexdigest()
    policy = (json.dumps({
        "backend": "codex",
        "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "network_mode": "NARROW_TRUSTED_PROXY_ONLY",
        "nonce": "ab" * 32,
        "profile_sha256": profile_sha,
        "schema": "plamen.egress-policy.v2",
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    admission = (json.dumps({
        "backend_sha256": hashlib.sha256(backend).hexdigest(),
        "policy_sha256": hashlib.sha256(policy).hexdigest(),
        "provider_sha256": hashlib.sha256(provider).hexdigest(),
        "schema": "plamen.egress-admission.v2",
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    runtime = _minimal_runtime_manifest_v2(profile)
    contents = (b"role5-schema", runtime, provider, backend, profile,
                b"credential", policy, admission)
    for path, content in zip(inputs, contents, strict=True):
        path.write_bytes(content)
    inputs[2].chmod(0o500)
    inputs[3].chmod(0o500)
    for index in (4, 6, 7):
        inputs[index].chmod(0o400)
    role5_sha = hashlib.sha256(inputs[0].read_bytes()).hexdigest()
    runtime_sha = hashlib.sha256(runtime).hexdigest()
    command = [
        os.fspath(native_peers[0]), "projection-builder", os.fspath(config),
        os.fspath(project), os.fspath(docs), os.fspath(export),
        *(os.fspath(path) for path in inputs), role5_sha, runtime_sha,
    ]
    completed = subprocess.run(
        command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    # A byte-valid but semantically altered policy is not an authority source.
    inputs[6].chmod(0o600)
    inputs[6].write_bytes(policy.replace(
        b"NARROW_TRUSTED_PROXY_ONLY", b"UNRESTRICTED_NETWORK",
    ))
    inputs[6].chmod(0o400)
    forged = subprocess.run(
        command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert forged.returncode != 0


def test_RED_BROKER_V2_SCM_RIGHTS_COUNT_ORDER_AND_PURPOSE_EXACT(
    native_peers: tuple[Path, Path],
) -> None:
    # The same peer validates CLOEXEC, access modes, full content identities,
    # sorted target/purpose metadata, and underlying-file alias rejection.
    subprocess.run([os.fspath(native_peers[0]), "selftest"], check=True)


def test_RED_BROKER_V2_START_WAIT_AND_REVOKE_DURABLE_transitions(
    native_peers: tuple[Path, Path], tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "journal-root")
    subprocess.run(
        [os.fspath(native_peers[0]), "journal-lifecycle", os.fspath(root), "audit-1"],
        check=True,
    )
    journal = root / "audit-1"
    records = sorted(journal.glob("*.rec"))
    assert len(records) == 6
    previous = bytes(32)
    for sequence, record_path in enumerate(records, 1):
        raw = record_path.read_bytes()
        assert len(raw) >= 192
        assert raw[:8] == b"PLMJRN2\0"
        assert struct.unpack_from(">H", raw, 8)[0] == 2
        assert struct.unpack_from(">I", raw, 12)[0] == 192
        assert struct.unpack_from(">Q", raw, 24)[0] == sequence
        assert raw[96:128] == previous
        payload_size = struct.unpack_from(">I", raw, 16)[0]
        assert len(raw) == 192 + payload_size
        assert hashlib.sha256(raw[192:]).digest() == raw[128:160]
        assert hashlib.sha256(raw[:160] + raw[192:]).digest() == raw[160:192]
        previous = raw[160:192]
        assert stat.S_IMODE(record_path.stat().st_mode) == 0o400
    assert stat.S_IMODE((journal / ".lock").stat().st_mode) == 0o600


def test_RED_BROKER_V2_START_ACK_LOSS_RECOVERS_without_duplicate(
    native_peers: tuple[Path, Path], tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "ack-root")
    command = [
        os.fspath(native_peers[0]), "journal-prepared", os.fspath(root),
        "same-request", "byte-identical",
    ]
    subprocess.run(command, check=True)
    original = (root / "same-request" / "00000000000000000001.rec").read_bytes()
    subprocess.run(command, check=True)
    assert (root / "same-request" / "00000000000000000001.rec").read_bytes() == original
    assert len(list((root / "same-request").glob("*.rec"))) == 1


def test_RED_BROKER_V2_CROSS_PROCESS_START_RACE_EXACTLY_ONCE(
    native_peers: tuple[Path, Path], tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "race-root")
    command = [
        os.fspath(native_peers[0]), "journal-prepared", os.fspath(root),
        "race", "identical",
    ]
    processes = [subprocess.Popen(command) for _ in range(12)]
    assert [process.wait(timeout=10) for process in processes] == [0] * 12
    assert len(list((root / "race").glob("*.rec"))) == 1


def test_RED_BROKER_V2_CROSS_PROCESS_divergent_CAS_rejected(
    native_peers: tuple[Path, Path], tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "conflict-root")
    prefix = [
        os.fspath(native_peers[0]), "journal-prepared", os.fspath(root), "conflict",
    ]
    processes = [
        subprocess.Popen(prefix + ["candidate-a"]),
        subprocess.Popen(prefix + ["candidate-b"]),
    ]
    codes = sorted(process.wait(timeout=10) for process in processes)
    assert codes == [0, 3]
    assert len(list((root / "conflict").glob("*.rec"))) == 1


def test_RED_BROKER_V2_PARENT_DEATH_DURABLE_RECONNECT_corruption_hardstop(
    native_peers: tuple[Path, Path], tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "fault-root")
    subprocess.run(
        [os.fspath(native_peers[1]), os.fspath(root), "crashed"], check=True,
    )
    completed = subprocess.run(
        [os.fspath(native_peers[0]), "journal-replay", os.fspath(root), "crashed"],
        check=False,
    )
    assert completed.returncode == 10


def test_TEST_ONLY_fault_peers_cannot_compile_as_production(tmp_path: Path) -> None:
    for source in (TEST_PEER, FAULT_PEER):
        completed = subprocess.run(
            _base_compile() + [os.fspath(source), "-o", os.fspath(tmp_path / source.stem)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert completed.returncode != 0
        assert b"TEST_ONLY" in completed.stderr


def test_production_broker_remains_hardstopped_until_native_service(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "production-broker"
    subprocess.run(
        _base_compile()
        + [os.fspath(PRODUCTION_BROKER), os.fspath(PROTOCOL),
           "-o", os.fspath(binary)]
        + _crypto_link(),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    completed = subprocess.run(
        [os.fspath(binary)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert completed.returncode == 78
    assert completed.stdout == b""
    assert b"HARDSTOP_NATIVE_V2_ADAPTER_REQUIRED" in completed.stderr
