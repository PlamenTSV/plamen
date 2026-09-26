from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path
import platform
import subprocess

import pytest


ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="Darwin native lifecycle only"
)


class _ProcessStartIdentity(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("child_pid", ctypes.c_int32),
        ("process_group_id", ctypes.c_int32),
        ("child_birth_us", ctypes.c_uint64),
        ("executable_device", ctypes.c_uint64),
        ("executable_inode", ctypes.c_uint64),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "executable_sha256", "executable_identity_sha256",
            "native_process_handle_sha256", "cdhash",
        )],
        ("cdhash_size", ctypes.c_uint32),
        ("signing_identifier", ctypes.c_char * 256),
        ("team_identifier", ctypes.c_char * 256),
    ]


class _StartReceipt(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32), ("status", ctypes.c_uint32),
        ("container_id", ctypes.c_char * 40),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "request_fingerprint_sha256", "spec_sha256",
            "launch_request_sha256", "start_operation_nonce",
            "start_argv_sha256", "native_process_handle_sha256",
        )],
        ("native_process_id", ctypes.c_int32),
        ("start_monotonic_ms", ctypes.c_uint64),
        *[(name, ctypes.c_uint8 * 32) for name in (
            "prepared_record_sha256", "custody_process_spec_sha256",
            "custody_prepared_checkpoint_sha256",
            "custody_started_checkpoint_sha256", "receipt_sha256",
        )],
        ("post_spawn_dynamic_identity_kind", ctypes.c_uint32),
        ("post_spawn_dynamic_identity_size", ctypes.c_uint32),
        ("post_spawn_dynamic_identity_sha256", ctypes.c_uint8 * 32),
    ]


@pytest.fixture(scope="module")
def lifecycle_library(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    output = tmp_path_factory.mktemp("apple-lifecycle-dynamic") / "lifecycle.dylib"
    subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-fblocks", "-dynamiclib",
            "-DPLAMEN_BROKER_V2_APPLE_CONTAINER_TEST_ONLY=1",
            "-I", str(ROOT / "native" / "include"),
            "-I", str(ROOT / "native" / "darwin"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custodian.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_client.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-framework", "Security", "-framework", "CoreFoundation",
            "-o", str(output),
        ],
        cwd=ROOT, check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    library = ctypes.CDLL(str(output))
    record_pointer = ctypes.POINTER(ctypes.c_uint8)
    library.plamen_broker_v2_apple_lifecycle_start_receipt_validate.argtypes = [
        ctypes.POINTER(_StartReceipt),
    ]
    library.plamen_broker_v2_apple_lifecycle_start_receipt_validate.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_start_receipt_dynamic_identity_validate.argtypes = [
        ctypes.POINTER(_StartReceipt),
    ]
    library.plamen_broker_v2_apple_lifecycle_start_receipt_dynamic_identity_validate.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_encode_start_receipt.argtypes = [
        ctypes.POINTER(_StartReceipt), record_pointer,
    ]
    library.plamen_broker_v2_apple_lifecycle_test_encode_start_receipt.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt.argtypes = [
        record_pointer, ctypes.POINTER(_StartReceipt),
    ]
    library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity.argtypes = [
        ctypes.POINTER(_StartReceipt), ctypes.POINTER(_ProcessStartIdentity),
    ]
    library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity.restype = ctypes.c_int
    library.plamen_broker_v2_apple_lifecycle_test_start_dynamic_identity_matches.argtypes = [
        ctypes.POINTER(_StartReceipt), ctypes.POINTER(_ProcessStartIdentity),
    ]
    library.plamen_broker_v2_apple_lifecycle_test_start_dynamic_identity_matches.restype = ctypes.c_int
    return library


def _set_digest(target: ctypes.Array[ctypes.c_uint8], value: bytes) -> None:
    assert len(value) == 32
    target[:] = value


def _identity(*, cdhash: bytes, pid: int = 4242, handle: bytes = b"H" * 32) -> _ProcessStartIdentity:
    identity = _ProcessStartIdentity(
        version=1, child_pid=pid, process_group_id=pid,
        child_birth_us=123456, executable_device=1, executable_inode=2,
        cdhash_size=len(cdhash), signing_identifier=b"com.apple.container.cli",
        team_identifier=b"UPBK2H6LZM",
    )
    _set_digest(identity.executable_sha256, b"E" * 32)
    _set_digest(identity.executable_identity_sha256, b"I" * 32)
    _set_digest(identity.native_process_handle_sha256, handle)
    identity.cdhash[:len(cdhash)] = cdhash
    return identity


def _receipt(*, version: int, identity: _ProcessStartIdentity) -> _StartReceipt:
    receipt = _StartReceipt(
        version=version, status=0,
        container_id=b"plamen-" + b"a" * 32,
        native_process_id=identity.child_pid,
        start_monotonic_ms=123456,
    )
    for index, name in enumerate((
        "request_fingerprint_sha256", "spec_sha256",
        "launch_request_sha256", "start_operation_nonce",
        "start_argv_sha256", "prepared_record_sha256",
        "custody_process_spec_sha256", "custody_prepared_checkpoint_sha256",
        "custody_started_checkpoint_sha256",
    ), start=1):
        _set_digest(getattr(receipt, name), bytes([index]) * 32)
    receipt.native_process_handle_sha256[:] = identity.native_process_handle_sha256
    return receipt


def _seal_v1(receipt: _StartReceipt) -> None:
    prefix_size = _StartReceipt.receipt_sha256.offset
    receipt.receipt_sha256[:] = hashlib.sha256(
        ctypes.string_at(ctypes.addressof(receipt), prefix_size)
    ).digest()


def _seal_v2(receipt: _StartReceipt) -> None:
    prefix_size = _StartReceipt.receipt_sha256.offset
    prefix = ctypes.string_at(ctypes.addressof(receipt), prefix_size)
    extension = (
        int(receipt.post_spawn_dynamic_identity_kind).to_bytes(4, "big")
        + int(receipt.post_spawn_dynamic_identity_size).to_bytes(4, "big")
        + bytes(receipt.post_spawn_dynamic_identity_sha256)
    )
    receipt.receipt_sha256[:] = hashlib.sha256(prefix + extension).digest()


def _encode(library: ctypes.CDLL, receipt: _StartReceipt) -> ctypes.Array[ctypes.c_uint8]:
    encoded = (ctypes.c_uint8 * 512)()
    assert library.plamen_broker_v2_apple_lifecycle_test_encode_start_receipt(
        ctypes.byref(receipt), encoded
    ) == 0
    return encoded


def _record_reseal(encoded: ctypes.Array[ctypes.c_uint8]) -> None:
    encoded[480:512] = hashlib.sha256(bytes(encoded[:480])).digest()


def test_v1_wire_and_digest_semantics_remain_exact(
    lifecycle_library: ctypes.CDLL,
) -> None:
    identity = _identity(cdhash=b"C" * 20)
    receipt = _receipt(version=1, identity=identity)
    _seal_v1(receipt)
    encoded = _encode(lifecycle_library, receipt)
    assert bytes(encoded[:8]) == b"PLMASR1\0"
    assert bytes(encoded[432:480]) == bytes(48)
    decoded = _StartReceipt()
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
        encoded, ctypes.byref(decoded)
    ) == 0
    assert bytes(decoded) == bytes(receipt)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_start_receipt_dynamic_identity_validate(
        ctypes.byref(decoded)
    ) != 0


@pytest.mark.parametrize("cdhash_size", [20, 32])
def test_v2_projects_exact_observed_cdhash_and_replays_byte_exactly(
    lifecycle_library: ctypes.CDLL, cdhash_size: int,
) -> None:
    raw = bytes(range(1, cdhash_size + 1))
    identity = _identity(cdhash=raw)
    receipt = _receipt(version=2, identity=identity)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
        ctypes.byref(receipt), ctypes.byref(identity)
    ) == 0
    assert receipt.post_spawn_dynamic_identity_kind == 1
    assert receipt.post_spawn_dynamic_identity_size == cdhash_size
    assert bytes(receipt.post_spawn_dynamic_identity_sha256) == hashlib.sha256(raw).digest()
    assert bytes(receipt.post_spawn_dynamic_identity_sha256) != bytes(
        receipt.native_process_handle_sha256
    )
    encoded = _encode(lifecycle_library, receipt)
    assert bytes(encoded[:8]) == b"PLMASR2\0"
    assert int.from_bytes(bytes(encoded[432:436]), "big") == 1
    assert int.from_bytes(bytes(encoded[436:440]), "big") == cdhash_size
    decoded = _StartReceipt()
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
        encoded, ctypes.byref(decoded)
    ) == 0
    replay = _encode(lifecycle_library, decoded)
    assert bytes(replay) == bytes(encoded)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_start_dynamic_identity_matches(
        ctypes.byref(decoded), ctypes.byref(identity)
    ) == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("post_spawn_dynamic_identity_kind", 2),
        ("post_spawn_dynamic_identity_size", 21),
    ],
)
def test_v2_rejects_resealed_invalid_kind_or_size(
    lifecycle_library: ctypes.CDLL, field: str, value: int,
) -> None:
    identity = _identity(cdhash=b"C" * 20)
    receipt = _receipt(version=2, identity=identity)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
        ctypes.byref(receipt), ctypes.byref(identity)
    ) == 0
    setattr(receipt, field, value)
    _seal_v2(receipt)
    encoded = _encode(lifecycle_library, receipt)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
        encoded, ctypes.byref(_StartReceipt())
    ) != 0


def test_v2_resealed_substituted_hash_fails_custody_replay_match(
    lifecycle_library: ctypes.CDLL,
) -> None:
    identity = _identity(cdhash=b"C" * 20)
    receipt = _receipt(version=2, identity=identity)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
        ctypes.byref(receipt), ctypes.byref(identity)
    ) == 0
    receipt.post_spawn_dynamic_identity_sha256[0] ^= 1
    _seal_v2(receipt)
    encoded = _encode(lifecycle_library, receipt)
    decoded = _StartReceipt()
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
        encoded, ctypes.byref(decoded)
    ) == 0
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_start_dynamic_identity_matches(
        ctypes.byref(decoded), ctypes.byref(identity)
    ) != 0


def test_v2_rejects_record_tamper_even_before_custody_comparison(
    lifecycle_library: ctypes.CDLL,
) -> None:
    identity = _identity(cdhash=b"C" * 20)
    receipt = _receipt(version=2, identity=identity)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
        ctypes.byref(receipt), ctypes.byref(identity)
    ) == 0
    encoded = _encode(lifecycle_library, receipt)
    for offset in (432, 436, 440):
        tampered = (ctypes.c_uint8 * 512).from_buffer_copy(encoded)
        tampered[offset] ^= 1
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
            tampered, ctypes.byref(_StartReceipt())
        ) != 0


def test_v2_rejects_foreign_process_context_and_missing_observation(
    lifecycle_library: ctypes.CDLL,
) -> None:
    identity = _identity(cdhash=b"C" * 20)
    receipt = _receipt(version=2, identity=identity)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
        ctypes.byref(receipt), ctypes.byref(identity)
    ) == 0
    foreign_handle = _identity(cdhash=b"C" * 20, handle=b"F" * 32)
    foreign_cdhash = _identity(cdhash=b"D" * 20)
    foreign_pid = _identity(cdhash=b"C" * 20, pid=4243)
    for foreign in (foreign_handle, foreign_cdhash, foreign_pid):
        assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_start_dynamic_identity_matches(
            ctypes.byref(receipt), ctypes.byref(foreign)
        ) != 0
    missing = _identity(cdhash=b"C" * 20)
    missing.cdhash_size = 0
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
        ctypes.byref(_receipt(version=2, identity=missing)), ctypes.byref(missing)
    ) != 0
    padded = _identity(cdhash=b"C" * 20)
    padded.cdhash[20] = 1
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
        ctypes.byref(_receipt(version=2, identity=padded)), ctypes.byref(padded)
    ) != 0


def test_v1_record_cannot_be_resealed_as_v2_without_observed_identity(
    lifecycle_library: ctypes.CDLL,
) -> None:
    identity = _identity(cdhash=b"C" * 20)
    receipt = _receipt(version=1, identity=identity)
    _seal_v1(receipt)
    encoded = _encode(lifecycle_library, receipt)
    encoded[6] = ord("2")
    encoded[11] = 2
    _record_reseal(encoded)
    assert lifecycle_library.plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
        encoded, ctypes.byref(_StartReceipt())
    ) != 0
