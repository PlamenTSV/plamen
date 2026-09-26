from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import stat
import struct
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="Darwin CryptoKit signer",
)


class Projection(ctypes.Structure):
    _fields_ = [
        ("role", ctypes.c_uint16),
        ("verifier_public_key_fd", ctypes.c_int),
        ("semantic_receipt_fd", ctypes.c_int),
        ("semantic_receipt_size", ctypes.c_uint64),
        ("verifier_public_key_sha256", ctypes.c_ubyte * 32),
        ("semantic_receipt_sha256", ctypes.c_ubyte * 32),
        ("payload_sha256", ctypes.c_ubyte * 32),
        ("payload_size", ctypes.c_uint64),
        ("source_manifest_sha256", ctypes.c_ubyte * 32),
        ("source_manifest_size", ctypes.c_uint64),
        ("policy_sha256", ctypes.c_ubyte * 32),
    ]


def _build(tmp_path: Path) -> ctypes.CDLL:
    c_object = tmp_path / "signer-c.o"
    policy_object = tmp_path / "policy.o"
    library = tmp_path / "libplamen-native-backend-signer-v1.dylib"
    common = [
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-Wno-deprecated-declarations", "-fPIC", "-I",
        str(ROOT / "native/darwin"), "-c",
    ]
    for source, output in (
        (ROOT / "native/darwin/plamen_native_backend_receipt_signer_v1.c", c_object),
        (ROOT / "native/tests/plamen_native_backend_receipt_signer_v1_policy.c", policy_object),
    ):
        completed = subprocess.run(
            [*common, str(source), "-o", str(output)], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=60,
        )
        assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    completed = subprocess.run(
        [
            "xcrun", "swiftc", "-warnings-as-errors", "-parse-as-library",
            "-emit-library",
            str(ROOT / "native/darwin/plamen_native_backend_receipt_signer_v1.swift"),
            str(c_object), str(policy_object), "-o", str(library),
        ],
        check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    native = ctypes.CDLL(str(library))
    native.plamen_native_backend_receipt_signer_create_v1.argtypes = [
        ctypes.c_uint32, ctypes.c_int, ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    native.plamen_native_backend_receipt_signer_create_v1.restype = ctypes.c_int
    native.plamen_native_backend_receipt_sign_v1.argtypes = [
        ctypes.c_void_p, ctypes.c_uint16, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(Projection),
    ]
    native.plamen_native_backend_receipt_sign_v1.restype = ctypes.c_int
    native.plamen_native_backend_signed_projection_dispose_v1.argtypes = [
        ctypes.POINTER(Projection),
    ]
    native.plamen_native_backend_receipt_signer_dispose_v1.argtypes = [
        ctypes.c_void_p,
    ]
    return native


def _pair(path: Path) -> tuple[int, int]:
    path.write_bytes(b"")
    path.chmod(0o600)
    return (
        os.open(path, os.O_RDWR | os.O_CLOEXEC),
        os.open(path, os.O_RDONLY | os.O_CLOEXEC),
    )


def _retained(path: Path, raw: bytes) -> int:
    path.write_bytes(raw)
    path.chmod(0o400)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()


def _unsigned(payload: bytes, manifest: bytes, *, payload_digest: str | None = None) -> bytes:
    return _canonical({
        "schema": "plamen.native-backend-latest-acquisition-receipt.v1",
        "selector": "codex",
        "policy_schema": "plamen.native-backend-acquisition.v2",
        "policy_sha256": "aa" * 32,
        "resolved_version": "0.154.0",
        "resolved_release": "0.154.0-darwin-arm64",
        "registry": {}, "upstream": None, "transport": {},
        "payload": {
            "size": len(payload),
            "sha256": payload_digest or hashlib.sha256(payload).hexdigest(),
        },
        "installed": {}, "probes": {},
        "install": {
            "transaction_id": "native-test",
            "generation_id": "npm-" + "11" * 32,
            "install_receipt_sha256": "22" * 32,
            "source_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "source_manifest_size": len(manifest),
        },
    })


def _read(fd: int) -> bytes:
    size = os.fstat(fd).st_size
    return os.pread(fd, size, 0)


def test_native_backend_signer_custodies_key_and_binds_retained_bytes(
    tmp_path: Path,
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from scripts import native_operation4_acquisition_validation as validation
    from scripts import test_native_operation4_acquisition_validation as vectors

    native = _build(tmp_path)
    public_writer, public_reader = _pair(tmp_path / "public.bin")
    signer = ctypes.c_void_p()
    assert native.plamen_native_backend_receipt_signer_create_v1(
        os.getuid(), public_writer, public_reader, ctypes.byref(signer),
    ) == 0
    assert signer.value
    assert stat.S_IMODE(os.fstat(public_reader).st_mode) == 0o400
    public = _read(public_reader)
    assert len(public) == 32
    payload = vectors.PAYLOAD
    manifest = _canonical({"schema": "source", "members": ["bin/codex"]})
    footer_values = {
        "policy_sha256": "aa" * 32,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_size": len(payload),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "manifest_size": len(manifest),
        "version": "0.154.0",
    }
    unsigned_value = vectors._receipt(
        "codex", Ed25519PrivateKey.generate(), footer_values,
    )
    unsigned_value.pop("authentication")
    unsigned_value.pop("receipt_sha256")
    unsigned_fd = _retained(tmp_path / "unsigned.json", _canonical(unsigned_value))
    payload_fd = _retained(tmp_path / "payload.bin", payload)
    manifest_fd = _retained(tmp_path / "manifest.json", manifest)
    receipt_writer, receipt_reader = _pair(tmp_path / "semantic.bin")
    projection = Projection()
    projection.verifier_public_key_fd = -1
    projection.semantic_receipt_fd = -1
    try:
        assert native.plamen_native_backend_receipt_sign_v1(
            signer, 5, unsigned_fd, payload_fd, manifest_fd,
            receipt_writer, receipt_reader, ctypes.byref(projection),
        ) == 0
        raw = _read(receipt_reader)
        semantic, footer = raw[:-512], raw[-512:]
        value = json.loads(semantic)
        unsigned_value = dict(value)
        authentication = unsigned_value.pop("authentication")
        unsigned_value.pop("receipt_sha256")
        message = _canonical(unsigned_value)
        assert authentication["scheme"] == "ed25519"
        assert authentication["key_id"] == hashlib.sha256(public).hexdigest()
        Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(authentication["signature"]), message,
        )
        candidate = dict(value)
        candidate.pop("receipt_sha256")
        assert value["receipt_sha256"] == hashlib.sha256(_canonical(candidate)).hexdigest()
        validation._validate_backend(
            value, footer_values, 5, public, payload,
            authenticate_registry=False,
        )
        assert footer[:8] == b"PLMOP4R1"
        assert struct.unpack_from(">HHHHH", footer, 8) == (1, 512, 5, 2, 4)
        assert struct.unpack_from(">QQQ", footer, 20) == (
            len(payload), len(manifest), len(semantic),
        )
        assert footer[44:76] == bytes.fromhex("aa" * 32)
        assert footer[76:108] == hashlib.sha256(payload).digest()
        assert footer[108:140] == hashlib.sha256(manifest).digest()
        assert footer[140:172] == hashlib.sha256(semantic).digest()
        assert hashlib.sha256(footer[:480]).digest() == footer[480:]
        assert projection.payload_size == len(payload)
        assert bytes(projection.verifier_public_key_sha256) == hashlib.sha256(public).digest()

        duplicate_writer, duplicate_reader = _pair(tmp_path / "duplicate.bin")
        duplicate_projection = Projection()
        duplicate_projection.verifier_public_key_fd = -1
        duplicate_projection.semantic_receipt_fd = -1
        try:
            assert native.plamen_native_backend_receipt_sign_v1(
                signer, 5, unsigned_fd, payload_fd, manifest_fd,
                duplicate_writer, duplicate_reader,
                ctypes.byref(duplicate_projection),
            ) == -1
            with pytest.raises(OSError):
                os.fstat(duplicate_writer)
        finally:
            native.plamen_native_backend_signed_projection_dispose_v1(
                ctypes.byref(duplicate_projection),
            )
            os.close(duplicate_reader)

        attacker_writer, attacker_reader = _pair(tmp_path / "attacker-public.bin")
        attacker = ctypes.c_void_p()
        assert native.plamen_native_backend_receipt_signer_create_v1(
            os.getuid(), attacker_writer, attacker_reader, ctypes.byref(attacker),
        ) == 0
        try:
            with pytest.raises(Exception):
                Ed25519PublicKey.from_public_bytes(_read(attacker_reader)).verify(
                    bytes.fromhex(authentication["signature"]), message,
                )
            mutated = bytearray(bytes.fromhex(authentication["signature"]))
            mutated[0] ^= 1
            with pytest.raises(Exception):
                Ed25519PublicKey.from_public_bytes(public).verify(bytes(mutated), message)
        finally:
            native.plamen_native_backend_receipt_signer_dispose_v1(attacker)
            os.close(attacker_reader)
    finally:
        native.plamen_native_backend_signed_projection_dispose_v1(ctypes.byref(projection))
        native.plamen_native_backend_receipt_signer_dispose_v1(signer)
        for descriptor in (public_reader, unsigned_fd, payload_fd, manifest_fd, receipt_reader):
            os.close(descriptor)


def test_native_backend_signer_recomputes_digest_and_consumes_writer_on_denial(
    tmp_path: Path,
) -> None:
    native = _build(tmp_path)
    public_writer, public_reader = _pair(tmp_path / "public.bin")
    signer = ctypes.c_void_p()
    assert native.plamen_native_backend_receipt_signer_create_v1(
        os.getuid(), public_writer, public_reader, ctypes.byref(signer),
    ) == 0
    payload = b"retained payload"
    manifest = b'{"manifest":1}'
    unsigned_fd = _retained(
        tmp_path / "unsigned.json",
        _unsigned(payload, manifest, payload_digest="00" * 32),
    )
    payload_fd = _retained(tmp_path / "payload.bin", payload)
    manifest_fd = _retained(tmp_path / "manifest.json", manifest)
    receipt_writer, receipt_reader = _pair(tmp_path / "semantic.bin")
    projection = Projection()
    projection.verifier_public_key_fd = -1
    projection.semantic_receipt_fd = -1
    try:
        assert native.plamen_native_backend_receipt_sign_v1(
            signer, 5, unsigned_fd, payload_fd, manifest_fd,
            receipt_writer, receipt_reader, ctypes.byref(projection),
        ) == -1
        with pytest.raises(OSError):
            os.fstat(receipt_writer)
        assert _read(receipt_reader) == b""
    finally:
        native.plamen_native_backend_signed_projection_dispose_v1(ctypes.byref(projection))
        native.plamen_native_backend_receipt_signer_dispose_v1(signer)
        for descriptor in (public_reader, unsigned_fd, payload_fd, manifest_fd, receipt_reader):
            os.close(descriptor)


def test_native_backend_signer_rejects_public_key_drift_and_writer_alias(
    tmp_path: Path,
) -> None:
    native = _build(tmp_path)
    public_path = tmp_path / "public.bin"
    public_writer, public_reader = _pair(public_path)
    signer = ctypes.c_void_p()
    assert native.plamen_native_backend_receipt_signer_create_v1(
        os.getuid(), public_writer, public_reader, ctypes.byref(signer),
    ) == 0
    payload = b"retained payload"
    manifest = b'{"manifest":1}'
    unsigned_fd = _retained(tmp_path / "unsigned.json", _unsigned(payload, manifest))
    payload_fd = _retained(tmp_path / "payload.bin", payload)
    manifest_fd = _retained(tmp_path / "manifest.json", manifest)
    aliased_writer, aliased_reader = _pair(tmp_path / "aliased.bin")
    undisclosed_alias = os.dup(aliased_writer)
    projection = Projection()
    projection.verifier_public_key_fd = -1
    projection.semantic_receipt_fd = -1
    try:
        assert native.plamen_native_backend_receipt_sign_v1(
            signer, 5, unsigned_fd, payload_fd, manifest_fd,
            aliased_writer, aliased_reader, ctypes.byref(projection),
        ) == -1
        os.close(undisclosed_alias)
        public_path.chmod(0o600)
        replacement = os.open(public_path, os.O_WRONLY | os.O_CLOEXEC)
        try:
            os.pwrite(replacement, b"\xff" * 32, 0)
            os.fsync(replacement)
        finally:
            os.close(replacement)
        public_path.chmod(0o400)
        drift_writer, drift_reader = _pair(tmp_path / "drift.bin")
        try:
            assert native.plamen_native_backend_receipt_sign_v1(
                signer, 5, unsigned_fd, payload_fd, manifest_fd,
                drift_writer, drift_reader, ctypes.byref(projection),
            ) == -1
            with pytest.raises(OSError):
                os.fstat(drift_writer)
        finally:
            os.close(drift_reader)
    finally:
        native.plamen_native_backend_signed_projection_dispose_v1(ctypes.byref(projection))
        native.plamen_native_backend_receipt_signer_dispose_v1(signer)
        for descriptor in (public_reader, unsigned_fd, payload_fd, manifest_fd, aliased_reader):
            os.close(descriptor)
