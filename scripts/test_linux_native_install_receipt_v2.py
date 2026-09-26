from __future__ import annotations

import ctypes
from pathlib import Path
import platform
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SIZE = 8192
MEMBER_COUNT = 4


Digest = ctypes.c_ubyte * 32


class Member(ctypes.Structure):
    _fields_ = [
        ("role", ctypes.c_uint16),
        ("relative_path", ctypes.c_char * 257),
        ("elf_interp_path", ctypes.c_char * 257),
        ("mode", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("byte_count", ctypes.c_uint64),
        ("device", ctypes.c_uint64),
        ("inode", ctypes.c_uint64),
        ("link_count", ctypes.c_uint64),
        ("sha256", Digest),
        ("fd_identity", Digest),
        ("elf_interp_identity_sha256", Digest),
        ("elf_needed_closure_sha256", Digest),
    ]


class Receipt(ctypes.Structure):
    _fields_ = [
        ("scope", ctypes.c_uint16),
        ("target_arch", ctypes.c_uint16),
        ("elf_class", ctypes.c_uint16),
        ("elf_data", ctypes.c_uint16),
        ("elf_machine", ctypes.c_uint32),
        ("trust_boundary", ctypes.c_uint16),
        ("expected_uid", ctypes.c_uint32),
        ("expected_gid", ctypes.c_uint32),
        ("python_major", ctypes.c_uint16),
        ("python_minor", ctypes.c_uint16),
        ("socket_path", ctypes.c_char * 257),
        ("python_soabi", ctypes.c_char * 129),
        ("python_implementation", ctypes.c_char * 65),
        ("generation_id_sha256", Digest),
        ("install_provenance_sha256", Digest),
        ("installed_closure_sha256", Digest),
        ("protocol_schema_sha256", Digest),
        ("runtime_package_manifest_sha256", Digest),
        ("native_deployment_receipt_sha256", Digest),
        ("install_root_fd_identity", Digest),
        ("receipt_producer_identity_sha256", Digest),
        ("members", Member * MEMBER_COUNT),
        ("receipt_sha256", Digest),
    ]


@pytest.fixture(scope="module")
def library(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    suffix = ".dylib" if platform.system() == "Darwin" else ".so"
    output = tmp_path_factory.mktemp("linux-install-receipt-v2") / (
        "receipt" + suffix
    )
    compiler = "/usr/bin/clang" if platform.system() == "Darwin" else "cc"
    command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror"]
    command.append("-dynamiclib" if platform.system() == "Darwin" else "-shared")
    if platform.system() != "Darwin":
        command.append("-fPIC")
    command.extend([
        "-I", str(ROOT / "native" / "include"),
        "-I", str(ROOT / "native" / "linux"),
        str(ROOT / "native" / "linux" / "plamen_linux_install_receipt_v2.c"),
        str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
        "-o", str(output),
    ])
    if platform.system() == "Linux":
        command.append("-lcrypto")
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    loaded = ctypes.CDLL(str(output))
    loaded.plamen_linux_install_receipt_v2_encode_exact.argtypes = [
        ctypes.POINTER(Receipt), ctypes.c_void_p, ctypes.c_size_t
    ]
    loaded.plamen_linux_install_receipt_v2_decode_exact.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Receipt)
    ]
    loaded.plamen_linux_install_receipt_v2_session_binding.argtypes = [
        ctypes.POINTER(Receipt), ctypes.c_void_p
    ]
    return loaded


def _digest(seed: int) -> Digest:
    return Digest(*([seed] * 32))


def _receipt(*, scope: int = 1, uid: int = 501, gid: int = 20) -> Receipt:
    value = Receipt()
    value.scope = scope
    value.target_arch = 1
    value.elf_class = 2
    value.elf_data = 1
    value.elf_machine = 62
    value.trust_boundary = 1
    value.expected_uid = uid
    value.expected_gid = gid
    value.python_major = 3
    value.python_minor = 12
    value.socket_path = (
        f"/run/user/{uid}/plamen/broker-v2.sock".encode()
        if scope == 1 else b"/run/plamen/broker-v2.sock"
    )
    value.python_soabi = b"cpython-312-x86_64-linux-gnu"
    value.python_implementation = b"cpython"
    for index, field in enumerate((
        "generation_id_sha256",
        "install_provenance_sha256",
        "installed_closure_sha256",
        "protocol_schema_sha256",
        "runtime_package_manifest_sha256",
        "native_deployment_receipt_sha256",
        "install_root_fd_identity",
        "receipt_producer_identity_sha256",
    ), start=1):
        setattr(value, field, _digest(index))
    paths = (
        b"libexec/plamen/plamen-audit-broker-v2",
        b"lib/plamen/_plamen_native_supervisor.cpython-312-x86_64-linux-gnu.so",
        b"bin/python3.12",
        b"libexec/plamen/plamen-linux-service-bootstrap-v2",
    )
    modes = (0o500, 0o400, 0o500, 0o500)
    for index, member in enumerate(value.members):
        member.role = index + 1
        member.relative_path = paths[index]
        member.elf_interp_path = b"/lib64/ld-linux-x86-64.so.2"
        member.mode = modes[index]
        member.uid = uid
        member.gid = gid
        member.byte_count = 1000 + index
        member.device = 2000
        member.inode = 3000 + index
        member.link_count = 1
        member.sha256 = _digest(20 + index)
        member.fd_identity = _digest(30 + index)
        member.elf_interp_identity_sha256 = _digest(40 + index)
        member.elf_needed_closure_sha256 = _digest(50 + index)
    return value


def _encode(library: ctypes.CDLL, value: Receipt) -> bytes:
    output = (ctypes.c_ubyte * SIZE)()
    assert library.plamen_linux_install_receipt_v2_encode_exact(
        ctypes.byref(value), output, SIZE
    ) == 0
    return bytes(output)


def test_exact_codec_is_deterministic_and_session_binds_self_digest(
    library: ctypes.CDLL,
) -> None:
    raw = _encode(library, _receipt())
    assert raw[:8] == b"PLNLIR2\0"
    assert len(raw) == SIZE
    decoded = Receipt()
    assert library.plamen_linux_install_receipt_v2_decode_exact(
        raw, len(raw), ctypes.byref(decoded)
    ) == 0
    assert _encode(library, decoded) == raw
    first = Digest()
    second = Digest()
    assert library.plamen_linux_install_receipt_v2_session_binding(
        ctypes.byref(decoded), first
    ) == 0
    changed = bytearray(raw)
    changed[-1] ^= 1
    assert library.plamen_linux_install_receipt_v2_decode_exact(
        bytes(changed), len(changed), ctypes.byref(Receipt())
    ) != 0
    decoded.receipt_sha256[0] ^= 1
    assert library.plamen_linux_install_receipt_v2_session_binding(
        ctypes.byref(decoded), second
    ) == 0
    assert bytes(first) != bytes(second)


@pytest.mark.parametrize("offset", [50, 320, 960, 5120, 8159])
def test_reserved_bytes_are_strictly_zero(
    library: ctypes.CDLL, offset: int
) -> None:
    raw = bytearray(_encode(library, _receipt()))
    raw[offset] = 1
    assert library.plamen_linux_install_receipt_v2_decode_exact(
        bytes(raw), len(raw), ctypes.byref(Receipt())
    ) != 0


def test_scope_derives_socket_and_guest_root_identity(library: ctypes.CDLL) -> None:
    outer = _receipt()
    outer.socket_path = b"/tmp/broker.sock"
    output = (ctypes.c_ubyte * SIZE)()
    assert library.plamen_linux_install_receipt_v2_encode_exact(
        ctypes.byref(outer), output, SIZE
    ) != 0
    assert _encode(library, _receipt(scope=2, uid=0, gid=0))
    guest_user = _receipt(scope=2, uid=501, gid=20)
    assert library.plamen_linux_install_receipt_v2_encode_exact(
        ctypes.byref(guest_user), output, SIZE
    ) != 0


def test_member_order_paths_elf_closure_and_identity_are_mandatory(
    library: ctypes.CDLL,
) -> None:
    output = (ctypes.c_ubyte * SIZE)()
    for mutate in (
        lambda value: setattr(value.members[0], "role", 2),
        lambda value: setattr(value.members[1], "relative_path", b"../escape"),
        lambda value: setattr(value.members[2], "link_count", 2),
        lambda value: setattr(value.members[3], "elf_needed_closure_sha256", Digest()),
        lambda value: setattr(value.members[0], "fd_identity", Digest()),
        lambda value: setattr(value.members[0], "elf_interp_path", b"/tmp/ld.so"),
    ):
        value = _receipt()
        mutate(value)
        assert library.plamen_linux_install_receipt_v2_encode_exact(
            ctypes.byref(value), output, SIZE
        ) != 0


def test_header_exposes_single_fixed_inherited_authority_numbers() -> None:
    header = (
        ROOT / "native" / "linux" / "plamen_linux_install_receipt_v2.h"
    ).read_text(encoding="utf-8")
    assert "#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_FD 198" in header
    assert "#define PLAMEN_LINUX_INSTALL_ROOT_V2_FD 199" in header
    assert "PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE 8192U" in header
