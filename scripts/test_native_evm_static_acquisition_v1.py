from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess

import pytest

import native_evm_static_acquisition_assets as assets


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native/darwin"
ASSET_ENV = "PLAMEN_EVM_STATIC_TEST_ASSET_DIR"


class RoleProjection(ctypes.Structure):
    _fields_ = [
        ("role", ctypes.c_uint16),
        ("payload_fd", ctypes.c_int),
        ("producer_receipt_fd", ctypes.c_int),
        ("source_manifest_fd", ctypes.c_int),
        ("payload_size", ctypes.c_uint64),
        ("producer_receipt_size", ctypes.c_uint64),
        ("source_manifest_size", ctypes.c_uint64),
        ("payload_sha256", ctypes.c_ubyte * 32),
        ("producer_receipt_sha256", ctypes.c_ubyte * 32),
        ("source_manifest_sha256", ctypes.c_ubyte * 32),
    ]


class Projection(ctypes.Structure):
    _fields_ = [("roles", RoleProjection * 2)]


def _array(raw: bytes) -> str:
    return "{" + ",".join(f"0x{item:02x}" for item in raw) + "}"


def _policy_source() -> str:
    rows = []
    for role in ("medusa", "solc_amd64"):
        item = assets.native_operation4_evm_policy_input(role)
        rows.append(
            f"[{item['role_ordinal']}]={{.role={item['role_ordinal']},"
            f".identity_mode={item['identity_mode']},"
            f".receipt_validator={item['receipt_validator']},"
            f".payload_size={item['payload_size']}ULL,"
            f".source_manifest_size={item['source_manifest_size']}ULL,"
            f".semantic_receipt_size={item['semantic_receipt_size']}ULL,"
            f".payload_sha256={_array(bytes.fromhex(item['payload_sha256']))},"
            f".source_manifest_sha256={_array(bytes.fromhex(item['source_manifest_sha256']))},"
            f".semantic_receipt_sha256={_array(bytes.fromhex(item['semantic_receipt_sha256']))},"
            f".policy_sha256={_array(bytes.fromhex(item['policy_sha256']))},"
            f".receipt_schema=\"{item['receipt_schema']}\"}}"
        )
    return (
        '#include "plamen_native_operation4_helper_v1.h"\n'
        "const struct plamen_native_operation4_fixed_policy_v1 "
        "plamen_native_operation4_generated_policy_v1={"
        ".version=1,.role_count=11,.roster_sha256={1},.rows={"
        + ",".join(rows)
        + "}};\n"
    )


def _embedded(name: str) -> bytes:
    source = (NATIVE / "plamen_native_evm_static_assets_v1.inc").read_text()
    match = re.search(
        rf"static const unsigned char {re.escape(name)}\[\] = \{{(.*?)\}};",
        source,
        re.DOTALL,
    )
    assert match is not None
    return bytes(int(item, 16) for item in re.findall(r"0x([0-9a-f]{2})", match.group(1)))


def test_embedded_assets_are_exact_reviewed_bytes() -> None:
    for role, prefix in (
        ("medusa", "verification_policy_medusa"),
        ("solc_amd64", "verification_policy_solc_amd64"),
    ):
        contract = assets.CONTRACTS[role]
        assert _embedded(prefix + "_acquisition_receipt_v1_json") == (
            ROOT / contract.receipt_path
        ).read_bytes()
        assert _embedded(prefix + "_runtime_source_manifest_v1_json") == (
            ROOT / contract.source_manifest_path
        ).read_bytes()


@pytest.mark.skipif(platform.system() != "Darwin", reason="Darwin provider")
def test_provider_sources_compile_with_warnings_as_errors(tmp_path: Path) -> None:
    subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(NATIVE), "-c",
            str(NATIVE / "plamen_native_evm_static_acquisition_v1.c"),
            "-o", str(tmp_path / "provider.o"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "/usr/bin/swiftc", "-warnings-as-errors", "-parse-as-library",
            "-emit-object",
            str(NATIVE / "plamen_native_evm_static_acquisition_v1.swift"),
            "-o", str(tmp_path / "provider-swift.o"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_public_surface_has_no_path_policy_network_or_callback_input() -> None:
    header = (NATIVE / "plamen_native_evm_static_acquisition_v1.h").read_text()
    source = (NATIVE / "plamen_native_evm_static_acquisition_v1.c").read_text()
    assert "staged_generation_root_fd" in header
    public_parameters = header.split(
        "int plamen_native_evm_static_acquisition_issue_v1", 1
    )[1].split(");", 1)[0]
    for forbidden in ("path", "callback", "policy", "digest", "network", "environment"):
        assert forbidden not in public_parameters
    for forbidden in ("getenv(", "system(", "execve(", "posix_spawn(", "socket("):
        assert forbidden not in source
    for leaf in (
        "08-medusa.payload", "08-medusa.producer-receipt",
        "08-medusa.source-manifest", "09-solc_amd64.payload",
        "09-solc_amd64.producer-receipt", "09-solc_amd64.source-manifest",
    ):
        assert leaf in source


def _live_asset_root() -> Path:
    raw = os.environ.get(ASSET_ENV)
    if raw is None:
        pytest.skip(f"set {ASSET_ENV} to run frozen upstream live vectors")
    root = Path(raw)
    expected = {
        "medusa.tar.gz": (11_948_454, "ddfe1517ae9028ef9fc331b00f5a6a9d5406f3fcd11a715d60c6b6fb3e4546d3"),
        "medusa.sigstore.json": (10_584, "e7a277b17588fe02425a0cf4656f36d98f39eea9d4a7b0548e6617184238efb6"),
        "list.json": (47_730, "ee1a2b4811bd1225c220cd2342e2b49a58cbe18f5687f230f456c443b29497d6"),
        "solc": (15_434_456, "d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef"),
    }
    for name, (size, digest) in expected.items():
        raw_bytes = (root / name).read_bytes()
        assert len(raw_bytes) == size
        assert hashlib.sha256(raw_bytes).hexdigest() == digest
    return root


@pytest.fixture
def live_library(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("Darwin provider")
    _live_asset_root()
    policy = tmp_path / "generated-policy.c"
    policy.write_text(_policy_source())
    objects = []
    for source in (
        NATIVE / "plamen_native_evm_static_acquisition_v1.c",
        policy,
    ):
        output = tmp_path / (source.stem + ".o")
        subprocess.run(
            ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-I", str(NATIVE), "-c", str(source), "-o", str(output)],
            check=True, capture_output=True, text=True,
        )
        objects.append(output)
    swift_object = tmp_path / "provider-swift.o"
    subprocess.run(
        ["/usr/bin/swiftc", "-warnings-as-errors", "-parse-as-library",
         "-emit-object", str(NATIVE / "plamen_native_evm_static_acquisition_v1.swift"),
         "-o", str(swift_object)],
        check=True, capture_output=True, text=True,
    )
    output = tmp_path / "libprovider.dylib"
    subprocess.run(
        ["/usr/bin/swiftc", "-emit-library", *(str(item) for item in objects),
         str(swift_object), "-Xlinker", "-lz", "-framework", "Foundation",
         "-framework", "CryptoKit", "-framework", "Security", "-o", str(output)],
        check=True, capture_output=True, text=True,
    )
    library = ctypes.CDLL(str(output), use_errno=True)
    library.plamen_native_evm_static_acquisition_issue_v1.argtypes = [
        ctypes.c_uint32, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.POINTER(Projection),
    ]
    library.plamen_native_evm_static_acquisition_issue_v1.restype = ctypes.c_int
    library.plamen_native_evm_static_projection_dispose_v1.argtypes = [
        ctypes.POINTER(Projection)
    ]
    return library


def _open_ro(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC)


def test_live_frozen_inputs_issue_exact_read_only_leaves(
    tmp_path: Path, live_library,
) -> None:
    upstream = _live_asset_root()
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    fds = [_open_ro(upstream / name) for name in (
        "medusa.tar.gz", "medusa.sigstore.json", "list.json", "solc",
    )]
    root_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    projection = Projection()
    try:
        assert live_library.plamen_native_evm_static_acquisition_issue_v1(
            os.getuid(), root_fd, *fds, ctypes.byref(projection)
        ) == 0
        for index, role in enumerate(("medusa", "solc_amd64")):
            contract = assets.CONTRACTS[role]
            row = projection.roles[index]
            assert row.role == contract.ordinal
            assert row.payload_size == contract.payload_size
            assert bytes(row.payload_sha256).hex() == contract.payload_sha256
            assert row.source_manifest_size == contract.source_manifest_size
            assert bytes(row.source_manifest_sha256).hex() == contract.source_manifest_sha256
            receipt = os.pread(
                row.producer_receipt_fd, row.producer_receipt_size, 0,
            )
            semantic = (ROOT / contract.receipt_path).read_bytes()
            footer = receipt[-512:]
            assert receipt[:-512] == semantic
            assert footer[:8] == b"PLMOP4R1"
            assert struct.unpack_from(">HHHHH", footer, 8) == (
                1, 512, contract.ordinal, 1, contract.receipt_validator,
            )
            assert struct.unpack_from(">QQQ", footer, 20) == (
                contract.payload_size,
                contract.source_manifest_size,
                contract.receipt_size,
            )
            assert footer[44:76].hex() == contract.policy_sha256
            assert footer[76:108].hex() == contract.payload_sha256
            assert footer[108:140].hex() == contract.source_manifest_sha256
            assert footer[140:172].hex() == contract.receipt_sha256
            assert footer[172:268].split(b"\0", 1)[0].decode() == contract.receipt_schema
            # Static payload roles have no dynamic resolved-version footer;
            # the exact version remains inside the compiled semantic prefix.
            assert not any(footer[268:396])
            assert not any(footer[396:480])
            assert footer[480:] == hashlib.sha256(footer[:480]).digest()
            for descriptor in (row.payload_fd, row.producer_receipt_fd,
                               row.source_manifest_fd):
                assert os.fstat(descriptor).st_mode & 0o777 == 0o400
                assert fcntl_get_access_mode(descriptor) == os.O_RDONLY
        live_library.plamen_native_evm_static_projection_dispose_v1(
            ctypes.byref(projection)
        )
        # O_EXCL refusal must preserve the first successful generation.
        assert live_library.plamen_native_evm_static_acquisition_issue_v1(
            os.getuid(), root_fd, *fds, ctypes.byref(projection)
        ) == -1
        assert len(list((stage / "share/plamen/native-source-authority-v1").iterdir())) == 6
    finally:
        live_library.plamen_native_evm_static_projection_dispose_v1(
            ctypes.byref(projection)
        )
        os.close(root_fd)
        for descriptor in fds:
            os.close(descriptor)


@pytest.mark.parametrize(
    "mutated_name",
    ("medusa.tar.gz", "medusa.sigstore.json", "list.json", "solc"),
)
def test_live_mutated_upstream_is_rejected_without_published_leaves(
    tmp_path: Path, live_library, mutated_name: str,
) -> None:
    upstream = _live_asset_root()
    copies = tmp_path / "inputs"
    copies.mkdir(mode=0o700)
    names = ("medusa.tar.gz", "medusa.sigstore.json", "list.json", "solc")
    for name in names:
        shutil.copyfile(upstream / name, copies / name)
        os.chmod(copies / name, 0o400)
    target = copies / mutated_name
    os.chmod(target, 0o600)
    with target.open("r+b") as stream:
        value = stream.read(1)
        stream.seek(0)
        stream.write(bytes([value[0] ^ 1]))
    os.chmod(target, 0o400)
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    root_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fds = [_open_ro(copies / name) for name in names]
    projection = Projection()
    try:
        assert live_library.plamen_native_evm_static_acquisition_issue_v1(
            os.getuid(), root_fd, *fds, ctypes.byref(projection)
        ) == -1
        authority = stage / "share/plamen/native-source-authority-v1"
        assert not authority.exists() or not list(authority.iterdir())
    finally:
        live_library.plamen_native_evm_static_projection_dispose_v1(
            ctypes.byref(projection)
        )
        os.close(root_fd)
        for descriptor in fds:
            os.close(descriptor)


def fcntl_get_access_mode(descriptor: int) -> int:
    import fcntl
    return fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
