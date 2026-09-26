"""Production-shape integration tests for the Darwin operation-4 helper.

The native helper testing constructor deliberately differs from production in
one respect only: its retained Python validator skips npm's P-256 registry
signature verification.  These tests still exercise exact semantic receipts,
Ed25519 install-generation signatures, payload SHA-256/SRI binding, inherited
descriptor execution, the no-network sandbox, and the MACed terminal receipt.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from typing import Callable

import pytest

import runtime_image_materializer as materializer
import test_runtime_image_materializer as materializer_fixture


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="the Darwin operation-4 helper requires sandbox_init"
)

ROLE_COUNT = 11
OUTPUT_COUNT = 5
SCRATCH_COUNT = 24
FOOTER_SIZE = 512
TERMINAL_SIZE = 4096

ROLES = (
    "base_rootfs",
    "debian_package_state",
    "plamen_guest",
    "cpython",
    "plamen_package",
    "codex",
    "claude",
    "foundry",
    "medusa",
    "solc_amd64",
    "amd64_compat",
)
ARTIFACTS = (
    "base",
    "debian-state",
    "plamen-guest",
    "cpython",
    "plamen",
    "codex",
    "claude",
    "foundry",
    "medusa",
    "solc",
    "amd64-compat",
)
MODES = (1, 1, 3, 1, 3, 2, 2, 1, 1, 1, 1)
VALIDATORS = (1, 1, 2, 3, 2, 4, 4, 5, 6, 7, 8)
SCHEMAS = (
    "plamen.debian-runtime-acquisition-receipt.v1",
    "plamen.debian-runtime-acquisition-receipt.v1",
    "plamen.plamen-source-projection-acquisition-receipt.v1",
    "plamen.cpython-runtime-acquisition-receipt.v1",
    "plamen.plamen-source-projection-acquisition-receipt.v1",
    "plamen.native-backend-latest-acquisition-receipt.v1",
    "plamen.native-backend-latest-acquisition-receipt.v1",
    "plamen.foundry-acquisition-receipt.v1",
    "plamen.medusa-acquisition-receipt.v1",
    "plamen.solc-amd64-acquisition-receipt.v1",
    "plamen.amd64-compat-acquisition-receipt.v1",
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


class PolicyRow(ctypes.Structure):
    _fields_ = [
        ("role", ctypes.c_uint16),
        ("identity_mode", ctypes.c_uint16),
        ("receipt_validator", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("payload_size", ctypes.c_uint64),
        ("source_manifest_size", ctypes.c_uint64),
        ("semantic_receipt_size", ctypes.c_uint64),
        ("payload_sha256", ctypes.c_uint8 * 32),
        ("source_manifest_sha256", ctypes.c_uint8 * 32),
        ("semantic_receipt_sha256", ctypes.c_uint8 * 32),
        ("policy_sha256", ctypes.c_uint8 * 32),
        ("receipt_schema", ctypes.c_char * 96),
    ]


class FixedPolicy(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("role_count", ctypes.c_uint32),
        ("roster_sha256", ctypes.c_uint8 * 32),
        ("rows", PolicyRow * ROLE_COUNT),
    ]


class SourceInput(ctypes.Structure):
    _fields_ = [
        ("payload_fd", ctypes.c_int),
        ("producer_receipt_fd", ctypes.c_int),
        ("source_manifest_fd", ctypes.c_int),
        ("identity_mode", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("expected_payload_size", ctypes.c_uint64),
        ("expected_payload_sha256", ctypes.c_uint8 * 32),
        ("expected_producer_receipt_size", ctypes.c_uint64),
        ("expected_producer_receipt_sha256", ctypes.c_uint8 * 32),
        ("expected_source_manifest_size", ctypes.c_uint64),
        ("expected_source_manifest_sha256", ctypes.c_uint8 * 32),
        ("policy_sha256", ctypes.c_uint8 * 32),
    ]


class FDIdentity(ctypes.Structure):
    _fields_ = [
        ("device", ctypes.c_uint64),
        ("inode", ctypes.c_uint64),
        ("mode", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("links", ctypes.c_uint32),
        ("size", ctypes.c_uint64),
        ("mtime_seconds", ctypes.c_int64),
        ("mtime_nanoseconds", ctypes.c_uint32),
        ("ctime_seconds", ctypes.c_int64),
        ("ctime_nanoseconds", ctypes.c_uint32),
        ("sha256", ctypes.c_uint8 * 32),
    ]


def _array32(raw: bytes) -> ctypes.Array:
    assert len(raw) == 32
    return (ctypes.c_uint8 * 32).from_buffer_copy(raw)


def _identity(raw: bytes) -> FDIdentity:
    value = FDIdentity()
    value.size = len(raw)
    value.sha256 = _array32(_sha256(raw))
    return value


def _fd_identity(descriptor: int) -> FDIdentity:
    state = os.fstat(descriptor)
    value = FDIdentity()
    value.device = state.st_dev
    value.inode = state.st_ino
    value.mode = state.st_mode
    value.uid = state.st_uid
    value.gid = state.st_gid
    value.links = state.st_nlink
    value.size = state.st_size
    value.mtime_seconds = state.st_mtime_ns // 1_000_000_000
    value.mtime_nanoseconds = state.st_mtime_ns % 1_000_000_000
    value.ctime_seconds = state.st_ctime_ns // 1_000_000_000
    value.ctime_nanoseconds = state.st_ctime_ns % 1_000_000_000
    value.sha256 = _array32(_sha256(os.pread(descriptor, state.st_size, 0)))
    return value


def _open_linked_readonly(path: Path, raw: bytes) -> int:
    path.write_bytes(raw)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    assert os.get_inheritable(descriptor) is False
    assert os.fstat(descriptor).st_nlink == 1
    return descriptor


def _open_linked_pair(path: Path) -> tuple[int, int]:
    writer = os.open(
        path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600
    )
    reader = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    return writer, reader


def _open_anonymous_pair(path: Path) -> tuple[int, int]:
    writer, reader = _open_linked_pair(path)
    path.unlink()
    assert os.fstat(writer).st_nlink == 0
    assert os.fstat(reader).st_nlink == 0
    return writer, reader


def _open_anonymous_scratch(path: Path) -> int:
    descriptor = os.open(
        path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600
    )
    path.unlink()
    assert os.fstat(descriptor).st_nlink == 0
    return descriptor


def _footer(
    role: int,
    policy_sha256: bytes,
    payload: bytes,
    source_manifest: bytes,
    semantic: bytes,
    version: str = "",
) -> bytes:
    raw = bytearray(FOOTER_SIZE)
    raw[:8] = b"PLMOP4R1"
    struct.pack_into(">HHHHH", raw, 8, 1, FOOTER_SIZE, role, MODES[role], VALIDATORS[role])
    struct.pack_into(">HQQQ", raw, 18, 0, len(payload), len(source_manifest), len(semantic))
    raw[44:76] = policy_sha256
    raw[76:108] = _sha256(payload)
    raw[108:140] = _sha256(source_manifest)
    raw[140:172] = _sha256(semantic)
    schema = SCHEMAS[role].encode("ascii")
    raw[172 : 172 + len(schema)] = schema
    if version:
        encoded_version = version.encode("ascii")
        raw[268 : 268 + len(encoded_version)] = encoded_version
    raw[480:512] = _sha256(raw[:480])
    return bytes(raw)


def _registry_signature() -> dict[str, str]:
    return {
        "keyid": "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
        "message_sha256": "10" * 32,
        "signature": "AA==",
    }


def _signed_backend_receipt(
    selector: str,
    payload: bytes,
    source_manifest: bytes,
    policy_sha256: bytes,
    private_key,
) -> tuple[bytes, str]:
    version = "0.154.0" if selector == "codex" else "2.1.270"
    root_package = (
        "@openai/codex" if selector == "codex" else "@anthropic-ai/claude-code"
    )
    platform_package = (
        "@openai/codex-linux-arm64"
        if selector == "codex"
        else "@anthropic-ai/claude-code-linux-arm64"
    )
    platform_version = version + "-linux-arm64" if selector == "codex" else version
    sri = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
    provenance = (
        {
            "predicate_type": "https://slsa.dev/provenance/v1",
            "url": "https://registry.npmjs.org/-/npm/v1/attestations/test",
        }
        if selector == "codex"
        else None
    )
    registry = {
        "selector": selector,
        "package": root_package,
        "version": version,
        "metadata_sha256": "11" * 32,
        "metadata_url": "https://registry.npmjs.org/"
        + root_package.replace("/", "%2f")
        + "/latest",
        "tarball_url": "https://registry.npmjs.org/root.tgz",
        "integrity": sri,
        "shasum": "12" * 20,
        "registry_signature": _registry_signature(),
        "trusted_publisher": (
            {"id": "github", "oidc_config_id": "test-oidc"}
            if selector == "codex"
            else None
        ),
        "provenance": provenance,
        "platform_package": {
            "install_name": platform_package,
            "package": root_package if selector == "codex" else platform_package,
            "version": platform_version,
            "metadata_url": "https://registry.npmjs.org/platform/exact",
            "metadata_sha256": "13" * 32,
            "tarball_url": "https://registry.npmjs.org/platform.tgz",
            "integrity": sri,
            "shasum": "14" * 20,
            "registry_signature": _registry_signature(),
            "provenance": provenance,
        },
    }
    observed_contract = (
        [
            "--allowedTools",
            "--disallowedTools",
            "--json-schema",
            "--mcp-config",
            "--model",
            "--output-format",
            "--permission-mode",
            "--strict-mcp-config",
        ]
        if selector == "claude"
        else [
            "--ephemeral",
            "--json",
            "--model",
            "--output-last-message",
            "--sandbox",
            "--skip-git-repo-check",
        ]
    )
    executable_sha256 = "21" * 32
    value = {
        "schema": "plamen.native-backend-latest-acquisition-receipt.v1",
        "selector": selector,
        "policy_schema": "plamen.native-backend-acquisition.v2",
        "policy_sha256": policy_sha256.hex(),
        "resolved_version": version,
        "resolved_release": platform_version,
        "registry": registry,
        "upstream": None,
        "transport": {
            "tls_minimum": "1.2",
            "redirect_count": 0,
            "credentials": "FORBIDDEN",
            "proxy_environment": "IGNORED",
            "endpoints_sha256": "22" * 32,
        },
        "payload": {
            "source_url": registry["platform_package"]["tarball_url"],
            "size": len(payload),
            "sha256": _sha256(payload).hex(),
            "sha512_sri": sri,
            "archive_format": "tar.gz",
            "member_count": 2,
            "member_roster_sha256": "23" * 32,
            "selected_member": (
                "package/vendor/aarch64-unknown-linux-gnu/bin/codex"
                if selector == "codex" else "package/claude"
            ),
            "path_traversal_rejected": True,
        },
        "installed": {
            "platform": "linux-arm64",
            "relative_path": (
                "node_modules/@openai/codex-linux-arm64/vendor/"
                "aarch64-unknown-linux-gnu/bin/codex"
                if selector == "codex"
                else "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
            ),
            "executable_size": 456,
            "executable_sha256": executable_sha256,
            "closure_count": 3,
            "closure_bytes": 789,
            "closure_sha256": "24" * 32,
            "code_signature": {
                "mode": "REGISTRY_SIGNATURE_ONLY",
                "identifier": None,
                "team_identifier": None,
                "cdhash_sha256": None,
            },
        },
        "probes": {
            "version": {
                "argv": ["--version"],
                "returncode": 0,
                "stdout_sha256": "26" * 32,
                "stderr_sha256": "27" * 32,
                "normalized_output": (
                    f"{version} (Claude Code)"
                    if selector == "claude"
                    else f"codex-cli {version}"
                ),
                "observed_contract": [],
            },
            "help": {
                "argv": ["--help"] if selector == "claude" else ["exec", "--help"],
                "returncode": 0,
                "stdout_sha256": "28" * 32,
                "stderr_sha256": "29" * 32,
                "normalized_output": "help",
                "observed_contract": observed_contract,
            },
        },
        "install": {
            "transaction_id": "install-test",
            "generation_id": "npm-" + "30" * 32,
            "install_receipt_sha256": "31" * 32,
            "source_manifest_sha256": _sha256(source_manifest).hex(),
            "source_manifest_size": len(source_manifest),
        },
    }
    if selector == "claude":
        value["upstream"] = {
            "latest_url": "https://downloads.claude.ai/claude-code-releases/latest",
            "latest_sha256": "32" * 32,
            "manifest_url": (
                f"https://downloads.claude.ai/claude-code-releases/{version}/manifest.json"
            ),
            "manifest_sha256": "33" * 32,
            "manifest_size": 1234,
            "commit": "34" * 20,
            "platform": "linux-arm64",
            "executable_sha256": executable_sha256,
            "executable_size": 456,
        }
    public = private_key.public_key().public_bytes_raw()
    value["authentication"] = {
        "scheme": "ed25519",
        "key_id": _sha256(public).hex(),
        "signature": private_key.sign(_canonical(value)).hex(),
    }
    value["receipt_sha256"] = _sha256(_canonical(value)).hex()
    return _canonical(value), version


def _native_inputs() -> tuple[bytes, list[bytes], list[bytes]]:
    manifest, by_artifact, source_by_artifact = materializer_fixture._fixture_values()
    manifest["schema_version"] = materializer.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION
    manifest["authentication_scope"] = materializer.NATIVE_RETAINED_AUTHENTICATION_SCOPE
    for source in manifest["sources"]:
        artifact = source["artifact_id"]
        value = json.loads(source_by_artifact[artifact])
        value["schema_version"] = materializer.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION
        value["authentication_scope"] = materializer.NATIVE_RETAINED_AUTHENTICATION_SCOPE
        raw_source = materializer_fixture._canonical(value)
        source_by_artifact[artifact] = raw_source
        source["source_manifest_sha256"] = _sha256(raw_source).hex()
        source["source_manifest_size"] = len(raw_source)
    return (
        materializer_fixture._canonical(manifest),
        [by_artifact[name] for name in ARTIFACTS],
        [source_by_artifact[name] for name in ARTIFACTS],
    )


@pytest.fixture(scope="module")
def native_library(tmp_path_factory):
    repo = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp("op4-native") / "libplamen-op4-test.dylib"
    command = [
        "/usr/bin/clang",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-DPLAMEN_NATIVE_OPERATION4_TESTING",
        "-dynamiclib",
        "-I",
        str(repo / "native/darwin"),
        str(repo / "native/darwin/plamen_native_operation4_helper_v1.c"),
        "-o",
        str(output),
    ]
    subprocess.run(command, cwd=repo, check=True, capture_output=True, text=True)
    library = ctypes.CDLL(str(output), use_errno=True)
    library.plamen_native_operation4_policy_finalize_for_testing_v1.argtypes = [
        ctypes.POINTER(FixedPolicy)
    ]
    library.plamen_native_operation4_policy_finalize_for_testing_v1.restype = ctypes.c_int
    library.plamen_native_operation4_context_create_for_testing_v1.argtypes = [
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(FixedPolicy),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.plamen_native_operation4_context_create_for_testing_v1.restype = ctypes.c_int
    library.plamen_native_operation4_context_dispose_v1.argtypes = [ctypes.c_void_p]
    library.plamen_native_operation4_policy_fill_fixed_v1.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(SourceInput),
    ]
    library.plamen_native_operation4_policy_fill_fixed_v1.restype = ctypes.c_int
    library.plamen_native_operation4_authenticate_source_fixed_v1.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint16,
        ctypes.c_int,
        ctypes.POINTER(SourceInput),
        ctypes.POINTER(FDIdentity),
        ctypes.POINTER(FDIdentity),
        ctypes.POINTER(FDIdentity),
    ]
    library.plamen_native_operation4_authenticate_source_fixed_v1.restype = ctypes.c_int
    library.plamen_native_operation4_invoke_fixed_v1.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
    ]
    library.plamen_native_operation4_invoke_fixed_v1.restype = ctypes.c_int
    library.plamen_native_operation4_rejoin_terminal_outputs_fixed_v1.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(FDIdentity),
    ]
    library.plamen_native_operation4_rejoin_terminal_outputs_fixed_v1.restype = (
        ctypes.c_int
    )
    library.plamen_native_operation4_attest_python_for_testing_v1.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
    ]
    library.plamen_native_operation4_attest_python_for_testing_v1.restype = ctypes.c_int
    return library


class Operation4Case:
    def __init__(
        self,
        tmp_path: Path,
        library,
        *,
        verifier_mismatch: bool = False,
        mutate_signature: bool = False,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.tmp_path = tmp_path
        self.library = library
        self.context = ctypes.c_void_p()
        self.descriptors: list[int] = []
        self.paths: dict[str, Path] = {}
        self.composition, self.payloads, self.manifests = _native_inputs()
        self.policy_hashes = [_sha256(b"operation4-policy:" + role.encode()) for role in ROLES]
        signing_key = Ed25519PrivateKey.generate()
        verifier_key = Ed25519PrivateKey.generate() if verifier_mismatch else signing_key
        public = verifier_key.public_key().public_bytes_raw()

        runtime_root = tmp_path / "runtime-root"
        scripts = runtime_root / "scripts"
        scripts.mkdir(parents=True)
        repo_scripts = Path(__file__).resolve().parent
        for name in (
            "plamen_transform_bundle.py",
            "native_runtime_grouped_transform.py",
            "runtime_image_materializer.py",
            "oci_retained_archive_transform.py",
            "native_operation4_acquisition_validation.py",
        ):
            shutil.copyfile(repo_scripts / name, scripts / name)
        self.paths["validator"] = scripts / "native_operation4_acquisition_validation.py"

        semantics: list[bytes] = []
        versions = [""] * ROLE_COUNT
        for role in range(ROLE_COUNT):
            if role in (5, 6):
                semantic, versions[role] = _signed_backend_receipt(
                    ROLES[role],
                    self.payloads[role],
                    self.manifests[role],
                    self.policy_hashes[role],
                    signing_key,
                )
                if mutate_signature and role == 5:
                    value = json.loads(semantic)
                    signature = bytearray.fromhex(value["authentication"]["signature"])
                    signature[7] ^= 1
                    value["authentication"]["signature"] = bytes(signature).hex()
                    value["receipt_sha256"] = _sha256(
                        _canonical({k: v for k, v in value.items() if k != "receipt_sha256"})
                    ).hex()
                    semantic = _canonical(value)
                semantics.append(semantic)
            else:
                semantics.append(_canonical({"role": ROLES[role], "schema": SCHEMAS[role]}))
        self.semantic_receipts = tuple(semantics)

        policy = FixedPolicy()
        policy.version = 1
        policy.role_count = ROLE_COUNT
        for role, row in enumerate(policy.rows):
            row.role = role
            row.identity_mode = MODES[role]
            row.receipt_validator = VALIDATORS[role]
            row.policy_sha256 = _array32(self.policy_hashes[role])
            row.receipt_schema = SCHEMAS[role].encode("ascii")
            if MODES[role] != 2:
                row.payload_size = len(self.payloads[role])
                row.source_manifest_size = len(self.manifests[role])
                row.semantic_receipt_size = len(semantics[role])
                row.payload_sha256 = _array32(_sha256(self.payloads[role]))
                row.source_manifest_sha256 = _array32(_sha256(self.manifests[role]))
                row.semantic_receipt_sha256 = _array32(_sha256(semantics[role]))
        assert library.plamen_native_operation4_policy_finalize_for_testing_v1(
            ctypes.byref(policy)
        ) == 0
        self.policy = policy

        self.root_fd = os.open(runtime_root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        self.python_fd = os.open(
            Path(__file__).resolve().parents[1] / ".venv-dev/bin/python3.12",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        self.transform_fd = os.open(
            scripts / "plamen_transform_bundle.py", os.O_RDONLY | os.O_CLOEXEC
        )
        self.verifier_fd = _open_linked_readonly(tmp_path / "verifier.key", public)
        self.descriptors.extend(
            [self.root_fd, self.python_fd, self.transform_fd, self.verifier_fd]
        )

        self.caller_group_pair = _open_anonymous_pair(tmp_path / "caller-group")
        self.caller_terminal_pair = _open_anonymous_pair(tmp_path / "caller-terminal")
        self.descriptors.extend(self.caller_group_pair + self.caller_terminal_pair)
        assert library.plamen_native_operation4_context_create_for_testing_v1(
            os.getuid(),
            self.root_fd,
            self.python_fd,
            self.transform_fd,
            self.verifier_fd,
            *self.caller_group_pair,
            *self.caller_terminal_pair,
            ctypes.byref(policy),
            ctypes.byref(self.context),
        ) == 0, ctypes.get_errno()
        # Descriptor transfer is complete.  The context must be the only
        # remaining holder of each private-store writer/reader capability.
        for descriptor in self.caller_group_pair + self.caller_terminal_pair:
            os.close(descriptor)
            self.descriptors.remove(descriptor)
        self.caller_group_pair = (-1, -1)
        self.caller_terminal_pair = (-1, -1)

        self.inputs = (SourceInput * ROLE_COUNT)()
        assert library.plamen_native_operation4_policy_fill_fixed_v1(
            self.context, self.inputs
        ) == 0
        self.payload_fds = (ctypes.c_int * ROLE_COUNT)()
        self.manifest_fds = (ctypes.c_int * ROLE_COUNT)()
        self.receipt_fds: list[int] = []
        for role in range(ROLE_COUNT):
            payload_fd = _open_linked_readonly(
                tmp_path / f"payload-{role}", self.payloads[role]
            )
            manifest_fd = _open_linked_readonly(
                tmp_path / f"manifest-{role}", self.manifests[role]
            )
            receipt = semantics[role] + _footer(
                role,
                self.policy_hashes[role],
                self.payloads[role],
                self.manifests[role],
                semantics[role],
                versions[role],
            )
            receipt_fd = _open_linked_readonly(tmp_path / f"receipt-{role}", receipt)
            self.descriptors.extend([payload_fd, manifest_fd, receipt_fd])
            self.receipt_fds.append(receipt_fd)
            self.payload_fds[role] = payload_fd
            self.manifest_fds[role] = manifest_fd
            payload_id = _identity(self.payloads[role])
            manifest_id = _identity(self.manifests[role])
            receipt_id = _identity(receipt)
            assert library.plamen_native_operation4_authenticate_source_fixed_v1(
                self.context,
                role,
                receipt_fd,
                ctypes.byref(self.inputs[role]),
                ctypes.byref(payload_id),
                ctypes.byref(receipt_id),
                ctypes.byref(manifest_id),
            ) == 0, (role, ctypes.get_errno())

        self.composition_fd = _open_linked_readonly(
            tmp_path / "composition.json", self.composition
        )
        self.descriptors.append(self.composition_fd)
        self.output_fds = (ctypes.c_int * OUTPUT_COUNT)()
        self.output_paths: list[Path] = []
        for index in range(OUTPUT_COUNT):
            path = tmp_path / f"output-{index}"
            descriptor = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600
            )
            path.unlink()
            self.output_paths.append(path)
            self.output_fds[index] = descriptor
            self.descriptors.append(descriptor)
        self.scratch_fds = (ctypes.c_int * SCRATCH_COUNT)()
        for index in range(SCRATCH_COUNT):
            descriptor = _open_anonymous_scratch(tmp_path / f"scratch-{index}")
            self.scratch_fds[index] = descriptor
            self.descriptors.append(descriptor)

    def invoke(self) -> tuple[int, int]:
        terminal_fd = ctypes.c_int(-1)
        result = self.library.plamen_native_operation4_invoke_fixed_v1(
            self.context,
            self.composition_fd,
            self.payload_fds,
            self.manifest_fds,
            self.output_fds,
            self.scratch_fds,
            ctypes.byref(terminal_fd),
        )
        if terminal_fd.value >= 0:
            self.descriptors.append(terminal_fd.value)
        return result, terminal_fd.value

    def close(self) -> None:
        if self.context:
            self.library.plamen_native_operation4_context_dispose_v1(self.context)
            self.context = ctypes.c_void_p()
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.descriptors.clear()


def _with_case(
    tmp_path: Path,
    library,
    operation: Callable[[Operation4Case], None],
    **options,
) -> None:
    case = Operation4Case(tmp_path, library, **options)
    try:
        operation(case)
    finally:
        case.close()


def test_real_operation4_uses_descriptor_first_private_stores_and_seals_terminal(
    native_library, tmp_path
):
    def exercise(case: Operation4Case) -> None:
        result, terminal_fd = case.invoke()
        assert result == 0, ctypes.get_errno()
        assert terminal_fd >= 0
        terminal = os.pread(terminal_fd, TERMINAL_SIZE, 0)
        assert len(terminal) == TERMINAL_SIZE
        assert terminal[:8] == b"PLMOP4T1"
        assert struct.unpack_from(">H", terminal, 18)[0] == 7
        assert struct.unpack_from(">II", terminal, 20) == (0, 0)
        assert os.fstat(terminal_fd).st_mode & 0o777 == 0o400
        assert fcntl.fcntl(terminal_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        with pytest.raises(OSError) as rejected:
            os.pwrite(terminal_fd, b"X", 0)
        assert rejected.value.errno == errno.EBADF
        assert os.fstat(terminal_fd).st_nlink == 0
        assert all(os.fstat(descriptor).st_size > 0 for descriptor in case.output_fds)
        observation = json.loads(os.pread(case.output_fds[1], os.fstat(case.output_fds[1]).st_size, 0))
        assert observation["schema_version"] == "plamen.runtime_materialization_observation.v1"
        again, second_terminal = case.invoke()
        assert again == -1 and second_terminal == -1

    _with_case(tmp_path, native_library, exercise)


def test_linked_helper_store_is_rejected(native_library, tmp_path):
    def exercise(case: Operation4Case) -> None:
        grouped = _open_linked_pair(tmp_path / "linked-grouped")
        terminal = _open_anonymous_pair(tmp_path / "private-terminal-2")
        second = ctypes.c_void_p()
        try:
            assert native_library.plamen_native_operation4_context_create_for_testing_v1(
                os.getuid(),
                case.root_fd,
                case.python_fd,
                case.transform_fd,
                case.verifier_fd,
                *grouped,
                *terminal,
                ctypes.byref(case.policy),
                ctypes.byref(second),
            ) == -1
            assert not second.value
            assert ctypes.get_errno() == errno.EINVAL
        finally:
            for descriptor in grouped + terminal:
                os.close(descriptor)

    _with_case(tmp_path, native_library, exercise)


def test_terminal_output_rejoin_rejects_post_hash_mutation(native_library, tmp_path):
    def exercise(case: Operation4Case) -> None:
        result, terminal_fd = case.invoke()
        assert result == 0, ctypes.get_errno()
        assert os.pwrite(case.output_fds[0], b"X", 0) == 1
        identities = (FDIdentity * OUTPUT_COUNT)()
        for index, descriptor in enumerate(case.output_fds):
            os.fchmod(descriptor, 0o400)
            identities[index] = _fd_identity(descriptor)
        assert native_library.plamen_native_operation4_rejoin_terminal_outputs_fixed_v1(
            case.context, terminal_fd, identities
        ) == -1
        assert ctypes.get_errno() == errno.ESTALE

    _with_case(tmp_path, native_library, exercise)


def test_terminal_output_rejoin_accepts_exact_final_census(native_library, tmp_path):
    def exercise(case: Operation4Case) -> None:
        result, terminal_fd = case.invoke()
        assert result == 0, ctypes.get_errno()
        identities = (FDIdentity * OUTPUT_COUNT)()
        for index, descriptor in enumerate(case.output_fds):
            os.fchmod(descriptor, 0o400)
            identities[index] = _fd_identity(descriptor)
        assert native_library.plamen_native_operation4_rejoin_terminal_outputs_fixed_v1(
            case.context, terminal_fd, identities
        ) == 0, ctypes.get_errno()

    _with_case(tmp_path, native_library, exercise)


def test_all_role_semantic_prefixes_are_canonical_json_without_lf(
    native_library, tmp_path
):
    def exercise(case: Operation4Case) -> None:
        assert len(case.semantic_receipts) == ROLE_COUNT
        for raw in case.semantic_receipts:
            assert raw.endswith(b"}")
            assert b"\n" not in raw and b"\r" not in raw
            assert raw == _canonical(json.loads(raw))

    _with_case(tmp_path, native_library, exercise)


@pytest.mark.parametrize("attack", ["wrong_verifier", "tampered_signature"])
def test_real_operation4_rejects_dynamic_receipt_authentication(
    native_library, tmp_path, attack
):
    options = {
        "verifier_mismatch": attack == "wrong_verifier",
        "mutate_signature": attack == "tampered_signature",
    }

    def exercise(case: Operation4Case) -> None:
        result, terminal_fd = case.invoke()
        assert result == -1
        assert terminal_fd == -1
        assert ctypes.get_errno() == errno.EIO

    _with_case(tmp_path, native_library, exercise, **options)


def test_path_substitution_is_rejected_by_runtime_closure_rejoin(native_library, tmp_path):
    def exercise(case: Operation4Case) -> None:
        replacement = case.paths["validator"].with_suffix(".replacement")
        replacement.write_text("def validate_all(*args, **kwargs): return None\n")
        os.replace(replacement, case.paths["validator"])
        result, terminal_fd = case.invoke()
        assert result == -1
        assert terminal_fd == -1
        assert ctypes.get_errno() in (errno.ESTALE, errno.EIO)

    _with_case(tmp_path, native_library, exercise)


def test_retained_validator_vnode_mutation_is_rejected(native_library, tmp_path):
    def exercise(case: Operation4Case) -> None:
        validator_path = case.paths["validator"]
        original_size = validator_path.stat().st_size
        prefix = b"def validate_all(*args, **kwargs):\n    return None\n#"
        malicious = prefix + b"x" * (original_size - len(prefix))
        assert len(malicious) == original_size
        with validator_path.open("r+b", buffering=0) as stream:
            stream.write(malicious)
            stream.flush()
            os.fsync(stream.fileno())
        result, terminal_fd = case.invoke()
        assert result == -1
        assert terminal_fd == -1
        assert ctypes.get_errno() in (errno.ESTALE, errno.EIO)

    _with_case(tmp_path, native_library, exercise)


def test_suspended_python_mapping_mismatch_is_rejected(native_library, tmp_path):
    repo = Path(__file__).resolve().parents[1]
    python_fd = os.open(
        repo / ".venv-dev/bin/python3.12", os.O_RDONLY | os.O_CLOEXEC
    )
    wrong_identity_fd = _open_linked_readonly(
        tmp_path / "not-the-python-executable", b"not the retained Python image\n"
    )
    try:
        result = native_library.plamen_native_operation4_attest_python_for_testing_v1(
            python_fd, wrong_identity_fd
        )
        assert result < 0
        assert ctypes.get_errno() == errno.ESTALE
    finally:
        os.close(wrong_identity_fd)
        os.close(python_fd)
