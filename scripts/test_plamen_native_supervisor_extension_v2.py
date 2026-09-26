"""Adversarial gates for the isolated CPython broker-v2 boundary.

The issuer in this file's target is deliberately TEST_ONLY.  It generates the
session ID and HMAC key in C, signs and queues a complete two-frame transcript,
and returns only an opaque consumer.  It is not a production bootstrap.
"""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import gc
import hashlib
import hmac
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pickle
import re
import shutil
import stat
import subprocess
import sys
import threading
from types import MethodDescriptorType, ModuleType
from typing import Any, Iterator

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_posix_native_supervisor.py"
SHARED_ABI = REPO_ROOT / "native" / "include" / "plamen_broker_v2.h"
EXTENSION_SOURCE = REPO_ROOT / "native" / "cpython" / "_plamen_native_supervisor.c"
PRODUCTION_MODULE = "_plamen_native_supervisor"
TEST_MODULE = "_plamen_native_supervisor_testonly"
FINGERPRINT = "fa9d6c7ecb3fe1795f42119865cc24f23e702d3fb91401a21720f1776b067a37"
ATTEMPT = "attempt-1"
REQUEST_PROJECTION_SHA256 = (
    "8041df45ffa5e711921c9d30f742334b65e36f668bf8a004e31e26ab3f870f92"
)


def _build(root: Path, variant: str) -> dict[str, Any]:
    completed = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--output-root",
            str(root),
            "--test-only" if variant == "test" else "--test-production-shape",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return json.loads(completed.stdout)


def _load_exact(path: str, name: str) -> ModuleType:
    sys.modules.pop(name, None)
    loader = importlib.machinery.ExtensionFileLoader(name, path)
    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _clear_test_tree_immutable_flags(root: Path) -> None:
    """Clear only UF_IMMUTABLE below one exact, pytest-owned root."""

    if sys.platform != "darwin" or not root.is_absolute():
        return
    immutable = getattr(stat, "UF_IMMUTABLE", 0)
    if not immutable or not hasattr(os, "chflags"):
        return
    try:
        root_info = root.lstat()
        exact_root = Path(os.path.abspath(os.fspath(root)))
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != os.geteuid()
            or root.resolve(strict=True) != exact_root
        ):
            return
    except OSError:
        return

    def clear(path: Path) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
            return
        flags = int(getattr(info, "st_flags", 0))
        if flags & immutable:
            os.chflags(path, flags & ~immutable, follow_symlinks=False)

    # A flagged directory must be cleared before walking its descendants.
    clear(root)
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        clear(parent)
        for name in (*names, *files):
            clear(parent / name)


@pytest.fixture(scope="session")
def v2_builds(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, dict[str, Any]]]:
    results: dict[str, dict[str, Any]] = {}
    roots: list[Path] = []
    try:
        for variant in ("production", "test"):
            root = tmp_path_factory.mktemp(
                f"native-supervisor-v2-{variant}"
            ).resolve(strict=True)
            roots.append(root)
            root.chmod(0o700)
            results[variant] = _build(root, variant)
        yield results
    finally:
        for root in roots:
            _clear_test_tree_immutable_flags(root)


def test_cleanup_clears_only_owned_exact_root_immutable_flags(tmp_path: Path) -> None:
    if sys.platform != "darwin":
        pytest.skip("Darwin immutable flag regression")
    immutable = getattr(stat, "UF_IMMUTABLE", 0)
    preserved = getattr(stat, "UF_HIDDEN", 0)
    if not immutable or not preserved or not hasattr(os, "chflags"):
        pytest.skip("Darwin user flags unavailable")

    root = (tmp_path / "exact-owned-root").resolve()
    root.mkdir(mode=0o700)
    artifact = root / "artifact"
    artifact.write_bytes(b"immutable-v2-test-artifact")
    alias = tmp_path / "root-alias"
    alias.symlink_to(root, target_is_directory=True)
    try:
        os.chflags(artifact, immutable | preserved)

        _clear_test_tree_immutable_flags(alias)
        assert artifact.stat().st_flags & immutable

        _clear_test_tree_immutable_flags(root)
        remaining = artifact.stat().st_flags
        assert not remaining & immutable
        assert remaining & preserved
        shutil.rmtree(root)
        assert not root.exists()
    finally:
        alias.unlink(missing_ok=True)
        if artifact.exists():
            os.chflags(artifact, 0, follow_symlinks=False)
        shutil.rmtree(root, ignore_errors=True)


def test_v2_builds_scrubs_registered_root_when_setup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform != "darwin":
        pytest.skip("Darwin immutable flag regression")
    immutable = getattr(stat, "UF_IMMUTABLE", 0)
    if not immutable or not hasattr(os, "chflags"):
        pytest.skip("Darwin immutable flags unavailable")

    artifact: Path | None = None

    class TempPathFactory:
        def mktemp(self, name: str) -> Path:
            root = tmp_path / name
            root.mkdir(mode=0o700)
            return root

    def build(root: Path, variant: str) -> dict[str, Any]:
        nonlocal artifact
        if variant == "test":
            raise RuntimeError("second build failed")
        build_root = root / ("a" * 64)
        build_root.mkdir(mode=0o700)
        artifact = build_root / "artifact"
        artifact.write_bytes(b"partial-v2-fixture-artifact")
        artifact.chmod(0o500)
        os.chflags(artifact, immutable, follow_symlinks=False)
        return {"artifact_path": str(artifact)}

    monkeypatch.setattr(sys.modules[__name__], "_build", build)
    fixture = v2_builds.__wrapped__(TempPathFactory())
    try:
        with pytest.raises(RuntimeError, match="second build failed"):
            next(fixture)
        assert artifact is not None
        assert not artifact.stat().st_flags & immutable
    finally:
        if artifact is not None and artifact.exists():
            os.chflags(artifact, 0, follow_symlinks=False)


@pytest.fixture(scope="session")
def v2_module(v2_builds: dict[str, dict[str, Any]]) -> ModuleType:
    return _load_exact(v2_builds["test"]["artifact_path"], TEST_MODULE)


def _issue(module: ModuleType, mutation: str = "none", **kwargs: int) -> object:
    return module.TEST_ONLY_issue_broker_v2(
        FINGERPRINT, ATTEMPT, mutation=mutation, **kwargs
    )


def test_red_broker_v2_abi_constant_equality(v2_module: ModuleType) -> None:
    header = SHARED_ABI.read_text(encoding="ascii")

    def macro(name: str) -> int:
        matched = re.search(rf"^#define {re.escape(name)} ([0-9]+)U$", header, re.MULTILINE)
        assert matched is not None, name
        return int(matched.group(1))

    assert v2_module.BROKER_V2_ABI_SCHEMA == "plamen.native-broker.v2"
    assert (
        v2_module.APPLE_FUZZ_SERVICE_ABI_SCHEMA
        == "plamen.apple-fuzz-service-admission.v1"
    )
    assert v2_module.BROKER_V2_PROTOCOL_VERSION == macro("PLAMEN_BROKER_V2_VERSION") == 2
    assert v2_module.BROKER_V2_FRAME_HEADER_SIZE == macro("PLAMEN_BROKER_V2_HEADER_SIZE") == 196
    assert v2_module.BROKER_V2_AUTH_OFFSET == macro("PLAMEN_BROKER_V2_AUTH_OFFSET") == 164
    assert v2_module.BROKER_V2_MAX_FRAME_PAYLOAD_BYTES == macro("PLAMEN_BROKER_V2_MAX_PAYLOAD") == 2_097_152
    assert v2_module.BROKER_V2_MAX_SCM_RIGHTS_FDS == macro("PLAMEN_BROKER_V2_MAX_FDS") == 16
    assert v2_module.BROKER_V2_SERVICE_ABI_VERSION == macro("PLAMEN_BROKER_V2_SERVICE_ABI_VERSION") == 2
    assert v2_module.BROKER_V2_SERVICE_HEADER_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE") == 124
    assert v2_module.BROKER_V2_SERVICE_MAX_PAYLOAD_BYTES == macro("PLAMEN_BROKER_V2_SERVICE_MAX_PAYLOAD") == 4096
    assert v2_module.BROKER_V2_SERVICE_MAX_FDS == macro("PLAMEN_BROKER_V2_SERVICE_MAX_FDS") == 15
    assert v2_module.BROKER_V2_SERVICE_READINESS_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE") == 96
    assert v2_module.BROKER_V2_SERVICE_READY_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_READY_SIZE") == 204
    assert v2_module.BROKER_V2_SERVICE_REGISTRATION_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE") == 1_488
    assert v2_module.BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE") == 210
    assert v2_module.BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE") == 96
    assert v2_module.BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE") == 954
    assert v2_module.BROKER_V2_SERVICE_SESSION_OPEN_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE") == 410
    assert v2_module.BROKER_V2_SERVICE_SESSION_ACK_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_SESSION_ACK_SIZE") == 164
    assert v2_module.BROKER_V2_SERVICE_ERROR_SIZE == macro("PLAMEN_BROKER_V2_SERVICE_ERROR_SIZE") == 40
    assert v2_module.BROKER_V2_REQUEST_PROJECTION_MAX_BYTES == macro("PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX") == 1_048_576
    assert v2_module.BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE == macro("PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE") == 392
    assert v2_module.BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE == macro("PLAMEN_BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE") == 104
    assert "PLAMEN_BROKER_V2_HELLO = 0x0001" in header
    assert "PLAMEN_BROKER_V2_AUTH_CONSUME = 0x0002" in header
    assert "PLAMEN_BROKER_V2_AUTH_ACCEPTED = 0x0003" in header


def test_specialized_bridge_abi_is_static_module_owned_and_unforgeable(
    v2_module: ModuleType,
) -> None:
    type_names = (
        "JSDependencyMaterializerAuthority",
        "JSDependencyMaterializerSessionLease",
        "JSDependencyMaterializerExecutionLease",
        "JSDependencyMaterializerTerminalReplayLease",
        "ManagedEVMToolchainInitialAuthority",
        "ManagedEVMToolchainProvisionLease",
        "ManagedEVMToolchainProvisionTerminal",
        "EVMAnalysisProjectionAuthority",
        "DarwinToolCustodyAuthority",
        "DarwinToolExecutionLease",
        "DarwinToolExecutionTerminal",
        "AppleFuzzServiceSessionAuthority",
        "AppleFuzzAdmissionContinuationLease",
        "AppleFuzzLifecycleTerminal",
    )
    function_names = (
        "authenticate_js_dependency_materializer_capability",
        "js_dependency_materializer_runtime_identity",
        "prepare_js_dependency_materializer_execution",
        "execute_js_dependency_materializer",
        "replay_js_dependency_materializer_terminal",
        "managed_evm_toolchain_runtime_identity",
        "prepare_managed_evm_toolchain_provision",
        "execute_managed_evm_toolchain_provision",
        "project_managed_evm_toolchain_terminal",
        "recover_evm_analysis_projection_authority",
        "commit_evm_analysis_projection",
        "project_evm_analysis_projection_receipt",
        "darwin_tool_runtime_identity",
        "acquire_darwin_tool_custody",
        "prepare_darwin_tool_execution",
        "project_darwin_fuzz_campaign_prepared",
        "execute_darwin_fuzz_campaign",
        "execute_darwin_tool",
        "project_darwin_tool_execution_terminal",
        "acquire_apple_fuzz_service_session",
        "admit_apple_fuzz_campaign",
        "project_apple_fuzz_secure_receipt",
        "execute_admitted_apple_fuzz_campaign",
        "project_admitted_apple_fuzz_terminal",
        "native_specialized_bridge_status",
    )
    for name in type_names:
        native_type = getattr(v2_module, name)
        assert type(native_type) is type
        assert native_type.__module__ == TEST_MODULE
        assert native_type.__flags__ & (1 << 8)
        assert not native_type.__flags__ & (1 << 9)
        assert not native_type.__flags__ & (1 << 10)
        for operation in (
            lambda t=native_type: t(),
            lambda t=native_type: object.__new__(t),
            lambda t=native_type: type("Forged", (t,), {}),
        ):
            with pytest.raises(TypeError):
                operation()
    for name in function_names:
        function = getattr(v2_module, name)
        assert type(function) is type(len)
        assert function.__module__ == TEST_MODULE
        assert function.__name__ == name
        assert function.__self__ is v2_module
    status = json.loads(v2_module.native_specialized_bridge_status())
    assert status == {
        "evm_analysis_projection": "PROVIDER_UNAVAILABLE",
        "js_dependency_materializer": "PROVIDER_UNAVAILABLE",
        "managed_evm_toolchain": "PROVIDER_UNAVAILABLE",
        "schema": "plamen.native-specialized-bridge-status.v1",
        "snapshot_bound_tools": "PROVIDER_UNAVAILABLE",
    }
    assert not hasattr(v2_module, "MANAGED_EVM_TOOLCHAIN_INITIAL_AUTHORITY")
    with pytest.raises(RuntimeError, match="native bridge capability is invalid"):
        v2_module.project_darwin_tool_execution_terminal(
            b'{"schema":"plamen.snapshot-bound-tool-execution-terminal.v3"}'
        )


def test_test_only_bridge_cannot_synthesize_apple_fuzz_authority(
    v2_module: ModuleType,
) -> None:
    guest_initial = _issue(v2_module, "guest_role")
    with pytest.raises(
        RuntimeError,
        match="TEST_ONLY cannot issue production Apple fuzz service authority",
    ):
        v2_module.acquire_apple_fuzz_service_session(guest_initial)
    outer_initial = _issue(v2_module)
    with pytest.raises(RuntimeError, match="requires guest-driver authority"):
        v2_module.acquire_apple_fuzz_service_session(outer_initial)


def test_apple_fuzz_service_acquisition_is_darwin_only() -> None:
    source = EXTENSION_SOURCE.read_text(encoding="ascii")
    body = source[source.index("acquire_apple_fuzz_service_session(") :]
    body = body[: body.index("\n}\n")]
    assert (
        "#if defined(__APPLE__) && "
        "!defined(PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY)"
    ) in body
    assert "Apple fuzz service is unavailable on this platform" in body


def test_specialized_bridge_leases_retain_fds_burn_and_hardstop(
    v2_module: ModuleType, tmp_path: Path,
) -> None:
    initial = _issue(v2_module)
    js_authority, managed_authority = (
        v2_module.TEST_ONLY_issue_specialized_bridge_authorities(initial)
    )
    assert type(js_authority) is v2_module.JSDependencyMaterializerAuthority
    assert type(managed_authority) is v2_module.ManagedEVMToolchainInitialAuthority
    for capability in (js_authority, managed_authority):
        with pytest.raises(TypeError):
            copy.copy(capability)
        with pytest.raises(TypeError):
            pickle.dumps(capability)

    session = v2_module.authenticate_js_dependency_materializer_capability(
        js_authority, b'{"schema":"admission"}'
    )
    with pytest.raises(RuntimeError, match="consumed"):
        v2_module.authenticate_js_dependency_materializer_capability(
            js_authority, b'{"schema":"admission"}'
        )
    roots = [tmp_path / name for name in ("source", "scratch", "state")]
    for root in roots:
        root.mkdir()
    archive_root = tmp_path / "archive-root"
    archive_root.mkdir()
    fds = [os.open(root, os.O_RDONLY) for root in roots]
    archive_root_fd = os.open(archive_root, os.O_RDONLY)
    try:
        oversized_initial = _issue(v2_module)
        oversized_authority, _unused_managed = (
            v2_module.TEST_ONLY_issue_specialized_bridge_authorities(
                oversized_initial
            )
        )
        oversized_session = (
            v2_module.authenticate_js_dependency_materializer_capability(
                oversized_authority, b'{"schema":"admission"}'
            )
        )
        with pytest.raises(TypeError):
            v2_module.prepare_js_dependency_materializer_execution(
                oversized_authority, oversized_session,
                b'{"schema":"request"}\n', *fds,
                (("legacy-archive", archive_root_fd),),
            )
        lease = v2_module.prepare_js_dependency_materializer_execution(
            js_authority, session, b'{"schema":"request"}\n',
            *fds, archive_root_fd
        )
        assert type(lease) is v2_module.JSDependencyMaterializerExecutionLease
        with pytest.raises(RuntimeError, match="provider hook is unavailable"):
            v2_module.execute_js_dependency_materializer(
                js_authority, session, lease
            )
        with pytest.raises(RuntimeError, match="consumed"):
            v2_module.execute_js_dependency_materializer(
                js_authority, session, lease
            )
        with pytest.raises(RuntimeError, match="replay provider hook is unavailable"):
            v2_module.replay_js_dependency_materializer_terminal(
                js_authority, session, b'{"schema":"request"}\n',
                b'{"schema":"terminal"}\n', *fds,
                archive_root_fd
            )
    finally:
        for fd in (*fds, archive_root_fd):
            os.close(fd)

    managed_identity = json.loads(
        v2_module.managed_evm_toolchain_runtime_identity(managed_authority)
    )
    assert managed_identity["schema"] == (
        "plamen.managed-evm-toolchain-runtime-identity.v1"
    )
    assert managed_identity["platform"] == (
        "MACOS" if sys.platform == "darwin" else "LINUX"
    )
    assert managed_identity["extension_sha256"] == hashlib.sha256(
        Path(v2_module.__file__).read_bytes()
    ).hexdigest()
    policy = tmp_path / "managed-policy.json"
    project = tmp_path / "managed-project"
    cache = tmp_path / "managed-cache"
    generations = tmp_path / "managed-generations"
    acquisition = tmp_path / "managed-acquisition.json"
    policy.write_bytes(b'{"schema":"policy"}')
    acquisition.write_bytes(b'{"schema":"acquisition"}')
    project.mkdir()
    cache.mkdir()
    generations.mkdir()
    managed_fds = (
        os.open(policy, os.O_RDONLY),
        os.open(project, os.O_RDONLY),
        os.open(cache, os.O_RDONLY),
        os.open(generations, os.O_RDONLY),
        os.open(acquisition, os.O_RDONLY),
    )
    try:
        managed_lease = v2_module.prepare_managed_evm_toolchain_provision(
            managed_authority, b'{"schema":"plan"}', *managed_fds
        )
        assert type(managed_lease) is v2_module.ManagedEVMToolchainProvisionLease
        with pytest.raises(RuntimeError, match="provider hook is unavailable"):
            v2_module.execute_managed_evm_toolchain_provision(managed_lease)
        with pytest.raises(RuntimeError, match="consumed"):
            v2_module.execute_managed_evm_toolchain_provision(managed_lease)
    finally:
        for fd in managed_fds:
            os.close(fd)

    with pytest.raises(RuntimeError, match="durable recovery provider hook"):
        v2_module.recover_evm_analysis_projection_authority("a" * 64)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        v2_module.recover_evm_analysis_projection_authority("A" * 64)


def test_snapshot_tool_bridge_retains_disjoint_descriptors_and_hardstops(
    v2_module: ModuleType, tmp_path: Path,
) -> None:
    initial = _issue(v2_module, "guest_role")
    runtime_identity = json.loads(v2_module.darwin_tool_runtime_identity(initial))
    assert runtime_identity["schema"] == "plamen.darwin-tool-runtime-identity.v1"
    assert runtime_identity["platform"] == (
        "MACOS" if sys.platform == "darwin" else "LINUX"
    )
    assert runtime_identity["extension_sha256"] == hashlib.sha256(
        Path(v2_module.__file__).read_bytes()
    ).hexdigest()
    custody = v2_module.acquire_darwin_tool_custody(initial)
    assert type(custody) is v2_module.DarwinToolCustodyAuthority
    guest_bundle = initial.consume_once(FINGERPRINT, ATTEMPT)
    assert type(guest_bundle) is v2_module.TEST_ONLY_GuestDriverAuthorities
    guest_members = guest_bundle.consume_once()
    assert len(guest_members) == 1
    assert type(guest_members[0]) is v2_module.TEST_ONLY_BackendExecutionAuthority
    source = tmp_path / "source"
    scratch = tmp_path / "scratch"
    state = tmp_path / "state"
    project = tmp_path / "project"
    source.write_bytes(b"source")
    scratch.mkdir()
    state.mkdir()
    project.mkdir()
    source_fd = os.open(source, os.O_RDONLY)
    scratch_fd = os.open(scratch, os.O_RDONLY)
    state_fd = os.open(state, os.O_RDONLY)
    project_fd = os.open(project, os.O_RDONLY)
    try:
        lease = v2_module.prepare_darwin_tool_execution(
            custody, b'{"schema":"plamen.snapshot-bound-tool-execution-request.v3"}',
            source_fd, scratch_fd, state_fd, project_fd,
        )
        assert type(lease) is v2_module.DarwinToolExecutionLease
        with pytest.raises(RuntimeError, match="provider hook is unavailable"):
            v2_module.execute_darwin_tool(custody, lease)
        with pytest.raises(RuntimeError, match="consumed"):
            v2_module.execute_darwin_tool(custody, lease)
    finally:
        os.close(project_fd)
        os.close(state_fd)
        os.close(scratch_fd)
        os.close(source_fd)


def test_outer_supervisor_initial_cannot_acquire_guest_tool_custody(
    v2_module: ModuleType,
) -> None:
    initial = _issue(v2_module)
    with pytest.raises(RuntimeError, match="guest-driver initial authority"):
        v2_module.acquire_darwin_tool_custody(initial)
    # A rejected cross-role request must not burn the outer authority.
    bundle = initial.consume_once(FINGERPRINT, ATTEMPT)
    assert type(bundle) is v2_module.TEST_ONLY_SupervisorAuthorities


def test_runtime_identity_canonically_escapes_non_ascii_extension_path(
    v2_builds: dict[str, dict[str, Any]], tmp_path: Path,
) -> None:
    unicode_root = tmp_path / "nativé"
    unicode_root.mkdir()
    source = Path(v2_builds["test"]["artifact_path"])
    copied = unicode_root / source.name
    shutil.copyfile(source, copied)
    copied.chmod(0o500)
    module = _load_exact(str(copied), TEST_MODULE)
    initial = _issue(module)
    raw = module.darwin_tool_runtime_identity(initial)
    assert raw == json.dumps(
        json.loads(raw), ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("ascii")
    assert json.loads(raw)["extension_path"] == str(copied)


def test_public_crypto_kat_independently_matches_sha256_and_hmac(
    v2_module: ModuleType,
) -> None:
    sha, tag = v2_module.TEST_ONLY_broker_v2_crypto_kat()
    first = b"broker-v2-public-kat-header"
    second = b"broker-v2-public-kat-payload"
    header = first + b"\0" * (196 - len(first))
    assert sha == hashlib.sha256(first + second).digest()
    assert tag == hmac.digest(bytes(range(32)), header[:164] + second, "sha256")


def test_production_bootstrap_and_rpc_deadlines_are_native_fixed() -> None:
    source = EXTENSION_SOURCE.read_text(encoding="ascii")
    assert re.search(
        r"v2_platform_take_initial_session\s*\([^)]*\)\s*\{\s*"
        r"\(void\)session;\s*return 0;\s*\}",
        source,
        re.DOTALL,
    ) is None
    for required in (
        '#include "../darwin/plamen_broker_v2_install_receipt.h"',
        "plamen_install_receipt_decode_exact",
        "plamen_install_receipt_open_member",
        "plamen_install_receipt_member_revalidate",
        "xpc_connection_set_peer_code_signing_requirement",
        "PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP",
        "PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE",
        "PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN",
        "PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED",
        "plamen_broker_v2_service_session_ack_matches_open",
        "plamen_broker_v2_derive_rpc_operation_key",
        "Py_BEGIN_ALLOW_THREADS",
    ):
        assert required in source
    assert "PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS INT64_C(60000)" in source
    assert "PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS INT64_C(1800000)" in source
    assert "PLAMEN_V2_OPERATION_WAIT_DEADLINE_MS INT64_C(259500000)" in source
    assert re.search(
        r'v2_provider_wait_driver, "wait_driver"[\s\S]*?'
        r'PLAMEN_V2_OPERATION_WAIT_DEADLINE_MS\)', source,
    )
    assert re.search(
        r'v2_backend_execution_wait_or_recover,[\s\S]*?'
        r'PLAMEN_V2_OPERATION_WAIT_DEADLINE_MS\)', source,
    )
    for method in (
        "v2_backend_execution_start_or_recover",
        "v2_backend_execution_wait_or_recover",
        "v2_backend_execution_read_output_or_recover",
        "v2_backend_execution_extinguish_or_recover",
        "v2_recovery_recover",
    ):
        match = re.search(rf"PLAMEN_V2_RPC_WRAPPER\({method},[\s\S]*?\)\n", source)
        assert match is not None
        assert "PLAMEN_BROKER_V2_OPERATION_RECOVER" in match.group(0)


def test_production_rpc_never_accepts_python_transport_authority() -> None:
    source = EXTENSION_SOURCE.read_text(encoding="ascii")
    body = source[source.rindex("v2_operation_rpc(PyObject *object") :]
    body = body[: body.index("#endif /* !PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY */")]
    assert "PyBytes_CheckExact(payload_object)" in body
    assert "payload[payload_size - 1] != '\\n'" in source
    assert "value == 0 || value > 0x7fU" in source
    assert "self->member_capability_id" in body
    assert "received.fd_count != 0" in body
    for forbidden in (
        "PyObject_GetAttr", "PyMapping", "PyDict", "PyLong_AsLong",
        "PyCapsule", "fileno", "getenv",
    ):
        assert forbidden not in body


def test_production_is_static_and_hardstopped_before_initial_authority(
    v2_builds: dict[str, dict[str, Any]],
) -> None:
    artifact = v2_builds["production"]["artifact_path"]
    probe = r'''
import importlib.machinery, importlib.util, sys, types
path = sys.argv[1]
name = "_plamen_native_supervisor"
loader = importlib.machinery.ExtensionFileLoader(name, path)
spec = importlib.util.spec_from_file_location(name, path, loader=loader)
module = importlib.util.module_from_spec(spec); loader.exec_module(module)
assert module.TEST_ONLY_BUILD is False
assert module.BROKER_V2_PROTOCOL_VERSION == 2
assert module.BROKER_V2_FRAME_HEADER_SIZE == 196
assert module.BROKER_V2_PRODUCTION_ACQUISITION == "HARD_STOP_NO_AUTHENTICATED_NATIVE_SERVICE_SESSION"
assert module.BROKER_V2_OPERATION_DISPATCH == "AUTHENTICATED_CANONICAL_BYTES_RPC"
assert module.BROKER_V2_INITIAL_AUTHORITY_AVAILABLE is False
assert not hasattr(module, "INITIAL_AUTHORITY")
assert module.NativeAuthorityConsumer is module.BrokerV2AuthorityConsumer
for forbidden in ("TEST_ONLY_issue_broker_v2", "issue_broker_v2", "create_consumer",
                  "acquire", "factory", "registry", "session_key", "socket_fd"):
    assert not hasattr(module, forbidden)
for name in ("BrokerV2AuthorityConsumer", "SupervisorAuthorities",
             "GuestDriverAuthorities", "BackendExecutionAuthority",
             "RuntimeImageAuthority", "WorkspaceAuthority", "BackendContextAuthority",
             "ProviderAuthority", "GuestAdmissionAuthority", "ExtinctionAuthority",
             "ArtifactAuthority", "ExportAuthority", "JournalAuthority", "RecoveryAuthority",
             "SupervisorAuthority", "ProcessReceiptProjection", "ExitReceiptProjection",
             "NetworkReceiptProjection"):
    native_type = getattr(module, name)
    assert type(native_type) is type
    assert native_type.__module__ == module.__name__
    assert native_type.__flags__ & (1 << 9) == 0
    assert native_type.__flags__ & (1 << 10) == 0
    for operation in (lambda: native_type(), lambda: object.__new__(native_type),
                      lambda: type("Subclass", (native_type,), {})):
        try: operation()
        except TypeError: pass
        else: raise AssertionError(name + " became constructible")
required_descriptors = {
    "RuntimeImageAuthority": ("authenticate",),
    "WorkspaceAuthority": ("admit_target", "revalidate_target", "prepare_layout",
                             "resume_layout", "write_guest_config", "recensus_layout"),
    "BackendContextAuthority": ("authenticate",),
    "ProviderAuthority": ("provider_kind", "create_stopped", "inspect_stopped",
                          "resume_guest", "start_driver", "wait_driver", "delete_guest"),
    "GuestAdmissionAuthority": ("admit_stopped_guest", "resume_admission"),
    "ExtinctionAuthority": ("extinguish",),
    "ArtifactAuthority": ("census",),
    "ExportAuthority": ("export",),
    "JournalAuthority": ("open", "arm", "commit", "resolve", "finish"),
    "RecoveryAuthority": ("recover",),
    "BackendExecutionAuthority": (
        "prepare", "start_or_recover", "wait_or_recover",
        "read_output_or_recover", "extinguish_or_recover", "close_operation",
    ),
}
for type_name, method_names in required_descriptors.items():
    assert "consume_once" not in getattr(module, type_name).__dict__
    for method_name in method_names:
        assert isinstance(getattr(module, type_name).__dict__[method_name],
                          types.MethodDescriptorType)
consumer_namespace = module.NativeAuthorityConsumer.__dict__
assert isinstance(consumer_namespace["request_projection"],
                  types.MethodDescriptorType)
'''
    completed = subprocess.run(
        [sys.executable, "-I", "-c", probe, artifact],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_absent_native_bootstrap_never_mints_on_repeat_module_initialization(
    v2_builds: dict[str, dict[str, Any]],
) -> None:
    artifact = v2_builds["production"]["artifact_path"]
    probe = r'''
import importlib.machinery, importlib.util, sys
path = sys.argv[1]
name = "_plamen_native_supervisor"
def load():
    loader = importlib.machinery.ExtensionFileLoader(name, path)
    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module
first = load()
second = load()
for module in (first, second):
    assert module.BROKER_V2_INITIAL_AUTHORITY_AVAILABLE is False
    assert module.BROKER_V2_PRODUCTION_ACQUISITION == "HARD_STOP_NO_AUTHENTICATED_NATIVE_SERVICE_SESSION"
    assert "INITIAL_AUTHORITY" not in vars(module)
    assert not any(callable(value) and name.lower() in {"acquire", "mint", "factory"}
                   for name, value in vars(module).items())
'''
    completed = subprocess.run(
        [sys.executable, "-I", "-c", probe, artifact],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_authenticated_session_returns_exact_one_shot_static_bundle(
    v2_module: ModuleType,
) -> None:
    consumer = _issue(v2_module)
    assert type(consumer) is v2_module.TEST_ONLY_BrokerV2AuthorityConsumer
    projection = consumer.request_projection()
    assert hashlib.sha256(projection).hexdigest() == REQUEST_PROJECTION_SHA256
    assert consumer.request_projection() == projection
    bundle = consumer.consume_once(FINGERPRINT, ATTEMPT)
    assert type(bundle) is v2_module.TEST_ONLY_SupervisorAuthorities
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.request_projection()
    members = bundle.consume_once()
    expected = (
        v2_module.TEST_ONLY_RuntimeImageAuthority,
        v2_module.TEST_ONLY_WorkspaceAuthority,
        v2_module.TEST_ONLY_BackendContextAuthority,
        v2_module.TEST_ONLY_ProviderAuthority,
        v2_module.TEST_ONLY_GuestAdmissionAuthority,
        v2_module.TEST_ONLY_ExtinctionAuthority,
        v2_module.TEST_ONLY_ArtifactAuthority,
        v2_module.TEST_ONLY_ExportAuthority,
        v2_module.TEST_ONLY_JournalAuthority,
        v2_module.TEST_ONLY_RecoveryAuthority,
    )
    assert tuple(type(item) for item in members) == expected
    assert tuple(item.consume_once() for item in members) == (
        "RUNTIME", "WORKSPACE", "BACKEND", "PROVIDER", "GUEST_ADMISSION",
        "EXTINCTION", "ARTIFACTS", "EXPORTER", "JOURNAL", "RECOVERY",
    )
    for item in members:
        with pytest.raises(RuntimeError, match="already consumed"):
            item.consume_once()
    with pytest.raises(RuntimeError, match="already consumed"):
        bundle.consume_once()


def test_wrong_native_initial_role_burns_before_protocol_io(v2_module: ModuleType) -> None:
    consumer = _issue(v2_module, "wrong_role")
    with pytest.raises(RuntimeError, match="role mismatch"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)


@pytest.mark.parametrize(
    "mutation",
    (
        "projection_bad_tag", "projection_bad_payload",
        "projection_binding_sha", "projection_binding_size",
        "projection_sequence", "projection_previous", "projection_session",
        "projection_nonce", "projection_fd", "projection_truncated",
        "projection_semantic_invalid",
    ),
)
def test_request_projection_is_authenticated_bounded_and_burns_on_failure(
    v2_module: ModuleType, mutation: str,
) -> None:
    consumer = _issue(v2_module, mutation)
    with pytest.raises(RuntimeError, match="request projection is invalid"):
        consumer.request_projection()
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.request_projection()
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)


def test_authenticated_guest_session_returns_only_backend_execution_authority(
    v2_module: ModuleType,
) -> None:
    consumer = _issue(v2_module, "guest_role")
    bundle = consumer.consume_once(FINGERPRINT, ATTEMPT)
    assert type(bundle) is v2_module.TEST_ONLY_GuestDriverAuthorities
    members = bundle.consume_once()
    assert len(members) == 1
    assert type(members[0]) is v2_module.TEST_ONLY_BackendExecutionAuthority
    assert members[0].consume_once() == "BACKEND_EXECUTION"
    with pytest.raises(RuntimeError, match="already consumed"):
        members[0].consume_once()
    with pytest.raises(RuntimeError, match="already consumed"):
        bundle.consume_once()


def test_member_retains_native_session_after_consumer_and_bundle_are_gone(
    v2_module: ModuleType,
) -> None:
    consumer = _issue(v2_module)
    bundle = consumer.consume_once(FINGERPRINT, ATTEMPT)
    del consumer
    gc.collect()
    runtime = bundle.consume_once()[0]
    del bundle
    gc.collect()
    assert runtime.consume_once() == "RUNTIME"


def test_all_zero_request_digest_cannot_mint_test_authority(
    v2_module: ModuleType,
) -> None:
    with pytest.raises(RuntimeError, match="construction failed"):
        v2_module.TEST_ONLY_issue_broker_v2("0" * 64, ATTEMPT)


def test_guest_backend_execution_descriptors_are_exact_arity_hardstops(
    v2_module: ModuleType,
) -> None:
    authority = (
        _issue(v2_module, "guest_role")
        .consume_once(FINGERPRINT, ATTEMPT)
        .consume_once()[0]
    )
    names = (
        "prepare", "start_or_recover", "wait_or_recover",
        "read_output_or_recover", "extinguish_or_recover", "close_operation",
    )
    for name in names:
        descriptor = type(authority).__dict__[name]
        assert type(descriptor) is MethodDescriptorType
        with pytest.raises(TypeError, match="requires exactly 1"):
            descriptor(authority)
        with pytest.raises(RuntimeError, match="schema is not frozen"):
            descriptor(authority, b"{}")
        with pytest.raises(TypeError, match="requires exactly 1"):
            descriptor(authority, b"{}", b"{}")
    assert "close" not in type(authority).__dict__
    assert "arm_binding" not in type(authority).__dict__


def test_supervisor_operation_descriptors_are_exact_arity_native_hardstops(
    v2_module: ModuleType,
) -> None:
    consumer = _issue(v2_module)
    members = consumer.consume_once(FINGERPRINT, ATTEMPT).consume_once()
    expected = (
        (members[0], {"authenticate": 1}),
        (members[1], {
            "admit_target": 1, "revalidate_target": 1, "prepare_layout": 1,
            "resume_layout": 1, "write_guest_config": 1,
            "recensus_layout": 1,
        }),
        (members[2], {"authenticate": 1}),
        (members[3], {
            "provider_kind": 1, "create_stopped": 1, "inspect_stopped": 1,
            "resume_guest": 1, "start_driver": 1, "wait_driver": 1,
            "delete_guest": 1,
        }),
        (members[4], {"admit_stopped_guest": 1, "resume_admission": 1}),
        (members[5], {"extinguish": 1}),
        (members[6], {"census": 1}),
        (members[7], {"export": 1}),
        (members[8], {
            "open": 1, "arm": 1, "commit": 1, "resolve": 1, "finish": 1,
        }),
        (members[9], {"recover": 1}),
    )
    sentinel = object()
    for authority, operations in expected:
        for name, arity in operations.items():
            assert isinstance(type(authority).__dict__[name], MethodDescriptorType)
            operation = getattr(authority, name)
            with pytest.raises(TypeError, match=rf"{name} requires exactly {arity}"):
                operation(*([sentinel] * (arity + 1)))
            with pytest.raises(
                RuntimeError,
                match="authenticated schema is not frozen",
            ):
                operation(*([sentinel] * arity))
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)


@pytest.mark.parametrize(
    "mutation",
    (
        "hello_bad_tag", "bad_magic", "bad_version", "bad_flags",
        "bad_header_size", "bad_payload_size", "bad_payload_digest", "bad_tag",
        "sequence_gap", "sequence_rollback", "bad_previous", "wrong_session",
        "cross_nonce", "trailing", "truncated", "replay",
    ),
)
def test_bad_header_payload_tag_sequence_and_replay_burn_once(
    v2_module: ModuleType, mutation: str,
) -> None:
    consumer = _issue(v2_module, mutation)
    with pytest.raises(RuntimeError, match="broker v2 session is invalid"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)


@pytest.mark.parametrize("mutation", ("fd_missing", "fd_surplus", "fd_alias", "hello_fd"))
def test_scm_rights_count_alias_and_hello_roster_are_exact(
    v2_module: ModuleType, mutation: str,
) -> None:
    consumer = _issue(v2_module, mutation)
    with pytest.raises(RuntimeError, match="broker v2 session is invalid"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)


def test_unconnected_unix_stream_cannot_back_a_native_session(
    v2_module: ModuleType,
) -> None:
    with pytest.raises(RuntimeError, match="construction failed"):
        _issue(v2_module, "unconnected_control_socket")


@pytest.mark.parametrize(
    "mutation",
    (
        "accepted_binding_role", "accepted_binding_registration",
        "accepted_binding_checkpoint", "accepted_binding_sha",
        "accepted_member_count", "accepted_member_duplicate",
        "accepted_member_zero",
    ),
)
def test_authenticated_accepted_bundle_binding_mismatch_burns_once(
    v2_module: ModuleType, mutation: str,
) -> None:
    consumer = _issue(v2_module, mutation)
    with pytest.raises(RuntimeError, match="broker v2 session is invalid"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)


@pytest.mark.parametrize(
    ("fingerprint", "attempt", "error"),
    (
        ("f" * 64, ATTEMPT, RuntimeError),
        (FINGERPRINT, "attempt-broker-v2-002", RuntimeError),
        (FINGERPRINT.upper(), ATTEMPT, ValueError),
        (bytes.fromhex(FINGERPRINT), ATTEMPT, ValueError),
        (123, ATTEMPT, ValueError),
    ),
)
def test_wrong_binding_burns_before_protocol_io(
    v2_module: ModuleType, fingerprint: object, attempt: object,
    error: type[BaseException],
) -> None:
    consumer = _issue(v2_module)
    with pytest.raises(error) as failure:
        consumer.consume_once(fingerprint, attempt)
    assert FINGERPRINT not in str(failure.value)
    assert ATTEMPT not in str(failure.value)
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)


def test_session_key_socket_fd_and_tokens_never_become_python_visible(
    v2_module: ModuleType,
) -> None:
    consumer = _issue(v2_module)
    forbidden_fragments = ("key", "secret", "socket", "fileno", "token", "session", "nonce", "fd")
    assert not hasattr(consumer, "__dict__")
    assert not any(fragment in name.lower() for name in dir(consumer) for fragment in forbidden_fragments)
    assert repr(consumer) == "<plamen native capability: opaque>"
    for operation in (
        lambda: copy.copy(consumer),
        lambda: copy.deepcopy(consumer),
        lambda: pickle.dumps(consumer),
        lambda: consumer.__reduce__(),
        lambda: consumer.__reduce_ex__(5),
    ):
        with pytest.raises(TypeError, match="cannot be copied or serialized"):
            operation()
    bundle = consumer.consume_once(FINGERPRINT, ATTEMPT)
    members = bundle.consume_once()
    for item in (bundle, *members):
        assert not hasattr(item, "__dict__")
        assert repr(item) == "<plamen native capability: opaque>"
        for operation in (
            lambda item=item: copy.copy(item),
            lambda item=item: copy.deepcopy(item),
            lambda item=item: pickle.dumps(item),
            lambda item=item: item.__reduce__(),
            lambda item=item: item.__reduce_ex__(5),
        ):
            with pytest.raises(TypeError, match="cannot be copied or serialized"):
                operation()


def test_constructor_subclass_and_test_only_namespace_are_sealed(v2_module: ModuleType) -> None:
    type_names = (
        "TEST_ONLY_BrokerV2AuthorityConsumer", "TEST_ONLY_SupervisorAuthorities",
        "TEST_ONLY_GuestDriverAuthorities", "TEST_ONLY_BackendExecutionAuthority",
        "TEST_ONLY_RuntimeImageAuthority", "TEST_ONLY_WorkspaceAuthority",
        "TEST_ONLY_BackendContextAuthority", "TEST_ONLY_ProviderAuthority",
        "TEST_ONLY_GuestAdmissionAuthority", "TEST_ONLY_ExtinctionAuthority",
        "TEST_ONLY_ArtifactAuthority", "TEST_ONLY_ExportAuthority",
        "TEST_ONLY_JournalAuthority", "TEST_ONLY_RecoveryAuthority",
        "TEST_ONLY_SupervisorAuthority",
        "TEST_ONLY_ProcessReceiptProjection", "TEST_ONLY_ExitReceiptProjection",
        "TEST_ONLY_NetworkReceiptProjection",
    )
    for name in type_names:
        native_type = getattr(v2_module, name)
        assert native_type.__module__ == TEST_MODULE
        assert native_type.__flags__ & (1 << 9) == 0
        assert native_type.__flags__ & (1 << 10) == 0
        for operation in (
            lambda native_type=native_type: native_type(),
            lambda native_type=native_type: object.__new__(native_type),
            lambda native_type=native_type: type("Subclass", (native_type,), {}),
        ):
            with pytest.raises(TypeError):
                operation()


def test_two_threads_observe_one_initial_and_member_consumption(v2_module: ModuleType) -> None:
    consumer = _issue(v2_module)
    barrier = threading.Barrier(3)

    def consume_initial() -> tuple[str, object]:
        barrier.wait()
        try:
            return "ok", consumer.consume_once(FINGERPRINT, ATTEMPT)
        except BaseException as exc:
            return "error", exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(consume_initial) for _ in range(2)]
        barrier.wait()
        outcomes = [future.result(timeout=5) for future in futures]
    success = [item for status, item in outcomes if status == "ok"]
    errors = [item for status, item in outcomes if status == "error"]
    assert len(success) == len(errors) == 1
    assert isinstance(errors[0], RuntimeError) and "already consumed" in str(errors[0])

    provider = success[0].consume_once()[3]
    barrier = threading.Barrier(3)

    def consume_member() -> tuple[str, object]:
        barrier.wait()
        try:
            return "ok", provider.consume_once()
        except BaseException as exc:
            return "error", exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(consume_member) for _ in range(2)]
        barrier.wait()
        outcomes = [future.result(timeout=5) for future in futures]
    assert [item for status, item in outcomes if status == "ok"] == ["PROVIDER"]
    errors = [item for status, item in outcomes if status == "error"]
    assert len(errors) == 1 and "already consumed" in str(errors[0])


def test_wrong_pid_and_actual_fork_burn_child_copy_only(v2_module: ModuleType) -> None:
    wrong = _issue(v2_module, creator_pid_override=os.getpid() + 1_000_000)
    with pytest.raises(RuntimeError, match="process boundary"):
        wrong.consume_once(FINGERPRINT, ATTEMPT)
    with pytest.raises(RuntimeError, match="already consumed"):
        wrong.consume_once(FINGERPRINT, ATTEMPT)

    if not hasattr(os, "fork"):
        pytest.skip("fork unavailable")
    consumer = _issue(v2_module)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - status crosses a pipe
        try:
            os.close(read_fd)
            try:
                consumer.consume_once(FINGERPRINT, ATTEMPT)
            except RuntimeError as exc:
                valid = "process boundary" in str(exc)
            else:
                valid = False
            os.write(write_fd, b"OK" if valid else b"BAD")
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 3) == b"OK"
        waited, status = os.waitpid(child, 0)
        assert waited == child and os.waitstatus_to_exitcode(status) == 0
        assert type(consumer.consume_once(FINGERPRINT, ATTEMPT)) is v2_module.TEST_ONLY_SupervisorAuthorities
    finally:
        os.close(read_fd)


def test_wrong_interpreter_binding_burns_once(v2_module: ModuleType) -> None:
    consumer = _issue(v2_module, creator_interpreter_id_override=1 << 62)
    with pytest.raises(RuntimeError, match="interpreter boundary"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)
    with pytest.raises(RuntimeError, match="already consumed"):
        consumer.consume_once(FINGERPRINT, ATTEMPT)
    try:
        import _interpreters
    except ImportError:
        return
    assert _interpreters.is_shareable(consumer) is False


def test_v2_extension_loads_in_subinterpreter_and_wrong_binding_burns(
    v2_builds: dict[str, dict[str, Any]],
) -> None:
    try:
        import _interpreters as interpreters
    except ImportError:
        pytest.skip("subinterpreter execution API unavailable")
    artifact = v2_builds["test"]["artifact_path"]
    code = f'''
import importlib.machinery, importlib.util
name = {TEST_MODULE!r}; path = {artifact!r}
loader = importlib.machinery.ExtensionFileLoader(name, path)
spec = importlib.util.spec_from_file_location(name, path, loader=loader)
module = importlib.util.module_from_spec(spec); loader.exec_module(module)
consumer = module.TEST_ONLY_issue_broker_v2(
    {FINGERPRINT!r}, {ATTEMPT!r}, creator_interpreter_id_override=(1 << 62)
)
try:
    consumer.consume_once({FINGERPRINT!r}, {ATTEMPT!r})
except RuntimeError as exc:
    assert "interpreter boundary" in str(exc)
    try: consumer.consume_once({FINGERPRINT!r}, {ATTEMPT!r})
    except RuntimeError as replay: assert "already consumed" in str(replay)
    else: raise AssertionError("wrong-interpreter consumer replayed")
else:
    raise AssertionError("wrong-interpreter consumer was accepted")
'''
    interpreter = interpreters.create()
    try:
        interpreters.exec(interpreter, code)
    finally:
        interpreters.destroy(interpreter)


def test_test_only_artifact_cannot_cross_production_module(
    v2_builds: dict[str, dict[str, Any]],
) -> None:
    with pytest.raises(ImportError, match="module export function"):
        _load_exact(v2_builds["test"]["artifact_path"], PRODUCTION_MODULE)
    with pytest.raises(ImportError, match="module export function"):
        _load_exact(v2_builds["production"]["artifact_path"], TEST_MODULE)
