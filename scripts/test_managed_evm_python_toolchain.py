"""P0 tests for the sealed CPython 3.12 EVM analysis toolchain."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

import managed_evm_python_toolchain as M


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "verification_policy" / "managed_evm_python_toolchain.v1.json"


@pytest.fixture(scope="session")
def policy_and_sha() -> tuple[dict[str, object], str]:
    return M.load_policy(POLICY_PATH)


def _managed_python_candidate() -> Path:
    configured = os.environ.get("PLAMEN_MANAGED_PYTHON")
    candidates = [
        Path(configured) if configured else Path("/__not_configured__"),
        Path.home() / ".local/share/plamen/runtime/py312/bin/python",
        Path(sys.executable),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            M.probe_interpreter(candidate)
        except M.ToolchainError:
            continue
        return candidate
    pytest.skip("a provisioned CPython >=3.12.1,<3.13 probe is not available")


def _acquisition_receipt(tmp_path: Path) -> Path:
    path = tmp_path / "signed-acquisition-receipt.json"
    path.write_bytes(
        b'{"receipt_sha256":"9999999999999999999999999999999999999999999999999999999999999999","schema":"plamen.test-acquisition-terminal.v1"}'
    )
    return path


def test_policy_is_canonical_complete_exact_and_cross_platform(
    policy_and_sha: tuple[dict[str, object], str],
) -> None:
    policy, digest = policy_and_sha
    assert digest == hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest()
    assert policy["roots"] == ["slither-analyzer==0.11.5", "solc-select==1.2.0"]
    targets = {row["id"]: row for row in policy["targets"]}
    assert {name: len(row["distributions"]) for name, row in targets.items()} == {
        "macos-arm64": 47,
        "linux-x86_64": 47,
        "windows-amd64": 48,
    }
    assert any(
        row["name"] == "pywin32"
        for row in targets["windows-amd64"]["distributions"]
    )
    for target in targets.values():
        assert target["compiler"]["long_version"] == "0.8.26+commit.8a97fa7a"
        assert target["compiler"]["source_url"].startswith(
            "https://binaries.soliditylang.org/"
        )
        for row in target["distributions"]:
            assert row["requirement"] == f"{row['name']}=={row['version']}"
            assert row["filename"].endswith(".whl")
            assert row["source_url"].startswith("https://files.pythonhosted.org/packages/")


def test_managed_policy_is_a_literal_runtime_asset() -> None:
    assert M.PLAMEN_RUNTIME_ASSETS == ({
        "kind": "control",
        "mode": "file",
        "path": "verification_policy/managed_evm_python_toolchain.v1.json",
    },)
    assert POLICY_PATH.is_file()


def test_production_entry_derives_policy_addressed_generation_and_threads_bundle(
    policy_and_sha: tuple[dict[str, object], str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed = tmp_path / "managed-evm"
    cache = managed / "cache"
    generations = managed / "generations"
    cache.mkdir(parents=True, mode=0o700)
    generations.mkdir(mode=0o700)
    managed.chmod(0o700)
    cache.chmod(0o700)
    generations.chmod(0o700)
    project = tmp_path / "project"
    project.mkdir()
    acquisition = _acquisition_receipt(tmp_path)
    runtime = object()
    observed: dict[str, object] = {}
    issued = object()

    def fake_provision(policy, python, generation, cache_root, **kwargs):
        observed.update({
            "policy": policy,
            "python": python,
            "generation": Path(generation),
            "cache": Path(cache_root),
            **kwargs,
        })
        Path(generation).mkdir()
        return object()

    monkeypatch.setattr(M, "provision", fake_provision)
    monkeypatch.setattr(
        M, "issue_managed_evm_generation_authority",
        lambda policy, generation: (
            issued
            if Path(policy) == POLICY_PATH
            and Path(generation) == generations / policy_and_sha[1]
            else None
        ),
    )
    result = M.provision_managed_evm_generation_authority(
        POLICY_PATH,
        "/unused/host-python",
        managed,
        acquisition_receipt_path=acquisition,
        project_root=project,
        native_interpreter_probe=_linux_guest_probe(),
        guest_execution_authority=_apple_guest_authority(),
        native_runtime_authority=runtime,
    )
    assert result is issued
    assert observed["generation"] == generations / policy_and_sha[1]
    assert observed["cache"] == cache
    assert observed["native_runtime_authority"] is runtime


def test_floated_transitive_requirement_is_rejected(
    policy_and_sha: tuple[dict[str, object], str],
) -> None:
    policy = copy.deepcopy(policy_and_sha[0])
    row = policy["targets"][0]["distributions"][0]
    row["requirement"] = f"{row['name']}>={row['version']}"
    with pytest.raises(M.ToolchainError, match="floated"):
        M.validate_policy(policy)


def test_missing_transitive_row_and_unreachable_row_are_rejected(
    policy_and_sha: tuple[dict[str, object], str],
) -> None:
    missing = copy.deepcopy(policy_and_sha[0])
    rows = missing["targets"][0]["distributions"]
    referenced = next(dep for row in rows for dep in row["dependencies"])
    rows[:] = [row for row in rows if row["name"] != referenced]
    with pytest.raises(M.ToolchainError, match="incomplete|missing root"):
        M.validate_policy(missing)

    unreachable = copy.deepcopy(policy_and_sha[0])
    victim = next(
        row
        for row in unreachable["targets"][0]["distributions"]
        if row["name"] not in {"slither-analyzer", "solc-select"}
    )
    for row in unreachable["targets"][0]["distributions"]:
        row["dependencies"] = [dep for dep in row["dependencies"] if dep != victim["name"]]
    with pytest.raises(M.ToolchainError, match="unreachable"):
        M.validate_policy(unreachable)


def test_python_314_and_python_3120_are_rejected() -> None:
    base = {
        "implementation": "CPython",
        "version": "3.14.0",
        "version_info": [3, 14, 0],
        "executable": "/managed/python",
        "prefix": "/managed",
        "base_prefix": "/managed/base",
        "sys_platform": "darwin",
        "machine": "arm64",
        "purelib": "/managed/lib",
        "platlib": "/managed/lib",
    }
    with pytest.raises(M.ToolchainError, match="3.14 is forbidden"):
        M.validate_interpreter_probe(base)
    base["version"] = "3.12.0"
    base["version_info"] = [3, 12, 0]
    with pytest.raises(M.ToolchainError, match="3.12.1"):
        M.validate_interpreter_probe(base)


def test_platform_mismatch_is_explicit_unsupported_debt() -> None:
    with pytest.raises(M.ToolchainError, match="UNSUPPORTED_DEBT"):
        M.detect_target(sys_platform="linux", machine="aarch64")
    assert M.detect_target(sys_platform="darwin", machine="aarch64") == "macos-arm64"
    assert M.detect_target(sys_platform="win32", machine="amd64") == "windows-amd64"


def test_partial_cache_and_hash_mismatch_fail_closed(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    policy = policy_and_sha[0]
    cache = tmp_path / "cache"
    cache.mkdir()
    with pytest.raises(M.ToolchainError, match="partial cache"):
        M.validate_cache(policy, "macos-arm64", cache)

    target = M.select_target(policy, "macos-arm64")
    first = target["distributions"][0]
    artifact = cache / "macos-arm64" / first["filename"]
    artifact.parent.mkdir()
    artifact.write_bytes(b"forged-wheel")
    with pytest.raises(M.ToolchainError, match="hash/size mismatch"):
        M.validate_cache(policy, "macos-arm64", cache)
    with pytest.raises(M.ToolchainError, match="not the locked object"):
        M.acquire_cache(policy, "macos-arm64", cache, offline=True)


class _FakeDownload:
    def __init__(self, url: str, data: bytes):
        self._url = url
        self._data = data
        self._offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self) -> str:
        return self._url

    def read(self, size: int) -> bytes:
        value = self._data[self._offset : self._offset + size]
        self._offset += len(value)
        return value


def test_download_hash_mismatch_never_publishes_partial(tmp_path: Path) -> None:
    url = "https://files.pythonhosted.org/packages/a/example.whl"
    destination = tmp_path / "example.whl"

    def opener(request, *, timeout):
        assert request.full_url == url
        assert timeout == 60
        return _FakeDownload(url, b"wrong")

    with pytest.raises(M.ToolchainError, match="hash/size mismatch"):
        M._download_one(url, destination, "0" * 64, 5, opener=opener)
    assert not destination.exists()
    assert not list(tmp_path.glob("*.partial"))


def test_managed_cpython312_probe_and_dry_plan_make_no_writes(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    python = _managed_python_candidate()
    probe = M.probe_interpreter(python)
    assert probe["implementation"] == "CPython"
    assert probe["version_info"][:2] == [3, 12]
    policy_sha = policy_and_sha[1]
    generation = tmp_path / "toolchains" / "generations" / policy_sha
    cache = tmp_path / "cache"
    result = M.provision(
        POLICY_PATH,
        python,
        generation,
        cache,
        acquisition_receipt_path=_acquisition_receipt(tmp_path),
        dry_run=True,
    )
    assert result["status"] == "DRY_RUN_READY"
    assert result["compiler"] == "0.8.26+commit.8a97fa7a"
    assert not generation.exists()
    assert not cache.exists()


def test_target_project_paths_are_never_writable_destinations(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    python = _managed_python_candidate()
    project = tmp_path / "project"
    project.mkdir()
    generation = project / "generations" / policy_and_sha[1]
    cache = tmp_path / "cache"
    before = sorted(project.iterdir())
    with pytest.raises(M.ToolchainError, match="outside and disjoint"):
        M.provision(
            POLICY_PATH,
            python,
            generation,
            cache,
            acquisition_receipt_path=_acquisition_receipt(tmp_path),
            project_root=project,
            dry_run=True,
        )
    assert sorted(project.iterdir()) == before


def test_pip_install_is_isolated_offline_hash_required_and_wheel_only() -> None:
    source = inspect.getsource(M.bootstrap_provision_test_only)
    for token in (
        '"--isolated"',
        '"--no-index"',
        'f"--find-links={cache_target}"',
        '"--require-hashes"',
        '"--only-binary=:all:"',
        '"--no-deps"',
        '"--no-compile"',
    ):
        assert token in source
    env_source = inspect.getsource(M._clean_env)
    assert 'startswith("PIP_")' in env_source
    assert '"PIP_CONFIG_FILE": os.devnull' in env_source


def test_optional_real_provision_replay_and_tamper_rejection(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    cache_value = os.environ.get("PLAMEN_EVM_TOOLCHAIN_CACHE")
    if not cache_value:
        pytest.skip("set PLAMEN_EVM_TOOLCHAIN_CACHE for the sealed integration test")
    python = _managed_python_candidate()
    project = tmp_path / "project"
    project.mkdir()
    generation = tmp_path / "generations" / policy_and_sha[1]
    first = M.bootstrap_provision_test_only(
        POLICY_PATH,
        python,
        generation,
        cache_value,
        project_root=project,
        offline=True,
        confirm_test_only=True,
    )
    second = M.bootstrap_provision_test_only(
        POLICY_PATH,
        python,
        generation,
        cache_value,
        project_root=project,
        offline=True,
        confirm_test_only=True,
    )
    assert first == second
    assert first["provided_tool_ids"] == ["slither", "solc"]
    interpreter = Path(first["interpreter"]["absolute_path"])
    bindir = interpreter.parent
    slither = bindir / ("slither.exe" if first["target_id"] == "windows-amd64" else "slither")
    slither_probe = subprocess.run(
        [str(slither), "--version"], check=True, capture_output=True, text=True
    )
    assert "0.11.5" in slither_probe.stdout
    metadata_probe = subprocess.run(
        [
            str(interpreter),
            "-I",
            "-B",
            "-c",
            'import importlib.metadata as m; print(m.version("solc-select"))',
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert metadata_probe.stdout.strip() == "1.2.0"
    solc = Path(first["solc"]["absolute_path"])
    solc_probe = subprocess.run(
        [str(solc), "--version"], check=True, capture_output=True, text=True
    )
    assert "0.8.26+commit.8a97fa7a" in solc_probe.stdout
    for path in generation.rglob("*"):
        info = path.lstat()
        assert not stat.S_ISLNK(info.st_mode)
        if stat.S_ISREG(info.st_mode):
            assert info.st_nlink == 1
        assert not (info.st_mode & 0o022)
    solc.chmod(0o755)
    original = solc.read_bytes()
    solc.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    solc.chmod(0o555)
    with pytest.raises(M.ToolchainError, match="solc identity"):
        M.bootstrap_provision_test_only(
            POLICY_PATH,
            python,
            generation,
            cache_value,
            project_root=project,
            offline=True,
            confirm_test_only=True,
        )


def test_production_without_native_capability_fails_before_mutation(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    generation = tmp_path / "generations" / policy_and_sha[1]
    cache = tmp_path / "cache"
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(M.ToolchainError, match="required before mutation"):
        M.provision(
            POLICY_PATH,
            _managed_python_candidate(),
            generation,
            cache,
            acquisition_receipt_path=_acquisition_receipt(tmp_path),
            project_root=project,
        )
    assert not generation.exists()
    assert not cache.exists()


def _linux_guest_probe() -> dict[str, object]:
    return {
        "implementation": "CPython",
        "version": "3.12.12",
        "version_info": [3, 12, 12],
        "executable": "/.plamen/toolchains/evm/venv/bin/python3.12",
        "prefix": "/.plamen/toolchains/evm/venv",
        "base_prefix": "/usr/local",
        "sys_platform": "linux",
        "machine": "x86_64",
        "purelib": "/.plamen/toolchains/evm/venv/lib/python3.12/site-packages",
        "platlib": "/.plamen/toolchains/evm/venv/lib/python3.12/site-packages",
    }


def _apple_guest_authority() -> dict[str, object]:
    return {
        "schema": M.APPLE_GUEST_CUSTODY_SCHEMA,
        "platform": "linux",
        "architecture": "amd64",
        "runtime_image_reference": "registry.example/plamen/debian@sha256:" + "1" * 64,
        "image_closure_sha256": "2" * 64,
        "provider_admission_sha256": "3" * 64,
        "rosetta_required": True,
        "rosetta_authority_sha256": "4" * 64,
        "rootfs_readonly": True,
        "network_policy": "DENY_ALL",
        "network_isolation_authority_sha256": "5" * 64,
        "custody_receipt_sha256": "6" * 64,
        "immutable_launch_authority": "PRIVATE_IMMUTABLE_PROJECTED_CLOSURE",
        "population_zero_authority": True,
    }


def _native_guest_managed_runtime_module(
    tmp_path: Path,
    authority: object,
    *,
    managed_python_size: object = 123456,
) -> tuple[types.ModuleType, dict[str, object], dict[str, object]]:
    extension = tmp_path / "plamen_native_supervisor.so"
    extension.write_bytes(b"native-extension")
    identity: dict[str, object] = {
        "schema": "plamen.managed-evm-toolchain-runtime-identity.v1",
        "platform": "MACOS",
        "extension_path": str(extension),
        "extension_sha256": hashlib.sha256(b"native-extension").hexdigest(),
        "extension_byte_count": len(b"native-extension"),
        "native_deployment_receipt_sha256": "1" * 64,
        "runtime_closure_sha256": "2" * 64,
        "broker_peer_identity_sha256": "3" * 64,
        "managed_toolchain_custody_sha256": "4" * 64,
        "guest_execution_authority": _apple_guest_authority(),
        "managed_python_sha256": "5" * 64,
        "managed_python_size": managed_python_size,
        "native_interpreter_probe": _linux_guest_probe(),
    }
    identity_raw = M._canonical_bytes(identity)
    bootstrap: dict[str, object] = {
        "schema": "plamen.native-guest-managed-evm-bootstrap-inputs.v1",
        "guest_execution_authority": identity["guest_execution_authority"],
        "managed_python_sha256": identity["managed_python_sha256"],
        "managed_python_size": identity["managed_python_size"],
        "managed_runtime_identity_sha256": hashlib.sha256(identity_raw).hexdigest(),
        "native_interpreter_probe": identity["native_interpreter_probe"],
    }
    runtime = types.ModuleType("posix_backend_execution")

    def runtime_identity(value: object) -> bytes:
        assert value is authority
        return identity_raw

    def bootstrap_inputs(value: object) -> bytes:
        assert value is authority
        return M._canonical_bytes(bootstrap)

    runtime.native_guest_managed_evm_runtime_identity = runtime_identity
    runtime.native_guest_managed_evm_bootstrap_inputs = bootstrap_inputs
    runtime.prepare_native_guest_managed_evm_provision = lambda *_args: object()
    runtime.execute_native_guest_managed_evm_provision = lambda *_args: object()
    runtime.project_native_guest_managed_evm_terminal = lambda *_args: b"{}"
    return runtime, identity, bootstrap


def test_opaque_native_guest_bridge_binds_exact_bootstrap_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = object()
    runtime, identity, bootstrap = _native_guest_managed_runtime_module(
        tmp_path, authority
    )
    monkeypatch.setattr(M.sys, "platform", "darwin")
    monkeypatch.setitem(sys.modules, "posix_backend_execution", runtime)
    observed_runtime, functions, binding = M._native_guest_managed_bridge(
        authority
    )
    assert observed_runtime is runtime
    assert len(functions) == 5
    assert binding == {"identity": identity, "bootstrap": bootstrap}


@pytest.mark.parametrize("invalid_size", [True, 0, -1, "123456"])
def test_opaque_native_guest_bridge_rejects_invalid_managed_python_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_size: object,
) -> None:
    authority = object()
    runtime, _identity, _bootstrap = _native_guest_managed_runtime_module(
        tmp_path, authority, managed_python_size=invalid_size
    )
    monkeypatch.setattr(M.sys, "platform", "darwin")
    monkeypatch.setitem(sys.modules, "posix_backend_execution", runtime)
    with pytest.raises(
        M.NativeToolchainUnavailable,
        match="opaque native guest managed-EVM provision authority",
    ):
        M._native_guest_managed_bridge(authority)


def test_native_plan_binds_linux_amd64_rosetta_guest_and_all_artifacts(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    generation = tmp_path / "generations" / policy_and_sha[1]
    project = tmp_path / "project"
    project.mkdir()
    plan = M.build_native_provision_plan(
        POLICY_PATH,
        _linux_guest_probe(),
        generation,
        tmp_path / "cache",
        acquisition_receipt_path=_acquisition_receipt(tmp_path),
        project_root=project,
        guest_execution_authority=_apple_guest_authority(),
    )
    assert plan["target_id"] == "linux-x86_64"
    assert plan["guest_execution_authority"]["rosetta_required"] is True
    assert plan["guest_execution_authority"]["network_policy"] == "DENY_ALL"
    assert len(plan["artifacts"]) == 48  # 47 wheels + exact solc 0.8.26
    assert plan["plan_sha256"] == hashlib.sha256(
        M._canonical_bytes({k: v for k, v in plan.items() if k != "plan_sha256"})
    ).hexdigest()


def test_native_plan_rejects_unattested_rosetta_without_mutation(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    guest = _apple_guest_authority()
    guest["rosetta_required"] = False
    generation = tmp_path / "generations" / policy_and_sha[1]
    cache = tmp_path / "cache"
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(M.ToolchainError, match="Linux/Rosetta"):
        M.build_native_provision_plan(
            POLICY_PATH,
            _linux_guest_probe(),
            generation,
            cache,
            acquisition_receipt_path=_acquisition_receipt(tmp_path),
            project_root=project,
            guest_execution_authority=guest,
        )
    assert not generation.exists()
    assert not cache.exists()


def _native_result(plan: dict[str, object], **overrides) -> dict[str, object]:
    artifact_fold = plan["artifact_set_sha256"]
    value = {
        "schema": M.NATIVE_RESULT_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "guest_execution_authority_sha256": plan["guest_execution_authority_sha256"],
        "native_capability_receipt_sha256": "7" * 64,
        "network_authority_receipt_sha256": "8" * 64,
        "acquisition_terminal_receipt_sha256": plan["acquisition_receipt_sha256"],
        "materialization_terminal_receipt_sha256": "a" * 64,
        "solc_probe_terminal_receipt_sha256": "b" * 64,
        "pypi_metadata_graph_terminal_receipt_sha256": "1" * 64,
        "snapshot_bound_materialization_receipt_sha256": "c" * 64,
        "source_provenance_sha256": "d" * 64,
        "pre_replay_sha256": artifact_fold,
        "post_replay_sha256": artifact_fold,
        "provider_receipt_sha256": "e" * 64,
        "provider_receipt_file_sha256": "f" * 64,
        "generation_payload_manifest_sha256": "0" * 64,
        "complete": True,
    }
    value.update(overrides)
    value["result_sha256"] = hashlib.sha256(M._canonical_bytes(value)).hexdigest()
    return value


def test_native_result_requires_every_terminal_receipt_and_exact_prepost_replay(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    plan = M.build_native_provision_plan(
        POLICY_PATH,
        _linux_guest_probe(),
        tmp_path / "generations" / policy_and_sha[1],
        tmp_path / "cache",
        acquisition_receipt_path=_acquisition_receipt(tmp_path),
        project_root=project,
        guest_execution_authority=_apple_guest_authority(),
    )
    missing = _native_result(plan)
    missing.pop("solc_probe_terminal_receipt_sha256")
    missing.pop("result_sha256")
    missing["result_sha256"] = hashlib.sha256(M._canonical_bytes(missing)).hexdigest()
    with pytest.raises(M.ToolchainError, match="keys differ"):
        M.validate_native_provision_result(plan, missing)

    forged = _native_result(plan, pre_replay_sha256="1" * 64)
    with pytest.raises(M.ToolchainError, match="pre/post artifact replay"):
        M.validate_native_provision_result(plan, forged)


def test_direct_bootstrap_requires_explicit_test_only_acknowledgment(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    generation = tmp_path / "generations" / policy_and_sha[1]
    cache = tmp_path / "cache"
    with pytest.raises(M.ToolchainError, match="TEST_ONLY"):
        M.bootstrap_provision_test_only(
            POLICY_PATH,
            _managed_python_candidate(),
            generation,
            cache,
        )
    assert not generation.exists()
    assert not cache.exists()


def test_policy_dependency_graph_is_bound_to_reviewed_digest(
    policy_and_sha: tuple[dict[str, object], str],
) -> None:
    forged = copy.deepcopy(policy_and_sha[0])
    rows = forged["targets"][0]["distributions"]
    names = [row["name"] for row in rows]
    for row in rows:
        row["dependencies"] = []
    root = next(row for row in rows if row["name"] == "slither-analyzer")
    root["dependencies"] = sorted(
        name for name in names if name not in {"slither-analyzer", "solc-select"}
    )
    with pytest.raises(M.ToolchainError, match="reviewed digest anchor"):
        M.validate_policy(forged)


def _metadata(name: str, version: str, *requirements: str) -> bytes:
    lines = ["Metadata-Version: 2.2", f"Name: {name}", f"Version: {version}"]
    lines.extend(f"Requires-Dist: {requirement}" for requirement in requirements)
    return ("\n".join(lines) + "\n\n").encode("ascii")


def test_requires_dist_graph_derives_markers_extras_and_target_edges() -> None:
    metadata = {
        "slither-analyzer": _metadata(
            "slither-analyzer",
            "0.11.5",
            'eth-hash[pycryptodome]>=0.8; python_version >= "3.12"',
            'async-timeout>=4; python_version < "3.11"',
        ),
        "solc-select": _metadata("solc-select", "1.2.0"),
        "eth-hash": _metadata(
            "eth-hash",
            "0.8.0",
            'pycryptodome>=3.6; extra == "pycryptodome"',
        ),
        "pycryptodome": _metadata("pycryptodome", "3.23.0"),
    }
    assert M._derive_metadata_dependency_graph("linux-x86_64", metadata) == {
        "eth-hash": ["pycryptodome"],
        "pycryptodome": [],
        "slither-analyzer": ["eth-hash"],
        "solc-select": [],
    }


def _minimal_record_generation(root: Path) -> dict[str, object]:
    site = root / "venv/lib/python3.12/site-packages"
    distributions = []
    for canonical, display, version in (
        ("slither-analyzer", "slither-analyzer", "0.11.5"),
        ("solc-select", "solc-select", "1.2.0"),
    ):
        dist_info = site / f"{canonical.replace('-', '_')}-{version}.dist-info"
        dist_info.mkdir(parents=True)
        metadata = _metadata(display, version)
        metadata_path = dist_info / "METADATA"
        module_path = site / f"{canonical.replace('-', '_')}.py"
        record_path = dist_info / "RECORD"
        metadata_path.write_bytes(metadata)
        module_path.write_text("VALUE = 1\n", encoding="ascii")
        record_path.write_text(
            "\n".join(
                (
                    f"{dist_info.name}/METADATA,,",
                    f"{dist_info.name}/RECORD,,",
                    f"{module_path.name},,",
                    "",
                )
            ),
            encoding="ascii",
        )
        distributions.append(
            {
                "name": canonical,
                "version": version,
                "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "dependencies": [],
            }
        )
    return {"id": "linux-x86_64", "distributions": distributions}


def test_unowned_sitecustomize_is_rejected_independent_of_tree_rehash(
    tmp_path: Path,
) -> None:
    generation = tmp_path / "generation"
    target = _minimal_record_generation(generation)
    installed, _fold = M._record_closure(generation, target, None)
    assert [row["name"] for row in installed] == ["slither-analyzer", "solc-select"]
    sitecustomize = generation / "venv/lib/python3.12/site-packages/sitecustomize.py"
    sitecustomize.write_text("raise SystemExit('executed')\n", encoding="ascii")
    with pytest.raises(M.ToolchainError, match="startup path is forbidden"):
        M._record_closure(generation, target, None)


def test_tree_manifest_commits_empty_directory_topology(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "payload").write_bytes(b"payload")
    before = M._ordinary_tree_manifest(root)
    (root / "empty").mkdir()
    after = M._ordinary_tree_manifest(root)
    assert after[0] == before[0] + 1
    assert after[1] != before[1]


def test_caller_callable_cannot_upgrade_test_only_generation(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    generation = tmp_path / "generations" / policy_and_sha[1]
    cache = tmp_path / "cache"
    invoked = False

    def forged_executor(_plan):
        nonlocal invoked
        invoked = True
        return {}

    with pytest.raises(M.ToolchainError, match="caller-supplied native executors"):
        M.provision(
            POLICY_PATH,
            _managed_python_candidate(),
            generation,
            cache,
            acquisition_receipt_path=_acquisition_receipt(tmp_path),
            project_root=project,
            native_executor=forged_executor,
            native_interpreter_probe=_linux_guest_probe(),
            guest_execution_authority=_apple_guest_authority(),
        )
    assert invoked is False
    assert not generation.exists()
    assert not cache.exists()


def test_ordinary_python_module_cannot_forge_native_toolchain_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = type(sys)(M.NATIVE_BRIDGE_MODULE)
    fake.BROKER_V2_ABI_SCHEMA = M.NATIVE_BRIDGE_ABI
    fake.BROKER_V2_PRODUCTION_ACQUISITION = "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
    fake.TEST_ONLY_BUILD = False
    fake.BROKER_V2_INITIAL_AUTHORITY_AVAILABLE = True
    monkeypatch.setitem(sys.modules, M.NATIVE_BRIDGE_MODULE, fake)
    with pytest.raises(M.NativeToolchainUnavailable, match="authenticated native"):
        M._native_toolchain_bridge(object())


def test_native_bridge_abi_and_terminal_schema_are_exact() -> None:
    assert M._NATIVE_TOOLCHAIN_TYPE_NAMES == (
        "ManagedEVMToolchainInitialAuthority",
        "ManagedEVMToolchainProvisionLease",
        "ManagedEVMToolchainProvisionTerminal",
    )
    assert M._NATIVE_TOOLCHAIN_FUNCTION_NAMES == (
        "managed_evm_toolchain_runtime_identity",
        "prepare_managed_evm_toolchain_provision",
        "execute_managed_evm_toolchain_provision",
        "project_managed_evm_toolchain_terminal",
    )
    required_projection_keys = {
        "schema",
        "result_sha256",
        "plan_sha256",
        "guest_execution_authority_sha256",
        "native_capability_receipt_sha256",
        "network_authority_receipt_sha256",
        "acquisition_terminal_receipt_sha256",
        "materialization_terminal_receipt_sha256",
        "solc_probe_terminal_receipt_sha256",
        "pypi_metadata_graph_terminal_receipt_sha256",
        "snapshot_bound_materialization_receipt_sha256",
        "source_provenance_sha256",
        "pre_replay_sha256",
        "post_replay_sha256",
        "provider_receipt_sha256",
        "provider_receipt_file_sha256",
        "generation_payload_manifest_sha256",
        "complete",
    }
    synthetic = {
        "artifact_set_sha256": "a" * 64,
        "plan_sha256": "b" * 64,
        "guest_execution_authority_sha256": "c" * 64,
        "acquisition_receipt_sha256": "9" * 64,
    }
    assert set(_native_result(synthetic)) == required_projection_keys
    production_source = inspect.getsource(M.provision)
    assert "request_bytes = _canonical_bytes(plan)" in production_source
    assert "return terminal" in production_source
    assert "native_executor(plan)" not in production_source


def test_windows_pe_structure_is_recorded_but_native_admission_stays_disabled(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    executable = tmp_path / "python.exe"
    image = bytearray(512)
    image[:2] = b"MZ"
    struct = __import__("struct")
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x8664, 3, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", image, 0x98, 0x20B)
    executable.write_bytes(image)
    identity = M._windows_pe_identity(executable)
    assert identity["pe_machine"] == "AMD64"
    assert identity["native_reparse_tag"] == "REQUIRED_AT_PRODUCTION_ADMISSION"

    project = tmp_path / "project"
    project.mkdir()
    plan = M.build_native_provision_plan(
        POLICY_PATH,
        _linux_guest_probe(),
        tmp_path / "generations" / policy_and_sha[1],
        tmp_path / "cache",
        acquisition_receipt_path=_acquisition_receipt(tmp_path),
        project_root=project,
        guest_execution_authority=_apple_guest_authority(),
    )
    plan["target_id"] = "windows-amd64"
    plan["plan_sha256"] = hashlib.sha256(
        M._canonical_bytes({k: v for k, v in plan.items() if k != "plan_sha256"})
    ).hexdigest()
    with pytest.raises(M.ToolchainError, match="WINDOWS_NATIVE_METADATA_UNAVAILABLE"):
        M.validate_native_provision_result(plan, {})


def test_filesystem_materialization_requires_explicit_project_root(
    policy_and_sha: tuple[dict[str, object], str], tmp_path: Path
) -> None:
    with pytest.raises(M.ToolchainError, match="project_root is required"):
        M.bootstrap_provision_test_only(
            POLICY_PATH,
            _managed_python_candidate(),
            tmp_path / "generations" / policy_and_sha[1],
            tmp_path / "cache",
            confirm_test_only=True,
        )
