"""Focused tests for the native POSIX supervisor extension boundary."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pickle
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
from types import ModuleType
from typing import Any, Iterator

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_posix_native_supervisor.py"
SOURCE = REPO_ROOT / "native" / "cpython" / "_plamen_native_supervisor.c"
PRODUCTION_MODULE = "_plamen_native_supervisor"
TEST_ONLY_MODULE = "_plamen_native_supervisor_testonly"
FINGERPRINT = hashlib.sha256(b"native-consumer-request").hexdigest()
ATTEMPT = "attempt-native-001"
SESSION = hashlib.sha256(b"native-consumer-session").hexdigest()
SESSION_MAGIC = b"PLAMENS1"
FRAME_MAGIC = b"PLAMENF1"


def _clear_test_tree_immutable_flags(root: Path) -> None:
    """Clear only UF_IMMUTABLE inside one pytest-owned temporary root."""

    if sys.platform != "darwin" or not root.is_absolute():
        return
    immutable = getattr(stat, "UF_IMMUTABLE", 0)
    if not immutable or not hasattr(os, "chflags"):
        return

    def clear(path: Path) -> None:
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
                return
            if getattr(info, "st_flags", 0) & immutable:
                os.chflags(
                    path,
                    int(info.st_flags) & ~immutable,
                    follow_symlinks=False,
                )
        except OSError:
            pass

    # Clear a flagged directory before scanning it, then its exact descendants.
    clear(root)
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        clear(parent)
        for name in (*names, *files):
            clear(parent / name)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_builder(
    root: Path, *, test_only: bool = False, production_shape: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    command = [
        sys.executable,
        str(BUILD_SCRIPT),
        "--output-root",
        str(root),
    ]
    if production_shape:
        command.append("--test-production-shape")
    elif test_only:
        command.append("--test-only")
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
    )


@pytest.fixture(scope="session")
def native_builds(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, dict[str, Any]]]:
    results: dict[str, dict[str, Any]] = {}
    roots: list[Path] = []
    try:
        for label, test_only in (("production", False), ("test", True)):
            root = tmp_path_factory.mktemp(
                f"native-supervisor-{label}"
            ).resolve(strict=True)
            roots.append(root)
            root.chmod(0o700)
            completed = _run_builder(
                root, test_only=test_only, production_shape=not test_only
            )
            assert completed.returncode == 0, completed.stderr.decode(
                "utf-8", "replace"
            )
            result = json.loads(completed.stdout)
            artifact = Path(result["artifact_path"])
            manifest = Path(result["manifest_path"])
            assert artifact.parent.name == result["build_key_sha256"]
            assert _sha256(artifact) == result["artifact_sha256"]
            assert _sha256(manifest) == result["manifest_sha256"]
            results[label] = result
        yield results
    finally:
        for root in roots:
            _clear_test_tree_immutable_flags(root)


@pytest.fixture(autouse=True)
def _clear_test_output_immutable_flags(request: pytest.FixtureRequest):
    yield
    root = request.node.funcargs.get("tmp_path")
    if sys.platform != "darwin" or not isinstance(root, Path):
        return
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        return
    if resolved != Path(os.path.abspath(os.fspath(root))):
        return
    _clear_test_tree_immutable_flags(resolved)


def test_cleanup_helper_clears_only_test_owned_immutable_flags(tmp_path: Path) -> None:
    if sys.platform != "darwin":
        pytest.skip("Darwin immutable flag regression")
    immutable = getattr(stat, "UF_IMMUTABLE", 0)
    if not immutable or not hasattr(os, "chflags"):
        pytest.skip("Darwin immutable flags unavailable")
    root = (tmp_path / "exact-owned-root").resolve()
    root.mkdir(mode=0o700)
    artifact = root / "artifact"
    artifact.write_bytes(b"retained-test-artifact")
    os.chflags(artifact, immutable)

    _clear_test_tree_immutable_flags(root)

    assert not artifact.stat().st_flags & immutable
    artifact.unlink()
    root.rmdir()


def _load_exact(path: Path, module_name: str) -> ModuleType:
    sys.modules.pop(module_name, None)
    loader = importlib.machinery.ExtensionFileLoader(module_name, str(path))
    spec = importlib.util.spec_from_file_location(
        module_name, str(path), loader=loader
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def _load_builder() -> ModuleType:
    name = "_plamen_native_builder_test_instance"
    spec = importlib.util.spec_from_file_location(name, BUILD_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def test_module(native_builds: dict[str, dict[str, Any]]) -> ModuleType:
    module = _load_exact(
        Path(native_builds["test"]["artifact_path"]), TEST_ONLY_MODULE
    )
    assert module.TEST_ONLY_BUILD is True
    assert module.__name__ == TEST_ONLY_MODULE
    return module


def _wire(
    *,
    fingerprint: str = FINGERPRINT,
    attempt: str = ATTEMPT,
    session: str = SESSION,
    session_on_frame: str | None = None,
    sequence: int = 1,
    payload_size: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    payload = attempt.encode("ascii")
    session_bytes = bytes.fromhex(session)
    frame_session = bytes.fromhex(session_on_frame or session)
    session_header = struct.pack(
        ">8sHH32sI", SESSION_MAGIC, 1, 48, session_bytes, 0
    )
    frame_header = struct.pack(
        ">8sHHIIQ32s32s",
        FRAME_MAGIC,
        1,
        1,
        92,
        len(payload) if payload_size is None else payload_size,
        sequence,
        frame_session,
        bytes.fromhex(fingerprint),
    )
    return session_header + frame_header + payload + trailing


def _consumer(
    module: ModuleType,
    wire: bytes,
    *,
    fingerprint: str = FINGERPRINT,
    attempt: str = ATTEMPT,
    session: str = SESSION,
    **overrides: int,
) -> tuple[object, socket.socket]:
    retained, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        consumer = module.TEST_ONLY_create_consumer(
            retained.fileno(), fingerprint, attempt, session, **overrides
        )
    finally:
        retained.close()
    peer.sendall(wire)
    peer.shutdown(socket.SHUT_WR)
    return consumer, peer


def test_build_manifest_binds_abi_compiler_source_and_private_artifact(
    native_builds: dict[str, dict[str, Any]],
) -> None:
    for label, expected_variant in (
        ("production", "TEST_ONLY_PRODUCTION_SHAPE"),
        ("test", "TEST_ONLY"),
    ):
        result = native_builds[label]
        manifest_path = Path(result["manifest_path"])
        manifest = json.loads(manifest_path.read_bytes())
        artifact = Path(result["artifact_path"])
        expected_module = (
            PRODUCTION_MODULE if label == "production" else TEST_ONLY_MODULE
        )
        assert manifest["schema"] == "plamen-native-supervisor-build-v2"
        assert result["schema"] == "plamen-native-supervisor-build-result-v2"
        assert manifest["variant"] == expected_variant
        assert manifest["module"] == expected_module
        assert manifest["init_symbol"] == f"PyInit_{expected_module}"
        assert manifest["output_basename"] == artifact.name
        assert result["module"] == expected_module
        assert manifest["production_packaging_allowed"] is False
        assert manifest["required_test_only_build"] is True
        assert manifest["python_implementation"] == "cpython"
        assert tuple(manifest["python_version"][:2]) in {(3, 12), (3, 14)}
        assert manifest["soabi"]
        assert manifest["extension_suffix"] in importlib.machinery.EXTENSION_SUFFIXES
        assert manifest["source"]["sha256"] == _sha256(SOURCE)
        assert len(manifest["compiler"]["sha256"]) == 64
        if sys.platform == "darwin":
            assert manifest["compiler"]["path"].startswith(
                "/Library/Developer/CommandLineTools/"
            )
            assert manifest["compiler_resolution"]["kind"] == (
                "DARWIN_SIP_XCRUN_EXACT_NATIVE_TOOL"
            )
        assert len(manifest["linker"]["sha256"]) == 64
        assert len(manifest["test_only_builder_path_observation"]["sha256"]) == 64
        assert manifest["builder_execution_authority"] == (
            "TEST_ONLY_UNAUTHENTICATED_LOADED_PYTHON_CODE"
        )
        assert manifest["toolchain_dynamic_closure"]["production_build_allowed"] is True
        for member in manifest["toolchain_dynamic_closure"]["members"]:
            assert member["root_role"] in {"compiler", "linker"}
            assert member["executable_directory"].startswith("/")
            assert member["loader_directory"].startswith("/")
            assert member["target_topology"]
        assert len(manifest["interpreter"]["sha256"]) == 64
        assert manifest["compiler_argv"][0] == manifest["compiler"]["path"]
        assert manifest["build_environment"] == {
            "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"
        }
        assert manifest["sysconfig"]["CC"]
        assert manifest["preprocess_flags"]
        assert manifest["final_compile_flags"]
        assert manifest["link_flags"]
        assert manifest["source_snapshot"]["sha256"] == manifest["source"]["sha256"]
        assert manifest["source_snapshot_observed"]["sha256"] == manifest["source"]["sha256"]
        assert manifest["python_include_trees"]
        assert manifest["translation_unit_closure"]["dependency_count"] > 0
        assert manifest["translation_unit"]["sha256"] == manifest["translation_unit_observed"]["sha256"]
        if sys.platform == "darwin":
            assert manifest["darwin_receipt_source"]["sha256"] == _sha256(
                REPO_ROOT / "native" / "darwin"
                / "plamen_broker_v2_install_receipt.c"
            )
            assert (
                manifest["darwin_receipt_source_snapshot"]["sha256"]
                == manifest["darwin_receipt_source"]["sha256"]
                == manifest["darwin_receipt_source_snapshot_observed"][
                    "sha256"
                ]
            )
            assert manifest["darwin_receipt_translation_unit"]["sha256"] == (
                manifest["darwin_receipt_translation_unit_observed"]["sha256"]
            )
            receipt_closure = manifest[
                "darwin_receipt_translation_unit_closure"
            ]
            assert receipt_closure["dependency_count"] > 0
            assert any(
                row["resolved_path"].endswith(
                    "/native/darwin/plamen_broker_v2_install_receipt.h"
                )
                for row in receipt_closure["dependencies"]
            )
        else:
            assert manifest["darwin_receipt_source"] is None
            assert manifest["darwin_receipt_translation_unit"] is None
        assert manifest["compiler_resource_headers"]["file_count"] > 0
        allowlist = manifest["production_packaging_allowlist"]
        assert allowlist == {
            "module": PRODUCTION_MODULE,
            "init_symbol": f"PyInit_{PRODUCTION_MODULE}",
            "output_basename": f"{PRODUCTION_MODULE}{manifest['extension_suffix']}",
            "variant": "PRODUCTION",
            "test_only_build": False,
        }
        assert manifest["output_basename"] != allowlist["output_basename"]
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o500
        assert artifact.stat().st_nlink == 1
        assert manifest_path.stat().st_mode & 0o777 == 0o400
        assert manifest["artifact_symbol_observation"]["expected_export"] == (
            f"_PyInit_{expected_module}"
        )
        assert result["build_key_sha256"] == artifact.parent.name
        assert {entry.name for entry in artifact.parent.iterdir()} == {
            artifact.name, manifest_path.name
        }

    production = native_builds["production"]
    test_only = native_builds["test"]
    assert production["build_key_sha256"] != test_only["build_key_sha256"]
    assert Path(production["artifact_path"]).name != Path(test_only["artifact_path"]).name


def test_production_builder_hardstops_before_work_and_never_coerces_bool(
    tmp_path: Path,
) -> None:
    builder = _load_builder()

    class StatefulBool:
        calls = 0

        def __bool__(self) -> bool:
            self.calls += 1
            return self.calls == 1

    malicious = StatefulBool()
    absent = tmp_path / "must-not-be-created"
    with pytest.raises(builder.BuildError, match="exact bool"):
        builder.build(absent, test_only=malicious)
    assert malicious.calls == 0
    assert not absent.exists()

    root = tmp_path / "production-root"
    root.mkdir(mode=0o700)
    with pytest.raises(builder.BuildError, match="production build hard-stop"):
        builder.build(root, test_only=False)
    assert not list(root.iterdir())


def test_overwritten_loaded_builder_cannot_claim_production_authority(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "copied-builder.py"
    shutil.copyfile(BUILD_SCRIPT, copied)
    name = "_plamen_overwritten_builder_test_instance"
    spec = importlib.util.spec_from_file_location(name, copied)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    copied.write_bytes(b"# overwritten after import\n")
    root = tmp_path / "production-root"
    root.mkdir(mode=0o700)
    with pytest.raises(builder.BuildError, match="production build hard-stop"):
        builder.build(root, test_only=False)
    assert not list(root.iterdir())


def test_header_aba_cannot_change_descriptor_frozen_translation_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    include_root = tmp_path / "include"
    shutil.copytree(Path(builder.sysconfig.get_path("include")), include_root)
    header = include_root / "plamen_header_aba.h"
    safe_header = b'#define PLAMEN_HEADER_VALUE "SAFE"\n'
    tampered_header = b'#define PLAMEN_HEADER_VALUE "HEADER_TAMPER"\n'
    header.write_bytes(safe_header)
    source = tmp_path / "header-aba-module.c"
    source.write_text(
        '#include <Python.h>\n#include "plamen_header_aba.h"\n'
        'static struct PyModuleDef m={.m_base=PyModuleDef_HEAD_INIT,'
        '.m_name="_plamen_native_supervisor",.m_size=-1};\n'
        'PyMODINIT_FUNC PyInit__plamen_native_supervisor(void){PyObject*x=PyModule_Create(&m);'
        'if(x)PyModule_AddStringConstant(x,"HEADER_VALUE",PLAMEN_HEADER_VALUE);return x;}\n',
        encoding="ascii",
    )
    real_get_path = builder.sysconfig.get_path
    monkeypatch.setattr(
        builder.sysconfig, "get_path",
        lambda key: str(include_root) if key in {"include", "platinclude"} else real_get_path(key),
    )
    monkeypatch.setattr(builder, "SOURCE", source)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir(mode=0o700); second_root.mkdir(mode=0o700)
    first = builder.TEST_ONLY_build_production_shape(first_root)
    real_run = builder.subprocess.run
    attacked = False

    def tamper_only_during_final_compile(*args: object, **kwargs: object) -> object:
        nonlocal attacked
        command = args[0] if args else kwargs.get("args")
        if not attacked and isinstance(command, (list, tuple)) and "cpp-output" in command:
            attacked = True
            header.write_bytes(tampered_header)
            try:
                return real_run(*args, **kwargs)
            finally:
                header.write_bytes(safe_header)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(builder.subprocess, "run", tamper_only_during_final_compile)
    second = builder.TEST_ONLY_build_production_shape(second_root)
    assert attacked is True
    assert first["build_key_sha256"] == second["build_key_sha256"]
    assert first["artifact_sha256"] == second["artifact_sha256"]
    module = _load_exact(Path(second["artifact_path"]), PRODUCTION_MODULE)
    assert module.HEADER_VALUE == "SAFE"


def test_closed_environment_mutation_after_key_has_no_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    real_run = builder.subprocess.run
    observed: dict[str, str] | None = None

    def mutate_global_before_final_compile(*args: object, **kwargs: object) -> object:
        nonlocal observed
        command = args[0] if args else kwargs.get("args")
        if observed is None and isinstance(command, (list, tuple)) and "cpp-output" in command:
            environment = kwargs["env"]
            with pytest.raises(TypeError):
                environment["LANG"] = "MUTATED"
            builder._CLOSED_ENV["LANG"] = "MUTATED"
            observed = dict(environment)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(builder.subprocess, "run", mutate_global_before_final_compile)
    result = builder.TEST_ONLY_build_production_shape(root)
    manifest = json.loads(Path(result["manifest_path"]).read_bytes())
    assert observed == {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    assert manifest["build_environment"] == observed


def test_artifact_mutation_between_initial_digest_and_link_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    real_link = builder.os.link
    attacked = False

    def mutate_then_link(source: str, destination: str, **kwargs: Any) -> None:
        nonlocal attacked
        if not attacked and source.startswith("artifact-"):
            attacked = True
            workspace_fd = kwargs["src_dir_fd"]
            os.chmod(source, 0o700, dir_fd=workspace_fd, follow_symlinks=False)
            attack_fd = os.open(
                source, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW,
                dir_fd=workspace_fd,
            )
            try:
                os.write(attack_fd, b"ARTIFACT_MUTATION")
                os.fsync(attack_fd)
            finally:
                os.close(attack_fd)
        real_link(source, destination, **kwargs)

    monkeypatch.setattr(builder.os, "link", mutate_then_link)
    with pytest.raises(builder.BuildError, match="published artifact"):
        builder.TEST_ONLY_build_production_shape(root)
    assert attacked is True
    assert not list(root.iterdir())


def test_manifest_mutation_after_write_is_rejected_and_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    real_write = builder._write_new_retained
    attacked = False

    def write_then_mutate(
        directory_fd: int, name: str, content: bytes, mode: int,
    ) -> tuple[int, dict[str, Any]]:
        nonlocal attacked
        descriptor, identity = real_write(directory_fd, name, content, mode)
        if name == "build-manifest.json":
            attacked = True
            os.chmod(name, 0o600, dir_fd=directory_fd, follow_symlinks=False)
            writer = os.open(
                name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=directory_fd
            )
            try:
                os.pwrite(writer, b"[", 0)
                os.fsync(writer)
            finally:
                os.close(writer)
            os.chmod(name, 0o400, dir_fd=directory_fd, follow_symlinks=False)
        return descriptor, identity

    monkeypatch.setattr(builder, "_write_new_retained", write_then_mutate)
    with pytest.raises(builder.BuildError, match="manifest changed"):
        builder.TEST_ONLY_build_production_shape(root)
    assert attacked is True
    assert not list(root.iterdir())


def test_sdk_authority_rejects_current_user_writable_ancestry(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    writable = tmp_path / "sdk" / "nested"
    writable.mkdir(parents=True)
    with pytest.raises(builder.BuildError, match="root-owned and non-writable"):
        builder._require_root_owned_nonwritable_ancestry(
            writable, "adversarial SDK"
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Mach-O-only authority check")
def test_macho_closure_rejects_user_owned_readonly_leaf_and_parent(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    fake_toolchain = tmp_path / "toolchain"
    fake_toolchain.mkdir(mode=0o755)
    fake_member = fake_toolchain / "compiler"
    fake_member.write_bytes(b"not-a-mach-o")
    fake_member.chmod(0o444)
    fake_toolchain.chmod(0o555)
    with pytest.raises(builder.BuildError, match="root-owned and non-writable"):
        builder._toolchain_dynamic_closure(
            fake_member, fake_member, builder.MappingProxyType(builder._CLOSED_ENV)
        )


def test_late_whole_build_directory_substitution_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    real_remove = builder._remove_workspace_at
    attacked = False

    def substitute_build_after_prior_checks(
        root_fd: int, name: str, workspace_fd: int,
    ) -> None:
        nonlocal attacked
        if not attacked and name.startswith("workspace-"):
            build_names = [
                entry for entry in os.listdir(root_fd)
                if len(entry) == 64 and entry != name
            ]
            assert len(build_names) == 1
            build_name = build_names[0]
            held_name = "held-" + build_name
            os.rename(
                build_name, held_name, src_dir_fd=root_fd, dst_dir_fd=root_fd,
            )
            os.mkdir(build_name, 0o700, dir_fd=root_fd)
            attacked = True
        real_remove(root_fd, name, workspace_fd)

    monkeypatch.setattr(builder, "_remove_workspace_at", substitute_build_after_prior_checks)
    with pytest.raises(builder.BuildError, match="publication directory rebound"):
        builder.TEST_ONLY_build_production_shape(root)
    assert attacked is True


def test_builder_rejects_clobber_and_symlink_alias(
    tmp_path: Path,
) -> None:
    canonical_root = (tmp_path / "root").resolve()
    canonical_root.mkdir(mode=0o700)
    first = _run_builder(canonical_root, production_shape=True)
    assert first.returncode == 0, first.stderr.decode("utf-8", "replace")
    second = _run_builder(canonical_root, production_shape=True)
    assert second.returncode == 2
    assert b"already exists" in second.stderr

    alias = tmp_path / "alias"
    alias.symlink_to(canonical_root, target_is_directory=True)
    aliased = _run_builder(alias, test_only=True)
    assert aliased.returncode == 2
    assert b"symlink alias" in aliased.stderr


def test_builder_compiles_retained_source_snapshot_after_original_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    mutable_source = tmp_path / "mutable-supervisor.c"
    original = SOURCE.read_bytes()
    needle = b"HARD_STOP_PENDING_AUTHENTICATED_NATIVE_DISPATCHER"
    replacement = b"TAMPERED_PENDING_AUTHENTICATED_NATIVE_DISPATCHER"
    assert needle in original
    mutable_source.write_bytes(original)
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(builder, "SOURCE", mutable_source)
    real_run = builder.subprocess.run
    mutated = False

    def mutate_before_compile(*args: object, **kwargs: object) -> object:
        nonlocal mutated
        command = args[0] if args else kwargs.get("args")
        if (
            not mutated
                and isinstance(command, (list, tuple))
            and "-o" in command
            and any(str(item).endswith("source.snapshot.c") or "/fd/" in str(item)
                    for item in command)
        ):
            mutable_source.write_bytes(original.replace(needle, replacement))
            mutated = True
        return real_run(*args, **kwargs)

    monkeypatch.setattr(builder.subprocess, "run", mutate_before_compile)
    result = builder.TEST_ONLY_build_production_shape(root)
    assert mutated is True
    manifest = json.loads(Path(result["manifest_path"]).read_bytes())
    assert manifest["source"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert _sha256(mutable_source) != manifest["source"]["sha256"]
    module = _load_exact(Path(result["artifact_path"]), PRODUCTION_MODULE)
    assert module.PRODUCTION_ACQUISITION == needle.decode("ascii")


def test_compiler_suffix_is_in_build_key_and_unsafe_wrappers_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    real_get = builder.sysconfig.get_config_var

    def metadata_for(cc: str) -> dict[str, Any]:
        monkeypatch.setattr(
            builder.sysconfig,
            "get_config_var",
            lambda key: cc if key == "CC" else real_get(key),
        )
        metadata, state = builder._metadata(True)
        for key in (
            "compiler_fd", "source_fd", "protocol_fd", "linker_fd",
            "artifact_inspector_fd",
        ):
            os.close(state[key])
        for descriptor, _identity in state["toolchain_fds"] + state["sdk_fds"]:
            os.close(descriptor)
        return metadata

    plain = metadata_for("clang")
    pthread = metadata_for("clang -pthread")
    assert plain["compiler_argv"] != pthread["compiler_argv"]
    assert hashlib.sha256(builder._canonical_json_bytes(plain)).digest() != hashlib.sha256(
        builder._canonical_json_bytes(pthread)
    ).digest()

    monkeypatch.setattr(
        builder.sysconfig,
        "get_config_var",
        lambda key: "clang -o attacker" if key == "CC" else real_get(key),
    )
    with pytest.raises(builder.BuildError, match="safe allowlist"):
        builder._metadata(True)


def test_preowned_output_rejects_symlink_clobber(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    sentinel = tmp_path / "outside"
    sentinel.write_bytes(b"DO-NOT-CLOBBER")
    token = "a" * 64
    monkeypatch.setattr(builder.secrets, "token_hex", lambda count: token)
    real_snapshot = builder._snapshot_source

    def inject_symlink(
        source_fd: int, identity: dict[str, Any], workspace_fd: int, name: str,
    ) -> tuple[int, dict[str, Any]]:
        result = real_snapshot(source_fd, identity, workspace_fd, name)
        os.symlink(str(sentinel), f"artifact-{token}", dir_fd=workspace_fd)
        return result

    monkeypatch.setattr(builder, "_snapshot_source", inject_symlink)
    with pytest.raises(OSError):
        builder.TEST_ONLY_build_production_shape(root)
    assert sentinel.read_bytes() == b"DO-NOT-CLOBBER"


def test_artifact_and_manifest_are_fsynced_before_publication_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "build-root"
    root.mkdir(mode=0o700)
    events: list[tuple[str, int]] = []
    real_fsync = builder.os.fsync

    def record_fsync(descriptor: int) -> None:
        info = os.fstat(descriptor)
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
        events.append((kind, stat.S_IMODE(info.st_mode)))
        real_fsync(descriptor)

    monkeypatch.setattr(builder.os, "fsync", record_fsync)
    result = builder.TEST_ONLY_build_production_shape(root)
    artifact_fsync = max(
        index for index, event in enumerate(events) if event == ("file", 0o500)
    )
    manifest_fsync = max(
        index for index, event in enumerate(events) if event == ("file", 0o400)
    )
    directory_fsyncs = [
        index for index, event in enumerate(events) if event[0] == "directory"
    ]
    assert len(directory_fsyncs) >= 2
    assert artifact_fsync < directory_fsyncs[-2]
    assert manifest_fsync < directory_fsyncs[-2]
    assert Path(result["artifact_path"]).is_file()


def test_production_and_test_artifacts_cannot_substitute_for_each_other(
    native_builds: dict[str, dict[str, Any]],
) -> None:
    production = Path(native_builds["production"]["artifact_path"])
    test_only = Path(native_builds["test"]["artifact_path"])
    with pytest.raises(ImportError, match="module export function"):
        _load_exact(test_only, PRODUCTION_MODULE)
    with pytest.raises(ImportError, match="module export function"):
        _load_exact(production, TEST_ONLY_MODULE)


def test_production_extension_origin_static_type_and_no_mint(
    native_builds: dict[str, dict[str, Any]],
) -> None:
    artifact = native_builds["production"]["artifact_path"]
    probe = r'''
import importlib.machinery, importlib.util, pathlib, sys
path = pathlib.Path(sys.argv[1]).resolve(strict=True)
loader = importlib.machinery.ExtensionFileLoader("_plamen_native_supervisor", str(path))
spec = importlib.util.spec_from_file_location("_plamen_native_supervisor", str(path), loader=loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
assert isinstance(module.__spec__.loader, importlib.machinery.ExtensionFileLoader)
assert module.__spec__.loader.name == "_plamen_native_supervisor"
assert pathlib.Path(module.__spec__.origin).resolve(strict=True) == path
assert pathlib.Path(module.__file__).resolve(strict=True) == path
native_type = module.NativeAuthorityConsumer
assert type(native_type) is type
assert native_type.__module__ == "_plamen_native_supervisor"
assert native_type.__flags__ & (1 << 9) == 0
assert native_type.__flags__ & (1 << 10) == 0
assert module.TEST_ONLY_BUILD is False
assert module.PRODUCTION_ACQUISITION == "HARD_STOP_PENDING_AUTHENTICATED_NATIVE_DISPATCHER"
for name in ("TEST_ONLY_create_consumer", "TEST_ONLY_NativeAuthorityConsumer",
             "create_consumer", "mint", "factory", "acquire", "registry"):
    assert not hasattr(module, name)
for operation in (
    lambda: native_type(),
    lambda: object.__new__(native_type),
    lambda: type("Subclass", (native_type,), {}),
):
    try:
        operation()
    except TypeError:
        pass
    else:
        raise AssertionError("production native type became Python-constructible")
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


def test_test_only_type_is_distinct_static_and_nonconstructible(
    test_module: ModuleType,
) -> None:
    production_type = test_module.NativeAuthorityConsumer
    test_type = test_module.TEST_ONLY_NativeAuthorityConsumer
    assert test_type is not production_type
    assert test_type.__flags__ & (1 << 9) == 0
    assert test_type.__flags__ & (1 << 10) == 0
    consumer, peer = _consumer(test_module, _wire())
    try:
        assert type(consumer) is test_type
        assert type(consumer) is not production_type
        with pytest.raises(TypeError):
            test_type()
        with pytest.raises(TypeError):
            object.__new__(test_type)
        with pytest.raises(TypeError):
            type("ForbiddenSubclass", (test_type,), {})
    finally:
        peer.close()


def test_copy_deepcopy_and_pickle_are_denied(test_module: ModuleType) -> None:
    consumer, peer = _consumer(test_module, _wire())
    try:
        for operation in (
            lambda: copy.copy(consumer),
            lambda: copy.deepcopy(consumer),
            lambda: pickle.dumps(consumer),
            lambda: consumer.__reduce__(),
            lambda: consumer.__reduce_ex__(5),
        ):
            with pytest.raises(TypeError, match="cannot be copied or serialized"):
                operation()
        assert consumer.consume_once(FINGERPRINT, ATTEMPT)[0] == "TEST_ONLY_CONSUMED"
    finally:
        peer.close()


def test_descriptor_is_retained_cloexec_and_closed_at_terminal_consume(
    test_module: ModuleType,
) -> None:
    consumer, peer = _consumer(test_module, _wire())
    try:
        descriptor = consumer.TEST_ONLY_fileno()
        assert descriptor >= 64
        assert fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        assert consumer.consume_once(FINGERPRINT, ATTEMPT) == (
            "TEST_ONLY_CONSUMED", 1, 1
        )
        assert consumer.TEST_ONLY_fileno() == -1
        with pytest.raises(RuntimeError, match="already consumed"):
            consumer.consume_once(FINGERPRINT, ATTEMPT)
    finally:
        peer.close()


@pytest.mark.parametrize(
    ("bad_fingerprint", "bad_attempt", "exception"),
    (
        ("f" * 64, ATTEMPT, RuntimeError),
        (FINGERPRINT, "attempt-native-002", RuntimeError),
        (FINGERPRINT.upper(), ATTEMPT, ValueError),
        (123, ATTEMPT, ValueError),
    ),
)
def test_wrong_or_noncanonical_binding_burns_before_validation(
    test_module: ModuleType,
    bad_fingerprint: object,
    bad_attempt: object,
    exception: type[BaseException],
) -> None:
    consumer, peer = _consumer(test_module, _wire())
    try:
        with pytest.raises(exception) as failure:
            consumer.consume_once(bad_fingerprint, bad_attempt)
        assert FINGERPRINT not in str(failure.value)
        assert ATTEMPT not in str(failure.value)
        assert consumer.TEST_ONLY_fileno() == -1
        with pytest.raises(RuntimeError, match="already consumed"):
            consumer.consume_once(FINGERPRINT, ATTEMPT)
    finally:
        peer.close()


def test_two_threads_observe_exactly_one_consumption(test_module: ModuleType) -> None:
    consumer, peer = _consumer(test_module, _wire())
    barrier = threading.Barrier(3)

    def consume() -> tuple[str, object]:
        barrier.wait()
        try:
            return "ok", consumer.consume_once(FINGERPRINT, ATTEMPT)
        except BaseException as exc:  # assertion captures exact loser below
            return "error", exc

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(consume) for _ in range(2)]
            barrier.wait()
            outcomes = [future.result(timeout=5) for future in futures]
        successes = [value for status, value in outcomes if status == "ok"]
        failures = [value for status, value in outcomes if status == "error"]
        assert successes == [("TEST_ONLY_CONSUMED", 1, 1)]
        assert len(failures) == 1
        assert type(failures[0]) is RuntimeError
        assert "already consumed" in str(failures[0])
        assert consumer.TEST_ONLY_fileno() == -1
    finally:
        peer.close()


def test_wrong_pid_rejects_and_actual_fork_cannot_consume(
    test_module: ModuleType,
) -> None:
    wrong_pid, peer = _consumer(
        test_module,
        _wire(),
        creator_pid_override=os.getpid() + 1_000_000,
    )
    try:
        with pytest.raises(RuntimeError, match="process boundary"):
            wrong_pid.consume_once(FINGERPRINT, ATTEMPT)
        assert wrong_pid.TEST_ONLY_fileno() == -1
    finally:
        peer.close()

    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    consumer, peer = _consumer(test_module, _wire())
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - assertions reported through the pipe
        try:
            os.close(read_fd)
            peer.close()
            try:
                consumer.consume_once(FINGERPRINT, ATTEMPT)
            except RuntimeError as exc:
                valid = (
                    "process boundary" in str(exc)
                    and consumer.TEST_ONLY_fileno() == -1
                )
            else:
                valid = False
            os.write(write_fd, b"OK" if valid else b"BAD")
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 3) == b"OK"
        waited, status = os.waitpid(child_pid, 0)
        assert waited == child_pid and os.waitstatus_to_exitcode(status) == 0
        peer.close()
        assert consumer.consume_once(FINGERPRINT, ATTEMPT)[0] == "TEST_ONLY_CONSUMED"
    finally:
        os.close(read_fd)
        peer.close()


def test_wrong_interpreter_binding_burns_and_test_object_is_not_shareable(
    test_module: ModuleType,
) -> None:
    consumer, peer = _consumer(
        test_module,
        _wire(),
        creator_interpreter_id_override=(1 << 62),
    )
    try:
        with pytest.raises(RuntimeError, match="interpreter boundary"):
            consumer.consume_once(FINGERPRINT, ATTEMPT)
        assert consumer.TEST_ONLY_fileno() == -1
        try:
            import _interpreters
        except ImportError:
            _interpreters = None
        if _interpreters is not None:
            assert _interpreters.is_shareable(consumer) is False
    finally:
        peer.close()


def test_extension_loads_in_subinterpreter_but_wrong_binding_is_rejected(
    native_builds: dict[str, dict[str, Any]],
) -> None:
    try:
        import _interpreters as interpreters
    except ImportError:
        pytest.skip("subinterpreter execution API is unavailable")
    artifact = native_builds["test"]["artifact_path"]
    code = f'''
import importlib.machinery, importlib.util, socket
path = {artifact!r}
loader = importlib.machinery.ExtensionFileLoader("_plamen_native_supervisor_testonly", path)
spec = importlib.util.spec_from_file_location("_plamen_native_supervisor_testonly", path, loader=loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
left, right = socket.socketpair()
consumer = module.TEST_ONLY_create_consumer(
    left.fileno(), {FINGERPRINT!r}, {ATTEMPT!r}, {SESSION!r},
    creator_interpreter_id_override=(1 << 62),
)
left.close()
try:
    consumer.consume_once({FINGERPRINT!r}, {ATTEMPT!r})
except RuntimeError as exc:
    assert "interpreter boundary" in str(exc)
    assert consumer.TEST_ONLY_fileno() == -1
else:
    raise AssertionError("wrong subinterpreter binding was accepted")
right.close()
'''
    interpreter = interpreters.create()
    try:
        interpreters.exec(interpreter, code)
    finally:
        interpreters.destroy(interpreter)


@pytest.mark.parametrize(
    "wire",
    (
        _wire()[:17],
        _wire(payload_size=129),
        _wire(sequence=2),
        _wire(session_on_frame=hashlib.sha256(b"wrong-session").hexdigest()),
        _wire(trailing=_wire()),
    ),
    ids=("truncated", "oversize", "replayed-sequence", "session-mismatch", "extra-replay"),
)
def test_frame_truncation_oversize_and_session_replay_burn(
    test_module: ModuleType,
    wire: bytes,
) -> None:
    consumer, peer = _consumer(test_module, wire)
    try:
        with pytest.raises(RuntimeError, match="session frame is invalid"):
            consumer.consume_once(FINGERPRINT, ATTEMPT)
        assert consumer.TEST_ONLY_fileno() == -1
        with pytest.raises(RuntimeError, match="already consumed"):
            consumer.consume_once(FINGERPRINT, ATTEMPT)
    finally:
        peer.close()


def test_factory_rejects_non_socket_and_noncanonical_bounds(
    test_module: ModuleType,
    tmp_path: Path,
) -> None:
    regular = tmp_path / "not-a-socket"
    regular.write_bytes(b"")
    descriptor = os.open(regular, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="AF_UNIX stream"):
            test_module.TEST_ONLY_create_consumer(
                descriptor, FINGERPRINT, ATTEMPT, SESSION
            )
    finally:
        os.close(descriptor)

    left, right = socket.socketpair()
    try:
        for fingerprint, attempt, session in (
            (FINGERPRINT.upper(), ATTEMPT, SESSION),
            (FINGERPRINT, "-bad", SESSION),
            (FINGERPRINT, "a" * 129, SESSION),
            (FINGERPRINT, ATTEMPT, SESSION[:-1]),
        ):
            with pytest.raises(ValueError, match="not canonical"):
                test_module.TEST_ONLY_create_consumer(
                    left.fileno(), fingerprint, attempt, session
                )
    finally:
        left.close()
        right.close()
