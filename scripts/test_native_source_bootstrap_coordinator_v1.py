from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="Darwin native coordinator",
)


def test_native_source_bootstrap_coordinator_transaction(tmp_path: Path) -> None:
    executable = tmp_path / "source-bootstrap-coordinator-test"
    compile_result = subprocess.run(
        [
            "/usr/bin/clang",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-deprecated-declarations",
            "-DPLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_TESTING=1",
            "-I",
            str(ROOT / "native/darwin"),
            str(
                ROOT
                / "native/tests/plamen_native_source_bootstrap_coordinator_v1_test.c"
            ),
            str(
                ROOT
                / "native/darwin/plamen_native_source_bootstrap_coordinator_v1.c"
            ),
            "-lproc",
            "-framework",
            "Security",
            "-framework",
            "CoreFoundation",
            "-o",
            str(executable),
        ],
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    assert compile_result.returncode == 0, compile_result.stderr.decode(
        "utf-8", "replace"
    )
    run = subprocess.run(
        [str(executable)],
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr.decode("utf-8", "replace")
    assert run.stdout == b"native source-bootstrap coordinator v1: ok\n"


def test_native_source_bootstrap_production_entrypoint_links_and_fails_closed(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "plamen-native-source-bootstrap-coordinator-v1"
    objects: list[Path] = []
    c_sources = (
        (
            ROOT
            / "native/darwin/plamen_native_source_bootstrap_coordinator_v1.c",
            ("-DPLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_MAIN=1",),
        ),
        (ROOT / "native/darwin/plamen_native_operation4_helper_v1.c", ()),
        (ROOT / "native/darwin/plamen_native_backend_receipt_signer_v1.c", ()),
        (ROOT / "native/darwin/plamen_native_evm_static_acquisition_v1.c", ()),
        (ROOT / "native/darwin/plamen_native_fixed_role_acquisition_v1.c", ()),
        (ROOT / "native/tests/plamen_native_backend_receipt_signer_v1_policy.c", ()),
    )
    for ordinal, (source, extra_flags) in enumerate(c_sources):
        object_path = tmp_path / f"production-{ordinal}.o"
        compile_result = subprocess.run(
            [
                "/usr/bin/clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-deprecated-declarations",
                *extra_flags,
                "-I",
                str(ROOT / "native/darwin"),
                "-c",
                str(source),
                "-o",
                str(object_path),
            ],
            cwd=ROOT,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        assert compile_result.returncode == 0, compile_result.stderr.decode(
            "utf-8", "replace"
        )
        objects.append(object_path)
    link_result = subprocess.run(
        [
            "/usr/bin/swiftc",
            "-warnings-as-errors",
            "-parse-as-library",
            str(ROOT / "native/darwin/plamen_native_backend_receipt_signer_v1.swift"),
            str(ROOT / "native/darwin/plamen_native_evm_static_acquisition_v1.swift"),
            *(str(object_path) for object_path in objects),
            "-Xlinker",
            "-framework",
            "-Xlinker",
            "Foundation",
            "-Xlinker",
            "-framework",
            "-Xlinker",
            "CryptoKit",
            "-Xlinker",
            "-framework",
            "-Xlinker",
            "Security",
            "-Xlinker",
            "-framework",
            "-Xlinker",
            "CoreFoundation",
            "-Xlinker",
            "-lz",
            "-Xlinker",
            "-lproc",
            "-o",
            str(executable),
        ],
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    assert link_result.returncode == 0, link_result.stderr.decode(
        "utf-8", "replace"
    )
    run = subprocess.run(
        [str(executable)],
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    assert run.returncode == 1
    assert run.stdout == b""
    assert run.stderr == b"Plamen native source bootstrap denied.\n"

    def retained(name: str, raw: bytes) -> int:
        path = tmp_path / name
        path.write_bytes(raw)
        path.chmod(0o400)
        return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)

    def pair(name: str) -> tuple[int, int]:
        path = tmp_path / name
        path.write_bytes(b"")
        path.chmod(0o600)
        return (
            os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW),
            os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW),
        )

    def canonical(value: object) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()

    def unsigned(selector: str, payload: bytes, manifest: bytes) -> bytes:
        return canonical({
            "schema": "plamen.native-backend-latest-acquisition-receipt.v1",
            "selector": selector,
            "policy_schema": "plamen.native-backend-acquisition.v2",
            "policy_sha256": "aa" * 32,
            "resolved_version": "0.154.0",
            "resolved_release": f"0.154.0-darwin-arm64-{selector}",
            "registry": {}, "upstream": None, "transport": {},
            "payload": {
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            },
            "installed": {}, "probes": {},
            "install": {
                "transaction_id": "native-cli-test",
                "generation_id": "npm-" + "11" * 32,
                "install_receipt_sha256": "22" * 32,
                "source_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "source_manifest_size": len(manifest),
            },
        })

    public_writer, public_reader = pair("cli-public.bin")
    descriptors = [public_writer, public_reader]
    semantic_readers: list[int] = []
    transferred_writers = [public_writer]
    retained_inputs: list[int] = []
    try:
        for selector in ("codex", "claude"):
            payload = f"native-{selector}-payload".encode()
            manifest = canonical({"schema": "source", "selector": selector})
            unsigned_fd = retained(
                f"cli-{selector}-unsigned.json",
                unsigned(selector, payload, manifest),
            )
            payload_fd = retained(f"cli-{selector}-payload.bin", payload)
            manifest_fd = retained(f"cli-{selector}-manifest.json", manifest)
            semantic_writer, semantic_reader = pair(
                f"cli-{selector}-semantic.bin"
            )
            retained_inputs.extend((unsigned_fd, payload_fd, manifest_fd))
            transferred_writers.append(semantic_writer)
            semantic_readers.append(semantic_reader)
            descriptors.extend((
                unsigned_fd, payload_fd, manifest_fd,
                semantic_writer, semantic_reader,
            ))
        process = subprocess.Popen(
            [str(executable), "sign-backends-v1",
             *(str(descriptor) for descriptor in descriptors)],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(descriptors),
            close_fds=True,
        )
        for descriptor in transferred_writers:
            os.close(descriptor)
        transferred_writers.clear()
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr.decode("utf-8", "replace")
        assert stdout == b""
        assert stderr == b""
        public_key = os.pread(public_reader, os.fstat(public_reader).st_size, 0)
        assert len(public_key) == 32
        key_id = hashlib.sha256(public_key).hexdigest()
        for selector, descriptor in zip(("codex", "claude"), semantic_readers):
            raw = os.pread(descriptor, os.fstat(descriptor).st_size, 0)
            assert raw[-512:-504] == b"PLMOP4R1"
            value = json.loads(raw[:-512])
            assert value["selector"] == selector
            assert value["authentication"]["scheme"] == "ed25519"
            assert value["authentication"]["key_id"] == key_id
    finally:
        for descriptor in transferred_writers:
            os.close(descriptor)
        for descriptor in (public_reader, *retained_inputs, *semantic_readers):
            os.close(descriptor)
