from __future__ import annotations

import hashlib
import importlib.util
import os
import platform
import shutil
import struct
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_posix_native_supervisor.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "_plamen_native_derived_cli_test", BUILDER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runtime_tree(root: Path) -> None:
    for relative in (
        "profiles/codex-v2.bin",
        "profiles/claude-v2.bin",
        "scripts/posix_audit_entrypoint.py",
        "scripts/posix_native_authority_adapter.py",
        "scripts/posix_specialized_tool_worker.py",
        "scripts/report_output_routing.py",
        "scripts/plamen_driver.py",
        "plamen_runtime/__init__.py",
        "plamen_runtime/run.py",
        "plamen_runtime/assets/policy.json",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((relative + "\n").encode("ascii"))
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o500 if path.is_dir() else 0o400)
    root.chmod(0o500)


def _image_rows() -> bytes:
    members = (
        ("forge", "/usr/local/lib/plamen/toolchains/foundry/bin/forge", 1, 0o500),
        ("js_offline_materializer", "/usr/local/libexec/plamen-js-offline-materializer.py", 2, 0o400),
        ("managed_provisioner", "/usr/local/libexec/plamen-managed-evm-provisioner.py", 2, 0o400),
        ("managed_python", "/usr/local/lib/plamen/python/bin/python3.12", 1, 0o500),
        ("medusa", "/usr/local/lib/plamen/toolchains/medusa/bin/medusa", 1, 0o500),
        ("opengrep", "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep", 1, 0o500),
        ("slither", "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither", 1, 0o500),
        ("solc", "/usr/local/lib/plamen/toolchains/solc-amd64/solc", 1, 0o500),
        ("specialized_worker", "/opt/plamen/scripts/posix_specialized_tool_worker.py", 2, 0o400),
    )
    rows = bytearray()
    for ordinal, (identity, path, flags, mode) in enumerate(members):
        member_id = identity.encode("ascii")
        member_path = path.encode("ascii")
        rows.extend(struct.pack(">HHHBBQ", ordinal, flags, mode,
            len(member_id), len(member_path), ordinal + 1))
        rows.extend(bytes([ordinal + 1]) * 32)
        rows.extend(member_id.ljust(32, b"\0"))
        rows.extend(member_path.ljust(240, b"\0"))
    return bytes(rows)


@pytest.mark.skipif(platform.system() != "Darwin", reason="Darwin only")
def test_derived_coordinator_cli_executes_parser_manifest_stage_and_receipt(
    tmp_path: Path,
) -> None:
    clang = shutil.which("clang")
    assert clang is not None
    builder = _load_builder()
    harness_source = tmp_path / "derived-coordinator-harness.c"
    harness_source.write_text(
        r'''
#define PLAMEN_NATIVE_INSTALL_COORDINATOR_V2_MAIN 1
#define main plamen_production_coordinator_main
#include "native/darwin/plamen_native_install_coordinator_v2.c"
#undef main

static int fake_publish(const struct plamen_native_install_request_v2 *request,
    struct plamen_native_install_result_v2 *result)
{
    struct plamen_install_receipt receipt;
    uint8_t bytes[PLAMEN_INSTALL_RECEIPT_SIZE];
    char generation_hex[65];
    static const char digits[] = "0123456789abcdef";
    size_t offset = 0U, index;
    struct stat info;
    if (request == NULL || result == NULL || request->deployment != NULL
            || request->require_specialized_authority != 1U
            || request->receipt_fd < 0
            || fstat(request->receipt_fd, &info) != 0
            || info.st_size != (off_t)sizeof(bytes)
            || (info.st_mode & 07777U) != 0400U)
        return -1;
    while (offset < sizeof(bytes)) {
        ssize_t amount = pread(request->receipt_fd, bytes + offset,
            sizeof(bytes) - offset, (off_t)offset);
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    if (plamen_install_receipt_decode_exact(bytes, sizeof(bytes), &receipt)
            != 0 || receipt.specialized_present != 1U
            || plamen_install_receipt_specialized_authority_revalidate(
                request->specialized_authority_fd,
                &receipt.specialized_authority) != 0)
        return -1;
    for (index = 0U; index < 32U; ++index) {
        generation_hex[index * 2U] =
            digits[receipt.generation_id_sha256[index] >> 4U];
        generation_hex[index * 2U + 1U] =
            digits[receipt.generation_id_sha256[index] & 15U];
    }
    generation_hex[64] = '\0';
    if (strcmp(request->generation_id_hex, generation_hex) != 0
            || strrchr(receipt.generation_path, '/') == NULL
            || strcmp(strrchr(receipt.generation_path, '/') + 1,
                generation_hex) != 0)
        return -1;
        for (index = 0U; index < 10U; ++index)
        if (plamen_install_receipt_member_revalidate(
                request->generation_member_fds[index],
                &receipt.members[index]) != 0)
            return -1;
    memset(result, 0, sizeof(*result));
    return 0;
}

    int main(int argc, char **argv)
{
    int status;
    if (argc == 2 && strcmp(argv[1], "capabilities-v2") == 0)
        return plamen_production_coordinator_main(argc, argv);
        status = prepare_publish_fds_cli_with_effect(argc, argv, fake_publish);
            return status == 0 ? 0 : (errno == EINPROGRESS ? 76 : 75);
}
''',
        encoding="utf-8",
    )
    executable = tmp_path / "derived-coordinator-harness"
    subprocess.run(
        [
            clang,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-deprecated-declarations",
            "-fblocks",
            "-I",
            str(ROOT),
            str(harness_source),
            str(ROOT / "native/darwin/plamen_native_code_identity_v2.c"),
            str(ROOT / "native/darwin/plamen_native_deployment_receipt_v2.c"),
            str(ROOT / "native/darwin/plamen_native_launchd_installer_v2.c"),
            str(ROOT / "native/darwin/plamen_native_launchd_readiness_v2.c"),
            str(ROOT / "native/darwin/plamen_broker_v2_install_receipt.c"),
            str(ROOT / "native/darwin/plamen_native_image_member_receipt_v2.c"),
            str(ROOT / "native/darwin/plamen_native_source_bootstrap_coordinator_v1.c"),
            str(ROOT / "native/posix/plamen_native_installer_v2.c"),
            str(ROOT / "native/posix/plamen_native_builder_v2.c"),
            "-framework",
            "CoreFoundation",
            "-framework",
            "Security",
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
    )
    capability = subprocess.run(
        [executable, "capabilities-v2"], check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env={},
    )
    assert capability.returncode == 0
    assert capability.stdout == (
        b"PLAMEN_NATIVE_INSTALL_COORDINATOR_V2 specialized-derived-v1 "
        b"source-bootstrap-derived-v1\n"
    )
    assert capability.stderr == b""

    install_root = tmp_path / "install"
    stage_parent = tmp_path / "stages"
    runtime = tmp_path / "runtime"
    install_root.mkdir(mode=0o700)
    stage_parent.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    _runtime_tree(runtime)
    role_files: list[Path] = []
    for index in range(6):
        path = tmp_path / f"role-{index + 1}"
        path.write_bytes(f"role {index + 1}\n".encode("ascii"))
        path.chmod(0o500 if index in (0, 1, 5) else 0o400)
        role_files.append(path)
    role_files.append(runtime / "scripts/posix_audit_entrypoint.py")
    manifest = tmp_path / "runtime-package-manifest-v2.bin"
    manifest.touch(mode=0o600)
    role_files.append(manifest)
    coordinator = tmp_path / "plamen-native-installer-v2"
    coordinator.write_bytes(b"installed coordinator\n")
    coordinator.chmod(0o500)
    role_files.append(coordinator)
    source_bootstrap = tmp_path / "plamen-native-source-bootstrap-coordinator-v1"
    source_bootstrap.write_bytes(b"installed source bootstrap coordinator\n")
    source_bootstrap.chmod(0o500)
    role_files.append(source_bootstrap)
    receipt = tmp_path / "native-install-receipt-v2.bin"
    broker_plist = tmp_path / "broker.plist"
    custody_plist = tmp_path / "custody.plist"
    for path in (receipt, broker_plist, custody_plist):
        path.touch(mode=0o600)
    image_rows = tmp_path / "image-member-rows.bin"
    image_rows.write_bytes(_image_rows())
    image_rows.chmod(0o400)
    image_receipt = tmp_path / "image-member-receipt-v2.bin"
    image_receipt.touch(mode=0o600)
    stage_name = "generation-stage-v2-" + "ab" * 32

    opened = [
        os.open(install_root, os.O_RDONLY | os.O_DIRECTORY),
        os.open(stage_parent, os.O_RDONLY | os.O_DIRECTORY),
        os.open(runtime, os.O_RDONLY | os.O_DIRECTORY),
        os.open(receipt, os.O_RDWR),
        os.open(broker_plist, os.O_RDWR),
        os.open(custody_plist, os.O_RDWR),
        *(os.open(path, os.O_RDWR if path == manifest else os.O_RDONLY)
          for path in role_files),
        os.open(image_rows, os.O_RDONLY),
        os.open(image_receipt, os.O_RDWR),
    ]
    digests = {
        field: format(index + 2, "064x")
        for index, field in enumerate(
            builder.RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS
        )
    }
    try:
        argv = [
            str(executable),
            "prepare-publish-specialized-derived-fds",
            *(str(fd) for fd in opened[:6]),
            str(install_root),
            stage_name,
            hashlib.sha256(
                b"plamen.native_audit_request_projection.v1"
            ).hexdigest(),
            hashlib.sha256(b"protocol-v2").hexdigest(),
            "12",
            "arm64",
            "registry.example/plamen/audit@sha256:"
            + digests["oci_index_digest"],
            "/usr/local/libexec/plamen-guest",
            *(digests[field]
              for field in builder.RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS),
            *(str(fd) for fd in opened[6:16]),
            str(opened[16]),
            str(opened[17]),
            "66" * 32,
            "77" * 32,
            "11" * 20,
            "22" * 20,
            "33" * 20,
            "55" * 20,
            "66" * 20,
            "org.python.python",
            "PYTHONTEAM",
            "44" * 20,
        ]
        assert len(argv) == 52
        completed = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            pass_fds=tuple(opened),
        )
        assert completed.returncode == 0, completed.stderr.decode(
            "utf-8", "replace"
        )
        assert completed.stdout == b""
        assert completed.stderr == b""
        assert len(image_receipt.read_bytes()) == 3136
        raw = receipt.read_bytes()
        assert len(raw) == builder.DARWIN_INSTALL_RECEIPT_V2_SIZE
        generation_id = raw[16:48].hex()
        assert (stage_parent / stage_name).is_dir()
        assert generation_id in raw[320:1344].rstrip(b"\0").decode("ascii")
        assert raw[192:196] == b"\0\0\0\1"
        staged_companion = (
            stage_parent / stage_name / "share" / "plamen"
            / "image-member-receipt-v2.bin"
        )
        assert staged_companion.read_bytes() == image_receipt.read_bytes()
        complete_outputs = {
            "manifest": manifest.read_bytes(),
            "receipt": receipt.read_bytes(),
            "broker": broker_plist.read_bytes(),
            "custody": custody_plist.read_bytes(),
            "image": image_receipt.read_bytes(),
        }
        immutable = {
            path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
            for path in (receipt, broker_plist, custody_plist, manifest,
                         image_receipt, staged_companion)
        }
        resumed_argv = list(argv)
        resumed_argv[1] = "resume-publish-specialized-derived-fds"
        resumed = subprocess.run(
            resumed_argv, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={},
            pass_fds=tuple(opened),
        )
        assert resumed.returncode == 0, resumed.stderr.decode(
            "utf-8", "replace"
        )
        assert resumed.stdout == resumed.stderr == b""
        for path, (raw_before, inode_before, mtime_before) in immutable.items():
            assert path.read_bytes() == raw_before
            assert path.stat().st_ino == inode_before
            assert path.stat().st_mtime_ns == mtime_before

        prefix_paths = {
            key: tmp_path / f"prefix-{key}.bin"
            for key in complete_outputs
        }
        prefix_sizes = {
            key: index * 7
            for index, key in enumerate(complete_outputs, start=1)
        }
        prefix_fds: dict[str, int] = {}
        try:
            for index, (key, raw_candidate) in enumerate(
                complete_outputs.items(), start=1
            ):
                prefix_paths[key].write_bytes(
                    raw_candidate[:prefix_sizes[key]]
                )
                prefix_paths[key].chmod(0o600)
                prefix_fds[key] = os.open(prefix_paths[key], os.O_RDWR)
            prefix_argv = list(argv)
            prefix_argv[5] = str(prefix_fds["receipt"])
            prefix_argv[6] = str(prefix_fds["broker"])
            prefix_argv[7] = str(prefix_fds["custody"])
            prefix_argv[9] = stage_name + ".attempt-0002"
            prefix_argv[37] = str(prefix_fds["manifest"])
            prefix_argv[41] = str(prefix_fds["image"])
            prefix_pass = tuple(
                opened[:3] + opened[6:13] + opened[14:17]
            ) \
                + tuple(prefix_fds.values())
            recovered_prefix = subprocess.run(
                prefix_argv, check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={},
                pass_fds=prefix_pass,
            )
            assert recovered_prefix.returncode == 0, (
                recovered_prefix.stderr.decode("utf-8", "replace")
            )
            for key, raw_candidate in complete_outputs.items():
                recovered = prefix_paths[key].read_bytes()
                assert recovered.startswith(
                    raw_candidate[:prefix_sizes[key]]
                )
                if key != "receipt":
                    assert recovered == raw_candidate
                assert prefix_paths[key].stat().st_mode & 0o777 == 0o400
            assert (stage_parent / (stage_name + ".attempt-0002")).is_dir()
        finally:
            for descriptor in prefix_fds.values():
                os.close(descriptor)

        bad = tmp_path / "bad-image-receipt.bin"
        bad.write_bytes(bytes([complete_outputs["image"][0] ^ 1]))
        bad.chmod(0o600)
        bad_fd = os.open(bad, os.O_RDWR)
        complete_fds = {
            key: os.open(path, os.O_RDONLY)
            for key, path in {
                "receipt": receipt,
                "broker": broker_plist,
                "custody": custody_plist,
                "manifest": manifest,
            }.items()
        }
        try:
            bad_argv = list(argv)
            bad_argv[5] = str(complete_fds["receipt"])
            bad_argv[6] = str(complete_fds["broker"])
            bad_argv[7] = str(complete_fds["custody"])
            bad_argv[9] = stage_name + ".attempt-0003"
            bad_argv[37] = str(complete_fds["manifest"])
            bad_argv[41] = str(bad_fd)
            bad_result = subprocess.run(
                bad_argv, check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={},
                pass_fds=tuple(
                    opened[:3] + opened[6:13] + opened[14:17]
                )
                    + tuple(complete_fds.values()) + (bad_fd,),
            )
            assert bad_result.returncode == 75
            assert bad.read_bytes() == bytes(
                [complete_outputs["image"][0] ^ 1]
            )
            assert not (stage_parent / (stage_name + ".attempt-0003")).exists()
        finally:
            os.close(bad_fd)
            for descriptor in complete_fds.values():
                os.close(descriptor)

        residue = stage_parent / (stage_name + ".attempt-0003")
        residue.mkdir(mode=0o700)
        residue_before = residue.stat()
        empty_receipt = tmp_path / "empty-receipt.bin"
        empty_receipt.touch(mode=0o600)
        empty_receipt_fd = os.open(empty_receipt, os.O_RDWR)
        replay_fds = {
            "broker": os.open(broker_plist, os.O_RDONLY),
            "custody": os.open(custody_plist, os.O_RDONLY),
            "manifest": os.open(manifest, os.O_RDONLY),
            "image": os.open(image_receipt, os.O_RDONLY),
        }
        try:
            residue_argv = list(argv)
            residue_argv[5] = str(empty_receipt_fd)
            residue_argv[6] = str(replay_fds["broker"])
            residue_argv[7] = str(replay_fds["custody"])
            residue_argv[9] = residue.name
            residue_argv[37] = str(replay_fds["manifest"])
            residue_argv[41] = str(replay_fds["image"])
            residue_result = subprocess.run(
                residue_argv, check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={},
                pass_fds=tuple(
                    opened[:3] + opened[6:13] + opened[14:17]
                )
                    + tuple(replay_fds.values()) + (empty_receipt_fd,),
            )
            assert residue_result.returncode == 76
            assert residue_result.stdout == residue_result.stderr == b""
            assert residue.stat() == residue_before
            assert empty_receipt.read_bytes() == b""
        finally:
            os.close(empty_receipt_fd)
            for descriptor in replay_fds.values():
                os.close(descriptor)
        original_rows = image_rows.read_bytes()
        image_rows.chmod(0o600)
        image_rows.write_bytes(bytes([original_rows[0] ^ 1]) + original_rows[1:])
        image_rows.chmod(0o400)
        rejected_resume = subprocess.run(
            resumed_argv, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={},
            pass_fds=tuple(opened),
        )
        assert rejected_resume.returncode == 75
        for path, (raw_before, inode_before, mtime_before) in immutable.items():
            assert path.read_bytes() == raw_before
            assert path.stat().st_ino == inode_before
            assert path.stat().st_mtime_ns == mtime_before
        image_rows.chmod(0o600)
        image_rows.write_bytes(original_rows)
        image_rows.chmod(0o400)
        before = (stage_parent / stage_name).stat()
        invalid = list(argv)
        invalid[9] = stage_name + ".attempt-0004"
        invalid[13] = "amd64"
        rejected = subprocess.run(
            invalid,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            pass_fds=tuple(opened),
        )
        assert rejected.returncode == 75
        assert (stage_parent / stage_name).stat() == before
        assert not (stage_parent / (stage_name + ".attempt-0004")).exists()
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
