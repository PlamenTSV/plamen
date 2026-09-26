from __future__ import annotations

import os
import platform
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _runtime_manifest(runtime: Path) -> bytes:
    source = ROOT / "scripts/build_posix_native_supervisor.py"
    spec = importlib.util.spec_from_file_location(
        "_plamen_coordinator_runtime_manifest_test", source
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    digests = {
        field: format(index + 2, "064x")
        for index, field in enumerate(
            builder.RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS
        )
    }
    return builder.TEST_ONLY_build_runtime_package_manifest_v2(
        runtime,
        bindings={
            "target_arch": "arm64",
            "oci_image_reference": (
                "registry.example/plamen/audit@sha256:"
                + digests["oci_index_digest"]
            ),
            "oci_init_reference": "/usr/local/libexec/plamen-guest",
            **digests,
        },
    )


@pytest.mark.skipif(platform.system() != "Darwin", reason="Darwin only")
def test_terminal_deployment_receipt_is_post_commit_exact_and_idempotent(
    tmp_path: Path,
) -> None:
    clang = shutil.which("clang")
    assert clang is not None
    root = tmp_path / "root"
    (root / "share/plamen").mkdir(parents=True)
    generation = tmp_path / "generation"
    for relative in (
        "bin/plamen-native-launcher",
        "bin/python3.12",
        "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so",
            "lib/plamen/plamen-audit-broker-v2",
            "libexec/plamen-native-installer-v2",
            "libexec/plamen-native-source-bootstrap-coordinator-v1",
            "lib/plamen/runtime/profiles/codex-v2.bin",
            "lib/plamen/runtime/profiles/claude-v2.bin",
            "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
            "lib/plamen/runtime/scripts/posix_native_authority_adapter.py",
            "lib/plamen/runtime/scripts/posix_specialized_tool_worker.py",
            "lib/plamen/runtime/scripts/report_output_routing.py",
        "lib/plamen/runtime/scripts/plamen_driver.py",
        "lib/plamen/runtime/plamen_runtime/__init__.py",
        "lib/plamen/runtime/plamen_runtime/run.py",
        "lib/plamen/runtime/plamen_runtime/assets/policy.json",
        "share/plamen/native-supervisor-schema-v2.json",
        "share/plamen/plamen_broker_v2.h",
        "share/plamen/runtime-package-manifest-v2.bin",
        "Library/LaunchAgents/com.plamen.audit.broker.v2.plist",
        "Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist",
    ):
        path = generation / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
    runtime = generation / "lib/plamen/runtime"
    for path in runtime.rglob("*"):
        path.chmod(0o500 if path.is_dir() else 0o400)
    runtime.chmod(0o500)
    manifest = generation / "share/plamen/runtime-package-manifest-v2.bin"
    manifest.write_bytes(_runtime_manifest(runtime))
    manifest.chmod(0o400)
    harness = tmp_path / "coordinator-harness.c"
    harness.write_text(
        r'''
#include "native/darwin/plamen_native_install_coordinator_v2.c"

static int commit_result;
static int fake_commit(void *context, uint32_t state) {
    (void)context; return state == UINT32_C(0x504c4d00) ? commit_result : -1;
}
static int fake_restore(void *context, uint32_t state) {
    (void)context; return state == UINT32_C(0x504c4d00) ? 0 : -1;
}

int main(int argc, char **argv) {
    struct coordinator_context context;
    struct plamen_install_receipt receipt, prior;
    struct stat info, replay_info;
    int root, generation, extra, terminal, tamper, runtime_file;
    uint8_t value; size_t index;
    if (argc != 3) return 2;
    root = open(argv[1], O_RDONLY | O_DIRECTORY); if (root < 0) return 3;
    generation = open(argv[2], O_RDONLY | O_DIRECTORY);
    if (generation < 0 || validate_generation_layout(generation) != 0) return 14;
    if (validate_runtime_package(generation, getuid()) != 0) return 16;
    runtime_file = openat(generation,
        "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
        O_RDONLY | O_NOFOLLOW);
    if (runtime_file < 0 || fchmod(runtime_file, 0600) != 0
        || close(runtime_file) != 0) return 17;
    runtime_file = openat(generation,
        "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
        O_WRONLY | O_NOFOLLOW);
    value = 'y';
    if (runtime_file < 0 || pwrite(runtime_file, &value, 1, 0) != 1
        || fsync(runtime_file) != 0 || fchmod(runtime_file, 0400) != 0
        || close(runtime_file) != 0
        || validate_runtime_package(generation, getuid()) == 0) return 18;
    extra = openat(generation, "unexpected", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (extra < 0 || close(extra) != 0
        || validate_generation_layout(generation) == 0) return 15;
    close(generation);
    memset(&context, 0, sizeof(context)); memset(&receipt, 0, sizeof(receipt));
    memset(&prior, 0, sizeof(prior));
    for (index = 0; index < 32; ++index) {
        receipt.generation_id_sha256[index] = (uint8_t)(index + 1);
        receipt.receipt_sha256[index] = (uint8_t)(index + 33);
        receipt.members[0].sha256[index] = (uint8_t)(index + 65);
        receipt.members[1].sha256[index] = (uint8_t)(index + 97);
        receipt.broker_launchd_plist.sha256[index] = (uint8_t)(index + 129);
        receipt.custody_launchd_plist.sha256[index] = (uint8_t)(index + 161);
    }
    context.root_fd = root; context.owner = getuid();
    context.transaction.replacement.receipt = &receipt;
    context.launchd.context = &context; context.launchd.commit = fake_commit;
    context.launchd.restore = fake_restore;
    commit_result = -1;
    if (wrapper_commit(&context, UINT32_C(0x504c4d00)) == 0) return 4;
    errno = 0;
    terminal = openat(root, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
        O_RDONLY | O_NOFOLLOW);
    if (terminal >= 0 || errno != ENOENT) return 5;
    commit_result = 0;
    if (wrapper_commit(&context, UINT32_C(0x504c4d00)) != 0) return 6;
    terminal = openat(root, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
        O_RDONLY | O_NOFOLLOW);
    if (terminal < 0 || fstat(terminal, &info) != 0
        || (info.st_mode & 07777) != 0400
        || info.st_size != PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE
        || plamen_native_darwin_deployment_receipt_validate_v2(
            terminal, &receipt) != 0) return 7;
    if (wrapper_commit(&context, UINT32_C(0x504c4d00)) != 0
        || fstat(terminal, &replay_info) != 0
        || replay_info.st_dev != info.st_dev
        || replay_info.st_ino != info.st_ino) return 8;
    if (validate_terminal_deployment_receipt(&context, &receipt) != 0)
        return 19;
    prior = receipt; prior.generation_id_sha256[0] ^= 1U;
    if (validate_terminal_deployment_receipt(&context, &prior) == 0)
        return 20;
    context.transaction.prior_present = 1;
    context.transaction.prior.receipt = &prior;
    if (wrapper_restore(&context, UINT32_C(0x504c4d00)) != 0) return 21;
    close(terminal);
    terminal = openat(root, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
        O_RDONLY | O_NOFOLLOW);
    if (terminal < 0 || plamen_native_darwin_deployment_receipt_validate_v2(
            terminal, &prior) != 0) return 22;
    close(terminal); terminal = -1;
    if (wrapper_commit(&context, UINT32_C(0x504c4d00)) != 0) return 23;
    terminal = openat(root, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
        O_RDONLY | O_NOFOLLOW);
    if (terminal < 0 || plamen_native_darwin_deployment_receipt_validate_v2(
            terminal, &receipt) != 0) return 24;
    receipt.generation_id_sha256[0] ^= 1U;
    if (plamen_native_darwin_deployment_receipt_validate_v2(
            terminal, &receipt) == 0) return 9;
    receipt.generation_id_sha256[0] ^= 1U; close(terminal);
    if (fchmodat(root, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
            0600, 0) != 0) return 10;
    tamper = openat(root, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
        O_WRONLY | O_NOFOLLOW); value = 0;
    if (tamper < 0 || pwrite(tamper, &value, 1, 0) != 1
        || fsync(tamper) != 0 || close(tamper) != 0
        || fchmodat(root, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
            0400, 0) != 0) return 11;
    if (wrapper_commit(&context, UINT32_C(0x504c4d00)) == 0) return 12;
    terminal = openat(root, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
        O_RDONLY | O_NOFOLLOW);
    if (terminal < 0 || pread(terminal, &value, 1, 0) != 1 || value != 0)
        return 13;
    close(terminal); close(root); return 0;
}
''',
        encoding="utf-8",
    )
    executable = tmp_path / "coordinator-harness"
    subprocess.run(
        [
            clang,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fblocks",
            "-I",
            str(ROOT),
            str(harness),
            str(ROOT / "native/darwin/plamen_native_code_identity_v2.c"),
            str(ROOT / "native/darwin/plamen_native_deployment_receipt_v2.c"),
            str(ROOT / "native/darwin/plamen_native_launchd_installer_v2.c"),
            str(ROOT / "native/darwin/plamen_native_launchd_readiness_v2.c"),
            str(ROOT / "native/darwin/plamen_broker_v2_install_receipt.c"),
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
    subprocess.run(
        [str(executable), str(root), str(generation)], check=True, env={}
    )
