import platform
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CLANG = Path("/usr/bin/clang")
HANDOFF = ROOT / "native/darwin/plamen_broker_v2_specialized_runtime_effects_handoff.c"


HARNESS = r'''
#include "plamen_broker_v2_specialized_runtime_effects_handoff.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct stat expected_runtime;
static unsigned load_count;

int
plamen_broker_v2_specialized_runtime_authority_load(
    const struct plamen_broker_v2_specialized_runtime_authority_open *open,
    struct plamen_broker_v2_specialized_runtime_authority *output)
{
    struct stat observed;
    if (open == NULL || output == NULL || open->generation_fd < 0
        || fstat(open->generation_fd, &observed) != 0
        || observed.st_dev != expected_runtime.st_dev
        || observed.st_ino != expected_runtime.st_ino)
        return -1;
    memset(output, 0, sizeof(*output));
    output->version = PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_AUTHORITY_VERSION;
    output->authority_sha256[0] = 1U;
    ++load_count;
    return 0;
}

static int
open_directory(const char *path)
{
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

int
main(int argc, char **argv)
{
    struct plamen_broker_v2_specialized_runtime_handoff_open open_request;
    struct plamen_broker_v2_specialized_runtime_handoff *handoff = NULL;
    struct plamen_install_receipt_member member;
    struct plamen_install_receipt_specialized_authority auxiliary;
    int generation_fd = -1, runtime_fd = -1, manifest_fd = -1, receipt_fd = -1;
    int alias_generation_fd = -1;
    if (argc != 6) return 10;
    generation_fd = open_directory(argv[1]);
    runtime_fd = open_directory(argv[2]);
    manifest_fd = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    receipt_fd = open(argv[4], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    alias_generation_fd = open_directory(argv[5]);
    if (generation_fd < 0 || runtime_fd < 0 || manifest_fd < 0
        || receipt_fd < 0 || alias_generation_fd < 0
        || fstat(runtime_fd, &expected_runtime) != 0)
        return 11;
    memset(&member, 0, sizeof(member));
    memset(&auxiliary, 0, sizeof(auxiliary));
    memset(&open_request, 0, sizeof(open_request));
    member.role = PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST;
    open_request.version = PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_HANDOFF_VERSION;
    open_request.generation_fd = generation_fd;
    open_request.runtime_manifest_fd = manifest_fd;
    open_request.runtime_manifest_member = &member;
    open_request.image_member_receipt_fd = receipt_fd;
    open_request.auxiliary = &auxiliary;
    if (plamen_broker_v2_specialized_runtime_handoff_create(
            &open_request, &handoff) != 0 || handoff == NULL)
        return 12;
    if (plamen_broker_v2_specialized_runtime_handoff_revalidate(handoff) != 0
        || load_count != 2U)
        return 13;
    plamen_broker_v2_specialized_runtime_handoff_destroy(handoff);
    handoff = NULL;

    /* Passing the runtime root as though it were the generation must fail. */
    open_request.generation_fd = runtime_fd;
    if (plamen_broker_v2_specialized_runtime_handoff_create(
            &open_request, &handoff) == 0 || handoff != NULL)
        return 14;

    /* An intermediate lib alias must not be traversed. */
    open_request.generation_fd = alias_generation_fd;
    if (plamen_broker_v2_specialized_runtime_handoff_create(
            &open_request, &handoff) == 0 || handoff != NULL)
        return 15;
    close(alias_generation_fd);
    close(receipt_fd);
    close(manifest_fd);
    close(runtime_fd);
    close(generation_fd);
    return 0;
}
'''


@pytest.mark.skipif(platform.system() != "Darwin", reason="Darwin native service")
def test_handoff_opens_fixed_runtime_root_beneath_generation(tmp_path: Path) -> None:
    generation = tmp_path / "generation"
    runtime = generation / "lib/plamen/runtime"
    runtime.mkdir(parents=True)
    alias_generation = tmp_path / "alias-generation"
    alias_generation.mkdir()
    (alias_generation / "lib").symlink_to(generation / "lib", target_is_directory=True)
    manifest = tmp_path / "manifest.bin"
    member_receipt = tmp_path / "member-receipt.bin"
    manifest.write_bytes(b"manifest")
    member_receipt.write_bytes(b"receipt")
    harness = tmp_path / "runtime-root-handoff.c"
    executable = tmp_path / "runtime-root-handoff"
    harness.write_text(HARNESS, encoding="utf-8")
    completed = subprocess.run(
        [
            str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "native/include"),
            "-I", str(ROOT / "native/darwin"),
            "-I", str(ROOT / "native/posix"),
            str(harness), str(HANDOFF), "-o", str(executable),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    executed = subprocess.run(
        [
            str(executable), str(generation), str(runtime), str(manifest),
            str(member_receipt), str(alias_generation),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert executed.returncode == 0, executed.stderr.decode()
