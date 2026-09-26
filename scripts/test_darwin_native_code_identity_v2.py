from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IDENTITIES = (
    ("bin/plamen-native-launcher", "com.plamen.audit.launcher.v2", 0o500),
    ("lib/plamen/plamen-audit-broker-v2", "com.plamen.audit.broker.v2", 0o500),
    (
        "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so",
        "com.plamen.audit.native-supervisor.v2",
        0o400,
    ),
    ("bin/python3.12", "org.python.test.plamen-v2", 0o500),
)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, text=True, capture_output=True)


def _cdhash(path: Path) -> str:
    observed = _run("/usr/bin/codesign", "-d", "--verbose=4", str(path))
    match = re.search(r"^CDHash=([0-9a-f]{40}|[0-9a-f]{64})$",
                      observed.stderr, re.MULTILINE)
    assert match is not None
    return match.group(1)


@pytest.mark.skipif(platform.system() != "Darwin", reason="Darwin only")
def test_observed_signed_closure_rejects_receipt_identity_tampering(tmp_path: Path) -> None:
    clang = shutil.which("clang")
    assert clang is not None
    generation = tmp_path / "generation"
    source = tmp_path / "member.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    cdhashes: list[str] = []
    for relative, identifier, mode in IDENTITIES:
        destination = generation / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        _run(clang, str(source), "-o", str(destination))
        _run("/usr/bin/codesign", "--force", "--sign", "-",
             "--identifier", identifier, str(destination))
        destination.chmod(mode)
        cdhashes.append(_cdhash(destination))
    for directory, children, _files in os.walk(generation, topdown=False):
        del children
        Path(directory).chmod(0o500)
    launcher = generation / IDENTITIES[0][0]
    swapped = tmp_path / "launcher-swapped"
    shutil.copy2(launcher, swapped)
    swapped.chmod(0o500)
    launcher.parent.chmod(0o700)

    harness = tmp_path / "identity_harness.c"
    harness.write_text(
        r'''
#include "native/darwin/plamen_native_code_identity_v2.h"
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *paths[4] = {
    "bin/plamen-native-launcher",
    "lib/plamen/plamen-audit-broker-v2",
    "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so",
    "bin/python3.12"
};
static const char *identifiers[4] = {
    "com.plamen.audit.launcher.v2", "com.plamen.audit.broker.v2",
    "com.plamen.audit.native-supervisor.v2", "org.python.test.plamen-v2"
};
static const size_t indexes[4] = { 0, 1, 2, 5 };
static const char *swap_source;
static char swap_prior[2048];
static void swap_path(const char *path) {
    plamen_native_code_identity_test_swap_hook_v2(NULL);
    if (snprintf(swap_prior, sizeof(swap_prior), "%s.prior", path)
            >= (int)sizeof(swap_prior)
        || rename(path, swap_prior) != 0 || rename(swap_source, path) != 0)
        _exit(12);
}

static int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}
static int digest_file(int fd, uint8_t output[32]) {
    struct stat info; uint8_t *bytes; size_t offset = 0;
    if (fstat(fd, &info) != 0 || info.st_size <= 0) return -1;
    bytes = malloc((size_t)info.st_size); if (bytes == NULL) return -1;
    while (offset < (size_t)info.st_size) {
        ssize_t amount = pread(fd, bytes + offset,
            (size_t)info.st_size - offset, (off_t)offset);
        if (amount <= 0) { free(bytes); return -1; }
        offset += (size_t)amount;
    }
    if (CC_SHA256(bytes, (CC_LONG)offset, output) == NULL) {
        free(bytes); return -1;
    }
    free(bytes); return 0;
}
int main(int argc, char **argv) {
    struct plamen_install_receipt receipt; size_t row, byte;
    int root;
    if (argc != 7) return 2;
    memset(&receipt, 0, sizeof(receipt));
    if (strlen(argv[1]) >= sizeof(receipt.generation_path)) return 3;
    strcpy(receipt.generation_path, argv[1]);
    root = open(argv[1], O_RDONLY | O_DIRECTORY); if (root < 0) return 4;
    for (row = 0; row < 4; ++row) {
        struct plamen_install_receipt_member *member =
            &receipt.members[indexes[row]];
        struct stat info; char full[2048]; int fd; size_t hex_size;
        member->role = (uint16_t)(indexes[row] + 1);
        strcpy(member->relative_path, paths[row]);
        strcpy(member->signing_identifier, identifiers[row]);
        if (snprintf(full, sizeof(full), "%s/%s", argv[1], paths[row])
                >= (int)sizeof(full)) return 5;
        fd = open(full, O_RDONLY); if (fd < 0 || fstat(fd, &info) != 0
            || digest_file(fd, member->sha256) != 0) return 6;
        close(fd);
        member->size = (uint64_t)info.st_size;
        member->mode = (uint32_t)(info.st_mode & 07777);
        member->device = (uint64_t)info.st_dev;
        member->inode = (uint64_t)info.st_ino;
        member->uid = (uint32_t)info.st_uid;
        member->gid = (uint32_t)info.st_gid;
        hex_size = strlen(argv[row + 2]);
        if (!(hex_size == 40 || hex_size == 64)) return 7;
        member->cdhash_size = (uint16_t)(hex_size / 2);
        for (byte = 0; byte < member->cdhash_size; ++byte) {
            int high = hex_value(argv[row + 2][byte * 2]);
            int low = hex_value(argv[row + 2][byte * 2 + 1]);
            if (high < 0 || low < 0) return 8;
            member->cdhash[byte] = (uint8_t)((high << 4) | low);
        }
    }
    if (plamen_native_darwin_validate_signed_closure_v2(&receipt, root) != 0)
        return 9;
    receipt.members[0].cdhash[0] ^= 1U;
    if (plamen_native_darwin_validate_signed_closure_v2(&receipt, root) == 0)
        return 10;
    receipt.members[0].cdhash[0] ^= 1U;
    strcpy(receipt.members[0].team_identifier, "FAKE-TEAM");
    if (plamen_native_darwin_validate_signed_closure_v2(&receipt, root) == 0)
        return 11;
    receipt.members[0].team_identifier[0] = '\0';
    swap_source = argv[6];
    plamen_native_code_identity_test_swap_hook_v2(swap_path);
    if (plamen_native_darwin_validate_signed_closure_v2(&receipt, root) == 0)
        return 13;
    close(root); return 0;
}
''',
        encoding="utf-8",
    )
    executable = tmp_path / "identity-harness"
    _run(
        clang,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-DPLAMEN_NATIVE_CODE_IDENTITY_V2_TESTING",
        "-I",
        str(ROOT),
        str(harness),
        str(ROOT / "native/darwin/plamen_native_code_identity_v2.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_install_receipt.c"),
        "-framework",
        "CoreFoundation",
        "-framework",
        "Security",
        "-o",
        str(executable),
    )
    _run(str(executable), str(generation), *cdhashes, str(swapped))
