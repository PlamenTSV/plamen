from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native/darwin/plamen_native_launchd_installer_v2.c"
RECEIPT = ROOT / "native/darwin/plamen_broker_v2_install_receipt.c"
READINESS = ROOT / "native/darwin/plamen_native_launchd_readiness_v2.c"


@pytest.fixture(scope="module")
def helper(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if os.uname().sysname != "Darwin":
        pytest.skip("Darwin launchd validation is Darwin-only")
    compiler = shutil.which("clang")
    if compiler is None:
        pytest.skip("clang is required")
    directory = tmp_path_factory.mktemp("native-launchd-v2")
    harness = directory / "harness.c"
    harness.write_text(
        r'''
#include "plamen_native_launchd_installer_v2.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int fd, status = -1;
    enum plamen_launchd_role_v2 role;
    if (argc < 2) return 64;
    if (strcmp(argv[1], "render") == 0 && argc == 5) {
        role = strcmp(argv[2], "broker") == 0
            ? PLAMEN_LAUNCHD_ROLE_BROKER_V2
            : PLAMEN_LAUNCHD_ROLE_CUSTODY_V2;
        fd = open(argv[4], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) return 70;
        status = plamen_native_launchd_render_plist_v2(fd, argv[3], role);
        close(fd); return status == 0 ? 0 : 71;
    }
    if (strcmp(argv[1], "validate") == 0 && argc == 5) {
        role = strcmp(argv[2], "broker") == 0
            ? PLAMEN_LAUNCHD_ROLE_BROKER_V2
            : PLAMEN_LAUNCHD_ROLE_CUSTODY_V2;
        fd = open(argv[4], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return 72;
        status = plamen_native_launchd_validate_plist_v2(fd, argv[3], role);
        close(fd); return status == 0 ? 0 : 73;
    }
    if (strcmp(argv[1], "print-custody") == 0 && argc == 2) {
        if (plamen_native_launchd_run_v2(getuid(),
                PLAMEN_LAUNCHD_ROLE_CUSTODY_V2, PLAMEN_LAUNCHD_PRINT_V2,
                NULL, &status) != 0) return 74;
        printf("%d\n", status); return 0;
    }
    return 64;
}
''',
        encoding="utf-8",
    )
    output = directory / "helper"
    subprocess.run(
        [
            compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
            "-I", str(ROOT / "native/darwin"),
            str(harness), str(SOURCE), str(READINESS), str(RECEIPT),
            "-framework", "CoreFoundation", "-framework", "Security",
            "-o", str(output),
        ],
        check=True, cwd=ROOT, timeout=30,
    )
    return output


@pytest.mark.parametrize("role", ["broker", "custody"])
def test_exact_plist_round_trip_and_mode(
    helper: Path, tmp_path: Path, role: str,
) -> None:
    service = "/Users/test & owner/.local/share/plamen/generations/abc/lib/plamen/broker"
    output = tmp_path / f"{role}.plist"
    rendered = subprocess.run(
        [str(helper), "render", role, service, str(output)],
        check=False, capture_output=True, text=True, timeout=10,
    )
    assert rendered.returncode == 0, rendered.stderr
    assert output.stat().st_mode & 0o777 == 0o400
    raw = output.read_bytes()
    assert b"/Users/test &amp; owner/" in raw
    assert raw.count(b"--process-custody-daemon") == (role == "custody")
    valid = subprocess.run(
        [str(helper), "validate", role, service, str(output)],
        check=False, capture_output=True, text=True, timeout=10,
    )
    assert valid.returncode == 0, valid.stderr


def test_plist_mutation_and_role_substitution_fail_closed(
    helper: Path, tmp_path: Path,
) -> None:
    service = "/Users/test/.local/share/plamen/generations/abc/lib/plamen/broker"
    output = tmp_path / "broker.plist"
    assert subprocess.run(
        [str(helper), "render", "broker", service, str(output)],
        check=False, timeout=10,
    ).returncode == 0
    assert subprocess.run(
        [str(helper), "validate", "custody", service, str(output)],
        check=False, timeout=10,
    ).returncode == 73
    raw = bytearray(output.read_bytes())
    raw[raw.index(b"KeepAlive")] ^= 1
    output.chmod(0o600)
    output.write_bytes(raw)
    output.chmod(0o400)
    assert subprocess.run(
        [str(helper), "validate", "broker", service, str(output)],
        check=False, timeout=10,
    ).returncode == 73


def test_fixed_launchctl_print_has_bounded_absence_result(helper: Path) -> None:
    completed = subprocess.run(
        [str(helper), "print-custody"], check=False, capture_output=True,
        text=True, timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    # 0 means a deliberately installed test/live job exists; 113 is launchd's
    # exact absent-service status.  Any transport/timeout error fails above.
    assert int(completed.stdout.strip()) in {0, 113}


def test_authenticated_readiness_is_transitive_and_runs_after_both_jobs() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    custody_kick = source.index(
        "PLAMEN_LAUNCHD_ROLE_CUSTODY_V2,\n            PLAMEN_LAUNCHD_KICKSTART_V2",
        source.index("bootstrap_closure"),
    )
    broker_kick = source.index(
        "PLAMEN_LAUNCHD_ROLE_BROKER_V2,\n            PLAMEN_LAUNCHD_KICKSTART_V2",
        custody_kick,
    )
    broker_ready = source.index(
        "PLAMEN_LAUNCHD_ROLE_BROKER_V2, closure->receipt",
        broker_kick,
    )
    custody_ready = source.index(
        "PLAMEN_LAUNCHD_ROLE_CUSTODY_V2, closure->receipt",
        broker_ready,
    )
    assert custody_kick < broker_kick < broker_ready < custody_ready
    assert "plamen_native_launchd_authenticated_ready_v2" in source
    launcher = (ROOT / "native/darwin/plamen_native_launcher.c").read_text(
        encoding="utf-8"
    )
    assert 'argc == 2 && strcmp(argv[1], "readiness") == 0' in launcher
    service = (ROOT / "native/darwin/plamen_broker_v2_service.c").read_text(
        encoding="utf-8"
    )
    assert "plamen_broker_v2_process_custody_client_readiness" in service
