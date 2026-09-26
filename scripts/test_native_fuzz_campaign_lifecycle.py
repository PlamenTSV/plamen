from __future__ import annotations

import json
from pathlib import Path
import platform
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="Apple Container native lifecycle",
)


def test_forge_medusa_lifecycle_and_extinction_contract(tmp_path: Path) -> None:
    executable = tmp_path / "fuzz-campaign-test"
    completed = subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-I", str(ROOT / "native/darwin"),
        "-I", str(ROOT / "native/include"),
        str(ROOT / "native/tests/plamen_broker_v2_fuzz_campaign_test.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_fuzz_campaign.c"),
        str(ROOT / "native/darwin/plamen_broker_v2_fuzz_service.c"),
        "-framework", "Security", "-framework", "CoreFoundation",
        "-o", str(executable),
    ], cwd=ROOT, check=False, stdin=subprocess.DEVNULL,
       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    run = subprocess.run(
        [str(executable)], cwd=ROOT, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    assert run.returncode == 0, run.stderr.decode("utf-8", "replace")
    receipt = json.loads(run.stdout)
    assert run.stdout == json.dumps(
        receipt, allow_nan=False, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    assert receipt["schema"] == "plamen.apple-container.native-fuzz-bundle.v1"
    terminal = receipt["terminal"]
    assert terminal["schema"] == (
        "plamen.apple-container.native-fuzz-terminal.v1"
    )
    assert all(terminal[field] is True for field in (
        "descendants_extinct", "guest_process_extinct",
        "backend_egress_revoked", "stop_control_process_reaped",
        "stop_control_process_group_extinct", "guest_population_zero",
        "container_vm_stopped",
    ))
    assert all(len(terminal[field]) == 64 for field in (
        "stop_argv_sha256", "stop_stdout_sha256", "stop_stderr_sha256",
        "stopped_observation_sha256",
        "guest_population_extinction_sha256",
    ))
