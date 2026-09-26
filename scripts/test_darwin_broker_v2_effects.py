from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
CLANG = shutil.which("clang")


def _projection() -> bytes:
    source = (
        b'{"_run_id":"run-1","cli_backend":"codex","language":"evm",'
        b'"mode":"core","pipeline":"sc","project_root":'
        b'"/workspace/project","scratchpad":"/workspace/scratch"}\n'
    )
    source_sha = hashlib.sha256(source).hexdigest()
    request = {
        "attempt_id": "attempt-1",
        "backend": "codex",
        "backend_admission_sha256": "66" * 32,
        "backend_context_sha256": "bb" * 32,
        "credential_bundle_sha256": "cc" * 32,
        "credential_isolation_sha256": "77" * 32,
        "docs_sha256": "dd" * 32,
        "egress_admission_sha256": "88" * 32,
        "egress_policy_sha256": "ee" * 32,
        "export_allowlist": [
            "project/AUDIT_REPORT.md",
            "scratch/_plamen.log",
            "scratch/_v2_checkpoint.json",
        ],
        "export_destination_identity_sha256": "ff" * 32,
        "export_max_total_bytes": 2_147_483_648,
        "failure_required_artifacts": ["scratch/_plamen.log"],
        "image_closure_sha256": "44" * 32,
        "image_manifest_digest": "sha256:" + "99" * 32,
        "language": "evm",
        "mode": "core",
        "pipeline": "sc",
        "provider_provenance_sha256": "55" * 32,
        "request_id": "request-1",
        "request_type": "SC_NEW",
        "required_artifacts": [
            "project/AUDIT_REPORT.md",
            "scratch/_v2_checkpoint.json",
        ],
        "run_id": "run-1",
        "runtime_layout_sha256": "33" * 32,
        "schema": "plamen.posix_audit_supervisor.v1",
        "scope_sha256": "11" * 32,
        "seccomp_profile_sha256": "22" * 32,
        "source_config": {
            "authenticated": True,
            "canonical_utf8_b64": base64.b64encode(source).decode("ascii"),
            "retained_source_handle": "opaque:" + "aa" * 32,
            "sha256": source_sha,
        },
        "source_config_sha256": source_sha,
        "startup_decision_receipt_sha256": "aa" * 32,
        "target_identity_sha256": "00" * 32,
    }
    return json.dumps(
        {
            "audit_request": request,
            "projection_schema": "plamen.native_audit_request_projection.v1",
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin native contract")
def test_effects_atomic_custody_replay_and_revalidation(tmp_path: Path) -> None:
    if CLANG is None:
        pytest.skip("clang is unavailable")
    projection = tmp_path / "projection.json"
    projection.write_bytes(_projection())
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    target = tmp_path / "target"
    export = tmp_path / "export"
    target.mkdir()
    export.mkdir()
    slots = {
        0: tmp_path / "config",
        1: target,
        4: export,
        5: tmp_path / "role5-schema",
        6: tmp_path / "runtime-manifest",
        7: tmp_path / "provider",
        8: tmp_path / "backend",
        9: tmp_path / "backend-profile",
        10: tmp_path / "credential",
        11: tmp_path / "egress-policy",
        12: tmp_path / "egress-admission",
    }
    for slot, path in slots.items():
        if path.is_dir():
            continue
        path.write_bytes(f"authority-{slot}\n".encode("ascii"))
        path.chmod(0o500 if slot in (7, 8) else 0o600)
    harness = tmp_path / "effects-test"
    command = [
        CLANG,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(ROOT / "native" / "include"),
        "-I",
        str(ROOT / "native" / "darwin"),
        "-I",
        str(ROOT / "native" / "posix"),
        str(ROOT / "native" / "tests" / "broker_v2_effects_test_peer.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_effects.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_workspace_effects.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_process.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custodian.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_client.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container_lifecycle.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_artifact_export.c"),
        str(ROOT / "native" / "darwin" / "plamen_broker_v2_tool_custody.c"),
        str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
        "-framework",
        "Security",
        "-framework",
        "CoreFoundation",
        "-o",
        str(harness),
    ]
    subprocess.run(command, check=True, capture_output=True)
    ordered = [str(slots[index]) for index in (0, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
    completed = subprocess.run(
        [str(harness), str(projection), str(state_dir), *ordered],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert os.stat(state_dir).st_mode & stat.S_IRWXO == 0
