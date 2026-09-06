"""Deterministically freeze R3.13 generated evidence artifacts.

This builder has no driver/provider/ledger/cutover integration.  It writes only
inside the R3.13 temporary handoff directory selected below.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys


REPO = Path(__file__).resolve().parent.parent
OUTPUT_ROOT = REPO / "Temp/program_facts_g3_launcher_r3_13_20260809"
RUNTIME_OUTPUT = OUTPUT_ROOT / "r3_13_runtime_closure.v1.json"
LAUNCHER = REPO / "scripts/program_facts_windows_native_launcher_r3_13.py"


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def freeze_runtime_closure() -> dict[str, object]:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(LAUNCHER),
            "--runtime-closure-child",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(REPO),
        check=False,
        timeout=120,
    )
    if completed.returncode != 0 or completed.stderr or not completed.stdout:
        raise RuntimeError("R3.13 runtime closure child failed")
    value = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    raw = canonical(value)
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    RUNTIME_OUTPUT.write_bytes(raw)
    return {
        "path": RUNTIME_OUTPUT.relative_to(REPO).as_posix(),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "module_origins": len(value["loaded_child_module_origins"]),
        "image_origins": len(value["loaded_child_image_origins"]),
    }


def main() -> int:
    print(json.dumps(freeze_runtime_closure(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
