from __future__ import annotations

import ctypes
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import test_darwin_apple_container_lifecycle as lifecycle_test


class _Factory:
    def __init__(self, root: Path) -> None:
        self.root = root

    def mktemp(self, name: str) -> Path:
        result = self.root / name
        result.mkdir()
        return result


def test_specialized_worker_platform_assignment_produces_arm64_argv(
    tmp_path: Path,
) -> None:
    source = (ROOT / "native/darwin/plamen_broker_v2_effects.c").read_text(
        encoding="utf-8"
    )
    start = source.index(
        "plamen_broker_v2_effects_run_specialized_worker_locked("
    )
    end = source.index("\nstatic int\n", start)
    body = source[start:end]
    assert "spec.rosetta_required = 0U;" in body
    assert "spec.rosetta_required = 1U;" not in body

    library = lifecycle_test.lifecycle_library.__wrapped__(_Factory(tmp_path))
    spec, _receipt, _arguments, descriptors, _state = lifecycle_test._spec(
        library, tmp_path / "spec"
    )
    try:
        spec.rosetta_required = 0
        output = ctypes.create_string_buffer(8192)
        assert library.plamen_broker_v2_apple_lifecycle_test_create_argv(
            ctypes.byref(spec), output, len(output)
        ) == 0
        argv = output.value.decode("utf-8").splitlines()
        assert "linux/arm64" in argv
        assert "--rosetta" not in argv
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
