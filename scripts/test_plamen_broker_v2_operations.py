from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
DARWIN = ROOT / "native" / "darwin"
INCLUDE = ROOT / "native" / "include"
PROTOCOL = ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"
OPERATIONS = DARWIN / "plamen_broker_v2_operations.c"
HARNESS = ROOT / "native" / "tests" / "plamen_broker_v2_operations_test.c"


def _run(command: list[str]) -> None:
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
        timeout=120,
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin broker module")
def test_operations_strict_compile_analyze_and_adversarial_harness(
    tmp_path: Path,
) -> None:
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("clang unavailable")
    common = [
        clang, "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-I", str(INCLUDE), "-I", str(DARWIN),
    ]
    operations_object = tmp_path / "operations.o"
    harness_object = tmp_path / "harness.o"
    protocol_object = tmp_path / "protocol.o"
    executable = tmp_path / "operations-test"
    _run(common + ["-c", str(OPERATIONS), "-o", str(operations_object)])
    _run(common + ["-c", str(HARNESS), "-o", str(harness_object)])
    # The concurrently-owned projection builder has private work-in-progress
    # helpers; suppress only that unrelated translation unit's warning.
    _run([
        clang, "-std=c11", "-Wall", "-Wextra", "-Wno-unused-function",
        "-I", str(INCLUDE), "-I", str(DARWIN), "-c", str(PROTOCOL),
        "-o", str(protocol_object),
    ])
    _run([
        clang, str(operations_object), str(harness_object),
        str(protocol_object), "-framework", "Security", "-framework",
        "CoreFoundation", "-o", str(executable),
    ])
    _run([str(executable)])
    _run(common + ["--analyze", str(OPERATIONS)])


def test_operations_table_covers_exact_schema_and_python_adapter_surface() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import posix_native_authority_adapter as adapter
    finally:
        sys.path.pop(0)
    adapter_methods = set(adapter._OPERATIONS)  # type: ignore[attr-defined]
    assert len(adapter_methods) == 26

    schema = json.loads(
        (DARWIN / "native-supervisor-schema-v2.json").read_text("utf-8")
    )
    schema_methods: set[tuple[str, str]] = set()
    member_alias = {
        "RuntimeImageAuthority": "runtime",
        "WorkspaceAuthority": "workspace",
        "BackendContextAuthority": "backend",
        "ProviderAuthority": "provider",
        "GuestAdmissionAuthority": "guest_admission",
        "ExtinctionAuthority": "extinction",
        "ArtifactAuthority": "artifacts",
        "ExportAuthority": "exporter",
        "JournalAuthority": "journal",
        "RecoveryAuthority": "recovery",
    }
    for member in schema["authority_surface"]["outer_supervisor"]["members"]:
        schema_methods.update(
            (member_alias[member["name"]], method)
            for method in member["methods"]
        )
    assert schema_methods == adapter_methods

    source = OPERATIONS.read_text("utf-8")
    c_methods = set(
        re.findall(
            r'"(runtime|workspace|backend|provider|guest_admission|extinction|'
            r'artifacts|exporter|journal|recovery)",\s*\n?\s*"([a-z_]+)"',
            source,
        )
    )
    assert c_methods == adapter_methods


def test_operations_constructor_requires_custody_replay_and_cancellation() -> None:
    header = (DARWIN / "plamen_broker_v2_operations.h").read_text("utf-8")
    for required in (
        "revalidate", "monotonic_ms", "cancelled", "execute",
        "dispose_result", "replay_lookup", "replay_commit",
        "monotonic_deadline_ms",
    ):
        assert required in header
    source = OPERATIONS.read_text("utf-8")
    assert "PLAMEN_BROKER_V2_RPC_REPLAY_MAX_ENTRIES" in source
    assert "PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS" in source
    assert "session->burned = 1" in source
