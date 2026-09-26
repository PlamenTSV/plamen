"""Run18 regression: compatibility must not counterfeit native EVM tools.

The installed Run18 lane was POSIX V2 host compatibility.  The native image
does contain reviewed OpenGrep/Slither member names, but that fact alone is not
a live, request-bound execution capability.  These checks keep the current
debt honest until the native-front installed-generation/readmission work is
complete.
"""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "scripts/plamen_driver.py"
RECON = ROOT / "scripts/recon_prepass.py"
IMAGE_MEMBERS = ROOT / "native/darwin/plamen_native_image_member_receipt_v2.c"
SPECIALIZED_REQUEST = ROOT / "native/darwin/plamen_broker_v2_specialized_request.c"


def _function_source(path: Path, name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    node = next(
        item
        for item in ast.walk(tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == name
    )
    assert node.end_lineno is not None
    return "\n".join(source.splitlines()[node.lineno - 1 : node.end_lineno])


def test_opengrep_image_member_is_real_but_compat_never_mints_session() -> None:
    roster = IMAGE_MEMBERS.read_text(encoding="utf-8")
    codec = SPECIALIZED_REQUEST.read_text(encoding="utf-8")
    main = _function_source(DRIVER, "main")

    assert (
        '{"opengrep", "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep", 1U}'
        in roster
    )
    assert 'strcmp(anchor, "opengrep") == 0' in codec
    assert 'path = "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep"' in codec

    # Host compatibility deliberately has no NativeGuestRuntimeAuthorities.
    # A fixed image-member string must never be promoted into that missing
    # process-local capability.
    acquisition = main.index("acquire_native_guest_runtime_authorities()")
    guard = main.rfind("not _requested_posix_compat_v2", 0, acquisition)
    assert guard >= 0
    observations = main.index("_evm_tool_observations = {")
    compat_guard = main.rfind("and not posix_compat_v2", 0, observations)
    assert compat_guard >= 0
    assert main.index("issue_session_bound_evm_tool_authority(") > observations


def test_evm_opengrep_refuses_before_path_or_rule_discovery() -> None:
    body = _function_source(RECON, "_run_opengrep_scan")
    unavailable = body.index("EVM_WORKSPACE_SCANNER_NATIVE_AUTHORITY_UNAVAILABLE")

    assert unavailable < body.index('shutil.which("opengrep")')
    assert unavailable < body.index("_ensure_opengrep_rules()")
    assert unavailable < body.index("tempfile.mkdtemp(")
    assert 'scanner_name = "opengrep" if "opengrep" in available_tool_ids else ""' in body
    assert "native_runtime_authority is None" in body[: unavailable + 256]


def test_slither_refuses_before_source_or_temporary_state_effects() -> None:
    body = _function_source(RECON, "_bake_evm_slither_native_graph")
    unavailable = body.index("NATIVE_SESSION_UNBOUND")

    assert "session_tool_authority is None" in body[:unavailable]
    assert "native_runtime_authority is None" in body[:unavailable]
    assert unavailable < body.index('proj.rglob("*.sol")')
    assert unavailable < body.index("tempfile.mkdtemp(")
    assert unavailable < body.index("execute_session_bound_evm_tool(")
