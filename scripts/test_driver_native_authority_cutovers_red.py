"""RED contracts for the remaining native driver authority cutovers.

These source-bound tests deliberately describe the production call order before
the native producers are released.  They prevent the final wiring from moving
managed setup after scratch/snapshot effects or retaining a reviewed-version
literal as an ambient compatibility shortcut.
"""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "scripts" / "plamen_driver.py"
HEADLESS = ROOT / "scripts" / "headless_worker_runtime.py"
TRANSACTION = ROOT / "scripts" / "worker_transaction.py"


def _function_source(source: str, name: str) -> str:
    tree = ast.parse(source)
    node = next(
        item
        for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == name
    )
    assert node.end_lineno is not None
    return "\n".join(source.splitlines()[node.lineno - 1 : node.end_lineno])


def test_managed_evm_preflight_precedes_scratch_snapshot_and_provider() -> None:
    source = DRIVER.read_text(encoding="utf-8")
    main = _function_source(source, "main")
    call = main.index("prepare_native_managed_evm_for_audit(")

    assert main.index("_admit_model_prompt_filesystem_roots(config)") < call
    assert call < main.index("scratchpad = Path(config[\"scratchpad\"])")
    assert call < main.index("_bind_checkpoint_audit_snapshot(")
    assert call < main.index("capture_command_provider_authority(")
    assert "native_request.target_identity_sha256" in main[:call + 1024]
    assert "managed_evm_generation_authority_for_runtime(" in main

    adapter = ROOT / "scripts" / "native_managed_evm_driver_preflight.py"
    adapter_source = adapter.read_text(encoding="utf-8")
    assert "NativeManagedEVMSetupEffects" in adapter_source
    assert "DarwinColdInstallEffects" not in adapter_source
    assert "Path.home(" not in adapter_source
    assert "expanduser(" not in adapter_source
    assert "subprocess" not in adapter_source
    assert "os.environ" not in adapter_source


def test_driver_uses_authenticated_dynamic_claude_generation() -> None:
    source = DRIVER.read_text(encoding="utf-8")
    projection = _function_source(
        source, "_selected_claude_backend_projection"
    )
    selection = _function_source(source, "_selected_claude_backend_argv_prefix")
    compilation = _function_source(
        source, "_compile_posix_claude_driver_provider_authority"
    )

    assert '"2.1.252"' not in selection
    assert '"2.1.252"' not in compilation
    assert "replay_mcp_current_selection(selection)" in projection
    assert '["backend_launches"]["claude"]' in projection
    assert "_selected_claude_backend_projection()" in selection
    assert "_backend_install_generation_authority_for_launch(config)" in compilation
    assert "require_backend_install_generation(" in compilation
    assert ".resolved_version" in compilation
    assert "config.get(" not in projection
    assert "os.environ" not in projection
    assert "--version" not in selection
    assert all(version not in source for version in (
        '"2.1.252"', '"2.1.270"', '"0.154.0"',
    ))


def test_every_native_headless_launch_carries_the_opaque_generation() -> None:
    source = DRIVER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "execute_headless_worker"
    ]
    assert len(calls) == 4
    for call in calls:
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        authority = keywords["backend_install_generation_authority"]
        assert isinstance(authority, ast.Call)
        assert isinstance(authority.func, ast.Name)
        assert authority.func.id == "_backend_install_generation_authority_for_launch"

    init = _function_source(source, "_backend_install_generation_authority_for_launch")
    assert "require_backend_install_generation(authority)" in init
    assert 'config.get("cli_backend")' in init
    assert "os.environ" not in init
    assert "subprocess" not in init


def test_generation_authority_reaches_native_prepare_without_fallback() -> None:
    headless = HEADLESS.read_text(encoding="utf-8")
    transaction = TRANSACTION.read_text(encoding="utf-8")
    for name in (
        "_execute_prepared_headless_worker",
        "execute_prepared_headless_worker",
        "execute_headless_worker",
    ):
        body = _function_source(headless, name)
        assert "backend_install_generation_authority" in body
    execute = _function_source(transaction, "execute_worker_transaction")
    assert "backend_install_generation_authority" in execute
    assert "prepare_posix_backend_execution(" in execute
    assert "backend_install_generation_authority=(" in execute
