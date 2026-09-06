"""Backend-safe MCP policy for the sole live MCP phase."""

from __future__ import annotations

from pathlib import Path

import plamen_driver as D
import plamen_types as T


def _rag_phase(pipeline: str):
    phases = T.SC_PHASES if pipeline == "sc" else T.L1_PHASES
    return next(phase for phase in phases if phase.name == "rag_sweep")


def test_typed_rag_sweep_launch_carries_the_selected_mcp_denominator_only_for_claude_headless(
    tmp_path: Path,
) -> None:
    for name in (
        "build_status.md",
        "findings_inventory.md",
        "precedent_finding_facts.json",
    ):
        (tmp_path / name).write_text("fixture\n", encoding="utf-8")

    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "claude_exec_mode": "headless",
        "project_root": str(tmp_path),
    }
    _contract, launch = D._typed_model_phase_contract_and_launch(
        _rag_phase("sc"), tmp_path, config
    )

    assert launch.tool_policy == ("filesystem", "mcp", "network")


def test_typed_rag_sweep_launch_is_honest_for_pty_and_codex(
    tmp_path: Path,
) -> None:
    for name in (
        "build_status.md",
        "findings_inventory.md",
        "precedent_finding_facts.json",
    ):
        (tmp_path / name).write_text("fixture\n", encoding="utf-8")

    phase = _rag_phase("sc")
    for backend, execution_mode in (("claude", "pty"), ("codex", "headless")):
        config = {
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": backend,
            "claude_exec_mode": execution_mode,
            "project_root": str(tmp_path),
        }
        _contract, launch = D._typed_model_phase_contract_and_launch(
            phase, tmp_path, config
        )
        assert launch.tool_policy == ("filesystem", "network")


def test_only_rag_sweep_declares_mcp_for_both_pipelines() -> None:
    for phases in (T.SC_PHASES, T.L1_PHASES):
        selected = [phase.name for phase in phases if phase.needs_mcp]
        assert selected == ["rag_sweep"]


def test_legacy_claude_pty_always_receives_strict_mcp_isolation() -> None:
    source = Path(D.__file__).read_text(encoding="utf-8")

    assert (
        'if claude_tool_boundary is None and backend != "codex":' in source
    )
    assert (
        'if claude_tool_boundary is None and not phase.needs_mcp' not in source
    )
